"""
tun.py — TUN/TAP Virtual Network Interface
Creates and manages a Linux TUN interface for Layer-3 IP tunneling.
Arianna — Week 3
"""

import os
import fcntl
import struct
import logging
import subprocess
from typing import Optional

log = logging.getLogger("vpn.tun")

# Linux ioctl constants for TUN/TAP
TUNSETIFF   = 0x400454CA
TUNSETOWNER = 0x400454CC
IFF_TUN     = 0x0001
IFF_TAP     = 0x0002
IFF_NO_PI   = 0x1000    # don't prepend packet information header

TUN_DEV_PATH = "/dev/net/tun"
DEFAULT_MTU  = 1420      # standard VPN MTU (1500 - overhead)
READ_BUFFER  = 65535


class TUNInterface:
    """
    Manages a Linux TUN virtual network interface.

    Usage:
        tun = TUNInterface("vpn0")
        tun.open()
        tun.configure("10.8.0.1", "10.8.0.0/24")

        raw_ip = tun.read()      # blocks until a packet arrives from the OS
        tun.write(raw_ip)        # inject a packet into the OS network stack
        tun.close()

    Can also be used as a context manager:
        with TUNInterface("vpn0") as tun:
            tun.configure(...)
            ...
    """

    def __init__(self, name: str = "vpn0", mtu: int = DEFAULT_MTU):
        self.name    = name
        self.mtu     = mtu
        self._fd: Optional[int] = None

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def open(self) -> None:
        """Open the TUN device and configure the interface name."""
        if not os.path.exists(TUN_DEV_PATH):
            raise OSError(
                f"TUN device {TUN_DEV_PATH!r} not found. "
                "Is the tun kernel module loaded? (sudo modprobe tun)"
            )

        self._fd = os.open(TUN_DEV_PATH, os.O_RDWR)

        # ifreq struct: 16-byte name + flags
        ifr = struct.pack("16sH", self.name.encode()[:15], IFF_TUN | IFF_NO_PI)
        try:
            fcntl.ioctl(self._fd, TUNSETIFF, ifr)
        except OSError as e:
            os.close(self._fd)
            self._fd = None
            raise OSError(f"Failed to create TUN interface {self.name!r}: {e}") from e

        log.info("TUN interface %r opened (fd=%d)", self.name, self._fd)

    def configure(
        self,
        local_ip:   str,
        network:    str,
        remote_ip:  Optional[str] = None,
        mtu:        Optional[int] = None,
    ) -> None:
        """
        Bring up the TUN interface and assign an IP address.
        Requires root / CAP_NET_ADMIN.
        """
        if self._fd is None:
            raise RuntimeError("TUN interface not opened")

        mtu = mtu or self.mtu

        cmds = [
            ["ip", "link", "set", "dev", self.name, "mtu", str(mtu)],
            ["ip", "addr", "add", f"{local_ip}/30" if remote_ip else local_ip, "dev", self.name],
            ["ip", "link", "set", "dev", self.name, "up"],
        ]

        for cmd in cmds:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                log.warning("Command %s failed: %s", " ".join(cmd), result.stderr.strip())
            else:
                log.debug("Ran: %s", " ".join(cmd))

        # Add route for the VPN subnet
        route_cmd = ["ip", "route", "add", network, "dev", self.name]
        result = subprocess.run(route_cmd, capture_output=True, text=True)
        if result.returncode != 0 and "File exists" not in result.stderr:
            log.warning("Route add failed: %s", result.stderr.strip())
        else:
            log.info("Route %s via %s configured", network, self.name)

        log.info(
            "TUN %r configured: local=%s network=%s mtu=%d",
            self.name, local_ip, network, mtu,
        )

    def set_default_route(self, gateway: str) -> None:
        """Route all traffic through the VPN (full tunnel mode)."""
        cmds = [
            # Save current default route first — call save_default_route() separately
            ["ip", "route", "add", "0.0.0.0/1", "via", gateway, "dev", self.name],
            ["ip", "route", "add", "128.0.0.0/1", "via", gateway, "dev", self.name],
        ]
        for cmd in cmds:
            subprocess.run(cmd, capture_output=True)
        log.info("Full tunnel routing via %s active", gateway)

    def restore_default_route(self, original_gateway: str, original_iface: str) -> None:
        """Restore the pre-VPN default route on disconnect."""
        cmds = [
            ["ip", "route", "del", "0.0.0.0/1"],
            ["ip", "route", "del", "128.0.0.0/1"],
            ["ip", "route", "add", "default", "via", original_gateway, "dev", original_iface],
        ]
        for cmd in cmds:
            subprocess.run(cmd, capture_output=True)
        log.info("Default route restored via %s (%s)", original_gateway, original_iface)

    def close(self) -> None:
        """Bring down and close the TUN interface."""
        if self._fd is not None:
            # Best-effort teardown
            subprocess.run(
                ["ip", "link", "set", "dev", self.name, "down"],
                capture_output=True,
            )
            os.close(self._fd)
            self._fd = None
            log.info("TUN interface %r closed", self.name)

    # ── I/O ────────────────────────────────────────────────────────────────────

    def read(self) -> bytes:
        """
        Read one IP packet from the TUN interface (blocking).
        Returns raw IP packet bytes (no TUN header since IFF_NO_PI is set).
        """
        if self._fd is None:
            raise RuntimeError("TUN interface not open")
        data = os.read(self._fd, READ_BUFFER)
        log.debug("TUN read %d bytes", len(data))
        return data

    def write(self, packet: bytes) -> None:
        """
        Inject a raw IP packet into the OS network stack via TUN.
        """
        if self._fd is None:
            raise RuntimeError("TUN interface not open")
        os.write(self._fd, packet)
        log.debug("TUN wrote %d bytes", len(packet))

    def fileno(self) -> int:
        """Return the file descriptor (for use with select/poll)."""
        if self._fd is None:
            raise RuntimeError("TUN interface not open")
        return self._fd

    # ── Context manager ────────────────────────────────────────────────────────

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *_):
        self.close()


# ── DNS Leak Prevention ────────────────────────────────────────────────────────

class DNSProtection:
    """
    Manages DNS leak prevention by overriding /etc/resolv.conf
    with VPN-internal DNS servers during an active session.
    Restores the original on teardown.
    """

    RESOLV_CONF = "/etc/resolv.conf"
    BACKUP_PATH = "/etc/resolv.conf.vpn-backup"

    def __init__(self, vpn_dns_servers: list):
        self._dns_servers = vpn_dns_servers
        self._active = False

    def apply(self) -> bool:
        """Override resolv.conf. Returns True on success."""
        try:
            # Back up current config
            with open(self.RESOLV_CONF, "r") as f:
                original = f.read()
            with open(self.BACKUP_PATH, "w") as f:
                f.write(original)

            # Write VPN DNS config
            lines = ["# VPN DNS — managed by vpn client\n"]
            for srv in self._dns_servers:
                lines.append(f"nameserver {srv}\n")
            with open(self.RESOLV_CONF, "w") as f:
                f.writelines(lines)

            self._active = True
            log.info("DNS protection active: %s", self._dns_servers)
            return True
        except PermissionError:
            log.warning("DNS protection: permission denied (not running as root?)")
            return False
        except Exception as e:
            log.error("DNS protection apply failed: %s", e)
            return False

    def restore(self) -> bool:
        """Restore the original resolv.conf. Returns True on success."""
        if not self._active:
            return True
        try:
            if os.path.exists(self.BACKUP_PATH):
                with open(self.BACKUP_PATH, "r") as f:
                    original = f.read()
                with open(self.RESOLV_CONF, "w") as f:
                    f.write(original)
                os.remove(self.BACKUP_PATH)
            self._active = False
            log.info("DNS protection removed — original resolv.conf restored")
            return True
        except Exception as e:
            log.error("DNS restore failed: %s", e)
            return False

    def __enter__(self):
        self.apply()
        return self

    def __exit__(self, *_):
        self.restore()
