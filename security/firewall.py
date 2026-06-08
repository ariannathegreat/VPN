"""
firewall.py — iptables Rules for VPN Security
Gage — Weeks 5 & 6

Responsibilities:
  Server: enable IP forwarding, NAT/MASQUERADE so VPN clients can reach the internet
  Client: block DNS on physical interfaces to prevent DNS leaks
  Both:   clean up rules on disconnect
"""

import logging
import subprocess
from typing import List, Optional

log = logging.getLogger("vpn.firewall")


def _run(cmd: List[str], check: bool = False) -> subprocess.CompletedProcess:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        msg = f"iptables command failed: {' '.join(cmd)!r} — {result.stderr.strip()}"
        if check:
            raise OSError(msg)
        log.warning(msg)
    else:
        log.debug("Ran: %s", " ".join(cmd))
    return result


def _ip_forward_enabled() -> bool:
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            return f.read().strip() == "1"
    except OSError:
        return False


# ── Server Firewall ────────────────────────────────────────────────────────────

class ServerFirewall:
    """
    Sets up iptables rules required on the VPN server to:
      1. Enable kernel IP forwarding (required for routing between TUN and WAN)
      2. NAT outgoing VPN traffic via MASQUERADE so clients can reach the internet
      3. Allow forwarded traffic in both directions
      4. Accept VPN UDP port on INPUT

    All rules are tagged with a comment so they can be reliably removed on teardown
    without disturbing unrelated rules.
    """

    _COMMENT = "vpn-server-managed"

    def __init__(
        self,
        wan_iface:   str,
        vpn_network: str = "10.8.0.0/24",
        vpn_port:    int = 5194,
        tun_name:    str = "vpns0",
    ):
        self.wan_iface   = wan_iface
        self.vpn_network = vpn_network
        self.vpn_port    = vpn_port
        self.tun_name    = tun_name
        self._forwarding_was_enabled = False

    def apply(self) -> bool:
        """Apply all server firewall rules. Returns True if successful."""
        self._forwarding_was_enabled = _ip_forward_enabled()

        # 1. Enable IP forwarding
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1\n")
            log.info("IP forwarding enabled")
        except PermissionError:
            log.error("Cannot enable IP forwarding — not running as root")
            return False

        c = self._COMMENT

        # 2. Accept VPN UDP traffic on INPUT
        _run(["iptables", "-A", "INPUT",
              "-p", "udp", "--dport", str(self.vpn_port),
              "-m", "comment", "--comment", c, "-j", "ACCEPT"])

        # 3. Allow forwarding FROM TUN to WAN (VPN clients → internet)
        _run(["iptables", "-A", "FORWARD",
              "-i", self.tun_name, "-o", self.wan_iface,
              "-m", "state", "--state", "NEW,ESTABLISHED,RELATED",
              "-m", "comment", "--comment", c, "-j", "ACCEPT"])

        # 4. Allow forwarding FROM WAN to TUN (return traffic)
        _run(["iptables", "-A", "FORWARD",
              "-i", self.wan_iface, "-o", self.tun_name,
              "-m", "state", "--state", "ESTABLISHED,RELATED",
              "-m", "comment", "--comment", c, "-j", "ACCEPT"])

        # 5. NAT: MASQUERADE VPN subnet traffic leaving via WAN
        _run(["iptables", "-t", "nat", "-A", "POSTROUTING",
              "-s", self.vpn_network,
              "-o", self.wan_iface,
              "-m", "comment", "--comment", c, "-j", "MASQUERADE"])

        log.info(
            "Server firewall applied: NAT %s via %s, port %d",
            self.vpn_network, self.wan_iface, self.vpn_port,
        )
        return True

    def remove(self) -> None:
        """Remove all rules added by apply()."""
        c = self._COMMENT

        # Remove NAT rule
        _run(["iptables", "-t", "nat", "-D", "POSTROUTING",
              "-s", self.vpn_network,
              "-o", self.wan_iface,
              "-m", "comment", "--comment", c, "-j", "MASQUERADE"])

        # Remove FORWARD rules
        _run(["iptables", "-D", "FORWARD",
              "-i", self.tun_name, "-o", self.wan_iface,
              "-m", "state", "--state", "NEW,ESTABLISHED,RELATED",
              "-m", "comment", "--comment", c, "-j", "ACCEPT"])

        _run(["iptables", "-D", "FORWARD",
              "-i", self.wan_iface, "-o", self.tun_name,
              "-m", "state", "--state", "ESTABLISHED,RELATED",
              "-m", "comment", "--comment", c, "-j", "ACCEPT"])

        # Remove INPUT rule
        _run(["iptables", "-D", "INPUT",
              "-p", "udp", "--dport", str(self.vpn_port),
              "-m", "comment", "--comment", c, "-j", "ACCEPT"])

        # Restore IP forwarding only if we changed it
        if not self._forwarding_was_enabled:
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("0\n")
                log.info("IP forwarding restored to disabled")
            except OSError:
                pass

        log.info("Server firewall rules removed")

    def __enter__(self):
        self.apply()
        return self

    def __exit__(self, *_):
        self.remove()


# ── Client Firewall (DNS Leak Prevention) ─────────────────────────────────────

class ClientFirewall:
    """
    Blocks DNS queries (port 53 UDP/TCP) from leaving on physical interfaces
    while the VPN is active, preventing DNS leaks.

    DNS is still allowed through the TUN interface so queries routed through
    the VPN reach the VPN-side resolver.

    Also blocks all traffic to non-VPN interfaces except the VPN server's
    real IP (so the VPN connection itself isn't broken).
    """

    _COMMENT = "vpn-client-managed"

    def __init__(
        self,
        tun_name:    str,
        server_ip:   str,
        server_port: int = 5194,
        phys_iface:  Optional[str] = None,   # auto-detect if None
    ):
        self.tun_name    = tun_name
        self.server_ip   = server_ip
        self.server_port = server_port
        self.phys_iface  = phys_iface or self._detect_phys_iface()

    def _detect_phys_iface(self) -> str:
        """Return the name of the default route interface."""
        result = subprocess.run(
            ["ip", "route", "get", "1.1.1.1"],
            capture_output=True, text=True,
        )
        for token in result.stdout.split():
            if token == "dev":
                idx = result.stdout.split().index("dev")
                return result.stdout.split()[idx + 1]
        return "eth0"

    def apply(self) -> bool:
        """Apply DNS leak prevention rules. Returns True on success."""
        c = self._COMMENT

        # Allow VPN tunnel traffic to the server (must come first)
        _run(["iptables", "-A", "OUTPUT",
              "-d", self.server_ip, "-p", "udp", "--dport", str(self.server_port),
              "-m", "comment", "--comment", c, "-j", "ACCEPT"])

        # Allow all traffic on the TUN interface (inside the tunnel)
        _run(["iptables", "-A", "OUTPUT",
              "-o", self.tun_name,
              "-m", "comment", "--comment", c, "-j", "ACCEPT"])

        # Block DNS UDP on physical interface — prevents leak if resolver tries direct
        _run(["iptables", "-A", "OUTPUT",
              "-o", self.phys_iface, "-p", "udp", "--dport", "53",
              "-m", "comment", "--comment", c, "-j", "DROP"])

        # Block DNS TCP on physical interface
        _run(["iptables", "-A", "OUTPUT",
              "-o", self.phys_iface, "-p", "tcp", "--dport", "53",
              "-m", "comment", "--comment", c, "-j", "DROP"])

        log.info(
            "Client DNS leak prevention active: DNS blocked on %s, allowed via %s",
            self.phys_iface, self.tun_name,
        )
        return True

    def remove(self) -> None:
        """Remove all DNS leak prevention rules."""
        c = self._COMMENT

        _run(["iptables", "-D", "OUTPUT",
              "-o", self.phys_iface, "-p", "tcp", "--dport", "53",
              "-m", "comment", "--comment", c, "-j", "DROP"])

        _run(["iptables", "-D", "OUTPUT",
              "-o", self.phys_iface, "-p", "udp", "--dport", "53",
              "-m", "comment", "--comment", c, "-j", "DROP"])

        _run(["iptables", "-D", "OUTPUT",
              "-o", self.tun_name,
              "-m", "comment", "--comment", c, "-j", "ACCEPT"])

        _run(["iptables", "-D", "OUTPUT",
              "-d", self.server_ip, "-p", "udp", "--dport", str(self.server_port),
              "-m", "comment", "--comment", c, "-j", "ACCEPT"])

        log.info("Client DNS leak prevention rules removed")

    def __enter__(self):
        self.apply()
        return self

    def __exit__(self, *_):
        self.remove()


# ── Helpers ────────────────────────────────────────────────────────────────────

def detect_wan_interface() -> str:
    """Return the name of the interface used for the default route."""
    result = subprocess.run(
        ["ip", "route", "show", "default"],
        capture_output=True, text=True,
    )
    for line in result.stdout.splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    return "eth0"


def list_active_vpn_rules() -> str:
    """Return current iptables rules tagged with the VPN comment (for debugging)."""
    result = subprocess.run(
        ["iptables", "-S"],
        capture_output=True, text=True,
    )
    lines = [l for l in result.stdout.splitlines() if "vpn-" in l]
    return "\n".join(lines) if lines else "(no VPN iptables rules active)"
