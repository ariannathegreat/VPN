"""
client.py — VPN Client Application
Connects to a VPN server, performs the handshake, then forwards encrypted traffic.
Arianna — Weeks 3, 4, 5, 6, 7
"""

import os
import sys
import time
import socket
import select
import logging
import threading
import argparse
from typing import Optional

# Add parent directory to path for imports when run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crypto     import DEFAULT_CIPHER
from core.handshake  import ClientHandshake, SessionKeys
from core.packet     import PacketEncapsulator, PacketType, VPNPacket, ReplayWindow, validate_timestamp
from core.tun        import TUNInterface, DNSProtection
from utils.logger    import setup_logging, AuditLogger

log = logging.getLogger("vpn.client")

BUFFER_SIZE         = 65535
KEEPALIVE_INTERVAL  = 20.0     # seconds
HANDSHAKE_TIMEOUT   = 10.0
RECONNECT_DELAY     = 5.0
MAX_RECONNECT_TRIES = 5


class VPNClient:
    """
    Full VPN client.

    Lifecycle:
      1. connect() → UDP socket to server
      2. _do_handshake() → ECDH + PSK auth, derive session keys
      3. _run_tunnel() → forward TUN ↔ UDP bidirectionally
      4. disconnect() → send DISCONNECT, restore DNS, close TUN
    """

    def __init__(
        self,
        server_host:   str,
        server_port:   int,
        psk:           str,
        tun_name:      str = "vpn0",
        local_tun_ip:  str = "10.8.0.2",
        vpn_network:   str = "10.8.0.0/24",
        dns_servers:   list = None,
        cipher:        str = DEFAULT_CIPHER,
        full_tunnel:   bool = False,
    ):
        self.server_host  = server_host
        self.server_port  = server_port
        self.psk          = psk
        self.tun_name     = tun_name
        self.local_tun_ip = local_tun_ip
        self.vpn_network  = vpn_network
        self.dns_servers  = dns_servers or ["10.8.0.1", "1.1.1.1"]
        self.cipher       = cipher
        self.full_tunnel  = full_tunnel

        self._sock:       Optional[socket.socket] = None
        self._tun:        Optional[TUNInterface]  = None
        self._dns:        Optional[DNSProtection] = None
        self._session:    Optional[SessionKeys]   = None
        self._encap:      Optional[PacketEncapsulator] = None
        self._replay:     ReplayWindow = ReplayWindow()
        self._running:    bool = False
        self._audit:      AuditLogger = AuditLogger()
        self._server_addr = (server_host, server_port)

    # ── Public API ─────────────────────────────────────────────────────────────

    def connect(self) -> bool:
        """Open TUN, connect UDP socket, perform handshake. Returns True on success."""
        # Open TUN
        try:
            self._tun = TUNInterface(self.tun_name)
            self._tun.open()
            self._tun.configure(self.local_tun_ip, self.vpn_network)
            log.info("TUN interface ready: %s (%s)", self.tun_name, self.local_tun_ip)
        except OSError as e:
            log.error("TUN setup failed: %s", e)
            return False

        # UDP socket
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(HANDSHAKE_TIMEOUT)
        log.info("Connecting to %s:%d ...", self.server_host, self.server_port)

        # Handshake
        if not self._do_handshake():
            self._cleanup()
            return False

        # DNS protection
        if self.dns_servers:
            self._dns = DNSProtection(self.dns_servers)
            self._dns.apply()

        self._sock.settimeout(None)      # switch to blocking after handshake
        self._running = True
        log.info("VPN connected — session %s", self._session.session_id.hex())
        self._audit.connect(self._server_addr, self._session.session_id.hex())
        return True

    def run(self) -> None:
        """Block and forward traffic until disconnect."""
        if not self._running:
            raise RuntimeError("Call connect() first")

        # Start keepalive thread
        ka_thread = threading.Thread(target=self._keepalive_loop, daemon=True)
        ka_thread.start()

        try:
            self._run_tunnel()
        except KeyboardInterrupt:
            log.info("Interrupted — disconnecting")
        finally:
            self.disconnect()

    def disconnect(self) -> None:
        """Gracefully shut down the VPN connection."""
        if not self._running:
            return
        self._running = False

        # Send DISCONNECT packet
        if self._sock and self._encap and self._session:
            try:
                raw = self._encap.encapsulate(b"", PacketType.DISCONNECT)
                ciphertext = self._session.send_cipher.encrypt(raw)
                self._sock.sendto(ciphertext, self._server_addr)
                log.info("DISCONNECT sent to server")
            except Exception:
                pass

        if self._session:
            self._audit.disconnect(self._server_addr, self._session.session_id.hex())

        self._cleanup()
        log.info("VPN disconnected")

    # ── Handshake ──────────────────────────────────────────────────────────────

    def _do_handshake(self) -> bool:
        """Execute 4-message handshake. Returns True on success."""
        hs = ClientHandshake(self.psk, self.cipher)

        try:
            # 1. CLIENT_HELLO
            hello = hs.build_hello()
            self._sock.sendto(hello, self._server_addr)
            log.debug("Sent CLIENT_HELLO (%d bytes)", len(hello))

            # 2. SERVER_HELLO
            data, _ = self._sock.recvfrom(BUFFER_SIZE)
            if not hs.process_server_hello(data):
                self._audit.auth_fail(self._server_addr, "SERVER_HELLO verification failed")
                return False
            log.debug("SERVER_HELLO verified OK")

            # 3. CLIENT_FINISH
            finish = hs.build_finish()
            self._sock.sendto(finish, self._server_addr)
            log.debug("Sent CLIENT_FINISH (%d bytes)", len(finish))

            # 4. SERVER_ACK
            data, _ = self._sock.recvfrom(BUFFER_SIZE)
            if not hs.process_server_ack(data):
                self._audit.auth_fail(self._server_addr, "SERVER_ACK failed")
                return False

        except socket.timeout:
            log.error("Handshake timed out after %.1fs", HANDSHAKE_TIMEOUT)
            self._audit.auth_fail(self._server_addr, "timeout")
            return False
        except Exception as e:
            log.error("Handshake error: %s", e)
            self._audit.auth_fail(self._server_addr, str(e))
            return False

        self._session = hs.session
        self._encap   = PacketEncapsulator(self._session.session_id)
        self._audit.auth_ok(self._server_addr)
        return True

    # ── Tunnel Loop ────────────────────────────────────────────────────────────

    def _run_tunnel(self) -> None:
        """Select loop forwarding between TUN and UDP socket."""
        tun_fd   = self._tun.fileno()
        sock_fd  = self._sock.fileno()

        log.info("Tunnel active — forwarding traffic")

        while self._running:
            try:
                r, _, _ = select.select([tun_fd, sock_fd], [], [], 1.0)
            except (OSError, ValueError):
                break

            if tun_fd in r:
                self._tun_to_udp()

            if sock_fd in r:
                self._udp_to_tun()

            # Check re-key
            if self._session and self._session.needs_rekey():
                log.info("Session approaching re-key threshold — re-connecting")
                self._audit.rekey(self._server_addr, self._session.session_id.hex())
                break    # outer logic can reconnect if desired

    def _tun_to_udp(self) -> None:
        """Read a packet from TUN, encrypt it, send to server."""
        try:
            raw_ip = self._tun.read()
        except OSError as e:
            log.error("TUN read error: %s", e)
            return

        try:
            vpn_pkt = self._encap.encapsulate(raw_ip, PacketType.DATA)
            ciphertext = self._session.send_cipher.encrypt(vpn_pkt)
            self._sock.sendto(ciphertext, self._server_addr)
            self._session.last_tx = time.time()
        except Exception as e:
            log.error("Encrypt/send error: %s", e)
            self._audit.error(self._server_addr, str(e))

    def _udp_to_tun(self) -> None:
        """Receive a UDP datagram from server, decrypt it, inject into TUN."""
        try:
            ciphertext, addr = self._sock.recvfrom(BUFFER_SIZE)
        except OSError:
            return

        # Decrypt
        try:
            raw = self._session.recv_cipher.decrypt(ciphertext)
        except Exception as e:
            log.warning("Decrypt failed from %s: %s", addr, e)
            return

        # Parse VPN packet
        try:
            pkt = VPNPacket.from_bytes(raw)
        except ValueError as e:
            log.warning("Malformed packet from %s: %s", addr, e)
            return

        # Timestamp check
        if not validate_timestamp(pkt.timestamp):
            log.warning("Timestamp out of range from %s — possible replay", addr)
            self._audit.replay(addr, pkt.seq_num)
            return

        # Replay window check
        if not self._replay.check_and_update(pkt.seq_num):
            log.warning("Replay detected from %s seq=%d", addr, pkt.seq_num)
            self._audit.replay(addr, pkt.seq_num)
            return

        self._session.last_rx = time.time()

        if pkt.pkt_type == PacketType.DATA:
            try:
                self._tun.write(pkt.payload)
            except OSError as e:
                log.error("TUN write error: %s", e)

        elif pkt.pkt_type == PacketType.DISCONNECT:
            log.info("Server sent DISCONNECT")
            self._running = False

        elif pkt.pkt_type == PacketType.KEEPALIVE:
            log.debug("Keepalive from server")

    # ── Keepalive ──────────────────────────────────────────────────────────────

    def _keepalive_loop(self) -> None:
        while self._running:
            time.sleep(KEEPALIVE_INTERVAL)
            if self._running and self._session and self._encap:
                try:
                    pkt = self._encap.encapsulate(b"", PacketType.KEEPALIVE)
                    ct  = self._session.send_cipher.encrypt(pkt)
                    self._sock.sendto(ct, self._server_addr)
                    log.debug("Keepalive sent")
                except Exception as e:
                    log.warning("Keepalive failed: %s", e)

    # ── Cleanup ────────────────────────────────────────────────────────────────

    def _cleanup(self) -> None:
        if self._dns:
            self._dns.restore()
            self._dns = None
        if self._tun:
            self._tun.close()
            self._tun = None
        if self._sock:
            self._sock.close()
            self._sock = None


# ── CLI Entry Point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="VPN Client")
    parser.add_argument("--host",        default="127.0.0.1",   help="VPN server hostname/IP")
    parser.add_argument("--port",  "-p", type=int, default=5194, help="VPN server UDP port")
    parser.add_argument("--psk",         required=True,          help="Pre-shared key")
    parser.add_argument("--tun",         default="vpn0",         help="TUN interface name")
    parser.add_argument("--local-ip",    default="10.8.0.2",     help="Local TUN IP address")
    parser.add_argument("--network",     default="10.8.0.0/24",  help="VPN subnet")
    parser.add_argument("--dns",         default="10.8.0.1",     help="VPN DNS server")
    parser.add_argument("--full-tunnel",    action="store_true", help="Route all traffic through VPN")
    parser.add_argument("--block-dns-leak", action="store_true", help="Use iptables to block DNS on physical interface (requires root)")
    parser.add_argument("--cipher",         default=DEFAULT_CIPHER, help="Cipher suite")
    parser.add_argument("--debug",          action="store_true",    help="Debug logging")
    args = parser.parse_args()

    setup_logging(level=logging.DEBUG if args.debug else logging.INFO)

    client = VPNClient(
        server_host  = args.host,
        server_port  = args.port,
        psk          = args.psk,
        tun_name     = args.tun,
        local_tun_ip = args.local_ip,
        vpn_network  = args.network,
        dns_servers  = [args.dns],
        cipher       = args.cipher,
        full_tunnel  = args.full_tunnel,
    )

    if not client.connect():
        log.error("Failed to connect to VPN server")
        sys.exit(1)

    # Optional iptables DNS leak prevention (supplements resolv.conf change)
    fw = None
    if args.block_dns_leak:
        from security.firewall import ClientFirewall
        fw = ClientFirewall(
            tun_name=args.tun,
            server_ip=args.host,
            server_port=args.port,
        )
        fw.apply()

    try:
        client.run()
    finally:
        if fw:
            fw.remove()


if __name__ == "__main__":
    main()
