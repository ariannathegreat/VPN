"""
server.py — VPN Server Application
Accepts multiple client connections, manages sessions, and forwards decrypted traffic.
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
from typing import Dict, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crypto    import DEFAULT_CIPHER
from core.handshake import ServerHandshake, SessionKeys
from core.packet    import PacketEncapsulator, PacketType, VPNPacket, validate_timestamp
from core.session   import Session, SessionManager, SessionState
from core.tun       import TUNInterface, DNSProtection
from utils.logger   import setup_logging, AuditLogger
from security.rate_limiter import HandshakeRateLimiter

log = logging.getLogger("vpn.server")

BUFFER_SIZE        = 65535
HANDSHAKE_TIMEOUT  = 10.0


# ── Pending Handshake Tracker ──────────────────────────────────────────────────

class PendingHandshake:
    """Tracks an in-progress handshake for a peer address."""
    def __init__(self, hs: ServerHandshake, peer: tuple):
        self.hs         = hs
        self.peer       = peer
        self.started_at = time.time()
        self.state      = "WAITING_FINISH"   # after SERVER_HELLO sent

    def is_expired(self) -> bool:
        return (time.time() - self.started_at) > HANDSHAKE_TIMEOUT


# ── VPN Server ─────────────────────────────────────────────────────────────────

class VPNServer:
    """
    Multi-client VPN server.

    For each peer:
      CLIENT_HELLO  → ServerHandshake.process_client_hello()
      SERVER_HELLO  ← send
      CLIENT_FINISH → ServerHandshake.process_client_finish()
      SERVER_ACK    ← send
      Session active

    Traffic is decrypted, stripped of the VPN header, and written to the TUN
    interface (sent to the internal network / internet).
    """

    def __init__(
        self,
        host:            str   = "0.0.0.0",
        port:            int   = 5194,
        psk:             str   = "",
        tun_name:        str   = "vpns0",
        server_tun_ip:   str   = "10.8.0.1",
        vpn_network:     str   = "10.8.0.0/24",
        dns_servers:     list  = None,
        cipher:          str   = DEFAULT_CIPHER,
    ):
        self.host           = host
        self.port           = port
        self.psk            = psk
        self.tun_name       = tun_name
        self.server_tun_ip  = server_tun_ip
        self.vpn_network    = vpn_network
        self.dns_servers    = dns_servers or ["1.1.1.1", "8.8.8.8"]
        self.cipher         = cipher

        self._sock:    Optional[socket.socket] = None
        self._tun:     Optional[TUNInterface]  = None
        self._running: bool = False
        self._audit:   AuditLogger = AuditLogger()

        # Rate limiter: prevent handshake floods and PSK brute-force
        self._rate_limiter = HandshakeRateLimiter(
            max_attempts=5, window_seconds=60.0, block_seconds=300.0
        )

        # Active sessions: session_id → Session
        self._session_mgr = SessionManager(
            on_session_expired = self._handle_session_expired,
            on_rekey_needed    = self._handle_rekey,
        )

        # Pending (mid-handshake) peers: peer_addr → PendingHandshake
        self._pending:     Dict[tuple, PendingHandshake] = {}
        self._pending_lock = threading.Lock()

        # Encapsulators per session
        self._encaps: Dict[bytes, PacketEncapsulator] = {}

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Open TUN, bind UDP socket, start main loop."""
        # TUN
        try:
            self._tun = TUNInterface(self.tun_name)
            self._tun.open()
            self._tun.configure(self.server_tun_ip, self.vpn_network)
            log.info("TUN interface %s ready (%s)", self.tun_name, self.server_tun_ip)
        except OSError as e:
            log.error("TUN setup failed: %s", e)
            return

        # UDP socket
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        log.info("VPN server listening on %s:%d", self.host, self.port)

        self._running = True
        try:
            self._run_loop()
        except KeyboardInterrupt:
            log.info("Server interrupted — shutting down")
        finally:
            self._shutdown()

    def _shutdown(self) -> None:
        self._running = False
        self._session_mgr.shutdown()
        if self._tun:
            self._tun.close()
        if self._sock:
            self._sock.close()
        log.info("Server shut down cleanly")

    # ── Main Loop ──────────────────────────────────────────────────────────────

    def _run_loop(self) -> None:
        tun_fd  = self._tun.fileno()
        sock_fd = self._sock.fileno()

        # Background thread: forward TUN → clients
        tun_fwd = threading.Thread(target=self._tun_forward_loop, daemon=True)
        tun_fwd.start()

        # Main thread: receive from clients
        while self._running:
            try:
                r, _, _ = select.select([sock_fd], [], [], 1.0)
            except (OSError, ValueError):
                break

            if sock_fd in r:
                try:
                    data, peer_addr = self._sock.recvfrom(BUFFER_SIZE)
                except OSError:
                    break
                self._handle_incoming(data, peer_addr)

            # Expire stale pending handshakes
            self._expire_pending()

    # ── Incoming Packet Dispatcher ─────────────────────────────────────────────

    def _handle_incoming(self, data: bytes, peer: tuple) -> None:
        """Dispatch a raw UDP datagram from a peer."""

        # Check if this peer has an active session
        session = self._session_mgr.get_by_peer(peer)
        if session and session.state in (SessionState.ACTIVE, SessionState.REKEYING):
            self._handle_data(data, peer, session)
            return

        # Check if mid-handshake
        with self._pending_lock:
            pending = self._pending.get(peer)

        if pending:
            self._handle_handshake_finish(data, peer, pending)
            return

        # New peer — must be CLIENT_HELLO
        self._handle_new_client(data, peer)

    # ── Handshake: new client ──────────────────────────────────────────────────

    def _handle_new_client(self, data: bytes, peer: tuple) -> None:
        # Rate-limit new handshake attempts per source IP
        if not self._rate_limiter.allow(peer[0]):
            self._audit.auth_fail(peer, "rate-limited")
            return   # silently drop — do not send an error response

        hs = ServerHandshake(self.psk, self.cipher)
        if not hs.process_client_hello(data):
            log.warning("Bad CLIENT_HELLO from %s:%d", *peer)
            self._audit.auth_fail(peer, "bad CLIENT_HELLO")
            return

        server_hello = hs.build_server_hello()
        self._sock.sendto(server_hello, peer)
        log.debug("SERVER_HELLO sent to %s:%d", *peer)

        with self._pending_lock:
            self._pending[peer] = PendingHandshake(hs, peer)

    def _handle_handshake_finish(self, data: bytes, peer: tuple, pending: PendingHandshake) -> None:
        hs = pending.hs
        if not hs.process_client_finish(data):
            log.warning("CLIENT_FINISH failed from %s:%d", *peer)
            self._audit.auth_fail(peer, "bad CLIENT_FINISH")
            with self._pending_lock:
                del self._pending[peer]
            return

        ack = hs.build_server_ack()
        self._sock.sendto(ack, peer)

        session_keys = hs.session
        encap = PacketEncapsulator(session_keys.session_id)

        session = Session(
            session_id = session_keys.session_id,
            peer_addr  = peer,
            keys       = session_keys,
        )
        self._session_mgr.add(session)
        self._encaps[session_keys.session_id] = encap

        with self._pending_lock:
            del self._pending[peer]

        log.info("Client authenticated: %s:%d session=%s", *peer, session_keys.session_id.hex())
        self._audit.auth_ok(peer)
        self._audit.connect(peer, session_keys.session_id.hex())

    # ── Data Handling ──────────────────────────────────────────────────────────

    def _handle_data(self, ciphertext: bytes, peer: tuple, session: Session) -> None:
        """Decrypt, validate, and handle a data packet from an active client."""

        try:
            raw = session.keys.recv_cipher.decrypt(ciphertext)
        except Exception as e:
            log.warning("Decrypt failed from %s:%d: %s", *peer, e)
            return

        try:
            pkt = VPNPacket.from_bytes(raw)
        except ValueError as e:
            log.warning("Malformed packet from %s:%d: %s", *peer, e)
            return

        # Timestamp validation
        if not validate_timestamp(pkt.timestamp):
            log.warning("Stale timestamp from %s:%d seq=%d", *peer, pkt.seq_num)
            self._audit.replay(peer, pkt.seq_num)
            return

        # Replay window
        if not session.replay_window.check_and_update(pkt.seq_num):
            log.warning("Replay detected from %s:%d seq=%d", *peer, pkt.seq_num)
            self._audit.replay(peer, pkt.seq_num)
            return

        session.touch_rx(len(ciphertext))

        if pkt.pkt_type == PacketType.DATA:
            if pkt.payload:
                try:
                    self._tun.write(pkt.payload)
                except OSError as e:
                    log.error("TUN write error: %s", e)

        elif pkt.pkt_type == PacketType.KEEPALIVE:
            log.debug("Keepalive from %s:%d", *peer)
            self._send_keepalive(session)

        elif pkt.pkt_type == PacketType.DISCONNECT:
            log.info("Client %s:%d disconnected gracefully", *peer)
            self._audit.disconnect(peer, session.session_id.hex())
            self._session_mgr.remove(session.session_id)

    def _send_keepalive(self, session: Session) -> None:
        encap = self._encaps.get(session.session_id)
        if encap:
            pkt = encap.encapsulate(b"", PacketType.KEEPALIVE)
            ct  = session.keys.send_cipher.encrypt(pkt)
            try:
                self._sock.sendto(ct, session.peer_addr)
                session.touch_tx(len(ct))
            except OSError:
                pass

    # ── TUN → Clients ──────────────────────────────────────────────────────────

    def _tun_forward_loop(self) -> None:
        """
        Read IP packets from TUN and forward them to the appropriate client.
        For a simple implementation, broadcast to all active sessions.
        Production code would use an IP routing table.
        """
        while self._running:
            try:
                raw_ip = self._tun.read()
            except OSError:
                break

            sessions = self._session_mgr.all_sessions()
            for session in sessions:
                if session.state != SessionState.ACTIVE:
                    continue
                encap = self._encaps.get(session.session_id)
                if not encap:
                    continue
                try:
                    pkt = encap.encapsulate(raw_ip, PacketType.DATA)
                    ct  = session.keys.send_cipher.encrypt(pkt)
                    self._sock.sendto(ct, session.peer_addr)
                    session.touch_tx(len(ct))
                except Exception as e:
                    log.error("Forward to %s:%d failed: %s", *session.peer_addr, e)

    # ── Session Callbacks ──────────────────────────────────────────────────────

    def _handle_session_expired(self, session: Session) -> None:
        log.info("Session %s expired", session.session_id.hex())
        self._audit.timeout(session.peer_addr, session.session_id.hex())
        self._encaps.pop(session.session_id, None)

    def _handle_rekey(self, session: Session) -> None:
        log.info("Re-key needed for session %s", session.session_id.hex())
        self._audit.rekey(session.peer_addr, session.session_id.hex())
        # Signal client by sending a REKEY packet
        encap = self._encaps.get(session.session_id)
        if encap:
            pkt = encap.encapsulate(b"", PacketType.REKEY)
            ct  = session.keys.send_cipher.encrypt(pkt)
            try:
                self._sock.sendto(ct, session.peer_addr)
            except OSError:
                pass

    # ── Pending Cleanup ────────────────────────────────────────────────────────

    def _expire_pending(self) -> None:
        with self._pending_lock:
            stale = [p for p, hs in self._pending.items() if hs.is_expired()]
            for p in stale:
                log.debug("Handshake timed out for %s:%d", *p)
                del self._pending[p]

    # ── Status ─────────────────────────────────────────────────────────────────

    def status(self) -> dict:
        sessions = self._session_mgr.all_sessions()
        return {
            "active_sessions": len(sessions),
            "sessions": [s.stats() for s in sessions],
        }


# ── CLI Entry Point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="VPN Server")
    parser.add_argument("--host",      default="0.0.0.0",    help="Bind address")
    parser.add_argument("--port","-p", type=int, default=5194, help="UDP port")
    parser.add_argument("--psk",       required=True,         help="Pre-shared key")
    parser.add_argument("--tun",       default="vpns0",       help="TUN interface name")
    parser.add_argument("--server-ip", default="10.8.0.1",    help="Server TUN IP")
    parser.add_argument("--network",   default="10.8.0.0/24", help="VPN subnet")
    parser.add_argument("--cipher",    default=DEFAULT_CIPHER, help="Cipher suite")
    parser.add_argument("--wan",       default=None,           help="WAN interface for NAT (e.g. eth0)")
    parser.add_argument("--debug",     action="store_true",   help="Debug logging")
    args = parser.parse_args()

    setup_logging(level=logging.DEBUG if args.debug else logging.INFO)

    # Optional NAT firewall setup
    firewall = None
    if args.wan:
        from security.firewall import ServerFirewall, detect_wan_interface
        wan = args.wan if args.wan != "auto" else detect_wan_interface()
        firewall = ServerFirewall(
            wan_iface=wan, vpn_network=args.network,
            vpn_port=args.port, tun_name=args.tun,
        )
        if not firewall.apply():
            log.error("Firewall setup failed — continuing without NAT")
            firewall = None

    try:
        server = VPNServer(
            host           = args.host,
            port           = args.port,
            psk            = args.psk,
            tun_name       = args.tun,
            server_tun_ip  = args.server_ip,
            vpn_network    = args.network,
            cipher         = args.cipher,
        )
        server.start()
    finally:
        if firewall:
            firewall.remove()


if __name__ == "__main__":
    main()
