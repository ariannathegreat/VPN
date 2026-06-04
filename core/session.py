"""
session.py — Session State Machine & Re-Key Logic
Tracks per-client sessions on the server and manages lifecycle.
Arianna — Week 6
"""

import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Callable

from .handshake import SessionKeys
from .packet import ReplayWindow

log = logging.getLogger("vpn.session")

SESSION_TIMEOUT_IDLE  = 300.0    # seconds of no traffic before session expires
SESSION_TIMEOUT_HARD  = 3600.0   # absolute max session lifetime before forced re-key
KEEPALIVE_INTERVAL    = 20.0     # seconds between keepalive probes
REKEY_GRACE           = 60.0     # seconds before hard timeout to start re-key


# ── Session State ──────────────────────────────────────────────────────────────

class SessionState:
    HANDSHAKING  = "HANDSHAKING"
    ACTIVE       = "ACTIVE"
    REKEYING     = "REKEYING"
    DISCONNECTED = "DISCONNECTED"


@dataclass
class Session:
    """Represents a single authenticated VPN session."""
    session_id:    bytes
    peer_addr:     tuple             # (ip, port)
    keys:          SessionKeys
    replay_window: ReplayWindow = field(default_factory=ReplayWindow)
    state:         str          = SessionState.ACTIVE
    created_at:    float        = field(default_factory=time.time)
    last_rx:       float        = field(default_factory=time.time)
    last_tx:       float        = field(default_factory=time.time)
    bytes_rx:      int          = 0
    bytes_tx:      int          = 0

    def touch_rx(self, nbytes: int = 0) -> None:
        self.last_rx = time.time()
        self.bytes_rx += nbytes

    def touch_tx(self, nbytes: int = 0) -> None:
        self.last_tx = time.time()
        self.bytes_tx += nbytes

    def is_idle(self) -> bool:
        return (time.time() - max(self.last_rx, self.last_tx)) >= SESSION_TIMEOUT_IDLE

    def is_hard_expired(self) -> bool:
        return (time.time() - self.created_at) >= SESSION_TIMEOUT_HARD

    def needs_rekey(self) -> bool:
        age = time.time() - self.created_at
        return age >= (SESSION_TIMEOUT_HARD - REKEY_GRACE)

    def stats(self) -> dict:
        return {
            "session_id": self.session_id.hex(),
            "peer":       f"{self.peer_addr[0]}:{self.peer_addr[1]}",
            "state":      self.state,
            "age_s":      round(time.time() - self.created_at, 1),
            "idle_s":     round(time.time() - max(self.last_rx, self.last_tx), 1),
            "bytes_rx":   self.bytes_rx,
            "bytes_tx":   self.bytes_tx,
        }


# ── Session Manager ────────────────────────────────────────────────────────────

class SessionManager:
    """
    Thread-safe store for active VPN sessions.
    Runs a background reaper thread to clean up idle/expired sessions.
    """

    def __init__(
        self,
        on_session_expired:  Optional[Callable[[Session], None]] = None,
        on_rekey_needed:     Optional[Callable[[Session], None]] = None,
        reap_interval:       float = 30.0,
    ):
        self._sessions:    Dict[bytes, Session] = {}
        self._lock         = threading.RLock()
        self._on_expired   = on_session_expired
        self._on_rekey     = on_rekey_needed

        # Background reaper
        self._reaper = threading.Thread(
            target=self._reap_loop,
            args=(reap_interval,),
            daemon=True,
            name="session-reaper",
        )
        self._running = True
        self._reaper.start()
        log.info("SessionManager started")

    # ── CRUD ───────────────────────────────────────────────────────────────────

    def add(self, session: Session) -> None:
        with self._lock:
            self._sessions[session.session_id] = session
        log.info(
            "Session %s added — peer %s:%d",
            session.session_id.hex(), *session.peer_addr,
        )

    def get(self, session_id: bytes) -> Optional[Session]:
        with self._lock:
            return self._sessions.get(session_id)

    def get_by_peer(self, addr: tuple) -> Optional[Session]:
        with self._lock:
            for s in self._sessions.values():
                if s.peer_addr == addr:
                    return s
        return None

    def remove(self, session_id: bytes) -> Optional[Session]:
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session:
            log.info("Session %s removed", session_id.hex())
        return session

    def all_sessions(self) -> list:
        with self._lock:
            return list(self._sessions.values())

    def count(self) -> int:
        with self._lock:
            return len(self._sessions)

    # ── Reaper ─────────────────────────────────────────────────────────────────

    def _reap_loop(self, interval: float) -> None:
        while self._running:
            time.sleep(interval)
            self._reap_once()

    def _reap_once(self) -> None:
        to_remove = []
        to_rekey  = []

        with self._lock:
            for sid, session in self._sessions.items():
                if session.state == SessionState.DISCONNECTED:
                    to_remove.append(sid)
                elif session.is_idle():
                    log.info("Session %s idle timeout", sid.hex())
                    to_remove.append(sid)
                elif session.is_hard_expired():
                    log.info("Session %s hard timeout", sid.hex())
                    to_remove.append(sid)
                elif session.needs_rekey() and session.state == SessionState.ACTIVE:
                    to_rekey.append(session)

        for sid in to_remove:
            session = self.remove(sid)
            if session and self._on_expired:
                try:
                    self._on_expired(session)
                except Exception as e:
                    log.error("on_expired callback error: %s", e)

        for session in to_rekey:
            with self._lock:
                if session.session_id in self._sessions:
                    session.state = SessionState.REKEYING
            if self._on_rekey:
                try:
                    self._on_rekey(session)
                except Exception as e:
                    log.error("on_rekey callback error: %s", e)

    def shutdown(self) -> None:
        self._running = False
        log.info("SessionManager stopped")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.shutdown()
