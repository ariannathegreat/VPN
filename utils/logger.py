"""
logger.py — Structured Logging & Audit Trail
Configures logging for the VPN application with rotating file output.
Arianna — Week 7
"""

import logging
import logging.handlers
import os
import json
import time
from typing import Optional

LOG_DIR          = os.path.join(os.path.dirname(__file__), "..", "logs")
LOG_FILE         = os.path.join(LOG_DIR, "vpn.log")
AUDIT_LOG_FILE   = os.path.join(LOG_DIR, "audit.log")
MAX_BYTES        = 5 * 1024 * 1024   # 5 MB per file
BACKUP_COUNT     = 5


def setup_logging(
    level: int     = logging.INFO,
    log_file:  str = LOG_FILE,
    to_stdout: bool = True,
) -> None:
    """
    Configure root logger with:
     - Rotating file handler (vpn.log)
     - Optional stdout handler
    """
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)-20s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(level)

    # Rotating file
    fh = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT
    )
    fh.setFormatter(fmt)
    root.addHandler(fh)

    # Stdout
    if to_stdout:
        ch = logging.StreamHandler()
        ch.setFormatter(fmt)
        root.addHandler(ch)


# ── Audit Logger ───────────────────────────────────────────────────────────────

class AuditLogger:
    """
    Writes structured JSON audit events for security-relevant actions.
    Each event line is a valid JSON object for easy log shipping / analysis.
    """

    EVENT_CONNECT    = "CONNECT"
    EVENT_DISCONNECT = "DISCONNECT"
    EVENT_AUTH_OK    = "AUTH_OK"
    EVENT_AUTH_FAIL  = "AUTH_FAIL"
    EVENT_REPLAY     = "REPLAY_DETECTED"
    EVENT_REKEY      = "REKEY"
    EVENT_TIMEOUT    = "SESSION_TIMEOUT"
    EVENT_ERROR      = "ERROR"
    EVENT_DNS_LEAK   = "DNS_LEAK_BLOCKED"

    def __init__(self, path: str = AUDIT_LOG_FILE):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._path = path
        self._log  = logging.getLogger("vpn.audit")

        # Dedicated audit file handler (not rotated — append only for forensics)
        fh = logging.FileHandler(path, mode="a")
        fh.setFormatter(logging.Formatter("%(message)s"))
        audit_logger = logging.getLogger("vpn.audit.file")
        audit_logger.propagate = False
        audit_logger.addHandler(fh)
        audit_logger.setLevel(logging.INFO)
        self._file_log = audit_logger

    def _write(self, event_type: str, peer: Optional[tuple] = None, **kwargs) -> None:
        record = {
            "ts":         time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event":      event_type,
            "peer_ip":    peer[0] if peer else None,
            "peer_port":  peer[1] if peer else None,
        }
        record.update(kwargs)
        line = json.dumps(record)
        self._file_log.info(line)
        self._log.info("[AUDIT] %s  peer=%s  %s",
                       event_type,
                       f"{peer[0]}:{peer[1]}" if peer else "—",
                       " ".join(f"{k}={v}" for k, v in kwargs.items()))

    def connect(self, peer: tuple, session_id: str)    -> None: self._write(self.EVENT_CONNECT,    peer, session_id=session_id)
    def disconnect(self, peer: tuple, session_id: str) -> None: self._write(self.EVENT_DISCONNECT, peer, session_id=session_id)
    def auth_ok(self, peer: tuple)                     -> None: self._write(self.EVENT_AUTH_OK,    peer)
    def auth_fail(self, peer: tuple, reason: str = "") -> None: self._write(self.EVENT_AUTH_FAIL,  peer, reason=reason)
    def replay(self, peer: tuple, seq: int)            -> None: self._write(self.EVENT_REPLAY,     peer, seq=seq)
    def rekey(self, peer: tuple, session_id: str)      -> None: self._write(self.EVENT_REKEY,      peer, session_id=session_id)
    def timeout(self, peer: tuple, session_id: str)    -> None: self._write(self.EVENT_TIMEOUT,    peer, session_id=session_id)
    def error(self, peer: Optional[tuple], msg: str)   -> None: self._write(self.EVENT_ERROR,      peer, msg=msg)
    def dns_leak_blocked(self, peer: tuple)            -> None: self._write(self.EVENT_DNS_LEAK,   peer)
