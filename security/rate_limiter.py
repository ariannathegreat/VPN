"""
rate_limiter.py — Handshake Rate Limiting
Gage — Week 7

Prevents brute-force PSK attacks and handshake-flood DoS.
Uses a token-bucket per source IP: each IP gets N handshake attempts
per time window. Persistent offenders are temporarily blocked.
"""

import time
import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional

log = logging.getLogger("vpn.ratelimit")

# Default policy — conservative for a VPN server
DEFAULT_MAX_ATTEMPTS   = 5       # attempts allowed per window
DEFAULT_WINDOW_SECONDS = 60.0    # rolling window
DEFAULT_BLOCK_SECONDS  = 300.0   # penalty box duration after exhausting attempts


@dataclass
class _IPState:
    attempts:     int   = 0
    window_start: float = field(default_factory=time.monotonic)
    blocked_until: float = 0.0

    def reset_window(self) -> None:
        self.attempts = 0
        self.window_start = time.monotonic()


class HandshakeRateLimiter:
    """
    Thread-safe per-IP rate limiter for VPN handshake attempts.

    Usage:
        limiter = HandshakeRateLimiter()
        if not limiter.allow(peer_ip):
            # drop the packet — don't even respond
            return
        # proceed with handshake
    """

    def __init__(
        self,
        max_attempts:    int   = DEFAULT_MAX_ATTEMPTS,
        window_seconds:  float = DEFAULT_WINDOW_SECONDS,
        block_seconds:   float = DEFAULT_BLOCK_SECONDS,
    ):
        self._max      = max_attempts
        self._window   = window_seconds
        self._block    = block_seconds
        self._state:   Dict[str, _IPState] = defaultdict(_IPState)
        self._lock     = threading.Lock()

        # Background cleanup so memory doesn't grow unbounded
        self._cleaner = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="ratelimit-cleanup",
        )
        self._cleaner.start()

    def allow(self, ip: str) -> bool:
        """
        Returns True if this IP is within its rate limit and may proceed.
        Returns False if the IP should be silently dropped.
        """
        now = time.monotonic()
        with self._lock:
            state = self._state[ip]

            # Still in penalty box?
            if state.blocked_until > now:
                remaining = round(state.blocked_until - now)
                log.warning(
                    "Rate-limited: %s blocked for %ds more", ip, remaining
                )
                return False

            # Roll the window if expired
            if (now - state.window_start) >= self._window:
                state.reset_window()

            # Increment and check
            state.attempts += 1
            if state.attempts > self._max:
                state.blocked_until = now + self._block
                log.warning(
                    "Rate limit exceeded: %s — blocked for %ds "
                    "(%d attempts in %.0fs window)",
                    ip, int(self._block), state.attempts, self._window,
                )
                return False

        return True

    def is_blocked(self, ip: str) -> bool:
        """Check whether an IP is currently in the penalty box."""
        with self._lock:
            state = self._state.get(ip)
            if state is None:
                return False
            return state.blocked_until > time.monotonic()

    def unblock(self, ip: str) -> None:
        """Manually clear the block on an IP and reset its attempt counter (admin use)."""
        with self._lock:
            if ip in self._state:
                self._state[ip].blocked_until = 0.0
                self._state[ip].reset_window()
        log.info("Manually unblocked: %s", ip)

    def stats(self) -> dict:
        """Return current rate-limit counters (for monitoring)."""
        now = time.monotonic()
        with self._lock:
            return {
                ip: {
                    "attempts":      s.attempts,
                    "blocked":       s.blocked_until > now,
                    "block_remaining": max(0.0, round(s.blocked_until - now, 1)),
                }
                for ip, s in self._state.items()
                if s.attempts > 0 or s.blocked_until > now
            }

    def _cleanup_loop(self) -> None:
        """Purge stale IP state every 10 minutes to avoid memory growth."""
        while True:
            time.sleep(600)
            cutoff = time.monotonic() - (self._window * 2)
            with self._lock:
                stale = [
                    ip for ip, s in self._state.items()
                    if s.window_start < cutoff and s.blocked_until < time.monotonic()
                ]
                for ip in stale:
                    del self._state[ip]
            if stale:
                log.debug("Rate limiter purged %d stale entries", len(stale))
