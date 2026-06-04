"""
packet.py — VPN Packet Encapsulation & Replay Protection
Handles wrapping/unwrapping of inner IP packets inside the VPN protocol.
Includes sliding-window replay attack protection.
Arianna — Weeks 5 & 6
"""

import struct
import time
from dataclasses import dataclass, field
from typing import Optional
from enum import IntEnum

# ── Packet Types ───────────────────────────────────────────────────────────────

class PacketType(IntEnum):
    DATA       = 0x01   # Encrypted IP data
    HANDSHAKE  = 0x02   # Key exchange
    KEEPALIVE  = 0x03   # Heartbeat
    DISCONNECT = 0x04   # Graceful close
    REKEY      = 0x05   # Re-key request


# ── Wire Format ────────────────────────────────────────────────────────────────
#
#  0         1         2         3
#  0123456789012345678901234567890123456789...
#  [VERSION:1][TYPE:1][SEQ:8][TIMESTAMP:8][SESSION_ID:4][PAYLOAD_LEN:4][PAYLOAD...]
#
#  Total fixed header: 26 bytes
#

HEADER_FORMAT  = "!BBQd4sI"   # big-endian: uint8, uint8, uint64, double, 4s, uint32
HEADER_SIZE    = struct.calcsize(HEADER_FORMAT)   # == 26 bytes
PROTOCOL_VER   = 1

# Replay window: accept sequence numbers within this range of the highest seen
REPLAY_WINDOW_SIZE = 64


@dataclass
class VPNPacket:
    """Structured representation of a VPN protocol packet."""
    pkt_type:   PacketType
    seq_num:    int
    timestamp:  float
    session_id: bytes
    payload:    bytes
    version:    int = PROTOCOL_VER

    # ── Serialise ──────────────────────────────────────────────────────────────

    def to_bytes(self) -> bytes:
        """Serialise to wire format (header + payload)."""
        sid = (self.session_id + b"\x00" * 4)[:4]   # pad/truncate to 4 bytes
        header = struct.pack(
            HEADER_FORMAT,
            self.version,
            int(self.pkt_type),
            self.seq_num,
            self.timestamp,
            sid,
            len(self.payload),
        )
        return header + self.payload

    # ── Deserialise ────────────────────────────────────────────────────────────

    @classmethod
    def from_bytes(cls, data: bytes) -> "VPNPacket":
        """Parse wire bytes into a VPNPacket. Raises ValueError on bad input."""
        if len(data) < HEADER_SIZE:
            raise ValueError(f"Packet too short: {len(data)} < {HEADER_SIZE}")
        version, ptype, seq, ts, sid, plen = struct.unpack(
            HEADER_FORMAT, data[:HEADER_SIZE]
        )
        if version != PROTOCOL_VER:
            raise ValueError(f"Unsupported protocol version: {version}")
        payload = data[HEADER_SIZE:]
        if len(payload) != plen:
            raise ValueError(
                f"Payload length mismatch: header says {plen}, got {len(payload)}"
            )
        return cls(
            pkt_type   = PacketType(ptype),
            seq_num    = seq,
            timestamp  = ts,
            session_id = sid,
            payload    = payload,
            version    = version,
        )


# ── Encapsulation / Decapsulation ──────────────────────────────────────────────

class PacketEncapsulator:
    """
    Wraps raw IP frames into VPN packets and unwraps them on the other side.
    Maintains a per-session sequence counter.
    """

    def __init__(self, session_id: bytes):
        self._session_id = (session_id + b"\x00" * 4)[:4]
        self._seq = 0

    def encapsulate(self, raw_ip: bytes, pkt_type: PacketType = PacketType.DATA) -> bytes:
        """Wrap a raw IP frame in a VPN packet and return bytes."""
        self._seq += 1
        pkt = VPNPacket(
            pkt_type   = pkt_type,
            seq_num    = self._seq,
            timestamp  = time.time(),
            session_id = self._session_id,
            payload    = raw_ip,
        )
        return pkt.to_bytes()

    def decapsulate(self, data: bytes) -> VPNPacket:
        """Parse raw bytes and return the inner VPNPacket."""
        return VPNPacket.from_bytes(data)


# ── Sliding-Window Replay Protection ──────────────────────────────────────────

class ReplayWindow:
    """
    Sliding-window replay attack protection (RFC 6479 / WireGuard-style).

    Maintains a bitmask of received sequence numbers within the window.
    Packets outside the window or already seen are rejected.
    """

    def __init__(self, window_size: int = REPLAY_WINDOW_SIZE):
        if window_size < 1 or window_size > 1024:
            raise ValueError("Window size must be 1–1024")
        self._size    = window_size
        self._highest = 0
        self._bitmap  = 0          # each bit = 1 means "seen"

    def check_and_update(self, seq: int) -> bool:
        """
        Returns True and marks the seq as seen if it is acceptable.
        Returns False (and does NOT update state) if the packet is a replay.
        """
        if seq <= 0:
            return False

        if seq > self._highest:
            # New highest — shift window forward
            shift = seq - self._highest
            if shift >= self._size:
                self._bitmap = 1      # everything old is outside the window
            else:
                self._bitmap = ((self._bitmap << shift) | 1) & ((1 << self._size) - 1)
            self._highest = seq
            return True

        diff = self._highest - seq
        if diff >= self._size:
            # Too old — outside the window
            return False

        bit_pos = diff
        if (self._bitmap >> bit_pos) & 1:
            # Already seen — replay!
            return False

        # Within window and not yet seen — accept
        self._bitmap |= (1 << bit_pos)
        return True

    @property
    def highest_seq(self) -> int:
        return self._highest


# ── Timestamp Validation ───────────────────────────────────────────────────────

MAX_CLOCK_SKEW_SECONDS = 60   # reject packets timestamped more than 60 s off

def validate_timestamp(pkt_timestamp: float, max_skew: float = MAX_CLOCK_SKEW_SECONDS) -> bool:
    """Reject packets with timestamps too far from now (replay / replay-delayed attack)."""
    return abs(time.time() - pkt_timestamp) <= max_skew
