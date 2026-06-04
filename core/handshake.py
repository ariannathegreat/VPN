"""
handshake.py — Secure Handshake Protocol (3-way ECDH + PSK)
Implements the VPN handshake state machine for both client and server.
Arianna — Week 4
"""

import os
import time
import struct
import logging
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, Tuple

from .crypto import ECDHKeyPair, derive_session_keys, CipherSuite, hash_psk, DEFAULT_CIPHER

log = logging.getLogger("vpn.handshake")

# ── Handshake Message Types ────────────────────────────────────────────────────

class HSMsgType(Enum):
    CLIENT_HELLO   = 0x10
    SERVER_HELLO   = 0x11
    CLIENT_FINISH  = 0x12
    SERVER_ACK     = 0x13
    ERROR          = 0xFF


# ── Message wire format helpers ────────────────────────────────────────────────
#
#  Each handshake message:
#   [msg_type: 1 byte] [nonce: 32 bytes] [pubkey: 32 bytes] [psk_proof: 32 bytes]
#   Optional FINISH/ACK also carry [session_id: 4 bytes]
#

HS_BASE_FORMAT = "!B32s32s32s"
HS_BASE_SIZE   = struct.calcsize(HS_BASE_FORMAT)   # 97 bytes
HS_FULL_FORMAT = HS_BASE_FORMAT + "4s"
HS_FULL_SIZE   = struct.calcsize(HS_FULL_FORMAT)   # 101 bytes

HANDSHAKE_TIMEOUT = 10.0  # seconds


def _pack_base(msg_type: HSMsgType, nonce: bytes, pubkey: bytes, psk_proof: bytes) -> bytes:
    return struct.pack(
        HS_BASE_FORMAT,
        msg_type.value,
        nonce[:32],
        pubkey[:32],
        psk_proof[:32],
    )


def _pack_full(msg_type: HSMsgType, nonce: bytes, pubkey: bytes, psk_proof: bytes, session_id: bytes) -> bytes:
    return struct.pack(
        HS_FULL_FORMAT,
        msg_type.value,
        nonce[:32],
        pubkey[:32],
        psk_proof[:32],
        (session_id + b"\x00" * 4)[:4],
    )


def _unpack_base(data: bytes) -> Tuple:
    if len(data) < HS_BASE_SIZE:
        raise ValueError(f"Handshake message too short: {len(data)}")
    return struct.unpack(HS_BASE_FORMAT, data[:HS_BASE_SIZE])


def _unpack_full(data: bytes) -> Tuple:
    if len(data) < HS_FULL_SIZE:
        raise ValueError(f"Handshake FINISH message too short: {len(data)}")
    return struct.unpack(HS_FULL_FORMAT, data[:HS_FULL_SIZE])


# ── Session Object ─────────────────────────────────────────────────────────────

@dataclass
class SessionKeys:
    """Holds the negotiated symmetric keys and metadata for one session."""
    session_id:    bytes
    send_cipher:   CipherSuite
    recv_cipher:   CipherSuite
    created_at:    float = field(default_factory=time.time)
    rekey_after:   float = 3600.0     # seconds before re-key is triggered
    cipher_name:   str   = DEFAULT_CIPHER

    def is_expired(self) -> bool:
        return (time.time() - self.created_at) >= self.rekey_after

    def needs_rekey(self, grace: float = 60.0) -> bool:
        return (time.time() - self.created_at) >= (self.rekey_after - grace)


# ── Client Handshake ───────────────────────────────────────────────────────────

class ClientHandshake:
    """
    Client-side handshake state machine.

      CLIENT_HELLO  →  (send to server)
      SERVER_HELLO  ←  (receive from server)
      CLIENT_FINISH →  (send to server)
      SERVER_ACK    ←  (receive from server)
      → SessionKeys
    """

    def __init__(self, psk: str, cipher: str = DEFAULT_CIPHER):
        self._psk_key    = hash_psk(psk)
        self._cipher     = cipher
        self._keypair    = ECDHKeyPair()
        self._nonce      = os.urandom(32)
        self._session_id = os.urandom(4)
        self._server_nonce: Optional[bytes] = None
        self._session_keys: Optional[SessionKeys] = None

    def build_hello(self) -> bytes:
        """Build CLIENT_HELLO message."""
        import hmac, hashlib
        psk_proof = hmac.new(self._psk_key, self._nonce + self._keypair.public_bytes, hashlib.sha256).digest()
        msg = _pack_base(
            HSMsgType.CLIENT_HELLO,
            self._nonce,
            self._keypair.public_bytes,
            psk_proof,
        )
        log.debug("CLIENT_HELLO built (nonce=%s)", self._nonce.hex()[:16])
        return msg

    def process_server_hello(self, data: bytes) -> bool:
        """Parse SERVER_HELLO, verify PSK proof, compute shared secret."""
        import hmac, hashlib
        try:
            msg_type_val, server_nonce, server_pubkey, server_psk_proof = _unpack_base(data)
        except (struct.error, ValueError) as e:
            log.error("Failed to unpack SERVER_HELLO: %s", e)
            return False

        if msg_type_val != HSMsgType.SERVER_HELLO.value:
            log.error("Expected SERVER_HELLO, got 0x%02x", msg_type_val)
            return False

        # Verify server's PSK proof
        expected_proof = hmac.new(
            self._psk_key,
            server_nonce + server_pubkey + self._nonce,   # binds to client nonce
            hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected_proof, server_psk_proof):
            log.error("SERVER_HELLO: PSK proof verification FAILED")
            return False

        self._server_nonce = server_nonce

        # Perform ECDH
        shared_secret = self._keypair.exchange(server_pubkey)
        salt = self._nonce + server_nonce
        keys = derive_session_keys(shared_secret, salt)

        self._session_keys = SessionKeys(
            session_id  = self._session_id,
            send_cipher = CipherSuite(keys["encrypt_key"], self._cipher),
            recv_cipher = CipherSuite(keys["decrypt_key"], self._cipher),
            cipher_name = self._cipher,
        )
        log.info("Session keys derived for session %s", self._session_id.hex())
        return True

    def build_finish(self) -> bytes:
        """Build CLIENT_FINISH message, confirming session establishment."""
        import hmac, hashlib
        if self._server_nonce is None:
            raise RuntimeError("SERVER_HELLO not yet processed")
        # Proof = HMAC(psk, "finish" || session_id || client_nonce || server_nonce)
        payload = b"finish" + self._session_id + self._nonce + self._server_nonce
        proof = hmac.new(self._psk_key, payload, hashlib.sha256).digest()
        msg = _pack_full(
            HSMsgType.CLIENT_FINISH,
            self._nonce,
            self._keypair.public_bytes,
            proof,
            self._session_id,
        )
        log.debug("CLIENT_FINISH built")
        return msg

    def process_server_ack(self, data: bytes) -> bool:
        """Verify SERVER_ACK and finalise the handshake."""
        if len(data) < 1:
            return False
        if data[0] != HSMsgType.SERVER_ACK.value:
            log.error("Expected SERVER_ACK, got 0x%02x", data[0])
            return False
        log.info("Handshake complete — session %s active", self._session_id.hex())
        return True

    @property
    def session(self) -> Optional[SessionKeys]:
        return self._session_keys


# ── Server Handshake ───────────────────────────────────────────────────────────

class ServerHandshake:
    """
    Server-side handshake state machine.

      CLIENT_HELLO  ←  (receive from client)
      SERVER_HELLO  →  (send to client)
      CLIENT_FINISH ←  (receive from client)
      SERVER_ACK    →  (send to client)
      → SessionKeys
    """

    def __init__(self, psk: str, cipher: str = DEFAULT_CIPHER):
        self._psk_key   = hash_psk(psk)
        self._cipher    = cipher
        self._keypair   = ECDHKeyPair()
        self._nonce     = os.urandom(32)
        self._client_nonce:  Optional[bytes] = None
        self._client_pubkey: Optional[bytes] = None
        self._session_id:    Optional[bytes] = None
        self._session_keys:  Optional[SessionKeys] = None

    def process_client_hello(self, data: bytes) -> bool:
        """Parse CLIENT_HELLO and verify PSK proof."""
        import hmac, hashlib
        try:
            msg_type_val, client_nonce, client_pubkey, client_psk_proof = _unpack_base(data)
        except (struct.error, ValueError) as e:
            log.error("Failed to unpack CLIENT_HELLO: %s", e)
            return False

        if msg_type_val != HSMsgType.CLIENT_HELLO.value:
            log.error("Expected CLIENT_HELLO, got 0x%02x", msg_type_val)
            return False

        expected_proof = hmac.new(
            self._psk_key,
            client_nonce + client_pubkey,
            hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected_proof, client_psk_proof):
            log.error("CLIENT_HELLO: PSK proof verification FAILED")
            return False

        self._client_nonce  = client_nonce
        self._client_pubkey = client_pubkey
        log.debug("CLIENT_HELLO verified OK")
        return True

    def build_server_hello(self) -> bytes:
        """Build SERVER_HELLO with server's public key and PSK proof."""
        import hmac, hashlib
        if self._client_nonce is None:
            raise RuntimeError("CLIENT_HELLO not yet processed")
        proof = hmac.new(
            self._psk_key,
            self._nonce + self._keypair.public_bytes + self._client_nonce,
            hashlib.sha256
        ).digest()
        msg = _pack_base(
            HSMsgType.SERVER_HELLO,
            self._nonce,
            self._keypair.public_bytes,
            proof,
        )
        log.debug("SERVER_HELLO built")
        return msg

    def process_client_finish(self, data: bytes) -> bool:
        """Verify CLIENT_FINISH, complete ECDH, derive session keys."""
        import hmac, hashlib
        try:
            msg_type_val, client_nonce, client_pubkey, finish_proof, session_id = _unpack_full(data)
        except (struct.error, ValueError) as e:
            log.error("Failed to unpack CLIENT_FINISH: %s", e)
            return False

        if msg_type_val != HSMsgType.CLIENT_FINISH.value:
            log.error("Expected CLIENT_FINISH, got 0x%02x", msg_type_val)
            return False

        # Re-verify PSK proof
        payload = b"finish" + session_id + client_nonce + self._nonce
        expected = hmac.new(self._psk_key, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, finish_proof):
            log.error("CLIENT_FINISH: proof verification FAILED")
            return False

        self._session_id = session_id

        # ECDH
        shared_secret = self._keypair.exchange(client_pubkey)
        salt = client_nonce + self._nonce
        keys = derive_session_keys(shared_secret, salt)

        # Note: server's encrypt key matches client's decrypt key (and vice versa)
        self._session_keys = SessionKeys(
            session_id  = session_id,
            send_cipher = CipherSuite(keys["decrypt_key"], self._cipher),
            recv_cipher = CipherSuite(keys["encrypt_key"], self._cipher),
            cipher_name = self._cipher,
        )
        log.info("Session keys derived — session %s", session_id.hex())
        return True

    def build_server_ack(self) -> bytes:
        """Build SERVER_ACK to complete handshake."""
        log.info("Sending SERVER_ACK — handshake complete")
        return bytes([HSMsgType.SERVER_ACK.value])

    @property
    def session(self) -> Optional[SessionKeys]:
        return self._session_keys
