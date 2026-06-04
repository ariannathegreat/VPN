"""
crypto.py — Encryption & Key Exchange Layer
Implements ECDH key exchange and authenticated encryption (AES-GCM / ChaCha20-Poly1305).
Arianna — Week 4
"""

import os
import struct
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

CIPHER_AES_GCM       = "AES-GCM"
CIPHER_CHACHA20      = "ChaCha20-Poly1305"
DEFAULT_CIPHER       = CIPHER_CHACHA20
NONCE_SIZE_AES       = 12   # bytes
NONCE_SIZE_CHACHA    = 12
KEY_SIZE             = 32   # 256-bit


# ── ECDH Key Exchange ──────────────────────────────────────────────────────────

class ECDHKeyPair:
    """X25519 ephemeral key pair for ECDH key exchange."""

    def __init__(self):
        self._private_key = X25519PrivateKey.generate()
        self._public_key  = self._private_key.public_key()

    @property
    def public_bytes(self) -> bytes:
        return self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def exchange(self, peer_public_bytes: bytes) -> bytes:
        """Perform ECDH and return raw shared secret (32 bytes)."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        peer_pub = X25519PublicKey.from_public_bytes(peer_public_bytes)
        return self._private_key.exchange(peer_pub)


def derive_session_keys(shared_secret: bytes, salt: bytes = b"") -> dict:
    """
    Derive symmetric keys from ECDH shared secret using HKDF-SHA256.
    Returns a dict with 'encrypt_key', 'decrypt_key' (each 32 bytes).
    The salt should be a nonce exchanged during the handshake.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE * 2,          # two 256-bit keys
        salt=salt if salt else None,
        info=b"vpn-session-keys-v1",
        backend=default_backend()
    )
    key_material = hkdf.derive(shared_secret)
    return {
        "encrypt_key": key_material[:KEY_SIZE],
        "decrypt_key": key_material[KEY_SIZE:],
    }


# ── Authenticated Encryption ───────────────────────────────────────────────────

class CipherSuite:
    """
    Wraps AEAD cipher (AES-GCM or ChaCha20-Poly1305).
    Each encrypt() call generates a fresh random nonce prepended to the ciphertext.
    Format: [nonce (12 bytes)] [ciphertext + tag]
    """

    def __init__(self, key: bytes, cipher: str = DEFAULT_CIPHER):
        if len(key) != KEY_SIZE:
            raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")
        self.cipher_name = cipher
        if cipher == CIPHER_AES_GCM:
            self._cipher = AESGCM(key)
            self._nonce_size = NONCE_SIZE_AES
        elif cipher == CIPHER_CHACHA20:
            self._cipher = ChaCha20Poly1305(key)
            self._nonce_size = NONCE_SIZE_CHACHA
        else:
            raise ValueError(f"Unknown cipher: {cipher}")

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Encrypt plaintext. Returns nonce + ciphertext."""
        nonce = os.urandom(self._nonce_size)
        ct    = self._cipher.encrypt(nonce, plaintext, aad or None)
        return nonce + ct

    def decrypt(self, data: bytes, aad: bytes = b"") -> bytes:
        """Decrypt. Expects nonce prepended to ciphertext."""
        if len(data) < self._nonce_size:
            raise ValueError("Data too short to contain nonce")
        nonce = data[:self._nonce_size]
        ct    = data[self._nonce_size:]
        return self._cipher.decrypt(nonce, ct, aad or None)


# ── HMAC Integrity ─────────────────────────────────────────────────────────────

def compute_hmac(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 for message integrity verification."""
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, tag: bytes) -> bool:
    """Constant-time HMAC verification."""
    expected = compute_hmac(key, data)
    return hmac.compare_digest(expected, tag)


# ── Pre-Shared Key Auth ────────────────────────────────────────────────────────

def hash_psk(psk: str) -> bytes:
    """Derive a fixed-size key from a pre-shared password."""
    return hashlib.sha256(psk.encode()).digest()
