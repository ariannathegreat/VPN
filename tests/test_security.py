"""
test_security.py — Security Tests & Known-Answer Vectors
Gage — Weeks 3, 6, 7

Run with: python -m pytest tests/test_security.py -v
"""

import os
import sys
import time
import struct
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crypto    import ECDHKeyPair, derive_session_keys, CipherSuite, CIPHER_AES_GCM, CIPHER_CHACHA20, KEY_SIZE
from core.packet    import VPNPacket, PacketType, PacketEncapsulator, ReplayWindow, validate_timestamp, HEADER_SIZE
from core.handshake import ClientHandshake, ServerHandshake
from security.rate_limiter import HandshakeRateLimiter


def full_handshake(psk="test-psk", cipher=CIPHER_CHACHA20):
    c, s = ClientHandshake(psk, cipher), ServerHandshake(psk, cipher)
    s.process_client_hello(c.build_hello())
    c.process_server_hello(s.build_server_hello())
    s.process_client_finish(c.build_finish())
    c.process_server_ack(s.build_server_ack())
    return c.session, s.session


# ── Known-Answer Test Vectors ──────────────────────────────────────────────────

class TestAESGCMKnownAnswer(unittest.TestCase):
    KEY   = bytes(32)
    NONCE = bytes(12)

    def _gcm(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(self.KEY)

    def test_output_length(self):
        ct = self._gcm().encrypt(self.NONCE, bytes(16), None)
        self.assertEqual(len(ct), 32)  # 16 plaintext + 16 tag

    def test_roundtrip(self):
        ct = self._gcm().encrypt(self.NONCE, b"hello", None)
        self.assertEqual(self._gcm().decrypt(self.NONCE, ct, None), b"hello")

    def test_aad_tamper_fails(self):
        ct = self._gcm().encrypt(self.NONCE, b"data", b"good-aad")
        with self.assertRaises(Exception):
            self._gcm().decrypt(self.NONCE, ct, b"bad-aad")

    def test_bit_flip_fails(self):
        ct = bytearray(self._gcm().encrypt(self.NONCE, b"data", None))
        ct[0] ^= 1
        with self.assertRaises(Exception):
            self._gcm().decrypt(self.NONCE, bytes(ct), None)


class TestChaCha20KnownAnswer(unittest.TestCase):
    # RFC 8439 §2.8.2 test vector
    KEY   = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    NONCE = bytes.fromhex("070000004041424344454647")
    PT    = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    AAD   = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")

    def _cc(self):
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        return ChaCha20Poly1305(self.KEY)

    def test_rfc_vector(self):
        ct = self._cc().encrypt(self.NONCE, self.PT, self.AAD)
        self.assertEqual(ct[:8], bytes.fromhex("d31a8d34648e60db"))

    def test_roundtrip(self):
        ct = self._cc().encrypt(self.NONCE, self.PT, self.AAD)
        self.assertEqual(self._cc().decrypt(self.NONCE, ct, self.AAD), self.PT)

    def test_truncated_tag_fails(self):
        ct = self._cc().encrypt(self.NONCE, self.PT, self.AAD)
        with self.assertRaises(Exception):
            self._cc().decrypt(self.NONCE, ct[:-1], self.AAD)


class TestHKDF(unittest.TestCase):
    IKM  = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    SALT = bytes.fromhex("000102030405060708090a0b0c")

    def test_deterministic(self):
        k1 = derive_session_keys(self.IKM, self.SALT)
        k2 = derive_session_keys(self.IKM, self.SALT)
        self.assertEqual(k1["encrypt_key"], k2["encrypt_key"])

    def test_different_salt_different_key(self):
        k1 = derive_session_keys(self.IKM, b"salt-a")
        k2 = derive_session_keys(self.IKM, b"salt-b")
        self.assertNotEqual(k1["encrypt_key"], k2["encrypt_key"])

    def test_key_length(self):
        k = derive_session_keys(self.IKM, self.SALT)
        self.assertEqual(len(k["encrypt_key"]), KEY_SIZE)
        self.assertEqual(len(k["decrypt_key"]), KEY_SIZE)


# ── MITM Resistance ────────────────────────────────────────────────────────────

class TestMITMResistance(unittest.TestCase):

    def test_forged_client_pubkey_rejected(self):
        c, s = ClientHandshake("psk"), ServerHandshake("psk")
        hello = bytearray(c.build_hello())
        hello[1+32 : 1+32+32] = os.urandom(32)  # replace pubkey
        self.assertFalse(s.process_client_hello(bytes(hello)))

    def test_forged_server_pubkey_rejected(self):
        c, s = ClientHandshake("psk"), ServerHandshake("psk")
        s.process_client_hello(c.build_hello())
        s_hello = bytearray(s.build_server_hello())
        s_hello[1+32 : 1+32+32] = os.urandom(32)
        self.assertFalse(c.process_server_hello(bytes(s_hello)))

    def test_wrong_psk_rejected(self):
        c, s = ClientHandshake("right"), ServerHandshake("wrong")
        self.assertFalse(s.process_client_hello(c.build_hello()))

    def test_session_ids_unique(self):
        ids = [full_handshake()[0].session_id for _ in range(10)]
        self.assertEqual(len(set(ids)), 10)


# ── Replay Attacks ─────────────────────────────────────────────────────────────

class TestReplayAttacks(unittest.TestCase):

    def test_exact_replay_blocked(self):
        rw = ReplayWindow(64)
        rw.check_and_update(42)
        self.assertFalse(rw.check_and_update(42))

    def test_all_64_slots(self):
        rw = ReplayWindow(64)
        for i in range(1, 65):
            self.assertTrue(rw.check_and_update(i))
        for i in range(1, 65):
            self.assertFalse(rw.check_and_update(i))

    def test_delayed_replay_past_window(self):
        rw = ReplayWindow(64)
        rw.check_and_update(1)
        for i in range(2, 70):
            rw.check_and_update(i)
        self.assertFalse(rw.check_and_update(1))

    def test_stale_timestamp_rejected(self):
        self.assertFalse(validate_timestamp(time.time() - 120))
        self.assertFalse(validate_timestamp(time.time() + 120))


# ── Fuzzing ────────────────────────────────────────────────────────────────────

class TestFuzzing(unittest.TestCase):

    def test_random_bytes_packet_parser(self):
        for _ in range(200):
            try:
                VPNPacket.from_bytes(os.urandom(64))
            except ValueError:
                pass
            except Exception as e:
                self.fail(f"Unexpected exception: {type(e).__name__}: {e}")

    def test_every_truncation_length(self):
        pkt  = VPNPacket(PacketType.DATA, 1, time.time(), b"\x01\x02\x03\x04", b"payload")
        data = pkt.to_bytes()
        for n in range(1, len(data)):
            with self.assertRaises(ValueError):
                VPNPacket.from_bytes(data[:n])

    def test_overflowed_payload_len_rejected(self):
        pkt = VPNPacket(PacketType.DATA, 1, time.time(), b"\x01\x02\x03\x04", b"x")
        raw = bytearray(pkt.to_bytes())
        raw[HEADER_SIZE-4 : HEADER_SIZE] = struct.pack("!I", 0xFFFFFFFF)
        with self.assertRaises(ValueError):
            VPNPacket.from_bytes(bytes(raw))

    def test_random_bytes_handshake(self):
        s = ServerHandshake("psk")
        c = ClientHandshake("psk")
        for _ in range(100):
            self.assertFalse(s.process_client_hello(os.urandom(64)))
            self.assertFalse(c.process_server_hello(os.urandom(97)))


# ── Downgrade Resistance ───────────────────────────────────────────────────────

class TestDowngrade(unittest.TestCase):

    def test_mismatched_ciphers_not_interoperable(self):
        c = ClientHandshake("psk", CIPHER_AES_GCM)
        s = ServerHandshake("psk", CIPHER_CHACHA20)
        s.process_client_hello(c.build_hello())
        c.process_server_hello(s.build_server_hello())
        s.process_client_finish(c.build_finish())
        c.process_server_ack(s.build_server_ack())
        ct = c.session.send_cipher.encrypt(b"test")
        with self.assertRaises(Exception):
            s.session.recv_cipher.decrypt(ct)


# ── Rate Limiter ───────────────────────────────────────────────────────────────

class TestRateLimiter(unittest.TestCase):

    def _limiter(self):
        return HandshakeRateLimiter(max_attempts=3, window_seconds=60, block_seconds=120)

    def test_allows_within_limit(self):
        lim = self._limiter()
        for _ in range(3):
            self.assertTrue(lim.allow("1.1.1.1"))

    def test_blocks_after_limit(self):
        lim = self._limiter()
        for _ in range(3):
            lim.allow("2.2.2.2")
        self.assertFalse(lim.allow("2.2.2.2"))

    def test_ips_are_independent(self):
        lim = self._limiter()
        for _ in range(3):
            lim.allow("3.3.3.3")
        self.assertFalse(lim.allow("3.3.3.3"))
        self.assertTrue(lim.allow("4.4.4.4"))

    def test_unblock_resets(self):
        lim = self._limiter()
        lim.allow("5.5.5.5")
        lim.allow("5.5.5.5")
        lim.allow("5.5.5.5")
        lim.allow("5.5.5.5")  # blocked
        lim.unblock("5.5.5.5")
        self.assertTrue(lim.allow("5.5.5.5"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
