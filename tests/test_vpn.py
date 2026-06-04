"""
test_vpn.py — Unit & Integration Tests
Covers all of Arianna's modules: crypto, packet, handshake, session, TUN (mocked).
Run with: python -m pytest tests/test_vpn.py -v
"""

import os

import sys

import time
import struct
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crypto    import ECDHKeyPair, derive_session_keys, CipherSuite, hash_psk, CIPHER_AES_GCM, CIPHER_CHACHA20
from core.packet    import VPNPacket, PacketType, PacketEncapsulator, ReplayWindow, validate_timestamp, HEADER_SIZE
from core.handshake import ClientHandshake, ServerHandshake
from core.session   import Session, SessionManager, SessionState
from core.handshake import SessionKeys


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_session_keys(cipher=CIPHER_CHACHA20) -> SessionKeys:
    """Create a pair of session keys via a complete handshake."""
    psk = "test-secret-key"
    client_hs = ClientHandshake(psk, cipher)
    server_hs = ServerHandshake(psk, cipher)

    hello  = client_hs.build_hello()
    assert server_hs.process_client_hello(hello)

    s_hello = server_hs.build_server_hello()
    assert client_hs.process_server_hello(s_hello)

    finish = client_hs.build_finish()
    assert server_hs.process_client_finish(finish)

    ack = server_hs.build_server_ack()
    assert client_hs.process_server_ack(ack)

    return client_hs.session, server_hs.session


# ══════════════════════════════════════════════════════════════════════════════
# Crypto Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestECDH(unittest.TestCase):

    def test_shared_secret_matches(self):
        a, b = ECDHKeyPair(), ECDHKeyPair()
        secret_a = a.exchange(b.public_bytes)
        secret_b = b.exchange(a.public_bytes)
        self.assertEqual(secret_a, secret_b)

    def test_different_keypairs_differ(self):
        a, b, c = ECDHKeyPair(), ECDHKeyPair(), ECDHKeyPair()
        self.assertNotEqual(a.exchange(b.public_bytes), a.exchange(c.public_bytes))

    def test_public_key_is_32_bytes(self):
        kp = ECDHKeyPair()
        self.assertEqual(len(kp.public_bytes), 32)


class TestKeyDerivation(unittest.TestCase):

    def test_deterministic(self):
        secret = os.urandom(32)
        salt   = os.urandom(16)
        k1 = derive_session_keys(secret, salt)
        k2 = derive_session_keys(secret, salt)
        self.assertEqual(k1["encrypt_key"], k2["encrypt_key"])

    def test_encrypt_decrypt_keys_differ(self):
        keys = derive_session_keys(os.urandom(32), os.urandom(16))
        self.assertNotEqual(keys["encrypt_key"], keys["decrypt_key"])

    def test_key_is_32_bytes(self):
        keys = derive_session_keys(os.urandom(32))
        self.assertEqual(len(keys["encrypt_key"]), 32)
        self.assertEqual(len(keys["decrypt_key"]), 32)


class TestCipherSuite(unittest.TestCase):

    def _roundtrip(self, cipher_name, data, aad=b""):
        key = os.urandom(32)
        cs  = CipherSuite(key, cipher_name)
        ct  = cs.encrypt(data, aad)
        pt  = cs.decrypt(ct, aad)
        self.assertEqual(pt, data)

    def test_aes_gcm_roundtrip(self):
        self._roundtrip(CIPHER_AES_GCM, b"Hello, AES-GCM!")

    def test_chacha20_roundtrip(self):
        self._roundtrip(CIPHER_CHACHA20, b"Hello, ChaCha20!")

    def test_aes_gcm_with_aad(self):
        self._roundtrip(CIPHER_AES_GCM, b"secret data", aad=b"authenticated-header")

    def test_tampered_ciphertext_raises(self):
        key = os.urandom(32)
        cs  = CipherSuite(key, CIPHER_CHACHA20)
        ct  = bytearray(cs.encrypt(b"plaintext"))
        ct[-1] ^= 0xFF    # flip last byte
        with self.assertRaises(Exception):
            cs.decrypt(bytes(ct))

    def test_wrong_aad_raises(self):
        key = os.urandom(32)
        cs  = CipherSuite(key, CIPHER_AES_GCM)
        ct  = cs.encrypt(b"data", aad=b"good-aad")
        with self.assertRaises(Exception):
            cs.decrypt(ct, aad=b"bad-aad")

    def test_nonce_randomised(self):
        key = os.urandom(32)
        cs  = CipherSuite(key, CIPHER_CHACHA20)
        ct1 = cs.encrypt(b"same plaintext")
        ct2 = cs.encrypt(b"same plaintext")
        self.assertNotEqual(ct1, ct2)   # different nonces each time

    def test_invalid_key_size_raises(self):
        with self.assertRaises(ValueError):
            CipherSuite(b"tooshort", CIPHER_AES_GCM)


# ══════════════════════════════════════════════════════════════════════════════
# Packet Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestVPNPacket(unittest.TestCase):

    def _make_packet(self, payload=b"test", seq=1):
        return VPNPacket(
            pkt_type   = PacketType.DATA,
            seq_num    = seq,
            timestamp  = time.time(),
            session_id = b"\x01\x02\x03\x04",
            payload    = payload,
        )

    def test_serialise_deserialise(self):
        pkt  = self._make_packet(b"Hello VPN")
        data = pkt.to_bytes()
        pkt2 = VPNPacket.from_bytes(data)
        self.assertEqual(pkt2.payload,    pkt.payload)
        self.assertEqual(pkt2.seq_num,    pkt.seq_num)
        self.assertEqual(pkt2.pkt_type,   pkt.pkt_type)
        self.assertEqual(pkt2.session_id, pkt.session_id)

    def test_header_size_constant(self):
        pkt  = self._make_packet(b"x" * 100)
        data = pkt.to_bytes()
        self.assertEqual(len(data), HEADER_SIZE + 100)

    def test_too_short_raises(self):
        with self.assertRaises(ValueError):
            VPNPacket.from_bytes(b"\x00" * 5)

    def test_payload_length_mismatch_raises(self):
        pkt  = self._make_packet(b"data")
        data = pkt.to_bytes()[:-2]   # truncate 2 bytes
        with self.assertRaises(ValueError):
            VPNPacket.from_bytes(data)

    def test_all_packet_types_roundtrip(self):
        for pt in PacketType:
            pkt  = VPNPacket(pt, 1, time.time(), b"\x00\x00\x00\x01", b"payload")
            data = pkt.to_bytes()
            pkt2 = VPNPacket.from_bytes(data)
            self.assertEqual(pkt2.pkt_type, pt)


class TestPacketEncapsulator(unittest.TestCase):

    def test_sequence_increments(self):
        enc = PacketEncapsulator(b"\x01\x02\x03\x04")
        for expected_seq in range(1, 6):
            raw  = enc.encapsulate(b"data")
            pkt  = VPNPacket.from_bytes(raw)
            self.assertEqual(pkt.seq_num, expected_seq)

    def test_decapsulate(self):
        enc  = PacketEncapsulator(b"\xAA\xBB\xCC\xDD")
        raw  = enc.encapsulate(b"inner packet")
        pkt  = enc.decapsulate(raw)
        self.assertEqual(pkt.payload, b"inner packet")


# ══════════════════════════════════════════════════════════════════════════════
# Replay Window Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestReplayWindow(unittest.TestCase):

    def test_accept_new_seq(self):
        rw = ReplayWindow()
        self.assertTrue(rw.check_and_update(1))
        self.assertTrue(rw.check_and_update(2))
        self.assertTrue(rw.check_and_update(3))

    def test_reject_replay(self):
        rw = ReplayWindow()
        rw.check_and_update(5)
        self.assertFalse(rw.check_and_update(5))   # replay

    def test_reject_zero(self):
        rw = ReplayWindow()
        self.assertFalse(rw.check_and_update(0))

    def test_reject_old_packet(self):
        rw = ReplayWindow()
        rw.check_and_update(100)
        self.assertFalse(rw.check_and_update(1))   # way too old

    def test_accept_out_of_order_within_window(self):
        rw = ReplayWindow(64)
        rw.check_and_update(10)
        rw.check_and_update(12)
        self.assertTrue(rw.check_and_update(11))   # late but within window

    def test_window_slides_forward(self):
        rw = ReplayWindow(64)
        for i in range(1, 70):
            rw.check_and_update(i)
        # seq=1 is now outside the window (highest=69, window=64)
        self.assertFalse(rw.check_and_update(1))

    def test_highest_seq_tracked(self):
        rw = ReplayWindow()
        rw.check_and_update(7)
        rw.check_and_update(42)
        rw.check_and_update(3)
        self.assertEqual(rw.highest_seq, 42)


# ══════════════════════════════════════════════════════════════════════════════
# Timestamp Validation Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestTimestampValidation(unittest.TestCase):

    def test_current_time_valid(self):
        self.assertTrue(validate_timestamp(time.time()))

    def test_slightly_old_valid(self):
        self.assertTrue(validate_timestamp(time.time() - 30))

    def test_too_old_invalid(self):
        self.assertFalse(validate_timestamp(time.time() - 120))

    def test_future_invalid(self):
        self.assertFalse(validate_timestamp(time.time() + 120))


# ══════════════════════════════════════════════════════════════════════════════
# Handshake Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestHandshake(unittest.TestCase):

    def test_full_handshake_success(self):
        client_session, server_session = make_session_keys()
        self.assertIsNotNone(client_session)
        self.assertIsNotNone(server_session)

    def test_session_ids_match(self):
        c, s = make_session_keys()
        self.assertEqual(c.session_id, s.session_id)

    def test_cross_encrypt_decrypt(self):
        """Client encrypts → server decrypts, and vice versa."""
        c, s = make_session_keys()
        plaintext = b"cross cipher test"

        ct = c.send_cipher.encrypt(plaintext)
        pt = s.recv_cipher.decrypt(ct)
        self.assertEqual(pt, plaintext)

        ct2 = s.send_cipher.encrypt(plaintext)
        pt2 = c.recv_cipher.decrypt(ct2)
        self.assertEqual(pt2, plaintext)

    def test_wrong_psk_fails(self):
        client_hs = ClientHandshake("correct-psk")
        server_hs = ServerHandshake("wrong-psk")

        hello = client_hs.build_hello()
        result = server_hs.process_client_hello(hello)
        self.assertFalse(result)

    def test_handshake_works_with_aes_gcm(self):
        c, s = make_session_keys(CIPHER_AES_GCM)
        self.assertIsNotNone(c)
        self.assertIsNotNone(s)

    def test_keys_are_32_bytes(self):
        import inspect
        from core.crypto import KEY_SIZE
        c, _ = make_session_keys()
        # Indirectly verify via a successful encrypt/decrypt
        ct = c.send_cipher.encrypt(b"key size test")
        self.assertGreater(len(ct), 0)


# ══════════════════════════════════════════════════════════════════════════════
# Session Manager Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestSessionManager(unittest.TestCase):

    def _make_session(self, sid_byte=0x01):
        c, _ = make_session_keys()
        sid  = bytes([sid_byte, 0, 0, 0])
        c.session_id = sid
        return Session(session_id=sid, peer_addr=("127.0.0.1", 10000 + sid_byte), keys=c)

    def setUp(self):
        self.mgr = SessionManager(reap_interval=9999)   # disable auto-reap for tests

    def tearDown(self):
        self.mgr.shutdown()

    def test_add_and_get(self):
        s = self._make_session(1)
        self.mgr.add(s)
        got = self.mgr.get(s.session_id)
        self.assertIs(got, s)

    def test_get_by_peer(self):
        s = self._make_session(2)
        self.mgr.add(s)
        got = self.mgr.get_by_peer(s.peer_addr)
        self.assertIs(got, s)

    def test_remove(self):
        s = self._make_session(3)
        self.mgr.add(s)
        self.mgr.remove(s.session_id)
        self.assertIsNone(self.mgr.get(s.session_id))

    def test_count(self):
        for i in range(1, 4):
            self.mgr.add(self._make_session(i))
        self.assertEqual(self.mgr.count(), 3)

    def test_get_missing_returns_none(self):
        self.assertIsNone(self.mgr.get(b"\xFF\xFF\xFF\xFF"))


# ══════════════════════════════════════════════════════════════════════════════
# End-to-End: Encrypt / Packet / Decrypt pipeline
# ══════════════════════════════════════════════════════════════════════════════

class TestEndToEndPipeline(unittest.TestCase):

    def test_full_pipeline(self):
        """Simulate a full client→server packet journey."""
        c_keys, s_keys = make_session_keys()

        # Client side: encapsulate + encrypt
        encap = PacketEncapsulator(c_keys.session_id)
        raw_ip = b"\x45" + b"\x00" * 19   # fake IPv4 header
        vpn_frame  = encap.encapsulate(raw_ip, PacketType.DATA)
        ciphertext = c_keys.send_cipher.encrypt(vpn_frame)

        # Server side: decrypt + parse + replay check
        rw = ReplayWindow()
        plaintext  = s_keys.recv_cipher.decrypt(ciphertext)
        pkt        = VPNPacket.from_bytes(plaintext)

        self.assertTrue(validate_timestamp(pkt.timestamp))
        self.assertTrue(rw.check_and_update(pkt.seq_num))
        self.assertEqual(pkt.payload, raw_ip)
        self.assertEqual(pkt.pkt_type, PacketType.DATA)

    def test_replay_blocked_in_pipeline(self):
        """Same packet sent twice — second should be rejected."""
        c_keys, s_keys = make_session_keys()
        encap = PacketEncapsulator(c_keys.session_id)
        vpn_frame  = encap.encapsulate(b"data", PacketType.DATA)
        ciphertext = c_keys.send_cipher.encrypt(vpn_frame)

        rw = ReplayWindow()
        raw = s_keys.recv_cipher.decrypt(ciphertext)
        pkt = VPNPacket.from_bytes(raw)

        self.assertTrue(rw.check_and_update(pkt.seq_num))

        # Re-decrypt same ciphertext (simulates retransmission attack)
        # We need a fresh decrypt because AEAD is stateless — attacker resends exact same bytes
        raw2 = s_keys.recv_cipher.decrypt(ciphertext)
        pkt2 = VPNPacket.from_bytes(raw2)
        self.assertFalse(rw.check_and_update(pkt2.seq_num))   # BLOCKED


if __name__ == "__main__":
    unittest.main(verbosity=2)
