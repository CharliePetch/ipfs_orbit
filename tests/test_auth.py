# tests/test_auth.py

import hashlib
import hmac as hmac_mod
import time

import pytest
from nacl.public import PrivateKey
from nacl.encoding import HexEncoder
from nacl import bindings

from orbit_node.auth import _derive_auth_key, _canonical


class TestCanonicalString:
    def test_basic_format(self):
        result = _canonical("POST", "/upload", "uid1", "dev1", "12345", "nonce1", "abcd")
        expected = b"POST\n/upload\nuid1\ndev1\n12345\nnonce1\nabcd"
        assert result == expected

    def test_method_uppercased(self):
        result = _canonical("get", "/path", "u", "d", "0", "n", "h")
        assert result.startswith(b"GET\n")

    def test_all_fields_present(self):
        result = _canonical("DELETE", "/api/v1", "user", "device", "999", "abc", "sha")
        parts = result.decode().split("\n")
        assert len(parts) == 7
        assert parts[0] == "DELETE"
        assert parts[1] == "/api/v1"
        assert parts[2] == "user"
        assert parts[3] == "device"
        assert parts[4] == "999"
        assert parts[5] == "abc"
        assert parts[6] == "sha"


class TestAuthKeyDerivation:
    def test_deterministic(self):
        sk_a = PrivateKey.generate()
        sk_b = PrivateKey.generate()

        key1 = _derive_auth_key(sk_a.encode(), sk_b.public_key.encode())
        key2 = _derive_auth_key(sk_a.encode(), sk_b.public_key.encode())
        assert key1 == key2

    def test_key_length(self):
        sk_a = PrivateKey.generate()
        sk_b = PrivateKey.generate()
        key = _derive_auth_key(sk_a.encode(), sk_b.public_key.encode())
        assert len(key) == 32

    def test_different_pairs_different_keys(self):
        sk_a = PrivateKey.generate()
        sk_b = PrivateKey.generate()
        sk_c = PrivateKey.generate()

        key_ab = _derive_auth_key(sk_a.encode(), sk_b.public_key.encode())
        key_ac = _derive_auth_key(sk_a.encode(), sk_c.public_key.encode())
        assert key_ab != key_ac


class TestHMACSignVerify:
    def test_sign_and_verify(self):
        sk_station = PrivateKey.generate()
        sk_device = PrivateKey.generate()

        auth_key = _derive_auth_key(sk_station.encode(), sk_device.public_key.encode())

        msg = _canonical("POST", "/upload", "uid1", "dev1", "12345", "nonce1", "bodysha")
        sig = hmac_mod.new(auth_key, msg, hashlib.sha256).hexdigest()

        expected = hmac_mod.new(auth_key, msg, hashlib.sha256).hexdigest()
        assert hmac_mod.compare_digest(sig, expected)

    def test_wrong_key_fails(self):
        sk_station = PrivateKey.generate()
        sk_device = PrivateKey.generate()
        sk_wrong = PrivateKey.generate()

        auth_key = _derive_auth_key(sk_station.encode(), sk_device.public_key.encode())
        wrong_key = _derive_auth_key(sk_station.encode(), sk_wrong.public_key.encode())

        msg = _canonical("POST", "/upload", "uid1", "dev1", "12345", "nonce1", "bodysha")
        sig = hmac_mod.new(auth_key, msg, hashlib.sha256).hexdigest()
        wrong_sig = hmac_mod.new(wrong_key, msg, hashlib.sha256).hexdigest()

        assert not hmac_mod.compare_digest(sig, wrong_sig)

    def test_tampered_message_fails(self):
        sk_station = PrivateKey.generate()
        sk_device = PrivateKey.generate()

        auth_key = _derive_auth_key(sk_station.encode(), sk_device.public_key.encode())

        msg_original = _canonical("POST", "/upload", "uid1", "dev1", "12345", "nonce1", "bodysha")
        msg_tampered = _canonical("POST", "/upload", "uid1", "dev1", "12345", "nonce1", "TAMPERED")

        sig = hmac_mod.new(auth_key, msg_original, hashlib.sha256).hexdigest()
        tampered_sig = hmac_mod.new(auth_key, msg_tampered, hashlib.sha256).hexdigest()

        assert not hmac_mod.compare_digest(sig, tampered_sig)


class TestNonceReplay:
    def test_nonce_seen_and_remember(self):
        from orbit_node.auth import _nonce_seen, _remember_nonce

        uid, dev, nonce = "user1", "device1", "unique-nonce-123"
        ts = int(time.time())

        assert not _nonce_seen(uid, dev, nonce)

        _remember_nonce(uid, dev, nonce, ts)

        assert _nonce_seen(uid, dev, nonce)

    def test_different_nonce_not_seen(self):
        from orbit_node.auth import _nonce_seen, _remember_nonce

        uid, dev = "user1", "device1"
        ts = int(time.time())

        _remember_nonce(uid, dev, "nonce-A", ts)

        assert not _nonce_seen(uid, dev, "nonce-B")
