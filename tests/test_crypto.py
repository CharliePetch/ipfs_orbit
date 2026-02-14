# tests/test_crypto.py

import pytest
from nacl.public import PrivateKey, SealedBox
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random
from nacl.encoding import HexEncoder

from orbit_node.crypto import (
    generate_identity_keypair,
    encrypt_private_keys,
    decrypt_private_keys,
    envelope_for_recipient,
    open_envelope,
)


class TestKeypairGeneration:
    def test_generates_distinct_keys(self):
        sk1, pk1 = generate_identity_keypair()
        sk2, pk2 = generate_identity_keypair()
        assert pk1.encode() != pk2.encode()
        assert sk1.encode() != sk2.encode()

    def test_key_sizes(self):
        sk, pk = generate_identity_keypair()
        assert len(sk.encode()) == 32
        assert len(pk.encode()) == 32


class TestSecretBox:
    def test_round_trip(self):
        key = nacl_random(SecretBox.KEY_SIZE)
        box = SecretBox(key)
        plaintext = b"hello orbit"
        ct = box.encrypt(plaintext)
        assert box.decrypt(ct) == plaintext

    def test_wrong_key_fails(self):
        key1 = nacl_random(SecretBox.KEY_SIZE)
        key2 = nacl_random(SecretBox.KEY_SIZE)
        ct = SecretBox(key1).encrypt(b"secret data")
        with pytest.raises(Exception):
            SecretBox(key2).decrypt(ct)

    def test_different_ciphertexts(self):
        key = nacl_random(SecretBox.KEY_SIZE)
        box = SecretBox(key)
        ct1 = box.encrypt(b"same data")
        ct2 = box.encrypt(b"same data")
        assert ct1 != ct2  # nonce makes them different


class TestSealedBox:
    def test_round_trip(self, test_keypair):
        sk, pk_hex = test_keypair
        plaintext = b"sealed secret"
        encrypted = envelope_for_recipient(plaintext, pk_hex)
        decrypted = open_envelope(encrypted, sk)
        assert decrypted == plaintext

    def test_wrong_key_fails(self, test_keypair, second_keypair):
        _, pk_hex = test_keypair
        wrong_sk, _ = second_keypair
        encrypted = envelope_for_recipient(b"secret", pk_hex)
        with pytest.raises(Exception):
            open_envelope(encrypted, wrong_sk)


class TestArgon2iKeyEncryption:
    def test_round_trip(self):
        sk, _ = generate_identity_keypair()
        raw = sk.encode()
        password = "test-password-123"
        bundle = encrypt_private_keys(raw, password)
        decrypted = decrypt_private_keys(bundle, password)
        assert decrypted == raw

    def test_wrong_password_fails(self):
        sk, _ = generate_identity_keypair()
        raw = sk.encode()
        bundle = encrypt_private_keys(raw, "correct")
        with pytest.raises(Exception):
            decrypt_private_keys(bundle, "wrong")

    def test_bundle_format(self):
        sk, _ = generate_identity_keypair()
        bundle = encrypt_private_keys(sk.encode(), "pw")
        # salt (16) + nonce (24) + encrypted (32) + mac (16) = 88
        assert len(bundle) == 16 + 24 + 32 + 16
