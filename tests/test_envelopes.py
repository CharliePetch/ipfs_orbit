# tests/test_envelopes.py

import pytest
from nacl.public import PrivateKey
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random
from nacl.encoding import HexEncoder

from orbit_node.envelopes import (
    create_symmetric_key,
    encrypt_key_for_follower,
    open_envelope,
)
from orbit_node.posts import (
    _dedupe_followers_for_user_level_envelopes,
    _filter_followers_for_audience,
)


class TestEnvelopeCreateOpen:
    def test_round_trip(self, test_keypair):
        sk, pk_hex = test_keypair
        sym_key = create_symmetric_key()

        envelope_hex = encrypt_key_for_follower(sym_key, pk_hex)
        assert envelope_hex is not None

        recovered = open_envelope(sk, envelope_hex)
        assert recovered == sym_key

    def test_wrong_key_returns_none(self, test_keypair, second_keypair):
        _, pk_hex = test_keypair
        wrong_sk, _ = second_keypair

        sym_key = create_symmetric_key()
        envelope_hex = encrypt_key_for_follower(sym_key, pk_hex)

        result = open_envelope(wrong_sk, envelope_hex)
        assert result is None

    def test_invalid_pubkey_returns_none(self):
        sym_key = create_symmetric_key()
        assert encrypt_key_for_follower(sym_key, "tooshort") is None
        assert encrypt_key_for_follower(sym_key, "zz" * 32) is None

    def test_symmetric_key_size(self):
        key = create_symmetric_key()
        assert len(key) == SecretBox.KEY_SIZE


class TestUserLevelDedup:
    def _make_follower(self, uid, device_uid=None, public_key=None, allowed="Allowed"):
        if device_uid is None:
            device_uid = uid
        if public_key is None:
            pk_hex = PrivateKey.generate().public_key.encode(encoder=HexEncoder).decode()
        else:
            pk_hex = public_key
        return {
            "uid": uid,
            "device_uid": device_uid,
            "public_key": pk_hex,
            "allowed": allowed,
        }

    def test_single_device_passes_through(self):
        f = self._make_follower("alice")
        result = _dedupe_followers_for_user_level_envelopes([f])
        assert len(result) == 1
        assert result[0]["uid"] == "alice"

    def test_multiple_devices_same_uid_deduped(self):
        f1 = self._make_follower("bob", device_uid="bob")
        f2 = self._make_follower("bob", device_uid="bob-phone")
        result = _dedupe_followers_for_user_level_envelopes([f1, f2])
        assert len(result) == 1
        assert result[0]["uid"] == "bob"

    def test_root_device_preferred(self):
        f1 = self._make_follower("carol", device_uid="carol-phone", public_key="aa" * 32)
        f2 = self._make_follower("carol", device_uid="carol", public_key="bb" * 32)
        result = _dedupe_followers_for_user_level_envelopes([f1, f2])
        assert len(result) == 1
        assert result[0]["device_uid"] == "carol"  # root preferred

    def test_blocked_followers_excluded(self):
        f1 = self._make_follower("dave", allowed="Blocked")
        f2 = self._make_follower("eve", allowed="Allowed")
        result = _dedupe_followers_for_user_level_envelopes([f1, f2])
        assert len(result) == 1
        assert result[0]["uid"] == "eve"

    def test_multiple_uids_sorted(self):
        f1 = self._make_follower("charlie")
        f2 = self._make_follower("alice")
        f3 = self._make_follower("bob")
        result = _dedupe_followers_for_user_level_envelopes([f1, f2, f3])
        uids = [r["uid"] for r in result]
        assert uids == ["alice", "bob", "charlie"]


class TestAudienceFiltering:
    def _make_follower(self, uid):
        pk_hex = PrivateKey.generate().public_key.encode(encoder=HexEncoder).decode()
        return {
            "uid": uid,
            "device_uid": uid,
            "public_key": pk_hex,
            "allowed": "Allowed",
        }

    def test_self_mode_returns_empty(self):
        followers = [self._make_follower("alice"), self._make_follower("bob")]
        result = _filter_followers_for_audience(
            followers_user_level=followers,
            self_uid="me",
            audience_mode="self",
            audience_uids=None,
        )
        assert result == []

    def test_all_mode_returns_all(self):
        followers = [self._make_follower("alice"), self._make_follower("bob")]
        result = _filter_followers_for_audience(
            followers_user_level=followers,
            self_uid="me",
            audience_mode="all",
            audience_uids=None,
        )
        assert len(result) == 2

    def test_specific_mode_filters(self):
        alice = self._make_follower("alice")
        bob = self._make_follower("bob")
        carol = self._make_follower("carol")
        followers = [alice, bob, carol]

        result = _filter_followers_for_audience(
            followers_user_level=followers,
            self_uid="me",
            audience_mode="specific",
            audience_uids=["alice", "carol"],
        )
        uids = [r["uid"] for r in result]
        assert sorted(uids) == ["alice", "carol"]

    def test_specific_mode_excludes_self(self):
        me = self._make_follower("me")
        alice = self._make_follower("alice")
        followers = [me, alice]

        result = _filter_followers_for_audience(
            followers_user_level=followers,
            self_uid="me",
            audience_mode="specific",
            audience_uids=["me", "alice"],
        )
        uids = [r["uid"] for r in result]
        assert "me" not in uids
        assert "alice" in uids

    def test_specific_mode_unknown_uid_raises(self):
        alice = self._make_follower("alice")
        followers = [alice]

        with pytest.raises(ValueError, match="not Allowed followers"):
            _filter_followers_for_audience(
                followers_user_level=followers,
                self_uid="me",
                audience_mode="specific",
                audience_uids=["alice", "unknown-user"],
            )
