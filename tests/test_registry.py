# tests/test_registry.py
"""
Subdomain registry tests.

``TestRegistryTCP`` boots a FastAPI app carrying the registry router with
uvicorn on an ephemeral 127.0.0.1 port (like tests/test_panel.py) and
drives it with httpx over a real socket: claim(201) / conflict(409) /
reserved(403) / invalid(400) / heartbeat / release / expiry / signature
rejection / rate limiting — all through the RegistryClient where signing
matters, so the client wire format is proven against the server verifier.

DNS is a recording in-memory provider; no external HTTP ever happens.
"""

import socket
import threading
import time

import httpx
import pytest
import uvicorn
from fastapi import FastAPI

import cipher_station.registry.config as rcfg
import cipher_station.registry.service as rsvc
import cipher_station.registry.store as rstore
from cipher_station import pqcrypto
from cipher_station.dns_providers import DnsRecord
from cipher_station.registry.client import RegistryClient, RegistryClientError
from cipher_station.registry.ratelimit import RateLimiter
from cipher_station.registry.router import rate_limiter, registry_router
from cipher_station.registry.signing import (
    SignatureError, sign_payload, verify_payload,
)


class MemoryDns:
    name = "memory"

    def __init__(self):
        self.records = {}

    def verify_token(self):
        return True

    def list_records(self, zone):
        return [DnsRecord(id=f"{n}/{t}", name=n, type=t, value=v)
                for (n, t), v in self.records.items()]

    def upsert_record(self, zone, name, record_type, value, ttl=300):
        self.records[(name, record_type)] = value
        return DnsRecord(id=f"{name}/{record_type}", name=name,
                         type=record_type, value=value)

    def delete_record(self, zone, name, record_type):
        return self.records.pop((name, record_type), None) is not None


@pytest.fixture
def keys():
    pub, sk = pqcrypto.generate_mldsa_keypair()
    return {"pub": pub.hex(), "sk": sk}


@pytest.fixture
def other_keys():
    pub, sk = pqcrypto.generate_mldsa_keypair()
    return {"pub": pub.hex(), "sk": sk}


@pytest.fixture
def registry_env(monkeypatch):
    """Zone config + in-memory DNS + fresh rate limiter."""
    dns = MemoryDns()
    rcfg.save_zones({
        "cipherstation.io": {"driver": "cloudflare",
                             "token_env": "TEST_CF_TOKEN",
                             "claim_mode": "public",
                             "reserved": ["charlie"]},
        "invite.zone": {"driver": "cloudflare",
                        "token_env": "TEST_CF_TOKEN",
                        "claim_mode": "invite"},
        "own.zone": {"driver": "cloudflare",
                     "token_env": "TEST_CF_TOKEN",
                     "claim_mode": "own"},
    })
    monkeypatch.setenv("TEST_CF_TOKEN", "test-token")
    monkeypatch.setattr(rsvc, "_dns_provider_for", lambda zone: dns)
    rate_limiter.reset()
    return dns


# ---------------------------------------------------------------------------
# Signing unit tests
# ---------------------------------------------------------------------------

class TestSigning:
    def test_roundtrip(self, keys):
        s = sign_payload(keys["sk"], "claim", "n", "z", "https://t", "CNAME")
        verify_payload(keys["pub"], "claim", "n", "z", "https://t", "CNAME",
                       s["ts"], s["nonce"], s["sig"])

    def test_wrong_key_rejected(self, keys, other_keys):
        s = sign_payload(keys["sk"], "claim", "n", "z", "t", "A")
        with pytest.raises(SignatureError):
            verify_payload(other_keys["pub"], "claim", "n", "z", "t", "A",
                           s["ts"], s["nonce"], s["sig"])

    def test_tampered_field_rejected(self, keys):
        s = sign_payload(keys["sk"], "claim", "n", "z", "t", "A")
        with pytest.raises(SignatureError):
            verify_payload(keys["pub"], "claim", "other-name", "z", "t", "A",
                           s["ts"], s["nonce"], s["sig"])

    def test_stale_timestamp_rejected(self, keys):
        s = sign_payload(keys["sk"], "claim", "n", "z", "t", "A",
                         ts=int(time.time()) - 10_000)
        with pytest.raises(SignatureError):
            verify_payload(keys["pub"], "claim", "n", "z", "t", "A",
                           s["ts"], s["nonce"], s["sig"])

    def test_replay_rejected(self, keys):
        seen = set()
        s = sign_payload(keys["sk"], "claim", "n", "z", "t", "A")
        kwargs = dict(nonce_seen=lambda p, n: (p, n) in seen,
                      remember_nonce=lambda p, n, ts: seen.add((p, n)))
        verify_payload(keys["pub"], "claim", "n", "z", "t", "A",
                       s["ts"], s["nonce"], s["sig"], **kwargs)
        with pytest.raises(SignatureError):
            verify_payload(keys["pub"], "claim", "n", "z", "t", "A",
                           s["ts"], s["nonce"], s["sig"], **kwargs)


# ---------------------------------------------------------------------------
# Service-level rules
# ---------------------------------------------------------------------------

class TestNameRules:
    @pytest.mark.parametrize("name", ["a", "abc", "a-b", "a1", "x" * 63])
    def test_valid(self, name):
        assert rsvc.validate_name(name) == name

    @pytest.mark.parametrize("name", ["", "-a", "a-", "a.b", "A_b", "x" * 64,
                                      "héllo", "a b"])
    def test_invalid(self, name):
        with pytest.raises(rsvc.RegistryError) as e:
            rsvc.validate_name(name)
        assert e.value.status == 400

    def test_uppercase_normalized(self):
        assert rsvc.validate_name("Alice") == "alice"


class TestServiceRules:
    def test_default_reserved_always_included(self, registry_env):
        reserved = rcfg.reserved_names("cipherstation.io")
        for n in ("www", "admin", "login", "bank", "ns1"):
            assert n in reserved
        assert "charlie" in reserved  # per-zone extra

    def test_own_mode_rejects_non_admin(self, registry_env, keys):
        with pytest.raises(rsvc.RegistryError) as e:
            rsvc.claim("alice", "own.zone", "1.2.3.4", "A", keys["pub"])
        assert e.value.status == 403

    def test_own_mode_allows_admin(self, registry_env, keys):
        out = rsvc.claim("alice", "own.zone", "1.2.3.4", "A", keys["pub"],
                         is_admin=True)
        assert out["claim"]["name"] == "alice"

    def test_invite_mode_requires_valid_code(self, registry_env, keys):
        with pytest.raises(rsvc.RegistryError):
            rsvc.claim("alice", "invite.zone", "1.2.3.4", "A", keys["pub"])
        code = rstore.create_invite("invite.zone")
        out = rsvc.claim("alice", "invite.zone", "1.2.3.4", "A", keys["pub"],
                         invite_code=code)
        assert out["claim"]["name"] == "alice"
        # single-use
        with pytest.raises(rsvc.RegistryError):
            rsvc.claim("bob", "invite.zone", "1.2.3.4", "A", keys["pub"],
                       invite_code=code)

    def test_expiry_reverts_name_and_deletes_dns(self, registry_env, keys):
        dns = registry_env
        rsvc.claim("stale", "cipherstation.io", "1.2.3.4", "A", keys["pub"])
        assert ("stale", "A") in dns.records
        # Age the claim past expiry.
        db = rstore.get_db()
        db.execute("UPDATE claims SET expires_at=? WHERE name='stale'",
                   (int(time.time()) - 1,))
        db.commit()
        out = rsvc.check_availability("stale", "cipherstation.io")
        assert out == {"available": True}
        assert ("stale", "A") not in dns.records
        assert rstore.get_claim("stale", "cipherstation.io") is None

    def test_admin_revoke(self, registry_env, keys):
        dns = registry_env
        rsvc.claim("gone", "cipherstation.io", "1.2.3.4", "A", keys["pub"])
        out = rsvc.admin_revoke("gone", "cipherstation.io")
        assert out["status"] == "revoked"
        assert ("gone", "A") not in dns.records
        with pytest.raises(rsvc.RegistryError) as e:
            rsvc.admin_revoke("gone", "cipherstation.io")
        assert e.value.status == 404

    def test_dns_failure_degrades_not_fatal(self, registry_env, monkeypatch, keys):
        monkeypatch.setattr(rsvc, "_dns_provider_for", lambda zone: None)
        out = rsvc.claim("nodns", "cipherstation.io", "1.2.3.4", "A", keys["pub"])
        assert out["dns_synced"] is False
        assert rstore.get_claim("nodns", "cipherstation.io") is not None

    def test_admin_set_reserved(self, registry_env):
        out = rsvc.admin_set_reserved("cipherstation.io", ["Newname", "other"])
        assert out == ["newname", "other"]
        assert "newname" in rcfg.reserved_names("cipherstation.io")
        # defaults still enforced
        assert "www" in rcfg.reserved_names("cipherstation.io")


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class TestRateLimiter:
    def test_burst_then_block(self):
        rl = RateLimiter(rate=0.0001, capacity=3)
        assert all(rl.allow("ip1") for _ in range(3))
        assert rl.allow("ip1") is False

    def test_keys_are_independent(self):
        rl = RateLimiter(rate=0.0001, capacity=1)
        assert rl.allow("a") is True
        assert rl.allow("a") is False
        assert rl.allow("b") is True

    def test_refill(self):
        rl = RateLimiter(rate=1000, capacity=1)
        assert rl.allow("a") is True
        time.sleep(0.01)
        assert rl.allow("a") is True


# ---------------------------------------------------------------------------
# Real TCP end-to-end
# ---------------------------------------------------------------------------

@pytest.fixture
def tcp_registry(registry_env):
    """Boot a FastAPI app with the registry router on an ephemeral port."""
    app = FastAPI()
    app.include_router(registry_router)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    config = uvicorn.Config(app, host="127.0.0.1", port=port,
                            proxy_headers=False, log_level="error",
                            lifespan="off")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]},
                              daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started:
        if time.time() > deadline:
            raise RuntimeError("registry test server did not start")
        time.sleep(0.02)
    # Plenty of budget so functional tests don't trip the limiter.
    rate_limiter.rate = 1000
    rate_limiter.capacity = 1000
    rate_limiter.reset()
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=10)
    sock.close()


def make_client(base, keys):
    c = RegistryClient(base, keys["sk"], keys["pub"])
    return c


class TestRegistryTCP:
    ZONE = "cipherstation.io"

    def test_check_available_and_invalid(self, tcp_registry):
        r = httpx.get(tcp_registry + "/registry/check",
                      params={"name": "alice", "zone": self.ZONE})
        assert r.status_code == 200
        assert r.json() == {"available": True}
        r = httpx.get(tcp_registry + "/registry/check",
                      params={"name": "-bad-", "zone": self.ZONE})
        assert r.status_code == 400
        r = httpx.get(tcp_registry + "/registry/check",
                      params={"name": "ok", "zone": "unknown.zone"})
        assert r.status_code == 400

    def test_check_reserved(self, tcp_registry):
        r = httpx.get(tcp_registry + "/registry/check",
                      params={"name": "admin", "zone": self.ZONE})
        assert r.json() == {"available": False, "reason": "reserved"}

    def test_claim_lifecycle(self, tcp_registry, registry_env, keys, other_keys):
        dns = registry_env
        client = make_client(tcp_registry, keys)

        # claim → 201, DNS record created
        out = client.claim("alice", self.ZONE, "203.0.113.5", "A")
        assert out["claim"]["status"] == "active"
        assert out["dns_synced"] is True
        assert dns.records[("alice", "A")] == "203.0.113.5"

        # conflict for a different key → 409 with taken_since
        other = make_client(tcp_registry, other_keys)
        with pytest.raises(RegistryClientError) as e:
            other.claim("alice", self.ZONE, "198.51.100.9", "A")
        assert e.value.status == 409
        assert "taken_since" in e.value.detail

        # heartbeat refreshes and can move the target
        before = rstore.get_claim("alice", self.ZONE)
        time.sleep(1.1)
        out = client.heartbeat("alice", self.ZONE, "203.0.113.99", "A")
        after = rstore.get_claim("alice", self.ZONE)
        assert after["last_heartbeat"] > before["last_heartbeat"]
        assert after["target"] == "203.0.113.99"
        assert dns.records[("alice", "A")] == "203.0.113.99"

        # heartbeat by a non-owner → 403
        with pytest.raises(RegistryClientError) as e:
            other.heartbeat("alice", self.ZONE)
        assert e.value.status == 403

        # release by a non-owner → 403; by the owner → row + DNS gone
        with pytest.raises(RegistryClientError) as e:
            other.release("alice", self.ZONE)
        assert e.value.status == 403
        out = client.release("alice", self.ZONE)
        assert out["status"] == "released"
        assert ("alice", "A") not in dns.records
        assert rstore.get_claim("alice", self.ZONE) is None

    def test_reserved_claim_is_403(self, tcp_registry, keys):
        client = make_client(tcp_registry, keys)
        with pytest.raises(RegistryClientError) as e:
            client.claim("login", self.ZONE, "203.0.113.5", "A")
        assert e.value.status == 403

    def test_invalid_name_is_400(self, tcp_registry, keys):
        client = make_client(tcp_registry, keys)
        with pytest.raises(RegistryClientError) as e:
            client.claim("bad name", self.ZONE, "203.0.113.5", "A")
        assert e.value.status == 400

    def test_invalid_record_type_is_400(self, tcp_registry, keys):
        client = make_client(tcp_registry, keys)
        with pytest.raises(RegistryClientError) as e:
            client.claim("alice", self.ZONE, "203.0.113.5", "MX")
        assert e.value.status == 400

    def test_bad_signature_is_401(self, tcp_registry, keys):
        payload = {
            "name": "sigless", "zone": self.ZONE, "target": "203.0.113.5",
            "record_type": "A", "pubkey": keys["pub"],
            "ts": str(int(time.time())), "nonce": "abcd" * 8,
            "sig": "aGVsbG8=",  # valid b64, invalid signature
        }
        r = httpx.post(tcp_registry + "/registry/claim", json=payload)
        assert r.status_code == 401
        assert rstore.get_claim("sigless", self.ZONE) is None

    def test_replayed_claim_is_401(self, tcp_registry, keys):
        s = sign_payload(keys["sk"], "claim", "replayme", self.ZONE,
                         "203.0.113.5", "A")
        payload = {"name": "replayme", "zone": self.ZONE,
                   "target": "203.0.113.5", "record_type": "A",
                   "pubkey": keys["pub"], **s}
        r1 = httpx.post(tcp_registry + "/registry/claim", json=payload)
        assert r1.status_code == 201
        r2 = httpx.post(tcp_registry + "/registry/claim", json=payload)
        assert r2.status_code == 401  # same nonce → replay

    def test_expired_claim_can_be_reclaimed(self, tcp_registry, registry_env,
                                            keys, other_keys):
        client = make_client(tcp_registry, keys)
        client.claim("cycle", self.ZONE, "203.0.113.5", "A")
        db = rstore.get_db()
        db.execute("UPDATE claims SET expires_at=? WHERE name='cycle'",
                   (int(time.time()) - 1,))
        db.commit()
        other = make_client(tcp_registry, other_keys)
        out = other.claim("cycle", self.ZONE, "198.51.100.7", "A")
        assert out["claim"]["owner_pubkey"] == other_keys["pub"]

    def test_rate_limited_is_429(self, tcp_registry):
        rate_limiter.rate = 0.0001
        rate_limiter.capacity = 3
        rate_limiter.reset()
        try:
            codes = [httpx.get(tcp_registry + "/registry/check",
                               params={"name": "x", "zone": self.ZONE}).status_code
                     for _ in range(6)]
            assert 429 in codes
            r = httpx.get(tcp_registry + "/registry/check",
                          params={"name": "x", "zone": self.ZONE})
            if r.status_code == 429:
                assert r.headers.get("retry-after") == "10"
        finally:
            rate_limiter.rate = 1000
            rate_limiter.capacity = 1000
            rate_limiter.reset()


# ---------------------------------------------------------------------------
# Registry gating on the main app + panel admin endpoints
# ---------------------------------------------------------------------------

class TestMainAppGating:
    def test_registry_absent_by_default(self):
        from cipher_station.main import app as main_app
        paths = [getattr(r, "path", "") for r in main_app.routes]
        assert not any(p.startswith("/registry") for p in paths)


class TestPanelRegistryAdmin:
    @pytest.fixture
    def panel_app(self, registry_env):
        from cipher_station.identity import get_identity
        from cipher_station.panel.app import create_panel_app
        get_identity()
        return create_panel_app()

    def call(self, app, method, path, obj=None):
        from tests.test_panel import call_json
        return call_json(app, method, path, obj)

    def test_overview_lists_zones_and_claims(self, panel_app, keys):
        rsvc.claim("alice", "cipherstation.io", "1.2.3.4", "A", keys["pub"])
        status, obj = self.call(panel_app, "GET", "/admin/api/registry")
        assert status == 200
        assert "cipherstation.io" in obj["zones"]
        assert obj["zones"]["cipherstation.io"]["claim_mode"] == "public"
        assert any(c["name"] == "alice" for c in obj["claims"])

    def test_revoke_via_panel(self, panel_app, keys):
        rsvc.claim("victim", "cipherstation.io", "1.2.3.4", "A", keys["pub"])
        status, obj = self.call(panel_app, "POST", "/admin/api/registry/revoke",
                                {"name": "victim", "zone": "cipherstation.io"})
        assert status == 200
        assert obj["status"] == "revoked"
        status, _ = self.call(panel_app, "POST", "/admin/api/registry/revoke",
                              {"name": "victim", "zone": "cipherstation.io"})
        assert status == 404

    def test_invite_issue_via_panel(self, panel_app):
        status, obj = self.call(panel_app, "POST", "/admin/api/registry/invite",
                                {"zone": "invite.zone"})
        assert status == 200
        assert obj["code"]
        status, _ = self.call(panel_app, "POST", "/admin/api/registry/invite",
                              {"zone": "nope.zone"})
        assert status == 400

    def test_reserved_edit_via_panel(self, panel_app):
        status, obj = self.call(panel_app, "POST", "/admin/api/registry/reserved",
                                {"zone": "cipherstation.io",
                                 "reserved": ["blocked"]})
        assert status == 200
        assert obj["reserved_extra"] == ["blocked"]

    def test_registry_admin_requires_token(self, panel_app):
        from tests.test_panel import call_panel
        status, _, _ = call_panel(panel_app, "GET", "/admin/api/registry",
                                  token=False)
        assert status == 401
