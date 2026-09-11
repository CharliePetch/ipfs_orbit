# tests/test_dns_providers.py
"""
DnsProvider drivers against mocked HTTP (no real Vercel/Cloudflare calls
ever leave the test) + the DDNS refresher logic.
"""

import json

import pytest
import requests

import cipher_station.dns_providers as dnsmod
from cipher_station import ddns
from cipher_station.dns_providers import (
    CloudflareDnsProvider, DnsAuthError, DnsProviderError, DnsRecord,
    VercelDnsProvider, get_provider, relative_label,
)


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text or json.dumps(self._payload)

    def json(self):
        return self._payload


class FakeHttp:
    """Records (method, url) calls; replies from a route table."""

    def __init__(self):
        self.routes = {}   # (method, url) -> FakeResponse | callable
        self.calls = []

    def add(self, method, url, response):
        self.routes[(method.upper(), url)] = response

    def request(self, method, url, **kwargs):
        self.calls.append((method.upper(), url, kwargs))
        handler = self.routes.get((method.upper(), url))
        if handler is None:
            return FakeResponse(404, {"error": "no route"})
        if callable(handler):
            return handler(**kwargs)
        return handler


@pytest.fixture
def http(monkeypatch):
    fake = FakeHttp()
    monkeypatch.setattr(dnsmod.requests, "request", fake.request)
    return fake


# ---------------------------------------------------------------------------
# Shared / factory
# ---------------------------------------------------------------------------

class TestFactory:
    def test_missing_token_raises_auth_error(self):
        with pytest.raises(DnsAuthError):
            get_provider("vercel", "")
        with pytest.raises(DnsAuthError):
            get_provider("cloudflare", None)

    def test_unknown_driver_raises_value_error(self):
        with pytest.raises(ValueError):
            get_provider("porkbun", "tok")

    def test_known_drivers_construct(self):
        assert isinstance(get_provider("vercel", "t"), VercelDnsProvider)
        assert isinstance(get_provider("cloudflare", "t"), CloudflareDnsProvider)

    def test_relative_label(self):
        assert relative_label("charlie.example.com", "example.com") == "charlie"
        assert relative_label("example.com", "example.com") == "@"
        assert relative_label("a.b.example.com", "example.com") == "a.b"
        with pytest.raises(ValueError):
            relative_label("other.net", "example.com")


# ---------------------------------------------------------------------------
# Vercel driver
# ---------------------------------------------------------------------------

VB = VercelDnsProvider.BASE


class TestVercel:
    def test_verify_token(self, http):
        http.add("GET", f"{VB}/v2/user", FakeResponse(200, {"user": {}}))
        assert VercelDnsProvider("tok").verify_token() is True

    def test_verify_token_rejected(self, http):
        http.add("GET", f"{VB}/v2/user", FakeResponse(403, {}))
        assert VercelDnsProvider("bad").verify_token() is False

    def test_list_records(self, http):
        http.add("GET", f"{VB}/v4/domains/example.com/records", FakeResponse(200, {
            "records": [{"id": "r1", "name": "charlie", "type": "A",
                         "value": "1.2.3.4"}]}))
        recs = VercelDnsProvider("tok").list_records("example.com")
        assert recs == [DnsRecord(id="r1", name="charlie", type="A", value="1.2.3.4")]

    def test_upsert_creates_when_absent(self, http):
        http.add("GET", f"{VB}/v4/domains/example.com/records",
                 FakeResponse(200, {"records": []}))
        http.add("POST", f"{VB}/v2/domains/example.com/records",
                 FakeResponse(200, {"uid": "new1"}))
        rec = VercelDnsProvider("tok").upsert_record(
            "example.com", "charlie", "A", "1.2.3.4")
        assert rec.id == "new1"
        posts = [c for c in http.calls if c[0] == "POST"]
        assert posts[0][2]["json"] == {"name": "charlie", "type": "A",
                                       "value": "1.2.3.4", "ttl": 300}

    def test_upsert_noop_when_value_matches(self, http):
        http.add("GET", f"{VB}/v4/domains/example.com/records", FakeResponse(200, {
            "records": [{"id": "r1", "name": "charlie", "type": "A",
                         "value": "1.2.3.4"}]}))
        rec = VercelDnsProvider("tok").upsert_record(
            "example.com", "charlie", "A", "1.2.3.4")
        assert rec.id == "r1"
        assert all(c[0] == "GET" for c in http.calls)

    def test_upsert_replaces_stale_record(self, http):
        http.add("GET", f"{VB}/v4/domains/example.com/records", FakeResponse(200, {
            "records": [{"id": "r1", "name": "charlie", "type": "A",
                         "value": "9.9.9.9"}]}))
        http.add("DELETE", f"{VB}/v2/domains/example.com/records/r1",
                 FakeResponse(200, {}))
        http.add("POST", f"{VB}/v2/domains/example.com/records",
                 FakeResponse(200, {"uid": "new2"}))
        rec = VercelDnsProvider("tok").upsert_record(
            "example.com", "charlie", "A", "1.2.3.4")
        assert rec.value == "1.2.3.4"
        assert ("DELETE", f"{VB}/v2/domains/example.com/records/r1") in [
            (c[0], c[1]) for c in http.calls]

    def test_delete_record(self, http):
        http.add("GET", f"{VB}/v4/domains/example.com/records", FakeResponse(200, {
            "records": [{"id": "r1", "name": "charlie", "type": "A",
                         "value": "1.2.3.4"}]}))
        http.add("DELETE", f"{VB}/v2/domains/example.com/records/r1",
                 FakeResponse(200, {}))
        assert VercelDnsProvider("tok").delete_record(
            "example.com", "charlie", "A") is True

    def test_delete_record_absent_is_false(self, http):
        http.add("GET", f"{VB}/v4/domains/example.com/records",
                 FakeResponse(200, {"records": []}))
        assert VercelDnsProvider("tok").delete_record(
            "example.com", "charlie", "A") is False

    def test_401_maps_to_auth_error(self, http):
        http.add("GET", f"{VB}/v4/domains/example.com/records", FakeResponse(401, {}))
        with pytest.raises(DnsAuthError):
            VercelDnsProvider("tok").list_records("example.com")

    def test_500_maps_to_provider_error(self, http):
        http.add("GET", f"{VB}/v4/domains/example.com/records", FakeResponse(500, {}))
        with pytest.raises(DnsProviderError):
            VercelDnsProvider("tok").list_records("example.com")

    def test_network_failure_maps_to_provider_error(self, monkeypatch):
        def boom(*a, **k):
            raise requests.ConnectionError("down")
        monkeypatch.setattr(dnsmod.requests, "request", boom)
        with pytest.raises(DnsProviderError):
            VercelDnsProvider("tok").list_records("example.com")


# ---------------------------------------------------------------------------
# Cloudflare driver
# ---------------------------------------------------------------------------

CB = CloudflareDnsProvider.BASE


def cf_zone(http):
    http.add("GET", f"{CB}/zones",
             FakeResponse(200, {"result": [{"id": "z1", "name": "example.com"}]}))


class TestCloudflare:
    def test_verify_token(self, http):
        http.add("GET", f"{CB}/user/tokens/verify",
                 FakeResponse(200, {"success": True}))
        assert CloudflareDnsProvider("tok").verify_token() is True

    def test_verify_token_rejected(self, http):
        http.add("GET", f"{CB}/user/tokens/verify", FakeResponse(401, {}))
        assert CloudflareDnsProvider("bad").verify_token() is False

    def test_list_records_normalizes_fqdn_to_label(self, http):
        cf_zone(http)
        http.add("GET", f"{CB}/zones/z1/dns_records", FakeResponse(200, {
            "result": [{"id": "c1", "name": "charlie.example.com", "type": "A",
                        "content": "1.2.3.4"}]}))
        recs = CloudflareDnsProvider("tok").list_records("example.com")
        assert recs == [DnsRecord(id="c1", name="charlie", type="A", value="1.2.3.4")]

    def test_unknown_zone_is_provider_error(self, http):
        http.add("GET", f"{CB}/zones", FakeResponse(200, {"result": []}))
        with pytest.raises(DnsProviderError):
            CloudflareDnsProvider("tok").list_records("nope.com")

    def test_upsert_creates(self, http):
        cf_zone(http)
        http.add("GET", f"{CB}/zones/z1/dns_records",
                 FakeResponse(200, {"result": []}))
        http.add("POST", f"{CB}/zones/z1/dns_records",
                 FakeResponse(200, {"result": {"id": "new1"}}))
        rec = CloudflareDnsProvider("tok").upsert_record(
            "example.com", "charlie", "AAAA", "::1")
        assert rec.id == "new1"
        post = [c for c in http.calls if c[0] == "POST"][0]
        assert post[2]["json"]["name"] == "charlie.example.com"
        assert post[2]["json"]["type"] == "AAAA"

    def test_upsert_updates_in_place(self, http):
        cf_zone(http)
        http.add("GET", f"{CB}/zones/z1/dns_records", FakeResponse(200, {
            "result": [{"id": "c1", "name": "charlie.example.com", "type": "A",
                        "content": "9.9.9.9"}]}))
        http.add("PUT", f"{CB}/zones/z1/dns_records/c1", FakeResponse(200, {
            "result": {"id": "c1"}}))
        rec = CloudflareDnsProvider("tok").upsert_record(
            "example.com", "charlie", "A", "1.2.3.4")
        assert rec.value == "1.2.3.4"
        assert any(c[0] == "PUT" for c in http.calls)

    def test_delete(self, http):
        cf_zone(http)
        http.add("GET", f"{CB}/zones/z1/dns_records", FakeResponse(200, {
            "result": [{"id": "c1", "name": "charlie.example.com", "type": "A",
                        "content": "1.2.3.4"}]}))
        http.add("DELETE", f"{CB}/zones/z1/dns_records/c1", FakeResponse(200, {}))
        assert CloudflareDnsProvider("tok").delete_record(
            "example.com", "charlie", "A") is True


# ---------------------------------------------------------------------------
# DDNS refresher
# ---------------------------------------------------------------------------

class MemoryProvider(dnsmod.DnsProvider):
    """In-memory DnsProvider for refresher logic tests."""
    name = "memory"

    def __init__(self):
        self.records: dict[tuple, str] = {}
        self.upserts = []
        self.deletes = []

    def verify_token(self):
        return True

    def list_records(self, zone):
        return [DnsRecord(id=f"{n}/{t}", name=n, type=t, value=v)
                for (n, t), v in self.records.items()]

    def upsert_record(self, zone, name, record_type, value, ttl=300):
        self.records[(name, record_type)] = value
        self.upserts.append((name, record_type, value))
        return DnsRecord(id=f"{name}/{record_type}", name=name,
                         type=record_type, value=value)

    def delete_record(self, zone, name, record_type):
        existed = (name, record_type) in self.records
        self.records.pop((name, record_type), None)
        if existed:
            self.deletes.append((name, record_type))
        return existed


class TestDdns:
    def make(self, monkeypatch, provider, ips):
        state = {"ips": ips}
        monkeypatch.setattr(ddns, "get_provider", lambda d, t: provider)
        r = ddns.DdnsRefresher("memory", "tok", "example.com",
                               "charlie.example.com",
                               ip_source=lambda: dict(state["ips"]))
        return r, state

    def test_first_run_creates_records(self, monkeypatch):
        prov = MemoryProvider()
        r, _ = self.make(monkeypatch, prov,
                         {"ipv4": "1.2.3.4", "ipv6": "2001:db8::1"})
        status = r.run_once()
        assert status["state"] == "ok"
        assert prov.records[("charlie", "A")] == "1.2.3.4"
        assert prov.records[("charlie", "AAAA")] == "2001:db8::1"

    def test_unchanged_ip_skips_dns_calls(self, monkeypatch):
        prov = MemoryProvider()
        r, _ = self.make(monkeypatch, prov, {"ipv4": "1.2.3.4", "ipv6": None})
        r.run_once()
        upserts_after_first = list(prov.upserts)
        r.run_once()
        assert prov.upserts == upserts_after_first  # no extra calls

    def test_ip_change_triggers_upsert(self, monkeypatch):
        prov = MemoryProvider()
        r, state = self.make(monkeypatch, prov, {"ipv4": "1.2.3.4", "ipv6": None})
        r.run_once()
        state["ips"] = {"ipv4": "5.6.7.8", "ipv6": None}
        status = r.run_once()
        assert status["state"] == "ok"
        assert prov.records[("charlie", "A")] == "5.6.7.8"

    def test_v4_only_deletes_stale_aaaa(self, monkeypatch):
        prov = MemoryProvider()
        prov.records[("charlie", "AAAA")] = "2001:db8::9"
        r, _ = self.make(monkeypatch, prov, {"ipv4": "1.2.3.4", "ipv6": None})
        r.run_once()
        assert ("charlie", "AAAA") not in prov.records
        assert ("charlie", "AAAA") in prov.deletes

    def test_no_public_ip_is_reported_not_fatal(self, monkeypatch):
        prov = MemoryProvider()
        r, _ = self.make(monkeypatch, prov, {"ipv4": None, "ipv6": None})
        status = r.run_once()
        assert status["state"] == "no_public_ip"

    def test_missing_token_degrades_to_auth_error(self, monkeypatch):
        def raise_auth(driver, token):
            raise DnsAuthError("VERCEL_API_TOKEN is not set")
        monkeypatch.setattr(ddns, "get_provider", raise_auth)
        r = ddns.DdnsRefresher("vercel", None, "example.com",
                               "charlie.example.com",
                               ip_source=lambda: {"ipv4": "1.2.3.4", "ipv6": None})
        status = r.run_once()
        assert status["state"] == "auth_error"
        assert "VERCEL_API_TOKEN" in status["error"]

    def test_sync_records_reports_changes(self, monkeypatch):
        prov = MemoryProvider()
        out = ddns.sync_records(prov, "example.com", "charlie.example.com",
                                {"ipv4": "1.2.3.4", "ipv6": None})
        assert out["a"] == "1.2.3.4"
        assert out["changed"] == ["A"]
