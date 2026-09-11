# tests/test_public_url.py
"""
Panel "Public URL" mode endpoints: mode switching persisted to .env,
validation, keys-optional degradation, and the grant proxy error mapping.
Reuses the in-process ASGI helpers + fixtures from tests/test_panel.py.
"""

import pytest

import cipher_station.panel.public_url as pu
import cipher_station.panel.service as service_mod
from cipher_station import ddns

from tests.test_panel import call_json, fake_ipfs, panel_app, panel_env  # noqa: F401


@pytest.fixture(autouse=True)
def clean_mode_env(monkeypatch):
    for key in pu.ENV_KEYS + ("CIPHER_PUBLIC_URL", "VERCEL_API_TOKEN",
                              "CLOUDFLARE_API_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    yield
    ddns.stop_refresher()


class TestGetPublicUrl:
    def test_default_is_quick(self, panel_app):
        status, obj = call_json(panel_app, "GET", "/admin/api/public-url")
        assert status == 200
        assert obj["mode"] == "quick"
        assert obj["effective_mode"] == "quick"
        assert obj["degraded"] is None
        assert "rotates" in obj["quick"]["note"]

    def test_domain_mode_without_token_is_degraded(self, panel_app, monkeypatch):
        monkeypatch.setenv("CIPHER_PUBLIC_URL_MODE", "domain")
        monkeypatch.setenv("CIPHER_DNS_DRIVER", "vercel")
        monkeypatch.setenv("CIPHER_DOMAIN_HOSTNAME", "charlie.example.com")
        monkeypatch.setenv("CIPHER_DOMAIN_ZONE", "example.com")
        status, obj = call_json(panel_app, "GET", "/admin/api/public-url")
        assert status == 200
        assert obj["mode"] == "domain"
        assert obj["effective_mode"] == "quick"   # graceful fallback
        assert "VERCEL_API_TOKEN" in obj["degraded"]

    def test_port_forward_guidance_present(self, panel_app):
        status, obj = call_json(panel_app, "GET", "/admin/api/public-url")
        pf = obj["domain"]["port_forward"]
        assert pf["port"] > 0
        assert "Forward WAN TCP" in pf["note"]


class TestSetPublicUrl:
    def test_domain_mode_persists_env_and_warns_without_token(
            self, panel_app, panel_env):
        status, obj = call_json(panel_app, "POST", "/admin/api/public-url", {
            "mode": "domain", "hostname": "charlie.example.com",
            "zone": "example.com", "driver": "vercel"})
        assert status == 200
        assert obj["restart_required"] is True
        assert any("VERCEL_API_TOKEN" in w for w in obj["warnings"])
        text = panel_env.read_text()
        assert "CIPHER_PUBLIC_URL_MODE=domain" in text
        assert "CIPHER_DOMAIN_HOSTNAME=charlie.example.com" in text
        assert "CIPHER_PUBLIC_URL=https://charlie.example.com" in text

    def test_domain_mode_with_valid_token_starts_refresher(
            self, panel_app, panel_env, monkeypatch):
        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "tok")

        class OkProvider:
            def verify_token(self):
                return True

        started = {}
        monkeypatch.setattr(pu, "get_provider", lambda d, t: OkProvider())
        monkeypatch.setattr(pu.ddns, "start_refresher",
                            lambda *a: started.update(args=a))
        status, obj = call_json(panel_app, "POST", "/admin/api/public-url", {
            "mode": "domain", "hostname": "charlie.example.com",
            "zone": "example.com", "driver": "cloudflare"})
        assert status == 200
        assert obj["warnings"] == []
        assert started["args"] == ("cloudflare", "tok", "example.com",
                                   "charlie.example.com")

    def test_bad_hostname_is_400(self, panel_app):
        status, _ = call_json(panel_app, "POST", "/admin/api/public-url", {
            "mode": "domain", "hostname": "not a hostname!",
            "zone": "example.com", "driver": "vercel"})
        assert status == 400

    def test_hostname_outside_zone_is_400(self, panel_app):
        status, _ = call_json(panel_app, "POST", "/admin/api/public-url", {
            "mode": "domain", "hostname": "charlie.other.net",
            "zone": "example.com", "driver": "vercel"})
        assert status == 400

    def test_unknown_mode_is_400(self, panel_app):
        status, _ = call_json(panel_app, "POST", "/admin/api/public-url",
                              {"mode": "carrier-pigeon"})
        assert status == 400

    def test_grant_mode_persists_and_derives_url(self, panel_app, panel_env):
        status, obj = call_json(panel_app, "POST", "/admin/api/public-url", {
            "mode": "grant", "registry_url": "https://registry.example.com",
            "grant_name": "charlie", "grant_zone": "cipherstation.io"})
        assert status == 200
        text = panel_env.read_text()
        assert "CIPHER_GRANT_REGISTRY_URL=https://registry.example.com" in text
        assert "CIPHER_PUBLIC_URL=https://charlie.cipherstation.io" in text

    def test_grant_mode_missing_fields_is_400(self, panel_app):
        status, _ = call_json(panel_app, "POST", "/admin/api/public-url",
                              {"mode": "grant"})
        assert status == 400

    def test_back_to_quick_clears_domain_settings(self, panel_app, panel_env):
        call_json(panel_app, "POST", "/admin/api/public-url", {
            "mode": "domain", "hostname": "charlie.example.com",
            "zone": "example.com", "driver": "vercel"})
        status, _ = call_json(panel_app, "POST", "/admin/api/public-url",
                              {"mode": "quick"})
        assert status == 200
        text = panel_env.read_text()
        assert "CIPHER_PUBLIC_URL_MODE=quick" in text
        assert "CIPHER_DOMAIN_HOSTNAME" not in text
        assert "CIPHER_PUBLIC_URL=" not in text


class TestGrantProxy:
    def test_grant_check_without_registry_url_is_400(self, panel_app):
        status, _ = call_json(panel_app, "POST",
                              "/admin/api/public-url/grant/check",
                              {"name": "charlie", "zone": "cipherstation.io"})
        assert status == 400

    def test_registry_error_maps_through(self, panel_app, monkeypatch):
        from cipher_station.registry.client import RegistryClientError

        class FakeClient:
            def check(self, name, zone):
                raise RegistryClientError(409, {"detail": "taken"})

        monkeypatch.setattr(pu, "_grant_client", lambda: FakeClient())
        status, obj = call_json(panel_app, "POST",
                                "/admin/api/public-url/grant/check",
                                {"name": "charlie", "zone": "cipherstation.io"})
        assert status == 409

    def test_unreachable_registry_maps_to_502(self, panel_app, monkeypatch):
        from cipher_station.registry.client import RegistryClientError

        class FakeClient:
            def check(self, name, zone):
                raise RegistryClientError(None, "registry unreachable: boom")

        monkeypatch.setattr(pu, "_grant_client", lambda: FakeClient())
        status, _ = call_json(panel_app, "POST",
                              "/admin/api/public-url/grant/check",
                              {"name": "charlie", "zone": "cipherstation.io"})
        assert status == 502
