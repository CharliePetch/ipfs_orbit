# tests/test_panel.py
"""
Admin panel tests.

The panel now runs as its OWN app (cipher_station.panel.app.create_panel_app)
on a dedicated 127.0.0.1 listener, with a per-boot bearer token on every
/admin/api route. These tests exercise the REAL paths:

- ``TestRealTCP`` boots the panel app with uvicorn on an ephemeral
  127.0.0.1 port (proxy_headers=False, exactly like production) and drives
  it with httpx over a real socket: no-token/wrong-token/X-Forwarded-For
  → 401, correct token → 200, oversized upload → 413, PINs absent from
  status, CSP/nosniff on downloads, evil-Origin state change → 403.
- The in-process ASGI tests cover the same guards plus config/drive logic
  (IPFS is never contacted — an in-memory fake CID store stands in for it,
  and the autouse temp_cipher_station_dir fixture keeps all state in a temp
  dir).
- ``TestMainAppHasNoPanel`` proves the public :8443-style app exposes no
  /admin routes at all.
"""

import hashlib
import json
import secrets
import socket
import threading
import time

import httpx
import pytest
import uvicorn

import cipher_station.config as cfg
import cipher_station.ipfs_client as ipfs_mod
import cipher_station.manifest as manifest_mod
import cipher_station.posts as posts_mod
import cipher_station.panel.drive as drive_mod
import cipher_station.panel.guard as guard_mod
import cipher_station.panel.service as service_mod
from cipher_station.identity import get_identity
from cipher_station.panel.app import create_panel_app
from cipher_station.panel.guard import ensure_panel_token, is_loopback_address


# ---------------------------------------------------------------------------
# In-process ASGI caller with body support
# ---------------------------------------------------------------------------

def call_app(app, method, path, *, headers=None, body=b"",
             client=("127.0.0.1", 50000), query=b""):
    import asyncio

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "query_string": query,
        "headers": [(k.lower().encode(), str(v).encode()) for k, v in (headers or {}).items()],
        "client": client,
        "server": ("testserver", 80),
    }

    messages = []

    async def run():
        sent = False

        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        async def send(message):
            messages.append(message)

        await app(scope, receive, send)

    asyncio.run(run())

    start = next(m for m in messages if m["type"] == "http.response.start")
    out_body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    out_headers = {k.decode().lower(): v.decode() for k, v in start["headers"]}
    return start["status"], out_headers, out_body


def auth_headers(extra=None):
    h = {"authorization": f"Bearer {ensure_panel_token()}"}
    h.update(extra or {})
    return h


def call_panel(app, method, path, *, headers=None, body=b"",
               client=("127.0.0.1", 50000), query=b"", token=True):
    headers = dict(headers or {})
    if token:
        headers.setdefault("authorization", f"Bearer {ensure_panel_token()}")
    return call_app(app, method, path, headers=headers, body=body,
                    client=client, query=query)


def call_json(app, method, path, obj=None, *, client=("127.0.0.1", 50000), token=True):
    body = json.dumps(obj).encode() if obj is not None else b""
    headers = {"content-type": "application/json", "content-length": str(len(body))}
    status, h, raw = call_panel(app, method, path, headers=headers, body=body,
                                client=client, token=token)
    try:
        return status, json.loads(raw)
    except Exception:
        return status, raw


def multipart_body(fields, files):
    """fields: {name: value}; files: {name: (filename, bytes)}."""
    boundary = "----panel" + secrets.token_hex(8)
    parts = []
    for name, value in fields.items():
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
        )
    for name, (filename, data) in files.items():
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; '
            f'filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode()
            + data + b"\r\n"
        )
    parts.append(f"--{boundary}--\r\n".encode())
    body = b"".join(parts)
    return body, f"multipart/form-data; boundary={boundary}"


# ---------------------------------------------------------------------------
# Fake IPFS
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_ipfs(monkeypatch):
    """In-memory CID store patched into every module that imported the fns."""
    store: dict[str, bytes] = {}

    def fake_add(data: bytes) -> str:
        cid = "Qm" + hashlib.sha256(data).hexdigest()[:44]
        store[cid] = data
        return cid

    def fake_get(cid: str) -> bytes:
        if cid not in store:
            raise ipfs_mod.IPFSError(f"unknown CID {cid}")
        return store[cid]

    for mod in (ipfs_mod, manifest_mod, posts_mod):
        monkeypatch.setattr(mod, "ipfs_add_bytes", fake_add, raising=False)
    for mod in (ipfs_mod, posts_mod, drive_mod):
        monkeypatch.setattr(mod, "ipfs_get_bytes", fake_get, raising=False)
    monkeypatch.setattr(manifest_mod, "ipfs_unpin", lambda cid: True, raising=False)
    monkeypatch.setattr(manifest_mod, "ipfs_repo_gc", lambda: [], raising=False)
    return store


@pytest.fixture
def panel_env(monkeypatch, tmp_path, fake_ipfs):
    """Panel-specific isolation: .env in tmp, IPFS status/config faked."""
    env_path = tmp_path / "panel-env" / ".env"
    env_path.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(service_mod, "ENV_PATH", env_path)
    monkeypatch.setattr(service_mod, "get_storage_max", lambda: "10GB")
    monkeypatch.setattr(
        ipfs_mod, "ipfs_repo_stat",
        lambda: {"RepoSize": 1024, "StorageMax": 10 * 1024**3, "NumObjects": 3},
    )
    get_identity()  # bootstrap public.json in the temp dir
    return env_path


@pytest.fixture
def panel_app(panel_env):
    return create_panel_app()


LOCAL = ("127.0.0.1", 50000)
REMOTE = ("203.0.113.9", 50000)


# ---------------------------------------------------------------------------
# 1. Real TCP: the exact paths a proxy / tunnel / browser would hit
# ---------------------------------------------------------------------------

@pytest.fixture
def tcp_panel(panel_env, monkeypatch):
    """
    Boot the REAL panel app with uvicorn on an ephemeral 127.0.0.1 port,
    proxy_headers disabled — exactly the production listener configuration
    (never :8443/:8444). Yields (base_url, token, port).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    app = create_panel_app(panel_port=port)
    config = uvicorn.Config(app, host="127.0.0.1", port=port,
                            proxy_headers=False, log_level="error",
                            lifespan="off")
    server = uvicorn.Server(config)
    thread = threading.Thread(
        target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started:
        if time.time() > deadline:
            raise RuntimeError("panel test server did not start")
        time.sleep(0.02)

    token = ensure_panel_token()
    yield f"http://127.0.0.1:{port}", token, port

    server.should_exit = True
    thread.join(timeout=10)
    sock.close()


class TestRealTCP:
    def test_no_token_is_401_even_with_forwarded_for(self, tcp_panel):
        """(a) A proxied request (loopback peer + X-Forwarded-For) without
        the token gets 401 — headers rewrite nothing with proxy_headers off."""
        base, _, _ = tcp_panel
        r = httpx.get(base + "/admin/api/status",
                      headers={"X-Forwarded-For": "127.0.0.1",
                               "X-Real-IP": "127.0.0.1"})
        assert r.status_code == 401
        assert r.headers.get("www-authenticate") == "Bearer"
        assert "panel_token" in r.json()["detail"]

    def test_wrong_token_is_401(self, tcp_panel):
        base, _, _ = tcp_panel
        r = httpx.get(base + "/admin/api/status",
                      headers={"Authorization": "Bearer wrong-token"})
        assert r.status_code == 401

    def test_correct_token_is_200_and_no_pins(self, tcp_panel):
        """(b) correct token → 200; (e) pairing PINs absent from status."""
        base, token, _ = tcp_panel
        r = httpx.get(base + "/admin/api/status",
                      headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        obj = r.json()
        assert obj["running"] is True
        assert "pairing_pins" not in obj
        assert "pin" not in r.text.lower() or "pairing" not in r.text.lower()

    def test_html_shell_serves_without_token(self, tcp_panel):
        base, _, _ = tcp_panel
        r = httpx.get(base + "/admin")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]

    def test_oversized_upload_is_413(self, tcp_panel, monkeypatch):
        """(d) upload over MAX_UPLOAD_SIZE → 413."""
        monkeypatch.setattr(cfg, "MAX_UPLOAD_SIZE", 10_000)
        base, token, _ = tcp_panel
        r = httpx.post(base + "/admin/api/drive/upload",
                       headers={"Authorization": f"Bearer {token}"},
                       files={"file": ("big.bin", b"x" * 50_000)})
        assert r.status_code == 413

    def test_download_has_csp_and_nosniff(self, tcp_panel):
        """(f) CSP + nosniff on decrypted content responses."""
        base, token, _ = tcp_panel
        auth = {"Authorization": f"Bearer {token}"}
        r = httpx.post(base + "/admin/api/drive/upload", headers=auth,
                       files={"file": ("photo.jpg", b"\xff\xd8\xff jpeg-ish")})
        assert r.status_code == 200
        post_cid = r.json()["post_cid"]
        r = httpx.get(f"{base}/admin/api/drive/file/{post_cid}", headers=auth)
        assert r.status_code == 200
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["content-security-policy"] == "default-src 'none'; sandbox"
        assert r.headers["cache-control"] == "no-store"

    def test_evil_origin_state_change_is_403(self, tcp_panel):
        """(g) a browser-driven cross-origin POST is refused outright."""
        base, token, _ = tcp_panel
        r = httpx.post(base + "/admin/api/config",
                       headers={"Authorization": f"Bearer {token}",
                                "Origin": "https://evil.example.com"},
                       json={"alias": "pwned"})
        assert r.status_code == 403

    def test_own_origin_state_change_is_allowed(self, tcp_panel):
        base, token, port = tcp_panel
        r = httpx.post(base + "/admin/api/config",
                       headers={"Authorization": f"Bearer {token}",
                                "Origin": f"http://127.0.0.1:{port}"},
                       json={"alias": "mine"})
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# 2. The main (public) app must expose no /admin surface at all
# ---------------------------------------------------------------------------

class TestMainAppHasNoPanel:
    def test_main_app_has_no_admin_routes(self):
        """(c) the :8443-style app has NO /admin routes."""
        from cipher_station.main import app as main_app
        admin_routes = [r.path for r in main_app.routes
                        if getattr(r, "path", "").startswith("/admin")]
        assert admin_routes == []

    def test_admin_paths_404_on_main_app(self, panel_env):
        from cipher_station.main import app as main_app
        for path in ("/admin", "/admin/", "/admin/api/status",
                     "/admin/api/drive/files"):
            status, _, _ = call_panel(main_app, "GET", path, client=LOCAL)
            assert status == 404, path

    def test_health_still_reachable_remotely(self, panel_env):
        from cipher_station.main import app as main_app
        status, _, _ = call_app(main_app, "GET", "/health", client=REMOTE)
        assert status in (200, 503)  # reachable, not 403/404


# ---------------------------------------------------------------------------
# 3. Guards (in-process): localhost + bearer token
# ---------------------------------------------------------------------------

class TestGuards:
    @pytest.mark.parametrize("path", [
        "/admin", "/admin/", "/admin/api/status", "/admin/api/config",
        "/admin/api/drive/files", "/admin/static/style.css",
    ])
    def test_remote_peer_gets_403(self, panel_app, path):
        status, _, body = call_panel(panel_app, "GET", path, client=REMOTE)
        assert status == 403
        assert b"localhost-only" in body

    def test_remote_post_gets_403(self, panel_app):
        status, _ = call_json(panel_app, "POST", "/admin/api/config",
                              {"alias": "x"}, client=REMOTE)
        assert status == 403

    def test_forwarded_for_header_does_not_bypass(self, panel_app):
        """X-Forwarded-For must be ignored — only the socket peer counts."""
        status, _, _ = call_panel(
            panel_app, "GET", "/admin/api/status",
            headers={"x-forwarded-for": "127.0.0.1", "x-real-ip": "127.0.0.1"},
            client=REMOTE,
        )
        assert status == 403

    def test_missing_client_is_refused(self, panel_app):
        status, _, _ = call_panel(panel_app, "GET", "/admin/api/status", client=None)
        assert status == 403

    @pytest.mark.parametrize("path", [
        "/admin/api/status", "/admin/api/config", "/admin/api/drive/files",
    ])
    def test_api_without_token_is_401(self, panel_app, path):
        status, headers, _ = call_panel(panel_app, "GET", path, token=False)
        assert status == 401
        assert headers.get("www-authenticate") == "Bearer"

    def test_api_with_wrong_token_is_401(self, panel_app):
        status, _, _ = call_panel(
            panel_app, "GET", "/admin/api/status", token=False,
            headers={"authorization": "Bearer nope"})
        assert status == 401

    def test_api_with_malformed_auth_is_401(self, panel_app):
        for value in ("Basic dXNlcjpwdw==", "Bearer", "", "token abc"):
            status, _, _ = call_panel(
                panel_app, "GET", "/admin/api/status", token=False,
                headers={"authorization": value})
            assert status == 401, value

    def test_api_with_token_is_200(self, panel_app):
        status, _, _ = call_panel(panel_app, "GET", "/admin/api/status")
        assert status == 200

    def test_shell_and_static_do_not_need_token(self, panel_app):
        status, headers, body = call_panel(panel_app, "GET", "/admin", token=False)
        assert status == 200
        assert "text/html" in headers["content-type"]
        assert b"Cipher Station" in body
        status, _, _ = call_panel(panel_app, "GET", "/admin/static/style.css",
                                  token=False)
        assert status == 200

    def test_token_file_is_0600_in_data_dir(self, panel_app):
        call_panel(panel_app, "GET", "/admin/api/status")
        path = guard_mod.panel_token_path()
        assert path.parent == cfg.BASE_DIR
        assert path.exists()
        assert (path.stat().st_mode & 0o777) == 0o600
        assert path.read_text().strip() == ensure_panel_token()

    def test_token_is_stable_within_process_boot(self, panel_env):
        assert ensure_panel_token() == ensure_panel_token()

    def test_loopback_helper(self):
        assert is_loopback_address("127.0.0.1")
        assert is_loopback_address("127.1.2.3")
        assert is_loopback_address("::1")
        assert is_loopback_address("::ffff:127.0.0.1")
        assert not is_loopback_address("10.0.0.1")
        assert not is_loopback_address("203.0.113.9")
        assert not is_loopback_address(None)
        assert not is_loopback_address("")

    def test_ipv6_loopback_is_allowed(self, panel_app):
        status, _, _ = call_panel(panel_app, "GET", "/admin/api/status",
                                  client=("::1", 50000))
        assert status == 200

    def test_static_traversal_is_refused(self, panel_app):
        status, _, _ = call_panel(panel_app, "GET", "/admin/static/..%2Frouter.py",
                                  token=False)
        assert status == 404

    def test_evil_origin_rejected_before_handler(self, panel_app):
        status, obj = call_json(
            panel_app, "POST", "/admin/api/config", {"alias": "x"})
        assert status == 200  # sanity: same request without Origin passes
        body = json.dumps({"alias": "evil"}).encode()
        status, _, _ = call_panel(
            panel_app, "POST", "/admin/api/config", body=body,
            headers={"content-type": "application/json",
                     "content-length": str(len(body)),
                     "origin": "https://evil.example.com"})
        assert status == 403

    def test_get_with_evil_origin_cannot_be_read_anyway(self, panel_app):
        """GETs aren't Origin-blocked, but there is no CORS middleware, so
        no Access-Control-Allow-Origin header ever leaks a response."""
        status, headers, _ = call_panel(
            panel_app, "GET", "/admin/api/status",
            headers={"origin": "https://evil.example.com"})
        assert status == 200
        assert "access-control-allow-origin" not in headers


# ---------------------------------------------------------------------------
# 4. Config endpoints
# ---------------------------------------------------------------------------

class TestStatusAndConfig:
    def test_status_shape(self, panel_app):
        status, obj = call_json(panel_app, "GET", "/admin/api/status")
        assert status == 200
        assert obj["running"] is True
        assert obj["uid"]
        assert obj["ipfs"]["running"] is True
        assert obj["ipfs"]["storage_max_bytes"] == 10 * 1024**3

    def test_status_never_contains_pins(self, panel_app):
        status, _, raw = call_panel(panel_app, "GET", "/admin/api/status")
        assert status == 200
        assert b"pairing_pins" not in raw
        assert b'"pin"' not in raw

    def test_get_config(self, panel_app):
        status, obj = call_json(panel_app, "GET", "/admin/api/config")
        assert status == 200
        assert obj["ipfs_storage_max"] == "10GB"
        assert "restart_command" in obj

    def test_set_alias_roundtrip(self, panel_app):
        status, obj = call_json(panel_app, "POST", "/admin/api/config",
                                {"alias": "Charlie's Station"})
        assert status == 200
        assert obj["alias"] == "Charlie's Station"

        on_disk = json.loads(cfg.PUBLIC_JSON_PATH.read_text())
        assert on_disk["alias"] == "Charlie's Station"
        # Identity fields survived the write.
        assert on_disk["uid"]
        assert on_disk["mlkem_public_key"]

    def test_alias_too_long_is_400(self, panel_app):
        status, _ = call_json(panel_app, "POST", "/admin/api/config",
                              {"alias": "x" * 81})
        assert status == 400

    def test_permanent_url_written_to_env(self, panel_app, panel_env):
        status, obj = call_json(panel_app, "POST", "/admin/api/config",
                                {"permanent_url": "https://station.example.com"})
        assert status == 200
        assert obj["restart_required"] is True
        assert "systemctl restart cipherstation" in obj["restart_command"]
        assert "CIPHER_PUBLIC_URL=https://station.example.com" in panel_env.read_text()

    def test_bad_permanent_url_is_400(self, panel_app, panel_env):
        status, _ = call_json(panel_app, "POST", "/admin/api/config",
                              {"permanent_url": "not a url"})
        assert status == 400
        assert not panel_env.exists() or "CIPHER_PUBLIC_URL" not in panel_env.read_text()

    def test_clear_permanent_url_removes_env_line(self, panel_app, panel_env):
        call_json(panel_app, "POST", "/admin/api/config",
                  {"permanent_url": "https://a.example.com"})
        status, _ = call_json(panel_app, "POST", "/admin/api/config",
                              {"clear_permanent_url": True})
        assert status == 200
        assert "CIPHER_PUBLIC_URL" not in panel_env.read_text()

    def test_tunnel_toggle_preserves_other_env_lines(self, panel_app, panel_env):
        panel_env.write_text("# comment\nCIPHER_PASSWORD=secret\n")
        status, _ = call_json(panel_app, "POST", "/admin/api/config",
                              {"cloudflare_tunnel_enabled": True})
        assert status == 200
        text = panel_env.read_text()
        assert "# comment" in text
        assert "CIPHER_PASSWORD=secret" in text
        assert "CLOUDFLARE_TUNNEL_ENABLED=true" in text

    def test_storage_max_valid(self, panel_app, monkeypatch):
        calls = []
        monkeypatch.setattr(service_mod, "set_storage_max",
                            lambda v: calls.append(v))
        status, obj = call_json(panel_app, "POST", "/admin/api/config/storage-max",
                                {"storage_max": "50GB"})
        assert status == 200
        assert obj["restart_required"] is True
        assert calls == ["50GB"]

    def test_storage_max_invalid_is_400(self, panel_app):
        status, _ = call_json(panel_app, "POST", "/admin/api/config/storage-max",
                              {"storage_max": "lots"})
        assert status == 400

    def test_storage_max_validation_helper(self):
        with pytest.raises(ValueError):
            service_mod.set_storage_max("banana")
        with pytest.raises(ValueError):
            service_mod.set_storage_max("")

    def test_profile_update(self, panel_app):
        status, obj = call_json(panel_app, "POST", "/admin/api/profile",
                                {"display_name": "Charlie", "bio": "hi"})
        assert status == 200
        assert obj["profile"]["display_name"] == "Charlie"

    def test_profile_validation_maps_to_400(self, panel_app):
        status, _ = call_json(panel_app, "POST", "/admin/api/profile",
                              {"username": "no spaces allowed"})
        assert status == 400


# ---------------------------------------------------------------------------
# 5. Drive endpoints
# ---------------------------------------------------------------------------

def upload(app, name, data, folder=None, content_length=True):
    fields = {"folder": folder} if folder else {}
    body, ctype = multipart_body(fields, {"file": (name, data)})
    headers = {"content-type": ctype}
    if content_length:
        headers["content-length"] = str(len(body))
    return call_panel(app, "POST", "/admin/api/drive/upload",
                      headers=headers, body=body)


class TestDrive:
    def test_empty_drive_lists_nothing(self, panel_app):
        status, obj = call_json(panel_app, "GET", "/admin/api/drive/files")
        assert status == 200
        assert obj == {"files": [], "folders": [], "errors": []}

    def test_upload_list_roundtrip(self, panel_app):
        data = b"hello drive " * 100
        status, _, raw = upload(panel_app, "notes.txt", data, folder="Documents")
        assert status == 200
        res = json.loads(raw)
        assert res["status"] == "uploaded"
        post_cid = res["post_cid"]

        status, obj = call_json(panel_app, "GET", "/admin/api/drive/files")
        assert status == 200
        assert obj["folders"] == ["Documents"]
        (f,) = obj["files"]
        assert f["filename"] == "notes.txt"
        assert f["folders"] == ["Documents"]
        assert f["size_bytes"] == len(data)
        assert f["post_cid"] == post_cid
        assert obj["errors"] == []

    def test_upload_lands_in_drive_manifest_bucket_encrypted(self, panel_app, fake_ipfs):
        """CipherVault compatibility: --client drive bucket, encrypted metadata
        hex, self envelope sealed to the station, ciphertext on IPFS."""
        data = b"secret-bytes"
        _, _, raw = upload(panel_app, "secret.bin", data, folder="Vault")
        post_cid = json.loads(raw)["post_cid"]

        manifest = manifest_mod.load_manifest(client="drive")
        (entry,) = manifest["clients"]["drive"]["posts"]
        assert entry["post_cid"] == post_cid
        assert entry["audience_mode"] == "self"
        assert isinstance(entry["metadata"], str)  # encrypted hex, not a dict
        assert entry["envelopes_cid"]

        # Stored blob is NOT the plaintext.
        assert fake_ipfs[post_cid] != data
        assert data not in fake_ipfs[post_cid]

        # The station's own envelope opens back to the sym key that decrypts it.
        env_obj = json.loads(fake_ipfs[entry["envelopes_cid"]])
        ident = get_identity()
        assert ident.uid in env_obj["envelopes"]
        from cipher_station.envelopes import open_envelope
        from nacl.secret import SecretBox
        sym = open_envelope(ident.mlkem_sk, env_obj["envelopes"][ident.uid])
        assert SecretBox(sym).decrypt(fake_ipfs[post_cid]) == data
        # And the metadata decrypts to filename + folder tags.
        meta = json.loads(SecretBox(sym).decrypt(bytes.fromhex(entry["metadata"])))
        assert meta["filename"] == "secret.bin"
        assert meta["tags"] == ["Vault"]

    def test_download_decrypts_server_side_with_hardening(self, panel_app):
        data = b"%PDF-1.4 fake pdf content"
        _, _, raw = upload(panel_app, "report.pdf", data)
        post_cid = json.loads(raw)["post_cid"]

        status, headers, body = call_panel(
            panel_app, "GET", f"/admin/api/drive/file/{post_cid}",
            query=b"download=true")
        assert status == 200
        assert body == data
        assert headers["content-type"] == "application/pdf"
        assert 'attachment; filename="report.pdf"' in headers["content-disposition"]
        assert headers["cache-control"] == "no-store"
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["content-security-policy"] == "default-src 'none'; sandbox"

    def test_preview_is_inline_for_media(self, panel_app):
        _, _, raw = upload(panel_app, "photo.jpg", b"\xff\xd8\xff jpeg-ish")
        post_cid = json.loads(raw)["post_cid"]
        status, headers, _ = call_panel(
            panel_app, "GET", f"/admin/api/drive/file/{post_cid}")
        assert status == 200
        assert headers["content-type"].startswith("image/jpeg")
        assert headers["content-disposition"].startswith("inline")
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["content-security-policy"] == "default-src 'none'; sandbox"

    def test_active_content_is_forced_to_octet_stream_attachment(self, panel_app):
        """HTML (or anything non-media) must never render inline."""
        _, _, raw = upload(panel_app, "evil.html", b"<script>alert(1)</script>")
        post_cid = json.loads(raw)["post_cid"]
        status, headers, _ = call_panel(
            panel_app, "GET", f"/admin/api/drive/file/{post_cid}")
        assert status == 200
        assert headers["content-type"].startswith("application/octet-stream")
        assert headers["content-disposition"].startswith("attachment")
        assert headers["x-content-type-options"] == "nosniff"

    def test_oversized_upload_streams_to_413_without_content_length(
            self, panel_app, monkeypatch):
        """Even with no Content-Length (chunked/lying client), the streaming
        reader aborts at the cap with 413."""
        monkeypatch.setattr(cfg, "MAX_UPLOAD_SIZE", 5_000)
        status, _, _ = upload(panel_app, "big.bin", b"x" * 20_000,
                              content_length=False)
        assert status == 413

    def test_oversized_content_length_is_413_before_body(self, panel_app, monkeypatch):
        monkeypatch.setattr(cfg, "MAX_UPLOAD_SIZE", 5_000)
        status, _, _ = upload(panel_app, "big.bin", b"x" * 20_000)
        assert status == 413

    def test_unknown_cid_is_404(self, panel_app):
        status, _ = call_json(panel_app, "GET",
                              "/admin/api/drive/file/QmNope" + "x" * 40)
        assert status == 404

    def test_upload_requires_filename(self, panel_app):
        body, ctype = multipart_body({}, {"file": ("", b"data")})
        status, _, _ = call_panel(
            panel_app, "POST", "/admin/api/drive/upload",
            headers={"content-type": ctype, "content-length": str(len(body))},
            body=body,
        )
        assert status in (400, 422)

    def test_empty_file_is_400(self, panel_app):
        status, _, _ = upload(panel_app, "empty.txt", b"")
        assert status == 400

    def test_filename_with_slash_is_400(self, panel_app):
        body, ctype = multipart_body({}, {"file": ("a/b.txt", b"x")})
        status, _, _ = call_panel(
            panel_app, "POST", "/admin/api/drive/upload",
            headers={"content-type": ctype, "content-length": str(len(body))},
            body=body,
        )
        assert status == 400

    def test_delete_removes_post_and_manifest_entry(self, panel_app):
        _, _, raw = upload(panel_app, "gone.txt", b"delete me")
        post_cid = json.loads(raw)["post_cid"]

        status, obj = call_json(panel_app, "POST", "/admin/api/drive/delete",
                                {"post_cid": post_cid})
        assert status == 200
        assert obj["status"] == "deleted"

        manifest = manifest_mod.load_manifest(client="drive")
        assert manifest["clients"]["drive"]["posts"] == []
        status, obj = call_json(panel_app, "GET", "/admin/api/drive/files")
        assert obj["files"] == []

    def test_delete_unknown_is_404(self, panel_app):
        status, _ = call_json(panel_app, "POST", "/admin/api/drive/delete",
                              {"post_cid": "QmMissing" + "z" * 37})
        assert status == 404

    def test_undecryptable_post_is_reported_not_dropped_silently(self, panel_app, fake_ipfs):
        _, _, raw = upload(panel_app, "good.txt", b"fine")
        # Sabotage: a drive entry whose envelopes CID is unknown to IPFS.
        manifest = manifest_mod.load_manifest(client="drive")
        manifest["clients"]["drive"]["posts"].append({
            "post_cid": "QmBroken" + "b" * 38,
            "envelopes_cid": "QmMissing" + "m" * 37,
            "metadata": "deadbeef",
            "audience_mode": "self",
            "created_at": 1,
        })
        manifest_mod.save_manifest(manifest, client="drive")

        status, obj = call_json(panel_app, "GET", "/admin/api/drive/files")
        assert status == 200
        assert len(obj["files"]) == 1
        assert len(obj["errors"]) == 1
        assert obj["errors"][0]["post_cid"].startswith("QmBroken")
