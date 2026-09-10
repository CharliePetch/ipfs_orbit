# tests/test_panel.py
"""
Admin panel tests: the localhost guard, the config endpoints, and the drive
API. IPFS is never contacted — an in-memory fake CID store stands in for it
(monkeypatched at every import site), and the autouse temp_cipher_station_dir
fixture keeps all state inside a temp dir.

Requests are driven through the real ASGI app with an in-process caller (the
same pattern as test_content.py) because the tests must control the SOCKET
peer address in the ASGI scope — the exact thing the guard checks.
"""

import hashlib
import json
import secrets

import pytest

import cipher_station.ipfs_client as ipfs_mod
import cipher_station.manifest as manifest_mod
import cipher_station.posts as posts_mod
import cipher_station.panel.drive as drive_mod
import cipher_station.panel.service as service_mod
from cipher_station.identity import get_identity
from cipher_station.main import app
from cipher_station.panel.guard import is_loopback_address


# ---------------------------------------------------------------------------
# In-process ASGI caller with body support
# ---------------------------------------------------------------------------

def call_app(method, path, *, headers=None, body=b"", client=("127.0.0.1", 50000),
             query=b""):
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


def call_json(method, path, obj=None, *, client=("127.0.0.1", 50000)):
    body = json.dumps(obj).encode() if obj is not None else b""
    headers = {"content-type": "application/json", "content-length": str(len(body))}
    status, h, raw = call_app(method, path, headers=headers, body=body, client=client)
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


LOCAL = ("127.0.0.1", 50000)
REMOTE = ("203.0.113.9", 50000)


# ---------------------------------------------------------------------------
# 1. Localhost guard
# ---------------------------------------------------------------------------

class TestLocalhostGuard:
    @pytest.mark.parametrize("path", [
        "/admin", "/admin/", "/admin/api/status", "/admin/api/config",
        "/admin/api/drive/files", "/admin/static/style.css",
    ])
    def test_remote_peer_gets_403(self, panel_env, path):
        status, _, body = call_app("GET", path, client=REMOTE)
        assert status == 403
        assert b"localhost-only" in body

    def test_remote_post_gets_403(self, panel_env):
        status, _ = call_json("POST", "/admin/api/config", {"alias": "x"}, client=REMOTE)
        assert status == 403

    def test_forwarded_for_header_does_not_bypass(self, panel_env):
        """X-Forwarded-For must be ignored — only the socket peer counts."""
        status, _, _ = call_app(
            "GET", "/admin/api/status",
            headers={"x-forwarded-for": "127.0.0.1", "x-real-ip": "127.0.0.1"},
            client=REMOTE,
        )
        assert status == 403

    def test_loopback_peer_is_allowed(self, panel_env):
        status, _, _ = call_app("GET", "/admin/api/status", client=LOCAL)
        assert status == 200

    def test_ipv6_loopback_is_allowed(self, panel_env):
        status, _, _ = call_app("GET", "/admin/api/status", client=("::1", 50000))
        assert status == 200

    def test_missing_client_is_refused(self, panel_env):
        status, _, _ = call_app("GET", "/admin/api/status", client=None)
        assert status == 403

    def test_loopback_helper(self):
        assert is_loopback_address("127.0.0.1")
        assert is_loopback_address("127.1.2.3")
        assert is_loopback_address("::1")
        assert is_loopback_address("::ffff:127.0.0.1")
        assert not is_loopback_address("10.0.0.1")
        assert not is_loopback_address("203.0.113.9")
        assert not is_loopback_address(None)
        assert not is_loopback_address("")

    def test_index_serves_html_on_loopback(self, panel_env):
        status, headers, body = call_app("GET", "/admin", client=LOCAL)
        assert status == 200
        assert "text/html" in headers["content-type"]
        assert b"Cipher Station" in body

    def test_static_traversal_is_refused(self, panel_env):
        status, _, _ = call_app("GET", "/admin/static/..%2Frouter.py", client=LOCAL)
        assert status == 404

    def test_device_api_routes_do_not_gain_the_guard(self, panel_env):
        """/health (an existing route) still answers from a remote peer."""
        status, _, _ = call_app("GET", "/health", client=REMOTE)
        assert status in (200, 503)  # reachable, not 403


# ---------------------------------------------------------------------------
# 2. Config endpoints
# ---------------------------------------------------------------------------

class TestStatusAndConfig:
    def test_status_shape(self, panel_env):
        status, obj = call_json("GET", "/admin/api/status")
        assert status == 200
        assert obj["running"] is True
        assert obj["uid"]
        assert obj["ipfs"]["running"] is True
        assert obj["ipfs"]["storage_max_bytes"] == 10 * 1024**3
        assert isinstance(obj["pairing_pins"], list)

    def test_get_config(self, panel_env):
        status, obj = call_json("GET", "/admin/api/config")
        assert status == 200
        assert obj["ipfs_storage_max"] == "10GB"
        assert "restart_command" in obj

    def test_set_alias_roundtrip(self, panel_env):
        status, obj = call_json("POST", "/admin/api/config", {"alias": "Charlie's Station"})
        assert status == 200
        assert obj["alias"] == "Charlie's Station"

        import cipher_station.config as cfg
        on_disk = json.loads(cfg.PUBLIC_JSON_PATH.read_text())
        assert on_disk["alias"] == "Charlie's Station"
        # Identity fields survived the write.
        assert on_disk["uid"]
        assert on_disk["mlkem_public_key"]

    def test_alias_too_long_is_400(self, panel_env):
        status, _ = call_json("POST", "/admin/api/config", {"alias": "x" * 81})
        assert status == 400

    def test_permanent_url_written_to_env(self, panel_env):
        status, obj = call_json("POST", "/admin/api/config",
                                {"permanent_url": "https://station.example.com"})
        assert status == 200
        assert obj["restart_required"] is True
        assert "systemctl restart cipherstation" in obj["restart_command"]
        assert "CIPHER_PUBLIC_URL=https://station.example.com" in panel_env.read_text()

    def test_bad_permanent_url_is_400(self, panel_env):
        status, _ = call_json("POST", "/admin/api/config",
                              {"permanent_url": "not a url"})
        assert status == 400
        assert not panel_env.exists() or "CIPHER_PUBLIC_URL" not in panel_env.read_text()

    def test_clear_permanent_url_removes_env_line(self, panel_env):
        call_json("POST", "/admin/api/config", {"permanent_url": "https://a.example.com"})
        status, _ = call_json("POST", "/admin/api/config", {"clear_permanent_url": True})
        assert status == 200
        assert "CIPHER_PUBLIC_URL" not in panel_env.read_text()

    def test_tunnel_toggle_preserves_other_env_lines(self, panel_env):
        panel_env.write_text("# comment\nCIPHER_PASSWORD=secret\n")
        status, _ = call_json("POST", "/admin/api/config",
                              {"cloudflare_tunnel_enabled": True})
        assert status == 200
        text = panel_env.read_text()
        assert "# comment" in text
        assert "CIPHER_PASSWORD=secret" in text
        assert "CLOUDFLARE_TUNNEL_ENABLED=true" in text

    def test_storage_max_valid(self, panel_env, monkeypatch):
        calls = []
        monkeypatch.setattr(service_mod, "set_storage_max",
                            lambda v: calls.append(v))
        status, obj = call_json("POST", "/admin/api/config/storage-max",
                                {"storage_max": "50GB"})
        assert status == 200
        assert obj["restart_required"] is True
        assert calls == ["50GB"]

    def test_storage_max_invalid_is_400(self, panel_env):
        status, _ = call_json("POST", "/admin/api/config/storage-max",
                              {"storage_max": "lots"})
        assert status == 400

    def test_storage_max_validation_helper(self):
        with pytest.raises(ValueError):
            service_mod.set_storage_max("banana")
        with pytest.raises(ValueError):
            service_mod.set_storage_max("")

    def test_profile_update(self, panel_env):
        status, obj = call_json("POST", "/admin/api/profile",
                                {"display_name": "Charlie", "bio": "hi"})
        assert status == 200
        assert obj["profile"]["display_name"] == "Charlie"

    def test_profile_validation_maps_to_400(self, panel_env):
        status, _ = call_json("POST", "/admin/api/profile",
                              {"username": "no spaces allowed"})
        assert status == 400


# ---------------------------------------------------------------------------
# 3. Drive endpoints
# ---------------------------------------------------------------------------

def upload(name, data, folder=None):
    fields = {"folder": folder} if folder else {}
    body, ctype = multipart_body(fields, {"file": (name, data)})
    return call_app(
        "POST", "/admin/api/drive/upload",
        headers={"content-type": ctype, "content-length": str(len(body))},
        body=body,
    )


class TestDrive:
    def test_empty_drive_lists_nothing(self, panel_env):
        status, obj = call_json("GET", "/admin/api/drive/files")
        assert status == 200
        assert obj == {"files": [], "folders": [], "errors": []}

    def test_upload_list_roundtrip(self, panel_env):
        data = b"hello drive " * 100
        status, _, raw = upload("notes.txt", data, folder="Documents")
        assert status == 200
        res = json.loads(raw)
        assert res["status"] == "uploaded"
        post_cid = res["post_cid"]

        status, obj = call_json("GET", "/admin/api/drive/files")
        assert status == 200
        assert obj["folders"] == ["Documents"]
        (f,) = obj["files"]
        assert f["filename"] == "notes.txt"
        assert f["folders"] == ["Documents"]
        assert f["size_bytes"] == len(data)
        assert f["post_cid"] == post_cid
        assert obj["errors"] == []

    def test_upload_lands_in_drive_manifest_bucket_encrypted(self, panel_env, fake_ipfs):
        """CipherVault compatibility: --client drive bucket, encrypted metadata
        hex, self envelope sealed to the station, ciphertext on IPFS."""
        data = b"secret-bytes"
        _, _, raw = upload("secret.bin", data, folder="Vault")
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

    def test_download_decrypts_server_side(self, panel_env):
        data = b"%PDF-1.4 fake pdf content"
        _, _, raw = upload("report.pdf", data)
        post_cid = json.loads(raw)["post_cid"]

        status, headers, body = call_app(
            "GET", f"/admin/api/drive/file/{post_cid}", query=b"download=true")
        assert status == 200
        assert body == data
        assert headers["content-type"] == "application/pdf"
        assert 'attachment; filename="report.pdf"' in headers["content-disposition"]
        assert headers["cache-control"] == "no-store"

    def test_preview_is_inline(self, panel_env):
        _, _, raw = upload("photo.jpg", b"\xff\xd8\xff jpeg-ish")
        post_cid = json.loads(raw)["post_cid"]
        status, headers, _ = call_app("GET", f"/admin/api/drive/file/{post_cid}")
        assert status == 200
        assert headers["content-type"] == "image/jpeg"
        assert headers["content-disposition"].startswith("inline")

    def test_unknown_cid_is_404(self, panel_env):
        status, _ = call_json("GET", "/admin/api/drive/file/QmNope" + "x" * 40)
        assert status == 404

    def test_upload_requires_filename(self, panel_env):
        body, ctype = multipart_body({}, {"file": ("", b"data")})
        status, _, _ = call_app(
            "POST", "/admin/api/drive/upload",
            headers={"content-type": ctype, "content-length": str(len(body))},
            body=body,
        )
        assert status in (400, 422)

    def test_empty_file_is_400(self, panel_env):
        status, _, _ = upload("empty.txt", b"")
        assert status == 400

    def test_filename_with_slash_is_400(self, panel_env):
        status, _, _ = upload("..%2Fevil", b"x")  # encoded here, but check raw too
        # raw slash in the multipart filename:
        body, ctype = multipart_body({}, {"file": ("a/b.txt", b"x")})
        status2, _, _ = call_app(
            "POST", "/admin/api/drive/upload",
            headers={"content-type": ctype, "content-length": str(len(body))},
            body=body,
        )
        assert status2 == 400

    def test_delete_removes_post_and_manifest_entry(self, panel_env):
        _, _, raw = upload("gone.txt", b"delete me")
        post_cid = json.loads(raw)["post_cid"]

        status, obj = call_json("POST", "/admin/api/drive/delete", {"post_cid": post_cid})
        assert status == 200
        assert obj["status"] == "deleted"

        manifest = manifest_mod.load_manifest(client="drive")
        assert manifest["clients"]["drive"]["posts"] == []
        status, obj = call_json("GET", "/admin/api/drive/files")
        assert obj["files"] == []

    def test_delete_unknown_is_404(self, panel_env):
        status, _ = call_json("POST", "/admin/api/drive/delete",
                              {"post_cid": "QmMissing" + "z" * 37})
        assert status == 404

    def test_undecryptable_post_is_reported_not_dropped_silently(self, panel_env, fake_ipfs):
        _, _, raw = upload("good.txt", b"fine")
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

        status, obj = call_json("GET", "/admin/api/drive/files")
        assert status == 200
        assert len(obj["files"]) == 1
        assert len(obj["errors"]) == 1
        assert obj["errors"][0]["post_cid"].startswith("QmBroken")
