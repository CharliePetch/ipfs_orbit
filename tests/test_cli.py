# tests/test_cli.py
"""
Tests for the cipher_cli client.

Two layers:

  1. Unit: envelope/metadata construction, signed headers, multipart encoding,
     config file permissions, output-path hygiene, TLS pinning — no station.
  2. End-to-end: the REAL commands (cmd_post / cmd_list / cmd_get / cmd_delete)
     driven through the REAL ASGI app — middleware, ML-DSA auth dependency,
     /post, /profile, /content, /rewrap, /post/delete — with IPFS replaced by
     an in-memory store. This is what proves the CLI's wire format and
     signatures are what the server actually accepts, rather than what a
     test re-implementation of the server thinks it accepts.

The autouse temp_cipher_station_dir fixture (conftest.py) keeps every station
path inside a temp dir; CIPHER_CLI_HOME is pointed at another.
"""

import asyncio
import base64
import hashlib
import json
import os
import re
import stat
from email.parser import BytesParser
from email.policy import HTTP

import pytest
from nacl.secret import SecretBox

import cipher_station.ipfs_client as ipfs_mod
import cipher_station.manifest as manifest_mod
import cipher_station.posts as posts_mod
import cipher_station.rewrap as rewrap_mod
from cipher_station import pqcrypto
from cipher_station.auth import _canonical
from cipher_station.followers import add_follower_device
from cipher_station.identity import get_identity
from cipher_station.main import app

import cipher_cli.cli as cli
from cipher_cli.cli import (
    BLOB_FILENAME,
    build_auth_headers,
    build_encrypted_post,
    build_metadata,
    decrypt_metadata,
    encode_multipart,
    output_path_for,
    save_config,
)


# ---------------------------------------------------------------------------
# Unit
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def station_keys():
    pub, sec = pqcrypto.generate_mlkem_keypair()
    return pub, sec


def test_build_encrypted_post_round_trip(station_keys):
    """The station must be able to recover the sym key from self_envelope and
    decrypt both the blob and the metadata — exactly what handle_new_post and
    a later reader do."""
    station_pub, station_sec = station_keys
    plaintext = b"hello cipher station"
    metadata = {"filename": "hello.txt", "tags": ["Herman"], "client": "cli"}

    blob, metadata_hex, self_envelope = build_encrypted_post(
        plaintext, metadata, station_pub.hex())

    sym = pqcrypto.open_key(station_sec, self_envelope)
    assert sym is not None and len(sym) == SecretBox.KEY_SIZE
    assert SecretBox(sym).decrypt(blob) == plaintext
    assert decrypt_metadata(metadata_hex, sym) == metadata
    assert plaintext not in blob
    assert json.dumps(metadata).encode() not in bytes.fromhex(metadata_hex)


def test_build_metadata_fields(tmp_path):
    f = tmp_path / "photo.JPG"
    f.write_bytes(b"x" * 123)
    md = build_metadata(f, folder="Vacation", filename=None)
    assert md["filename"] == "photo.JPG"
    assert md["size_bytes"] == 123
    assert md["extension"] == "jpg"
    assert md["tags"] == ["Vacation"]
    assert md["client"] == "cli"
    assert md["mime_type"] == "image/jpeg"
    iso = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
    assert re.match(iso, md["created_at"])
    assert re.match(iso, md["file_created_at"])
    assert re.match(iso, md["file_modified_at"])


def test_build_metadata_extension_follows_override(tmp_path):
    f = tmp_path / "scan.bin"
    f.write_bytes(b"x")
    md = build_metadata(f, folder=None, filename="report.PDF")
    assert md["filename"] == "report.PDF"
    assert md["extension"] == "pdf"
    assert md["mime_type"] == "application/pdf"


def test_auth_headers_verify_like_the_server():
    """Rebuild the server's canonical string (via the server's own helper) and
    verify the ML-DSA signature with the device public key."""
    mldsa_pub, mldsa_sec = pqcrypto.generate_mldsa_keypair()
    cfg = {"station_uid": "owner-uid", "device_uid": "device-1",
           "mldsa_secret_key": mldsa_sec.hex()}
    body = b'{"post_cid":"Qmabc"}'
    headers = build_auth_headers(cfg, "POST", "/post/delete", body)

    assert headers["x-cipher-body-sha256"] == hashlib.sha256(body).hexdigest()
    assert re.fullmatch(r"[0-9a-f]{32}", headers["x-cipher-nonce"]), "spec 12.3: hex nonce"
    canonical = _canonical("POST", "/post/delete", "owner-uid", "device-1",
                           headers["x-cipher-ts"], headers["x-cipher-nonce"],
                           headers["x-cipher-body-sha256"])
    sig = base64.b64decode(headers["x-cipher-sig"])
    assert pqcrypto.verify(mldsa_pub, canonical, sig)
    assert not pqcrypto.verify(mldsa_pub, canonical + b"x", sig)


def _parse_multipart(body: bytes, ctype: str):
    msg = BytesParser(policy=HTTP).parsebytes(b"Content-Type: " + ctype.encode() + b"\r\n\r\n" + body)
    assert msg.is_multipart()
    out = {}
    for part in msg.iter_parts():
        out[part.get_param("name", header="content-disposition")] = part
    return out


def test_encode_multipart_parses():
    """The hand-rolled body must be parseable by a real multipart parser and
    preserve every byte of the payload."""
    payload = bytes(range(256))
    body, ctype = encode_multipart(
        {"client": "cli", "audience_mode": "self"}, "file", BLOB_FILENAME, payload)
    assert ctype.startswith("multipart/form-data; boundary=")
    parts = _parse_multipart(body, ctype)
    assert parts["client"].get_payload(decode=True) == b"cli"
    assert parts["audience_mode"].get_payload(decode=True) == b"self"
    assert parts["file"].get_payload(decode=True) == payload
    assert parts["file"].get_filename() == BLOB_FILENAME


def test_encode_multipart_neutralises_header_injection():
    body, _ = encode_multipart({}, "file", 'x"; name="evil\r\nX-Injected: 1', b"")
    assert b"\r\nX-Injected" not in body, "CRLF stripped: no new header line can be smuggled in"
    assert b'filename="x; name=evilX-Injected: 1"' in body


def test_save_config_is_never_world_readable(tmp_path, monkeypatch):
    monkeypatch.setenv("CIPHER_CLI_HOME", str(tmp_path / "cli-home"))
    old = os.umask(0o022)
    try:
        save_config({"mldsa_secret_key": "deadbeef"})
    finally:
        os.umask(old)
    home = tmp_path / "cli-home"
    assert stat.S_IMODE(home.stat().st_mode) == 0o700
    assert stat.S_IMODE((home / "config.json").stat().st_mode) == 0o600
    assert not (home / "config.json.tmp").exists()
    assert json.loads((home / "config.json").read_text())["mldsa_secret_key"] == "deadbeef"


class TestOutputPath:
    def test_explicit_output_is_honoured(self, tmp_path):
        assert output_path_for({"filename": "../x"}, "Qm1", str(tmp_path / "out.bin")) == tmp_path / "out.bin"

    @pytest.mark.parametrize("hostile", ["../../.bashrc", "/etc/passwd", "sub/dir/file.txt", "..", ""])
    def test_metadata_filename_is_reduced_to_a_basename_in_cwd(self, tmp_path, monkeypatch, hostile):
        monkeypatch.chdir(tmp_path)
        out = output_path_for({"filename": hostile}, "Qmcid", None)
        assert out.parent == tmp_path
        assert out.name in ("Qmcid", ".bashrc", "passwd", "file.txt")

    def test_refuses_to_clobber(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "photo.jpg").write_bytes(b"precious")
        with pytest.raises(SystemExit):
            output_path_for({"filename": "photo.jpg"}, "Qmcid", None)


class TestTlsPinning:
    def test_verified_stations_skip_the_pin(self, monkeypatch):
        monkeypatch.setattr(cli, "tls_fingerprint", lambda url: pytest.fail("must not probe"))
        cli.check_pinned_cert({"verify_tls": True})

    def test_matching_pin_passes(self, monkeypatch):
        monkeypatch.setattr(cli, "tls_fingerprint", lambda url: "ab" * 32)
        cli.check_pinned_cert({"verify_tls": False, "station_url": "https://s:8443",
                               "tls_fingerprint_sha256": "ab" * 32})

    def test_changed_certificate_is_refused(self, monkeypatch):
        monkeypatch.setattr(cli, "tls_fingerprint", lambda url: "cd" * 32)
        with pytest.raises(SystemExit) as ex:
            cli.check_pinned_cert({"verify_tls": False, "station_url": "https://s:8443",
                                   "tls_fingerprint_sha256": "ab" * 32})
        assert "certificate has changed" in str(ex.value)

    def test_insecure_without_pin_is_refused(self):
        with pytest.raises(SystemExit):
            cli.check_pinned_cert({"verify_tls": False, "station_url": "https://s:8443"})


# ---------------------------------------------------------------------------
# End-to-end through the real app
# ---------------------------------------------------------------------------

def _fake_cid(data: bytes) -> str:
    return "Qm" + hashlib.sha256(data).hexdigest()[:44]  # 46 alnum chars: plausible CIDv0


class FakeUpstream:
    def __init__(self, body: bytes):
        self.status_code = 200
        self.headers = {"Content-Length": str(len(body))}
        self._body = body

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i:i + chunk_size]

    def close(self):
        pass


@pytest.fixture
def fake_ipfs(monkeypatch):
    """In-memory IPFS. Every module that bound an ipfs_* name at import time
    gets its own patch; nothing in this test ever opens a socket."""
    store: dict[str, bytes] = {}

    def add(data: bytes) -> str:
        cid = _fake_cid(data)
        store[cid] = data
        return cid

    def get(cid: str) -> bytes:
        return store[cid]

    def open_local(cid, *, range_header=None):
        if cid not in store:
            raise ipfs_mod.IPFSNotLocal(cid)
        return FakeUpstream(store[cid])

    monkeypatch.setattr(posts_mod, "ipfs_add_bytes", add)
    monkeypatch.setattr(posts_mod, "ipfs_get_bytes", get)
    monkeypatch.setattr(manifest_mod, "ipfs_add_bytes", add)
    monkeypatch.setattr(manifest_mod, "ipfs_unpin", lambda cid: True)
    monkeypatch.setattr(manifest_mod, "ipfs_repo_gc", lambda: [])
    monkeypatch.setattr(manifest_mod, "request_publish", lambda: None)
    monkeypatch.setattr(rewrap_mod, "ipfs_get_bytes", get)
    monkeypatch.setattr(ipfs_mod, "ipfs_open_local_stream", open_local)
    return store


def _asgi(method: str, url: str, headers: dict, body: bytes):
    """One request through the real app, with a body. Returns a response shim
    quacking like requests.Response for the parts the CLI touches."""
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "https",
        "path": parts.path, "raw_path": parts.path.encode(), "root_path": "",
        "query_string": parts.query.encode(),
        "headers": [(k.lower().encode(), str(v).encode()) for k, v in headers.items()]
                   + [(b"content-length", str(len(body)).encode())],
        "client": ("127.0.0.1", 50000), "server": ("testserver", 8443),
    }
    messages: list[dict] = []

    async def run():
        sent = False
        done = asyncio.Event()

        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            await done.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            messages.append(message)
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                done.set()

        await app(scope, receive, send)

    asyncio.run(run())
    start = next(m for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")

    class Resp:
        status_code = start["status"]
        headers = {k.decode().lower(): v.decode() for k, v in start["headers"]}
        content = raw
        text = raw.decode("utf-8", "replace")

        def json(self):
            return json.loads(raw)

        def raise_for_status(self):
            if self.status_code >= 400:
                raise cli.requests.exceptions.HTTPError(str(self.status_code))

    return Resp()


class FakeSession:
    """Stands in for requests.Session; routes every call into the ASGI app.
    Records each request so tests can inspect the exact wire bytes."""
    log: list[dict] = []

    def __init__(self):
        self.verify = True

    def request(self, method, url, data=None, headers=None, timeout=None, stream=False):
        body = data or b""
        FakeSession.log.append({"method": method, "url": url, "headers": dict(headers or {}), "body": body})
        return _asgi(method, url, headers or {}, body)

    def get(self, url, timeout=None, **kw):
        return self.request("GET", url, headers=kw.get("headers"))

    def post(self, url, json=None, timeout=None, **kw):
        body = json_dumps(json)
        return self.request("POST", url, data=body, headers={"Content-Type": "application/json"})


def json_dumps(obj) -> bytes:
    return json.dumps(obj).encode() if obj is not None else b""


@pytest.fixture
def paired_cli(tmp_path, monkeypatch, fake_ipfs):
    """A CLI config for a device paired as one of the OWNER's delegates, with
    the CLI's network layer redirected into the in-process app."""
    ident = get_identity()
    mlkem_pk, mlkem_sk = pqcrypto.generate_mlkem_keypair()
    mldsa_pk, mldsa_sk = pqcrypto.generate_mldsa_keypair()
    device_uid = "cli-test-device"
    add_follower_device(ident.uid, device_uid, mlkem_public_key=mlkem_pk.hex(),
                        mldsa_public_key=mldsa_pk.hex(), alias=None, allowed="Allowed")
    monkeypatch.setenv("CIPHER_CLI_HOME", str(tmp_path / "cli-home"))
    save_config({
        "station_url": "https://station.test:8443",
        "verify_tls": True,
        "station_uid": ident.uid,
        "station_mlkem_public_key": ident.mlkem_pub_hex,
        "device_uid": device_uid,
        "mlkem_public_key": mlkem_pk.hex(),
        "mlkem_secret_key": mlkem_sk.hex(),
        "mldsa_public_key": mldsa_pk.hex(),
        "mldsa_secret_key": mldsa_sk.hex(),
    })
    FakeSession.log.clear()
    monkeypatch.setattr(cli, "_session", lambda cfg: FakeSession())
    monkeypatch.chdir(tmp_path)
    return {"uid": ident.uid, "device_uid": device_uid, "home": tmp_path}


class Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_post_list_get_delete_round_trip(paired_cli, fake_ipfs, capsys):
    secret = b"the quick brown fox " * 200
    src = paired_cli["home"] / "src" / "holiday photo.jpg"
    src.parent.mkdir()
    src.write_bytes(secret)

    # post — encrypted client-side, signed, accepted by the real /post route
    cli.cmd_post(Args(file=str(src), folder="Trips", audience="self",
                      audience_uids=None, filename=None, client="cli"))
    cid = capsys.readouterr().out.strip()
    assert re.fullmatch(r"[A-Za-z0-9]{46,128}", cid)

    post_req = next(r for r in FakeSession.log if r["url"].endswith("/post"))
    assert secret not in post_req["body"], "content must be encrypted on the wire"
    assert b"holiday photo.jpg" not in post_req["body"], "filename must not leak in plaintext"
    assert f'filename="{BLOB_FILENAME}"'.encode() in post_req["body"]
    assert b"Trips" not in post_req["body"], "tags live only inside encrypted metadata"
    assert secret not in fake_ipfs[cid]

    # list — manifest via /content, sym key via /rewrap, metadata decrypted locally
    cli.cmd_list(Args())
    out = capsys.readouterr().out
    assert cid in out and "holiday photo.jpg" in out and "Trips" in out
    assert any(r["url"].endswith("/rewrap") for r in FakeSession.log)

    # get — bytes round-trip exactly, written under the decrypted name in cwd
    cli.cmd_get(Args(cid=cid, output=None))
    written = paired_cli["home"] / "holiday photo.jpg"
    assert written.read_bytes() == secret
    # ...and a second get refuses to clobber it
    with pytest.raises(SystemExit):
        cli.cmd_get(Args(cid=cid, output=None))

    # delete — gone from the manifest, list is empty again
    cli.cmd_delete(Args(cid=cid))
    capsys.readouterr()
    cli.cmd_list(Args())
    assert capsys.readouterr().out.strip() == "No posts."


def test_public_post_is_plaintext_with_plaintext_metadata(paired_cli, fake_ipfs, capsys):
    src = paired_cli["home"] / "readme.txt"
    src.write_bytes(b"anyone may read this")
    cli.cmd_post(Args(file=str(src), folder=None, audience="public",
                      audience_uids=None, filename=None, client="cli"))
    cid = capsys.readouterr().out.strip()
    assert fake_ipfs[cid] == b"anyone may read this"
    cli.cmd_list(Args())
    assert "readme.txt" in capsys.readouterr().out


def test_list_on_fresh_station_is_empty_not_an_error(paired_cli, capsys):
    cli.cmd_list(Args())
    assert capsys.readouterr().out.strip() == "No posts."


def test_tampered_signature_is_rejected_by_the_real_server(paired_cli, monkeypatch, capsys):
    real = cli.build_auth_headers

    def forged(cfg, method, path, body):
        h = real(cfg, method, path, body)
        h["x-cipher-body-sha256"] = hashlib.sha256(b"other").hexdigest()
        return h

    monkeypatch.setattr(cli, "build_auth_headers", forged)
    with pytest.raises(SystemExit) as ex:
        cli.cmd_delete(Args(cid="Qm" + "a" * 44))
    assert "HTTP 401" in str(ex.value)


def test_http_error_detail_uses_error_key_too(paired_cli, monkeypatch):
    """The upload-size middleware answers {"error": ...}, not {"detail": ...}."""
    class Big:
        status_code = 413
        text = ""

        def json(self):
            return {"error": "Request too large (max 100 bytes)"}

    monkeypatch.setattr(cli, "_session", lambda cfg: type("S", (), {"request": lambda *a, **k: Big()})())
    with pytest.raises(SystemExit) as ex:
        cli.signed_request(cli.load_config(), "POST", "/post", b"x")
    assert "Request too large" in str(ex.value)
