#!/usr/bin/env python3
# cipher_cli/cli.py
"""
Cipher Station CLI client.

Commands
--------
  cipher pair --station https://station:8443 [--insecure] [--name alias]
  cipher post FILE [--folder NAME] [--audience self|all|specific|public]
                   [--audience-uids UID,UID] [--filename NAME]
  cipher list
  cipher get CID [-o OUT]
  cipher delete CID

Protocol notes (see PROTOCOL.md)
--------------------------------
* Pairing: the CLI generates its own ML-KEM-768 (content) and ML-DSA-65
  (auth) keypairs plus a device_uid, registers them via POST /delegate/start,
  and confirms with the 6-digit PIN shown on the station (/delegate/confirm).
  The device is added under the station OWNER's uid, so it can drive
  owner-only endpoints.
* Auth: every owner endpoint request carries signed headers. The canonical
  string is METHOD\nPATH\nUID\nDEVICE_UID\nTS\nNONCE\nBODY_SHA256 signed with
  the device ML-DSA-65 secret key (x-cipher-* headers; 60s max skew,
  single-use nonces).
* Posting: content is encrypted client-side with a fresh 32-byte SecretBox
  key; metadata is SecretBox(sym).encrypt(json).hex(); the sym key is
  ML-KEM-sealed to the STATION's public key as self_envelope. The station
  never sees plaintext.
* Reading: post envelopes are keyed by UID, and the owner-uid envelope is
  sealed to the STATION's ML-KEM key — a delegate device cannot open it
  directly. The CLI therefore requests POST /rewrap, and the station returns
  an envelope re-sealed to this device's ML-KEM public key.

State lives in $CIPHER_CLI_HOME (default ~/.config/cipher-cli/) as
config.json (0600, created with that mode — never briefly world-readable)
holding the device keypairs, device_uid, station URL, station uid and station
ML-KEM public key.

TLS: `pair --insecure` is for self-signed stations. It does NOT mean "trust
anything forever": the station's certificate fingerprint is pinned at pairing
(trust-on-first-use) and every later command refuses to talk to a station
whose certificate has changed. Without that, a MITM at pairing could hand us
a substitute ML-KEM key and read every future post's symmetric key.
"""

import argparse
import base64
import hashlib
import json
import mimetypes
import os
import ssl
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import requests
import urllib3
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random

from cipher_station import pqcrypto
from cipher_cli import __version__

CLIENT_NAME = "cli"


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def config_home() -> Path:
    env = os.environ.get("CIPHER_CLI_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".config" / "cipher-cli"


def config_path() -> Path:
    return config_home() / "config.json"


def load_config() -> dict:
    p = config_path()
    if not p.exists():
        sys.exit(f"Not paired yet (no {p}). Run: cipher pair --station <URL>")
    return json.loads(p.read_text())


def save_config(cfg: dict) -> None:
    """
    Write config.json holding secret keys. Created 0600 from the first byte:
    a plain write_text() would create it under the umask (usually 0644) and
    only then chmod, leaving a window where the keys are world-readable.
    Written to a sibling temp file and renamed so a crash never leaves a
    half-written config behind.
    """
    home = config_home()
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(home, 0o700)
    p = config_path()
    tmp = p.with_name(p.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(cfg, indent=2))
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Signed-request auth (cipher_station/auth.py counterpart)
# ---------------------------------------------------------------------------

def build_auth_headers(cfg: dict, method: str, path: str, body: bytes) -> dict:
    """Signed x-cipher-* headers for one request over `body`."""
    ts = str(int(time.time()))
    nonce = uuid.uuid4().hex  # PROTOCOL.md section 12.3: hex nonce
    body_sha = hashlib.sha256(body).hexdigest()
    canonical = "\n".join([
        method.upper(), path, cfg["station_uid"], cfg["device_uid"],
        ts, nonce, body_sha,
    ]).encode("utf-8")
    sig = pqcrypto.sign(bytes.fromhex(cfg["mldsa_secret_key"]), canonical)
    return {
        "x-cipher-uid": cfg["station_uid"],
        "x-cipher-device": cfg["device_uid"],
        "x-cipher-ts": ts,
        "x-cipher-nonce": nonce,
        "x-cipher-body-sha256": body_sha,
        "x-cipher-sig": base64.b64encode(sig).decode("ascii"),
    }


def tls_fingerprint(station_url: str) -> str:
    """SHA-256 (hex) of the DER certificate the station presents right now."""
    parts = urlsplit(station_url)
    host, port = parts.hostname, parts.port or 443
    if not host:
        sys.exit(f"Bad station URL: {station_url}")
    pem = ssl.get_server_certificate((host, port))
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest()


def check_pinned_cert(cfg: dict) -> None:
    """
    Trust-on-first-use for --insecure stations: the certificate seen at pairing
    is the only one we will ever talk to. A changed fingerprint is treated as an
    attack, not an inconvenience — re-pair deliberately if the station's cert
    really did change.
    """
    if cfg.get("verify_tls", True):
        return
    pinned = cfg.get("tls_fingerprint_sha256")
    if not pinned:
        sys.exit("Config has verify_tls=false but no pinned certificate. Re-run: cipher pair --insecure --force")
    seen = tls_fingerprint(cfg["station_url"])
    if seen != pinned:
        sys.exit(
            "REFUSING TO CONNECT: the station's TLS certificate has changed.\n"
            f"  pinned: {pinned}\n"
            f"  seen:   {seen}\n"
            "If you replaced the station's certificate on purpose, re-pair with\n"
            "'cipher pair --insecure --force'. Otherwise someone may be intercepting\n"
            "the connection."
        )


def _session(cfg: dict) -> requests.Session:
    s = requests.Session()
    if not cfg.get("verify_tls", True):
        check_pinned_cert(cfg)
        s.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return s


def signed_request(cfg: dict, method: str, path: str, body: bytes = b"",
                   content_type: str | None = None, stream: bool = False) -> requests.Response:
    headers = build_auth_headers(cfg, method, path, body)
    if content_type:
        headers["Content-Type"] = content_type
    s = _session(cfg)
    url = cfg["station_url"].rstrip("/") + path
    resp = s.request(method, url, data=body if body else None,
                     headers=headers, timeout=120, stream=stream)
    if resp.status_code >= 400:
        try:
            payload = resp.json()
            detail = payload.get("detail") or payload.get("error") or resp.text[:200]
        except Exception:
            detail = resp.text[:200]
        sys.exit(f"{method} {path} failed: HTTP {resp.status_code}: {detail}")
    return resp


def signed_json(cfg: dict, method: str, path: str, obj: dict | None = None) -> dict:
    body = b""
    ctype = None
    if obj is not None:
        body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        ctype = "application/json"
    return signed_request(cfg, method, path, body, ctype).json()


# ---------------------------------------------------------------------------
# Multipart encoding (built by hand so the exact body bytes can be signed)
# ---------------------------------------------------------------------------

BLOB_FILENAME = "blob"


def _mp_token(value: str) -> str:
    """A value safe to interpolate into a multipart header (no quotes/CRLF)."""
    return "".join(c for c in value if c not in '"\r\n')


def encode_multipart(fields: dict[str, str], file_field: str,
                     filename: str, file_bytes: bytes) -> tuple[bytes, str]:
    """
    Hand-rolled multipart/form-data so the exact wire bytes can be hashed into
    the signature. `filename` goes into the Content-Disposition header, which
    is NOT encrypted — callers must pass BLOB_FILENAME (not the user's real
    filename, which lives only inside the encrypted metadata).
    """
    boundary = "----cipher-cli-" + uuid.uuid4().hex
    filename = _mp_token(filename)
    parts = []
    for name, value in fields.items():
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{_mp_token(name)}"\r\n\r\n'
            f"{value}\r\n".encode("utf-8")
        )
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n".encode("utf-8")
        + file_bytes + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode("utf-8"))
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


# ---------------------------------------------------------------------------
# Post construction (PROTOCOL.md section 7.1)
# ---------------------------------------------------------------------------

def build_encrypted_post(file_bytes: bytes, metadata: dict,
                         station_mlkem_pub_hex: str) -> tuple[bytes, str, str]:
    """
    Client-side encryption for a non-public post.

    Returns (encrypted_blob, metadata_hex, self_envelope_hex):
      * encrypted_blob : SecretBox(sym_key) ciphertext of the file
      * metadata_hex   : SecretBox(sym_key) ciphertext of compact JSON metadata
      * self_envelope  : sym_key ML-KEM-sealed to the station's public key
    """
    sym_key = nacl_random(SecretBox.KEY_SIZE)
    box = SecretBox(sym_key)
    blob = bytes(box.encrypt(file_bytes))
    meta_raw = json.dumps(metadata, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    metadata_hex = bytes(box.encrypt(meta_raw)).hex()
    self_envelope = pqcrypto.seal_key(sym_key, station_mlkem_pub_hex)
    if not self_envelope:
        raise ValueError("failed to seal sym key to station ML-KEM public key")
    return blob, metadata_hex, self_envelope


def build_metadata(file_path: Path, *, folder: str | None, filename: str | None,
                   client: str = CLIENT_NAME) -> dict:
    name = filename or file_path.name
    mime, _ = mimetypes.guess_type(name)
    st = file_path.stat()
    # st_ctime is inode-change time on POSIX, not creation; prefer the real
    # birth time where the platform exposes it, else fall back to mtime.
    born = getattr(st, "st_birthtime", None) or st.st_mtime
    iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))  # noqa: E731
    return {
        "mime_type": mime or "application/octet-stream",
        "filename": name,
        "size_bytes": st.st_size,
        "extension": Path(name).suffix.lstrip(".").lower(),
        "tags": [folder] if folder else [],
        "created_at": iso(time.time()),
        "file_created_at": iso(born),
        "file_modified_at": iso(st.st_mtime),
        "client": client,
        "client_version": __version__,
    }


# ---------------------------------------------------------------------------
# Manifest / envelope reading
# ---------------------------------------------------------------------------

def fetch_manifest(cfg: dict) -> dict:
    s = _session(cfg)
    prof = s.get(cfg["station_url"].rstrip("/") + "/profile", timeout=30)
    prof.raise_for_status()
    manifest_cid = prof.json().get("manifest_cid") or prof.json().get("manifest_pointer")
    if not manifest_cid:
        return {"clients": {}}  # nothing published yet
    resp = signed_request(cfg, "GET", f"/content/{manifest_cid}")
    return json.loads(resp.content.decode("utf-8"))


def iter_posts(manifest: dict):
    for client_name, bucket in (manifest.get("clients") or {}).items():
        if isinstance(bucket, dict):
            for entry in bucket.get("posts") or []:
                if isinstance(entry, dict):
                    yield client_name, entry


def recover_sym_key(cfg: dict, entry: dict) -> bytes | None:
    """
    Recover a post's symmetric key on this delegate device.

    The envelopes doc ({v, post_cid, envelopes}) keys envelopes by UID and the
    owner-uid entry is sealed to the STATION's ML-KEM key, which this device
    cannot open. Ask the station to rewrap it to our device key instead.
    """
    post_cid = entry.get("post_cid")
    envelopes_cid = entry.get("envelopes_cid")
    if not post_cid or not envelopes_cid:
        return None
    result = signed_json(cfg, "POST", "/rewrap", {
        "uid": cfg["station_uid"],
        "device_uid": cfg["device_uid"],
        "post_cid": post_cid,
        "envelopes_cid": envelopes_cid,
    })
    envelope_hex = (result.get("result") or {}).get("envelope")
    if not envelope_hex:
        return None
    sym = pqcrypto.open_key(bytes.fromhex(cfg["mlkem_secret_key"]), envelope_hex)
    if sym and len(sym) == SecretBox.KEY_SIZE:
        return sym
    return None


def decrypt_metadata(metadata_hex: str, sym_key: bytes) -> dict | None:
    try:
        raw = SecretBox(sym_key).decrypt(bytes.fromhex(metadata_hex))
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_pair(args) -> None:
    station = args.station.rstrip("/")
    verify_tls = not args.insecure

    if config_path().exists() and not args.force:
        sys.exit(f"{config_path()} already exists (this device is paired). "
                 "Re-run with --force to replace that identity.")

    pinned = None
    if not verify_tls:
        pinned = tls_fingerprint(station)
        print("WARNING: --insecure: TLS certificate NOT verified against a CA.")
        print(f"         Pinning this station's certificate (sha256 {pinned[:16]}...).")
        print("         Future commands will refuse a station whose certificate changes.")

    print("Generating device identity (ML-KEM-768 + ML-DSA-65)...")
    mlkem_pk, mlkem_sk = pqcrypto.generate_mlkem_keypair()
    mldsa_pk, mldsa_sk = pqcrypto.generate_mldsa_keypair()
    device_uid = (args.name or "cipher-cli") + "-" + uuid.uuid4().hex[:12]

    s = requests.Session()
    if not verify_tls:
        s.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    r = s.post(f"{station}/delegate/start", json={
        "device_uid": device_uid,
        "mlkem_public_key": mlkem_pk.hex(),
        "mldsa_public_key": mldsa_pk.hex(),
    }, timeout=30)
    if r.status_code >= 400:
        sys.exit(f"/delegate/start failed: HTTP {r.status_code}: {r.text[:200]}")
    pairing_id = r.json()["pairing_id"]
    print(f"Pairing session started (id={pairing_id}).")
    print("A 6-digit PIN is now shown on the station (its logs/console).")

    pin = args.pin or input("Enter PIN: ").strip()
    r = s.post(f"{station}/delegate/confirm",
               json={"pairing_id": pairing_id, "pin": pin}, timeout=30)
    if r.status_code >= 400:
        sys.exit(f"/delegate/confirm failed: HTTP {r.status_code}: {r.text[:200]}")
    confirm = r.json()
    station_uid = confirm["uid"]

    prof = s.get(f"{station}/profile", timeout=30)
    prof.raise_for_status()
    profile = prof.json()

    save_config({
        "station_url": station,
        "verify_tls": verify_tls,
        "tls_fingerprint_sha256": pinned,
        "station_uid": station_uid,
        "station_mlkem_public_key": profile["mlkem_public_key"],
        "station_mldsa_public_key": profile.get("mldsa_public_key"),
        "device_uid": device_uid,
        "mlkem_public_key": mlkem_pk.hex(),
        "mlkem_secret_key": mlkem_sk.hex(),
        "mldsa_public_key": mldsa_pk.hex(),
        "mldsa_secret_key": mldsa_sk.hex(),
        "paired_at": int(time.time()),
    })
    print(f"Paired as device {device_uid} (owner uid {station_uid}).")
    print(f"Config saved to {config_path()}")


def cmd_post(args) -> None:
    cfg = load_config()
    file_path = Path(args.file)
    if not file_path.is_file():
        sys.exit(f"No such file: {file_path}")
    file_bytes = file_path.read_bytes()
    metadata = build_metadata(file_path, folder=args.folder, filename=args.filename,
                              client=args.client)

    fields = {"client": args.client, "audience_mode": args.audience}
    if args.audience == "specific":
        if not args.audience_uids:
            sys.exit("--audience specific requires --audience-uids")
        fields["audience_uids"] = json.dumps(
            [u.strip() for u in args.audience_uids.split(",") if u.strip()])

    if args.audience == "public":
        upload, meta_field = file_bytes, json.dumps(metadata, separators=(",", ":"))
    else:
        upload, meta_field, self_envelope = build_encrypted_post(
            file_bytes, metadata, cfg["station_mlkem_public_key"])
        fields["self_envelope"] = self_envelope
    fields["metadata"] = meta_field

    # The real filename stays inside the encrypted metadata; the multipart
    # header (which is plaintext on the wire) carries a fixed placeholder.
    body, ctype = encode_multipart(fields, "file", BLOB_FILENAME, upload)
    result = signed_request(cfg, "POST", "/post", body, ctype).json()
    print(result["cid"])


def cmd_list(args) -> None:
    cfg = load_config()
    manifest = fetch_manifest(cfg)
    rows = []
    for client_name, entry in iter_posts(manifest):
        cid = entry.get("post_cid", "?")
        meta = entry.get("metadata")
        if entry.get("encrypted") is False:
            md = meta if isinstance(meta, dict) else {}
        else:
            md = {}
            if isinstance(meta, str) and meta:
                sym = recover_sym_key(cfg, entry)
                if sym:
                    md = decrypt_metadata(meta, sym) or {}
        created = md.get("created_at") or entry.get("created_at")
        if isinstance(created, (int, float)):
            created = time.strftime("%Y-%m-%d %H:%M", time.localtime(created))
        rows.append([
            client_name, cid, str(md.get("filename", "?")),
            str(md.get("size_bytes", "?")),
            ",".join(str(t) for t in (md.get("tags") if isinstance(md.get("tags"), list) else [])),
            str(created or "?"),
        ])
    if not rows:
        print("No posts.")
        return
    headers = ["client", "cid", "filename", "size", "tags", "created_at"]
    widths = [max(len(headers[i]), *(len(r[i]) for r in rows)) for i in range(len(headers))]
    print(" | ".join(h.ljust(w) for h, w in zip(headers, widths)))
    print("-+-".join("-" * w for w in widths))
    for r in rows:
        print(" | ".join(c.ljust(w) for c, w in zip(r, widths)))


def cmd_get(args) -> None:
    cfg = load_config()
    manifest = fetch_manifest(cfg)
    entry = None
    for _, e in iter_posts(manifest):
        if e.get("post_cid") == args.cid:
            entry = e
            break
    if entry is None:
        sys.exit(f"Post {args.cid} not found in manifest")

    resp = signed_request(cfg, "GET", f"/content/{args.cid}")
    blob = resp.content

    if entry.get("encrypted") is False:
        plaintext, md = blob, entry.get("metadata") or {}
    else:
        sym = recover_sym_key(cfg, entry)
        if not sym:
            sys.exit("Could not recover post key (rewrap failed)")
        plaintext = SecretBox(sym).decrypt(blob)
        md = {}
        meta = entry.get("metadata")
        if isinstance(meta, str) and meta:
            md = decrypt_metadata(meta, sym) or {}

    out = output_path_for(md, args.cid, args.output)
    out.write_bytes(plaintext)
    print(f"Wrote {len(plaintext)} bytes to {out}")


def output_path_for(md: dict, cid: str, output: str | None) -> Path:
    """
    Where `get` writes. An explicit -o is honoured as given. Otherwise the
    name comes from DECRYPTED METADATA — which another paired device wrote —
    so it is reduced to a bare basename (no directories, no '..') inside the
    current directory, and an existing file is never overwritten silently.
    """
    if output:
        return Path(output)
    name = Path(str(md.get("filename") or "")).name
    if name in ("", ".", ".."):
        name = cid
    out = Path.cwd() / name
    if out.exists():
        sys.exit(f"Refusing to overwrite existing {out}; pass -o to choose a path")
    return out


def cmd_delete(args) -> None:
    cfg = load_config()
    result = signed_json(cfg, "POST", "/post/delete", {"post_cid": args.cid})
    print(json.dumps(result))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="cipher", description="Cipher Station CLI client")
    p.add_argument("--version", action="version", version=f"cipher-cli {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("pair", help="pair this device with a station (PIN ceremony)")
    sp.add_argument("--station", required=True, help="station base URL, e.g. https://host:8443")
    sp.add_argument("--insecure", "-k", action="store_true",
                    help="skip TLS certificate verification (self-signed stations)")
    sp.add_argument("--name", default="cipher-cli", help="device name prefix")
    sp.add_argument("--pin", help="6-digit PIN (otherwise prompted)")
    sp.add_argument("--force", action="store_true",
                    help="replace an existing pairing for this device")
    sp.set_defaults(func=cmd_pair)

    sp = sub.add_parser("post", help="encrypt and publish a file")
    sp.add_argument("file")
    sp.add_argument("--folder", help="folder label (stored as a metadata tag)")
    sp.add_argument("--audience", default="self",
                    choices=["self", "all", "specific", "public"])
    sp.add_argument("--audience-uids", help="comma-separated uids (audience=specific)")
    sp.add_argument("--filename", help="override stored filename")
    sp.add_argument("--client", default=CLIENT_NAME,
                    help="client bucket in the manifest (e.g. 'drive' to appear in drive apps; default: cli)")
    sp.set_defaults(func=cmd_post)

    sp = sub.add_parser("list", help="list posts with decrypted metadata")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("get", help="fetch and decrypt a post")
    sp.add_argument("cid")
    sp.add_argument("-o", "--output", help="output path (default: stored filename)")
    sp.set_defaults(func=cmd_get)

    sp = sub.add_parser("delete", help="remove a post from the manifest")
    sp.add_argument("cid")
    sp.set_defaults(func=cmd_delete)

    args = p.parse_args(argv)
    try:
        args.func(args)
    except requests.exceptions.SSLError as exc:
        sys.exit(f"TLS error talking to the station: {exc}\n"
                 "(self-signed certificate? pair with --insecure to pin it)")
    except requests.exceptions.RequestException as exc:
        sys.exit(f"Could not reach the station: {exc}")
    except CryptoError:
        sys.exit("Decryption failed: the post's key does not match its bytes")
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
