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
config.json (0600) holding the device keypairs, device_uid, station URL,
station uid and station ML-KEM public key.
"""

import argparse
import base64
import hashlib
import json
import mimetypes
import os
import secrets
import sys
import time
import uuid
from pathlib import Path

import requests
import urllib3
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
    home = config_home()
    home.mkdir(parents=True, exist_ok=True)
    os.chmod(home, 0o700)
    p = config_path()
    p.write_text(json.dumps(cfg, indent=2))
    os.chmod(p, 0o600)


# ---------------------------------------------------------------------------
# Signed-request auth (cipher_station/auth.py counterpart)
# ---------------------------------------------------------------------------

def build_auth_headers(cfg: dict, method: str, path: str, body: bytes) -> dict:
    """Signed x-cipher-* headers for one request over `body`."""
    ts = str(int(time.time()))
    nonce = secrets.token_urlsafe(16)
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


def _session(cfg: dict) -> requests.Session:
    s = requests.Session()
    if not cfg.get("verify_tls", True):
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
            detail = resp.json().get("detail")
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

def encode_multipart(fields: dict[str, str], file_field: str,
                     filename: str, file_bytes: bytes) -> tuple[bytes, str]:
    boundary = "----cipher-cli-" + uuid.uuid4().hex
    parts = []
    for name, value in fields.items():
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
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
    return {
        "mime_type": mime or "application/octet-stream",
        "filename": name,
        "size_bytes": file_path.stat().st_size,
        "extension": file_path.suffix.lstrip(".").lower(),
        "tags": [folder] if folder else [],
        "created_at": int(time.time()),
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
        sys.exit("Station profile has no manifest_cid")
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

    body, ctype = encode_multipart(fields, "file", metadata["filename"], upload)
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
            str(md.get("size_bytes", "?")), ",".join(md.get("tags") or []),
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

    out = Path(args.output) if args.output else Path(md.get("filename") or args.cid)
    out.write_bytes(plaintext)
    print(f"Wrote {len(plaintext)} bytes to {out}")


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
    args.func(args)


if __name__ == "__main__":
    main()
