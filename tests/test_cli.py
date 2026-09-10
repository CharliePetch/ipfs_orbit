# tests/test_cli.py
"""
Tests for the cipher_cli client: envelope/metadata construction and signed
request headers. No running station required — the station side of each
exchange is exercised directly with the same primitives the server uses.
"""

import base64
import hashlib
import json

import pytest
from nacl.secret import SecretBox

from cipher_station import pqcrypto
from cipher_cli.cli import (
    build_auth_headers,
    build_encrypted_post,
    build_metadata,
    decrypt_metadata,
    encode_multipart,
)


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

    # Station-side: decapsulate the envelope
    sym = pqcrypto.open_key(station_sec, self_envelope)
    assert sym is not None and len(sym) == SecretBox.KEY_SIZE

    # Content decrypts back to the original bytes
    assert SecretBox(sym).decrypt(blob) == plaintext

    # Metadata decrypts to the original dict
    assert decrypt_metadata(metadata_hex, sym) == metadata

    # Blob and metadata are NOT plaintext on the wire
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
    assert isinstance(md["created_at"], int)


def test_auth_headers_verify_like_the_server():
    """Rebuild the server's canonical string from the headers and verify the
    ML-DSA signature with the device public key — mirrors auth.require_delegate."""
    mldsa_pub, mldsa_sec = pqcrypto.generate_mldsa_keypair()
    cfg = {
        "station_uid": "owner-uid",
        "device_uid": "device-1",
        "mldsa_secret_key": mldsa_sec.hex(),
    }
    body = b'{"post_cid":"Qmabc"}'
    headers = build_auth_headers(cfg, "POST", "/post/delete", body)

    assert headers["x-cipher-body-sha256"] == hashlib.sha256(body).hexdigest()

    canonical = "\n".join([
        "POST", "/post/delete", "owner-uid", "device-1",
        headers["x-cipher-ts"], headers["x-cipher-nonce"],
        headers["x-cipher-body-sha256"],
    ]).encode("utf-8")
    sig = base64.b64decode(headers["x-cipher-sig"])
    assert pqcrypto.verify(mldsa_pub, canonical, sig)
    # Tampered canonical string must not verify
    assert not pqcrypto.verify(mldsa_pub, canonical + b"x", sig)


def test_encode_multipart_parses():
    """The hand-rolled multipart body must be parseable and preserve bytes."""
    payload = bytes(range(256))
    body, ctype = encode_multipart(
        {"client": "cli", "audience_mode": "self"}, "file", "blob.bin", payload)
    assert ctype.startswith("multipart/form-data; boundary=")
    boundary = ctype.split("boundary=")[1]
    assert f"--{boundary}".encode() in body
    assert payload in body
    assert b'name="client"\r\n\r\ncli\r\n' in body
    assert b'name="audience_mode"\r\n\r\nself\r\n' in body
