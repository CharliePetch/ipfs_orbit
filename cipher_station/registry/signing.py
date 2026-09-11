# cipher_station/registry/signing.py
"""
ML-DSA signed request payloads for the registry API.

Same design as the station's x-cipher-* device auth (cipher_station/auth.py):
a canonical newline-joined string is signed with the claimant's ML-DSA-65
identity key, verified with the pubkey carried in the claim (and pinned in
the claims row thereafter). Freshness = timestamp window + per-pubkey nonce
replay protection.

Canonical payload (client and server must match byte-for-byte):

    REGISTRY1\n{action}\n{name}\n{zone}\n{target}\n{record_type}\n{ts}\n{nonce}

``target``/``record_type`` are empty strings for actions that don't carry
them (release, heartbeat without a target update).
"""

from __future__ import annotations

import base64
import time

from cipher_station import pqcrypto

MAX_SKEW_SECONDS = 300  # registry calls cross the internet; be lenient


class SignatureError(Exception):
    pass


def canonical_payload(action: str, name: str, zone: str, target: str,
                      record_type: str, ts: str, nonce: str) -> bytes:
    return "\n".join([
        "REGISTRY1", action, name, zone, target or "", record_type or "",
        str(ts), nonce,
    ]).encode("utf-8")


def sign_payload(mldsa_sk: bytes, action: str, name: str, zone: str,
                 target: str = "", record_type: str = "", *,
                 ts: int | None = None, nonce: str | None = None) -> dict:
    """Build the signed fields a client sends: {ts, nonce, sig}."""
    import secrets
    ts = int(ts if ts is not None else time.time())
    nonce = nonce or secrets.token_hex(16)
    msg = canonical_payload(action, name, zone, target, record_type, str(ts), nonce)
    sig = pqcrypto.sign(mldsa_sk, msg)
    return {"ts": str(ts), "nonce": nonce,
            "sig": base64.b64encode(sig).decode()}


def verify_payload(pubkey_hex: str, action: str, name: str, zone: str,
                   target: str, record_type: str, ts: str, nonce: str,
                   sig_b64: str, *, nonce_seen=None, remember_nonce=None,
                   now: float | None = None) -> None:
    """Raise SignatureError on any failure; record the nonce on success."""
    try:
        ts_i = int(ts)
    except (TypeError, ValueError):
        raise SignatureError("bad timestamp")
    now_i = int(now if now is not None else time.time())
    if abs(now_i - ts_i) > MAX_SKEW_SECONDS:
        raise SignatureError("stale request")

    try:
        pub = bytes.fromhex(pubkey_hex)
    except (TypeError, ValueError):
        raise SignatureError("bad public key encoding")
    if len(pub) != pqcrypto.MLDSA_PUBLIC_BYTES:
        raise SignatureError("bad public key length")

    if not nonce or (nonce_seen is not None and nonce_seen(pubkey_hex, nonce)):
        raise SignatureError("replay")

    try:
        sig = base64.b64decode(sig_b64 or "", validate=True)
    except Exception:
        raise SignatureError("bad signature encoding")

    msg = canonical_payload(action, name, zone, target, record_type, str(ts_i), nonce)
    if not pqcrypto.verify(pub, msg, sig):
        raise SignatureError("bad signature")

    if remember_nonce is not None:
        remember_nonce(pubkey_hex, nonce, ts_i)
