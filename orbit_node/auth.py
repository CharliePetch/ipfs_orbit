# orbit_node/auth.py
import hmac
import hashlib
import logging
import time
from functools import lru_cache
from fastapi import Header, HTTPException, Request
from nacl import bindings

from orbit_node.identity import get_identity
from orbit_node.followers import list_follower_devices
from orbit_node.database import get_db

logger = logging.getLogger(__name__)

MAX_SKEW_SECONDS = 60
NONCE_TTL_SECONDS = 60 * 60 * 24  # keep for 24h


def _derive_auth_key(station_sk_bytes: bytes, device_pk_bytes: bytes) -> bytes:
    """
    X25519 -> shared secret -> domain-separated auth key.
    Must match your client (blake2b person=b"orbit-auth").
    """
    shared = bindings.crypto_scalarmult(station_sk_bytes, device_pk_bytes)
    return hashlib.blake2b(shared, digest_size=32, person=b"orbit-auth").digest()


def _canonical(method: str, path: str, uid: str, device_uid: str, ts: str, nonce: str, body_sha256: str) -> bytes:
    """
    Must match iOS/client exactly:
      METHOD\nPATH\nUID\nDEVICE_UID\nTS\nNONCE\nBODY_SHA256
    """
    s = "\n".join([method.upper(), path, uid, device_uid, ts, nonce, body_sha256])
    return s.encode("utf-8")


def _nonce_seen(uid: str, device_uid: str, nonce: str) -> bool:
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT 1 FROM auth_nonces WHERE uid=? AND device_uid=? AND nonce=?",
        (uid, device_uid, nonce),
    )
    return cur.fetchone() is not None


def _remember_nonce(uid: str, device_uid: str, nonce: str, ts: int):
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO auth_nonces(uid, device_uid, nonce, ts) VALUES(?,?,?,?)",
        (uid, device_uid, nonce, ts),
    )
    db.commit()


def _cleanup_nonces(now_ts: int):
    cutoff = now_ts - NONCE_TTL_SECONDS
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM auth_nonces WHERE ts < ?", (cutoff,))
    db.commit()


@lru_cache(maxsize=1)
def _station_sk_bytes() -> bytes:
    station_sk, _station_pk_hex, _pub_json = get_identity()
    sk_bytes = station_sk.encode()
    if len(sk_bytes) != 32:
        raise RuntimeError(f"Station private key must be 32 bytes, got {len(sk_bytes)}")
    return sk_bytes


async def require_delegate(
    request: Request,
    x_orbit_uid: str = Header(..., alias="x-orbit-uid"),
    x_orbit_device: str = Header(..., alias="x-orbit-device"),
    x_orbit_ts: str = Header(..., alias="x-orbit-ts"),
    x_orbit_nonce: str = Header(..., alias="x-orbit-nonce"),
    x_orbit_body_sha256: str = Header(..., alias="x-orbit-body-sha256"),
    x_orbit_hmac: str = Header(..., alias="x-orbit-hmac"),
):
    # 1) time window
    try:
        ts_i = int(x_orbit_ts)
    except Exception:
        raise HTTPException(401, "bad timestamp")

    now = int(time.time())
    if abs(now - ts_i) > MAX_SKEW_SECONDS:
        raise HTTPException(401, "stale request")

    # optional cleanup occasionally
    if (now % 100) == 0:
        try:
            _cleanup_nonces(now)
        except Exception:
            pass

    # 2) device must be authorized (+ Allowed)
    devices = list_follower_devices(x_orbit_uid)
    dev = next(
        (d for d in devices if d.get("device_uid") == x_orbit_device and d.get("allowed") == "Allowed"),
        None,
    )
    if not dev:
        raise HTTPException(403, "device not authorized")

    # 3) replay protection (store AFTER auth succeeds)
    if _nonce_seen(x_orbit_uid, x_orbit_device, x_orbit_nonce):
        raise HTTPException(401, "replay")

    # 4) body-hash check WITHOUT consuming stream
    # If you add a middleware that sets request.state.raw_body_sha256, we'll enforce it.
    cached_sha = getattr(request.state, "raw_body_sha256", None)
    if cached_sha is not None:
        if not hmac.compare_digest(cached_sha, x_orbit_body_sha256.lower()):
            raise HTTPException(401, "bad body hash")
    # else: skip (assumes TLS / trusted path); still included in signed canonical string.

    # 5) verify HMAC
    try:
        device_pk_bytes = bytes.fromhex(dev["public_key"])
    except Exception:
        raise HTTPException(401, "bad device public key")

    if len(device_pk_bytes) != 32:
        raise HTTPException(401, "bad device public key length")

    key = _derive_auth_key(_station_sk_bytes(), device_pk_bytes)
    msg = _canonical(
        request.method,
        request.url.path,
        x_orbit_uid,
        x_orbit_device,
        x_orbit_ts,
        x_orbit_nonce,
        x_orbit_body_sha256.lower(),
    )
    expected = hmac.new(key, msg, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected, x_orbit_hmac.lower()):
        raise HTTPException(401, "bad auth")

    # 6) remember nonce only after successful verification
    _remember_nonce(x_orbit_uid, x_orbit_device, x_orbit_nonce, ts_i)

    return {"uid": x_orbit_uid, "device_uid": x_orbit_device}
