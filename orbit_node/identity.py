# orbit_node/identity.py

import json
import logging
from pathlib import Path
from nacl.public import PrivateKey
from nacl.encoding import HexEncoder
import uuid

from orbit_node.config import KEYS_DIR, PUBLIC_JSON_PATH, ORBIT_PASSWORD, ensure_directories

logger = logging.getLogger(__name__)

PRIVATE_KEY_PATH = KEYS_DIR / "private.bin"

# Cached identity tuple: (private_key, public_key_hex, public_json_dict)
_cached_identity = None


# -----------------------------------------------------------
# Internal key file helpers
# -----------------------------------------------------------

def _write_private_key(sk: PrivateKey):
    """
    Writes 64 bytes:
    - first 32 = private key
    - next 32 = public key
    """
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    PRIVATE_KEY_PATH.write_bytes(sk.encode() + sk.public_key.encode())


def _read_private_key() -> PrivateKey:
    raw = PRIVATE_KEY_PATH.read_bytes()
    if len(raw) != 64:
        raise Exception(f"private.bin is {len(raw)} bytes, expected 64.")
    return PrivateKey(raw[:32])


def _load_or_create_public_json(pub_hex: str) -> dict:
    """
    Ensures public.json exists and matches the real public key.
    """
    if PUBLIC_JSON_PATH.exists():
        obj = json.loads(PUBLIC_JSON_PATH.read_text())
    else:
        obj = {
            "uid": None,
            "public_key": pub_hex,
            "endpoint": None,
            "manifest_pointer": None,
        }

    obj["public_key"] = pub_hex  # force consistency
    PUBLIC_JSON_PATH.write_text(json.dumps(obj, indent=2))
    return obj


# -----------------------------------------------------------
# Cached identity accessor (used by all server modules)
# -----------------------------------------------------------

def get_identity():
    """
    Returns the cached (private_key, public_key_hex, public_json) tuple.
    Loads from disk on first call, then caches in memory.
    """
    global _cached_identity
    if _cached_identity is None:
        _cached_identity = load_identity(password=ORBIT_PASSWORD or None)
        logger.info("Identity loaded and cached")
    return _cached_identity


# -----------------------------------------------------------
# Required API functions
# -----------------------------------------------------------

def load_identity(password: str | None = None):
    """
    Returns (private_key_obj, public_key_hex, public_json_dict)
    """
    ensure_directories()

    # Load or create keypair
    if PRIVATE_KEY_PATH.exists():
        sk = _read_private_key()
    else:
        public_json, _uuid, pk_hex, sk = bootstrap_identity()

    pk_hex = sk.public_key.encode(encoder=HexEncoder).decode()
    public_json = _load_or_create_public_json(pk_hex)

    return sk, pk_hex, public_json


def load_public_identity():
    """
    Used by profile.py — returns the JSON dict only.
    """
    ensure_directories()

    if PUBLIC_JSON_PATH.exists():
        return json.loads(PUBLIC_JSON_PATH.read_text())

    # If missing, generate a fresh identity
    sk = PrivateKey.generate()
    _write_private_key(sk)

    pk_hex = sk.public_key.encode(encoder=HexEncoder).decode()
    return _load_or_create_public_json(pk_hex)


def bootstrap_identity(password: str | None = None):
    """
    Generates:
    - UUIDv4 identity
    - keypair
    - minimal public.json with encrypted social graph pointers
    """

    ensure_directories()

    sk = PrivateKey.generate()
    _write_private_key(sk)

    pk_hex = sk.public_key.encode(encoder=HexEncoder).decode()

    uid = str(uuid.uuid4())

    public_json = {
        "alias": None,
        "uid": uid,
        "public_key": pk_hex,
        "endpoint": None,
        "manifest_pointer": None,

        # encrypted social graph pointers (initially empty)
        "followers_cid": None,
        "following_cid": None,
        "follow_decoder_envelopes_cid": None
    }

    PUBLIC_JSON_PATH.write_text(json.dumps(public_json, indent=2))
    logger.info(f"Identity bootstrapped: uid={uid}")
    return public_json, uuid, pk_hex, sk
