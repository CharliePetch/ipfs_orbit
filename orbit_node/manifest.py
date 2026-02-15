# orbit_node/manifest.py

import json
import logging
from typing import Optional, Literal

from orbit_node.config import MANIFEST_DIR, PUBLIC_JSON_PATH

logger = logging.getLogger(__name__)
from orbit_node.storage import write_json
from orbit_node.envelopes import encrypt_key_for_follower
from orbit_node.ipfs_client import ipfs_add_bytes, publish_public_json_to_ipns

MANIFEST_PATH = MANIFEST_DIR / "manifest.json"

AudienceMode = Literal["self", "specific", "all"]


# -----------------------------
# Manifest shape helpers
# -----------------------------

def _normalize_manifest_shape(manifest: dict, *, default_client: Optional[str] = None) -> dict:
    """
    Normalize manifest to the new shape:

    {
      "clients": {
        "<client>": { "posts": [ ... ] }
      }
    }

    Back-compat:
      - If we load an old shape like {"client":"orbitstagram","posts":[...]}
        we migrate it in-memory to the new clients map.
      - If we load {"posts":[...]} with no client, we place it under default_client
        if provided, else under "default".
    """
    if not isinstance(manifest, dict):
        manifest = {}

    # Already new shape
    if isinstance(manifest.get("clients"), dict):
        # Ensure each client entry has "posts"
        for c, obj in manifest["clients"].items():
            if not isinstance(obj, dict):
                manifest["clients"][c] = {"posts": []}
                continue
            obj.setdefault("posts", [])
            if not isinstance(obj["posts"], list):
                obj["posts"] = []
        return manifest

    # Old shape: {"client": "...", "posts": [...]}
    old_posts = manifest.get("posts")
    if not isinstance(old_posts, list):
        old_posts = []

    old_client = manifest.get("client")
    if not isinstance(old_client, str) or not old_client.strip():
        old_client = (default_client or "default").strip()

    return {
        "clients": {
            old_client: {"posts": old_posts}
        }
    }


def load_manifest(*, client: Optional[str] = None) -> dict:
    """
    Loads manifest.json and normalizes to new shape.
    """
    if MANIFEST_PATH.exists():
        try:
            obj = json.loads(MANIFEST_PATH.read_text())
            return _normalize_manifest_shape(obj, default_client=client)
        except Exception as e:
            logger.error(f"Failed to load manifest.json: {e}")

    # default empty manifest in new shape
    return _normalize_manifest_shape({}, default_client=client)


def save_manifest(manifest: dict, *, client: Optional[str] = None):
    """
    Saves manifest in new shape only.
    """
    manifest = _normalize_manifest_shape(manifest, default_client=client)
    write_json(MANIFEST_PATH, manifest)


def _publish_manifest_to_ipfs(manifest: dict) -> str:
    manifest_bytes = json.dumps(manifest, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return ipfs_add_bytes(manifest_bytes)


def _update_public_json_manifest_pointer(manifest_cid: str) -> dict:
    try:
        public_obj = json.loads(PUBLIC_JSON_PATH.read_text()) if PUBLIC_JSON_PATH.exists() else {}
    except Exception as e:
        logger.error(f"Failed to load public.json (will recreate): {e}")
        public_obj = {}

    public_obj["manifest_pointer"] = manifest_cid
    write_json(PUBLIC_JSON_PATH, public_obj)

    # Republish to IPFS + IPNS so the decentralized pointer stays current
    publish_public_json_to_ipns()

    return public_obj


# -----------------------------
# Envelopes publishing
# -----------------------------

def _publish_envelopes_to_ipfs(post_cid: str, envelopes: dict) -> str:
    """
    Publish per-post envelopes JSON to IPFS, return CID.
    (This file can remain versioned independently from the manifest.)
    """
    payload = {
        "v": 1,
        "post_cid": post_cid,
        "envelopes": envelopes,  # uid -> sealed_box_hex
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return ipfs_add_bytes(raw)


# -----------------------------
# Public API
# -----------------------------

def add_post_to_manifest(
    post_cid: str,
    followers: list,
    sym_key: bytes,
    metadata: dict | None = None,          # kept for compat; not stored
    metadata_enc: str | None = None,
    *,
    audience_mode: AudienceMode = "all",
    audience_uids: Optional[list[str]] = None,
    client: Optional[str] = None,          # REQUIRED conceptually; defaults to "default" if missing
) -> dict:
    """
    New behavior:
      - Build per-follower envelopes dict (uid -> sealed_box_hex)
      - Publish envelopes JSON to IPFS -> envelopes_cid
      - Store envelopes_cid + envelopes_count + audience_mode (+ audience_uids) in the CLIENT's posts list
      - Publish manifest to IPFS + update public.json["manifest_pointer"]

    Manifest layout:
      {
        "clients": {
          "<client>": { "posts": [ ... ] }
        }
      }
    """
    if audience_mode not in ("self", "specific", "all"):
        raise ValueError(f"Invalid audience_mode: {audience_mode}")

    if audience_mode == "specific":
        if audience_uids is None:
            audience_uids = []
        if not isinstance(audience_uids, list) or not all(isinstance(u, str) and u.strip() for u in audience_uids):
            raise ValueError("audience_uids must be a list[str] (non-empty strings) when audience_mode='specific'")
        audience_uids = sorted({u.strip() for u in audience_uids})

    # Decide client bucket
    client_key = (client or "default").strip()
    if not client_key:
        client_key = "default"

    # -------------------------------------
    # 1) Build per-follower encrypted envelopes
    # -------------------------------------
    envelopes: dict[str, str] = {}  # uid -> sealed_box_hex

    for follower in followers:
        uid = follower.get("uid")
        public_key_hex = follower.get("public_key")

        if not uid or not isinstance(uid, str):
            continue

        if not isinstance(public_key_hex, str) or len(public_key_hex) != 64:
            logger.warning(f"Skipping follower {uid}: invalid pubkey")
            continue

        encrypted_hex = encrypt_key_for_follower(sym_key, public_key_hex)
        if encrypted_hex is None:
            logger.warning(f"Failed envelope for follower {uid}")
            continue

        envelopes[uid] = encrypted_hex

    # -------------------------------------
    # 2) Publish envelopes JSON to IPFS
    # -------------------------------------
    envelopes_cid = _publish_envelopes_to_ipfs(post_cid, envelopes)

    # -------------------------------------
    # 3) Build post entry
    # -------------------------------------
    entry: dict = {
        "post_cid": post_cid,
        "audience_mode": audience_mode,
        "envelopes_cid": envelopes_cid,
        "envelopes_count": len(envelopes),
    }

    if audience_mode == "specific":
        entry["audience_uids"] = audience_uids or []

    if metadata_enc is not None:
        if not isinstance(metadata_enc, str):
            raise ValueError("metadata_enc must be a hex string or None")
        entry["metadata"] = metadata_enc  # encrypted metadata

    # -------------------------------------
    # 4) Append + Save locally (new shape)
    # -------------------------------------
    manifest = load_manifest(client=client_key)
    manifest = _normalize_manifest_shape(manifest, default_client=client_key)

    manifest["clients"].setdefault(client_key, {"posts": []})
    if not isinstance(manifest["clients"][client_key], dict):
        manifest["clients"][client_key] = {"posts": []}

    manifest["clients"][client_key].setdefault("posts", [])
    if not isinstance(manifest["clients"][client_key]["posts"], list):
        manifest["clients"][client_key]["posts"] = []

    manifest["clients"][client_key]["posts"].append(entry)
    save_manifest(manifest, client=client_key)

    # -------------------------------------
    # 5) Publish manifest to IPFS + update public.json pointer
    # -------------------------------------
    manifest_cid = _publish_manifest_to_ipfs(manifest)
    _update_public_json_manifest_pointer(manifest_cid)

    return manifest
