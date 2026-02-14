# orbit_node/inbox.py

import json
import logging
import os

from nacl.public import PrivateKey

from orbit_node.identity import get_identity

logger = logging.getLogger(__name__)
from orbit_node.followers import (
    add_follower,
    add_follower_device,
    list_follower_devices,
)
from orbit_node.envelopes import open_envelope, encrypt_key_for_follower
from orbit_node.ipfs_client import ipfs_get_bytes
from orbit_node.manifest import load_manifest
from orbit_node.rewrap_envelopes import rewrap_all_posts


# -----------------------------
# Safety knobs (dev-friendly)
# -----------------------------
MAX_DEVICES_PER_FOLLOWER = int(os.getenv("ORBIT_MAX_DEVICES_PER_FOLLOWER", "20"))
# If set to "0", disables expensive rewrap_all_posts on follow changes (handy in dev)
AUTO_REWRAP_ON_FOLLOW_CHANGE = os.getenv("ORBIT_AUTO_REWRAP_ON_FOLLOW_CHANGE", "1") != "0"


def _is_hex_32_bytes(s: str) -> bool:
    """True if s is 64 hex chars (32 bytes)."""
    if not isinstance(s, str) or len(s) != 64:
        return False
    try:
        bytes.fromhex(s)
        return True
    except Exception:
        return False


def _load_envelopes_map(envelopes_cid: str) -> dict:
    """
    Accept both:
      - {"envelopes": {...}}
      - {"v":1,"post_cid":"...","envelopes": {...}}
    """
    raw = ipfs_get_bytes(envelopes_cid)
    obj = json.loads(raw.decode("utf-8"))
    env = obj.get("envelopes", {})
    return env if isinstance(env, dict) else {}


def handle_rewrap_request(private_key: PrivateKey, message: dict):
    """
    Delegated device flow (UNCHANGED CONCEPTUALLY):
      • device says: "I am device X of user U"
      • node verifies device is authorized
      • node finds the post entry
      • node decrypts existing (user-level) envelope -> sym_key
      • node re-encrypts sym_key for this device's public key
      • node returns new envelope (for that device)
    """

    uid = message.get("uid")
    device_uid = message.get("device_uid")
    post_cid = message.get("post_cid")

    if not uid or not device_uid or not post_cid:
        return {"error": "uid, device_uid, and post_cid are required"}

    # ---------------------------------------------------
    # 1) Verify the device exists under that user
    # ---------------------------------------------------
    devices = list_follower_devices(uid)
    matching = next((d for d in devices if d["device_uid"] == device_uid), None)
    if not matching:
        return {"error": f"device {device_uid} not authorized for user {uid}"}

    device_pubkey_hex = matching["public_key"]

    # ---------------------------------------------------
    # 2) Locate the post entry in our manifest
    #     (support both old 'cid' and new 'post_cid')
    # ---------------------------------------------------
    manifest = load_manifest()
    posts = manifest.get("posts", [])

    entry = next(
        (p for p in posts if p.get("post_cid") == post_cid or p.get("cid") == post_cid),
        None
    )
    if not entry:
        return {"error": f"post_cid {post_cid} not found"}

    # ---------------------------------------------------
    # 3) Decrypt root envelope -> sym_key
    #     (support both new envelopes_cid and legacy inline envelopes)
    # ---------------------------------------------------
    root_envelope_hex = None

    if entry.get("envelopes_cid"):
        env_map = _load_envelopes_map(entry["envelopes_cid"])
        root_envelope_hex = env_map.get(uid)

    if root_envelope_hex is None and isinstance(entry.get("envelopes"), dict):
        root_envelope_hex = entry["envelopes"].get(uid)

    if not root_envelope_hex:
        return {"error": f"root envelope for uid {uid} not found in post"}

    sym_key = open_envelope(private_key, root_envelope_hex)
    if sym_key is None:
        return {"error": "failed to decrypt root envelope"}

    # ---------------------------------------------------
    # 4) Rewrap -> encrypt for device
    # ---------------------------------------------------
    new_envelope = encrypt_key_for_follower(sym_key, device_pubkey_hex)

    return {
        "status": "rewrap_ok",
        "uid": uid,
        "device_uid": device_uid,
        "post_cid": post_cid,
        "envelope": new_envelope,
    }


def process_inbox_message(private_key: PrivateKey, message: dict):
    """
    Handles inbox messages:
      - follow_request   (multi-device)
      - post_key_update  (future)
      - manifest_update  (future)

    Behavior:
      - when a follower is newly approved/added (or key changed),
        can trigger follower-envelope rewrap across all posts
        (updates envelopes_cid in each post + republishes manifest pointer)
    """

    mtype = message.get("type")

    # ---------------------------------------------------------
    # FOLLOW REQUEST (dev auto-accept)
    # ---------------------------------------------------------
    if mtype == "follow_request":
        follower_uid = message.get("uid")
        if not follower_uid:
            return {"error": "follow_request missing uid"}

        # ---------------------------------------------------------
        # SECURITY PATCH (minimal but critical):
        # Never allow follow_request to modify *our own* uid.
        # Prevents attacker from injecting themselves as a "device" under our uid.
        # ---------------------------------------------------------
        try:
            _sk, _pk, pub_json = get_identity()
            my_uid = pub_json["uid"]
            if follower_uid == my_uid:
                return {"error": "follow_request cannot target local uid"}
        except Exception as e:
            return {"error": f"identity_load_failed: {e}"}

        changed = False

        # Extract IPNS peer ID (permanent discovery address) if provided
        follower_ipns_id = message.get("ipns_id")

        # Case A: Multi-device follow request payload
        if "devices" in message and message["devices"] is not None:
            devices = message["devices"]
            if not isinstance(devices, list):
                return {"error": "devices field must be a list"}

            # Existing devices for this follower uid
            existing_rows = list_follower_devices(follower_uid)
            existing = {
                d["device_uid"]: d["public_key"]
                for d in existing_rows
                if d.get("device_uid")
            }

            # Hard cap per follower (prevents DB blow-up)
            # Allow rotations of existing devices, but block net-new additions past the cap.
            new_additions = 0

            for dev in devices:
                device_uid = dev.get("device_uid")
                public_key = dev.get("public_key")

                if not device_uid or not public_key:
                    return {"error": f"Malformed device entry: {dev}"}
                if not _is_hex_32_bytes(public_key):
                    return {"error": f"Malformed public_key for device {device_uid} (expected 64 hex chars)"}

                is_new = device_uid not in existing
                if is_new:
                    if (len(existing) + new_additions) >= MAX_DEVICES_PER_FOLLOWER:
                        return {"error": f"too many devices for follower (cap={MAX_DEVICES_PER_FOLLOWER})"}
                    new_additions += 1

                # Trigger if new device OR rotated key
                if existing.get(device_uid) != public_key:
                    changed = True

                add_follower_device(follower_uid, device_uid, public_key, ipns_id=follower_ipns_id)

            result = {"status": "follow_accepted_multi_device", "rewrap_triggered": changed}

        # Case B: Legacy single-device follow request
        else:
            follower_pk = message.get("public_key")
            if not follower_pk:
                return {"error": "follow_request missing public_key"}
            if not _is_hex_32_bytes(follower_pk):
                return {"error": "follow_request public_key must be 64 hex chars"}

            existing_devices = list_follower_devices(follower_uid)

            # Hard cap (legacy path): if already at cap, don't add new entries
            # (rotations are handled better in multi-device path)
            if len(existing_devices) >= MAX_DEVICES_PER_FOLLOWER:
                return {"error": f"too many devices for follower (cap={MAX_DEVICES_PER_FOLLOWER})"}

            # Trigger if first time we've seen them OR key changed
            if not existing_devices:
                changed = True
            else:
                if all(d.get("public_key") != follower_pk for d in existing_devices):
                    changed = True

            add_follower_device(follower_uid, device_uid=follower_uid, public_key=follower_pk, ipns_id=follower_ipns_id)
            result = {"status": "follow_accepted", "rewrap_triggered": changed}

        # If we changed follower state, optionally rewrap follower envelopes for every post
        if changed and AUTO_REWRAP_ON_FOLLOW_CHANGE:
            try:
                result["rewrap"] = rewrap_all_posts(private_key)
            except Exception as e:
                result["rewrap_error"] = str(e)

        if changed and not AUTO_REWRAP_ON_FOLLOW_CHANGE:
            result["rewrap_skipped"] = True

        return result

    # ---------------------------------------------------------
    elif mtype == "post_key_update":
        return {"status": "unhandled_post_key_update"}

    elif mtype == "manifest_update":
        return {"status": "unhandled_manifest_update"}

    return {"error": f"Unknown inbox message type: {mtype}"}
