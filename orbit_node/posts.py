# orbit_node/posts.py
import json
import logging
from typing import Literal, Optional

from nacl.public import PrivateKey
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random

from orbit_node.ipfs_client import ipfs_add_bytes, ipfs_get_bytes
from orbit_node.followers import list_followers
from orbit_node.manifest import add_post_to_manifest, load_manifest, remove_post_from_manifest
from orbit_node.identity import get_identity
from orbit_node.envelopes import open_envelope, encrypt_key_for_follower

logger = logging.getLogger(__name__)

# Back-compat: older clients used "all_followers"
AudienceMode = Literal["self", "specific", "all", "all_followers"]


def _normalize_audience_mode(mode: str) -> Literal["self", "specific", "all"]:
    if mode == "all_followers":
        return "all"
    if mode in ("self", "specific", "all"):
        return mode  # type: ignore[return-value]
    raise ValueError(f"Invalid audience_mode: {mode}")


def _encrypt_metadata(metadata: dict, sym_key: bytes) -> str:
    """
    Encrypt metadata dict with the same SecretBox key used for the post.
    Returns hex string (nonce+ciphertext).
    """
    raw = json.dumps(metadata, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    box = SecretBox(sym_key)
    ct = box.encrypt(raw)  # includes nonce
    return ct.hex()


def _dedupe_followers_for_user_level_envelopes(followers: list[dict]) -> list[dict]:
    """
    Reduce device-level follower rows -> ONE row per uid for user-level envelopes.

    Preference:
      1) allowed == "Allowed"
      2) device_uid == uid (treat as "root" device when present)
      3) otherwise: first Allowed row for that uid

    Rationale:
      - Your envelopes JSON is keyed by uid (not device_uid).
      - Passing multiple devices per uid causes overwrites, and can make "self"
        envelope end up sealed to the wrong device key.
    """
    allowed = [f for f in followers if isinstance(f, dict) and f.get("allowed") == "Allowed"]

    by_uid: dict[str, dict] = {}
    for f in allowed:
        uid = f.get("uid")
        if not uid or not isinstance(uid, str):
            continue

        cur = by_uid.get(uid)
        if cur is None:
            by_uid[uid] = f
            continue

        cur_is_root = (cur.get("device_uid") == uid)
        new_is_root = (f.get("device_uid") == uid)
        if (not cur_is_root) and new_is_root:
            by_uid[uid] = f

    return [by_uid[k] for k in sorted(by_uid.keys())]


def _force_self_row(
    *,
    followers: list[dict],
    self_uid: str,
    station_pk_hex: str,
    pub_json: dict,
) -> list[dict]:
    """
    Ensure exactly one 'self' row exists and it is sealed to the station public key.
    """
    followers = [f for f in followers if f.get("uid") != self_uid]
    followers.insert(
        0,
        {
            "uid": self_uid,
            "public_key": station_pk_hex,   # key that matches station_sk
            "device_uid": self_uid,         # treat as "root" device
            "alias": pub_json.get("alias"),
            "allowed": "Allowed",
            "endpoint": pub_json.get("endpoint"),
            "ipns_id": pub_json.get("ipfs_peer_id"),  # permanent IPNS discovery address
        },
    )
    return followers


def _filter_followers_for_audience(
    *,
    followers_user_level: list[dict],
    self_uid: str,
    audience_mode: Literal["self", "specific", "all"],
    audience_uids: Optional[list[str]],
) -> list[dict]:
    """
    Return subset of followers_user_level to receive envelopes.

    followers_user_level is expected to already be:
      - Allowed-only
      - deduped to one row per uid
      - NOT including self yet (we add self separately)
    """
    if audience_mode == "self":
        return []  # we’ll add self explicitly later

    if audience_mode == "all":
        return followers_user_level

    # audience_mode == "specific"
    uids = audience_uids or []
    uids = [u.strip() for u in uids if isinstance(u, str) and u.strip()]

    want = set(uids) - {self_uid}
    if not want:
        return []

    by_uid = {f.get("uid"): f for f in followers_user_level if isinstance(f, dict)}
    selected = [by_uid[uid] for uid in sorted(want) if uid in by_uid]

    missing = sorted(want - set(by_uid.keys()))
    if missing:
        raise ValueError(
            "Specific audience contains uids that are not Allowed followers (or unknown): "
            + ", ".join(missing)
        )

    return selected


def handle_new_post(
    file_bytes: bytes,
    metadata: dict | None = None,
    *,
    audience_mode: AudienceMode = "all",
    audience_uids: Optional[list[str]] = None,
    client: str | None = None,
):
    """
    Encrypt post bytes, upload to IPFS, generate envelopes, and append to manifest.

    Post visibility is controlled by audience_mode:
      - "self": only self gets an envelope
      - "specific": self + specified Allowed follower uids
      - "all" / (legacy "all_followers"): self + all Allowed followers

    Notes:
      - Envelopes are published as a separate JSON to IPFS
      - Manifest stores envelopes_cid (not envelopes inline)
      - Followers list is deduped to ONE device per uid
      - Self uid is forced to station public key (not delegate device)
    """
    # Load the station identity (source of truth for "self")
    _station_sk, station_pk_hex, pub_json = get_identity()
    self_uid = pub_json.get("uid")
    if not self_uid or not isinstance(self_uid, str):
        raise ValueError("Identity missing uid in public.json")

    # ✅ normalize legacy value
    aud_mode = _normalize_audience_mode(audience_mode)

    # 1) Fresh symmetric key (per post)
    sym_key = nacl_random(SecretBox.KEY_SIZE)
    box = SecretBox(sym_key)

    # 2) Encrypt post bytes
    encrypted_blob = box.encrypt(file_bytes)

    # 3) Upload encrypted blob to IPFS
    cid = ipfs_add_bytes(encrypted_blob)
    logger.info(f"Encrypted post uploaded: CID={cid}")

    # 4) Followers (device-level) -> dedupe to user-level Allowed followers
    followers_raw = list_followers()
    followers_user_level = _dedupe_followers_for_user_level_envelopes(followers_raw)

    # 4a) Remove self from follower list prior to audience selection (self is forced separately)
    followers_user_level = [f for f in followers_user_level if f.get("uid") != self_uid]

    # 4b) Apply audience filter to non-self recipients
    recipients = _filter_followers_for_audience(
        followers_user_level=followers_user_level,
        self_uid=self_uid,
        audience_mode=aud_mode,
        audience_uids=audience_uids,
    )

    # 4c) Force "self" envelope to the station public key
    followers_for_envelopes = _force_self_row(
        followers=recipients,
        self_uid=self_uid,
        station_pk_hex=station_pk_hex,
        pub_json=pub_json,
    )

    # 5) Encrypt metadata (optional)
    metadata_enc = None
    if metadata is not None:
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be a dict or None")
        metadata_enc = _encrypt_metadata(metadata, sym_key)

    # 6) Write manifest entry (store encrypted metadata only)
    manifest = add_post_to_manifest(
        post_cid=cid,
        followers=followers_for_envelopes,
        sym_key=sym_key,
        metadata_enc=metadata_enc,
        audience_mode=aud_mode,        # "self" | "specific" | "all"
        audience_uids=audience_uids,   # list[str] if specific
        client=client,                 # client app name (e.g., "orbitstagram", "drive")
    )

    # 7) Pull the envelopes CID from the new entry (just appended)
    envelopes_cid = None
    try:
        envelopes_cid = manifest["posts"][-1].get("envelopes_cid")
    except Exception:
        pass

    return {
        "status": "post_ok",
        "cid": cid,
        "envelopes_cid": envelopes_cid,
        "audience_mode": aud_mode,
        "audience_uids": (audience_uids or []) if aud_mode == "specific" else None,
        "followers_raw": len(followers_raw),
        "followers_used": len(followers_for_envelopes),
        "manifest_posts": len(manifest.get("posts", [])),
    }


def handle_reshare_post(
    post_cid: str,
    *,
    audience_mode: AudienceMode = "specific",
    audience_uids: Optional[list[str]] = None,
    client: Optional[str] = None,
) -> dict:
    """
    Update a post's audience by removing and re-creating its manifest entry
    with new envelopes.

    The station recovers the symmetric key from its own sealed-box envelope,
    then re-encrypts for the new audience set.
    """
    station_sk, station_pk_hex, pub_json = get_identity()
    self_uid = pub_json.get("uid")
    if not self_uid:
        raise ValueError("Identity missing uid")

    aud_mode = _normalize_audience_mode(audience_mode)

    # 1) Find the existing post entry in the manifest
    manifest = load_manifest(client=client)
    client_key = (client or "default").strip() or "default"

    # Search for the post
    old_entry = None
    for ck, bucket in manifest.get("clients", {}).items():
        for entry in bucket.get("posts", []):
            if entry.get("post_cid") == post_cid:
                old_entry = entry
                client_key = ck
                break
        if old_entry:
            break

    if not old_entry:
        return {"status": "not_found", "post_cid": post_cid}

    old_envelopes_cid = old_entry.get("envelopes_cid")
    old_metadata_enc = old_entry.get("metadata")

    # 2) Recover the symmetric key from the station's own envelope
    if not old_envelopes_cid:
        return {"status": "error", "detail": "Post has no envelopes_cid"}

    raw = ipfs_get_bytes(old_envelopes_cid)
    env_obj = json.loads(raw.decode("utf-8"))
    envelopes_map = env_obj.get("envelopes", {})

    self_envelope_hex = envelopes_map.get(self_uid)
    if not self_envelope_hex:
        return {"status": "error", "detail": "No self envelope found; cannot recover key"}

    # station_sk is already a PrivateKey from get_identity()
    sym_key = open_envelope(station_sk, self_envelope_hex)
    if not sym_key or len(sym_key) != SecretBox.KEY_SIZE:
        return {"status": "error", "detail": "Failed to recover symmetric key"}

    # 3) Build new follower list for the new audience
    followers_raw = list_followers()
    followers_user_level = _dedupe_followers_for_user_level_envelopes(followers_raw)
    followers_user_level = [f for f in followers_user_level if f.get("uid") != self_uid]

    recipients = _filter_followers_for_audience(
        followers_user_level=followers_user_level,
        self_uid=self_uid,
        audience_mode=aud_mode,
        audience_uids=audience_uids,
    )

    followers_for_envelopes = _force_self_row(
        followers=recipients,
        self_uid=self_uid,
        station_pk_hex=station_pk_hex,
        pub_json=pub_json,
    )

    # 4) Remove old entry from manifest
    remove_post_from_manifest(post_cid, client=client_key)

    # 5) Re-add with new audience (same post_cid, same metadata, new envelopes)
    manifest = add_post_to_manifest(
        post_cid=post_cid,
        followers=followers_for_envelopes,
        sym_key=sym_key,
        metadata_enc=old_metadata_enc,
        audience_mode=aud_mode,
        audience_uids=audience_uids,
        client=client_key,
    )

    return {
        "status": "shared",
        "post_cid": post_cid,
        "audience_mode": aud_mode,
        "audience_uids": (audience_uids or []) if aud_mode == "specific" else None,
        "envelopes_count": len(followers_for_envelopes),
    }
