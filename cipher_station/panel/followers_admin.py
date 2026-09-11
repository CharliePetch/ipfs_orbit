# cipher_station/panel/followers_admin.py
"""
Followers administration backing the panel's Followers tab.

Same-process calls into cipher_station.followers (the panel runs inside the
station process), mirroring the owner-authed /followers* routes in main.py:

- approving a follower triggers the SAME post-approve path as
  POST /followers/approve: rewrap all post envelopes so the new follower
  receives content keys, then rebuild the encrypted social graphs.
- removing (decline pending / revoke approved) mirrors POST /followers/remove:
  the rewrap + graph rebuild only runs when an *Allowed* device was removed —
  a declined Pending request never held envelopes, so nothing needs rewrapping.
- ``CIPHER_AUTO_REWRAP_ON_FOLLOW_CHANGE`` (see inbox.py) is honored exactly
  like the inbound follow-request path: with the flag off the expensive
  envelope rewrap is skipped (reported as ``rewrap_skipped``) while the graph
  rebuild still runs, so published follower state stays correct.
"""

import logging

from cipher_station.followers import (
    approve_follower,
    list_followers,
    list_pending_followers,
    remove_follower,
)
from cipher_station.graph import rebuild_graphs_and_envelopes
from cipher_station.identity import get_identity
from cipher_station.rewrap_envelopes import rewrap_all_posts

logger = logging.getLogger(__name__)


class SelfUidError(ValueError):
    """Raised when an action targets the station's own identity."""


class NotFoundError(KeyError):
    """Raised when no follower row matched the requested action."""


def _auto_rewrap_enabled() -> bool:
    # Single source of truth: inbox.py reads CIPHER_AUTO_REWRAP_ON_FOLLOW_CHANGE
    # at import time; tests monkeypatch the same attribute.
    from cipher_station import inbox
    return inbox.AUTO_REWRAP_ON_FOLLOW_CHANGE


def get_pending() -> dict:
    """Follower devices awaiting approval (station's own uid excluded)."""
    self_uid = get_identity().uid
    pending = [p for p in list_pending_followers() if p.get("uid") != self_uid]
    return {"status": "ok", "pending": pending, "count": len(pending)}


def get_followers() -> dict:
    """
    Current (Allowed) followers at user level, each with its device detail —
    the panel shows alias/uid plus every registered device.
    """
    self_uid = get_identity().uid
    seen: dict[str, dict] = {}
    for f in list_followers():
        uid = f.get("uid")
        if not uid or uid == self_uid:
            continue
        if f.get("allowed") != "Allowed":
            continue
        entry = seen.setdefault(uid, {
            "uid": uid,
            "alias": None,
            "endpoint": f.get("endpoint"),
            "ipns_id": f.get("ipns_id"),
            "allowed": "Allowed",
            "devices": [],
        })
        if not entry["alias"] and f.get("alias"):
            entry["alias"] = f["alias"]
        entry["devices"].append({
            "device_uid": f.get("device_uid"),
            "alias": f.get("alias"),
        })
    return {
        "status": "ok",
        "followers": sorted(seen.values(), key=lambda f: f["uid"]),
    }


def _post_follow_change() -> tuple[dict | None, bool, dict]:
    """
    The exact post-change behavior of main.py's owner routes: rewrap all post
    envelopes (unless auto-rewrap is disabled) and rebuild the encrypted
    social graphs. Returns (rewrap_result, rewrap_skipped, graph_cids).
    """
    rewrap = None
    rewrap_skipped = False
    if _auto_rewrap_enabled():
        ident = get_identity()
        try:
            rewrap = rewrap_all_posts(ident.mlkem_sk)
        except Exception as e:
            rewrap = {"error": str(e)}
    else:
        rewrap_skipped = True
    cids = rebuild_graphs_and_envelopes()
    return rewrap, rewrap_skipped, cids


def approve(uid: str, device_uid: str | None = None) -> dict:
    """Promote a pending follower to Allowed and grant it envelope access."""
    self_uid = get_identity().uid
    if uid == self_uid:
        raise SelfUidError("cannot approve the station's own uid")

    updated = approve_follower(uid, device_uid)
    if updated == 0:
        raise NotFoundError("no matching follower to approve")

    rewrap, rewrap_skipped, cids = _post_follow_change()

    result = {
        "status": "ok",
        "action": "approve_follower",
        "uid": uid,
        "device_uid": device_uid,
        "devices_approved": updated,
        "rewrap": rewrap,
        "updated_graph": cids,
    }
    if rewrap_skipped:
        result["rewrap_skipped"] = True
    return result


def remove(uid: str, device_uid: str | None = None) -> dict:
    """
    Decline a pending follow request or revoke an approved follower.
    Only a removed *Allowed* follower triggers the rewrap + graph rebuild.
    """
    self_uid = get_identity().uid
    if uid == self_uid:
        raise SelfUidError("cannot remove the station's own identity")

    res = remove_follower(uid, device_uid)
    if res["removed"] == 0:
        raise NotFoundError("no matching follower to remove")

    rewrap = None
    rewrap_skipped = False
    cids = None
    if res["removed_allowed"]:
        rewrap, rewrap_skipped, cids = _post_follow_change()

    result = {
        "status": "ok",
        "action": "remove_follower",
        "uid": uid,
        "device_uid": device_uid,
        "removed": res["removed"],
        "removed_allowed": res["removed_allowed"],
        "rewrap": rewrap,
        "updated_graph": cids,
    }
    if rewrap_skipped:
        result["rewrap_skipped"] = True
    return result
