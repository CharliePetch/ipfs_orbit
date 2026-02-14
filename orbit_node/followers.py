# orbit_node/followers.py

from typing import List, Dict
from orbit_node.database import get_db


# ---------------------------------------------------------
# INSERT HELPERS
# ---------------------------------------------------------

def add_follower_device(
    uid: str,
    device_uid: str,
    public_key: str,
    alias: str = None,
    allowed: str = "Allowed",
    endpoint: str = None,
    ipns_id: str = None,
) -> None:
    """
    Registers a device-level follower entry.
    Supports nullable endpoint for iOS-only read-only followers.
    ipns_id is the follower's IPFS peer ID for permanent IPNS discovery.
    """
    db = get_db()
    db.execute(
        """
        INSERT OR REPLACE INTO followers(uid, public_key, device_uid, alias, allowed, endpoint, ipns_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (uid, public_key, device_uid, alias, allowed, endpoint, ipns_id)
    )
    db.commit()


def add_follower(uid: str, public_key: str) -> None:
    """
    Legacy fallback path: follower without device info.
    Uses uid as the device_uid and NULL endpoint.
    """
    add_follower_device(uid, device_uid=uid, public_key=public_key)


def remove_follower(uid: str) -> None:
    """
    Removes all follower device entries for a given user UID.
    """
    db = get_db()
    db.execute("DELETE FROM followers WHERE uid = ?", (uid,))
    db.commit()


# ---------------------------------------------------------
# LIST HELPERS
# ---------------------------------------------------------

def list_followers() -> List[Dict]:
    """
    Return all follower device entries, including endpoint and ipns_id.
    """
    db = get_db()
    rows = db.execute(
        """
        SELECT uid, public_key, device_uid, alias, allowed, endpoint, ipns_id
        FROM followers
        ORDER BY uid, device_uid
        """
    ).fetchall()

    return [
        {
            "uid": r["uid"],
            "public_key": r["public_key"],
            "device_uid": r["device_uid"],
            "alias": r["alias"],
            "allowed": r["allowed"],
            "endpoint": r["endpoint"],
            "ipns_id": r["ipns_id"],
        }
        for r in rows
    ]


def list_follower_devices(uid: str) -> List[Dict]:
    """
    Return all devices for a single follower, including endpoint and ipns_id.
    """
    db = get_db()
    rows = db.execute(
        """
        SELECT device_uid, public_key, alias, allowed, endpoint, ipns_id
        FROM followers
        WHERE uid = ?
        ORDER BY device_uid
        """,
        (uid,)
    ).fetchall()

    return [
        {
            "device_uid": r["device_uid"],
            "public_key": r["public_key"],
            "alias": r["alias"],
            "allowed": r["allowed"],
            "endpoint": r["endpoint"],
            "ipns_id": r["ipns_id"],
        }
        for r in rows
    ]


def list_all_public_keys() -> List[str]:
    """
    Return all public keys across all followers.
    Useful for envelope regeneration.
    """
    db = get_db()
    rows = db.execute("SELECT public_key FROM followers").fetchall()
    return [r["public_key"] for r in rows]
