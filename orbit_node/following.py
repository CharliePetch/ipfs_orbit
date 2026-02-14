# orbit_node/following.py

from typing import Dict, List
from orbit_node.database import get_db


def follow_user(uid: str, public_key: str, endpoint: str, ipns_id: str = None) -> None:
    """
    Registers an outbound follow relationship.
    No device-level info.
    No manifest caching.
    ipns_id is the target's IPFS peer ID for permanent IPNS discovery.
    """
    db = get_db()
    db.execute(
        """
        INSERT OR REPLACE INTO following(uid, public_key, endpoint, ipns_id)
        VALUES (?, ?, ?, ?)
        """,
        (uid, public_key, endpoint, ipns_id)
    )
    db.commit()


def unfollow_user(uid: str) -> None:
    """
    Deletes an outbound follow relationship.
    """
    db = get_db()
    db.execute("DELETE FROM following WHERE uid = ?", (uid,))
    db.commit()


def list_following() -> List[Dict]:
    """
    Returns a list of all outbound follow relationships:
      [
        {
          "uid": "alice",
          "public_key": "...",
          "endpoint": "https://alice-node.example"
        }
      ]
    """
    db = get_db()
    rows = db.execute(
        "SELECT uid, public_key, endpoint, ipns_id FROM following ORDER BY uid"
    ).fetchall()

    return [dict(r) for r in rows]


def get_following(uid: str) -> Dict | None:
    """
    Returns a single outbound follow record for a user.
    """
    db = get_db()
    row = db.execute(
        "SELECT uid, public_key, endpoint, ipns_id FROM following WHERE uid = ?",
        (uid,)
    ).fetchone()

    return dict(row) if row else None
