# cipher_station/registry/store.py
"""
SQLite persistence for the subdomain registry.

Own DB file (<data_dir>/registry.db) rather than the station DB: the
registry is an optional, separable service — an operator can back it up or
wipe it independently of station state. Same per-thread-connection + WAL
discipline as cipher_station/database.py.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

from cipher_station import config as cfg

_local = threading.local()

DB_FILENAME = "registry.db"


def registry_db_path() -> Path:
    return Path(cfg.BASE_DIR) / DB_FILENAME


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS claims (
            name TEXT NOT NULL,
            zone TEXT NOT NULL,
            owner_pubkey TEXT NOT NULL,
            target TEXT NOT NULL,
            record_type TEXT NOT NULL,
            claimed_at INTEGER NOT NULL,
            last_heartbeat INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            PRIMARY KEY (name, zone)
        );
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS invites (
            code TEXT PRIMARY KEY,
            zone TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            used_at INTEGER NULL,
            used_by_name TEXT NULL
        );
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS registry_nonces (
            pubkey TEXT NOT NULL,
            nonce TEXT NOT NULL,
            ts INTEGER NOT NULL,
            PRIMARY KEY (pubkey, nonce)
        );
    """)
    conn.commit()


def get_db() -> sqlite3.Connection:
    path = registry_db_path()
    conn = getattr(_local, "conn", None)
    if conn is not None and getattr(_local, "path", None) == str(path):
        return conn
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    _init_schema(conn)
    _local.conn = conn
    _local.path = str(path)
    return conn


# ---------------------------------------------------------------------------
# Claims
# ---------------------------------------------------------------------------

def get_claim(name: str, zone: str) -> dict | None:
    row = get_db().execute(
        "SELECT * FROM claims WHERE name=? AND zone=?", (name, zone)
    ).fetchone()
    return dict(row) if row else None


def insert_claim(name: str, zone: str, owner_pubkey: str, target: str,
                 record_type: str, ttl_seconds: int) -> dict:
    now = int(time.time())
    db = get_db()
    db.execute(
        "INSERT INTO claims(name, zone, owner_pubkey, target, record_type,"
        " claimed_at, last_heartbeat, expires_at, status)"
        " VALUES(?,?,?,?,?,?,?,?, 'active')",
        (name, zone, owner_pubkey, target, record_type, now, now,
         now + ttl_seconds),
    )
    db.commit()
    return get_claim(name, zone)  # type: ignore[return-value]


def touch_claim(name: str, zone: str, ttl_seconds: int,
                target: str | None = None,
                record_type: str | None = None) -> dict | None:
    now = int(time.time())
    db = get_db()
    if target is not None:
        db.execute(
            "UPDATE claims SET last_heartbeat=?, expires_at=?, target=?,"
            " record_type=COALESCE(?, record_type) WHERE name=? AND zone=?",
            (now, now + ttl_seconds, target, record_type, name, zone),
        )
    else:
        db.execute(
            "UPDATE claims SET last_heartbeat=?, expires_at=? WHERE name=? AND zone=?",
            (now, now + ttl_seconds, name, zone),
        )
    db.commit()
    return get_claim(name, zone)


def delete_claim(name: str, zone: str) -> bool:
    db = get_db()
    cur = db.execute("DELETE FROM claims WHERE name=? AND zone=?", (name, zone))
    db.commit()
    return cur.rowcount > 0


def list_claims(zone: str | None = None) -> list[dict]:
    db = get_db()
    if zone:
        rows = db.execute(
            "SELECT * FROM claims WHERE zone=? ORDER BY claimed_at DESC", (zone,)
        ).fetchall()
    else:
        rows = db.execute("SELECT * FROM claims ORDER BY claimed_at DESC").fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Invite codes
# ---------------------------------------------------------------------------

def create_invite(zone: str) -> str:
    import secrets
    code = secrets.token_urlsafe(12)
    db = get_db()
    db.execute("INSERT INTO invites(code, zone, created_at) VALUES(?,?,?)",
               (code, zone, int(time.time())))
    db.commit()
    return code


def consume_invite(code: str, zone: str, used_by_name: str) -> bool:
    """Atomically consume an unused invite for the zone. True on success."""
    db = get_db()
    cur = db.execute(
        "UPDATE invites SET used_at=?, used_by_name=? "
        "WHERE code=? AND zone=? AND used_at IS NULL",
        (int(time.time()), used_by_name, code, zone),
    )
    db.commit()
    return cur.rowcount > 0


def list_invites(zone: str | None = None) -> list[dict]:
    db = get_db()
    if zone:
        rows = db.execute(
            "SELECT * FROM invites WHERE zone=? ORDER BY created_at DESC", (zone,)
        ).fetchall()
    else:
        rows = db.execute("SELECT * FROM invites ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Replay nonces
# ---------------------------------------------------------------------------

def nonce_seen(pubkey: str, nonce: str) -> bool:
    row = get_db().execute(
        "SELECT 1 FROM registry_nonces WHERE pubkey=? AND nonce=?",
        (pubkey, nonce),
    ).fetchone()
    return row is not None


def remember_nonce(pubkey: str, nonce: str, ts: int) -> None:
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO registry_nonces(pubkey, nonce, ts) VALUES(?,?,?)",
        (pubkey, nonce, ts),
    )
    # Opportunistic prune of old nonces (>24h).
    db.execute("DELETE FROM registry_nonces WHERE ts < ?",
               (int(time.time()) - 86400,))
    db.commit()
