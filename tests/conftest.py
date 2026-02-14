# tests/conftest.py

import os
import pytest
from pathlib import Path
from nacl.public import PrivateKey
from nacl.encoding import HexEncoder


@pytest.fixture(autouse=True)
def temp_orbit_dir(tmp_path, monkeypatch):
    """
    Point all Orbit data dirs to a fresh temp directory per test.
    """
    monkeypatch.setenv("ORBIT_BASE_DIR", str(tmp_path / "orbit_data"))
    monkeypatch.setenv("ORBIT_PASSWORD", "")

    import orbit_node.config as cfg
    monkeypatch.setattr(cfg, "BASE_DIR", tmp_path / "orbit_data")
    monkeypatch.setattr(cfg, "KEYS_DIR", tmp_path / "orbit_data" / "keys")
    monkeypatch.setattr(cfg, "DB_PATH", tmp_path / "orbit_data" / "orbit.db")
    monkeypatch.setattr(cfg, "PUBLIC_JSON_PATH", tmp_path / "orbit_data" / "public.json")
    monkeypatch.setattr(cfg, "MANIFEST_DIR", tmp_path / "orbit_data" / "manifests")

    (tmp_path / "orbit_data").mkdir(parents=True, exist_ok=True)
    (tmp_path / "orbit_data" / "keys").mkdir(parents=True, exist_ok=True)
    (tmp_path / "orbit_data" / "manifests").mkdir(parents=True, exist_ok=True)

    # Reset cached identity between tests
    import orbit_node.identity as ident
    monkeypatch.setattr(ident, "_cached_identity", None)

    # Reset DB connection between tests (close old connection first)
    import orbit_node.database as db_mod
    if db_mod._conn is not None:
        try:
            db_mod._conn.close()
        except Exception:
            pass
    monkeypatch.setattr(db_mod, "_conn", None)
    # Patch DB_PATH on the database module too (it binds at import time)
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "orbit_data" / "orbit.db")

    yield tmp_path


@pytest.fixture
def test_keypair():
    """Generate a fresh Curve25519 keypair for tests."""
    sk = PrivateKey.generate()
    pk_hex = sk.public_key.encode(encoder=HexEncoder).decode()
    return sk, pk_hex


@pytest.fixture
def second_keypair():
    """A second independent keypair."""
    sk = PrivateKey.generate()
    pk_hex = sk.public_key.encode(encoder=HexEncoder).decode()
    return sk, pk_hex
