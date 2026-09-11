# cipher_station/registry/config.py
"""
Registry configuration.

- ``REGISTRY_ENABLED`` (.env, default false) gates the public API mount.
- Per-zone config lives in ``<data_dir>/registry.json``:

    {
      "zones": {
        "cipherstation.io": {
          "driver": "cloudflare",            // vercel | cloudflare
          "token_env": "CLOUDFLARE_API_TOKEN",
          "claim_mode": "public",            // own | invite | public
          "reserved": ["extra", "names"]     // merged with DEFAULT_RESERVED
        }
      }
    }

The file is read on demand (not cached at import) so tests and the panel
can edit it without a restart of anything but the registry views.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from cipher_station import config as cfg

REGISTRY_ENABLED = os.getenv("REGISTRY_ENABLED", "false").lower() in ("true", "1", "yes")

# Names that can never be claimed on any zone: infrastructure labels plus an
# impersonation/phishing list. Always enforced, per-zone lists only extend it.
DEFAULT_RESERVED = frozenset({
    "www", "mail", "api", "admin", "panel", "station", "hosting",
    "apex", "@", "mx", "smtp", "imap", "pop", "webmail", "ftp",
    "ns", "ns1", "ns2", "ns3", "ns4", "dns",
    "login", "secure", "support", "official", "bank", "account",
    "accounts", "auth", "signin", "sign-in", "verify", "wallet",
    "payment", "payments", "billing", "help", "security", "root",
})

CLAIM_MODES = ("own", "invite", "public")

# Claims expire this long after the last heartbeat.
CLAIM_TTL_SECONDS = 90 * 24 * 3600


def registry_json_path() -> Path:
    return Path(cfg.BASE_DIR) / "registry.json"


def load_zones() -> dict[str, dict]:
    """Zone-name -> config dict; {} when unconfigured or unreadable."""
    path = registry_json_path()
    try:
        obj = json.loads(path.read_text())
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return {}
    zones = obj.get("zones")
    return zones if isinstance(zones, dict) else {}


def save_zones(zones: dict[str, dict]) -> None:
    import tempfile
    path = registry_json_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".registry.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"zones": zones}, f, indent=2)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def zone_config(zone: str) -> dict | None:
    return load_zones().get(zone)


def reserved_names(zone: str) -> set[str]:
    zcfg = zone_config(zone) or {}
    extra = {str(n).lower() for n in zcfg.get("reserved", [])}
    return set(DEFAULT_RESERVED) | extra


def zone_claim_mode(zone: str) -> str:
    mode = (zone_config(zone) or {}).get("claim_mode", "own")
    return mode if mode in CLAIM_MODES else "own"


def zone_driver(zone: str) -> tuple[str | None, str | None]:
    """(driver_name, token) for a zone; token read from the env var named
    by token_env. Either may be None (keys-optional degradation)."""
    zcfg = zone_config(zone) or {}
    driver = zcfg.get("driver")
    token_env = zcfg.get("token_env") or ""
    token = os.getenv(token_env) if token_env else None
    return driver, token
