# cipher_station/registry/service.py
"""
Registry business logic: name rules, availability, lazy expiry,
claim / heartbeat / release with DNS record management.

DNS is best-effort keys-optional: when the zone's driver token is missing
or invalid, claims are still recorded (the row is the source of truth) and
the response carries ``dns_synced: false`` so callers know the record was
not written. The registry operator fixes the token and the next heartbeat
re-upserts.
"""

from __future__ import annotations

import logging
import re
import time

from cipher_station.dns_providers import (
    DnsAuthError, DnsProviderError, get_provider,
)
from cipher_station.registry import config as rcfg
from cipher_station.registry import store

logger = logging.getLogger(__name__)

NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

ALLOWED_RECORD_TYPES = ("A", "AAAA", "CNAME")


class RegistryError(Exception):
    def __init__(self, status: int, detail: str, **extra):
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.extra = extra


def validate_name(name: str) -> str:
    """Lowercase single DNS label, 1-63 chars, [a-z0-9-], no edge hyphens."""
    name = (name or "").strip().lower()
    if not name or len(name) > 63 or not NAME_RE.match(name):
        raise RegistryError(400, "invalid name: 1-63 chars of [a-z0-9-], "
                                 "no leading/trailing hyphen, single label")
    return name


def _require_zone(zone: str) -> dict:
    zone = (zone or "").strip().lower()
    zcfg = rcfg.zone_config(zone)
    if zcfg is None:
        raise RegistryError(400, f"unknown zone: {zone!r}")
    return zcfg


def _dns_provider_for(zone: str):
    """Provider or None (keys-optional degradation)."""
    driver, token = rcfg.zone_driver(zone)
    if not driver:
        return None
    try:
        return get_provider(driver, token)
    except (DnsAuthError, ValueError) as exc:
        logger.warning("registry: DNS driver unavailable for %s: %s", zone, exc)
        return None


def _expire_if_stale(claim: dict | None, zone: str) -> dict | None:
    """Lazy 90-day expiry: drop the row + its DNS record when expired."""
    if claim is None:
        return None
    if claim["expires_at"] > int(time.time()):
        return claim
    logger.info("registry: claim %s.%s expired, releasing", claim["name"], zone)
    _delete_dns(zone, claim)
    store.delete_claim(claim["name"], zone)
    return None


def _upsert_dns(zone: str, name: str, record_type: str, target: str) -> bool:
    provider = _dns_provider_for(zone)
    if provider is None:
        return False
    try:
        provider.upsert_record(zone, name, record_type, target)
        return True
    except (DnsAuthError, DnsProviderError) as exc:
        logger.warning("registry: DNS upsert failed for %s.%s: %s", name, zone, exc)
        return False


def _delete_dns(zone: str, claim: dict) -> bool:
    provider = _dns_provider_for(zone)
    if provider is None:
        return False
    try:
        return provider.delete_record(zone, claim["name"], claim["record_type"])
    except (DnsAuthError, DnsProviderError) as exc:
        logger.warning("registry: DNS delete failed for %s.%s: %s",
                       claim["name"], zone, exc)
        return False


# ---------------------------------------------------------------------------
# Public operations
# ---------------------------------------------------------------------------

def check_availability(name: str, zone: str) -> dict:
    name = validate_name(name)
    _require_zone(zone)
    zone = zone.strip().lower()
    if name in rcfg.reserved_names(zone):
        return {"available": False, "reason": "reserved"}
    claim = _expire_if_stale(store.get_claim(name, zone), zone)
    if claim is not None:
        return {"available": False, "reason": "taken",
                "taken_since": claim["claimed_at"]}
    return {"available": True}


def _validate_target(target: str, record_type: str) -> tuple[str, str]:
    record_type = (record_type or "").strip().upper()
    if record_type not in ALLOWED_RECORD_TYPES:
        raise RegistryError(400, f"record_type must be one of {ALLOWED_RECORD_TYPES}")
    target = (target or "").strip()
    if not target or len(target) > 255 or any(c.isspace() for c in target):
        raise RegistryError(400, "invalid target")
    return target, record_type


def claim(name: str, zone: str, target: str, record_type: str,
          pubkey: str, *, invite_code: str | None = None,
          is_admin: bool = False) -> dict:
    """Create a claim (signature already verified by the router)."""
    name = validate_name(name)
    _require_zone(zone)
    zone = zone.strip().lower()
    target, record_type = _validate_target(target, record_type)

    if name in rcfg.reserved_names(zone):
        raise RegistryError(403, "name is reserved")

    mode = rcfg.zone_claim_mode(zone)
    if mode == "own" and not is_admin:
        raise RegistryError(403, "zone accepts admin-issued claims only")
    if mode == "invite" and not is_admin:
        if not invite_code or not store.consume_invite(invite_code, zone, name):
            raise RegistryError(403, "valid invite code required")

    existing = _expire_if_stale(store.get_claim(name, zone), zone)
    if existing is not None:
        if existing["owner_pubkey"] == pubkey:
            # Idempotent re-claim by the same owner refreshes everything.
            row = store.touch_claim(name, zone, rcfg.CLAIM_TTL_SECONDS,
                                    target=target, record_type=record_type)
            synced = _upsert_dns(zone, name, record_type, target)
            return {"claim": row, "dns_synced": synced, "renewed": True}
        raise RegistryError(409, "name already claimed",
                            taken_since=existing["claimed_at"])

    row = store.insert_claim(name, zone, pubkey, target, record_type,
                             rcfg.CLAIM_TTL_SECONDS)
    synced = _upsert_dns(zone, name, record_type, target)
    return {"claim": row, "dns_synced": synced, "renewed": False}


def _owned_claim(name: str, zone: str, pubkey: str) -> dict:
    name = validate_name(name)
    _require_zone(zone)
    zone = zone.strip().lower()
    claim_row = _expire_if_stale(store.get_claim(name, zone), zone)
    if claim_row is None:
        raise RegistryError(404, "no such claim")
    if claim_row["owner_pubkey"] != pubkey:
        raise RegistryError(403, "not the claim owner")
    return claim_row


def heartbeat(name: str, zone: str, pubkey: str,
              target: str | None = None,
              record_type: str | None = None) -> dict:
    claim_row = _owned_claim(name, zone, pubkey)
    zone = zone.strip().lower()
    name = claim_row["name"]
    synced = None
    if target is not None:
        target, record_type = _validate_target(
            target, record_type or claim_row["record_type"])
        row = store.touch_claim(name, zone, rcfg.CLAIM_TTL_SECONDS,
                                target=target, record_type=record_type)
        if target != claim_row["target"] or record_type != claim_row["record_type"]:
            if record_type != claim_row["record_type"]:
                _delete_dns(zone, claim_row)  # type changed: clear old record
            synced = _upsert_dns(zone, name, record_type, target)
    else:
        row = store.touch_claim(name, zone, rcfg.CLAIM_TTL_SECONDS)
    out: dict = {"claim": row}
    if synced is not None:
        out["dns_synced"] = synced
    return out


def release(name: str, zone: str, pubkey: str) -> dict:
    claim_row = _owned_claim(name, zone, pubkey)
    zone = zone.strip().lower()
    dns_deleted = _delete_dns(zone, claim_row)
    store.delete_claim(claim_row["name"], zone)
    return {"status": "released", "dns_deleted": dns_deleted}


# ---------------------------------------------------------------------------
# Admin operations (panel-only)
# ---------------------------------------------------------------------------

def admin_revoke(name: str, zone: str) -> dict:
    name = validate_name(name)
    zone = zone.strip().lower()
    claim_row = store.get_claim(name, zone)
    if claim_row is None:
        raise RegistryError(404, "no such claim")
    dns_deleted = _delete_dns(zone, claim_row)
    store.delete_claim(name, zone)
    return {"status": "revoked", "dns_deleted": dns_deleted}


def admin_overview() -> dict:
    zones = rcfg.load_zones()
    out_zones = {}
    for zone, zcfg in zones.items():
        driver, token = rcfg.zone_driver(zone)
        out_zones[zone] = {
            "driver": driver,
            "token_present": bool(token),
            "claim_mode": rcfg.zone_claim_mode(zone),
            "reserved": sorted(rcfg.reserved_names(zone)),
            "reserved_extra": sorted(
                {str(n).lower() for n in (zcfg.get("reserved") or [])}),
        }
    return {
        "enabled": rcfg.REGISTRY_ENABLED,
        "zones": out_zones,
        "claims": store.list_claims(),
        "invites": store.list_invites(),
    }


def admin_set_reserved(zone: str, names: list[str]) -> list[str]:
    zones = rcfg.load_zones()
    if zone not in zones:
        raise RegistryError(400, f"unknown zone: {zone!r}")
    cleaned = sorted({validate_name(n) for n in names if (n or "").strip()})
    zones[zone]["reserved"] = cleaned
    rcfg.save_zones(zones)
    return cleaned
