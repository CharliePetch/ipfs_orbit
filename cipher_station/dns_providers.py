# cipher_station/dns_providers.py
"""
DNS provider drivers behind one small interface.

Used by two features:

- **Own-domain public URL mode** (panel): the station keeps A/AAAA records
  for a hostname the operator controls pointed at its current public IPs
  (see ddns.py).
- **Subdomain registry** (cipher_station/registry): the registry service
  creates/deletes records for claimed names on zones it controls.

Design goals:

- One abstraction (``DnsProvider``) so more drivers (e.g. porkbun) can be
  added later without touching callers.
- Keys-optional: a missing/blank token raises ``DnsAuthError`` from
  ``get_provider`` so callers can degrade gracefully — never crash the
  station because a credential is absent.
- No new dependencies: plain ``requests`` (already a station dep).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import requests

logger = logging.getLogger(__name__)

DNS_TIMEOUT = 15  # seconds per API call


class DnsProviderError(Exception):
    """Any DNS-provider API failure (network, 5xx, unexpected shape)."""


class DnsAuthError(DnsProviderError):
    """Missing or rejected credentials."""


@dataclass(frozen=True)
class DnsRecord:
    id: str
    name: str        # record label relative to the zone ("charlie", "@")
    type: str        # "A" | "AAAA" | "CNAME" | "TXT" | ...
    value: str


def relative_label(hostname: str, zone: str) -> str:
    """
    "charlie.example.com" in zone "example.com" -> "charlie".
    The zone apex maps to "@". Raises ValueError when the hostname is not
    inside the zone.
    """
    hostname = hostname.strip(".").lower()
    zone = zone.strip(".").lower()
    if hostname == zone:
        return "@"
    suffix = "." + zone
    if not hostname.endswith(suffix):
        raise ValueError(f"{hostname!r} is not inside zone {zone!r}")
    return hostname[: -len(suffix)]


class DnsProvider:
    """list_records / upsert_record / delete_record / verify_token."""

    name = "abstract"

    def verify_token(self) -> bool:
        raise NotImplementedError

    def list_records(self, zone: str) -> list[DnsRecord]:
        raise NotImplementedError

    def upsert_record(self, zone: str, name: str, record_type: str,
                      value: str, ttl: int = 300) -> DnsRecord:
        raise NotImplementedError

    def delete_record(self, zone: str, name: str, record_type: str) -> bool:
        """Delete matching record(s); True if anything was deleted."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Vercel — https://vercel.com/docs/rest-api/endpoints/dns
# ---------------------------------------------------------------------------

class VercelDnsProvider(DnsProvider):
    name = "vercel"
    BASE = "https://api.vercel.com"

    def __init__(self, token: str):
        if not (token or "").strip():
            raise DnsAuthError("VERCEL_API_TOKEN is not set")
        self._token = token.strip()

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token}"}

    def _request(self, method: str, path: str, **kwargs):
        try:
            r = requests.request(method, self.BASE + path,
                                 headers=self._headers(),
                                 timeout=DNS_TIMEOUT, **kwargs)
        except requests.RequestException as exc:
            raise DnsProviderError(f"vercel API unreachable: {exc}") from exc
        if r.status_code in (401, 403):
            raise DnsAuthError(f"vercel token rejected (HTTP {r.status_code})")
        if r.status_code >= 400:
            raise DnsProviderError(f"vercel API error {r.status_code}: {r.text[:300]}")
        return r

    def verify_token(self) -> bool:
        try:
            self._request("GET", "/v2/user")
            return True
        except DnsAuthError:
            return False

    def list_records(self, zone: str) -> list[DnsRecord]:
        r = self._request("GET", f"/v4/domains/{zone}/records", params={"limit": "100"})
        out = []
        for rec in r.json().get("records", []):
            out.append(DnsRecord(id=str(rec.get("id", "")),
                                 name=rec.get("name", ""),
                                 type=rec.get("type", ""),
                                 value=rec.get("value", "")))
        return out

    def upsert_record(self, zone: str, name: str, record_type: str,
                      value: str, ttl: int = 300) -> DnsRecord:
        existing = [rec for rec in self.list_records(zone)
                    if rec.name == name and rec.type == record_type]
        for rec in existing:
            if rec.value == value:
                return rec  # already correct
        # Vercel has no update-in-place worth relying on: delete stale, create.
        for rec in existing:
            self._request("DELETE", f"/v2/domains/{zone}/records/{rec.id}")
        r = self._request("POST", f"/v2/domains/{zone}/records",
                          json={"name": name, "type": record_type,
                                "value": value, "ttl": ttl})
        rid = str(r.json().get("uid", ""))
        return DnsRecord(id=rid, name=name, type=record_type, value=value)

    def delete_record(self, zone: str, name: str, record_type: str) -> bool:
        deleted = False
        for rec in self.list_records(zone):
            if rec.name == name and rec.type == record_type:
                self._request("DELETE", f"/v2/domains/{zone}/records/{rec.id}")
                deleted = True
        return deleted


# ---------------------------------------------------------------------------
# Cloudflare — https://developers.cloudflare.com/api/
# ---------------------------------------------------------------------------

class CloudflareDnsProvider(DnsProvider):
    name = "cloudflare"
    BASE = "https://api.cloudflare.com/client/v4"

    def __init__(self, token: str):
        if not (token or "").strip():
            raise DnsAuthError("CLOUDFLARE_API_TOKEN is not set")
        self._token = token.strip()
        self._zone_ids: dict[str, str] = {}

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token}"}

    def _request(self, method: str, path: str, **kwargs):
        try:
            r = requests.request(method, self.BASE + path,
                                 headers=self._headers(),
                                 timeout=DNS_TIMEOUT, **kwargs)
        except requests.RequestException as exc:
            raise DnsProviderError(f"cloudflare API unreachable: {exc}") from exc
        if r.status_code in (401, 403):
            raise DnsAuthError(f"cloudflare token rejected (HTTP {r.status_code})")
        if r.status_code >= 400:
            raise DnsProviderError(f"cloudflare API error {r.status_code}: {r.text[:300]}")
        return r

    def verify_token(self) -> bool:
        try:
            r = self._request("GET", "/user/tokens/verify")
            return bool(r.json().get("success"))
        except DnsAuthError:
            return False

    def _zone_id(self, zone: str) -> str:
        if zone in self._zone_ids:
            return self._zone_ids[zone]
        r = self._request("GET", "/zones", params={"name": zone})
        result = r.json().get("result") or []
        if not result:
            raise DnsProviderError(f"cloudflare zone not found: {zone}")
        zid = result[0]["id"]
        self._zone_ids[zone] = zid
        return zid

    def list_records(self, zone: str) -> list[DnsRecord]:
        zid = self._zone_id(zone)
        r = self._request("GET", f"/zones/{zid}/dns_records",
                          params={"per_page": "100"})
        out = []
        for rec in r.json().get("result", []):
            # Cloudflare returns FQDNs; normalize to zone-relative labels so
            # both drivers speak the same shape.
            try:
                label = relative_label(rec.get("name", ""), zone)
            except ValueError:
                label = rec.get("name", "")
            out.append(DnsRecord(id=str(rec.get("id", "")), name=label,
                                 type=rec.get("type", ""),
                                 value=rec.get("content", "")))
        return out

    def _fqdn(self, zone: str, name: str) -> str:
        return zone if name in ("@", "") else f"{name}.{zone}"

    def upsert_record(self, zone: str, name: str, record_type: str,
                      value: str, ttl: int = 300) -> DnsRecord:
        zid = self._zone_id(zone)
        existing = [rec for rec in self.list_records(zone)
                    if rec.name == name and rec.type == record_type]
        payload = {"name": self._fqdn(zone, name), "type": record_type,
                   "content": value, "ttl": ttl}
        if existing:
            rec = existing[0]
            if rec.value == value:
                return rec
            self._request("PUT", f"/zones/{zid}/dns_records/{rec.id}", json=payload)
            return DnsRecord(id=rec.id, name=name, type=record_type, value=value)
        r = self._request("POST", f"/zones/{zid}/dns_records", json=payload)
        rid = str((r.json().get("result") or {}).get("id", ""))
        return DnsRecord(id=rid, name=name, type=record_type, value=value)

    def delete_record(self, zone: str, name: str, record_type: str) -> bool:
        zid = self._zone_id(zone)
        deleted = False
        for rec in self.list_records(zone):
            if rec.name == name and rec.type == record_type:
                self._request("DELETE", f"/zones/{zid}/dns_records/{rec.id}")
                deleted = True
        return deleted


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

DRIVERS = {
    "vercel": VercelDnsProvider,
    "cloudflare": CloudflareDnsProvider,
}


def get_provider(driver: str, token: str | None) -> DnsProvider:
    """
    Build a driver by name. Raises ``DnsAuthError`` when the token is
    missing/blank and ``ValueError`` for an unknown driver — callers catch
    DnsAuthError to degrade gracefully rather than fail hard.
    """
    cls = DRIVERS.get((driver or "").strip().lower())
    if cls is None:
        raise ValueError(f"unknown DNS driver: {driver!r} (have: {sorted(DRIVERS)})")
    return cls(token or "")
