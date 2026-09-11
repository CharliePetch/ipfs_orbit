# cipher_station/ddns.py
"""
Own-domain public URL mode: keep A/AAAA records for a hostname pointed at
the station's current public IPs (DDNS).

- Public IPs are discovered via api.ipify.org (v4) / api6.ipify.org (v6)
  with icanhazip.com as a fallback. v4-only and v6-only networks are fine:
  whichever family resolves gets a record, the other is skipped (and any
  stale record of the missing family is deleted).
- A background refresher re-checks every 5 minutes and upserts records only
  when the public IP actually changed.
- Keys-optional: a missing/invalid token stops the refresher with a status
  the panel can show as a banner — the station itself is unaffected.

This mode requires a router port-forward (WAN :443/:8443 -> the station's
LAN IP:8443); the panel surfaces the exact LAN IP + port to forward.
"""

from __future__ import annotations

import logging
import socket
import threading
import time

import requests

from cipher_station.dns_providers import (
    DnsAuthError, DnsProviderError, get_provider, relative_label,
)

logger = logging.getLogger(__name__)

REFRESH_INTERVAL = 300  # 5 minutes
IP_TIMEOUT = 10

IPV4_SOURCES = ("https://api.ipify.org", "https://ipv4.icanhazip.com")
IPV6_SOURCES = ("https://api6.ipify.org", "https://ipv6.icanhazip.com")


def _fetch_ip(sources: tuple[str, ...], family: int) -> str | None:
    for url in sources:
        try:
            r = requests.get(url, timeout=IP_TIMEOUT)
            r.raise_for_status()
            ip = r.text.strip()
            socket.inet_pton(family, ip)  # validate shape
            return ip
        except (requests.RequestException, OSError, ValueError):
            continue
    return None


def discover_public_ips() -> dict[str, str | None]:
    """{"ipv4": "..."|None, "ipv6": "..."|None} — either may be absent."""
    return {
        "ipv4": _fetch_ip(IPV4_SOURCES, socket.AF_INET),
        "ipv6": _fetch_ip(IPV6_SOURCES, socket.AF_INET6),
    }


def lan_ip() -> str | None:
    """The station's own LAN address (for port-forward guidance)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.0.2.1", 80))  # no traffic actually sent (UDP)
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


def sync_records(provider, zone: str, hostname: str,
                 ips: dict[str, str | None], ttl: int = 300) -> dict:
    """
    Make the DNS state match ``ips`` for hostname-in-zone. Upserts A/AAAA
    for present families, deletes records of absent families. Returns a
    summary dict {"a": ip|None, "aaaa": ip|None, "changed": [...]}.
    """
    label = relative_label(hostname, zone)
    changed: list[str] = []
    for rtype, key in (("A", "ipv4"), ("AAAA", "ipv6")):
        ip = ips.get(key)
        if ip:
            current = [r for r in provider.list_records(zone)
                       if r.name == label and r.type == rtype]
            if not current or current[0].value != ip:
                provider.upsert_record(zone, label, rtype, ip, ttl=ttl)
                changed.append(rtype)
        else:
            if provider.delete_record(zone, label, rtype):
                changed.append(f"-{rtype}")
    return {"a": ips.get("ipv4"), "aaaa": ips.get("ipv6"), "changed": changed}


class DdnsRefresher:
    """
    Background thread: every REFRESH_INTERVAL, re-discover public IPs and
    upsert records when they changed. Status is readable by the panel.
    """

    def __init__(self, driver: str, token: str | None, zone: str,
                 hostname: str, *,
                 interval: float = REFRESH_INTERVAL,
                 ip_source=discover_public_ips):
        self.driver = driver
        self.zone = zone
        self.hostname = hostname
        self.interval = interval
        self._ip_source = ip_source
        self._token = token
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.status: dict = {"state": "idle", "last_ips": None,
                             "last_sync": None, "error": None}

    # -- one cycle, factored out so tests can drive it synchronously --
    def run_once(self) -> dict:
        try:
            provider = get_provider(self.driver, self._token)
        except (DnsAuthError, ValueError) as exc:
            with self._lock:
                self.status.update(state="auth_error", error=str(exc))
            return self.status
        ips = self._ip_source()
        if not ips.get("ipv4") and not ips.get("ipv6"):
            with self._lock:
                self.status.update(state="no_public_ip",
                                   error="could not discover any public IP")
            return self.status
        with self._lock:
            last = self.status.get("last_ips")
        if last == ips:
            with self._lock:
                self.status.update(state="ok", error=None)
            return self.status
        try:
            summary = sync_records(provider, self.zone, self.hostname, ips)
        except DnsAuthError as exc:
            with self._lock:
                self.status.update(state="auth_error", error=str(exc))
            return self.status
        except DnsProviderError as exc:
            with self._lock:
                self.status.update(state="error", error=str(exc))
            return self.status
        with self._lock:
            self.status.update(state="ok", error=None, last_ips=ips,
                               last_sync=time.time(), last_result=summary)
        if summary["changed"]:
            logger.info("DDNS: %s updated (%s)", self.hostname, summary["changed"])
        return self.status

    def _loop(self):
        while not self._stop.is_set():
            self.run_once()
            # An auth error will not fix itself — stop burning API calls.
            if self.status.get("state") == "auth_error":
                logger.warning("DDNS refresher stopped: %s", self.status.get("error"))
                return
            self._stop.wait(self.interval)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="ddns-refresher")
        self._thread.start()

    def stop(self):
        self._stop.set()


# Module-level singleton managed by the panel service.
_refresher: DdnsRefresher | None = None
_refresher_lock = threading.Lock()


def start_refresher(driver: str, token: str | None, zone: str,
                    hostname: str) -> DdnsRefresher:
    global _refresher
    with _refresher_lock:
        if _refresher is not None:
            _refresher.stop()
        _refresher = DdnsRefresher(driver, token, zone, hostname)
        _refresher.start()
        return _refresher


def stop_refresher() -> None:
    global _refresher
    with _refresher_lock:
        if _refresher is not None:
            _refresher.stop()
            _refresher = None


def refresher_status() -> dict | None:
    with _refresher_lock:
        return dict(_refresher.status) if _refresher else None
