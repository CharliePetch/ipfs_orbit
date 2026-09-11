# cipher_station/panel/public_url.py
"""
Public URL modes backing the panel's "Public URL" section.

Three modes, persisted in .env as CIPHER_PUBLIC_URL_MODE:

- ``quick``  (default) — Cloudflare quick tunnel; ephemeral trycloudflare
  URL that rotates on restart. Existing tunnel machinery, untouched.
- ``domain`` — a hostname on a domain the operator controls. The panel
  keeps A/AAAA records pointed at the station's public IPs via a DNS
  driver (vercel|cloudflare) and a 5-minute DDNS refresher. Requires a
  router port-forward; the panel shows the exact LAN IP + port.
- ``grant``  — claim a name from a remote subdomain registry, signed with
  the station's ML-DSA identity key (registry/client.py).

Everything is keys-optional: missing/invalid credentials surface as a
``degraded`` banner and the station keeps whatever URL it already has —
never an unreachable station.
"""

from __future__ import annotations

import logging
import os

from cipher_station import config as cfg
from cipher_station import ddns
from cipher_station.dns_providers import DnsAuthError, get_provider
from cipher_station.panel import service

logger = logging.getLogger(__name__)

MODES = ("quick", "domain", "grant")

# .env keys owned by this feature (extends service.EDITABLE_ENV_KEYS).
ENV_KEYS = (
    "CIPHER_PUBLIC_URL_MODE",
    "CIPHER_DOMAIN_HOSTNAME",
    "CIPHER_DOMAIN_ZONE",
    "CIPHER_DNS_DRIVER",
    "CIPHER_GRANT_REGISTRY_URL",
    "CIPHER_GRANT_NAME",
    "CIPHER_GRANT_ZONE",
)

TOKEN_ENVS = {"vercel": "VERCEL_API_TOKEN", "cloudflare": "CLOUDFLARE_API_TOKEN"}


def _env(key: str) -> str | None:
    return (os.getenv(key) or "").strip() or None


def current_mode() -> str:
    mode = (_env("CIPHER_PUBLIC_URL_MODE") or "quick").lower()
    return mode if mode in MODES else "quick"


def get_public_url_config() -> dict:
    """Everything the Public URL section renders, in one call."""
    mode = current_mode()
    driver = (_env("CIPHER_DNS_DRIVER") or "").lower() or None
    token_env = TOKEN_ENVS.get(driver or "")
    token_present = bool(_env(token_env)) if token_env else False

    degraded = None
    if mode == "domain":
        if not driver:
            degraded = "No DNS driver configured — falling back to quick tunnel."
        elif not token_present:
            degraded = (f"{token_env} is not set — own-domain mode is inactive; "
                        "the station falls back to the quick tunnel.")

    out = {
        "mode": mode,
        "effective_mode": "quick" if degraded else mode,
        "degraded": degraded,
        "quick": {
            "enabled": cfg.CLOUDFLARE_TUNNEL_ENABLED,
            "url": service._read_public_json().get("endpoint"),
            "note": "URL rotates every time the station or cloudflared restarts.",
        },
        "domain": {
            "hostname": _env("CIPHER_DOMAIN_HOSTNAME"),
            "zone": _env("CIPHER_DOMAIN_ZONE"),
            "driver": driver,
            "token_env": token_env,
            "token_present": token_present,
            "ddns": ddns.refresher_status(),
            "port_forward": {
                "lan_ip": ddns.lan_ip(),
                "port": cfg.CIPHER_PORT,
                "note": ("Forward WAN TCP {port} (or 443) to this station's "
                         "LAN address on your router.").format(port=cfg.CIPHER_PORT),
            },
            "tls_note": ("The station serves its own TLS certificate on "
                         f":{cfg.CIPHER_PORT}; a trusted-cert (ACME) flow is "
                         "future work."),
        },
        "grant": {
            "registry_url": _env("CIPHER_GRANT_REGISTRY_URL"),
            "name": _env("CIPHER_GRANT_NAME"),
            "zone": _env("CIPHER_GRANT_ZONE"),
        },
        "permanent_url": cfg.CIPHER_PUBLIC_URL,
    }
    return out


def _validate_hostname(hostname: str, zone: str) -> None:
    import re
    host_re = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+"
                         r"[a-z]{2,}$")
    for label, value in (("hostname", hostname), ("zone", zone)):
        if not host_re.match(value.lower()):
            raise ValueError(f"{label} does not look like a valid DNS name: {value!r}")
    if hostname.lower() != zone.lower() and not hostname.lower().endswith("." + zone.lower()):
        raise ValueError(f"hostname {hostname!r} is not inside zone {zone!r}")


def set_public_url_mode(*, mode: str,
                        hostname: str | None = None,
                        zone: str | None = None,
                        driver: str | None = None,
                        registry_url: str | None = None,
                        grant_name: str | None = None,
                        grant_zone: str | None = None) -> dict:
    """
    Persist the chosen mode + its settings to .env (atomic rewrite via the
    existing panel machinery) and derive CIPHER_PUBLIC_URL. Restart-requiring
    like every other .env change; the DDNS refresher, however, is started/
    stopped immediately so records stay fresh without a restart.
    """
    mode = (mode or "").lower()
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")

    changes: dict[str, str | None] = {"CIPHER_PUBLIC_URL_MODE": mode}
    warnings: list[str] = []

    if mode == "quick":
        changes.update({
            "CIPHER_DOMAIN_HOSTNAME": None, "CIPHER_DOMAIN_ZONE": None,
            "CIPHER_DNS_DRIVER": None, "CIPHER_PUBLIC_URL": None,
        })
        ddns.stop_refresher()

    elif mode == "domain":
        hostname = (hostname or "").strip().lower()
        zone = (zone or "").strip().lower()
        driver = (driver or "").strip().lower()
        if not hostname or not zone:
            raise ValueError("own-domain mode needs a hostname and its zone")
        if driver not in TOKEN_ENVS:
            raise ValueError(f"driver must be one of {sorted(TOKEN_ENVS)}")
        _validate_hostname(hostname, zone)
        changes.update({
            "CIPHER_DOMAIN_HOSTNAME": hostname,
            "CIPHER_DOMAIN_ZONE": zone,
            "CIPHER_DNS_DRIVER": driver,
            "CIPHER_PUBLIC_URL": f"https://{hostname}",
        })
        token = _env(TOKEN_ENVS[driver])
        if token:
            try:
                provider = get_provider(driver, token)
                if not provider.verify_token():
                    raise DnsAuthError("token rejected by the provider")
                ddns.start_refresher(driver, token, zone, hostname)
            except DnsAuthError as exc:
                warnings.append(f"DNS credentials problem ({exc}); staying on "
                                "the quick tunnel until fixed.")
                ddns.stop_refresher()
            except Exception as exc:  # network flake etc. — degrade, don't die
                warnings.append(f"Could not verify DNS credentials: {exc}")
        else:
            warnings.append(f"{TOKEN_ENVS[driver]} is not set — records will "
                            "not be managed until you export it and restart.")

    elif mode == "grant":
        registry_url = (registry_url or "").strip()
        grant_name = (grant_name or "").strip().lower()
        grant_zone = (grant_zone or "").strip().lower()
        if not registry_url or not grant_name or not grant_zone:
            raise ValueError("subdomain-grant mode needs a registry URL, name and zone")
        if not registry_url.startswith(("http://", "https://")):
            raise ValueError("registry URL must be http(s)://")
        changes.update({
            "CIPHER_GRANT_REGISTRY_URL": registry_url,
            "CIPHER_GRANT_NAME": grant_name,
            "CIPHER_GRANT_ZONE": grant_zone,
            "CIPHER_PUBLIC_URL": f"https://{grant_name}.{grant_zone}",
        })
        ddns.stop_refresher()

    service._rewrite_env(changes)
    # Keep the in-process env in sync so a later GET reflects the change
    # without a restart (the .env file is only read at boot).
    for key, value in changes.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value

    return {
        "status": "ok",
        "mode": mode,
        "warnings": warnings,
        "changed": sorted(changes),
        "restart_required": True,
        "restart_command": "sudo systemctl restart cipherstation",
    }


def _grant_client():
    from cipher_station.identity import get_identity
    from cipher_station.registry.client import RegistryClient
    registry_url = _env("CIPHER_GRANT_REGISTRY_URL")
    if not registry_url:
        raise ValueError("no registry URL configured")
    ident = get_identity()
    return RegistryClient(registry_url, ident.mldsa_sk, ident.mldsa_pub_hex)


def grant_check(name: str, zone: str) -> dict:
    return _grant_client().check(name, zone)


def grant_claim(name: str, zone: str, target: str, record_type: str,
                invite_code: str | None = None) -> dict:
    return _grant_client().claim(name, zone, target, record_type,
                                 invite_code=invite_code)


def grant_heartbeat(name: str, zone: str, target: str | None = None,
                    record_type: str | None = None) -> dict:
    return _grant_client().heartbeat(name, zone, target, record_type)


def grant_release(name: str, zone: str) -> dict:
    return _grant_client().release(name, zone)
