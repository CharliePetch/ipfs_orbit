# cipher_station/registry/client.py
"""
Signed claim client — the station side of "subdomain grant" public URL
mode. Talks to a remote registry (registry/router.py running on another
station) and signs every mutating call with THIS station's ML-DSA
identity key.

The panel drives claim/release interactively; a background heartbeat
thread keeps the claim fresh (well inside the registry's 90-day expiry)
and pushes target changes (e.g. a rotated quick-tunnel URL).
"""

from __future__ import annotations

import logging
import threading

import requests

from cipher_station.registry.signing import sign_payload

logger = logging.getLogger(__name__)

CLIENT_TIMEOUT = 20
HEARTBEAT_INTERVAL = 6 * 3600  # 6 hours — 90-day TTL leaves huge margin


class RegistryClientError(Exception):
    def __init__(self, status: int | None, detail):
        super().__init__(f"registry error {status}: {detail}")
        self.status = status
        self.detail = detail


class RegistryClient:
    def __init__(self, base_url: str, mldsa_sk: bytes, pubkey_hex: str):
        self.base_url = base_url.rstrip("/")
        self._sk = mldsa_sk
        self._pub = pubkey_hex

    def _post(self, path: str, payload: dict) -> dict:
        try:
            r = requests.post(self.base_url + path, json=payload,
                              timeout=CLIENT_TIMEOUT, verify=False)
        except requests.RequestException as exc:
            raise RegistryClientError(None, f"registry unreachable: {exc}")
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except ValueError:
                detail = r.text
            raise RegistryClientError(r.status_code, detail)
        return r.json()

    def check(self, name: str, zone: str) -> dict:
        try:
            r = requests.get(self.base_url + "/registry/check",
                             params={"name": name, "zone": zone},
                             timeout=CLIENT_TIMEOUT, verify=False)
        except requests.RequestException as exc:
            raise RegistryClientError(None, f"registry unreachable: {exc}")
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except ValueError:
                detail = r.text
            raise RegistryClientError(r.status_code, detail)
        return r.json()

    def claim(self, name: str, zone: str, target: str, record_type: str,
              invite_code: str | None = None) -> dict:
        name, zone = name.strip().lower(), zone.strip().lower()
        signed = sign_payload(self._sk, "claim", name, zone, target, record_type)
        payload = {"name": name, "zone": zone, "target": target,
                   "record_type": record_type, "pubkey": self._pub, **signed}
        if invite_code:
            payload["invite_code"] = invite_code
        return self._post("/registry/claim", payload)

    def heartbeat(self, name: str, zone: str, target: str | None = None,
                  record_type: str | None = None) -> dict:
        name, zone = name.strip().lower(), zone.strip().lower()
        signed = sign_payload(self._sk, "heartbeat", name, zone,
                              target or "", record_type or "")
        payload = {"name": name, "zone": zone, "pubkey": self._pub, **signed}
        if target is not None:
            payload["target"] = target
        if record_type is not None:
            payload["record_type"] = record_type
        return self._post("/registry/heartbeat", payload)

    def release(self, name: str, zone: str) -> dict:
        name, zone = name.strip().lower(), zone.strip().lower()
        signed = sign_payload(self._sk, "release", name, zone)
        payload = {"name": name, "zone": zone, "pubkey": self._pub, **signed}
        return self._post("/registry/release", payload)


class GrantHeartbeat:
    """Background heartbeat for an active subdomain grant."""

    def __init__(self, client: RegistryClient, name: str, zone: str,
                 target_fn, *, interval: float = HEARTBEAT_INTERVAL):
        self._client = client
        self.name = name
        self.zone = zone
        self._target_fn = target_fn  # () -> (target, record_type) | None
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.status: dict = {"state": "idle", "error": None}

    def run_once(self) -> dict:
        try:
            tgt = self._target_fn()
            if tgt:
                target, record_type = tgt
                self._client.heartbeat(self.name, self.zone, target, record_type)
            else:
                self._client.heartbeat(self.name, self.zone)
            self.status.update(state="ok", error=None)
        except RegistryClientError as exc:
            self.status.update(state="error", error=str(exc))
        return self.status

    def _loop(self):
        while not self._stop.is_set():
            self.run_once()
            self._stop.wait(self.interval)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="grant-heartbeat")
        self._thread.start()

    def stop(self):
        self._stop.set()
