# cipher_station/registry/router.py
"""
Public registry API, mounted on the PUBLIC station app (:8443) when
REGISTRY_ENABLED=true — it is meant to be internet-reachable so other
stations can claim names.

Security model:
- Every mutating call is ML-DSA-signed over a canonical payload
  (registry/signing.py); the pubkey in the request is self-asserted at
  claim time and pinned thereafter (heartbeat/release must be signed by
  the SAME key that claimed the name).
- Timestamp window + per-pubkey nonce replay protection.
- In-memory per-IP token-bucket rate limiting on every route.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from cipher_station.registry import service, store
from cipher_station.registry.ratelimit import RateLimiter
from cipher_station.registry.signing import SignatureError, verify_payload

logger = logging.getLogger(__name__)

registry_router = APIRouter(prefix="/registry", tags=["registry"])

# ~1 request/second sustained, burst of 10, per client IP.
rate_limiter = RateLimiter(rate=1.0, capacity=10.0)


def _rate_limit(request: Request) -> None:
    client = request.client
    key = client.host if client else "unknown"
    if not rate_limiter.allow(key):
        raise HTTPException(status_code=429, detail="rate limited",
                            headers={"Retry-After": "10"})


def _raise(err: service.RegistryError):
    detail: dict = {"detail": err.detail}
    detail.update(err.extra)
    raise HTTPException(status_code=err.status, detail=err.detail if not err.extra
                        else {"detail": err.detail, **err.extra})


@registry_router.get("/check")
def registry_check(request: Request, name: str = "", zone: str = ""):
    _rate_limit(request)
    try:
        return service.check_availability(name, zone)
    except service.RegistryError as err:
        _raise(err)


class ClaimRequest(BaseModel):
    name: str
    zone: str
    target: str
    record_type: str
    pubkey: str
    ts: str
    nonce: str
    sig: str
    invite_code: str | None = None


@registry_router.post("/claim", status_code=201)
def registry_claim(request: Request, req: ClaimRequest):
    _rate_limit(request)
    try:
        verify_payload(req.pubkey, "claim", req.name.strip().lower(),
                       req.zone.strip().lower(), req.target, req.record_type,
                       req.ts, req.nonce, req.sig,
                       nonce_seen=store.nonce_seen,
                       remember_nonce=store.remember_nonce)
    except SignatureError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    try:
        return service.claim(req.name, req.zone, req.target, req.record_type,
                             req.pubkey, invite_code=req.invite_code)
    except service.RegistryError as err:
        _raise(err)


class HeartbeatRequest(BaseModel):
    name: str
    zone: str
    pubkey: str
    ts: str
    nonce: str
    sig: str
    target: str | None = None
    record_type: str | None = None


@registry_router.post("/heartbeat")
def registry_heartbeat(request: Request, req: HeartbeatRequest):
    _rate_limit(request)
    try:
        verify_payload(req.pubkey, "heartbeat", req.name.strip().lower(),
                       req.zone.strip().lower(), req.target or "",
                       req.record_type or "", req.ts, req.nonce, req.sig,
                       nonce_seen=store.nonce_seen,
                       remember_nonce=store.remember_nonce)
    except SignatureError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    try:
        return service.heartbeat(req.name, req.zone, req.pubkey,
                                 target=req.target, record_type=req.record_type)
    except service.RegistryError as err:
        _raise(err)


class ReleaseRequest(BaseModel):
    name: str
    zone: str
    pubkey: str
    ts: str
    nonce: str
    sig: str


@registry_router.post("/release")
def registry_release(request: Request, req: ReleaseRequest):
    _rate_limit(request)
    try:
        verify_payload(req.pubkey, "release", req.name.strip().lower(),
                       req.zone.strip().lower(), "", "",
                       req.ts, req.nonce, req.sig,
                       nonce_seen=store.nonce_seen,
                       remember_nonce=store.remember_nonce)
    except SignatureError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    try:
        return service.release(req.name, req.zone, req.pubkey)
    except service.RegistryError as err:
        _raise(err)
