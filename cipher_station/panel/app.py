# cipher_station/panel/app.py
"""
The dedicated admin-panel ASGI app.

Served by its OWN uvicorn server bound to 127.0.0.1 (default port
CIPHER_PANEL_PORT=8444, plain HTTP, ``proxy_headers=False``) in the same
process as the station — see run.py. The main :8443 station app has no
/admin routes, so cloudflared / reverse proxies / port-forwards of :8443 can
never reach the panel.

App-level hardening on top of the per-route guards (see guard.py):

- **No CORS middleware at all** — the browser's same-origin policy stays
  fully in force; no cross-origin JS can read panel responses.
- **Origin check**: state-changing requests (anything but GET/HEAD/OPTIONS)
  that carry an Origin header not matching the panel's own origin are
  rejected with 403 before any handler runs (CSRF defense in depth on top
  of the bearer token).
- **Content-Length precheck**: requests declaring a body larger than
  MAX_UPLOAD_SIZE are rejected with 413 before the body is read (the upload
  route additionally enforces the cap while streaming, for chunked bodies
  and lying clients).
"""

import logging

from fastapi import FastAPI, Request
from starlette.responses import JSONResponse

from cipher_station import config as cfg
from cipher_station.panel.router import panel_api, panel_router

logger = logging.getLogger(__name__)


def allowed_panel_origins(port: int | None = None) -> set[str]:
    port = port or cfg.CIPHER_PANEL_PORT
    return {
        f"http://localhost:{port}",
        f"http://127.0.0.1:{port}",
        f"http://[::1]:{port}",
    }


def create_panel_app(*, panel_port: int | None = None) -> FastAPI:
    app = FastAPI(title="Cipher Station Admin Panel", version="1.0.0",
                  docs_url=None, redoc_url=None, openapi_url=None)
    origins = allowed_panel_origins(panel_port)

    @app.middleware("http")
    async def origin_and_size_guard(request: Request, call_next):
        # CSRF hardening: a state-changing request from a browser page on a
        # foreign origin always carries that origin — refuse it outright.
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin is not None and origin.rstrip("/") not in origins:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "cross-origin requests are not allowed"},
                )
            cl = request.headers.get("content-length")
            if cl is not None and cl.isdigit() and int(cl) > cfg.MAX_UPLOAD_SIZE:
                return JSONResponse(
                    status_code=413,
                    content={"detail": f"request too large (max {cfg.MAX_UPLOAD_SIZE} bytes)"},
                )
        return await call_next(request)

    app.include_router(panel_router)
    app.include_router(panel_api)
    return app
