# cipher_station/panel/guard.py
"""
Access control for the admin panel.

Trust model (two independent layers, both enforced):

1. **Dedicated loopback listener.** The panel is served ONLY by its own
   uvicorn server bound to 127.0.0.1 (default port 8444, see
   cipher_station/panel/app.py and run.py). The main :8443 app — the one
   cloudflared and any reverse proxy target — has NO /admin routes at all,
   so the panel is unreachable through the tunnel or any port-forward of
   :8443. The panel listener runs with ``proxy_headers=False`` so
   ``request.client`` is always the real socket peer; X-Forwarded-For /
   X-Real-IP cannot rewrite it.

2. **Per-boot bearer token.** Every /admin/api route requires
   ``Authorization: Bearer <token>``, compared in constant time. The token
   is generated once per station boot (``secrets.token_urlsafe(32)``) and
   written with mode 0600 to ``<data_dir>/panel_token``. Read it on the
   station with ``cat <data_dir>/panel_token``. The HTML shell and static
   assets are served without the token (they contain no secrets); the SPA
   prompts for the token on 401 and keeps it in sessionStorage.

``require_localhost`` (the socket-peer check) is kept as defense in depth on
every panel route. Remote use is an SSH tunnel:
``ssh -L 8444:localhost:8444 user@station``.
"""

import hmac
import logging
import os
import secrets
import threading
from pathlib import Path

from fastapi import HTTPException, Request

from cipher_station import config as cfg

logger = logging.getLogger(__name__)

TOKEN_FILENAME = "panel_token"

# Loopback peers only. "::ffff:127.0.0.1" is IPv4 loopback seen through an
# IPv6 dual-stack socket.
_LOOPBACK = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}

_token_lock = threading.Lock()
# Keyed by token-file path so tests with per-test data dirs each get a fresh
# token; in production there is exactly one entry for the process lifetime.
_token_cache: dict[str, str] = {}


def panel_token_path() -> Path:
    return Path(cfg.BASE_DIR) / TOKEN_FILENAME


def ensure_panel_token() -> str:
    """
    Generate the per-boot panel token (idempotent within the process) and
    write it 0600 to <data_dir>/panel_token. Logs the location once.
    """
    path = panel_token_path()
    key = str(path)
    with _token_lock:
        cached = _token_cache.get(key)
        if cached is not None:
            return cached
        token = secrets.token_urlsafe(32)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(token + "\n")
        except BaseException:
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
        os.chmod(path, 0o600)  # in case the file pre-existed with wider perms
        _token_cache[key] = token
        logger.info(
            "Admin panel access token written to %s — read it with: cat %s",
            path, path,
        )
        return token


async def require_panel_token(request: Request) -> None:
    """Constant-time check of `Authorization: Bearer <per-boot token>`."""
    expected = ensure_panel_token()
    supplied = ""
    auth = request.headers.get("authorization", "")
    scheme, _, value = auth.partition(" ")
    if scheme.lower() == "bearer":
        supplied = value.strip()
    if not supplied or not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(
            status_code=401,
            detail="Panel token required. On the station: cat <data_dir>/panel_token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def is_loopback_address(host: str | None) -> bool:
    if not host:
        return False
    if host in _LOOPBACK:
        return True
    # Any 127.0.0.0/8 address is loopback.
    return host.startswith("127.")


async def require_localhost(request: Request) -> None:
    client = request.client
    if client is None or not is_loopback_address(client.host):
        raise HTTPException(
            status_code=403,
            detail="Admin panel is localhost-only. Use an SSH tunnel: "
                   "ssh -L 8444:localhost:8444 user@station",
        )
