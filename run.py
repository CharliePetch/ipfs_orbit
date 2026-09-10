import os
os.environ["PYTHONNOUSERSITE"] = "1"

import asyncio
import subprocess
import logging
from pathlib import Path

import uvicorn

from cipher_station.config import (
    CIPHER_PORT, CIPHER_HOST, CIPHER_PANEL_HOST, CIPHER_PANEL_PORT,
    SSL_CERTFILE, SSL_KEYFILE, LOG_LEVEL, ensure_directories,
)

logger = logging.getLogger(__name__)


def _ensure_ssl_cert():
    cert = Path(SSL_CERTFILE)
    key = Path(SSL_KEYFILE)

    if cert.exists() and key.exists():
        return

    cert.parent.mkdir(parents=True, exist_ok=True)

    logger.info("Generating self-signed TLS certificate ...")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key),
            "-out", str(cert),
            "-days", "3650", "-nodes",
            "-subj", "/CN=cipherstation",
        ],
        check=True,
        capture_output=True,
    )
    logger.info(f"Certificate written to {cert}")


async def _serve():
    """
    Two uvicorn servers in one process:

    - the station app on CIPHER_HOST:CIPHER_PORT (HTTPS) — the only listener
      cloudflared / clients ever talk to;
    - the admin panel on 127.0.0.1:CIPHER_PANEL_PORT (plain HTTP,
      proxy_headers disabled so request.client is always the real socket
      peer). The panel is never reachable through the tunnel.
    """
    station_config = uvicorn.Config(
        "cipher_station.main:app",
        port=CIPHER_PORT,
        host=CIPHER_HOST,
        reload=False,
        ssl_certfile=SSL_CERTFILE,
        ssl_keyfile=SSL_KEYFILE,
        log_level=LOG_LEVEL.lower(),
    )

    from cipher_station.panel.app import create_panel_app
    from cipher_station.panel.guard import ensure_panel_token
    ensure_panel_token()  # generate + log the per-boot token path once
    panel_config = uvicorn.Config(
        create_panel_app(),
        port=CIPHER_PANEL_PORT,
        host=CIPHER_PANEL_HOST,   # always 127.0.0.1
        reload=False,
        proxy_headers=False,      # request.client must be the real peer
        log_level=LOG_LEVEL.lower(),
    )

    station = uvicorn.Server(station_config)
    panel = uvicorn.Server(panel_config)
    await asyncio.gather(station.serve(), panel.serve())


if __name__ == "__main__":
    ensure_directories()
    _ensure_ssl_cert()
    asyncio.run(_serve())
