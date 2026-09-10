import os
os.environ["PYTHONNOUSERSITE"] = "1"

import asyncio
import socket
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


def _bind_panel_socket(host: str, port: int) -> socket.socket | None:
    """
    Bind the admin panel's listening socket up front, so a port clash is a
    logged warning rather than a fatal error. uvicorn calls sys.exit(3) when
    it cannot bind, and inside asyncio.gather that would take the STATION
    down with it — turning "something else is on 8444" into "the station no
    longer boots" after an upgrade. The panel is a convenience; the station
    is the product. Returns None (panel skipped) when the port is taken.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
    except OSError as exc:
        sock.close()
        logger.error(
            "Admin panel NOT started: cannot bind %s:%d (%s). The station is "
            "running normally without it; set CIPHER_PANEL_PORT to a free port "
            "and restart to enable the panel.", host, port, exc,
        )
        return None
    return sock


async def _serve_panel(panel: "uvicorn.Server", sock: socket.socket) -> None:
    """Run the panel server; never let its failure escape into gather()."""
    try:
        await panel.serve(sockets=[sock])
    except SystemExit as exc:  # uvicorn's startup failure path
        logger.error("Admin panel exited at startup (code %s); station continues.", exc.code)
    except Exception:  # noqa: BLE001 — anything else is equally non-fatal
        logger.exception("Admin panel crashed; station continues without it.")
    finally:
        try:
            sock.close()
        except OSError:
            pass


async def _serve():
    """
    Two uvicorn servers in one process:

    - the station app on CIPHER_HOST:CIPHER_PORT (HTTPS) — the only listener
      cloudflared / clients ever talk to;
    - the admin panel on 127.0.0.1:CIPHER_PANEL_PORT (plain HTTP,
      proxy_headers disabled so request.client is always the real socket
      peer). The panel is never reachable through the tunnel, and its
      failure to start is never allowed to stop the station.
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
    tasks = [station.serve()]

    panel_sock = _bind_panel_socket(CIPHER_PANEL_HOST, CIPHER_PANEL_PORT)
    if panel_sock is not None:
        panel = uvicorn.Server(panel_config)
        tasks.append(_serve_panel(panel, panel_sock))

    await asyncio.gather(*tasks)


if __name__ == "__main__":
    ensure_directories()
    _ensure_ssl_cert()
    asyncio.run(_serve())
