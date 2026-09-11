#!/usr/bin/env python3
"""
run_registry.py — standalone subdomain-registry server.

Runs ONLY the registry API (no IPFS, no drive, no station identity, no
panel) so the registry can be deployed on its own host — e.g. a small VPS
fronting registry.<your-zone> — independent of any station's uptime.

Same code, same config as the station-mounted registry:
  - REGISTRY_ENABLED must be true (.env or environment)
  - <data_dir>/registry.json defines zones/drivers/claim modes
  - DNS driver tokens come from the environment (e.g. CLOUDFLARE_API_TOKEN)

Usage:
  REGISTRY_ENABLED=true CIPHER_DATA_DIR=/srv/registry \\
      python run_registry.py [--host 0.0.0.0] [--port 8443]

TLS: terminate at a reverse proxy (caddy/nginx) or pass --ssl-certfile/
--ssl-keyfile through to uvicorn via the extra args below.
"""

from __future__ import annotations

import argparse
import logging

import uvicorn
from fastapi import FastAPI

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(name)-28s  %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("run_registry")


def create_app() -> FastAPI:
    from cipher_station.registry.config import REGISTRY_ENABLED

    if not REGISTRY_ENABLED:
        raise SystemExit(
            "REGISTRY_ENABLED is not true — refusing to start. "
            "Set REGISTRY_ENABLED=true in the environment or .env."
        )

    from cipher_station.registry.router import registry_router

    app = FastAPI(title="Cipher Subdomain Registry", version="1.0.0")
    app.include_router(registry_router)

    @app.get("/health")
    async def health() -> dict:
        from cipher_station.registry.config import load_zones

        zones = load_zones()
        return {"status": "ok", "zones": sorted(zones.keys())}

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Standalone subdomain registry")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--ssl-certfile", default=None)
    parser.add_argument("--ssl-keyfile", default=None)
    args = parser.parse_args()

    app = create_app()
    logger.info("Standalone registry starting on %s:%s", args.host, args.port)
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        ssl_certfile=args.ssl_certfile,
        ssl_keyfile=args.ssl_keyfile,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
