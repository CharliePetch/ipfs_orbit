import os
os.environ["PYTHONNOUSERSITE"] = "1"

import subprocess
import logging
from pathlib import Path

import uvicorn

from orbit_node.config import (
    ORBIT_PORT, ORBIT_HOST, SSL_CERTFILE, SSL_KEYFILE,
    LOG_LEVEL, ensure_directories,
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
            "-subj", "/CN=orbit-station",
        ],
        check=True,
        capture_output=True,
    )
    logger.info(f"Certificate written to {cert}")


if __name__ == "__main__":
    ensure_directories()
    _ensure_ssl_cert()

    uvicorn.run(
        "orbit_node.main:app",
        port=ORBIT_PORT,
        host=ORBIT_HOST,
        reload=False,
        ssl_certfile=SSL_CERTFILE,
        ssl_keyfile=SSL_KEYFILE,
        log_level=LOG_LEVEL.lower(),
    )
