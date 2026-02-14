# orbit_node/ipfs_client.py

import logging
import time

import requests

from orbit_node.config import IPFS_API, IPFS_TIMEOUT, IPFS_MAX_RETRIES

logger = logging.getLogger(__name__)


class IPFSError(Exception):
    """Raised when an IPFS operation fails after all retries."""
    pass


def _with_retry(func):
    """
    Execute *func* with exponential-backoff retry on transient errors.
    Non-transient HTTP errors (4xx) are raised immediately.
    """
    last_exc = None
    for attempt in range(IPFS_MAX_RETRIES):
        try:
            return func()
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
            last_exc = exc
            if attempt < IPFS_MAX_RETRIES - 1:
                wait = 2 ** attempt
                logger.warning(
                    "IPFS retry %d/%d in %ds: %s", attempt + 1, IPFS_MAX_RETRIES, wait, exc
                )
                time.sleep(wait)
        except requests.exceptions.RequestException as exc:
            raise IPFSError(f"IPFS request error: {exc}") from exc

    raise IPFSError(
        f"IPFS failed after {IPFS_MAX_RETRIES} attempts: {last_exc}"
    ) from last_exc


def ipfs_add_bytes(data: bytes) -> str:
    """
    Upload raw binary content to IPFS.
    Returns the CID (string).
    """
    def _post():
        r = requests.post(
            f"{IPFS_API}/api/v0/add",
            files={"file": ("blob.bin", data)},
            timeout=IPFS_TIMEOUT,
        )
        r.raise_for_status()
        cid = r.json()["Hash"]
        logger.debug("IPFS add OK: %s (%d bytes)", cid, len(data))
        return cid

    return _with_retry(_post)


def ipfs_add_file(path: str) -> str:
    """
    Upload a local disk file to IPFS and return the CID.
    """
    with open(path, "rb") as f:
        return ipfs_add_bytes(f.read())


def ipfs_get_bytes(cid: str) -> bytes:
    """
    Fetch raw binary data from IPFS.
    """
    def _post():
        r = requests.post(
            f"{IPFS_API}/api/v0/cat",
            params={"arg": cid},
            timeout=IPFS_TIMEOUT,
        )
        r.raise_for_status()
        logger.debug("IPFS cat OK: %s (%d bytes)", cid, len(r.content))
        return r.content

    return _with_retry(_post)


# ---------------------------------------------------------------------------
# IPNS
# ---------------------------------------------------------------------------

def ipfs_name_publish(cid: str, lifetime: str = "720h") -> dict:
    """
    Publish a CID to IPNS under this node's peer ID (the 'self' key).
    Returns {"Name": "<peer-id>", "Value": "/ipfs/<cid>"}.
    Uses a longer timeout because IPNS DHT publishing is slow.
    """
    def _post():
        r = requests.post(
            f"{IPFS_API}/api/v0/name/publish",
            params={"arg": cid, "lifetime": lifetime},
            timeout=60,
        )
        r.raise_for_status()
        result = r.json()
        logger.info("IPNS publish OK: %s -> /ipfs/%s", result.get("Name", "?"), cid)
        return result

    return _with_retry(_post)


def ipfs_name_resolve(name: str) -> str:
    """
    Resolve an IPNS name to an /ipfs/CID path.
    Returns the path string, e.g. "/ipfs/QmXyz...".
    """
    def _post():
        r = requests.post(
            f"{IPFS_API}/api/v0/name/resolve",
            params={"arg": name},
            timeout=30,
        )
        r.raise_for_status()
        return r.json()["Path"]

    return _with_retry(_post)


def ipfs_id() -> dict:
    """
    Get this IPFS node's identity.
    Returns {"ID": "<peer-id>", "PublicKey": "...", "Addresses": [...]}.
    """
    def _post():
        r = requests.post(
            f"{IPFS_API}/api/v0/id",
            timeout=IPFS_TIMEOUT,
        )
        r.raise_for_status()
        return r.json()

    return _with_retry(_post)
