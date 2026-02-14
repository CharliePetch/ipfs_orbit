# orbit_node/storage.py

import json
import logging
from pathlib import Path

from orbit_node.config import BASE_DIR, KEYS_DIR, PUBLIC_JSON_PATH

logger = logging.getLogger(__name__)


def write_file(path: Path, data: bytes):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
    except OSError as exc:
        logger.error("Failed to write file %s: %s", path, exc)
        raise


def read_file(path: Path) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        logger.error("File not found: %s", path)
        raise
    except OSError as exc:
        logger.error("Failed to read file %s: %s", path, exc)
        raise


def write_json(path: Path, obj: dict):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(obj, f, indent=4)
    except (OSError, TypeError) as exc:
        logger.error("Failed to write JSON %s: %s", path, exc)
        raise


def read_json(path: Path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error("JSON file not found: %s", path)
        raise
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON in %s: %s", path, exc)
        raise
    except OSError as exc:
        logger.error("Failed to read JSON %s: %s", path, exc)
        raise
