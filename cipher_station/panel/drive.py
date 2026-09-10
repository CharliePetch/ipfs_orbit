# cipher_station/panel/drive.py
"""
Server-side drive client (feature area B) — CipherVault-compatible.

Conventions (must match the CipherVault iOS app so both see the same drive):
  * Drive posts live in the manifest bucket ``clients.drive.posts`` — the
    ``--client drive`` namespace.
  * Folder membership is ``tags: [FolderName]`` inside the ENCRYPTED metadata.
  * The filename (and mime type / size) also live in the encrypted metadata.
  * Metadata is SecretBox-encrypted hex using the post's own symmetric key
    (posts._encrypt_metadata wire format: nonce||ciphertext, hex).
  * The symmetric key is recoverable by the station via its own self envelope
    (envelopes JSON on IPFS, sealed to the station ML-KEM key) — the same
    rewrap machinery rewrap.py uses.

The panel runs INSIDE the station process and is localhost-only, so it uses
the station keys directly: decrypt server-side, stream plaintext to the
browser. Plaintext is never written to disk.
"""

import json
import logging
import mimetypes
import time

from nacl.secret import SecretBox

from cipher_station.envelopes import open_envelope
from cipher_station.identity import get_identity
from cipher_station.ipfs_client import ipfs_get_bytes
from cipher_station.manifest import load_manifest, remove_post_from_manifest
from cipher_station.posts import handle_new_post

logger = logging.getLogger(__name__)

DRIVE_CLIENT = "drive"


class DriveError(Exception):
    """A drive operation failed in a way the UI should surface."""


def _decrypt_metadata(metadata_hex: str, sym_key: bytes) -> dict:
    """Inverse of posts._encrypt_metadata: SecretBox(hex nonce||ct) -> dict."""
    raw = SecretBox(sym_key).decrypt(bytes.fromhex(metadata_hex))
    obj = json.loads(raw.decode("utf-8"))
    return obj if isinstance(obj, dict) else {}


def _recover_sym_key(entry: dict) -> bytes:
    """Recover a drive post's symmetric key via the station's self envelope."""
    envelopes_cid = entry.get("envelopes_cid")
    if not envelopes_cid:
        raise DriveError("post has no envelopes_cid")

    ident = get_identity()
    raw = ipfs_get_bytes(envelopes_cid)
    env_obj = json.loads(raw.decode("utf-8"))
    env_map = env_obj.get("envelopes", {})
    self_env = env_map.get(ident.uid)
    if not self_env:
        raise DriveError("no self envelope for the station on this post")

    sym_key = open_envelope(ident.mlkem_sk, self_env)
    if not sym_key or len(sym_key) != SecretBox.KEY_SIZE:
        raise DriveError("failed to recover symmetric key")
    return sym_key


def _drive_entries() -> list[dict]:
    manifest = load_manifest(client=DRIVE_CLIENT)
    bucket = manifest.get("clients", {}).get(DRIVE_CLIENT, {})
    posts = bucket.get("posts", []) if isinstance(bucket, dict) else []
    return [p for p in posts if isinstance(p, dict)]


def _entry_for_cid(post_cid: str) -> dict:
    for entry in _drive_entries():
        if entry.get("post_cid") == post_cid:
            return entry
    raise KeyError(post_cid)


def list_files() -> dict:
    """
    Decrypt every drive post's metadata and return the file listing plus the
    folder set. Posts whose metadata cannot be decrypted are reported (not
    silently dropped) so the UI can show a real error state.
    """
    files: list[dict] = []
    errors: list[dict] = []

    for entry in _drive_entries():
        post_cid = entry.get("post_cid")
        item: dict = {
            "post_cid": post_cid,
            "created_at": entry.get("created_at"),
        }
        try:
            metadata_hex = entry.get("metadata")
            if not isinstance(metadata_hex, str) or not metadata_hex:
                raise DriveError("post has no encrypted metadata")
            sym_key = _recover_sym_key(entry)
            meta = _decrypt_metadata(metadata_hex, sym_key)
            tags = meta.get("tags")
            folders = [t for t in tags if isinstance(t, str)] if isinstance(tags, list) else []
            item.update({
                "filename": meta.get("filename") or "(unnamed)",
                "size_bytes": meta.get("size_bytes"),
                "mime_type": meta.get("mime_type"),
                "folders": folders,
                "created_at": meta.get("created_at") or entry.get("created_at"),
            })
            files.append(item)
        except Exception as exc:
            logger.warning("Drive: could not read metadata for %s: %s", post_cid, exc)
            errors.append({"post_cid": post_cid, "error": str(exc)})

    folders = sorted({f for item in files for f in item["folders"]})
    files.sort(key=lambda f: (f.get("created_at") or 0), reverse=True)
    return {"files": files, "folders": folders, "errors": errors}


def open_file(post_cid: str) -> tuple[bytes, dict]:
    """
    Decrypt one drive file fully in memory.
    Returns (plaintext_bytes, metadata_dict). Raises KeyError / DriveError.
    """
    entry = _entry_for_cid(post_cid)
    sym_key = _recover_sym_key(entry)

    meta: dict = {}
    metadata_hex = entry.get("metadata")
    if isinstance(metadata_hex, str) and metadata_hex:
        try:
            meta = _decrypt_metadata(metadata_hex, sym_key)
        except Exception as exc:
            logger.warning("Drive: metadata decrypt failed for %s: %s", post_cid, exc)

    ciphertext = ipfs_get_bytes(post_cid)
    try:
        plaintext = SecretBox(sym_key).decrypt(ciphertext)
    except Exception as exc:
        raise DriveError(f"content decryption failed: {exc}") from exc
    return plaintext, meta


def guess_mime(meta: dict) -> str:
    mime = meta.get("mime_type")
    if isinstance(mime, str) and "/" in mime:
        return mime
    filename = meta.get("filename")
    if isinstance(filename, str):
        guessed, _ = mimetypes.guess_type(filename)
        if guessed:
            return guessed
    return "application/octet-stream"


def upload_file(file_bytes: bytes, filename: str, folder: str | None = None) -> dict:
    """
    Store a file on the drive exactly like a ``--client drive`` device post
    (station-driven path: fresh sym key, SecretBox content, encrypted metadata
    with filename + tags), so CipherVault sees it as a native drive file.
    """
    filename = (filename or "").strip()
    if not filename:
        raise ValueError("filename is required")
    if "/" in filename or "\x00" in filename:
        raise ValueError("filename must not contain '/'")

    folder = (folder or "").strip()
    mime, _ = mimetypes.guess_type(filename)
    now = int(time.time())
    metadata = {
        "filename": filename,
        "mime_type": mime or "application/octet-stream",
        "size_bytes": len(file_bytes),
        "created_at": now,
        "modified_at": now,
        "tags": [folder] if folder else [],
    }

    result = handle_new_post(
        file_bytes,
        metadata=metadata,
        audience_mode="self",     # personal drive: only the station holds the key
        client=DRIVE_CLIENT,
    )
    return {
        "status": "uploaded",
        "post_cid": result.get("cid"),
        "filename": filename,
        "folder": folder or None,
        "size_bytes": len(file_bytes),
    }


def delete_file(post_cid: str) -> dict:
    """Remove the post + manifest entry via the existing delete path
    (unpins content + envelopes and runs IPFS GC, like /post/delete)."""
    result = remove_post_from_manifest(post_cid, client=DRIVE_CLIENT)
    if result.get("status") == "not_found":
        raise KeyError(post_cid)
    return result
