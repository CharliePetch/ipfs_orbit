# cipher_station/panel/router.py
"""
Admin panel routes, mounted in main.py under /admin.

Every route — page, static assets, and API — carries the localhost-only guard
(guard.require_localhost) as a router-level dependency. None of them use the
x-cipher-* signed-header auth: the trust boundary is the loopback socket.
"""

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel
from starlette.responses import FileResponse, Response

from cipher_station.panel import drive, service
from cipher_station.panel.guard import require_localhost

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"

panel_router = APIRouter(prefix="/admin", dependencies=[Depends(require_localhost)])


# ---------------------------------------------------------------------------
# Page + static assets
# ---------------------------------------------------------------------------

@panel_router.get("", include_in_schema=False)
@panel_router.get("/", include_in_schema=False)
def panel_index():
    return FileResponse(STATIC_DIR / "index.html", media_type="text/html")


@panel_router.get("/static/{filename}", include_in_schema=False)
def panel_static(filename: str):
    # Flat static dir; refuse anything that is not a direct child of it.
    target = (STATIC_DIR / filename).resolve()
    if target.parent != STATIC_DIR or not target.is_file():
        raise HTTPException(status_code=404, detail="not found")
    return FileResponse(target)


# ---------------------------------------------------------------------------
# Status + configuration API
# ---------------------------------------------------------------------------

@panel_router.get("/api/status")
def api_status():
    return service.get_status()


@panel_router.get("/api/config")
def api_get_config():
    return service.get_config()


class ConfigUpdate(BaseModel):
    alias: str | None = None
    cloudflare_tunnel_enabled: bool | None = None
    permanent_url: str | None = None
    clear_permanent_url: bool = False


@panel_router.post("/api/config")
def api_update_config(req: ConfigUpdate):
    provided = req.model_dump(exclude_unset=True)
    result: dict = {"status": "ok", "restart_required": False}
    try:
        if "alias" in provided:
            result["alias"] = service.set_alias(provided["alias"])["alias"]
        env_result = service.update_env_settings(
            cloudflare_tunnel_enabled=provided.get("cloudflare_tunnel_enabled"),
            permanent_url=provided.get("permanent_url"),
            clear_permanent_url=req.clear_permanent_url,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    result["env_changed"] = env_result.get("changed", [])
    if env_result.get("restart_required"):
        result["restart_required"] = True
        result["restart_command"] = env_result["restart_command"]
    return result


class StorageMaxUpdate(BaseModel):
    storage_max: str


@panel_router.post("/api/config/storage-max")
def api_set_storage_max(req: StorageMaxUpdate):
    try:
        service.set_storage_max(req.storage_max)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"IPFS unreachable: {e}")
    return {
        "status": "ok",
        "storage_max": req.storage_max,
        # StorageMax applies at GC time; a daemon restart re-reads it now.
        "restart_required": True,
        "restart_command": "sudo systemctl restart ipfs",
    }


class ProfileUpdate(BaseModel):
    display_name: str | None = None
    username: str | None = None
    bio: str | None = None
    link: str | None = None


@panel_router.post("/api/profile")
def api_update_profile(req: ProfileUpdate):
    from cipher_station.profile import update_profile_fields
    provided = req.model_dump(exclude_unset=True)
    try:
        prof = update_profile_fields(**provided)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "ok", "profile": prof}


# ---------------------------------------------------------------------------
# Drive API
# ---------------------------------------------------------------------------

@panel_router.get("/api/drive/files")
def api_drive_files():
    try:
        return drive.list_files()
    except Exception as e:
        logger.error("Drive listing failed: %s", e)
        raise HTTPException(status_code=503, detail=f"drive unavailable: {e}")


@panel_router.get("/api/drive/file/{post_cid}")
def api_drive_file(post_cid: str, download: bool = False):
    try:
        plaintext, meta = drive.open_file(post_cid)
    except KeyError:
        raise HTTPException(status_code=404, detail="file not found")
    except drive.DriveError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except Exception as e:
        logger.error("Drive read failed for %s: %s", post_cid, e)
        raise HTTPException(status_code=503, detail=f"drive unavailable: {e}")

    filename = meta.get("filename") or post_cid
    disposition = "attachment" if download else "inline"
    safe_name = str(filename).replace('"', "")
    return Response(
        content=plaintext,
        media_type=drive.guess_mime(meta),
        headers={
            "Content-Disposition": f'{disposition}; filename="{safe_name}"',
            # Decrypted private content: keep it out of shared caches.
            "Cache-Control": "no-store",
        },
    )


@panel_router.post("/api/drive/upload")
def api_drive_upload(
    file: UploadFile = File(...),
    folder: str = Form(None),
):
    file_bytes = file.file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="empty file")
    try:
        return drive.upload_file(file_bytes, file.filename or "", folder)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Drive upload failed: %s", e)
        raise HTTPException(status_code=503, detail=f"upload failed: {e}")


class DriveDelete(BaseModel):
    post_cid: str


@panel_router.post("/api/drive/delete")
def api_drive_delete(req: DriveDelete):
    try:
        return drive.delete_file(req.post_cid)
    except KeyError:
        raise HTTPException(status_code=404, detail="file not found")
    except Exception as e:
        logger.error("Drive delete failed for %s: %s", req.post_cid, e)
        raise HTTPException(status_code=503, detail=f"delete failed: {e}")
