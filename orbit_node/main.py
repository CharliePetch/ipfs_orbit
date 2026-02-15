from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from pydantic import BaseModel
import json
import hashlib
import logging

from orbit_node.config import ensure_directories, MAX_UPLOAD_SIZE, CORS_ORIGINS
from orbit_node.inbox import process_inbox_message
from orbit_node.rewrap import handle_rewrap_request

from orbit_node.posts import handle_new_post
from orbit_node.profile import get_public_profile
from orbit_node.following import follow_user, unfollow_user
from orbit_node.graph import rebuild_graphs_and_envelopes
from orbit_node.database import get_db
from orbit_node.identity import get_identity
from orbit_node.followers import add_follower_device
from orbit_node.pairing import create_pairing_session, confirm_pairing_session
from orbit_node.auth import require_delegate
from orbit_node.tunnel import start_tunnel_monitor

logger = logging.getLogger(__name__)


class DelegateStart(BaseModel):
    device_uid: str
    public_key: str

class DelegateConfirm(BaseModel):
    pairing_id: str
    pin: str

class InboxMessage(BaseModel):
    type: str
    uid: str | None = None
    public_key: str | None = None
    payload_hex: str | None = None
    devices: list[dict] | None = None

class RewrapMessage(BaseModel):
    uid: str
    device_uid: str
    post_cid: str
    envelopes_cid: str | None = None

app = FastAPI(title="Orbit Node", version="1.0.0")

# --------------------------------------------
# CORS
# --------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------
# Middleware: body SHA256 + upload size limit
# --------------------------------------------
@app.middleware("http")
async def capture_raw_body_sha256(request: Request, call_next):
    guarded_paths = {"/post", "/rewrap", "/follow", "/unfollow", "/inbox"}
    if request.url.path in guarded_paths:
        cl = request.headers.get("content-length")
        if cl is not None and cl.isdigit() and int(cl) > MAX_UPLOAD_SIZE:
            return JSONResponse(
                status_code=413,
                content={"error": f"Request too large (max {MAX_UPLOAD_SIZE} bytes)"}
            )

        body = await request.body()
        request.state.raw_body_sha256 = hashlib.sha256(body).hexdigest()

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        request._receive = receive

    return await call_next(request)


@app.on_event("startup")
def startup():
    ensure_directories()
    get_db()

    sk, public_key, pub_json = get_identity()
    uid = pub_json["uid"]
    device_uid = pub_json.get("device_uid", uid)

    try:
        add_follower_device(
            uid,
            device_uid,
            public_key,
            alias=pub_json.get("alias"),
            allowed="Allowed"
        )
    except Exception:
        pass

    logger.info(f"Station ready: uid={uid}, device_uid={device_uid}")

    # Start Cloudflare tunnel URL monitor (if enabled)
    start_tunnel_monitor()


# ---------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------
@app.get("/health")
def health_check():
    checks = {"database": False, "ipfs": False, "identity": False}

    try:
        db = get_db()
        db.execute("SELECT 1").fetchone()
        checks["database"] = True
    except Exception as e:
        logger.error(f"Health check DB failed: {e}")

    try:
        from orbit_node.ipfs_client import ipfs_add_bytes
        ipfs_add_bytes(b"health")
        checks["ipfs"] = True
    except Exception as e:
        logger.error(f"Health check IPFS failed: {e}")

    try:
        get_identity()
        checks["identity"] = True
    except Exception as e:
        logger.error(f"Health check identity failed: {e}")

    all_ok = all(checks.values())
    return JSONResponse(
        status_code=200 if all_ok else 503,
        content={"status": "healthy" if all_ok else "degraded", "checks": checks}
    )


# ---------------------------------------------------------
# INBOX
# ---------------------------------------------------------
@app.post("/inbox")
async def inbox(request: Request, msg: InboxMessage):
    if msg.type != "follow_request":
        await require_delegate(request)

    priv, pub, _ = get_identity()
    result = process_inbox_message(priv, msg.model_dump())
    return {"status": "ok", "result": result}


# ---------------------------------------------------------
# REWRAP
# ---------------------------------------------------------
@app.post("/rewrap")
def rewrap_route(msg: RewrapMessage, delegate=Depends(require_delegate)):
    if delegate["uid"] != msg.uid or delegate["device_uid"] != msg.device_uid:
        raise HTTPException(status_code=401, detail="header/body mismatch")

    priv, pub, _pub_json = get_identity()
    result = handle_rewrap_request(priv, msg.model_dump())
    return {"status": "ok", "result": result}


# ---------------------------------------------------------
# NEW POST
# ---------------------------------------------------------
@app.post("/post")
def create_post(
    delegate=Depends(require_delegate),
    file: UploadFile = File(...),
    metadata: str = Form(None),
    client: str = Form(None),
):
    file_bytes = file.file.read()

    metadata_obj = None
    if metadata:
        try:
            metadata_obj = json.loads(metadata)
        except Exception as e:
            logger.warning(f"Invalid metadata JSON: {e}")

    return handle_new_post(file_bytes, metadata=metadata_obj, client=client)


# ---------------------------------------------------------
# PUBLIC PROFILE
# ---------------------------------------------------------
@app.get("/profile")
def profile():
    return get_public_profile()


class FollowRequest(BaseModel):
    uid: str
    endpoint: str
    public_key: str
    ipns_id: str | None = None  # IPNS peer ID for permanent discovery


# ---------------------------------------------------------
# FOLLOW / UNFOLLOW
# ---------------------------------------------------------
@app.post("/follow")
def api_follow(req: FollowRequest, auth_ctx=Depends(require_delegate)):
    follow_user(req.uid, req.public_key, req.endpoint, ipns_id=req.ipns_id)

    cids = rebuild_graphs_and_envelopes()
    prof = get_public_profile()

    return {
        "status": "ok",
        "action": "follow",
        "target": {
            "uid": req.uid,
            "public_key": req.public_key,
            "endpoint": req.endpoint,
            "ipns_id": req.ipns_id,
        },
        "updated_graph": cids,
        "updated_profile": prof
    }


class UnfollowRequest(BaseModel):
    uid: str
    public_key: str


@app.post("/unfollow")
def api_unfollow(req: UnfollowRequest, auth_ctx=Depends(require_delegate)):
    unfollow_user(req.uid, req.public_key)

    cids = rebuild_graphs_and_envelopes()
    prof = get_public_profile()

    return {
        "status": "ok",
        "action": "unfollow",
        "target": {
            "uid": req.uid,
            "public_key": req.public_key
        },
        "updated_graph": cids,
        "updated_profile": prof
    }


@app.post("/delegate/start")
def delegate_start(req: DelegateStart):
    sess = create_pairing_session(req.device_uid, req.public_key)
    logger.info(f"Pairing session created: pairing_id={sess.pairing_id}")
    logger.info(f">>> PAIRING PIN: {sess.pin} <<< (expires in 5 minutes)")
    return {"status": "ok", "pairing_id": sess.pairing_id, "expires_in_seconds": 5 * 60}


@app.post("/delegate/confirm")
def delegate_confirm(req: DelegateConfirm):
    device_uid, device_public_key = confirm_pairing_session(req.pairing_id, req.pin)

    priv, pub, pub_json = get_identity()
    uid = pub_json["uid"]

    add_follower_device(
        uid,
        device_uid,
        device_public_key,
        alias=None,
        allowed="Allowed"
    )

    return {"status": "ok", "action": "delegate_added", "uid": uid, "device_uid": device_uid}
