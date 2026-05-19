"""
FastAPI backend for the watermark MVP.

Endpoints:
  POST /v1/tenants                     — bootstrap tenant + user (admin-only)
  POST /v1/devices/enroll              — provision a device, return enrollment secret
  POST /v1/sessions                    — issue a session token + MAC key (agent)
  POST /v1/extract                     — forensic extraction (investigator)
  GET  /v1/health                      — liveness

The endpoints that would require enterprise SSO (BUILD_SPEC.md §5.1) are
gated by simple bearer tokens here:
  - Tenant admin bearer: set per tenant at creation.
  - Investigator bearer: shared admin token (env WATERMARK_ADMIN_TOKEN).
  - Device bearer: device enroll secret returned at enrollment.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import os
import secrets
from typing import Optional

import numpy as np
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core import (
    PAYLOAD_BITS,
    TOKEN_BITS,
    conv_code,
    derive_mac_key,
    payload as payload_mod,
    symbols,
)
from . import db
from .db import (
    AuditEvent,
    Device,
    Extraction,
    Session_,
    Tenant,
    User,
)


ADMIN_TOKEN_ENV = "WATERMARK_ADMIN_TOKEN"
DEFAULT_TOKEN_TTL_SECONDS = 5 * 60  # 5-minute rotation per spec §3.1


def get_admin_token() -> str:
    tok = os.environ.get(ADMIN_TOKEN_ENV)
    if not tok:
        raise RuntimeError(
            f"set {ADMIN_TOKEN_ENV} before starting the backend "
            "(e.g., export WATERMARK_ADMIN_TOKEN=$(openssl rand -hex 16))"
        )
    return tok


# ---------------------------------------------------------------------------
# DI helpers
# ---------------------------------------------------------------------------
def db_session() -> Session:
    s = db.get_session()
    try:
        yield s
    finally:
        s.close()


def require_admin(authorization: str = Header(None)) -> None:
    expected = get_admin_token()
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    if not secrets.compare_digest(authorization[7:], expected):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "bad admin token")


def require_device(
    s: Session = Depends(db_session),
    authorization: str = Header(None),
    x_device_id: str = Header(None),
) -> Device:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    if not x_device_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "missing X-Device-Id header")
    device = s.get(Device, x_device_id)
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    if not secrets.compare_digest(authorization[7:], device.enroll_secret):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "bad device secret")
    return device


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class CreateTenantReq(BaseModel):
    tenant_name: str
    user_email: str


class CreateTenantResp(BaseModel):
    tenant_id: str
    user_id: str


class EnrollDeviceReq(BaseModel):
    tenant_id: str
    user_id: str
    hostname: str
    os: str = "unknown"


class EnrollDeviceResp(BaseModel):
    device_id: str
    enroll_secret: str


class IssueSessionResp(BaseModel):
    token: int = Field(..., description="40-bit opaque session token")
    token_hex: str
    mac_key_hex: str
    issued_at: dt.datetime
    expires_at: dt.datetime
    payload_bits: list[int]
    encoded_symbols: list[int]
    watermark_w: int
    watermark_h: int
    symbol_size: int


class ExtractResp(BaseModel):
    success: bool
    strategy: str
    ber_estimate: float
    token_hex: Optional[str] = None
    tenant_id: Optional[str] = None
    user_email: Optional[str] = None
    device_hostname: Optional[str] = None
    time_window_start: Optional[dt.datetime] = None
    time_window_end: Optional[dt.datetime] = None
    failure_reason: Optional[str] = None
    audit_id: Optional[str] = None


class TenantOut(BaseModel):
    id: str
    name: str
    created_at: dt.datetime


class UserOut(BaseModel):
    id: str
    tenant_id: str
    email: str
    created_at: dt.datetime


class DeviceOut(BaseModel):
    id: str
    tenant_id: str
    user_id: str
    hostname: str
    os: str
    created_at: dt.datetime


class SessionOut(BaseModel):
    token: int
    token_hex: str
    tenant_id: str
    user_id: str
    device_id: str
    issued_at: dt.datetime
    expires_at: dt.datetime


class ExtractionOut(BaseModel):
    id: str
    tenant_id: Optional[str] = None
    investigator_email: str
    case_id: str
    image_sha256: str
    result_summary: Optional[str] = None
    ts: dt.datetime


class AuditEventOut(BaseModel):
    id: str
    tenant_id: Optional[str] = None
    event_type: str
    actor: Optional[str] = None
    target: Optional[str] = None
    payload: Optional[str] = None
    ts: dt.datetime


class CreateUserReq(BaseModel):
    tenant_id: str
    email: str


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
def _audit(s: Session, tenant_id: Optional[str], event_type: str, actor: Optional[str],
           target: Optional[str], payload: Optional[dict]) -> AuditEvent:
    evt = AuditEvent(
        tenant_id=tenant_id,
        event_type=event_type,
        actor=actor,
        target=target,
        payload=json.dumps(payload) if payload else None,
    )
    s.add(evt)
    s.flush()
    return evt


def create_app() -> FastAPI:
    app = FastAPI(title="Watermark MVP", version="0.1.0")

    # CORS — comma-separated origins via WATERMARK_CORS_ORIGINS, or "*" by default
    # so the prompt-and-store-token UI can talk to the API from any host.
    cors_env = os.environ.get("WATERMARK_CORS_ORIGINS", "*").strip()
    if cors_env == "*":
        allow_origins = ["*"]
    else:
        allow_origins = [o.strip() for o in cors_env.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Eager-init DB so SQLite file is created on startup.
    db.get_engine()

    @app.get("/v1/health")
    def health():
        return {"status": "ok"}

    @app.post("/v1/tenants", response_model=CreateTenantResp,
              dependencies=[Depends(require_admin)])
    def create_tenant(req: CreateTenantReq, s: Session = Depends(db_session)):
        tenant = Tenant(name=req.tenant_name, master_key=secrets.token_bytes(32))
        s.add(tenant)
        s.flush()
        user = User(tenant_id=tenant.id, email=req.user_email)
        s.add(user)
        s.flush()
        _audit(s, tenant.id, "tenant.created", actor=req.user_email,
               target=tenant.id, payload={"user_id": user.id})
        s.commit()
        return CreateTenantResp(tenant_id=tenant.id, user_id=user.id)

    @app.post("/v1/devices/enroll", response_model=EnrollDeviceResp,
              dependencies=[Depends(require_admin)])
    def enroll_device(req: EnrollDeviceReq, s: Session = Depends(db_session)):
        tenant = s.get(Tenant, req.tenant_id)
        if tenant is None:
            raise HTTPException(404, "tenant not found")
        user = s.get(User, req.user_id)
        if user is None or user.tenant_id != tenant.id:
            raise HTTPException(404, "user not found in tenant")
        secret = secrets.token_urlsafe(32)
        device = Device(
            tenant_id=tenant.id,
            user_id=user.id,
            hostname=req.hostname,
            os=req.os,
            enroll_secret=secret,
        )
        s.add(device)
        s.flush()
        _audit(s, tenant.id, "device.enrolled", actor=user.email,
               target=device.id, payload={"hostname": req.hostname, "os": req.os})
        s.commit()
        return EnrollDeviceResp(device_id=device.id, enroll_secret=secret)

    def _issue_unique_token(s: Session) -> int:
        # Generate a 40-bit token; collide-check against active sessions.
        for _ in range(8):
            tok = secrets.randbits(TOKEN_BITS)
            if s.get(Session_, tok) is None:
                return tok
        raise HTTPException(500, "token allocation failed")

    @app.post("/v1/sessions", response_model=IssueSessionResp)
    def issue_session(
        s: Session = Depends(db_session),
        device: Device = Depends(require_device),
    ):
        tenant = s.get(Tenant, device.tenant_id)
        assert tenant is not None  # FK
        user = s.get(User, device.user_id)
        assert user is not None  # FK

        token = _issue_unique_token(s)
        mac_key = derive_mac_key(
            tenant.master_key, token, user_id=user.id, device_id=device.id,
        )
        now = dt.datetime.now(dt.timezone.utc)
        expires = now + dt.timedelta(seconds=DEFAULT_TOKEN_TTL_SECONDS)
        sess = Session_(
            token=token,
            tenant_id=tenant.id,
            user_id=user.id,
            device_id=device.id,
            mac_key=mac_key,
            issued_at=now,
            expires_at=expires,
        )
        s.add(sess)
        _audit(s, tenant.id, "session.issued", actor=user.email,
               target=str(token), payload={"device_id": device.id, "ttl": DEFAULT_TOKEN_TTL_SECONDS})
        s.commit()

        # Pre-compute encoded symbols so the agent can render without
        # duplicating algorithm code. Production agents would call the
        # core lib locally to avoid round-tripping payload over the wire.
        payload_bits = payload_mod.make_payload(token, mac_key)
        encoded = conv_code.encode(payload_bits)

        return IssueSessionResp(
            token=token,
            token_hex=f"0x{token:010x}",
            mac_key_hex=mac_key.hex(),
            issued_at=now,
            expires_at=expires,
            payload_bits=payload_bits,
            encoded_symbols=encoded,
            watermark_w=symbols.WATERMARK_W,
            watermark_h=symbols.WATERMARK_H,
            symbol_size=symbols.SYMBOL_SIZE,
        )

    @app.post("/v1/extract", response_model=ExtractResp)
    def extract(
        case_id: str = Form(...),
        investigator_email: str = Form(...),
        screen_w: int = Form(...),
        screen_h: int = Form(...),
        image: UploadFile = File(...),
        s: Session = Depends(db_session),
        _admin: None = Depends(require_admin),
    ):
        raw = image.file.read()
        if not raw:
            raise HTTPException(400, "empty image upload")
        sha256 = hashlib.sha256(raw).hexdigest()

        try:
            pil = Image.open(io.BytesIO(raw)).convert("RGB")
        except Exception as e:
            raise HTTPException(400, f"unreadable image: {e}")
        arr = np.array(pil)
        if arr.shape[:2] != (screen_h, screen_w):
            raise HTTPException(
                400,
                f"image size {arr.shape[1]}x{arr.shape[0]} does not match "
                f"declared screen {screen_w}x{screen_h}",
            )

        soft = symbols.extract_soft_bits(arr, screen_w, screen_h)

        # MAC verifier needs to find the matching session's MAC key. We try
        # each Viterbi candidate against the DB: the recovered token is the
        # primary key, so this is a single point lookup per candidate.
        def verifier(bits: list[int]):
            tok = payload_mod.int_from_bits(bits[:TOKEN_BITS])
            sess = s.get(Session_, tok)
            if sess is None:
                return False, tok
            ok, _ = payload_mod.verify_payload(bits, sess.mac_key)
            return ok, tok

        result = conv_code.decode(soft, verifier)

        # Build response: lookup attribution metadata if MAC verified.
        resp = ExtractResp(
            success=result.mac_ok,
            strategy=result.strategy,
            ber_estimate=result.ber_estimate,
        )
        if result.mac_ok and result.token is not None:
            sess = s.get(Session_, result.token)
            assert sess is not None
            user = s.get(User, sess.user_id)
            device = s.get(Device, sess.device_id)
            tenant = s.get(Tenant, sess.tenant_id)
            resp.token_hex = f"0x{result.token:010x}"
            resp.tenant_id = sess.tenant_id
            resp.user_email = user.email if user else None
            resp.device_hostname = device.hostname if device else None
            resp.time_window_start = sess.issued_at
            resp.time_window_end = sess.expires_at
        else:
            resp.failure_reason = (
                "no Viterbi candidate verified MAC; image may not contain a "
                "watermark or is too degraded"
            )

        extraction = Extraction(
            tenant_id=resp.tenant_id,
            investigator_email=investigator_email,
            case_id=case_id,
            image_sha256=sha256,
            result_summary=resp.model_dump_json(),
        )
        s.add(extraction)
        audit = _audit(
            s,
            resp.tenant_id,
            "extraction.completed" if result.mac_ok else "extraction.failed",
            actor=investigator_email,
            target=resp.token_hex,
            payload={
                "case_id": case_id,
                "image_sha256": sha256,
                "strategy": result.strategy,
                "ber_estimate": result.ber_estimate,
            },
        )
        resp.audit_id = audit.id
        s.commit()
        return resp

    # -----------------------------------------------------------------------
    # Read endpoints (admin) — backing the management UI
    # -----------------------------------------------------------------------
    @app.get("/v1/tenants", response_model=list[TenantOut],
             dependencies=[Depends(require_admin)])
    def list_tenants(s: Session = Depends(db_session)):
        rows = s.execute(select(Tenant).order_by(Tenant.created_at.desc())).scalars().all()
        return [TenantOut(id=t.id, name=t.name, created_at=t.created_at) for t in rows]

    @app.get("/v1/users", response_model=list[UserOut],
             dependencies=[Depends(require_admin)])
    def list_users(
        tenant_id: Optional[str] = None,
        s: Session = Depends(db_session),
    ):
        q = select(User)
        if tenant_id:
            q = q.where(User.tenant_id == tenant_id)
        rows = s.execute(q.order_by(User.created_at.desc())).scalars().all()
        return [
            UserOut(id=u.id, tenant_id=u.tenant_id, email=u.email, created_at=u.created_at)
            for u in rows
        ]

    @app.post("/v1/users", response_model=UserOut,
              dependencies=[Depends(require_admin)])
    def create_user(req: CreateUserReq, s: Session = Depends(db_session)):
        tenant = s.get(Tenant, req.tenant_id)
        if tenant is None:
            raise HTTPException(404, "tenant not found")
        user = User(tenant_id=tenant.id, email=req.email)
        s.add(user)
        s.flush()
        _audit(s, tenant.id, "user.created", actor=req.email,
               target=user.id, payload={"tenant_id": tenant.id})
        s.commit()
        return UserOut(id=user.id, tenant_id=user.tenant_id, email=user.email,
                       created_at=user.created_at)

    @app.get("/v1/devices", response_model=list[DeviceOut],
             dependencies=[Depends(require_admin)])
    def list_devices(
        tenant_id: Optional[str] = None,
        user_id: Optional[str] = None,
        s: Session = Depends(db_session),
    ):
        q = select(Device)
        if tenant_id:
            q = q.where(Device.tenant_id == tenant_id)
        if user_id:
            q = q.where(Device.user_id == user_id)
        rows = s.execute(q.order_by(Device.created_at.desc())).scalars().all()
        return [
            DeviceOut(
                id=d.id, tenant_id=d.tenant_id, user_id=d.user_id,
                hostname=d.hostname, os=d.os, created_at=d.created_at,
            )
            for d in rows
        ]

    @app.get("/v1/sessions", response_model=list[SessionOut],
             dependencies=[Depends(require_admin)])
    def list_sessions(
        tenant_id: Optional[str] = None,
        user_id: Optional[str] = None,
        device_id: Optional[str] = None,
        limit: int = 100,
        s: Session = Depends(db_session),
    ):
        q = select(Session_)
        if tenant_id:
            q = q.where(Session_.tenant_id == tenant_id)
        if user_id:
            q = q.where(Session_.user_id == user_id)
        if device_id:
            q = q.where(Session_.device_id == device_id)
        rows = s.execute(q.order_by(Session_.issued_at.desc()).limit(limit)).scalars().all()
        return [
            SessionOut(
                token=r.token,
                token_hex=f"0x{r.token:010x}",
                tenant_id=r.tenant_id,
                user_id=r.user_id,
                device_id=r.device_id,
                issued_at=r.issued_at,
                expires_at=r.expires_at,
            )
            for r in rows
        ]

    @app.get("/v1/extractions", response_model=list[ExtractionOut],
             dependencies=[Depends(require_admin)])
    def list_extractions(
        tenant_id: Optional[str] = None,
        limit: int = 100,
        s: Session = Depends(db_session),
    ):
        q = select(Extraction)
        if tenant_id:
            q = q.where(Extraction.tenant_id == tenant_id)
        rows = s.execute(q.order_by(Extraction.ts.desc()).limit(limit)).scalars().all()
        return [
            ExtractionOut(
                id=r.id, tenant_id=r.tenant_id,
                investigator_email=r.investigator_email,
                case_id=r.case_id, image_sha256=r.image_sha256,
                result_summary=r.result_summary, ts=r.ts,
            )
            for r in rows
        ]

    @app.get("/v1/audit", response_model=list[AuditEventOut],
             dependencies=[Depends(require_admin)])
    def list_audit(
        tenant_id: Optional[str] = None,
        limit: int = 200,
        s: Session = Depends(db_session),
    ):
        q = select(AuditEvent)
        if tenant_id:
            q = q.where(AuditEvent.tenant_id == tenant_id)
        rows = s.execute(q.order_by(AuditEvent.ts.desc()).limit(limit)).scalars().all()
        return [
            AuditEventOut(
                id=r.id, tenant_id=r.tenant_id, event_type=r.event_type,
                actor=r.actor, target=r.target, payload=r.payload, ts=r.ts,
            )
            for r in rows
        ]

    return app
