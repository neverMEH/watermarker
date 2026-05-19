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
from fastapi.responses import Response
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
    Asset,
    AuditEvent,
    Device,
    Extraction,
    Session_,
    Tenant,
    User,
)


ADMIN_TOKEN_ENV = "WATERMARK_ADMIN_TOKEN"
DEFAULT_TOKEN_TTL_SECONDS = 5 * 60  # 5-minute rotation per spec §3.1
# Asset-bound tokens never expire (forensic value depends on long-lived
# verifiability); use a 100-year sentinel.
ASSET_TOKEN_TTL_SECONDS = 100 * 365 * 24 * 60 * 60


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
    # Populated when the matched token is bound to an issued asset
    # (kind == "asset"). Lets the investigator console show who an artifact
    # was issued to without a second round-trip.
    session_kind: Optional[str] = None
    asset_id: Optional[str] = None
    asset_type: Optional[str] = None
    asset_status: Optional[str] = None
    asset_case_id: Optional[str] = None
    asset_description: Optional[str] = None
    asset_recipient_name: Optional[str] = None
    asset_recipient_email: Optional[str] = None
    asset_recipient_ref: Optional[str] = None
    asset_created_at: Optional[dt.datetime] = None


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


class AssetOut(BaseModel):
    id: str
    tenant_id: str
    asset_type: str
    case_id: Optional[str] = None
    description: Optional[str] = None
    recipient_user_id: Optional[str] = None
    recipient_name: Optional[str] = None
    recipient_email: Optional[str] = None
    recipient_ref: Optional[str] = None
    issued_by_email: Optional[str] = None
    token: int
    token_hex: str
    original_sha256: str
    original_mime: str
    original_w: int
    original_h: int
    status: str
    created_at: dt.datetime
    revoked_at: Optional[dt.datetime] = None
    revoked_reason: Optional[str] = None


class RevokeAssetReq(BaseModel):
    reason: Optional[str] = None


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


# Minimum image dimensions so the watermark grid (1248×384) plus its corner
# anchor markers fit with breathing room. Smaller uploads get upscaled.
_ASSET_MIN_W = symbols.WATERMARK_W + 32
_ASSET_MIN_H = symbols.WATERMARK_H + 36


def _watermark_png_bytes(orig_bytes: bytes, encoded_symbols: list[int]) -> tuple[bytes, int, int]:
    """Decode bytes → RGB → apply overlay → re-encode as PNG. Upscales
    images smaller than the watermark region (preserving aspect). Returns
    (png_bytes, final_w, final_h)."""
    pil = Image.open(io.BytesIO(orig_bytes)).convert("RGB")
    W, H = pil.size
    if W < _ASSET_MIN_W or H < _ASSET_MIN_H:
        scale = max(_ASSET_MIN_W / W, _ASSET_MIN_H / H)
        new_w = int(W * scale + 0.5)
        new_h = int(H * scale + 0.5)
        pil = pil.resize((new_w, new_h), Image.LANCZOS)
        W, H = new_w, new_h
    arr = np.array(pil)
    overlay = symbols.build_overlay(encoded_symbols, W, H)
    marked = symbols.apply_overlay(arr, overlay)
    buf = io.BytesIO()
    Image.fromarray(marked).save(buf, format="PNG")
    return buf.getvalue(), W, H


def _asset_to_out(a: Asset) -> "AssetOut":
    return AssetOut(
        id=a.id,
        tenant_id=a.tenant_id,
        asset_type=a.asset_type,
        case_id=a.case_id,
        description=a.description,
        recipient_user_id=a.recipient_user_id,
        recipient_name=a.recipient_name,
        recipient_email=a.recipient_email,
        recipient_ref=a.recipient_ref,
        issued_by_email=a.issued_by_email,
        token=a.token,
        token_hex=f"0x{a.token:010x}",
        original_sha256=a.original_sha256,
        original_mime=a.original_mime,
        original_w=a.original_w,
        original_h=a.original_h,
        status=a.status,
        created_at=a.created_at,
        revoked_at=a.revoked_at,
        revoked_reason=a.revoked_reason,
    )


def create_app() -> FastAPI:
    app = FastAPI(title="Unseen API", version="0.1.0")

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
            resp.session_kind = sess.kind
            # If this token is bound to an issued asset, surface that
            # context — it's the answer the investigator actually wants.
            asset = s.execute(
                select(Asset).where(Asset.token == result.token)
            ).scalars().first()
            if asset is not None:
                resp.asset_id = asset.id
                resp.asset_type = asset.asset_type
                resp.asset_status = asset.status
                resp.asset_case_id = asset.case_id
                resp.asset_description = asset.description
                resp.asset_recipient_name = asset.recipient_name
                resp.asset_recipient_email = asset.recipient_email
                resp.asset_recipient_ref = asset.recipient_ref
                resp.asset_created_at = asset.created_at
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

    # -----------------------------------------------------------------------
    # Assets — long-lived watermarked artifacts (ID cards, SIM cards, docs)
    # -----------------------------------------------------------------------
    def _ensure_asset_issuer(s: Session, tenant: Tenant) -> tuple[User, Device]:
        """Synthetic 'asset-issuer' user + device per tenant so the existing
        sessions schema (which requires user_id and device_id FKs) accepts
        long-lived asset tokens without needing a real enrolled device."""
        ISSUER_EMAIL = "asset-issuer@unseen.local"
        ISSUER_HOST = "asset-issuer"
        user = s.execute(
            select(User).where(User.tenant_id == tenant.id, User.email == ISSUER_EMAIL)
        ).scalars().first()
        if user is None:
            user = User(tenant_id=tenant.id, email=ISSUER_EMAIL)
            s.add(user)
            s.flush()
        device = s.execute(
            select(Device).where(Device.tenant_id == tenant.id, Device.user_id == user.id,
                                 Device.hostname == ISSUER_HOST)
        ).scalars().first()
        if device is None:
            device = Device(
                tenant_id=tenant.id, user_id=user.id, hostname=ISSUER_HOST,
                os="server", enroll_secret=secrets.token_urlsafe(32),
            )
            s.add(device)
            s.flush()
        return user, device

    @app.post("/v1/assets", response_model=AssetOut,
              dependencies=[Depends(require_admin)])
    def issue_asset(
        tenant_id: str = Form(...),
        asset_type: str = Form("other"),
        case_id: Optional[str] = Form(None),
        description: Optional[str] = Form(None),
        recipient_user_id: Optional[str] = Form(None),
        recipient_name: Optional[str] = Form(None),
        recipient_email: Optional[str] = Form(None),
        recipient_ref: Optional[str] = Form(None),
        issued_by_email: Optional[str] = Form(None),
        image: UploadFile = File(...),
        s: Session = Depends(db_session),
    ):
        tenant = s.get(Tenant, tenant_id)
        if tenant is None:
            raise HTTPException(404, "tenant not found")

        # Recipient validation: exactly one flow must be populated.
        if recipient_user_id:
            recip = s.get(User, recipient_user_id)
            if recip is None or recip.tenant_id != tenant.id:
                raise HTTPException(404, "recipient user not found in tenant")
            recipient_name_eff = recipient_name or recip.email
            recipient_email_eff = recipient_email or recip.email
        else:
            if not (recipient_name or recipient_ref or recipient_email):
                raise HTTPException(
                    400,
                    "must provide either recipient_user_id or "
                    "(recipient_name / recipient_email / recipient_ref)",
                )
            recipient_name_eff = recipient_name
            recipient_email_eff = recipient_email

        raw = image.file.read()
        if not raw:
            raise HTTPException(400, "empty image upload")
        sha = hashlib.sha256(raw).hexdigest()
        # Validate decodable + capture pre-resize dimensions
        try:
            probe = Image.open(io.BytesIO(raw)).convert("RGB")
        except Exception as e:
            raise HTTPException(400, f"unreadable image: {e}")
        orig_w, orig_h = probe.size

        issuer_user, issuer_device = _ensure_asset_issuer(s, tenant)
        token = _issue_unique_token(s)
        mac_key = derive_mac_key(
            tenant.master_key, token,
            user_id=issuer_user.id, device_id=issuer_device.id,
        )
        now = dt.datetime.now(dt.timezone.utc)
        expires = now + dt.timedelta(seconds=ASSET_TOKEN_TTL_SECONDS)
        sess = Session_(
            token=token,
            tenant_id=tenant.id,
            user_id=issuer_user.id,
            device_id=issuer_device.id,
            mac_key=mac_key,
            issued_at=now,
            expires_at=expires,
            kind="asset",
        )
        s.add(sess)

        asset = Asset(
            tenant_id=tenant.id,
            asset_type=asset_type or "other",
            case_id=case_id,
            description=description,
            recipient_user_id=recipient_user_id,
            recipient_name=recipient_name_eff,
            recipient_email=recipient_email_eff,
            recipient_ref=recipient_ref,
            issued_by_email=issued_by_email,
            token=token,
            original_bytes=raw,
            original_sha256=sha,
            original_mime=image.content_type or "image/png",
            original_w=orig_w,
            original_h=orig_h,
            status="active",
        )
        s.add(asset)
        s.flush()
        _audit(
            s, tenant.id, "asset.issued",
            actor=issued_by_email or "admin",
            target=asset.id,
            payload={
                "token": f"0x{token:010x}",
                "asset_type": asset.asset_type,
                "recipient_user_id": recipient_user_id,
                "recipient_name": recipient_name_eff,
                "recipient_ref": recipient_ref,
                "case_id": case_id,
                "sha256": sha,
            },
        )
        s.commit()
        return _asset_to_out(asset)

    @app.get("/v1/assets", response_model=list[AssetOut],
             dependencies=[Depends(require_admin)])
    def list_assets(
        tenant_id: Optional[str] = None,
        recipient_user_id: Optional[str] = None,
        case_id: Optional[str] = None,
        asset_type: Optional[str] = None,
        status_filter: Optional[str] = None,
        limit: int = 200,
        s: Session = Depends(db_session),
    ):
        q = select(Asset)
        if tenant_id:
            q = q.where(Asset.tenant_id == tenant_id)
        if recipient_user_id:
            q = q.where(Asset.recipient_user_id == recipient_user_id)
        if case_id:
            q = q.where(Asset.case_id == case_id)
        if asset_type:
            q = q.where(Asset.asset_type == asset_type)
        if status_filter:
            q = q.where(Asset.status == status_filter)
        rows = s.execute(q.order_by(Asset.created_at.desc()).limit(limit)).scalars().all()
        return [_asset_to_out(a) for a in rows]

    @app.get("/v1/assets/{asset_id}", response_model=AssetOut,
             dependencies=[Depends(require_admin)])
    def get_asset(asset_id: str, s: Session = Depends(db_session)):
        a = s.get(Asset, asset_id)
        if a is None:
            raise HTTPException(404, "asset not found")
        return _asset_to_out(a)

    @app.get("/v1/assets/{asset_id}/marked",
             dependencies=[Depends(require_admin)])
    def get_asset_marked(asset_id: str, s: Session = Depends(db_session)):
        a = s.get(Asset, asset_id)
        if a is None:
            raise HTTPException(404, "asset not found")
        sess = s.get(Session_, a.token)
        if sess is None:
            raise HTTPException(500, "session row missing for asset token")
        # Re-derive encoded symbols deterministically from the token + MAC key
        payload_bits = payload_mod.make_payload(a.token, sess.mac_key)
        encoded = conv_code.encode(payload_bits)
        png_bytes, _, _ = _watermark_png_bytes(a.original_bytes, encoded)
        _audit(s, a.tenant_id, "asset.downloaded.marked", actor=None,
               target=a.id, payload={"sha256": a.original_sha256})
        s.commit()
        return Response(content=png_bytes, media_type="image/png",
                        headers={"Content-Disposition":
                                 f'inline; filename="asset-{a.id}-marked.png"'})

    @app.get("/v1/assets/{asset_id}/original",
             dependencies=[Depends(require_admin)])
    def get_asset_original(asset_id: str, s: Session = Depends(db_session)):
        a = s.get(Asset, asset_id)
        if a is None:
            raise HTTPException(404, "asset not found")
        _audit(s, a.tenant_id, "asset.downloaded.original", actor=None,
               target=a.id, payload=None)
        s.commit()
        return Response(content=a.original_bytes, media_type=a.original_mime,
                        headers={"Content-Disposition":
                                 f'attachment; filename="asset-{a.id}-original"'})

    @app.post("/v1/assets/{asset_id}/revoke", response_model=AssetOut,
              dependencies=[Depends(require_admin)])
    def revoke_asset(asset_id: str, req: RevokeAssetReq,
                     s: Session = Depends(db_session)):
        a = s.get(Asset, asset_id)
        if a is None:
            raise HTTPException(404, "asset not found")
        if a.status == "revoked":
            return _asset_to_out(a)
        a.status = "revoked"
        a.revoked_at = dt.datetime.now(dt.timezone.utc)
        a.revoked_reason = req.reason
        _audit(s, a.tenant_id, "asset.revoked", actor=None,
               target=a.id, payload={"reason": req.reason})
        s.commit()
        return _asset_to_out(a)

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
