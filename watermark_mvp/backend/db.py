"""
SQLAlchemy models matching the simplified data model in BUILD_SPEC.md §8.

For the MVP we use SQLite. The schema mirrors the production design but
trims fields not needed for the Phase-1 happy path.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid
from typing import Optional

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    create_engine,
    inspect,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String, nullable=False)
    # Per BUILD_SPEC.md §5.3, this should live in KMS only. For the MVP we
    # store the master key bytes here; document the deviation explicitly.
    master_key = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_now)


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    email = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_now)


class Device(Base):
    __tablename__ = "devices"
    id = Column(String, primary_key=True, default=_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    hostname = Column(String, nullable=False)
    os = Column(String, nullable=False, default="unknown")
    # mTLS device cert thumbprint goes here in prod; MVP uses an enrollment
    # secret returned at /enroll time.
    enroll_secret = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_now)


class Session_(Base):
    __tablename__ = "sessions"
    # 40-bit opaque token, stored as integer. Primary key + index.
    token = Column(Integer, primary_key=True)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    # MAC key derived via HKDF at issuance and persisted so extraction can
    # verify HMAC. In production, key derivation would be a KMS-internal op
    # and the raw bytes would NOT be persisted; the KMS handle would be.
    mac_key = Column(LargeBinary, nullable=False)
    issued_at = Column(DateTime(timezone=True), default=_now)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    # "screen" (rotating 5-min token used by the live agent) or "asset"
    # (long-lived token bound to an issued artifact). Lets one table back
    # both flows without separate schemas.
    kind = Column(String, nullable=False, default="screen", index=True)


class Asset(Base):
    """One issued, watermarked artifact (ID card, SIM activation card,
    document, etc.). Each asset has a long-lived session token whose MAC
    binding lets the investigator console attribute leaked copies.
    """
    __tablename__ = "assets"
    id = Column(String, primary_key=True, default=_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)

    # Asset metadata.
    asset_type = Column(String, nullable=False, default="other", index=True)
    case_id = Column(String, nullable=True, index=True)
    description = Column(Text, nullable=True)

    # Recipient — exactly one of these flows is populated. Internal recipients
    # link to a User row; external recipients carry free-text identity fields.
    recipient_user_id = Column(String, ForeignKey("users.id"), nullable=True, index=True)
    recipient_name = Column(String, nullable=True)
    recipient_email = Column(String, nullable=True)
    recipient_ref = Column(String, nullable=True)  # ICCID, employee no, etc.

    # Who pressed the button.
    issued_by_email = Column(String, nullable=True)

    # Forensic binding to a session token.
    token = Column(Integer, ForeignKey("sessions.token"), nullable=False, unique=True, index=True)

    # Original image bytes — kept so we can re-render the marked version
    # on demand (watermarking is deterministic given token + original).
    original_bytes = Column(LargeBinary, nullable=False)
    original_sha256 = Column(String, nullable=False, index=True)
    original_mime = Column(String, nullable=False, default="image/png")
    original_w = Column(Integer, nullable=False)
    original_h = Column(Integer, nullable=False)

    status = Column(String, nullable=False, default="active", index=True)
    created_at = Column(DateTime(timezone=True), default=_now, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_reason = Column(Text, nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id = Column(String, primary_key=True, default=_uuid)
    # nullable: actions like a failed extraction may have no resolved tenant.
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=True, index=True)
    event_type = Column(String, nullable=False)
    actor = Column(String, nullable=True)
    target = Column(String, nullable=True)
    payload = Column(Text, nullable=True)
    ts = Column(DateTime(timezone=True), default=_now, index=True)


class Extraction(Base):
    __tablename__ = "extractions"
    id = Column(String, primary_key=True, default=_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=True, index=True)
    investigator_email = Column(String, nullable=False)
    case_id = Column(String, nullable=False)
    image_sha256 = Column(String, nullable=False)
    result_summary = Column(Text, nullable=True)
    ts = Column(DateTime(timezone=True), default=_now)


_ENGINE = None
_SESSION_LOCAL = None


def _apply_lightweight_migrations(engine) -> None:
    """Add columns to pre-existing tables that `Base.metadata.create_all`
    won't ALTER. Idempotent — safe to run on every startup.

    Keep this trivial; the moment we need rename/drop/data-rewrite, switch
    to Alembic.
    """
    insp = inspect(engine)
    if "sessions" in insp.get_table_names():
        cols = {c["name"] for c in insp.get_columns("sessions")}
        if "kind" not in cols:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE sessions ADD COLUMN kind VARCHAR "
                    "NOT NULL DEFAULT 'screen'"
                ))


def get_engine(url: Optional[str] = None):
    global _ENGINE, _SESSION_LOCAL
    if _ENGINE is None:
        if url is None:
            url = os.environ.get("WATERMARK_DB_URL", "sqlite:///watermark_mvp.db")
        # In-memory SQLite needs a shared connection pool so every
        # SQLAlchemy session sees the same database.
        kwargs: dict = {"future": True}
        if url.startswith("sqlite:") and ":memory:" in url:
            kwargs["connect_args"] = {"check_same_thread": False}
            kwargs["poolclass"] = StaticPool
        _ENGINE = create_engine(url, **kwargs)
        Base.metadata.create_all(_ENGINE)
        _apply_lightweight_migrations(_ENGINE)
        _SESSION_LOCAL = sessionmaker(bind=_ENGINE, expire_on_commit=False, future=True)
    return _ENGINE


def get_session() -> Session:
    if _SESSION_LOCAL is None:
        get_engine()
    return _SESSION_LOCAL()  # type: ignore[misc]


def reset_engine() -> None:
    """Tear down singletons — used by tests that want an in-memory DB."""
    global _ENGINE, _SESSION_LOCAL
    _ENGINE = None
    _SESSION_LOCAL = None
