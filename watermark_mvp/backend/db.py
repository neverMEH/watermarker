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
