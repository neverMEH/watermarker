"""
End-to-end test mirroring the Phase-1 exit criterion of BUILD_SPEC.md §10:
"can install on a laptop, photograph the screen, identify which laptop and when."

We run the backend in-process via FastAPI's TestClient, enroll a tenant +
user + device, request a session token, render a watermark on a synthetic
"screen" image, simulate camera capture, and call /v1/extract — then
assert the attribution names the correct tenant/user/device.
"""

from __future__ import annotations

import io
import os

import numpy as np
import pytest
from fastapi.testclient import TestClient
from PIL import Image, ImageFilter

from watermark_mvp.backend import db
from watermark_mvp.backend.app import create_app
from watermark_mvp.core import symbols


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("WATERMARK_ADMIN_TOKEN", "test-admin-token")
    monkeypatch.setenv("WATERMARK_DB_URL", "sqlite:///:memory:")
    db.reset_engine()
    app = create_app()
    with TestClient(app) as c:
        yield c


def _bootstrap(client: TestClient) -> dict:
    h_admin = {"Authorization": "Bearer test-admin-token"}
    r = client.post(
        "/v1/tenants",
        headers=h_admin,
        json={"tenant_name": "Acme Corp", "user_email": "alice@acme.test"},
    )
    assert r.status_code == 200, r.text
    t = r.json()
    r = client.post(
        "/v1/devices/enroll",
        headers=h_admin,
        json={
            "tenant_id": t["tenant_id"],
            "user_id": t["user_id"],
            "hostname": "WS-LAPTOP-007",
            "os": "Windows 11",
        },
    )
    assert r.status_code == 200, r.text
    d = r.json()
    return {
        "tenant_id": t["tenant_id"],
        "user_id": t["user_id"],
        "device_id": d["device_id"],
        "enroll_secret": d["enroll_secret"],
    }


def _issue_session(client: TestClient, device_id: str, secret: str) -> dict:
    r = client.post(
        "/v1/sessions",
        headers={"Authorization": f"Bearer {secret}", "X-Device-Id": device_id},
    )
    assert r.status_code == 200, r.text
    return r.json()


def _simulate_photo(rendered_rgb: np.ndarray) -> bytes:
    """JPEG + blur + resize + noise — same pipeline as the POC."""
    H, W = rendered_rgb.shape[:2]
    pil = Image.fromarray(rendered_rgb).filter(ImageFilter.GaussianBlur(radius=0.7))
    pil = pil.resize((W // 2, H // 2), Image.LANCZOS).resize((W, H), Image.LANCZOS)
    buf = io.BytesIO()
    pil.save(buf, "JPEG", quality=78)
    buf.seek(0)
    arr = np.array(Image.open(buf)).astype(np.int16)
    rng = np.random.default_rng(42)
    arr += rng.normal(0, 2.5, arr.shape).astype(np.int16)
    arr = np.clip(arr, 0, 255).astype(np.uint8)
    out = io.BytesIO()
    Image.fromarray(arr).save(out, "JPEG", quality=85)
    return out.getvalue()


def test_phase1_exit_criterion(client: TestClient):
    """Render watermark → simulate camera → /v1/extract → attribution matches."""
    ids = _bootstrap(client)
    sess = _issue_session(client, ids["device_id"], ids["enroll_secret"])

    W, H = 1280, 720
    clean = np.full((H, W, 3), 250, dtype=np.uint8)
    mask = symbols.build_overlay(sess["encoded_symbols"], W, H)
    wm = symbols.apply_overlay(clean, mask)
    photo_bytes = _simulate_photo(wm)
    # Decode the JPEG back to dimensions in case caller resized — keep as PNG
    # to preserve exact size for the extractor.
    pil = Image.open(io.BytesIO(photo_bytes)).convert("RGB")
    buf = io.BytesIO()
    pil.save(buf, "PNG")
    buf.seek(0)

    r = client.post(
        "/v1/extract",
        headers={"Authorization": "Bearer test-admin-token"},
        data={
            "case_id": "CASE-1",
            "investigator_email": "inv@acme.test",
            "screen_w": str(W),
            "screen_h": str(H),
        },
        files={"image": ("simulated_photo.png", buf.getvalue(), "image/png")},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"], f"extraction failed: {body}"
    assert body["token_hex"] == sess["token_hex"]
    assert body["tenant_id"] == ids["tenant_id"]
    assert body["user_email"] == "alice@acme.test"
    assert body["device_hostname"] == "WS-LAPTOP-007"
    assert body["audit_id"]


def test_extract_unknown_image_returns_failure(client: TestClient):
    """Random noise → no MAC match → success=False, no attribution leaked."""
    _bootstrap(client)  # so there are sessions in the DB, but ours won't match
    W, H = 1280, 720
    rng = np.random.default_rng(0)
    noise = rng.integers(0, 256, (H, W, 3), dtype=np.uint8)
    buf = io.BytesIO(); Image.fromarray(noise).save(buf, "PNG"); buf.seek(0)
    r = client.post(
        "/v1/extract",
        headers={"Authorization": "Bearer test-admin-token"},
        data={
            "case_id": "CASE-noise",
            "investigator_email": "inv@acme.test",
            "screen_w": str(W),
            "screen_h": str(H),
        },
        files={"image": ("noise.png", buf.getvalue(), "image/png")},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert not body["success"]
    assert body["tenant_id"] is None
    assert body["audit_id"]


def test_auth_rejects_bad_admin_token(client: TestClient):
    r = client.post(
        "/v1/tenants",
        headers={"Authorization": "Bearer WRONG"},
        json={"tenant_name": "X", "user_email": "x@example.com"},
    )
    assert r.status_code == 403


def test_auth_rejects_bad_device_secret(client: TestClient):
    ids = _bootstrap(client)
    r = client.post(
        "/v1/sessions",
        headers={
            "Authorization": "Bearer WRONG",
            "X-Device-Id": ids["device_id"],
        },
    )
    assert r.status_code == 403
