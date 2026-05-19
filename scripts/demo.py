#!/usr/bin/env python3
"""
End-to-end demo of the watermark MVP, runnable without external services.

Boots the backend in-process via FastAPI's TestClient, enrolls a tenant +
user + device, renders a watermark on a synthetic document, simulates a
phone-camera photograph, runs forensic extraction, and prints the
attribution result. Writes intermediate artifacts to ./artifacts/.

Run:
    .venv/bin/python scripts/demo.py
"""

from __future__ import annotations

import io
import os
import pathlib
import sys
import time

import numpy as np
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("WATERMARK_ADMIN_TOKEN", "demo-admin")
os.environ.setdefault("WATERMARK_DB_URL", "sqlite:///:memory:")

from watermark_mvp.backend import db  # noqa: E402
from watermark_mvp.backend.app import create_app  # noqa: E402
from watermark_mvp.core import symbols  # noqa: E402


def make_document(W: int, H: int) -> np.ndarray:
    img = Image.new("RGB", (W, H), (250, 250, 250))
    d = ImageDraw.Draw(img)
    try:
        title = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 24)
        body = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 16)
    except Exception:
        title = body = ImageFont.load_default()
    d.text((40, 30), "CONFIDENTIAL — Q4 STRATEGY MEMO", fill=(20, 20, 20), font=title)
    lines = [
        "",
        "This document contains proprietary information. Unauthorized",
        "disclosure is strictly prohibited.",
        "",
        "1. Revenue projections revised upward based on stronger-than-",
        "   expected enterprise demand in EMEA and APAC.",
        "",
        "2. Pricing strategy: maintain current list with selective",
        "   enterprise discounting up to 18% for multi-year commits.",
        "",
        "3. Headcount plan adds 23 FTEs across engineering and GTM.",
        "",
        "4. M&A pipeline includes three active conversations; details",
        "   restricted to executive committee.",
    ]
    y = 75
    for ln in lines:
        d.text((40, y), ln, fill=(40, 40, 40), font=body)
        y += 22
    return np.array(img)


def simulate_photo(rendered: np.ndarray, seed: int = 1) -> np.ndarray:
    """Blur + JPEG + downscale + sensor noise — approximates a phone capture."""
    H, W = rendered.shape[:2]
    pil = Image.fromarray(rendered).filter(ImageFilter.GaussianBlur(radius=0.7))
    pil = pil.resize((W // 2, H // 2), Image.LANCZOS).resize((W, H), Image.LANCZOS)
    buf = io.BytesIO(); pil.save(buf, "JPEG", quality=75); buf.seek(0)
    arr = np.array(Image.open(buf)).astype(np.int16)
    rng = np.random.default_rng(seed)
    arr += rng.normal(0, 2.5, arr.shape).astype(np.int16)
    return np.clip(arr, 0, 255).astype(np.uint8)


def main() -> int:
    print("=" * 64)
    print(" Watermark MVP — end-to-end demo")
    print("=" * 64)

    art = ROOT / "artifacts"
    art.mkdir(exist_ok=True)

    db.reset_engine()
    app = create_app()
    client = TestClient(app)
    h_admin = {"Authorization": "Bearer demo-admin"}

    # 1. Bootstrap
    print("\n[1] Create tenant + user …")
    r = client.post("/v1/tenants", headers=h_admin,
                    json={"tenant_name": "Acme Corp", "user_email": "alice@acme.test"})
    r.raise_for_status()
    ids = r.json()
    print(f"    tenant_id = {ids['tenant_id']}")
    print(f"    user_id   = {ids['user_id']}")

    print("\n[2] Enroll device …")
    r = client.post("/v1/devices/enroll", headers=h_admin,
                    json={"tenant_id": ids["tenant_id"], "user_id": ids["user_id"],
                          "hostname": "WS-LAPTOP-007", "os": "Windows 11"})
    r.raise_for_status()
    d = r.json()
    print(f"    device_id = {d['device_id']}")

    # 2. Get session
    print("\n[3] Agent requests session token …")
    r = client.post("/v1/sessions",
                    headers={"Authorization": f"Bearer {d['enroll_secret']}",
                             "X-Device-Id": d["device_id"]})
    r.raise_for_status()
    sess = r.json()
    print(f"    token = {sess['token_hex']}")
    print(f"    expires_at = {sess['expires_at']}")

    # 3. Render
    W, H = 1280, 720
    print(f"\n[4] Render watermark on a synthetic document ({W}x{H}) …")
    doc = make_document(W, H)
    Image.fromarray(doc).save(art / "1_clean_document.png")

    mask = symbols.build_overlay(sess["encoded_symbols"], W, H)
    wm = symbols.apply_overlay(doc, mask)
    Image.fromarray(wm).save(art / "2_watermarked_screen.png")

    amp = np.clip(128 + mask * 30, 0, 255).astype(np.uint8)
    Image.fromarray(amp).save(art / "3_overlay_amplified.png")
    print("    wrote clean / watermarked / overlay-amplified PNGs to artifacts/")

    # 4. Simulate camera
    print("\n[5] Simulate phone-camera capture (blur + JPEG + noise) …")
    photo = simulate_photo(wm)
    photo_buf = io.BytesIO()
    Image.fromarray(photo).save(photo_buf, "PNG")
    photo_buf.seek(0)
    Image.fromarray(photo).save(art / "4_simulated_photo.png")

    # 5. Extract
    print("\n[6] Investigator uploads photo to /v1/extract …")
    t0 = time.time()
    r = client.post("/v1/extract", headers=h_admin,
                    data={"case_id": "DEMO-1",
                          "investigator_email": "inv@acme.test",
                          "screen_w": str(W), "screen_h": str(H)},
                    files={"image": ("photo.png", photo_buf.getvalue(), "image/png")})
    r.raise_for_status()
    body = r.json()
    elapsed = time.time() - t0

    print(f"\n[7] Attribution result ({elapsed*1000:.0f} ms):")
    print(f"     success        : {body['success']}")
    print(f"     strategy       : {body['strategy']}")
    if body["success"]:
        print(f"     token          : {body['token_hex']}")
        print(f"     tenant_id      : {body['tenant_id']}")
        print(f"     user_email     : {body['user_email']}")
        print(f"     device_hostname: {body['device_hostname']}")
        print(f"     time_window    : {body['time_window_start']}")
        print(f"                      → {body['time_window_end']}")
        print(f"     audit_id       : {body['audit_id']}")
    else:
        print(f"     reason         : {body['failure_reason']}")
        return 1

    print("\nDemo OK. Artifacts in ./artifacts/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
