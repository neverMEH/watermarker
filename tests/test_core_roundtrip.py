"""Unit-level test of the core algorithm (no backend, no I/O)."""

from __future__ import annotations

import io
import secrets

import numpy as np
import pytest
from PIL import Image, ImageFilter

from watermark_mvp.core import (
    conv_code,
    payload as payload_mod,
    symbols,
)


def _verifier(mac_key: bytes):
    def verify(bits: list[int]):
        return payload_mod.verify_payload(bits, mac_key)
    return verify


def test_clean_round_trip():
    """Encoded → strong soft bits → Viterbi → matching token."""
    mac_key = secrets.token_bytes(32)
    token = secrets.randbits(payload_mod.TOKEN_BITS)
    pl = payload_mod.make_payload(token, mac_key)
    encoded = conv_code.encode(pl)
    assert len(encoded) == conv_code.TOTAL_SYMBOLS
    softs = [4.0 if b == 0 else -4.0 for b in encoded]
    res = conv_code.decode(softs, _verifier(mac_key))
    assert res.mac_ok
    assert res.token == token
    assert res.strategy.startswith("per-pair-")


def test_payload_round_trip():
    mac_key = secrets.token_bytes(32)
    token = 0xDEADBEEF12  # 40 bits
    bits = payload_mod.make_payload(token, mac_key)
    ok, recovered = payload_mod.verify_payload(bits, mac_key)
    assert ok and recovered == token


def test_full_pipeline_with_simulated_camera():
    """Render → simulated camera (JPEG/blur/noise) → extract → decode."""
    W, H = 1280, 720
    mac_key = secrets.token_bytes(32)
    token = secrets.randbits(payload_mod.TOKEN_BITS)
    pl = payload_mod.make_payload(token, mac_key)
    encoded = conv_code.encode(pl)

    clean = np.full((H, W, 3), 250, dtype=np.uint8)
    mask = symbols.build_overlay(encoded, W, H)
    wm = symbols.apply_overlay(clean, mask)

    # Simulated camera: blur, JPEG, resize, gaussian noise.
    pil = Image.fromarray(wm).filter(ImageFilter.GaussianBlur(radius=0.7))
    pil = pil.resize((W // 2, H // 2), Image.LANCZOS).resize((W, H), Image.LANCZOS)
    buf = io.BytesIO()
    pil.save(buf, "JPEG", quality=75)
    buf.seek(0)
    arr = np.array(Image.open(buf)).astype(np.int16)
    rng = np.random.default_rng(7)
    arr += rng.normal(0, 2.5, arr.shape).astype(np.int16)
    photo = np.clip(arr, 0, 255).astype(np.uint8)

    softs = symbols.extract_soft_bits(photo, W, H)
    res = conv_code.decode(softs, _verifier(mac_key))
    assert res.mac_ok, f"decode failed: {res}"
    assert res.token == token


@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5])
def test_round_trip_many_tokens(seed: int):
    rng = np.random.default_rng(seed)
    mac_key = rng.bytes(32)
    token = int(rng.integers(0, 1 << payload_mod.TOKEN_BITS))
    pl = payload_mod.make_payload(token, mac_key)
    encoded = conv_code.encode(pl)
    softs = [4.0 if b == 0 else -4.0 for b in encoded]
    res = conv_code.decode(softs, _verifier(mac_key))
    assert res.mac_ok and res.token == token


def test_decode_rejects_unknown_token():
    """A random soft stream should fail MAC verification."""
    mac_key = secrets.token_bytes(32)
    rng = np.random.default_rng(0)
    softs = (rng.normal(0, 0.1, conv_code.TOTAL_SYMBOLS)).tolist()
    res = conv_code.decode(softs, _verifier(mac_key))
    # MAC has 24 bits → 1-in-16M chance of accidental match on noise.
    assert not res.mac_ok
    assert res.strategy == "none"
