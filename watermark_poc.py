"""
Screen Watermark — Proof of Concept
====================================
Working end-to-end demonstration of the algorithm from BUILD_SPEC.md.
Uses K=7 convolutional code for POC speed; production design uses K=15 with
split sub-watermarks (see spec §3.2).

Pipeline demonstrated:
  1. Issue session token + derive MAC key
  2. Build 64-bit payload (40-bit token || 24-bit truncated HMAC-SHA256)
  3. Convolutional encode (K=7, rate-1/2, NASA-classic (171,133)_octal)
  4. Render symbols as overlay mask on a synthetic "document"
  5. Simulate phone-camera capture (blur + downscale + JPEG + sensor noise)
  6. Extract soft bits via differential luminance per symbol cell
  7. Soft-decision Viterbi decode
  8. Verify HMAC → recover the session token

Run:
    pip install --break-system-packages numpy pillow
    python watermark_poc.py
"""

import hmac
import hashlib
import secrets
from io import BytesIO

import numpy as np
from PIL import Image, ImageDraw, ImageFont, ImageFilter


# =====================================================================
# Convolutional code (K=7, rate 1/2)
# =====================================================================
K = 7
G1 = 0o171  # 0b1111001
G2 = 0o133  # 0b1011011


def popcount(x: int) -> int:
    return bin(x).count("1")


def conv_encode(bits):
    """Return two parallel output streams (b1, b2), zero-terminated."""
    state = 0
    b1, b2 = [], []
    for bit in list(bits) + [0] * (K - 1):
        reg = (bit << (K - 1)) | state
        b1.append(popcount(reg & G1) & 1)
        b2.append(popcount(reg & G2) & 1)
        state = reg >> 1
    return b1, b2


def viterbi_decode(soft_b1, soft_b2, payload_len):
    """Soft-decision Viterbi.  soft > 0 means 'bit is 0' (center brighter)."""
    n_states = 1 << (K - 1)
    n_steps = len(soft_b1)
    INF = 1e9

    metrics = np.full(n_states, INF, dtype=np.float64)
    metrics[0] = 0.0
    preds = np.zeros((n_steps, n_states), dtype=np.int16)

    for t in range(n_steps):
        new_metrics = np.full(n_states, INF, dtype=np.float64)
        for state in range(n_states):
            if metrics[state] >= INF:
                continue
            for bit in (0, 1):
                reg = (bit << (K - 1)) | state
                e1 = popcount(reg & G1) & 1
                e2 = popcount(reg & G2) & 1
                # Cost is the negative correlation with the soft input,
                # so matching expected bits decreases cumulative cost.
                c1 = soft_b1[t] if e1 == 1 else -soft_b1[t]
                c2 = soft_b2[t] if e2 == 1 else -soft_b2[t]
                m = metrics[state] + c1 + c2
                ns = reg >> 1
                if m < new_metrics[ns]:
                    new_metrics[ns] = m
                    preds[t, ns] = state | (bit << (K - 1))
        metrics = new_metrics

    # Traceback from terminated zero state
    state = 0
    out_bits = []
    for t in range(n_steps - 1, -1, -1):
        info = int(preds[t, state])
        bit = (info >> (K - 1)) & 1
        state = info & ((1 << (K - 1)) - 1)
        out_bits.append(bit)
    out_bits.reverse()
    return out_bits[:payload_len]


# =====================================================================
# Payload: 40-bit token || 24-bit truncated HMAC
# =====================================================================
TOKEN_BITS = 40
MAC_BITS = 24
PAYLOAD_BITS = TOKEN_BITS + MAC_BITS


def bits_from_int(n: int, width: int):
    return [(n >> i) & 1 for i in range(width - 1, -1, -1)]


def int_from_bits(bits):
    n = 0
    for b in bits:
        n = (n << 1) | b
    return n


def make_payload(token: int, mac_key: bytes):
    tb = token.to_bytes(5, "big")
    mac = hmac.new(mac_key, tb, hashlib.sha256).digest()
    mac_int = int.from_bytes(mac[:3], "big")
    return bits_from_int(token, TOKEN_BITS) + bits_from_int(mac_int, MAC_BITS)


def verify_payload(bits, mac_key: bytes):
    token = int_from_bits(bits[:TOKEN_BITS])
    got = int_from_bits(bits[TOKEN_BITS:])
    expected = int.from_bytes(
        hmac.new(mac_key, token.to_bytes(5, "big"), hashlib.sha256).digest()[:3], "big"
    )
    return (got == expected), token


# =====================================================================
# Symbol overlay rendering
# =====================================================================
SYMBOL_SIZE = 32
INNER_R = 4
OUTER_R = 12
DELTA = 3  # per-channel luminance offset (paper found (3,3,3) imperceptible in text areas)


def make_symbol_kernel():
    """Soft-edged circular symbol, built once and reused."""
    k = np.zeros((SYMBOL_SIZE, SYMBOL_SIZE), dtype=np.float32)
    cx = cy = SYMBOL_SIZE / 2 - 0.5
    rng = np.random.default_rng(0)
    for y in range(SYMBOL_SIZE):
        for x in range(SYMBOL_SIZE):
            d = float(np.hypot(x - cx, y - cy))
            if d <= INNER_R:
                v = 1.0
            elif d <= OUTER_R:
                t = (d - INNER_R) / (OUTER_R - INNER_R)
                v = 0.5 * (1 + np.cos(np.pi * t))
            else:
                v = 0.0
            if INNER_R < d <= OUTER_R:
                v += rng.normal(0, 0.06)
            k[y, x] = v
    return k


def build_overlay(bits, screen_h: int, screen_w: int):
    kernel = make_symbol_kernel()
    mask = np.zeros((screen_h, screen_w, 3), dtype=np.int16)
    cols = screen_w // SYMBOL_SIZE
    rows = screen_h // SYMBOL_SIZE
    for i, bit in enumerate(bits):
        if i >= cols * rows:
            break
        col, row = i % cols, i // cols
        y0, x0 = row * SYMBOL_SIZE, col * SYMBOL_SIZE
        sign = -1 if bit == 1 else +1
        contrib = (sign * DELTA * kernel).astype(np.int16)
        for ch in range(3):
            mask[y0:y0 + SYMBOL_SIZE, x0:x0 + SYMBOL_SIZE, ch] += contrib
    return mask, cols, rows


def apply_overlay(img, mask):
    return np.clip(img.astype(np.int16) + mask, 0, 255).astype(np.uint8)


# =====================================================================
# Soft-bit extraction
# =====================================================================
def extract_soft(captured, n_bits: int):
    H, W = captured.shape[:2]
    cols = W // SYMBOL_SIZE
    rows = H // SYMBOL_SIZE
    lum = (0.299 * captured[:, :, 0]
           + 0.587 * captured[:, :, 1]
           + 0.114 * captured[:, :, 2]).astype(np.float32)
    softs = []
    for i in range(n_bits):
        if i >= cols * rows:
            softs.append(0.0)
            continue
        col, row = i % cols, i // cols
        y0, x0 = row * SYMBOL_SIZE, col * SYMBOL_SIZE
        cy, cx = y0 + SYMBOL_SIZE // 2, x0 + SYMBOL_SIZE // 2
        inner = lum[cy - 3:cy + 3, cx - 3:cx + 3].mean()
        outer = (
            lum[y0:y0 + 5, x0:x0 + 5].mean()
            + lum[y0:y0 + 5, x0 + SYMBOL_SIZE - 5:x0 + SYMBOL_SIZE].mean()
            + lum[y0 + SYMBOL_SIZE - 5:y0 + SYMBOL_SIZE, x0:x0 + 5].mean()
            + lum[y0 + SYMBOL_SIZE - 5:y0 + SYMBOL_SIZE,
                  x0 + SYMBOL_SIZE - 5:x0 + SYMBOL_SIZE].mean()
        ) / 4.0
        softs.append(float(inner - outer))
    return softs


# =====================================================================
# Document + camera simulation
# =====================================================================
def make_document(w=1280, h=720):
    # Slightly off-white background: pure 255 saturates the +Δ direction.
    # Real screen rendering rarely produces pure 255 (color profiles, AA, sRGB curve).
    img = Image.new("RGB", (w, h), (250, 250, 250))
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 22)
        small = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 15)
    except Exception:
        font = small = ImageFont.load_default()
    draw.text((40, 30), "CONFIDENTIAL — Q4 STRATEGY MEMO",
              fill=(20, 20, 20), font=font)
    body = (
        "This document contains proprietary information. Unauthorized\n"
        "disclosure is strictly prohibited.\n\n"
        "1. Revenue projections revised upward based on stronger-than-expected\n"
        "   enterprise demand in EMEA and APAC.\n\n"
        "2. Pricing strategy: maintain current list with selective enterprise\n"
        "   discounting up to 18% for multi-year commitments.\n\n"
        "3. Headcount plan adds 23 FTEs across engineering and GTM.\n\n"
        "4. M&A pipeline includes three active conversations; details\n"
        "   restricted to executive committee.\n"
    )
    draw.multiline_text((40, 90), body, fill=(40, 40, 40), font=small, spacing=6)
    return np.array(img)


def simulate_camera(img, seed=1):
    """Approximate the degradation of photographing a screen with a phone."""
    pil = Image.fromarray(img)
    pil = pil.filter(ImageFilter.GaussianBlur(radius=0.7))
    w, h = pil.size
    pil = pil.resize((w // 2, h // 2), Image.LANCZOS)
    pil = pil.resize((w, h), Image.LANCZOS)
    buf = BytesIO()
    pil.save(buf, "JPEG", quality=75)
    buf.seek(0)
    pil = Image.open(buf)
    arr = np.array(pil).astype(np.int16)
    rng = np.random.default_rng(seed)
    arr += rng.normal(0, 2.5, arr.shape).astype(np.int16)
    return np.clip(arr, 0, 255).astype(np.uint8)


# =====================================================================
# Demo
# =====================================================================
def main(outdir="/home/claude/build"):
    print("Screen Watermark — Proof of Concept")
    print("=" * 60)

    token = secrets.randbits(TOKEN_BITS)
    mac_key = secrets.token_bytes(32)
    print(f"Session token         : 0x{token:010x}")

    payload = make_payload(token, mac_key)
    b1, b2 = conv_encode(payload)

    # Interleave b1, b2 so adjacent symbols carry related trellis info
    encoded = []
    for x, y in zip(b1, b2):
        encoded += [x, y]

    # Spread REPS copies of the encoded bitstream across separated screen regions
    # so each rep encounters independent local conditions (text vs whitespace).
    # Each rep occupies a non-overlapping band of cells.
    REPS = 5
    bitstream = []
    for r in range(REPS):
        bitstream.extend(encoded)
    # bitstream[r * enc_len + i] = rep r of encoded bit i
    enc_len = len(encoded)
    print(f"Encoded length        : {enc_len} symbols x {REPS} reps = {len(bitstream)}")

    doc = make_document()
    Image.fromarray(doc).save(f"{outdir}/clean_screen.png")

    mask, cols, rows = build_overlay(bitstream, doc.shape[0], doc.shape[1])
    print(f"Symbol grid           : {cols}x{rows} = {cols * rows} cells available")

    watermarked = apply_overlay(doc, mask)
    Image.fromarray(watermarked).save(f"{outdir}/watermarked_screen.png")

    amp = np.clip(128 + mask * 30, 0, 255).astype(np.uint8)
    Image.fromarray(amp).save(f"{outdir}/overlay_amplified.png")

    photo = simulate_camera(watermarked)
    Image.fromarray(photo).save(f"{outdir}/simulated_photo.png")

    softs = extract_soft(photo, len(bitstream))

    # Robust combine: median of REPS bands, not mean. A symbol where text overlaps
    # the center produces a huge wrong-magnitude soft value; mean would let it
    # dominate, median rejects it as an outlier.
    import statistics
    combined_softs = [
        statistics.median(softs[r * enc_len + i] for r in range(REPS))
        for i in range(enc_len)
    ]

    hard = [1 if s < 0 else 0 for s in combined_softs]
    ber = sum(1 for a, b in zip(hard, encoded) if a != b) / len(encoded)
    print(f"Combined BER (after {REPS}x rep): {ber:.1%}")

    n = len(b1)
    soft_b1 = [combined_softs[2 * i] for i in range(n)]
    soft_b2 = [combined_softs[2 * i + 1] for i in range(n)]
    decoded = viterbi_decode(soft_b1, soft_b2, PAYLOAD_BITS)

    ok, recovered = verify_payload(decoded, mac_key)
    print(f"Recovered token       : 0x{recovered:010x}")
    print(f"MAC verification      : {'PASS' if ok else 'FAIL'}")

    if ok:
        print()
        print("In production, the recovered token would be looked up in the")
        print("session DB to return (tenant, user, device, time-window).")

    print()
    print("Generated artifacts:")
    print(f"  {outdir}/clean_screen.png        — original document")
    print(f"  {outdir}/watermarked_screen.png  — invisible overlay applied")
    print(f"  {outdir}/overlay_amplified.png   — overlay alone, 30x amplified")
    print(f"  {outdir}/simulated_photo.png     — after camera-like degradation")


if __name__ == "__main__":
    main()
