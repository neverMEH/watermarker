"""
Symbol overlay rendering and extraction (BUILD_SPEC.md §3.3, §3.4).

Each symbol is a 32×32 cell with a soft-edged circular gradient:
  - Inner disk (r ≤ 4):  luminance shifted by ±Δ (+Δ for bit=0, -Δ for bit=1)
  - Transition annulus (4 < r ≤ 12): cosine falloff to 0, with low-amplitude noise
  - Outer area: untouched; acts as the local reference for differential decoding

The 468 symbols are laid out as a 26×18 cell grid (832×576 px), arranged as
6 spatial blocks in a 2×3 super-grid so a partial crop has a chance of
preserving an entire block. Anchor markers are placed at the four corners
for grid registration.
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

import numpy as np

from .conv_code import BLOCK_SYMBOLS, NUM_BLOCKS, TOTAL_SYMBOLS

SYMBOL_SIZE = 32
INNER_R = 4
OUTER_R = 12
DEFAULT_DELTA = 3  # per-channel additive luminance offset

# Grid layout: 6 blocks (= 2 rows × 3 cols of blocks),
# each block 78 cells = 6 rows × 13 cols of cells.
BLOCK_GRID_ROWS = 2
BLOCK_GRID_COLS = 3
CELLS_PER_BLOCK_ROW = 6
CELLS_PER_BLOCK_COL = 13
assert BLOCK_GRID_ROWS * BLOCK_GRID_COLS == NUM_BLOCKS
assert CELLS_PER_BLOCK_ROW * CELLS_PER_BLOCK_COL == BLOCK_SYMBOLS

GRID_COLS = BLOCK_GRID_COLS * CELLS_PER_BLOCK_COL  # 39
GRID_ROWS = BLOCK_GRID_ROWS * CELLS_PER_BLOCK_ROW  # 12
WATERMARK_W = GRID_COLS * SYMBOL_SIZE  # 1248
WATERMARK_H = GRID_ROWS * SYMBOL_SIZE  # 384
assert GRID_COLS * GRID_ROWS == TOTAL_SYMBOLS


def _make_symbol_kernel(seed: int = 0) -> np.ndarray:
    """Soft-edged circular kernel in [-1, 1], same as POC. Built once."""
    k = np.zeros((SYMBOL_SIZE, SYMBOL_SIZE), dtype=np.float32)
    cx = cy = SYMBOL_SIZE / 2 - 0.5
    rng = np.random.default_rng(seed)
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


_KERNEL = _make_symbol_kernel()


def _bit_to_cell(bit_index: int) -> Tuple[int, int]:
    """Map a logical symbol index (0..467) to (cell_row, cell_col) in the grid.

    Block b ∈ [0, 6) occupies sub-region (b // 3, b % 3) of the 2×3 super-grid.
    Bit i ∈ [0, 78) within the block is laid out as (i // 13, i % 13) in the
    block's 6×13 cell area.
    """
    block = bit_index // BLOCK_SYMBOLS
    within = bit_index % BLOCK_SYMBOLS
    br, bc = block // BLOCK_GRID_COLS, block % BLOCK_GRID_COLS
    cr, cc = within // CELLS_PER_BLOCK_COL, within % CELLS_PER_BLOCK_COL
    return br * CELLS_PER_BLOCK_ROW + cr, bc * CELLS_PER_BLOCK_COL + cc


# Precompute the cell coordinate for each symbol index — used by both
# encoder and extractor.
_CELL_FOR_BIT = [_bit_to_cell(i) for i in range(TOTAL_SYMBOLS)]


def watermark_pixel_bbox(screen_w: int, screen_h: int) -> Tuple[int, int, int, int]:
    """Return (x0, y0, x1, y1) of the watermark region centered on the screen.

    Falls back to (0, 0, WATERMARK_W, WATERMARK_H) when the screen is smaller
    than the watermark (caller should pad/scale, but for MVP it's expected
    that screens are at least 1248×384).
    """
    x0 = max(0, (screen_w - WATERMARK_W) // 2)
    y0 = max(0, (screen_h - WATERMARK_H) // 2)
    return x0, y0, x0 + WATERMARK_W, y0 + WATERMARK_H


def build_overlay(
    bits: Sequence[int],
    screen_w: int,
    screen_h: int,
    delta: int = DEFAULT_DELTA,
) -> np.ndarray:
    """Construct an RGB additive mask (int16) sized (screen_h, screen_w, 3)
    with the watermark grid centered on the screen.

    bits must be exactly TOTAL_SYMBOLS in length.
    """
    if len(bits) != TOTAL_SYMBOLS:
        raise ValueError(f"expected {TOTAL_SYMBOLS} bits, got {len(bits)}")
    if screen_w < WATERMARK_W or screen_h < WATERMARK_H:
        raise ValueError(
            f"screen {screen_w}x{screen_h} smaller than watermark "
            f"region {WATERMARK_W}x{WATERMARK_H}"
        )
    mask = np.zeros((screen_h, screen_w, 3), dtype=np.int16)
    x0, y0, _, _ = watermark_pixel_bbox(screen_w, screen_h)

    for i, bit in enumerate(bits):
        cell_row, cell_col = _CELL_FOR_BIT[i]
        py = y0 + cell_row * SYMBOL_SIZE
        px = x0 + cell_col * SYMBOL_SIZE
        sign = -1 if bit else +1
        contrib = (sign * delta * _KERNEL).astype(np.int16)
        for ch in range(3):
            mask[py:py + SYMBOL_SIZE, px:px + SYMBOL_SIZE, ch] += contrib

    # Anchor markers: small dark dots at the 4 corners of the watermark region.
    # Used by the extractor for grid registration. 3px square at each corner.
    for ax, ay in (
        (x0 - 6, y0 - 6),
        (x0 + WATERMARK_W + 3, y0 - 6),
        (x0 - 6, y0 + WATERMARK_H + 3),
        (x0 + WATERMARK_W + 3, y0 + WATERMARK_H + 3),
    ):
        if 0 <= ax < screen_w - 3 and 0 <= ay < screen_h - 3:
            mask[ay:ay + 3, ax:ax + 3, :] -= 60  # strong dark anchor
    return mask


def apply_overlay(image: np.ndarray, mask: np.ndarray) -> np.ndarray:
    """Clamp-additive blend of mask onto the image (RGB uint8)."""
    if image.shape != mask.shape:
        raise ValueError(f"shape mismatch: image {image.shape} vs mask {mask.shape}")
    return np.clip(image.astype(np.int16) + mask, 0, 255).astype(np.uint8)


def extract_soft_bits(
    captured: np.ndarray,
    screen_w: int,
    screen_h: int,
) -> List[float]:
    """Extract TOTAL_SYMBOLS soft bits from a captured image.

    For MVP we assume the captured image is already in screen-space (the
    agent renders pixel-exact and the simulated camera does not introduce
    geometric distortion). A production extractor would first de-skew the
    photo and locate the anchor markers via Hough/learned detection
    (BUILD_SPEC.md §3.4 step 1-2).

    Per-symbol decision: soft = mean(center 6×6 region) - mean(corner 5×5
    patches). Positive = "bit 0" (center brighter than surround).
    """
    if captured.shape[:2] != (screen_h, screen_w):
        raise ValueError(
            f"captured shape {captured.shape[:2]} != ({screen_h}, {screen_w})"
        )
    lum = (
        0.299 * captured[:, :, 0]
        + 0.587 * captured[:, :, 1]
        + 0.114 * captured[:, :, 2]
    ).astype(np.float32)

    x0, y0, _, _ = watermark_pixel_bbox(screen_w, screen_h)
    softs: List[float] = []
    for i in range(TOTAL_SYMBOLS):
        cell_row, cell_col = _CELL_FOR_BIT[i]
        py = y0 + cell_row * SYMBOL_SIZE
        px = x0 + cell_col * SYMBOL_SIZE
        cy = py + SYMBOL_SIZE // 2
        cx = px + SYMBOL_SIZE // 2
        inner = lum[cy - 3:cy + 3, cx - 3:cx + 3].mean()
        outer = 0.25 * (
            lum[py:py + 5, px:px + 5].mean()
            + lum[py:py + 5, px + SYMBOL_SIZE - 5:px + SYMBOL_SIZE].mean()
            + lum[py + SYMBOL_SIZE - 5:py + SYMBOL_SIZE, px:px + 5].mean()
            + lum[py + SYMBOL_SIZE - 5:py + SYMBOL_SIZE,
                  px + SYMBOL_SIZE - 5:px + SYMBOL_SIZE].mean()
        )
        softs.append(float(inner - outer))
    return softs
