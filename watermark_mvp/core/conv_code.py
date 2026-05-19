"""
Rate-1/2 convolutional code with K=15, with split sub-watermarks and
seeded block permutations (BUILD_SPEC.md §3.2).

Encoding flow:
  1. 64-bit payload → pad with K-1=14 zero termination bits → 78 bits.
  2. Run through two generators g1, g2 → B1, B2 (each 78 bits).
  3. Apply 3 seeded permutations to (B1, B2) → 6 blocks of 78 symbols.
  4. Total physical bits: 6 × 78 = 468.

Decoding flow:
  - Each (perm_s(B1), perm_s(B2)) pair is independently Viterbi-decodable.
  - Try each pair in turn; verify MAC; return first success.
  - If all fail, soft-combine across the 3 pairs and retry.

The Viterbi is numpy-vectorized: 2^(K-1) = 16384 states, ~10ms per block.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

import numpy as np

from .payload import PAYLOAD_BITS

# Constraint length and generator polynomials. K=15 rate-1/2 generators with
# good free distance (commonly cited pair, octal 75063 / 56711).
K = 15
G1 = 0o75063
G2 = 0o56711

# Per-block symbol count = payload + (K-1) termination bits.
BLOCK_SYMBOLS = PAYLOAD_BITS + (K - 1)  # 78

# 6 sub-watermark blocks: 3 seeded permutations × {B1, B2}.
NUM_BLOCKS = 6
NUM_PERMS = 3
TOTAL_SYMBOLS = NUM_BLOCKS * BLOCK_SYMBOLS  # 468

_N_STATES = 1 << (K - 1)  # 16384
_REG_MASK = (1 << K) - 1
_STATE_MASK = (1 << (K - 1)) - 1


def _popcount(x: int) -> int:
    return bin(x).count("1")


def _popcount_arr(x: np.ndarray) -> np.ndarray:
    # numpy popcount: unpackbits + sum. Inputs are uint16 (K up to 16).
    arr = x.astype(np.uint16).view(np.uint8).reshape(-1, 2)
    return np.unpackbits(arr, axis=1).sum(axis=1).astype(np.int32)


# Precomputed Viterbi trellis tables (built once at import).
def _build_trellis():
    """For each next-state ns, find the 2 predecessor states and the
    expected output bits (e1, e2) for each branch.

    State machine: state s is (K-1) bits = memory contents. Input bit b.
    Register reg = (b << K-1) | s (K bits). Outputs e1=parity(reg&G1),
    e2=parity(reg&G2). Next state ns = reg >> 1 (lower K-1 bits).

    From ns, we can recover:
      b = (ns >> (K-2)) & 1   (came from the top bit of pre-shift reg)
      prev_state bits 1..(K-2) = ns bits 0..(K-3)
      prev_state bit 0 ∈ {0, 1}  (the bit that was shifted out)
    So each ns has exactly 2 predecessors (one per shifted-out LSB).
    """
    ns_arr = np.arange(_N_STATES, dtype=np.int32)
    # The input bit for every predecessor of ns is encoded in ns's top bit.
    input_bit = ((ns_arr >> (K - 2)) & 1).astype(np.int8)
    # Predecessor state has bits 1..(K-2) = ns bits 0..(K-3); bit 0 is the
    # bit that was shifted out, which differs between the two predecessors.
    prev_hi = (ns_arr << 1) & _STATE_MASK  # bits 1..(K-2) populated; bit 0 = 0
    pred0 = prev_hi  # bit 0 = 0
    pred1 = prev_hi | 1  # bit 0 = 1

    # Compute (e1, e2) for each branch by reconstructing the register.
    reg0 = (input_bit.astype(np.int32) << (K - 1)) | pred0
    reg1 = (input_bit.astype(np.int32) << (K - 1)) | pred1
    e1_0 = (_popcount_arr(reg0 & G1) & 1).astype(np.int8)
    e2_0 = (_popcount_arr(reg0 & G2) & 1).astype(np.int8)
    e1_1 = (_popcount_arr(reg1 & G1) & 1).astype(np.int8)
    e2_1 = (_popcount_arr(reg1 & G2) & 1).astype(np.int8)

    return (
        pred0.astype(np.int32),
        pred1.astype(np.int32),
        input_bit,
        e1_0,
        e2_0,
        e1_1,
        e2_1,
    )


_PRED0, _PRED1, _INPUT_BIT, _E1_0, _E2_0, _E1_1, _E2_1 = _build_trellis()


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------
def _conv_encode_single(payload_bits: List[int]) -> Tuple[List[int], List[int]]:
    """Encode payload with K-1 termination bits → (B1, B2) each BLOCK_SYMBOLS long."""
    if len(payload_bits) != PAYLOAD_BITS:
        raise ValueError(f"expected {PAYLOAD_BITS} payload bits, got {len(payload_bits)}")
    state = 0
    b1: List[int] = []
    b2: List[int] = []
    for bit in payload_bits + [0] * (K - 1):
        reg = ((bit & 1) << (K - 1)) | state
        b1.append(_popcount(reg & G1) & 1)
        b2.append(_popcount(reg & G2) & 1)
        state = (reg >> 1) & _STATE_MASK
    return b1, b2


def _perm_indices(seed: int) -> np.ndarray:
    """Deterministic permutation of [0, BLOCK_SYMBOLS) for the given seed."""
    rng = np.random.default_rng(seed)
    idx = np.arange(BLOCK_SYMBOLS)
    rng.shuffle(idx)
    return idx


_PERM_SEEDS = (0x5EED01, 0x5EED02, 0x5EED03)
_PERMS = [_perm_indices(s) for s in _PERM_SEEDS]
_INV_PERMS = [np.argsort(p) for p in _PERMS]


def encode(payload_bits: List[int]) -> List[int]:
    """Encode a 64-bit payload into 468 physical symbols.

    Layout: [perm0(B1) | perm1(B1) | perm2(B1) | perm0(B2) | perm1(B2) | perm2(B2)]
    """
    b1, b2 = _conv_encode_single(payload_bits)
    b1_arr = np.asarray(b1, dtype=np.int8)
    b2_arr = np.asarray(b2, dtype=np.int8)
    out: List[int] = []
    for perm in _PERMS:
        out.extend(int(x) for x in b1_arr[perm])
    for perm in _PERMS:
        out.extend(int(x) for x in b2_arr[perm])
    return out


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------
def _viterbi(soft_b1: np.ndarray, soft_b2: np.ndarray) -> np.ndarray:
    """Soft-decision Viterbi.  soft > 0 means 'symbol indicated bit 0'.

    Returns the decoded info-bit array of length PAYLOAD_BITS (termination
    bits trimmed). Assumes the encoder zero-terminated, so we trace back
    from state 0.
    """
    if len(soft_b1) != BLOCK_SYMBOLS or len(soft_b2) != BLOCK_SYMBOLS:
        raise ValueError(f"each soft stream must be {BLOCK_SYMBOLS} long")

    INF = 1e18
    metrics = np.full(_N_STATES, INF, dtype=np.float64)
    metrics[0] = 0.0
    # traceback[t, ns] = 0 if predecessor pred0 was chosen, 1 if pred1.
    traceback = np.zeros((BLOCK_SYMBOLS, _N_STATES), dtype=np.uint8)

    sign1 = (2 * _E1_0.astype(np.float64) - 1)  # ±1
    sign2 = (2 * _E2_0.astype(np.float64) - 1)
    sign1_alt = (2 * _E1_1.astype(np.float64) - 1)
    sign2_alt = (2 * _E2_1.astype(np.float64) - 1)

    for t in range(BLOCK_SYMBOLS):
        s1 = soft_b1[t]
        s2 = soft_b2[t]
        # cost contribution: +soft if expected==1, -soft if expected==0.
        cost0 = s1 * sign1 + s2 * sign2  # per-ns cost for pred0 branch
        cost1 = s1 * sign1_alt + s2 * sign2_alt  # per-ns cost for pred1 branch
        cand0 = metrics[_PRED0] + cost0
        cand1 = metrics[_PRED1] + cost1
        new_metrics = np.minimum(cand0, cand1)
        traceback[t] = (cand1 < cand0).astype(np.uint8)
        metrics = new_metrics

    # Traceback from terminated state 0.
    state = 0
    out: List[int] = []
    for t in range(BLOCK_SYMBOLS - 1, -1, -1):
        which = int(traceback[t, state])
        bit = int(_INPUT_BIT[state])
        prev = int(_PRED1[state]) if which else int(_PRED0[state])
        out.append(bit)
        state = prev
    out.reverse()
    # Drop the K-1 zero-termination bits.
    return np.asarray(out[:PAYLOAD_BITS], dtype=np.int8)


@dataclass
class DecodeResult:
    """Result of decoding 468 soft symbols.

    Attributes:
        payload_bits: recovered 64-bit payload, or None if no candidate
            achieved a successful MAC verification.
        token: recovered token (low TOKEN_BITS of the payload).
        mac_ok: whether the MAC verified.
        strategy: which decode path succeeded ("per-pair-{0,1,2}" or
            "combined") or "none" on failure.
        ber_estimate: a coarse pre-decode BER estimate based on the
            best-pair soft-bit consistency.
    """

    payload_bits: Optional[List[int]]
    token: Optional[int]
    mac_ok: bool
    strategy: str
    ber_estimate: float


def decode(soft_symbols: List[float], mac_verifier) -> DecodeResult:
    """Decode 468 soft symbols → DecodeResult.

    `mac_verifier(payload_bits) -> (ok: bool, token: int)` is called for each
    candidate; the first successful candidate is returned.
    """
    if len(soft_symbols) != TOTAL_SYMBOLS:
        raise ValueError(f"expected {TOTAL_SYMBOLS} soft symbols, got {len(soft_symbols)}")
    arr = np.asarray(soft_symbols, dtype=np.float64)

    # Un-permute each of the 6 blocks.
    b1_blocks: List[np.ndarray] = []
    b2_blocks: List[np.ndarray] = []
    for p in range(NUM_PERMS):
        chunk = arr[p * BLOCK_SYMBOLS:(p + 1) * BLOCK_SYMBOLS]
        b1_blocks.append(chunk[_INV_PERMS[p]])
    for p in range(NUM_PERMS):
        chunk = arr[(NUM_PERMS + p) * BLOCK_SYMBOLS:(NUM_PERMS + p + 1) * BLOCK_SYMBOLS]
        b2_blocks.append(chunk[_INV_PERMS[p]])

    # Try each (B1, B2) pair independently.
    best_ber = 1.0
    for p in range(NUM_PERMS):
        soft_b1 = b1_blocks[p]
        soft_b2 = b2_blocks[p]
        # Coarse pre-decode BER estimate: fraction of soft values within a
        # narrow band around zero. Not used for decisions, just diagnostics.
        margin = float(np.median(np.abs(np.concatenate([soft_b1, soft_b2]))))
        if margin > 0:
            weak = float(np.mean(np.abs(np.concatenate([soft_b1, soft_b2])) < 0.5 * margin))
            best_ber = min(best_ber, weak)
        bits = _viterbi(soft_b1, soft_b2)
        ok, token = mac_verifier(bits.tolist())
        if ok:
            return DecodeResult(
                payload_bits=bits.tolist(),
                token=token,
                mac_ok=True,
                strategy=f"per-pair-{p}",
                ber_estimate=best_ber,
            )

    # Block-combining fallback: sum soft values across the 3 inverse-permuted pairs.
    combined_b1 = sum(b1_blocks)
    combined_b2 = sum(b2_blocks)
    bits = _viterbi(combined_b1, combined_b2)
    ok, token = mac_verifier(bits.tolist())
    if ok:
        return DecodeResult(
            payload_bits=bits.tolist(),
            token=token,
            mac_ok=True,
            strategy="combined",
            ber_estimate=best_ber,
        )

    return DecodeResult(
        payload_bits=None,
        token=None,
        mac_ok=False,
        strategy="none",
        ber_estimate=best_ber,
    )
