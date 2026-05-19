"""
Watermark payload: 40-bit opaque token || 24-bit truncated HMAC-SHA256.

The token carries no semantic content — it is an opaque lookup key into
the session DB. The MAC binds the token to a per-session key derived from
a tenant master key via HKDF.

See BUILD_SPEC.md §3.1.
"""

from __future__ import annotations

import hmac
import hashlib
from typing import List, Tuple

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

TOKEN_BITS = 40
MAC_BITS = 24
PAYLOAD_BITS = TOKEN_BITS + MAC_BITS  # 64

_TOKEN_BYTES = (TOKEN_BITS + 7) // 8  # 5
_MAC_BYTES = (MAC_BITS + 7) // 8  # 3


def derive_mac_key(
    tenant_master_key: bytes,
    token: int,
    user_id: str,
    device_id: str,
) -> bytes:
    """HKDF a per-session MAC key. Tenant master key never leaves the KMS in prod;
    here we accept the bytes directly. Returns 32 bytes."""
    info = (
        token.to_bytes(_TOKEN_BYTES, "big")
        + b"|"
        + user_id.encode("utf-8")
        + b"|"
        + device_id.encode("utf-8")
    )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"watermark-mvp/v1/mac",
        info=info,
    )
    return hkdf.derive(tenant_master_key)


def bits_from_int(n: int, width: int) -> List[int]:
    return [(n >> i) & 1 for i in range(width - 1, -1, -1)]


def int_from_bits(bits: List[int]) -> int:
    n = 0
    for b in bits:
        n = (n << 1) | (b & 1)
    return n


def _compute_mac(token: int, mac_key: bytes) -> int:
    tag = hmac.new(mac_key, token.to_bytes(_TOKEN_BYTES, "big"), hashlib.sha256).digest()
    return int.from_bytes(tag[:_MAC_BYTES], "big")


def make_payload(token: int, mac_key: bytes) -> List[int]:
    """Build the 64-bit payload bit-list for a token under the given MAC key."""
    if not (0 <= token < (1 << TOKEN_BITS)):
        raise ValueError(f"token must fit in {TOKEN_BITS} bits")
    mac = _compute_mac(token, mac_key)
    return bits_from_int(token, TOKEN_BITS) + bits_from_int(mac, MAC_BITS)


def verify_payload(bits: List[int], mac_key: bytes) -> Tuple[bool, int]:
    """Returns (mac_ok, token)."""
    if len(bits) != PAYLOAD_BITS:
        raise ValueError(f"payload must be {PAYLOAD_BITS} bits")
    token = int_from_bits(bits[:TOKEN_BITS])
    got = int_from_bits(bits[TOKEN_BITS:])
    expected = _compute_mac(token, mac_key)
    return (got == expected), token
