"""Core watermarking algorithm: payload, convolutional code, symbol render/extract."""

from .payload import (
    PAYLOAD_BITS,
    TOKEN_BITS,
    MAC_BITS,
    derive_mac_key,
    make_payload,
    verify_payload,
)
from .conv_code import (
    K,
    BLOCK_SYMBOLS,
    NUM_BLOCKS,
    TOTAL_SYMBOLS,
    encode,
    decode,
)
from .symbols import (
    SYMBOL_SIZE,
    DEFAULT_DELTA,
    build_overlay,
    extract_soft_bits,
)

__all__ = [
    "PAYLOAD_BITS",
    "TOKEN_BITS",
    "MAC_BITS",
    "derive_mac_key",
    "make_payload",
    "verify_payload",
    "K",
    "BLOCK_SYMBOLS",
    "NUM_BLOCKS",
    "TOTAL_SYMBOLS",
    "encode",
    "decode",
    "SYMBOL_SIZE",
    "DEFAULT_DELTA",
    "build_overlay",
    "extract_soft_bits",
]
