"""MurmurHash3 x86 32-bit, stdlib only (spec §2.9, WP9).

``hash32`` returns the same signed value as the reference ``mmh3.hash`` package; ``favicon_hash`` applies the Shodan
convention used by nuclei's favicon-detect templates: ``mmh3(base64.encodebytes(icon))`` (base64 with a newline every
76 characters and a trailing newline, exactly as Python's ``base64.encodebytes`` produces it).
"""

from __future__ import annotations

import base64
import struct

_C1 = 0xCC9E2D51
_C2 = 0x1B873593
_M32 = 0xFFFFFFFF


def _rotl(x: int, r: int) -> int:
    return ((x << r) | (x >> (32 - r))) & _M32


def hash32(data: bytes | str, seed: int = 0, *, signed: bool = True) -> int:
    """MurmurHash3_x86_32 of ``data`` (``str`` is UTF-8 encoded, as the reference package does)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    h = seed & _M32
    n = len(data)
    body = n - n % 4
    for (k,) in struct.iter_unpack("<I", data[:body]):
        k = _rotl((k * _C1) & _M32, 15) * _C2 & _M32
        h = (_rotl(h ^ k, 13) * 5 + 0xE6546B64) & _M32
    tail = data[body:]
    k = 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if tail:
        k ^= tail[0]
        k = _rotl((k * _C1) & _M32, 15) * _C2 & _M32
        h ^= k
    h ^= n
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & _M32
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & _M32
    h ^= h >> 16
    if signed and h & 0x80000000:
        return h - (1 << 32)
    return h


def favicon_hash(icon: bytes) -> int:
    """Shodan/nuclei favicon hash: signed mmh3 of ``base64.encodebytes(icon)``."""
    return hash32(base64.encodebytes(icon))


__all__ = ["hash32", "favicon_hash"]
