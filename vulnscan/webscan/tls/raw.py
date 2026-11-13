"""Raw ClientHello probes: builder and plaintext reply parser (spec §2.8 step 3, WP10).

A probe is byte-for-byte the first flight a browser sends: one ClientHello per TCP connection. Kashif reads only the
server's plaintext reply (ServerHello, Certificate, CertificateStatus, ServerKeyExchange, ServerHelloDone; for TLS 1.3
only the ServerHello or HelloRetryRequest, because everything after it is encrypted) and closes the connection. No key
exchange is completed, no malformed or attack record is ever sent (no Heartbleed, ROBOT, padding-oracle or
renegotiation test), and the cipher suites listed in a hello are only ever *offered*.

Why raw hellos: Python's ``ssl`` cannot offer TLS < 1.2 on OpenSSL 3 at the default security level, cannot offer
suites compiled out of the local OpenSSL (RC4, 3DES, EXPORT, NULL, anon), has no TLS 1.3 suite or group API and
exposes neither stapled OCSP nor TLS-delivered SCTs. A hand-built hello is independent of the local OpenSSL build.

Everything here is pure except :func:`exchange`, which sends a hello on a socket the caller opened (``tls/probe.py``
opens sockets only through the scan's Fetcher: SSRF guard, DNS pin, proxy tunnel and pacing).
"""

from __future__ import annotations

import os
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import NamedTuple

# ----------------------------------------------------------------------------------------------- versions

SSL2, SSL3, TLS10, TLS11, TLS12, TLS13 = 0x0002, 0x0300, 0x0301, 0x0302, 0x0303, 0x0304
VERSION_NAMES = {SSL2: "SSLv2", SSL3: "SSLv3", TLS10: "TLSv1.0", TLS11: "TLSv1.1", TLS12: "TLSv1.2", TLS13: "TLSv1.3"}
VERSION_IDS = {v: k for k, v in VERSION_NAMES.items()}
# probe order: newest first (a server that answers the modern hellos is healthy before any legacy hello is sent)
PROBE_VERSIONS = ("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3", "SSLv2")
# openssl s_client flag reproducing a version probe (§3.6 evidence)
OPENSSL_FLAGS = {"SSLv3": "-ssl3", "TLSv1.0": "-tls1", "TLSv1.1": "-tls1_1", "TLSv1.2": "-tls1_2", "TLSv1.3": "-tls1_3"}

HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
DOWNGRADE_TLS12 = b"DOWNGRD\x01"     # RFC 8446 §4.1.3: a TLS 1.3 server answering a TLS 1.2 hello
DOWNGRADE_TLS11 = b"DOWNGRD\x00"     # … answering a TLS 1.1-or-older hello

# ----------------------------------------------------------------------------------------------- extensions

EXT_SNI, EXT_STATUS_REQUEST, EXT_GROUPS, EXT_POINT_FMT = 0, 5, 10, 11
EXT_SIGALGS, EXT_ALPN, EXT_SCT, EXT_PADDING = 13, 16, 18, 21
EXT_ETM, EXT_EMS, EXT_TICKET, EXT_SUPPORTED_VERSIONS = 22, 23, 35, 43
EXT_PSK_MODES, EXT_KEY_SHARE, EXT_RENEG = 45, 51, 0xFF01

SCSV_RENEGOTIATION = 0x00FF          # TLS_EMPTY_RENEGOTIATION_INFO_SCSV (RFC 5746)
SCSV_FALLBACK = 0x5600               # TLS_FALLBACK_SCSV (RFC 7507)

GROUPS = {0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x001D: "x25519", 0x001E: "x448",
          0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096", 0x0103: "ffdhe6144", 0x0104: "ffdhe8192",
          0x11EB: "SecP256r1MLKEM768", 0x11EC: "X25519MLKEM768", 0x11ED: "SecP384r1MLKEM1024",
          0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024"}
GROUP_IDS = {v: k for k, v in GROUPS.items()}
X25519MLKEM768 = 0x11EC
# deep-profile TLS 1.3 group probes (one hello each, empty key_share → HelloRetryRequest iff supported)
PROBE_GROUPS = (0x11EC, 0x001D, 0x0017, 0x0018, 0x0019, 0x001E, 0x0100, 0x0101)
# ECDHE/key size in "RSA-equivalent" bits (SSL Labs key-exchange score)
GROUP_RSA_EQUIV = {"secp256r1": 3072, "secp384r1": 7680, "secp521r1": 15360, "x25519": 3072, "x448": 7680,
                   "ffdhe2048": 2048, "ffdhe3072": 3072, "ffdhe4096": 4096, "ffdhe6144": 6144, "ffdhe8192": 8192,
                   "X25519MLKEM768": 3072, "SecP256r1MLKEM768": 3072, "SecP384r1MLKEM1024": 7680}

SIGALGS = (0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201)

ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure",
          42: "bad_certificate", 47: "illegal_parameter", 50: "decode_error", 51: "decrypt_error",
          70: "protocol_version", 71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
          90: "user_canceled", 109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name",
          120: "no_application_protocol"}
# alerts that mean "I do not support what you offered" (definitive "no", §2.8 step 3)
REFUSAL_ALERTS = frozenset({40, 70, 71, 47, 50, 10, 112, 109, 110})

# ----------------------------------------------------------------------------------------------- cipher suites


class Suite(NamedTuple):
    name: str
    kex: str          # ECDHE | DHE | RSA | RSA_EXPORT | DHE_EXPORT | ECDH | DH | any (TLS 1.3)
    auth: str         # RSA | ECDSA | DSS | anon | any
    enc: str          # AESGCM | CHACHA20 | AES | CAMELLIA | 3DES | DES | RC4 | NULL | AESCCM
    bits: int         # symmetric strength
    mac: str          # AEAD | SHA1 | SHA256 | SHA384 | MD5


def _s(name, kex, auth, enc, bits, mac):
    return Suite(name, kex, auth, enc, bits, mac)


SUITES: dict[int, Suite] = {
    # TLS 1.3
    0x1301: _s("TLS_AES_128_GCM_SHA256", "any", "any", "AESGCM", 128, "AEAD"),
    0x1302: _s("TLS_AES_256_GCM_SHA384", "any", "any", "AESGCM", 256, "AEAD"),
    0x1303: _s("TLS_CHACHA20_POLY1305_SHA256", "any", "any", "CHACHA20", 256, "AEAD"),
    0x1304: _s("TLS_AES_128_CCM_SHA256", "any", "any", "AESCCM", 128, "AEAD"),
    0x1305: _s("TLS_AES_128_CCM_8_SHA256", "any", "any", "AESCCM", 128, "AEAD"),
    # ECDHE AEAD (Mozilla intermediate)
    0xC02B: _s("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", "ECDSA", "AESGCM", 128, "AEAD"),
    0xC02F: _s("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "RSA", "AESGCM", 128, "AEAD"),
    0xC02C: _s("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", "ECDSA", "AESGCM", 256, "AEAD"),
    0xC030: _s("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "RSA", "AESGCM", 256, "AEAD"),
    0xCCA9: _s("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "ECDSA", "CHACHA20", 256, "AEAD"),
    0xCCA8: _s("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "RSA", "CHACHA20", 256, "AEAD"),
    # DHE AEAD
    0x009E: _s("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE", "RSA", "AESGCM", 128, "AEAD"),
    0x009F: _s("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE", "RSA", "AESGCM", 256, "AEAD"),
    0xCCAA: _s("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "DHE", "RSA", "CHACHA20", 256, "AEAD"),
    # ECDHE CBC
    0xC023: _s("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE", "ECDSA", "AES", 128, "SHA256"),
    0xC027: _s("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE", "RSA", "AES", 128, "SHA256"),
    0xC024: _s("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE", "ECDSA", "AES", 256, "SHA384"),
    0xC028: _s("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE", "RSA", "AES", 256, "SHA384"),
    0xC009: _s("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE", "ECDSA", "AES", 128, "SHA1"),
    0xC013: _s("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE", "RSA", "AES", 128, "SHA1"),
    0xC00A: _s("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE", "ECDSA", "AES", 256, "SHA1"),
    0xC014: _s("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE", "RSA", "AES", 256, "SHA1"),
    # DHE CBC
    0x0067: _s("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE", "RSA", "AES", 128, "SHA256"),
    0x006B: _s("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE", "RSA", "AES", 256, "SHA256"),
    0x0033: _s("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE", "RSA", "AES", 128, "SHA1"),
    0x0039: _s("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE", "RSA", "AES", 256, "SHA1"),
    0x0045: _s("TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", "DHE", "RSA", "CAMELLIA", 128, "SHA1"),
    0x0088: _s("TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", "DHE", "RSA", "CAMELLIA", 256, "SHA1"),
    # static RSA key exchange (no forward secrecy)
    0x009C: _s("TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", "RSA", "AESGCM", 128, "AEAD"),
    0x009D: _s("TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA", "RSA", "AESGCM", 256, "AEAD"),
    0x003C: _s("TLS_RSA_WITH_AES_128_CBC_SHA256", "RSA", "RSA", "AES", 128, "SHA256"),
    0x003D: _s("TLS_RSA_WITH_AES_256_CBC_SHA256", "RSA", "RSA", "AES", 256, "SHA256"),
    0x002F: _s("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", "RSA", "AES", 128, "SHA1"),
    0x0035: _s("TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", "RSA", "AES", 256, "SHA1"),
    0x0041: _s("TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", "RSA", "RSA", "CAMELLIA", 128, "SHA1"),
    0x0084: _s("TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", "RSA", "RSA", "CAMELLIA", 256, "SHA1"),
    # 3DES (SWEET32)
    0xC008: _s("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "ECDHE", "ECDSA", "3DES", 112, "SHA1"),
    0xC012: _s("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE", "RSA", "3DES", 112, "SHA1"),
    0x0016: _s("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "DHE", "RSA", "3DES", 112, "SHA1"),
    0x000A: _s("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", "RSA", "3DES", 112, "SHA1"),
    # RC4
    0xC007: _s("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "ECDHE", "ECDSA", "RC4", 128, "SHA1"),
    0xC011: _s("TLS_ECDHE_RSA_WITH_RC4_128_SHA", "ECDHE", "RSA", "RC4", 128, "SHA1"),
    0x0005: _s("TLS_RSA_WITH_RC4_128_SHA", "RSA", "RSA", "RC4", 128, "SHA1"),
    0x0004: _s("TLS_RSA_WITH_RC4_128_MD5", "RSA", "RSA", "RC4", 128, "MD5"),
    # single DES
    0x0009: _s("TLS_RSA_WITH_DES_CBC_SHA", "RSA", "RSA", "DES", 56, "SHA1"),
    0x0015: _s("TLS_DHE_RSA_WITH_DES_CBC_SHA", "DHE", "RSA", "DES", 56, "SHA1"),
    # EXPORT
    0x0003: _s("TLS_RSA_EXPORT_WITH_RC4_40_MD5", "RSA_EXPORT", "RSA", "RC4", 40, "MD5"),
    0x0006: _s("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "RSA_EXPORT", "RSA", "RC2", 40, "MD5"),
    0x0008: _s("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "RSA_EXPORT", "RSA", "DES", 40, "SHA1"),
    0x0014: _s("TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "DHE_EXPORT", "RSA", "DES", 40, "SHA1"),
    # NULL encryption
    0x0001: _s("TLS_RSA_WITH_NULL_MD5", "RSA", "RSA", "NULL", 0, "MD5"),
    0x0002: _s("TLS_RSA_WITH_NULL_SHA", "RSA", "RSA", "NULL", 0, "SHA1"),
    0x003B: _s("TLS_RSA_WITH_NULL_SHA256", "RSA", "RSA", "NULL", 0, "SHA256"),
    0xC006: _s("TLS_ECDHE_ECDSA_WITH_NULL_SHA", "ECDHE", "ECDSA", "NULL", 0, "SHA1"),
    0xC010: _s("TLS_ECDHE_RSA_WITH_NULL_SHA", "ECDHE", "RSA", "NULL", 0, "SHA1"),
    # anonymous (no authentication)
    0x0018: _s("TLS_DH_anon_WITH_RC4_128_MD5", "DH", "anon", "RC4", 128, "MD5"),
    0x0034: _s("TLS_DH_anon_WITH_AES_128_CBC_SHA", "DH", "anon", "AES", 128, "SHA1"),
    0x003A: _s("TLS_DH_anon_WITH_AES_256_CBC_SHA", "DH", "anon", "AES", 256, "SHA1"),
    0x00A6: _s("TLS_DH_anon_WITH_AES_128_GCM_SHA256", "DH", "anon", "AESGCM", 128, "AEAD"),
    0xC018: _s("TLS_ECDH_anon_WITH_AES_128_CBC_SHA", "ECDH", "anon", "AES", 128, "SHA1"),
    0xC019: _s("TLS_ECDH_anon_WITH_AES_256_CBC_SHA", "ECDH", "anon", "AES", 256, "SHA1"),
}
TLS13_SUITES = (0x1301, 0x1302, 0x1303)
TLS13_ALL_SUITES = (0x1301, 0x1302, 0x1303, 0x1304, 0x1305)
LEGACY_SUITES = tuple(c for c in SUITES if c not in TLS13_ALL_SUITES)
# suites an SSL 3.0 server can pick (no GCM/SHA-256 suites, no ECC)
SSL3_SUITES = tuple(c for c, s in SUITES.items() if c not in TLS13_ALL_SUITES and s.mac in ("SHA1", "MD5")
                    and s.kex not in ("ECDHE", "ECDH"))
MOZILLA_INTERMEDIATE = (0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8)


def suite_name(cid: int | None) -> str:
    if cid is None:
        return ""
    s = SUITES.get(cid)
    return s.name if s else f"0x{cid:04X}"


def suite_category(cid: int) -> str:
    """The weakness category of a TLS ≤ 1.2 suite (WEB706): null, anon, export, des, rc4, 3des, krsa, cbc or good.

    ``krsa`` = static RSA key exchange with an otherwise acceptable cipher (no forward secrecy); ``cbc`` = forward
    secret but CBC (not a WEB706 finding, only a Mozilla deviation); ``good`` = ECDHE/DHE with an AEAD cipher."""
    s = SUITES.get(cid)
    if s is None:
        return "unknown"
    if s.enc == "NULL":
        return "null"
    if s.auth == "anon":
        return "anon"
    if "EXPORT" in s.kex:
        return "export"
    if s.enc == "DES":
        return "des"
    if s.enc == "RC4":
        return "rc4"
    if s.enc == "3DES":
        return "3des"
    if s.kex == "RSA":
        return "krsa"
    if s.mac != "AEAD":
        return "cbc"
    return "good"


def _cat(*names: str) -> tuple[int, ...]:
    return tuple(c for c in LEGACY_SUITES if suite_category(c) in names)


# one raw hello per probe set: the server picks a member iff it supports one (§2.8 step 3, verified in the lab)
CATEGORY_PROBES: dict[str, tuple[int, ...]] = {
    "null_anon": _cat("null", "anon"),
    "export_des": _cat("export", "des"),
    "rc4": _cat("rc4"),
    "3des": _cat("3des"),
    "krsa": _cat("krsa"),
    "cbc": _cat("cbc"),
    "aead": tuple(c for c in LEGACY_SUITES if SUITES[c].mac == "AEAD" and SUITES[c].auth != "anon"),
}
FS_SUITES = tuple(c for c in LEGACY_SUITES if SUITES[c].kex in ("ECDHE", "DHE") and suite_category(c) != "null")
DHE_SUITES = tuple(c for c in LEGACY_SUITES if SUITES[c].kex == "DHE")
ECDHE_SUITES = tuple(c for c in LEGACY_SUITES if SUITES[c].kex == "ECDHE" and suite_category(c) not in ("null",))

# ----------------------------------------------------------------------------------------------- builder


def _u8(b: bytes) -> bytes:
    return struct.pack(">B", len(b)) + b


def _u16(b: bytes) -> bytes:
    return struct.pack(">H", len(b)) + b


def _u24(b: bytes) -> bytes:
    return struct.pack(">I", len(b))[1:] + b


def ext(t: int, body: bytes) -> bytes:
    return struct.pack(">H", t) + _u16(body)


def is_ip(host: str) -> bool:
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, host)
            return True
        except (OSError, ValueError):
            pass
    return False


def _sni(host: str | None) -> bytes:
    if not host or is_ip(host):            # RFC 6066 §3: no IP literals in server_name
        return b""
    try:
        name = host.rstrip(".").encode("idna")
    except UnicodeError:
        name = host.rstrip(".").encode("ascii", "ignore")
    return ext(EXT_SNI, _u16(b"\x00" + _u16(name)))


def client_hello(host: str | None, version: int, ciphers: tuple[int, ...] | list[int], *,
                 groups: tuple[int, ...] = (0x001D, 0x0017, 0x0018, 0x0019),
                 key_share_groups: tuple[int, ...] = (0x001D,), alpn: tuple[str, ...] = ("http/1.1",),
                 status_request: bool = True, sct: bool = True, compression: tuple[int, ...] = (0,),
                 renegotiation_info: bool = True, extra_suites: tuple[int, ...] = (),
                 record_version: int = TLS10, random: bytes | None = None, session_id: bytes | None = None) -> bytes:
    """One TLS ClientHello record (TLS 1.0 … 1.3).

    ``version`` is the highest version offered. TLS 1.3 uses legacy_version 0x0303 and ``supported_versions``
    [1.3, 1.2] so a 1.2-only server still answers with its own version. ``key_share_groups=()`` sends an empty
    key_share list: a TLS 1.3 server that supports one of ``groups`` must answer HelloRetryRequest (RFC 8446 §4.1.4).
    The record version is 0x0301 like browsers send (the most tolerant choice). Hellos of 256–511 bytes are padded
    to 512 (RFC 7685), as Chrome and OpenSSL do, because such sizes hang some old load balancers."""
    exts = _sni(host)
    if groups:
        exts += ext(EXT_GROUPS, _u16(b"".join(struct.pack(">H", g) for g in groups)))
        exts += ext(EXT_POINT_FMT, _u8(b"\x00"))
    if version >= TLS12:
        exts += ext(EXT_SIGALGS, _u16(b"".join(struct.pack(">H", s) for s in SIGALGS)))
    if status_request:                       # CertificateStatusRequest: ocsp(1), no responder ids, no extensions
        exts += ext(EXT_STATUS_REQUEST, b"\x01\x00\x00\x00\x00")
    if sct:
        exts += ext(EXT_SCT, b"")
    if alpn:
        exts += ext(EXT_ALPN, _u16(b"".join(_u8(p.encode("ascii")) for p in alpn)))
    exts += ext(EXT_EMS, b"") + ext(EXT_TICKET, b"")
    if renegotiation_info:
        exts += ext(EXT_RENEG, b"\x00")      # empty renegotiated_connection (RFC 5746 §3.4)
    if version >= TLS13:
        exts += ext(EXT_SUPPORTED_VERSIONS, _u8(struct.pack(">HH", TLS13, TLS12)))
        exts += ext(EXT_PSK_MODES, _u8(b"\x01"))
        shares = b""
        for g in key_share_groups:           # x25519: any 32 bytes are a valid u-coordinate; no secret is kept
            if g == 0x001D:
                shares += struct.pack(">H", g) + _u16(os.urandom(32))
        exts += ext(EXT_KEY_SHARE, _u16(shares))
    legacy = min(version, TLS12)
    rnd = random if random is not None else os.urandom(32)
    sid = session_id if session_id is not None else os.urandom(32)
    suites = tuple(ciphers) + tuple(extra_suites)

    def body(e: bytes) -> bytes:
        return (struct.pack(">H", legacy) + rnd + _u8(sid) + _u16(b"".join(struct.pack(">H", c) for c in suites))
                + _u8(bytes(compression)) + _u16(e))

    b = body(exts)
    if 0xFF < len(b) + 4 < 0x200:
        pad = 0x200 - (len(b) + 4) - 4
        b = body(exts + ext(EXT_PADDING, b"\x00" * max(pad, 1)))
    hs = b"\x01" + _u24(b)
    return b"\x16" + struct.pack(">H", record_version) + _u16(hs)


def sslv3_client_hello(ciphers: tuple[int, ...] = SSL3_SUITES, *, random: bytes | None = None) -> bytes:
    """An SSL 3.0 ClientHello: version 0x0300 in record and hello, no extensions block, plus the renegotiation SCSV."""
    rnd = random if random is not None else os.urandom(32)
    suites = tuple(ciphers) + (SCSV_RENEGOTIATION,)
    b = (struct.pack(">H", SSL3) + rnd + _u8(b"") + _u16(b"".join(struct.pack(">H", c) for c in suites))
         + _u8(b"\x00"))
    hs = b"\x01" + _u24(b)
    return b"\x16" + struct.pack(">H", SSL3) + _u16(hs)


SSL2_CIPHER_SPECS = bytes.fromhex("010080" "020080" "030080" "040080" "050080" "060040" "0700C0")


def sslv2_client_hello(challenge: bytes | None = None) -> bytes:
    """An SSL 2.0 CLIENT-HELLO (2-byte header with the high bit set): the seven SSLv2 cipher specs, no session id,
    a 16-byte challenge. A server that speaks SSLv2 answers SERVER-HELLO (message type 4, version 0x0002)."""
    ch = challenge if challenge is not None else os.urandom(16)
    body = (b"\x01" + struct.pack(">H", SSL2) + struct.pack(">HHH", len(SSL2_CIPHER_SPECS), 0, len(ch))
            + SSL2_CIPHER_SPECS + ch)
    return struct.pack(">H", 0x8000 | len(body)) + body


# ----------------------------------------------------------------------------------------------- reply parser

MAX_RECORD = 18432                     # 2^14 + 2048 (RFC 5246 §6.2.3)
MAX_FLIGHT = 256 * 1024
# detail of a reply cut by the deadline (a server dripping bytes): counts as a timeout for the back-off (§2.8 step 4)
PARTIAL_TIMEOUT = "partial reply, then silence"


@dataclass
class Flight:
    """What the server answered to one ClientHello (plaintext part only).

    ``result``: ``hello`` (ServerHello or HelloRetryRequest), ``alert``, ``eof`` (connection closed or reset without a
    reply), ``timeout``, ``not_tls`` (a reply that is not a TLS handshake), ``error`` (no connection) or
    ``incomplete`` (still reading). ``version`` is the negotiated version (``supported_versions`` wins over
    legacy_version); ``sslv2`` marks an SSL 2.0 SERVER-HELLO."""
    result: str = "incomplete"
    version: int | None = None
    legacy_version: int | None = None
    cipher: int | None = None
    compression: int | None = None
    extensions: dict[int, bytes] = field(default_factory=dict)
    hrr: bool = False
    downgrade: str | None = None          # "tls12" | "tls11" sentinel in the server random
    certs: list[bytes] = field(default_factory=list)   # TLS ≤ 1.2 Certificate message (DER, as sent)
    ocsp: bytes | None = None             # TLS ≤ 1.2 CertificateStatus (DER OCSPResponse)
    ske: bytes | None = None              # ServerKeyExchange body
    alert: tuple[int, int] | None = None
    record_version: int | None = None
    done: bool = False                    # ServerHelloDone / TLS 1.3 ServerHello / HRR / alert seen
    detail: str = ""
    nbytes: int = 0

    @property
    def accepted(self) -> bool:
        return self.result == "hello"

    @property
    def version_name(self) -> str:
        return VERSION_NAMES.get(self.version or -1, f"0x{self.version:04X}" if self.version else "")

    def selected_group(self) -> int | None:
        """The group of a TLS 1.3 key_share (HRR: the requested group; ServerHello: the server's share)."""
        ks = self.extensions.get(EXT_KEY_SHARE)
        if ks and len(ks) >= 2:
            return struct.unpack(">H", ks[:2])[0]
        return None

    def to_dict(self) -> dict:
        return {"result": self.result, "version": self.version_name or None, "cipher": suite_name(self.cipher) or None,
                "compression": self.compression, "hrr": self.hrr, "downgrade": self.downgrade,
                "alert": list(self.alert) if self.alert else None,
                "alert_name": ALERTS.get(self.alert[1], str(self.alert[1])) if self.alert else None,
                "extensions": sorted(self.extensions), "detail": self.detail}


class _Malformed(ValueError):
    pass


def _parse_server_hello(m: bytes, out: Flight) -> None:
    if len(m) < 38:
        raise _Malformed("short ServerHello")
    ver = struct.unpack(">H", m[0:2])[0]
    rnd = m[2:34]
    sidlen = m[34]
    p = 35 + sidlen
    if p + 3 > len(m):
        raise _Malformed("short ServerHello")
    cipher = struct.unpack(">H", m[p:p + 2])[0]
    comp = m[p + 2]
    p += 3
    exts: dict[int, bytes] = {}
    if p + 2 <= len(m):
        elen = struct.unpack(">H", m[p:p + 2])[0]
        p += 2
        end = min(p + elen, len(m))
        while p + 4 <= end:
            t, ln = struct.unpack(">HH", m[p:p + 4])
            exts.setdefault(t, m[p + 4:p + 4 + ln])
            p += 4 + ln
    out.legacy_version = ver
    sv = exts.get(EXT_SUPPORTED_VERSIONS)
    if sv is not None and len(sv) == 2:
        ver = struct.unpack(">H", sv)[0]
    out.version, out.cipher, out.compression, out.extensions = ver, cipher, comp, exts
    out.hrr = rnd == HRR_RANDOM
    tail = rnd[-8:]
    out.downgrade = {DOWNGRADE_TLS12: "tls12", DOWNGRADE_TLS11: "tls11"}.get(tail)


def _parse_certificate(m: bytes) -> list[bytes]:
    if len(m) < 3:
        return []
    total = int.from_bytes(m[0:3], "big")
    p, end, certs = 3, min(3 + total, len(m)), []
    while p + 3 <= end and len(certs) < 20:
        ln = int.from_bytes(m[p:p + 3], "big")
        if p + 3 + ln > end:
            break
        certs.append(bytes(m[p + 3:p + 3 + ln]))
        p += 3 + ln
    return certs


def _parse_sslv2(data: bytes, out: Flight) -> Flight:
    if len(data) < 2:
        return out
    if data[0] & 0x80:
        hdr = 2
        length = ((data[0] & 0x7F) << 8) | data[1]
    else:
        hdr = 3
        length = ((data[0] & 0x3F) << 8) | data[1]
    if len(data) < hdr + min(length, 7):
        return out                                    # need more bytes
    body = data[hdr:hdr + length]
    if len(body) >= 5 and body[0] == 0x04:            # SERVER-HELLO: hit, cert type, version
        out.result, out.done, out.version = "hello", True, struct.unpack(">H", body[3:5])[0]
        out.legacy_version = out.version
        return out
    out.result, out.done, out.detail = "not_tls", True, "SSLv2-style reply that is not SERVER-HELLO"
    return out


def parse_flight(data: bytes, *, eof: bool = False) -> Flight:
    """Parse the server's reply bytes (everything received so far). ``eof`` marks a closed connection.

    Pure function; never raises on hostile input (a malformed reply becomes ``not_tls`` with a detail)."""
    out = Flight(nbytes=len(data))
    if not data:
        if eof:
            out.result, out.done = "eof", True
        return out
    if data[0] & 0x80 and data[0] not in (20, 21, 22, 23):
        _parse_sslv2(data, out)
        if not out.done and eof:
            out.result, out.done, out.detail = "not_tls", True, "truncated SSLv2 reply"
        return out
    p = 0
    hs = b""
    try:
        while p + 5 <= len(data):
            ctype = data[p]
            rver = struct.unpack(">H", data[p + 1:p + 3])[0]
            rlen = struct.unpack(">H", data[p + 3:p + 5])[0]
            if ctype not in (20, 21, 22, 23) or rver >> 8 != 3 or rlen > MAX_RECORD:
                if out.result == "hello":
                    out.done = True
                    return out
                out.result, out.done = "not_tls", True
                out.detail = f"not a TLS record (first bytes {data[p:p + 5].hex()})"
                return out
            if p + 5 + rlen > len(data):
                break                                     # wait for the rest of the record
            payload = data[p + 5:p + 5 + rlen]
            p += 5 + rlen
            if out.record_version is None:
                out.record_version = rver
            if ctype == 21:
                if len(payload) >= 2:
                    out.alert = (payload[0], payload[1])
                if out.result != "hello":
                    out.result = "alert"
                out.done = True
                return out
            if ctype in (20, 23):                         # ChangeCipherSpec / encrypted data: TLS 1.3 flight goes on
                if out.result == "hello":
                    out.done = True
                    return out
                out.result, out.done, out.detail = "not_tls", True, "encrypted record before ServerHello"
                return out
            hs += payload
            while len(hs) >= 4:
                mtype = hs[0]
                mlen = int.from_bytes(hs[1:4], "big")
                if mlen > MAX_FLIGHT:
                    raise _Malformed("handshake message too large")
                if len(hs) < 4 + mlen:
                    break
                msg, hs = hs[4:4 + mlen], hs[4 + mlen:]
                if mtype == 2:
                    _parse_server_hello(msg, out)
                    out.result = "hello"
                    if out.hrr or (out.version or 0) >= TLS13:
                        out.done = True                   # the rest is encrypted, or HRR needs a second hello
                        return out
                elif out.result != "hello":
                    raise _Malformed(f"handshake message {mtype} before ServerHello")
                elif mtype == 11:
                    out.certs = _parse_certificate(msg)
                elif mtype == 22:                         # CertificateStatus: ocsp(1), u24 length, OCSPResponse
                    if msg and msg[0] == 1 and len(msg) >= 4:
                        out.ocsp = bytes(msg[4:4 + int.from_bytes(msg[1:4], "big")])
                elif mtype == 12:
                    out.ske = bytes(msg)
                elif mtype == 14:                         # ServerHelloDone
                    out.done = True
                    return out
    except (_Malformed, struct.error, IndexError) as e:
        if out.result == "hello":
            out.done, out.detail = True, f"malformed flight after ServerHello: {e}"
            return out
        out.result, out.done, out.detail = "not_tls", True, f"malformed reply: {e}"
        return out
    if eof and not out.done:
        out.done = True
        if out.result == "incomplete":
            out.result, out.detail = ("not_tls", "connection closed inside a record")
    return out


def exchange(sock: socket.socket, hello: bytes, timeout: float, *, max_bytes: int = MAX_FLIGHT) -> tuple[Flight, bytes]:
    """Send ``hello`` and read the plaintext reply until the flight is complete, the peer closes, the deadline passes
    or ``max_bytes`` arrive. Returns the parsed flight and the raw bytes received (for recording fixtures)."""
    deadline = time.monotonic() + timeout
    data = b""
    try:
        sock.settimeout(timeout)
        sock.sendall(hello)
        while len(data) < max_bytes:
            left = deadline - time.monotonic()
            if left <= 0:
                raise socket.timeout("flight deadline")
            sock.settimeout(left)
            chunk = sock.recv(65536)
            if not chunk:
                return parse_flight(data, eof=True), data
            data += chunk
            fl = parse_flight(data)
            if fl.done:
                return fl, data
        fl = parse_flight(data, eof=True)
        fl.detail = fl.detail or "reply larger than the read cap"
        return fl, data
    except socket.timeout:
        fl = parse_flight(data)
        if fl.result == "hello":
            fl.done, fl.detail = True, "timed out after ServerHello"
            return fl, data
        if data:
            fl.result, fl.detail = "not_tls", PARTIAL_TIMEOUT
        else:
            fl.result = "timeout"
        fl.done = True
        return fl, data
    except (ConnectionError, OSError) as e:
        fl = parse_flight(data, eof=True)
        if fl.result in ("eof", "not_tls") and not data:
            fl.result, fl.detail = "eof", f"connection reset: {e.__class__.__name__}"
        return fl, data


# ----------------------------------------------------------------------------------------------- ServerKeyExchange

def parse_ske(ske: bytes | None, kex: str) -> dict:
    """ECDHE: ``{"group": name}``; DHE: ``{"dh_bits": n, "dh_prime": bytes}`` (TLS ≤ 1.2 ServerKeyExchange)."""
    if not ske:
        return {}
    try:
        if kex.startswith("ECDH") and ske[0] == 3 and len(ske) >= 3:
            g = struct.unpack(">H", ske[1:3])[0]
            return {"group": GROUPS.get(g, f"0x{g:04X}")}
        if kex.startswith("DH"):
            plen = struct.unpack(">H", ske[0:2])[0]
            p = ske[2:2 + plen]
            if len(p) != plen:
                return {}
            return {"dh_bits": int.from_bytes(p, "big").bit_length(), "dh_prime": bytes(p)}
    except (IndexError, struct.error):
        return {}
    return {}


__all__ = [
    "SSL2", "SSL3", "TLS10", "TLS11", "TLS12", "TLS13", "VERSION_NAMES", "VERSION_IDS", "PROBE_VERSIONS", "OPENSSL_FLAGS",
    "HRR_RANDOM", "GROUPS", "GROUP_IDS", "X25519MLKEM768", "PROBE_GROUPS", "GROUP_RSA_EQUIV", "ALERTS", "REFUSAL_ALERTS",
    "Suite", "SUITES", "TLS13_SUITES", "TLS13_ALL_SUITES", "LEGACY_SUITES", "SSL3_SUITES", "MOZILLA_INTERMEDIATE",
    "CATEGORY_PROBES", "FS_SUITES", "DHE_SUITES", "ECDHE_SUITES", "SCSV_RENEGOTIATION", "SCSV_FALLBACK", "suite_name",
    "suite_category", "client_hello", "sslv3_client_hello", "sslv2_client_hello", "Flight", "parse_flight", "exchange",
    "parse_ske", "ext", "is_ip", "PARTIAL_TIMEOUT", "EXT_STATUS_REQUEST", "EXT_SCT", "EXT_RENEG", "EXT_KEY_SHARE", "EXT_SUPPORTED_VERSIONS",
    "EXT_ALPN",
]
