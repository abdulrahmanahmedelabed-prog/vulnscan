"""Minimal DER / X.509 reader for TLS assessment (spec §2.8, WP10). Stdlib only, no key material is ever derived.

Enough of X.690 DER to read what SSL Labs, testssl.sh and the Mozilla guidelines judge: signature algorithm, key type,
size, curve and RSA exponent, validity and lifetime, subject/issuer, SAN, basicConstraints, EKU, AIA (OCSP and CA
issuers), CRL distribution points, the embedded SCT list (CT), the TLS-feature must-staple flag, certificate policies
(EV/OV/DV), SKI/AKI. Plus the RFC 6962 SCT list, an RFC 6960 OCSPResponse reader for stapled responses, RFC 6125
host-name matching without the common-name fallback (browsers dropped it), and the weak-key tests of WEB707: the ROCA
fingerprint (CVE-2017-15361) and Fermat factorisation of close primes (CVE-2022-26320). Those report only
"vulnerable"; factors are never returned, stored or logged (§0.6).

Every byte comes from the scanned server: the parser checks every length and raises :class:`X509Error` (a
``ValueError``) on malformed input instead of crashing; :func:`try_parse` returns ``None``.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import math
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone


class X509Error(ValueError):
    """Malformed or unsupported DER."""


# ----------------------------------------------------------------------------------------------- DER walker

def _tlv(b: bytes, p: int, end: int | None = None) -> tuple[int, int, int]:
    """``(tag, content_start, content_end)`` of the TLV at ``p`` (definite lengths only, ≤ 4 length bytes)."""
    end = len(b) if end is None else end
    if p + 2 > end:
        raise X509Error("truncated DER")
    tag = b[p]
    if tag & 0x1F == 0x1F:
        raise X509Error("high tag numbers are not used in certificates")
    ln = b[p + 1]
    p += 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or p + n > end:
            raise X509Error("unsupported DER length")
        ln = int.from_bytes(b[p:p + n], "big")
        p += n
    if p + ln > end:
        raise X509Error("truncated DER")
    return tag, p, p + ln


def _children(b: bytes, start: int, end: int, limit: int = 4096) -> list[tuple[int, int, int]]:
    out, p = [], start
    while p < end:
        t = _tlv(b, p, end)
        out.append(t)
        p = t[2]
        if len(out) > limit:
            raise X509Error("too many DER elements")
    return out


def oid_str(raw: bytes) -> str:
    if not raw:
        raise X509Error("empty OID")
    first = raw[0]
    top = min(first // 40, 2)
    parts = [str(top), str(first - 40 * top)]
    v = 0
    for c in raw[1:]:
        v = (v << 7) | (c & 0x7F)
        if not c & 0x80:
            parts.append(str(v))
            v = 0
    return ".".join(parts)


SIG_OIDS = {
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption", "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption", "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption", "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption", "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1", "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256", "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512", "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448",
    "1.2.840.10040.4.3": "dsa-with-SHA1", "2.16.840.1.101.3.4.3.2": "dsa-with-SHA256",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44", "2.16.840.1.101.3.4.3.18": "ML-DSA-65", "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}
KEY_OIDS = {"1.2.840.113549.1.1.1": "RSA", "1.2.840.10045.2.1": "EC", "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448",
            "1.2.840.10040.4.1": "DSA", "1.2.840.113549.1.1.10": "RSA-PSS"}
CURVE_OIDS = {"1.2.840.10045.3.1.7": ("secp256r1", 256), "1.3.132.0.34": ("secp384r1", 384),
              "1.3.132.0.35": ("secp521r1", 521), "1.3.132.0.10": ("secp256k1", 256),
              "1.2.840.10045.3.1.1": ("secp192r1", 192), "1.3.132.0.33": ("secp224r1", 224)}
EXT_NAMES = {"2.5.29.17": "san", "2.5.29.19": "basic_constraints", "2.5.29.15": "key_usage", "2.5.29.37": "eku",
             "1.3.6.1.5.5.7.1.1": "aia", "2.5.29.31": "crl_dp", "1.3.6.1.4.1.11129.2.4.2": "sct_list",
             "1.3.6.1.5.5.7.1.24": "tls_feature", "2.5.29.32": "policies", "2.5.29.14": "ski", "2.5.29.35": "aki",
             "1.3.6.1.4.1.11129.2.4.3": "ct_poison"}
POLICY = {"2.23.140.1.1": "EV", "2.23.140.1.2.1": "DV", "2.23.140.1.2.2": "OV", "2.23.140.1.2.3": "IV"}
EKU_NAMES = {"1.3.6.1.5.5.7.3.1": "serverAuth", "1.3.6.1.5.5.7.3.2": "clientAuth", "1.3.6.1.5.5.7.3.3": "codeSigning",
             "1.3.6.1.5.5.7.3.4": "emailProtection", "1.3.6.1.5.5.7.3.9": "OCSPSigning", "2.5.29.37.0": "anyExtendedKeyUsage"}
ATTR_NAMES = {"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
              "2.5.4.5": "serialNumber", "1.2.840.113549.1.9.1": "emailAddress", "0.9.2342.19200300.100.1.25": "DC"}
OCSP_OID = "1.3.6.1.5.5.7.48.1"
CA_ISSUERS_OID = "1.3.6.1.5.5.7.48.2"
OCSP_SCT_OID = bytes.fromhex("2b06010401d679020405")      # 1.3.6.1.4.1.11129.2.4.5 (SCT list in an OCSP response)


# ----------------------------------------------------------------------------------------------- data classes

@dataclass(frozen=True)
class Sct:
    """One Signed Certificate Timestamp (RFC 6962 §3.2). ``source``: embedded | tls | ocsp."""
    version: int
    log_id: bytes
    timestamp: datetime
    source: str = "embedded"

    @property
    def log_id_b64(self) -> str:
        return base64.b64encode(self.log_id).decode("ascii")

    def to_dict(self) -> dict:
        return {"version": self.version, "log_id": self.log_id_b64, "timestamp": _iso(self.timestamp),
                "source": self.source}


@dataclass
class Certificate:
    der: bytes
    sha256: str
    serial_hex: str
    serial_bits: int
    sig_oid: str
    sig_alg: str
    issuer_raw: bytes
    subject_raw: bytes
    issuer: str
    subject: str
    issuer_cn: str | None
    subject_cn: str | None
    not_before: datetime
    not_after: datetime
    key_type: str
    key_bits: int | None = None
    rsa_exponent: int | None = None
    rsa_modulus: int | None = None
    curve: str | None = None
    san_dns: list[str] = field(default_factory=list)
    san_ip: list[str] = field(default_factory=list)
    has_san: bool = False
    is_ca: bool = False
    eku: list[str] = field(default_factory=list)
    ocsp_urls: list[str] = field(default_factory=list)
    ca_issuers: list[str] = field(default_factory=list)
    crl_urls: list[str] = field(default_factory=list)
    must_staple: bool = False
    policies: list[str] = field(default_factory=list)
    validation: str | None = None
    scts: list[Sct] = field(default_factory=list)
    ski: bytes | None = None
    aki: bytes | None = None
    ct_poison: bool = False
    version: int = 3

    @property
    def self_issued(self) -> bool:
        return self.issuer_raw == self.subject_raw

    @property
    def lifetime(self) -> float:
        """Validity period in days, counted as the CA/B Forum does (notAfter − notBefore + 1 second)."""
        return ((self.not_after - self.not_before).total_seconds() + 1) / 86400

    def remaining(self, now: datetime) -> float:
        """Days until notAfter (negative once expired)."""
        return (self.not_after - now).total_seconds() / 86400

    @property
    def sig_hash(self) -> str:
        s = self.sig_alg.lower()
        for h in ("md2", "md5", "sha1", "sha224", "sha256", "sha384", "sha512"):
            if s.startswith(h) or f"with-{h}" in s or f"with{h}" in s.replace("-", ""):
                return h
        return "other"

    @property
    def rsa_equiv_bits(self) -> int | None:
        """Key strength in RSA-equivalent bits (SSL Labs key-exchange score)."""
        if self.key_bits is None:
            return None
        if self.key_type in ("RSA", "RSA-PSS", "DSA"):
            return self.key_bits
        if self.key_type == "EC":
            return {192: 1536, 224: 2048, 256: 3072, 384: 7680, 521: 15360}.get(self.key_bits, self.key_bits * 12)
        if self.key_type in ("Ed25519",):
            return 3072
        if self.key_type in ("Ed448",):
            return 7680
        return self.key_bits

    def key_text(self) -> str:
        if self.key_type == "EC":
            return f"EC {self.curve or '?'}"
        if self.key_type in ("RSA", "RSA-PSS"):
            return f"{self.key_type} {self.key_bits} e={self.rsa_exponent}"
        return f"{self.key_type} {self.key_bits or ''}".strip()

    def summary(self) -> dict:
        """JSON-safe summary for evidence and the inventory (§3.6 ``tls``)."""
        return {"subject": self.subject, "issuer": self.issuer, "not_before": _iso(self.not_before),
                "not_after": _iso(self.not_after), "lifetime_days": round(self.lifetime, 2), "san": self.san_names()[:50],
                "san_count": len(self.san_dns) + len(self.san_ip), "key": self.key_text(), "sigalg": self.sig_alg,
                "sha256": self.sha256, "serial": self.serial_hex, "validation": self.validation,
                "must_staple": self.must_staple, "ocsp": self.ocsp_urls[:3], "scts": len(self.scts), "is_ca": self.is_ca,
                "self_issued": self.self_issued}

    def san_names(self) -> list[str]:
        return list(self.san_dns) + list(self.san_ip)


def _iso(d: datetime | None) -> str | None:
    if d is None:
        return None
    return d.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ----------------------------------------------------------------------------------------------- helpers

def _time(b: bytes, t: int, s: int, e: int) -> datetime:
    try:
        txt = b[s:e].decode("ascii")
    except UnicodeDecodeError:
        raise X509Error("non-ASCII time") from None
    if t == 0x17:                                    # UTCTime YYMMDDHHMMSSZ
        if len(txt) < 12:
            raise X509Error("short UTCTime")
        yy = int(txt[:2])
        txt = ("19" if yy >= 50 else "20") + txt
    elif t != 0x18:                                  # GeneralizedTime YYYYMMDDHHMMSS[.f]Z
        raise X509Error("not a time")
    digits = txt[:14]
    if len(digits) < 12 or not digits.isdigit():
        raise X509Error(f"bad time {txt!r}")
    if len(digits) == 12:
        digits += "00"
    try:
        return datetime.strptime(digits, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        raise X509Error(f"bad time {txt!r}") from None


def _string(b: bytes, t: int, s: int, e: int) -> str:
    raw = b[s:e]
    if t == 0x1E:                                    # BMPString
        return raw.decode("utf-16-be", "replace")
    if t == 0x1C:                                    # UniversalString
        return raw.decode("utf-32-be", "replace")
    if t in (0x0C,):
        return raw.decode("utf-8", "replace")
    return raw.decode("latin-1", "replace")


def _name(b: bytes, s: int, e: int) -> tuple[str, str | None]:
    """RFC 4514-style text (most significant RDN last, as OpenSSL's one-line form shows first) and the CN."""
    parts: list[str] = []
    cn = None
    for _, ss, se in _children(b, s, e):              # RDN SET
        for _, as_, ae in _children(b, ss, se):       # AttributeTypeAndValue SEQ
            kids = _children(b, as_, ae)
            if len(kids) < 2:
                continue
            (_, os_, oe), (vt, vs, ve) = kids[:2]
            o = oid_str(b[os_:oe])
            val = _string(b, vt, vs, ve)
            if o == "2.5.4.3" and cn is None:
                cn = val
            label = ATTR_NAMES.get(o, o)
            parts.append(f"{label}={val}")
    return ", ".join(parts), cn


def _uris(d: bytes, s: int, e: int, depth: int = 0) -> list[str]:
    """Every GeneralName uniformResourceIdentifier ([6] IA5String) inside a nested structure."""
    out: list[str] = []
    if depth > 6:
        return out
    for t, cs, ce in _children(d, s, e):
        if t == 0x86:
            out.append(d[cs:ce].decode("ascii", "replace"))
        elif t & 0x20:
            out.extend(_uris(d, cs, ce, depth + 1))
    return out


def _ext_inner(d: bytes) -> tuple[int, int]:
    _, s, e = _tlv(d, 0)
    return s, e


# ----------------------------------------------------------------------------------------------- certificate

def parse_certificate(der: bytes) -> Certificate:
    """Parse one DER certificate. Raises :class:`X509Error` on malformed input."""
    der = bytes(der)
    try:
        return _parse(der)
    except X509Error:
        raise
    except (IndexError, ValueError, struct.error, UnicodeError) as e:
        raise X509Error(f"malformed certificate: {e}") from None


def try_parse(der: bytes | None) -> Certificate | None:
    if not der:
        return None
    try:
        return parse_certificate(der)
    except X509Error:
        return None


def _parse(der: bytes) -> Certificate:
    t, cs, ce = _tlv(der, 0)
    if t != 0x30:
        raise X509Error("not a certificate")
    top = _children(der, cs, ce)
    if len(top) < 3:
        raise X509Error("certificate without signature")
    tbs, sigalg = top[0], top[1]
    fields = _children(der, tbs[1], tbs[2])
    i = 0
    version = 1
    if fields and fields[0][0] == 0xA0:
        _vt, vs, ve = _tlv(der, fields[0][1], fields[0][2])
        version = int.from_bytes(der[vs:ve], "big") + 1
        i = 1
    if len(fields) < i + 6:
        raise X509Error("short tbsCertificate")
    serial = fields[i]
    serial_bytes = der[serial[1]:serial[2]]
    sa = _children(der, sigalg[1], sigalg[2])
    so = oid_str(der[sa[0][1]:sa[0][2]])
    issuer, validity, subject, spki = fields[i + 2], fields[i + 3], fields[i + 4], fields[i + 5]
    issuer_txt, issuer_cn = _name(der, issuer[1], issuer[2])
    subject_txt, subject_cn = _name(der, subject[1], subject[2])
    vk = _children(der, validity[1], validity[2])
    if len(vk) != 2:
        raise X509Error("bad validity")
    cert = Certificate(
        der=der, sha256=hashlib.sha256(der).hexdigest(), serial_hex=serial_bytes.hex(),
        serial_bits=int.from_bytes(serial_bytes, "big").bit_length(), sig_oid=so, sig_alg=SIG_OIDS.get(so, so),
        issuer_raw=der[issuer[1]:issuer[2]], subject_raw=der[subject[1]:subject[2]],
        issuer=issuer_txt, subject=subject_txt, issuer_cn=issuer_cn, subject_cn=subject_cn,
        not_before=_time(der, *vk[0]), not_after=_time(der, *vk[1]), key_type="unknown", version=version)
    _parse_spki(der, spki, cert)
    for t2, s, e in fields[i + 6:]:
        if t2 != 0xA3:
            continue
        _, xs, xe = _tlv(der, s, e)
        for _, es_, ee_ in _children(der, xs, xe):
            parts = _children(der, es_, ee_)
            if len(parts) < 2:
                continue
            eo = oid_str(der[parts[0][1]:parts[0][2]])
            _, vs, ve = parts[-1]
            try:
                _decode_ext(EXT_NAMES.get(eo, eo), der[vs:ve], cert)
            except (X509Error, IndexError, ValueError, struct.error):
                continue                                  # one broken extension does not hide the others
    return cert


def _parse_spki(der: bytes, spki: tuple[int, int, int], cert: Certificate) -> None:
    kids = _children(der, spki[1], spki[2])
    if len(kids) != 2:
        raise X509Error("bad SubjectPublicKeyInfo")
    algseq, bitstr = kids
    alg = _children(der, algseq[1], algseq[2])
    ko = oid_str(der[alg[0][1]:alg[0][2]])
    cert.key_type = KEY_OIDS.get(ko, ko)
    key = der[bitstr[1] + 1:bitstr[2]]              # skip the unused-bits byte
    if cert.key_type in ("RSA", "RSA-PSS"):
        _, ks, ke = _tlv(key, 0)
        nums = _children(key, ks, ke)
        if len(nums) < 2:
            raise X509Error("bad RSA key")
        n = int.from_bytes(key[nums[0][1]:nums[0][2]], "big")
        cert.rsa_modulus = n
        cert.key_bits = n.bit_length()
        cert.rsa_exponent = int.from_bytes(key[nums[1][1]:nums[1][2]], "big")
    elif cert.key_type == "EC" and len(alg) > 1 and alg[1][0] == 0x06:
        co = oid_str(der[alg[1][1]:alg[1][2]])
        cert.curve, cert.key_bits = CURVE_OIDS.get(co, (co, None))
    elif cert.key_type in ("Ed25519", "Ed448"):
        cert.key_bits = 256 if cert.key_type == "Ed25519" else 456
    elif cert.key_type == "DSA":
        try:
            _, ps, pe = _tlv(der, alg[1][1])
            cert.key_bits = int.from_bytes(der[ps:pe], "big").bit_length()
        except (X509Error, IndexError):
            cert.key_bits = None


def _decode_ext(name: str, d: bytes, cert: Certificate) -> None:
    if name == "san":
        s, e = _ext_inner(d)
        cert.has_san = True
        for t, cs, ce in _children(d, s, e):
            if t == 0x82:
                cert.san_dns.append(d[cs:ce].decode("ascii", "replace"))
            elif t == 0x87:
                try:
                    cert.san_ip.append(str(ipaddress.ip_address(d[cs:ce])))
                except ValueError:
                    pass
    elif name == "basic_constraints":
        s, e = _ext_inner(d)
        kids = _children(d, s, e)
        cert.is_ca = bool(kids and kids[0][0] == 0x01 and d[kids[0][1]] != 0)
    elif name == "eku":
        s, e = _ext_inner(d)
        for t, cs, ce in _children(d, s, e):
            if t == 0x06:
                o = oid_str(d[cs:ce])
                cert.eku.append(EKU_NAMES.get(o, o))
    elif name == "aia":
        s, e = _ext_inner(d)
        for _, ads, ade in _children(d, s, e):
            kids = _children(d, ads, ade)
            if len(kids) < 2:
                continue
            method = oid_str(d[kids[0][1]:kids[0][2]])
            lt, ls, le = kids[1]
            if lt == 0x86:
                url = d[ls:le].decode("ascii", "replace")
                if method == OCSP_OID:
                    cert.ocsp_urls.append(url)
                elif method == CA_ISSUERS_OID:
                    cert.ca_issuers.append(url)
    elif name == "crl_dp":
        cert.crl_urls.extend(_uris(d, 0, len(d)))
    elif name == "tls_feature":                      # SEQUENCE OF INTEGER; 5 = status_request → OCSP Must-Staple
        s, e = _ext_inner(d)
        cert.must_staple = any(d[cs:ce] == b"\x05" for t, cs, ce in _children(d, s, e) if t == 0x02)
    elif name == "policies":
        s, e = _ext_inner(d)
        for _, ps, pe in _children(d, s, e):
            kids = _children(d, ps, pe)
            if kids and kids[0][0] == 0x06:
                cert.policies.append(oid_str(d[kids[0][1]:kids[0][2]]))
        cert.validation = next((POLICY[p] for p in cert.policies if p in POLICY), None)
    elif name == "sct_list":
        _, s, e = _tlv(d, 0)                          # inner OCTET STRING with the TLS-encoded list
        cert.scts = parse_sct_list(d[s:e], source="embedded")
    elif name == "ski":
        _, s, e = _tlv(d, 0)
        cert.ski = d[s:e]
    elif name == "aki":
        s, e = _ext_inner(d)
        for t, cs, ce in _children(d, s, e):
            if t == 0x80:
                cert.aki = d[cs:ce]
    elif name == "ct_poison":
        cert.ct_poison = True


def parse_sct_list(tls: bytes, *, source: str = "embedded") -> list[Sct]:
    """RFC 6962 §3.3 SignedCertificateTimestampList (the same TLS encoding in the X.509 extension, the TLS
    ``signed_certificate_timestamp`` extension and the OCSP extension). Malformed entries are skipped."""
    out: list[Sct] = []
    if len(tls) < 2:
        return out
    total = struct.unpack(">H", tls[:2])[0]
    p, end = 2, min(2 + total, len(tls))
    while p + 2 <= end and len(out) < 64:
        ln = struct.unpack(">H", tls[p:p + 2])[0]
        s = tls[p + 2:p + 2 + ln]
        p += 2 + ln
        if len(s) < 43 or s[0] != 0:
            continue
        ts = struct.unpack(">Q", s[33:41])[0]
        try:
            when = datetime.fromtimestamp(ts / 1000, timezone.utc)
        except (OverflowError, OSError, ValueError):
            continue
        out.append(Sct(version=s[0], log_id=bytes(s[1:33]), timestamp=when, source=source))
    return out


# ----------------------------------------------------------------------------------------------- PEM

_PEM = re.compile(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.S)


def pem_to_der_list(text: str) -> list[bytes]:
    return [base64.b64decode("".join(m.split())) for m in _PEM.findall(text)]


def der_to_pem(der: bytes) -> str:
    b = base64.b64encode(der).decode("ascii")
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + \
        "\n-----END CERTIFICATE-----\n"


# ----------------------------------------------------------------------------------------------- OCSP

@dataclass
class OcspResponse:
    status: int                           # 0 successful, 1 malformedRequest, 2 internalError, 3 tryLater, 5, 6
    cert_status: str | None = None        # good | revoked | unknown
    produced_at: datetime | None = None
    this_update: datetime | None = None
    next_update: datetime | None = None
    has_scts: bool = False

    def to_dict(self) -> dict:
        return {"status": self.status, "cert_status": self.cert_status, "produced_at": _iso(self.produced_at),
                "this_update": _iso(self.this_update), "next_update": _iso(self.next_update), "has_scts": self.has_scts}


def parse_ocsp_response(resp: bytes) -> OcspResponse:
    """RFC 6960 OCSPResponse (first SingleResponse). Raises :class:`X509Error` on malformed input."""
    try:
        return _parse_ocsp(bytes(resp))
    except X509Error:
        raise
    except (IndexError, ValueError, struct.error) as e:
        raise X509Error(f"malformed OCSP response: {e}") from None


def _parse_ocsp(resp: bytes) -> OcspResponse:
    _, s, e = _tlv(resp, 0)
    kids = _children(resp, s, e)
    if not kids or kids[0][0] != 0x0A:
        raise X509Error("no responseStatus")
    out = OcspResponse(status=resp[kids[0][1]])
    if out.status != 0 or len(kids) < 2:
        return out
    _, rbs, rbe = _tlv(resp, kids[1][1], kids[1][2])           # [0] EXPLICIT → ResponseBytes SEQUENCE
    rb = _children(resp, rbs, rbe)
    if len(rb) < 2:
        raise X509Error("bad ResponseBytes")
    basic = resp[rb[1][1]:rb[1][2]]
    _, bs, be = _tlv(basic, 0)
    tbs = _children(basic, bs, be)[0]
    f = _children(basic, tbs[1], tbs[2])
    i = 1 if f and f[0][0] == 0xA0 else 0                       # optional version
    out.produced_at = _time(basic, *f[i + 1])
    responses = _children(basic, f[i + 2][1], f[i + 2][2])
    if not responses:
        return out
    single = responses[0]
    sk = _children(basic, single[1], single[2])
    out.cert_status = {0x80: "good", 0xA1: "revoked", 0x82: "unknown"}.get(sk[1][0], f"0x{sk[1][0]:02x}")
    out.this_update = _time(basic, *sk[2])
    for t, cs, ce in sk[3:]:
        if t == 0xA0:
            out.next_update = _time(basic, *_tlv(basic, cs, ce))
    for t, cs, ce in f[i + 3:]:
        if t == 0xA1 and OCSP_SCT_OID in basic[cs:ce]:
            out.has_scts = True
    return out


# ----------------------------------------------------------------------------------------------- host names

def _alabel(name: str) -> str:
    name = name.strip().rstrip(".").lower()
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return name


def host_matches(cert: Certificate, host: str) -> bool:
    """RFC 6125 matching as browsers do it: SAN only (no common-name fallback), one left-most ``*`` label matching
    exactly one label, no partial wildcards, IP literals only against SAN IP entries."""
    host = host.strip("[]").rstrip(".").lower()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        return any(ipaddress.ip_address(a) == ip for a in cert.san_ip)
    h = _alabel(host)
    hl = h.split(".")
    for name in cert.san_dns:
        n = _alabel(name)
        if not n:
            continue
        if n == h:
            return True
        nl = n.split(".")
        if nl[0] == "*" and len(nl) >= 3 and len(nl) == len(hl) and nl[1:] == hl[1:] and hl[0]:
            return True
    return False


# ----------------------------------------------------------------------------------------------- weak keys (WEB707)

_ROCA_PRIMES = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
                103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167)
# bit i of _ROCA_PRINTS[k] is set iff i is in the subgroup generated by 65537 modulo _ROCA_PRIMES[k]: the same table
# as the ROCA authors' detector (crocs-muni/roca, MIT; computed here instead of copied, and compared with theirs in
# tests/web/test_tls_x509.py). A set, not a sum: the powers repeat inside the subgroup.
_ROCA_PRINTS = tuple(sum(1 << x for x in {pow(65537, k, p) for k in range(p)}) for p in _ROCA_PRIMES)


def roca_vulnerable(n: int | None) -> bool:
    """True when the RSA modulus has the ROCA fingerprint (Infineon RSALib, CVE-2017-15361)."""
    if not n or n < 3:
        return False
    return all((_ROCA_PRINTS[i] >> (n % p)) & 1 for i, p in enumerate(_ROCA_PRIMES))


def fermat_factorable(n: int | None, rounds: int = 100) -> bool:
    """True when ``n`` factors by Fermat's method within ``rounds`` steps (primes too close: CVE-2022-26320).
    Only the yes/no answer leaves this function; the factors are discarded."""
    if not n or n < 9 or n % 2 == 0:
        return False
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(rounds):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return 1 < a - b < n
        a += 1
    return False


__all__ = ["X509Error", "Certificate", "Sct", "OcspResponse", "parse_certificate", "try_parse", "parse_sct_list",
           "parse_ocsp_response", "pem_to_der_list", "der_to_pem", "host_matches", "roca_vulnerable",
           "fermat_factorable", "oid_str", "SIG_OIDS", "KEY_OIDS", "CURVE_OIDS", "POLICY"]
