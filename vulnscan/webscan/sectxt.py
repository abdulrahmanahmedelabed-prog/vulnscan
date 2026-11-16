"""security.txt (RFC 9116) parser and validator for WEB900 (spec §2.10), WP11.

Re-implemented from RFC 9116 itself (the ``sectxt`` package is EUPL and is not copied). Pure: no I/O, no network.

* :func:`parse` reads the body: byte order mark, UTF-8, the final newline, the OpenPGP cleartext-signature *structure*
  (``-----BEGIN PGP SIGNED MESSAGE-----`` … ``-----BEGIN PGP SIGNATURE-----`` … ``-----END PGP SIGNATURE-----``; the
  signature is never verified), dash-escaped lines, comments and ``Name: value`` fields (RFC 9116 §4 ABNF: the field name,
  a colon and exactly one space or tab).
* :func:`validate` adds the field and transport rules: at least one ``Contact`` (``mailto:``, ``tel:`` or an ``https://``
  web URI; ``http://`` → info), exactly one ``Expires`` in RFC 3339 that lies in the future (expired → low, more than a
  year ahead → info), at most one ``Preferred-Languages`` with valid language tags, ``Canonical`` listing the URL the file
  was fetched from, https-only web URIs in the other URI fields, unknown fields, ``Content-Type: text/plain;
  charset=utf-8``, HTTPS transport and the ``/.well-known/`` location.

Every problem has a code, a severity (low for: no Contact, no or invalid Expires, expired, served only over http;
info for everything else) and English and Arabic text. WEB900 lists all of them in one finding.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

# RFC 9116 §2.5 fields, plus CSAF (registered in the IANA "security.txt Fields" registry by OASIS CSAF 2.0)
KNOWN_FIELDS: dict[str, str] = {
    "acknowledgments": "Acknowledgments", "canonical": "Canonical", "contact": "Contact", "csaf": "CSAF",
    "encryption": "Encryption", "expires": "Expires", "hiring": "Hiring", "policy": "Policy",
    "preferred-languages": "Preferred-Languages",
}
URI_FIELDS = ("acknowledgments", "canonical", "csaf", "encryption", "hiring", "policy")
LOW_PROBLEMS = frozenset({"no_contact", "no_expires", "invalid_expires", "expired", "http_only"})
LONG_EXPIRY_DAYS = 366            # RFC 9116 §2.5.5: "less than a year into the future"
WELL_KNOWN_PATH = "/.well-known/security.txt"
LEGACY_PATH = "/security.txt"

PGP_BEGIN = "-----BEGIN PGP SIGNED MESSAGE-----"
PGP_SIG = "-----BEGIN PGP SIGNATURE-----"
PGP_END = "-----END PGP SIGNATURE-----"

_DAYS = ("{n} day", "{n} days", ("يوم واحد", "يومين", "{n} أيام", "{n} يومًا", "{n} يوم"))

# (en, ar); {placeholders} are filled from Problem.params (strings, or (en, ar) tuples for counts)
STR: dict[str, tuple[str, str]] = {
    "no_contact": ("No Contact field: RFC 9116 requires at least one (a mailto:, tel: or https: URI).",
                   "لا يوجد حقل Contact: يشترط RFC 9116 حقلًا واحدًا على الأقل (عنوان URI من نوع mailto: أو tel: أو https:)."),
    "no_expires": ("No Expires field: RFC 9116 requires exactly one.",
                   "لا يوجد حقل Expires: يشترط RFC 9116 حقلًا واحدًا بالضبط."),
    "invalid_expires": ("Expires value \"{value}\" is not an RFC 3339 date and time (for example 2027-05-13T00:00:00Z).",
                        "قيمة Expires ‏«{value}» ليست تاريخًا ووقتًا بصيغة RFC 3339 (مثل 2027-05-13T00:00:00Z)."),
    "expired": ("The file expired on {date} ({days} ago); researchers should treat it as out of date.",
                "انتهت صلاحية الملف في {date} (قبل {days})؛ لذا ينبغي للباحثين عدُّه قديمًا."),
    "multiple_expires": ("Expires appears more than once; RFC 9116 allows it only once.",
                         "يتكرر الحقل Expires أكثر من مرة؛ ولا يسمح RFC 9116 به إلا مرة واحدة."),
    "long_expiry": ("Expires is {days} ahead; RFC 9116 recommends less than a year so the file is reviewed regularly.",
                    "تاريخ Expires بعد {days}؛ ويوصي RFC 9116 بأقل من سنة كي يُراجَع الملف بانتظام."),
    "contact_invalid": ("Contact value \"{value}\" is not a mailto:, tel: or https: URI.",
                        "قيمة Contact ‏«{value}» ليست عنوان URI من نوع mailto: أو tel: أو https:."),
    "contact_http": ("Contact \"{value}\" uses http:; web URIs in security.txt must begin with https://.",
                     "يستخدم Contact ‏«{value}» البروتوكول http:؛ ويجب أن تبدأ عناوين الويب في security.txt بـ https://."),
    "uri_http": ("{field} \"{value}\" uses http:; web URIs in security.txt must begin with https://.",
                 "يستخدم الحقل {field} ‏«{value}» البروتوكول http:؛ ويجب أن تبدأ عناوين الويب في security.txt بـ https://."),
    "uri_invalid": ("{field} value \"{value}\" is not a URI.", "قيمة الحقل {field} ‏«{value}» ليست عنوان URI."),
    "multiple_languages": ("Preferred-Languages appears more than once; RFC 9116 allows it only once.",
                           "يتكرر الحقل Preferred-Languages أكثر من مرة؛ ولا يسمح RFC 9116 به إلا مرة واحدة."),
    "invalid_language": ("Preferred-Languages contains \"{value}\", which is not a language tag (RFC 5646, e.g. en, ar).",
                         "يحتوي الحقل Preferred-Languages على «{value}»، وهي ليست وسم لغة (RFC 5646، مثل en وar)."),
    "canonical_mismatch": ("Canonical does not list the URL the file was fetched from ({url}); clients should not trust "
                           "the file's contents.",
                           "لا يذكر الحقل Canonical العنوان الذي جُلب منه الملف ({url})؛ لذا لا ينبغي للعملاء الوثوق بمحتواه."),
    "unknown_field": ("Unknown field \"{field}\" (not in the IANA security.txt field registry).",
                      "حقل غير معروف «{field}» (ليس في سجل IANA لحقول security.txt)."),
    "empty_value": ("{field} on line {line} has no value.", "الحقل {field} في السطر {line} بلا قيمة."),
    "bad_line": ("Line {line} is not a field (\"Name: value\" with one space or tab after the colon), a comment or an "
                 "empty line: {value}",
                 "السطر {line} ليس حقلًا (بالصيغة «Name: value» مع مسافة واحدة أو علامة جدولة بعد النقطتين) ولا تعليقًا "
                 "ولا سطرًا فارغًا: {value}"),
    "bom": ("The file starts with a byte order mark (BOM).", "يبدأ الملف بعلامة ترتيب البايتات (BOM)."),
    "not_utf8": ("The file is not valid UTF-8.", "الملف ليس نصًّا صالحًا بترميز UTF-8."),
    "no_final_newline": ("The last line does not end with a line break.", "السطر الأخير لا ينتهي بفاصل أسطر."),
    "pgp_structure": ("The OpenPGP signed message is malformed ({detail}); the signature was not verified.",
                      "رسالة OpenPGP الموقَّعة غير سليمة البنية ({detail})؛ ولم يُتحقَّق من التوقيع."),
    "pgp_no_blank": ("no empty line after the armor headers", "لا يوجد سطر فارغ بعد ترويسات التغليف"),
    "pgp_no_signature": ("no -----BEGIN PGP SIGNATURE----- block", "لا توجد كتلة -----BEGIN PGP SIGNATURE-----"),
    "pgp_no_end": ("no -----END PGP SIGNATURE----- line", "لا يوجد السطر -----END PGP SIGNATURE-----"),
    "pgp_text_outside": ("text outside the signed message", "نص خارج الرسالة الموقَّعة"),
    "content_type": ("Content-Type is {value}; RFC 9116 requires text/plain.",
                     "نوع المحتوى {value}؛ ويشترط RFC 9116 النوع text/plain."),
    "content_type_missing": ("missing", "غير موجود"),
    "charset_missing": ("Content-Type has no charset; RFC 9116 requires text/plain; charset=utf-8.",
                        "لا يحدد Content-Type مجموعة المحارف؛ ويشترط RFC 9116 القيمة text/plain; charset=utf-8."),
    "charset_wrong": ("Content-Type charset is {value}; RFC 9116 requires utf-8.",
                      "مجموعة المحارف في Content-Type هي {value}؛ ويشترط RFC 9116 القيمة utf-8."),
    "http_only": ("The file is served over plain HTTP; RFC 9116 requires HTTPS so its contents cannot be altered in "
                  "transit.",
                  "يُقدَّم الملف عبر HTTP غير المشفّر؛ ويشترط RFC 9116 بروتوكول HTTPS كي لا يُعدَّل محتواه أثناء النقل."),
    "legacy_location": ("The file is only at /security.txt; RFC 9116 places it at /.well-known/security.txt (the "
                        "top-level path is for legacy compatibility only).",
                        "الملف موجود في /security.txt فقط؛ ويضعه RFC 9116 في /.well-known/security.txt (والمسار في "
                        "الجذر للتوافق مع الأنظمة القديمة فقط)."),
    "signed": ("The file carries an OpenPGP cleartext signature (its structure was checked; the signature was not "
               "verified).",
               "يحمل الملف توقيع OpenPGP نصيًا (فُحصت بنيته، ولم يُتحقَّق من التوقيع نفسه)."),
}

_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
_FIELD = re.compile(r"^([!-9;-~]+):[ \t](.*)$")            # field-name ":" WSP value (RFC 9116 §4; WSP = SP / HTAB)
_FIELD_LOOSE = re.compile(r"^\s*([!-9;-~]+)\s*:\s*(.*)$")    # what a lenient reader would still take as a field
_RFC3339 = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$")
_LANG = re.compile(r"^(?:[A-Za-z]{2,3}(?:-[A-Za-z]{3}){0,3}|[A-Za-z]{4,8}|[xXiI](?:-[A-Za-z0-9]{1,8})+)"
                   r"(?:-[A-Za-z0-9]{1,8})*$")
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):(\S+)$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_TEL = re.compile(r"^\+?[0-9][0-9().\- ]{2,30}$")


def _count(n: int, forms: tuple) -> tuple[str, str]:
    from ..i18n.plural import ar_count   # lazy: vulnscan.i18n imports webscan modules through cat_web2
    return (forms[0] if n == 1 else forms[1]).replace("{n}", str(n)), ar_count(n, forms[2])


def _clean(value: str, limit: int = 120) -> str:
    v = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", value).strip()
    return v if len(v) <= limit else v[: limit - 1] + "…"


@dataclass
class Problem:
    """One RFC 9116 problem. ``params`` values are strings or (en, ar) pairs."""
    code: str
    severity: str = "info"
    line: int = 0
    params: dict = field(default_factory=dict)

    def text(self, lang: str = "en") -> str:
        en, ar = STR[self.code]
        template = ar if lang == "ar" else en

        def sub(m: re.Match) -> str:
            v = self.params.get(m.group(1), m.group(0))
            if isinstance(v, tuple):
                v = v[1] if lang == "ar" else v[0]
            return str(v)
        return _PLACEHOLDER.sub(sub, template)

    def note(self) -> tuple[str, str]:
        return self.text("en"), self.text("ar")


@dataclass
class Field:
    name: str          # as written
    key: str           # lower-case
    value: str
    line: int          # 1-based line in the file


@dataclass
class SecurityTxt:
    """Parsed file plus its problems (``validate`` fills the field/transport problems)."""
    fields: list[Field] = field(default_factory=list)
    problems: list[Problem] = field(default_factory=list)
    signed: bool = False
    contacts: list[str] = field(default_factory=list)       # valid contact URIs (http: ones included)
    expires: datetime | None = None
    languages: list[str] = field(default_factory=list)
    canonical: list[str] = field(default_factory=list)

    def get_all(self, key: str) -> list[Field]:
        k = key.lower()
        return [f for f in self.fields if f.key == k]

    @property
    def severity(self) -> str | None:
        """``low`` when any problem is low, ``info`` when there are only info problems, ``None`` when valid."""
        if not self.problems:
            return None
        return "low" if any(p.severity == "low" for p in self.problems) else "info"

    def notes(self) -> list[tuple[str, str]]:
        return [p.note() for p in self.problems]

    def summary(self) -> dict:
        """Inventory/diff data: no secrets in a security.txt, so values are kept (capped)."""
        return {"signed": self.signed, "contacts": [_clean(c, 200) for c in self.contacts],
                "expires": self.expires.isoformat().replace("+00:00", "Z") if self.expires else None,
                "languages": list(self.languages), "canonical": [_clean(c, 300) for c in self.canonical],
                "fields": sorted({f.name for f in self.fields}),
                "problems": [p.code for p in self.problems]}

    def _add(self, code: str, at: int = 0, /, **params: Any) -> None:
        self.problems.append(Problem(code, "low" if code in LOW_PROBLEMS else "info", at, params))


# ----------------------------------------------------------------------------------------------- parsing

def _decode(body: bytes | str, st: SecurityTxt) -> str:
    if isinstance(body, str):
        text = body
        if text.startswith("﻿"):
            st._add("bom")
            text = text[1:]
        return text
    if body.startswith(b"\xef\xbb\xbf"):
        st._add("bom")
        body = body[3:]
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        st._add("not_utf8")
        return body.decode("utf-8", "replace")


def _signed_content(lines: list[str], st: SecurityTxt) -> list[tuple[int, str]]:
    """The cleartext lines (with their 1-based numbers) of a signed message; problems for a broken structure."""
    start = next(i for i, ln in enumerate(lines) if ln.strip())
    i = start + 1
    while i < len(lines) and lines[i].strip() and re.match(r"^[A-Za-z][A-Za-z0-9-]*: ", lines[i]):
        i += 1                                                # armor headers (Hash: SHA256, …)
    if i >= len(lines) or lines[i].strip():
        st._add("pgp_structure", detail=STR["pgp_no_blank"])
    else:
        i += 1
    content: list[tuple[int, str]] = []
    sig_at = None
    for j in range(i, len(lines)):
        if lines[j].rstrip() == PGP_SIG:
            sig_at = j
            break
        ln = lines[j]
        if ln.startswith("- "):
            ln = ln[2:]                                       # dash-escaped line (RFC 4880 §7.1)
        content.append((j + 1, ln))
    if sig_at is None:
        st._add("pgp_structure", detail=STR["pgp_no_signature"])
        return content
    end_at = next((k for k in range(sig_at + 1, len(lines)) if lines[k].rstrip() == PGP_END), None)
    if end_at is None:
        st._add("pgp_structure", detail=STR["pgp_no_end"])
    elif any(ln.strip() for ln in lines[end_at + 1:]) or any(ln.strip() for ln in lines[:start]):
        st._add("pgp_structure", detail=STR["pgp_text_outside"])
    return content


def parse(body: bytes | str) -> SecurityTxt:
    """Syntax of a security.txt body (encoding, line structure, signature structure, fields)."""
    st = SecurityTxt()
    text = _decode(body, st)
    if text and not text.endswith("\n"):
        st._add("no_final_newline")
    lines = [ln[:-1] if ln.endswith("\r") else ln for ln in text.split("\n")]
    if lines and lines[-1] == "":
        lines.pop()
    first = next((ln for ln in lines if ln.strip()), "")
    if first.rstrip() == PGP_BEGIN:
        st.signed = True
        numbered = _signed_content(lines, st)
    else:
        numbered = [(i + 1, ln) for i, ln in enumerate(lines)]
    bad = 0
    for no, raw in numbered:
        ln = raw.rstrip(" \t")                                # eol = *WSP [CR] LF
        if not ln or ln.startswith("#"):
            continue
        m = _FIELD.match(ln)
        if m is None:
            loose = _FIELD_LOOSE.match(ln)
            if bad < 5:
                st._add("bad_line", no, line=str(no), value=_clean(ln, 80))
            bad += 1
            if loose is None or loose.group(1).lower() not in KNOWN_FIELDS:
                continue
            name, value = loose.group(1), loose.group(2).strip()   # still read it, so one typo is not "no Contact"
        else:
            name, value = m.group(1), m.group(2).strip()
        st.fields.append(Field(name, name.lower(), value, no))
    return st


# ----------------------------------------------------------------------------------------------- field checks

def parse_rfc3339(value: str) -> datetime | None:
    """An RFC 3339 ``date-time`` (``Z`` or a numeric offset; ``T``/``Z`` in either case), as an aware UTC datetime."""
    m = _RFC3339.match(value.strip())
    if not m:
        return None
    y, mo, d, h, mi, s, frac, off = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), min(int(s), 59),
                      int((frac[1:] + "000000")[:6]) if frac else 0, tzinfo=timezone.utc)   # truncate, never round up
        if off not in ("Z", "z"):
            sign = 1 if off[0] == "+" else -1
            hh, mm = int(off[1:3]), int(off[4:6])
            if hh > 23 or mm > 59:
                return None
            try:
                dt -= sign * timedelta(hours=hh, minutes=mm)
            except OverflowError:                # 0001-01-01T00:00:00+01:00, 9999-12-31T23:59:59-01:00: valid, clamped
                dt = (datetime.min if sign > 0 else datetime.max).replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return dt


def uri_kind(value: str) -> str:
    """``mailto`` | ``tel`` | ``https`` | ``http`` | ``other`` (another URI scheme) | ``invalid``."""
    v = value.strip()
    m = _SCHEME.match(v)
    if not m:
        return "invalid"
    scheme, rest = m.group(1).lower(), m.group(2)
    if scheme == "mailto":
        addrs = urllib.parse.unquote(rest.split("?", 1)[0]).split(",")     # RFC 6068: one or more addresses
        return "mailto" if all(_EMAIL.match(a.strip()) for a in addrs) else "invalid"
    if scheme == "tel":
        return "tel" if _TEL.match(urllib.parse.unquote(rest).split(";", 1)[0]) else "invalid"
    if scheme in ("http", "https"):
        try:
            host = urllib.parse.urlsplit(v).hostname
        except ValueError:
            host = None
        if not host or not rest.startswith("//"):
            return "invalid"
        return scheme
    return "other"


def _same_url(a: str, b: str) -> bool:
    def norm(u: str) -> tuple:
        try:
            p = urllib.parse.urlsplit(u.strip())
            port = p.port
        except ValueError:
            return (u.strip(),)
        scheme = p.scheme.lower()
        if port is None or (scheme, port) in (("http", 80), ("https", 443)):
            port = None
        return scheme, (p.hostname or "").lower().rstrip("."), port, p.path or "/", p.query
    return norm(a) == norm(b)


def validate(body: bytes | str, *, url: str = "", requested_url: str | None = None, content_type: str | None = None,
             now: datetime | None = None, legacy: bool = False) -> SecurityTxt:
    """Parse ``body`` and check it against RFC 9116. ``url`` is the final URL it was served from (scheme decides the
    HTTPS rule; ``url``/``requested_url`` must appear in ``Canonical`` when present); ``legacy`` = only the top-level
    ``/security.txt`` exists. ``content_type`` ``None`` skips the media-type checks (unit tests of the body alone)."""
    now = now or datetime.now(timezone.utc)
    st = parse(body)
    by_key: dict[str, list[Field]] = {}
    for f in st.fields:
        by_key.setdefault(f.key, []).append(f)
    for f in st.fields:
        if f.key in KNOWN_FIELDS and not f.value:
            st._add("empty_value", f.line, field=KNOWN_FIELDS[f.key], line=str(f.line))
    # Contact (≥ 1)
    for f in by_key.get("contact", []):
        if not f.value:
            continue
        kind = uri_kind(f.value)
        if kind in ("mailto", "tel", "https"):
            st.contacts.append(f.value)
        elif kind == "http":
            st.contacts.append(f.value)
            st._add("contact_http", f.line, value=_clean(f.value))
        else:
            st._add("contact_invalid", f.line, value=_clean(f.value))
    if not st.contacts:
        st._add("no_contact")
    # Expires (exactly one, RFC 3339, future, < 1 year)
    expires = [f for f in by_key.get("expires", []) if f.value]
    if not expires:
        st._add("no_expires")
    else:
        if len(expires) > 1:
            st._add("multiple_expires", expires[1].line)
        dt = parse_rfc3339(expires[0].value)
        if dt is None:
            st._add("invalid_expires", expires[0].line, value=_clean(expires[0].value, 60))
        else:
            st.expires = dt
            if dt <= now:
                days = max(0, (now - dt).days)
                st._add("expired", expires[0].line, date=dt.date().isoformat(), days=_count(days, _DAYS))
            elif dt - now > timedelta(days=LONG_EXPIRY_DAYS):
                st._add("long_expiry", expires[0].line, days=_count((dt - now).days, _DAYS))
    # Preferred-Languages (≤ 1, language tags)
    langs = [f for f in by_key.get("preferred-languages", []) if f.value]
    if len(langs) > 1:
        st._add("multiple_languages", langs[1].line)
    for f in langs[:1]:
        for tag in (t.strip() for t in f.value.split(",")):
            if not tag:
                continue
            if _LANG.match(tag):
                st.languages.append(tag)
            else:
                st._add("invalid_language", f.line, value=_clean(tag, 40))
    # URI fields (web URIs must be https)
    for key in URI_FIELDS:
        for f in by_key.get(key, []):
            if not f.value:
                continue
            kind = uri_kind(f.value)
            if kind == "invalid":
                st._add("uri_invalid", f.line, field=KNOWN_FIELDS[key], value=_clean(f.value))
            elif kind == "http":
                st._add("uri_http", f.line, field=KNOWN_FIELDS[key], value=_clean(f.value))
            if key == "canonical" and kind != "invalid":
                st.canonical.append(f.value)
    if st.canonical and (url or requested_url):
        fetched = [u for u in (url, requested_url) if u]
        if not any(_same_url(c, u) for c in st.canonical for u in fetched):
            st._add("canonical_mismatch", url=_clean(fetched[-1], 200))
    # unknown fields (once per name)
    seen: set[str] = set()
    for f in st.fields:
        if f.key not in KNOWN_FIELDS and f.key not in seen:
            seen.add(f.key)
            st._add("unknown_field", f.line, field=_clean(f.name, 60))
    # transport and media type
    if content_type is not None:
        ctype = content_type.strip()
        ess = ctype.split(";", 1)[0].strip().lower()
        if not ctype:
            st._add("content_type", value=STR["content_type_missing"])
        elif ess != "text/plain":
            st._add("content_type", value=_clean(ess, 80))
        else:
            charset = None
            for part in ctype.split(";")[1:]:
                k, _, v = part.partition("=")
                if k.strip().lower() == "charset":
                    charset = v.strip().strip("\"'")
            if not charset:
                st._add("charset_missing")
            elif charset.lower().replace("_", "-") not in ("utf-8", "utf8"):
                st._add("charset_wrong", value=_clean(charset, 40))
    if url and urllib.parse.urlsplit(url).scheme.lower() == "http":
        st._add("http_only")
    if legacy:
        st._add("legacy_location")
    order = {"low": 0, "info": 1}
    st.problems.sort(key=lambda p: (order.get(p.severity, 2), p.line))
    return st


def looks_like_sectxt(text: str) -> bool:
    """True when ``text`` has at least one known security.txt field line or the OpenPGP signed-message header (a 200
    HTML page at the well-known path without either is a catch-all or a homepage, not a security.txt)."""
    for ln in text.splitlines()[:200]:
        s = ln.strip()
        if s == PGP_BEGIN:
            return True
        m = _FIELD_LOOSE.match(s)
        if m and m.group(1).lower() in KNOWN_FIELDS:
            return True
    return False


def i18n_catalog() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """``(CATALOG, PATTERNS)`` for cat_web2: Arabic → English for the fixed texts and ``rules.template_patterns`` for the
    templated ones (the ``days`` count expands to its five Arabic forms, as the registry's own templates do)."""
    from .rules import template_patterns
    catalog: dict[str, str] = {}
    patterns: list[tuple[str, str]] = []
    for en, ar in STR.values():
        if _PLACEHOLDER.search(ar):
            patterns.extend(template_patterns(ar, en))
        else:
            catalog[ar] = en
    return catalog, patterns


__all__ = ["KNOWN_FIELDS", "URI_FIELDS", "LOW_PROBLEMS", "WELL_KNOWN_PATH", "LEGACY_PATH", "STR", "Problem", "Field",
           "SecurityTxt", "parse", "validate", "parse_rfc3339", "uri_kind", "looks_like_sectxt", "i18n_catalog"]
