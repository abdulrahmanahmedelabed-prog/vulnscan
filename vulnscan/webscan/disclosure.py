"""Information disclosure (spec §2.7), WP8: WEB010, WEB011, WEB055, WEB056 and WEB600–WEB619.

Header rules (gate G2) judge every fetched response of the scanned site, redirect hops and error pages included
(WAF/rate-limit pages and third-party hosts excluded): Server and X-Powered-By banners, backend and debug headers from
``data/web/leak-headers.json``, internal addresses, Apache inode ETags, serialized objects in header and cookie values
and the Heartbleed-era OpenSSL banner.

Body rules read the responses already in the context (this module never fetches). Shared guards (§2.7):

* binary bodies (control bytes in the first 1 KB, or a binary magic number) and bodies in a content coding Kashif did
  not request (``opaque-coding``, §0.6) are never read; for an opaque document the body checks are ``not_tested``;
* body rules run on documents, API JSON/XML, text and error pages; JS and CSS only at ``paranoid`` — except WEB609
  (secrets), which targets scripts, and WEB602 (source maps);
* a match inside ``<pre>``, ``<code>``, ``<textarea>`` or ``<samp>`` of a 2xx document is ``tentative`` (or dropped when the
  rule only allows ``firm``) unless the page carries a debug-page marker (documentation quotes stack traces: D16);
* one cause, one finding: the same match on several responses of a host (a catch-all error page answering every
  probe) is reported once; when the host's soft-404 baseline shows it too, the finding says it is site-wide.

Secrets (WEB609) reuse Kashif's SEC rules (``history.secret_rules()``) restricted to the prefix-anchored subset named in
``data/web/secret-rules.json`` plus its web-only patterns, with an entropy floor for the variable part, placeholder and
publishable-key exclusions, and redaction (first 4 + last 2 characters) everywhere: no secret value ever leaves this
module, not even in ``group_value`` (a truncated SHA-256 is used to group identical secrets).

Pure: reads ``ctx`` and writes coverage states only.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import html as _html
import ipaddress
import json
import math
import re
import struct
import urllib.parse
import zlib
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any, Iterable, Iterator

from . import htmlparse, psl
from .rules import RULES, checks_for_module
from .types import (
    CookieFact,
    Evidence,
    Issue,
    ParsedHTML,
    Response,
    ScanContext,
    cap,
    normalise_host,
    python_codec,
    redact_secret,
    strip_controls,
)

CHECKS: tuple[str, ...] = checks_for_module("disclosure")

# ----------------------------------------------------------------------------------------------- user-facing text

# (en, ar) note templates. ``{name}`` is filled literally (no str.format: values come from the scanned site, §0.6).
STR: dict[str, tuple[str, str]] = {
    "server_bare": ("The Server header names the product without a version: {value}.",
                    "ترويسة Server تذكر اسم المنتج بلا رقم إصدار: {value}."),
    "powered_bare": ("X-Powered-By names the technology without a version: {value}.",
                     "ترويسة X-Powered-By تذكر التقنية بلا رقم إصدار: {value}."),
    "leak_header": ("{header}: {value} ({what}).", "{header}: {value} ({what})."),
    "timing": ("{header} exposes the server's processing time, a timing side channel.",
               "تكشف {header} زمن المعالجة في الخادم، وهذه قناة جانبية زمنية."),
    "server_timing": ("The Server-Timing entry {value} reveals backend internals.",
                      "مدخل Server-Timing بالقيمة {value} يكشف تفاصيل داخلية للخلفية."),
    "debug_headers": ("Debug headers present: {value}.", "ترويسات تصحيح موجودة: {value}."),
    "decoded": ("Decoded debug output: {value}", "مخرجات التصحيح بعد فك الترميز: {value}"),
    "map_fetched": ("The source map {url} was downloaded and lists {sources}.",
                    "نُزّلت خريطة المصدر {url} وهي تسرد {sources}."),
    "map_inline": ("The script embeds its source map inline (data: URL), so the original sources ship with it.",
                   "يضمّن السكربت خريطة المصدر داخله (رابط data:)، فتُشحن الشيفرة الأصلية معه."),
    "map_referenced": ("The file names a source map ({url}); it was not downloaded in this profile, so whether it is "
                       "public is not confirmed (use --deep).",
                       "يشير الملف إلى خريطة مصدر ({url})؛ لم تُنزَّل في هذا الملف الشخصي للفحص، فلم يُتأكَّد من أنها "
                       "عامة (استخدم ‎--deep)."),
    "ip_header": ("{header} contains the internal address {value}.", "تحتوي {header} على العنوان الداخلي {value}."),
    "ip_body": ("The response body contains the internal address {value}.",
                "يحتوي جسم الاستجابة على العنوان الداخلي {value}."),
    "etag": ("The ETag {value} has Apache's inode-size-mtime form.", "قيمة ETag ‏{value} بصيغة Apache ‏(inode-الحجم-الوقت)."),
    "error_sig": ("{platform}: {value}", "{platform}: {value}"),
    "console": ("The page offers an interactive debugger console: anyone who reaches it can run code on the server.",
                "تتيح الصفحة وحدة تحكم تفاعلية للتصحيح: يستطيع كل من يصل إليها تنفيذ شيفرة على الخادم."),
    "guarded": ("Found inside <pre>/<code> on a normal page; it may be documentation.",
                "وُجد داخل <pre> أو <code> في صفحة عادية؛ قد يكون جزءًا من توثيق."),
    "site_wide": ("The host's not-found page shows the same text, so every missing path returns it; reported once for the "
                  "host.",
                  "صفحة «غير موجود» لدى المضيف تعرض النص نفسه، فيظهر في كل مسار غير موجود؛ لذا أُبلغ عنه مرة واحدة للمضيف."),
    "listing": ("{platform} directory listing.", "فهرس مجلد من {platform}."),
    "default_page": ("{platform} default page.", "الصفحة الافتراضية لـ {platform}."),
    "parked": ("Parking page ({platform}).", "صفحة نطاق مركون ({platform})."),
    "source_code": ("{value} source code is served instead of being executed.",
                    "تُقدَّم شيفرة {value} كما هي بدل تنفيذها."),
    "secret": ("{kind}: {value}", "{kind}: {value}"),
    "secret_where": ("Found in {where}.", "وُجد في {where}."),
    "serialized": ("{where} starts with a {value} serialized object.", "{where} يبدأ بكائن مُسلسَل بصيغة {value}."),
    "viewstate_nomac": ("The ASP.NET ViewState ends without a MAC (trailing-bytes heuristic; unreliable on .NET 4.5.2 and "
                        "later, where the MAC cannot be disabled).",
                        "ينتهي ViewState في ASP.NET بلا MAC (استنتاج من البايتات الأخيرة؛ غير موثوق في ‎.NET 4.5.2 وما "
                        "بعده حيث لا يمكن تعطيل MAC)."),
    "viewstate_old": ("X-AspNet-Version {value} predates .NET 4.5, where the ViewState MAC could still be switched off.",
                      "الإصدار X-AspNet-Version ‏{value} أقدم من ‎.NET 4.5، حين كان يمكن تعطيل MAC لـ ViewState."),
    "jsf": ("javax.faces.ViewState decodes to unencrypted Java objects ({value}).",
            "يُفك ترميز javax.faces.ViewState إلى كائنات Java غير مشفّرة ({value})."),
    "hash": ("{kind} hash: {value}", "تجزئة {kind}: {value}"),
    "card": ("{kind} card number: {value}", "رقم بطاقة {kind}: {value}"),
    "test_card": ("This is a well-known test card number.", "هذا رقم بطاقة اختبار معروف."),
    "comment": ("Comment: {value}", "التعليق: {value}"),
    "heartbleed": ("{value} is in the Heartbleed range (1.0.1 to 1.0.1f); the banner alone does not prove the server is "
                   "vulnerable.",
                   "الإصدار {value} ضمن نطاق Heartbleed ‏(1.0.1 حتى 1.0.1f)؛ والترويسة وحدها لا تثبت أن الخادم معرّض."),
    "exif": ("The image's EXIF metadata carries GPS latitude and longitude.",
             "تحمل بيانات EXIF في الصورة خط العرض وخط الطول (GPS)."),
    "truncated": ("The body was larger than the size cap; only its first part was checked.",
                  "كان جسم الاستجابة أكبر من الحد المسموح؛ فلم يُفحص إلا جزؤه الأول."),
}
_SOURCES = ("{n} original source file", "{n} original source files",
            ("ملف مصدر أصلي واحد", "ملفَي مصدر أصليين", "{n} ملفات مصدر أصلية", "{n} ملفًا مصدريًا أصليًا",
             "{n} ملف مصدر أصلي"))
_WHERE: dict[str, tuple[str, str]] = {
    "inline": ("an inline script", "سكربت مضمَّن في الصفحة"),
    "attribute": ("an HTML attribute", "سمة HTML"),
    "script": ("a script file", "ملف سكربت"),
    "json": ("a JSON response", "استجابة JSON"),
    "sourcemap": ("the sources embedded in a source map", "الشيفرة المضمَّنة في خريطة مصدر"),
    "header": ("the response header", "ترويسة الاستجابة"),
    "cookie": ("the cookie value", "قيمة الكوكي"),
    "hidden": ("the hidden form field", "حقل النموذج المخفي"),
    "body": ("the response body", "جسم الاستجابة"),
}
_PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")


def _note(key: str, **values) -> tuple[str, str]:
    """``(en, ar)`` of ``STR[key]`` with ``{name}`` filled literally; ``(en, ar)`` tuple values pick their language."""
    en, ar = STR[key]

    def fill(text: str, lang: str) -> str:
        def sub(m: re.Match) -> str:
            v = values.get(m.group(1), m.group(0))
            if isinstance(v, tuple):
                v = v[1] if lang == "ar" else v[0]
            return strip_controls(str(v))
        return _PLACEHOLDER.sub(sub, text)
    return fill(en, "en"), fill(ar, "ar")


def _count(n: int, forms: tuple) -> tuple[str, str]:
    from ..i18n.plural import ar_count   # lazy: vulnscan.i18n imports webscan modules through cat_web2
    en = (forms[0] if n == 1 else forms[1]).replace("{n}", str(n))
    return en, ar_count(n, forms[2])


def _short(value: str, limit: int = 120) -> str:
    v = " ".join(strip_controls(value).split())
    return v if len(v) <= limit else v[: limit - 1] + "…"


# ----------------------------------------------------------------------------------------------- response helpers

SKIP_KINDS = frozenset({"waf_challenge", "rate_limited", "error"})
TEXT_KINDS = frozenset({"document", "api_json", "api_xml", "text", "error_page", "soft404", "other"})
CODE_KINDS = frozenset({"script", "style"})
_DECODED = frozenset({"", "identity", "gzip", "x-gzip", "deflate"})
_HTML = frozenset({"text/html", "application/xhtml+xml"})
SCAN_CAP = 1_000_000            # characters of a body the regex rules read
SCRIPT_CAP = 3_000_000          # characters of a script WEB609 reads (the fetcher caps JS at 3 MB)
_BINARY_MAGIC = (b"\x89PNG", b"GIF8", b"\xff\xd8\xff", b"%PDF", b"PK\x03\x04", b"\x1f\x8b", b"\x7fELF", b"MZ",
                 b"\x00asm", b"wOFF", b"wOF2", b"\x00\x01\x00\x00", b"OTTO", b"7z\xbc\xaf", b"Rar!", b"BZh",
                 b"\xca\xfe\xba\xbe", b"SQLite format 3", b"RIFF", b"\x00\x00\x01\x00", b"ID3", b"OggS", b"fLaC",
                 b"\x1aE\xdf\xa3")


def _kind(r: Response) -> str:
    """The classified kind, or a rough one for responses classify.py has not seen (unit tests)."""
    if r.kind:
        return r.kind
    if r.status is None or r.error:
        return "error"
    if r.is_redirect:
        return "redirect"
    if r.status >= 400:
        return "error_page"
    if r.status < 200:
        return "informational"
    if r.status in (204, 205):
        return "no_content"
    if r.status == 304:
        return "not_modified"
    ess = r.essence
    if ess in _HTML:
        return "document"
    if ess.endswith("json"):
        return "api_json"
    if ess in ("application/xml", "text/xml") or ess.endswith("+xml"):
        return "api_xml"
    if "javascript" in ess or "ecmascript" in ess:
        return "script"
    if ess == "text/css":
        return "style"
    if ess == "text/plain":
        return "text"
    if ess.startswith(("image/", "font/", "audio/", "video/")):
        return "image" if ess.startswith("image/") else "media"
    head = r.body[:256].lstrip().lower()
    if head.startswith((b"<!doctype html", b"<html")):
        return "document"
    return "other"


def _opaque(r: Response) -> bool:
    if "opaque-coding" in r.flags:
        return True
    enc = (r.encoding or "").strip().lower()
    return bool(enc) and any(t.strip() not in _DECODED for t in enc.split(","))


def is_binary(body: bytes) -> bool:
    """§2.7 binary skip: a binary magic number, or control bytes (other than whitespace and ESC) in the first 1 KB."""
    if not body:
        return False
    if body.startswith((b"\xff\xfe", b"\xfe\xff")):
        return False                                      # UTF-16 text with a BOM
    if body.startswith(_BINARY_MAGIC):
        return True
    head = body[:1024]
    if b"\x00" in head:
        return True
    ctrl = sum(1 for b in head if b < 32 and b not in (9, 10, 11, 12, 13, 27))
    return ctrl > 4


def _is_2xx(r: Response) -> bool:
    return r.status is not None and 200 <= r.status < 300


def _is_error_status(r: Response) -> bool:
    return r.status is not None and r.status >= 400


def _byte_offset(r: Response, text: str, pos: int) -> int:
    try:
        return len(text[:pos].encode(python_codec(r.detected_charset()), "replace"))
    except (LookupError, ValueError):
        return pos


def _excerpt(text: str, start: int, end: int, *, replace: str | None = None, around: int = 70) -> str:
    """Context around ``text[start:end]`` (the match replaced by ``replace`` when given), one line, controls removed."""
    mid = text[start:end] if replace is None else replace
    out = text[max(0, start - around):start] + mid + text[end:end + around]
    return cap(" ".join(strip_controls(out).split()), 200)


_NUMS = re.compile(r"\b[0-9a-f]{8,}\b|\d+", re.I)


def _norm(text: str) -> str:
    """Normalised match text for dedupe: numbers and hex runs removed, whitespace collapsed, lower case."""
    return " ".join(_NUMS.sub("0", text).lower().split())[:200]


def _b64decode(value: str, limit: int = 1 << 20) -> bytes | None:
    s = re.sub(r"\s+", "", value)[: limit * 4 // 3 + 4]
    if not s or not re.fullmatch(r"[A-Za-z0-9+/_=-]+", s):
        return None
    s = s.rstrip("=")
    s += "=" * (-len(s) % 4)
    try:
        if "-" in s or "_" in s:
            return base64.urlsafe_b64decode(s)
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def _gunzip(data: bytes, limit: int = 1 << 20) -> bytes | None:
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = d.decompress(data, limit)
        return out
    except zlib.error:
        return None


def entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


# ----------------------------------------------------------------------------------------------- body signatures

@dataclass(frozen=True)
class _Cond:
    type: str
    pattern: Any                 # compiled regex, str (contains/prefix, lower-cased when ``icase``) or bytes (magic)
    icase: bool = False
    min_count: int = 1
    within: int = 0


@dataclass(frozen=True)
class Signature:
    id: str
    rule: str
    platform: str
    all: tuple[_Cond, ...] = ()
    any: tuple[_Cond, ...] = ()
    none: tuple[_Cond, ...] = ()
    not_html: bool = False
    status: str = "any"
    severity: str | None = None
    confidence: str | None = None
    debug_marker: bool = False

    def status_ok(self, r: Response) -> bool:
        if self.status == "error":
            return _is_error_status(r)
        if self.status == "2xx":
            return _is_2xx(r)
        return True


_FLAGS = {"i": re.I, "m": re.M, "s": re.S, "x": re.X}


def _compile_cond(c: dict) -> _Cond:
    t = c["type"]
    flags = c.get("flags", "")
    icase = "i" in flags
    if t == "regex":
        f = 0
        for ch in flags:
            f |= _FLAGS[ch]
        pat: Any = re.compile(c["pattern"], f)
    elif t == "magic":
        pat = bytes.fromhex(c["pattern"])
    else:
        pat = c["pattern"].lower() if icase else c["pattern"]
    return _Cond(t, pat, icase, int(c.get("min_count", 1)), int(c.get("within", 0)))


def compile_signature(entry: dict) -> Signature:
    s = entry["signature"]
    return Signature(
        id=entry["id"], rule=entry["rule"], platform=entry["platform"],
        all=tuple(_compile_cond(c) for c in s.get("all", ())), any=tuple(_compile_cond(c) for c in s.get("any", ())),
        none=tuple(_compile_cond(c) for c in s.get("none", ())), not_html=bool(s.get("not_html")),
        status=entry.get("status", "any"), severity=entry.get("severity"), confidence=entry.get("confidence"),
        debug_marker=bool(entry.get("debug_marker")))


def _find(c: _Cond, text: str, lower: str | None, body: bytes) -> tuple[int, int] | None:
    if c.type == "magic":
        return (0, len(c.pattern)) if body.startswith(c.pattern) else None
    hay = text[: c.within] if c.within else text
    if c.type == "regex":
        if c.min_count <= 1:
            m = c.pattern.search(hay)
            return m.span() if m else None
        first = None
        n = 0
        for m in c.pattern.finditer(hay):
            first = first or m.span()
            n += 1
            if n >= c.min_count:
                return first
        return None
    src = (lower if lower is not None else text.lower()) if c.icase else text
    if c.within:
        src = src[: c.within]
    if c.type == "prefix":
        stripped = src.lstrip()
        off = len(src) - len(stripped)
        return (off, off + len(c.pattern)) if stripped.startswith(c.pattern) else None
    if c.min_count <= 1:
        i = src.find(c.pattern)
        return (i, i + len(c.pattern)) if i >= 0 else None
    i, n, first = 0, 0, None
    while n < c.min_count:
        j = src.find(c.pattern, i)
        if j < 0:
            return None
        first = first or (j, j + len(c.pattern))
        n += 1
        i = j + 1
    return first


def match_signature(sig: Signature, text: str, *, body: bytes = b"", is_html: bool = False,
                    lower: str | None = None) -> tuple[int, int] | None:
    """Span of the first decisive condition when ``sig`` matches ``text`` (decoded body), else ``None``."""
    if sig.not_html and is_html:
        return None
    if lower is None and any(c.icase for c in (*sig.all, *sig.any, *sig.none)):
        lower = text.lower()
    span = None
    for c in sig.all:
        s = _find(c, text, lower, body)
        if s is None:
            return None
        span = span or s
    if sig.any:
        hits = [s for s in (_find(c, text, lower, body) for c in sig.any) if s is not None]
        if not hits:
            return None
        span = span or min(hits)
    for c in sig.none:
        if _find(c, text, lower, body) is not None:
            return None
    return span


# ----------------------------------------------------------------------------------------------- data

_COMPILED: dict[tuple[int, str], Any] = {}


def _data(ctx: ScanContext):
    d = ctx.data
    if d is not None and hasattr(d, "load_json"):
        return d
    from . import data as data_mod
    return data_mod


def _load(ctx: ScanContext, name: str) -> Any | None:
    try:
        return _data(ctx).load_json(name)
    except (OSError, ValueError, KeyError):
        return None


def signatures(ctx: ScanContext) -> list[Signature] | None:
    obj = _load(ctx, "error-signatures.json")
    if not isinstance(obj, dict):
        return None
    key = (id(obj), "sigs")
    if key not in _COMPILED:
        _COMPILED[key] = [compile_signature(e) for e in obj.get("signatures", [])]
    return _COMPILED[key]


@dataclass(frozen=True)
class LeakHeader:
    name: str
    match: str
    rule: str
    version: re.Pattern | None
    decode: str
    severity: str
    note: str

    def matches(self, header: str) -> bool:
        h = header.lower()
        n = self.name.lower()
        if "*" in n:
            return fnmatchcase(h, n)
        return h.startswith(n) if self.match == "prefix" else h == n


def leak_headers(ctx: ScanContext) -> list[LeakHeader] | None:
    obj = _load(ctx, "leak-headers.json")
    if not isinstance(obj, dict):
        return None
    key = (id(obj), "leak")
    if key not in _COMPILED:
        out = []
        for e in obj.get("headers", []):
            vp = e.get("version_pattern")
            out.append(LeakHeader(e["name"], e["match"], e["rule"], re.compile(vp) if vp else None, e.get("decode", ""),
                                  e.get("severity", ""), e.get("note", "")))
        _COMPILED[key] = out
    return _COMPILED[key]


# ----------------------------------------------------------------------------------------------- run state

@dataclass
class _Body:
    """A response whose body the text rules read (decoded once, capped)."""
    r: Response
    kind: str
    text: str
    is_html: bool
    code: bool                                   # script/style (paranoid only for the general rules)
    doc: ParsedHTML | None = None
    _lower: str | None = None
    _spans: list[tuple[int, int]] | None = None
    _debug: bool | None = None

    @property
    def lower(self) -> str:
        if self._lower is None:
            self._lower = self.text.lower()
        return self._lower

    @property
    def guard_applies(self) -> bool:
        return self.is_html and _is_2xx(self.r) and self.kind in ("document", "soft404")

    def in_guard(self, pos: int) -> bool:
        if not self.guard_applies:
            return False
        if self._spans is None:
            self._spans = guarded_spans(self.text)
        return any(a <= pos < b for a, b in self._spans)


_GUARD_OPEN = re.compile(r"<(pre|code|textarea|samp|xmp|listing)\b[^>]*>", re.I)


def guarded_spans(text: str) -> list[tuple[int, int]]:
    """Character ranges inside ``<pre>``, ``<code>``, ``<textarea>``, ``<samp>`` (and the obsolete ``<xmp>``/``<listing>``)."""
    spans: list[tuple[int, int]] = []
    pos = 0
    low = None
    while True:
        m = _GUARD_OPEN.search(text, pos)
        if not m:
            break
        if low is None:
            low = text.lower()
        close = low.find("</" + m.group(1).lower(), m.end())
        end = len(text) if close < 0 else close
        spans.append((m.end(), end))
        pos = max(end, m.end())
    return spans


class _Run:
    """One pass over a context: issues, dedupe and per-check coverage bookkeeping."""

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.paranoid = ctx.options.sensitivity == "paranoid"
        self.issues: list[Issue] = []
        self.evaluated: dict[str, set[str]] = {}
        self.failed: dict[str, set[str]] = {}
        self.not_tested: dict[str, dict[str, str]] = {}     # check → host → reason
        self.dedupe: set[tuple] = set()
        self.own_sites = {psl.site(h) for h in (ctx.target_host, ctx.entry.host if ctx.entry else "") if h}
        self.blocked_hosts: dict[str, str] = {}
        if ctx.entry is not None and _kind(ctx.entry) in ("waf_challenge", "rate_limited"):
            reason = "waf" if _kind(ctx.entry) == "waf_challenge" else "rate_limited"
            for h in ctx.entry.hops():
                self.blocked_hosts[h.host] = reason
        self._bodies: list[_Body] | None = None
        self._docs: dict[int, ParsedHTML | None] = {}
        self._baselines: dict[str, list[str]] | None = None
        self.secret_rules: SecretSet | None = None

    # -- bookkeeping ----------------------------------------------------------------------------------------
    def seen(self, check: str, host: str) -> None:
        self.evaluated.setdefault(check, set()).add(host)

    def skip(self, check: str, host: str, reason: str) -> None:
        self.not_tested.setdefault(check, {}).setdefault(host, reason)

    def emit(self, rule: str, r: Response, evidence: Evidence, *, severity: str | None = None,
             confidence: str | None = None, group_value: str = "", notes: Iterable[tuple[str, str]] = (),
             params: dict | None = None, key: tuple | None = None, url: str | None = None,
             host: str | None = None) -> bool:
        meta = RULES[rule]
        conf = confidence or meta.confidence
        if conf not in meta.allowed_confidences:
            return False
        h = host or r.host
        k = (rule, h, key if key is not None else group_value)
        if k in self.dedupe:
            return False
        self.dedupe.add(k)
        sev = severity if severity in meta.allowed_severities else None
        self.issues.append(Issue(rule=rule, url=url or r.url, confidence=conf, evidence=evidence, params=dict(params or {}),
                                 severity=sev, group_value=cap(group_value, 300), notes=list(notes), host=h))
        self.seen(meta.check_id, h)
        if self.ctx.options.reports(conf):
            self.failed.setdefault(meta.check_id, set()).add(h)
        return True

    def ev(self, r: Response, **kw) -> Evidence:
        return Evidence.for_response(r, now=self.ctx.now, **kw)

    # -- response sets ----------------------------------------------------------------------------------------
    def own(self, r: Response) -> bool:
        return bool(r.host) and psl.site(r.host) in self.own_sites

    def header_responses(self) -> list[Response]:
        """G2: every fetched response of the site (hops included), except WAF/rate-limit pages and network errors."""
        return [r for r in self.ctx.all_responses() if self.own(r) and _kind(r) not in SKIP_KINDS
                and r.status is not None and r.host not in self.blocked_hosts]

    def doc_for(self, r: Response) -> ParsedHTML | None:
        if id(r) not in self._docs:
            page = self.ctx.page_for(r)
            doc = page.doc if page is not None else None
            if doc is None and r.body and not _opaque(r) and (r.essence in _HTML or _kind(r) == "document"):
                try:
                    doc = htmlparse.parse_response(r)
                except Exception:                      # a hostile page must never stop the module
                    doc = None
            self._docs[id(r)] = doc
        return self._docs[id(r)]

    def bodies(self) -> list[_Body]:
        """Final responses whose body the text rules read: own site; documents, API, text and error pages (scripts
        and styles at paranoid); deep-probe and baseline responses only when they are error pages (2xx probe
        bodies are exposure.py's)."""
        if self._bodies is not None:
            return self._bodies
        out: list[_Body] = []
        seen: set[int] = set()
        docs_first = [p.response for p in self.ctx.pages]
        for r in [*( [self.ctx.entry] if self.ctx.entry is not None else []), *docs_first,
                  *self.ctx.all_responses(include_hops=False)]:
            if r is None or id(r) in seen:
                continue
            seen.add(id(r))
            if not self.own(r) or r.status is None or r.host in self.blocked_hosts:
                continue
            k = _kind(r)
            if k in SKIP_KINDS or k in ("redirect", "informational", "no_content", "not_modified"):
                continue
            if r.source in ("probe", "baseline") and not _is_error_status(r):
                continue
            if r.source in ("sourcemap", "image"):
                continue
            code = k in CODE_KINDS
            if not (k in TEXT_KINDS or code):
                continue
            if _opaque(r):
                if r.source in ("entry", "crawl") or k == "document":
                    for check in _BODY_CHECKS:
                        self.skip(check, r.host, "unsupported_coding")
                continue
            if not r.body or is_binary(r.body):
                continue
            is_html = r.essence in _HTML or (not r.essence and k in ("document", "soft404", "error_page")
                                              and r.body[:512].lstrip().lower().startswith((b"<!doctype", b"<html")))
            text = r.text()[:SCAN_CAP]
            out.append(_Body(r, k, text, is_html, code, self.doc_for(r) if is_html else None))
        self._bodies = out
        return out

    def baseline_texts(self, host: str) -> list[str]:
        """Bodies of the host's soft-404 baselines (deep random paths and natural catch-all well-known files)."""
        if self._baselines is None:
            self._baselines = {}
            cands = list(self.ctx.baselines) + [r for r in self.ctx.wellknown.values()
                                                if _kind(r) == "soft404" or {"soft404", "catch-all"} & set(r.flags)]
            for r in cands:
                if r.body and not _opaque(r) and not is_binary(r.body):
                    self._baselines.setdefault(r.host, []).append(r.text()[:SCAN_CAP])
        return self._baselines.get(host, [])

    # -- coverage ---------------------------------------------------------------------------------------------
    def record_coverage(self) -> None:
        cov = self.ctx.coverage
        if cov is None:
            return
        for check in CHECKS:
            hosts = self.evaluated.get(check, set())
            failed = self.failed.get(check, set())
            skipped = self.not_tested.get(check, {})
            for host in sorted(hosts):
                if host in failed:
                    cov.failed(check, host)
                else:
                    cov.passed(check, host)
            for host, reason in sorted(skipped.items()):
                cov.not_tested(check, reason, host=host)
            for host, reason in self.blocked_hosts.items():
                if host not in hosts:
                    cov.inconclusive(check, reason, host=host)
            if not hosts and not skipped and not self.blocked_hosts:
                if RULES[check].paranoid_only and not self.paranoid:
                    cov.not_tested(check, "sensitivity")
                elif check == "WEB619" and not (self.ctx.options.deep or self.ctx.options.crawl):
                    cov.not_tested(check, "deep_off")
                else:
                    cov.not_applicable(check, "no_document" if check in _BODY_CHECKS else "")


_BODY_CHECKS = ("WEB055", "WEB056", "WEB603", "WEB605", "WEB606", "WEB607", "WEB608", "WEB609", "WEB610", "WEB611",
                "WEB612", "WEB613", "WEB614", "WEB616", "WEB617")


def run(ctx: ScanContext) -> list[Issue]:
    """All §2.7 checks over the context (pure apart from coverage states)."""
    st = _Run(ctx)
    _banners(st)
    _leak_headers(st)
    _etag(st)
    _internal_ips(st)
    _serialized(st)
    _error_signatures(st)
    _listing(st)
    _source_code(st)
    _viewstate(st)
    _hashes(st)
    _cards(st)
    _comments(st)
    _secrets(st)
    _sourcemaps(st)
    _images(st)
    st.record_coverage()
    return st.issues


# =============================================================================================== headers

PRODUCTS = ("Apache", "nginx", "Microsoft-IIS", "LiteSpeed", "openresty", "Jetty", "Tomcat", "Kestrel", "gunicorn",
            "Werkzeug", "Python", "PHP", "OpenSSL", "Caddy", "Envoy", "lighttpd", "Cowboy")
_PRODUCT_RX = "|".join(re.escape(p) for p in PRODUCTS)
VERSION_TOKEN = re.compile(r"(?<![\w.-])[A-Za-z][\w.-]*/v?\d+(?:\.\d+)+")
PRODUCT_VERSION = re.compile(r"\b(?:" + _PRODUCT_RX + r")\b[\s/(:-]{0,3}v?\d+\.\d+(?:\.\d+)?\b", re.I)
BARE_PRODUCT = re.compile(r"\b(?:" + _PRODUCT_RX + r")\b", re.I)
_POWERED_VERSION = re.compile(r"\d+(?:\.\d+)+|/v?\d")
HEARTBLEED = re.compile(r"\bOpenSSL/(1\.0\.(?:1[a-f]?|1-beta\d?|2-beta\d?))(?![\w.])", re.I)
BACKPORT = re.compile(r"-fips\b|red ?hat|\brhel\b|\bel\d\b|centos|ubuntu|debian|\bdeb\d|rocky|almalinux|amazon|amzn|"
                      r"suse|\bsles\b|fedora|oracle linux|raspbian", re.I)


def server_version(value: str) -> str | None:
    """The version-shaped token of a Server value (``Apache/2.4.49``), or ``None`` (``ECS (dcb/7F84)``: D18)."""
    m = VERSION_TOKEN.search(value) or PRODUCT_VERSION.search(value)
    return m.group(0) if m else None


def _banners(st: _Run) -> None:
    for r in st.header_responses():
        host = r.host
        for check in ("WEB010", "WEB011", "WEB615"):
            st.seen(check, host)
        for value in r.headers.get_all("server"):
            value = strip_controls(value)
            v = _short(value, 200)
            if not v:
                continue
            ver = server_version(value)
            if ver:
                st.emit("WEB010", r, st.ev(r, name="Server", value=v), severity="low", params={"value": v},
                        group_value=v.lower())
            elif st.paranoid and BARE_PRODUCT.search(value):
                st.emit("WEB010", r, st.ev(r, name="Server", value=v), severity="info", params={"value": v},
                        group_value=v.lower(), notes=[_note("server_bare", value=v)])
            hb = HEARTBLEED.search(value)
            if hb and not BACKPORT.search(value):
                st.emit("WEB615", r, st.ev(r, name="Server", value=v), group_value=hb.group(1).lower(),
                        notes=[_note("heartbleed", value="OpenSSL/" + hb.group(1))])
        for value in r.headers.get_all("x-powered-by"):
            value = strip_controls(value)
            v = _short(value, 200)
            if not v:
                continue
            versioned = bool(_POWERED_VERSION.search(value))
            st.emit("WEB011", r, st.ev(r, name="X-Powered-By", value=v), severity="low" if versioned else "info",
                    params={"value": v}, group_value=v.lower(),
                    notes=[] if versioned else [_note("powered_bare", value=v)])


_ST_INTERNAL = re.compile(r"\b(?:db|sql|mysql|mariadb|pg|postgres(?:ql)?|psql|query|queries|redis|memcache[d]?|mongo(?:db)?|"
                          r"elastic(?:search)?|cassandra|dynamo(?:db)?|oracle|mssql|sqlite|orm|table|select)\b", re.I)
_ST_HOSTLIKE = re.compile(r"\b[\w-]+\.(?:internal|local|lan|corp|intranet|cluster\.local|svc)\b|\b(?:\d{1,3}\.){3}\d{1,3}\b",
                          re.I)


def server_timing_leaks(value: str) -> list[str]:
    """Server-Timing entries whose name or ``desc`` reveals backend internals (``db``, ``sql``, a host name …);
    plain ``cdn-cache``/``edge``/``total`` timings are not reported."""
    out = []
    for entry in value.split(","):
        entry = entry.strip()
        if not entry:
            continue
        name, _, params = entry.partition(";")
        desc = ""
        for p in params.split(";"):
            k, _, v = p.strip().partition("=")
            if k.strip().lower() == "desc":
                desc = v.strip().strip('"')
        words = re.sub(r"[_\-.]", " ", f"{name} {desc}")
        if _ST_INTERNAL.search(words) or _ST_HOSTLIKE.search(f"{name} {desc}"):
            out.append(_short(entry, 80))
    return out


def _leak_headers(st: _Run) -> None:
    table = leak_headers(st.ctx)
    if table is None:
        for check in ("WEB600", "WEB601"):
            st.skip(check, st.ctx.target_host, "data_missing")
        return
    for r in st.header_responses():
        host = r.host
        st.seen("WEB600", host)
        st.seen("WEB601", host)
        debug: list[tuple[str, str, LeakHeader]] = []
        for name, value in r.headers:
            low = name.lower()
            if low == "server-timing":
                for entry in server_timing_leaks(value):
                    st.emit("WEB600", r, st.ev(r, name=name, value=_short(value, 300)), severity="info",
                            params={"header": "Server-Timing"}, group_value="server-timing",
                            notes=[_note("server_timing", value=entry)])
                continue
            spec = next((h for h in table if h.matches(name)), None)
            if spec is None:
                continue
            v = _short(value, 200)
            if spec.rule == "WEB601":
                debug.append((name, value, spec))
                continue
            if spec.severity:
                sev = spec.severity
            elif spec.version is not None:
                sev = "low" if spec.version.search(value) else "info"
            else:
                sev = "low"
            notes = []
            if low in ("x-runtime", "x-request-duration", "x-envoy-upstream-service-time"):
                notes.append(_note("timing", header=name))
            elif spec.note:
                notes.append(_note("leak_header", header=name, value=v, what=spec.note))
            st.emit("WEB600", r, st.ev(r, name=name, value=v), severity=sev, params={"header": name},
                    group_value=low, notes=notes)
        if debug:
            names = sorted({n for n, _v, _s in debug}, key=str.lower)
            first_name, first_value, _ = debug[0]
            notes = [_note("debug_headers", value=", ".join(names))]
            for n, v, spec in debug:
                if spec.decode == "base64":
                    raw = _b64decode(v, 65536)
                    if raw:
                        notes.append(_note("decoded", value=_short(raw.decode("utf-8", "replace"), 160)))
                        break
            st.emit("WEB601", r, st.ev(r, name=first_name, value=_short(first_value, 300),
                                         excerpt="; ".join(f"{n}: {_short(v, 60)}" for n, v, _ in debug)),
                    params={"header": ", ".join(names)}, group_value=",".join(n.lower() for n in names), notes=notes)


ETAG_INODE = re.compile(r'^\s*(?:W/)?"([0-9a-f]+)-([0-9a-f]+)-([0-9a-f]+)(?:-gzip|-br|-deflate|;gzip)?"\s*$', re.I)


def _etag(st: _Run) -> None:
    for r in st.header_responses():
        st.seen("WEB604", r.host)
        for value in r.headers.get_all("etag"):
            if ETAG_INODE.match(value):
                v = _short(value, 100)
                st.emit("WEB604", r, st.ev(r, name="ETag", value=v), group_value="apache-inode",
                        notes=[_note("etag", value=v)])
                break


# ----------------------------------------------------------------------------------------------- WEB603 internal IPs

_IPV4 = re.compile(r"(?<![\w.])(?<!\d\.)((?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?(?!\.\d)(?!-\d)(?![\w])")
_IPV6 = re.compile(r"(?<![\w:.])((?:f[cd][0-9a-f]{2}|fe[89ab][0-9a-f]):[0-9a-f:]*[0-9a-f])(?![\w:])", re.I)
_EC2 = re.compile(r"\bip-(10|172-(?:1[6-9]|2\d|3[01])|192-168)((?:-\d{1,3}){2,3})\b")
_VERSIONISH = re.compile(r"(?:version|ver\.?|\bv\.?|release|build|rev\.?|firmware)\s*[:#]?\s*$", re.I)
_PRIVATE_V4 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                       "169.254.0.0/16"))
_PRIVATE_V6 = tuple(ipaddress.ip_network(n) for n in ("fc00::/7", "fe80::/10"))
_CLIENT_ECHO = re.compile(r"^x-(?:forwarded(?:-for)?|real-ip|client-ip|originating-ip|remote-(?:addr|ip)|your-ip|"
                          r"cluster-client-ip|request-ip|true-client-ip)$", re.I)
_IP_HEADERS = frozenset({"location", "content-location", "via", "refresh", "link"})


def internal_ips(text: str, *, exclude: Iterable[str] = (), limit: int = 10) -> list[tuple[str, int, int]]:
    """Internal addresses in ``text`` as ``(address, start, end)``: RFC 1918, 100.64/10, 169.254/16, fc00::/7, fe80::/10
    and EC2 ``ip-10-…`` names, with ZAP's boundary guards (not after ``\\d.``, not before ``.\\d``/``-\\d``) and no
    version-like context (``v10.0.0.1``)."""
    skip = {normalise_host(x) for x in exclude if x}
    out: list[tuple[str, int, int]] = []
    seen: set[str] = set()

    def add(addr: str, s: int, e: int) -> None:
        if addr in skip or addr in seen:
            return
        seen.add(addr)
        out.append((addr, s, e))

    for m in _IPV4.finditer(text):
        addr = m.group(1)
        if _VERSIONISH.search(text[max(0, m.start() - 12):m.start()]):
            continue
        try:
            ip = ipaddress.IPv4Address(addr)
        except ValueError:
            continue
        if any(ip in n for n in _PRIVATE_V4):
            add(addr, m.start(1), m.end(1))
        if len(out) >= limit:
            return out
    for m in _IPV6.finditer(text):
        try:
            ip6 = ipaddress.IPv6Address(m.group(1))
        except ValueError:
            continue
        if any(ip6 in n for n in _PRIVATE_V6):
            add(str(ip6), m.start(1), m.end(1))
        if len(out) >= limit:
            return out
    for m in _EC2.finditer(text):
        parts = [int(p) for p in m.group(2).strip("-").split("-")]
        if all(p <= 255 for p in parts):
            add(m.group(0), m.start(), m.end())
        if len(out) >= limit:
            break
    return out


def _ip_exclusions(st: _Run, r: Response) -> list[str]:
    ex = [st.ctx.target_host, r.ip or "", r.host]
    if st.ctx.entry is not None:
        ex += [st.ctx.entry.ip or "", st.ctx.entry.host]
    return ex


def _target_private(st: _Run) -> bool:
    ip = st.ctx.entry.ip if st.ctx.entry is not None else None
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    nets = _PRIVATE_V4 if addr.version == 4 else _PRIVATE_V6
    return any(addr in n for n in nets)


def _internal_ips(st: _Run) -> None:
    private_target = _target_private(st)
    for r in st.header_responses():
        st.seen("WEB603", r.host)
        for name, value in r.headers:
            low = name.lower()
            if not (low in _IP_HEADERS or (low.startswith("x-") and not _CLIENT_ECHO.match(low))):
                continue
            ips = internal_ips(value, exclude=_ip_exclusions(st, r))
            if not ips:
                continue
            shown = ", ".join(a for a, _s, _e in ips)
            st.emit("WEB603", r, st.ev(r, name=name, value=_short(value, 300)),
                    confidence="tentative" if private_target else "firm", group_value=f"header:{low}:{shown}",
                    notes=[_note("ip_header", header=name, value=shown)])
    for b in st.bodies():
        if b.code and not st.paranoid:
            continue
        st.seen("WEB603", b.r.host)
        ips = internal_ips(b.text, exclude=_ip_exclusions(st, b.r))
        if not ips:
            continue
        shown = ", ".join(a for a, _s, _e in ips)
        _a, s, e = ips[0]
        tentative = private_target or b.code or (b.kind in ("document", "soft404") and _is_2xx(b.r))
        st.emit("WEB603", b.r, st.ev(b.r, where="body", name="body", value=shown, offset=_byte_offset(b.r, b.text, s),
                                     excerpt=_excerpt(b.text, s, e)),
                confidence="tentative" if tentative else "firm", group_value=f"body:{shown}",
                notes=[_note("ip_body", value=shown)])


# ----------------------------------------------------------------------------------------------- WEB610 serialized

_PHP_SER = re.compile(r'^(?:[OC]:\d+:"[\w\\]{1,200}":\d+:\{|a:\d+:\{|s:\d+:".*";)', re.S)


def serialized_format(value: str | bytes) -> str | None:
    """The native serialization format a value starts with (after percent-decoding), or ``None``: Java
    (``AC ED 00 05`` / ``rO0AB``), .NET BinaryFormatter (``AAEAAAD/////``), PHP (``O:8:"…"``, ``a:2:{``, ``s:5:"…";`` and
    the base64 forms ``Tzo``/``YTo``) and Python pickle (``\\x80\\x04\\x95`` / ``gASV``). Base64 forms are decoded and
    verified, so a random token that happens to start with ``YTo`` is not reported."""
    if isinstance(value, bytes):
        raw = value.lstrip()
        if raw.startswith(b"\xac\xed\x00\x05"):
            return "Java"
        if raw.startswith((b"\x80\x04\x95", b"\x80\x05\x95")):
            return "Python pickle"
        if raw.startswith(b"\x00\x01\x00\x00\x00\xff\xff\xff\xff"):
            return ".NET BinaryFormatter"
        try:
            value = raw[:4096].decode("utf-8")
        except UnicodeDecodeError:
            return None
    s = value.strip()
    if "%" in s[:64]:
        s = urllib.parse.unquote(s)
    s = s.strip().strip('"')
    if not s:
        return None
    if _PHP_SER.match(s[:4096]):
        return "PHP"
    head = s[:8]
    if head.startswith(("rO0AB", "AAEAAAD", "Tzo", "YTo", "gASV", "gAWV")):
        token = re.match(r"[A-Za-z0-9+/_=-]+", s)
        raw = _b64decode(token.group(0)[:8192]) if token else None
        if not raw:
            return None
        if raw.startswith(b"\xac\xed\x00\x05"):
            return "Java"
        if raw.startswith(b"\x00\x01\x00\x00\x00\xff\xff\xff\xff"):
            return ".NET BinaryFormatter"
        if raw.startswith((b"\x80\x04\x95", b"\x80\x05\x95")):
            return "Python pickle"
        try:
            dec = raw[:4096].decode("utf-8")
        except UnicodeDecodeError:
            return None
        if _PHP_SER.match(dec):
            return "PHP"
    return None


_SER_SKIP_HEADERS = frozenset({"set-cookie", "etag", "authorization", "www-authenticate", "date", "content-type",
                               "content-length", "content-security-policy", "last-modified", "expires", "server",
                               "x-powered-by", "x-chromelogger-data", "x-chromephp-data"})


def _cookie_facts(st: _Run) -> list[CookieFact]:
    if st.ctx.cookies:
        return [c for c in st.ctx.cookies if st.own(c.response)]
    out = []
    for r in st.header_responses():
        for i, raw in enumerate(r.headers.get_all("set-cookie")):
            first, _, _rest = raw.partition(";")
            name, eq, value = first.partition("=")
            if eq:
                out.append(CookieFact(name=name.strip(), value=value.strip(), attrs={}, raw=raw, response=r, host=r.host,
                                      secure_context=r.is_https, index=i))
    return out


def _serialized(st: _Run) -> None:
    for r in st.header_responses():
        st.seen("WEB610", r.host)
        for name, value in r.headers:
            if name.lower() in _SER_SKIP_HEADERS:
                continue
            fmt = serialized_format(value)
            if fmt:
                st.emit("WEB610", r, st.ev(r, name=name, value=_short(value[:24], 40) + "…"),
                        group_value=f"header:{name.lower()}:{fmt}",
                        notes=[_note("serialized", where=(f"The header {name}", f"الترويسة {name}"), value=fmt)])
    for c in _cookie_facts(st):
        if c.deletion or c.ignored:
            continue
        fmt = serialized_format(c.value)
        if fmt:
            r = c.response
            st.emit("WEB610", r, st.ev(r, where="cookie", name=c.name, value=c.redacted()),
                    group_value=f"cookie:{c.name}:{fmt}",
                    notes=[_note("serialized", where=(f"The cookie {c.name}", f"الكوكي {c.name}"), value=fmt)])
    for b in st.bodies():
        if b.code:
            continue
        st.seen("WEB610", b.r.host)
        fmt = serialized_format(b.r.body[:8192]) if not b.is_html else None
        if fmt:
            st.emit("WEB610", b.r, st.ev(b.r, where="body", name="body", value=fmt, offset=0,
                                         excerpt=_short(b.text[:40], 40)),
                    group_value=f"body:{fmt}", notes=[_note("serialized", where=("The response body", "جسم الاستجابة"),
                                                            value=fmt)])
        if b.doc is None:
            continue
        for e in b.doc.find_all("input"):
            if (e.get("type") or "").strip().lower() != "hidden":
                continue
            name = e.get("name") or e.get("id") or ""
            if name.upper().startswith(("__VIEWSTATE", "__EVENTVALIDATION")) or "faces.viewstate" in name.lower():
                continue
            fmt = serialized_format(e.get("value") or "")
            if fmt:
                v = e.get("value") or ""
                st.emit("WEB610", b.r, st.ev(b.r, where="body", name=f"input[name={name}]",
                                             value=_short(v[:24], 40) + "…", offset=e.offset),
                        group_value=f"hidden:{name}:{fmt}",
                        notes=[_note("serialized", where=(f"The hidden field {name}", f"الحقل المخفي {name}"), value=fmt)])


# =============================================================================================== bodies

def _site_wide(st: _Run, host: str, matched: str) -> bool:
    if len(matched.strip()) < 8:
        return False
    return any(matched in t for t in st.baseline_texts(host))


def _sig_conf(sig: Signature, b: _Body, pos: int, debug_page: bool) -> tuple[str | None, bool]:
    """(confidence, guarded) for a signature hit at ``pos`` per the shared guard; ``None`` drops the hit."""
    meta = RULES[sig.rule]
    guarded = b.in_guard(pos) and not debug_page
    if sig.rule == "WEB056":
        if guarded:
            return "tentative", True
        if b.code:
            return "tentative", False
        return "firm", False
    conf = sig.confidence or meta.confidence
    if guarded or b.code:
        conf = "tentative"
    return (conf if conf in meta.allowed_confidences else None), guarded


def _error_signatures(st: _Run) -> None:
    sigs = signatures(st.ctx)
    rules = ("WEB056", "WEB605", "WEB606", "WEB607", "WEB616", "WEB617")
    if sigs is None:
        for check in rules:
            st.skip(check, st.ctx.target_host, "data_missing")
        return
    by_rule: dict[str, list[Signature]] = {r: [s for s in sigs if s.rule == r] for r in rules}
    for b in st.bodies():
        r = b.r
        host = r.host
        if b.code and not st.paranoid:
            continue
        for check in rules:
            st.seen(check, host)
        lower = b.lower
        debug_hit: tuple[Signature, tuple[int, int]] | None = None
        if not b.code:
            for s in by_rule["WEB605"]:
                if not s.status_ok(r):
                    continue
                span = match_signature(s, b.text, body=r.body, is_html=b.is_html, lower=lower)
                if span is not None and not b.in_guard(span[0]):
                    debug_hit = (s, span)
                    break
        if debug_hit is not None:
            s, (a, z) = debug_hit
            notes = [_note("error_sig", platform=s.platform, value=_short(b.text[a:z], 100))]
            if s.severity == "critical":
                notes.append(_note("console"))
            _emit_sig(st, b, s, (a, z), "certain", s.severity or "high", notes)
        for rule in ("WEB056", "WEB606", "WEB607", "WEB616", "WEB617"):
            if rule == "WEB056" and debug_hit is not None:
                continue                          # one cause: the debug page already reports the trace
            if rule == "WEB617" and (b.kind != "document" or not _is_2xx(r) or b.code):
                continue
            if rule in ("WEB607", "WEB616") and not _is_error_status(r):
                continue
            for s in by_rule[rule]:
                if not s.status_ok(r):
                    continue
                span = match_signature(s, b.text, body=r.body, is_html=b.is_html, lower=lower)
                if span is None:
                    continue
                conf, guarded = _sig_conf(s, b, span[0], debug_hit is not None)
                if conf is None:
                    continue
                notes = []
                if rule == "WEB617":
                    notes.append(_note("parked" if s.severity == "info" else "default_page", platform=s.platform))
                else:
                    notes.append(_note("error_sig", platform=s.platform, value=_short(b.text[span[0]:span[1]], 100)))
                if guarded:
                    notes.append(_note("guarded"))
                _emit_sig(st, b, s, span, conf, s.severity, notes)
                break


def _emit_sig(st: _Run, b: _Body, s: Signature, span: tuple[int, int], conf: str, severity: str | None,
              notes: list[tuple[str, str]]) -> None:
    r = b.r
    a, z = span
    matched = b.text[a:z]
    site_wide = _site_wide(st, r.host, matched)
    if site_wide:
        notes = [*notes, _note("site_wide")]
    if b.r.truncated:
        notes = [*notes, _note("truncated")]
    key = (s.id, "site-wide") if site_wide else (s.id, _norm(matched))
    st.emit(s.rule, r, st.ev(r, where="body", name=s.platform, value=_short(matched, 300),
                             offset=_byte_offset(r, b.text, a), excerpt=_excerpt(b.text, a, z)),
            confidence=conf, severity=severity, group_value=s.id, notes=notes, key=key)


# ----------------------------------------------------------------------------------------------- WEB055 listings

_A_HREF = re.compile(r"""<a\s[^>]*href\s*=\s*["']?([^"'\s>]+)""", re.I)
_TITLE = re.compile(r"<title\b[^>]{0,200}>(.{0,1024}?)</title\s*>", re.I | re.S)    # bounded: hostile pages
_H1 = re.compile(r"<h1\b[^>]{0,200}>(.{0,2048}?)</h1\s*>", re.I | re.S)
_TAGS = re.compile(r"<[^>]*>")
_SORT = re.compile(r"\?C=[NMSD];O=[AD]", re.I)


def _plain(fragment: str) -> str:
    return " ".join(_html.unescape(_TAGS.sub(" ", fragment)).split())


def listing_platform(text: str) -> str | None:
    """Server whose automatic directory listing ``text`` is (WEB055 signature table), or ``None``. A signature in the
    title/h1 alone is not enough: a link to ``../`` (or the parent-directory entry) or a sort link is required, plus at
    least one other link — a blog post titled "Index of …" is not a listing."""
    if not text:
        return None
    t = text[:262144]
    low = t.lower()
    hrefs = [h for h in _A_HREF.findall(t)]
    parent = any(h.rstrip("/") in ("..", "../..") or h in ("../", "..") for h in hrefs) or "[to parent directory]" in low \
        or "parent directory" in low
    sort = bool(_SORT.search(t))
    others = [h for h in hrefs if h.rstrip("/") not in ("..", "") and not _SORT.match(h) and not h.startswith("?")]
    if not others:
        return None
    tm = _TITLE.search(t)
    title = _plain(tm.group(1)) if tm else ""
    hm = _H1.search(t)
    h1 = _plain(hm.group(1)) if hm else ""
    tl, hl = title.lower(), h1.lower()
    if "[to parent directory]" in low and "<pre" in low:
        return "Microsoft IIS"
    if tl.startswith("index of /") or hl.startswith("index of /"):
        if '<div class="list">' in low:
            return "lighttpd"
        if sort and tl.startswith("index of /"):
            return "Apache httpd"
        if tl.startswith("index of /") and hl.startswith("index of /") and parent:
            if "apache" in low and "server at" in low:
                return "Apache httpd"
            return "nginx"
        if parent and tl.startswith("index of /"):
            return "Apache httpd"
        return None
    if ("directory listing for /" in tl or "directory listing for /" in hl) and ("<ul" in low or "<li" in low):
        return "Python http.server"
    if "directory listing for /" in low and "<table" in low and (parent or "tomcat" in low):
        return "Apache Tomcat"
    if tl.startswith("directory: /") and (parent or len(others) >= 1):
        return "Jetty"
    if title.startswith("/") and 'class="listing"' in low:
        return "Caddy"
    if 'id="files"' in low and tl.startswith("listing directory"):
        return "Express serve-index"
    return None


def _listing(st: _Run) -> None:
    for b in st.bodies():
        r = b.r
        if b.kind != "document" or not _is_2xx(r) or not b.is_html or "soft404" in r.flags:
            continue
        st.seen("WEB055", r.host)
        platform = listing_platform(b.text)
        if platform is None:
            continue
        if any(t == b.text for t in st.baseline_texts(r.host)):
            continue                       # the catch-all page itself, not a listing
        tm = _TITLE.search(b.text)
        title = _short(_plain(tm.group(1)), 120) if tm else ""
        st.emit("WEB055", r, st.ev(r, where="body", name="title", value=title, offset=_byte_offset(r, b.text, tm.start())
                                   if tm else None, excerpt=title),
                group_value=platform, key=(platform, r.url), notes=[_note("listing", platform=platform)])


# ----------------------------------------------------------------------------------------------- WEB608 source

_SOURCE = (
    ("PHP", re.compile(r"<\?php\b", re.I)),
    ("JSP", re.compile(r"<%@\s*page\b|<jsp:directive\.", re.I)),
    ("ASP.NET", re.compile(r"<%@\s*Page\b|<script\s[^>]{0,200}runat\s*=\s*[\"']?server", re.I)),
    ("ColdFusion", re.compile(r"<cfquery\b", re.I)),
)
_PHP_WINDOW = 4000


def source_code(text: str, skip=lambda pos: False) -> tuple[str, int, int] | None:
    """Raw server-side source in ``text`` as ``(language, start, end)``: ``<?php`` followed by a ``;`` before ``?>`` or
    the end of the text (within 4000 characters; at most 20 candidates, so a hostile page cannot make it slow),
    ``<%@ page``, ``<%@ Page``, ``<jsp:directive``, ``<cfquery``, ``<script runat="server">``. ``skip(pos)`` vetoes a hit."""
    for lang, rx in _SOURCE:
        for n, m in enumerate(rx.finditer(text)):
            if n >= 20:
                break
            if skip(m.start()):
                continue
            if lang == "PHP":
                window = text[m.end():m.end() + _PHP_WINDOW]
                close = window.find("?>")
                semi = window.find(";")
                if semi < 0 or (0 <= close < semi):
                    continue
                return lang, m.start(), m.end() + semi + 1
            return lang, m.start(), m.end()
    return None
_DOC_PATH = re.compile(r"/(?:docs?|examples?|samples?|documentation)(?:/|$)", re.I)


def _source_code(st: _Run) -> None:
    for b in st.bodies():
        r = b.r
        if b.code or b.kind not in ("document", "text", "download", "other", "soft404"):
            continue
        st.seen("WEB608", r.host)
        if r.essence == "text/plain" and _DOC_PATH.search(urllib.parse.urlsplit(r.url).path):
            continue
        spans = guarded_spans(b.text) if b.is_html else []
        hit = source_code(b.text, lambda pos: any(a <= pos < z for a, z in spans))
        if hit:
            lang, a, z = hit
            st.emit("WEB608", r, st.ev(r, where="body", name=lang, value=_short(b.text[a:z], 120),
                                       offset=_byte_offset(r, b.text, a), excerpt=_excerpt(b.text, a, z)),
                    group_value=lang, notes=[_note("source_code", value=lang)])
    # downloads (Content-Disposition: attachment, octet-stream) are not in the text set: judge them here
    for r in st.ctx.all_responses(include_hops=False):
        if not st.own(r) or _kind(r) != "download" or not r.body or _opaque(r) or is_binary(r.body):
            continue
        if r.source in ("probe", "baseline"):
            continue
        st.seen("WEB608", r.host)
        text = r.text()[:SCAN_CAP]
        hit = source_code(text)
        if hit:
            lang, a, z = hit
            st.emit("WEB608", r, st.ev(r, where="body", name=lang, value=_short(text[a:z], 120),
                                       offset=_byte_offset(r, text, a), excerpt=_excerpt(text, a, z)),
                    group_value=lang, notes=[_note("source_code", value=lang)])


# ----------------------------------------------------------------------------------------------- WEB611 ViewState

_ASPNET_VERSION = re.compile(r"^\s*(\d+)\.(\d+)")


def viewstate_mac(raw: bytes) -> str:
    """ZAP 10032 trailing-bytes heuristic on a decoded ASP.NET ViewState: ``"none"`` (ends with the ``dd`` null
    markers, so nothing follows the object graph), ``"mac"`` (the markers sit 20 or 32 bytes before the end:
    HMAC-SHA1/SHA256), ``"unknown"`` otherwise or when the preamble is not ASP.NET 2.0+ (``FF 01``)."""
    if raw.startswith(b"\xff\x01"):
        end = b"dd"
    elif raw.startswith(b"t<"):            # ASP.NET 1.x LosFormatter
        end = b">>"
    else:
        return "unknown"
    if len(raw) < 24:
        return "unknown"
    if raw.endswith(end):
        return "none"
    if raw[-22:-20] == end or (len(raw) >= 34 and raw[-34:-32] == end):
        return "mac"
    return "unknown"


def jsf_state_classes(value: str) -> list[str] | None:
    """Java class names in an unencrypted client-side ``javax.faces.ViewState`` (base64, optionally gzip), or ``None``
    when the state is server-side (``-123:456``), encrypted or not decodable."""
    v = value.strip()
    if not v or v.startswith("_") or ":" in v or len(v) < 16:
        return None
    raw = _b64decode(v, 1 << 20)
    if not raw:
        return None
    if raw.startswith(b"\x1f\x8b"):
        raw = _gunzip(raw) or b""
    if b"java" not in raw:
        return None
    names = sorted({m.decode("ascii", "replace") for m in re.findall(rb"(?:java|javax|jakarta)\.[\w.$]{3,80}", raw)})
    return names[:5] or ["java"]


def _viewstate(st: _Run) -> None:
    aspnet_old = None
    for r in st.header_responses():
        v = r.headers.first("x-aspnet-version")
        m = _ASPNET_VERSION.match(v or "")
        if m and int(m.group(1)) < 4:          # 4.0.30319 covers CLR 4 (4.0–4.8): only 1.x/2.0 prove < 4.5
            aspnet_old = v.strip()
    for b in st.bodies():
        if b.doc is None:
            continue
        st.seen("WEB611", b.r.host)
        inputs = {}
        for e in b.doc.find_all("input"):
            name = (e.get("name") or e.get("id") or "").strip()
            if name:
                inputs.setdefault(name, e)
        vs = inputs.get("__VIEWSTATE")
        if vs is not None and "__VIEWSTATEENCRYPTED" not in inputs:
            value = vs.get("value") or ""
            count = inputs.get("__VIEWSTATEFIELDCOUNT")
            if count is not None:
                try:
                    n = min(int((count.get("value") or "1").strip()), 64)
                except ValueError:
                    n = 1
                value += "".join(inputs[f"__VIEWSTATE{i}"].get("value") or "" for i in range(1, n)
                                 if f"__VIEWSTATE{i}" in inputs)
            raw = _b64decode(value, 1 << 20)
            if raw and viewstate_mac(raw) == "none":
                notes = [_note("viewstate_nomac")]
                conf = "tentative"
                if aspnet_old:
                    conf = "firm"
                    notes.append(_note("viewstate_old", value=aspnet_old))
                st.emit("WEB611", b.r, st.ev(b.r, where="body", name="__VIEWSTATE", value=_short(value[:32], 40) + "…",
                                             offset=vs.offset),
                        severity="medium", confidence=conf, group_value="aspnet", notes=notes)
        for name, e in inputs.items():
            if name.lower().endswith("faces.viewstate") or "faces.viewstate" in (e.get("id") or "").lower():
                classes = jsf_state_classes(e.get("value") or "")
                if classes:
                    st.emit("WEB611", b.r, st.ev(b.r, where="body", name=name, value=", ".join(classes),
                                                 offset=e.offset),
                            severity="high", confidence="firm", group_value="jsf",
                            notes=[_note("jsf", value=", ".join(classes))])
                break


# ----------------------------------------------------------------------------------------------- WEB612 hashes

_HASH_END = r"(?![./A-Za-z0-9$])"
HASHES = (
    ("bcrypt", re.compile(r"(?<![\w$])\$2[abxy]\$\d\d\$[./A-Za-z0-9]{53}" + _HASH_END)),
    ("MD5-crypt", re.compile(r"(?<![\w$])\$1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}" + _HASH_END)),
    ("SHA-256-crypt", re.compile(r"(?<![\w$])\$5\$(?:rounds=\d+\$)?[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{43}" + _HASH_END)),
    ("SHA-512-crypt", re.compile(r"(?<![\w$])\$6\$(?:rounds=\d+\$)?[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}" + _HASH_END)),
    ("Argon2", re.compile(r"(?<![\w$])\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]{8,}\$[A-Za-z0-9+/]{16,}")),
    ("scrypt", re.compile(r"(?<![\w$])\$scrypt\$ln=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/.]{8,}\$[A-Za-z0-9+/.]{16,}")),
    ("yescrypt/scrypt", re.compile(r"(?<![\w$])\$7\$[./A-Za-z0-9]{11,}\$[./A-Za-z0-9]{43}" + _HASH_END)),
    ("PBKDF2", re.compile(r"(?<![\w$])\$pbkdf2-sha(?:1|256|512)\$\d+\$[./A-Za-z0-9+]{8,}\$[./A-Za-z0-9+]{20,}")),
    ("Django PBKDF2", re.compile(r"(?<![\w$])pbkdf2_sha(?:1|256)\$\d{4,}\$[A-Za-z0-9]{8,}\$[A-Za-z0-9+/]{43,}={0,2}")),
)


def password_hashes(text: str) -> list[tuple[str, str, int, int]]:
    """Complete crypt-format password hashes in ``text`` as ``(type, hash, start, end)`` (bare hex is never one)."""
    out = []
    for name, rx in HASHES:
        for m in rx.finditer(text):
            out.append((name, m.group(0), m.start(), m.end()))
    out.sort(key=lambda t: t[2])
    return out


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def _hashes(st: _Run) -> None:
    for b in st.bodies():
        if b.code and not st.paranoid:
            continue
        st.seen("WEB612", b.r.host)
        for kind, value, s, e in password_hashes(b.text):
            if b.in_guard(s) or b.code:
                continue                       # WEB612 allows firm only: documentation examples are dropped
            red = redact_secret(value)
            st.emit("WEB612", b.r, st.ev(b.r, where="body", name=kind, value=red, offset=_byte_offset(b.r, b.text, s),
                                         excerpt=_excerpt(b.text, s, e, replace=red)),
                    group_value=f"{kind}:{_digest(value)}", notes=[_note("hash", kind=kind, value=red)])


# ----------------------------------------------------------------------------------------------- WEB613 cards

_CARD = re.compile(r"(?<![\d])\d(?:[ -]?\d){12,18}(?![\d])")
TEST_CARDS = frozenset({
    "4111111111111111", "4242424242424242", "4012888888881881", "4222222222222", "4000056655665556", "4000000000000002",
    "4000000000000077", "4000000000000093", "4000000000003220", "4000002500003155", "4000000000009995",
    "5555555555554444", "5105105105105100", "5200828282828210", "2223003122003222", "2223000048400011",
    "378282246310005", "371449635398431", "378734493671000", "6011111111111117", "6011000990139424",
    "6011000000000004", "3530111333300000", "3566002020360505", "3566111111111113", "30569309025904",
    "38520000023237", "36227206271667", "6200000000000005", "6759649826438453", "5019717010103742",
})


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def card_brand(d: str) -> str | None:
    n = len(d)
    p2, p3, p4, p6 = int(d[:2]), int(d[:3]), int(d[:4]), int(d[:6])
    if d[0] == "4" and n in (13, 16, 19):
        return "Visa"
    if (51 <= p2 <= 55 or 2221 <= p4 <= 2720) and n == 16:
        return "Mastercard"
    if p2 in (34, 37) and n == 15:
        return "American Express"
    if (p4 == 6011 or p2 == 65 or 644 <= p3 <= 649 or 622126 <= p6 <= 622925) and 16 <= n <= 19:
        return "Discover"
    if 3528 <= p4 <= 3589 and 16 <= n <= 19:
        return "JCB"
    if (300 <= p3 <= 305 or p2 in (36, 38, 39)) and 14 <= n <= 19:
        return "Diners Club"
    if p4 in (5018, 5020, 5038, 5893, 6304, 6759, 6761, 6762, 6763) and 12 <= n <= 19:
        return "Maestro"
    return None


def card_numbers(text: str) -> list[tuple[str, str, int, int]]:
    """Luhn-valid card numbers with a brand prefix as ``(brand, digits, start, end)``, with ZAP's context guards: no
    ``.``/``_`` within 3 characters, no exponent, no ``+`` (phone numbers), one consistent separator in groups of ≥ 3."""
    out = []
    for m in _CARD.finditer(text):
        raw = m.group(0)
        s, e = m.span()
        before, after = text[max(0, s - 3):s], text[e:e + 3]
        if "." in before or "_" in before or "_" in after or re.match(r"[^.]{0,2}\.\d", after):
            continue                                   # decimals, identifiers (a sentence-ending period is fine)
        if text[e:e + 1] in ("e", "E") or text[max(0, s - 1):s] in ("+", "-", "/", "#", "=", "$", "€"):
            continue
        if text[max(0, s - 1):s].isalnum() or text[e:e + 1].isalnum():
            continue
        seps = {c for c in raw if not c.isdigit()}
        if len(seps) > 1:
            continue
        if seps:
            groups = re.split(r"[ -]", raw)
            if any(len(g) < 3 for g in groups) or len(groups) > 5:
                continue
        d = re.sub(r"\D", "", raw)
        if not 13 <= len(d) <= 19 or len(set(d)) <= 2:
            if d not in TEST_CARDS:
                continue
        brand = card_brand(d)
        if brand is None or not luhn_ok(d):
            continue
        out.append((brand, d, s, e))
    return out


_STYLE_OPEN = re.compile(r"<style\b", re.I)


def _style_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    low = None
    pos = 0
    while True:
        m = _STYLE_OPEN.search(text, pos)
        if not m:
            return spans
        if low is None:
            low = text.lower()
        close = low.find("</style", m.end())
        end = len(text) if close < 0 else close
        spans.append((m.start(), end))
        pos = max(end, m.end())


def _in_tag(text: str, pos: int) -> bool:
    """True when ``pos`` lies inside a start/end tag (an attribute value), not in text content or a script."""
    lt = text.rfind("<", 0, pos)
    return lt >= 0 and text.rfind(">", 0, pos) < lt


def _cards(st: _Run) -> None:
    for b in st.bodies():
        if (b.code and not st.paranoid) or b.kind == "style":
            continue
        st.seen("WEB613", b.r.host)
        styles = _style_spans(b.text) if b.is_html else []
        for brand, d, s, e in card_numbers(b.text):
            if b.is_html and (_in_tag(b.text, s) or any(a <= s < z for a, z in styles)):
                continue                       # visible text and scripts only (never attributes or styles)
            if b.in_guard(s):
                continue                       # WEB613 allows firm only
            masked = "*" * (len(d) - 4) + d[-4:]
            test = d in TEST_CARDS
            notes = [_note("card", kind=brand, value=masked)]
            if test:
                notes.append(_note("test_card"))
            st.emit("WEB613", b.r, st.ev(b.r, where="body", name=brand, value=masked,
                                         offset=_byte_offset(b.r, b.text, s), excerpt=_excerpt(b.text, s, e, replace=masked)),
                    severity="info" if test else "medium", group_value=f"{brand}:{d[-4:]}:{_digest(d)}", notes=notes)


# ----------------------------------------------------------------------------------------------- WEB614 comments

SENSITIVE_COMMENT = re.compile(
    r"pass(?:word|wd)\s*[=:]|\bpasswd\b|\bapi[_-]?key\b|BEGIN [A-Z ]*PRIVATE|"
    r"\b[\w-]+(?:\.[\w-]+)*\.(?:internal|local|corp)\b|\b(?:TODO|FIXME)\b[^\n]{0,80}\b(?:security|auth\w*|password)\b",
    re.I)
_SECRETISH = re.compile(r"((?:pass(?:word|wd)?|api[_-]?key|secret|token)\s*[=:]\s*)\S+", re.I)


def _comments(st: _Run) -> None:
    if not st.paranoid:
        return                                 # paranoid-only rule: not even evaluated below paranoid (§3.6)
    for b in st.bodies():
        if b.doc is None:
            continue
        st.seen("WEB614", b.r.host)
        for c in b.doc.comments:
            m = SENSITIVE_COMMENT.search(c.text)
            if not m:
                continue
            shown = _short(_SECRETISH.sub(lambda mm: mm.group(1) + "…", c.text), 160)
            st.emit("WEB614", b.r, st.ev(b.r, where="body", name="comment", value=shown,
                                         offset=_byte_offset(b.r, b.text, c.offset), excerpt=shown),
                    group_value=_norm(m.group(0)), notes=[_note("comment", value=shown)])


# =============================================================================================== WEB609 secrets

@dataclass(frozen=True)
class SecretRule:
    id: str
    regex: re.Pattern
    severity: str
    confidence: str
    title_en: str
    title_ar: str
    min_entropy: float = 3.5
    source: str = "sec"                    # sec | extra


@dataclass
class SecretSet:
    rules: list[SecretRule] = field(default_factory=list)
    publishable: list[re.Pattern] = field(default_factory=list)


_SEC_LEVEL = {"SEC001": ("critical", "certain"), "SEC006": ("critical", "firm"), "SEC030": ("high", "firm")}


def secret_set(ctx: ScanContext) -> SecretSet | None:
    obj = _load(ctx, "secret-rules.json")
    if not isinstance(obj, dict):
        return None
    key = (id(obj), "secrets")
    if key in _COMPILED:
        return _COMPILED[key]
    from .. import history                     # read-only reuse of Kashif's SEC rules (§4.2 import rule)
    wanted = set(obj.get("sec_rules", []))
    out = SecretSet()
    for rule in history.secret_rules():
        if rule.id not in wanted:
            continue
        sev, conf = _SEC_LEVEL.get(rule.id, ("high", "firm"))
        out.rules.append(SecretRule(rule.id, rule.pattern, sev, conf, rule.title, rule.title_ar))
    for e in obj.get("extra", []):
        out.rules.append(SecretRule(e["id"], re.compile(e["pattern"]), e["severity"], e["confidence"], e["title_en"],
                                    e["title_ar"], float(e.get("min_entropy", 3.5)), "extra"))
    out.publishable = [re.compile(p) for p in obj.get("publishable", [])]
    _COMPILED[key] = out
    return out


_PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----")
_B64CHARS = re.compile(r"[A-Za-z0-9+/=]+")
_DB_PASS = re.compile(r"://[^:/\s'\"@]+:([^@\s'\"]{3,})@")
_AZ_KEY = re.compile(r"AccountKey=([A-Za-z0-9+/]{40,}={0,2})", re.I)
_BOUND = re.compile(r"""[:=]\s*['"]?([A-Za-z0-9/+=_\-.]{8,})['"]?\s*$""")
_PREFIX = re.compile(r"^(?:[A-Za-z]{1,10}[_.-]){1,3}")
_PLACEHOLDERS = ("xxxx", "example", "your_", "your-", "yourkey", "placeholder", "dummy", "sample", "changeme", "redacted",
                 "<", ">", "${", "{{", "%s", "insert", "replace")
_DB_PLACEHOLDER_PW = frozenset({"password", "pass", "passwd", "pwd", "secret", "changeme", "xxx", "****", "123456", "root",
                                "admin", "user", "test", "example", "postgres", "mysql"})
_REPEAT = re.compile(r"(.)\1{5,}")
_FIREBASE = re.compile(r"authDomain|messagingSenderId|firebase|storageBucket", re.I)


def _pem_body(text: str, end_of_header: int) -> str | None:
    """Base64 body of a PEM private key that starts at ``end_of_header`` (escaped ``\\n`` and string concatenation in
    JS allowed), or ``None`` when no real key body follows (a library constant naming the header)."""
    m = _PEM_END.search(text, end_of_header, end_of_header + 16384)
    if not m:
        return None
    seg = text[end_of_header:m.start()]
    seg = re.sub(r"\\[rnt]", " ", seg)
    body = "".join(_B64CHARS.findall(seg))
    if len(body) < 64 or len(body) < 0.6 * len(seg.replace(" ", "").replace("\n", "")):
        return None
    if entropy(body) < 4.5:
        return None
    return body


def _variable_part(value: str) -> str:
    return value[_PREFIX.match(value).end():] if _PREFIX.match(value) else value


def _placeholder(value: str) -> bool:
    low = value.lower()
    return any(p in low for p in _PLACEHOLDERS) or bool(_REPEAT.search(value))


def _entropy_ok(value: str, floor: float) -> bool:
    var = _variable_part(value)
    if len(var) < 12:
        return True
    if re.fullmatch(r"[0-9a-fA-F]+", var):
        floor = min(floor, 3.0)
    return entropy(var) >= floor


@dataclass(frozen=True)
class SecretHit:
    label: str                 # rule id (SEC0xx or extra id)
    title: tuple[str, str]
    value: str                 # the secret (in memory only)
    start: int
    end: int
    severity: str
    confidence: str


# literal anchors per rule: a rule whose anchors are all absent from a text cannot match it, so its (lookbehind-heavy,
# ≈ 50 ms per 3 MB) regex is skipped. ``ci`` anchors are looked up in the lower-cased text. Unknown ids always run.
_ANCHORS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "SEC001": (("PRIVATE KEY",), ()),
    "SEC003": (("ghp_", "gho_", "github_pat_", "glpat-", "xox", "sk_live_", "T3BlbkFJ", "AIza"), ()),
    "SEC006": ((), ("postgres", "mysql", "mongodb", "redis", "amqp", "mssql")),
    "SEC007": (("SG.", "SK", "AC", "key-", "npm_", "pypi-", "dop_v1_", "shpat_", "sq0atp-", "EAA", "ya29.", ":AA"), ()),
    "SEC008": (("hooks.slack.com", "discord", "webhook.office.com"), ()),
    "SEC010": ((), ("accountkey=", "defaultendpointsprotocol=")),
    "SEC012": (("ghu_", "ghs_", "ghr_"), ()),
    "SEC013": (("glptt-", "GR1348941", "glrt-", "gldt-", "glsoat-", "glcbt-", "glffct-", "glimt-", "glagent-", "gloas-",
                "glpat-"), ()),
    "SEC014": (("xapp-", "xoxe-"), ()),
    "SEC015": (("sk_live_", "rk_live_", "whsec_"), ()),
    "SEC016": (("-us",), ()),
    "SEC017": (("shpss_", "shpca_", "shppa_"), ()),
    "SEC018": (("ATATT3",), ()),
    "SEC020": (("Q~",), ()),
    "SEC021": (("GOCSPX-",), ()),
    "SEC022": ((), ("hrku-", "heroku")),
    "SEC023": (("dckr_",), ()),
    "SEC024": (("hf_", "api_org_"), ()),
    "SEC025": (("sk-proj-", "sk-svcacct-", "sk-admin-"), ()),
    "SEC026": (("sk-ant-",), ()),
    "SEC027": (("dapi",), ()),
    "SEC028": (("hvs.", "hvb.", "hvr."), ()),
    "SEC029": (("glc_", "glsa_", "PMAK-", "lin_api_", "NRAK-", "pul-", ".atlasv1.", "dp.", "sntrys_", "sntryu_", "sbp_",
                "pscale_", "pat", "sq0csp-", "LTAI", "AGE-SECRET-KEY-1"), ()),
    "SEC030": (("ENCRYPTED PRIVATE KEY", "PuTTY-User-Key-File"), ()),
    "SEC031": ((), ("aws",)),
    "google-api-key": (("AIza",), ()),
    "aws-secret-pair": (("AKIA", "ASIA"), ()),
    "aws-secret-assign": ((), ("access",)),
    "braintree-token": (("access_token$production$",), ()),
    "fcm-server-key": (("APA91b",), ()),
}


def _may_match(rule_id: str, text: str, lower: str) -> bool:
    anchors = _ANCHORS.get(rule_id)
    if anchors is None:
        return True
    cs, ci = anchors
    return any(a in text for a in cs) or any(a in lower for a in ci)


def find_secrets(text: str, rules: SecretSet) -> list[SecretHit]:
    """Secrets in ``text`` per the WEB609 rule set (values in memory only; callers must redact)."""
    out: list[SecretHit] = []
    taken: list[tuple[int, int]] = []
    lower = text.lower()
    for rule in rules.rules:
        if not _may_match(rule.id, text, lower):
            continue
        for m in rule.regex.finditer(text):
            hit = _judge(rule, m, text, rules)
            if hit is None:
                continue
            if any(a < hit.end and hit.start < b for a, b in taken):
                continue
            taken.append((hit.start, hit.end))
            out.append(hit)
            if len(out) >= 50:
                return out
    out.sort(key=lambda h: h.start)
    return out


def _judge(rule: SecretRule, m: re.Match, text: str, rules: SecretSet) -> SecretHit | None:
    s, e = m.span()
    match = m.group(0)
    sev, conf, label, title = rule.severity, rule.confidence, rule.id, (rule.title_en, rule.title_ar)
    if rule.id in ("SEC001", "SEC030"):
        if match.startswith("PuTTY"):
            return None
        body = _pem_body(text, e)
        if body is None:
            return None
        end = _PEM_END.search(text, e).end()
        return SecretHit(label, title, body, s, end, sev, conf)
    if rule.id == "SEC006":
        pm = _DB_PASS.search(match)
        if not pm or pm.group(1).lower() in _DB_PLACEHOLDER_PW or _placeholder(pm.group(1)):
            return None
        return SecretHit(label, title, pm.group(1), s, e, sev, conf)
    if rule.id == "SEC010":
        km = _AZ_KEY.search(text, s, min(len(text), e + 400))
        if not km or _placeholder(km.group(1)):
            return None
        return SecretHit(label, title, km.group(1), s, max(e, km.end()), sev, conf)
    value = m.groupdict().get("secret") if "secret" in rule.regex.groupindex else None
    if value is None:
        value = match
        if rule.id == "SEC031" or "=" in value or ":" in value:
            bm = _BOUND.search(value)
            if bm and rule.id == "SEC031":
                value = bm.group(1)
    value = value.strip("'\"` ")
    if not value:
        return None
    if rule.id == "SEC007":
        if value.startswith("AC"):
            return None                            # a Twilio account SID alone is an identifier, not a secret
        if value.startswith("SK") and not re.search(r"(?<![A-Za-z0-9])AC[0-9a-fA-F]{32}(?![A-Za-z0-9])", text):
            return None                            # Twilio API key: only with its account SID
    if rule.id == "SEC029" and value.startswith("LTAI"):
        return None                                # Alibaba AccessKey id alone
    if value.startswith("AIza"):
        window = text[max(0, s - 400):e + 400]
        if _FIREBASE.search(window):
            return None                            # Firebase web config: public by design
        label, sev, conf = "google-api-key", "low", "tentative"
        g = next((r for r in rules.rules if r.id == "google-api-key"), None)
        if g is not None:
            title = (g.title_en, g.title_ar)
    if any(p.match(value) for p in rules.publishable):
        return None
    if _placeholder(value) or not _entropy_ok(value, rule.min_entropy):
        return None
    return SecretHit(label, title, value, s, e, sev, conf)


@dataclass
class _Source:
    response: Response
    where: str                  # inline | attribute | script | json | sourcemap
    name: str
    text: str
    base: int | None            # offset of ``text`` in the response's decoded text (None: not in the body as is)


def _secret_sources(st: _Run) -> Iterator[_Source]:
    seen: set[int] = set()
    for b in st.bodies():
        seen.add(id(b.r))
        if b.doc is not None:
            for sc in b.doc.inline_scripts:
                yield _Source(b.r, "inline", "script", sc.text, sc.offset)
            for el in b.doc.elements:
                for k, v in el.attrs.items():
                    if v and len(v) >= 20 and (k.startswith("data-") or k == "value"):
                        yield _Source(b.r, "attribute", f"{el.tag}[{k}]", v, None)
        elif b.kind == "api_json":
            yield _Source(b.r, "json", "body", b.text, 0)
    for r in st.ctx.all_responses(include_hops=False):
        if _kind(r) != "script" or not r.body or _opaque(r) or is_binary(r.body):
            continue
        third = not st.own(r)
        if third and r.source != "subresource":
            continue
        yield _Source(r, "script", "script", r.text()[:SCRIPT_CAP], 0)


def _secrets(st: _Run) -> None:
    rules = secret_set(st.ctx)
    if rules is None:
        st.skip("WEB609", st.ctx.target_host, "data_missing")
        return
    st.secret_rules = rules                     # reused by _sourcemaps for sourcesContent
    for src in _secret_sources(st):
        _scan_secrets(st, src, rules)


def _scan_secrets(st: _Run, src: _Source, rules: SecretSet) -> None:
    r = src.response
    st.seen("WEB609", r.host if st.own(r) else st.ctx.target_host)
    for hit in find_secrets(src.text, rules):
        red = redact_secret(hit.value)
        offset = None
        if src.base is not None:
            offset = _byte_offset(r, r.text(), src.base + hit.start) if src.base >= 0 else None
        where = _WHERE.get(src.where, _WHERE["body"])
        notes = [_note("secret", kind=hit.title, value=red), _note("secret_where", where=where)]
        st.emit("WEB609", r, st.ev(r, where="body", name=f"{src.name}: {hit.title[0]}", value=red, offset=offset,
                                   excerpt=_excerpt(src.text, hit.start, hit.end, replace=f"<{hit.label} {red}>", around=50)),
                severity=hit.severity, confidence=hit.confidence, group_value=f"{hit.label}:{_digest(hit.value)}",
                notes=notes, host=r.host if st.own(r) else st.ctx.target_host)


# =============================================================================================== WEB602 source maps

_MAP_COMMENT = re.compile(r"(?://|/\*)\s*[#@]\s*sourceMappingURL\s*=\s*([^\s*'\"]+)")


def sourcemap_reference(r: Response, text: str | None = None) -> str | None:
    """The source map a script or style names (``SourceMap``/``X-SourceMap`` header, else the last
    ``sourceMappingURL`` comment), resolved against the file's URL; ``data:`` URLs are returned as is."""
    h = r.headers.first("sourcemap") or r.headers.first("x-sourcemap")
    ref = h.strip() if h and h.strip() else None
    if ref is None:
        t = text if text is not None else r.text()
        tail = t[-8192:]
        found = _MAP_COMMENT.findall(tail)
        ref = found[-1] if found else None
    if not ref:
        return None
    if ref.lower().startswith("data:"):
        return ref
    try:
        return urllib.parse.urldefrag(urllib.parse.urljoin(r.url, ref))[0]
    except ValueError:
        return None


def parse_sourcemap(text: str) -> dict | None:
    """A source map object (``version`` plus ``sources`` or ``sections``), XSSI prefix ``)]}'`` tolerated."""
    t = text.lstrip("\ufeff")
    if t.startswith(")]}"):
        t = t.split("\n", 1)[1] if "\n" in t else ""
    try:
        obj = json.loads(t)
    except ValueError:
        return None
    if not isinstance(obj, dict) or not (isinstance(obj.get("sources"), list) or isinstance(obj.get("sections"), list)):
        return None
    return obj


def _data_url_text(url: str) -> str | None:
    head, _, payload = url.partition(",")
    try:
        if ";base64" in head.lower():
            raw = _b64decode(urllib.parse.unquote(payload), 8 << 20)
            return raw.decode("utf-8", "replace") if raw else None
        return urllib.parse.unquote(payload)
    except ValueError:
        return None


def _map_sources(obj: dict) -> Iterator[tuple[str, str]]:
    """``(source name, content)`` of the embedded sources (``sections`` flattened)."""
    maps = [obj] + [s.get("map") for s in obj.get("sections", []) if isinstance(s, dict) and isinstance(s.get("map"), dict)]
    for m in maps:
        names = m.get("sources") or []
        contents = m.get("sourcesContent") or []
        if not isinstance(contents, list):
            continue
        for i, c in enumerate(contents):
            if isinstance(c, str) and c:
                name = names[i] if i < len(names) and isinstance(names[i], str) else f"source {i}"
                yield name, c[:SCRIPT_CAP]


def _source_count(obj: dict) -> int:
    n = len(obj.get("sources") or [])
    for s in obj.get("sections") or []:
        if isinstance(s, dict) and isinstance(s.get("map"), dict):
            n += len(s["map"].get("sources") or [])
    return n


def _sourcemaps(st: _Run) -> None:
    rules = st.secret_rules
    fetched: dict[str, Response] = {}
    for r in st.ctx.sourcemaps:
        fetched.setdefault(urllib.parse.urldefrag(r.url)[0], r)
        for h in r.chain:
            fetched.setdefault(urllib.parse.urldefrag(h.url)[0], r)
    judged: set[int] = set()
    for r in st.ctx.all_responses(include_hops=False):
        if _kind(r) not in CODE_KINDS or not st.own(r) or r.status is None or not _is_2xx(r) or _opaque(r):
            continue
        st.seen("WEB602", r.host)
        text = r.text() if r.body and not is_binary(r.body) else ""
        ref = sourcemap_reference(r, text)
        if ref is None:
            continue
        if ref.lower().startswith("data:"):
            obj = parse_sourcemap(_data_url_text(ref) or "")
            if obj is None:
                continue
            st.emit("WEB602", r, st.ev(r, where="body", name="sourceMappingURL", value="data:…"), severity="low",
                    group_value="inline", key=("inline", r.url), notes=[_note("map_inline")])
            if rules is not None:
                for name, content in _map_sources(obj):
                    _scan_secrets(st, _Source(r, "sourcemap", name, content, None), rules)
            continue
        m = fetched.get(ref)
        if m is None:
            st.emit("WEB602", r, st.ev(r, where="header" if r.headers.first("sourcemap") or r.headers.first("x-sourcemap")
                                       else "body", name="SourceMap", value=_short(ref, 300)),
                    severity="info", group_value="referenced", key=("referenced", ref),
                    notes=[_note("map_referenced", url=_short(ref, 160))])
            continue
        judged.add(id(m))
        _judge_map(st, m, rules)
    for m in st.ctx.sourcemaps:
        if id(m) not in judged and st.own(m):
            _judge_map(st, m, rules)


def _judge_map(st: _Run, m: Response, rules: SecretSet | None) -> None:
    st.seen("WEB602", m.host)
    if not _is_2xx(m) or _opaque(m) or not m.body or _kind(m) in ("soft404", "document", "error_page") \
            or "soft404" in m.flags:
        return
    obj = parse_sourcemap(m.text())
    if obj is None:
        return
    n = _source_count(obj)
    st.emit("WEB602", m, st.ev(m, where="probe", name="source map", value=_short(m.url, 300)), severity="low",
            group_value="fetched", key=("fetched", m.url),
            notes=[_note("map_fetched", url=_short(m.url, 160), sources=_count(n, _SOURCES))])
    if rules is not None:
        for name, content in _map_sources(obj):
            _scan_secrets(st, _Source(m, "sourcemap", name, content, None), rules)


# =============================================================================================== WEB619 EXIF GPS

def _u16(b: bytes, off: int, e: str) -> int:
    return struct.unpack_from(e + "H", b, off)[0]


def _u32(b: bytes, off: int, e: str) -> int:
    return struct.unpack_from(e + "I", b, off)[0]


def _ifd(t: bytes, off: int, e: str) -> dict[int, tuple[int, int, int]]:
    """Entries of the TIFF IFD at ``off``: tag → (type, count, value-or-offset field position)."""
    out: dict[int, tuple[int, int, int]] = {}
    if off <= 0 or off + 2 > len(t):
        return out
    n = min(_u16(t, off, e), 512)
    for i in range(n):
        p = off + 2 + 12 * i
        if p + 12 > len(t):
            break
        out[_u16(t, p, e)] = (_u16(t, p + 2, e), _u32(t, p + 4, e), p + 8)
    return out


def _rationals(t: bytes, entry: tuple[int, int, int], e: str) -> list[float] | None:
    typ, count, pos = entry
    if typ not in (5, 10) or not 1 <= count <= 8:
        return None
    off = _u32(t, pos, e)
    if off + 8 * count > len(t):
        return None
    vals = []
    for i in range(count):
        num, den = struct.unpack_from(e + "II", t, off + 8 * i)
        vals.append(num / den if den else 0.0)
    return vals


def exif_gps(data: bytes) -> bool:
    """True when a JPEG's EXIF (APP1) carries non-zero GPSLatitude and GPSLongitude (tags 2 and 4 of the GPS IFD)."""
    if not data.startswith(b"\xff\xd8"):
        return False
    i = 2
    try:
        while i + 4 <= len(data):
            if data[i] != 0xFF:
                return False
            marker = data[i + 1]
            if marker == 0xFF:
                i += 1
                continue
            if marker in (0x01, 0xD8) or 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            if marker in (0xDA, 0xD9):
                return False
            seglen = struct.unpack_from(">H", data, i + 2)[0]
            if seglen < 2:
                return False
            seg = data[i + 4:i + 2 + seglen]
            if marker == 0xE1 and seg.startswith(b"Exif\x00\x00"):
                t = seg[6:]
                e = "<" if t[:2] == b"II" else ">" if t[:2] == b"MM" else ""
                if e and len(t) >= 8 and _u16(t, 2, e) == 42:
                    ifd0 = _ifd(t, _u32(t, 4, e), e)
                    gps_entry = ifd0.get(0x8825)
                    if gps_entry:
                        gps = _ifd(t, _u32(t, gps_entry[2], e), e)
                        if 2 in gps and 4 in gps:
                            lat = _rationals(t, gps[2], e)
                            lon = _rationals(t, gps[4], e)
                            if lat and lon and (any(lat) or any(lon)):
                                return True
            i += 2 + seglen
    except struct.error:
        return False
    return False


def _images(st: _Run) -> None:
    for r in st.ctx.images:
        if not st.own(r) or not _is_2xx(r) or not r.body or _opaque(r):
            continue
        st.seen("WEB619", r.host)
        if exif_gps(r.body):
            st.emit("WEB619", r, st.ev(r, where="body", name="EXIF GPS", value="GPSLatitude, GPSLongitude", offset=None),
                    group_value="exif-gps", key=("gps", r.url), notes=[_note("exif")])


# =============================================================================================== i18n

def i18n_catalog() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """``(CATALOG, PATTERNS)`` for cat_web2: fixed Arabic notes → English, and anchored regex patterns for templates."""
    catalog: dict[str, str] = {}
    patterns: list[tuple[str, str]] = []
    pairs = list(STR.values()) + list(_WHERE.values())
    for en, ar in pairs:
        if "{" not in ar:
            catalog[ar] = en
            continue
        names: list[str] = []
        out, pos = [], 0
        for m in _PLACEHOLDER.finditer(ar):
            out.append(re.escape(ar[pos:m.start()]))
            if m.group(1) in names:
                out.append(f"(?P={m.group(1)})")
            else:
                out.append(f"(?P<{m.group(1)}>.+?)")
                names.append(m.group(1))
            pos = m.end()
        out.append(re.escape(ar[pos:]))
        patterns.append(("^" + "".join(out) + "$", _PLACEHOLDER.sub(lambda mm: f"\\g<{mm.group(1)}>", en)))
    for form in _SOURCES[2]:
        if "{n}" not in form:
            catalog[form] = _SOURCES[0].replace("{n}", "1") if form == _SOURCES[2][0] else _SOURCES[1].replace("{n}", "2")
    return catalog, patterns


__all__ = ["CHECKS", "STR", "run", "is_binary", "entropy", "guarded_spans", "Signature", "compile_signature",
           "match_signature", "signatures", "leak_headers", "server_version", "server_timing_leaks", "internal_ips",
           "serialized_format", "listing_platform", "viewstate_mac", "jsf_state_classes", "password_hashes", "luhn_ok",
           "card_brand", "card_numbers", "TEST_CARDS", "source_code", "secret_set", "find_secrets", "sourcemap_reference",
           "parse_sourcemap", "exif_gps", "i18n_catalog"]
