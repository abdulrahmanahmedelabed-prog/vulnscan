"""Frozen interfaces of the passive web scanner (spec §4.2, WP0).

Every check module receives a :class:`ScanContext` and returns a list of :class:`Issue`; the engine turns issues into
``model.Finding`` objects using the rule registry (``webscan.rules``). The dataclasses here are the contract between
the work packages: fields may be *added* (with defaults) but never removed or renamed during 1.x.

Conventions
* All URLs are absolute strings. Hosts are lower-case, without brackets for IPv6 and without a trailing dot.
* ``Response`` compares and hashes by identity (``eq=False``), so a response can key a dict (``ctx.csp[resp]``).
* Times are aware UTC ``datetime`` objects (``ScanContext.now``).
* Nothing in this module touches the network or the file system.
"""

from __future__ import annotations

import codecs
import hashlib
import re
import shlex
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator, Protocol, runtime_checkable

# ----------------------------------------------------------------------------------------------- constants

PROFILES = ("minimal", "standard", "deep")
SENSITIVITIES = ("strict", "default", "paranoid")
CONFIDENCES = ("certain", "firm", "tentative")
# which confidences each sensitivity reports (§0.5)
SENSITIVITY_CONFIDENCES = {
    "strict": frozenset({"certain"}),
    "default": frozenset({"certain", "firm"}),
    "paranoid": frozenset({"certain", "firm", "tentative"}),
}
# SARIF properties.precision for each confidence (§0.5)
SARIF_PRECISION = {"certain": "very-high", "firm": "high", "tentative": "low"}

RESPONSE_SOURCES = ("entry", "http_probe", "https_probe", "cors", "crawl", "subresource", "wellknown", "probe",
                    "baseline", "sourcemap", "image")
RESPONSE_KINDS = ("error", "informational", "no_content", "not_modified", "redirect", "waf_challenge", "rate_limited",
                  "error_page", "document", "api_json", "api_xml", "script", "style", "image", "font", "media",
                  "download", "text", "soft404", "other")
PAGE_ROLES = ("login", "signup", "authenticated", "admin", "api_docs", "error", "listing", "static", "app")
CHECK_STATES = ("pass", "fail", "not_applicable", "not_tested", "inconclusive")
DNS_STATUSES = ("ok", "nxdomain", "nodata", "tempfail", "not_tested")
COOKIE_CLASSES = ("session", "auth", "csrf", "preference", "analytics", "lb", "cdn_bot", "consent", "unknown",
                  "unknown_secret")
SESSION_CLASSES = frozenset({"session", "auth"})        # "session/auth" in the catalogue (§3.3)

UA_INFO_URL = "https://abdulrahmanahmedelabed-prog.github.io/vulnscan/scanner.html"
CORS_PROBE_ORIGIN = "https://kashif-cors-check.invalid"   # RFC 6761 reserved name (§2.4)
ACCEPT_DOCUMENT = "text/html,application/xhtml+xml,*/*;q=0.8"
ACCEPT_PROBE = "*/*"
ACCEPT_ENCODING = "gzip, deflate"
ACCEPT_LANGUAGE = "en"

EVIDENCE_VALUE_CAP = 300
EVIDENCE_EXCERPT_CAP = 200
EVIDENCE_HEADER_CAP = 1000
EVIDENCE_HEADERS_MAX = 120


def user_agent() -> str:
    """The honest User-Agent of §0.2; the version comes from ``vulnscan.__version__``."""
    from .. import __version__
    return f"Kashif/{__version__} (+{UA_INFO_URL})"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ----------------------------------------------------------------------------------------------- headers

@dataclass(frozen=True)
class HeaderList:
    """Raw headers in original case and order, duplicates kept (``Set-Cookie`` twice stays twice)."""
    items: tuple[tuple[str, str], ...] = ()

    @classmethod
    def of(cls, *pairs: tuple[str, str]) -> "HeaderList":
        return cls(tuple((str(k), str(v)) for k, v in pairs))

    @classmethod
    def from_mapping(cls, mapping: "dict[str, str | Iterable[str]]") -> "HeaderList":
        out: list[tuple[str, str]] = []
        for k, v in mapping.items():
            if isinstance(v, (list, tuple)):
                out.extend((k, str(x)) for x in v)
            else:
                out.append((k, str(v)))
        return cls(tuple(out))

    def get_all(self, name: str) -> list[str]:
        low = name.lower()
        return [v for k, v in self.items if k.lower() == low]

    def first(self, name: str) -> str | None:
        low = name.lower()
        for k, v in self.items:
            if k.lower() == low:
                return v
        return None

    def has(self, name: str) -> bool:
        low = name.lower()
        return any(k.lower() == low for k, _ in self.items)

    def count(self, name: str) -> int:
        low = name.lower()
        return sum(1 for k, _ in self.items if k.lower() == low)

    def joined(self, name: str, sep: str = ", ") -> str | None:
        """All field lines of ``name`` combined as RFC 9110 §5.3 does (``None`` when absent)."""
        vals = self.get_all(name)
        return sep.join(vals) if vals else None

    def names(self) -> list[str]:
        """Lower-cased names in first-seen order, without duplicates."""
        seen: dict[str, None] = {}
        for k, _ in self.items:
            seen.setdefault(k.lower(), None)
        return list(seen)

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)


# ----------------------------------------------------------------------------------------------- charsets

# WHATWG Encoding Standard labels → canonical names (the subset seen on real sites; anything else goes
# through codecs.lookup). "latin1", "iso-8859-1" and "ascii" are windows-1252 per WHATWG.
_WHATWG_LABELS = {
    "utf-8": "UTF-8", "utf8": "UTF-8", "unicode-1-1-utf-8": "UTF-8", "unicode11utf8": "UTF-8", "unicode20utf8": "UTF-8",
    "x-unicode20utf8": "UTF-8",
    "utf-16": "UTF-16LE", "utf-16le": "UTF-16LE", "unicode": "UTF-16LE", "ucs-2": "UTF-16LE", "csunicode": "UTF-16LE",
    "iso-10646-ucs-2": "UTF-16LE", "unicodefeff": "UTF-16LE", "utf-16be": "UTF-16BE", "unicodefffe": "UTF-16BE",
    "us-ascii": "windows-1252", "ascii": "windows-1252", "ansi_x3.4-1968": "windows-1252", "iso-8859-1": "windows-1252",
    "iso8859-1": "windows-1252", "iso_8859-1": "windows-1252", "iso88591": "windows-1252", "latin1": "windows-1252",
    "l1": "windows-1252", "cp1252": "windows-1252", "windows-1252": "windows-1252", "x-cp1252": "windows-1252",
    "cp819": "windows-1252", "ibm819": "windows-1252", "csisolatin1": "windows-1252",
    "windows-1256": "windows-1256", "cp1256": "windows-1256", "x-cp1256": "windows-1256",
    "windows-1251": "windows-1251", "cp1251": "windows-1251", "windows-1250": "windows-1250", "cp1250": "windows-1250",
    "iso-8859-6": "ISO-8859-6", "arabic": "ISO-8859-6", "iso8859-6": "ISO-8859-6", "iso_8859-6": "ISO-8859-6",
    "iso-8859-2": "ISO-8859-2", "iso-8859-5": "ISO-8859-5", "iso-8859-7": "ISO-8859-7", "iso-8859-8": "ISO-8859-8",
    "iso-8859-9": "windows-1254", "latin5": "windows-1254", "iso-8859-15": "ISO-8859-15", "latin9": "ISO-8859-15",
    "koi8-r": "KOI8-R", "koi8-u": "KOI8-U",
    "shift_jis": "Shift_JIS", "shift-jis": "Shift_JIS", "sjis": "Shift_JIS", "ms_kanji": "Shift_JIS",
    "windows-31j": "Shift_JIS", "x-sjis": "Shift_JIS", "euc-jp": "EUC-JP", "iso-2022-jp": "ISO-2022-JP",
    "gbk": "GBK", "gb2312": "GBK", "x-gbk": "GBK", "gb18030": "gb18030", "big5": "Big5", "big5-hkscs": "Big5",
    "euc-kr": "EUC-KR", "ks_c_5601-1987": "EUC-KR", "windows-949": "EUC-KR", "windows-874": "windows-874",
    "tis-620": "windows-874", "x-user-defined": "x-user-defined",
}
_PY_CODECS = {
    "UTF-8": "utf-8", "UTF-16LE": "utf-16-le", "UTF-16BE": "utf-16-be", "windows-1252": "cp1252",
    "windows-1256": "cp1256", "windows-1251": "cp1251", "windows-1250": "cp1250", "windows-1254": "cp1254",
    "windows-874": "cp874", "ISO-8859-6": "iso8859-6", "ISO-8859-2": "iso8859-2", "ISO-8859-5": "iso8859-5",
    "ISO-8859-7": "iso8859-7", "ISO-8859-8": "iso8859-8", "ISO-8859-15": "iso8859-15", "KOI8-R": "koi8-r",
    "KOI8-U": "koi8-u", "Shift_JIS": "cp932", "EUC-JP": "euc-jp", "ISO-2022-JP": "iso2022-jp", "GBK": "gbk",
    "gb18030": "gb18030", "Big5": "big5hkscs", "EUC-KR": "cp949", "x-user-defined": "latin-1",
}
_META_CHARSET = re.compile(rb"""<meta[^>]*?charset\s*=\s*["']?\s*([A-Za-z0-9._:\-]+)""", re.I)


def normalise_charset(label: str | None) -> str | None:
    """WHATWG canonical encoding name for ``label`` (quotes and case ignored), or ``None`` when unknown.

    ``utf8`` and ``UTF-8`` are the same encoding (fixes ZAP 90011's false positives); ``latin1`` is windows-1252."""
    if not label:
        return None
    lab = label.strip().strip("\"'").strip().lower()
    if not lab:
        return None
    if lab in _WHATWG_LABELS:
        return _WHATWG_LABELS[lab]
    try:
        name = codecs.lookup(lab).name
    except LookupError:
        return None
    for canon, py in _PY_CODECS.items():
        try:
            if codecs.lookup(py).name == name:
                return canon
        except LookupError:   # pragma: no cover - all listed codecs exist in CPython
            continue
    return name


def python_codec(canonical: str | None) -> str:
    return _PY_CODECS.get(canonical or "", "utf-8")


def essence(content_type: str | None) -> str:
    """The MIME essence (``type/subtype``, lower-case) of a Content-Type value; ``""`` when absent."""
    if not content_type:
        return ""
    return content_type.split(";", 1)[0].strip().lower()


def charset_param(content_type: str | None) -> str | None:
    """The raw ``charset`` parameter of a Content-Type value (quotes stripped), or ``None``."""
    if not content_type:
        return None
    for part in content_type.split(";")[1:]:
        k, _, v = part.partition("=")
        if k.strip().lower() == "charset":
            return v.strip().strip("\"'") or None
    return None


def bom_encoding(body: bytes) -> str | None:
    if body.startswith(b"\xef\xbb\xbf"):
        return "UTF-8"
    if body.startswith(b"\xff\xfe"):
        return "UTF-16LE"
    if body.startswith(b"\xfe\xff"):
        return "UTF-16BE"
    return None


def meta_charset(body: bytes, limit: int = 1024) -> str | None:
    """The charset declared by ``<meta charset>`` or the http-equiv form within the first ``limit`` bytes."""
    m = _META_CHARSET.search(body[:limit])
    return m.group(1).decode("ascii", "replace") if m else None


# ----------------------------------------------------------------------------------------------- responses

@dataclass(eq=False)
class Response:
    """One HTTP response as received. ``chain`` holds the earlier hops of a redirect chain; the final response owns it.

    Defaults exist so tests can build synthetic responses with only the fields they need. ``kind``, ``roles`` and
    ``flags`` are filled by classify.py (``flags`` include ``sniffed``, ``sensitive``, ``obs-fold``, ``truncated-body``,
    ``opaque-coding``, ``soft404``)."""
    url: str
    method: str = "GET"
    status: int | None = 200
    reason: str = ""
    http_version: str = "HTTP/1.1"
    headers: HeaderList = field(default_factory=HeaderList)
    body: bytes = b""
    truncated: bool = False
    encoding: str | None = None          # Content-Encoding seen on the wire (gzip, deflate, br, …)
    request_headers: HeaderList = field(default_factory=HeaderList)
    elapsed: float = 0.0
    ip: str | None = None
    error: str | None = None
    chain: list["Response"] = field(default_factory=list)
    source: str = "entry"                 # entry|http_probe|https_probe|cors|crawl|subresource|wellknown|probe|baseline|…
    kind: str = ""
    roles: frozenset[str] = frozenset()
    flags: frozenset[str] = frozenset()
    _text: str | None = field(default=None, init=False, repr=False)

    # -- decoding -------------------------------------------------------------------------------------------
    def detected_charset(self) -> str | None:
        """WHATWG name of the encoding used by :meth:`text`: BOM, then header charset, then meta prescan."""
        return (bom_encoding(self.body) or normalise_charset(charset_param(self.content_type))
                or normalise_charset(meta_charset(self.body)))

    def text(self) -> str:
        """Body decoded with the BOM/header/meta charset (UTF-8 when none is declared), ``errors="replace"``; cached."""
        if self._text is None:
            body = self.body
            bom = bom_encoding(body)
            if bom == "UTF-8":
                body = body[3:]
            elif bom:
                body = body[2:]
            codec = python_codec(self.detected_charset())
            try:
                self._text = body.decode(codec, "replace")
            except LookupError:   # pragma: no cover - codec names come from _PY_CODECS
                self._text = body.decode("utf-8", "replace")
        return self._text

    # -- convenience (pure) --------------------------------------------------------------------------------
    @property
    def parsed_url(self) -> urllib.parse.SplitResult:
        return urllib.parse.urlsplit(self.url)

    @property
    def scheme(self) -> str:
        return self.parsed_url.scheme.lower()

    @property
    def host(self) -> str:
        return normalise_host(self.parsed_url.hostname or "")

    @property
    def origin(self) -> str:
        return url_origin(self.url)

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    @property
    def content_type(self) -> str | None:
        return self.headers.first("content-type")

    @property
    def essence(self) -> str:
        return essence(self.content_type)

    @property
    def location(self) -> str | None:
        """The Location header resolved against this response's URL (``None`` when absent)."""
        loc = self.headers.first("location")
        if loc is None:
            return None
        return urllib.parse.urljoin(self.url, loc.strip())

    @property
    def is_redirect(self) -> bool:
        return self.status is not None and 300 <= self.status < 400 and self.headers.has("location")

    @property
    def is_2xx(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    def hops(self) -> list["Response"]:
        """The whole chain in request order, this (final) response last."""
        return [*self.chain, self]

    def body_sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()


@dataclass(frozen=True)
class ResponseSignature:
    """Soft-404 signature of a response (§3.2), computed by ``classify.signature``."""
    status: int | None
    essence: str
    length: int
    sha256: str
    simhash: int
    url: str = ""


# ----------------------------------------------------------------------------------------------- parsed HTML

@dataclass(slots=True)
class Element:
    """One start tag of the light DOM. ``attrs`` keys are lower-case; the first duplicate wins (HTML spec)."""
    tag: str
    attrs: dict[str, str]
    line: int            # 1-based
    col: int             # 0-based
    offset: int          # character offset of the ``<`` in the decoded document
    parent: int          # index of the parent element, -1 at the top
    index: int
    live: bool = True    # False inside <template> / <noscript> (not rendered / not executed)
    in_head: bool = False
    form: int = -1       # index of the owning <form> for form controls (form element pointer or form="id")

    def get(self, name: str, default: str | None = None) -> str | None:
        return self.attrs.get(name, default)

    def has(self, name: str) -> bool:
        return name in self.attrs

    def tokens(self, name: str) -> frozenset[str]:
        """Lower-cased ASCII-whitespace-separated tokens of an attribute (``rel``, ``sandbox``, …)."""
        return frozenset(t.lower() for t in (self.attrs.get(name) or "").split())


@dataclass(slots=True)
class InlineScript:
    """Text of an inline ``<script>``; ``line``/``col``/``offset`` are where the script text starts in the page, so
    script line N is page line ``line + N - 1``."""
    text: str
    element: int
    line: int
    col: int
    offset: int
    nonce: str | None
    type: str            # the type attribute lower-cased and trimmed ("" when absent)
    live: bool = True

    @property
    def is_javascript(self) -> bool:
        t = self.type.split(";", 1)[0].strip()
        return t in ("", "module", "text/javascript", "application/javascript", "application/ecmascript",
                     "text/ecmascript", "application/x-javascript", "text/x-javascript", "text/jscript",
                     "text/livescript", "text/javascript1.0", "text/javascript1.1", "text/javascript1.2",
                     "text/javascript1.3", "text/javascript1.4", "text/javascript1.5", "application/x-ecmascript")


@dataclass(slots=True)
class InlineStyle:
    text: str
    element: int
    line: int
    offset: int
    live: bool = True


@dataclass(slots=True)
class Comment:
    text: str
    line: int
    offset: int
    live: bool = True    # False when inside <template>/<noscript>


@dataclass(slots=True)
class Form:
    element: int                 # index of the <form> element
    action: str                  # resolved absolute URL; the document URL when the attribute is absent or empty
    action_attr: str | None      # the raw attribute (None when absent)
    method: str                  # lower-cased attribute, "" when absent (the browser default is GET)
    inputs: list[int] = field(default_factory=list)   # form-associated controls (input, button, select, textarea)
    live: bool = True

    def effective_method(self) -> str:
        return self.method if self.method in ("post", "dialog") else "get"


@dataclass
class ParsedHTML:
    """The light DOM of §2.6 produced by ``htmlparse.parse``. Lists keep document order."""
    url: str
    base_url: str                         # base for URL resolution (<base href> resolved, else the document URL)
    base_href: str | None = None          # raw href of the first <base href>, None when absent
    doctype: str | None = None            # e.g. "html" (None when there is no doctype: quirks mode)
    title: str = ""
    elements: list[Element] = field(default_factory=list)
    inline_scripts: list[InlineScript] = field(default_factory=list)
    inline_styles: list[InlineStyle] = field(default_factory=list)
    comments: list[Comment] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    visible_text: str = ""
    ids: dict[str, int] = field(default_factory=dict)   # first element with each id
    parse_error: str = ""                 # html.parser exception text when parsing stopped early (partial DOM kept)

    def resolve(self, value: str | None) -> str:
        """Resolve an attribute URL like a browser: strip ASCII whitespace, drop tab/newline, join with the base."""
        if value is None:
            return ""
        v = re.sub(r"[\t\n\r]", "", value.strip(" \t\n\r\f"))
        try:
            return urllib.parse.urljoin(self.base_url, v)
        except ValueError:   # e.g. a malformed IPv6 literal
            return v

    def find_all(self, *tags: str, live_only: bool = True) -> list[Element]:
        want = {t.lower() for t in tags}
        return [e for e in self.elements if (not want or e.tag in want) and (e.live or not live_only)]

    def live_elements(self) -> Iterator[Element]:
        return (e for e in self.elements if e.live)

    def metas(self, http_equiv: str | None = None, name: str | None = None, *, head_only: bool = False) -> list[Element]:
        out = []
        for e in self.elements:
            if e.tag != "meta" or not e.live or (head_only and not e.in_head):
                continue
            if http_equiv is not None and (e.attrs.get("http-equiv") or "").strip().lower() != http_equiv.lower():
                continue
            if name is not None and (e.attrs.get("name") or "").strip().lower() != name.lower():
                continue
            out.append(e)
        return out

    def links(self, rel: str | None = None) -> list[Element]:
        return [e for e in self.elements if e.tag == "link" and e.live and (rel is None or rel.lower() in e.tokens("rel"))]

    def password_inputs(self) -> list[Element]:
        return [e for e in self.elements if e.tag == "input" and e.live
                and (e.attrs.get("type") or "").strip().lower() == "password"]

    @property
    def has_password_field(self) -> bool:
        return bool(self.password_inputs())

    def element(self, index: int) -> Element:
        return self.elements[index]

    def ancestors(self, index: int) -> Iterator[Element]:
        p = self.elements[index].parent
        while p >= 0:
            yield self.elements[p]
            p = self.elements[p].parent


@dataclass
class Page:
    """A document response with its parsed DOM (``doc`` is None when the body could not be parsed)."""
    response: Response
    doc: ParsedHTML | None
    depth: int = 0


# ----------------------------------------------------------------------------------------------- options

@dataclass
class ScanOptions:
    profile: str = "standard"             # minimal | standard | deep
    crawl: bool = False
    max_pages: int = 20
    max_depth: int = 2
    delay: float = 0.5
    timeout: float = 20.0
    sensitivity: str = "default"          # strict | default | paranoid
    respect_robots: bool = True
    third_party_lookups: bool = False
    max_requests: int | None = None
    max_bytes: int = 50_000_000
    time_budget: float = 600.0
    cookie_ignore: tuple[str, ...] = ()
    lang: str = "ar"
    # additions (defaults keep the §4.2 shape): §0.7 --no-proxy and the §0.6 per-response wall-clock deadline
    use_proxy: bool = True
    response_deadline: float = 30.0

    @property
    def deep(self) -> bool:
        return self.profile == "deep"

    @property
    def paranoid(self) -> bool:
        return self.sensitivity == "paranoid"

    def reports(self, confidence: str) -> bool:
        """True when a finding of ``confidence`` is shown at this sensitivity (§0.5)."""
        return confidence in SENSITIVITY_CONFIDENCES.get(self.sensitivity, SENSITIVITY_CONFIDENCES["default"])


# ----------------------------------------------------------------------------------------------- stage-1 facts

@dataclass
class CspPolicy:
    """One parsed policy (csp.py, WP4). ``directives`` keeps the first occurrence of each lower-cased name."""
    raw: str
    origin: str                                       # "header" | "meta" | "report-only"
    directives: dict[str, list[str]] = field(default_factory=dict)
    duplicates: list[tuple[str, str]] = field(default_factory=list)   # (name, ignored value) → WEB202
    errors: list[dict] = field(default_factory=list)                  # syntax problems → WEB201 (keys owned by WP4)
    dropped: list[str] = field(default_factory=list)                  # meta-only: ignored directives → WEB207
    element: int | None = None                                        # meta element index for meta policies


@dataclass
class CspFacts:
    """CSP of one response: ``ctx.csp[response]`` (stage 1, ``csp.parse_all``)."""
    enforced: list[CspPolicy] = field(default_factory=list)       # header and meta policies
    report_only: list[CspPolicy] = field(default_factory=list)
    legacy: list[tuple[str, str]] = field(default_factory=list)   # (X-Content-Security-Policy|X-WebKit-CSP, value)
    effective: dict[str, Any] = field(default_factory=dict)       # intersection per directive (shape owned by WP4)
    frame_ancestors: list[str] | None = None   # from enforced *header* policies; None when none sets it
    frame_ancestors_protects: bool = False     # header frame-ancestors restricts framing (not ANY)
    upgrade_insecure_requests: bool = False    # any enforced policy has upgrade-insecure-requests
    nonces: list[str] = field(default_factory=list)   # nonce-source values of enforced policies

    @property
    def has_enforced(self) -> bool:
        return bool(self.enforced)


@dataclass
class HstsVerdict:
    """HSTS as a browser would note it for one host: ``ctx.hsts[host]`` (stage 1, ``transport.hsts_facts``)."""
    host: str
    present: bool = False
    valid: bool = False                 # RFC 6797 grammar ok (WEB112 otherwise)
    max_age: int | None = None
    include_subdomains: bool = False
    preload: bool = False
    preloaded: bool = False             # in the preload snapshot (with include_subdomains when inherited) or a preloaded TLD
    effective: bool = False             # a browser keeps it: https, valid, max_age > 0, no certificate error
    cert_error: bool = False
    header_values: tuple[str, ...] = ()
    problems: tuple[str, ...] = ()      # hstspreload-style issue codes (owned by WP6)
    response: Response | None = None    # the response that was judged


@dataclass
class CookieFact:
    """One parsed ``Set-Cookie`` field (stage 1, ``cookies.parse_and_classify``). ``value`` stays in memory only:
    evidence must use :meth:`redacted`."""
    name: str
    value: str
    attrs: dict[str, str]               # lower-cased attribute names → value ("" when valueless); last one wins
    raw: str
    response: Response
    host: str
    secure_context: bool
    cls: str = "unknown"                # one of COOKIE_CLASSES
    class_source: str = "default"       # table | heuristic | value | default
    deletion: bool = False              # Max-Age <= 0 or Expires in the past (skipped by every rule)
    ignored: bool = False               # on the user's --web-cookie-ignore list
    index: int = 0                      # position among the response's Set-Cookie fields
    expires: datetime | None = None
    max_age: int | None = None

    @property
    def domain(self) -> str | None:
        d = self.attrs.get("domain")
        return d.strip().lstrip(".").lower() if d else None

    @property
    def path(self) -> str | None:
        return self.attrs.get("path")

    @property
    def secure(self) -> bool:
        return "secure" in self.attrs

    @property
    def httponly(self) -> bool:
        return "httponly" in self.attrs

    @property
    def partitioned(self) -> bool:
        return "partitioned" in self.attrs

    @property
    def samesite(self) -> str | None:
        return self.attrs.get("samesite")

    @property
    def is_session_class(self) -> bool:
        return self.cls in SESSION_CLASSES

    def redacted(self) -> str:
        """``name=<redacted:N bytes>; attributes`` for evidence."""
        name, sep, rest = self.raw.partition("=")
        value, semi, attrs = rest.partition(";")
        if not sep:
            return redact_cookie_header(self.raw)
        return f"{name}=<redacted:{len(value.encode('utf-8', 'replace'))} bytes>{semi}{attrs}"


@dataclass(frozen=True)
class DnsRecord:
    """Resolver result for one host: ``ctx.dns[host]`` (filled by http.py's resolver, WP1).

    ``status``: ok | nxdomain (EAI_NONAME) | nodata (EAI_NODATA) | tempfail (EAI_AGAIN, timeout) | not_tested.
    ``canonical`` is ``gethostbyname_ex(host)[0]`` (the CNAME target) and ``aliases`` its index 1 (§WEB901)."""
    host: str
    status: str
    addresses: tuple[str, ...] = ()
    canonical: str = ""
    aliases: tuple[str, ...] = ()
    registrable: str = ""               # eTLD+1 of host (PSL)
    registrable_status: str = ""        # status of the one registrable-domain lookup (WEB517), "" when not looked up
    reason: str = ""                    # why not_tested (e.g. "proxied")
    errno: int | None = None


# ----------------------------------------------------------------------------------------------- issues, evidence

def redact_secret(value: str) -> str:
    """First 4 and last 2 characters (§3.6); short values are fully masked."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}…{value[-2:]}"


def redact_cookie_header(value: str) -> str:
    """A ``Set-Cookie`` value with the cookie value replaced by ``<redacted:N bytes>`` (name and attributes kept)."""
    first, semi, attrs = value.partition(";")
    name, eq, val = first.partition("=")
    if not eq:
        return f"<redacted:{len(first.encode('utf-8', 'replace'))} bytes>{semi}{attrs}"
    return f"{name}=<redacted:{len(val.encode('utf-8', 'replace'))} bytes>{semi}{attrs}"


_CONTROL = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\-_]|[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def strip_controls(text: str) -> str:
    """Remove C0/C1 control characters and ANSI escape sequences (§0.6), keeping tab and newline."""
    return _CONTROL.sub("", text)


def cap(text: str | None, limit: int) -> str:
    if not text:
        return ""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def safe_url(url: str) -> str:
    """Re-serialise a URL with control characters, spaces and non-ASCII percent-encoded (§0.6)."""
    return urllib.parse.quote(url, safe=":/?#[]@!$&'()*+,;=%~-._")


def curl_command(url: str, *, origin: str | None = None, user_agent_value: str | None = None) -> str:
    """One-line ``curl`` reproduction; every argument goes through ``shlex.quote`` (§0.6, §3.6)."""
    args = ["curl", "-sS", "-D", "-", "-o", "/dev/null", "-A", user_agent_value or user_agent()]
    if origin:
        args += ["-H", f"Origin: {origin}"]
    args.append(safe_url(url))
    return " ".join(shlex.quote(a) for a in args)


def openssl_command(host: str, ip: str | None = None, port: int = 443, flag: str = "") -> str:
    """``openssl s_client`` reproduction for TLS findings (``flag`` e.g. ``-tls1``)."""
    target = f"[{ip}]:{port}" if ip and ":" in ip else f"{ip or host}:{port}"
    args = ["openssl", "s_client", "-connect", target, "-servername", host]
    if flag:
        args.append(flag)
    return " ".join(shlex.quote(a) for a in args)


@dataclass
class Evidence:
    """``Finding.extra["evidence"]`` (§3.6). Build it with :meth:`for_response`; strings are capped there."""
    request: dict = field(default_factory=dict)     # {method, url, headers: [[name, value]]}
    chain: list[dict] = field(default_factory=list)  # [{url, status, location}]
    status: int | None = None
    headers: list[list[str]] = field(default_factory=list)   # as received, Set-Cookie values redacted
    match: dict | None = None      # {where: header|body|tls|cookie|dns|probe, name, value, offset, excerpt}
    body_sha256: str = ""
    kind: str = ""
    role: list[str] = field(default_factory=list)
    baseline: dict | None = None   # {url, status, sha256, simhash}
    tls: dict | None = None        # {ip, version, cipher, subject, issuer, not_before, not_after, san, key, sigalg, sha256}
    observed_at: str = ""
    curl: str = ""
    truncated: bool = False

    @classmethod
    def for_response(cls, response: Response | None, *, where: str = "header", name: str = "", value: str = "",
                     offset: int | None = None, excerpt: str = "", now: datetime | None = None,
                     baseline: dict | None = None, tls: dict | None = None, command: str | None = None) -> "Evidence":
        stamp = (now or utcnow()).astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        match = {"where": where, "name": cap(name, 200), "value": cap(value, EVIDENCE_VALUE_CAP),
                 "offset": offset, "excerpt": cap(excerpt, EVIDENCE_EXCERPT_CAP)}
        if response is None:
            return cls(match=match, observed_at=stamp, baseline=baseline, tls=tls, curl=command or "")
        req_headers = [[k, cap(v, 300)] for k, v in response.request_headers if k.lower() in
                       ("user-agent", "accept", "origin", "accept-encoding", "accept-language")]
        headers = []
        for k, v in list(response.headers)[:EVIDENCE_HEADERS_MAX]:
            v = redact_cookie_header(v) if k.lower() == "set-cookie" else v
            headers.append([k, cap(v, EVIDENCE_HEADER_CAP)])
        chain = [{"url": cap(h.url, 2000), "status": h.status, "location": cap(h.headers.first("location"), 2000)}
                 for h in response.chain]
        origin = response.request_headers.first("origin")
        ua = response.request_headers.first("user-agent")
        return cls(request={"method": response.method, "url": cap(response.url, 2000), "headers": req_headers},
                   chain=chain, status=response.status, headers=headers, match=match,
                   body_sha256=response.body_sha256() if response.body else "", kind=response.kind,
                   role=sorted(response.roles), baseline=baseline, tls=tls, observed_at=stamp,
                   curl=command if command is not None else curl_command(response.url, origin=origin, user_agent_value=ua),
                   truncated=response.truncated)

    def to_dict(self) -> dict:
        return {"request": self.request, "chain": self.chain, "status": self.status, "headers": self.headers,
                "match": self.match, "body_sha256": self.body_sha256, "kind": self.kind, "role": self.role,
                "baseline": self.baseline, "tls": self.tls, "observed_at": self.observed_at, "curl": self.curl,
                "truncated": self.truncated}


@dataclass
class Issue:
    """What a check module returns; the engine turns it into a ``model.Finding`` (spec §4.2).

    ``params`` fills the registry's title/advice format strings (cookie name, version, …) and may name a
    ``variant`` (``RuleMeta.variants``). ``severity`` defaults to the rule's default and must be one of
    ``RULES[rule].allowed_severities``; ``confidence`` one of ``RULES[rule].allowed_confidences``.
    ``notes`` are bilingual (en, ar) remarks shown with the finding (e.g. "preloaded")."""
    rule: str
    url: str
    confidence: str
    evidence: Evidence
    params: dict = field(default_factory=dict)
    severity: str | None = None
    group_value: str = ""
    notes: list[tuple[str, str]] = field(default_factory=list)
    host: str = ""                       # defaults to the URL's host (engine)
    ips: tuple[str, ...] = ()            # TLS findings: IPs the issue applies to (§2.8 step 5)


@dataclass
class CheckState:
    """Coverage state of one check (§3.8). ``reasons`` hold (code, en, ar) for every non-pass state."""
    check_id: str
    state: str = "not_tested"
    reasons: list[tuple[str, str, str]] = field(default_factory=list)
    hosts: dict[str, str] = field(default_factory=dict)   # host → state, when recorded per host

    def to_dict(self) -> dict:
        return {"check": self.check_id, "state": self.state,
                "reasons": [{"code": c, "en": en, "ar": ar} for c, en, ar in self.reasons], "hosts": dict(self.hosts)}


@runtime_checkable
class CheckModule(Protocol):
    CHECKS: tuple[str, ...]               # check ids it owns (coverage)

    def run(self, ctx: "ScanContext") -> list[Issue]: ...


# ----------------------------------------------------------------------------------------------- context, result

@dataclass
class ScanContext:
    """Everything a check module may read (spec §4.2). Only the engine fills it; check modules never fetch except
    exposure.py (deep list and baselines) and tls/ (handshakes), through ``fetcher``."""
    options: ScanOptions
    target: str
    entry: Response | None = None                  # final response of the entry chain (owns the chain)
    http_probe: Response | None = None             # http:// counterpart chain (final response)
    https_probe: Response | None = None            # https:// counterpart chain (final response)
    cors: Response | None = None                   # cookieless GET with Origin: CORS_PROBE_ORIGIN
    pages: list[Page] = field(default_factory=list)            # entry document first, then crawled documents
    subresources: list[Response] = field(default_factory=list)  # same-site (and, deep, third-party) scripts/styles
    sourcemaps: list[Response] = field(default_factory=list)
    images: list[Response] = field(default_factory=list)
    wellknown: dict[str, Response] = field(default_factory=dict)  # path → response ("/robots.txt", …)
    probes: list[Response] = field(default_factory=list)          # deep-probe responses (exposure.py)
    tls: dict[str, Any] = field(default_factory=dict)             # per-IP TLS report (shape owned by WP10)
    baselines: list[Response] = field(default_factory=list)       # soft-404 baselines (deep) – natural ones are in wellknown
    robots: Any = None                                            # robots.Robots (WP1) or None
    dns: dict[str, DnsRecord] = field(default_factory=dict)
    proxied: bool = False
    observatory: dict[str, str] = field(default_factory=dict)     # Observatory test → slug
    inventory: dict[str, Any] = field(default_factory=dict)
    coverage: Any = None                                          # coverage.Coverage
    data: Any = None                                              # the webscan.data module (or a stub in tests)
    now: datetime = field(default_factory=utcnow)
    fetcher: Any = None                                           # http.Fetcher (only exposure.py / tls/ may use it)
    # stage-1 facts (§4.2): filled before any check module runs
    csp: dict[Response, CspFacts] = field(default_factory=dict)
    hsts: dict[str, HstsVerdict] = field(default_factory=dict)
    cookies: list[CookieFact] = field(default_factory=list)

    # -- pure helpers --------------------------------------------------------------------------------------
    @property
    def target_host(self) -> str:
        return normalise_host(urllib.parse.urlsplit(self.target).hostname or "")

    def documents(self) -> list[Page]:
        return list(self.pages)

    def all_responses(self, *, include_hops: bool = True) -> list[Response]:
        """Every fetched response once (identity), redirect hops included by default (gate G2)."""
        seen: dict[int, Response] = {}

        def add(r: Response | None) -> None:
            if r is None:
                return
            for h in (r.hops() if include_hops else [r]):
                seen.setdefault(id(h), h)

        for r in (self.entry, self.http_probe, self.https_probe, self.cors):
            add(r)
        for p in self.pages:
            add(p.response)
        for group in (self.subresources, self.sourcemaps, self.images, list(self.wellknown.values()), self.probes,
                      self.baselines):
            for r in group:
                add(r)
        return list(seen.values())

    def hsts_for(self, host: str) -> HstsVerdict | None:
        return self.hsts.get(normalise_host(host))

    def csp_for(self, response: Response) -> CspFacts | None:
        return self.csp.get(response)

    def cookies_for(self, response: Response) -> list[CookieFact]:
        return [c for c in self.cookies if c.response is response]

    def page_for(self, response: Response) -> Page | None:
        for p in self.pages:
            if p.response is response:
                return p
        return None


@dataclass
class WebScanResult:
    """What ``webscan.scan`` returns (engine, WP15a)."""
    target: str
    findings: list = field(default_factory=list)          # model.Finding
    grades: dict = field(default_factory=dict)            # {"kashif": …, "observatory": …, "ssllabs": …}
    coverage: dict = field(default_factory=dict)          # Coverage.to_dict()
    inventory: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)        # Arabic notes (English via i18n), as scan_site returns
    snapshot: dict = field(default_factory=dict)          # store.py web_snapshot (§3.7)
    diff: dict | None = None
    final_url: str = ""
    profile: str = "standard"
    requests: int = 0
    bytes_received: int = 0
    data_date: str = ""                                   # "web data as of <date>"


# ----------------------------------------------------------------------------------------------- URL helpers

def normalise_host(host: str) -> str:
    """Lower-case, no brackets, no trailing dot."""
    h = (host or "").strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h.rstrip(".")


def url_origin(url: str) -> str:
    """``scheme://host[:port]`` with the default port omitted (same-origin = scheme + host + port)."""
    p = urllib.parse.urlsplit(url)
    scheme = p.scheme.lower()
    host = normalise_host(p.hostname or "")
    try:
        port = p.port
    except ValueError:
        port = None
    shown = f"[{host}]" if ":" in host else host
    if port is None or (scheme, port) in (("http", 80), ("https", 443)):
        return f"{scheme}://{shown}"
    return f"{scheme}://{shown}:{port}"


def same_origin(a: str, b: str) -> bool:
    return url_origin(a) == url_origin(b)


__all__ = [
    "PROFILES", "SENSITIVITIES", "CONFIDENCES", "SENSITIVITY_CONFIDENCES", "SARIF_PRECISION", "RESPONSE_SOURCES",
    "RESPONSE_KINDS", "PAGE_ROLES", "CHECK_STATES", "DNS_STATUSES", "COOKIE_CLASSES", "SESSION_CLASSES", "UA_INFO_URL",
    "CORS_PROBE_ORIGIN", "ACCEPT_DOCUMENT", "ACCEPT_PROBE", "ACCEPT_ENCODING", "ACCEPT_LANGUAGE", "user_agent", "utcnow",
    "HeaderList", "normalise_charset", "python_codec", "essence", "charset_param", "bom_encoding", "meta_charset",
    "Response", "ResponseSignature", "Element", "InlineScript", "InlineStyle", "Comment", "Form", "ParsedHTML", "Page",
    "ScanOptions", "CspPolicy", "CspFacts", "HstsVerdict", "CookieFact", "DnsRecord", "redact_secret",
    "redact_cookie_header", "strip_controls", "cap", "safe_url", "curl_command", "openssl_command", "Evidence", "Issue",
    "CheckState", "CheckModule", "ScanContext", "WebScanResult", "normalise_host", "url_origin", "same_origin",
]
