"""Response classification and soft-404 baselines (spec §3.1, §3.2, §WEB315), WP2.

Everything here is pure: no function fetches, and the only state is a per-response signature cache. The engine
calls :func:`classify_context` once after fetching (it sets ``kind``, ``roles`` and ``flags`` on every response and
marks soft 404s), then :func:`mark_sensitive` in the stage-1 facts pass. Check modules may import the pure functions
:func:`signature` and :func:`similar` (§4.2 import rule); the other helpers are for the engine, exposure.py's deep
probe and tests.

Kinds (§3.1, first match wins): ``error`` → ``informational``/``no_content``/``not_modified`` → ``redirect`` →
``waf_challenge`` → ``rate_limited`` → ``error_page`` → by Content-Type essence → sniffed (no Content-Type) →
``soft404`` (overrides the last two when the response matches the host's soft-404 baseline, §3.2).

Flags written here: ``sniffed`` (kind came from magic bytes), ``magic:<mime>`` (what the body's magic bytes say;
headers.py reads it for WEB313 without importing this module), ``ctype-mismatch`` (declared type contradicts the
magic bytes as WEB313 defines it), ``waf:<provider-id>``, ``rate-limited``, ``soft404``, ``catch-all`` (a natural
baseline that proved the host answers every path), ``sensitive`` (§WEB315, :func:`mark_sensitive`), ``truncated-body``
and ``opaque-coding`` (body not decodable: br, zstd, …; body rules must not read it, §0.6).
"""

from __future__ import annotations

import html as _html
import json
import re
import secrets
import urllib.parse
import weakref
from dataclasses import dataclass, field
from typing import Callable, Iterable, Sequence

from . import simhash as _sh
from .types import CookieFact, ParsedHTML, Response, ResponseSignature, ScanContext, normalise_host

# ----------------------------------------------------------------------------------------------- user-facing text

# (en, ar) pairs; ``{provider}``/``{status}`` are filled by the caller. No counts here, so no plural forms needed.
STR: dict[str, tuple[str, str]] = {
    "waf": ("The response is a {provider} challenge or block page; checks that need the real page could not run.",
            "الاستجابة صفحة تحدٍّ أو حظر من {provider}؛ تعذّر تشغيل الفحوص التي تحتاج إلى الصفحة الحقيقية."),
    "rate_limited": ("The server limited the request rate (HTTP {status}); results for this host are partial.",
                     "قيّد الخادم معدل الطلبات (HTTP {status})؛ نتائج هذا المضيف جزئية."),
    "catch_all": ("The host answers every path with the same page (catch-all); pages that match it are treated as "
                  "soft 404s.",
                  "يجيب المضيف عن كل مسار بالصفحة نفسها؛ لذا تُعامَل الصفحات المطابقة لها على أنها صفحات «غير موجود» "
                  "مقنَّعة."),
    "soft404": ("This response matches the host's not-found page (soft 404), so it is not judged as a real page.",
                "هذه الاستجابة تطابق صفحة «غير موجود» لدى المضيف (404 مقنَّعة)، فلا تُقيَّم على أنها صفحة حقيقية."),
    "real_404": ("The host returns real 404 responses for paths that do not exist.",
                 "يعيد المضيف استجابات 404 حقيقية للمسارات غير الموجودة."),
    "opaque": ("The body uses the content coding {coding}, which Kashif did not request and cannot decode; body checks "
               "were skipped.",
               "يستخدم جسم الاستجابة الترميز {coding} الذي لم يطلبه كاشف ولا يستطيع فكّه؛ لذا تُخطّيت فحوص الجسم."),
}

# ----------------------------------------------------------------------------------------------- kinds

HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
JSON_TYPES = frozenset({"application/json", "text/json", "application/x-json"})
XML_TYPES = frozenset({"application/xml", "text/xml"})
JS_TYPES = frozenset({"text/javascript", "application/javascript", "application/x-javascript", "application/ecmascript",
                      "text/ecmascript", "text/jscript", "application/x-ecmascript", "text/x-javascript",
                      "text/livescript", "application/x-js"})
DOWNLOAD_TYPES = frozenset({
    "application/pdf", "application/octet-stream", "application/zip", "application/x-zip-compressed", "application/gzip",
    "application/x-gzip", "application/x-tar", "application/x-gtar", "application/x-bzip2", "application/x-bzip",
    "application/x-xz", "application/x-7z-compressed", "application/x-rar-compressed", "application/vnd.rar",
    "application/java-archive", "application/x-java-archive", "application/x-msdownload", "application/x-msdos-program",
    "application/x-executable", "application/x-elf", "application/vnd.microsoft.portable-executable",
    "application/x-apple-diskimage", "application/vnd.debian.binary-package", "application/x-rpm",
    "application/x-sqlite3", "application/vnd.sqlite3", "application/msword", "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint", "application/x-shockwave-flash", "application/postscript",
})
FONT_TYPES = frozenset({"application/vnd.ms-fontobject", "application/font-woff", "application/x-font-ttf"})
# kinds a soft-404 match may override (rows 7 and 8 of §3.1)
CONTENT_KINDS = frozenset({"document", "api_json", "api_xml", "script", "style", "image", "font", "media", "download",
                           "text", "other"})
DECODED_CODINGS = frozenset({"", "identity", "gzip", "x-gzip", "deflate"})


def _attachment(response: Response) -> bool:
    cd = response.headers.first("content-disposition")
    return bool(cd) and cd.split(";", 1)[0].strip().lower() == "attachment"


def kind_for_essence(ess: str, body: bytes = b"") -> str | None:
    """Kind from a Content-Type essence (row 7 of §3.1); ``None`` when the essence is empty."""
    if not ess:
        return None
    if ess in HTML_TYPES:
        return "document"
    if ess.startswith("image/"):
        return "image"
    if ess in JSON_TYPES or ess.endswith("+json"):
        return "api_json"
    if ess in XML_TYPES or ess.endswith("+xml"):
        return "document" if xml_root(body) == "html" else "api_xml"
    if ess in JS_TYPES:
        return "script"
    if ess == "text/css":
        return "style"
    if ess.startswith("font/") or ess.startswith("application/font-") or ess.startswith("application/x-font-") \
            or ess in FONT_TYPES:
        return "font"
    if ess.startswith("audio/") or ess.startswith("video/"):
        return "media"
    if ess in DOWNLOAD_TYPES or ess.startswith("application/vnd.openxmlformats-") \
            or ess.startswith("application/vnd.oasis.opendocument."):
        return "download"
    if ess.startswith("text/"):          # text/plain (spec) and the other text/* types (csv, markdown, …)
        return "text"
    return "other"


# ----------------------------------------------------------------------------------------------- magic sniffing

_WS_BYTES = b"\t\n\x0c\r "
# WHATWG MIME Sniffing §7.1 "HTML" patterns (case-insensitive, followed by a tag-terminating byte)
_HTML_SNIFF = (b"<!doctype html", b"<html", b"<head", b"<script", b"<iframe", b"<h1", b"<div", b"<font", b"<table",
               b"<a", b"<style", b"<title", b"<b", b"<body", b"<br", b"<p", b"<!--")
# (offset, prefix, mime label)
_MAGIC: tuple[tuple[int, bytes, str], ...] = (
    (0, b"%PDF-", "application/pdf"),
    (0, b"%!PS-Adobe-", "application/postscript"),
    (0, b"\x89PNG\r\n\x1a\n", "image/png"),
    (0, b"GIF87a", "image/gif"),
    (0, b"GIF89a", "image/gif"),
    (0, b"\xff\xd8\xff", "image/jpeg"),
    (0, b"\x00\x00\x01\x00", "image/x-icon"),
    (0, b"\x00\x00\x02\x00", "image/x-icon"),
    (0, b"OggS\x00", "audio/ogg"),
    (0, b"ID3", "audio/mpeg"),
    (0, b"fLaC", "audio/flac"),
    (0, b"\x1aE\xdf\xa3", "video/webm"),
    (0, b"wOFF", "font/woff"),
    (0, b"wOF2", "font/woff2"),
    (0, b"OTTO", "font/otf"),
    (0, b"ttcf", "font/collection"),
    (0, b"\x00\x01\x00\x00\x00", "font/ttf"),
    (0, b"PK\x03\x04", "application/zip"),
    (0, b"PK\x05\x06", "application/zip"),
    (0, b"\x1f\x8b\x08", "application/gzip"),
    (0, b"Rar!\x1a\x07", "application/vnd.rar"),
    (0, b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (0, b"\xfd7zXZ\x00", "application/x-xz"),
    (0, b"\x7fELF", "application/x-executable"),
    (0, b"\xfe\xed\xfa\xce", "application/x-mach-binary"),
    (0, b"\xfe\xed\xfa\xcf", "application/x-mach-binary"),
    (0, b"\xce\xfa\xed\xfe", "application/x-mach-binary"),
    (0, b"\xcf\xfa\xed\xfe", "application/x-mach-binary"),
    (0, b"\x00\x00\x00\x01Bud1", "application/x-apple-ds-store"),
    (0, b"SQLite format 3\x00", "application/vnd.sqlite3"),
    (0, b"\xac\xed\x00\x05", "application/x-java-serialized-object"),
    (257, b"ustar", "application/x-tar"),
)
ARCHIVE_OR_EXECUTABLE = frozenset({"application/zip", "application/gzip", "application/vnd.rar",
                                   "application/x-7z-compressed", "application/x-xz", "application/x-bzip2",
                                   "application/x-tar", "application/x-executable", "application/x-msdownload",
                                   "application/x-mach-binary"})
_XML_ROOT = re.compile(r"<([A-Za-z_][\w.:-]*)")
_XML_SKIP = re.compile(r"\s*(?:<\?.*?\?>|<!--.*?-->|<!DOCTYPE[^>\[]*(?:\[.*?\])?\s*>)", re.S | re.I)


def xml_root(body: bytes) -> str | None:
    """Local name (lower-case) of the root element of an XML body, skipping the declaration, comments and doctype."""
    if not body:
        return None
    text = body[:4096].lstrip(b"\xef\xbb\xbf").decode("utf-8", "replace")
    pos = 0
    while True:
        m = _XML_SKIP.match(text, pos)
        if not m or m.end() == pos:
            break
        pos = m.end()
    m = _XML_ROOT.match(text, len(text) - len(text[pos:].lstrip()))
    if not m:
        return None
    return m.group(1).split(":")[-1].lower()


def _json_like(rest: bytes) -> bool:
    """``rest`` starts with ``{`` or ``[`` (whitespace skipped): plausible JSON (not CSS or a JS block)."""
    head = rest[:1]
    after = rest[1:200].lstrip(_WS_BYTES)[:1]
    if head == b"{":
        return after in (b'"', b"}")
    if head == b"[":
        return after == b"" or after in b'{["-0123456789tfn]'
    return False


def sniff(body: bytes) -> str | None:
    """MIME label the body's magic bytes indicate (WHATWG-style), or ``None``: ``text/html``, ``text/xml``,
    ``image/svg+xml``, ``application/json``, image/audio/video/font types, archives, executables, PDF, …"""
    if not body:
        return None
    for off, prefix, label in _MAGIC:
        if body[off:off + len(prefix)] == prefix:
            if label == "font/ttf" and len(body) < 12:
                continue
            return label
    if body[:4] == b"RIFF" and len(body) >= 12:
        return {b"WEBP": "image/webp", b"WAVE": "audio/wav", b"AVI ": "video/x-msvideo"}.get(body[8:12])
    if body[4:8] == b"ftyp":
        return "video/mp4"
    if body[:2] == b"MZ" and len(body) >= 64:
        lfanew = int.from_bytes(body[60:64], "little")
        if body[lfanew:lfanew + 4] == b"PE\x00\x00" or lfanew == 0 or len(body) < lfanew + 4:
            return "application/x-msdownload"
    if body[:3] == b"BZh" and body[3:4].isdigit():
        return "application/x-bzip2"
    rest = body.lstrip(b"\xef\xbb\xbf").lstrip(_WS_BYTES)
    low = rest[:32].lower()
    for pat in _HTML_SNIFF:
        if low.startswith(pat):
            nxt = low[len(pat):len(pat) + 1]
            if pat == b"<!--" or nxt in (b" ", b">", b"\t", b"\n", b"\r", b"\x0c", b"/"):
                return "text/html"
    if low.startswith(b"<?xml"):
        root = xml_root(rest)
        return {"html": "text/html", "svg": "image/svg+xml"}.get(root or "", "text/xml")
    if low.startswith(b"<svg"):
        return "image/svg+xml"
    if _json_like(rest):
        return "application/json"
    return None


def sniffed_kind(label: str | None) -> str | None:
    """Kind for a sniffed MIME label (row 8 of §3.1)."""
    if not label:
        return None
    if label == "text/html":
        return "document"
    if label == "text/xml":
        return "api_xml"
    if label == "application/json":
        return "api_json"
    top = label.split("/", 1)[0]
    return {"image": "image", "audio": "media", "video": "media", "font": "font"}.get(top, "download")


def _strict_json(body: bytes) -> bool:
    if len(body) > 1_000_000:
        return _json_like(body.lstrip(_WS_BYTES))
    try:
        json.loads(body.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError):
        return False
    return True


def ctype_mismatch(response: Response) -> tuple[str, str] | None:
    """``(declared essence, sniffed label)`` when the declared Content-Type contradicts the magic bytes in one of the
    ways WEB313 names: HTML served as ``image/*``, JSON served as ``text/html``, an archive or executable served as
    ``text/*``. ``None`` otherwise (and for empty or undecodable bodies)."""
    declared = response.essence
    if not declared or not response.body or _opaque(response):
        return None
    label = sniff(response.body)
    if not label:
        return None
    if label == "text/html" and declared.startswith("image/"):
        return declared, label
    if label == "application/json" and declared == "text/html" and _strict_json(response.body):
        return declared, label
    if label in ARCHIVE_OR_EXECUTABLE and declared.startswith("text/"):
        return declared, label
    return None


def _opaque(response: Response) -> bool:
    enc = (response.encoding or "").strip().lower()
    if not enc:
        return False
    return any(tok.strip() not in DECODED_CODINGS for tok in enc.split(","))


# ----------------------------------------------------------------------------------------------- WAF / challenge

WAF_PROVIDERS: dict[str, str] = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "cloudfront": "AWS CloudFront",
    "aws-waf": "AWS WAF",
    "imperva": "Imperva Incapsula",
    "sucuri": "Sucuri",
    "f5-asm": "F5 BIG-IP ASM",
    "azure-front-door": "Azure Front Door",
    "datadome": "DataDome",
    "perimeterx": "PerimeterX (HUMAN)",
    "recaptcha": "Google reCAPTCHA",
}
_WAF_TEXT_CAP = 65536


def _waf_text(response: Response) -> str:
    if not response.body or _opaque(response):
        return ""
    return _html.unescape(response.text()[:_WAF_TEXT_CAP])


def waf_provider(response: Response) -> str | None:
    """Provider id (a key of :data:`WAF_PROVIDERS`) when ``response`` is a WAF/CDN challenge or block page (§3.1).

    Only signatures of normal responses are used; nothing is ever sent to provoke them."""
    st = response.status
    if st is None:
        return None
    h = response.headers
    server = (h.first("server") or "").strip().lower()
    text: str | None = None

    def body() -> str:
        nonlocal text
        if text is None:
            text = _waf_text(response)
        return text

    # 1 Cloudflare: the official header, or Server: cloudflare + 403/503 + challenge markup
    if (h.first("cf-mitigated") or "").strip().lower() == "challenge":
        return "cloudflare"
    if server == "cloudflare" and st in (403, 503):
        b = body()
        if re.search(r"<title>\s*Just a moment\.\.\.\s*</title>", b, re.I) or "cf-chl-" in b or "challenge-platform" in b:
            return "cloudflare"
    # 2 Akamai: AkamaiGHost + 403 + "Reference #"
    if server.startswith("akamaighost") and st == 403 and re.search(r"Reference\s*#\s*[0-9a-f]", body(), re.I):
        return "akamai"
    # 3 AWS CloudFront error + 403
    if st == 403 and "error from cloudfront" in (h.first("x-cache") or "").lower():
        return "cloudfront"
    # 4 AWS WAF: 403/405 + x-amzn-waf-action, or the aws-waf-token challenge
    if st in (403, 405):
        if h.has("x-amzn-waf-action"):
            return "aws-waf"
        if any("aws-waf-token" in v for v in h.get_all("set-cookie")) or "aws-waf-token" in body():
            return "aws-waf"
    # 5 Imperva / Incapsula: the incident page, or x-iinfo on an error status (x-iinfo alone is on every response)
    if "Incapsula incident ID" in body() or ("_Incapsula_Resource" in body() and st >= 400):
        return "imperva"
    if h.has("x-iinfo") and st >= 400 and ("incapsula" in body().lower() or st in (403, 429)):
        return "imperva"
    # 6 Sucuri: x-sucuri-id + 403 + the firewall page
    if st == 403 and (h.has("x-sucuri-id") or h.has("x-sucuri-block") or server.startswith("sucuri")) \
            and "Sucuri WebSite Firewall" in body():
        return "sucuri"
    # 7 F5 BIG-IP ASM block page (often served with 200)
    b = body()
    if "The requested URL was rejected. Please consult with your administrator." in b and re.search(r"support ID", b, re.I):
        return "f5-asm"
    # 8 Azure Front Door: 403 + x-azure-ref + "The request is blocked."
    if st == 403 and h.has("x-azure-ref") and "The request is blocked." in b:
        return "azure-front-door"
    # 9 DataDome: its headers + 403
    if st == 403 and (h.has("x-datadome") or h.has("x-dd-b") or h.has("x-datadome-cid")):
        return "datadome"
    # 10 PerimeterX (HUMAN): the captcha element or "Press & Hold" on a block status
    if "_pxCaptcha" in b or 'id="px-captcha"' in b or (st in (403, 429) and "Press & Hold" in b
                                                         and re.search(r"_px|perimeterx|px-cdn|human", b, re.I)):
        return "perimeterx"
    # 11 Google reCAPTCHA interstitial, only on 403/429
    if st in (403, 429) and re.search(r"google\.com/recaptcha|recaptcha/api\.js|class=[\"']g-recaptcha", b, re.I):
        return "recaptcha"
    return None


def waf_name(provider_id: str | None) -> str:
    """Display name of a provider id (brand names are the same in English and Arabic)."""
    return WAF_PROVIDERS.get(provider_id or "", provider_id or "")


def is_rate_limited(response: Response) -> bool:
    """429, or 503 with ``Retry-After`` (row 5 of §3.1)."""
    return response.status == 429 or (response.status == 503 and response.headers.has("retry-after"))


# ----------------------------------------------------------------------------------------------- kind

def kind_of(response: Response) -> tuple[str, frozenset[str]]:
    """``(kind, flags)`` of a response by rows 1–8 of §3.1 (soft-404 matching is separate: :class:`Soft404Index`)."""
    flags: set[str] = set()
    if response.truncated:
        flags.add("truncated-body")
    opaque = _opaque(response)
    if opaque:
        flags.add("opaque-coding")
    st = response.status
    if response.error or st is None:
        return "error", frozenset(flags)
    if 100 <= st < 200:
        return "informational", frozenset(flags)
    if st in (204, 205):
        return "no_content", frozenset(flags)
    if st == 304:
        return "not_modified", frozenset(flags)
    if response.is_redirect:
        return "redirect", frozenset(flags)
    waf = waf_provider(response)
    if waf:
        flags.add(f"waf:{waf}")
        return "waf_challenge", frozenset(flags)
    if is_rate_limited(response):
        flags.add("rate-limited")
        return "rate_limited", frozenset(flags)
    if st >= 400:
        return "error_page", frozenset(flags)
    label = None if opaque else sniff(response.body)
    if label:
        flags.add(f"magic:{label}")
    if not opaque and ctype_mismatch(response):
        flags.add("ctype-mismatch")
    if _attachment(response):
        return "download", frozenset(flags)
    ess = response.essence
    if ess:
        return kind_for_essence(ess, b"" if opaque else response.body) or "other", frozenset(flags)
    k = sniffed_kind(label)
    if k:
        flags.add("sniffed")
        return k, frozenset(flags)
    return "other", frozenset(flags)


# ----------------------------------------------------------------------------------------------- page roles

_LOGIN_ACTION = re.compile(r"/(?:log-?in|sign-?in|auth(?:enticate|orize)?|sessions?|wp-login\.php|j_security_check)"
                           r"(?=$|[/?#.;_-])", re.I)
_LOGOUT = re.compile(r"log[-_ ]?out|sign[-_ ]?out|log[-_ ]?off|sign[-_ ]?off", re.I)
_ACCOUNT_MARKERS = frozenset({"user-menu", "usermenu", "account-menu", "accountmenu", "user-dropdown",
                              "account-dropdown", "logged-in", "is-logged-in", "user-avatar", "wpadminbar"})
_ADMIN_PATH = re.compile(r"/(?:admin|administrator|wp-admin|manage|dashboard|cpanel)(?=$|[/?#._-])", re.I)
_ADMIN_TEXT = re.compile(r"\badmin\b|administration|administrator|dashboard|control panel|cpanel|phpmyadmin|"
                         r"لوحة التحكم|الإدارة|لوحة الإدارة", re.I)
_ADMIN_IDS = frozenset({"adminmenu", "wpadminbar", "wpbody", "admin-header", "admin-menu", "pma_navigation",
                        "site-name", "content-main"})
_API_DOC_IDS = frozenset({"swagger-ui", "redoc", "graphiql", "api-reference", "graphql-playground", "rapidoc"})
_API_DOC_TAGS = frozenset({"redoc", "rapi-doc", "elements-api", "graphiql"})
_API_DOC_SRC = re.compile(r"swagger-ui|redoc(?:\.standalone)?|graphiql|graphql-playground|rapidoc|"
                          r"@scalar/api-reference|@stoplight/elements", re.I)
_API_DOC_TITLE = re.compile(r"^\s*(?:swagger ui|redoc|graphiql|graphql playground|api reference|api docs?)\b", re.I)
_SPA_IDS = frozenset({"root", "app", "__next", "__nuxt", "svelte", "q-app", "___gatsby", "main-app", "react-root"})
_SPA_ATTRS = ("ng-app", "ng-version", "data-reactroot", "data-v-app", "data-server-rendered")
_ERROR_STRONG = re.compile(r"\b(?:404|410)\b|not\s+found|page\s+(?:does\s*n[o']t|doesn't)\s+exist|no\s+such\s+page|"
                           r"page\s+not\s+available|غير\s+موجود|الصفحة\s+غير", re.I)
_ERROR_WEAK = re.compile(r"\berror\b|\b5\d\d\b|خطأ", re.I)
_H1 = re.compile(r"<h1\b[^>]*>(.*?)</h1\s*>", re.I | re.S)
_TAGS = re.compile(r"<[^>]*>")


def listing_server(text: str) -> str | None:
    """Server whose automatic directory listing ``text`` (decoded HTML) is, per the WEB055 signature table, or
    ``None``. A title alone is not enough: a link to ``../``, a sort link or the parent-directory entry is required."""
    if not text:
        return None
    t = text[:262144]
    low = t.lower()
    parent = bool(re.search(r"""href\s*=\s*["']?\.\./?["'\s>]""", t, re.I)) or "parent directory" in low
    sort = "?c=n;o=d" in low or "?c=m;o=a" in low or "?c=s;o=a" in low
    if "[to parent directory]" in low:
        return "IIS"
    title = re.search(r"<title\b[^>]*>(.*?)</title", t, re.I | re.S)
    title_s = _html.unescape(title.group(1)).strip() if title else ""
    if title_s.lower().startswith("index of /"):
        if sort:
            return "Apache"
        if '<div class="list">' in low and parent:
            return "lighttpd"
        if re.search(r"<h1[^>]*>\s*index of /", t, re.I) and parent:
            return "nginx" if not ("apache" in low and "server at" in low) else "Apache"
        if parent:
            return "Apache"
    if re.search(r"directory listing for /", low) and "<a href" in low:
        return "Python"
    if "directory listing for /" in low and ("tomcat" in low or "<table" in low):
        return "Tomcat"
    if title_s.lower().startswith("directory: /") and (parent or "<a href" in low):
        return "Jetty"
    if title_s.startswith("/") and 'class="listing"' in low:
        return "Caddy"
    if 'id="files"' in low and title_s.lower().startswith("listing directory"):
        return "serve-index"
    return None


def _first_h1(text: str) -> str:
    m = _H1.search(text[:131072])
    return " ".join(_html.unescape(_TAGS.sub(" ", m.group(1))).split()) if m else ""


def _form_role(doc: ParsedHTML, inputs: Sequence[int]) -> set[str]:
    pw = [doc.elements[i] for i in inputs if doc.elements[i].tag == "input" and doc.elements[i].live
          and (doc.elements[i].attrs.get("type") or "").strip().lower() == "password"]
    if not pw:
        return set()
    acs = [(e.attrs.get("autocomplete") or "").strip().lower().split() for e in pw]
    new = any("new-password" in a for a in acs)
    current = any("current-password" in a for a in acs)
    if new or len(pw) >= 2:
        return {"signup", "login"} if current else {"signup"}
    return {"login"}


def page_roles(response: Response, doc: ParsedHTML | None) -> frozenset[str]:
    """Multi-label page roles of a document (§3.1 table). ``doc`` is its light DOM (parsed here when ``None``)."""
    if doc is None:
        from . import htmlparse
        doc = htmlparse.parse_response(response)
    roles: set[str] = set()
    text = response.text()
    els = doc.elements

    # login / signup: password fields grouped by form (controls outside a form form one group)
    in_form: set[int] = set()
    for f in doc.forms:
        if not f.live:
            continue
        in_form.update(f.inputs)
        roles |= _form_role(doc, f.inputs)
        path = urllib.parse.urlsplit(f.action or "").path
        hidden_delete = any(els[i].tag == "input" and (els[i].attrs.get("name") or "") == "_method"
                            and (els[i].attrs.get("value") or "").strip().lower() == "delete" for i in f.inputs)
        if f.action_attr is not None and _LOGIN_ACTION.search(path) and not _LOGOUT.search(path) and not hidden_delete:
            roles.add("login")
    loose = [e.index for e in els if e.tag == "input" and e.index not in in_form and e.form < 0]
    roles |= _form_role(doc, loose)

    # authenticated: a logout link/form or an account-menu marker
    for e in els:
        if not e.live:
            continue
        for attr in ("href", "action", "formaction"):
            v = e.attrs.get(attr)
            if v and _LOGOUT.search(v):
                roles.add("authenticated")
        markers = {e.attrs.get("id", "").strip().lower(), *e.tokens("class")}
        if markers & _ACCOUNT_MARKERS:
            roles.add("authenticated")
        if "authenticated" in roles:
            break

    title = doc.title or ""
    h1 = _first_h1(text)
    # admin: admin path and (login form or admin markers)
    path = response.parsed_url.path or "/"
    if _ADMIN_PATH.search(path):
        ids = {e.attrs.get("id", "").strip().lower() for e in els if e.live}
        if "login" in roles or _ADMIN_TEXT.search(title) or _ADMIN_TEXT.search(h1) or ids & _ADMIN_IDS:
            roles.add("admin")

    # api_docs: swagger-ui / redoc / graphiql / openapi viewers
    for e in els:
        if not e.live:
            continue
        if e.tag in _API_DOC_TAGS or (e.attrs.get("id") or "").strip().lower() in _API_DOC_IDS or "spec-url" in e.attrs:
            roles.add("api_docs")
            break
        src = e.attrs.get("src") if e.tag == "script" else e.attrs.get("href") if e.tag == "link" else None
        if src and _API_DOC_SRC.search(src):
            roles.add("api_docs")
            break
    if _API_DOC_TITLE.search(title):
        roles.add("api_docs")

    # error: a 2xx document whose title/h1 says not found / error (a soft error page)
    if response.is_2xx:
        for s in (title, h1):
            if s and (_ERROR_STRONG.search(s) or (_ERROR_WEAK.search(s) and len(s.split()) <= 5)):
                roles.add("error")
                break

    # listing: directory-listing signature (WEB055)
    if listing_server(text):
        roles.add("listing")

    # app: an SPA shell (root element, little text, scripts)
    scripts = [e for e in els if e.tag == "script" and e.live]
    words = len(doc.visible_text.split())
    root = any(e.live and ((e.attrs.get("id") or "").strip().lower() in _SPA_IDS or e.tag == "app-root"
                           or any(a in e.attrs for a in _SPA_ATTRS)) for e in els)
    links = sum(1 for e in els if e.tag == "a" and e.live and e.attrs.get("href"))
    if scripts and ((root and words < 80) or (len(scripts) >= 3 and words < 20 and links == 0)):
        roles.add("app")

    # static: none of the above, no form, no script, no inline event handler, no javascript: URL
    if not roles:
        dynamic = any(f.live for f in doc.forms) or bool(scripts) or any(
            e.live and (any(a.startswith("on") and len(a) > 2 for a in e.attrs)
                        or (e.attrs.get("href") or "").strip().lower().startswith("javascript:")) for e in els)
        if not dynamic:
            roles.add("static")
    return frozenset(roles)


# ----------------------------------------------------------------------------------------------- classify

def classify(response: Response, doc: ParsedHTML | None = None) -> Response:
    """Set ``kind``, ``roles`` (documents only) and the flags above on ``response`` and return it. Idempotent; flags
    set by others (``sensitive``, ``obs-fold``, ``soft404``, …) are kept, and an earlier ``soft404`` verdict stays."""
    kind, flags = kind_of(response)
    keep_soft = response.kind == "soft404" and kind in CONTENT_KINDS
    response.flags = frozenset(response.flags) | flags
    response.kind = "soft404" if keep_soft else kind
    if kind == "document" and response.body and "opaque-coding" not in flags:
        response.roles = page_roles(response, doc)
    else:
        response.roles = frozenset()
    return response


# ----------------------------------------------------------------------------------------------- sensitivity (§WEB315)

_SENSITIVE_ROLES = frozenset({"login", "authenticated", "admin"})


def is_sensitive(response: Response, *, cookies: Sequence[CookieFact] = (), doc: ParsedHTML | None = None) -> bool:
    """§WEB315: the response sets a session/auth cookie (``cookies`` are that response's parsed Set-Cookie facts), the
    document has a password field (``doc``), the page role is login/authenticated/admin (``response.roles``), the
    status is 401, or ``Vary`` contains Cookie/Authorization."""
    if response.status == 401:
        return True
    if any(c.is_session_class and not c.deletion and not c.ignored for c in cookies):
        return True
    if doc is not None and doc.has_password_field:
        return True
    if response.roles & _SENSITIVE_ROLES:
        return True
    for v in response.headers.get_all("vary"):
        for tok in v.split(","):
            if tok.strip().lower() in ("cookie", "authorization"):
                return True
    return False


def mark_sensitive(ctx: ScanContext) -> int:
    """Stage-1 helper for the engine: add the ``sensitive`` flag to every response that :func:`is_sensitive` says is
    sensitive (using ``ctx.cookies`` and each page's DOM). Returns how many were flagged."""
    by_resp: dict[int, list[CookieFact]] = {}
    for c in ctx.cookies:
        by_resp.setdefault(id(c.response), []).append(c)
    docs = {id(p.response): p.doc for p in ctx.pages}
    n = 0
    for r in ctx.all_responses():
        if is_sensitive(r, cookies=by_resp.get(id(r), ()), doc=docs.get(id(r))):
            r.flags = frozenset(r.flags) | {"sensitive"}
            n += 1
    return n


# ----------------------------------------------------------------------------------------------- signatures (§3.2)

_SIG_CACHE: "weakref.WeakKeyDictionary[Response, tuple[int, int, ResponseSignature]]" = weakref.WeakKeyDictionary()
SHORT_BODY = 512


def _is_html_body(response: Response) -> bool:
    ess = response.essence
    if ess in HTML_TYPES:
        return True
    return not ess and sniff(response.body) == "text/html"


def signature(response: Response) -> ResponseSignature:
    """Soft-404 signature of ``response`` (§3.2): status, content-type essence, body length, body SHA-256 and a 64-bit
    simhash of the normalised visible text (HTML) or 4-byte shingles (other bodies), after removing the requested
    path, query values, dates, times, numbers of ≥ 4 digits and hex runs of ≥ 16."""
    key = (id(response.body), len(response.body))
    cached = _SIG_CACHE.get(response)
    if cached is not None and cached[:2] == key:
        return cached[2]
    body = response.body
    if not body:
        sh = 0
    elif _is_html_body(response) and not _opaque(response):
        sh = _sh.simhash64(_sh.html_features(response.text(), response.url))
    else:
        sh = _sh.simhash64(_sh.bytes_features(body, response.url))
    sig = ResponseSignature(status=response.status, essence=response.essence, length=len(body),
                            sha256=response.body_sha256(), simhash=sh, url=response.url)
    _SIG_CACHE[response] = (*key, sig)
    return sig


def _status_class(status: int | None) -> int | None:
    return None if status is None else status // 100


def similar(a: ResponseSignature, b: ResponseSignature) -> bool:
    """§3.2: same status class and same essence and (equal SHA-256, or simhash Hamming distance ≤ 3, or — for bodies
    under 512 bytes — |len − len_b| ≤ max(64, 5 % of len_b))."""
    return _similar_reason(a, b) is not None


def _similar_reason(a: ResponseSignature, b: ResponseSignature) -> str | None:
    if _status_class(a.status) != _status_class(b.status) or a.essence != b.essence:
        return None
    if a.sha256 == b.sha256:
        return "sha256"
    if a.length < SHORT_BODY and b.length < SHORT_BODY and abs(a.length - b.length) <= max(64, b.length * 5 // 100):
        return "length"
    if (a.length and b.length) and _sh.hamming(a.simhash, b.simhash) <= _sh.SIMILAR_DISTANCE:
        return "simhash"
    return None


# ----------------------------------------------------------------------------------------------- soft-404 baselines

BASELINE_PREFIX = "kashif-404-"
EXT_CLASSES = ("none", "php", "text", "data")
BASELINE_EXT = {"none": "", "php": ".php", "text": ".txt", "data": ".json"}
MAX_BASELINES_PER_HOST = 5           # 1 root + 4 (directory, extension class) baselines (§0.1, §3.2)
MAX_BASELINES_PER_SCAN = 10
NATURAL_PATHS = ("/robots.txt", "/.well-known/security.txt", "/security.txt", "/favicon.ico")
_PHP_EXT = frozenset({"php", "php3", "php4", "php5", "php7", "phtml", "phar", "inc", "asp", "aspx", "ashx", "asmx",
                      "jsp", "jspx", "do", "action", "cgi", "pl", "cfm"})
_DATA_EXT = frozenset({"json", "xml", "yaml", "yml", "wsdl", "jsonld"})
_PAGE_EXT = frozenset({"html", "htm", "xhtml", "shtml", ""})
_BASELINE_NAME = re.compile(r"^kashif-404-[0-9a-f]{16}(?:\.[a-z]+)?$")


def ext_class(path: str) -> str:
    """Extension class of the last path segment: ``none`` (no extension, a directory, .html), ``php`` (server-side
    script extensions), ``data`` (.json/.xml/.yaml) or ``text`` (dot-files and every other file extension: .txt,
    .env, .log, .sql, .bak, archives, …)."""
    name = (path or "/").rsplit("/", 1)[-1]
    if not name:
        return "none"
    if name.startswith(".") and name.count(".") == 1:
        return "text"                     # .env, .htaccess, .DS_Store
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext in _PAGE_EXT:
        return "none"
    if ext in _PHP_EXT:
        return "php"
    if ext in _DATA_EXT:
        return "data"
    return "text"


def directory_of(path: str) -> str:
    """The directory part of a URL path (``/a/b/c.txt`` → ``/a/b/``; ``/`` for top-level names)."""
    path = path or "/"
    return path[: path.rfind("/") + 1] or "/"


def _parents(directory: str) -> list[str]:
    """``/a/b/`` → [``/a/b/``, ``/a/``, ``/``]."""
    out = [directory]
    d = directory
    while d != "/":
        d = d[: d.rstrip("/").rfind("/") + 1] or "/"
        out.append(d)
    return out


def baseline_path(directory: str = "/", cls: str = "none", token: str | None = None) -> str:
    """``/<dir>/kashif-404-<16 hex><ext>`` (§0.2: an honest name that site logs explain)."""
    if cls not in BASELINE_EXT:
        raise ValueError(f"unknown extension class {cls!r}")
    token = token or secrets.token_hex(8)
    if not re.fullmatch(r"[0-9a-f]{16}", token):
        raise ValueError("baseline token must be 16 lower-case hex digits")
    d = directory if directory.endswith("/") else directory + "/"
    if not d.startswith("/"):
        d = "/" + d
    return f"{d}{BASELINE_PREFIX}{token}{BASELINE_EXT[cls]}"


def is_baseline_url(url: str) -> bool:
    return bool(_BASELINE_NAME.match(urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1]))


def plan_baselines(probe_urls: Iterable[str], *, have: Iterable[str] = (), per_host: int = MAX_BASELINES_PER_HOST,
                   total: int = MAX_BASELINES_PER_SCAN, token: Callable[[], str] | None = None) -> list[str]:
    """Baseline URLs to fetch before the deep probe of ``probe_urls`` (§3.2): the root of every host first, then the
    (directory, extension class) pairs that cover the most probes, at most ``per_host`` per host and ``total`` per
    scan, counting the baselines already fetched (``have``). Pure: it only builds URLs."""
    make = token or (lambda: secrets.token_hex(8))
    used_total = 0
    used_host: dict[str, int] = {}
    have_keys: set[tuple[str, str, str]] = set()
    for u in have:
        p = urllib.parse.urlsplit(u)
        host = normalise_host(p.hostname or "")
        have_keys.add((host, directory_of(p.path), ext_class(p.path)))
        used_host[host] = used_host.get(host, 0) + 1
        used_total += 1
    origins: dict[str, str] = {}
    need: dict[tuple[str, str, str], int] = {}
    for u in probe_urls:
        p = urllib.parse.urlsplit(u)
        host = normalise_host(p.hostname or "")
        origins.setdefault(host, f"{p.scheme}://{p.netloc}")
        key = (host, directory_of(p.path or "/"), ext_class(p.path or "/"))
        need[key] = need.get(key, 0) + 1
    out: list[str] = []

    def take(key: tuple[str, str, str]) -> bool:
        nonlocal used_total
        host, d, cls = key
        if key in have_keys or used_total >= total or used_host.get(host, 0) >= per_host:
            return False
        out.append(origins[host] + baseline_path(d, cls, make()))
        have_keys.add(key)
        used_host[host] = used_host.get(host, 0) + 1
        used_total += 1
        return True

    for host in origins:                       # roots first, in first-seen order
        take((host, "/", "none"))
    ranked = sorted(need.items(), key=lambda kv: (-kv[1], kv[0][1].count("/"), kv[0][1], kv[0][2], kv[0][0]))
    for key, _n in ranked:
        take(key)
    return out


@dataclass(frozen=True)
class Baseline:
    """One soft-404 reference response of a host."""
    host: str
    directory: str
    cls: str
    signature: ResponseSignature
    natural: bool = False
    path: str = ""

    @property
    def real_404(self) -> bool:
        return self.signature.status in (404, 410)

    def evidence(self) -> dict:
        """``Evidence.baseline`` (§3.6): {url, status, sha256, simhash}."""
        s = self.signature
        return {"url": s.url, "status": s.status, "sha256": s.sha256, "simhash": _sh.to_hex(s.simhash)}


@dataclass(frozen=True)
class Soft404Match:
    """``response`` resembles ``baseline`` (``reason``: sha256 | simhash | length)."""
    baseline: Baseline
    reason: str
    distance: int

    def evidence(self) -> dict:
        ev = self.baseline.evidence()
        ev.update({"reason": self.reason, "hamming": self.distance, "natural": self.baseline.natural})
        return ev


@dataclass
class HostSoft404:
    """Per-host soft-404 knowledge: deep baselines, natural catch-all evidence and real-404 evidence."""
    host: str
    baselines: list[Baseline] = field(default_factory=list)       # deep (random-path) baselines
    catch_all: list[Baseline] = field(default_factory=list)       # natural responses that proved a catch-all
    real_404_paths: list[str] = field(default_factory=list)       # natural responses that were 404/410

    @property
    def is_catch_all(self) -> bool:
        if self.catch_all:
            return True
        root = [b for b in self.baselines if b.directory == "/" and b.cls == "none"]
        return bool(root) and not root[0].real_404 and root[0].signature.status is not None \
            and 200 <= root[0].signature.status < 300

    @property
    def real_404s(self) -> bool | None:
        """True when the host was seen to return real 404s, False when it answered a random path with 2xx, None when
        unknown."""
        root = [b for b in self.baselines if b.directory == "/" and b.cls == "none"]
        if root:
            return root[0].real_404
        if self.real_404_paths:
            return True
        if self.catch_all:
            return False
        return None

    def to_dict(self) -> dict:
        return {"host": self.host, "catch_all": self.is_catch_all, "real_404s": self.real_404s,
                "baselines": [b.evidence() | {"directory": b.directory, "class": b.cls} for b in self.baselines],
                "natural_catch_all": [b.evidence() for b in self.catch_all],
                "real_404_paths": list(self.real_404_paths)}


class Soft404Index:
    """Soft-404 baselines of a scan (§3.2). Pure: it never fetches; feed it the baseline and well-known responses.

    * :meth:`add_baseline` registers a deep random-path baseline (``/<dir>/kashif-404-<hex><ext>``);
    * :meth:`add_natural` evaluates the already-fetched well-known files (standard profile, no extra request);
    * :meth:`match` says whether a response resembles the applicable baseline, most specific first: the same
      directory and extension class, its parent directories, then the extension-less baselines, then the natural
      catch-all page. A 404/410 baseline met on the way means "this server returns real 404s here": no match.
    """

    def __init__(self) -> None:
        self.hosts: dict[str, HostSoft404] = {}

    def host(self, host: str) -> HostSoft404:
        h = normalise_host(host)
        if h not in self.hosts:
            self.hosts[h] = HostSoft404(h)
        return self.hosts[h]

    def add_baseline(self, response: Response) -> Baseline:
        path = response.parsed_url.path or "/"
        b = Baseline(host=response.host, directory=directory_of(path), cls=ext_class(path),
                     signature=signature(response), path=path)
        hs = self.host(response.host)
        hs.baselines = [x for x in hs.baselines if (x.directory, x.cls) != (b.directory, b.cls)] + [b]
        return b

    def add_natural(self, wellknown: dict[str, Response] | Iterable[Response],
                    entry: Response | None = None) -> list[Response]:
        """Evaluate natural baselines (§3.2). Two of the well-known responses that are 200 ``text/html`` and similar,
        or one similar to the 200 HTML ``entry`` document, prove a catch-all; so do two different well-known paths
        answering 200 with byte-identical non-empty bodies (any type). A 404/410 among them proves real 404s.
        Returns the responses that proved the catch-all (the caller marks them ``soft404``)."""
        responses = list(wellknown.values()) if isinstance(wellknown, dict) else list(wellknown)
        by_host: dict[str, list[Response]] = {}
        for r in responses:
            if r is None or (r.parsed_url.path or "/") not in NATURAL_PATHS:
                continue
            by_host.setdefault(r.host, []).append(r)
        proven: list[Response] = []
        for host, rs in by_host.items():
            hs = self.host(host)
            for r in rs:
                if r.status in (404, 410) and (r.parsed_url.path or "/") not in hs.real_404_paths:
                    hs.real_404_paths.append(r.parsed_url.path or "/")
            ok = [r for r in rs if r.status == 200 and r.body and "opaque-coding" not in r.flags]
            html_ok = [r for r in ok if r.essence in HTML_TYPES]
            hits: dict[int, Response] = {}
            for i, a in enumerate(html_ok):
                for b in html_ok[i + 1:]:
                    if similar(signature(a), signature(b)):
                        hits[id(a)], hits[id(b)] = a, b
            if entry is not None and entry.status == 200 and entry.essence in HTML_TYPES and entry.host == host:
                es = signature(entry)
                for a in html_ok:
                    if similar(signature(a), es):
                        hits[id(a)] = a
            for i, a in enumerate(ok):
                for b in ok[i + 1:]:
                    if a.body == b.body and a.parsed_url.path != b.parsed_url.path:
                        hits[id(a)], hits[id(b)] = a, b
            for r in hits.values():
                path = r.parsed_url.path or "/"
                if all(b.path != path for b in hs.catch_all):
                    hs.catch_all.append(Baseline(host=host, directory=directory_of(path), cls=ext_class(path),
                                                 signature=signature(r), natural=True, path=path))
                proven.append(r)
        return proven

    def candidates(self, response: Response) -> list[Baseline]:
        hs = self.hosts.get(response.host)
        if hs is None:
            return []
        path = response.parsed_url.path or "/"
        d, cls = directory_of(path), ext_class(path)
        table = {(b.directory, b.cls): b for b in hs.baselines}
        order: list[Baseline] = []
        for c in ([cls, "none"] if cls != "none" else ["none"]):
            for parent in _parents(d):
                b = table.get((parent, c))
                if b is not None and b not in order:
                    order.append(b)
        return order

    def match(self, response: Response) -> Soft404Match | None:
        """The baseline ``response`` resembles, or ``None`` (see the class docstring for the order)."""
        hs = self.hosts.get(response.host)
        if hs is None or response.status is None:
            return None
        sig = signature(response)
        path = response.parsed_url.path or "/"
        for b in self.candidates(response):
            if b.path == path:
                continue
            reason = _similar_reason(sig, b.signature)
            if reason:
                return Soft404Match(b, reason, _sh.hamming(sig.simhash, b.signature.simhash))
            if b.real_404:
                return None
        for b in hs.catch_all:
            if b.path == path:
                return Soft404Match(b, "sha256", 0)
            reason = _similar_reason(sig, b.signature)
            if reason:
                return Soft404Match(b, reason, _sh.hamming(sig.simhash, b.signature.simhash))
        return None

    def to_dict(self) -> dict:
        """Report data (``ctx.inventory["soft404"]``): per host, catch-all and real-404 verdicts and baseline evidence."""
        return {h: hs.to_dict() for h, hs in sorted(self.hosts.items())}


def build_index(ctx: ScanContext) -> tuple[Soft404Index, list[Response]]:
    """Index of ``ctx.baselines`` (deep) and the natural baselines in ``ctx.wellknown`` (with ``ctx.entry``); also
    returns the well-known responses that proved a catch-all."""
    idx = Soft404Index()
    for r in ctx.baselines:
        if r is not None and r.status is not None and not r.error:
            idx.add_baseline(r)
    proven = idx.add_natural(ctx.wellknown, ctx.entry)
    return idx, proven


def mark_soft404(response: Response) -> Response:
    """Turn a content response into kind ``soft404`` (row 9 of §3.1); other kinds (errors, redirects, WAF) stay."""
    if response.kind in CONTENT_KINDS or response.kind == "soft404":
        response.kind = "soft404"
        response.flags = frozenset(response.flags) | {"soft404"}
    return response


def apply_soft404(ctx: ScanContext, index: Soft404Index, proven: Sequence[Response] = ()) -> list[Response]:
    """Mark every response that matches its host's soft-404 baseline as ``soft404``: crawled pages, well-known files,
    deep probes, subresources, source maps, images and 2xx baselines themselves. The entry chain, the counterpart
    probes and the CORS fetch are never marked (they are the page the user asked about). Returns the marked ones."""
    marked: list[Response] = []
    for r in proven:
        mark_soft404(r)
        r.flags = frozenset(r.flags) | {"catch-all"}
        marked.append(r)
    protected = {id(h) for r in (ctx.entry, ctx.http_probe, ctx.https_probe, ctx.cors) if r is not None
                 for h in r.hops()}
    groups: list[Response] = [p.response for p in ctx.pages] + list(ctx.wellknown.values()) + list(ctx.probes) + \
        list(ctx.subresources) + list(ctx.sourcemaps) + list(ctx.images)
    for r in groups:
        if r is None or id(r) in protected or r.kind not in CONTENT_KINDS or any(r is m for m in marked):
            continue
        if index.match(r):
            mark_soft404(r)
            marked.append(r)
    for r in ctx.baselines:
        if r is not None and r.kind in CONTENT_KINDS:
            mark_soft404(r)
            marked.append(r)
    return marked


def classify_context(ctx: ScanContext) -> Soft404Index:
    """Engine entry point after fetching: classify every response (pages with their DOM), build the soft-404 index
    from the deep and natural baselines, mark soft 404s and store the per-host verdicts in
    ``ctx.inventory["soft404"]``. Returns the index (exposure.py's deep probe can keep using it)."""
    docs = {id(p.response): p.doc for p in ctx.pages}
    for r in ctx.all_responses():
        classify(r, docs.get(id(r)))
    index, proven = build_index(ctx)
    apply_soft404(ctx, index, proven)
    if isinstance(ctx.inventory, dict):
        ctx.inventory["soft404"] = index.to_dict()
    return index


__all__ = [
    "STR", "HTML_TYPES", "CONTENT_KINDS", "WAF_PROVIDERS", "ARCHIVE_OR_EXECUTABLE", "kind_for_essence", "xml_root",
    "sniff", "sniffed_kind", "ctype_mismatch", "waf_provider", "waf_name", "is_rate_limited", "kind_of",
    "listing_server", "page_roles", "classify", "is_sensitive", "mark_sensitive", "signature", "similar",
    "BASELINE_PREFIX", "EXT_CLASSES", "NATURAL_PATHS", "ext_class", "directory_of", "baseline_path", "is_baseline_url",
    "plan_baselines", "Baseline", "Soft404Match", "HostSoft404", "Soft404Index", "build_index", "mark_soft404",
    "apply_soft404", "classify_context",
]
