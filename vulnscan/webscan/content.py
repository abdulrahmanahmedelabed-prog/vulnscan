"""Page content and client-side code (spec §2.6), WP7: WEB050–WEB053 and WEB500–WEB519, plus the MDN Observatory v6
``subresource-integrity`` slug.

What is judged
* **Documents only** (§2.6): pages whose response kind is ``document`` (a final 2xx HTML response; when the engine
  has not classified a page, a 2xx ``text/html``/``application/xhtml+xml`` response). Crawled ``soft404`` pages, WAF
  and rate-limit pages, error pages and non-HTML responses are never parsed. A WAF/rate-limited entry (G4) makes the
  document checks ``inconclusive``; a body in an unsupported content-coding makes them ``not_tested``.
* **Live DOM only**: elements inside ``<template>``/``<noscript>`` and markup inside comments are never judged
  (htmlparse marks them ``live=False`` / keeps comments apart), so commented-out or templated markup cannot fire.
* **Same-site** means the same registrable domain (PSL, private section included): ``static.example.com`` is not a
  third party of ``www.example.com`` (fixes D22). **Cross-origin** (WEB500) is scheme + host + port.

Inputs read from the context (never through another check module, §4.2): ``ctx.pages`` (+ their light DOM),
``ctx.subresources``/``ctx.images`` (fetched by the engine: SRI verification WEB503, http hops for WEB050, deleted
buckets WEB517-C, same-site stylesheets for ``@import``/``url()``), ``ctx.csp`` (``upgrade_insecure_requests``),
``ctx.cookies`` (WEB516), ``ctx.dns`` + ``ctx.proxied`` (WEB517) and ``data/web/malicious-hosts.json``. content.py
never fetches anything; it writes ``ctx.observatory["subresource-integrity"]``, ``ctx.inventory["forms"]``,
``ctx.inventory["third_parties"]`` and ``ctx.inventory["integrity_policy"]`` and records coverage states.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import os
import re
import sys
import urllib.parse
from dataclasses import dataclass, field

from . import htmlparse, psl, sfv
from .coverage import REASONS
from .rules import RULES, checks_for_module
from .types import (
    Element,
    Evidence,
    Issue,
    Page,
    ParsedHTML,
    Response,
    ScanContext,
    normalise_host,
    redact_secret,
    strip_controls,
    url_origin,
)

CHECKS: tuple[str, ...] = checks_for_module("content")
MALICIOUS_FILE = "malicious-hosts.json"
OBS_TEST = "subresource-integrity"
PLATFORM = sys.platform               # patched by tests (WEB517 variant A is tentative on macOS)
TEST_HOOK_ENV = "KASHIF_TEST_RESOLVE"  # the corpus resolver hook (http.py): reserved .test names are then real

# ----------------------------------------------------------------------------------------------- user-facing text

# (en, ar) note templates. ``{name}`` values come from the scanned site and are substituted literally (no
# ``str.format``), so a value with braces cannot break or inject a format string, and control characters are stripped.
STR: dict[str, tuple[str, str]] = {
    "mixed_items": ("Insecure items: {items}.", "العناصر غير الآمنة: {items}."),
    "mixed_active": ("Active content ({count}: scripts, styles, frames or plugins) is blocked by browsers.",
                     "المحتوى النشط ({count}: سكربتات أو أنماط أو إطارات أو إضافات) يحجبه المتصفح."),
    "mixed_passive": ("Only passive content (images, media): browsers upgrade or show it as not secure.",
                      "المحتوى سلبي فقط (صور ووسائط): يرقّيه المتصفح إلى https أو يعرضه على أنه غير آمن."),
    "mixed_uir": ("The enforced CSP has upgrade-insecure-requests, so browsers request these over https.",
                  "تتضمن سياسة CSP المطبّقة upgrade-insecure-requests، لذا يطلبها المتصفح عبر https."),
    "mixed_hop": ("{url} redirects through plain http ({hop}).", "المورد {url} يمر بتوجيه عبر http غير مشفّر ({hop})."),
    "mixed_css": ("Found in the stylesheet {url}.", "وُجد في ملف الأنماط {url}."),
    "form_password": ("The form contains a password field.", "يحتوي النموذج على حقل كلمة مرور."),
    "form_action": ("Destination: {url}.", "الوجهة: {url}."),
    "sri_files": ("Files without integrity: {items}.", "ملفات بلا integrity: {items}."),
    "sri_evergreen": ("{items} cannot be pinned (the provider changes the file in place); govern it with CSP instead.",
                      "لا يمكن تثبيت {items} (المزوّد يغيّر الملف في مكانه)؛ تحكّم به عبر CSP بدل ذلك."),
    "sri_versioned": ("Versioned public-CDN files: SRI is easy to add here.",
                      "ملفات بإصدار محدد من CDN عام: إضافة SRI هنا سهلة."),
    "sri_ip_enforced": ("Enforced by Integrity-Policy: the browser refuses these scripts without integrity metadata.",
                        "مفروض عبر Integrity-Policy: يرفض المتصفح هذه السكربتات دون بيانات integrity."),
    "sri_ip_invalid": ("The Integrity-Policy header is not a valid structured-field dictionary ({error}); browsers "
                       "ignore it.",
                       "ترويسة Integrity-Policy ليست قاموس حقول مهيكلة صالحًا ({error})؛ لذا يتجاهلها المتصفح."),
    "sri_unknown_alg": ("{value} uses no supported algorithm (sha256, sha384, sha512), so the browser treats the "
                        "element as having no integrity metadata.",
                        "القيمة {value} لا تستخدم خوارزمية مدعومة (sha256 أو sha384 أو sha512)، فيعامل المتصفح العنصر "
                        "كأنه بلا integrity."),
    "sri_bad_digest": ("{value}: the digest does not decode to the {bytes} of {alg}; the browser blocks the file.",
                       "{value}: القيمة لا تُفكّ إلى {bytes} كما تتطلب {alg}؛ فيحجب المتصفح الملف."),
    "sri_weak_extra": ("Unsupported algorithms are ignored: {value}.", "الخوارزميات غير المدعومة تُتجاهل: {value}."),
    "sri_nocors": ("The request is sent without CORS, its response is opaque and cannot be checked, so the browser "
                   "blocks {url}.",
                   "يُرسَل الطلب دون CORS فتكون الاستجابة معتمة لا يمكن التحقق منها، لذا يحجب المتصفح {url}."),
    "sri_mismatch": ("Expected {expected}; the served file hashes to {actual}.",
                     "القيمة المتوقعة {expected}، بينما تجزئة الملف المقدَّم {actual}."),
    "sri_rewrite": ("Edge optimisers (minification, Rocket Loader) can rewrite files; compare the response headers.",
                    "قد تعيد أدوات تحسين الحافة (التصغير أو Rocket Loader) كتابة الملفات؛ قارن ترويسات الاستجابة."),
    "opener": ("{url} opens with rel=\"{rel}\": the opened page can navigate this one (window.opener).",
               "الرابط {url} يُفتح مع rel=\"{rel}\": تستطيع الصفحة المفتوحة توجيه هذه الصفحة (window.opener)."),
    "malicious_host": ("{host}: {reason}.", "{host}: {reason}."),
    "malicious_inline": ("A URL on {host} appears inside an inline script.", "يظهر رابط على {host} داخل سكربت مضمّن."),
    "compromise": ("Signature {id} ({kind}) matched {where}.", "تطابق التوقيع {id} ({kind}) في {where}."),
    "password_autocomplete": ("autocomplete=\"{value}\" on the password field.", "autocomplete=\"{value}\" على حقل كلمة المرور."),
    "password_paste": ("The password field cancels paste ({value}).", "حقل كلمة المرور يلغي اللصق ({value})."),
    "login_get_explicit": ("The form sets method=\"{value}\": the password ends up in the URL, history and logs.",
                           "يحدد النموذج method=\"{value}\": تنتهي كلمة المرور في الرابط وسجل المتصفح والسجلات."),
    "login_get_default": ("The form has no method, so the browser submits it with GET.",
                          "النموذج بلا method، لذا يرسله المتصفح بطريقة GET."),
    "login_get_js": ("The form has no method but is probably submitted by JavaScript ({why}); check how it is sent.",
                     "النموذج بلا method لكنه يُرسَل غالبًا عبر JavaScript ({why})؛ تحقّق من طريقة الإرسال."),
    "session_param": ("Parameter {name} carries a value of {length} in {url}.",
                      "المعامل {name} يحمل قيمة من {length} في {url}."),
    "session_referer": ("The page also links to other sites, which receive the URL in the Referer header.",
                        "الصفحة ترتبط أيضًا بمواقع أخرى تستقبل الرابط في ترويسة Referer."),
    "sensitive_param": ("Parameter {name} in {url} ({why}).", "المعامل {name} في {url} ({why})."),
    "redirect_param": ("{name}={value} in {url}; Kashif did not request it.",
                       "{name}={value} في {url}؛ لم يطلبه كاشف."),
    "upload": ("File input {name} in the form posting to {url}.", "حقل رفع الملفات {name} في النموذج المرسل إلى {url}."),
    "quirks": ("No <!doctype html> (quirks mode) and the stylesheet {url} is path-relative.",
               "لا يوجد <!doctype html> (وضع quirks) وملف الأنماط {url} مسار نسبي."),
    "inline_handlers": ("Inline event handlers: {handlers}; javascript: URLs: {urls}.",
                        "معالجات الأحداث المضمّنة: {handlers}؛ روابط javascript: {urls}."),
    "csrf_form": ("No anti-CSRF token among the form fields, and no session cookie with SameSite=Lax or Strict.",
                  "لا يوجد رمز مضاد لـ CSRF بين حقول النموذج، ولا كوكي جلسة مع SameSite=Lax أو Strict."),
    "dns_a": ("{host} does not exist and neither does its domain {domain}: anyone can register it and serve code here.",
              "المضيف {host} غير موجود، ولا نطاقه {domain} أيضًا: يستطيع أي شخص تسجيله وتقديم شيفرة لهذه الصفحة."),
    "dns_a_macos": ("macOS reports \"no data\" answers as \"name not found\" too; confirm the domain is unregistered.",
                    "يبلّغ macOS عن إجابات \"لا بيانات\" على أنها \"اسم غير موجود\" أيضًا؛ تأكّد أن النطاق غير مسجّل."),
    "dns_b": ("{host} does not exist inside the live domain {domain}; only its owner can create it (check for a "
              "dangling CNAME).",
              "المضيف {host} غير موجود داخل النطاق الفعّال {domain}؛ لا يستطيع إنشاءه إلا مالك النطاق (تحقّق من سجل CNAME معلّق)."),
    "dns_c": ("{url} answers {code}: the storage bucket was deleted and its name can be claimed by anyone.",
              "المورد {url} يجيب {code}: حاوية التخزين محذوفة ويمكن لأي شخص حجز اسمها."),
    "dns_intranet": ("{host} is an intranet name that visitors cannot resolve.",
                     "المضيف {host} اسم داخلي لا يستطيع الزوار تحليله."),
    "dns_refs": ("Referenced by: {items}.", "مُشار إليه في: {items}."),
    "cross_site_form": ("The password form posts to {host}.", "نموذج كلمة المرور يُرسَل إلى {host}."),
    "cross_site_lonely": ("{host} is not referenced anywhere else on the site.", "المضيف {host} غير مُشار إليه في أي مكان آخر من الموقع."),
    "cross_site_malicious": ("{host} is on the malicious-hosts list.", "المضيف {host} مدرج في قائمة المضيفين الخبيثين."),
    "unpinned": ("{url} does not pin an exact version ({why}).", "الرابط {url} لا يثبّت إصدارًا محددًا ({why})."),
    "truncated": ("The page was larger than the size cap; only the first part was analysed.",
                  "الصفحة أكبر من الحد المسموح؛ حُلِّل الجزء الأول منها فقط."),
}
# reasons used inside notes (en, ar)
WHY: dict[str, tuple[str, str]] = {
    "no_action": ("no action attribute", "لا توجد سمة action"),
    "onsubmit": ("onsubmit handler", "معالج onsubmit"),
    "script_ref": ("referenced by an inline script", "مُشار إليه في سكربت مضمّن"),
    "app": ("single-page application", "تطبيق صفحة واحدة"),
    "secret_name": ("secret-looking name with a non-trivial value", "اسم يوحي بسرّ مع قيمة غير بسيطة"),
    "email": ("an email address", "عنوان بريد إلكتروني"),
    "card": ("a payment card number", "رقم بطاقة دفع"),
    "no_version": ("no version", "بلا إصدار"),
    "latest": ("@latest", "@latest"),
    "range": ("a version range", "نطاق إصدارات"),
    "branch": ("a branch, not a tag or commit", "فرع وليس وسمًا أو التزامًا"),
    "inline_script": ("an inline script", "سكربت مضمّن"),
    "script_url": ("a script URL", "رابط سكربت"),
    "script_file": ("the script file {url}", "ملف السكربت {url}"),
    "title_text": ("the page title and text", "عنوان الصفحة ونصّها"),
}
_COUNT_ACTIVE = ("{n} active item", "{n} active items",
                 ("عنصر نشط واحد", "عنصران نشطان", "{n} عناصر نشطة", "{n} عنصرًا نشطًا", "{n} عنصر نشط"))
_COUNT_CHARS = ("{n} character", "{n} characters", ("حرف واحد", "حرفان", "{n} أحرف", "{n} حرفًا", "{n} حرف"))
_COUNT_BYTES = ("{n} byte", "{n} bytes", ("بايت واحد", "بايتان", "{n} بايتات", "{n} بايتًا", "{n} بايت"))
COUNT_FORMS = {"active": _COUNT_ACTIVE, "chars": _COUNT_CHARS, "bytes": _COUNT_BYTES}
_PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")
_MAX_LIST = 10


def _fill(text: str, values: dict, lang: str) -> str:
    def sub(m: re.Match) -> str:
        v = values.get(m.group(1), m.group(0))
        if isinstance(v, tuple):          # (en, ar) pair
            v = v[1] if lang == "ar" else v[0]
        return strip_controls(str(v))     # §0.6: no terminal escapes from the target in notes
    return _PLACEHOLDER.sub(sub, text)


def _note(key: str, **values) -> tuple[str, str]:
    """``(en, ar)`` of ``STR[key]`` with ``{name}`` filled literally."""
    en, ar = STR[key]
    return _fill(en, values, "en"), _fill(ar, values, "ar")


def _why(key: str, **values) -> tuple[str, str]:
    en, ar = WHY[key]
    return _fill(en, values, "en"), _fill(ar, values, "ar")


def _count(n: int, forms: tuple) -> tuple[str, str]:
    from ..i18n.plural import ar_count   # lazy: vulnscan.i18n imports webscan modules through cat_web2
    en = (forms[0] if n == 1 else forms[1]).replace("{n}", str(n))
    return en, ar_count(n, forms[2])


def _list(items: list[str], limit: int = _MAX_LIST) -> str:
    shown = [_short(i) for i in items[:limit]]
    more = len(items) - len(shown)
    return ", ".join(shown) + (f" (+{more})" if more > 0 else "")


def _short(value: str, limit: int = 160) -> str:
    v = " ".join(str(value).split())
    return v if len(v) <= limit else v[: limit - 1] + "…"


# ----------------------------------------------------------------------------------------------- URL helpers

_RESERVED_SUFFIXES = ("localhost", "test", "example", "invalid")          # RFC 6761 / 2606: never judged
_INTRANET_SUFFIXES = ("local", "internal", "home.arpa", "lan", "intranet", "corp")


_HOST_CACHE: dict[str, str] = {}


def _host(url: str) -> str:
    host = _HOST_CACHE.get(url)
    if host is None:
        try:
            host = normalise_host(urllib.parse.urlsplit(url).hostname or "")
        except ValueError:
            host = ""
        if len(_HOST_CACHE) > 50000:
            _HOST_CACHE.clear()
        _HOST_CACHE[url] = host
    return host


def _scheme(url: str) -> str:
    try:
        return urllib.parse.urlsplit(url).scheme.lower()
    except ValueError:
        return ""


def _defrag(url: str) -> str:
    try:
        return urllib.parse.urldefrag(url)[0]
    except ValueError:
        return url


def _ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return None


def is_loopback(host: str) -> bool:
    """``localhost``, ``*.localhost`` and loopback IP literals (browsers treat them as potentially trustworthy)."""
    h = normalise_host(host)
    if h == "localhost" or h.endswith(".localhost"):
        return True
    ip = _ip(h)
    return bool(ip and ip.is_loopback)


def _suffix_of(host: str, suffixes: tuple[str, ...]) -> bool:
    return any(host == s or host.endswith("." + s) for s in suffixes)


def _hooked() -> bool:
    return os.environ.get(TEST_HOOK_ENV) == "1"


def _reserved_name(host: str) -> bool:
    """Reserved names (RFC 6761/2606) that are never judged by WEB517; with the corpus resolver hook, ``.test``
    names are real (the corpus serves every case under ``*.kashif.test``)."""
    reserved = tuple(s for s in _RESERVED_SUFFIXES if not (s == "test" and _hooked()))
    return _suffix_of(host, reserved)


def _intranet_name(host: str) -> bool:
    return "." not in host or _suffix_of(host, _INTRANET_SUFFIXES)


def _public_name(host: str) -> bool:
    return bool(host) and _ip(host) is None and not _reserved_name(host) and not _intranet_name(host)


_SITE_CACHE: dict[str, str] = {}


def _site(host: str) -> str:
    """``psl.site`` memoised for one run (pages repeat the same few hosts thousands of times)."""
    site = _SITE_CACHE.get(host)
    if site is None:
        if len(_SITE_CACHE) > 20000:
            _SITE_CACHE.clear()
        site = _SITE_CACHE[host] = psl.site(host)
    return site


def _query_pairs(url: str) -> list[tuple[str, str]]:
    if "?" not in url:
        return []
    try:
        query = urllib.parse.urlsplit(url).query
    except ValueError:
        return []
    return urllib.parse.parse_qsl(query, keep_blank_values=True)


# ----------------------------------------------------------------------------------------------- SRI (§3.5 grammar)

SRI_ALGORITHMS = {"sha256": 32, "sha384": 48, "sha512": 64}
_ALGO_RANK = {"sha256": 1, "sha384": 2, "sha512": 3}
_B64 = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")


@dataclass
class SriToken:
    raw: str
    algorithm: str                 # lower-cased
    digest_text: str
    digest: bytes | None           # decoded (base64 or base64url); None when it does not decode
    options: str = ""

    @property
    def supported(self) -> bool:
        return self.algorithm in SRI_ALGORITHMS

    @property
    def well_formed(self) -> bool:
        return self.supported and self.digest is not None and len(self.digest) == SRI_ALGORITHMS[self.algorithm]


@dataclass
class SriMetadata:
    """Parsed ``integrity`` attribute (SRI §3.3.3): the browser keeps tokens with a supported algorithm and uses the
    strongest algorithm present."""
    raw: str
    tokens: list[SriToken] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self.raw.strip()

    @property
    def supported(self) -> list[SriToken]:
        return [t for t in self.tokens if t.supported]

    @property
    def has_metadata(self) -> bool:
        """True when the browser applies an integrity check (at least one supported algorithm)."""
        return bool(self.supported)

    @property
    def unsupported(self) -> list[SriToken]:
        return [t for t in self.tokens if not t.supported]

    def strongest(self) -> list[SriToken]:
        sup = self.supported
        if not sup:
            return []
        best = max(_ALGO_RANK[t.algorithm] for t in sup)
        return [t for t in sup if _ALGO_RANK[t.algorithm] == best]

    def malformed(self) -> list[SriToken]:
        """Supported-algorithm tokens whose digest does not decode to the algorithm's length."""
        return [t for t in self.supported if not t.well_formed]

    def matches(self, body: bytes) -> bool | None:
        """Whether ``body`` (the decoded response body) satisfies the metadata; None when there is none."""
        strongest = self.strongest()
        if not strongest:
            return None
        algo = strongest[0].algorithm
        actual = hashlib.new(algo, body).digest()
        return any(t.digest == actual for t in strongest)


def _b64decode(text: str) -> bytes | None:
    if not text or not _B64.match(text):
        return None
    s = text.rstrip("=")
    if "-" in s or "_" in s:
        s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def parse_sri(value: str | None) -> SriMetadata:
    """Parse an ``integrity`` value: whitespace-separated ``alg-digest[?options]`` tokens."""
    meta = SriMetadata(value or "")
    for tok in (value or "").split():
        expr, _, opts = tok.partition("?")
        alg, dash, digest = expr.partition("-")
        if not dash:
            meta.tokens.append(SriToken(tok, alg.lower(), "", None, opts))
            continue
        meta.tokens.append(SriToken(tok, alg.lower(), digest, _b64decode(digest), opts))
    return meta


def sri_digest(algorithm: str, body: bytes) -> str:
    """``alg-base64`` of ``body`` (what the integrity attribute should contain)."""
    return f"{algorithm}-{base64.b64encode(hashlib.new(algorithm, body).digest()).decode('ascii')}"


# ----------------------------------------------------------------------------------------------- package CDNs

_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_VERSION_IN_PATH = re.compile(r"(?:^|[/@_-])v?\d+\.\d+(?:\.\d+)?(?:[-.][0-9A-Za-z]+)*(?=$|[/._-])")


@dataclass(frozen=True)
class CdnPin:
    """What a package-CDN URL pins: ``pinned`` False → WEB519 (``why`` in WHY), None → not a package-CDN URL."""
    cdn: str
    package: str
    version: str | None
    pinned: bool
    why: str = ""


def _npm_spec(segments: list[str]) -> tuple[str, str | None, int] | None:
    """``(package, version or None, segments used)`` from path segments starting at a package name."""
    if not segments or not segments[0]:
        return None
    if segments[0].startswith("@"):
        if len(segments) < 2:
            return None
        scope, rest = segments[0], segments[1]
        name, at, ver = rest.partition("@")
        return f"{scope}/{name}", (ver if at else None), 2
    name, at, ver = segments[0].partition("@")
    return name, (ver if at else None), 1


def _judge(cdn: str, package: str, version: str | None, *, gh: bool = False) -> CdnPin:
    if not package:
        return CdnPin(cdn, package, version, True)
    if version is None or version == "":
        return CdnPin(cdn, package, version, False, "no_version")
    v = urllib.parse.unquote(version)
    if v.lower() == "latest":
        return CdnPin(cdn, package, version, False, "latest")
    if _SEMVER.match(v) or (gh and (_SEMVER.match(v[1:] if v[:1] in "vV" else v) or _SHA40.match(v.lower()))):
        return CdnPin(cdn, package, version, True)
    if gh and not re.match(r"^[v^~<>=]?\d", v):
        return CdnPin(cdn, package, version, False, "branch")
    return CdnPin(cdn, package, version, False, "range")


def cdn_pin(url: str) -> list[CdnPin]:
    """Package-CDN pinning facts of a URL (one entry per package; jsDelivr ``combine`` URLs name several).

    jsDelivr ``/npm/<pkg>[@v]`` and ``/gh/<user>/<repo>[@ref]``, unpkg, esm.sh (``/v135/``, ``/stable/``, ``*``
    prefixes), cdn.skypack.dev (``/-/pkg@ver-hash/`` pinned URLs) and ga.jspm.io (``/npm:pkg@ver``). Pinned means
    ``@\\d+.\\d+.\\d+(-pre|+build)`` (a 40-hex commit, or a ``v``-prefixed tag, for ``gh/``)."""
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return []
    host = normalise_host(p.hostname or "")
    segs = [urllib.parse.unquote(s) for s in p.path.split("/")[1:]]
    out: list[CdnPin] = []
    if host == "cdn.jsdelivr.net":
        if segs and segs[0] == "combine":
            for part in "/".join(segs[1:]).split(","):
                out.extend(cdn_pin(f"https://cdn.jsdelivr.net/{part.strip()}"))
            return out
        if segs and segs[0] == "npm":
            spec = _npm_spec(segs[1:])
            if spec:
                out.append(_judge("jsdelivr", spec[0], spec[1]))
        elif segs and segs[0] == "gh" and len(segs) >= 3:
            repo, at, ref = segs[2].partition("@")
            out.append(_judge("jsdelivr", f"{segs[1]}/{repo}", ref if at else None, gh=True))
    elif host == "unpkg.com":
        spec = _npm_spec(segs)
        if spec:
            out.append(_judge("unpkg", spec[0], spec[1]))
    elif host == "esm.sh":
        rest = list(segs)
        while rest and (re.match(r"^v\d+$", rest[0]) or rest[0] == "stable"):
            rest = rest[1:]
        if rest and rest[0] == "gh":                # /gh/<owner>/<repo>[@ref]/… : the jsDelivr gh/ rule
            if len(rest) >= 3 and rest[1] and rest[2]:
                repo, at, ref = rest[2].partition("@")
                out.append(_judge("esm.sh", f"{rest[1]}/{repo}", ref if at else None, gh=True))
            return out
        if rest and rest[0].startswith("*"):
            rest[0] = rest[0][1:]
        spec = _npm_spec(rest)
        if spec and not spec[0].startswith("~"):
            out.append(_judge("esm.sh", spec[0], spec[1]))
    elif host == "cdn.skypack.dev":
        hashed = bool(segs) and segs[0] in ("-", "pin")
        rest = segs[1:] if hashed else segs
        spec = _npm_spec(rest)
        if spec:
            ver = spec[1]
            if hashed and ver:      # /pin/pkg@v1.2.3-AbCdEf/… and /-/pkg@v1.2.3-AbCdEf/…: Skypack's immutable URLs
                ver = ver.split("-", 1)[0]
                ver = ver[1:] if ver[:1] in "vV" and ver[1:2].isdigit() else ver
            out.append(_judge("skypack", spec[0], ver))
    elif host == "ga.jspm.io":
        if segs and segs[0].startswith("npm:"):
            spec = _npm_spec([segs[0][4:], *segs[1:]])
            if spec:
                out.append(_judge("jspm", spec[0], spec[1]))
    return out


# SRI is easy on these when the URL names a version (WEB053 low); evergreen scripts cannot carry SRI (WEB053 info)
_VERSIONED_CDN_HOSTS = ("cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "code.jquery.com",
                        "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com", "netdna.bootstrapcdn.com",
                        "ajax.googleapis.com")
EVERGREEN: tuple[tuple[str, str, str], ...] = (       # (host, path prefix, product)
    ("www.googletagmanager.com", "/", "Google Tag Manager"),
    ("googletagmanager.com", "/", "Google Tag Manager"),
    ("www.google-analytics.com", "/", "Google Analytics"),
    ("ssl.google-analytics.com", "/", "Google Analytics"),
    ("region1.google-analytics.com", "/", "Google Analytics"),
    ("www.google.com", "/recaptcha/", "reCAPTCHA"),
    ("www.recaptcha.net", "/recaptcha/", "reCAPTCHA"),
    ("www.gstatic.com", "/recaptcha/", "reCAPTCHA"),
    ("js.stripe.com", "/", "Stripe.js"),
    ("www.paypal.com", "/sdk/", "PayPal SDK"),
    ("www.paypalobjects.com", "/", "PayPal SDK"),
    ("widget.intercom.io", "/", "Intercom"),
    ("js.intercomcdn.com", "/", "Intercom"),
    ("static.hotjar.com", "/", "Hotjar"),
    ("script.hotjar.com", "/", "Hotjar"),
    ("connect.facebook.net", "/", "Facebook SDK"),
    # not a script, but the same situation: the CSS is generated per browser (User-Agent), so no hash can match
    ("fonts.googleapis.com", "/", "Google Fonts CSS"),
)


def evergreen_product(url: str) -> str | None:
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    host = normalise_host(p.hostname or "")
    for h, prefix, product in EVERGREEN:
        if host == h and (p.path or "/").startswith(prefix):
            return product
    return None


def versioned_public_cdn(url: str) -> bool:
    """A versioned file on a public CDN where adding SRI is feasible (§WEB053 "low")."""
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    host = normalise_host(p.hostname or "")
    if host not in _VERSIONED_CDN_HOSTS:
        return False
    path = urllib.parse.unquote(p.path)
    if host in ("cdn.jsdelivr.net", "unpkg.com"):
        pins = cdn_pin(url)
        return bool(pins) and all(x.pinned for x in pins)
    if host in ("cdnjs.cloudflare.com", "ajax.googleapis.com"):
        m = re.match(r"^/ajax/libs/[^/]+/([^/]+)/", path)
        return bool(m and re.match(r"^v?\d+(?:\.\d+)*", m.group(1)))
    return bool(_VERSION_IN_PATH.search(path))


# ----------------------------------------------------------------------------------------------- element sets

ACTIVE_LINK_RELS = frozenset({"stylesheet", "preload", "modulepreload", "prefetch", "manifest"})
PASSIVE_LINK_RELS = frozenset({"icon", "apple-touch-icon", "apple-touch-icon-precomposed"})
SRI_LINK_RELS = frozenset({"stylesheet", "preload", "modulepreload"})


@dataclass
class Item:
    """One URL reference of the live DOM (or of a stylesheet) relevant to a rule."""
    url: str                 # resolved absolute URL
    raw: str                 # as written
    where: str               # e.g. script[src]
    active: bool
    element: Element | None
    offset: int | None
    category: str = "other"  # WEB517: script | style | iframe | form | img | other
    source_url: str = ""     # stylesheet the reference comes from (css items)


_CSS_COMMENT = re.compile(r"/\*.*?\*/", re.S)
# ``(`` is excluded from the URL characters: an unterminated ``url(`` must stop at the next ``url(``, otherwise every
# ``url(`` of a hostile stylesheet rescans the rest of the text (quadratic: 1.7 MB of ``url(url(…`` took hours).
_CSS_IMPORT = re.compile(r"""@import\s+(?:url\(\s*(?P<q1>['"]?)(?P<u1>[^'"()\s]+)(?P=q1)\s*\)|(?P<q2>['"])(?P<u2>[^'"]+)(?P=q2))""",
                         re.I)
_CSS_URL = re.compile(r"""url\(\s*(?P<q>['"]?)(?P<u>[^'"()\s]+)(?P=q)\s*\)""", re.I)


def css_references(css: str) -> list[tuple[str, bool, int]]:
    """``(url, active, offset)`` of ``@import`` (active) and other ``url()`` references (passive) in CSS text."""
    text = _CSS_COMMENT.sub(lambda m: " " * len(m.group(0)), css)
    out: list[tuple[str, bool, int]] = []
    spans: list[tuple[int, int]] = []
    for m in _CSS_IMPORT.finditer(text):
        out.append((m.group("u1") or m.group("u2") or "", True, m.start()))
        spans.append(m.span())
    for m in _CSS_URL.finditer(text):
        if any(a <= m.start() < b for a, b in spans):
            continue
        out.append((m.group("u"), False, m.start()))
    return out


def _attr_items(doc: ParsedHTML) -> list[Item]:
    """Every subresource reference of the live DOM, classified active/passive as for mixed content (§WEB050)."""
    out: list[Item] = []
    resolved: dict[str, str] = {}

    def add(el: Element, attr: str, value: str | None, active: bool, category: str) -> None:
        if value is None or not value.strip():
            return
        url = resolved.get(value)
        if url is None:
            url = resolved[value] = doc.resolve(value)
        out.append(Item(url, value, f"{el.tag}[{attr}]", active, el, el.offset, category))

    for el in doc.elements:
        if not el.live:
            continue
        t, a = el.tag, el.attrs
        if t == "script" and "src" in a:
            add(el, "src", a["src"], True, "script")
        elif t in ("iframe", "frame") and "src" in a:
            add(el, "src", a["src"], True, "iframe")
        elif t == "link" and "href" in a:
            rels = el.tokens("rel")
            if rels & ACTIVE_LINK_RELS:
                cat = "style" if rels & {"stylesheet", "modulepreload"} else "other"
                add(el, "href", a["href"], True, cat)
            elif rels & PASSIVE_LINK_RELS:
                add(el, "href", a["href"], False, "other")
        elif t == "object" and "data" in a:
            add(el, "data", a["data"], True, "other")
        elif t == "embed" and "src" in a:
            add(el, "src", a["src"], True, "other")
        elif t == "applet":
            add(el, "code", a.get("code"), True, "other")
            for part in re.split(r"[\s,]+", a.get("archive") or ""):
                add(el, "archive", part or None, True, "other")
        elif t == "use":
            add(el, "href", a.get("href") or a.get("xlink:href"), True, "other")
        elif t == "img":
            add(el, "src", a.get("src"), False, "img")
            for u in htmlparse.srcset_urls(a.get("srcset")):
                add(el, "srcset", u, False, "img")
        elif t == "source":
            add(el, "src", a.get("src"), False, "other")
            for u in htmlparse.srcset_urls(a.get("srcset")):
                add(el, "srcset", u, False, "img")
        elif t in ("audio", "video"):
            add(el, "src", a.get("src"), False, "other")
            if t == "video":
                add(el, "poster", a.get("poster"), False, "img")
        elif t == "track":
            add(el, "src", a.get("src"), False, "other")
        if "background" in a:
            add(el, "background", a["background"], False, "img")
        if "style" in a and "url(" in a["style"].lower():
            for u, _active, _off in css_references(a["style"]):
                add(el, "style", u, False, "img")
    for st in doc.inline_styles:
        if not st.live:
            continue
        el = doc.elements[st.element] if 0 <= st.element < len(doc.elements) else None
        for u, active, off in css_references(st.text):
            if u:
                out.append(Item(doc.resolve(u), u, "style@import" if active else "style url()", active, el,
                                st.offset + off, "style" if active else "img"))
    return out


def _form_targets(doc: ParsedHTML) -> list[tuple[int, Item]]:
    """``(form element index, Item)`` for every live form action and submit-button formaction."""
    out: list[tuple[int, Item]] = []
    for form in doc.forms:
        if not form.live:
            continue
        el = doc.elements[form.element]
        if form.action_attr is not None:
            out.append((form.element, Item(form.action, form.action_attr, "form[action]", True, el, el.offset, "form")))
        for idx in form.inputs:
            ctl = doc.elements[idx]
            if ctl.live and ctl.tag in ("button", "input") and "formaction" in ctl.attrs and ctl.attrs["formaction"].strip():
                out.append((form.element, Item(doc.resolve(ctl.attrs["formaction"]), ctl.attrs["formaction"],
                                               f"{ctl.tag}[formaction]", True, ctl, ctl.offset, "form")))
    return out


def _sri_elements(doc: ParsedHTML) -> list[tuple[Element, str, str]]:
    """``(element, raw URL, resolved URL)`` of live ``script[src]`` and ``link[rel~=stylesheet|preload|modulepreload]``
    (``preload`` only for ``as=script|style``, the destinations SRI covers)."""
    out = []
    for el in doc.elements:
        if not el.live:
            continue
        if el.tag == "script" and (el.attrs.get("src") or "").strip():
            out.append((el, el.attrs["src"], doc.resolve(el.attrs["src"])))
        elif el.tag == "link" and (el.attrs.get("href") or "").strip():
            rels = el.tokens("rel")
            if not rels & SRI_LINK_RELS:
                continue
            if rels == {"preload"} or (rels & {"preload"} and not rels & {"stylesheet", "modulepreload"}):
                if (el.attrs.get("as") or "").strip().lower() not in ("script", "style"):
                    continue
            out.append((el, el.attrs["href"], doc.resolve(el.attrs["href"])))
    return out


def _password_inputs(doc: ParsedHTML, form) -> list[Element]:
    return [doc.elements[i] for i in form.inputs if doc.elements[i].live and doc.elements[i].tag == "input"
            and (doc.elements[i].attrs.get("type") or "").strip().lower() == "password"]


# ----------------------------------------------------------------------------------------------- the run

def _kind(r: Response) -> str:
    if r.kind:
        return r.kind
    if r.error or r.status is None:
        return "error"
    if r.is_2xx and r.essence in ("text/html", "application/xhtml+xml"):
        return "document"
    return "other"


_DECODABLE = {None, "", "identity", "gzip", "x-gzip", "deflate"}


def _opaque(r: Response) -> bool:
    if "opaque-coding" in r.flags:
        return True
    codings = [c.strip().lower() for c in (r.encoding or "").split(",") if c.strip()]
    return any(c not in _DECODABLE for c in codings)


_DOC_CHECKS = frozenset(c for c in CHECKS if c not in ("WEB503", "WEB517"))


class _Run:
    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.issues: list[Issue] = []
        self.evaluated: dict[str, set[str]] = {}
        self.failed: dict[str, set[str]] = {}
        self.states: dict[str, list[tuple[str, str, str]]] = {}   # check → [(state, reason, host)] explicit states
        self.paranoid = ctx.options.sensitivity == "paranoid"
        self.blocked: str = ""
        self.docs: list[tuple[Response, ParsedHTML]] = []
        self.opaque_hosts: set[str] = set()
        self._malicious: dict | None = None
        self._malicious_error = False
        self.pending_mixed: dict[int, tuple[Response, ParsedHTML, list[Item]]] = {}
        self._items: dict[int, list[Item]] = {}
        self._links: dict[int, list[tuple[Element, str]]] = {}
        self.ref_sites: set[str] | None = None
        if ctx.entry is not None and _kind(ctx.entry) in ("waf_challenge", "rate_limited"):
            self.blocked = "waf" if _kind(ctx.entry) == "waf_challenge" else "rate_limited"
        seen: set[int] = set()
        pages = list(ctx.pages)
        if ctx.entry is not None and not any(p.response is ctx.entry for p in pages):
            pages.insert(0, Page(ctx.entry, None, 0))     # an engine that did not list the entry document
        for page in pages:
            r = page.response
            if id(r) in seen or _kind(r) != "document":
                continue
            seen.add(id(r))
            if _opaque(r):
                self.opaque_hosts.add(r.host)
                continue
            doc = page.doc if page.doc is not None else htmlparse.parse_response(r)
            self.docs.append((r, doc))

    # -- bookkeeping ----------------------------------------------------------------------------------------
    def seen(self, check: str, host: str) -> None:
        self.evaluated.setdefault(check, set()).add(host)

    def state(self, check: str, state: str, reason: str = "", host: str = "") -> None:
        self.states.setdefault(check, []).append((state, reason, host))

    def emit(self, rule: str, r: Response, evidence: Evidence, *, severity: str | None = None,
             confidence: str | None = None, group_value: str = "", notes: list[tuple[str, str]] | None = None,
             url: str | None = None, host: str | None = None) -> None:
        meta = RULES[rule]
        conf = confidence or meta.confidence
        if conf not in meta.allowed_confidences:
            conf = meta.confidence
        sev = severity if severity in meta.allowed_severities else None
        if r.truncated:
            notes = [*(notes or []), _note("truncated")]
        h = host or r.host
        self.issues.append(Issue(rule=rule, url=url or r.url, confidence=conf, evidence=evidence,
                                 severity=sev, group_value=_short(group_value, 300), notes=list(notes or []), host=h))
        self.seen(meta.check_id, h)
        if self.ctx.options.reports(conf):
            self.failed.setdefault(meta.check_id, set()).add(h)

    def evidence(self, r: Response, *, where: str = "body", name: str = "", value: str = "",
                 offset: int | None = None, excerpt: str | None = None, secrets: tuple[str, ...] = ()) -> Evidence:
        if excerpt is None and offset is not None and where == "body":
            text = r.text()
            excerpt = text[offset: offset + 200]
        for secret in secrets:                      # §3.6: secrets in evidence keep only their first 4 + last 2
            if secret and len(secret) >= 8 and excerpt:
                excerpt = excerpt.replace(secret, redact_secret(secret))
        if secrets and excerpt:
            # the excerpt is raw markup: the value may be written percent-, plus- or entity-encoded there
            # ("a%40b.com", "Secr3t+Passw0rd"), so every long URL parameter value in it is reduced as well
            excerpt = _EXCERPT_PARAM.sub(lambda m: m.group(1) + redact_secret(m.group(2)), excerpt)
        return Evidence.for_response(r, where=where, name=name, value=strip_controls(value), offset=offset,
                                     excerpt=strip_controls(excerpt or ""), now=self.ctx.now)

    def links(self, doc: ParsedHTML) -> list[tuple[Element, str]]:
        """Live ``a``/``area`` elements with an href, resolved once per document."""
        if id(doc) not in self._links:
            self._links[id(doc)] = [(el, doc.resolve(el.attrs["href"])) for el in doc.find_all("a", "area")
                                    if (el.attrs.get("href") or "").strip()]
        return self._links[id(doc)]

    def items(self, doc: ParsedHTML) -> list[Item]:
        if id(doc) not in self._items:
            self._items[id(doc)] = _attr_items(doc)
        return self._items[id(doc)]

    # -- data -------------------------------------------------------------------------------------------------
    def malicious(self) -> dict:
        if self._malicious is None:
            loader = self.ctx.data
            if loader is None:
                from . import data as loader
            try:
                obj = loader.load_json(MALICIOUS_FILE)
            except (OSError, ValueError, AttributeError):
                obj, self._malicious_error = {}, True
            hosts = [(normalise_host(h.get("host", "")), h.get("match", "suffix"), h.get("reason", ""))
                     for h in (obj or {}).get("hosts", []) if h.get("host")]
            sigs = []
            for s in (obj or {}).get("signatures", []):
                flags = 0
                for ch in s.get("flags", ""):
                    flags |= {"i": re.I, "m": re.M, "s": re.S, "x": re.X}.get(ch, 0)
                try:
                    sigs.append((s["id"], s["kind"], re.compile(s["pattern"], flags)))
                except (re.error, KeyError):
                    continue
            self._malicious = {"hosts": hosts, "signatures": sigs}
        return self._malicious

    def malicious_host(self, host: str) -> tuple[str, str] | None:
        h = normalise_host(host)
        for entry, match, reason in self.malicious()["hosts"]:
            if h == entry or (match == "suffix" and h.endswith("." + entry)):
                return entry, reason
        return None

    # -- coverage ---------------------------------------------------------------------------------------------
    def record_coverage(self) -> None:
        cov = self.ctx.coverage
        if cov is None:
            return
        for check in CHECKS:
            hosts = self.evaluated.get(check, set())
            failed = self.failed.get(check, set())
            for host in sorted(hosts):
                (cov.failed if host in failed else cov.passed)(check, host)
            explicit = self.states.get(check, [])
            for state, reason, host in explicit:
                cov.record(check, state, reason, host=host)
            if hosts or explicit:
                continue
            if self.blocked and check in _DOC_CHECKS:
                cov.inconclusive(check, self.blocked)
            elif self.opaque_hosts and check in _DOC_CHECKS and not self.docs:
                cov.not_tested(check, "unsupported_coding")
            elif RULES[check].paranoid_only and not self.paranoid:
                cov.not_tested(check, "sensitivity")
            elif check in _DOC_CHECKS and not self.docs:
                cov.not_applicable(check, "no_document")
            else:
                cov.not_applicable(check)


def run(ctx: ScanContext) -> list[Issue]:
    """All §2.6 WEB050–WEB519 checks over the context (pure apart from ctx.observatory / inventory / coverage)."""
    _SITE_CACHE.clear()
    _HOST_CACHE.clear()
    _SCRIPT_WORDS.clear()
    _FORMS_BY_ELEMENT.clear()
    st = _Run(ctx)
    for r, doc in st.docs:
        items = st.items(doc)
        forms = _form_targets(doc)
        _mixed_content(st, r, doc, items)
        _forms_transport(st, r, doc, forms)
        _sri(st, r, doc)
        _opener(st, r, doc)
        _malicious_scripts(st, r, doc)
        _compromise(st, r, doc)
        _password_fields(st, r, doc)
        _login_get(st, r, doc)
        _url_params(st, r, doc)
        _upload(st, r, doc)
        _quirks(st, r, doc)
        _inline_handlers(st, r, doc)
        _csrf(st, r, doc)
        _cross_site_password(st, r, doc, forms)
        _unpinned(st, r, doc)
    _subresource_mixed(st)
    _compromise_files(st)
    _sri_verify(st)
    _dangling(st)
    if st.blocked:
        for check in _DOC_CHECKS:
            st.state(check, "inconclusive", st.blocked, ctx.entry.host if ctx.entry else "")
    st.record_coverage()
    ctx.observatory[OBS_TEST] = observatory_sri(ctx, st.docs)
    _inventory(st)
    return st.issues


# ----------------------------------------------------------------------------------------------- WEB050

def _uir(ctx: ScanContext, r: Response, doc: ParsedHTML) -> bool:
    """``upgrade-insecure-requests`` in an enforced CSP of the response (header or meta)."""
    facts = ctx.csp.get(r)
    if facts is not None:
        return bool(facts.upgrade_insecure_requests)
    policies = list(r.headers.get_all("content-security-policy"))
    policies += [m.attrs.get("content") or "" for m in doc.metas(http_equiv="content-security-policy")]
    for value in policies:
        for policy in value.split(","):
            for directive in policy.split(";"):
                parts = directive.strip().split()
                if parts and parts[0].lower() == "upgrade-insecure-requests":
                    return True
    return False


def _insecure(url: str) -> bool:
    return _scheme(url) == "http" and not is_loopback(_host(url))


def _mixed_content(st: _Run, r: Response, doc: ParsedHTML, items: list[Item]) -> None:
    if not r.is_https:
        return
    st.seen("WEB050", r.host)
    st.pending_mixed.setdefault(id(r), (r, doc, []))[2].extend(i for i in items if _insecure(i.url))


def _emit_mixed(st: _Run) -> None:
    for r, doc, found in st.pending_mixed.values():
        if not found:
            continue
        uniq: dict[tuple[str, bool], Item] = {}
        for i in found:
            uniq.setdefault((i.url, i.active), i)
        found = list(uniq.values())
        active = [i for i in found if i.active]
        uir = _uir(st.ctx, r, doc)
        sev = "info" if uir else ("medium" if active else "low")
        first = (active or found)[0]
        notes = [_note("mixed_items", items=_list([f"{i.where} {i.url}" for i in found]))]
        if active:
            notes.append(_note("mixed_active", count=_count(len(active), _COUNT_ACTIVE)))
        else:
            notes.append(_note("mixed_passive"))
        for i in found:
            if i.where == "redirect":
                notes.append(_note("mixed_hop", url=i.raw, hop=i.url))
            elif i.source_url:
                notes.append(_note("mixed_css", url=i.source_url))
        if uir:
            notes.append(_note("mixed_uir"))
        ev = st.evidence(r, name=first.where, value=first.url, offset=first.offset if first.source_url == "" else None)
        group = ("active:" if active else "passive:") + ",".join(sorted({_defrag(i.url).split("?", 1)[0] for i in found}))
        st.emit("WEB050", r, ev, severity=sev, group_value=group, notes=_dedupe(notes))


def _dedupe(notes: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return list(dict.fromkeys(notes))


def _referencing(st: _Run, url: str) -> list[tuple[Response, ParsedHTML, Item]]:
    """Documents (and the item) whose live DOM references ``url`` (fragment ignored)."""
    want = _defrag(url)
    out = []
    for r, doc in st.docs:
        for i in st.items(doc):
            if _defrag(i.url) == want:
                out.append((r, doc, i))
                break
    return out


def _subresource_mixed(st: _Run) -> None:
    """Fetched https subresources whose redirect chain has an http hop, and http references inside fetched same-site
    stylesheets (§WEB050), attributed to the https documents that reference them."""
    ctx = st.ctx
    pend = st.pending_mixed
    for r in [*ctx.subresources, *ctx.images]:
        hops = r.hops()
        first = hops[0]
        if first.scheme != "https":
            continue
        bad = next((h for h in hops[1:] if h.scheme == "http" and not is_loopback(h.host)), None)
        refs = _referencing(st, first.url)
        if bad is not None:
            active = _kind(r) in ("script", "style") or r.essence in ("text/css", "text/javascript",
                                                                       "application/javascript")
            for page, _doc, item in refs:
                if page.is_https and id(page) in pend:
                    pend[id(page)][2].append(Item(bad.url, first.url, "redirect", active or item.active, item.element,
                                                  item.offset, item.category))
        is_css = _kind(r) == "style" or r.essence == "text/css"
        if not is_css or not r.is_2xx or _opaque(r) or not psl.same_site(r.host, ctx.target_host or r.host):
            continue
        for u, active, _off in css_references(r.text()):
            resolved = urllib.parse.urljoin(r.url, u.strip())
            if not _insecure(resolved):
                continue
            for page, _doc, item in refs:
                if page.is_https and id(page) in pend:
                    pend[id(page)][2].append(Item(resolved, u, "css @import" if active else "css url()", active,
                                                  item.element, item.offset, "style" if active else "img", r.url))
    _emit_mixed(st)


# ----------------------------------------------------------------------------------------------- WEB051 / WEB052 / WEB504

_FORMS_BY_ELEMENT: dict[int, tuple[ParsedHTML, dict]] = {}


def _form_of(doc: ParsedHTML, form_index: int):
    """The :class:`Form` whose ``<form>`` element is ``form_index`` (indexed once per document: a linear search per
    form or per file input was quadratic on pages with thousands of forms)."""
    cached = _FORMS_BY_ELEMENT.get(id(doc))
    if cached is None or cached[0] is not doc:
        if len(_FORMS_BY_ELEMENT) > 64:
            _FORMS_BY_ELEMENT.clear()
        cached = _FORMS_BY_ELEMENT[id(doc)] = (doc, {f.element: f for f in doc.forms})
    return cached[1].get(form_index)


def _form_has_password(doc: ParsedHTML, form_index: int) -> bool:
    f = _form_of(doc, form_index)
    return f is not None and bool(_password_inputs(doc, f))


def _forms_transport(st: _Run, r: Response, doc: ParsedHTML, forms: list[tuple[int, Item]]) -> None:
    st.seen("WEB051", r.host)
    for form_index, item in forms:
        scheme = _scheme(item.url)
        if scheme == "http" and not is_loopback(_host(item.url)):
            explicit = item.raw.strip().lower().startswith("http://")
            if not r.is_https and not explicit:
                continue          # an http page posting to itself: WEB000/WEB052 explain it
            pw = _form_has_password(doc, form_index)
            notes = [_note("form_action", url=item.url)]
            if pw:
                notes.append(_note("form_password"))
            st.emit("WEB051", r, st.evidence(r, name=item.where, value=item.url, offset=item.offset),
                    severity="high" if pw else "medium", group_value=_defrag(item.url).split("?", 1)[0], notes=notes)
    if not r.is_https:
        st.seen("WEB052", r.host)
        pws = doc.password_inputs()
        if pws:
            el = pws[0]
            st.emit("WEB052", r, st.evidence(r, name="input[type=password]", value=el.attrs.get("name") or "",
                                             offset=el.offset))
        st.seen("WEB504", r.host)
        done: set[str] = set()
        for _fi, item in forms:
            if _scheme(item.url) == "https":
                key = _defrag(item.url).split("?", 1)[0]
                if key in done:
                    continue
                done.add(key)
                st.emit("WEB504", r, st.evidence(r, name=item.where, value=item.url, offset=item.offset),
                        group_value=key, notes=[_note("form_action", url=item.url)])


# ----------------------------------------------------------------------------------------------- WEB053 / WEB500–WEB502

@dataclass
class IntegrityPolicy:
    present: bool = False
    valid: bool = True
    error: str = ""
    destinations: frozenset[str] = frozenset()
    report_only: bool = False
    raw: str = ""


def integrity_policy(r: Response, header: str = "integrity-policy") -> IntegrityPolicy:
    """Parse ``Integrity-Policy`` (or ``Integrity-Policy-Report-Only``) as an RFC 8941 Dictionary."""
    fields = r.headers.get_all(header)
    if not fields:
        return IntegrityPolicy(report_only=header.endswith("report-only"))
    value, err = sfv.try_parse("dictionary", fields)
    raw = ", ".join(fields)
    if err is not None:
        return IntegrityPolicy(True, False, str(err), frozenset(), header.endswith("report-only"), raw)
    dests: set[str] = set()
    member = value.get("blocked-destinations")
    if isinstance(member, sfv.InnerList):
        dests = {str(i.value).lower() for i in member.items if isinstance(i.value, sfv.Token)}
    sources = value.get("sources")
    if isinstance(sources, sfv.InnerList):
        toks = {str(i.value).lower() for i in sources.items if isinstance(i.value, sfv.Token)}
        if toks and "inline" not in toks:        # only the "inline" source is defined: anything else blocks nothing
            dests = set()
    return IntegrityPolicy(True, True, "", frozenset(dests), header.endswith("report-only"), raw)


def _sri(st: _Run, r: Response, doc: ParsedHTML) -> None:
    page_site = _site(r.host)
    page_origin = url_origin(r.url)
    ip = integrity_policy(r)
    for rule in ("WEB053", "WEB500", "WEB501", "WEB502"):
        st.seen(rule, r.host)
    per_host: dict[str, list[tuple[Element, str, str]]] = {}
    for el, raw, url in _sri_elements(doc):
        scheme = _scheme(url)
        if scheme not in ("http", "https"):
            continue                                   # data:, blob:, javascript: … are not fetched from a host
        meta = parse_sri(el.attrs.get("integrity"))
        has_attr = "integrity" in el.attrs and not meta.empty
        host = _host(url)
        third = bool(host) and _site(host) != page_site
        cross_origin = url_origin(url) != page_origin
        if has_attr:
            gv = _defrag(url)
            # WEB501: no supported algorithm, or a supported one whose digest is malformed
            if not meta.has_metadata:
                st.emit("WEB501", r, st.evidence(r, name=f"{el.tag}[integrity]", value=meta.raw, offset=el.offset),
                        group_value=gv, notes=[_note("sri_unknown_alg", value=_short(meta.raw, 80))])
            else:
                bad = [t for t in meta.strongest() if not t.well_formed]
                if bad:
                    t = bad[0]
                    st.emit("WEB501", r, st.evidence(r, name=f"{el.tag}[integrity]", value=meta.raw, offset=el.offset),
                            group_value=gv, notes=[_note("sri_bad_digest", value=_short(t.raw, 80),
                                                         bytes=_count(SRI_ALGORITHMS[t.algorithm], _COUNT_BYTES),
                                                         alg=t.algorithm)])
            # WEB502: integrity on an http URL (on an https page WEB050 already explains the element)
            if scheme == "http" and not is_loopback(host) and not r.is_https:
                st.emit("WEB502", r, st.evidence(r, name=f"{el.tag}[src]" if el.tag == "script" else "link[href]",
                                                 value=url, offset=el.offset), group_value=gv)
            # WEB500: cross-origin, no crossorigin attribute → no-cors → opaque → blocked
            module = el.tag == "script" and (el.attrs.get("type") or "").strip().lower() == "module"
            cors_by_default = module or (el.tag == "link" and "modulepreload" in el.tokens("rel"))
            if meta.has_metadata and cross_origin and "crossorigin" not in el.attrs and not cors_by_default:
                st.emit("WEB500", r, st.evidence(r, name=el.tag, value=url, offset=el.offset), group_value=gv,
                        notes=[_note("sri_nocors", url=url)])
            continue
        if third:
            per_host.setdefault(host, []).append((el, raw, url))
    for host, els in per_host.items():
        sevs: list[str] = []
        evergreen: list[str] = []
        versioned = False
        enforced: list[str] = []
        for el, _raw, url in els:
            product = evergreen_product(url)
            dest = ("script" if el.tag == "script" or "modulepreload" in el.tokens("rel")
                    or (el.attrs.get("as") or "").strip().lower() == "script" else "style")
            if ip.valid and dest in ip.destinations:
                enforced.append(url)
                sevs.append("info")
            elif product:
                evergreen.append(product)
                sevs.append("info")
            elif versioned_public_cdn(url):
                versioned = True
                sevs.append("low")
            else:
                sevs.append("info")
        sev = "low" if "low" in sevs else "info"
        files = [u for _e, _r, u in els]
        notes = [_note("sri_files", items=_list(files))]
        if versioned:
            notes.append(_note("sri_versioned"))
        if evergreen:
            notes.append(_note("sri_evergreen", items=", ".join(dict.fromkeys(evergreen))))
        if enforced:
            notes.append(_note("sri_ip_enforced"))
        if ip.present and not ip.valid:
            notes.append(_note("sri_ip_invalid", error=_short(ip.error, 80)))
        el0 = els[0][0]
        st.emit("WEB053", r, st.evidence(r, name=el0.tag, value=els[0][2], offset=el0.offset), severity=sev,
                group_value=host, notes=notes)


# ----------------------------------------------------------------------------------------------- WEB503

def _sri_verify(st: _Run) -> None:
    """Deep (or any fetched subresource): the decoded body must satisfy the element's integrity metadata."""
    ctx = st.ctx
    wanted: dict[str, list[tuple[Response, Element, SriMetadata, str]]] = {}
    for r, doc in st.docs:
        for el, _raw, url in _sri_elements(doc):
            meta = parse_sri(el.attrs.get("integrity"))
            # a strongest-algorithm digest that does not even decode is WEB501's finding, not a changed file
            if meta.has_metadata and _scheme(url) in ("http", "https") and any(t.well_formed for t in meta.strongest()):
                wanted.setdefault(_defrag(url), []).append((r, el, meta, url))
    if not wanted:
        return
    by_url: dict[str, Response] = {}
    for s in ctx.subresources:
        by_url.setdefault(_defrag(s.hops()[0].url), s)
        by_url.setdefault(_defrag(s.url), s)
    verified = 0
    for url, refs in wanted.items():
        s = by_url.get(url)
        if s is None:
            continue
        page = refs[0][0]
        if s.truncated or _opaque(s) or s.error or not s.is_2xx:
            if s.truncated or _opaque(s):
                st.state("WEB503", "not_tested", "truncated" if s.truncated else "unsupported_coding", page.host)
            continue
        verified += 1
        st.seen("WEB503", page.host)
        for r, el, meta, _u in refs:
            if meta.matches(s.body) is False:
                strongest = meta.strongest()
                actual = sri_digest(strongest[0].algorithm, s.body)
                notes = [_note("sri_mismatch", expected=", ".join(t.raw for t in strongest), actual=actual),
                         _note("sri_rewrite")]
                ev = Evidence.for_response(s, where="body", name="integrity", value=actual,
                                           excerpt=", ".join(t.raw for t in strongest), now=ctx.now)
                st.emit("WEB503", r, ev, group_value=url, notes=notes, url=r.url, host=r.host)
                break
    if not verified and ctx.options.profile != "deep":
        st.state("WEB503", "not_tested", "deep_off")


# ----------------------------------------------------------------------------------------------- WEB505

def _opener(st: _Run, r: Response, doc: ParsedHTML) -> None:
    st.seen("WEB505", r.host)
    page_site = _site(r.host)
    for el in doc.find_all("a", "area"):
        target = (el.attrs.get("target") or "").strip().lower()
        if not target or target in ("_self", "_parent", "_top"):
            continue
        rels = el.tokens("rel")
        if "opener" not in rels or rels & {"noopener", "noreferrer"}:
            continue
        url = doc.resolve(el.attrs.get("href"))
        host = _host(url)
        if _scheme(url) not in ("http", "https") or not host or _site(host) == page_site:
            continue
        st.emit("WEB505", r, st.evidence(r, name=f"{el.tag}[rel]", value=url, offset=el.offset),
                group_value=_site(host), notes=[_note("opener", url=url, rel=el.attrs.get("rel", ""))])


# ----------------------------------------------------------------------------------------------- WEB506 / WEB507

_URL_IN_SCRIPT = re.compile(r"(?:https?:)?//([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9-]+)+)", re.I)


def _malicious_scripts(st: _Run, r: Response, doc: ParsedHTML) -> None:
    if not st.malicious()["hosts"]:
        if st._malicious_error:
            st.state("WEB506", "not_tested", "data_missing", r.host)
        return
    st.seen("WEB506", r.host)
    reported: set[str] = set()
    for el in doc.find_all("script"):
        src = (el.attrs.get("src") or "").strip()
        if not src:
            continue
        url = doc.resolve(src)
        hit = st.malicious_host(_host(url))
        if hit and hit[0] not in reported:
            reported.add(hit[0])
            st.emit("WEB506", r, st.evidence(r, name="script[src]", value=url, offset=el.offset), confidence="certain",
                    group_value=hit[0], notes=[_note("malicious_host", host=hit[0], reason=hit[1])])
    for sc in doc.inline_scripts:
        if not sc.live or not sc.is_javascript:
            continue
        for m in _URL_IN_SCRIPT.finditer(sc.text):
            hit = st.malicious_host(normalise_host(m.group(1)))
            if hit and hit[0] not in reported:
                reported.add(hit[0])
                st.emit("WEB506", r, st.evidence(r, name="script", value=m.group(0), offset=sc.offset + m.start()),
                        confidence="firm", group_value=hit[0],
                        notes=[_note("malicious_inline", host=hit[0]), _note("malicious_host", host=hit[0], reason=hit[1])])


def _signatures(st: _Run, kinds: tuple[str, ...]):
    return [s for s in st.malicious()["signatures"] if s[1] in kinds]


def _compromise(st: _Run, r: Response, doc: ParsedHTML) -> None:
    sigs = _signatures(st, ("miner", "loader"))
    deface = _signatures(st, ("defacement",))
    if not sigs and not deface:
        if st._malicious_error:
            st.state("WEB507", "not_tested", "data_missing", r.host)
        return
    st.seen("WEB507", r.host)
    hits: list[tuple[str, str, tuple[str, str], int | None, str]] = []    # (id, kind, where, offset, matched)
    for sc in doc.inline_scripts:
        if not sc.live or not sc.is_javascript:
            continue
        for sid, kind, rx in sigs:
            m = rx.search(sc.text)
            if m:
                hits.append((sid, kind, _why("inline_script"), sc.offset + m.start(), m.group(0)))
    for el in doc.find_all("script"):
        src = el.attrs.get("src")
        if not src:
            continue
        url = doc.resolve(src)
        for sid, kind, rx in sigs:
            m = rx.search(url)
            if m:
                hits.append((sid, kind, _why("script_url"), el.offset, url))
    for sid, kind, rx in deface:
        # the phrase must open the title ("~ Hacked by X ~"): a headline such as "Site hacked by group, says report"
        # on a news page carries it in the middle and is not a defacement
        m = rx.search(doc.title) if doc.title else None
        if m and not any(ch.isalnum() for ch in doc.title[:m.start()]) and rx.search(doc.visible_text):
            hits.append((sid, kind, _why("title_text"), None, doc.title))
    seen: set[str] = set()
    for sid, kind, where, offset, matched in hits:
        if sid in seen:
            continue
        seen.add(sid)
        st.emit("WEB507", r, st.evidence(r, name=sid, value=matched, offset=offset), group_value=sid,
                notes=[_note("compromise", id=sid, kind=kind, where=where)])


def _compromise_files(st: _Run) -> None:
    """Miner/loader signatures in fetched script files, reported on the page that loads them."""
    sigs = _signatures(st, ("miner", "loader"))
    if not sigs:
        return
    reported = {(i.host, i.group_value) for i in st.issues if i.rule == "WEB507"}
    for s in st.ctx.subresources:
        if not s.is_2xx or _opaque(s) or not (_kind(s) == "script" or "javascript" in s.essence):
            continue
        text = s.text()
        for sid, kind, rx in sigs:
            m = rx.search(text)
            if not m:
                continue
            refs = _referencing(st, s.hops()[0].url)
            page = refs[0][0] if refs else (st.docs[0][0] if st.docs else None)
            if page is None or (page.host, sid) in reported:
                continue
            reported.add((page.host, sid))
            ev = Evidence.for_response(s, where="body", name=sid, value=m.group(0), offset=m.start(),
                                       excerpt=strip_controls(text[m.start(): m.start() + 200]), now=st.ctx.now)
            st.emit("WEB507", page, ev, group_value=sid, url=page.url, host=page.host,
                    notes=[_note("compromise", id=sid, kind=kind, where=_why("script_file", url=s.url))])


# ----------------------------------------------------------------------------------------------- WEB508 / WEB509

_PASTE_BLOCK = re.compile(r"return\s+false|preventDefault\s*\(", re.I)


def _password_fields(st: _Run, r: Response, doc: ParsedHTML) -> None:
    pws = doc.password_inputs()
    st.seen("WEB508", r.host)
    for el in pws:
        ac = (el.attrs.get("autocomplete") or "").strip().lower()
        paste = el.attrs.get("onpaste") or ""
        if ac == "off":
            st.emit("WEB508", r, st.evidence(r, name="input[autocomplete]", value=ac, offset=el.offset),
                    group_value="autocomplete", notes=[_note("password_autocomplete", value=ac)])
            return
        if paste and _PASTE_BLOCK.search(paste):
            st.emit("WEB508", r, st.evidence(r, name="input[onpaste]", value=paste, offset=el.offset),
                    group_value="paste", notes=[_note("password_paste", value=_short(paste, 60))])
            return


_SCRIPT_WORD = re.compile(r"[\w$-]+")
_SCRIPT_WORDS: dict[int, tuple[ParsedHTML, str, frozenset[str]]] = {}


def _script_mentions(doc: ParsedHTML, name: str) -> bool:
    """``name`` appears as a whole word (not inside a longer ``[\\w$-]`` run) in a live inline script. The words of
    the scripts are collected once per document: one regex scan per form made a page with thousands of forms and a
    large inline script take minutes."""
    if not name or len(name) < 2:
        return False
    cached = _SCRIPT_WORDS.get(id(doc))
    if cached is None or cached[0] is not doc:
        text = "\n".join(sc.text for sc in doc.inline_scripts if sc.live)
        if len(_SCRIPT_WORDS) > 64:
            _SCRIPT_WORDS.clear()
        cached = _SCRIPT_WORDS[id(doc)] = (doc, text, frozenset(_SCRIPT_WORD.findall(text)))
    if _SCRIPT_WORD.fullmatch(name):
        return name in cached[2]
    if name not in cached[1]:                      # names with other characters (rare): substring prefilter first
        return False
    return bool(re.search(r"(?<![\w$-])" + re.escape(name) + r"(?![\w$-])", cached[1]))


def _login_get(st: _Run, r: Response, doc: ParsedHTML) -> None:
    st.seen("WEB509", r.host)
    done: set[tuple[str, str]] = set()          # one issue per (destination, variant) and page
    for form in doc.forms:
        if not form.live or not _password_inputs(doc, form):
            continue
        el = doc.elements[form.element]
        method = form.method
        # submit buttons: <button> defaults to type=submit, <input> to type=text (never a submitter)
        submitters = [c for c in (doc.elements[i] for i in form.inputs) if c.live and (
            (c.tag == "button" and (c.attrs.get("type") or "submit").strip().lower() == "submit")
            or (c.tag == "input" and (c.attrs.get("type") or "").strip().lower() in ("submit", "image")))]
        if any((s.attrs.get("formmethod") or "").strip().lower() == "post" for s in submitters):
            continue
        if method in ("post", "dialog"):
            continue
        gv = _defrag(form.action).split("?", 1)[0]
        if method:
            if (gv, "explicit") in done:
                continue
            done.add((gv, "explicit"))                                   # explicit get (or an invalid value: the browser uses GET)
            st.emit("WEB509", r, st.evidence(r, name="form[method]", value=method, offset=el.offset),
                    severity="high", confidence="certain", group_value=gv,
                    notes=[_note("login_get_explicit", value=method)])
            continue
        why: list[tuple[str, str]] = []
        if form.action_attr is None or not form.action_attr.strip():
            why.append(_why("no_action"))
        if "onsubmit" in el.attrs:
            why.append(_why("onsubmit"))
        if _script_mentions(doc, el.attrs.get("id", "")) or _script_mentions(doc, el.attrs.get("name", "")):
            why.append(_why("script_ref"))
        if "app" in r.roles:
            why.append(_why("app"))
        if (gv, "js" if why else "default") in done:
            continue
        done.add((gv, "js" if why else "default"))
        if why:
            reason = (", ".join(w[0] for w in why), "، ".join(w[1] for w in why))
            st.emit("WEB509", r, st.evidence(r, name="form", value=form.action, offset=el.offset), severity="low",
                    confidence="tentative", group_value=gv, notes=[_note("login_get_js", why=reason)])
        else:
            st.emit("WEB509", r, st.evidence(r, name="form", value=form.action, offset=el.offset), severity="high",
                    confidence="certain", group_value=gv, notes=[_note("login_get_default")])


# ----------------------------------------------------------------------------------------------- WEB510–WEB512

# ZAP InfoSessionIdUrl default session tokens + framework names (lower-case)
SESSION_PARAMS = frozenset({
    "asp.net_sessionid", "aspsessionid", "siteserver", "cfid", "cftoken", "jsessionid", "phpsessid", "sessid", "sid",
    "viewstate", "zenid", "sessionid", "session_id", "session", "laravel_session", "ci_session", "connect.sid",
    "_session_id", "phpsessionid", "sess_id", "s_id", "osessionid", "wt.sessionid"})
# generic names that sites also use for other things (a conference "session", a numeric "sid" = site id): their value
# must look like a token, not a slug such as "keynote-2024-day1" or a short number
_GENERIC_SESSION_PARAMS = frozenset({"session", "sid", "sessionid", "session_id", "sessid", "sess_id", "s_id"})
_TOKEN_VALUE = re.compile(r"^[A-Za-z0-9+/=.]{9,}$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _session_value(name: str, value: str) -> bool:
    """A session-id parameter value that is worth reporting (ZAP: longer than 8 characters)."""
    if len(value) <= 8 or _TEMPLATE.search(value):
        return False
    if name in _GENERIC_SESSION_PARAMS:
        return bool(_TOKEN_VALUE.match(value)) and not (value.isdigit() and len(value) < 16)
    return True


_PATH_SESSION = re.compile(r";(jsessionid|phpsessid|sessionid|sid)=([0-9A-Za-z._-]{8,})", re.I)
_ASPNET_COOKIELESS = re.compile(r"/\(S\(([a-z0-9]{24})\)\)/", re.I)
SENSITIVE_PARAMS = frozenset({"password", "passwd", "pwd", "token", "api_key", "apikey", "secret", "access_token",
                              "auth"})
REDIRECT_PARAMS = frozenset({"next", "url", "redirect", "return", "returnto", "continue", "dest", "goto"})
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")
_TEMPLATE = re.compile(r"[{}$<>%]|^(?:null|undefined|none|true|false|x+|\*+)$", re.I)


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


# issuer prefixes and lengths of the major card schemes (Visa, Mastercard incl. 2-series, Amex, Diners, JCB,
# Discover/UnionPay/RuPay 6x, Maestro 50/56-69, Mir 2200-2204). A bare Luhn check flags one numeric id in ten, e.g.
# millisecond timestamps (13 digits starting with 1) used as cache-busters in links.
_CARD_IIN = re.compile(r"^(?:4\d{12}(?:\d{3}){0,2}|5[1-5]\d{14}|2(?:22[1-9]|2[3-9]\d|[3-6]\d\d|7[01]\d|720)\d{12}"
                       r"|220[0-4]\d{12}|3[47]\d{13}|3(?:0[0-5]|[689]\d)\d{11,16}|35(?:2[89]|[3-8]\d)\d{12,15}"
                       r"|6\d{15,18}|5[06-9]\d{11,17})$")


def _card(value: str) -> bool:
    d = re.sub(r"[ -]", "", value)
    return d.isdigit() and 13 <= len(d) <= 19 and len(set(d)) > 1 and bool(_CARD_IIN.match(d)) and luhn_ok(d)


def _nontrivial(value: str) -> bool:
    v = value.strip()
    if len(v) < 8 or len(set(v)) < 4 or _TEMPLATE.search(v):
        return False
    return any(c.isdigit() for c in v) or len(v) >= 16


def _site_urls(st: _Run, r: Response, doc: ParsedHTML) -> list[tuple[str, Element | None, str]]:
    """Same-site URLs of the page: links, GET-form submissions (hidden fields), and the page's own URL."""
    site = _site(r.host)
    out: list[tuple[str, Element | None, str]] = [(r.url, None, "page")]
    for el, url in st.links(doc):
        out.append((url, el, f"{el.tag}[href]"))
    for form in doc.forms:
        if not form.live or form.effective_method() != "get":
            continue
        pairs = []
        for i in form.inputs:
            ctl = doc.elements[i]
            if ctl.live and ctl.tag == "input" and (ctl.attrs.get("type") or "").strip().lower() == "hidden" \
                    and ctl.attrs.get("name"):
                pairs.append((ctl.attrs["name"], ctl.attrs.get("value") or ""))
        if pairs:
            base = _defrag(form.action).split("?", 1)[0]
            out.append((base + "?" + urllib.parse.urlencode(pairs), doc.elements[form.element], "form[method=get]"))
    return [(u, el, w) for u, el, w in out if _scheme(u) in ("http", "https") and _host(u)
            and _site(_host(u)) == site]


def _offsite_links(st: _Run, r: Response, doc: ParsedHTML) -> bool:
    site = _site(r.host)
    for _el, u in st.links(doc):
        if _scheme(u) in ("http", "https") and _host(u) and _site(_host(u)) != site:
            return True
    return False


def _url_params(st: _Run, r: Response, doc: ParsedHTML) -> None:
    for rule in ("WEB510", "WEB511", "WEB512"):
        st.seen(rule, r.host)
    urls = _site_urls(st, r, doc)
    done: dict[str, set[str]] = {"WEB510": set(), "WEB511": set(), "WEB512": set()}
    offsite = None
    for url, el, where in urls:
        offset = el.offset if el is not None else None
        # WEB510: session ids in the URL (query, ;jsessionid= path parameters, ASP.NET cookieless sessions)
        hits: list[tuple[str, str]] = []
        for name, value in _query_pairs(url):
            if name.strip().lower() in SESSION_PARAMS and _session_value(name.strip().lower(), value):
                hits.append((name, value))
        if ";" in url:
            for m in _PATH_SESSION.finditer(url):
                hits.append((m.group(1), m.group(2)))
        m = _ASPNET_COOKIELESS.search(url) if "(S(" in url or "(s(" in url else None
        if m:
            hits.append(("(S(…))", m.group(1)))
        for name, value in hits:
            key = name.lower()
            if key in done["WEB510"]:
                continue
            done["WEB510"].add(key)
            if offsite is None:
                offsite = _offsite_links(st, r, doc)
            notes = [_note("session_param", name=name, length=_count(len(value), _COUNT_CHARS), url=_redact_url(url))]
            if offsite:
                notes.append(_note("session_referer"))
            st.emit("WEB510", r, st.evidence(r, name=where, value=_redact_url(url), offset=offset,
                                             excerpt="" if offset is None else None, secrets=(value,)),
                    group_value=key, notes=notes)
        # WEB511 / WEB512
        for name, value in _query_pairs(url):
            low = name.strip().lower()
            why = None
            if low in SENSITIVE_PARAMS and _nontrivial(value):
                why = _why("secret_name")
            elif _EMAIL.match(value.strip()):
                why = _why("email")
            elif _card(value):
                why = _why("card")
            if why and low not in done["WEB511"]:
                done["WEB511"].add(low)
                st.emit("WEB511", r, st.evidence(r, name=where, value=_redact_url(url), offset=offset,
                                                 excerpt="" if offset is None else None, secrets=(value,)),
                        group_value=low, notes=[_note("sensitive_param", name=name, url=_redact_url(url), why=why)])
            v = value.strip()
            if low in REDIRECT_PARAMS and re.match(r"^https?://[^/\s]", v, re.I) and low not in done["WEB512"]:
                done["WEB512"].add(low)
                st.emit("WEB512", r, st.evidence(r, name=where, value=url, offset=offset,
                                                 excerpt="" if offset is None else None),
                        group_value=low, notes=[_note("redirect_param", name=name, value=_short(v, 100), url=url)])


_EXCERPT_PARAM = re.compile(r"((?:[?&;]|&amp;)[^=&\"'\s<>#]{1,64}=)([^&\"'\s<>#]{8,})")


def _redact_url(url: str) -> str:
    """The URL with every query value and ;param value of 8+ characters reduced to first 4 + last 2 (§3.6)."""
    def red(v: str) -> str:
        return v if len(v) < 8 else f"{v[:4]}…{v[-2:]}"
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    path = _PATH_SESSION.sub(lambda m: f";{m.group(1)}={red(m.group(2))}", p.path)
    path = _ASPNET_COOKIELESS.sub(lambda m: f"/(S({red(m.group(1))}))/", path)
    q = "&".join(f"{k}={red(v)}" if v else k for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True))
    return urllib.parse.urlunsplit((p.scheme, p.netloc, path, q, ""))


# ----------------------------------------------------------------------------------------------- WEB513 / WEB514 / WEB515

def _upload(st: _Run, r: Response, doc: ParsedHTML) -> None:
    st.seen("WEB513", r.host)
    done: set[str] = set()
    for el in doc.find_all("input"):
        if (el.attrs.get("type") or "").strip().lower() != "file":
            continue
        f = _form_of(doc, el.form) if el.form >= 0 else None
        action = f.action if f is not None else r.url
        key = _defrag(action).split("?", 1)[0]
        if key in done:
            continue
        done.add(key)
        st.emit("WEB513", r, st.evidence(r, name="input[type=file]", value=el.attrs.get("name") or "", offset=el.offset),
                group_value=key, notes=[_note("upload", name=el.attrs.get("name") or "-", url=action)])


# HTML §13.2.6.4.1 ("initial" insertion mode): public identifiers that set quirks mode (prefixes, lower-cased)
_QUIRKS_PUBLIC_PREFIXES = (
    "+//silmaril//dtd html pro v0r11 19970101//", "-//as//dtd html 3.0 aswedit + extensions//",
    "-//advasoft ltd//dtd html 3.0 aswedit + extensions//", "-//ietf//dtd html", "-//metrius//dtd metrius presentational//",
    "-//microsoft//dtd internet explorer 2.0 ", "-//microsoft//dtd internet explorer 3.0 ",
    "-//netscape comm. corp.//dtd html//", "-//netscape comm. corp.//dtd strict html//",
    "-//o'reilly and associates//dtd html 2.0//", "-//o'reilly and associates//dtd html extended 1.0//",
    "-//o'reilly and associates//dtd html extended relaxed 1.0//", "-//sq//dtd html 2.0 hotmetal + extensions//",
    "-//softquad software//dtd hotmetal pro 6.0::19990601::extensions to html 4.0//",
    "-//softquad//dtd hotmetal pro 4.0::19971010::extensions to html 4.0//", "-//spyglass//dtd html 2.0 extended//",
    "-//sun microsystems corp.//dtd hotjava html//", "-//sun microsystems corp.//dtd hotjava strict html//",
    "-//w3c//dtd html 3 1995-03-24//", "-//w3c//dtd html 3.2 draft//", "-//w3c//dtd html 3.2 final//",
    "-//w3c//dtd html 3.2//", "-//w3c//dtd html 3.2s draft//", "-//w3c//dtd html 4.0 frameset//",
    "-//w3c//dtd html 4.0 transitional//", "-//w3c//dtd html experimental 19960712//",
    "-//w3c//dtd html experimental 970421//", "-//w3c//dtd w3 html//", "-//w3o//dtd w3 html 3.0//",
    "-//webtechs//dtd mozilla html 2.0//", "-//webtechs//dtd mozilla html//")
_QUIRKS_PUBLIC_EXACT = ("-//w3o//dtd w3 html strict 3.0//en//", "-/w3c/dtd html 4.0 transitional/en", "html")
_QUIRKS_IF_NO_SYSTEM = ("-//w3c//dtd html 4.01 frameset//", "-//w3c//dtd html 4.01 transitional//")
_QUIRKS_SYSTEM = "http://www.ibm.com/data/dtd/v11/ibmxhtml1-transitional.dtd"
_DOCTYPE = re.compile(r"""^(?P<name>\S+)(?:\s+public\s*(?P<q>["'])(?P<pub>.*?)(?P=q)(?:\s*(?P<q2>["'])(?P<sys>.*?)(?P=q2))?"""
                      r"""|\s+system\s*(?P<q3>["'])(?P<sys2>.*?)(?P=q3))?""", re.S)


def quirks_mode(doctype: str | None) -> bool:
    """No doctype, a doctype whose name is not ``html``, or a legacy public/system identifier that triggers quirks
    mode (HTML §13.2.6.4.1). ``doctype`` is what follows ``<!DOCTYPE``, lower-cased (htmlparse)."""
    if doctype is None:
        return True
    d = doctype.strip().lower()
    m = _DOCTYPE.match(d)
    if m is None or m.group("name") != "html":
        return True
    pub = m.group("pub")
    system = m.group("sys") if m.group("sys") is not None else m.group("sys2")
    if system == _QUIRKS_SYSTEM:
        return True
    if pub is None:
        return False
    if pub in _QUIRKS_PUBLIC_EXACT or pub.startswith(_QUIRKS_PUBLIC_PREFIXES):
        return True
    return system is None and pub.startswith(_QUIRKS_IF_NO_SYSTEM)


def _quirks(st: _Run, r: Response, doc: ParsedHTML) -> None:
    st.seen("WEB514", r.host)
    if r.essence == "application/xhtml+xml" or not quirks_mode(doc.doctype):    # XML documents are never in quirks
        return
    for el in doc.links("stylesheet"):
        href = (el.attrs.get("href") or "").strip()
        if not href or href.startswith(("/", "#")) or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", href):
            continue
        st.emit("WEB514", r, st.evidence(r, name="link[href]", value=href, offset=el.offset),
                notes=[_note("quirks", url=href)])
        return


def _inline_handlers(st: _Run, r: Response, doc: ParsedHTML) -> None:
    if not st.paranoid:
        return
    st.seen("WEB515", r.host)
    handlers, js_urls, first = 0, 0, None
    for el in doc.live_elements():
        for name, value in el.attrs.items():
            if name.startswith("on") and len(name) > 2 and name.isalpha():
                handlers += 1
                first = first or (el, name)
            elif name in ("href", "src", "action", "formaction") and value.strip().lower().startswith("javascript:"):
                js_urls += 1
                first = first or (el, name)
    if handlers or js_urls:
        el, name = first
        st.emit("WEB515", r, st.evidence(r, name=f"{el.tag}[{name}]", value=el.attrs.get(name, ""), offset=el.offset),
                notes=[_note("inline_handlers", handlers=handlers, urls=js_urls)])   # bare numbers: no noun to agree


# ----------------------------------------------------------------------------------------------- WEB516

# ZAP anti-CSRF token names (Options → Anti-CSRF) + common framework names; names containing csrf/xsrf also count
CSRF_NAMES = frozenset({"anticsrf", "csrftoken", "__requestverificationtoken", "csrfmiddlewaretoken",
                        "authenticity_token", "owasp_csrftoken", "anoncsrf", "csrf_token", "_csrf", "_csrfsecret",
                        "__csrf_magic", "csrf", "_token", "_csrf_token", "_csrftoken", "form_key", "form_build_id",
                        "_wpnonce", "nonce"})
_SEARCH_NAMES = frozenset({"q", "query", "search", "s", "keyword", "keywords", "term"})


def _csrf(st: _Run, r: Response, doc: ParsedHTML) -> None:
    if not st.paranoid:
        return
    st.seen("WEB516", r.host)
    sessions = [c for c in st.ctx.cookies if c.is_session_class and not c.deletion and not c.ignored
                and psl.same_site(c.host or r.host, r.host)]
    if any((c.samesite or "").strip().lower() in ("lax", "strict") for c in sessions):
        return
    for form in doc.forms:
        if not form.live or form.method != "post":
            continue
        controls = [doc.elements[i] for i in form.inputs if doc.elements[i].live]
        names = [(c.attrs.get("name") or "").strip().lower() for c in controls]
        if any(n in CSRF_NAMES or "csrf" in n or "xsrf" in n for n in names):
            continue
        meaningful = [c for c in controls if c.tag in ("input", "textarea", "select")
                      and (c.attrs.get("type") or "text").strip().lower() not in ("hidden", "submit", "button", "reset",
                                                                                   "image", "search")
                      and (c.attrs.get("name") or "").strip().lower() not in _SEARCH_NAMES]
        if not meaningful:
            continue
        el = doc.elements[form.element]
        st.emit("WEB516", r, st.evidence(r, name="form[method=post]", value=form.action, offset=el.offset),
                group_value=_defrag(form.action).split("?", 1)[0], notes=[_note("csrf_form")])


# ----------------------------------------------------------------------------------------------- WEB518 / WEB519

def _referenced_sites(st: _Run) -> set[str]:
    """Sites referenced anywhere on the scanned pages (subresources and links), computed once per run."""
    if st.ref_sites is None:
        out: set[str] = set()
        for _r, doc in st.docs:
            for i in st.items(doc):
                if _host(i.url):
                    out.add(_site(_host(i.url)))
            for _el, u in st.links(doc):
                if _host(u):
                    out.add(_site(_host(u)))
        st.ref_sites = out
    return st.ref_sites


def _cross_site_password(st: _Run, r: Response, doc: ParsedHTML, forms: list[tuple[int, Item]]) -> None:
    st.seen("WEB518", r.host)
    page_site = _site(r.host)
    done: set[str] = set()
    for form_index, item in forms:
        if _scheme(item.url) not in ("http", "https") or not _form_has_password(doc, form_index):
            continue
        host = _host(item.url)
        if not host or _site(host) == page_site or _site(host) in done:
            continue
        done.add(_site(host))
        notes = [_note("cross_site_form", host=host)]
        sev = "low"
        if st.malicious_host(host):
            sev = "medium"
            notes.append(_note("cross_site_malicious", host=host))
        elif _site(host) not in _referenced_sites(st):
            sev = "medium"
            notes.append(_note("cross_site_lonely", host=host))
        st.emit("WEB518", r, st.evidence(r, name=item.where, value=item.url, offset=item.offset), severity=sev,
                group_value=_site(host), notes=notes)


def _unpinned(st: _Run, r: Response, doc: ParsedHTML) -> None:
    st.seen("WEB519", r.host)
    for el in doc.elements:
        if not el.live:
            continue
        if el.tag == "script":
            raw = el.attrs.get("src")
        elif el.tag == "link" and el.tokens("rel") & {"modulepreload", "stylesheet"}:
            raw = el.attrs.get("href")
        else:
            continue
        if not raw or not raw.strip() or ("integrity" in el.attrs and parse_sri(el.attrs["integrity"]).has_metadata):
            continue
        url = doc.resolve(raw)
        bad = [p for p in cdn_pin(url) if not p.pinned]
        if not bad:
            continue
        p = bad[0]
        st.emit("WEB519", r, st.evidence(r, name=f"{el.tag}[{'src' if el.tag == 'script' else 'href'}]", value=url,
                                         offset=el.offset),
                group_value=_defrag(url), notes=[_note("unpinned", url=url, why=_why(p.why))])


# ----------------------------------------------------------------------------------------------- WEB517

# names that certainly exist: if the resolver says one of them does not, it cannot resolve public names
CANARY_HOSTS = frozenset({
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "ajax.googleapis.com", "code.jquery.com",
    "www.googletagmanager.com", "www.google-analytics.com", "fonts.googleapis.com", "fonts.gstatic.com",
    "www.gstatic.com", "www.google.com", "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
    "connect.facebook.net", "js.stripe.com", "static.cloudflareinsights.com", "www.youtube.com",
    "platform.twitter.com", "ajax.aspnetcdn.com", "www.recaptcha.net", "use.fontawesome.com", "kit.fontawesome.com"})
KNOWN_REGISTERED = frozenset({
    "cloudflare.com", "jsdelivr.net", "unpkg.com", "googleapis.com", "gstatic.com", "google.com", "jquery.com",
    "googletagmanager.com", "google-analytics.com", "bootstrapcdn.com", "facebook.net", "stripe.com",
    "cloudflareinsights.com", "youtube.com", "twitter.com", "aspnetcdn.com", "microsoft.com", "amazonaws.com",
    "recaptcha.net", "fontawesome.com", "paypal.com", "hotjar.com", "intercom.io", "akamaihd.net",
    # trackers, ads and consent managers: DNS filters (corporate resolvers, NextDNS/AdGuard in NXDOMAIN mode) answer
    # "name does not exist" for them, which would otherwise read as "unregistered domain, anyone can take it" (A)
    "clarity.ms", "hs-scripts.com", "hs-analytics.net", "hsforms.net", "hubspot.com", "segment.com", "licdn.com",
    "linkedin.com", "bing.com", "ads-twitter.com", "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "taboola.com", "outbrain.com", "criteo.com", "criteo.net", "mxpnl.com", "mixpanel.com", "amplitude.com",
    "newrelic.com", "nr-data.net", "sentry-cdn.com", "cookielaw.org", "onetrust.com", "cookiebot.com", "tiktok.com",
    "pinimg.com", "yandex.ru", "quantserve.com", "scorecardresearch.com", "adroll.com", "zdassets.com", "tawk.to",
    "optimizely.com", "fullstory.com", "mouseflow.com", "crazyegg.com", "facebook.com", "adnxs.com",
    "amazon-adsystem.com", "addthis.com", "sharethis.com", "disqus.com", "typekit.net"})
_STORAGE_HOST = re.compile(r"(?:^|\.)(?:s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?|storage\.googleapis\.com"
                           r"|blob\.core\.windows\.net|digitaloceanspaces\.com)$")
_BUCKET_GONE = re.compile(r"<Code>\s*NoSuchBucket\s*</Code>|ContainerNotFound|The specified container does not exist",
                          re.I)
_HIGH_CATEGORIES = ("script", "style", "iframe")
_SEV_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}


def resolver_guard(ctx: ScanContext) -> str | None:
    """None when DNS answers can be trusted for WEB517, else the coverage reason (``proxied`` | ``resolver``)."""
    if ctx.proxied or any(rec.reason == "proxied" for rec in ctx.dns.values()):
        return "proxied"
    for host, rec in ctx.dns.items():
        if rec.status == "nxdomain" and normalise_host(host) in CANARY_HOSTS:
            return "resolver"
        if rec.registrable_status == "nxdomain" and (rec.registrable or _site(host)) in KNOWN_REGISTERED:
            return "resolver"
    for host, rec in ctx.dns.items():
        if rec.status == "ok" and _public_name(normalise_host(host)):
            return None
    target = ctx.target_host
    if _public_name(target) and ctx.entry is not None and ctx.entry.status is not None and ctx.entry.ip:
        return None
    return "resolver"


def _referenced_hosts(st: _Run) -> dict[str, list[tuple[Response, Item]]]:
    """Third-party hosts referenced by live elements of the documents (with the page and the element)."""
    own = {st.ctx.target_host, *(r.host for r, _d in st.docs)}
    if st.ctx.entry is not None:
        own |= {h.host for h in st.ctx.entry.hops()}
    out: dict[str, list[tuple[Response, Item]]] = {}
    for r, doc in st.docs:
        items = st.items(doc) + [i for _f, i in _form_targets(doc)]
        for i in items:
            h = _host(i.url)
            if not h or _scheme(i.url) not in ("http", "https") or h in own or _ip(h) is not None:
                continue
            out.setdefault(h, []).append((r, i))
    return out


DNS_REFERENCED_CAP = 30
_CATEGORY_PRIORITY = {"script": 0, "style": 1, "iframe": 2, "form": 3, "img": 4, "other": 5}


def dns_candidates(pages: list, target: str = "", limit: int = DNS_REFERENCED_CAP) -> list[str]:
    """The third-party hosts WEB517 judges, in priority order (script, style, iframe, form, image, other), for the engine
    to resolve into ``ctx.dns`` (§0.1: ≤ 30 referenced hosts, then one registrable-domain lookup for each nxdomain).
    Reserved names, IP literals and the target's own hosts are left out. ``pages`` are :class:`Page` objects."""
    own = {normalise_host(urllib.parse.urlsplit(target).hostname or "")} if target else set()
    best: dict[str, int] = {}
    order: list[str] = []
    for p in pages:
        doc = p.doc if p.doc is not None else None
        if doc is None or _kind(p.response) != "document" or _opaque(p.response):
            continue
        own.add(p.response.host)
        for i in _attr_items(doc) + [i for _f, i in _form_targets(doc)]:
            h = _host(i.url)
            if not h or _scheme(i.url) not in ("http", "https") or _ip(h) is not None or _reserved_name(h):
                continue
            rank = _CATEGORY_PRIORITY.get(i.category, 5)
            if h not in best:
                order.append(h)
                best[h] = rank
            else:
                best[h] = min(best[h], rank)
    hosts = [h for h in order if h not in own]
    hosts.sort(key=lambda h: best[h])          # stable: document order inside one category
    return hosts[:limit]


def _worst_category(refs: list[tuple[Response, Item]]) -> str:
    cats = [i.category for _r, i in refs]
    for c in ("script", "style", "iframe", "form", "img"):
        if c in cats:
            return c
    return "other"


def _dangling(st: _Run) -> None:
    ctx = st.ctx
    refs = _referenced_hosts(st)
    # variant C (no DNS involved): a deleted storage bucket answered the browser-equivalent fetch
    c_hosts: set[str] = set()
    for s in ctx.subresources:
        host = s.host
        if not _STORAGE_HOST.search(host) or s.status != 404 or _opaque(s) or not _BUCKET_GONE.search(s.text()[:4096]):
            continue
        first = s.hops()[0].url
        page_refs = _referencing(st, first)
        if not page_refs and not st.docs:
            continue
        page = page_refs[0][0] if page_refs else st.docs[0][0]
        cat = page_refs[0][2].category if page_refs else ("style" if _kind(s) == "style" else "script")
        m = _BUCKET_GONE.search(s.text())
        code = re.sub(r"<[^>]+>", "", m.group(0)).strip() if m else ""
        ev = Evidence.for_response(s, where="body", name="bucket", value=code, offset=m.start() if m else None,
                                   excerpt=strip_controls(s.text()[:200]), now=ctx.now)
        st.emit("WEB517", page, ev, severity="high" if cat in ("script", "style") else "medium", confidence="firm",
                group_value=host, url=page.url, host=page.host, notes=[_note("dns_c", url=s.url, code=code)])
        c_hosts.add(host)
    if not refs and not c_hosts:
        return
    if ctx.options.profile == "minimal":
        st.state("WEB517", "not_tested", "profile")
        return
    guard = resolver_guard(ctx)
    if guard is not None:
        st.state("WEB517", "not_tested", guard, ctx.target_host)
        return
    judged = False
    looked_up = False
    macos = PLATFORM == "darwin" and not _hooked()
    for host, hrefs in sorted(refs.items()):
        if host in c_hosts or _reserved_name(host):
            continue
        rec = ctx.dns.get(host)
        if rec is None:
            continue
        looked_up = True
        if rec.status == "not_tested":
            st.state("WEB517", "not_tested", rec.reason if rec.reason in REASONS else "not_run", host)
            continue
        intranet = _intranet_name(host)
        if rec.status == "tempfail" or (rec.status == "nxdomain" and not intranet
                                        and rec.registrable_status in ("", "tempfail", "not_tested")):
            st.state("WEB517", "not_tested", "network", host)
            continue
        judged = True
        page, item = hrefs[0]
        if rec.status != "nxdomain":
            st.seen("WEB517", page.host)
            continue
        cat = _worst_category(hrefs)
        ref_list = _note("dns_refs", items=_list(sorted({f"{i.where} {i.url}" for _p, i in hrefs})))
        ev = Evidence.for_response(page, where="dns", name=host, value=rec.status, offset=item.offset,
                                   excerpt=strip_controls(page.text()[item.offset: item.offset + 200])
                                   if item.offset is not None else "", now=ctx.now)
        domain = rec.registrable or psl.registrable_domain(host) or host
        if intranet:
            if _public_name(ctx.target_host):
                st.emit("WEB517", page, ev, severity="info", confidence="firm", group_value=host,
                        notes=[_note("dns_intranet", host=host), ref_list])
            else:
                st.seen("WEB517", page.host)
            continue
        if rec.registrable_status == "nxdomain":
            notes = [_note("dns_a", host=host, domain=domain), ref_list]
            conf = "firm"
            if macos:
                conf = "tentative"
                notes.append(_note("dns_a_macos"))
            st.emit("WEB517", page, ev, severity="high" if cat in _HIGH_CATEGORIES else "medium", confidence=conf,
                    group_value=host, notes=notes)
        else:
            st.emit("WEB517", page, ev, severity="low", confidence="tentative", group_value=host,
                    notes=[_note("dns_b", host=host, domain=domain), ref_list])
    if not judged and not c_hosts:
        if refs and not looked_up:
            st.state("WEB517", "not_tested", "not_run", ctx.target_host)    # the engine resolved none of them
        elif not looked_up or not st.states.get("WEB517"):
            st.state("WEB517", "not_applicable", "", ctx.target_host)


# ----------------------------------------------------------------------------------------------- Observatory

_OBS_GOODNESS = ("sri-implemented-and-all-scripts-loaded-securely",
                 "sri-implemented-and-external-scripts-loaded-securely",
                 "sri-implemented-but-external-scripts-not-loaded-securely",
                 "sri-not-implemented-but-external-scripts-loaded-securely",
                 "sri-not-implemented-and-external-scripts-not-loaded-securely",
                 "sri-not-implemented-response-not-html")


def _obs_auto(ctx: ScanContext) -> Response | None:
    """Observatory's ``responses.auto``: the https session's final response when https answered, else http's."""
    for r in (ctx.entry, ctx.https_probe, ctx.http_probe):
        if r is not None and r.is_https and r.status is not None and not r.error:
            return r
    for r in (ctx.entry, ctx.http_probe):
        if r is not None and r.status is not None and not r.error:
            return r
    return None


def _only_if_worse(new: str, old: str | None) -> str:
    if not old:
        return new
    return new if _OBS_GOODNESS.index(new) > _OBS_GOODNESS.index(old) else old


def observatory_sri_slug(response: Response | None, site_host: str, doc: ParsedHTML | None = None) -> str:
    """``subresource-integrity`` exactly as mdn-http-observatory 1.7.2 computes it, quirks included: only
    ``<script src>`` is examined; a raw (untrimmed, case-sensitive) ``http(s)://`` prefix decides absolute vs relative;
    a protocol-relative ``//x`` src is foreign and never "secure"; registrable domains use tldts without the PSL
    private section; ``<script>`` tags inside ``<template>``/``<noscript>`` count (htmlparser2 parses them)."""
    if response is None:
        return "sri-not-implemented-but-no-scripts-loaded"
    ctype = response.headers.first("content-type")
    mime = (ctype if ctype is not None else "").strip().split(";", 1)[0]
    if mime and mime not in ("text/html", "application/xhtml+xml"):
        return "sri-not-implemented-response-not-html"
    if doc is None:
        doc = htmlparse.parse(response.text(), response.url)
    scripts = [e for e in doc.elements if e.tag == "script"]
    site_domain = psl.registrable_domain(site_host, private=False)
    session_https = response.hops()[0].scheme == "https"
    result: str | None = None
    foreign_seen = False
    for el in scripts:
        src = el.attrs.get("src")
        if not src:
            continue
        integrity = el.attrs.get("integrity") or None
        relative_origin = relative_protocol = False
        if re.match(r"^//[^/]", src):
            relative_protocol = True
            same_domain = True
        elif re.match(r"^https?://", src):
            same_domain = psl.registrable_domain(_host(src), private=False) == site_domain
        else:
            relative_origin = True
            same_domain = True
        secure_origin = relative_origin or (same_domain and not relative_protocol)
        if not secure_origin:
            foreign_seen = True
        scheme = None if (relative_protocol or relative_origin) else _scheme(src) + ":"
        secure_scheme = scheme == "https:" or (relative_origin and session_https)
        if not secure_origin:
            if integrity and not secure_scheme:
                result = _only_if_worse("sri-implemented-but-external-scripts-not-loaded-securely", result)
            elif not integrity and secure_scheme:
                result = _only_if_worse("sri-not-implemented-but-external-scripts-loaded-securely", result)
            elif not integrity and not secure_scheme:
                result = _only_if_worse("sri-not-implemented-and-external-scripts-not-loaded-securely", result)
        elif integrity and secure_scheme and not result:
            result = "sri-implemented-and-all-scripts-loaded-securely"
    if not scripts:
        return "sri-not-implemented-but-no-scripts-loaded"
    if not result:
        return ("sri-implemented-and-external-scripts-loaded-securely" if foreign_seen
                else "sri-not-implemented-but-all-scripts-loaded-from-secure-origin")
    return result


def observatory_sri(ctx: ScanContext, docs: list[tuple[Response, ParsedHTML]] = ()) -> str:
    auto = _obs_auto(ctx)
    doc = next((d for r, d in docs if r is auto), None)
    return observatory_sri_slug(auto, ctx.target_host, doc)


# ----------------------------------------------------------------------------------------------- inventory

def _inventory(st: _Run) -> None:
    forms = []
    third: dict[str, set[str]] = {}
    for r, doc in st.docs:
        site = _site(r.host)
        for f in doc.forms:
            if not f.live:
                continue
            ctls = [doc.elements[i] for i in f.inputs]
            types = {(c.attrs.get("type") or "").strip().lower() for c in ctls if c.tag == "input"}
            forms.append({"page": r.url, "method": f.effective_method(), "action": f.action,
                          "password": "password" in types, "file": "file" in types,  # nosec - field-type test
                          "cross_site": bool(_host(f.action)) and _site(_host(f.action)) != site})
        for i in st.items(doc):
            h = _host(i.url)
            if h and _scheme(i.url) in ("http", "https") and _site(h) != site:
                kind = {"script": "script", "style": "style", "iframe": "frame", "img": "image"}.get(i.category, "other")
                third.setdefault(h, set()).add(kind)
    inv = st.ctx.inventory
    inv["forms"] = forms[:200]
    inv["third_parties"] = {h: sorted(k) for h, k in sorted(third.items())}
    if st.docs:
        r = st.docs[0][0]
        pol = {}
        for header in ("integrity-policy", "integrity-policy-report-only"):
            ip = integrity_policy(r, header)
            if ip.present:
                pol[header] = {"value": _short(ip.raw, 300), "valid": ip.valid, "error": ip.error,
                               "blocked_destinations": sorted(ip.destinations), "enforced": not ip.report_only}
        if pol:
            inv["integrity_policy"] = pol


# ----------------------------------------------------------------------------------------------- i18n

def i18n_catalog() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """``(CATALOG, PATTERNS)`` for cat_web2: fixed Arabic notes → English, regex patterns for templated ones."""
    catalog: dict[str, str] = {}
    patterns: list[tuple[str, str]] = []
    for en, ar in [*STR.values(), *WHY.values()]:
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
        patterns.append(("^" + "".join(out) + "$", _PLACEHOLDER.sub(lambda m: f"\\g<{m.group(1)}>", en)))
    for en_one, en_many, ar_forms in COUNT_FORMS.values():
        catalog[ar_forms[0]] = en_one.replace("{n}", "1")
        catalog[ar_forms[1]] = en_many.replace("{n}", "2")
        for form in ar_forms[2:]:
            rx = "^" + re.escape(form).replace(re.escape("{n}"), r"(?P<n>\d+)") + "$"
            patterns.append((rx, en_many.replace("{n}", r"\g<n>")))
    return catalog, patterns


__all__ = ["CHECKS", "run", "STR", "WHY", "SriToken", "SriMetadata", "parse_sri", "sri_digest", "CdnPin", "cdn_pin",
           "versioned_public_cdn", "evergreen_product", "EVERGREEN", "IntegrityPolicy", "integrity_policy",
           "css_references", "quirks_mode", "luhn_ok", "is_loopback", "resolver_guard", "observatory_sri",
           "observatory_sri_slug", "SESSION_PARAMS", "SENSITIVE_PARAMS", "REDIRECT_PARAMS", "CSRF_NAMES",
           "CANARY_HOSTS", "KNOWN_REGISTERED", "OBS_TEST", "MALICIOUS_FILE", "dns_candidates", "i18n_catalog"]
