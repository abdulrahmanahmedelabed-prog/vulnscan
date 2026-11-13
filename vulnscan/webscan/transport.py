"""Transport, redirect chains and HSTS (spec §2.1), WP6.

Rules: WEB000, WEB101–WEB106, WEB-strict-transport-security, WEB110–WEB119. The module also writes the MDN Observatory v6
slugs of the ``redirection`` and ``strict-transport-security`` tests into ``ctx.observatory`` (``mdn-http-observatory``
1.7.2 logic, quirks included: the HSTS test takes the first field, a comma anywhere makes it invalid and ``max-age`` is
read with JavaScript ``parseInt``, so a quoted value passes).

Stage 1 (§4.2): :func:`hsts_facts` returns ``host → HstsVerdict`` for every https host of the scan (plus the preloaded
parents that cover them), which cookies.py reads for the HSTS mitigation of WEB020 without importing this module.

Inputs, all from the context (nothing here touches the network):

* the http chain: ``ctx.entry`` when the target is ``http://``, else ``ctx.http_probe``; the https counterpart of an http
  target is ``ctx.https_probe`` (WEB000 variants A/B); every other fetched chain for WEB103/WEB106/WEB117;
* the fetcher's flags: ``cert-error`` (HSTS is not judged on a host whose certificate failed), ``redirect-loop`` and
  ``redirect-limit`` (WEB104), ``obs-fold:strict-transport-security`` (a note, never a failure: RFC 9112 §5.2 says to
  replace obs-fold with a space before interpreting), ``opaque-coding`` (WEB119 cannot read the body);
* ``ctx.cookies`` (WEB114: a session cookie with a ``Domain`` attribute raises it to low), ``ctx.tls`` (SHA-1 leaf for
  WEB115, read defensively because its shape is owned by WP10), ``Response.kind`` from classify.py.

The HSTS grammar is RFC 6797 §6.1 with the stricter points the spec adopts from hstspreload (leading zero) and Chromium
(a comma inside one field). The preload snapshot is ``data/web/hsts-preload.json.gz`` (Chromium, BSD-3-Clause); the 52
preloaded TLDs are also inlined here so a missing data file never hides them.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Iterable

from . import htmlparse, psl
from .rules import PLURAL_PARAMS, RULES, checks_for_module
from .types import (
    Evidence,
    HstsVerdict,
    Issue,
    ParsedHTML,
    Response,
    ScanContext,
    normalise_host,
    strip_controls,
)

CHECKS: tuple[str, ...] = checks_for_module("transport")

STS = "strict-transport-security"
ONE_YEAR = 31_536_000                 # hstspreload minimum, ASVS 5.0 3.4.1
SIX_MONTHS = 15_552_000               # Observatory's "six months" (180 days)
TEN_YEARS = 315_360_000               # hstspreload warning
MAX_AGE_MAX = 2 ** 64 - 1             # beyond this hstspreload's ParseUint overflows
PRELOAD_MAX_REDIRECTS = 3             # hstspreload redirects.too_many
TEMPORARY_REDIRECTS = (302, 303, 307)
PRELOAD_DATA = "hsts-preload.json.gz"

# Chromium's preloaded TLDs (policy "public-suffix", all include_subdomains), 2026-11-13. Inlined so the hosts under them
# are recognised even when the data file is missing (§4.4); tools/webdata/hsts_preload.py prints the current list.
PRELOADED_TLDS = frozenset({
    "amazon", "android", "app", "audible", "azure", "bank", "bing", "boo", "channel", "chrome", "dad", "day", "dev", "eat",
    "esq", "fire", "fly", "foo", "fujitsu", "gle", "gmail", "google", "hangout", "here", "hotmail", "imdb", "ing",
    "insurance", "kindle", "meet", "meme", "microsoft", "mov", "new", "nexus", "office", "page", "phd", "play", "prime",
    "prof", "rsvp", "search", "silk", "skype", "windows", "xbox", "xn--cckwcxetd", "xn--jlq480n2rg", "youtube", "zappos",
    "zip"})

# ----------------------------------------------------------------------------------------------- user-facing text

# (en, ar) note templates. ``{name}`` values come from the scanned site and are substituted literally (:func:`_note`), so a
# value with braces cannot inject a format string (§0.6).
STR: dict[str, tuple[str, str]] = {
    "http_served": ("{url} answered {status} with content over plain HTTP instead of redirecting to HTTPS.",
                    "أجاب {url} بالحالة {status} ومعه محتوى عبر HTTP غير المشفّر بدل التوجيه إلى HTTPS."),
    "variant_a": ("Variant A: HTTPS is not available on this host ({reason}).",
                  "الحالة A: لا يتوفر HTTPS على هذا المضيف ({reason})."),
    "variant_b": ("Variant B: HTTPS works ({url}), but plain HTTP still serves the content.",
                  "الحالة B: يعمل HTTPS ({url})، لكن HTTP غير المشفّر ما زال يقدّم المحتوى."),
    "https_cert": ("its certificate does not validate", "شهادته غير صالحة"),
    "https_down": ("the HTTPS request failed", "فشل طلب HTTPS"),
    "https_port": ("HTTPS not checked: the target uses a non-default port.",
                   "لم يُفحص HTTPS: الهدف يستخدم منفذًا غير افتراضي."),
    "https_profile": ("HTTPS not checked: the minimal profile sends no counterpart request.",
                      "لم يُفحص HTTPS: ملف الفحص minimal لا يرسل طلب النظير."),
    "preloaded": ("{host} is in the browsers' HSTS preload list ({entry}), so browsers never use plain HTTP for it.",
                  "المضيف {host} مدرج في قائمة HSTS المسبقة في المتصفحات ({entry})، فلا تستخدم المتصفحات HTTP غير المشفّر معه."),
    "loopback": ("{host} is a loopback address (a developer's local server).",
                 "المضيف {host} عنوان استرجاع محلي (خادم تطوير على الجهاز نفسه)."),
    "api": ("This is an API response: refuse plain HTTP instead of redirecting it (ASVS 5.0 4.1.2).",
            "هذه استجابة واجهة API: ارفض HTTP غير المشفّر بدل توجيهه (ASVS 5.0 4.1.2)."),
    "chain": ("Redirect chain: {chain}", "سلسلة التوجيه: {chain}"),
    "first_hop_http": ("The first redirect goes from {src} to {dst}, which is still plain HTTP.",
                       "يذهب أول توجيه من {src} إلى {dst}، وهو ما زال HTTP غير مشفّر."),
    "first_hop_host": ("The first redirect goes from {src} straight to another host ({dst}), so HSTS can never be set for "
                       "{host}.",
                       "يذهب أول توجيه من {src} مباشرة إلى مضيف آخر ({dst})، فلا يمكن ضبط HSTS للمضيف {host} أبدًا."),
    "downgrade": ("{src} redirects to the plain-HTTP address {dst}.", "يوجّه {src} إلى العنوان غير المشفّر {dst}."),
    "meta_downgrade": ("<meta http-equiv=\"refresh\"> on this HTTPS page sends the browser to {dst}.",
                       "وسم <meta http-equiv=\"refresh\"> في صفحة HTTPS هذه يرسل المتصفح إلى {dst}."),
    "script_downgrade": ("An inline script assigns the plain-HTTP address {dst} to location (line {line}).",
                         "سكربت داخلي يسند العنوان غير المشفّر {dst} إلى location (السطر {line})."),
    "too_long": ("The chain has {hops} before the final response; hstspreload accepts at most 3.",
                 "تمر السلسلة بـ {hops} قبل الاستجابة النهائية؛ ولا يقبل hstspreload أكثر من 3."),
    "loop": ("The redirect chain loops ({url} repeats).", "سلسلة التوجيه دائرية (يتكرر {url})."),
    "limit": ("The chain was still redirecting after {hops}; Kashif stops there, as browsers stop after about 20.",
              "كانت السلسلة ما زالت توجّه بعد {hops}؛ يتوقف كاشف عندها، كما تتوقف المتصفحات بعد نحو 20 قفزة."),
    "temporary": ("The HTTP→HTTPS redirect uses status {status}; browsers do not cache it, so every visit starts on HTTP.",
                  "يستخدم التوجيه من HTTP إلى HTTPS الحالة {status}؛ ولا تخزّنه المتصفحات، فتبدأ كل زيارة عبر HTTP."),
    "big_redirect": ("The {status} response carries {length} bytes of page content ({signals}); first text: {text}",
                     "تحمل استجابة {status} مقدار {length} بايت من محتوى الصفحة ({signals})؛ أول النص: {text}"),
    "sts_missing": ("{url} has no Strict-Transport-Security header.",
                    "لا توجد ترويسة Strict-Transport-Security في {url}."),
    "sts_preloaded_info": ("Already enforced by the browsers' preload list ({entry}); the header still protects browsers "
                           "with an old list and other clients.",
                           "الحماية مطبّقة أصلًا عبر قائمة المتصفحات المسبقة ({entry})؛ ولا تزال الترويسة تحمي المتصفحات ذات "
                           "القائمة القديمة والعملاء الآخرين."),
    "sts_zero": ("max-age is 0: browsers delete the HSTS entry for {host}.",
                 "القيمة max-age تساوي 0: فتحذف المتصفحات سجل HSTS للمضيف {host}."),
    "sts_short": ("max-age is {seconds} seconds (about {days}).", "القيمة max-age هي {seconds} ثانية (نحو {days})."),
    "sts_long": ("max-age is {seconds} seconds (about {days}), more than ten years.",
                 "القيمة max-age هي {seconds} ثانية (نحو {days})، أي أكثر من عشر سنوات."),
    "sts_value": ("Header value: {value}", "قيمة الترويسة: {value}"),
    "sts_multi_same": ("The same value is sent in {fields}; browsers use the first.",
                       "تُرسَل القيمة نفسها في {fields}؛ وتستخدم المتصفحات الأولى."),
    "sts_multi_diff": ("The header is sent in {fields} with different values; browsers use only the first: {value}",
                       "تُرسَل الترويسة في {fields} بقيم مختلفة؛ ولا تستخدم المتصفحات إلا الأولى: {value}"),
    "sts_no_isd": ("Subdomains of {host} are not covered by HSTS.", "النطاقات الفرعية للمضيف {host} لا تغطيها HSTS."),
    "sts_isd_cookie": ("The session cookie {cookie} is sent to every host under {domain}, but HSTS does not cover them.",
                       "الكوكي {cookie} للجلسة يُرسَل إلى كل مضيف تحت {domain}، لكن HSTS لا تغطي هذه المضيفات."),
    "sts_obs_fold": ("The header was folded over several lines (obsolete line folding); it was read as one line.",
                     "كانت الترويسة مطوية على عدة أسطر (طيّ أسطر متقادم)؛ وقُرئت كسطر واحد."),
    "preload_fail": ("Not eligible for the preload list: {codes}", "غير مستوفٍ لشروط القائمة المسبقة: {codes}"),
    "preload_ok": ("Eligible for the HSTS preload list but not in the bundled snapshot of {date} (it may be pending).",
                   "مستوفٍ لشروط قائمة HSTS المسبقة لكنه غير موجود في النسخة المضمّنة بتاريخ {date} (ربما ما زال الطلب قيد "
                   "المراجعة)."),
    "preload_unchecked": ("Not checked: {what}.", "لم يُفحص: {what}."),
    "preload_http_unchecked": ("the HTTP redirect of {host} was not fetched", "لم يُجلب توجيه HTTP للمضيف {host}"),
    "sts_on_http": ("{url} sends Strict-Transport-Security over plain HTTP, where browsers ignore it.",
                    "يرسل {url} الترويسة Strict-Transport-Security عبر HTTP غير المشفّر، حيث يتجاهلها المتصفح."),
    "sts_meta": ("<meta http-equiv=\"Strict-Transport-Security\"> has no effect.",
                 "الوسم <meta http-equiv=\"Strict-Transport-Security\"> لا أثر له."),
    "hop_no_sts": ("{src} redirects to {dst} without an HSTS header, so HSTS is never set for {host}.",
                   "يوجّه {src} إلى {dst} بلا ترويسة HSTS، فلا تُضبط HSTS للمضيف {host} أبدًا."),
    "auth_http": ("{url} asks for {scheme} authentication over plain HTTP.",
                  "يطلب {url} مصادقة {scheme} عبر HTTP غير المشفّر."),
    "breach": ("The page is sent with Content-Encoding: {coding} and contains the secret form field {field}.",
               "تُرسَل الصفحة مع Content-Encoding: {coding} وتحتوي على حقل النموذج السري {field}."),
}

# hstspreload-style issue codes (``HstsVerdict.problems``, WEB112/WEB115 notes) → (en, ar)
CODES: dict[str, tuple[str, str]] = {
    "header.parse.empty": ("the header is empty", "الترويسة فارغة"),
    "header.parse.comma": ("a comma inside one field (folded duplicates; Chromium rejects the header)",
                           "فاصلة داخل حقل واحد (قيم مكررة مدمجة؛ يرفض Chromium الترويسة)"),
    "header.parse.non_ascii": ("non-ASCII or control characters (for example curly quotes)",
                               "أحرف غير ASCII أو أحرف تحكم (مثل علامات التنصيص المنحنية)"),
    "header.parse.quoted_directive": ("quotes before max-age", "علامات تنصيص قبل max-age"),
    "header.parse.max_age.missing": ("max-age is missing", "القيمة max-age مفقودة"),
    "header.parse.invalid.max_age.no_value": ("max-age has no value", "القيمة max-age بلا قيمة"),
    "header.parse.max_age.non_digit_characters": ("max-age contains characters that are not digits",
                                                  "القيمة max-age تحتوي على أحرف ليست أرقامًا"),
    "header.parse.max_age.leading_zero": ("max-age has a leading zero (hstspreload rejects it)",
                                          "القيمة max-age تبدأ بصفر (يرفضها hstspreload)"),
    "header.parse.max_age.parse_int_error": ("max-age is too large to parse", "القيمة max-age أكبر من أن تُقرأ"),
    "header.parse.repeated.max_age": ("max-age is repeated", "القيمة max-age مكررة"),
    "header.parse.repeated.include_sub_domains": ("includeSubDomains is repeated", "التوجيه includeSubDomains مكرر"),
    "header.parse.repeated.preload": ("preload is repeated", "التوجيه preload مكرر"),
    "header.parse.invalid.include_sub_domains": ("includeSubDomains has a value", "التوجيه includeSubDomains له قيمة"),
    "header.parse.invalid.preload": ("preload has a value, so it is not recognised", "التوجيه preload له قيمة فلا يُعتدّ به"),
    "header.parse.empty_directive": ("an empty directive or extra semicolon", "توجيه فارغ أو فاصلة منقوطة زائدة"),
    "header.parse.unknown_directive": ("an unknown directive is ignored", "توجيه غير معروف يُهمَل"),
    "response.multiple_headers": ("more than one Strict-Transport-Security header", "أكثر من ترويسة Strict-Transport-Security"),
    "header.preloadable.include_sub_domains.missing": ("includeSubDomains is missing", "التوجيه includeSubDomains مفقود"),
    "header.preloadable.preload.missing": ("preload is missing", "التوجيه preload مفقود"),
    "header.preloadable.max_age.missing": ("max-age is missing", "القيمة max-age مفقودة"),
    "header.preloadable.max_age.zero": ("max-age is 0", "القيمة max-age تساوي 0"),
    "header.preloadable.max_age.below_1_year": ("max-age is below one year (31536000)",
                                                "القيمة max-age أقل من سنة (31536000)"),
    "redirects.http.no_redirect": ("HTTP does not redirect to HTTPS", "لا يوجّه HTTP إلى HTTPS"),
    "redirects.http.www_first": ("HTTP redirects to www first instead of to HTTPS on the same host",
                                 "يوجّه HTTP أولًا إلى www بدل HTTPS على نفس المضيف"),
    "redirects.http.first_redirect.insecure": ("the first HTTP redirect is not to HTTPS on the same host",
                                               "أول توجيه من HTTP ليس إلى HTTPS على نفس المضيف"),
    "redirects.http.first_redirect.no_hsts": ("the first HTTPS response after the HTTP redirect has no preloadable HSTS",
                                              "أول استجابة HTTPS بعد توجيه HTTP لا تحمل HSTS صالحة للإدراج المسبق"),
    "redirects.http.useless_header": ("the HTTP response sends HSTS, which has no effect there",
                                      "استجابة HTTP ترسل HSTS ولا أثر لها هناك"),
    "redirects.insecure.initial": ("the first redirect goes to plain HTTP", "أول توجيه يذهب إلى HTTP غير المشفّر"),
    "redirects.insecure.subsequent": ("a later redirect goes to plain HTTP", "توجيه لاحق يذهب إلى HTTP غير المشفّر"),
    "redirects.too_many": ("more than 3 redirects", "أكثر من 3 توجيهات"),
    "domain.is_subdomain": ("the host is a subdomain; only the registrable domain can be preloaded",
                            "المضيف نطاق فرعي؛ ولا يُدرج مسبقًا إلا النطاق القابل للتسجيل"),
    "domain.format.public_suffix": ("the host is a public suffix", "المضيف لاحقة عامة"),
    "domain.format.is_ip_address": ("the host is an IP address", "المضيف عنوان IP"),
    "domain.tls.invalid_cert_chain": ("the certificate does not validate", "الشهادة غير صالحة"),
    "domain.tls.sha1": ("the certificate is signed with SHA-1", "الشهادة موقّعة بخوارزمية SHA-1"),
}

_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
NOTE_VALUE_CAP = 1000                 # one substituted value (a hostile Location can be megabytes long, §0.6)
GROUP_VALUE_CAP = 200
_FIELDS_FORMS = ("{n} field", "{n} fields", ("حقل واحد", "حقلين", "{n} حقول", "{n} حقلًا", "{n} حقل"))


def _note(key: str, **values: Any) -> tuple[str, str]:
    """``(en, ar)`` of ``STR[key]`` with ``{name}`` filled literally; a value may itself be an ``(en, ar)`` pair."""
    en, ar = STR[key]

    def fill(text: str, lang: str) -> str:
        def sub(m: re.Match) -> str:
            v = values.get(m.group(1), m.group(0))
            if isinstance(v, tuple):
                v = v[1] if lang == "ar" else v[0]
            v = strip_controls(str(v))
            return v if len(v) <= NOTE_VALUE_CAP else v[: NOTE_VALUE_CAP - 1] + "…"
        return _PLACEHOLDER.sub(sub, text)
    return fill(en, "en"), fill(ar, "ar")


def _count(n: int, forms: tuple) -> tuple[str, str]:
    from ..i18n.plural import ar_count   # lazy: vulnscan.i18n imports webscan modules through cat_web2
    return (forms[0] if n == 1 else forms[1]).replace("{n}", str(n)), ar_count(n, forms[2])


def _plural(name: str, n: int) -> tuple[str, str]:
    return _count(n, PLURAL_PARAMS[name])


def _codes_text(codes: Iterable[str]) -> tuple[str, str]:
    codes = list(dict.fromkeys(codes))
    en = "; ".join(f"{CODES.get(c, (c, c))[0]} ({c})" for c in codes)
    ar = "؛ ".join(f"{CODES.get(c, (c, c))[1]} ({c})" for c in codes)
    return en, ar


def _short(value: str, limit: int = 160) -> str:
    v = " ".join(strip_controls(value).split())
    return v if len(v) <= limit else v[: limit - 1] + "…"


# ----------------------------------------------------------------------------------------------- hosts and URLs

def _ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(normalise_host(host).split("%", 1)[0])
    except ValueError:
        return None


def is_ip_literal(host: str) -> bool:
    return _ip(host) is not None


def is_loopback_host(host: str) -> bool:
    """``localhost`` (and ``*.localhost``) or a loopback IP literal (127/8, ::1): a developer's local server."""
    h = normalise_host(host)
    if h == "localhost" or h.endswith(".localhost"):
        return True
    ip = _ip(h)
    return ip is not None and ip.is_loopback


def _url_host(url: str) -> str:
    try:
        return normalise_host(urllib.parse.urlsplit(url).hostname or "")
    except ValueError:
        return ""


def _url_scheme(url: str) -> str:
    try:
        return urllib.parse.urlsplit(url).scheme.lower()
    except ValueError:
        return ""


def _default_port(url: str) -> bool:
    try:
        p = urllib.parse.urlsplit(url)
        return p.port is None or (p.scheme.lower(), p.port) in (("http", 80), ("https", 443))
    except ValueError:
        return True


def _location(r: Response) -> str | None:
    try:
        return r.location
    except ValueError:
        return None


# ----------------------------------------------------------------------------------------------- preload snapshot

_PRELOAD_CACHE: dict[tuple, "Preload"] = {}


class Preload:
    """The HSTS preload snapshot: ``lookup(host)`` → ``(preloaded, include_subdomains, matched entry)``.

    Chromium semantics: an exact ``force-https`` entry preloads the host (its own include_subdomains says whether the
    subtree is covered); a parent entry with include_subdomains covers every host below it."""

    def __init__(self, entries: dict[str, bool] | None = None, tlds: Iterable[str] = (), date: str = ""):
        self.entries: dict[str, bool] = dict(entries or {})
        for t in set(tlds) | PRELOADED_TLDS:
            self.entries.setdefault(t, True)
        self.date = date
        self.available = entries is not None

    @classmethod
    def load(cls, data_module: Any = None) -> "Preload":
        """The snapshot from ``data_module`` (default ``webscan.data``), cached per file (path, size, mtime)."""
        if data_module is None:
            from . import data as data_module
        key = None
        try:
            path_for = getattr(data_module, "path_for", None)
            if path_for is not None:
                path, _origin = path_for(PRELOAD_DATA)
                st = path.stat()
                key = (str(path), st.st_size, st.st_mtime_ns)
                if key in _PRELOAD_CACHE:
                    return _PRELOAD_CACHE[key]
            doc = data_module.load_json(PRELOAD_DATA)
            obj = cls(doc.get("entries") or {}, doc.get("tlds") or (), str((doc.get("meta") or {}).get("date", "")))
        except Exception:      # noqa: BLE001 - a missing or broken data file must not stop the scan
            return cls(None)
        if key is not None:
            _PRELOAD_CACHE.clear()
            _PRELOAD_CACHE[key] = obj
        return obj

    def lookup(self, host: str) -> tuple[bool, bool, str]:
        h = psl.normalise(host)
        if not h or is_ip_literal(h):
            return False, False, ""
        if h in self.entries:
            return True, self.entries[h], h
        labels = h.split(".")
        for i in range(1, len(labels)):
            parent = ".".join(labels[i:])
            if self.entries.get(parent):
                return True, True, parent
        return False, False, ""

    def preloaded(self, host: str) -> bool:
        return self.lookup(host)[0]


def preload_lookup(host: str, data_module: Any = None) -> tuple[bool, bool, str]:
    """Module-level convenience over :class:`Preload` (the bundled snapshot, cached by ``data.load_json``)."""
    return Preload.load(data_module).lookup(host)


# ----------------------------------------------------------------------------------------------- HSTS grammar

@dataclass
class StsHeader:
    """One parsed ``Strict-Transport-Security`` field (RFC 6797 §6.1 plus the stricter checks of §2.1 WEB112)."""
    raw: str
    max_age: int | None = None
    include_subdomains: bool = False
    preload: bool = False
    errors: list[str] = field(default_factory=list)      # issue codes that make the header invalid (WEB112)
    warnings: list[str] = field(default_factory=list)    # info notes (unknown/empty directives, preload with a value)
    unknown: list[str] = field(default_factory=list)     # unknown directive names (evidence)

    @property
    def valid(self) -> bool:
        return not self.errors

    def preloadable_codes(self) -> list[str]:
        """hstspreload's ``header.preloadable.*`` failures of this header (empty = preloadable)."""
        codes: list[str] = []
        if not self.include_subdomains:
            codes.append("header.preloadable.include_sub_domains.missing")
        if not self.preload:
            codes.append("header.preloadable.preload.missing")
        if self.max_age is None:
            codes.append("header.preloadable.max_age.missing")
        elif self.max_age == 0:
            codes.append("header.preloadable.max_age.zero")
        elif self.max_age < ONE_YEAR:
            codes.append("header.preloadable.max_age.below_1_year")
        return codes


_DIGITS = re.compile(r"[0-9]+")
_QUOTES = ("\"", "'", "“", "”", "‘", "’", "â")   # â: first byte of a UTF-8 curly quote


def _bad_char(c: str) -> bool:
    o = ord(c)
    return o > 0x7E or (o < 0x20 and c != "\t")


def parse_sts(value: str) -> StsHeader:
    """Parse one header field. Directive names are case-insensitive; ``max-age`` may be a quoted string (RFC 6797);
    a field with a comma (folded duplicates), non-ASCII or control characters, a repeated directive, a missing,
    empty, non-numeric, zero-padded or overflowing max-age is invalid. Unknown and empty directives are warnings."""
    h = StsHeader(raw=value)
    if any(_bad_char(c) for c in value):
        h.errors.append("header.parse.non_ascii")
    if "," in value:
        h.errors.append("header.parse.comma")
    parts = value.split(";")
    if len(parts) == 1 and not parts[0].strip(" \t"):
        h.errors.append("header.parse.empty")
    seen: set[str] = set()
    quoted_max_age = False
    for part in parts:
        d = part.strip(" \t")
        if not d:
            if value.strip(" \t"):
                _add(h.warnings, "header.parse.empty_directive")
            continue
        name, eq, val = d.partition("=")
        lname = name.strip(" \t").lower()
        val = val.strip(" \t")
        if lname.startswith(_QUOTES):
            if "max-age" in lname:
                quoted_max_age = True
                _add(h.errors, "header.parse.quoted_directive")
            else:
                _add(h.warnings, "header.parse.unknown_directive")
                h.unknown.append(_short(name, 60))
            continue
        if lname == "max-age":
            if lname in seen:
                _add(h.errors, "header.parse.repeated.max_age")
                continue
            seen.add(lname)
            if not eq or not val:
                _add(h.errors, "header.parse.invalid.max_age.no_value")
                continue
            v = val[1:-1] if len(val) >= 2 and val[0] == val[-1] == "\"" else val
            if not _DIGITS.fullmatch(v):
                _add(h.errors, "header.parse.max_age.non_digit_characters")
                continue
            if len(v) > 1 and v[0] == "0":
                _add(h.errors, "header.parse.max_age.leading_zero")
            # never int() a hostile digit string: Python 3.10.7+ refuses > 4300 digits (ValueError), and 2^64 has 20
            digits = v.lstrip("0") or "0"
            if len(digits) > 20 or int(digits) > MAX_AGE_MAX:
                _add(h.errors, "header.parse.max_age.parse_int_error")
                continue
            h.max_age = int(digits)
        elif lname == "includesubdomains":
            if lname in seen:
                _add(h.errors, "header.parse.repeated.include_sub_domains")
                continue
            seen.add(lname)
            if eq:
                _add(h.errors, "header.parse.invalid.include_sub_domains")
                continue
            h.include_subdomains = True
        elif lname == "preload":
            if lname in seen:
                _add(h.errors, "header.parse.repeated.preload")
                continue
            seen.add(lname)
            if eq:
                _add(h.warnings, "header.parse.invalid.preload")
                continue
            h.preload = True
        else:
            _add(h.warnings, "header.parse.unknown_directive")
            h.unknown.append(_short(lname, 60))
    if h.max_age is None and "max-age" not in seen and not quoted_max_age and "header.parse.empty" not in h.errors:
        h.errors.append("header.parse.max_age.missing")
    elif h.max_age is None and "header.parse.empty" in h.errors:
        h.errors.append("header.parse.max_age.missing")
    return h


def _add(lst: list[str], code: str) -> None:
    if code not in lst:
        lst.append(code)


# ----------------------------------------------------------------------------------------------- response sets

_SKIP_KINDS = frozenset({"waf_challenge", "rate_limited", "error"})


def _received(r: Response) -> bool:
    return r.status is not None and not r.error


def _final_2xx(r: Response) -> bool:
    return _received(r) and r.is_2xx and r.kind not in _SKIP_KINDS


def _ordered_responses(ctx: ScanContext) -> list[Response]:
    """Every fetched response once: final responses first (entry, counterparts, pages, …), then the redirect hops."""
    finals = ctx.all_responses(include_hops=False)
    seen = {id(r) for r in finals}
    hops = [r for r in ctx.all_responses() if id(r) not in seen]
    return finals + hops


def _chains(ctx: ScanContext) -> list[Response]:
    """Final responses of every fetched chain (each owns its hops), the entry and the counterparts first."""
    out: list[Response] = []
    seen: set[int] = set()
    for r in [ctx.entry, ctx.http_probe, ctx.https_probe, ctx.cors] + [p.response for p in ctx.pages] + \
            list(ctx.subresources) + list(ctx.wellknown.values()) + list(ctx.sourcemaps) + list(ctx.images) + \
            list(ctx.probes) + list(ctx.baselines):
        if r is not None and id(r) not in seen:
            seen.add(id(r))
            out.append(r)
    return out


def http_chain(ctx: ScanContext) -> Response | None:
    """Final response of the http chain: the entry when the target is ``http://``, else the http counterpart."""
    if ctx.entry is not None and ctx.entry.hops()[0].scheme == "http":
        return ctx.entry
    if ctx.http_probe is not None and ctx.http_probe.hops()[0].scheme == "http":
        return ctx.http_probe
    return None


def https_chain(ctx: ScanContext) -> Response | None:
    """Final response of the https session: the entry when the target is ``https://``, else the https counterpart."""
    if ctx.entry is not None and ctx.entry.hops()[0].scheme == "https":
        return ctx.entry
    if ctx.https_probe is not None and ctx.https_probe.hops()[0].scheme == "https":
        return ctx.https_probe
    return None


def _cert_error_hosts(ctx: ScanContext) -> set[str]:
    return {r.host for r in ctx.all_responses() if "cert-error" in r.flags or any(
        f.startswith("cert-verify:") for f in r.flags)}


# ----------------------------------------------------------------------------------------------- stage 1: HSTS facts

def _host_responses(ctx: ScanContext, scheme: str = "https") -> dict[str, list[Response]]:
    out: dict[str, list[Response]] = {}
    for r in _ordered_responses(ctx):
        if r.scheme == scheme and r.host and _received(r):
            out.setdefault(r.host, []).append(r)
    return out


def _entry_error_sts(rs: list[Response], entry: Response | None) -> Response | None:
    """The entry when the entry chain ended on this host with a final non-2xx response that carries HSTS (a 500 or 404
    page). Browsers note HSTS from any https response whatever its status, so a later 2xx side fetch without the header
    (``/robots.txt`` served by another handler) does not make the host's HSTS "missing"."""
    if entry is None or entry.is_redirect or not entry.headers.has(STS) or _final_2xx(entry):
        return None
    return entry if any(r is entry for r in rs) else None


def _judged_response(rs: list[Response], entry: Response | None = None) -> Response:
    """The response that represents a host: the entry's error page when it carries HSTS (:func:`_entry_error_sts`), else
    its first final 2xx, else the first carrying HSTS, else the first."""
    err = _entry_error_sts(rs, entry)
    if err is not None:
        return err
    for r in rs:
        if _final_2xx(r):
            return r
    for r in rs:
        if r.headers.has(STS):
            return r
    return rs[0]


def _verdict(host: str, rs: list[Response], preload: Preload, cert_hosts: set[str],
             entry: Response | None = None) -> HstsVerdict:
    r = _judged_response(rs, entry)
    fields = r.headers.get_all(STS)
    pre, pre_isd, _entry = preload.lookup(host)
    cert = host in cert_hosts
    ip = is_ip_literal(host)
    v = HstsVerdict(host=host, present=bool(fields), preloaded=pre, cert_error=cert, header_values=tuple(fields),
                    response=r)
    problems: list[str] = []
    if len(fields) > 1:
        problems.append("response.multiple_headers")
    if fields:
        p = parse_sts(fields[0])
        problems.extend(p.errors)
        v.valid = p.valid
        v.max_age = p.max_age
        v.preload = p.preload
        dynamic = p.valid and (p.max_age or 0) > 0 and not cert and not ip and r.is_https
        v.effective = dynamic or pre
        v.include_subdomains = (dynamic and p.include_subdomains) or (pre and pre_isd)
    else:
        v.effective = pre
        v.include_subdomains = pre and pre_isd
    if cert:
        problems.append("domain.tls.invalid_cert_chain")
    v.problems = tuple(dict.fromkeys(problems))
    return v


def hsts_facts(ctx: ScanContext) -> dict[str, HstsVerdict]:
    """Stage 1 (pure): HSTS as a browser would note it, per https host seen in the scan (keys are normalised hosts).

    ``effective`` is True when a browser enforces HTTPS for the host: a kept dynamic policy (https response, valid
    header, max-age > 0, certificate valid, not an IP literal) or a preload entry. ``include_subdomains`` is True when
    that enforcement covers the subdomains (the header's directive on an effective policy, or a preload entry with
    include_subdomains). Preloaded parents (``dev``, ``example.com`` with include_subdomains) of the hosts seen get their
    own verdict too, so a cookie whose ``Domain`` is such a parent is recognised as covered. ``problems`` lists
    hstspreload-style codes of the judged header."""
    preload = Preload.load(ctx.data)
    cert_hosts = _cert_error_hosts(ctx)
    out: dict[str, HstsVerdict] = {}
    for host, rs in _host_responses(ctx, "https").items():
        out[host] = _verdict(host, rs, preload, cert_hosts, ctx.entry)
    hosts = {r.host for r in ctx.all_responses() if r.host} | {ctx.target_host} - {""}
    for host in sorted(hosts):
        if host not in out:
            pre, pre_isd, _ = preload.lookup(host)
            if pre:
                out[host] = HstsVerdict(host=host, preloaded=True, effective=True, include_subdomains=pre_isd)
        if is_ip_literal(host):
            continue
        labels = host.split(".")
        for i in range(1, len(labels)):
            parent = ".".join(labels[i:])
            if parent not in out and preload.entries.get(parent):
                out[parent] = HstsVerdict(host=parent, preloaded=True, effective=True, include_subdomains=True)
    return out


# ----------------------------------------------------------------------------------------------- the run

class _Run:
    """One pass over a context: issues plus per-check coverage bookkeeping."""

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.issues: list[Issue] = []
        self.evaluated: dict[str, set[str]] = {}
        self.failed: dict[str, set[str]] = {}
        self.skipped: dict[str, list[tuple[str, str, str, tuple[str, str]]]] = {}   # check → (state, host, reason, detail)
        self.paranoid = ctx.options.sensitivity == "paranoid"
        self.preload = Preload.load(ctx.data)
        self.cert_hosts = _cert_error_hosts(ctx)
        self.own_sites = {psl.site(h) for h in (ctx.target_host, ctx.entry.host if ctx.entry else "") if h}
        self.blocked: dict[str, str] = {}
        if ctx.entry is not None and ctx.entry.kind in ("waf_challenge", "rate_limited"):
            reason = "waf" if ctx.entry.kind == "waf_challenge" else "rate_limited"
            for h in ctx.entry.hops():
                self.blocked[h.host] = reason
        self._emitted: set[tuple] = set()

    def own(self, host: str) -> bool:
        return bool(host) and psl.site(host) in self.own_sites

    def seen(self, check: str, host: str) -> None:
        self.evaluated.setdefault(check, set()).add(host)

    def skip(self, check: str, state: str, host: str, reason: str = "", detail: tuple[str, str] = ("", "")) -> None:
        self.skipped.setdefault(check, []).append((state, host, reason, detail))

    def emit(self, rule: str, r: Response, evidence: Evidence, *, url: str | None = None, severity: str | None = None,
             confidence: str | None = None, group_value: str = "", notes: list[tuple[str, str]] | None = None,
             params: dict | None = None, host: str | None = None, key: Any = None) -> None:
        meta = RULES[rule]
        conf = confidence or meta.confidence
        if conf not in meta.allowed_confidences:
            return
        host = host if host is not None else r.host
        dedupe = (rule, host, key if key is not None else group_value)
        if dedupe in self._emitted:
            return
        self._emitted.add(dedupe)
        sev = severity if severity in meta.allowed_severities else None
        group_value = group_value[:GROUP_VALUE_CAP]
        self.issues.append(Issue(rule=rule, url=url or r.url, confidence=conf, evidence=evidence,
                                 params=dict(params or {}), severity=sev, group_value=group_value,
                                 notes=list(notes or []), host=host))
        self.seen(meta.check_id, host)
        if self.ctx.options.reports(conf):
            self.failed.setdefault(meta.check_id, set()).add(host)

    def ev(self, r: Response | None, *, where: str = "header", name: str = "", value: str = "", offset: int | None = None,
           excerpt: str = "") -> Evidence:
        return Evidence.for_response(r, where=where, name=name, value=value, offset=offset, excerpt=excerpt,
                                     now=self.ctx.now)

    def record_coverage(self) -> None:
        cov = self.ctx.coverage
        if cov is None:
            return
        for check in CHECKS:
            hosts = self.evaluated.get(check, set())
            failed = self.failed.get(check, set())
            for host in sorted(hosts):
                (cov.failed if host in failed else cov.passed)(check, host)
            for host, reason in self.blocked.items():
                if host not in hosts:
                    cov.inconclusive(check, reason, host=host)
            skips = self.skipped.get(check, [])
            for state, host, reason, (den, dar) in skips:
                if host in hosts:
                    continue
                cov.record(check, state, reason, host=host, detail_en=den, detail_ar=dar)
            if not hosts and not self.blocked and not skips:
                if RULES[check].paranoid_only and not self.paranoid:
                    cov.not_tested(check, "sensitivity")
                else:
                    cov.not_applicable(check)


def run(ctx: ScanContext) -> list[Issue]:
    """All §2.1 checks over the context (pure apart from writing ``ctx.observatory`` and coverage states)."""
    st = _Run(ctx)
    if not ctx.hsts:
        ctx_hsts = hsts_facts(ctx)          # unit tests may leave stage 1 empty; never written back
    else:
        ctx_hsts = ctx.hsts
    _plain_http(st)
    _redirects(st)
    _downgrades(st)
    _chain_length(st)
    _big_redirects(st)
    _hsts(st, ctx_hsts)
    _hsts_ignored(st)
    _weak_auth(st)
    _breach(st)
    st.record_coverage()
    ctx.observatory.update(observatory_slugs(ctx, st.preload))
    return st.issues


# ----------------------------------------------------------------------------------------------- WEB000

def _chain_text(final: Response) -> str:
    parts = []
    for h in final.hops():
        parts.append(f"{h.url} [{h.status if h.status is not None else 'error'}]")
    return _short(" → ".join(parts), 600)


def _page_doc(ctx: ScanContext, r: Response) -> ParsedHTML | None:
    p = ctx.page_for(r)
    if p is not None and p.doc is not None:
        return p.doc
    if r.body and "opaque-coding" not in r.flags and r.essence in ("text/html", "application/xhtml+xml"):
        try:
            return htmlparse.parse_response(r)
        except Exception:      # noqa: BLE001 - a broken page must not stop the module
            return None
    return None


def _meta_refresh_targets(doc: ParsedHTML) -> list[tuple[float, str, Any]]:
    out = []
    for m in doc.metas(http_equiv="refresh"):
        parsed = htmlparse.parse_meta_refresh(m.get("content"))
        if parsed and parsed[1]:
            out.append((parsed[0], doc.resolve(parsed[1]), m))
    return out


def _plain_http(st: _Run) -> None:
    ctx = st.ctx
    check = "WEB000"
    final = http_chain(ctx)
    target_scheme = _url_scheme(ctx.target)
    if final is None:
        if target_scheme == "https":
            if ctx.options.profile == "minimal":
                st.skip(check, "not_tested", ctx.target_host, "profile")
            elif not _default_port(ctx.target):
                st.skip(check, "not_applicable", ctx.target_host, "", ("non-default port", "منفذ غير افتراضي"))
            else:
                st.skip(check, "not_tested", ctx.target_host, "not_run")
        return
    hops = final.hops()
    first = hops[0]
    host = first.host
    if host in st.blocked or final.kind in ("waf_challenge", "rate_limited"):
        st.skip(check, "inconclusive", host, "waf" if final.kind == "waf_challenge" else "rate_limited")
        return
    st.seen(check, host)
    if not _received(final):
        return                                   # plain HTTP does not answer: nothing is served over it
    if any(h.scheme == "https" for h in hops):
        return                                   # redirected to https somewhere: WEB101–WEB103 judge the chain
    if not final.is_2xx or not (final.body or "opaque-coding" in final.flags or final.truncated):
        return
    doc = _page_doc(ctx, final)
    if doc is not None:
        for delay, url, _m in _meta_refresh_targets(doc):
            if delay <= 1 and _url_scheme(url) == "https":
                return                           # a browser is sent to https at once
    notes = [_note("http_served", url=final.url, status=final.status)]
    severity = "high"
    params: dict = {}
    if final.kind in ("api_json", "api_xml"):
        params["variant"] = "api"
        notes.append(_note("api"))
    # variant A / B
    if target_scheme == "http":
        hp = ctx.https_probe
        if hp is None:
            if not _default_port(ctx.target):
                notes.append(_note("https_port"))
            elif ctx.options.profile == "minimal":
                notes.append(_note("https_profile"))
        elif not _received(hp) or "cert-error" in hp.hops()[-1].flags or hp.host in st.cert_hosts:
            reason = _note("https_down") if not _received(hp) else _note("https_cert")
            notes.append(_note("variant_a", reason=reason))
        else:
            notes.append(_note("variant_b", url=hp.url))
    elif ctx.entry is not None and (any("cert-error" in h.flags for h in ctx.entry.hops())
                                    or ctx.entry.hops()[0].host in st.cert_hosts):
        notes.append(_note("variant_a", reason=_note("https_cert")))
    else:
        notes.append(_note("variant_b", url=ctx.entry.url if ctx.entry is not None else ctx.target))
    pre, _isd, entry = st.preload.lookup(host)
    if pre:
        severity = "info"
        notes.append(_note("preloaded", host=host, entry=entry))
    if is_loopback_host(host):
        severity = "info"
        notes.append(_note("loopback", host=host))
    if len(hops) > 1:
        notes.append(_note("chain", chain=_chain_text(final)))
    st.emit(check, final, st.ev(final, where="header", name="status", value=str(final.status)), url=first.url,
            severity=severity, group_value="http", notes=notes, params=params, host=host)


# ----------------------------------------------------------------------------------------------- WEB101 / WEB102 / WEB105

def _redirects(st: _Run) -> None:
    ctx = st.ctx
    final = http_chain(ctx)
    checks = ("WEB101", "WEB102", "WEB105")
    if final is None:
        for c in checks:
            if ctx.options.profile == "minimal" and _url_scheme(ctx.target) == "https":
                st.skip(c, "not_tested", ctx.target_host, "profile")
        return
    hops = final.hops()
    first = hops[0]
    host = first.host
    if host in st.blocked:
        return
    pre, _isd, entry = st.preload.lookup(host)
    if pre:
        for c in checks:
            st.skip(c, "not_applicable", host, "", (f"preloaded ({entry})", f"مدرج مسبقًا ({entry})"))
        return
    for c in checks:
        st.seen(c, host)
    if not _received(first) or not first.is_redirect:
        return
    reaches_https = any(h.scheme == "https" for h in hops[1:]) or (
        final.is_redirect and _url_scheme(_location(final) or "") == "https")
    loc = _location(first) or ""
    chain_note = _note("chain", chain=_chain_text(final))
    if _url_scheme(loc) == "http" and reaches_https:
        st.emit("WEB101", first, st.ev(final, name="Location", value=loc), url=first.url, group_value="http-first",
                notes=[_note("first_hop_http", src=first.url, dst=loc), chain_note], host=host)
    elif _url_scheme(loc) == "https" and _url_host(loc) and _url_host(loc) != host:
        st.emit("WEB102", first, st.ev(final, name="Location", value=loc), url=first.url, group_value=_url_host(loc),
                notes=[_note("first_hop_host", src=first.url, dst=loc, host=host), chain_note], host=host)
    for h in hops:
        if h.scheme == "http" and h.is_redirect and _url_scheme(_location(h) or "") == "https":
            if h.status in TEMPORARY_REDIRECTS:
                st.emit("WEB105", h, st.ev(h, name="status", value=str(h.status)), url=h.url,
                        group_value=str(h.status), notes=[_note("temporary", status=h.status), chain_note], host=host)
            break


# ----------------------------------------------------------------------------------------------- WEB103

_JS_LOCATION = re.compile(
    r"""(?:^|[^\w$.])(?:(?:window|self|top|parent|document)\s*\.\s*)?location(?:\s*\.\s*href)?\s*=(?!=)\s*"""
    r"""(["'`])(http://[^"'`\s]+)\1"""
    r"""|(?:^|[^\w$.])(?:(?:window|self|top|parent|document)\s*\.\s*)?location\s*\.\s*(?:replace|assign)\s*\(\s*"""
    r"""(["'`])(http://[^"'`\s]+)\3""", re.M)

_JS_DECL = re.compile(r"\b(?:var|let|const)\s+$")


def _downgrades(st: _Run) -> None:
    ctx = st.ctx
    check = "WEB103"
    if is_loopback_host(ctx.target_host):
        st.skip(check, "not_applicable", ctx.target_host, "", ("loopback target", "هدف على عنوان الاسترجاع المحلي"))
        return
    for final in _chains(ctx):
        for h in final.hops():
            if not st.own(h.host) or h.host in st.blocked or not _received(h):
                continue
            if h.scheme != "https":
                continue
            st.seen(check, h.host)
            if not h.is_redirect:
                continue
            loc = _location(h) or ""
            if _url_scheme(loc) == "http" and not is_loopback_host(_url_host(loc)):
                st.emit(check, h, st.ev(h, name="Location", value=loc), url=h.url, group_value=f"location {loc}",
                        key=("loc", h.url, loc), notes=[_note("downgrade", src=h.url, dst=loc),
                                                        _note("chain", chain=_chain_text(final))])
    for page in ctx.pages:
        r = page.response
        if not r.is_https or not st.own(r.host) or r.host in st.blocked or not _received(r):
            continue
        doc = page.doc if page.doc is not None else _page_doc(ctx, r)
        if doc is None:
            continue
        st.seen(check, r.host)
        for _delay, url, m in _meta_refresh_targets(doc):
            if _url_scheme(url) == "http" and not is_loopback_host(_url_host(url)):
                st.emit(check, r, st.ev(r, where="body", name="meta refresh", value=m.get("content") or "",
                                        offset=m.offset), group_value=f"meta {url}", key=("meta", r.url, url),
                        notes=[_note("meta_downgrade", dst=url)])
        for s in doc.inline_scripts:
            if not s.live or not s.is_javascript:
                continue
            for mt in _JS_LOCATION.finditer(s.text):
                url = mt.group(2) or mt.group(4) or ""
                if is_loopback_host(_url_host(url)):
                    continue
                if _JS_DECL.search(s.text, max(0, mt.start() - 16), mt.start() + 1):
                    continue                     # ``var location = "http://…"`` is a local variable, not navigation
                line = s.line + s.text.count("\n", 0, mt.start())
                st.emit(check, r, st.ev(r, where="body", name="script", value=url, offset=s.offset + mt.start(),
                                        excerpt=_short(mt.group(0), 200)),
                        confidence="tentative", group_value=f"script {url}", key=("script", r.url, url),
                        notes=[_note("script_downgrade", dst=url, line=line)])


# ----------------------------------------------------------------------------------------------- WEB104

def _chain_length(st: _Run) -> None:
    ctx = st.ctx
    check = "WEB104"
    done: set[str] = set()
    for final in (ctx.entry, ctx.http_probe, ctx.https_probe):
        if final is None:
            continue
        hops = final.hops()
        start = hops[0]
        if start.url in done or start.host in st.blocked:
            continue
        done.add(start.url)
        st.seen(check, start.host)
        n = sum(1 for h in hops if h.is_redirect)
        urls = [h.url for h in hops]
        # A URL that repeats in a chain which then completes (``/`` → ``/cookie-check`` → ``/`` + cookie → 200) is a
        # cookie or bot check, not a loop: the fetcher's ``redirect-loop`` flag (URL + cookie-jar state) is the truth;
        # a repeat counts by itself only when the chain stopped on a redirect.
        loop = "redirect-loop" in final.flags or (final.is_redirect and len(set(urls)) < len(urls))
        limit = "redirect-limit" in final.flags
        if not (loop or limit or n > PRELOAD_MAX_REDIRECTS):
            continue
        notes = [_note("chain", chain=_chain_text(final))]
        if loop:
            repeated = next((u for u in urls if urls.count(u) > 1), _location(final) or final.url)
            notes.insert(0, _note("loop", url=repeated))
            sev, gv = "low", "loop"
        elif limit:
            notes.insert(0, _note("limit", hops=_plural("hops", n)))
            sev, gv = "low", "limit"
        else:
            notes.insert(0, _note("too_long", hops=_plural("hops", n)))
            sev, gv = "info", "long"
        st.emit(check, final, st.ev(final, name="redirects", value=str(n)), url=start.url, severity=sev,
                group_value=gv, notes=notes, host=start.host, key=("chain", start.url))


# ----------------------------------------------------------------------------------------------- WEB106

def big_redirect_signals(r: Response) -> tuple[list[str], str]:
    """The §WEB106 page signals of a redirect body (``form``, ``links``, ``table``, ``text``) and its first visible text.

    Read from the light DOM (live elements only), not with ``<a\\b[^>]*href`` style regexes: those backtrack
    quadratically on a hostile body such as ``"<a " * 100000`` (a redirect body may be up to the 2 MB HTML cap, §0.6)."""
    text = r.text()
    signals = []
    try:
        doc = htmlparse.parse(text, r.url)
    except Exception:      # noqa: BLE001 - parse() never raises by contract; a bug there only loses the signals
        return [], ""
    if doc.find_all("form"):
        signals.append("form")
    if sum(1 for a in doc.find_all("a") if a.has("href")) >= 3:
        signals.append("links")
    if doc.find_all("table"):
        signals.append("table")
    visible = " ".join(doc.visible_text.split())
    if len(visible.encode("utf-8")) > 1024:
        signals.append("text")
    return signals, visible[:200]


def _big_redirects(st: _Run) -> None:
    ctx = st.ctx
    check = "WEB106"
    for r in _ordered_responses(ctx):
        if not st.own(r.host) or r.host in st.blocked or not _received(r) or r.method != "GET":
            continue
        if not r.is_redirect or r.status == 304:
            continue
        st.seen(check, r.host)
        loc = r.headers.first("location") or ""
        if "opaque-coding" in r.flags or len(r.body) <= len(loc) + 300:
            continue
        signals, visible = big_redirect_signals(r)
        if len(signals) < 2:
            continue
        st.emit(check, r, st.ev(r, where="body", name="body", value=str(len(r.body)), excerpt=visible),
                group_value="+".join(signals), key=("big", r.url),
                notes=[_note("big_redirect", status=r.status, length=len(r.body), signals=", ".join(signals),
                             text=_short(visible, 200))])


# ----------------------------------------------------------------------------------------------- HSTS rules

def _session_domain_cookie(ctx: ScanContext, host: str):
    for c in ctx.cookies:
        if c.host == host and c.is_session_class and c.domain and not c.deletion and not c.ignored:
            return c
    return None


def preload_eligibility(ctx: ScanContext, host: str, r: Response, header: StsHeader, n_fields: int,
                        cert_error: bool) -> tuple[list[str], list[tuple[str, str]]]:
    """hstspreload's rules for ``host`` from the responses already fetched: ``(failed codes, notes)``."""
    codes: list[str] = []
    notes: list[tuple[str, str]] = []
    if n_fields > 1:
        codes.append("response.multiple_headers")
    codes.extend(c for c in header.errors)
    codes.extend(header.preloadable_codes())
    if is_ip_literal(host):
        codes.append("domain.format.is_ip_address")
    elif psl.is_public_suffix(host):
        codes.append("domain.format.public_suffix")
    elif psl.registrable_domain(host) != psl.normalise(host):
        codes.append("domain.is_subdomain")
    if cert_error:
        codes.append("domain.tls.invalid_cert_chain")
    if _sha1_leaf(ctx, host):
        codes.append("domain.tls.sha1")
    # the http redirect of http://host
    chain = None
    for final in (ctx.entry, ctx.http_probe):
        if final is not None and final.hops()[0].scheme == "http" and final.hops()[0].host == host:
            chain = final
            break
    if chain is None:
        notes.append(_note("preload_unchecked", what=_note("preload_http_unchecked", host=host)))
    else:
        hops = chain.hops()
        h0 = hops[0]
        if _received(h0):
            if not h0.is_redirect:
                codes.append("redirects.http.no_redirect")
            else:
                loc = _location(h0) or ""
                if _url_scheme(loc) == "https" and _url_host(loc) == host:
                    nxt = hops[1] if len(hops) > 1 else None
                    if nxt is not None and _received(nxt):
                        fields = nxt.headers.get_all(STS)
                        ph = parse_sts(fields[0]) if fields else None
                        if ph is None or len(fields) > 1 or ph.errors or ph.preloadable_codes():
                            codes.append("redirects.http.first_redirect.no_hsts")
                    for i, h in enumerate(hops[1:], start=1):
                        if h.scheme != "https":
                            codes.append("redirects.insecure.initial" if i == 1 else "redirects.insecure.subsequent")
                            break
                        if h.is_redirect and _url_scheme(_location(h) or "") == "http":
                            codes.append("redirects.insecure.initial" if i == 1 else "redirects.insecure.subsequent")
                            break
                elif _url_host(loc) == "www." + host:
                    codes.append("redirects.http.www_first")
                else:
                    codes.append("redirects.http.first_redirect.insecure")
            if sum(1 for h in hops if h.is_redirect) > PRELOAD_MAX_REDIRECTS:
                codes.append("redirects.too_many")
    # the https chain that starts at https://host
    for final in (ctx.entry, ctx.https_probe):
        if final is None or final.hops()[0].scheme != "https" or final.hops()[0].host != host:
            continue
        hops = final.hops()
        for i, h in enumerate(hops):
            if h.is_redirect and _url_scheme(_location(h) or "") == "http":
                codes.append("redirects.insecure.initial" if i == 0 else "redirects.insecure.subsequent")
                break
        if sum(1 for h in hops if h.is_redirect) > PRELOAD_MAX_REDIRECTS:
            codes.append("redirects.too_many")
        break
    return list(dict.fromkeys(codes)), notes


def _sha1_leaf(ctx: ScanContext, host: str) -> bool:
    """True when ``ctx.tls`` (WP10's per-IP report, read defensively) shows a SHA-1-signed leaf for ``host``."""
    def walk(obj: Any, depth: int = 0) -> bool:
        if depth > 4:
            return False
        if isinstance(obj, dict):
            hv = obj.get("host")
            if hv and normalise_host(str(hv)) != host:
                return False
            for k in ("sigalg", "signature_algorithm", "sig_alg"):
                v = obj.get(k)
                if isinstance(v, str) and "sha1" in v.lower().replace("-", ""):
                    return True
            return any(walk(v, depth + 1) for k, v in obj.items() if k in ("leaf", "cert", "certificate", "chain"))
        if isinstance(obj, (list, tuple)):
            return any(walk(v, depth + 1) for v in obj[:1])
        return False
    try:
        return any(walk(v) for v in (ctx.tls or {}).values())
    except Exception:      # noqa: BLE001 - foreign shape
        return False


def _hsts(st: _Run, verdicts: dict[str, HstsVerdict]) -> None:
    ctx = st.ctx
    by_host = _host_responses(ctx, "https")
    navigational = {id(h) for f in [ctx.entry, ctx.http_probe, ctx.https_probe] + [p.response for p in ctx.pages]
                    if f is not None for h in f.hops()}
    for host, rs in by_host.items():
        if not st.own(host):
            continue
        if host in st.blocked:
            continue
        hsts_checks = ("WEB-strict-transport-security", "WEB110", "WEB111", "WEB112", "WEB113", "WEB114", "WEB115",
                       "WEB117")
        if host in st.cert_hosts:
            for c in hsts_checks:
                st.skip(c, "not_applicable", host, "", ("certificate error: browsers ignore HSTS there",
                                                         "خطأ في الشهادة: يتجاهل المتصفح HSTS هناك"))
            continue
        if is_ip_literal(host):
            for c in hsts_checks:
                st.skip(c, "not_applicable", host, "", ("IP-literal host (RFC 6797 §8.1)", "مضيف بعنوان IP (RFC 6797 §8.1)"))
            continue
        pre, pre_isd, entry = st.preload.lookup(host)
        verdict = verdicts.get(host)
        finals = [r for r in rs if _final_2xx(r) and not r.is_redirect]
        # -- WEB117: an https hop to another host without HSTS. Only for a host seen *only* as a redirecting hop: a
        # host that also serves a final 2xx is judged there (missing / WEB110 / WEB112), one cause, one finding (§2.1).
        # Only navigations count (entry, counterparts, crawled pages): a subresource host that redirects is loaded
        # over https by the page anyway, so HSTS there protects nothing a visitor types or follows.
        st.seen("WEB117", host)
        if not pre and not finals and not (verdict is not None and verdict.effective and verdict.present):
            for r in rs:
                if id(r) not in navigational or not r.is_redirect or r.headers.has(STS):
                    continue
                loc = _location(r) or ""
                if _url_host(loc) and _url_host(loc) != host:
                    st.emit("WEB117", r, st.ev(r, name="Location", value=loc), group_value="no-hsts", key="hop",
                            notes=[_note("hop_no_sts", src=r.url, dst=loc, host=host)])
                    break
        # -- missing (judged on the host's first final 2xx)
        if finals:
            r0 = finals[0]
            st.seen("WEB-strict-transport-security", host)
            if not r0.headers.has(STS) and _entry_error_sts(rs, ctx.entry) is None:
                notes = [_note("sts_missing", url=r0.url)]
                sev = None
                if pre:
                    sev = "info"
                    notes.append(_note("sts_preloaded_info", entry=entry))
                st.emit("WEB-strict-transport-security", r0, st.ev(r0, name="Strict-Transport-Security", value=""),
                        severity=sev, group_value="missing", notes=notes)
        # -- value rules on every distinct header seen for the host
        judged: set[tuple[str, ...]] = set()
        carrying = [r for r in rs if r.headers.has(STS)]
        if carrying:
            for c in ("WEB110", "WEB111", "WEB112", "WEB113", "WEB114"):
                st.seen(c, host)
        for r in carrying:
            fields = tuple(r.headers.get_all(STS))
            if fields in judged:
                continue
            judged.add(fields)
            _judge_value(st, host, r, list(fields), pre, pre_isd, entry)
        # -- WEB115 preload eligibility
        vr = next((r for r in finals if r.headers.has(STS)), carrying[0] if carrying else None)
        if vr is None:
            continue
        fields = vr.headers.get_all(STS)
        header = parse_sts(fields[0])
        apex = psl.registrable_domain(host) == psl.normalise(host)
        if not (header.preload or apex):
            continue
        st.seen("WEB115", host)
        if not header.preload or pre:
            continue                     # not requesting preload, or already preloaded (a positive, not a finding)
        codes, extra = preload_eligibility(ctx, host, vr, header, len(fields), host in st.cert_hosts)
        if codes:
            st.emit("WEB115", vr, st.ev(vr, name="Strict-Transport-Security", value=fields[0]), severity="low",
                    group_value=" ".join(sorted(codes)), key="preload",
                    notes=[_note("preload_fail", codes=_codes_text(codes))] + extra)
        else:
            st.emit("WEB115", vr, st.ev(vr, name="Strict-Transport-Security", value=fields[0]), severity="info",
                    confidence="firm", group_value="eligible", key="preload",
                    notes=[_note("preload_ok", date=st.preload.date or "?")] + extra)


def _judge_value(st: _Run, host: str, r: Response, fields: list[str], pre: bool, pre_isd: bool, entry: str) -> None:
    ctx = st.ctx
    header = parse_sts(fields[0])
    value = fields[0]
    ev = st.ev(r, name="Strict-Transport-Security", value=value)
    base_notes: list[tuple[str, str]] = []
    if f"obs-fold:{STS}" in r.flags:
        base_notes.append(_note("sts_obs_fold"))
    if len(fields) > 1:
        same = len({f.strip() for f in fields}) == 1
        cnt = _count(len(fields), _FIELDS_FORMS)
        note = _note("sts_multi_same", fields=cnt) if same else _note("sts_multi_diff", fields=cnt, value=_short(value))
        st.emit("WEB113", r, st.ev(r, name="Strict-Transport-Security", value=" | ".join(fields)),
                severity="info" if same else "low", group_value="same" if same else "different",
                key=("multi", tuple(fields)), notes=[note] + base_notes)
    if header.warnings:
        base_notes.append(_note("sts_value", value=_short(value)))
    if not header.valid:
        notes = [_note("sts_value", value=_short(value)), _codes_text(header.errors)]
        if header.warnings:
            notes.append(_codes_text(header.warnings))
        st.emit("WEB112", r, ev, group_value=" ".join(sorted(header.errors)), key=("invalid", value),
                notes=notes + [n for n in base_notes if n[0] != notes[0][0]])
        return
    if header.max_age == 0:
        st.emit("WEB110", r, ev, group_value="max-age=0", key="zero", notes=[_note("sts_zero", host=host)] + base_notes)
        return
    age = header.max_age or 0
    days = _plural("days", age // 86400)
    if age < ONE_YEAR:
        sev = "medium" if age < SIX_MONTHS else "low"
        st.emit("WEB111", r, ev, severity=sev, group_value=f"short-{sev}", key=("short", age),
                notes=[_note("sts_short", seconds=age, days=days)] + base_notes)
    elif age > TEN_YEARS:
        st.emit("WEB111", r, ev, severity="info", group_value="too-long", key=("long", age),
                notes=[_note("sts_long", seconds=age, days=days)] + base_notes,
                params={"variant": "too_long"})
    if not header.include_subdomains and not (pre and pre_isd):
        cookie = _session_domain_cookie(ctx, host)
        notes = [_note("sts_no_isd", host=host)]
        sev = "info"
        if cookie is not None:
            sev = "low"
            notes.append(_note("sts_isd_cookie", cookie=cookie.name, domain=cookie.domain))
        st.emit("WEB114", r, ev, severity=sev, group_value="no-includesubdomains", key="isd", notes=notes + base_notes)


def _hsts_ignored(st: _Run) -> None:
    """WEB116: HSTS over http (RFC 6797 §8.1) and in a meta tag."""
    ctx = st.ctx
    check = "WEB116"
    for r in _ordered_responses(ctx):
        if not st.own(r.host) or r.host in st.blocked or not _received(r) or r.scheme != "http":
            continue
        st.seen(check, r.host)
        fields = r.headers.get_all(STS)
        if fields:
            st.emit(check, r, st.ev(r, name="Strict-Transport-Security", value=fields[0]), group_value="http",
                    key="http", notes=[_note("sts_on_http", url=r.url)])
    for page in ctx.pages:
        r = page.response
        if not st.own(r.host) or r.host in st.blocked or page.doc is None:
            continue
        st.seen(check, r.host)
        for m in page.doc.metas(http_equiv="strict-transport-security"):
            st.emit(check, r, st.ev(r, where="body", name="meta", value=m.get("content") or "", offset=m.offset),
                    group_value="meta", key="meta", notes=[_note("sts_meta")])
            break


# ----------------------------------------------------------------------------------------------- WEB118 / WEB119

_AUTH_SCHEME = re.compile(r"(?:^|,)\s*(basic|digest)(?=\s|$|,)", re.I)


def auth_schemes(values: Iterable[str]) -> list[str]:
    """``Basic``/``Digest`` challenges named in WWW-Authenticate field values (lower-case, first-seen order)."""
    out: list[str] = []
    for v in values:
        for m in _AUTH_SCHEME.finditer(v):
            s = m.group(1).lower()
            if s not in out:
                out.append(s)
    return out


def _weak_auth(st: _Run) -> None:
    ctx = st.ctx
    check = "WEB118"
    for r in _ordered_responses(ctx):
        if not st.own(r.host) or r.host in st.blocked or not _received(r) or r.scheme != "http":
            continue
        if st.preload.preloaded(r.host):
            continue
        st.seen(check, r.host)
        schemes = auth_schemes(r.headers.get_all("www-authenticate"))
        if not schemes:
            continue
        scheme = "basic" if "basic" in schemes else "digest"
        st.emit(check, r, st.ev(r, name="WWW-Authenticate", value=r.headers.joined("www-authenticate") or ""),
                severity="high" if scheme == "basic" else "medium", group_value=scheme, key=scheme,
                notes=[_note("auth_http", url=r.url, scheme=scheme.capitalize())])


_TOKEN_NAME = re.compile(r"csrf|xsrf|token|__requestverificationtoken|authenticity", re.I)
_COMPRESSED = ("gzip", "x-gzip", "deflate", "br", "zstd")


def _codings(r: Response) -> list[str]:
    out = []
    for v in r.headers.get_all("content-encoding"):
        out.extend(t.strip().lower() for t in v.split(",") if t.strip())
    if not out and r.encoding:
        out = [t.strip().lower() for t in r.encoding.split(",") if t.strip()]
    return out


def _breach(st: _Run) -> None:
    ctx = st.ctx
    check = "WEB119"
    for page in ctx.pages:
        r = page.response
        if not r.is_https or not st.own(r.host) or r.host in st.blocked or not _final_2xx(r):
            continue
        codings = [c for c in _codings(r) if c in _COMPRESSED]
        if not codings:
            st.seen(check, r.host)
            continue
        if "opaque-coding" in r.flags or not r.body:
            st.skip(check, "not_tested", r.host, "unsupported_coding", (codings[0], codings[0]))
            continue
        doc = page.doc if page.doc is not None else _page_doc(ctx, r)
        if doc is None:
            continue
        st.seen(check, r.host)
        for e in doc.find_all("input"):
            if (e.get("type") or "").strip().lower() != "hidden":
                continue
            name = e.get("name") or ""
            if _TOKEN_NAME.search(name) and (e.get("value") or "").strip():
                st.emit(check, r, st.ev(r, where="body", name="input", value=name, offset=e.offset),
                        severity="low" if st.paranoid else "info", group_value=name.lower(), key=("breach", r.url),
                        notes=[_note("breach", coding=codings[0], field=name)])
                break


# ----------------------------------------------------------------------------------------------- Observatory v6

def _js_parse_int(s: str) -> float | None:
    """JavaScript ``Number.parseInt(s, 10)``: leading whitespace, optional sign, digits; ``None`` stands for NaN."""
    m = re.match(r"[\s﻿\xa0]*([+-]?)([0-9]+)", s)
    if not m:
        return None
    n = int(m.group(2))
    return -n if m.group(1) == "-" else n


def observatory_hsts_slug(response: Response | None, site_host: str, preload: Preload,
                          verified: bool = True) -> str | None:
    """Observatory's ``strict-transport-security`` result for the https response (``None``: no https was attempted)."""
    if response is None:
        return None
    if not _received(response):
        result = "hsts-not-implemented-no-https"
    elif not verified:
        result = "hsts-invalid-cert"
    else:
        result = "hsts-not-implemented"
        joined = response.headers.joined(STS)       # Node's http module joins duplicate fields with ", " (two headers
        if joined is not None:                      # therefore always contain a comma: "hsts-header-invalid")
            data = joined[:1024]
            if "," in data:
                result = "hsts-header-invalid"
            else:
                max_age: float | None | str = "unset"
                for part in (p.strip().lower() for p in data.split(";")):
                    if part.startswith("max-age="):
                        max_age = _js_parse_int(part[8:128])
                if max_age == "unset":
                    result = "hsts-header-invalid"
                elif max_age is not None and max_age < SIX_MONTHS:      # NaN < x is false in JavaScript
                    result = "hsts-implemented-max-age-less-than-six-months"
                else:
                    result = "hsts-implemented-max-age-at-least-six-months"
    if preload.lookup(site_host)[0]:
        result = "hsts-preloaded"
    return result


def observatory_redirection_slug(final: Response | None, preload: Preload, attempted: bool = True) -> str | None:
    """Observatory's ``redirection`` result for the http chain (``None``: plain HTTP was not tried)."""
    if final is None or not _received(final.hops()[0]):
        return "redirection-not-needed-no-http" if attempted else None
    hops = final.hops()
    if any("cert-error" in h.flags for h in hops):
        return "redirection-invalid-cert"
    route = [h.url for h in hops]
    if all(preload.lookup(_url_host(u))[0] for u in route):
        return "redirection-all-redirects-preloaded"
    if len(route) == 1:
        return "redirection-missing"
    if _url_scheme(route[-1]) != "https":
        return "redirection-not-to-https"
    if _url_scheme(route[1]) == "http":
        return "redirection-not-to-https-on-initial-redirection"
    if _url_scheme(route[0]) == "http" and _url_scheme(route[1]) == "https" and _url_host(route[0]) != _url_host(route[1]):
        return "redirection-off-host-from-http"
    return "redirection-to-https"


def observatory_slugs(ctx: ScanContext, preload: Preload | None = None) -> dict[str, str]:
    """The ``redirection`` and ``strict-transport-security`` Observatory results (omitted when not tested)."""
    preload = preload or Preload.load(ctx.data)
    out: dict[str, str] = {}
    hc = http_chain(ctx)
    attempted = hc is not None or (_url_scheme(ctx.target) == "https" and ctx.options.profile != "minimal"
                                   and _default_port(ctx.target))
    red = observatory_redirection_slug(hc, preload, attempted=attempted and hc is not None)
    if red:
        out["redirection"] = red
    hs = https_chain(ctx)
    if hs is not None:
        verified = not any("cert-error" in h.flags for h in hs.hops())
        slug = observatory_hsts_slug(hs, ctx.target_host, preload, verified)
        if slug:
            out["strict-transport-security"] = slug
    elif hc is not None and ctx.options.profile != "minimal" and _default_port(ctx.target):
        out["strict-transport-security"] = "hsts-not-implemented-no-https"
    return out


# ----------------------------------------------------------------------------------------------- i18n

def i18n_catalog() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """``(CATALOG, PATTERNS)`` for cat_web2: fixed Arabic notes → English, and regex patterns for templated ones."""
    catalog: dict[str, str] = {ar: en for en, ar in CODES.values()}
    patterns: list[tuple[str, str]] = []
    for en, ar in STR.values():
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
    return catalog, patterns


__all__ = ["CHECKS", "run", "hsts_facts", "parse_sts", "StsHeader", "Preload", "preload_lookup", "PRELOADED_TLDS",
           "preload_eligibility", "http_chain", "https_chain", "is_loopback_host", "is_ip_literal", "auth_schemes",
           "big_redirect_signals", "observatory_slugs", "observatory_hsts_slug", "observatory_redirection_slug", "STR",
           "CODES", "i18n_catalog"]
