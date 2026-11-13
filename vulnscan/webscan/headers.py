"""Framing, MIME, referrer, permissions, isolation, caching and other response headers (spec §2.3), WP3.

Rules: WEB-x-frame-options, WEB-x-content-type-options, WEB-referrer-policy, WEB-permissions-policy and WEB300–WEB318.
The module also writes the MDN Observatory v6 slugs of six tests into ``ctx.observatory`` (``referrer-policy``,
``x-content-type-options``, ``x-frame-options``, ``cross-origin-resource-policy``, ``cross-origin-embedder-policy``,
``cross-origin-opener-policy``), reproducing ``mdn-http-observatory`` 1.7.2 bit for bit, quirks included (§3.4 b).

Gates (§2.0): "missing" rules judge only G1 documents (final, 2xx, kind ``document``; at ``paranoid`` also HTML
4xx/5xx pages at confidence ``tentative`` when the registry allows it); header-value rules run on every fetched
response of the site (G2: redirects and error pages included, third-party hosts and WAF/rate-limit pages excluded);
COOP/COEP/Clear-Site-Data are judged only on https (G3); a WAF-challenged entry makes the host's document-level checks
``inconclusive`` (G4). One cause gives one finding: an ineffective X-Frame-Options yields WEB300/WEB301 instead of
WEB-x-frame-options, and Feature-Policy without Permissions-Policy yields WEB307 instead of WEB-permissions-policy.

Inputs read from the context and never recomputed through another check module (§4.2): ``ctx.csp`` (frame-ancestors
of enforced header policies; when a response has no CSP facts a minimal local reading of the header is used),
``ctx.cookies`` (session/auth Set-Cookie facts), the ``sensitive``, ``ctype-mismatch`` and ``magic:<mime>`` flags of
classify.py, and ``Response.kind``/``roles``. Pure: nothing here touches the network.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import urllib.parse
import zlib
from dataclasses import dataclass, field
from typing import Iterable

from . import htmlparse, psl, sfv
from .rules import RULES, checks_for_module
from .types import (
    CookieFact,
    Evidence,
    Issue,
    Page,
    ParsedHTML,
    Response,
    ScanContext,
    bom_encoding,
    charset_param,
    meta_charset,
    normalise_charset,
    normalise_host,
    strip_controls,
)

CHECKS: tuple[str, ...] = checks_for_module("headers")

# ----------------------------------------------------------------------------------------------- user-facing text

# (en, ar) note templates; ``{name}`` values come from the scanned site and are filled with str.format-free
# substitution (:func:`_note`), so a value containing braces cannot break or inject a format string (§0.6).
STR: dict[str, tuple[str, str]] = {
    "xfo_allow_from": ("ALLOW-FROM ({value}) is ignored by current browsers, so any site can frame this page.",
                       "القيمة ALLOW-FROM ({value}) يتجاهلها المتصفح الحديث، فيستطيع أي موقع تضمين هذه الصفحة."),
    "xfo_invalid": ("{value} is not DENY or SAMEORIGIN, so browsers treat the header as absent.",
                    "القيمة {value} ليست DENY ولا SAMEORIGIN، فيعامل المتصفح الترويسة كأنها غير موجودة."),
    "xfo_multi_invalid": ("The values {value} contradict each other and none of them blocks framing, so browsers "
                          "ignore the header.",
                          "القيم {value} متعارضة ولا تمنع أيٌّ منها التضمين، فيتجاهل المتصفح الترويسة."),
    "xfo_conflict": ("Browsers treat the conflicting values {value} as DENY, but two layers are setting the header.",
                     "يعامل المتصفح القيم المتعارضة {value} على أنها DENY، لكن هناك طبقتان تضبطان الترويسة."),
    "xfo_identical": ("The same value is sent in {fields}; browsers accept it, but set it in one layer only.",
                      "تُرسَل القيمة نفسها في {fields}؛ يقبلها المتصفح، لكن اضبطها في طبقة واحدة فقط."),
    "xfo_fa_protects": ("CSP frame-ancestors already protects this response; X-Frame-Options only matters for old "
                        "browsers.",
                        "يحمي frame-ancestors في CSP هذه الاستجابة أصلًا؛ ولا تهم X-Frame-Options إلا للمتصفحات القديمة."),
    "xfo_meta": ("<meta http-equiv=\"X-Frame-Options\" content=\"{value}\"> has no effect.",
                 "الوسم <meta http-equiv=\"X-Frame-Options\" content=\"{value}\"> لا أثر له."),
    "xcto_kinds": ("Missing on {responses} of these kinds: {kinds}.",
                   "مفقودة في {responses} من هذه الأنواع: {kinds}."),
    "xcto_invalid": ("The first value is {value}; browsers enable nosniff only for the exact value nosniff.",
                     "القيمة الأولى هي {value}؛ ولا يفعّل المتصفح nosniff إلا بالقيمة nosniff بالضبط."),
    "ref_effective": ("Effective policy: {policy} (from {source}).", "السياسة الفعلية: {policy} (من {source})."),
    "ref_none": ("No recognised policy in {value}; browsers fall back to strict-origin-when-cross-origin.",
                 "لا توجد سياسة معروفة في {value}؛ فيعود المتصفح إلى strict-origin-when-cross-origin."),
    "pp_parse": ("Not a valid structured-field dictionary ({error}); browsers ignore the whole header, so no "
                 "restriction applies.",
                 "ليست قاموس حقول مهيكلة صالحًا ({error})؛ فيتجاهل المتصفح الترويسة كلها ولا يُطبَّق أي تقييد."),
    "pp_bare_token": ("{member} is not standard syntax; browsers treat it as {feature}=() (disabled), which is "
                      "probably what you meant.",
                      "الصيغة {member} غير قياسية؛ ويعاملها المتصفح على أنها {feature}=() (معطّلة)، وهذا غالبًا ما قصدته."),
    "pp_bare_string": ("{member} disables {feature} even for that origin: write it as an inner list, "
                       "{feature}=({value}).",
                       "الصيغة {member} تعطّل {feature} حتى لذلك الموقع: اكتبها كقائمة داخلية، {feature}=({value})."),
    "pp_list_member": ("{member}: the element {value} is ignored (only *, self and quoted origins count).",
                       "{member}: العنصر {value} مُهمَل (لا يُعتدّ إلا بـ * وself والمواقع بين علامتي تنصيص)."),
    "pp_typo": ("Unknown feature {feature} is ignored; did you mean {known}?",
                "الميزة {feature} غير معروفة فتُهمَل؛ هل تقصد {known}؟"),
    "pp_star": ("{feature} is allowed for every origin ({member}).",
                "الميزة {feature} مسموحة لكل المواقع ({member})."),
    "iframe_star": ("The iframe from {host} gets {feature} for every origin (allow=\"{value}\").",
                    "الإطار المضمَّن من {host} يحصل على {feature} لكل المواقع (allow=\"{value}\")."),
    "iframe_delegate": ("The page delegates {feature} to the cross-site iframe {host} (allow=\"{value}\").",
                        "تفوّض الصفحة الميزة {feature} إلى الإطار المضمَّن من موقع آخر {host} (allow=\"{value}\")."),
    "fp_no_pp": ("Permissions-Policy is absent, so Chromium ignores this Feature-Policy for the features "
                 "Permissions-Policy covers.",
                 "ترويسة Permissions-Policy غير موجودة، فيتجاهل Chromium إعدادات Feature-Policy هذه للميزات التي "
                 "تغطيها Permissions-Policy."),
    "g3_ignored": ("{header} is ignored on plain-HTTP responses.", "تُهمَل {header} في استجابات HTTP غير المشفّرة."),
    "coop_missing": ("No Cross-Origin-Opener-Policy on this document.", "لا توجد Cross-Origin-Opener-Policy في هذه الصفحة."),
    "coop_unsafe_none": ("unsafe-none gives no protection (the same as no header).",
                         "القيمة unsafe-none لا تحمي شيئًا (كأن الترويسة غير موجودة)."),
    "iso_invalid": ("{value} is not a valid {header} value; browsers ignore the header.",
                    "القيمة {value} ليست قيمة صالحة لـ {header}؛ فيتجاهل المتصفح الترويسة."),
    "iso_multi": ("{header} is sent in {fields}; browsers ignore it.", "تُرسَل {header} في {fields}؛ فيتجاهلها المتصفح."),
    "coep_missing": ("No Cross-Origin-Embedder-Policy (needed only for cross-origin isolation).",
                     "لا توجد Cross-Origin-Embedder-Policy (لا تلزم إلا للعزل بين المصادر)."),
    "corp_invalid": ("{value} is not same-origin, same-site or cross-origin (the value is case-sensitive); browsers "
                     "ignore it.",
                     "القيمة {value} ليست same-origin ولا same-site ولا cross-origin (والقيمة حساسة لحالة الأحرف)؛ "
                     "فيتجاهلها المتصفح."),
    "corp_missing": ("This JSON response carries session data but has no Cross-Origin-Resource-Policy.",
                     "هذه الاستجابة بصيغة JSON تحمل بيانات جلسة لكن بلا Cross-Origin-Resource-Policy."),
    "xxss": ("X-XSS-Protection: {value} switches on the auditor of old browsers.",
             "القيمة X-XSS-Protection: {value} تشغّل المدقق في المتصفحات القديمة."),
    "depr_header": ("{header} is deprecated and ignored by current browsers.",
                    "الترويسة {header} متقادمة ويتجاهلها المتصفح الحديث."),
    "depr_pragma": ("Pragma: {value} without Cache-Control only affects HTTP/1.0 caches.",
                    "Pragma: {value} بلا Cache-Control لا تؤثر إلا في ذاكرات HTTP/1.0 المؤقتة."),
    "ct_missing": ("The response has a body but no Content-Type, so browsers guess the type.",
                   "للاستجابة جسم لكن بلا Content-Type، فيخمّن المتصفح نوعها."),
    "ct_multi": ("Several Content-Type fields with different types: {value}.",
                 "عدة ترويسات Content-Type بأنواع مختلفة: {value}."),
    "ct_mismatch": ("Declared as {declared}, but the body looks like {sniffed}.",
                    "النوع المعلن {declared}، لكن الجسم يبدو {sniffed}."),
    "cs_missing": ("No charset in the Content-Type header, no byte-order mark and no <meta charset> in the first "
                   "1024 bytes.",
                   "لا ترميز في ترويسة Content-Type ولا علامة ترتيب بايتات ولا <meta charset> في أول 1024 بايت."),
    "cs_unknown": ("The charset label {value} is unknown to browsers, so it is ignored.",
                   "تسمية الترميز {value} غير معروفة للمتصفح فتُهمَل."),
    "cs_conflict": ("The header declares {header} but the page declares {meta}; browsers use {header}.",
                    "تعلن الترويسة الترميز {header} بينما تعلن الصفحة {meta}؛ ويستخدم المتصفح {header}."),
    "cache_same_session": ("The same {cookie} session value was issued to two separate requests that sent no cookie "
                           "({first} and {second}): a shared cache hands one visitor's session to the next.",
                           "صدرت قيمة الجلسة نفسها للكوكي {cookie} لطلبين منفصلين لم يرسلا أي كوكي ({first} و{second}): "
                           "فذاكرة مؤقتة مشتركة تسلّم جلسة زائر إلى الزائر التالي."),
    "cache_hit": ("Served from a shared cache ({value}) while setting the session cookie {cookie}.",
                  "قُدِّمت من ذاكرة مؤقتة مشتركة ({value}) وهي تضبط كوكي الجلسة {cookie}."),
    "cache_shared": ("Shared caches (CDN, proxies) may store this sensitive response: Cache-Control: {value}.",
                     "يمكن للذاكرات المؤقتة المشتركة (CDN والوسطاء) تخزين هذه الاستجابة الحساسة: Cache-Control: {value}."),
    "cache_shared_cookie": ("A shared cache may store this response together with its Set-Cookie: Cache-Control: "
                            "{value}.",
                            "يمكن لذاكرة مؤقتة مشتركة تخزين هذه الاستجابة مع ترويسة Set-Cookie فيها: Cache-Control: {value}."),
    "cache_vary_keyed": ("Caches that honour Vary keep one copy per Cookie/Authorization value, so this alone does not "
                         "hand one user's page to another; CDNs configured to ignore Vary would.",
                         "الذاكرات المؤقتة التي تحترم Vary تحفظ نسخة لكل قيمة Cookie أو Authorization، فلا يكفي هذا وحده "
                         "لتسليم صفحة مستخدم إلى غيره؛ لكن شبكات CDN المضبوطة على تجاهل Vary تفعل ذلك."),
    "cache_no_store": ("Sensitive response without no-store (Cache-Control: {value}).",
                       "استجابة حساسة بلا no-store (Cache-Control: {value})."),
    "cache_why": ("Sensitive because: {why}.", "حساسة لأن: {why}."),
    "xpcdp_missing": ("No X-Permitted-Cross-Domain-Policies header.", "لا توجد ترويسة X-Permitted-Cross-Domain-Policies."),
    "csd_unquoted": ("{value} is not a list of quoted strings; browsers ignore the whole header.",
                     "القيمة {value} ليست قائمة من نصوص بين علامتي تنصيص؛ فيتجاهل المتصفح الترويسة كلها."),
    "csd_broad": ("{value} on an ordinary page clears data for every subdomain of the site and logs users out.",
                  "القيمة {value} في صفحة عادية تمسح بيانات كل النطاقات الفرعية للموقع وتُخرج المستخدمين من حساباتهم."),
    "err_dropped": ("Missing on error responses ({statuses}) although the host's pages send them: {headers}.",
                    "مفقودة في استجابات الخطأ ({statuses}) مع أن صفحات المضيف ترسلها: {headers}."),
}

_RESPONSES = ("one response", "{n} responses", ("استجابة واحدة", "استجابتين", "{n} استجابات", "{n} استجابةً",
                                                 "{n} استجابة"))
_FIELDS = ("one field", "{n} fields", ("حقل واحد", "حقلين", "{n} حقول", "{n} حقلًا", "{n} حقل"))
_SENSITIVE_WHY = {
    "cookie": ("it sets a session cookie", "تضبط كوكي جلسة"),
    "password": ("the page has a password field", "في الصفحة حقل كلمة مرور"),
    "role": ("it is a login, account or admin page", "صفحة دخول أو حساب أو إدارة"),
    "401": ("the status is 401", "رمز الحالة 401"),
    "vary": ("it varies by Cookie or Authorization", "تختلف بحسب Cookie أو Authorization"),
    "flag": ("it was classified as sensitive", "صُنّفت حساسة"),
}
_SOURCE_NAMES = {"header": ("the header", "الترويسة"), "meta": ("<meta name=referrer>", "<meta name=referrer>")}

_PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")


def _note(key: str, **values) -> tuple[str, str]:
    """``(en, ar)`` of ``STR[key]`` with ``{name}`` filled literally (no ``str.format``; values are site data)."""
    en, ar = STR[key]

    def fill(text: str, lang: str) -> str:
        def sub(m: re.Match) -> str:
            v = values.get(m.group(1), m.group(0))
            if isinstance(v, tuple):          # (en, ar) pair
                v = v[1] if lang == "ar" else v[0]
            return strip_controls(str(v))     # §0.6: no terminal escapes from the target in notes
        return _PLACEHOLDER.sub(sub, text)
    return fill(en, "en"), fill(ar, "ar")


def _count(n: int, forms: tuple) -> tuple[str, str]:
    from ..i18n.plural import ar_count   # lazy: vulnscan.i18n imports webscan modules through cat_web2
    en = (forms[0] if n == 1 else forms[1]).replace("{n}", str(n))
    return en, ar_count(n, forms[2])


def _short(value: str, limit: int = 120) -> str:
    v = " ".join(value.split())
    return v if len(v) <= limit else v[: limit - 1] + "…"


def _shown(value: str, limit: int = 120) -> str:
    """:func:`_short` for a header value quoted in a note; an empty value reads ``""`` instead of vanishing."""
    return _short(value, limit) or '""'


# ----------------------------------------------------------------------------------------------- shared helpers

HTML_ESSENCES = frozenset({"text/html", "application/xhtml+xml"})
STATIC_KINDS = frozenset({"script", "style", "image", "font", "media", "download"})
SKIP_KINDS = frozenset({"waf_challenge", "rate_limited", "error"})
XCTO_KINDS = ("document", "script", "style", "api_json", "api_xml", "text")
_LOGOUT_PATH = re.compile(r"log[-_]?out|sign[-_]?out|log[-_]?off|sign[-_]?off|logged[-_]?out", re.I)
_PARANOID = "paranoid"


def _kind(r: Response) -> str:
    """``r.kind`` as classify.py set it; a cheap fallback for unclassified (synthetic) responses."""
    if r.kind:
        return r.kind
    s = r.status
    if s is None or r.error:
        return "error"
    if s < 200 or s in (204, 205, 304):
        return "no_content"
    if 300 <= s < 400 and r.headers.has("location"):
        return "redirect"
    if s >= 400:
        return "error_page"
    ess = r.essence
    if ess in HTML_ESSENCES:
        return "document"
    if ess == "application/json" or ess.endswith("+json"):
        return "api_json"
    if ess in ("application/xml", "text/xml") or ess.endswith("+xml"):
        return "api_xml"
    if "javascript" in ess or "ecmascript" in ess:
        return "script"
    if ess == "text/css":
        return "style"
    top = ess.split("/", 1)[0]
    if top in ("image", "font"):
        return top
    if top in ("audio", "video"):
        return "media"
    if ess == "text/plain":
        return "text"
    if not ess and r.body.lstrip()[:15].lower().startswith((b"<!doctype html", b"<html")):
        return "document"
    return "other"


def _is_final_2xx(r: Response) -> bool:
    return r.is_2xx and not r.error


def _opaque(r: Response) -> bool:
    return "opaque-coding" in r.flags


def _parse(r: Response) -> ParsedHTML | None:
    """The light DOM of ``r``; ``None`` when the target's bytes or charset label break decoding (§0.6: a hostile
    response degrades this module's checks, it never aborts the scan)."""
    try:
        return htmlparse.parse_response(r)
    except (ValueError, LookupError, UnicodeError):
        return None


def _charset(label: str | None) -> str | None:
    """:func:`types.normalise_charset` that treats a label ``codecs.lookup`` rejects (NUL byte) as unknown."""
    try:
        return normalise_charset(label)
    except (ValueError, LookupError, UnicodeError):
        return None


def _secure_context(r: Response) -> bool:
    """G3: https, or a potentially trustworthy http origin (``localhost``, ``*.localhost``, loopback IPs), where
    browsers honour COOP, COEP and Clear-Site-Data too, so a developer scanning a local server is not told they are
    ignored."""
    if r.is_https:
        return True
    h = r.host
    if h == "localhost" or h.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(h.strip("[]")).is_loopback
    except ValueError:
        return False


def _ev(ctx: ScanContext, r: Response, *, where: str = "header", name: str = "", value: str = "",
        offset: int | None = None, excerpt: str = "") -> Evidence:
    return Evidence.for_response(r, where=where, name=name, value=value, offset=offset, excerpt=excerpt, now=ctx.now)


def _joined(r: Response, name: str) -> str | None:
    return r.headers.joined(name)


def _split_list(values: Iterable[str]) -> list[str]:
    """Fetch "get, decode, and split" over several field values (commas inside double quotes are kept)."""
    out: list[str] = []
    for v in values:
        buf, quoted, i = [], False, 0
        while i < len(v):
            c = v[i]
            if c == '"':
                quoted = not quoted
            elif c == "\\" and quoted and i + 1 < len(v):
                buf.append(c)
                i += 1
                c = v[i]
            elif c == "," and not quoted:
                out.append("".join(buf).strip(" \t"))
                buf = []
                i += 1
                continue
            buf.append(c)
            i += 1
        out.append("".join(buf).strip(" \t"))
    return out


def _cookie_facts(ctx: ScanContext, r: Response) -> list[CookieFact]:
    return [c for c in ctx.cookies if c.response is r and not c.deletion and not c.ignored]


def _session_cookies(ctx: ScanContext, r: Response) -> list[CookieFact]:
    return [c for c in _cookie_facts(ctx, r) if c.is_session_class]


def _sensitive_reasons(ctx: ScanContext, r: Response, doc: ParsedHTML | None) -> list[str]:
    """Why ``r`` is sensitive (§WEB315); empty when it is not. The engine's ``sensitive`` flag also counts."""
    why = []
    if _session_cookies(ctx, r):
        why.append("cookie")
    if doc is not None and doc.has_password_field:
        why.append("password")
    if r.roles & {"login", "authenticated", "admin"}:
        why.append("role")
    if r.status == 401:
        why.append("401")
    for v in r.headers.get_all("vary"):
        if any(t.strip().lower() in ("cookie", "authorization") for t in v.split(",")):
            why.append("vary")
            break
    if not why and "sensitive" in r.flags:
        why.append("flag")
    return why


# ----------------------------------------------------------------------------------------------- X-Frame-Options

@dataclass(frozen=True)
class XfoVerdict:
    """The HTML spec's "check a navigation response's adherence to X-Frame-Options" for one response."""
    present: bool
    values: tuple[str, ...]          # get-decode-split values, lower-cased (duplicates kept)
    fields: int                      # number of header fields
    effect: str                      # "absent" | "deny" | "sameorigin"
    reason: str = ""                 # "" | "allow-from" | "invalid" | "multi-invalid" | "conflict" | "identical"

    @property
    def blocks(self) -> bool:
        return self.effect != "absent"


def xfo_verdict(fields: list[str]) -> XfoVerdict:
    if not fields:
        return XfoVerdict(False, (), 0, "absent")
    # Empty members (``DENY,``, a stray comma from a template) are dropped as Chromium does (SPLIT_WANT_NONEMPTY):
    # cross-origin framing is blocked under either reading, and a trailing comma is not "two layers fighting" (WEB301).
    values = tuple(v.lower() for v in _split_list(fields) if v)
    if not values:
        return XfoVerdict(True, ("",), len(fields), "absent", "invalid")
    distinct = set(values)
    if len(distinct) > 1:
        if distinct & {"deny", "allowall", "sameorigin"}:
            return XfoVerdict(True, values, len(fields), "deny", "conflict")
        return XfoVerdict(True, values, len(fields), "absent", "multi-invalid")
    only = values[0]
    identical = len(values) > 1
    if only == "deny":
        return XfoVerdict(True, values, len(fields), "deny", "identical" if identical else "")
    if only == "sameorigin":
        return XfoVerdict(True, values, len(fields), "sameorigin", "identical" if identical else "")
    return XfoVerdict(True, values, len(fields), "absent", "allow-from" if only.startswith("allow-from") else "invalid")


_BROAD_FA = frozenset({"*", "http:", "https:", "http://*", "https://*", "http://*.*", "https://*.*", "ftp:"})


def _local_frame_ancestors(r: Response) -> list[list[str]]:
    """frame-ancestors source lists of the enforced header CSPs (one per policy that sets it), used only when
    ``ctx.csp`` has no facts for ``r``. A deliberately small reading: WP4's parser is authoritative when it ran."""
    found: list[list[str]] = []
    for value in r.headers.get_all("content-security-policy"):
        for policy in value.split(","):
            seen: set[str] = set()
            for directive in policy.split(";"):
                parts = directive.strip().split()
                if not parts:
                    continue
                name = parts[0].lower()
                if name in seen:
                    continue
                seen.add(name)
                if name == "frame-ancestors":
                    found.append([p.lower() for p in parts[1:]])
    return found


def _frame_ancestors(ctx: ScanContext, r: Response) -> tuple[bool, bool]:
    """``(has frame-ancestors in an enforced header policy, it restricts framing)``."""
    facts = ctx.csp.get(r)
    if facts is not None:
        return facts.frame_ancestors is not None, bool(facts.frame_ancestors_protects)
    lists = _local_frame_ancestors(r)
    if not lists:
        return False, False
    # every enforced policy applies: framing is restricted when any one of them restricts it
    return True, any(not (set(fa) & _BROAD_FA) for fa in lists)


# ----------------------------------------------------------------------------------------------- Referrer-Policy

REFERRER_POLICIES = ("no-referrer", "no-referrer-when-downgrade", "same-origin", "origin", "strict-origin",
                     "origin-when-cross-origin", "strict-origin-when-cross-origin", "unsafe-url")
REFERRER_PRIVATE = frozenset({"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"})
REFERRER_LEAKY = frozenset({"origin", "origin-when-cross-origin", "no-referrer-when-downgrade"})
# HTML <meta name=referrer> legacy keywords
_META_LEGACY = {"never": "no-referrer", "default": "strict-origin-when-cross-origin", "always": "unsafe-url",
                "origin-when-crossorigin": "origin-when-cross-origin"}


@dataclass(frozen=True)
class ReferrerVerdict:
    present: bool                    # a header field or a <meta name=referrer> exists
    policy: str | None               # effective policy (None = nothing recognised)
    source: str = ""                 # "header" | "meta"
    raw: str = ""


def referrer_verdict(r: Response, doc: ParsedHTML | None) -> ReferrerVerdict:
    """Effective policy: the last recognised token across all header fields, then a valid ``<meta name=referrer>``
    (HTML processes metas in order, the last valid one wins and overrides the header)."""
    fields = r.headers.get_all("referrer-policy")
    policy, source = None, ""
    for tok in _split_list(fields):
        t = tok.strip().lower()
        if t in REFERRER_POLICIES:
            policy, source = t, "header"
    metas = doc.metas(name="referrer") if doc is not None else []
    raw_meta = []
    for m in metas:
        content = m.get("content")
        if content is None:
            continue
        raw_meta.append(content)
        v = content.strip().lower()
        v = _META_LEGACY.get(v, v)
        if v in REFERRER_POLICIES:
            policy, source = v, "meta"
    raw = ", ".join([*fields, *raw_meta])
    return ReferrerVerdict(bool(fields) or bool(raw_meta), policy, source, raw)


# ----------------------------------------------------------------------------------------------- Permissions-Policy

PP_FEATURES = frozenset("""
accelerometer ambient-light-sensor aria-notify attribution-reporting autoplay bluetooth browsing-topics camera
captured-surface-control ch-ua-high-entropy-values compute-pressure cross-origin-isolated deferred-fetch
deferred-fetch-minimal display-capture encrypted-media fullscreen gamepad geolocation gyroscope hid
identity-credentials-get idle-detection language-detector language-model local-fonts local-network
local-network-access loopback-network magnetometer microphone midi on-device-speech-recognition otp-credentials payment
picture-in-picture private-state-token-issuance private-state-token-redemption publickey-credentials-create
publickey-credentials-get screen-wake-lock serial speaker-selection storage-access summarizer translator unload usb
web-share window-management xr-spatial-tracking
""".split())
# names browsers knew at some point or still parse: never reported, never a typo target
PP_OBSOLETE = frozenset("""
interest-cohort document-domain sync-xhr vibrate battery execution-while-not-rendered execution-while-out-of-viewport
focus-without-user-activation keyboard-map navigation-override run-ad-auction join-ad-interest-group sync-script
clipboard-read clipboard-write digital-credentials-get vr wake-lock layout-animations legacy-image-formats
oversized-images unoptimized-images unoptimized-lossy-images unoptimized-lossless-images unsized-media
vertical-scroll lazyload loading-frame-default-eager document-write font-display-late-swap animations ch-dpr
ch-viewport-width ch-width ch-device-memory ch-downlink ch-ect ch-rtt ch-ua ch-ua-arch ch-ua-bitness ch-ua-full-version
ch-ua-full-version-list ch-ua-mobile ch-ua-model ch-ua-platform ch-ua-platform-version ch-ua-wow64 ch-ua-form-factors
ch-prefers-color-scheme ch-prefers-reduced-motion ch-prefers-reduced-transparency ch-save-data ch-viewport-height
direct-sockets shared-autofill smart-card all-screens-capture popins controlled-frame web-printing
fenced-unpartitioned-storage-read autofill manual-text browsing-topics-ad
""".split())
POWERFUL_FEATURES = ("camera", "microphone", "geolocation", "payment", "usb", "serial", "hid", "bluetooth",
                     "display-capture", "publickey-credentials-get", "clipboard-read", "local-network-access")


def _edit_distance(a: str, b: str, limit: int = 3) -> int:
    if abs(len(a) - len(b)) >= limit:
        return limit
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
        if min(prev) >= limit:
            return limit
    return min(prev[-1], limit)


def typo_of(name: str) -> str | None:
    """The known feature ``name`` is probably a misspelling of (edit distance ≤ 2, ≤ 1 for names under 5 letters)."""
    if name in PP_FEATURES or name in PP_OBSOLETE:
        return None
    best, best_d = None, 99
    for known in sorted(PP_FEATURES):
        d = _edit_distance(name, known)
        if d < best_d:
            best, best_d = known, d
    allowed = 1 if min(len(name), len(best or "")) < 5 else 2
    return best if best is not None and 0 < best_d <= allowed else None


def _origin_of(value: str) -> str | None:
    try:
        p = urllib.parse.urlsplit(value.strip())
        if p.scheme.lower() in ("http", "https", "ws", "wss", "ftp") and p.hostname:
            return f"{p.scheme.lower()}://{normalise_host(p.hostname)}" + (f":{p.port}" if p.port else "")
    except ValueError:
        return None
    return None


@dataclass
class PermissionsPolicy:
    """A parsed Permissions-Policy (``members`` keeps the sfv members); ``error`` when the header is ignored."""
    members: dict = field(default_factory=dict)
    error: str = ""
    present: bool = False

    def allowlist(self, feature: str) -> tuple[bool, set[str], bool] | None:
        """``(matches all, origins, self)`` for a declared feature per "construct policy from dictionary"; ``None``
        when the feature is not declared (or the header is invalid)."""
        if self.error or feature not in self.members:
            return None
        m = self.members[feature]
        star, origins, self_ = False, set(), False
        items = m.items if isinstance(m, sfv.InnerList) else [m]
        for it in items:
            v = it.value
            if isinstance(v, sfv.Token):
                if v == "*":
                    star = True
                elif v == "self":
                    self_ = True
            elif isinstance(v, str) and isinstance(m, sfv.InnerList):
                o = _origin_of(v)
                if o:
                    origins.add(o)
        return star, origins, self_


def parse_permissions_policy(fields: list[str]) -> PermissionsPolicy:
    if not fields:
        return PermissionsPolicy()
    joined = ", ".join(fields)
    if not joined.strip():
        return PermissionsPolicy(present=True)
    res, err = sfv.try_parse("dictionary", fields)
    if err is not None:
        return PermissionsPolicy(error=err, present=True)
    return PermissionsPolicy(members=dict(res), present=True)


def _member_text(name: str, m) -> str:
    def bare(v) -> str:
        if isinstance(v, sfv.Token):
            return str(v)
        if isinstance(v, bool):
            return "?1" if v else "?0"
        if isinstance(v, str):
            return '"' + v + '"'
        return str(v)
    if isinstance(m, sfv.InnerList):
        return f"{name}=(" + " ".join(bare(i.value) for i in m.items) + ")"
    if isinstance(m.value, bool) and m.value:
        return name
    return f"{name}={bare(m.value)}"


def pp_problems(pp: PermissionsPolicy) -> list[tuple[str, str, tuple[str, str], str]]:
    """``[(rule, severity, note, group value)]`` for WEB305/WEB306 on a parsed policy."""
    out: list[tuple[str, str, tuple[str, str], str]] = []
    if pp.error:
        return [("WEB305", "medium", _note("pp_parse", error=_short(pp.error)), "parse-error")]
    for name, m in pp.members.items():
        text = _member_text(name, m)
        if name not in PP_FEATURES and name not in PP_OBSOLETE:
            known = typo_of(name)
            if known:
                out.append(("WEB305", "low", _note("pp_typo", feature=_short(name, 60), known=known),
                            f"typo:{_short(name, 60)}"))
            continue
        if isinstance(m, sfv.InnerList):
            # one finding per member: the worst ignored element (a hostile header may list thousands)
            worst: tuple[str, str] | None = None
            for it in m.items:
                v = it.value
                if isinstance(v, sfv.Token) and v in ("*", "self"):
                    continue
                if isinstance(v, str) and not isinstance(v, sfv.Token) and _origin_of(v):
                    continue
                shown = v if isinstance(v, sfv.Token) else f'"{v}"' if isinstance(v, str) else str(v)
                # an origin the author meant to allow is lost (a quoted non-origin, or an unquoted origin, which
                # parses as a Token): low; other junk such as (none) only disables the feature: info
                meant_origin = isinstance(v, str) and (not isinstance(v, sfv.Token) or _origin_of(v) is not None)
                sev = "low" if meant_origin else "info"
                if worst is None or (sev == "low" and worst[0] == "info"):
                    worst = (sev, shown)
            if worst is not None:
                out.append(("WEB305", worst[0], _note("pp_list_member", member=_short(text), value=_short(worst[1])),
                            f"member:{_short(text)}"))
        else:
            v = m.value
            if isinstance(v, sfv.Token) and v in ("*", "self"):
                pass
            elif isinstance(v, str) and (not isinstance(v, sfv.Token) or _origin_of(v) is not None):
                # a bare string, or an unquoted origin (it parses as a Token): the origin is not added either way
                out.append(("WEB305", "low", _note("pp_bare_string", member=_short(text), feature=name,
                                                   value=_short(f'"{v}"')), f"member:{_short(text)}"))
            else:
                out.append(("WEB305", "info", _note("pp_bare_token", member=_short(text), feature=name),
                            f"member:{_short(text)}"))
        if name in POWERFUL_FEATURES:
            al = pp.allowlist(name)
            if al and al[0]:
                out.append(("WEB306", "low", _note("pp_star", feature=name, member=_short(text)), f"star:{name}"))
    return out


def parse_allow_attribute(value: str) -> list[tuple[str, list[str]]]:
    """``<iframe allow>`` per Permissions Policy "parse policy directive": ``[(feature, targets)]``; an empty target
    list means the default ``'src'``."""
    out = []
    for decl in value.split(";"):
        toks = decl.split()
        if not toks:
            continue
        out.append((toks[0].lower(), toks[1:]))
    return out


# ----------------------------------------------------------------------------------------------- COOP / COEP / CORP

COOP_TOKENS = ("same-origin", "same-origin-allow-popups", "noopener-allow-popups", "unsafe-none")
COEP_TOKENS = ("require-corp", "credentialless", "unsafe-none")
CORP_VALUES = ("same-origin", "same-site", "cross-origin")


def isolation_token(fields: list[str], allowed: tuple[str, ...]) -> tuple[str | None, str]:
    """``(token, problem)`` for COOP/COEP (an RFC 8941 Item whose bare item is a Token from ``allowed``; parameters
    are allowed). ``problem``: "" | "missing" | "multi" | "invalid"."""
    if not fields:
        return None, "missing"
    if len(fields) > 1:
        return None, "multi"
    item, err = sfv.try_parse("item", fields[0])
    if err is not None or not isinstance(item.value, sfv.Token) or item.value not in allowed:
        return None, "invalid"
    return str(item.value), ""


def corp_value(fields: list[str]) -> tuple[str | None, str]:
    """Fetch's CORP check: the combined value compared byte for byte (case-sensitive)."""
    if not fields:
        return None, "missing"
    if len(fields) > 1:
        return None, "multi"
    v = fields[0].strip(" \t")
    return (v, "") if v in CORP_VALUES else (None, "invalid")


# ----------------------------------------------------------------------------------------------- Cache-Control

def parse_cache_control(fields: list[str]) -> dict[str, str]:
    """RFC 9111 directives (lower-case names; values unquoted; the first occurrence of a name wins)."""
    out: dict[str, str] = {}
    for part in _split_list(fields):
        if not part:
            continue
        name, eq, val = part.partition("=")
        name = name.strip().lower()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] == '"':
            val = val[1:-1]
        out.setdefault(name, val if eq else "")
    return out


def _int(v: str | None) -> int | None:
    if v is None:
        return None
    v = v.strip()
    return int(v) if v.isdigit() else None


def shared_cacheable(cc: dict[str, str]) -> bool:
    """``public`` or ``s-maxage > 0``, and neither ``private`` nor ``no-store`` (RFC 9111 §3, §5.2.2)."""
    if "no-store" in cc or "private" in cc:
        return False
    return "public" in cc or (_int(cc.get("s-maxage")) or 0) > 0


# RFC 9110 §15.1: status codes that are heuristically cacheable (stored without explicit freshness)
HEURISTIC_STATUSES = frozenset({200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501})


def _storable(r: Response, cc: dict[str, str]) -> bool:
    """A cache may store ``r``: no no-store, and a heuristically cacheable status or explicit freshness."""
    if "no-store" in cc:
        return False
    if r.status in HEURISTIC_STATUSES:
        return True
    return ("public" in cc or "max-age" in cc or "s-maxage" in cc or r.headers.has("expires"))


def cache_hit(r: Response) -> str | None:
    """The header that shows ``r`` came from a shared cache (passively observed), or ``None``."""
    h = r.headers
    age = _int(h.first("age"))
    if age is not None and age > 0:
        return f"Age: {age}"
    for name in ("x-cache", "cf-cache-status", "x-cache-status", "akamai-cache-status", "x-proxy-cache",
                 "x-varnish-cache", "cdn-cache-status"):
        for v in h.get_all(name):
            first = v.split(",")[0].strip().lower()
            if first.startswith(("hit", "tcp_hit", "tcp_mem_hit")) or first == "stale":
                return f"{name}: {_short(v, 60)}"
    return None


# ----------------------------------------------------------------------------------------------- Clear-Site-Data

def clear_site_data_values(fields: list[str]) -> tuple[list[str], bool]:
    """``(types, valid)``: the quoted types of ``1#quoted-string``; ``valid`` is False when any member is unquoted."""
    types, valid = [], True
    for part in _split_list(fields):
        if not part:
            continue
        if len(part) >= 2 and part[0] == part[-1] == '"':
            types.append(part[1:-1])
        else:
            valid = False
    return types, valid


# ----------------------------------------------------------------------------------------------- Observatory v6

OBS_TESTS = ("referrer-policy", "x-content-type-options", "x-frame-options", "cross-origin-resource-policy",
             "cross-origin-embedder-policy", "cross-origin-opener-policy")
_OBS_REF_GOOD = ("no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin")
_OBS_REF_BAD = ("origin", "origin-when-cross-origin", "unsafe-url", "no-referrer-when-downgrade")


def _obs_header(r: Response, name: str) -> str | None:
    """What Node's http module hands Observatory: duplicate fields joined with ", "."""
    return r.headers.joined(name)


def _obs_html(r: Response) -> bool:
    ct = r.headers.first("content-type")
    return ct is not None and ct.split(";", 1)[0] in HTML_ESSENCES and bool(r.body)


def _obs_csp_has_frame_ancestors(r: Response, doc: ParsedHTML | None) -> bool:
    """Observatory's ``contentSecurityPolicyTest(...).data["frame-ancestors"]`` truthiness (csp.js, cspParser.js)."""
    header = [p.strip() for v in r.headers.get_all("content-security-policy") for p in v.split(",")]
    meta: list[str] = []
    if doc is not None and _obs_html(r):
        for m in doc.find_all("meta"):
            if m.has("http-equiv") and m.has("content"):
                if (m.get("http-equiv") or "").strip().lower() == "content-security-policy" and m.get("content"):
                    meta.extend(p.strip() for p in (m.get("content") or "").split(","))

    def parse(policies: list[str], drop: tuple[str, ...] = ()) -> set[str] | None:
        names: set[str] = set()
        for pol in policies:
            pol = pol.replace("\r", "").replace("\n", "").strip()
            if not pol or len(pol) < 6:
                return None
            seen: set[str] = set()
            for entry in pol.split(";"):
                parts = entry.strip().split()
                if not parts or not parts[0]:
                    continue
                d = parts[0].lower()
                if d in seen and d not in ("report-uri", "report-to"):
                    return None
                seen.add(d)
                names.add(d)
        return {n for n in names if n not in drop}

    combined = parse(header + meta)
    if combined is None:                                   # csp-header-invalid: data stays null
        return False
    header_only = parse(header) or set()
    meta_only = parse(meta, ("frame-ancestors", "report-uri", "sandbox")) or set()
    if not header_only and not meta_only:                  # csp-not-implemented
        return False
    return "frame-ancestors" in combined


def observatory_slugs(r: Response | None, doc: ParsedHTML | None) -> dict[str, str]:
    """The six Observatory v6 results for the "auto" response (Observatory 1.7.2, quirks included)."""
    if r is None:
        return {"referrer-policy": "referrer-policy-not-implemented",
                "x-content-type-options": "x-content-type-options-not-implemented",
                "x-frame-options": "x-frame-options-not-implemented",
                "cross-origin-resource-policy": "corp-not-implemented",
                "cross-origin-embedder-policy": "coep-not-implemented",
                "cross-origin-opener-policy": "coop-not-implemented"}
    out: dict[str, str] = {}
    html_doc = doc if _obs_html(r) else None

    # referrer-policy: header values then <meta name=referrer> (the last one with content), last valid token
    parts = list(r.headers.get_all("referrer-policy"))
    meta_ref = None
    if html_doc is not None:
        for m in html_doc.find_all("meta"):
            if m.has("http-equiv") and m.has("content"):
                continue
            if (m.get("name") or "").strip().lower() == "referrer" and m.get("content"):
                meta_ref = m.get("content")
    if meta_ref is not None:
        parts.append(meta_ref)
    if not parts:
        out["referrer-policy"] = "referrer-policy-not-implemented"
    else:
        valid = [t.strip().lower() for t in ", ".join(parts).split(",")
                 if t.strip().lower() in _OBS_REF_GOOD + _OBS_REF_BAD]
        pol = valid[-1] if valid else ""
        out["referrer-policy"] = ("referrer-policy-private" if pol in _OBS_REF_GOOD else
                                  "referrer-policy-unsafe" if pol in _OBS_REF_BAD else "referrer-policy-header-invalid")

    xcto = _obs_header(r, "x-content-type-options")
    if xcto is None:
        out["x-content-type-options"] = "x-content-type-options-not-implemented"
    else:
        out["x-content-type-options"] = ("x-content-type-options-nosniff" if xcto[:256].strip().lower() == "nosniff"
                                         else "x-content-type-options-header-invalid")

    xfo = _obs_header(r, "x-frame-options")
    if xfo is None:
        slug = "x-frame-options-not-implemented"
    else:
        v = xfo[:1024].strip().lower()
        slug = ("x-frame-options-sameorigin-or-deny" if v in ("deny", "sameorigin") else
                "x-frame-options-allow-from-origin" if v.startswith("allow-from") else "x-frame-options-header-invalid")
    if _obs_csp_has_frame_ancestors(r, html_doc):
        slug = "x-frame-options-implemented-via-csp"
    out["x-frame-options"] = slug

    corp = _obs_header(r, "cross-origin-resource-policy")
    if not corp:
        out["cross-origin-resource-policy"] = "corp-not-implemented"
    else:
        v = corp[:256].strip().lower()
        out["cross-origin-resource-policy"] = {"same-site": "corp-implemented-with-same-site",
                                               "same-origin": "corp-implemented-with-same-origin",
                                               "cross-origin": "corp-implemented-with-cross-origin"}.get(
                                                   v, "corp-header-invalid")

    for test, header, prefix, tokens in (
            ("cross-origin-embedder-policy", "cross-origin-embedder-policy", "coep", COEP_TOKENS),
            ("cross-origin-opener-policy", "cross-origin-opener-policy", "coop", COOP_TOKENS)):
        fields = r.headers.get_all(header)
        if not fields or not ", ".join(fields):
            out[test] = f"{prefix}-not-implemented"
            continue
        item, err = sfv.try_parse("item", ", ".join(fields)[:1024].strip())
        tok = str(item.value) if err is None and isinstance(item.value, sfv.Token) else None
        out[test] = f"{prefix}-implemented-with-{tok}" if tok in tokens else f"{prefix}-header-invalid"
    return out


def observatory_auto(ctx: ScanContext) -> Response | None:
    """Observatory's ``responses.auto``: the https session's final response when https answered, else http's."""
    for r in (ctx.entry, ctx.https_probe, ctx.http_probe):
        if r is not None and r.is_https and r.status is not None and not r.error:
            return r
    for r in (ctx.entry, ctx.http_probe):
        if r is not None and r.status is not None and not r.error:
            return r
    return None


# ----------------------------------------------------------------------------------------------- the run

class _Run:
    """One pass of the module over a context: emitted issues plus per-check coverage bookkeeping."""

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.issues: list[Issue] = []
        self.evaluated: dict[str, set[str]] = {}       # check → hosts where it was evaluated
        self.failed: dict[str, set[str]] = {}          # check → hosts with a reported issue
        self.paranoid = ctx.options.sensitivity == _PARANOID
        self.own_sites = {psl.site(h) for h in (ctx.target_host, ctx.entry.host if ctx.entry else "") if h}
        self.blocked_hosts: dict[str, str] = {}        # host → G4 reason (waf | rate_limited)
        if ctx.entry is not None and _kind(ctx.entry) in ("waf_challenge", "rate_limited"):
            reason = "waf" if _kind(ctx.entry) == "waf_challenge" else "rate_limited"
            for h in ctx.entry.hops():
                self.blocked_hosts[h.host] = reason

    # -- bookkeeping ----------------------------------------------------------------------------------------
    def seen(self, check: str, host: str) -> None:
        self.evaluated.setdefault(check, set()).add(host)

    def emit(self, rule: str, r: Response, evidence: Evidence, *, severity: str | None = None,
             confidence: str | None = None, group_value: str = "", notes: list[tuple[str, str]] | None = None,
             params: dict | None = None) -> None:
        meta = RULES[rule]
        conf = confidence or meta.confidence
        if conf not in meta.allowed_confidences:
            return
        sev = severity if severity in meta.allowed_severities else None
        self.issues.append(Issue(rule=rule, url=r.url, confidence=conf, evidence=evidence, params=dict(params or {}),
                                 severity=sev, group_value=group_value, notes=list(notes or []), host=r.host))
        self.seen(meta.check_id, r.host)
        if self.ctx.options.reports(conf):
            self.failed.setdefault(meta.check_id, set()).add(r.host)

    # -- response sets ----------------------------------------------------------------------------------------
    def own(self, r: Response) -> bool:
        return bool(r.host) and psl.site(r.host) in self.own_sites

    def value_responses(self) -> list[Response]:
        """G2: every fetched response of the site (hops included), except WAF/rate-limit pages and network errors."""
        return [r for r in self.ctx.all_responses() if self.own(r) and _kind(r) not in SKIP_KINDS
                and r.status is not None]

    def final_responses(self) -> list[Response]:
        return [r for r in self.ctx.all_responses(include_hops=False) if self.own(r) and _kind(r) not in SKIP_KINDS
                and r.status is not None]

    def documents(self) -> list[tuple[Response, ParsedHTML | None, str]]:
        """G1 targets ``(response, doc, confidence override)``: final 2xx documents, and at paranoid HTML 4xx/5xx
        pages (confidence ``tentative``). Hosts under G4 are excluded."""
        out: list[tuple[Response, ParsedHTML | None, str]] = []
        seen: set[int] = set()
        pages: list[Page] = list(self.ctx.pages)
        if self.ctx.entry is not None and not any(p.response is self.ctx.entry for p in pages):
            pages.insert(0, Page(self.ctx.entry, None, 0))
        for p in pages:
            r = p.response
            if id(r) in seen or not self.own(r) or r.host in self.blocked_hosts:
                continue
            k = _kind(r)
            conf = ""
            if k == "document" and _is_final_2xx(r):
                pass
            elif self.paranoid and k == "error_page" and r.essence in HTML_ESSENCES:
                conf = "tentative"
            else:
                continue
            seen.add(id(r))
            doc = p.doc
            if doc is None and r.body and not _opaque(r):
                doc = _parse(r)
            out.append((r, doc, conf))
        if self.paranoid:
            for r in self.final_responses():
                if id(r) in seen or r.host in self.blocked_hosts:
                    continue
                if _kind(r) == "error_page" and r.essence in HTML_ESSENCES and r.body and not _opaque(r):
                    seen.add(id(r))
                    out.append((r, _parse(r), "tentative"))
        return out

    # -- coverage ---------------------------------------------------------------------------------------------
    def record_coverage(self) -> None:
        cov = self.ctx.coverage
        if cov is None:
            return
        for check in CHECKS:
            hosts = self.evaluated.get(check, set())
            failed = self.failed.get(check, set())
            for host in sorted(hosts):
                if host in failed:
                    cov.failed(check, host)
                else:
                    cov.passed(check, host)
            for host, reason in self.blocked_hosts.items():
                if host not in hosts:
                    cov.inconclusive(check, reason, host=host)
            if not hosts and not self.blocked_hosts:
                if RULES[check].paranoid_only and not self.paranoid:
                    cov.not_tested(check, "sensitivity")
                else:
                    cov.not_applicable(check, "no_document" if check in _DOC_CHECKS else "")


_DOC_CHECKS = frozenset({"WEB-x-frame-options", "WEB-referrer-policy", "WEB-permissions-policy", "WEB302", "WEB308",
                         "WEB314", "WEB318"})


def run(ctx: ScanContext) -> list[Issue]:
    """All §2.3 checks over the context (pure apart from writing ``ctx.observatory`` and coverage states)."""
    st = _Run(ctx)
    docs = st.documents()
    _framing(st, docs)
    _xcto(st)
    _referrer(st, docs)
    _permissions(st, docs)
    _isolation(st, docs)
    _legacy(st, docs)
    _content_type(st, docs)
    _caching(st, docs)
    _clear_site_data(st)
    _error_pages(st, docs)
    st.record_coverage()
    auto = observatory_auto(ctx)
    page = ctx.page_for(auto) if auto is not None else None
    auto_doc = page.doc if page is not None else None
    if auto is not None and auto_doc is None and _obs_html(auto) and not _opaque(auto):
        auto_doc = _parse(auto)
    ctx.observatory.update(observatory_slugs(auto, auto_doc))
    if isinstance(ctx.inventory, dict):
        ctx.inventory["security_headers"] = header_inventory(ctx, docs)
    return st.issues


INVENTORY_MAX_RESPONSES = 20
_INV_VALUE_CAP = 200


def header_inventory(ctx: ScanContext, docs) -> list[dict]:
    """§3.9 "security headers table (value + verdict)" for the judged documents (at most 20): report data, not
    findings. ``-Report-Only`` isolation headers land here only (§WEB308)."""
    out: list[dict] = []
    for r, doc, _conf in docs[:INVENTORY_MAX_RESPONSES]:
        h = r.headers
        rows: dict[str, dict] = {}

        def row(name: str, verdict: str, values: list[str]) -> None:
            value = strip_controls(_short(", ".join(values), _INV_VALUE_CAP)) if values else None
            rows[name] = {"value": value, "verdict": verdict}

        xfo = h.get_all("x-frame-options")
        v = xfo_verdict(xfo)
        has_fa, fa_protects = _frame_ancestors(ctx, r)
        if v.blocks:
            xfo_state = v.effect
        elif has_fa:
            xfo_state = "frame-ancestors" if fa_protects else "frame-ancestors-broad"
        else:
            xfo_state = v.reason or "missing"
        row("X-Frame-Options", xfo_state, xfo)
        xcto = h.get_all("x-content-type-options")
        first = (_split_list(xcto) or [""])[0].strip().lower() if xcto else ""
        row("X-Content-Type-Options", "nosniff" if first == "nosniff" else "invalid" if xcto else "missing", xcto)
        rv = referrer_verdict(r, doc)
        row("Referrer-Policy", rv.policy or ("unrecognised" if rv.present else "missing"),
            h.get_all("referrer-policy"))
        pp_fields = h.get_all("permissions-policy")
        pp = parse_permissions_policy(pp_fields)
        row("Permissions-Policy", "invalid" if pp.error else "present" if pp.present else "missing", pp_fields)
        for name, allowed in (("Cross-Origin-Opener-Policy", COOP_TOKENS), ("Cross-Origin-Embedder-Policy", COEP_TOKENS)):
            for header in (name, name + "-Report-Only"):
                fields = h.get_all(header)
                if not fields and header != name:
                    continue
                tok, problem = isolation_token(fields, allowed)
                verdict = tok or problem
                if fields and not _secure_context(r):
                    verdict = "ignored-on-http"
                elif tok and header != name:
                    verdict = "report-only:" + tok
                row(header, verdict, fields)
        corp = h.get_all("cross-origin-resource-policy")
        cv, problem = corp_value(corp)
        row("Cross-Origin-Resource-Policy", cv or problem, corp)
        for header in ("Feature-Policy", "X-XSS-Protection", "Clear-Site-Data", "X-Permitted-Cross-Domain-Policies",
                       "Cache-Control"):
            fields = h.get_all(header)
            if fields:
                row(header, "present", fields)
        out.append({"url": r.url, "status": r.status, "headers": rows})
    return out


# ----------------------------------------------------------------------------------------------- checks

def _framing(st: _Run, docs) -> None:
    ctx = st.ctx
    # WEB300 / WEB301: value rules on every response that carries the header
    reported: set[int] = set()
    for r in st.value_responses():
        fields = r.headers.get_all("x-frame-options")
        st.seen("WEB300", r.host)
        st.seen("WEB301", r.host)
        if not fields:
            continue
        v = xfo_verdict(fields)
        shown = _shown(", ".join(fields))
        ev = _ev(ctx, r, name="X-Frame-Options", value=", ".join(fields))
        _has_fa, fa_protects = _frame_ancestors(ctx, r)
        if v.reason in ("allow-from", "invalid", "multi-invalid"):
            key = {"allow-from": "xfo_allow_from", "invalid": "xfo_invalid", "multi-invalid": "xfo_multi_invalid"}[v.reason]
            notes = [_note(key, value=shown)]
            if fa_protects:
                notes.append(_note("xfo_fa_protects"))
            st.emit("WEB300", r, ev, severity="low" if fa_protects else "medium", notes=notes,
                    group_value=", ".join(v.values))
            reported.add(id(r))
        elif v.reason == "conflict":
            st.emit("WEB301", r, ev, severity="low", notes=[_note("xfo_conflict", value=shown)],
                    group_value=", ".join(sorted(set(v.values))))
            reported.add(id(r))
        elif v.reason == "identical" and st.paranoid:
            # browsers honour identical duplicates; the spec's "info" note is shown at paranoid only (corpus trap
            # hdr-xfo-sameorigin-dup: WEB301 must stay silent at default sensitivity)
            st.emit("WEB301", r, ev, severity="info",
                    notes=[_note("xfo_identical", fields=_count(len(v.values), _FIELDS))],
                    group_value=v.values[0])
    # WEB-x-frame-options (G1) and WEB302 (meta)
    for r, doc, conf in docs:
        st.seen("WEB-x-frame-options", r.host)
        st.seen("WEB302", r.host)
        if doc is not None:
            # one finding per document (the first meta): a page repeating the tag is one cause, not N findings
            for m in doc.metas(http_equiv="x-frame-options")[:1]:
                content = m.get("content") or ""
                st.emit("WEB302", r, _ev(ctx, r, where="body", name="meta http-equiv=X-Frame-Options", value=content,
                                         offset=m.offset,
                                         excerpt=f'<meta http-equiv="X-Frame-Options" content="{_short(content, 100)}">'),
                        notes=[_note("xfo_meta", value=_short(content))], group_value=_short(content.strip().lower()))
        has_fa, _protects = _frame_ancestors(ctx, r)
        if has_fa:
            continue                           # frame-ancestors decides (WEB206 judges a broad one)
        v = xfo_verdict(r.headers.get_all("x-frame-options"))
        if v.blocks or (v.present and id(r) in reported):
            continue                           # protected, or WEB300/WEB301 explains the gap
        roles = r.roles
        interactive = bool(roles & {"login", "signup", "authenticated", "admin"}) or (
            doc is not None and (any(f.live for f in doc.forms) or doc.has_password_field))
        st.emit("WEB-x-frame-options", r, _ev(ctx, r, name="X-Frame-Options"),
                severity="medium" if interactive else "low", confidence=conf or None)


def _xcto(st: _Run) -> None:
    ctx = st.ctx
    missing: dict[str, list[Response]] = {}
    for r in st.value_responses():
        fields = r.headers.get_all("x-content-type-options")
        st.seen("WEB303", r.host)
        if fields:
            values = _split_list(fields)
            first = values[0] if values else ""
            if first.strip().lower() != "nosniff":
                st.emit("WEB303", r, _ev(ctx, r, name="X-Content-Type-Options", value=", ".join(fields)),
                        notes=[_note("xcto_invalid", value=_short(first or '""'))], group_value=first.strip().lower())
    for r in st.final_responses():
        if r.host in st.blocked_hosts:
            continue
        k = _kind(r)
        if k not in XCTO_KINDS or not _is_final_2xx(r) or not r.body:
            continue
        st.seen("WEB-x-content-type-options", r.host)
        if not r.headers.has("x-content-type-options"):
            missing.setdefault(r.host, []).append(r)
    for host, rs in missing.items():
        entry = ctx.entry
        first = next((r for r in rs if r is entry), rs[0])
        kinds = sorted({_kind(r) for r in rs}, key=XCTO_KINDS.index)
        n = len({r.url for r in rs})
        st.emit("WEB-x-content-type-options", first, _ev(ctx, first, name="X-Content-Type-Options"),
                notes=[_note("xcto_kinds", responses=_count(n, _RESPONSES), kinds=", ".join(kinds))],
                group_value="")


def _referrer(st: _Run, docs) -> None:
    ctx = st.ctx
    doc_map = {id(r): (doc, conf) for r, doc, conf in docs}
    for r in st.value_responses():
        doc, _conf = doc_map.get(id(r), (None, ""))
        st.seen("WEB304", r.host)
        v = referrer_verdict(r, doc)
        if not v.present:
            continue
        if v.policy is None:
            st.emit("WEB304", r, _ev(ctx, r, name="Referrer-Policy", value=v.raw), severity="low",
                    notes=[_note("ref_none", value=_short(v.raw or '""'))], group_value="unrecognised")
        elif v.policy == "unsafe-url" or v.policy in REFERRER_LEAKY:
            st.emit("WEB304", r, _ev(ctx, r, where="header" if v.source == "header" else "body",
                                     name="Referrer-Policy" if v.source == "header" else "meta name=referrer",
                                     value=v.raw),
                    severity="medium" if v.policy == "unsafe-url" else "low",
                    notes=[_note("ref_effective", policy=v.policy, source=_SOURCE_NAMES[v.source])],
                    group_value=v.policy, params={"policy": v.policy})
    for r, doc, conf in docs:
        st.seen("WEB-referrer-policy", r.host)
        if not referrer_verdict(r, doc).present:
            st.emit("WEB-referrer-policy", r, _ev(ctx, r, name="Referrer-Policy"), confidence=conf or None)


def _permissions(st: _Run, docs) -> None:
    ctx = st.ctx
    doc_map = {id(r): (doc, conf) for r, doc, conf in docs}
    for r in st.value_responses():
        st.seen("WEB305", r.host)
        st.seen("WEB306", r.host)
        st.seen("WEB307", r.host)
        fields = r.headers.get_all("permissions-policy")
        pp = parse_permissions_policy(fields)
        if pp.present:
            for rule, sev, note, gv in pp_problems(pp):
                st.emit(rule, r, _ev(ctx, r, name="Permissions-Policy", value=", ".join(fields)), severity=sev,
                        notes=[note], group_value=gv)
        fp = r.headers.get_all("feature-policy")
        if fp:
            no_pp = not fields
            st.emit("WEB307", r, _ev(ctx, r, name="Feature-Policy", value=", ".join(fp)),
                    severity="low" if no_pp else "info", notes=[_note("fp_no_pp")] if no_pp else [],
                    group_value="without-pp" if no_pp else "with-pp")
        # WEB306 for <iframe allow> on documents
        doc, _conf = doc_map.get(id(r), (None, ""))
        if doc is not None:
            _iframe_delegation(st, r, doc, pp)
    for r, doc, conf in docs:
        st.seen("WEB-permissions-policy", r.host)
        if not r.headers.has("permissions-policy") and not r.headers.has("feature-policy"):
            st.emit("WEB-permissions-policy", r, _ev(ctx, r, name="Permissions-Policy"), confidence=conf or None)


def _iframe_delegation(st: _Run, r: Response, doc: ParsedHTML, pp: PermissionsPolicy) -> None:
    page_site = psl.site(r.host)
    for el in doc.find_all("iframe"):
        allow = el.get("allow")
        if not allow:
            continue
        src = doc.resolve(el.get("src")) if el.get("src") else ""
        try:
            src_host = normalise_host(urllib.parse.urlsplit(src).hostname or "") if src else ""
        except ValueError:
            src_host = ""
        src_origin = _origin_of(src) if src else None
        cross_site = bool(src_host) and psl.site(src_host) != page_site
        for feature, targets in parse_allow_attribute(allow):
            if feature not in POWERFUL_FEATURES:
                continue
            star = "*" in targets
            delegated = False
            if not star and cross_site:
                for t in targets or ["'src'"]:
                    tl = t.lower()
                    if tl == "'src'":
                        delegated = True
                    elif tl not in ("'self'", "'none'"):
                        o = _origin_of(t)
                        if o and psl.site(urllib.parse.urlsplit(o).hostname or "") != page_site:
                            delegated = True
            if not (star or delegated):
                continue
            al = pp.allowlist(feature)
            if al is not None and not al[0] and (src_origin is None or src_origin not in al[1]):
                continue                       # the page's own policy keeps the feature from the frame
            host_shown = src_host or "(no src)"
            key = "iframe_star" if star else "iframe_delegate"
            st.emit("WEB306", r, _ev(st.ctx, r, where="body", name="iframe allow", value=allow, offset=el.offset,
                                     excerpt=f'<iframe src="{src}" allow="{allow}">'),
                    notes=[_note(key, host=host_shown, feature=feature, value=_short(allow))],
                    group_value=f"iframe:{feature}:{host_shown}")


def _isolation(st: _Run, docs) -> None:
    ctx = st.ctx
    for r in st.value_responses():
        for rule, header, allowed in (("WEB308", "Cross-Origin-Opener-Policy", COOP_TOKENS),
                                      ("WEB309", "Cross-Origin-Embedder-Policy", COEP_TOKENS)):
            fields = r.headers.get_all(header)
            st.seen(rule, r.host)
            if not fields:
                continue
            ev = _ev(ctx, r, name=header, value=", ".join(fields))
            if not _secure_context(r):                             # G3
                st.emit(rule, r, ev, severity="info", notes=[_note("g3_ignored", header=header)], group_value="http")
                continue
            tok, problem = isolation_token(fields, allowed)
            if problem == "multi":
                st.emit(rule, r, ev, severity="low", group_value="multi",
                        notes=[_note("iso_multi", header=header, fields=_count(len(fields), _FIELDS))])
            elif problem == "invalid":
                st.emit(rule, r, ev, severity="low", group_value=fields[0].strip(),
                        notes=[_note("iso_invalid", header=header, value=_shown(fields[0]))])
        # WEB310 CORP: invalid or duplicated, on any response
        fields = r.headers.get_all("cross-origin-resource-policy")
        st.seen("WEB310", r.host)
        if fields:
            _v, problem = corp_value(fields)
            if problem:
                ev = _ev(ctx, r, name="Cross-Origin-Resource-Policy", value=", ".join(fields))
                note = (_note("iso_multi", header="Cross-Origin-Resource-Policy", fields=_count(len(fields), _FIELDS))
                        if problem == "multi" else _note("corp_invalid", value=_shown(fields[0])))
                st.emit("WEB310", r, ev, severity="low", notes=[note], group_value=problem + ":" + fields[0].strip())
        elif (_kind(r) == "api_json" and _is_final_2xx(r) and _session_or_sensitive(ctx, r)
              and not any(n.lower().startswith("access-control-allow-") for n in r.headers.names())):
            st.emit("WEB310", r, _ev(ctx, r, name="Cross-Origin-Resource-Policy"), severity="info",
                    confidence="tentative", notes=[_note("corp_missing")], group_value="missing")
    # WEB308 missing on https documents; WEB309 missing at paranoid
    for r, doc, conf in docs:
        if not _secure_context(r):
            continue
        st.seen("WEB308", r.host)
        fields = r.headers.get_all("cross-origin-opener-policy")
        tok, problem = isolation_token(fields, COOP_TOKENS)
        if problem == "missing" or tok == "unsafe-none":
            important = bool(r.roles & {"login", "authenticated"}) or (doc is not None and doc.has_password_field)
            st.emit("WEB308", r, _ev(ctx, r, name="Cross-Origin-Opener-Policy", value=", ".join(fields)),
                    severity="low" if important else "info", confidence=conf or None,
                    notes=[_note("coop_unsafe_none" if tok == "unsafe-none" else "coop_missing")],
                    group_value="unsafe-none" if tok == "unsafe-none" else "missing")
        if st.paranoid and not r.headers.has("cross-origin-embedder-policy"):
            st.seen("WEB309", r.host)
            st.emit("WEB309", r, _ev(ctx, r, name="Cross-Origin-Embedder-Policy"), severity="info",
                    notes=[_note("coep_missing")], group_value="missing", confidence=conf or None)


def _session_or_sensitive(ctx: ScanContext, r: Response) -> bool:
    return bool(_session_cookies(ctx, r)) or "sensitive" in r.flags or r.status == 401


def _legacy(st: _Run, docs) -> None:
    ctx = st.ctx
    for r in st.value_responses():
        st.seen("WEB311", r.host)
        st.seen("WEB312", r.host)
        st.seen("WEB316", r.host)
        xxss = r.headers.get_all("x-xss-protection")
        if xxss:
            joined = ", ".join(xxss)
            first = joined.strip().split(";", 1)[0].split(",", 1)[0].strip()
            if first != "0":
                st.emit("WEB311", r, _ev(ctx, r, name="X-XSS-Protection", value=joined),
                        notes=[_note("xxss", value=_shown(joined))], group_value=" ".join(joined.lower().split()))
        for header in ("Public-Key-Pins", "Public-Key-Pins-Report-Only", "Expect-CT"):
            vals = r.headers.get_all(header)
            if vals:
                st.emit("WEB312", r, _ev(ctx, r, name=header, value=", ".join(vals)),
                        notes=[_note("depr_header", header=header)], group_value=header.lower())
        pragma = r.headers.get_all("pragma")
        if pragma and not r.headers.has("cache-control"):
            st.emit("WEB312", r, _ev(ctx, r, name="Pragma", value=", ".join(pragma)),
                    notes=[_note("depr_pragma", value=_short(", ".join(pragma)))], group_value="pragma")
        xp = r.headers.get_all("x-permitted-cross-domain-policies")
        if xp and any(v.strip().lower() == "all" for v in _split_list(xp)):
            st.emit("WEB316", r, _ev(ctx, r, name="X-Permitted-Cross-Domain-Policies", value=", ".join(xp)),
                    group_value="all")
    if st.paranoid:
        for r, _doc, conf in docs:
            if not r.headers.has("x-permitted-cross-domain-policies"):
                st.emit("WEB316", r, _ev(ctx, r, name="X-Permitted-Cross-Domain-Policies"), severity="info",
                        notes=[_note("xpcdp_missing")], group_value="missing", confidence=conf or None)


def _content_type(st: _Run, docs) -> None:
    ctx = st.ctx
    for r in st.final_responses():
        if not _is_final_2xx(r) or not r.body or r.host in st.blocked_hosts:
            continue
        st.seen("WEB313", r.host)
        fields = r.headers.get_all("content-type")
        if not fields or not any(f.strip() for f in fields):
            st.emit("WEB313", r, _ev(ctx, r, name="Content-Type", value=", ".join(fields)), confidence="certain",
                    notes=[_note("ct_missing")], group_value="missing")
            continue
        essences = []
        for f in fields:
            e = f.split(";", 1)[0].strip().lower()
            if e and e not in essences:
                essences.append(e)
        if len(essences) > 1:
            st.emit("WEB313", r, _ev(ctx, r, name="Content-Type", value=" | ".join(fields)), confidence="certain",
                     notes=[_note("ct_multi", value=_short(" | ".join(fields)))], group_value="multi:" + ",".join(essences))
            continue
        if "ctype-mismatch" in r.flags:
            sniffed = next((f.split(":", 1)[1] for f in r.flags if f.startswith("magic:")), "?")
            st.emit("WEB313", r, _ev(ctx, r, name="Content-Type", value=fields[0]), confidence="firm",
                    notes=[_note("ct_mismatch", declared=_short(r.essence, 60), sniffed=_short(sniffed, 60))],
                    group_value=f"mismatch:{r.essence}>{sniffed}")
    # WEB314 on HTML documents
    for r, _doc, conf in docs:
        if r.essence not in ("text/html", "") or _opaque(r) or not r.body:
            continue
        st.seen("WEB314", r.host)
        if bom_encoding(r.body):
            continue
        raw_header = charset_param(r.content_type)
        header = _charset(raw_header)
        raw_meta = meta_charset(r.body)
        meta = _charset(raw_meta)
        ev_value = r.content_type or ""
        if header and meta and header != meta:
            st.emit("WEB314", r, _ev(ctx, r, name="Content-Type", value=ev_value),
                    notes=[_note("cs_conflict", header=_short(raw_header, 40), meta=_short(raw_meta, 40))],
                    group_value=f"conflict:{header}>{meta}", confidence=conf or None)
        elif not header and not meta:
            notes = [_note("cs_missing")]
            if raw_header:
                notes.append(_note("cs_unknown", value=_short(raw_header, 40)))
            st.emit("WEB314", r, _ev(ctx, r, name="Content-Type", value=ev_value), notes=notes,
                    group_value="missing", confidence=conf or None)


# base64 JSON (``eyJ``) or zlib-compressed JSON (``eJ``, Flask's leading ``.``), optionally with timestamp/signature parts
_SELF_CONTAINED = re.compile(r"^\.?(?:eyJ|eJ)[A-Za-z0-9_\-+/=]*(?:\.[A-Za-z0-9_\-+/=]*){0,3}$")
# keys whose value is random per issuance (Laravel's encryption IV, a JWT id, a CSRF secret kept in the session):
# two identical payloads carrying one of them were replayed, not re-derived
_UNIQUE_KEYS = frozenset({"iv", "jti", "nonce", "csrf_token", "_csrf_token", "sid", "session_id"})


def _payload_keys(v: str) -> set[str]:
    """Top-level JSON keys of a base64(-zlib) JSON cookie payload (JWT payload segment, Flask, Laravel); empty when it
    does not decode. Bounded: at most 8 KB of input and 64 KB decompressed."""
    segs = v.lstrip(".").split(".")
    seg = segs[1] if v.startswith("eyJ") and len(segs) >= 3 and segs[1].startswith("eyJ") else segs[0]
    seg = seg[:8192]
    try:
        raw = base64.urlsafe_b64decode(seg.replace("+", "-").replace("/", "_") + "=" * (-len(seg) % 4))
        if v.startswith(".") or seg.startswith("eJ"):
            raw = zlib.decompressobj().decompress(raw, 65536)
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, zlib.error, UnicodeDecodeError, RecursionError):
        return set()
    return {str(k).lower() for k in obj} if isinstance(obj, dict) else set()


def _self_contained_value(name: str, value: str) -> bool:
    """A client-side session payload rather than a server-side session id: a JWT, a Flask/itsdangerous or Express
    cookie-session value, or the ``.sig`` cookie signing one. Two anonymous visitors legitimately receive identical
    bytes when the payload is identical (no per-visitor id, one-second timestamps), so equal values prove nothing.
    Payloads that carry a per-issuance random field (Laravel's ``iv``, a JWT ``jti``) stay opaque: equal values
    there mean a cache replayed them."""
    if name.lower().endswith(".sig"):
        return True
    v = urllib.parse.unquote(value.strip().strip('"'))
    if not _SELF_CONTAINED.match(v):
        return False
    return not (_payload_keys(v) & _UNIQUE_KEYS)


def _caching(st: _Run, docs) -> None:
    ctx = st.ctx
    doc_map = {id(r): doc for r, doc, _conf in docs}
    pages = {id(p.response): p.doc for p in ctx.pages}
    # certain tier: one session value issued to two separate requests that sent no cookie (§WEB315)
    shared_session: dict[int, tuple[CookieFact, Response]] = {}
    by_value: dict[tuple[str, str], list[CookieFact]] = {}
    for c in ctx.cookies:
        if not c.is_session_class or c.deletion or c.ignored or len(c.value) < 8 or not st.own(c.response):
            continue
        if _self_contained_value(c.name, c.value):
            continue                         # identical payloads are expected; the cache-hit tiers still apply
        sent = ";".join(c.response.request_headers.get_all("cookie"))
        if re.search(r"(?:^|[;\s])" + re.escape(c.name) + r"=", sent):
            continue
        by_value.setdefault((c.name, c.value), []).append(c)
    for (_name, _value), facts in by_value.items():
        resps: list[Response] = []
        for f in facts:
            if all(f.response is not x for x in resps):
                resps.append(f.response)
        if len(resps) < 2:
            continue
        primary = next((x for x in resps if x is ctx.entry), resps[0])
        other = next(x for x in resps if x is not primary)
        shared_session[id(primary)] = (next(f for f in facts if f.response is primary), other)
        for x in resps:
            if x is not primary:
                shared_session.setdefault(id(x), (facts[0], primary))
    done: set[int] = set()
    for r in st.value_responses():
        k = _kind(r)
        if k in STATIC_KINDS or k == "soft404":
            continue
        doc = doc_map.get(id(r)) or pages.get(id(r))
        why = _sensitive_reasons(ctx, r, doc)
        st.seen("WEB315", r.host)
        if not why:
            continue
        cc_fields = r.headers.get_all("cache-control")
        cc = parse_cache_control(cc_fields)
        cc_shown = _short(", ".join(cc_fields)) or "(none)"
        why_note = _note("cache_why", why=("; ".join(_SENSITIVE_WHY[w][0] for w in why),
                                           "؛ ".join(_SENSITIVE_WHY[w][1] for w in why)))
        ev = _ev(ctx, r, name="Cache-Control", value=", ".join(cc_fields))
        sess = _session_cookies(ctx, r)
        if id(r) in shared_session:
            fact, other = shared_session[id(r)]
            if id(r) in done or id(other) in done:
                continue                     # the pair is reported once, on the entry response
            done.add(id(r))
            ev = _ev(ctx, r, where="cookie", name=fact.name, value=fact.redacted())
            st.emit("WEB315", r, ev, severity="high", confidence="certain", group_value="session-shared",
                    notes=[_note("cache_same_session", cookie=fact.name, first=_short(r.url, 80),
                                 second=_short(other.url, 80)), why_note],
                    params={"cookie": fact.name})
            continue
        hit = cache_hit(r)
        if shared_cacheable(cc):
            key = "cache_shared_cookie" if r.headers.has("set-cookie") else "cache_shared"
            notes = [_note(key, value=cc_shown), why_note]
            # ``public`` + ``Vary: Cookie`` (and nothing else sensitive) is the documented way to let a CDN cache the
            # anonymous variant: caches that honour Vary key it per cookie, so this is only low (CDNs that ignore
            # Vary would still share it)
            vary_only = why == ["vary"]
            if vary_only:
                notes.append(_note("cache_vary_keyed"))
            st.emit("WEB315", r, ev, severity="low" if vary_only else "medium", confidence="firm",
                    group_value="shared-vary" if vary_only else "shared", notes=notes)
        elif hit and sess:
            st.emit("WEB315", r, ev, severity="medium", confidence="firm", group_value="cache-hit",
                    notes=[_note("cache_hit", value=hit, cookie=sess[0].name), why_note],
                    params={"cookie": sess[0].name})
        elif why == ["vary"] and not (r.request_headers.has("cookie") or r.request_headers.has("authorization")):
            # only the private (browser) cache is left, and the request carried no Cookie/Authorization: the stored copy
            # is the anonymous variant (Django's SessionMiddleware adds Vary: Cookie to every page that reads the session)
            continue
        elif "no-store" not in cc and _storable(r, cc):
            st.emit("WEB315", r, ev, severity="low", confidence="firm", group_value="no-store-missing",
                    notes=[_note("cache_no_store", value=cc_shown), why_note])


def _clear_site_data(st: _Run) -> None:
    ctx = st.ctx
    for r in st.value_responses():
        st.seen("WEB317", r.host)
        fields = r.headers.get_all("clear-site-data")
        if not fields:
            continue
        joined = ", ".join(fields)
        ev = _ev(ctx, r, name="Clear-Site-Data", value=joined)
        if not _secure_context(r):
            st.emit("WEB317", r, ev, notes=[_note("g3_ignored", header="Clear-Site-Data")], group_value="http")
            continue
        types, valid = clear_site_data_values(fields)
        if not valid:
            st.emit("WEB317", r, ev, notes=[_note("csd_unquoted", value=_shown(joined))], group_value="unquoted")
            continue
        broad = [t for t in types if t in ("*", "cookies")]
        parts = urllib.parse.urlsplit(r.url)
        path, query = parts.path, parts.query     # /wp-login.php?action=logout
        if broad and r.method == "GET" and not _LOGOUT_PATH.search(path) and not _LOGOUT_PATH.search(query):
            st.emit("WEB317", r, ev, notes=[_note("csd_broad", value=", ".join(f'"{t}"' for t in broad))],
                    group_value="broad:" + ",".join(broad))


_DROP_HEADERS = (("Content-Security-Policy", ("content-security-policy",)),
                 ("X-Frame-Options / frame-ancestors", ("x-frame-options",)),
                 ("X-Content-Type-Options", ("x-content-type-options",)),
                 ("Strict-Transport-Security", ("strict-transport-security",)))


def _has_security_header(ctx: ScanContext, r: Response, label: str, names: tuple[str, ...]) -> bool:
    if any(r.headers.has(n) for n in names):
        return True
    if label.startswith("X-Frame-Options"):
        return _frame_ancestors(ctx, r)[0]
    return False


def _error_pages(st: _Run, docs) -> None:
    ctx = st.ctx
    by_host: dict[str, list[Response]] = {}
    for r, _doc, conf in docs:
        if not conf:
            by_host.setdefault(r.host, []).append(r)
    errors: dict[str, list[Response]] = {}
    for r in st.final_responses():
        k = _kind(r)
        if (k == "error_page" and r.status is not None and r.status >= 400 and r.essence == "text/html"
                and r.host in by_host and r.host not in st.blocked_hosts):
            errors.setdefault(r.host, []).append(r)
    for host, good in by_host.items():
        st.seen("WEB318", host)
        errs = errors.get(host)
        if not errs:
            continue
        missing: list[str] = []
        statuses: set[int] = set()
        first: Response | None = None
        for label, names in _DROP_HEADERS:
            if label.startswith("Strict") and not all(g.is_https for g in good):
                continue
            if not all(_has_security_header(ctx, g, label, names) for g in good):
                continue
            for e in errs:
                if label.startswith("Strict") and not e.is_https:
                    continue
                if not _has_security_header(ctx, e, label, names):
                    if label not in missing:
                        missing.append(label)
                    statuses.add(e.status or 0)
                    first = first or e
        if missing and first is not None:
            st.emit("WEB318", first, _ev(ctx, first, name=missing[0]),
                    notes=[_note("err_dropped", statuses=", ".join(str(s) for s in sorted(statuses)),
                                 headers=", ".join(missing))],
                    group_value=",".join(missing))


def i18n_catalog() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """``(CATALOG, PATTERNS)`` for cat_web2: fixed Arabic notes → English, and regex patterns for the templated ones."""
    catalog: dict[str, str] = {}
    patterns: list[tuple[str, str]] = []
    for en, ar in STR.values():
        if "{" not in ar:
            catalog[ar] = en
            continue
        names: list[str] = []

        def to_rx(text: str, names_: list[str]) -> str:
            out, pos = [], 0
            for m in _PLACEHOLDER.finditer(text):
                out.append(re.escape(text[pos:m.start()]))
                if m.group(1) in names_:
                    out.append(f"(?P={m.group(1)})")
                else:
                    out.append(f"(?P<{m.group(1)}>.+?)")
                    names_.append(m.group(1))
                pos = m.end()
            out.append(re.escape(text[pos:]))
            return "^" + "".join(out) + "$"
        rx = to_rx(ar, names)
        repl = _PLACEHOLDER.sub(lambda m: f"\\g<{m.group(1)}>", en)
        patterns.append((rx, repl))
    for en, ar in _SENSITIVE_WHY.values():
        catalog[ar] = en
    for en, ar in _SOURCE_NAMES.values():
        catalog.setdefault(ar, en)
    return catalog, patterns


__all__ = ["CHECKS", "run", "STR", "XfoVerdict", "xfo_verdict", "ReferrerVerdict", "referrer_verdict",
           "PermissionsPolicy", "parse_permissions_policy", "pp_problems", "parse_allow_attribute", "typo_of",
           "isolation_token", "corp_value", "parse_cache_control", "shared_cacheable", "cache_hit",
           "clear_site_data_values", "observatory_slugs", "observatory_auto", "header_inventory", "OBS_TESTS", "PP_FEATURES",
           "POWERFUL_FEATURES", "REFERRER_POLICIES", "i18n_catalog"]
