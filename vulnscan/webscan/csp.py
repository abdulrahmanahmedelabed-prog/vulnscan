"""Content-Security-Policy parser, evaluator and checks (spec §2.2), WP4.

Rules: WEB-content-security-policy, WEB040–WEB043, WEB200–WEB219. The module also writes the MDN Observatory v6 slug of
the ``content-security-policy`` test into ``ctx.observatory`` (``mdn-http-observatory`` 1.7.2 reproduced bit for bit,
quirks included: duplicate directives make the header invalid, multiple policies are merged by its path-prefix
"intersection", ``'strict-dynamic'`` without a nonce is invalid).

Semantics follow CSP Level 3 (the browser algorithms), not Observatory:

* **Sources.** Every ``Content-Security-Policy`` field (split on ``,``), every ``<meta http-equiv>`` policy that is a
  child of ``<head>`` (one policy each; ``frame-ancestors``, ``report-uri`` and ``sandbox`` dropped → WEB207), every
  ``Content-Security-Policy-Report-Only`` field (analysed separately, never enforced), the obsolete ``X-*`` headers.
* **Parsing.** Split on ``;``; a directive token with non-ASCII characters is skipped (WEB201); names are lower-cased;
  the first occurrence wins (WEB202). Values split on ASCII whitespace; keywords, schemes and hosts are case-insensitive,
  nonce and hash values are not. Grammar problems → WEB201 (:data:`ERROR_CODES`).
* **Fallback** (CSP3 §6.8.3): ``script-src-elem/-attr`` → ``script-src`` → ``default-src``; the same for styles;
  ``worker-src`` → ``child-src`` → ``script-src`` → ``default-src``; ``frame-src`` → ``child-src`` → ``default-src``;
  other fetch directives → ``default-src``; no fallback for ``base-uri``, ``form-action``, ``frame-ancestors``, …
* **Neutralisation.** A list with a valid nonce or hash ignores ``'unsafe-inline'``; a script list with
  ``'strict-dynamic'`` ignores host and scheme sources, ``'self'`` and ``'unsafe-inline'`` (CSP3; without a nonce or
  hash that blocks every script, which WEB203 reports).
* **Multiple enforced policies** must all allow a resource, so a weakness is reported only when *every* enforced policy
  is weak for that directive (intersection), and at least one of them states the weakness explicitly.
* **Non-script policy.** When no enforced policy restricts scripts (no ``script-src``, ``script-src-elem`` or
  ``default-src``), one WEB042 (variant ``non_script``) replaces WEB040, WEB043, WEB204, WEB209 and WEB218.

Gates (§2.0): "missing" (WEB-content-security-policy, WEB200) judges G1 documents (final, 2xx, kind ``document``; at
``paranoid`` HTML error pages too, at the confidence the registry allows). Value rules run on the documents that carry
a policy. WEB201/WEB202 (syntax) run on every fetched response of the site, once per distinct policy and host. A
WAF-challenged entry makes the host's document checks ``inconclusive`` (G4).

Stage 1 (:func:`parse_all`) is pure and fills ``ctx.csp``; headers.py and content.py read those facts. Nothing here
touches the network. Policies can be large and hostile: parsing is linear, every list is capped and strings that reach
notes go through ``strip_controls``.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Iterable

from . import htmlparse, psl, sfv
from .rules import RULES, checks_for_module
from .types import (
    CspFacts,
    CspPolicy,
    Evidence,
    Issue,
    Page,
    ParsedHTML,
    Response,
    ScanContext,
    strip_controls,
    url_origin,
)

CHECKS: tuple[str, ...] = checks_for_module("csp")

# ----------------------------------------------------------------------------------------------- vocabulary

FETCH_DIRECTIVES = ("child-src", "connect-src", "default-src", "fenced-frame-src", "font-src", "frame-src", "img-src",
                    "manifest-src", "media-src", "object-src", "script-src", "script-src-attr", "script-src-elem",
                    "style-src", "style-src-attr", "style-src-elem", "worker-src")
OTHER_DIRECTIVES = ("base-uri", "form-action", "frame-ancestors", "report-to", "report-uri", "require-trusted-types-for",
                    "sandbox", "treat-as-public-address", "trusted-types", "upgrade-insecure-requests", "webrtc")
DEPRECATED_DIRECTIVES = ("block-all-mixed-content", "disown-opener", "navigate-to", "plugin-types", "prefetch-src",
                         "referrer", "reflected-xss", "require-sri-for")
KNOWN_DIRECTIVES = frozenset(FETCH_DIRECTIVES + OTHER_DIRECTIVES + DEPRECATED_DIRECTIVES)
SOURCE_LIST_DIRECTIVES = frozenset(FETCH_DIRECTIVES + ("base-uri", "form-action", "frame-ancestors", "prefetch-src",
                                                       "navigate-to"))
META_IGNORED = ("frame-ancestors", "report-uri", "sandbox")
KEYWORDS = frozenset({"'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'", "'unsafe-hashes'",
                      "'report-sample'", "'unsafe-allow-redirects'", "'wasm-unsafe-eval'", "'trusted-types-eval'",
                      "'report-sha256'", "'report-sha384'", "'report-sha512'", "'unsafe-webtransport-hashes'",
                      "'inline-speculation-rules'"})
_BARE_KEYWORDS = frozenset(k.strip("'") for k in KEYWORDS)
SANDBOX_TOKENS = frozenset({"allow-downloads", "allow-forms", "allow-modals", "allow-orientation-lock",
                            "allow-pointer-lock", "allow-popups", "allow-popups-to-escape-sandbox", "allow-presentation",
                            "allow-same-origin", "allow-scripts", "allow-storage-access-by-user-activation",
                            "allow-top-navigation", "allow-top-navigation-by-user-activation",
                            "allow-top-navigation-to-custom-protocols"})
HASH_BYTES = {"sha256": 32, "sha384": 48, "sha512": 64}

FALLBACK: dict[str, tuple[str, ...]] = {
    "script-src-elem": ("script-src-elem", "script-src", "default-src"),
    "script-src-attr": ("script-src-attr", "script-src", "default-src"),
    "script-src": ("script-src", "default-src"),
    "style-src-elem": ("style-src-elem", "style-src", "default-src"),
    "style-src-attr": ("style-src-attr", "style-src", "default-src"),
    "style-src": ("style-src", "default-src"),
    "worker-src": ("worker-src", "child-src", "script-src", "default-src"),
    "frame-src": ("frame-src", "child-src", "default-src"),
    "fenced-frame-src": ("fenced-frame-src", "frame-src", "child-src", "default-src"),
    "child-src": ("child-src", "default-src"),
    "connect-src": ("connect-src", "default-src"),
    "font-src": ("font-src", "default-src"),
    "img-src": ("img-src", "default-src"),
    "manifest-src": ("manifest-src", "default-src"),
    "media-src": ("media-src", "default-src"),
    "object-src": ("object-src", "default-src"),
    "default-src": ("default-src",),
}
SCRIPT_LISTS = ("script-src-elem", "script-src-attr", "script-src", "worker-src")
# WEB211: the resource types a browser loads, by effective directive; img/media are "passive" (low)
ACTIVE_TYPES = ("script-src-elem", "style-src-elem", "frame-src", "connect-src", "object-src", "worker-src", "font-src",
                "manifest-src")
PASSIVE_TYPES = ("img-src", "media-src")
# NEEDS_EVAL: JSONP hosts whose CSP Evaluator bypass works only with 'unsafe-eval' (upstream "needsEval"; the frozen
# csp-bypass.json schema has no key for it, see tools/webdata/csp_bypass.py)
NEEDS_EVAL = ("google-analytics.com", "googletagmanager.com", "ssl.google-analytics.com", "www.google-analytics.com",
              "www.googleadservices.com", "www.googletagmanager.com")

_ASCII_WS = " \t\n\f\r"
_WS_SPLIT = re.compile(r"[ \t\n\f\r]+")
_NAME_OK = re.compile(r"^[a-z0-9-]+$")
_SCHEME_SRC = re.compile(r"^([a-z][a-z0-9+.\-]*):$", re.I)
_HOST_SRC = re.compile(r"^(?:([a-z][a-z0-9+.\-]*)://)?(\*|(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*)(?::([0-9]+|\*))?"
                       r"(/[^;,\s]*)?$", re.I)
_B64VALUE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")
_NONCE = re.compile(r"^'nonce-(.*)'$", re.I | re.S)
_HASH = re.compile(r"^'(sha256|sha384|sha512)-(.*)'$", re.I | re.S)
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_MAX_ERRORS = 40
_MAX_TOKENS = 2000         # per directive: hostile policies cannot make evaluation quadratic
_RAW_CAP = 2000

# ----------------------------------------------------------------------------------------------- user-facing text

STR: dict[str, tuple[str, str]] = {
    # syntax (WEB201)
    "err_unknown": ("Unknown directive {directive}; browsers ignore it.", "التوجيه {directive} غير معروف، فيتجاهله المتصفح."),
    "err_unknown_typo": ("Unknown directive {directive} (did you mean {suggest}?); browsers ignore it.",
                         "التوجيه {directive} غير معروف (هل تقصد {suggest}؟)، فيتجاهله المتصفح."),
    "err_colon": ("Directive names do not end with a colon: {directive}.",
                  "أسماء التوجيهات لا تنتهي بنقطتين رأسيتين: {directive}."),
    "err_semicolon": ("{value} inside {directive} looks like a directive name: a ';' is probably missing.",
                      "القيمة {value} داخل {directive} تبدو اسم توجيه، والأرجح أن الفاصلة المنقوطة ';' ناقصة."),
    "err_unquoted": ("{value} in {directive} must be written in single quotes ('{value}').",
                     "يجب كتابة {value} في {directive} بين علامتي اقتباس مفردتين ('{value}')."),
    "err_quoted_host": ("{value} in {directive}: hosts and schemes must not be quoted.",
                        "القيمة {value} في {directive}: لا توضع المضيفات والبروتوكولات بين علامتي اقتباس."),
    "err_none_combined": ("'none' in {directive} is combined with other sources, so it has no effect.",
                          "القيمة 'none' في {directive} مقترنة بمصادر أخرى، فلا أثر لها."),
    "err_bad_hash": ("{value} in {directive} is not a valid {alg} hash (it must decode to {size}).",
                     "القيمة {value} في {directive} ليست قيمة {alg} صالحة (يجب أن تُفك إلى {size})."),
    "err_bad_nonce": ("{value} in {directive} is not valid base64, so browsers ignore this nonce.",
                      "القيمة {value} في {directive} ليست base64 صالحة، فيتجاهل المتصفح هذا الـ nonce."),
    "err_bad_keyword": ("{value} in {directive} is not a CSP keyword.", "القيمة {value} في {directive} ليست كلمة مفتاحية في CSP."),
    "err_invalid_source": ("{value} in {directive} is not a valid source expression; browsers ignore it.",
                           "القيمة {value} في {directive} ليست تعبير مصدر صالحًا، فيتجاهلها المتصفح."),
    "err_invalid_value": ("{value} is not a valid value for {directive}.", "القيمة {value} غير صالحة للتوجيه {directive}."),
    "err_ip": ("{value} in {directive} is an IP address; it matches only that literal address (informational).",
               "القيمة {value} في {directive} عنوان IP، ولا تطابق إلا هذا العنوان الحرفي (معلومة فقط)."),
    "err_non_ascii": ("A directive with non-ASCII characters is ignored by browsers: {value}.",
                      "يتجاهل المتصفح التوجيه الذي يحتوي محارف غير ASCII: {value}."),
    "err_obs_fold": ("The {header} header was folded over several lines (obsolete line folding); it was read as one "
                     "line, but some clients may not.",
                     "طُويت الترويسة {header} على عدة أسطر (طيّ أسطر متقادم)؛ فقُرئت سطرًا واحدًا، لكن بعض العملاء قد لا يقرؤها كذلك."),
    "err_ineffective": ("Because of this error the policy no longer restricts scripts.",
                        "بسبب هذا الخطأ لم تعد السياسة تقيّد السكربتات."),
    # WEB202
    "duplicate": ("{directive} appears again with {value}; browsers use only the first occurrence.",
                  "يتكرر {directive} بالقيمة {value}؛ والمتصفح يستخدم أول ظهور فقط."),
    # value rules
    "inline_where": ("'unsafe-inline' is effective in {directive}.", "القيمة 'unsafe-inline' فعّالة في {directive}."),
    "inline_kept": ("'unsafe-inline' is ignored because the list has a nonce, a hash or 'strict-dynamic'; it is kept only "
                    "for old browsers.",
                    "يتجاهل المتصفح 'unsafe-inline' لأن القائمة تحتوي nonce أو hash أو 'strict-dynamic'، وهو باقٍ للمتصفحات القديمة فقط."),
    "eval_where": ("{value} is allowed by {directive}.", "القيمة {value} مسموحة في {directive}."),
    "any_source": ("{directive} allows {value}.", "التوجيه {directive} يسمح بـ {value}."),
    "missing_directive": ("The policy has no {directive} and nothing it falls back to, so it is unrestricted.",
                          "لا تحتوي السياسة على {directive} ولا على توجيه بديل له، فهو غير مقيَّد."),
    "non_script": ("This policy restricts neither script-src nor default-src (it has: {directives}).",
                   "هذه السياسة لا تقيّد script-src ولا default-src (تحتوي: {directives})."),
    "strict_dynamic_alone": ("'strict-dynamic' in {directive} without a nonce or hash blocks every script in current "
                             "browsers; older ones fall back to the host list.",
                             "وجود 'strict-dynamic' في {directive} بلا nonce أو hash يحجب كل السكربتات في المتصفحات الحالية، "
                             "وتعود المتصفحات الأقدم إلى قائمة المضيفين."),
    "base_nonce": ("The policy relies on nonces, so an injected <base href> can re-target relative script URLs.",
                   "تعتمد السياسة على nonce، فيمكن لوسم <base href> محقون أن يحوّل روابط السكربتات النسبية إلى مضيف آخر."),
    "base_allowlist": ("Hardening only: script-src does not allow the attacker's host, so a re-based script URL is "
                       "still blocked.",
                       "تحصين فقط: script-src لا يسمح بمضيف المهاجم، فيبقى رابط السكربت المعاد توجيهه محجوبًا."),
    "form_password": ("The page has a password form; an injected form could send credentials to another site.",
                      "في الصفحة نموذج كلمة مرور؛ ويمكن لنموذج محقون أن يرسل بيانات الدخول إلى موقع آخر."),
    "form_other": ("The page has forms but no password field.", "في الصفحة نماذج لكن بلا حقل كلمة مرور."),
    "fa_any": ("frame-ancestors {value} lets any site frame the page, and it overrides X-Frame-Options in browsers.",
               "القيمة frame-ancestors {value} تسمح لأي موقع بتضمين الصفحة، وتتقدّم على X-Frame-Options في المتصفح."),
    "meta_dropped": ("{directives} in the <meta> policy is ignored by browsers.",
                     "يتجاهل المتصفح {directives} داخل سياسة وسم <meta>."),
    "meta_fa_only": ("frame-ancestors in <meta> was the page's only clickjacking defence (no X-Frame-Options and no "
                     "header frame-ancestors).",
                     "كان frame-ancestors داخل <meta> الحماية الوحيدة للصفحة من Clickjacking (لا X-Frame-Options ولا "
                     "frame-ancestors في الترويسة)."),
    "meta_late": ("The CSP <meta> tag comes after <{element}> (line {line}); content before the tag is not governed by "
                  "the policy.",
                  "وسم CSP يأتي بعد <{element}> (السطر {line})؛ والمحتوى الذي يسبق الوسم لا تحكمه السياسة."),
    "meta_in_body": ("A CSP <meta> tag outside <head> is ignored by browsers.",
                     "يتجاهل المتصفح وسم CSP الموجود خارج <head>."),
    "bypass_jsonp": ("{host} hosts JSONP endpoints (e.g. {url}) that let an attacker run script under this policy.",
                     "المضيف {host} يقدّم نقاط JSONP (مثل {url}) تتيح للمهاجم تشغيل سكربت رغم هذه السياسة."),
    "bypass_angular": ("{host} hosts AngularJS (e.g. {url}), whose templates let an attacker run script under this "
                       "policy.",
                       "المضيف {host} يقدّم AngularJS (مثل {url})، وقوالبها تتيح للمهاجم تشغيل سكربت رغم هذه السياسة."),
    "bypass_needs_eval": ("This bypass needs eval, which the policy does not allow (low).",
                          "هذا التجاوز يحتاج eval، والسياسة لا تسمح به (منخفض)."),
    "unsafe_hashes": ("{directive} contains 'unsafe-hashes'.", "التوجيه {directive} يحتوي 'unsafe-hashes'."),
    "insecure_source": ("{directive} allows the insecure source {value} on an HTTPS page.",
                        "التوجيه {directive} يسمح بالمصدر غير الآمن {value} في صفحة HTTPS."),
    "uir_mitigates": ("upgrade-insecure-requests upgrades these requests to HTTPS, which limits the risk.",
                      "التوجيه upgrade-insecure-requests يرقّي هذه الطلبات إلى HTTPS، مما يحدّ من الخطر."),
    "static_nonce": ("The nonce {nonce} appeared in two separate responses ({first} and {second}).",
                     "ظهرت قيمة nonce نفسها {nonce} في استجابتين منفصلتين ({first} و{second})."),
    "cached_nonce": ("The page carries a nonce and shared caches may store it ({cache}), so many users get the same "
                     "nonce.",
                     "الصفحة تحمل nonce ويمكن للذاكرات المؤقتة المشتركة تخزينها ({cache})، فيحصل مستخدمون كثيرون على nonce نفسه."),
    "short_nonce": ("The nonce {nonce} has only {chars}.", "قيمة nonce {nonce} طولها {chars} فقط."),
    "weak_nonce": ("The nonce {nonce} decodes to only {size} (fewer than 16).",
                   "قيمة nonce {nonce} تُفك إلى {size} فقط (أقل من 16)."),
    "no_reporting": ("The policy has neither report-to nor report-uri.", "لا تحتوي السياسة على report-to ولا report-uri."),
    "report_group_missing": ("report-to names the group {group}, which no Reporting-Endpoints or Report-To header "
                             "defines.",
                             "يشير report-to إلى المجموعة {group}، ولا تعرّفها ترويسة Reporting-Endpoints ولا Report-To."),
    "deprecated": ("Deprecated directive: {directive}.", "توجيه متقادم: {directive}."),
    "legacy_header": ("{header} is an obsolete prefixed header that current browsers ignore.",
                      "الترويسة {header} قديمة ببادئة ويتجاهلها المتصفح الحديث."),
    "legacy_no_standard": ("There is no standard Content-Security-Policy, so current browsers enforce no CSP here.",
                           "لا توجد ترويسة Content-Security-Policy القياسية، فلا يطبّق المتصفح الحديث أي CSP هنا."),
    "allowlist_only": ("{directive} allows {value} without nonces or hashes.", "التوجيه {directive} يسمح بـ {value} بلا nonce أو hash."),
    "no_trusted_types": ("The policy has no require-trusted-types-for 'script'.",
                         "لا تحتوي السياسة على require-trusted-types-for 'script'."),
    "ro_weak": ("If enforced, this report-only policy would still have: {rules}.",
                "لو طُبِّقت سياسة التقرير هذه لبقيت فيها: {rules}."),
    "ro_clean": ("The report-only policy has none of the weaknesses Kashif checks.",
                 "سياسة التقرير لا تحتوي أيًّا من نقاط الضعف التي يفحصها كاشف."),
    "static_doc": ("The page has no scripts, forms or event handlers, so the risk is lower.",
                   "الصفحة بلا سكربتات ولا نماذج ولا معالجات أحداث، فالخطر أقل."),
    "ceiling": ("Capped at {severity}: a weak policy is never rated worse than no policy on the same page (a missing CSP "
                "is {severity} here because the page has no scripts, forms or event handlers).",
                "خُفّضت الخطورة إلى {severity}: لا تُقيَّم السياسة الضعيفة أسوأ من غياب السياسة على الصفحة نفسها (غياب "
                "CSP هنا خطورته {severity} لأن الصفحة بلا سكربتات ولا نماذج ولا معالجات أحداث)."),
    "object_self": ("object-src 'self' allows plugins from this origin; object-src 'none' is safer.",
                    "القيمة object-src 'self' تسمح بالإضافات من هذا الأصل؛ والقيمة object-src 'none' أكثر أمانًا."),
    "flash_bypass": ("{host} hosts Flash files that could bypass object-src (Flash no longer runs in current browsers).",
                     "المضيف {host} يقدّم ملفات Flash قد تتجاوز object-src (لم يعد Flash يعمل في المتصفحات الحالية)."),
}

_CHARS = ("{n} character", "{n} characters", ("حرف واحد", "حرفان", "{n} أحرف", "{n} حرفًا", "{n} حرف"))
_BYTES = ("{n} byte", "{n} bytes", ("بايت واحد", "بايتان", "{n} بايتات", "{n} بايتًا", "{n} بايت"))
_PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")
_PARANOID = "paranoid"
HTML_ESSENCES = frozenset({"text/html", "application/xhtml+xml"})
SKIP_KINDS = frozenset({"waf_challenge", "rate_limited", "error"})


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
    v = " ".join(str(value).split())
    return v if len(v) <= limit else v[: limit - 1] + "…"


# ----------------------------------------------------------------------------------------------- source expressions

@dataclass(frozen=True)
class Source:
    """One classified source expression. ``kind``: keyword | nonce | hash | scheme | host | invalid."""
    raw: str
    kind: str
    norm: str                 # normalised token (keywords/schemes/hosts lower-case; nonce/hash values kept)
    scheme: str = ""          # scheme-source / host-source scheme ("" when absent)
    host: str = ""
    port: str = ""
    path: str = ""
    error: str = ""           # error code for invalid / suspicious expressions
    detail: str = ""          # e.g. the hash algorithm

    @property
    def valid(self) -> bool:
        return self.kind != "invalid"


def _b64_bytes(value: str) -> bytes | None:
    """Decode a CSP base64-value (base64 or base64url, padding optional); None when it does not decode."""
    if not _B64VALUE.match(value):
        return None
    v = value.rstrip("=").replace("-", "+").replace("_", "/")
    try:
        return base64.b64decode(v + "=" * (-len(v) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


@lru_cache(maxsize=4096)
def classify_source(token: str) -> Source:
    """Classify one source expression against the CSP3 grammar (§2.3.1)."""
    low = token.lower()
    if token.startswith("'"):
        if low in KEYWORDS:
            return Source(token, "keyword", low)
        m = _NONCE.match(token)
        if m:
            value = m.group(1)
            if _B64VALUE.match(value):
                return Source(token, "nonce", "'nonce-" + value + "'", detail=value)
            return Source(token, "invalid", token, error="bad_nonce", detail=value)
        m = _HASH.match(token)
        if m:
            alg, value = m.group(1).lower(), m.group(2)
            raw = _b64_bytes(value)
            if raw is not None and len(raw) == HASH_BYTES[alg]:
                return Source(token, "hash", f"'{alg}-{value}'", detail=alg)
            return Source(token, "invalid", token, error="bad_hash", detail=alg)
        inner = token.strip("'")
        if inner and ("." in inner or "://" in inner or inner.endswith(":")) and \
                (_HOST_SRC.match(inner) or _SCHEME_SRC.match(inner)):
            return Source(token, "invalid", token, error="quoted_host")
        return Source(token, "invalid", token, error="bad_keyword")
    if low in _BARE_KEYWORDS or low.startswith(("nonce-", "sha256-", "sha384-", "sha512-")):
        # a valid host-source grammatically ("self" is a host name), but certainly a mistake
        m = _HOST_SRC.match(token)
        if m:
            return Source(token, "host", low, host=low, error="unquoted")
        return Source(token, "invalid", token, error="unquoted")
    m = _SCHEME_SRC.match(token)
    if m:
        return Source(token, "scheme", low, scheme=low[:-1])
    if token.startswith("[") or (token.split("://", 1)[-1].startswith("[")):
        return Source(token, "invalid", token, error="ip")
    m = _HOST_SRC.match(token)
    if m:
        scheme = (m.group(1) or "").lower()
        host = m.group(2).lower()
        port = m.group(3) or ""
        path = m.group(4) or ""
        if port and port != "*":
            digits = port.lstrip("0") or "0"
            if len(digits) > 5 or int(digits) > 65535:     # never int() a 5000-digit port (3.11+ raises ValueError)
                return Source(token, "invalid", token, error="invalid_source")
            port = digits
        norm = (f"{scheme}://" if scheme else "") + host + (f":{port}" if port else "") + path
        err = "ip" if _IPV4.match(host) else ""
        return Source(token, "host", norm, scheme=scheme, host=host, port=port, path=path, error=err)
    return Source(token, "invalid", token, error="invalid_source")


def _sources(values: Iterable[str]) -> list[Source]:
    return [classify_source(v) for v in values]


# ----------------------------------------------------------------------------------------------- parsing

def _edit_distance(a: str, b: str, limit: int = 3) -> int:
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > limit:
            return limit + 1
        prev = cur
    return prev[-1]


def typo_of(name: str) -> str | None:
    """The known (non-deprecated) directive within edit distance 2 of ``name``, if any."""
    best, best_d = None, 3
    for known in FETCH_DIRECTIVES + OTHER_DIRECTIVES:
        d = _edit_distance(name, known, 2)
        if d < best_d:
            best, best_d = known, d
    return best if best_d <= 2 else None


def _err(code: str, directive: str, value: str = "", severity: str = "low", **extra) -> dict:
    e = {"code": code, "directive": directive, "value": value, "severity": severity}
    e.update(extra)
    return e


def parse_policy(raw: str, origin: str = "header", element: int | None = None) -> CspPolicy:
    """Parse one serialized policy (CSP3 §2.2.1). ``origin``: header | meta | report-only."""
    pol = CspPolicy(raw=raw, origin=origin, element=element)
    errors = pol.errors

    def add(e: dict) -> None:
        if len(errors) < _MAX_ERRORS:
            errors.append(e)

    for token in raw.split(";"):
        token = token.strip(_ASCII_WS)
        if not token:
            continue
        if not token.isascii():
            # the whole directive is ignored (curly quotes pasted from a word processor are the usual cause); keep
            # its name so a lost script-src/default-src is rated medium like any other error that disables it
            lost = _WS_SPLIT.split(token, 1)[0].lower()
            add(_err("non_ascii", "", _short(token, 80), swallowed=lost if lost.isascii() else ""))
            continue
        parts = _WS_SPLIT.split(token)
        name = parts[0].lower()
        values = parts[1:][:_MAX_TOKENS]
        if name in pol.directives or name in pol.dropped:
            if len(pol.duplicates) < _MAX_ERRORS:
                pol.duplicates.append((name, " ".join(values)))
            continue
        if len(errors) < _MAX_ERRORS:
            _check_directive(name, values, add)
        if origin == "meta" and name in META_IGNORED:
            pol.dropped.append(name)
            continue
        pol.directives[name] = [_normalise_value(name, v) for v in values]
    _ineffective_scripts(pol)
    return pol


def _normalise_value(directive: str, value: str) -> str:
    if directive in SOURCE_LIST_DIRECTIVES:
        return classify_source(value).norm
    return value


def _check_directive(name: str, values: list[str], add) -> None:
    if name not in KNOWN_DIRECTIVES:
        if name.endswith(":") and name[:-1] in KNOWN_DIRECTIVES:
            add(_err("colon", name, suggest=name[:-1]))
        else:
            sug = typo_of(name) if _NAME_OK.match(name) else None
            add(_err("unknown_typo" if sug else "unknown", name, suggest=sug or ""))
        return
    for v in values:
        if v.lower() in KNOWN_DIRECTIVES and v.lower() != name:
            add(_err("semicolon", name, v, swallowed=v.lower()))
    if name in SOURCE_LIST_DIRECTIVES:
        srcs = _sources(values)
        if any(s.norm == "'none'" for s in srcs) and len(values) > 1:
            add(_err("none_combined", name))
        for s in srcs:
            if s.kind == "invalid" or s.error:
                if s.raw.lower() in KNOWN_DIRECTIVES:
                    continue   # already reported as a missing ';'
                code = s.error or "invalid_source"
                add(_err(code, name, s.raw, "info" if code == "ip" else "low", alg=s.detail if code == "bad_hash" else ""))
        return
    if name == "sandbox":
        for v in values:
            if v.lower() not in SANDBOX_TOKENS:
                add(_err("invalid_value", name, v))
    elif name in ("upgrade-insecure-requests", "block-all-mixed-content"):
        for v in values[:1]:
            add(_err("invalid_value", name, v))
    elif name == "require-trusted-types-for":
        for v in values:
            if v.lower() == "script":
                add(_err("unquoted", name, v))
            elif v.lower() != "'script'":
                add(_err("invalid_value", name, v))
    elif name == "trusted-types":
        for v in values:
            if v.lower() not in ("'none'", "'allow-duplicates'", "*") and not re.match(r"^[A-Za-z0-9\-#=_/@.%]+$", v):
                add(_err("invalid_value", name, v))
    elif name == "treat-as-public-address":     # Chromium (Private Network Access); takes no value
        for v in values[:1]:
            add(_err("invalid_value", name, v))
    elif name == "webrtc":
        for v in values:
            if v.lower() not in ("'allow'", "'block'"):
                add(_err("invalid_value", name, v))
    elif name == "report-to":
        for v in values[1:2]:
            add(_err("invalid_value", name, v))


def _ineffective_scripts(pol: CspPolicy) -> None:
    """Raise to medium the errors that leave the policy without any script restriction (§WEB201)."""
    if restricts_scripts(pol):
        return
    for e in pol.errors:
        target = e.get("suggest") or e.get("swallowed") or ""
        if target in ("script-src", "default-src", "script-src-elem"):
            e["severity"] = "medium"
            e["ineffective"] = True


def split_policies(value: str) -> list[str]:
    """A header field's policies (split on ``,``; empty ones dropped)."""
    return [p for p in value.split(",") if p.strip(_ASCII_WS)]


def parse_header(values: Iterable[str], origin: str = "header") -> list[CspPolicy]:
    out = []
    for v in values:
        for piece in split_policies(v):
            pol = parse_policy(piece, origin)
            if pol.directives or pol.errors or pol.duplicates or pol.dropped:
                out.append(pol)
    return out


# ----------------------------------------------------------------------------------------------- effective lists

def restricts_scripts(p: CspPolicy) -> bool:
    return any(d in p.directives for d in ("script-src", "script-src-elem", "default-src"))


def chain(p: CspPolicy, directive: str) -> tuple[str | None, list[str] | None]:
    """``(directive actually used, its value)`` after the CSP3 fallback, or ``(None, None)``."""
    for name in FALLBACK.get(directive, (directive,)):
        if name in p.directives:
            return name, p.directives[name]
    return None, None


def effective(p: CspPolicy, directive: str) -> list[Source] | None:
    """The valid sources of the directive's effective list after neutralisation; None when unrestricted."""
    _name, values = chain(p, directive)
    if values is None:
        return None
    srcs = [s for s in _sources(values) if s.valid]
    if len(srcs) == 1 and srcs[0].norm == "'none'":
        return []
    srcs = [s for s in srcs if s.norm != "'none'"]
    has_nonce_hash = any(s.kind in ("nonce", "hash") for s in srcs)
    script_like = directive in SCRIPT_LISTS
    strict_dynamic = script_like and any(s.norm == "'strict-dynamic'" for s in srcs)
    if has_nonce_hash or strict_dynamic:
        srcs = [s for s in srcs if s.norm != "'unsafe-inline'"]
    if strict_dynamic:
        srcs = [s for s in srcs if s.kind not in ("host", "scheme") and s.norm != "'self'"]
    return srcs


def _loopback(host: str) -> bool:
    """``localhost``, ``*.localhost`` and 127/8: "potentially trustworthy" origins (Secure Contexts §3.1), which mixed
    content does not block and a network attacker cannot intercept; ``http://localhost:3000`` left over from
    development is not an insecure source (WEB211)."""
    h = host.lstrip("*.")
    return h == "localhost" or h.endswith(".localhost") or (bool(_IPV4.match(h)) and h.startswith("127."))


def _norms(srcs: list[Source] | None) -> set[str]:
    return {s.norm for s in srcs} if srcs else set()


_ANY_SCHEMES = {"script": ("http", "https", "data", "blob"), "object": ("http", "https", "data"),
                "base": ("http", "https", "data"), "frame": ("http", "https"), "default": ("http", "https")}


def broad_sources(srcs: list[Source] | None, kind: str = "default") -> list[str]:
    """The sources that make a list "allow any source" (ANY): ``*``, ``http:``, ``https:``, ``data:``/``blob:`` where
    relevant, any-host wildcards; ``['(missing)']`` when the list is unrestricted. Host wildcards such as
    ``*.example.com`` are not ANY."""
    if srcs is None:
        return ["(missing)"]
    schemes = _ANY_SCHEMES.get(kind, _ANY_SCHEMES["default"])
    out = []
    for s in srcs:
        if s.kind == "scheme" and s.scheme in schemes:
            out.append(s.norm)
        elif s.kind == "host" and s.host == "*" and s.scheme in ("", "http", "https") and not s.path.strip("/"):
            out.append(s.norm)
    return out


def is_any(srcs: list[Source] | None, kind: str = "default") -> bool:
    return bool(broad_sources(srcs, kind))


def nonce_hash_based(p: CspPolicy) -> bool:
    """CSP Evaluator's "needs base-uri" test: script nonces, or hashes with 'strict-dynamic'."""
    _n, values = chain(p, "script-src")
    srcs = [s for s in _sources(values or []) if s.valid]
    if any(s.kind == "nonce" for s in srcs):
        return True
    return any(s.kind == "hash" for s in srcs) and any(s.norm == "'strict-dynamic'" for s in srcs)


def valid_nonces(p: CspPolicy) -> list[str]:
    out: list[str] = []
    for name, values in p.directives.items():
        if name not in SOURCE_LIST_DIRECTIVES:
            continue
        for v in values:
            s = classify_source(v)
            if s.kind == "nonce" and s.detail not in out:
                out.append(s.detail)
    return out


# ----------------------------------------------------------------------------------------------- URL matching

def _default_port(scheme: str) -> int | None:
    return {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}.get(scheme)


def source_matches_url(src: Source, url: str, self_origin: str) -> bool:
    """CSP3 §6.7.2.6/7 "does url match expression in origin" for scheme, host and 'self' sources."""
    u = urllib.parse.urlsplit(url)
    scheme = u.scheme.lower()
    host = (u.hostname or "").lower()
    try:
        port = u.port or _default_port(scheme)
    except ValueError:
        return False
    self_scheme = self_origin.split("://", 1)[0]
    if src.norm == "'self'":
        o = urllib.parse.urlsplit(self_origin)
        if (o.hostname or "").lower() != host:
            return False
        if scheme == self_scheme and url_origin(url) == self_origin:
            return True
        return self_scheme == "http" and scheme == "https"
    if src.kind == "scheme":
        return src.scheme == scheme or (src.scheme == "http" and scheme == "https") or \
            (src.scheme == "ws" and scheme in ("wss", "http", "https"))
    if src.kind != "host":
        return False
    if src.scheme:
        if not (src.scheme == scheme or (src.scheme == "http" and scheme == "https")):
            return False
    elif not (scheme == self_scheme or (self_scheme == "http" and scheme == "https")):
        return False
    if src.host == "*":
        pass
    elif src.host.startswith("*."):
        if not host.endswith(src.host[1:]):
            return False
    elif src.host != host:
        return False
    if src.port == "*":
        pass
    elif src.port:
        if int(src.port) != port:
            return False
    else:
        want = _default_port(src.scheme or scheme)
        if port != want and not (src.scheme == "http" and scheme == "https" and port == 443):
            return False
    if src.path and src.path != "/":
        path = urllib.parse.unquote(u.path or "/")
        sp = urllib.parse.unquote(src.path)
        if sp.endswith("/"):
            if not path.startswith(sp):
                return False
        elif path != sp:
            return False
    return True


def list_allows_url(srcs: list[Source] | None, url: str, self_origin: str) -> bool:
    if srcs is None:
        return True
    return any(source_matches_url(s, url, self_origin) for s in srcs if s.kind in ("host", "scheme") or s.norm == "'self'")


# ----------------------------------------------------------------------------------------------- bypass data

@dataclass(frozen=True)
class BypassData:
    jsonp: tuple[str, ...] = ()
    angular: tuple[str, ...] = ()
    flash: tuple[str, ...] = ()
    needs_eval: frozenset[str] = frozenset(NEEDS_EVAL)
    available: bool = False


def load_bypass(data_module=None) -> BypassData:
    """The bundled (or updated) csp-bypass.json; an empty set when the file is missing (coverage notes it)."""
    try:
        if data_module is None or not hasattr(data_module, "load_json"):
            from . import data as data_module
        obj = data_module.load_json("csp-bypass.json")
    except (OSError, ValueError, KeyError):
        return BypassData()
    return _bypass_from(json.dumps(obj, sort_keys=True))


@lru_cache(maxsize=4)
def _bypass_from(blob: str) -> BypassData:
    obj = json.loads(blob)

    def urls(key: str) -> tuple[str, ...]:
        return tuple(u for u in obj.get(key, []) if isinstance(u, str) and u.startswith("//"))
    needs = obj.get("needs_eval") or NEEDS_EVAL
    return BypassData(urls("jsonp"), urls("angular"), urls("flash"), frozenset(h.lower() for h in needs), True)


@lru_cache(maxsize=8)
def _url_index(urls: tuple[str, ...]) -> dict[str, tuple[tuple[int, str], ...]]:
    """host → ((position in the list, absolute https URL), …) for a bypass list."""
    index: dict[str, list[tuple[int, str]]] = {}
    for i, u in enumerate(urls):
        full = "https:" + u
        index.setdefault((urllib.parse.urlsplit(full).hostname or "").lower(), []).append((i, full))
    return {h: tuple(v) for h, v in index.items()}


def find_bypasses(srcs: list[Source] | None, urls: tuple[str, ...], self_origin: str, limit: int = 3) -> list[str]:
    """Bypass URLs (``https:``-absolute) that an explicit host-source of ``srcs`` allows, in list order."""
    if not srcs:
        return []
    hosts = [s for s in srcs if s.kind == "host" and s.host != "*"]
    if not hosts:
        return []
    index = _url_index(urls)
    cands: dict[int, str] = {}
    for s in hosts:
        if s.host.startswith("*."):
            suffix = s.host[1:]
            for h, entries in index.items():
                if h.endswith(suffix):
                    cands.update(entries)
        else:
            cands.update(index.get(s.host, ()))
    out: list[str] = []
    for _i, full in sorted(cands.items()):
        if any(source_matches_url(s, full, self_origin) for s in hosts):
            out.append(full)
            if len(out) >= limit:
                break
    return out


# ----------------------------------------------------------------------------------------------- stage 1

def _is_html(r: Response) -> bool:
    return r.essence in HTML_ESSENCES or (not r.essence and r.body.lstrip()[:15].lower().startswith((b"<!doctype html",
                                                                                                  b"<html")))


def _opaque(r: Response) -> bool:
    return "opaque-coding" in r.flags


def _meta_candidate(r: Response) -> bool:
    return bool(r.body) and _is_html(r) and not _opaque(r) and b"content-security-policy" in r.body[:4_000_000].lower()


_HEADISH = htmlparse.HEAD_TAGS | {"html", "head"}


def _after_head(doc: ParsedHTML, index: int) -> bool:
    """A ``<meta>`` between ``</head>`` and the body: the HTML tree builder's "after head" mode re-inserts it into
    ``<head>`` (HTML §13.2.6.4.6), so its policy applies. True when no body-only element precedes it."""
    return all(el.tag in _HEADISH for el in doc.elements[:index] if el.live)


def meta_policies(doc: ParsedHTML | None) -> tuple[list[CspPolicy], list[int]]:
    """``(enforced meta policies, indices of CSP <meta> elements outside <head>)``."""
    if doc is None:
        return [], []
    out, outside = [], []
    for e in doc.metas(http_equiv="content-security-policy"):
        content = e.get("content")
        if content is None:
            continue
        if not (e.in_head or _after_head(doc, e.index)):
            outside.append(e.index)
            continue
        pol = parse_policy(content, "meta", element=e.index)
        if pol.directives or pol.errors or pol.duplicates or pol.dropped:
            out.append(pol)
    return out, outside


def facts_for(r: Response, doc: ParsedHTML | None = None) -> CspFacts:
    """The CSP facts of one response (pure). ``doc`` supplies the ``<meta>`` policies."""
    enforced = parse_header(r.headers.get_all("content-security-policy"))
    metas, outside = meta_policies(doc)
    enforced += metas
    ro = parse_header(r.headers.get_all("content-security-policy-report-only"), "report-only")
    legacy = [(name, v) for name in ("X-Content-Security-Policy", "X-WebKit-CSP") for v in r.headers.get_all(name)]
    facts = CspFacts(enforced=enforced, report_only=ro, legacy=legacy)
    header_fa = [p.directives["frame-ancestors"] for p in enforced if p.origin == "header" and "frame-ancestors" in p.directives]
    if header_fa:
        protects = [fa for fa in header_fa if not is_any(_valid_or_empty(fa), "frame")]
        facts.frame_ancestors = list(protects[0] if protects else header_fa[0])
        facts.frame_ancestors_protects = bool(protects)
    facts.upgrade_insecure_requests = any("upgrade-insecure-requests" in p.directives for p in enforced)
    nonces: list[str] = []
    for p in enforced:
        for n in valid_nonces(p):
            if n not in nonces:
                nonces.append(n)
    facts.nonces = nonces
    facts.effective = effective_summary(enforced)
    if outside:
        facts.effective["meta_outside_head"] = outside
    return facts


def _valid_or_empty(values: list[str]) -> list[Source]:
    srcs = [s for s in _sources(values) if s.valid]
    return [] if len(srcs) == 1 and srcs[0].norm == "'none'" else [s for s in srcs if s.norm != "'none'"]


_SUMMARY_DIRECTIVES = ("script-src-elem", "script-src-attr", "script-src", "style-src-elem", "style-src-attr",
                       "object-src", "base-uri", "form-action", "frame-ancestors", "frame-src", "connect-src", "img-src",
                       "worker-src")


def effective_summary(policies: list[CspPolicy]) -> dict:
    """``CspFacts.effective`` (shape owned by WP4): per directive, the effective source list of every enforced policy
    (``None`` = unrestricted), plus ``restricts_scripts``, ``strict`` (every policy nonce/hash-based) and ``policies``."""
    out: dict = {"policies": len(policies), "restricts_scripts": any(restricts_scripts(p) for p in policies),
                 "strict": bool(policies) and all(nonce_hash_based(p) for p in policies), "directives": {}}
    for d in _SUMMARY_DIRECTIVES:
        lists = []
        for p in policies:
            if d in ("base-uri", "form-action", "frame-ancestors"):
                v = p.directives.get(d)
                lists.append(None if v is None else [s.norm for s in _valid_or_empty(v)])
            else:
                e = effective(p, d)
                lists.append(None if e is None else [s.norm for s in e])
        out["directives"][d] = lists
    return out


def _doc_for(ctx: ScanContext, r: Response) -> ParsedHTML | None:
    page = ctx.page_for(r)
    if page is not None and page.doc is not None:
        return page.doc
    if _meta_candidate(r):
        try:
            return htmlparse.parse_response(r)
        except Exception:   # noqa: BLE001 - a hostile body must never break stage 1
            return None
    return None


def parse_all(ctx: ScanContext) -> dict[Response, CspFacts]:
    """Stage 1 (pure): the parsed policies and effective directives of every fetched response (headers, ``<meta
    http-equiv>`` of HTML documents, report-only, legacy X-CSP headers). Responses without any policy get empty facts."""
    out: dict[Response, CspFacts] = {}
    for r in ctx.all_responses():
        if r.status is None:
            continue
        doc = _doc_for(ctx, r) if _is_html(r) and r.body else None
        out[r] = facts_for(r, doc)
    return out


# ----------------------------------------------------------------------------------------------- nonces (WEB212)

def response_nonces(r: Response, facts: CspFacts | None = None) -> set[str]:
    if facts is None:
        doc = htmlparse.parse_response(r) if _meta_candidate(r) else None
        facts = facts_for(r, doc)
    return set(facts.nonces)


def compare_nonces(resp_a: Response, resp_b: Response, facts_a: CspFacts | None = None,
                   facts_b: CspFacts | None = None) -> list[str]:
    """Nonces shared by two separate fetches (static nonce, WEB212). Compared only when both are 2xx documents with a
    CSP and of the same kind; an empty list otherwise."""
    if resp_a is resp_b:
        return []
    for r in (resp_a, resp_b):
        if not (r.is_2xx and not r.error and _is_html(r)):
            return []
    if resp_a.kind and resp_b.kind and resp_a.kind != resp_b.kind:
        return []
    return sorted(response_nonces(resp_a, facts_a) & response_nonces(resp_b, facts_b))


def _cache_control(r: Response) -> dict[str, str]:
    out: dict[str, str] = {}
    for v in r.headers.get_all("cache-control"):
        for part in v.split(","):
            k, _, val = part.strip().partition("=")
            if k:
                out.setdefault(k.strip().lower(), val.strip().strip('"'))
    return out


def shared_cacheable(r: Response) -> str:
    """The Cache-Control directive that lets shared caches store the response ("" when none)."""
    cc = _cache_control(r)
    if "no-store" in cc or "private" in cc:
        return ""
    if "public" in cc:
        return "public"
    try:
        if int(cc.get("s-maxage", "0") or 0) > 0:
            return "s-maxage=" + cc["s-maxage"]
    except ValueError:
        return ""
    return ""


def _seconds(value: str | None) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except ValueError:
        return 0                                       # RFC 9111 §1.2.2: an invalid delta-seconds is treated as stale


def cache_reuses_nonce(r: Response) -> str:
    """:func:`shared_cacheable`, narrowed to responses a shared cache may hand out again **without** asking the origin.

    ``public, max-age=0, must-revalidate`` (the Netlify, Vercel and Cloudflare Pages default) or ``no-cache`` makes the cache
    revalidate every use, and the origin then answers with a fresh nonce: no reuse. Zero freshness with
    ``stale-while-revalidate``/``stale-if-error`` still allows a stale copy (and its nonce) to be served, so it counts."""
    label = shared_cacheable(r)
    if not label:
        return ""
    cc = _cache_control(r)
    if "no-cache" in cc:
        return ""
    lifetime = _seconds(cc.get("s-maxage"))
    if lifetime is None:
        lifetime = _seconds(cc.get("max-age"))
    if lifetime is None and r.headers.has("expires"):
        expires = (r.headers.first("expires") or "").strip()
        if not expires or expires.lstrip("-").isdigit():  # "0" / "-1": an invalid Expires means already expired
            lifetime = 0
    if lifetime is not None and lifetime <= 0:
        stale = max(_seconds(cc.get("stale-while-revalidate")) or 0, _seconds(cc.get("stale-if-error")) or 0)
        if stale <= 0:
            return ""
    return label


# ----------------------------------------------------------------------------------------------- evaluation

@dataclass
class Hit:
    """One weakness found by :func:`evaluate` (turned into an Issue by the run)."""
    rule: str
    severity: str | None = None
    confidence: str | None = None
    notes: list[tuple[str, str]] = field(default_factory=list)
    value: str = ""
    group: str = ""
    params: dict = field(default_factory=dict)
    policy: CspPolicy | None = None


@dataclass
class DocInfo:
    url: str
    https: bool
    forms: bool = False
    password: bool = False
    reporting_groups: frozenset[str] | None = None   # None = no Reporting-Endpoints/Report-To header


def _reporting_groups(r: Response) -> frozenset[str] | None:
    groups: set[str] = set()
    seen = False
    re_values = r.headers.get_all("reporting-endpoints")
    if re_values:
        seen = True
        d, err = sfv.try_parse("dictionary", re_values)
        if err is None and isinstance(d, dict):
            groups.update(d.keys())
    for v in r.headers.get_all("report-to"):
        seen = True
        try:
            obj = json.loads("[" + v + "]")
        except (ValueError, RecursionError):   # hostile: "[[[[…" overflows the C decoder's recursion limit
            continue
        for g in obj if isinstance(obj, list) else []:
            if isinstance(g, dict):
                groups.add(str(g.get("group", "default")))
    return frozenset(groups) if seen else None


def _first(policies: list[CspPolicy], pred) -> CspPolicy | None:
    for p in policies:
        if pred(p):
            return p
    return None


def evaluate(policies: list[CspPolicy], info: DocInfo, bypass: BypassData | None = None,
             paranoid: bool = False) -> list[Hit]:
    """Every value rule over a set of policies that all apply to one document (intersection semantics)."""
    hits: list[Hit] = []
    if not policies:
        return hits
    self_origin = url_origin(info.url)
    script_restricted = any(restricts_scripts(p) for p in policies)

    # ---- WEB042 (any script source / non-script policy)
    if not script_restricted:
        names = sorted({d for p in policies for d in p.directives})
        hits.append(Hit("WEB042", params={"variant": "non_script"}, group="non_script",
                        notes=[_note("non_script", directives=", ".join(names) or "—")], policy=policies[0]))
    else:
        elem = [(p, effective(p, "script-src-elem")) for p in policies]
        if all(is_any(e, "script") for _p, e in elem):
            explicit = [(p, broad_sources(e, "script")) for p, e in elem if e is not None]
            if explicit:
                p, broad = explicit[0]
                name, _v = chain(p, "script-src-elem")
                hits.append(Hit("WEB042", value=" ".join(broad), group=" ".join(sorted(broad)), policy=p,
                                notes=[_note("any_source", directive=name or "script-src", value=" ".join(broad))]))

    # ---- WEB040 (inline scripts)
    if script_restricted:
        for d in ("script-src-elem", "script-src-attr"):
            lists = [(p, effective(p, d)) for p in policies]
            if all(e is None or "'unsafe-inline'" in _norms(e) for _p, e in lists):
                exp = [p for p, e in lists if e is not None and "'unsafe-inline'" in _norms(e)]
                if exp:
                    name, _v = chain(exp[0], d)
                    hits.append(Hit("WEB040", value="'unsafe-inline'", group=name or d, policy=exp[0],
                                    notes=[_note("inline_where", directive=name or d)]))
                    break

    # ---- WEB041 (eval): CSP3 string compilation checks script-src → default-src
    def eval_tokens(p: CspPolicy) -> list[str]:
        _n, values = chain(p, "script-src")
        norms = {s.norm for s in _sources(values or []) if s.valid}
        out = []
        if "'unsafe-eval'" in norms:
            out.append("'unsafe-eval'")
        tt = [v.lower() for v in p.directives.get("require-trusted-types-for", [])]
        if "'trusted-types-eval'" in norms and "'script'" not in tt:
            out.append("'trusted-types-eval'")
        return out

    if all(chain(p, "script-src")[1] is None or eval_tokens(p) for p in policies):
        exp = [p for p in policies if eval_tokens(p)]
        if exp:
            name, _v = chain(exp[0], "script-src")
            tok = eval_tokens(exp[0])[0]
            hits.append(Hit("WEB041", value=tok, group=tok, policy=exp[0],
                            notes=[_note("eval_where", value=tok, directive=name or "script-src")]))

    # ---- WEB203 ('strict-dynamic' without nonce/hash): a broken policy, reported when any policy has it
    for p in policies:
        name, values = chain(p, "script-src-elem")
        srcs = [s for s in _sources(values or []) if s.valid]
        if any(s.norm == "'strict-dynamic'" for s in srcs) and not any(s.kind in ("nonce", "hash") for s in srcs):
            hits.append(Hit("WEB203", value="'strict-dynamic'", group=name or "script-src", policy=p,
                            notes=[_note("strict_dynamic_alone", directive=name or "script-src")]))
            break

    # ---- WEB043 (object-src)
    if script_restricted:
        objs = [(p, effective(p, "object-src")) for p in policies]
        if all(is_any(e, "object") for _p, e in objs):
            p, e = objs[0]
            broad = broad_sources(e, "object")
            note = _note("missing_directive", directive="object-src") if e is None else \
                _note("any_source", directive=chain(p, "object-src")[0] or "object-src", value=" ".join(broad))
            hits.append(Hit("WEB043", value=" ".join(broad), group=" ".join(broad), policy=p, notes=[note]))

    # ---- WEB204 (base-uri; no fallback)
    if script_restricted:
        bases = [(p, None if "base-uri" not in p.directives else _valid_or_empty(p.directives["base-uri"]))
                 for p in policies]
        if all(is_any(b, "base") for _p, b in bases):
            broad = [x for _p, b in bases if b is not None for x in broad_sources(b, "base")]
            nonce_based = any(nonce_hash_based(p) for p in policies)
            sev = "medium" if (nonce_based or broad) else "info"
            notes = [_note("any_source", directive="base-uri", value=" ".join(broad)) if broad else
                     _note("missing_directive", directive="base-uri"),
                     _note("base_nonce") if nonce_based else _note("base_allowlist")]
            if broad and not nonce_based:
                notes = notes[:1]
            hits.append(Hit("WEB204", severity=sev, value=" ".join(broad) or "(missing)",
                            group=" ".join(broad) or "missing", policy=policies[0], notes=notes))

    # ---- WEB205 (form-action; no fallback)
    if info.forms:
        forms = [(p, None if "form-action" not in p.directives else _valid_or_empty(p.directives["form-action"]))
                 for p in policies]
        if all(is_any(f) for _p, f in forms):
            broad = [x for _p, f in forms if f is not None for x in broad_sources(f)]
            sev = "medium" if info.password else "info"
            notes = [_note("any_source", directive="form-action", value=" ".join(broad)) if broad else
                     _note("missing_directive", directive="form-action"),
                     _note("form_password") if info.password else _note("form_other")]
            hits.append(Hit("WEB205", severity=sev, value=" ".join(broad) or "(missing)",
                            group=" ".join(broad) or "missing", policy=policies[0], notes=notes))

    # ---- WEB206 (frame-ancestors ANY in an enforced header policy; none restricts)
    header = [p for p in policies if p.origin in ("header", "report-only")]
    fas = [(p, _valid_or_empty(p.directives["frame-ancestors"])) for p in header if "frame-ancestors" in p.directives]
    if fas and all(is_any(f, "frame") for _p, f in fas):
        p, f = fas[0]
        broad = broad_sources(f, "frame")
        hits.append(Hit("WEB206", value=" ".join(broad), group=" ".join(broad), policy=p,
                        notes=[_note("fa_any", value=" ".join(broad))]))

    # ---- WEB209 (allowlisted host with a known JSONP / AngularJS bypass)
    if script_restricted and bypass is not None and bypass.available:
        elem = [(p, effective(p, "script-src-elem")) for p in policies]
        found: list[tuple[str, str, bool]] = []    # (kind, url, needs eval)
        for p, e in elem:
            for kind, urls in (("jsonp", bypass.jsonp), ("angular", bypass.angular)):
                for u in find_bypasses(e, urls, self_origin):
                    if all(list_allows_url(e2, u, self_origin) for _p2, e2 in elem):
                        host = urllib.parse.urlsplit(u).hostname or ""
                        found.append((kind, u, kind == "jsonp" and host in bypass.needs_eval))
            if found:
                break
        if found:
            eval_ok = all(chain(p, "script-src")[1] is None or "'unsafe-eval'" in eval_tokens(p) for p in policies)
            usable = [f for f in found if not f[2] or eval_ok]
            sev = "medium" if usable else "low"
            kind, u, _ne = (usable or found)[0]
            host = urllib.parse.urlsplit(u).hostname or ""
            notes = [_note("bypass_jsonp" if kind == "jsonp" else "bypass_angular", host=host, url=u)]
            if not usable:
                notes.append(_note("bypass_needs_eval"))
            hits.append(Hit("WEB209", severity=sev, value=u, group=host, policy=elem[0][0], notes=notes))

    # ---- WEB210 ('unsafe-hashes')
    attrs = [(p, effective(p, "script-src-attr")) for p in policies]

    def handlers_allowed(e: list[Source] | None) -> bool:
        return e is None or bool(_norms(e) & {"'unsafe-inline'", "'unsafe-hashes'"})
    if all(handlers_allowed(e) for _p, e in attrs):
        exp = [(p, e) for p, e in attrs if e is not None and "'unsafe-hashes'" in _norms(e)]
        if exp:
            name, _v = chain(exp[0][0], "script-src-attr")
            hits.append(Hit("WEB210", value="'unsafe-hashes'", group=name or "script-src", policy=exp[0][0],
                            notes=[_note("unsafe_hashes", directive=name or "script-src")]))

    # ---- WEB211 (insecure http:/ftp: sources on an https page)
    if info.https:
        weak: list[tuple[str, str, str, CspPolicy]] = []    # (resource type, directive used, tokens, policy)
        for d in ACTIVE_TYPES + PASSIVE_TYPES:
            lists = [(p, effective(p, d)) for p in policies]
            insecure = [(p, [s.norm for s in e if (s.kind == "scheme" and s.scheme in ("http", "ftp")) or
                             (s.kind == "host" and s.scheme in ("http", "ftp") and not _loopback(s.host))])
                        for p, e in lists if e is not None]
            explicit = [(p, toks) for p, toks in insecure if toks]
            if not explicit:
                continue

            def allows_insecure(e: list[Source] | None) -> bool:
                return e is None or any((s.kind == "scheme" and s.scheme in ("http", "ftp")) or
                                        (s.kind == "host" and s.scheme in ("http", "ftp") and not _loopback(s.host))
                                        or (s.kind == "host" and s.host == "*") for s in e)
            if all(allows_insecure(e) for _p, e in lists):
                p, toks = explicit[0]
                name, _v = chain(p, d)
                weak.append((d, name or d, " ".join(dict.fromkeys(toks)), p))
        if weak:
            active = any(d not in PASSIVE_TYPES for d, _n, _t, _p in weak)
            uir = any("upgrade-insecure-requests" in p.directives for p in policies)
            sev = "medium" if active and not uir else "low"
            seen_d: set[str] = set()
            notes = []
            for _d, name, toks, _p in weak:
                if name not in seen_d:
                    seen_d.add(name)
                    notes.append(_note("insecure_source", directive=name, value=toks))
            if uir:
                notes.append(_note("uir_mitigates"))
            hits.append(Hit("WEB211", severity=sev, value=weak[0][2], group=",".join(sorted(seen_d)),
                            policy=weak[0][3], notes=notes[:6]))

    # ---- WEB213 (short / weak nonces)
    worst: tuple[int, str, str, int] | None = None   # (rank, nonce, kind, n)
    for p in policies:
        for n in valid_nonces(p):
            raw = _b64_bytes(n)
            if len(n) < 8:
                cand = (2, n, "short", len(n))
            elif raw is not None and len(raw) < 16:
                cand = (1, n, "weak", len(raw))
            else:
                continue
            if worst is None or cand[0] > worst[0]:
                worst = cand
    if worst is not None:
        _rank, n, kind, size = worst
        shown = _short(n, 40)
        if kind == "short":
            hits.append(Hit("WEB213", severity="medium", value=shown, group="short",
                            notes=[_note("short_nonce", nonce=shown, chars=_count(size, _CHARS))]))
        else:
            hits.append(Hit("WEB213", severity="info", value=shown, group="weak",
                            notes=[_note("weak_nonce", nonce=shown, size=_count(size, _BYTES))]))

    # ---- WEB214 (inline styles)
    for d in ("style-src-elem", "style-src-attr"):
        lists = [(p, effective(p, d)) for p in policies]
        if all(e is None or "'unsafe-inline'" in _norms(e) for _p, e in lists):
            exp = [p for p, e in lists if e is not None and "'unsafe-inline'" in _norms(e)]
            if exp:
                name, _v = chain(exp[0], d)
                hits.append(Hit("WEB214", value="'unsafe-inline'", group=name or d, policy=exp[0],
                                notes=[_note("inline_where", directive=name or d)]))
                break

    # ---- WEB215 (reporting)
    rep = [p for p in policies if "report-uri" in p.directives or "report-to" in p.directives]
    if not rep:
        hits.append(Hit("WEB215", severity="info", value="", group="none", notes=[_note("no_reporting")]))
    else:
        groups = [p.directives["report-to"][0] for p in rep if p.directives.get("report-to")]
        if groups and not any("report-uri" in p.directives for p in rep):
            known = info.reporting_groups or frozenset()
            missing = [g for g in groups if g not in known]
            if missing:
                hits.append(Hit("WEB215", severity="low", value=missing[0], group="group:" + missing[0],
                                notes=[_note("report_group_missing", group=_short(missing[0], 60))]))

    # ---- WEB216 (deprecated directives)
    dep = sorted({d for p in policies for d in p.directives if d in DEPRECATED_DIRECTIVES})
    if dep:
        hits.append(Hit("WEB216", value=", ".join(dep), group=",".join(dep),
                        notes=[_note("deprecated", directive=d) for d in dep]))

    # ---- WEB218 (allowlist-only script policy)
    if script_restricted:
        elem = [(p, effective(p, "script-src-elem")) for p in policies]
        if not any(any(s.kind in ("nonce", "hash") for s in (e or [])) or
                   any(s.norm == "'strict-dynamic'" for s in (e or [])) for _p, e in elem):
            allow = [(p, [s.norm for s in e if s.kind in ("host", "scheme") or s.norm == "'self'"])
                     for p, e in elem if e is not None]
            allow = [(p, a) for p, a in allow if a]
            narrow = [(p, a) for (p, a) in allow if not is_any(effective(p, "script-src-elem"), "script")]
            if allow and not all(is_any(e, "script") for _p, e in elem):
                p, a = (narrow or allow)[0]
                name, _v = chain(p, "script-src-elem")
                shown = " ".join(a[:6]) + (" …" if len(a) > 6 else "")
                hits.append(Hit("WEB218", value=shown, group="allowlist", policy=p,
                                notes=[_note("allowlist_only", directive=name or "script-src", value=shown)]))

    # ---- WEB219 (Trusted Types; paranoid only)
    if paranoid and script_restricted:
        if not any("'script'" in [v.lower() for v in p.directives.get("require-trusted-types-for", [])]
                   for p in policies):
            hits.append(Hit("WEB219", value="", group="missing", notes=[_note("no_trusted_types")]))
    return hits


def policy_notes(policies: list[CspPolicy], bypass: BypassData | None = None,
                 self_origin: str = "https://invalid.invalid") -> list[tuple[str, str]]:
    """Inventory notes: neutralised 'unsafe-inline', object-src 'self', Flash hosts in object-src."""
    notes: list[tuple[str, str]] = []
    for p in policies:
        if bypass is not None and bypass.flash:
            for u in find_bypasses(effective(p, "object-src"), bypass.flash, self_origin, limit=1):
                notes.append(_note("flash_bypass", host=urllib.parse.urlsplit(u).hostname or ""))
        for d in ("script-src-elem", "script-src"):
            _n, values = chain(p, d)
            if values and "'unsafe-inline'" in values and "'unsafe-inline'" not in _norms(effective(p, d)):
                notes.append(_note("inline_kept"))
                break
        obj = effective(p, "object-src")
        if obj and _norms(obj) == {"'self'"}:
            notes.append(_note("object_self"))
    return list(dict.fromkeys(notes))


# ----------------------------------------------------------------------------------------------- Observatory v6

OBS_TEST = "content-security-policy"
_OBS_BROAD = ("ftp:", "http:", "https:", "*", "http://*", "http://*.*", "https://*", "https://*.*")
_OBS_UNSAFE = ("'unsafe-inline'", "data:")
_OBS_NONCE_HASH = ("'sha256-", "'sha384-", "'sha512-", "'nonce-")
_OBS_DUP = "_observatory_duplicate_key_warnings"
_OBS_MAX_POLICIES = 32
_OBS_MAX_SOURCES = 2000          # per directive
_OBS_TOKEN_BUDGET = 4000         # across the merged policies
_ICU_PUNCT = "_-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$"
_ICU_RANK = {c: i for i, c in enumerate(_ICU_PUNCT)}
_JS_TRIM = re.compile(r"^[\s﻿]+|[\s﻿]+$")
_PCT_BAD = re.compile(r"%(?![0-9A-Fa-f]{2})")


class _ObsInvalid(Exception):
    pass


def _icu_key(s: str) -> list[int]:
    """Sort key emulating ``Intl.Collator("en").compare`` (CLDR root, non-ignorable) for the ASCII range."""
    out = []
    for ch in s:
        if ch in _ICU_RANK:
            out.append(100 + _ICU_RANK[ch])
        elif "0" <= ch <= "9":
            out.append(200 + ord(ch) - 48)
        elif "a" <= ch <= "z" or "A" <= ch <= "Z":
            out.append(300 + ord(ch.lower()) - 97)
        elif ch.isspace() or ord(ch) < 32:
            out.append(50)
        else:
            out.append(1000 + ord(ch))
    return out


def _js_trim(s: str) -> str:
    return _JS_TRIM.sub("", s)


def _js_len(s: str) -> int:
    return len(s.encode("utf-16-le")) // 2


def _js_decode(s: str) -> str:
    if _PCT_BAD.search(s):
        raise _ObsInvalid("URIError")
    try:
        return urllib.parse.unquote_to_bytes(s).decode("utf-8")
    except UnicodeDecodeError as e:
        raise _ObsInvalid("URIError") from e


def _obs_path_part_match(a: str, b: str) -> bool:
    if len(a) == 0 or (a == "/" and len(b) == 0):
        return True
    exact = not a.endswith("/")
    la, lb = a.split("/"), b.split("/")
    if len(la) > len(lb) or (exact and len(la) != len(lb)):
        return False
    if not exact:
        la.pop()
    for i, pa in enumerate(la):
        if _js_decode(pa) != _js_decode(lb[i]):
            return False
    return True


def obs_parse_csp(csp_list: list[str]) -> dict[str, set[str]]:
    """``cspParser.parseCsp`` of mdn-http-observatory 1.7.2 (raises ``_ObsInvalid`` where it throws)."""
    clean = [_js_trim(re.sub(r"[\r\n]", "", s)) for s in csp_list]
    if not clean:
        return {}
    for s in clean:
        if not s or _js_len(s) < 6:
            raise _ObsInvalid(s)
    # Observatory's merge re-sorts the accumulated sources for every further policy, which is quadratic: a hostile
    # header with thousands of policies (or <meta> tags) would stall the scan. Real sites send a handful of policies
    # with at most a few hundred sources; beyond the caps the slug is computed on the first policies / sources only
    # (an approximation that only affects such input). The first policy is always used in full (up to the cap).
    budget, kept = _OBS_TOKEN_BUDGET, []
    for i, s in enumerate(clean[:_OBS_MAX_POLICIES]):
        budget -= s.count(" ") + s.count("\t") + s.count(";") + 1
        if i and budget < 0:
            break
        kept.append(s)
    clean = kept
    csp: dict[str, list[list]] = {}
    dup: set[str] = set()
    for pi, policy in enumerate(clean):
        seen: set[str] = set()
        for entry in policy.split(";"):
            parts = re.split(r"\s+", _js_trim(entry))
            if not parts[0]:
                continue
            d = parts[0].lower()
            if d in seen:
                if d in ("report-uri", "report-to"):
                    dup.add(d)
                else:
                    raise _ObsInvalid(d)
            else:
                seen.add(d)
            keep = pi == 0
            values = [[_js_trim(v).lower(), pi, keep] for v in parts[1:_OBS_MAX_SOURCES + 1]]
            if not parts[1:] and d.endswith("-src"):
                values = [["'none'", pi, keep]]
            combined = list(values) if pi == 0 else csp.get(d, []) + values
            combined.sort(key=lambda e: _icu_key(e[0]))
            for i in range(1, len(combined)):
                src, prev = combined[i], combined[i - 1]
                if src[1] == prev[1] and src[0].startswith(prev[0]):
                    src[2] = False
                if src[1] != prev[1] and _obs_path_part_match(prev[0], src[0]):
                    src[2] = True
            csp[d] = [e for e in combined if e[2]]
            if pi == 0 and len(csp_list) > 1:
                for e in csp[d]:
                    e[2] = False
    final: dict[str, set[str]] = {d: ({e[0] for e in lst} if lst else {"'none'"}) for d, lst in csp.items()}
    if dup:
        final[_OBS_DUP] = dup
    return final


def _obs_html(r: Response) -> bool:
    ct = r.headers.first("content-type")
    return ct is not None and ct.split(";", 1)[0] in HTML_ESSENCES and bool(r.body)


def observatory_slug(r: Response | None, doc: ParsedHTML | None = None, session_url: str | None = None) -> str:
    """The Observatory v6 ``content-security-policy`` result for the "auto" response (``csp.js`` of 1.7.2)."""
    if r is None:
        return "csp-not-implemented"
    url = session_url or (r.chain[0].url if r.chain else r.url)
    http_policies = [p.strip() for v in r.headers.get_all("content-security-policy") for p in v.split(",")]
    equiv: list[str] = []
    if doc is not None and _obs_html(r):
        for m in doc.find_all("meta", live_only=False):
            if m.has("http-equiv") and m.has("content"):
                if (m.get("http-equiv") or "").strip().lower() == "content-security-policy" and m.get("content"):
                    equiv.extend(p.strip() for p in (m.get("content") or "").split(","))
    try:
        csp = obs_parse_csp(http_policies + equiv)
    except _ObsInvalid:
        return "csp-header-invalid"
    try:
        header_only = obs_parse_csp(http_policies)
    except _ObsInvalid:
        header_only = {}
    try:
        meta = obs_parse_csp(equiv)
        for d in ("frame-ancestors", "report-uri", "sandbox"):
            meta.pop(d, None)
    except _ObsInvalid:
        meta = {}
    if len(header_only) + len(meta) == 0:
        return ("csp-not-implemented-but-reporting-enabled" if r.headers.joined("content-security-policy-report-only")
                else "csp-not-implemented")

    def get(*names: str) -> set[str]:
        for n in names:
            if n in csp:
                return csp[n]
        return {"*"}
    object_src = get("object-src", "default-src")
    script_src = get("script-src", "default-src")
    style_src = get("style-src", "default-src")
    result: str | None = None
    for lst in (script_src, style_src):
        if any(s.startswith(_OBS_NONCE_HASH) for s in lst) and "'unsafe-inline'" in lst:
            lst.discard("'unsafe-inline'")
    if any(s.startswith(_OBS_NONCE_HASH) for s in script_src) and "'strict-dynamic'" in script_src:
        for s in list(script_src):
            if s.startswith(_OBS_BROAD) or s in ("'self'", "'unsafe-inline'"):
                script_src.discard(s)
    elif "'strict-dynamic'" in script_src:
        result = "csp-header-invalid"
    active = [s for d, lst in csp.items() if d not in ("img-src", "media-src") and d != "script-src" for s in lst]
    active += list(script_src)
    passive = [s for d in ("img-src", "media-src") for s in (csp.get(d) or csp.get("default-src") or set())]
    https = url.lower().startswith("https:")
    broad_unsafe = set(_OBS_BROAD) | set(_OBS_UNSAFE)
    if script_src & broad_unsafe or object_src & set(_OBS_BROAD):
        result = result or "csp-implemented-with-unsafe-inline"
    if https and any(s.startswith(("http:", "ftp:")) for s in active):
        result = result or "csp-implemented-with-insecure-scheme"
    if "'unsafe-eval'" in (script_src | style_src):
        result = result or "csp-implemented-with-unsafe-eval"
    if https and any(s.startswith(("http:", "ftp:")) for s in passive):
        result = result or "csp-implemented-with-insecure-scheme-in-passive-content-only"
    if style_src & broad_unsafe:
        result = result or "csp-implemented-with-unsafe-inline-in-style-src-only"
    dflt = csp.get("default-src")
    if dflt is not None and "'none'" in dflt and len(dflt) == 1:
        result = result or "csp-implemented-with-no-unsafe-default-src-none"
    else:
        result = result or "csp-implemented-with-no-unsafe"
    passing = ("csp-implemented-with-no-unsafe", "csp-implemented-with-no-unsafe-default-src-none",
               "csp-implemented-with-unsafe-inline-in-style-src-only",
               "csp-implemented-with-insecure-scheme-in-passive-content-only")
    if result in passing and _OBS_DUP in csp:
        result = "csp-implemented-but-duplicate-directives"
    return result


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
    if _is_html(r):
        return "document"
    ess = r.essence
    if ess == "application/json" or ess.endswith("+json"):
        return "api_json"
    return "other"


class _Run:
    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.issues: list[Issue] = []
        self.evaluated: dict[str, set[str]] = {}
        self.failed: dict[str, set[str]] = {}
        self.no_policy: dict[str, set[str]] = {}     # check → hosts with a document that has no enforced policy
        self.paranoid = ctx.options.sensitivity == _PARANOID
        self.own_sites = {psl.site(h) for h in (ctx.target_host, ctx.entry.host if ctx.entry else "") if h}
        self.blocked_hosts: dict[str, str] = {}
        if ctx.entry is not None and _kind(ctx.entry) in ("waf_challenge", "rate_limited"):
            reason = "waf" if _kind(ctx.entry) == "waf_challenge" else "rate_limited"
            for h in ctx.entry.hops():
                self.blocked_hosts[h.host] = reason
        self.bypass = load_bypass(ctx.data)
        self.facts_cache: dict[int, CspFacts] = {}
        self.docs: dict[int, ParsedHTML | None] = {}     # id(response) → document, as documents() parsed it

    def doc_of(self, r: Response) -> ParsedHTML | None:
        page = self.ctx.page_for(r)
        return page.doc if page is not None else None

    def seen(self, check: str, host: str) -> None:
        self.evaluated.setdefault(check, set()).add(host)

    def without_policy(self, check: str, host: str) -> None:
        """The check judges policy content and this host's document has none: not_applicable (``no_policy``), never a
        pass (a later weak policy is then a new finding, not a "check regressed")."""
        self.no_policy.setdefault(check, set()).add(host)

    def facts(self, r: Response, doc: ParsedHTML | None = None) -> CspFacts:
        f = self.ctx.csp.get(r)
        if f is not None:
            return f
        if id(r) not in self.facts_cache:
            if doc is None and _is_html(r) and r.body:
                doc = _doc_for(self.ctx, r)
            self.facts_cache[id(r)] = facts_for(r, doc)
        return self.facts_cache[id(r)]

    def emit(self, rule: str, r: Response, evidence: Evidence, *, severity: str | None = None,
             confidence: str | None = None, group_value: str = "", notes: list[tuple[str, str]] | None = None,
             params: dict | None = None) -> None:
        meta = RULES[rule]
        conf = confidence or meta.confidence
        if conf not in meta.allowed_confidences:
            return
        sev = severity if severity in meta.allowed_severities else None
        notes = list(notes or [])[:8]
        if rule in CEILING_RULES:
            ceiling = missing_severity(self.docs.get(id(r)) if id(r) in self.docs else self.doc_of(r))
            base = sev or meta.severity
            if _SEV_RANK[base] < _SEV_RANK[ceiling] and ceiling in meta.allowed_severities:
                sev = ceiling
                notes.append(ceiling_note(ceiling))
        self.issues.append(Issue(rule=rule, url=r.url, confidence=conf, evidence=evidence, params=dict(params or {}),
                                 severity=sev, group_value=group_value, notes=notes, host=r.host))
        self.seen(meta.check_id, r.host)
        if self.ctx.options.reports(conf):
            self.failed.setdefault(meta.check_id, set()).add(r.host)

    def own(self, r: Response) -> bool:
        return bool(r.host) and psl.site(r.host) in self.own_sites

    def documents(self) -> list[tuple[Response, ParsedHTML | None, str]]:
        """G1 targets ``(response, doc, confidence override)``: final 2xx documents (paranoid: HTML error pages)."""
        out: list[tuple[Response, ParsedHTML | None, str]] = []
        seen: set[int] = set()
        pages: list[Page] = list(self.ctx.pages)
        if self.ctx.entry is not None and not any(p.response is self.ctx.entry for p in pages):
            pages.insert(0, Page(self.ctx.entry, None, 0))
        for p in pages:
            r = p.response
            if id(r) in seen or not self.own(r) or r.host in self.blocked_hosts or r.status is None:
                continue
            k = _kind(r)
            conf = ""
            if k == "document" and r.is_2xx and not r.error:
                pass
            elif self.paranoid and k == "error_page" and _is_html(r):
                conf = "tentative"
            else:
                continue
            seen.add(id(r))
            doc = p.doc
            if doc is None and r.body and not _opaque(r):
                doc = htmlparse.parse_response(r)
            self.docs[id(r)] = doc
            out.append((r, doc, conf))
        return out

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
            na = self.no_policy.get(check, set()) - hosts
            for host in sorted(na):
                cov.not_applicable(check, "no_policy", host=host)
            for host, reason in self.blocked_hosts.items():
                if host not in hosts:
                    cov.inconclusive(check, reason, host=host)
            if not hosts and not na and not self.blocked_hosts:
                if RULES[check].paranoid_only and not self.paranoid:
                    cov.not_tested(check, "sensitivity")
                elif check == "WEB209" and not self.bypass.available:
                    cov.not_tested(check, "data_missing")
                else:
                    cov.not_applicable(check, "no_document")


def _ev(ctx: ScanContext, r: Response, policy: CspPolicy | None = None, *, name: str = "", value: str = "",
        doc: ParsedHTML | None = None) -> Evidence:
    if policy is not None and policy.origin == "meta":
        offset = None
        if doc is not None and policy.element is not None and 0 <= policy.element < len(doc.elements):
            offset = doc.elements[policy.element].offset
        return Evidence.for_response(r, where="body", name="meta http-equiv=Content-Security-Policy",
                                     value=value or policy.raw, offset=offset, excerpt=_short(policy.raw, 200),
                                     now=ctx.now)
    if policy is not None:
        hname = "Content-Security-Policy-Report-Only" if policy.origin == "report-only" else "Content-Security-Policy"
        return Evidence.for_response(r, where="header", name=hname, value=value or policy.raw, now=ctx.now)
    return Evidence.for_response(r, where="header", name=name or "Content-Security-Policy", value=value, now=ctx.now)


def _doc_info(r: Response, doc: ParsedHTML | None) -> DocInfo:
    forms = bool(doc and any(f.live for f in doc.forms))
    return DocInfo(url=r.url, https=r.is_https, forms=forms, password=bool(doc and doc.has_password_field),
                   reporting_groups=_reporting_groups(r))


# §2.2 severity ceiling: no CSP-weakness rule is more severe than WEB-content-security-policy on the same document
CEILING_RULES = frozenset({"WEB040", "WEB041", "WEB042", "WEB043"} | {f"WEB{n}" for n in range(200, 220)})
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_AR = {"critical": "حرجة", "high": "عالية", "medium": "متوسطة", "low": "منخفضة", "info": "معلوماتية"}


def missing_severity(doc: ParsedHTML | None) -> str:
    """The severity WEB-content-security-policy has (or would have) on this document: low on a static one."""
    return "low" if _static_doc(doc) else RULES["WEB-content-security-policy"].severity


def ceiling_note(severity: str) -> tuple[str, str]:
    return _note("ceiling", severity=(severity, _SEV_AR.get(severity, severity)))


def _static_doc(doc: ParsedHTML | None) -> bool:
    if doc is None:
        return False
    for e in doc.elements:
        if not e.live:
            continue
        if e.tag in ("script", "form", "iframe", "object", "embed"):
            return False
        if any(a.startswith("on") for a in e.attrs):
            return False
    return True


def _xfo_protects(r: Response) -> bool:
    vals = [v.strip().lower() for f in r.headers.get_all("x-frame-options") for v in f.split(",") if v.strip()]
    return bool(vals) and all(v in ("deny", "sameorigin") for v in vals)


def run(ctx: ScanContext) -> list[Issue]:
    """All §2.2 checks over the context (pure apart from writing ``ctx.observatory``, ``ctx.inventory`` and coverage)."""
    if not ctx.csp:
        ctx.csp = parse_all(ctx)
    st = _Run(ctx)
    docs = st.documents()
    evaluated_docs: set[tuple[str, tuple]] = set()
    inventory: list[dict] = []
    for r, doc, conf in docs:
        facts = st.facts(r, doc)
        _missing(st, r, doc, conf, facts)
        if conf:
            continue
        key = (r.url, tuple(r.headers.get_all("content-security-policy")),
               tuple(p.raw for p in facts.enforced if p.origin == "meta"))
        if key in evaluated_docs:
            continue
        evaluated_docs.add(key)
        _values(st, r, doc, facts)
        _meta_rules(st, r, doc, facts)
        _legacy(st, r, facts)
        inventory.append(_inventory_entry(r, facts, st.bypass))
    _syntax(st, docs)
    _static_nonces(st, docs)
    st.record_coverage()
    if inventory:
        ctx.inventory.setdefault("csp", []).extend(inventory[:50])
    auto = observatory_auto(ctx)
    auto_doc = None
    if auto is not None:
        page = ctx.page_for(auto)
        auto_doc = page.doc if page is not None else None
        if auto_doc is None and _obs_html(auto) and not _opaque(auto):
            auto_doc = htmlparse.parse_response(auto)
    ctx.observatory[OBS_TEST] = observatory_slug(auto, auto_doc)
    return st.issues


def _missing(st: _Run, r: Response, doc: ParsedHTML | None, conf: str, facts: CspFacts) -> None:
    ctx = st.ctx
    st.seen("WEB-content-security-policy", r.host)
    st.seen("WEB200", r.host)
    if facts.enforced:
        return
    notes: list[tuple[str, str]] = []
    if facts.effective.get("meta_outside_head"):
        notes.append(_note("meta_in_body"))
    if facts.report_only and conf:
        return      # WEB200 judges final 2xx documents only (its registry entry has no tentative confidence)
    if facts.report_only:
        ro_hits = evaluate(facts.report_only, _doc_info(r, doc), st.bypass, st.paranoid)
        weak = [h.rule for h in ro_hits if (h.severity or RULES[h.rule].severity) != "info"]
        if any(p.errors for p in facts.report_only):
            weak.append("WEB201")
        if any(p.duplicates for p in facts.report_only):
            weak.append("WEB202")
        weak = list(dict.fromkeys(weak))
        if weak:
            notes.append(_note("ro_weak", rules=("; ".join(f"{w} ({RULES[w].name_en})" for w in weak[:8]),
                                                 "؛ ".join(f"{w} ({RULES[w].name_ar})" for w in weak[:8]))))
        else:
            notes.append(_note("ro_clean"))
        ev = _ev(ctx, r, facts.report_only[0])
        if ev.match is not None:
            ev.match["excerpt"] = ("would be weak when enforced: " + ", ".join(weak)) if weak else ""
        st.emit("WEB200", r, ev, notes=notes, group_value="report-only")
        return
    if facts.legacy:
        notes.append(_note("legacy_no_standard"))
    static = _static_doc(doc)
    if static:
        notes.append(_note("static_doc"))
    st.emit("WEB-content-security-policy", r, _ev(ctx, r, name="Content-Security-Policy"), confidence=conf or None,
            severity="low" if static else None, notes=notes, group_value="missing")


# the checks that judge the content of an enforced policy: on a document without one they are not_applicable
POLICY_CONTENT_CHECKS = ("WEB040", "WEB041", "WEB042", "WEB043", "WEB203", "WEB204", "WEB205", "WEB206", "WEB209",
                         "WEB210", "WEB211", "WEB213", "WEB214", "WEB215", "WEB216", "WEB218")


def _values(st: _Run, r: Response, doc: ParsedHTML | None, facts: CspFacts) -> None:
    ctx = st.ctx
    checks = POLICY_CONTENT_CHECKS + (("WEB219",) if st.paranoid else ())
    if not facts.enforced:
        for rule in checks + ("WEB201", "WEB202", "WEB207", "WEB208", "WEB212"):
            st.without_policy(rule, r.host)
        return
    for rule in checks:
        st.seen(rule, r.host)
    for h in evaluate(facts.enforced, _doc_info(r, doc), st.bypass, st.paranoid):
        st.emit(h.rule, r, _ev(ctx, r, h.policy or facts.enforced[0], value=h.value if h.policy is None else "", doc=doc),
                severity=h.severity, confidence=h.confidence, notes=h.notes, params=h.params, group_value=h.group)
    # WEB212 (cached nonce): a nonce'd document that shared caches may store
    if facts.nonces:
        cache = cache_reuses_nonce(r)
        if cache:
            st.emit("WEB212", r, _ev(ctx, r, name="Cache-Control", value=", ".join(r.headers.get_all("cache-control"))),
                    confidence="firm", notes=[_note("cached_nonce", cache=cache)], group_value="cached")


def _meta_rules(st: _Run, r: Response, doc: ParsedHTML | None, facts: CspFacts) -> None:
    metas = [p for p in facts.enforced if p.origin == "meta"]
    if not metas:
        return
    ctx = st.ctx
    st.seen("WEB207", r.host)
    st.seen("WEB208", r.host)
    for p in metas:
        if p.dropped:
            fa_only = ("frame-ancestors" in p.dropped and not facts.frame_ancestors_protects and not _xfo_protects(r))
            notes = [_note("meta_dropped", directives=", ".join(p.dropped))]
            if fa_only:
                notes.append(_note("meta_fa_only"))
            st.emit("WEB207", r, _ev(ctx, r, p, doc=doc), severity="medium" if fa_only else "low", notes=notes,
                    group_value=",".join(sorted(p.dropped)))
    if doc is None:
        return
    first_meta = min((p.element for p in metas if p.element is not None), default=None)
    if first_meta is None:
        return
    for e in doc.elements[:first_meta]:
        if not e.live:
            continue
        if (e.tag == "script" and _classic_or_module(e.get("type"))) or e.tag == "style" or \
                (e.tag == "link" and "stylesheet" in e.tokens("rel")):
            p = next(m for m in metas if m.element == first_meta)
            st.emit("WEB208", r, _ev(ctx, r, p, doc=doc), notes=[_note("meta_late", element=e.tag, line=e.line)],
                    group_value=e.tag)
            break


_JS_MIME = frozenset({"", "module", "importmap", "speculationrules", "text/javascript", "application/javascript",
                      "application/ecmascript", "application/x-ecmascript", "application/x-javascript",
                      "text/ecmascript", "text/javascript1.0", "text/javascript1.1", "text/javascript1.2",
                      "text/javascript1.3", "text/javascript1.4", "text/javascript1.5", "text/jscript",
                      "text/livescript", "text/x-ecmascript", "text/x-javascript"})


def _classic_or_module(type_attr: str | None) -> bool:
    """True for a ``<script>`` the browser runs or interprets (HTML "prepare the script element" step 8); false for
    data blocks such as JSON-LD, which CSP does not govern."""
    if type_attr is None:
        return True
    return type_attr.strip(_ASCII_WS).lower() in _JS_MIME


def _legacy(st: _Run, r: Response, facts: CspFacts) -> None:
    st.seen("WEB217", r.host)
    if not facts.legacy:
        return
    names = list(dict.fromkeys(n for n, _v in facts.legacy))
    notes = [_note("legacy_header", header=n) for n in names]
    no_standard = not facts.enforced
    if no_standard:
        notes.append(_note("legacy_no_standard"))
    st.emit("WEB217", r, _ev(st.ctx, r, name=names[0], value=facts.legacy[0][1]), severity="low" if no_standard else None,
            notes=notes, group_value=",".join(names))


def _syntax(st: _Run, docs) -> None:
    """WEB201/WEB202 on every response of the site, once per (host, policy text)."""
    ctx = st.ctx
    doc_by_id = {id(r): doc for r, doc, _c in docs}
    done: set[tuple[str, str, str]] = set()
    candidates = [r for r, _d, _c in docs] + [r for r in ctx.all_responses() if r.status is not None]
    for r in candidates:
        if not st.own(r) or _kind(r) in SKIP_KINDS or r.host in st.blocked_hosts:
            continue
        facts = st.facts(r, doc_by_id.get(id(r)))
        # report-only policies of a document without an enforced one are judged inside WEB200 (not separately)
        policies = facts.enforced + (facts.report_only if facts.enforced or id(r) not in doc_by_id else [])
        if not policies:
            continue
        st.seen("WEB201", r.host)
        st.seen("WEB202", r.host)
        for p in policies:
            key = (r.host, p.origin, p.raw)
            if key in done:
                continue
            done.add(key)
            doc = doc_by_id.get(id(r))
            errors = list(p.errors)
            hname = "content-security-policy-report-only" if p.origin == "report-only" else "content-security-policy"
            if p.origin != "meta" and f"obs-fold:{hname}" in r.flags:
                # §0.6: http.py unfolds obs-fold before any check and records the fact; a note, never more than info
                errors.append(_err("obs_fold", "", "", "info",
                                   header="Content-Security-Policy" + ("-Report-Only" if p.origin == "report-only" else "")))
            if errors:
                rank = {"info": 0, "low": 1, "medium": 2}
                sev = max((e["severity"] for e in errors), key=rank.__getitem__)
                notes = [_error_note(e) for e in errors[:6]]
                if any(e.get("ineffective") for e in errors):
                    notes.append(_note("err_ineffective"))
                st.emit("WEB201", r, _ev(ctx, r, p, doc=doc), severity=sev, notes=notes,
                        group_value=",".join(sorted({e["code"] + ":" + e["directive"] for e in errors}))[:200])
            if p.duplicates:
                notes = [_note("duplicate", directive=n, value=_short(v, 80) or "(empty)") for n, v in p.duplicates[:6]]
                st.emit("WEB202", r, _ev(ctx, r, p, doc=doc), notes=notes,
                        group_value=",".join(sorted({n for n, _v in p.duplicates})))


def _error_note(e: dict) -> tuple[str, str]:
    code = e["code"]
    d = _short(e.get("directive", ""), 60)
    v = _short(e.get("value", ""), 80)
    if code == "unknown_typo":
        return _note("err_unknown_typo", directive=d, suggest=e.get("suggest", ""))
    if code == "unknown":
        return _note("err_unknown", directive=d)
    if code == "colon":
        return _note("err_colon", directive=d)
    if code == "semicolon":
        return _note("err_semicolon", directive=d, value=v)
    if code == "unquoted":
        return _note("err_unquoted", directive=d, value=v)
    if code == "quoted_host":
        return _note("err_quoted_host", directive=d, value=v)
    if code == "none_combined":
        return _note("err_none_combined", directive=d)
    if code == "bad_hash":
        alg = e.get("alg") or "sha256"
        return _note("err_bad_hash", directive=d, value=v, alg=alg, size=_count(HASH_BYTES.get(alg, 32), _BYTES))
    if code == "bad_nonce":
        return _note("err_bad_nonce", directive=d, value=v)
    if code == "bad_keyword":
        return _note("err_bad_keyword", directive=d, value=v)
    if code == "ip":
        return _note("err_ip", directive=d, value=v)
    if code == "non_ascii":
        return _note("err_non_ascii", value=v)
    if code == "obs_fold":
        return _note("err_obs_fold", header=e.get("header", "Content-Security-Policy"))
    if code == "invalid_value":
        return _note("err_invalid_value", directive=d, value=v)
    return _note("err_invalid_source", directive=d, value=v)


def _static_nonces(st: _Run, docs) -> None:
    """WEB212: the same nonce in two separate fetches (entry, CORS GET, counterpart chain, crawl revisits)."""
    ctx = st.ctx
    cands: list[Response] = []
    seen: set[int] = set()
    for r in [r for r, _d, c in docs if not c] + [ctx.cors, ctx.https_probe, ctx.http_probe]:
        if r is None or id(r) in seen or not st.own(r) or r.host in st.blocked_hosts:
            continue
        seen.add(id(r))
        cands.append(r)
    reported: set[str] = set()
    for i, a in enumerate(cands):
        fa = st.facts(a)
        if not fa.nonces:
            continue
        for b in cands[i + 1:]:
            fb = st.facts(b)
            shared = compare_nonces(a, b, fa, fb)
            if not shared or a.host in reported:
                continue
            reported.add(a.host)
            nonce = _short(shared[0], 40)
            target = a if a.source != "cors" else b
            other = b if target is a else a
            ft = fa if target is a else fb
            pol = next((p for p in ft.enforced if shared[0] in valid_nonces(p)), ft.enforced[0] if ft.enforced else None)
            st.emit("WEB212", target, _ev(ctx, target, pol, doc=st.doc_of(target)),
                    notes=[_note("static_nonce", nonce=nonce, first=_short(target.url, 100),
                                 second=_short(other.url, 100) + f" ({other.source})")], group_value="static")


def _inventory_entry(r: Response, facts: CspFacts, bypass: BypassData | None = None) -> dict:
    def pol(p: CspPolicy) -> dict:
        # unknown directive names and invalid tokens can carry C0 controls / ANSI escapes (§0.6)
        return {"origin": p.origin, "raw": strip_controls(p.raw[:_RAW_CAP]),
                "directives": {strip_controls(k[:100]): [strip_controls(x[:200]) for x in v[:50]]
                               for k, v in list(p.directives.items())[:60]}}
    hosts: dict[str, list[str]] = {}
    for kind, d in (("script", "script-src-elem"), ("style", "style-src-elem"), ("frame", "frame-src"),
                    ("connect", "connect-src")):
        hs: list[str] = []
        for p in facts.enforced:
            for s in effective(p, d) or []:
                if s.kind == "host" and s.host != "*" and s.host not in hs:
                    hs.append(s.host)
        if hs:
            hosts[kind] = hs[:30]
    return {"url": r.url, "policies": [pol(p) for p in facts.enforced[:10]],
            "report_only": [pol(p) for p in facts.report_only[:5]],
            "legacy": [[n, strip_controls(v[:_RAW_CAP])] for n, v in facts.legacy[:5]], "effective": facts.effective,
            "hosts": hosts, "notes": [list(n) for n in policy_notes(facts.enforced, bypass, url_origin(r.url))]}


# ----------------------------------------------------------------------------------------------- i18n

def i18n_catalog() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """``(CATALOG, PATTERNS)`` for cat_web2: fixed Arabic notes → English, and regex patterns for the templated ones."""
    catalog: dict[str, str] = {}
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


__all__ = ["CHECKS", "run", "parse_all", "facts_for", "parse_policy", "parse_header", "split_policies",
           "classify_source", "Source", "effective", "chain", "restricts_scripts", "broad_sources", "is_any",
           "nonce_hash_based", "valid_nonces", "source_matches_url", "list_allows_url", "BypassData", "load_bypass",
           "find_bypasses", "compare_nonces", "response_nonces", "shared_cacheable", "cache_reuses_nonce", "evaluate", "Hit", "DocInfo",
           "policy_notes", "typo_of", "observatory_slug", "observatory_auto", "obs_parse_csp", "effective_summary",
           "meta_policies", "STR", "NEEDS_EVAL", "KNOWN_DIRECTIVES", "DEPRECATED_DIRECTIVES", "i18n_catalog"]
