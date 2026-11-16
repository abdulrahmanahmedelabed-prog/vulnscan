"""Set-Cookie parser, cookie classifier and cookie checks (spec §2.5, §3.3), WP5.

Rules: WEB020–WEB022 and WEB400–WEB414. The module also writes the MDN Observatory v6 ``cookies`` slug into
``ctx.observatory`` (``mdn-http-observatory`` 1.7.2 logic, quirks included) and the §3.9 cookie table into
``ctx.inventory["cookies"]`` (names, classes and attributes; never values).

Shared semantics. Every ``Set-Cookie`` field of every fetched response (redirect hops included) is parsed on its own
(RFC 6265bis §5.6): split on ``;``; the first pair is name=value (no ``=`` → empty name); attributes are case-insensitive
names with an optional ``=value``, trimmed; the last valid occurrence of an attribute wins; never a substring test (fixes
D3). A field with control characters, or with neither name nor value, is ignored like a browser ignores it. Deletion
cookies (``Max-Age<=0`` or ``Expires`` in the past, fixes D4) and names on the user's ignore list are flagged on the
fact and skipped by every rule. Cookies are judged on the scanned site's own responses (same registrable domain as the
target or the final entry host); third-party hosts and WAF/rate-limit pages are not the owner's cookies. One finding per
(rule, cookie name, host), whichever response set it.

Classification (§3.3): the table of ``data/web/cookies.json`` (exact names, then globs, most specific first), then the
name-word heuristics, then the value shape, then ``unknown``. ``unknown_secret`` (a long random-looking value) is judged
with the session/auth severities at confidence ``tentative`` at paranoid sensitivity, and as ``unknown`` otherwise.

A cookie the browser rejects (WEB400, WEB401, WEB403, WEB404 rejected domain, WEB408, WEB410) gets only the rejection
finding: the quality rules (Secure, HttpOnly, SameSite, lifetime …) would describe a cookie that never exists. Facts
about the value itself (WEB411, WEB412, WEB413, WEB414) are reported in every case, because the value was sent.

Inputs read from the context, never recomputed through another check module (§4.2): ``ctx.cookies`` (stage 1, this
module's :func:`parse_and_classify`; recomputed locally when a test leaves it empty), ``ctx.hsts`` (the HSTS verdict per
host, WEB020 mitigation) and ``Response.kind``. Pure: nothing here touches the network.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import ipaddress
import json
import math
import re
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from . import data as _data
from . import psl
from .rules import PLURAL_PARAMS, RULES, SEVERITIES, checks_for_module
from .types import (
    SESSION_CLASSES,
    CookieFact,
    Evidence,
    Issue,
    Response,
    ScanContext,
    redact_cookie_header,
    redact_secret,
    strip_controls,
)

CHECKS: tuple[str, ...] = checks_for_module("cookies")

# ----------------------------------------------------------------------------------------------- user-facing text

# (en, ar) note templates. ``{name}`` values may come from the scanned site, so they are filled by plain substitution
# (:func:`_note`), never ``str.format``: a value with braces cannot break or inject a format string (§0.6).
STR: dict[str, tuple[str, str]] = {
    "class": ("Classified as {cls} ({how}).", "صُنّفت على أنها {cls} ({how})."),
    "secret_guess": ("The name is not a known session cookie, but the value looks like a random token; confirm whether "
                     "it identifies a session.",
                     "الاسم ليس اسم كوكي جلسة معروفًا، لكن القيمة تبدو رمزًا عشوائيًا؛ تحقّق مما إذا كانت تعرّف جلسة."),
    "hsts_mitigates": ("HSTS on {scope} keeps browsers on HTTPS, which limits the exposure; before the first HTTPS visit "
                       "the cookie can still travel over plain HTTP unless the domain is preloaded.",
                       "تُبقي HSTS على {scope} المتصفح على HTTPS فيحدّ ذلك من الخطر؛ لكن قبل أول زيارة عبر HTTPS قد "
                       "تنتقل الكوكي عبر HTTP غير مشفّر ما لم يكن النطاق مُدرجًا مسبقًا."),
    "no_hsts": ("No HSTS policy covers {scope}, so a network attacker can make the browser send this cookie over plain "
                "HTTP.",
                "لا تغطي أي سياسة HSTS {scope}، فيستطيع مهاجم على الشبكة جعل المتصفح يرسل هذه الكوكي عبر HTTP غير مشفّر."),
    "prefix_secure": ("{prefix} cookies must carry the Secure attribute; browsers reject this one.",
                      "يجب أن تحمل كوكيز {prefix} السمة Secure؛ لذلك يرفض المتصفح هذه الكوكي."),
    "prefix_http": ("{prefix} cookies can only be set by an HTTPS response; browsers reject this one.",
                    "لا تُضبط كوكيز {prefix} إلا من استجابة HTTPS؛ لذلك يرفض المتصفح هذه الكوكي."),
    "prefix_domain": ("{prefix} cookies must not carry a Domain attribute (Domain={value}); browsers reject this one.",
                      "يجب ألا تحمل كوكيز {prefix} السمة Domain (القيمة Domain={value})؛ لذلك يرفض المتصفح هذه الكوكي."),
    "prefix_path": ("{prefix} cookies must carry Path=/ (found: {value}); browsers reject this one.",
                    "يجب أن تحمل كوكيز {prefix} السمة Path=/ (الموجود: {value})؛ لذلك يرفض المتصفح هذه الكوكي."),
    "prefix_httponly": ("{prefix} cookies must carry the HttpOnly attribute; browsers reject this one.",
                        "يجب أن تحمل كوكيز {prefix} السمة HttpOnly؛ لذلك يرفض المتصفح هذه الكوكي."),
    "samesite_none": ("SameSite=None without Secure: browsers reject the cookie.",
                      "SameSite=None بلا Secure: يرفض المتصفح الكوكي."),
    "samesite_invalid": ("SameSite={value} is not Strict, Lax or None; browsers ignore it and apply their default.",
                         "القيمة SameSite={value} ليست Strict ولا Lax ولا None؛ فيتجاهلها المتصفح ويطبّق سلوكه "
                         "الافتراضي."),
    "partitioned": ("Partitioned without Secure: browsers reject the cookie (CHIPS).",
                    "Partitioned بلا Secure: يرفض المتصفح الكوكي (CHIPS)."),
    "domain_suffix": ("Domain={value} is a public suffix; browsers reject the cookie.",
                      "القيمة Domain={value} لاحقة عامة؛ فيرفض المتصفح الكوكي."),
    "domain_mismatch": ("Domain={value} does not match the host {host}; browsers reject the cookie.",
                        "القيمة Domain={value} لا تطابق المضيف {host}؛ فيرفض المتصفح الكوكي."),
    "domain_parent": ("Domain={value} sends this session cookie to every host under {value}, so any of them can read "
                      "or overwrite it.",
                      "القيمة Domain={value} ترسل كوكي الجلسة هذه إلى كل مضيف تحت {value}، فيستطيع أيٌّ منها قراءتها أو "
                      "استبدالها."),
    "lifetime": ("Lifetime: {days}.", "مدة البقاء: {days}."),
    "clamp": ("Browsers cap cookie lifetimes at 400 days.", "تحدّ المتصفحات عمر الكوكي بـ 400 يوم."),
    "duplicate": ("Set {times} in one response with different values or attributes; the browser keeps the last one.",
                  "ضُبطت {times} في استجابة واحدة بقيم أو سمات مختلفة؛ ويحتفظ المتصفح بآخرها."),
    "size": ("Name and value take {size} bytes; browsers ignore cookies above 4096 bytes.",
             "يبلغ حجم الاسم والقيمة {size} بايت؛ ويتجاهل المتصفح الكوكي التي تتجاوز 4096 بايت."),
    "host_prefix": ("Host-only session cookie without the __Host- prefix.",
                    "كوكي جلسة خاصة بالمضيف بلا البادئة __Host-."),
    "secure_http": ("The Secure attribute cannot be set by a plain-HTTP response; browsers reject this cookie.",
                    "لا يمكن لاستجابة HTTP غير مشفّرة ضبط السمة Secure؛ لذلك يرفض المتصفح هذه الكوكي."),
    "bigip": ("The value decodes to the internal address {address}.",
              "تكشف القيمة بعد فك ترميزها العنوان الداخلي {address}."),
    "jwt_none": ("The value is a JWT with alg=none: it is not signed, so its claims can be forged.",
                 "القيمة رمز JWT بالخوارزمية alg=none: أي أنه غير موقّع، فيمكن تزوير محتواه."),
    "password_key": ("The decoded value contains the field {key}.", "تحتوي القيمة بعد فك ترميزها على الحقل {key}."),
    "pii": ("The decoded value contains personal data fields: {claims}.",
            "تحتوي القيمة بعد فك ترميزها على حقول بيانات شخصية: {claims}."),
    "over_http": ("Set by the plain-HTTP response {url}.", "ضُبطت في استجابة HTTP غير مشفّرة: {url}."),
    "echo": ("The session value appears in {where} of {url}.", "تظهر قيمة الجلسة في {where} ضمن {url}."),
    "responses": ("Set by {responses}.", "ضُبطت في {responses}."),
    "same_site_none_partitioned": ("Partitioned limits it to the embedding site.",
                                   "السمة Partitioned تحصرها في الموقع المضمِّن."),
}

CLASS_NAMES: dict[str, tuple[str, str]] = {
    "session": ("a session cookie", "كوكي جلسة"),
    "auth": ("an authentication cookie", "كوكي مصادقة"),
    "csrf": ("an anti-CSRF token", "رمز مضاد لـ CSRF"),
    "preference": ("a preference cookie", "كوكي تفضيلات"),
    "analytics": ("an analytics cookie", "كوكي تحليلات"),
    "lb": ("a load-balancer cookie", "كوكي موازن حمل"),
    "cdn_bot": ("a CDN or bot-protection cookie", "كوكي شبكة توزيع محتوى أو حماية من البوتات"),
    "consent": ("a consent cookie", "كوكي موافقة"),
    "unknown": ("an unknown cookie", "كوكي غير معروفة"),
    "unknown_secret": ("an unknown cookie with a random-looking value", "كوكي غير معروفة بقيمة تبدو عشوائية"),
}
HOW_NAMES: dict[str, tuple[str, str]] = {
    "table": ("known cookie name", "اسم كوكي معروف"),
    "heuristic": ("name pattern", "نمط الاسم"),
    "value": ("value shape", "شكل القيمة"),
    "default": ("no known pattern", "لا يطابق نمطًا معروفًا"),
}
WHERE_NAMES: dict[str, tuple[str, str]] = {
    "script": ("an inline script", "سكربت مضمَّن"),
    "data": ("a data-* attribute", "سمة data-*"),
    "hidden": ("a hidden form field", "حقل نموذج مخفي"),
    "meta": ("a meta tag", "وسم meta"),
    "attribute": ("an HTML attribute", "سمة HTML"),
    "content": ("the page content", "محتوى الصفحة"),
    "script_file": ("the script file", "ملف السكربت"),
}
# Arabic count phrases (one, two, few, many, other) for vulnscan.i18n.plural.ar_count
_TIMES = ("{n} time", "{n} times", ("مرة واحدة", "مرتين", "{n} مرات", "{n} مرةً", "{n} مرة"))
_RESPONSES = ("{n} response", "{n} responses", ("استجابة واحدة", "استجابتين", "{n} استجابات", "{n} استجابةً",
                                                 "{n} استجابة"))


def _count(n: int, forms: tuple[str, str, tuple[str, ...]]) -> tuple[str, str]:
    from ..i18n.plural import ar_count   # lazy: vulnscan.i18n may import webscan modules
    en = (forms[0] if n == 1 else forms[1]).replace("{n}", str(n))
    return en, ar_count(n, forms[2])


def _clean(value: Any, limit: int = 120) -> str:
    s = strip_controls(str(value))
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _shown_name(f: Any, limit: int = 120) -> str:
    """The cookie name for titles and evidence; a nameless cookie (``Set-Cookie: token``, 6265bis) is shown as ``""``
    so the ``{cookie}`` title parameter is never empty."""
    return _clean(f.name, limit) or '""'


_PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")


def _note(which: str, /, **values: Any) -> tuple[str, str]:
    """``(en, ar)`` of ``STR[which]`` with ``{name}`` filled literally (no ``str.format``; values are site data). A
    value may be a plain string or an ``(en, ar)`` pair."""
    en, ar = STR[which]

    def fill(text: str, lang: str) -> str:
        def sub(m: re.Match) -> str:
            v = values.get(m.group(1), m.group(0))
            if isinstance(v, tuple):
                v = v[1] if lang == "ar" else v[0]
            return _clean(v, 300)                         # §0.6: no terminal escapes from the target in notes
        return _PLACEHOLDER.sub(sub, text)
    return fill(en, "en"), fill(ar, "ar")


def i18n_catalog() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """``(CATALOG, PATTERNS)`` for cat_web2: fixed Arabic notes → English, and regex patterns for the templated ones
    (a repeated placeholder becomes a back-reference). The bilingual fragments (class names …) are catalogue entries."""
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
    for table in (CLASS_NAMES, HOW_NAMES, WHERE_NAMES):
        for en, ar in table.values():
            catalog.setdefault(ar, en)
    return catalog, patterns


# ----------------------------------------------------------------------------------------------- parsing (6265bis)

_CTL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_MAX_AGE = re.compile(r"-?[0-9]+")
_MONTHS = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov",
                                      "dec"), start=1)}
_DELIM = re.compile(r"[\x09\x20-\x2f\x3b-\x40\x5b-\x60\x7b-\x7e]+")
MAX_ATTR_VALUE = 1024        # 6265bis: longer attribute values are ignored
MAX_NAME_VALUE = 4096        # 6265bis: longer name+value pairs are ignored (WEB408)
DAY = 86400
SESSION_LIFETIME_DAYS = 30   # WEB405 low
CLAMP_DAYS = 400             # WEB405 info: browsers cap Expires/Max-Age at 400 days
MAX_LIFETIME = 10 ** 12      # seconds; far above the clamp, small enough for float()


def parse_cookie_date(value: str) -> datetime | None:
    """RFC 6265bis §5.1.1 cookie-date → aware UTC datetime (None when it does not parse)."""
    hms = day = month = year = None
    for tok in _DELIM.split(value):
        if not tok:
            continue
        if hms is None:
            m = re.fullmatch(r"(\d{1,2}):(\d{1,2}):(\d{1,2})(?:\D.*)?", tok, re.A | re.S)
            if m:
                hms = tuple(int(x) for x in m.groups())
                continue
        if day is None:
            m = re.fullmatch(r"(\d{1,2})(?:\D.*)?", tok, re.A | re.S)
            if m:
                day = int(m.group(1))
                continue
        if month is None and tok[:3].lower() in _MONTHS:
            month = _MONTHS[tok[:3].lower()]
            continue
        if year is None:
            m = re.fullmatch(r"(\d{2,4})(?:\D.*)?", tok, re.A | re.S)
            if m:
                year = int(m.group(1))
                if 70 <= year <= 99:
                    year += 1900
                elif year <= 69:
                    year += 2000
                continue
    if hms is None or day is None or month is None or year is None:
        return None
    if not 1 <= day <= 31 or year < 1601 or hms[0] > 23 or hms[1] > 59 or hms[2] > 59:
        return None
    try:
        return datetime(year, month, day, hms[0], hms[1], hms[2], tzinfo=timezone.utc)
    except ValueError:
        return None


@dataclass(frozen=True)
class ParsedCookie:
    name: str
    value: str
    attrs: dict[str, str]           # lower-cased names → value ("" for flags); last valid occurrence wins
    expires: datetime | None
    max_age: int | None


def parse_set_cookie(raw: str) -> ParsedCookie | None:
    """One ``Set-Cookie`` field per RFC 6265bis §5.6; None when a browser would ignore the whole field (control
    characters, or neither name nor value)."""
    if _CTL.search(raw):
        return None
    pair, _sep, rest = raw.partition(";")
    if "=" in pair:
        name, _eq, value = pair.partition("=")
    else:
        name, value = "", pair
    name, value = name.strip(" \t"), value.strip(" \t")
    if not name and not value:
        return None
    attrs: dict[str, str] = {}
    expires: datetime | None = None
    max_age: int | None = None
    for av in rest.split(";") if rest else ():
        an, _eq, aval = av.partition("=")
        an, aval = an.strip(" \t").lower(), aval.strip(" \t")
        if not an or len(aval.encode("utf-8", "replace")) > MAX_ATTR_VALUE:
            continue
        if an == "expires":
            when = parse_cookie_date(aval)
            if when is None:
                continue
            expires = when
        elif an == "max-age":
            if not _MAX_AGE.fullmatch(aval):
                continue
            max_age = int(aval)
        elif an == "domain":
            if not aval:
                continue
        elif an in ("secure", "httponly", "partitioned"):
            aval = ""
        attrs[an] = aval
    return ParsedCookie(name, value, attrs, expires, max_age)


def default_path(url: str) -> str:
    """RFC 6265bis §5.1.4 default-path of a request URL."""
    path = urllib.parse.urlsplit(url).path
    if not path.startswith("/") or path.count("/") == 1:
        return "/"
    return path[: path.rfind("/")]


def cookie_path(fact: CookieFact) -> str:
    p = fact.attrs.get("path")
    return p if p and p.startswith("/") else default_path(fact.response.url)


def lifetime_seconds(fact: CookieFact, now: datetime) -> float | None:
    """Seconds until the cookie expires (Max-Age wins over Expires); None for a non-persistent cookie."""
    if fact.max_age is not None:
        # clamp before float(): a 1024-digit Max-Age would raise OverflowError (hostile input, §0.6)
        return float(max(-MAX_LIFETIME, min(fact.max_age, MAX_LIFETIME)))
    if fact.expires is not None:
        return (fact.expires - now).total_seconds()
    return None


# ----------------------------------------------------------------------------------------------- classification

_JWT = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.")
_PREF_VALUES = frozenset({"0", "1", "true", "false", "on", "off", "yes", "no", "light", "dark"})
_PREFIXES = ("__host-http-", "__http-", "__host-", "__secure-")
SECRET_MIN_LENGTH = 16
SECRET_MIN_ENTROPY = 3.5


def name_words(name: str) -> list[str]:
    """Words of a cookie name: split on ``_ . -``, any other punctuation, digits and camelCase; lower-cased."""
    s = re.sub(r"([a-z])([A-Z])", r"\1 \2", name)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", s)
    return [w.lower() for w in re.split(r"[^A-Za-z]+", s) if w]


def strip_prefix(name: str) -> str:
    low = name.lower()
    for p in _PREFIXES:
        if low.startswith(p):
            return name[len(p):]
    return name


def cookie_prefix(name: str) -> str:
    """The cookie-name prefix (``__Host-`` …, canonical case) or ""; matched case-insensitively."""
    low = name.lower()
    for p, canon in (("__host-http-", "__Host-Http-"), ("__http-", "__Http-"), ("__host-", "__Host-"),
                     ("__secure-", "__Secure-")):
        if low.startswith(p):
            return canon
    return ""


def heuristic_class(name: str) -> str | None:
    """§3.3 name heuristics (word-bounded, so ``sidebar_state``, ``consider``, ``author_pref`` stay unknown)."""
    low = name.lower()
    if "csrf" in low or "xsrf" in low:
        return "csrf"
    words = name_words(name)
    for w in words:
        if w.startswith("sess") or w in ("sid", "login") or w.endswith(("session", "sessid", "sessionid")):
            return "session"
    for w in words:
        if w in ("auth", "token", "jwt", "remember"):
            return "auth"
    return None


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in Counter(value).values())


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def value_class(value: str) -> str | None:
    v = _unquote(value)
    if _JWT.match(v):
        return "auth"
    low = v.lower()
    if low in _PREF_VALUES or re.fullmatch(r"[a-z]{2}", low):
        return "preference"
    if len(v) >= SECRET_MIN_LENGTH and shannon_entropy(v) >= SECRET_MIN_ENTROPY and not _plain_json(v):
        return "unknown_secret"
    return None


def _plain_json(value: str) -> bool:
    """A readable JSON object/array (raw or URL-encoded), e.g. a consent or device-detection cookie: structured data,
    not a random token, even though percent-escapes push its character entropy above the threshold."""
    for cand in (value, urllib.parse.unquote(value)) if "%" in value else (value,):
        c = cand.strip()
        if c[:1] in ("{", "[") and isinstance(_json_loads(c), (dict, list)):
            return True
    return False


class ClassTable:
    """The exact/glob table of ``cookies.json``: exact names first, then globs, most literal characters first.

    Imported (non-``kashif``) globs are *weak*: an Open Cookie Database pattern such as ``data-*``, ``partner-*`` or
    ``recs-*`` (ad-tech vendors) must not turn the site's own ``data-session`` or ``partner-auth-token`` into an
    analytics cookie, so the name heuristics win over a weak glob for session/auth/csrf (:func:`classify`). Exact
    imported names were already filtered by the same heuristics when the table was built."""

    def __init__(self, entries: Iterable[dict]):
        self.exact: dict[str, str] = {}
        globs: list[tuple[int, int, re.Pattern, str, bool]] = []
        for i, e in enumerate(entries):
            name, cls = str(e.get("name", "")), str(e.get("class", ""))
            if not name or not cls:
                continue
            if e.get("match") == "glob" or "*" in name or "?" in name:
                literal = len(name.replace("*", "").replace("?", ""))
                weak = str(e.get("source", "kashif")) != "kashif"
                globs.append((-literal, i, re.compile(fnmatch.translate(name.lower()), re.S), cls, weak))
            else:
                self.exact.setdefault(name.lower(), cls)
        globs.sort(key=lambda g: (g[0], g[1]))
        self.globs = [(rx, cls) for _l, _i, rx, cls, _w in globs]
        self._weak = [w for _l, _i, _rx, _c, w in globs]

    def match(self, name: str) -> tuple[str, bool] | None:
        """``(class, weak)`` of the best entry for ``name`` (weak: an imported glob), or None."""
        low = name.lower()
        cls = self.exact.get(low)
        if cls:
            return cls, False
        for (rx, c), weak in zip(self.globs, self._weak):
            if rx.match(low):
                return c, weak
        return None

    def lookup(self, name: str) -> str | None:
        hit = self.match(name)
        return hit[0] if hit else None


_TABLES: dict[int, tuple[Any, ClassTable]] = {}


def class_table(source: Any = None) -> ClassTable:
    """The classification table from ``source.load_json("cookies.json")`` (default: the bundled data loader)."""
    loader = source if source is not None and hasattr(source, "load_json") else _data
    try:
        obj = loader.load_json("cookies.json")
        entries = obj.get("entries", []) if isinstance(obj, dict) else []
    except (OSError, ValueError, KeyError):
        entries = []
    key = id(entries)
    hit = _TABLES.get(key)
    if hit is None or hit[0] is not entries:
        hit = (entries, ClassTable(entries))
        _TABLES.clear()
        _TABLES[key] = hit
    return hit[1]


def classify(name: str, value: str, table: ClassTable | None = None) -> tuple[str, str]:
    """``(class, source)`` per §3.3: table → name heuristics → value shape → ``unknown``. Prefixes (``__Host-`` …) are
    ignored for the lookup (``__Host-sid`` is ``sid``)."""
    table = table if table is not None else class_table()
    bare = strip_prefix(name)
    heuristic = heuristic_class(bare) if bare else None
    for candidate in dict.fromkeys((name, bare)):
        hit = table.match(candidate) if candidate else None
        if hit:
            cls, weak = hit
            if weak and heuristic in ("session", "auth", "csrf") and cls not in SESSION_CLASSES:
                return heuristic, "heuristic"
            return cls, "table"
    if heuristic:
        return heuristic, "heuristic"
    cls = value_class(value)
    if cls:
        return cls, "value"
    return "unknown", "default"


def _ignored(name: str, patterns: Iterable[str]) -> bool:
    low = name.lower()
    for p in patterns:
        p = (p or "").strip().lower()
        if p and (low == p or (("*" in p or "?" in p) and fnmatch.fnmatchcase(low, p))):
            return True
    return False


# ----------------------------------------------------------------------------------------------- stage 1

def parse_and_classify(ctx: ScanContext) -> list[CookieFact]:
    """Stage 1 (pure): every ``Set-Cookie`` field of every fetched response (redirect hops included), parsed per
    RFC 6265bis §5.6 and classified per §3.3 (deletion cookies and ``options.cookie_ignore`` names flagged)."""
    table = class_table(ctx.data)
    ignore = tuple(ctx.options.cookie_ignore or ())
    now = ctx.now
    facts: list[CookieFact] = []
    for r in ctx.all_responses():
        for index, raw in enumerate(r.headers.get_all("set-cookie")):
            p = parse_set_cookie(raw)
            if p is None:
                continue
            cls, source = classify(p.name, p.value, table)
            deletion = (p.max_age <= 0) if p.max_age is not None else (p.expires is not None and p.expires <= now)
            facts.append(CookieFact(name=p.name, value=p.value, attrs=dict(p.attrs), raw=raw, response=r, host=r.host,
                                    secure_context=r.is_https, cls=cls, class_source=source, deletion=deletion,
                                    ignored=_ignored(p.name, ignore), index=index, expires=p.expires,
                                    max_age=p.max_age))
    return facts


# ----------------------------------------------------------------------------------------------- value decoders

_BIGIP_V4 = re.compile(r"^(\d{1,10})\.(\d{1,5})\.0000$", re.A)
_BIGIP_RD_V4 = re.compile(r"^rd\d+o0{20}ffff([0-9a-f]{8})o(\d{1,5})$", re.I | re.A)
_BIGIP_V6 = re.compile(r"^vi([0-9a-f]{32})\.(\d{1,5})$", re.I | re.A)
_BIGIP_RD_V6 = re.compile(r"^rd\d+o([0-9a-f]{32})o(\d{1,5})$", re.I | re.A)


def decode_bigip(value: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int] | None:
    """F5 BIG-IP persistence cookie (unencrypted) → (address, port); None for anything else (K6917)."""
    v = _unquote(value).strip()
    m = _BIGIP_V4.match(v)
    if m:
        ip_int, port_int = int(m.group(1)), int(m.group(2))
        if ip_int > 0xFFFFFFFF or port_int > 0xFFFF:
            return None
        ip = ipaddress.IPv4Address(ip_int.to_bytes(4, "little"))
        return ip, ((port_int & 0xFF) << 8) | (port_int >> 8)
    m = _BIGIP_RD_V4.match(v)
    if m:
        port = int(m.group(2))
        return (ipaddress.IPv4Address(bytes.fromhex(m.group(1))), port) if port <= 0xFFFF else None
    m = _BIGIP_V6.match(v)
    if m:
        port_int = int(m.group(2))
        if port_int > 0xFFFF:
            return None
        return ipaddress.IPv6Address(bytes.fromhex(m.group(1))), ((port_int & 0xFF) << 8) | (port_int >> 8)
    m = _BIGIP_RD_V6.match(v)
    if m:
        port = int(m.group(2))
        return (ipaddress.IPv6Address(bytes.fromhex(m.group(1))), port) if port <= 0xFFFF else None
    return None


MAX_JSON = 8192


def _json_loads(text: str) -> Any:
    """``json.loads`` for site data: None for invalid JSON, over-long text or nesting deep enough to raise
    RecursionError (``[[[[…`` in a cookie value crashes 3.10/3.11 at ~1000 levels, §0.6)."""
    if len(text) > MAX_JSON:
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def _b64json(segment: str) -> Any:
    """base64/base64url → JSON (None when it is not JSON). Decoding only; nothing is verified or altered."""
    s = segment.strip()
    if not s or len(s) > 8192 or not re.fullmatch(r"[A-Za-z0-9_\-+/]+=*", s):
        return None
    try:
        raw = base64.urlsafe_b64decode(s.replace("+", "-").replace("/", "_").rstrip("=") + "=" * (-len(s.rstrip("=")) % 4))
    except (binascii.Error, ValueError):
        return None
    raw = raw.strip()
    if not raw.startswith((b"{", b"[")):
        return None
    try:
        return _json_loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        return None


def jwt_parts(value: str) -> tuple[dict, Any] | None:
    """``(header, payload)`` of a JWT-shaped value (payload None when it is not JSON). Decoding only."""
    v = _unquote(urllib.parse.unquote(value)).strip()
    if v.lower().startswith("bearer "):
        v = v[7:].strip()
    if not _JWT.match(v):
        return None
    head, payload = v.split(".")[:2]
    header = _b64json(head)
    if not isinstance(header, dict):
        return None
    return header, _b64json(payload)


_PASSWORD_WORDS = frozenset({"password", "passwd", "passwort", "pwd", "pass", "passphrase"})
PII_KEYS = frozenset({"email", "email_address", "mail", "phone", "phone_number", "mobile", "msisdn", "address",
                      "street_address", "birthdate", "date_of_birth", "dob", "ssn", "national_id", "passport",
                      "passport_number", "tax_id", "iban", "card_number", "credit_card", "cc_number"})


def _password_key(key: str) -> bool:
    """``password``, ``user_pass``, ``userPassword``, ``login.pwd`` …: the last word of the key names a password
    (``has_password`` is caught too, so the value decides: :func:`_has_data`)."""
    words = name_words(key)
    return bool(words) and words[-1] in _PASSWORD_WORDS


def _has_data(value: Any) -> bool:
    """A field that carries data, not a flag: ``{"has_password": true}`` or ``{"mobile": false}`` are not secrets."""
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return abs(value) >= 1000                      # phone numbers, PINs, ids; not 0/1 flags
    if isinstance(value, str):
        return value.strip().lower() not in ("", "true", "false", "null", "none", "0", "1", "yes", "no")
    return bool(value)


def _walk_keys(obj: Any, depth: int = 0) -> Iterable[tuple[str, Any]]:
    if depth > 4:
        return
    if isinstance(obj, dict):
        for k, v in list(obj.items())[:200]:
            yield str(k), v
            yield from _walk_keys(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj[:50]:
            yield from _walk_keys(v, depth + 1)


def _json_value(value: str) -> Any:
    """JSON carried in a cookie value: raw, URL-encoded, base64 or the first segment of a signed value."""
    v = _unquote(value).strip()
    for cand in dict.fromkeys((v, urllib.parse.unquote(v))):
        c = cand.strip()
        if c.startswith(("{", "[")):
            obj = _json_loads(c)
            if obj is not None:
                return obj
        first = c.lstrip(".").split(".", 1)[0]
        obj = _b64json(first)
        if obj is not None:
            return obj
    return None


def sensitive_value(value: str) -> tuple[str, list[tuple[str, str]], str] | None:
    """WEB412: ``(severity, notes, group value)`` when the value carries an unsigned JWT, a password field or personal
    data; None otherwise. Only names of fields are reported, never their values."""
    jwt = jwt_parts(value)
    payload: Any = None
    notes: list[tuple[str, str]] = []
    severity = group = ""
    if jwt is not None:
        header, payload = jwt
        if "alg" not in header and "typ" not in header:
            # itsdangerous (Flask session) "payload.timestamp.signature": the first segment is the data itself
            header, payload = {}, header
        if str(header.get("alg", "")).strip().lower() == "none":
            severity, group = "medium", "jwt-none"
            notes.append(_note("jwt_none"))
    else:
        payload = _json_value(value)
    if payload is None and not severity:
        return None
    pw = sorted({_clean(k, 60) for k, v in _walk_keys(payload) if _password_key(k) and _has_data(v)})
    if pw:
        severity, group = "medium", group or "password"
        notes.append(_note("password_key", key=", ".join(pw[:5])))
    pii = sorted({_clean(k, 60) for k, v in _walk_keys(payload) if k.lower() in PII_KEYS and _has_data(v)})
    if pii:
        severity, group = severity or "low", group or "pii"
        notes.append(_note("pii", claims=", ".join(pii[:8])))
    if not severity:
        return None
    return severity, notes, group


# ----------------------------------------------------------------------------------------------- HSTS mitigation

def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]").split("%", 1)[0])
        return True
    except ValueError:
        return False


def _hsts_ok(ctx: ScanContext, host: str, *, subdomains: bool) -> bool:
    """True when a recorded HSTS verdict covers ``host`` (and, with ``subdomains``, every host below it): the host's own
    verdict (effective, or preloaded), or an ancestor's effective verdict with includeSubDomains. A preload entry of
    unknown subtree is not taken as covering subdomains."""
    v = ctx.hsts_for(host)
    if v is not None:
        if subdomains and v.effective and v.include_subdomains:
            return True
        if not subdomains and (v.effective or v.preloaded):
            return True
    if _is_ip(host):                                   # an IP literal has no parent domain
        return False
    labels = host.split(".")
    for i in range(1, len(labels)):
        pv = ctx.hsts_for(".".join(labels[i:]))
        if pv is not None and pv.effective and pv.include_subdomains:
            return True
    return False


def hsts_protects(ctx: ScanContext, fact: CookieFact) -> tuple[bool, str]:
    """``(protected, scope)``: HSTS covers every host the cookie is sent to (the host for a host-only cookie; the Domain
    and all hosts under it otherwise; §2.5 WEB020)."""
    domain = fact.domain
    if not domain:
        return _hsts_ok(ctx, fact.host, subdomains=False), fact.host
    return _hsts_ok(ctx, domain, subdomains=True), f"{domain} (*.{domain})"


# ----------------------------------------------------------------------------------------------- body exposure

_SCRIPT_OPEN = re.compile(r"<script\b", re.I)
_SCRIPT_CLOSE = re.compile(r"</script\s*>", re.I)
_TAG_OPEN = re.compile(r"<([a-zA-Z][a-zA-Z0-9-]*)\b[^<>]*$", re.S)
_ATTR_BEFORE = re.compile(r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*[\"']?[^\"'<>]*$", re.S)


def exposure_context(text: str, offset: int, *, script_file: bool = False) -> str:
    """Where a value found at ``offset`` sits: script, data, hidden, meta, attribute, content or script_file."""
    if script_file:
        return "script_file"
    before = text[max(0, offset - 4000):offset]
    opens = [m.end() for m in _SCRIPT_OPEN.finditer(before)]
    closes = [m.end() for m in _SCRIPT_CLOSE.finditer(before)]
    if opens and (not closes or opens[-1] > closes[-1]):
        return "script"
    tag = _TAG_OPEN.search(before[-2000:])
    if tag:
        name = tag.group(1).lower()
        attr = _ATTR_BEFORE.search(tag.group(0))
        attr_name = attr.group(1).lower() if attr else ""
        if attr_name.startswith("data-"):
            return "data"
        if name == "input" and re.search(r"type\s*=\s*[\"']?hidden", tag.group(0), re.I):
            return "hidden"
        if name == "meta":
            return "meta"
        return "attribute"
    return "content"


_OPAQUE_OK = (None, "", "identity", "gzip", "x-gzip", "deflate")


def _readable(r: Response) -> bool:
    return bool(r.body) and (r.encoding or "").lower() in _OPAQUE_OK and "opaque-coding" not in r.flags \
        and r.error is None


def _request_has(r: Response, name: str, value: str) -> bool:
    for header in r.request_headers.get_all("cookie"):
        for pair in header.split(";"):
            n, _eq, v = pair.strip().partition("=")
            if n == name and v == value:
                return True
    return False


# ----------------------------------------------------------------------------------------------- Observatory

OBS_GOODNESS = ("cookies-without-secure-flag-but-protected-by-hsts", "cookies-without-secure-flag",
                "cookies-session-without-secure-flag-but-protected-by-hsts", "cookies-samesite-flag-invalid",
                "cookies-anticsrf-without-samesite-flag", "cookies-session-without-httponly-flag",
                "cookies-session-without-secure-flag")
OBS_HSTS_SIX_MONTHS = 15_552_000


def observatory_auto(ctx: ScanContext) -> Response | None:
    """Observatory's ``responses.auto``: the https session's final response when https answered, else http's."""
    for r in (ctx.entry, ctx.https_probe, ctx.http_probe):
        if r is not None and r.is_https and r.status is not None and not r.error:
            return r
    for r in (ctx.entry, ctx.http_probe):
        if r is not None and r.status is not None and not r.error:
            return r
    return None


def _js_parse_int(s: str) -> int | None:
    m = re.match(r"\s*([+-]?[0-9]+)", s)            # JS: Unicode whitespace, ASCII digits
    return int(m.group(1)) if m else None


def observatory_hsts_pass(ctx: ScanContext) -> bool:
    """Observatory's HSTS test ``pass`` (used by its cookie test): ``ctx.observatory`` when WP6 already wrote it, else
    the same algorithm on the https response (first header, 1024 characters, comma → invalid, ``parseInt`` max-age so a
    quoted value passes, < 180 days fails, preload overrides)."""
    slug = ctx.observatory.get("strict-transport-security")
    if slug:
        return slug in ("hsts-preloaded", "hsts-implemented-max-age-at-least-six-months")
    https = ctx.entry if ctx.entry is not None and ctx.entry.is_https else ctx.https_probe
    if https is None or https.status is None or https.error:
        return False
    verdict = ctx.hsts_for(https.host)
    if verdict is not None and verdict.preloaded:
        return True
    if verdict is not None and verdict.cert_error:
        return False
    header = https.headers.first("strict-transport-security")
    if header is None:
        return False
    header = header[:1024]
    if "," in header:
        return False
    max_age = None
    found = False
    for part in header.split(";"):
        p = part.strip().lower()
        if p.startswith("max-age="):
            found = True
            max_age = _js_parse_int(p[8:128])
    if not found:
        return False
    return max_age is None or max_age >= OBS_HSTS_SIX_MONTHS     # NaN < x is false in JS: a quoted max-age passes


def _obs_samesite(attrs: dict[str, str]) -> str | None:
    v = attrs.get("samesite")
    if v is None:
        return None
    v = v.lower()
    return v if v in ("strict", "lax", "none") else None


def _obs_invalid_samesite(raw: str) -> bool:
    for part in raw.strip().split(";"):
        bits = part.strip().split("=")
        if not bits[0] or bits[0].strip().lower() != "samesite":
            continue
        value = bits[1] if len(bits) > 1 else ""
        if not value or value.strip().lower() not in ("lax", "strict", "none"):
            return True
    return False


def observatory_slug(ctx: ScanContext, facts: list[CookieFact] | None = None) -> str:
    """The Observatory v6 ``cookies`` result (mdn-http-observatory 1.7.2 ``cookies.js``)."""
    auto = observatory_auto(ctx)
    facts = ctx.cookies if facts is None else facts
    result: str | None = None

    def worse(new: str) -> None:
        nonlocal result
        if result is None or result not in OBS_GOODNESS or OBS_GOODNESS.index(new) > OBS_GOODNESS.index(result):
            result = new

    if auto is not None:
        for raw in auto.headers.get_all("set-cookie"):
            if _obs_invalid_samesite(raw):
                worse("cookies-samesite-flag-invalid")
    # the session's jar: every hop of the auto chain plus the robots.txt fetch (tough-cookie keeps expired cookies)
    session_responses: list[Response] = auto.hops() if auto is not None else []
    robots = ctx.wellknown.get("/robots.txt")
    if robots is not None and auto is not None and robots.origin == auto.origin:
        session_responses = session_responses + robots.hops()
    ids = {id(r) for r in session_responses}
    jar: dict[tuple[str, str, str], CookieFact] = {}
    for f in facts:
        if id(f.response) not in ids or not f.name or f.name in ("heroku-session-affinity",):
            continue
        if _rejected_domain(f) or _prefix_problem(f):
            continue
        jar[(f.domain or f.host, cookie_path(f), f.name)] = f
    if not jar:
        return "cookies-not-found"
    hsts = observatory_hsts_pass(ctx)
    missing_samesite = False
    for f in jar.values():
        low = f.name.lower()
        session = "login" in low or "sess" in low
        anticsrf = "csrf" in low
        samesite = _obs_samesite(f.attrs)
        if not f.secure and samesite == "none":
            worse("cookies-samesite-flag-invalid")
        if not f.secure:
            worse("cookies-without-secure-flag-but-protected-by-hsts" if hsts else "cookies-without-secure-flag")
        if anticsrf and not samesite:
            worse("cookies-anticsrf-without-samesite-flag")
        if session and not f.secure:
            worse("cookies-session-without-secure-flag-but-protected-by-hsts" if hsts
                  else "cookies-session-without-secure-flag")
        if session and not f.httponly:
            worse("cookies-session-without-httponly-flag")
        if not samesite:
            missing_samesite = True
    if result is None:
        result = ("cookies-secure-with-httponly-sessions" if missing_samesite
                  else "cookies-secure-with-httponly-sessions-and-samesite")
    return result


# ----------------------------------------------------------------------------------------------- rejection facts

def _prefix_problem(f: CookieFact) -> list[tuple[str, str]]:
    """Notes for broken prefix rules (WEB401); empty when the prefix rules hold or the name has no prefix."""
    prefix = cookie_prefix(f.name)
    if not prefix:
        return []
    out = []
    if not f.secure:
        out.append(_note("prefix_secure", prefix=prefix))
    if not f.secure_context:
        out.append(_note("prefix_http", prefix=prefix))
    if prefix in ("__Host-", "__Host-Http-"):
        if "domain" in f.attrs:
            out.append(_note("prefix_domain", prefix=prefix, value=f.attrs["domain"]))
        if f.attrs.get("path") != "/":
            out.append(_note("prefix_path", prefix=prefix, value=f.attrs.get("path") or "—"))
    if prefix in ("__Http-", "__Host-Http-") and not f.httponly:
        out.append(_note("prefix_httponly", prefix=prefix))
    return out


def _rejected_domain(f: CookieFact) -> tuple[str, str] | None:
    """``(variant, domain)`` when the browser rejects the Domain attribute: ``suffix`` or ``mismatch``."""
    domain = f.domain
    if not domain:
        return None
    host = psl.normalise(f.host)
    domain = psl.normalise(domain) or domain
    if _is_ip(host):
        return None if domain == host else ("mismatch", domain)
    if psl.is_public_suffix(domain) and domain != host:
        return "suffix", domain
    if not (host == domain or host.endswith("." + domain)):
        return "mismatch", domain
    return None


# ----------------------------------------------------------------------------------------------- the run

_RANK = {s: i for i, s in enumerate(SEVERITIES)}
_BLOCK_KINDS = ("waf_challenge", "rate_limited")


class _Run:
    def __init__(self, ctx: ScanContext, facts: list[CookieFact]):
        self.ctx = ctx
        self.facts = facts
        self.paranoid = ctx.options.sensitivity == "paranoid"
        self.issues: dict[tuple[str, str, str], Issue] = {}
        self.instances: dict[tuple[str, str, str], set[int]] = {}
        self.evaluated: dict[str, set[str]] = {}
        self.failed: dict[str, set[str]] = {}
        sites = {psl.site(h) for h in (ctx.target_host, ctx.entry.host if ctx.entry is not None else "") if h}
        self.own_sites = sites
        self.blocked_hosts: dict[str, str] = {}
        if ctx.entry is not None and ctx.entry.kind in _BLOCK_KINDS:
            reason = "waf" if ctx.entry.kind == "waf_challenge" else "rate_limited"
            for h in ctx.entry.hops():
                if h.host:
                    self.blocked_hosts[h.host] = reason

    # -- selection -----------------------------------------------------------------------------------------
    def own(self, f: CookieFact) -> bool:
        return bool(f.host) and psl.site(f.host) in self.own_sites

    def judged(self) -> list[CookieFact]:
        out = []
        for f in self.facts:
            r = f.response
            if f.deletion or f.ignored or not self.own(f) or r.kind in _BLOCK_KINDS or f.host in self.blocked_hosts:
                continue
            out.append(f)
        return out

    # -- bookkeeping ---------------------------------------------------------------------------------------
    def seen(self, rule: str, host: str) -> None:
        self.evaluated.setdefault(RULES[rule].check_id, set()).add(host)

    def emit(self, rule: str, f: CookieFact, *, severity: str | None = None, confidence: str | None = None,
             notes: list[tuple[str, str]] | None = None, group_value: str | None = None,
             response: Response | None = None, evidence: Evidence | None = None) -> None:
        meta = RULES[rule]
        conf = confidence or meta.confidence
        if conf not in meta.allowed_confidences:
            return
        sev = severity if severity in meta.allowed_severities else meta.severity
        r = response or f.response
        self.seen(rule, f.host)
        key = (rule, f.name, f.host)
        self.instances.setdefault(key, set()).add(id(r))
        old = self.issues.get(key)
        if old is not None and _RANK[old.severity or meta.severity] <= _RANK[sev]:
            return
        if evidence is None:
            # redact_cookie_header, not CookieFact.redacted(): the latter splits on the first "=" of the whole field,
            # so a nameless cookie ("SECRET; Path=/x") would put its value in evidence
            evidence = Evidence.for_response(r, where="cookie", name=_shown_name(f, 200),
                                             value=redact_cookie_header(f.raw), now=self.ctx.now)
        all_notes = list(notes or [])
        all_notes.append(_note("class", cls=CLASS_NAMES.get(f.cls, CLASS_NAMES["unknown"]),
                               how=HOW_NAMES.get(f.class_source, HOW_NAMES["default"])))
        self.issues[key] = Issue(rule=rule, url=r.url, confidence=conf, evidence=evidence,
                                 params={"cookie": _shown_name(f)}, severity=sev,
                                 group_value=group_value if group_value is not None else f.name.lower(),
                                 notes=all_notes, host=f.host)
        if self.ctx.options.reports(conf):
            self.failed.setdefault(meta.check_id, set()).add(f.host)

    def finish(self) -> list[Issue]:
        out = []
        for key, issue in self.issues.items():
            n = len(self.instances.get(key, ()))
            if n > 1:
                issue.notes.append(_note("responses", responses=_count(n, _RESPONSES)))
            out.append(issue)
        return out

    def record_coverage(self) -> None:
        cov = self.ctx.coverage
        if cov is None:
            return
        for check in CHECKS:
            hosts = self.evaluated.get(check, set())
            failed = self.failed.get(check, set())
            for host in sorted(hosts):
                (cov.failed if host in failed else cov.passed)(check, host)
            for host, reason in self.blocked_hosts.items():
                if host not in hosts:
                    cov.inconclusive(check, reason, host=host)
            if not hosts and not self.blocked_hosts:
                if RULES[check].paranoid_only and not self.paranoid:
                    cov.not_tested(check, "sensitivity")
                else:
                    cov.not_applicable(check)

    # -- class used for severities ---------------------------------------------------------------------------
    def judged_class(self, f: CookieFact) -> tuple[str, str | None]:
        """``(class, confidence override)``: unknown_secret is judged as session at paranoid (tentative)."""
        if f.cls == "unknown_secret":
            return ("session", "tentative") if self.paranoid else ("unknown", None)
        return f.cls, None


def _days(seconds: float) -> int:
    return max(0, int(seconds // DAY))


def _days_text(n: int) -> tuple[str, str]:
    one, many, ar_forms = PLURAL_PARAMS["days"]
    return _count(n, (one, many, ar_forms))


def _check_fact(st: _Run, f: CookieFact) -> None:
    ctx = st.ctx
    cls, conf_over = st.judged_class(f)
    session = cls in SESSION_CLASSES
    host = f.host
    extra = [_note("secret_guess")] if conf_over else []

    # ---- rejected by the browser: only the rejection findings -------------------------------------------------
    rejected = False
    size = len(f.name.encode("utf-8", "replace")) + len(f.value.encode("utf-8", "replace"))
    st.seen("WEB408", host)
    if size > MAX_NAME_VALUE:
        st.emit("WEB408", f, notes=[_note("size", size=str(size))])
        rejected = True
    st.seen("WEB401", host)
    prefix_notes = _prefix_problem(f)
    if prefix_notes:
        st.emit("WEB401", f, notes=prefix_notes)
        rejected = True
    samesite = f.samesite
    st.seen("WEB400", host)
    if samesite is not None and samesite.strip().lower() == "none" and not f.secure:
        st.emit("WEB400", f, notes=[_note("samesite_none")])
        rejected = True
    st.seen("WEB403", host)
    if f.partitioned and not f.secure:
        st.emit("WEB403", f, notes=[_note("partitioned")])
        rejected = True
    st.seen("WEB404", host)
    bad_domain = _rejected_domain(f)
    if bad_domain:
        variant, domain = bad_domain
        note = (_note("domain_suffix", value=domain) if variant == "suffix"
                else _note("domain_mismatch", value=domain, host=host))
        st.emit("WEB404", f, severity="low", notes=[note], group_value=f"{f.name.lower()}|{variant}")
        rejected = True

    # ---- plain HTTP: the value crossed the network in clear text (WEB413), or Secure is ignored (WEB410) ----------
    if not f.secure_context:
        st.seen("WEB413", host)
        st.seen("WEB410", host)
        w413 = None
        if session:
            w413 = "high"
        elif cls in ("csrf", "unknown"):
            w413 = "low"
        if w413:
            st.emit("WEB413", f, severity=w413, confidence=conf_over,
                    notes=[_note("over_http", url=_clean(f.response.url, 200)), *extra])
        elif f.secure and not prefix_notes:
            st.emit("WEB410", f, notes=[_note("secure_http")])
        if f.secure:
            rejected = True

    # ---- facts about the value (always) -------------------------------------------------------------------------
    st.seen("WEB411", host)
    if f.name.lower().startswith("bigipserver"):
        decoded = decode_bigip(f.value)
        if decoded is not None and (decoded[0].is_private or decoded[0].is_loopback or decoded[0].is_link_local):
            ip, port = decoded
            shown = f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"
            st.emit("WEB411", f, notes=[_note("bigip", address=shown)], group_value=f"{f.name.lower()}|{shown}")
    st.seen("WEB412", host)
    sens = sensitive_value(f.value)
    if sens is not None:
        sev, notes, group = sens
        st.emit("WEB412", f, severity=sev, notes=notes, group_value=f"{f.name.lower()}|{group}")

    if rejected:
        return

    # ---- quality of an accepted cookie ----------------------------------------------------------------------------
    paranoid = st.paranoid
    if f.secure_context:
        st.seen("WEB020", host)
        if not f.secure:
            if session:
                protected, scope = hsts_protects(ctx, f)
                note = _note("hsts_mitigates" if protected else "no_hsts", scope=scope)
                st.emit("WEB020", f, severity="medium" if protected else "high", confidence=conf_over,
                        notes=[note, *extra])
            elif cls in ("csrf", "unknown", "lb", "cdn_bot"):
                st.emit("WEB020", f, severity="low")
            elif paranoid:                                   # analytics, consent, preference
                st.emit("WEB020", f, severity="info")
    st.seen("WEB021", host)
    if not f.httponly:
        if session:
            conf = conf_over or ("certain" if f.class_source == "table" else "firm")
            st.emit("WEB021", f, severity="medium", confidence=conf, notes=extra)
        elif cls == "unknown" and paranoid:
            st.emit("WEB021", f, severity="info", confidence="tentative")
    st.seen("WEB022", host)
    st.seen("WEB402", host)
    if samesite is None:
        if session or cls == "csrf":
            st.emit("WEB022", f, severity="low", confidence=conf_over, notes=extra)
        elif paranoid:
            st.emit("WEB022", f, severity="info")
    elif samesite.strip().lower() not in ("strict", "lax", "none"):
        st.emit("WEB402", f, notes=[_note("samesite_invalid", value=samesite or '""')])
    st.seen("WEB404", host)
    if session and f.domain and not bad_domain and psl.normalise(f.domain) != psl.normalise(host):
        st.emit("WEB404", f, severity="low", confidence=conf_over,
                notes=[_note("domain_parent", value=f.domain), *extra], group_value=f"{f.name.lower()}|parent")
    st.seen("WEB405", host)
    life = lifetime_seconds(f, ctx.now)
    if life is not None:
        days = _days(life)
        if session and life > SESSION_LIFETIME_DAYS * DAY:
            notes = [_note("lifetime", days=_days_text(days))]
            if life > CLAMP_DAYS * DAY:
                notes.append(_note("clamp"))
            st.emit("WEB405", f, severity="low", confidence=conf_over, notes=notes + extra)
        elif life > CLAMP_DAYS * DAY:
            st.emit("WEB405", f, severity="info", notes=[_note("lifetime", days=_days_text(days)), _note("clamp")])
    st.seen("WEB407", host)
    if session and samesite is not None and samesite.strip().lower() == "none":
        notes = [_note("same_site_none_partitioned")] if f.partitioned else []
        st.emit("WEB407", f, severity="info" if f.partitioned else "low", confidence=conf_over, notes=notes + extra)
    if paranoid and f.secure_context:
        st.seen("WEB409", host)
        if session and "domain" not in f.attrs and not f.name.lower().startswith("__host-"):
            st.emit("WEB409", f, confidence=conf_over, notes=[_note("host_prefix"), *extra])


def _check_duplicates(st: _Run, facts: list[CookieFact]) -> None:
    by_resp: dict[int, list[CookieFact]] = {}
    for f in facts:
        by_resp.setdefault(id(f.response), []).append(f)
    for group in by_resp.values():
        st.seen("WEB406", group[0].host)
        keys: dict[tuple[str, str, str], list[CookieFact]] = {}
        for f in group:
            keys.setdefault((f.name, (f.domain or ""), cookie_path(f)), []).append(f)
        for same in keys.values():
            variants = {(f.value, tuple(sorted(f.attrs.items()))) for f in same}
            if len(same) > 1 and len(variants) > 1:
                last = same[-1]
                st.emit("WEB406", last, notes=[_note("duplicate", times=_count(len(same), _TIMES))])


def _exposure_targets(ctx: ScanContext, own_sites: set[str]) -> list[tuple[Response, bool]]:
    """Documents and same-site scripts that a session could have been served: ``(response, is_script_file)``."""
    out: dict[int, tuple[Response, bool]] = {}
    for p in ctx.pages:
        out.setdefault(id(p.response), (p.response, False))
    for r in ctx.all_responses(include_hops=False):
        kind = r.kind or ""
        ess = r.essence
        if kind == "document" or (not kind and ess in ("text/html", "application/xhtml+xml")):
            out.setdefault(id(r), (r, False))
        elif (kind == "script" or (not kind and "javascript" in ess)) and r.host and psl.site(r.host) in own_sites:
            out.setdefault(id(r), (r, True))
    return [v for v in out.values() if _readable(v[0])]


def _masked_excerpt(text: str, off: int, value: str, red: str, width: int = 80) -> str:
    """``width`` characters around the match with every copy of the value masked, including a copy cut by either
    edge of the window (``var a="TOKEN", b="TOK`` must not leak the start of the second copy)."""
    end = off + len(value)
    before, after = text[max(0, off - width):off], text[end:end + width]
    before, after = before.replace(value, red), after.replace(value, red)
    for k in range(min(len(value) - 1, len(after)), 3, -1):         # a prefix of the value cut by the right edge
        if after.endswith(value[:k]):
            after = after[:-k] + red
            break
    for k in range(min(len(value) - 1, len(before)), 3, -1):        # a suffix of the value cut by the left edge
        if before.startswith(value[-k:]):
            before = red + before[k:]
            break
    return strip_controls(before + red + after)


def _check_exposure(st: _Run, facts: list[CookieFact]) -> None:
    """WEB414: the exact value of a session/auth cookie appears in a document or same-site script served to that
    session (in-memory comparison; evidence shows only the redacted value)."""
    ctx = st.ctx
    candidates = [f for f in facts if f.cls in SESSION_CLASSES and len(_unquote(f.value)) >= SECRET_MIN_LENGTH]
    if not candidates:
        return
    targets = _exposure_targets(ctx, st.own_sites)
    done: set[tuple[str, str, str]] = set()                 # (host, name, value) already reported
    searched: set[tuple[int, str]] = set()                  # (response, value) already searched
    for f in candidates:
        st.seen("WEB414", f.host)
        value = _unquote(f.value)
        if (f.host, f.name, value) in done:                  # a session cookie re-set on every page: report once
            continue
        for r, script_file in targets:
            if r.host != f.host or (id(r), value) in searched \
                    or not (r is f.response or _request_has(r, f.name, f.value)):
                continue
            searched.add((id(r), value))
            text = r.text()
            off = text.find(value)
            if off < 0:
                continue
            where = exposure_context(text, off, script_file=script_file)
            red = redact_secret(value)
            excerpt = _masked_excerpt(text, off, value, red)
            ev = Evidence.for_response(r, where="body", name=_shown_name(f, 200), value=red, offset=off,
                                       excerpt=excerpt, now=ctx.now)
            st.emit("WEB414", f, response=r, evidence=ev,
                    notes=[_note("echo", where=WHERE_NAMES[where], url=_clean(r.url, 200))])
            done.add((f.host, f.name, value))
            break


def _inventory(st: _Run, facts: list[CookieFact]) -> list[dict]:
    rows: dict[tuple[str, str, str, str], dict] = {}
    for f in facts:
        if not st.own(f):
            continue
        key = (f.host, f.name, f.domain or "", cookie_path(f))
        life = lifetime_seconds(f, st.ctx.now)
        rows[key] = {
            "name": _shown_name(f, 200), "host": f.host, "class": f.cls, "class_source": f.class_source,
            "secure": f.secure, "httponly": f.httponly, "samesite": f.samesite, "partitioned": f.partitioned,
            "domain": f.domain, "path": cookie_path(f), "prefix": cookie_prefix(f.name),
            "persistent_days": None if life is None else _days(life), "deletion": f.deletion, "ignored": f.ignored,
            "set_over": "https" if f.secure_context else "http", "value_bytes": len(f.value.encode("utf-8", "replace")),
        }
    return list(rows.values())


def run(ctx: ScanContext) -> list[Issue]:
    """All §2.5 checks over the context (pure apart from writing ``ctx.observatory``, ``ctx.inventory`` and coverage)."""
    facts = ctx.cookies if ctx.cookies else parse_and_classify(ctx)
    st = _Run(ctx, facts)
    judged = st.judged()
    for f in judged:
        _check_fact(st, f)
    _check_duplicates(st, judged)
    _check_exposure(st, judged)
    st.record_coverage()
    ctx.observatory["cookies"] = observatory_slug(ctx, facts)
    ctx.inventory["cookies"] = _inventory(st, facts)
    return st.finish()


__all__ = ["CHECKS", "STR", "CLASS_NAMES", "ParsedCookie", "parse_set_cookie", "parse_cookie_date", "default_path",
           "cookie_path", "lifetime_seconds", "name_words", "strip_prefix", "cookie_prefix", "heuristic_class",
           "value_class", "shannon_entropy", "ClassTable", "class_table", "classify", "parse_and_classify",
           "decode_bigip", "jwt_parts", "sensitive_value", "hsts_protects", "exposure_context", "observatory_auto",
           "observatory_hsts_pass", "observatory_slug", "run", "i18n_catalog"]
