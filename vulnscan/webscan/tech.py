"""Technologies, platform versions, server software CVEs and end of life (spec §2.9), WP9.

Rules: WEB080 (detected platform), WEB081 (outdated platform version), WEB800 (server software version with known
vulnerabilities), WEB801 (end-of-life server software or runtime), WEB802 (obsolete plugin content).

* **Detection** (:func:`detect`) runs Kashif's signature set (``data/web/tech.json``) over *scoped* sources only:
  response headers and cookie names of the site's own responses, ``<meta>`` contents, ``<script src>`` and
  ``<link href>`` URLs, markup-anchored HTML patterns, page URLs and the favicon (``favicons.json``, Shodan-style mmh3);
  never free page prose (fixes D15). Each technology adds up the confidence of its matched signals (capped at 100),
  takes its version from the strongest versioned signal, and follows ``implies``/``excludes``. **Every** detected
  platform is reported (1.0.1 stopped at the first). The result is also the inventory (``ctx.inventory["technologies"]``)
  and is what the engine hands to exposure.py for the platform deep paths.
* **WEB081** compares a platform version with ``eol.json`` (endoflife.date): medium for an end-of-life branch, low for a
  supported branch below its latest patch.
* **WEB800/WEB801** parse ``product/version`` banners from ``Server``, ``X-Powered-By`` and error-page banners (Apache
  ``<address>``, nginx ``<center>``, Tomcat ``<h3>``) and compare them with ``server-cve.json`` and ``eol.json``.
  Distribution builds (``(Ubuntu)``, ``-4ubuntu2.19``, ``el8``, ``-fips`` …) usually carry backported fixes: WEB800 drops
  to tentative ("may be affected") and WEB801 is not reported for them (the distribution, not upstream, supports them).
  Incomplete versions (``PHP/8.1``) are tentative and list every CVE of that branch.
* **WEB802** flags Flash, Silverlight and Java applet content in live markup.

The module never fetches anything; it reads ``ctx`` only.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Iterable

from . import data as _data
from . import mmh3, psl
from .rules import RULES, checks_for_module
from .types import Evidence, Issue, Page, Response, ScanContext, essence, strip_controls

CHECKS: tuple[str, ...] = checks_for_module("tech")

TECH_FILE = "tech.json"
FAVICON_FILE = "favicons.json"
EOL_FILE = "eol.json"
CVE_FILE = "server-cve.json"
HTML_CAP = 2 * 1024 * 1024
MAX_CVE_NOTES = 10
SHOW_AT_DEFAULT = 50            # WEB080: confidence >= 50 is shown at default sensitivity (firm), below at paranoid only

# technologies in these categories are "platforms" (WEB080/WEB081); everything else goes to the inventory only
PLATFORM_CATEGORIES = frozenset({"cms", "blog", "ecommerce", "lms", "wiki", "forum", "web-framework", "database-admin",
                                 "ci", "devops", "monitoring", "collaboration", "webmail", "admin-panel", "low-code",
                                 "portal"})
# platform versions that omit a ".0" patch (WordPress "4.9" is 4.9.0)
ZERO_PATCH = frozenset({"wordpress"})

# banner product token → (server-cve/eol product key, display name)
BANNER_PRODUCTS: dict[str, tuple[str, str]] = {
    "apache": ("apache-http-server", "Apache HTTP Server"),
    "nginx": ("nginx", "nginx"),
    "php": ("php", "PHP"),
    "openssl": ("openssl", "OpenSSL"),
    "microsoft-iis": ("iis", "Microsoft IIS"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "python": ("python", "Python"),
    "cpython": ("python", "Python"),
    "apache tomcat": ("tomcat", "Apache Tomcat"),
    "tomcat": ("tomcat", "Apache Tomcat"),
}
TWO_PART = frozenset({"iis"})            # products whose full version has two parts (IIS 10.0)
LETTER_SUFFIX = frozenset({"openssl"})   # products whose patch level is a letter (OpenSSL 1.0.2k)
_DISTRO_COMMENT = re.compile(r"\b(Ubuntu|Debian|Red Hat|RedHat|CentOS|AlmaLinux|Rocky Linux|Rocky|Amazon Linux|Amazon|"
                             r"Fedora|SUSE|openSUSE|Raspbian|Oracle Linux|Unix)\b", re.I)
_DISTRO_SUFFIX = re.compile(r"(ubuntu|deb\d+|\+deb|debian|\.el\d+|el\d+(?:_\d+)?|\.fc\d+|fc\d+|-fips|\.amzn\d|amzn\d|"
                            r"\.module\+el|suse|\.mga\d|\+dfsg)", re.I)
_DISTRO_NAMES = {"ubuntu": "Ubuntu", "deb": "Debian", "debian": "Debian", "el": "Red Hat / CentOS", "fc": "Fedora",
                 "fips": "a FIPS vendor build", "amzn": "Amazon Linux", "suse": "SUSE"}
_TOKEN = re.compile(r"([A-Za-z][A-Za-z0-9_.+-]*?)/v?(\d[0-9A-Za-z.+~_-]*)")
_COMMENT = re.compile(r"\(([^)]*)\)")
_ERROR_BANNERS = (
    re.compile(r"<address>\s*(Apache/[^<]{1,120}?)\s+Server at\b", re.I),
    re.compile(r"<hr\s*/?>\s*<center>\s*(nginx/[0-9][^<\s]{0,40})\s*</center>", re.I),
    re.compile(r"<h3>\s*(Apache Tomcat/\d[^<\s]{0,40})\s*</h3>", re.I),
    re.compile(r"<title>[^<]{0,80}</title>[\s\S]{0,4000}?\b(Apache Tomcat/\d+(?:\.\d+)+)", re.I),
)
_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

STR: dict[str, tuple[str, str]] = {
    "signal": ("Detected from {where}: {value}", "اكتُشفت من {where}: {value}"),
    "where_header": ("the {name} header", "الترويسة {name}"),
    "where_cookie": ("the cookie name", "اسم الكوكي"),
    "where_meta": ("<meta name={name}>", "الوسم <meta name={name}>"),
    "where_script": ("a script URL", "رابط سكربت"),
    "where_link": ("a <link> URL", "رابط في وسم <link>"),
    "where_html": ("page markup", "ترميز الصفحة"),
    "where_url": ("the page URL", "رابط الصفحة"),
    "where_favicon": ("the favicon hash", "بصمة أيقونة الموقع (favicon)"),
    "confidence": ("Detection confidence: {value}/100.", "ثقة الاكتشاف: {value} من 100."),
    "eol_branch": ("The {branch} branch reached end of life on {date}.", "انتهى دعم الفرع {branch} في {date}."),
    "eol_branch_nodate": ("The {branch} branch is end of life.", "انتهى دعم الفرع {branch}."),
    "latest_patch": ("The latest release of the {branch} branch is {latest}.", "آخر إصدار في الفرع {branch} هو {latest}."),
    "cve": ("{id} ({severity}): {summary}; fixed in {fixed}", "{id} ({severity}): {summary}؛ مُصحَّح في {fixed}"),
    "cve_more": ("…and {count} more CVEs.", "…و{count} من الثغرات الأخرى."),
    "distro": ("This looks like a {distro} build: distributions backport security fixes without changing the version, "
               "so this server may already be patched. Check the package changelog.",
               "يبدو أن هذا إصدار من توزيعة {distro}: التوزيعات تنقل تصحيحات الأمان دون تغيير رقم الإصدار، لذا قد يكون "
               "هذا الخادم مُصحَّحًا بالفعل. راجع سجل تغييرات الحزمة."),
    "incomplete": ("The banner shows only {version}; every release of that branch with a known CVE is listed.",
                   "الترويسة تُظهر {version} فقط؛ لذا ذُكرت كل ثغرات إصدارات هذا الفرع."),
    "assumed": ("This version is older than every fixed branch the advisories list; it is assumed affected.",
                "هذا الإصدار أقدم من كل الفروع المُصحَّحة في النشرات؛ لذا يُفترض أنه متأثر."),
    "seen_in": ("Seen in {where}: {value}", "ظهر في {where}: {value}"),
    "plugin": ("<{tag}> element: {what}", "العنصر <{tag}>: {what}"),
    "flash": ("Adobe Flash content (end of life since 2020-12-31)", "محتوى Adobe Flash (انتهى دعمه في 2020-12-31)"),
    "silverlight": ("Microsoft Silverlight content (end of life since 2021-10-12)",
                    "محتوى Microsoft Silverlight (انتهى دعمه في 2021-10-12)"),
    "applet": ("a Java applet (no browser runs applets since 2017)", "بُريمج Java (لا يشغّله أي متصفح منذ 2017)"),
}
_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


def _note(key: str, **values: Any) -> tuple[str, str]:
    en, ar = STR[key]

    def fill(text: str, lang: str) -> str:
        def sub(m: re.Match) -> str:
            v = values.get(m.group(1), m.group(0))
            if isinstance(v, tuple):
                v = v[1] if lang == "ar" else v[0]
            return strip_controls(str(v))
        return _PLACEHOLDER.sub(sub, text)
    return fill(en, "en"), fill(ar, "ar")


def _short(value: str, limit: int = 160) -> str:
    v = " ".join(strip_controls(value).split())
    return v if len(v) <= limit else v[: limit - 1] + "…"


# ----------------------------------------------------------------------------------------------- versions

def version_key(v: str) -> tuple:
    """Order of server/platform versions: numbers numerically; a letter right after a number is a later patch
    (OpenSSL ``1.0.1e`` > ``1.0.1``); alphabetic parts (``M1``, ``RC1``, ``beta``) are pre-releases. Missing parts
    count as 0 (``8.1`` == ``8.1.0``)."""
    out = []
    for part in re.split(r"[.\-]", v.strip().lower()):
        if not part:
            continue
        m = re.match(r"^(\d+)([a-z]*)$", part)
        if m:
            out.append((2, int(m.group(1)), m.group(2), 0))
            continue
        m = re.match(r"^([a-z]+)(\d*)$", part)
        if m:
            out.append((0, 0, m.group(1), int(m.group(2) or 0)))
            continue
        out.append((1, 0, part, 0))
    while out and out[-1] == (2, 0, "", 0):
        out.pop()
    return tuple(out)


def _cmp(a: str, b: str) -> int:
    ka, kb = list(version_key(a)), list(version_key(b))
    n = max(len(ka), len(kb))
    ka += [(2, 0, "", 0)] * (n - len(ka))
    kb += [(2, 0, "", 0)] * (n - len(kb))
    return (ka > kb) - (ka < kb)


def numeric_parts(v: str) -> list[str]:
    """``["1", "0", "2"]`` for ``1.0.2k`` (letter patch levels and suffixes dropped)."""
    out = []
    for part in re.split(r"[.\-]", v):
        m = re.match(r"^(\d+)", part)
        if not m:
            break
        out.append(m.group(1))
        if m.group(0) != part:
            break
    return out


def find_cycle(product: dict, version: str) -> dict | None:
    """The most specific endoflife.date cycle whose numeric parts prefix the version's."""
    vp = numeric_parts(version)
    best = None
    for c in product.get("cycles", []):
        cp = numeric_parts(str(c.get("cycle", "")))
        if cp and len(vp) >= len(cp) and vp[:len(cp)] == cp and (best is None or len(cp) > len(numeric_parts(
                str(best["cycle"])))):
            best = c
    return best


def eol_verdict(product: dict, version: str, today: date) -> tuple[str, str, str] | None:
    """``(state, branch, date)`` where state is ``eol``, ``patch`` (supported, below the latest patch) or ``ok``;
    None when the version matches no cycle and is not older than all of them."""
    cyc = find_cycle(product, version)
    if cyc is None:
        cycles = [c for c in product.get("cycles", []) if numeric_parts(str(c.get("cycle", "")))]
        if not cycles:
            return None
        oldest = min(cycles, key=lambda c: version_key(str(c["cycle"])))
        if _cmp(version, str(oldest["cycle"])) < 0 and _eol_past(oldest.get("eol"), today)[0]:
            major = ".".join(numeric_parts(version)[:len(numeric_parts(str(oldest["cycle"])))])
            return "eol", major or version, _eol_past(oldest.get("eol"), today)[1]
        return None
    past, when = _eol_past(cyc.get("eol"), today)
    if past:
        return "eol", str(cyc["cycle"]), when
    latest = str(cyc.get("latest") or "")
    if latest and re.match(r"^\d+(\.\d+)+$", latest) and _cmp(version, latest) < 0:
        return "patch", str(cyc["cycle"]), latest
    return "ok", str(cyc["cycle"]), ""


def _eol_past(value: Any, today: date) -> tuple[bool, str]:
    if value is True:
        return True, ""
    if isinstance(value, str):
        try:
            return date.fromisoformat(value) <= today, value
        except ValueError:
            return False, ""
    return False, ""


# ----------------------------------------------------------------------------------------------- signature DB

_META = set(".^$*+?{}[]\\|()")
_WORD = re.compile(r"[a-z0-9_$]+")
_TOKEN_TABLE = bytes(c if chr(c).isascii() and (chr(c).isalnum() or chr(c) in "_$") else 32 for c in range(256))


def literal_runs(src: str) -> list[str]:
    """Plain-text runs every match of ``src`` must contain (outside groups and classes, quantified characters
    dropped); ``[]`` when the pattern has a top-level alternation (no run is then required)."""
    runs: list[str] = []
    cur = ""
    depth = 0
    i = 0
    while i < len(src):
        c = src[i]
        if c == "\\" and i + 1 < len(src):
            nxt = src[i + 1]
            if depth == 0 and not nxt.isalnum():
                cur += nxt
            else:
                runs.append(cur)
                cur = ""
            i += 2
            continue
        if c == "[":
            runs.append(cur)
            cur = ""
            j = i + 1
            if j < len(src) and src[j] == "]":
                j += 1
            while j < len(src) and src[j] != "]":
                j += 2 if src[j] == "\\" else 1
            i = j + 1
            continue
        if c in "*?{":
            runs.append(cur[:-1])
            cur = ""
            if c == "{":
                i = src.find("}", i) + 1 or len(src)
                continue
            i += 1
            continue
        if c == "|" and depth == 0:
            return []
        if c in _META:
            runs.append(cur)
            cur = ""
            if c == "(":
                depth += 1
                if src.startswith(("?:", "?=", "?!"), i + 1):
                    i += 2
            elif c == ")":
                depth = max(0, depth - 1)
            i += 1
            continue
        if depth == 0:
            cur += c
        else:
            runs.append(cur)
            cur = ""
        i += 1
    runs.append(cur)
    return [r for r in runs if r]


def word_requirement(src: str) -> str:
    """A cheap necessary condition (checked on the page's lower-cased token index) for ``src`` to match: the longest
    word of a required run, as a whole token when it is bounded inside the run (``"\\nword\\n"``), as a token end or
    start at a run edge, or as part of a token. ``""`` when nothing of 4+ characters is required."""
    if "(?i" in src or "(?x" in src:
        src = src.replace("(?i)", "").replace("(?x)", "")
    best = ""
    for run in literal_runs(src):
        low = run.lower()
        for m in _WORD.finditer(low):
            w = m.group(0)
            if len(w) < 4:
                continue
            at_start, at_end = m.start() == 0, m.end() == len(low)
            cond = w if at_start and at_end else (w + "\n" if at_start else ("\n" + w if at_end else "\n" + w + "\n"))
            if len(cond) > len(best):
                best = cond
    return best


def token_index(text: str) -> str:
    words = set(text.encode("utf-8", "replace").lower().translate(_TOKEN_TABLE).split())
    return "\n" + b"\n".join(words).decode("ascii", "replace") + "\n"


@dataclass
class Signal:
    tech: str
    source: str
    name: str
    rx: re.Pattern
    version: str
    confidence: int
    index: int
    need: str = ""            # html signals: word_requirement(pattern)


@dataclass
class TechDef:
    id: str
    name: str
    categories: tuple[str, ...]
    cpe: str = ""
    implies: tuple[str, ...] = ()
    excludes: tuple[str, ...] = ()
    eol_product: str = ""

    @property
    def platform(self) -> bool:
        return bool(PLATFORM_CATEGORIES.intersection(self.categories))


@dataclass
class TechDB:
    techs: dict[str, TechDef]
    signals: dict[str, list[Signal]]          # source → signals
    favicons: dict[int, tuple[str, str]]      # hash → (tech id, name)
    skipped: int = 0


def _flags(s: str) -> int:
    f = 0
    for ch in s or "":
        f |= {"i": re.I, "m": re.M, "s": re.S, "x": re.X}.get(ch, 0)
    return f


def build_db(tech_obj: dict, favicon_obj: dict | None = None) -> TechDB:
    techs: dict[str, TechDef] = {}
    signals: dict[str, list[Signal]] = {}
    skipped = 0
    n = 0
    for t in (tech_obj or {}).get("technologies", []):
        tid = str(t.get("id", ""))
        if not tid:
            continue
        techs[tid] = TechDef(tid, str(t.get("name") or tid), tuple(t.get("categories") or ()), str(t.get("cpe") or ""),
                             tuple(t.get("implies") or ()), tuple(t.get("excludes") or ()), str(t.get("eol_product") or ""))
        for s in t.get("signals") or []:
            try:
                rx = re.compile(str(s["pattern"]), _flags(str(s.get("flags", ""))))
            except (re.error, KeyError):
                skipped += 1
                continue
            source = str(s["source"])
            signals.setdefault(source, []).append(
                Signal(tid, source, str(s.get("name", "")).lower(), rx, str(s.get("version", "")),
                       int(s.get("confidence", 0)), n, word_requirement(rx.pattern) if source == "html" else ""))
            n += 1
    favs: dict[int, tuple[str, str]] = {}
    for h in (favicon_obj or {}).get("hashes", []):
        try:
            favs.setdefault(int(h["hash"]), (str(h["tech"]), str(h.get("name") or h["tech"])))
        except (KeyError, TypeError, ValueError):
            continue
    return TechDB(techs, signals, favs, skipped)


_DB_CACHE: dict[tuple[int, int], TechDB] = {}


def load_db(data_mod: Any = None) -> TechDB | None:
    dm = data_mod or _data
    try:
        tobj = dm.load_json(TECH_FILE)
    except (OSError, ValueError):
        return None
    try:
        fobj = dm.load_json(FAVICON_FILE)
    except (OSError, ValueError):
        fobj = None
    key = (id(tobj), id(fobj))
    if key not in _DB_CACHE:
        _DB_CACHE.clear()
        _DB_CACHE[key] = build_db(tobj, fobj)
    return _DB_CACHE[key]


def _load(dm: Any, name: str) -> Any:
    try:
        return dm.load_json(name)
    except (OSError, ValueError):
        return None


# ----------------------------------------------------------------------------------------------- detection

@dataclass
class Hit:
    signal: Signal | None
    source: str
    name: str
    value: str
    response: Response | None
    version: str = ""


@dataclass
class Detected:
    tech: TechDef
    hits: list[Hit] = field(default_factory=list)
    confidence: int = 0
    version: str = ""
    version_confidence: int = 0
    implied_by: str = ""

    def to_dict(self) -> dict:
        return {"id": self.tech.id, "name": self.tech.name, "version": self.version, "confidence": self.confidence,
                "categories": list(self.tech.categories), "cpe": self.cpe(), "platform": self.tech.platform,
                "implied_by": self.implied_by,
                "evidence": [{"source": h.source, "name": h.name, "value": _short(h.value, 120)} for h in self.hits[:5]]}

    def cpe(self) -> str:
        if not self.tech.cpe:
            return ""
        parts = self.tech.cpe.split(":")
        while len(parts) < 13:
            parts.append("*")
        if self.version:
            parts[5] = self.version
        return ":".join(parts[:13])


def _own_sites(ctx: ScanContext) -> set[str]:
    hosts = {ctx.target_host}
    if ctx.entry is not None:
        hosts.add(ctx.entry.host)
    return {psl.site(h) for h in hosts if h}


def own_responses(ctx: ScanContext) -> list[Response]:
    sites = _own_sites(ctx)
    out = []
    for r in ctx.all_responses():
        if r.status is None or r.error or not r.host or psl.site(r.host) not in sites:
            continue
        if r.kind in ("waf_challenge", "rate_limited"):
            continue
        out.append(r)
    return out


def _expand(template: str, m: re.Match) -> str:
    if not template:
        return ""
    try:
        v = m.expand(template)
    except (re.error, IndexError):
        return ""
    v = v.strip()
    return v if re.match(r"^\d+(?:\.\d+)*[a-z]?$", v) else ""


def _cookie_names(r: Response, ctx: ScanContext) -> list[str]:
    facts = ctx.cookies_for(r)
    if facts:
        return [c.name for c in facts]
    names = []
    for v in r.headers.get_all("set-cookie"):
        name = v.split(";", 1)[0].split("=", 1)[0].strip()
        if name:
            names.append(name)
    return names


def _metas(doc) -> list[tuple[str, str]]:
    out = []
    for el in doc.find_all("meta"):
        key = (el.get("name") or el.get("property") or el.get("itemprop") or "").strip().lower()
        content = el.get("content")
        if key and content is not None:
            out.append((key, content.strip()))
    return out


def _urls(doc, tag: str, attr: str) -> list[str]:
    out = []
    for el in doc.find_all(tag):
        v = el.get(attr)
        if v and v.strip():
            u = doc.resolve(v.strip())
            if u.startswith(("http://", "https://")):
                out.append(u)
    return out


def _favicons(ctx: ScanContext) -> list[Response]:
    out = []
    for key, r in ctx.wellknown.items():
        path = urllib.parse.urlsplit(r.url).path.lower()
        if "icon" in key.lower() or "favicon" in path or path.endswith(".ico"):
            out.append(r)
    for r in ctx.images:
        if "favicon" in urllib.parse.urlsplit(r.url).path.lower():
            out.append(r)
    good = []
    for r in out:
        if r.status != 200 or not r.body or r.truncated:
            continue
        head = r.body[:64].lstrip().lower()
        if head.startswith((b"<!doctype html", b"<html", b"<head")) or essence(r.content_type) == "text/html":
            continue
        good.append(r)
    return good


class _Detector:
    def __init__(self, ctx: ScanContext, db: TechDB):
        self.ctx = ctx
        self.db = db
        self.found: dict[str, Detected] = {}
        self.seen_signal: dict[str, set[int]] = {}

    def hit(self, tid: str, h: Hit, conf: int) -> None:
        tech = self.db.techs.get(tid)
        if tech is None:
            tech = TechDef(tid, h.name if h.source == "favicon" else tid, ("other",))
            self.db.techs[tid] = tech
        d = self.found.get(tid)
        if d is None:
            d = self.found[tid] = Detected(tech)
        key = h.signal.index if h.signal is not None else -1 - abs(hash(h.value)) % 1_000_000
        seen = self.seen_signal.setdefault(tid, set())
        if key not in seen:
            seen.add(key)
            d.confidence = min(100, d.confidence + conf)
            d.hits.append(h)
        if h.version and conf > d.version_confidence:
            d.version, d.version_confidence = h.version, conf

    def run_signals(self, source: str, items: Iterable[tuple[str, str, Response | None]]) -> None:
        """``items`` = (name, value, response); a signal with a ``name`` only sees items of that name."""
        sigs = self.db.signals.get(source, [])
        if not sigs:
            return
        for name, value, resp in items:
            index = token_index(value) if source == "html" and len(value) > 2048 else None
            for s in sigs:
                if s.name and s.name != name:
                    continue
                if index is not None and s.need and s.need not in index:
                    continue
                m = s.rx.search(value)
                if m:
                    self.hit(s.tech, Hit(s, source, name, m.group(0) if source == "html" else value, resp,
                                         _expand(s.version, m)), s.confidence)

    def detect(self) -> dict[str, Detected]:
        ctx = self.ctx
        responses = own_responses(ctx)
        header_items = []
        cookie_items = []
        for r in responses:
            for k, v in r.headers:
                header_items.append((k.lower(), v, r))
            for name in _cookie_names(r, ctx):
                cookie_items.append(("", name, r))
        self.run_signals("header", header_items)
        self.run_signals("cookie", cookie_items)
        meta_items, script_items, link_items, html_items, url_items = [], [], [], [], []
        for page in ctx.pages:
            r = page.response
            if r.host and psl.site(r.host) not in _own_sites(ctx):
                continue
            url_items.append(("", r.url, r))
            if page.doc is None:
                continue
            meta_items.extend((k, v, r) for k, v in _metas(page.doc))
            script_items.extend(("", u, r) for u in _urls(page.doc, "script", "src"))
            link_items.extend(("", u, r) for u in _urls(page.doc, "link", "href"))
            try:
                html_items.append(("", r.text()[:HTML_CAP], r))
            except (LookupError, ValueError):
                pass
        self.run_signals("meta", meta_items)
        self.run_signals("script", script_items)
        self.run_signals("link", link_items)
        self.run_signals("url", url_items)
        self.run_signals("html", html_items)
        for r in _favicons(ctx):
            h = mmh3.favicon_hash(r.body)
            hit = self.db.favicons.get(h)
            if hit:
                self.hit(hit[0], Hit(None, "favicon", hit[1], str(h), r), 60)
        self._implies()
        for d in self.found.values():
            for ex in d.tech.excludes:
                other = self.found.get(ex)
                if other is not None and other.confidence < d.confidence:
                    del self.found[ex]
        return self.found

    def _implies(self) -> None:
        queue = list(self.found.values())
        while queue:
            d = queue.pop()
            for imp in d.tech.implies:
                if imp in self.found:
                    continue
                tech = self.db.techs.get(imp) or TechDef(imp, imp, ("other",))
                nd = Detected(tech, confidence=d.confidence, implied_by=d.tech.id)
                self.found[imp] = nd
                queue.append(nd)


def detect(ctx: ScanContext, db: TechDB | None = None) -> dict[str, Detected]:
    """Technologies of the site (pure; reads ``ctx`` only). Also stores the inventory list in
    ``ctx.inventory["technologies"]`` so the engine can pass detected platforms to exposure.py."""
    db = db or load_db(ctx.data)
    if db is None:
        return {}
    found = _Detector(ctx, db).detect()
    ctx.inventory["technologies"] = sorted((d.to_dict() for d in found.values()),
                                           key=lambda x: (not x["platform"], -x["confidence"], x["id"]))
    return found


# ----------------------------------------------------------------------------------------------- banners

@dataclass
class Banner:
    product: str          # server-cve / eol key
    display: str
    version: str          # as shown (e.g. 7.4.3-4ubuntu2.19)
    base: str             # comparable version (7.4.3)
    distro: str           # "" or a distribution name
    incomplete: bool
    where: str            # header name or "error page"
    raw: str
    response: Response


def _distro_of(token_version: str, comments: list[str]) -> str:
    m = _DISTRO_SUFFIX.search(token_version)
    if m:
        key = re.sub(r"[^a-z]", "", m.group(1).lower())
        for k, name in _DISTRO_NAMES.items():
            if key.startswith(k):
                return name
        return "a distribution"
    for c in comments:
        m = _DISTRO_COMMENT.search(c)
        if m and m.group(1).lower() != "unix":
            return m.group(1)
    return ""


def parse_banner(value: str) -> list[tuple[str, str, str, list[str]]]:
    """``[(token name, version, display key, comments)]`` for every ``product/version`` token of a banner."""
    comments = _COMMENT.findall(value)
    stripped = _COMMENT.sub(" ", value)
    out = []
    for m in _TOKEN.finditer(stripped):
        name = m.group(1)
        out.append((name, m.group(2), name.lower(), comments))
    m = re.search(r"\bApache Tomcat/(\d[\w.\-]*)", value)
    if m:
        out = [t for t in out if t[2] != "tomcat"] + [("Apache Tomcat", m.group(1), "apache tomcat", comments)]
    return out


def _base_version(product: str, version: str) -> str:
    rx = r"^\d+(?:\.\d+)*[a-z]?" if product in LETTER_SUFFIX else r"^\d+(?:\.\d+)*"
    m = re.match(rx, version)
    return m.group(0) if m else ""


def banners(ctx: ScanContext) -> list[Banner]:
    out: list[Banner] = []
    for r in own_responses(ctx):
        sources: list[tuple[str, str]] = [("Server", v) for v in r.headers.get_all("server")]
        sources += [("X-Powered-By", v) for v in r.headers.get_all("x-powered-by")]
        if r.status is not None and r.status >= 400 and r.body and b"<" in r.body[:4096]:
            try:
                text = r.text()[:200_000]
            except (LookupError, ValueError):
                text = ""
            for rx in _ERROR_BANNERS:
                m = rx.search(text)
                if m:
                    sources.append(("error page", m.group(1)))
        for where, value in sources:
            for name, version, key, comments in parse_banner(value):
                prod = BANNER_PRODUCTS.get(key)
                if prod is None:
                    continue
                pkey, display = prod
                base = _base_version(pkey, version)
                if not base:
                    continue
                need = 2 if pkey in TWO_PART else 3
                incomplete = len(numeric_parts(base)) < need
                out.append(Banner(pkey, display, version, base, _distro_of(version, comments), incomplete, where,
                                  value, r))
        for v in r.headers.get_all("server"):
            if re.search(r"\(CentOS\)", v):
                apache = re.search(r"Apache/(\d+\.\d+\.\d+)", v)
                ver = ""
                if apache:
                    a = apache.group(1)
                    ver = "6" if a.startswith("2.2.") else ("7" if a == "2.4.6" else ("8" if a.startswith("2.4.37") else ""))
                out.append(Banner("centos", "CentOS Linux", ver, ver, "", False, "Server", v, r))
    return out


def cve_matches(product_cves: list[dict], b: Banner) -> list[tuple[dict, dict]]:
    """``[(cve, matched range)]`` for a banner. An incomplete version matches every range that intersects its branch."""
    out = []
    if b.incomplete:
        parts = numeric_parts(b.base)
        nxt = parts[:-1] + [str(int(parts[-1]) + 1)] if parts else []
        upper = ".".join(nxt)
    for cve in product_cves:
        for rng in cve.get("ranges", []):
            low = str(rng.get("at_or_above") or "0")
            below = str(rng.get("below") or "")
            if not below:
                continue
            if b.incomplete:
                hit = _cmp(low, upper) < 0 and _cmp(below, b.base) > 0
            else:
                hit = _cmp(b.base, low) >= 0 and _cmp(b.base, below) < 0
            if hit:
                out.append((cve, rng))
                break
    return out


def _fixed_version(b: Banner, matches: list[tuple[dict, dict]]) -> str:
    branch = numeric_parts(b.base)[:2]
    same = [str(r["below"]) for _c, r in matches if numeric_parts(str(r["below"]))[:2] == branch]
    pool = same or [str(r["below"]) for _c, r in matches]
    pool = [p for p in pool if not p.startswith("999")]
    if not pool:
        return ""
    best = pool[0]
    for p in pool[1:]:
        if _cmp(p, best) > 0:
            best = p
    return best


# ----------------------------------------------------------------------------------------------- WEB802

_FLASH_TYPES = ("application/x-shockwave-flash", "application/futuresplash")
_SILVERLIGHT_TYPES = ("application/x-silverlight", "application/x-silverlight-2")
_FLASH_CLSID = "d27cdb6e-ae6d-11cf-96b8-444553540000"


def plugin_elements(page: Page) -> list[tuple[str, Any, str]]:
    """``[(kind, element, value)]`` for live ``<object>``/``<embed>``/``<applet>``/``<param>`` plugin content."""
    doc = page.doc
    if doc is None:
        return []
    out = []
    for el in doc.find_all("object", "embed", "applet", "param"):
        tag = el.tag
        typ = (el.get("type") or "").strip().lower()
        src = (el.get("data") or el.get("src") or "").strip()
        path = urllib.parse.urlsplit(src).path.lower() if src else ""
        classid = (el.get("classid") or "").lower()
        if tag == "applet":
            out.append(("applet", el, el.get("code") or el.get("archive") or "applet"))
        elif tag == "param":
            name = (el.get("name") or "").lower()
            value = (el.get("value") or "").strip()
            vpath = urllib.parse.urlsplit(value).path.lower()
            if name in ("movie", "src") and vpath.endswith(".swf"):
                out.append(("flash", el, value))
            elif name == "source" and vpath.endswith(".xap"):
                out.append(("silverlight", el, value))
        elif typ.startswith(_FLASH_TYPES) or path.endswith(".swf") or _FLASH_CLSID in classid:
            out.append(("flash", el, src or typ or classid))
        elif typ.startswith(_SILVERLIGHT_TYPES) or path.endswith(".xap"):
            out.append(("silverlight", el, src or typ))
        elif typ.startswith("application/x-java-applet") or "8ad9c840-044e-11d1-b3e9-00805f499d93" in classid:
            out.append(("applet", el, src or typ or classid))
    return out


# ----------------------------------------------------------------------------------------------- the run

def _where(h: Hit) -> tuple[str, str]:
    key = f"where_{h.source}"
    return _note(key, name=h.name) if key in STR else (h.source, h.source)


def _evidence_for_hit(ctx: ScanContext, h: Hit) -> Evidence:
    where = {"header": "header", "cookie": "cookie", "favicon": "probe"}.get(h.source, "body")
    name = h.name or h.source
    return Evidence.for_response(h.response, where=where, name=name, value=_short(h.value, 300), now=ctx.now)


def _site_host(ctx: ScanContext, r: Response | None) -> str:
    if r is not None and r.host:
        return r.host
    return ctx.target_host


class _Run:
    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.issues: list[Issue] = []
        self.failed: set[str] = set()
        self.evaluated: set[str] = set()
        self.today = ctx.now.date()

    def emit(self, issue: Issue) -> None:
        self.issues.append(issue)
        if self.ctx.options.reports(issue.confidence):
            self.failed.add(RULES[issue.rule].check_id)


def _platform_issues(st: _Run, found: dict[str, Detected], eol_data: dict | None) -> None:
    ctx = st.ctx
    products = (eol_data or {}).get("products", {}) if isinstance(eol_data, dict) else {}
    for d in sorted(found.values(), key=lambda x: (-x.confidence, x.tech.id)):
        if not d.tech.platform or d.implied_by or not d.hits:
            continue
        st.evaluated.add("WEB080")
        best = max(d.hits, key=lambda h: h.signal.confidence if h.signal else 60)
        conf = "firm" if d.confidence >= SHOW_AT_DEFAULT else "tentative"
        shown = f"{d.tech.name} {d.version}" if d.version else d.tech.name
        where = _where(best)
        notes = [_note("signal", where=where, value=_short(best.value, 120)), _note("confidence", value=d.confidence)]
        url = best.response.url if best.response is not None else (ctx.entry.url if ctx.entry else ctx.target)
        st.emit(Issue(rule="WEB080", url=url, confidence=conf, evidence=_evidence_for_hit(ctx, best),
                      params={"platform": shown, "name": d.tech.name, "id": d.tech.id, "version": d.version,
                              "confidence_score": d.confidence, "cpe": d.cpe()},
                      group_value=d.tech.id, notes=notes, host=_site_host(ctx, best.response)))
        if not d.version or not d.tech.eol_product:
            continue
        product = products.get(d.tech.eol_product)
        if not product:
            continue
        st.evaluated.add("WEB081")
        version = d.version
        if d.tech.id in ZERO_PATCH and len(numeric_parts(version)) == 2:
            version = version + ".0"
        verdict = eol_verdict(product, version, st.today)
        if verdict is None or verdict[0] == "ok":
            continue
        state, branch, when = verdict
        if state == "patch" and len(numeric_parts(version)) < len(numeric_parts(when)):
            continue                     # "6.6" vs latest "6.6.2": the banner does not say which patch it is
        vconf = "firm" if d.version_confidence >= SHOW_AT_DEFAULT else "tentative"
        vhit = next((h for h in d.hits if h.version == d.version), best)
        if state == "eol":
            notes = [_note("eol_branch", branch=branch, date=when) if when else _note("eol_branch_nodate", branch=branch)]
            params = {"platform": d.tech.name, "version": d.version, "branch": branch, "date": when or "?"}
            sev = "medium"
        else:
            notes = [_note("latest_patch", branch=branch, latest=when)]
            params = {"platform": d.tech.name, "version": d.version, "branch": branch, "latest": when,
                      "variant": "patch"}
            sev = "low"
        notes.append(_note("signal", where=_where(vhit), value=_short(vhit.value, 120)))
        st.emit(Issue(rule="WEB081", url=vhit.response.url if vhit.response else url, confidence=vconf,
                      evidence=_evidence_for_hit(ctx, vhit), params=params, severity=sev,
                      group_value=f"{d.tech.id}@{d.version}", notes=notes, host=_site_host(ctx, vhit.response)))


def _server_issues(st: _Run, cve_data: dict | None, eol_data: dict | None) -> None:
    ctx = st.ctx
    cves = (cve_data or {}).get("products", {}) if isinstance(cve_data, dict) else {}
    eols = (eol_data or {}).get("products", {}) if isinstance(eol_data, dict) else {}
    seen800: set[tuple[str, str]] = set()
    seen801: set[tuple[str, str]] = set()
    inventory: list[dict] = []
    for b in banners(ctx):
        key = (b.product, b.version)
        inventory.append({"product": b.display, "version": b.version, "distro": b.distro, "where": b.where})
        ev = Evidence.for_response(b.response, where="header" if b.where != "error page" else "body",
                                   name=b.where, value=_short(b.raw, 300), now=ctx.now)
        where = ("error page", "صفحة خطأ") if b.where == "error page" else (b.where, b.where)
        seen_note = _note("seen_in", where=where, value=_short(b.raw, 120))
        # WEB800
        if b.product in cves and key not in seen800 and b.base:
            seen800.add(key)
            st.evaluated.add("WEB800")
            matches = cve_matches(cves[b.product], b)
            if matches:
                assumed = all(r.get("assumed") for _c, r in matches)
                tentative = bool(b.distro) or b.incomplete or assumed
                ordered = sorted(matches, key=lambda cr: (-_SEV_ORDER.get(cr[0].get("severity", ""), 0),
                                                          -float(cr[0].get("cvss") or 0), cr[0]["id"]))
                sev = ordered[0][0].get("severity", "medium")
                if tentative and sev == "critical":
                    sev = "high"
                notes = [seen_note]
                if b.distro:
                    notes.append(_note("distro", distro=b.distro))
                if b.incomplete:
                    notes.append(_note("incomplete", version=b.version))
                elif assumed:
                    notes.append(_note("assumed"))
                for c, r in ordered[:MAX_CVE_NOTES]:
                    notes.append(_note("cve", id=c["id"], severity=c.get("severity", ""),
                                       summary=_short(str(c.get("summary") or ""), 120) or "-",
                                       fixed=c.get("fixed") or r.get("below")))
                if len(ordered) > MAX_CVE_NOTES:
                    notes.append(_note("cve_more", count=len(ordered) - MAX_CVE_NOTES))
                fixed = _fixed_version(b, matches) or "the latest release"
                params = {"product": b.display, "version": b.version, "fixed": fixed,
                          "cves": [c["id"] for c, _r in ordered][:50]}
                if tentative:
                    params["variant"] = "tentative"
                st.emit(Issue(rule="WEB800", url=b.response.url, confidence="tentative" if tentative else "firm",
                              evidence=ev, params=params, severity=sev if sev in RULES["WEB800"].allowed_severities else
                              "medium", group_value=f"{b.product}@{b.version}", notes=notes, host=b.response.host))
        # WEB801
        product = eols.get(b.product)
        if product and key not in seen801 and (b.base or b.product == "centos"):
            seen801.add(key)
            st.evaluated.add("WEB801")
            if b.distro and b.product != "centos":
                continue                 # the distribution supports its own build (backports): not upstream EOL
            if b.product == "centos":
                if b.version:
                    verdict = eol_verdict(product, b.version, st.today)
                else:
                    past = [_eol_past(c.get("eol"), st.today) for c in product.get("cycles", [])]
                    verdict = ("eol", "Linux", max(w for _p, w in past)) if past and all(p for p, _w in past) else None
            else:
                verdict = eol_verdict(product, b.base, st.today)
            if verdict is None or verdict[0] != "eol":
                continue
            _state, branch, when = verdict
            notes = [_note("eol_branch", branch=branch, date=when) if when else _note("eol_branch_nodate", branch=branch),
                     seen_note]
            st.emit(Issue(rule="WEB801", url=b.response.url, confidence="firm", evidence=ev,
                          params={"product": b.display, "version": b.version or branch, "branch": branch,
                                  "date": when},
                          group_value=f"{b.product}@{branch}", notes=notes, host=b.response.host))
    ctx.inventory["server_software"] = inventory


def _plugin_issues(st: _Run) -> None:
    ctx = st.ctx
    sites = _own_sites(ctx)
    for page in ctx.pages:
        if page.doc is None or (page.response.host and psl.site(page.response.host) not in sites):
            continue
        st.evaluated.add("WEB802")
        seen: set[str] = set()
        for kind, el, value in plugin_elements(page):
            if kind in seen:
                continue
            seen.add(kind)
            r = page.response
            ev = Evidence.for_response(r, where="body", name=f"<{el.tag}>", value=_short(str(value), 300),
                                       offset=el.offset, excerpt=f"<{el.tag} … {_short(str(value), 120)}>", now=ctx.now)
            st.emit(Issue(rule="WEB802", url=r.url, confidence="certain", evidence=ev,
                          params={"technology": kind}, group_value=kind,
                          notes=[_note("plugin", tag=el.tag, what=_note(kind))], host=r.host))


def run(ctx: ScanContext) -> list[Issue]:
    cov = ctx.coverage
    dm = ctx.data or _data
    st = _Run(ctx)
    host = ctx.target_host
    db = load_db(dm)
    eol_data = _load(dm, EOL_FILE)
    cve_data = _load(dm, CVE_FILE)
    has_input = bool(ctx.pages) or bool(own_responses(ctx))
    if not has_input:
        if cov is not None:
            for c in CHECKS:
                cov.not_tested(c, "no_document", host=host)
        return []
    if db is not None:
        found = detect(ctx, db)
        _platform_issues(st, found, eol_data)
    _server_issues(st, cve_data, eol_data)
    _plugin_issues(st)
    if cov is not None:
        missing = {"WEB080": db is None, "WEB081": db is None or eol_data is None, "WEB800": cve_data is None,
                   "WEB801": eol_data is None, "WEB802": False}
        for c in CHECKS:
            if missing.get(c):
                cov.not_tested(c, "data_missing", host=host)
            elif c in st.failed:
                cov.failed(c, host)
            elif c == "WEB802" and not ctx.pages:
                cov.not_tested(c, "no_document", host=host)
            else:
                cov.passed(c, host)
    return st.issues


def i18n_catalog() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """``(CATALOG, PATTERNS)`` for cat_web2: fixed Arabic notes → English, and patterns for templated ones."""
    from .rules import template_patterns
    catalog: dict[str, str] = {}
    patterns: list[tuple[str, str]] = []
    for en, ar in STR.values():
        if "{" in ar:
            patterns.extend(template_patterns(ar, en))
        else:
            catalog[ar] = en
    return catalog, patterns


__all__ = ["CHECKS", "run", "detect", "load_db", "build_db", "banners", "parse_banner", "cve_matches", "eol_verdict",
           "find_cycle", "version_key", "numeric_parts", "plugin_elements", "own_responses", "Detected", "TechDB",
           "Banner", "PLATFORM_CATEGORIES", "STR", "i18n_catalog"]
