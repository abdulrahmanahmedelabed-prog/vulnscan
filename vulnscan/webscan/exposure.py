"""Exposure, well-known files, the deep probe and subdomain takeover (spec §2.10), WP11.

Rules: WEB060 (no security.txt), WEB900 (security.txt invalid, RFC 9116 via :mod:`.sectxt`), WEB061 (robots.txt names
sensitive paths), WEB062 (exposed sensitive file, ``data/web/exposed-paths.json``), WEB082/WEB083 (platform deep paths
from ``tech.json``), WEB901 (possible subdomain takeover, ``takeover.json``) and WEB903 (permissive Flash/Silverlight
cross-domain policy).

Two entry points:

* :func:`probe` — **the only network access of this module** (spec §4.2), called by the engine in pipeline step 6 and
  only with ``--deep``. It plans the fixed list (``exposed-paths.json``, the deep paths of the platforms tech.py
  detected, ``/crossdomain.xml`` and ``/clientaccesspolicy.xml``; at most :data:`MAX_PROBES`, never a path of the §0.1
  never-list), fetches the per-directory soft-404 baselines planned by ``classify.plan_baselines`` and then each path once
  with ``GET`` through the scan's Fetcher (no redirect is followed, so a probe costs one request), appending to
  ``ctx.baselines`` and ``ctx.probes``. The plan and what could not be fetched go to ``ctx.inventory["deep_probe"]``.
* :func:`run` — pure; judges what is in ``ctx`` (well-known files, probes, baselines, DNS facts).

The §2.10 gate for a deep-probe path: (a) status 200 or 206; (b) the body matches the path's signature (every path has
one); (c) no soft-404 baseline of the same directory and extension class (or a parent, or a natural catch-all page)
matches that signature, and none is byte-identical; (d) the response kind is one the path expects (HTML only where the
exposure is HTML by nature). For a *strong* signature (magic bytes, ``^ref: refs/``, ``[core]`` …) (c) is decisive: a
short file is never dismissed because a catch-all page has a similar length or simhash. For a *weak* signature (HTML
pages: phpinfo, server-status, Swagger UI, admin and login pages) the response must in addition not be similar to the
baseline (``classify.Soft404Index.match``) nor to the entry document (SPA shells).

Evidence never carries a full body: excerpts of configuration, credential and log files have their values redacted
(first 4 and last 2 characters, §3.6).
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Iterable

from . import classify, htmlparse, psl, sectxt
from . import data as _data
from .rules import RULES, checks_for_module
from .types import (Evidence, Issue, Response, ScanContext, normalise_host, redact_secret, strip_controls,
                    url_origin)

CHECKS: tuple[str, ...] = checks_for_module("exposure")

EXPOSED_FILE = "exposed-paths.json"
TAKEOVER_FILE = "takeover.json"
TECH_FILE = "tech.json"
MAX_PROBES = 70                       # §0.1: fixed deep list incl. platform paths
OK_STATUS = (200, 206)
SHOW_PLATFORM_AT = 50                 # tech.py confidence from which a platform's deep paths are probed (paranoid: any)
SECTXT_PATH = sectxt.WELL_KNOWN_PATH
SECTXT_LEGACY = sectxt.LEGACY_PATH
ROBOTS_PATH = "/robots.txt"
CROSSDOMAIN = "/crossdomain.xml"
CLIENTACCESS = "/clientaccesspolicy.xml"
DEEP_RULES = ("WEB062", "WEB082", "WEB083", "WEB903")

# §0.1 never-list: endpoints whose GET makes the server do expensive or state-changing work. No data file may list
# them and probe() refuses them even if one does (defence in depth; tests/web/test_exposure.py greps the data files).
NEVER_LIST = re.compile(
    r"(?i)heapdump|threaddump|thread-dump|heap-dump|/debug/pprof|pprof|/actuator/(?:shutdown|restart|pause|resume|refresh"
    r"|logfile|loggers|caches|jolokia|sessions|startup|quartz)|/jolokia|/purge|cache[-_/]?(?:clear|purge|flush)"
    r"|/flush|/install(?:er)?(?:\.php)?(?:/|$)|/setup(?:\.php)?(?:/|$)|/upgrade(?:\.php)?(?:/|$)|/cron(?:\.php)?(?:/|$)"
    r"|/wp-cron\.php|/xmlrpc\.php\?|/(?:shutdown|restart|reboot)(?:/|$)|/server-status\?(?!auto)")

# robots.txt words judged as path segments (WEB061)
ROBOTS_WORDS = frozenset({"admin", "internal", "private", "backup", "secret", "config", "staging", "dev", "test", "old",
                          "db", "sql", "phpmyadmin", "cpanel"})
ROBOTS_DOT_WORDS = (".git", ".env")
ACTUATOR_SENSITIVE = ("heapdump", "threaddump", "env", "logfile", "jolokia")
# paths whose matched text carries no secret (no value redaction in evidence)
_NO_SECRET_PATHS = frozenset({"/.git/HEAD", "/.svn/entries", "/.hg/requires", "/nginx_status", "/.DS_Store",
                              "/.svn/wc.db"})

STR: dict[str, tuple[str, str]] = {
    "probe_never": ("Paths on the never-list (heap/thread dumps, profilers, cache purges, installers) are never requested.",
                    "لا تُطلب أبدًا المسارات الممنوعة (تفريغ الذاكرة أو الخيوط، وأدوات التحليل، ومسح الذاكرة المؤقتة، "
                    "وبرامج التثبيت)."),
    "sectxt_absent": ("{url} answered {status}; no security.txt was found at /.well-known/security.txt or /security.txt.",
                      "أجاب {url} بالرمز {status}؛ ولم يوجد ملف security.txt في /.well-known/security.txt ولا في "
                      "/security.txt."),
    "sectxt_catch_all": ("The server answers every path with the same page, so the response at {url} is not a "
                         "security.txt.",
                         "يجيب الخادم عن كل مسار بالصفحة نفسها، لذا فالاستجابة في {url} ليست ملف security.txt."),
    "sectxt_html": ("{url} returned an HTML page without any security.txt field.",
                    "أعاد {url} صفحة HTML لا تحوي أي حقل من حقول security.txt."),
    "robots_paths": ("robots.txt names: {paths}. These paths were not requested.",
                     "يذكر ملف robots.txt المسارات: {paths}. ولم يطلب كاشف هذه المسارات."),
    "baseline_differs": ("A request for a random path in the same directory ({baseline}) answered differently, so this "
                         "is a real file and not a catch-all page.",
                         "أجاب طلب لمسار عشوائي في المجلد نفسه ({baseline}) إجابةً مختلفة، لذا فهذا ملف حقيقي وليس صفحة "
                         "عامة تُعاد لكل المسارات."),
    "actuator_links": ("The Actuator index lists {links}; these endpoints were not requested.",
                       "يسرد فهرس Actuator النقاط {links}؛ ولم يطلبها كاشف."),
    "public_api_docs": ("The site links to this page itself, so it looks like intentionally published API documentation.",
                        "يشير الموقع نفسه إلى هذه الصفحة، لذا تبدو توثيقًا منشورًا عمدًا لواجهة API."),
    "crossdomain": ("{path} allows every domain: {value}", "يسمح الملف {path} لكل النطاقات: {value}"),
    "crossdomain_insecure": ("secure=\"false\" also lets pages served over plain HTTP read HTTPS content.",
                             "كما تسمح القيمة secure=\"false\" لصفحات تُقدَّم عبر HTTP غير المشفّر بقراءة محتوى HTTPS."),
    "crossdomain_no_session": ("The site sets no session cookie, so the policy exposes less.",
                               "لا يضبط الموقع كوكي جلسة، لذا فالسياسة تكشف قدرًا أقل."),
    "takeover": ("{host} is a CNAME to {cname} ({provider}) and the response is that provider's page for an unclaimed "
                 "name: \"{fingerprint}\". Anyone who registers that name at {provider} can serve content on {host}.",
                 "{host} اسم مستعار CNAME يشير إلى {cname} ({provider})، والاستجابة هي صفحة ذلك المزوّد لاسم غير مُطالَب "
                 "به: «{fingerprint}». ويستطيع أي شخص يسجّل ذلك الاسم لدى {provider} أن ينشر محتوى على {host}."),
    "dangling": ("The name does not resolve; if it is a CNAME to a cloud service, check for a dangling DNS record "
                 "(takeover risk).",
                 "الاسم لا يُحَلّ إلى عنوان؛ فإن كان اسمًا مستعارًا CNAME لخدمة سحابية فتحقّق من وجود سجل DNS معلّق (خطر "
                 "الاستيلاء على النطاق)."),
    "offsite": ("the entry page redirected to another site, which was not deep-probed",
                "أعادت الصفحة الأولى التوجيه إلى موقع آخر، فلم يُفحص فحصًا عميقًا"),
    "sectxt_not_sectxt": ("{url} returned a file without any security.txt field.",
                          "أعاد {url} ملفًا لا يحوي أي حقل من حقول security.txt."),
    "sectxt_denied": ("{url} answered {status}, so researchers cannot read a security.txt there.",
                      "أجاب {url} بالرمز {status}، لذا لا يستطيع الباحثون قراءة ملف security.txt هناك."),
    "takeover_mitigated": ("{host} points to {provider} ({cname}), whose unclaimed-name page was seen, but {provider} no "
                           "longer allows claiming a name this way; not reported.",
                           "يشير {host} إلى {provider} ‏({cname})، وظهرت صفحة الاسم غير المُطالَب به، لكن {provider} لم "
                           "يعد يسمح بالمطالبة بالاسم بهذه الطريقة؛ لذا لم يُبلَّغ عنه."),
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


def _load(dm: Any, name: str) -> Any:
    try:
        return dm.load_json(name)
    except Exception:   # noqa: BLE001 - a missing or broken data file makes the check not_tested, never a crash
        return None


# ----------------------------------------------------------------------------------------------- deep-path specs

@dataclass(frozen=True)
class DeepPath:
    """One deep-probe path (a DEEP_PATH data entry, or a built-in WEB903 policy file)."""
    path: str
    rule: str
    severity: str
    cwe: str
    kinds: tuple[str, ...]
    signature: dict
    strength: str
    title_en: str = ""
    title_ar: str = ""
    advice_en: str = ""
    advice_ar: str = ""
    status: tuple[int, ...] = OK_STATUS
    severity_if: tuple[tuple[str, str], ...] = ()
    asvs5: str = ""
    platform: str = ""                # technology name (WEB082/WEB083)
    tech_id: str = ""
    note: str = ""

    @classmethod
    def from_dict(cls, d: dict, platform: str = "", tech_id: str = "") -> "DeepPath":
        return cls(path=d["path"], rule=d["rule"], severity=d["severity"], cwe=d.get("cwe", ""),
                   kinds=tuple(d.get("kinds") or ()), signature=d.get("signature") or {},
                   strength=d.get("strength", "strong"), title_en=d.get("title_en", ""), title_ar=d.get("title_ar", ""),
                   advice_en=d.get("advice_en", ""), advice_ar=d.get("advice_ar", ""),
                   status=tuple(d.get("status") or OK_STATUS),
                   severity_if=tuple(sorted((d.get("severity_if") or {}).items())), asvs5=d.get("asvs5", ""),
                   platform=platform, tech_id=tech_id, note=d.get("note", ""))


_ANY_KIND = ("api_xml", "text", "download", "other", "api_json", "document")
POLICY_FILES: dict[str, DeepPath] = {
    CROSSDOMAIN: DeepPath(CROSSDOMAIN, "WEB903", "medium", "CWE-942", _ANY_KIND,
                          {"all": [{"type": "regex", "pattern": r"<cross-domain-policy\b"},
                                   {"type": "regex", "pattern": r"<allow-access-from\b[^>]*\bdomain\s*=\s*[\"']\*[\"']"}],
                           "not_html": True}, "strong"),
    CLIENTACCESS: DeepPath(CLIENTACCESS, "WEB903", "medium", "CWE-942", _ANY_KIND,
                           {"all": [{"type": "regex", "pattern": r"<access-policy\b"},
                                    {"type": "regex", "flags": "s",
                                     "pattern": r"<allow-from\b[^>]*>(?:(?!</allow-from>).){0,2000}?"
                                                r"<domain\s+uri\s*=\s*[\"']\*[\"']"}],
                            "not_html": True}, "strong"),
}


def exposed_paths(dm: Any = None) -> list[DeepPath]:
    doc = _load(dm or _data, EXPOSED_FILE)
    if not isinstance(doc, dict):
        return []
    return [DeepPath.from_dict(d) for d in doc.get("paths") or [] if isinstance(d, dict) and d.get("path")]


def platform_paths(dm: Any = None, platforms: Iterable[str] | None = None) -> list[DeepPath]:
    """Deep paths of tech.json (WEB082/WEB083), for the given technology ids (all when ``platforms`` is None)."""
    doc = _load(dm or _data, TECH_FILE)
    if not isinstance(doc, dict):
        return []
    want = None if platforms is None else {p.lower() for p in platforms}
    out = []
    for t in doc.get("technologies") or []:
        if not isinstance(t, dict) or (want is not None and str(t.get("id", "")).lower() not in want):
            continue
        for d in t.get("deep_paths") or []:
            if isinstance(d, dict) and d.get("path"):
                out.append(DeepPath.from_dict(d, platform=str(t.get("name") or t.get("id")), tech_id=str(t.get("id"))))
    return out


def detected_platforms(ctx: ScanContext) -> list[str]:
    """Technology ids from ``ctx.inventory["technologies"]`` (tech.py) whose deep paths should be probed."""
    out = []
    for t in (ctx.inventory or {}).get("technologies") or []:
        if not isinstance(t, dict) or not t.get("id"):
            continue
        conf = t.get("confidence", 100)
        if ctx.options.paranoid or not isinstance(conf, (int, float)) or conf >= SHOW_PLATFORM_AT:
            out.append(str(t["id"]))
    return out


def _sev_rank(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev, 5)


def plan(ctx: ScanContext, platforms: Iterable[str] | None = None) -> list[DeepPath]:
    """The ordered probe list (most severe first, exposed list, then platform paths, then the policy files), at most
    :data:`MAX_PROBES`, each path once, never a never-list path."""
    dm = ctx.data or _data
    plats = detected_platforms(ctx) if platforms is None else list(platforms)
    items = sorted(exposed_paths(dm), key=lambda p: _sev_rank(p.severity))
    items += sorted(platform_paths(dm, plats), key=lambda p: _sev_rank(p.severity)) if plats else []
    items += list(POLICY_FILES.values())
    seen: set[str] = set()
    out: list[DeepPath] = []
    for p in items:
        if p.path in seen or NEVER_LIST.search(p.path):
            continue
        seen.add(p.path)
        out.append(p)
    return out[:MAX_PROBES]


def _probe_origin(ctx: ScanContext) -> tuple[str | None, str]:
    """(origin to probe, reason when the deep probe cannot run)."""
    entry = ctx.entry
    if entry is not None:
        kind = _orig_kind(entry)
        if kind == "waf_challenge":
            return None, "waf"
        if kind == "rate_limited":
            return None, "rate_limited"
        if entry.status is not None and not entry.error:
            if not _same_site(entry.host, ctx.target_host):
                return None, "offsite"           # never deep-probe a site the entry chain merely redirected to
            return url_origin(entry.url), ""
    if ctx.target:
        return url_origin(ctx.target), ""
    return None, "not_run"


def _same_site(a: str, b: str) -> bool:
    if not a or not b or a == b:
        return True
    try:
        return psl.same_site(a, b)
    except Exception:   # noqa: BLE001 - PSL data missing: compare host names only
        return a == b


def probe(ctx: ScanContext, platforms: Iterable[str] | None = None) -> dict:
    """Fetch the per-directory soft-404 baselines and the deep-probe paths (``--deep`` only; see the module docstring).

    ``platforms``: technology ids whose tech.json deep paths are probed (default: what tech.py stored in
    ``ctx.inventory["technologies"]``). Returns the report also stored in ``ctx.inventory["deep_probe"]``."""
    report: dict[str, Any] = {"planned": [], "fetched": 0, "skipped": [], "skipped_reason": "", "baselines": 0}
    ctx.inventory["deep_probe"] = report
    if not ctx.options.deep:
        report["skipped_reason"] = "deep_off"
        return report
    fetcher = ctx.fetcher
    origin, why = _probe_origin(ctx)
    if fetcher is None or origin is None:
        report["skipped_reason"] = why or "not_run"
        return report
    items = plan(ctx, platforms)
    report["planned"] = [{"path": p.path, "rule": p.rule, "platform": p.platform} for p in items]
    urls = [origin + p.path for p in items]
    have = [r.url for r in ctx.baselines if r is not None]
    for u in classify.plan_baselines(urls, have=have):
        if _remaining(fetcher) <= 0:
            break
        ctx.baselines.append(fetcher.fetch(u, source="baseline", follow=False, accept="probe"))
        report["baselines"] += 1
    for p, u in zip(items, urls):
        if NEVER_LIST.search(p.path):        # pragma: no cover - plan() already removed them
            continue
        if _remaining(fetcher) <= 0:
            report["skipped"].append({"path": p.path, "reason": "budget"})
            continue
        ctx.probes.append(fetcher.fetch(u, source="probe", follow=False, accept="probe"))
        report["fetched"] += 1
    return report


def _remaining(fetcher: Any) -> int:
    fn = getattr(fetcher, "remaining_requests", None)
    if fn is None:
        return 1 << 30
    try:
        return int(fn("probe"))
    except Exception:   # noqa: BLE001 - a test double without budgets
        return 1 << 30


# ----------------------------------------------------------------------------------------------- signatures

_FLAG_BITS = {"i": re.I, "m": re.M, "s": re.S, "x": re.X}
_RX_CACHE: dict[tuple[str, str], re.Pattern] = {}
_HTML_START = re.compile(r"\A\s*(?:<!--.*?-->\s*)*<(?:!doctype\s+html|html|head|body)\b", re.I | re.S)


def _rx(pattern: str, flags: str = "") -> re.Pattern:
    key = (pattern, flags)
    rx = _RX_CACHE.get(key)
    if rx is None:
        bits = 0
        for f in flags:
            bits |= _FLAG_BITS.get(f, 0)
        rx = _RX_CACHE[key] = re.compile(pattern, bits)
    return rx


def looks_html(body: bytes, text: str | None = None) -> bool:
    if classify.sniff(body[:1024]) == "text/html":
        return True
    t = text if text is not None else body[:2048].decode("utf-8", "replace")
    return bool(_HTML_START.match(t[:2048]))


@dataclass
class CondMatch:
    cond: dict
    offset: int          # character offset in the text (bytes for magic)
    value: str


def _cond(cond: dict, body: bytes, text: str) -> CondMatch | None:
    typ, pat = cond.get("type"), cond.get("pattern", "")
    within = cond.get("within")
    need = int(cond.get("min_count") or 1)
    if typ == "magic":
        try:
            magic = bytes.fromhex(pat)
        except ValueError:
            return None
        return CondMatch(cond, 0, f"magic {magic.hex()}") if body.startswith(magic) else None
    hay = text[:within] if within else text
    if typ == "prefix":
        h = hay.lstrip("﻿")
        return CondMatch(cond, 0, pat) if h.startswith(pat) else None
    if typ == "contains":
        n = hay.count(pat)
        return CondMatch(cond, hay.find(pat), pat) if n >= need and n else None
    if typ == "regex":
        rx = _rx(pat, cond.get("flags", ""))
        first = None
        n = 0
        for m in rx.finditer(hay):
            first = first or m
            n += 1
            if n >= need:
                break
        if first is not None and n >= need:
            return CondMatch(cond, first.start(), first.group(0))
    return None


def match_signature(sig: dict, body: bytes, text: str | None = None) -> list[CondMatch] | None:
    """The matched conditions of a DEEP_PATH signature (``all`` + the matching ``any``), or None when it does not
    match (an ``all`` condition fails, no ``any`` matches, a ``none`` matches, or ``not_html`` and the body is HTML)."""
    if not sig or not body:
        return None
    if text is None:
        text = body.decode("utf-8", "replace")
    if sig.get("not_html") and looks_html(body, text):
        return None
    out: list[CondMatch] = []
    for c in sig.get("all") or []:
        m = _cond(c, body, text)
        if m is None:
            return None
        out.append(m)
    anys = sig.get("any") or []
    if anys:
        hits = [m for m in (_cond(c, body, text) for c in anys) if m is not None]
        if not hits:
            return None
        out.extend(hits)
    for c in sig.get("none") or []:
        if _cond(c, body, text) is not None:
            return None
    return out or None


# ----------------------------------------------------------------------------------------------- the gate

def _orig_kind(r: Response) -> str:
    """The §3.1 kind before the soft-404 override (row 9): exposure judges soft 404s itself."""
    if r.kind and r.kind != "soft404":
        return r.kind
    return classify.kind_of(r)[0]


# ``error:<code>`` flags of responses that were never received → coverage reason (mirrors http.ERROR_CODES; check
# modules do not import http.py, spec §4.2)
_ERR_REASON = {"budget": "budget", "time_budget": "time_budget", "byte_budget": "byte_budget", "timeout": "timeout",
               "deadline": "timeout", "robots": "robots", "host_stopped": "rate_limited", "profile": "profile"}


def _error_reason(r: Response) -> str:
    for f in r.flags:
        if f.startswith("error:"):
            return _ERR_REASON.get(f[6:], "network")
    if "host-stopped" in r.flags:
        return "rate_limited"
    return "network"


@dataclass
class Verdict:
    state: str                                 # exposed | clean | not_tested | inconclusive
    reason: str = ""
    matches: list[CondMatch] = field(default_factory=list)
    baseline: dict | None = None


def _text(r: Response) -> str:
    try:
        return r.text()
    except Exception:   # noqa: BLE001 - undecodable bodies are judged as empty text
        return ""


def judge(r: Response, spec: DeepPath, index: classify.Soft404Index, refs: dict[str, Response],
          entry: Response | None = None) -> Verdict:
    """Apply the §2.10 gate to one deep-probe response (see the module docstring)."""
    if r.error or r.status is None:
        return Verdict("not_tested", _error_reason(r))
    kind = _orig_kind(r)
    if kind == "waf_challenge":
        return Verdict("inconclusive", "waf")
    if kind == "rate_limited":
        return Verdict("inconclusive", "rate_limited")
    if r.status not in spec.status:
        return Verdict("clean", f"status {r.status}")
    if "opaque-coding" in r.flags:
        return Verdict("not_tested", "unsupported_coding")
    text = _text(r)
    if kind == "document" and spec.signature.get("not_html") and "document" not in spec.kinds \
            and not looks_html(r.body, text):
        kind = "text"                     # a text file mislabelled text/html (e.g. a server's default type)
    if spec.kinds and kind not in spec.kinds:
        return Verdict("clean", f"kind {kind}")
    matches = match_signature(spec.signature, r.body, text)
    if not matches:
        return Verdict("clean", "signature")
    hs = index.hosts.get(r.host)
    candidates = list(index.candidates(r)) + (list(hs.catch_all) if hs else [])
    sha = r.body_sha256()
    path = r.parsed_url.path or "/"
    for b in candidates:
        if b.path == path:
            continue
        if b.signature.sha256 == sha:
            return Verdict("clean", "identical to the soft-404 baseline")
        br = refs.get(b.signature.url)
        if br is not None and br.status is not None and 200 <= br.status < 300 and br.body \
                and match_signature(spec.signature, br.body, _text(br)):
            return Verdict("clean", "the soft-404 baseline matches the signature too")
    if spec.strength == "weak":
        if index.match(r) is not None:
            return Verdict("clean", "similar to the soft-404 baseline")
        # SPA shells: without a baseline proving real 404s here, a page like the entry document is the shell
        real_404_here = bool(candidates) and candidates[0].real_404
        if not real_404_here and entry is not None and entry is not r and entry.is_2xx and entry.body:
            if match_signature(spec.signature, entry.body, _text(entry)):
                return Verdict("clean", "the entry document matches the signature too")
            if classify.similar(classify.signature(r), classify.signature(entry)):
                return Verdict("clean", "similar to the entry document")
    base = candidates[0].evidence() if candidates else None
    return Verdict("exposed", "", matches, base)


# ----------------------------------------------------------------------------------------------- evidence helpers

_VALUE = re.compile(r"(?P<sep>[=:]|=>)(?P<sp>\s*)(?P<q>[\"']?)(?P<v>[^\s\"'<>,;)]{3,})")
_USERINFO = re.compile(r"(?P<pre>://[^:/@\s]+:)(?P<pw>[^@/\s]+)(?=@)")


def redact_values(line: str) -> str:
    """Redact assigned values (``KEY=value``, ``"key": "value"``, ``user:hash``) and URL passwords in one line."""
    line = _USERINFO.sub(lambda m: m.group("pre") + redact_secret(m.group("pw")), line)
    return _VALUE.sub(lambda m: m.group("sep") + m.group("sp") + m.group("q") + redact_secret(m.group("v")), line)


def _excerpt(text: str, offset: int, redact: bool) -> str:
    start = text.rfind("\n", 0, max(0, offset)) + 1
    end = text.find("\n", offset)
    line = text[start: end if end >= 0 else len(text)]
    line = _short(line, 200)
    return redact_values(line) if redact else line


def _match_evidence(spec: DeepPath, r: Response, matches: list[CondMatch]) -> tuple[str, int | None, str]:
    """(value, offset, excerpt) for a matched probe; values of secret-bearing files are redacted."""
    m = matches[0]
    if m.cond.get("type") == "magic":
        return m.value, 0, m.value
    text = _text(r)
    html = "document" in spec.kinds
    redact = not html and spec.path not in _NO_SECRET_PATHS
    excerpt = _excerpt(text, m.offset, redact)
    value = _short(m.value, 120)
    if redact:
        value = redact_values(value)
    return value, m.offset, excerpt


# ----------------------------------------------------------------------------------------------- run state

class _Run:
    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.cov = ctx.coverage
        self.issues: list[Issue] = []
        self.host = ctx.target_host

    def emit(self, issue: Issue) -> None:
        meta = RULES[issue.rule]
        if issue.severity is not None and issue.severity not in meta.allowed_severities:
            issue.severity = meta.severity
        if not issue.host:
            issue.host = normalise_host(urllib.parse.urlsplit(issue.url).hostname or "") or self.host
        self.issues.append(issue)

    def state(self, check: str, state: str, reason: str = "", host: str = "", **kw: Any) -> None:
        if self.cov is not None:
            self.cov.record(check, state, reason, host=host or self.host, **kw)


def _resp_path(r: Response) -> str:
    first = r.chain[0] if r.chain else r
    return urllib.parse.urlsplit(first.url).path or "/"


# ----------------------------------------------------------------------------------------------- security.txt

def _presence(r: Response | None, index: classify.Soft404Index,
              looks_like: Any = sectxt.looks_like_sectxt) -> tuple[str, str, str]:
    """(present | absent | unknown, reason code, detail key) for a well-known response. ``looks_like(text)`` says
    whether a 2xx body is that file at all (an HTML page or a bare "OK" from a catch-all is not)."""
    if r is None:
        return "unknown", "not_run", ""
    if r.error or r.status is None:
        return "unknown", _error_reason(r), ""
    kind = _orig_kind(r)
    if kind == "waf_challenge":
        return "unknown", "waf", ""
    if kind == "rate_limited":
        return "unknown", "rate_limited", ""
    if r.status in (404, 410):
        return "absent", "", "sectxt_absent"
    if r.status in (401, 403, 451):
        return "absent", "", "sectxt_denied"
    if not r.is_2xx:
        return "unknown", "network", ""
    if r.kind == "soft404" or "soft404" in r.flags or index.match(r) is not None:
        return "absent", "", "sectxt_catch_all"
    if "opaque-coding" in r.flags:
        return "unknown", "unsupported_coding", ""
    text = _text(r)
    if not looks_like(text):
        if r.essence in classify.HTML_TYPES or looks_html(r.body, text):
            return "absent", "", "sectxt_html"
        return "absent", "", "sectxt_not_sectxt"
    return "present", "", ""


def _security_txt(st: _Run, index: classify.Soft404Index) -> None:
    ctx = st.ctx
    if ctx.options.profile == "minimal":
        st.state("WEB060", "not_tested", "profile")
        st.state("WEB900", "not_tested", "profile")
        return
    wk = ctx.wellknown.get(SECTXT_PATH)
    legacy = ctx.wellknown.get(SECTXT_LEGACY)
    p_wk = _presence(wk, index)
    p_lg = _presence(legacy, index) if legacy is not None else None
    chosen: Response | None = None
    is_legacy = False
    if p_wk[0] == "present":
        chosen = wk
    elif p_wk[0] == "absent" and p_lg is not None and p_lg[0] == "present":
        chosen, is_legacy = legacy, True
    elif p_wk[0] == "absent" and (p_lg is None or p_lg[0] == "absent"):
        r = legacy if legacy is not None else wk
        detail = (p_lg or p_wk)[2] or p_wk[2]
        ev = Evidence.for_response(r, where="probe", name=_resp_path(r), value=f"HTTP {r.status}", now=ctx.now)
        st.emit(Issue(rule="WEB060", url=r.url, confidence="certain", evidence=ev, group_value="security.txt",
                      notes=[_note(detail or "sectxt_absent", url=_short(r.url, 200), status=str(r.status))]))
        st.state("WEB060", "fail")
        st.state("WEB900", "not_applicable", "")
        ctx.inventory["security_txt"] = {"present": False}
        return
    else:
        code = p_wk[1] if p_wk[0] == "unknown" else (p_lg[1] if p_lg else "not_run")
        state = "inconclusive" if code in ("waf", "rate_limited") else "not_tested"
        st.state("WEB060", state, code or "not_run")
        st.state("WEB900", state, code or "not_run")
        return
    st.state("WEB060", "pass")
    assert chosen is not None
    requested = chosen.chain[0].url if chosen.chain else chosen.url
    result = sectxt.validate(chosen.body, url=chosen.url, requested_url=requested, content_type=chosen.content_type or "",
                             now=ctx.now, legacy=is_legacy)
    ctx.inventory["security_txt"] = {"present": True, "url": _short(chosen.url, 300), "legacy": is_legacy,
                                     **result.summary()}
    if not result.problems:
        st.state("WEB900", "pass")
        return
    first = result.problems[0]
    lines = _text(chosen).splitlines()
    excerpt = lines[first.line - 1] if 0 < first.line <= len(lines) else ""
    ev = Evidence.for_response(chosen, where="body", name=_resp_path(chosen), value=first.text("en"),
                               excerpt=_short(excerpt, 200), now=ctx.now)
    notes = result.notes()
    if result.signed:
        notes.append(_note_raw(sectxt.STR["signed"]))
    st.emit(Issue(rule="WEB900", url=chosen.url, confidence="certain", evidence=ev, severity=result.severity,
                  group_value="security.txt", notes=notes,
                  params={"problems": [p.code for p in result.problems]}))
    st.state("WEB900", "fail")


def _note_raw(pair: tuple[str, str]) -> tuple[str, str]:
    return pair[0], pair[1]


# ----------------------------------------------------------------------------------------------- robots.txt

def robots_paths(text: str) -> dict[str, list[str]]:
    """``{"disallow": [...], "allow": [...], "sitemaps": [...]}`` from a robots.txt body (all groups; never fetched)."""
    out: dict[str, list[str]] = {"disallow": [], "allow": [], "sitemaps": []}
    for raw in text.splitlines()[:5000]:
        line = raw.split("#", 1)[0].strip()
        key, sep, value = line.partition(":")
        if not sep:
            continue
        k = key.strip().lower()
        v = value.strip()
        if not v:
            continue
        if k == "disallow" and v not in out["disallow"]:
            out["disallow"].append(v)
        elif k == "allow" and v not in out["allow"]:
            out["allow"].append(v)
        elif k == "sitemap" and v not in out["sitemaps"]:
            out["sitemaps"].append(v)
    return out


def sensitive_robots_path(path: str) -> bool:
    """True when a robots path has a sensitive word as a whole path segment (``/admin/``, ``/backup.zip``, ``/.git``),
    not inside a longer word (``/administration-guide``, ``/wp-admin/``)."""
    p = path.split("?", 1)[0]
    for seg in p.split("/"):
        s = re.split(r"[*$;#]", seg.lower(), maxsplit=1)[0]
        if not s:
            continue
        if any(s == d or s.startswith(d + ".") or s.startswith(d + "/") for d in ROBOTS_DOT_WORDS):
            return True
        if s.startswith("."):
            continue
        stem = s.split(".", 1)[0]
        if s in ROBOTS_WORDS or stem in ROBOTS_WORDS:
            return True
    return False


def _robots(st: _Run, index: classify.Soft404Index) -> None:
    ctx = st.ctx
    if ctx.options.profile == "minimal":
        st.state("WEB061", "not_tested", "profile")
        return
    r = ctx.wellknown.get(ROBOTS_PATH)
    state, reason, _detail = _presence_text(r, index)
    if state == "unknown":
        st.state("WEB061", "inconclusive" if reason in ("waf", "rate_limited") else "not_tested", reason)
        return
    if state == "absent":
        st.state("WEB061", "not_applicable")
        return
    assert r is not None
    text = _text(r)
    found = robots_paths(text)
    ctx.inventory["robots"] = {"url": _short(r.url, 300), "disallow": found["disallow"][:200],
                               "allow": found["allow"][:200], "sitemaps": found["sitemaps"][:20]}
    hits = [p for p in found["disallow"] + found["allow"] if sensitive_robots_path(p)]
    if not hits:
        st.state("WEB061", "pass")
        return
    first = hits[0]
    off = -1
    for m in re.finditer(r"(?im)^\s*(?:dis)?allow\s*:\s*(\S+)", text):
        if m.group(1) == first:
            off = m.start()
            break
    excerpt = _excerpt(text, off, False) if off >= 0 else first
    shown = ", ".join(_short(h, 80) for h in hits[:10]) + (" …" if len(hits) > 10 else "")
    ev = Evidence.for_response(r, where="body", name=ROBOTS_PATH, value=shown, offset=off if off >= 0 else None,
                               excerpt=excerpt, now=ctx.now)
    st.emit(Issue(rule="WEB061", url=r.url, confidence="firm", evidence=ev, group_value="robots.txt",
                  notes=[_note("robots_paths", paths=shown)], params={"paths": hits[:50]}))
    st.state("WEB061", "fail")


_ROBOTS_LINE = re.compile(r"(?im)^\s*(?:user-agent|disallow|allow|sitemap|crawl-delay)\s*:")


def looks_like_robots(text: str) -> bool:
    """True when ``text`` has at least one robots.txt record line and is not an HTML page."""
    return bool(_ROBOTS_LINE.search(text[:65536])) and not _HTML_START.match(text[:2048])


def _presence_text(r: Response | None, index: classify.Soft404Index) -> tuple[str, str, str]:
    """Like :func:`_presence` for robots.txt: an HTML page or a body without any record line is not the file."""
    return _presence(r, index, looks_like_robots)


# ----------------------------------------------------------------------------------------------- deep probe

def _session_cookie(ctx: ScanContext) -> bool:
    return any(c.is_session_class and not c.deletion and not c.ignored for c in ctx.cookies)


def _site_links_to(ctx: ScanContext, path: str) -> bool:
    for p in ctx.pages:
        if p.doc is None:
            continue
        for el in p.doc.find_all("a", "link"):
            href = el.get("href")
            if not href:
                continue
            u = urllib.parse.urlsplit(p.doc.resolve(href))
            if (u.path or "/").rstrip("/") == path.rstrip("/") and normalise_host(u.hostname or "") == p.response.host:
                return True
    return False


def _actuator_links(r: Response) -> list[str]:
    try:
        doc = json.loads(_text(r))
    except ValueError:
        return []
    links = doc.get("_links") if isinstance(doc, dict) else None
    if not isinstance(links, dict):
        return []
    return [k for k in ACTUATOR_SENSITIVE if k in links]


def _severity(st: _Run, spec: DeepPath, r: Response, notes: list[tuple[str, str]]) -> str:
    sev = spec.severity
    for cond, value in spec.severity_if:
        if cond == "actuator_sensitive_links":
            links = _actuator_links(r)
            if links:
                sev = value
                notes.append(_note("actuator_links", links=", ".join(links)))
        elif cond == "public_api_docs" and _site_links_to(st.ctx, spec.path):
            sev = value
            notes.append(_note("public_api_docs"))
    if spec.rule == "WEB903" and not _session_cookie(st.ctx):
        sev = "low"
        notes.append(_note("crossdomain_no_session"))
    return sev


def _live_login(r: Response, matches: list[CondMatch]) -> bool:
    """WEB083: a live password field (not inside <template>/<noscript>) or a non-password admin marker matched."""
    if any("password" not in str(m.cond.get("pattern", "")).lower() for m in matches):
        return True
    try:
        doc = htmlparse.parse_response(r)
    except Exception:   # noqa: BLE001 - unparsable HTML has no live field
        return False
    return doc.has_password_field


def _deep(st: _Run, index: classify.Soft404Index) -> None:
    ctx = st.ctx
    if not ctx.options.deep:
        for c in DEEP_RULES:
            st.state(c, "not_tested", "deep_off")
        return
    report = (ctx.inventory or {}).get("deep_probe") or {}
    skipped_reason = report.get("skipped_reason") or ""
    if skipped_reason and not ctx.probes:
        state = "inconclusive" if skipped_reason in ("waf", "rate_limited") else "not_tested"
        detail: dict[str, str] = {}
        if skipped_reason == "offsite":          # not a coverage.REASONS code: explain it in both languages
            skipped_reason = "not_run"
            detail = dict(zip(("detail_en", "detail_ar"), STR["offsite"]))
        for c in DEEP_RULES:
            st.state(c, state, skipped_reason, **detail)
        return
    if not ctx.probes and not report.get("planned"):
        for c in DEEP_RULES:
            st.state(c, "not_tested", "not_run")
        return
    dm = ctx.data or _data
    specs: dict[str, DeepPath] = {}
    for p in [*exposed_paths(dm), *platform_paths(dm), *POLICY_FILES.values()]:
        specs.setdefault(p.path, p)
    refs: dict[str, Response] = {}
    for r in [*ctx.baselines, *ctx.wellknown.values(), ctx.entry]:
        if r is not None:
            refs.setdefault(r.url, r)
    seen_rules: set[str] = set()
    for r in ctx.probes:
        if r is None:
            continue
        path = _resp_path(r)
        spec = specs.get(path)
        if spec is None:
            continue
        seen_rules.add(spec.rule)
        v = judge(r, spec, index, refs, ctx.entry)
        if v.state in ("not_tested", "inconclusive"):
            st.state(spec.rule, v.state, v.reason, detail_en=path, detail_ar=path)
            continue
        if v.state == "clean":
            st.state(spec.rule, "pass")
            continue
        if spec.rule == "WEB083" and not _live_login(r, v.matches):
            st.state(spec.rule, "pass")
            continue
        _emit_probe(st, spec, r, v)
        st.state(spec.rule, "fail")
    for item in report.get("skipped") or []:
        spec = specs.get(item.get("path", ""))
        if spec is not None:
            seen_rules.add(spec.rule)
            st.state(spec.rule, "not_tested", item.get("reason") or "budget", detail_en=spec.path, detail_ar=spec.path)
    for c in DEEP_RULES:
        if c not in seen_rules:
            if c in ("WEB082", "WEB083"):
                st.state(c, "not_applicable")       # no detected platform with deep paths
            else:
                st.state(c, "not_tested", "not_run")


def _emit_probe(st: _Run, spec: DeepPath, r: Response, v: Verdict) -> None:
    ctx = st.ctx
    notes: list[tuple[str, str]] = []
    if spec.title_en and spec.title_ar:
        notes.append((spec.title_en, spec.title_ar))
    if spec.advice_en and spec.advice_ar:
        notes.append((spec.advice_en, spec.advice_ar))
    sev = _severity(st, spec, r, notes)
    value, offset, excerpt = _match_evidence(spec, r, v.matches)
    if v.baseline:
        notes.append(_note("baseline_differs", baseline=_short(v.baseline.get("url", ""), 200)))
    params: dict[str, Any] = {"path": spec.path}
    if spec.platform:
        params["platform"] = spec.platform
    if spec.cwe:
        params["cwe"] = spec.cwe
    if spec.asvs5:
        params["asvs5"] = spec.asvs5
    if spec.rule == "WEB903":
        m = re.search(r"<(?:allow-access-from|domain)\b[^>]*>", _text(r))
        shown = _short(m.group(0), 160) if m else value
        notes.insert(0, _note("crossdomain", path=spec.path, value=shown))
        if m and re.search(r"\bsecure\s*=\s*[\"']false[\"']", m.group(0), re.I):
            notes.append(_note("crossdomain_insecure"))
        value, excerpt = shown, shown
    ev = Evidence.for_response(r, where="probe", name=spec.path, value=value, offset=offset, excerpt=excerpt,
                               now=ctx.now, baseline=v.baseline)
    conf = "firm" if spec.rule == "WEB083" else "certain"
    st.emit(Issue(rule=spec.rule, url=r.url, confidence=conf, evidence=ev, params=params, severity=sev,
                  group_value=spec.path, notes=notes))
    hits = ctx.inventory.setdefault("deep_probe_hits", [])
    hits.append({"path": spec.path, "rule": spec.rule, "status": r.status, "severity": sev,
                 "platform": spec.platform})


# ----------------------------------------------------------------------------------------------- takeover

@dataclass(frozen=True)
class Provider:
    name: str
    cname: tuple[str, ...]
    fingerprints: tuple[str, ...]
    status: int | None
    vulnerable: bool
    nxdomain: bool = False

    def suffix_of(self, name: str) -> str | None:
        n = normalise_host(name)
        for s in self.cname:
            s = s.lower().strip(".")
            if n == s or n.endswith("." + s):
                return s
        return None


def providers(dm: Any = None) -> list[Provider]:
    doc = _load(dm or _data, TAKEOVER_FILE)
    if not isinstance(doc, dict):
        return []
    out = []
    for p in doc.get("providers") or []:
        if not isinstance(p, dict) or not p.get("cname") or not p.get("fingerprints"):
            continue
        out.append(Provider(str(p.get("name", "")), tuple(p["cname"]), tuple(p["fingerprints"]), p.get("status"),
                            bool(p.get("vulnerable")), bool(p.get("nxdomain"))))
    return out


def cname_provider(host: str, canonical: str, aliases: Iterable[str],
                   provs: list[Provider]) -> tuple[Provider, str] | None:
    """The provider whose CNAME suffix matches the canonical name (``gethostbyname_ex(host)[0]``, the CNAME target)
    or one of the aliases (index 1: the queried name and intermediate CNAMEs), excluding the scanned name itself; a
    host that is itself under the provider's domain (``x.github.io``) is the provider's own name, not a CNAME."""
    h = normalise_host(host)
    names = [normalise_host(n) for n in (canonical, *aliases) if n]
    names = [n for n in dict.fromkeys(names) if n and n != h]
    for p in provs:
        if p.suffix_of(h):
            continue
        for n in names:
            if p.suffix_of(n):
                return p, n
    return None


def _ip_literal(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _takeover(st: _Run) -> None:
    ctx = st.ctx
    host = ctx.target_host
    if not host or _ip_literal(host):
        st.state("WEB901", "not_applicable")
        return
    if ctx.proxied:
        st.state("WEB901", "not_tested", "proxied")
        return
    provs = providers(ctx.data or _data)
    if not provs:
        st.state("WEB901", "not_tested", "data_missing")
        return
    responses: list[Response] = []
    for r in (ctx.entry, ctx.https_probe, ctx.http_probe):
        if r is not None:
            responses.extend(h for h in r.hops() if h.status is not None and not h.error)
    hosts = list(dict.fromkeys([host, *(r.host for r in responses)]))
    judged = False
    any_found = False
    for h in hosts:
        rec = ctx.dns.get(h)
        if rec is None:
            continue
        if rec.status == "not_tested":
            st.state("WEB901", "not_tested", rec.reason if rec.reason in ("proxied", "budget") else "not_run", host=h)
            continue
        if rec.status != "ok":
            continue
        judged = True
        hit = cname_provider(h, rec.canonical, rec.aliases, provs)
        if hit is None:
            st.state("WEB901", "pass", host=h)
            continue
        prov, cname = hit
        found = False
        inv = ctx.inventory.setdefault("takeover", [])
        entry = {"host": h, "cname": cname, "provider": prov.name, "vulnerable": prov.vulnerable,
                 "fingerprint": False}
        inv.append(entry)
        for r in (x for x in responses if x.host == h):
            if prov.status is not None and r.status != prov.status:
                continue
            text = _text(r)
            fp = next((f for f in prov.fingerprints if f in text), None)
            if fp is None:
                continue
            entry["fingerprint"] = True
            if not prov.vulnerable:
                entry["note"] = _note("takeover_mitigated", host=h, provider=prov.name, cname=cname)
                break
            off = text.find(fp)
            ev = Evidence.for_response(r, where="dns", name=h, value=f"CNAME {cname}", offset=off,
                                       excerpt=_short(fp, 200), now=ctx.now)
            st.emit(Issue(rule="WEB901", url=r.url, confidence="firm", evidence=ev, group_value=prov.name, host=h,
                          params={"provider": prov.name, "cname": cname},
                          notes=[_note("takeover", host=h, cname=cname, provider=prov.name,
                                       fingerprint=_short(fp, 120))]))
            st.state("WEB901", "fail", host=h)
            found = any_found = True
            break
        if not found:
            st.state("WEB901", "pass", host=h)
    if not judged and not any_found:
        st.state("WEB901", "not_tested", "not_run")


def dangling_hint() -> tuple[str, str]:
    """(en, ar) sentence for ``explain_failure`` when the target name does not resolve (spec §2.10 WEB901 limitation)."""
    return STR["dangling"]


# ----------------------------------------------------------------------------------------------- entry point

def run(ctx: ScanContext) -> list[Issue]:
    """Judge well-known files, deep-probe responses and DNS facts already in ``ctx`` (no network access)."""
    st = _Run(ctx)
    if ctx.inventory is None:
        ctx.inventory = {}
    index, _proven = classify.build_index(ctx)
    for part in (_security_txt, _robots, _deep):
        try:
            part(st, index)
        except Exception:   # noqa: BLE001 - one broken input must not hide the other checks
            for c in {_security_txt: ("WEB060", "WEB900"), _robots: ("WEB061",), _deep: DEEP_RULES}[part]:
                st.state(c, "not_tested", "error")
    try:
        _takeover(st)
    except Exception:   # noqa: BLE001
        st.state("WEB901", "not_tested", "error")
    return st.issues


def i18n_catalog() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """``(CATALOG, PATTERNS)`` for cat_web2: this module's notes, the per-path titles and advice of
    ``exposed-paths.json`` and the RFC 9116 problem texts (sectxt)."""
    from .rules import template_patterns
    catalog: dict[str, str] = {}
    patterns: list[tuple[str, str]] = []
    for en, ar in STR.values():
        if _PLACEHOLDER.search(ar):
            patterns.extend(template_patterns(ar, en))
        else:
            catalog[ar] = en
    for p in exposed_paths():
        for en, ar in ((p.title_en, p.title_ar), (p.advice_en, p.advice_ar)):
            if en and ar:
                catalog.setdefault(ar, en)
    c2, p2 = sectxt.i18n_catalog()
    catalog.update({k: v for k, v in c2.items() if k not in catalog})
    patterns.extend(p2)
    return catalog, patterns


__all__ = ["CHECKS", "MAX_PROBES", "NEVER_LIST", "STR", "DeepPath", "POLICY_FILES", "Provider", "Verdict", "CondMatch",
           "exposed_paths", "platform_paths", "detected_platforms", "plan", "probe", "match_signature", "looks_html",
           "judge", "redact_values", "robots_paths", "sensitive_robots_path", "providers", "cname_provider",
           "dangling_hint", "run", "i18n_catalog"]
