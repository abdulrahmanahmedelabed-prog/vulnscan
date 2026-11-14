"""Pipeline orchestration of the passive web scanner (spec §4.3, §3.5–§3.8; WP15a).

:func:`scan` runs one scan and returns a :class:`~vulnscan.webscan.types.WebScanResult`:

1. **Target.** Only ``http``/``https`` URLs with a host are scanned; anything else, and an entry URL that cannot be
   fetched at all, raises :class:`WebUnreachable` with the bilingual explanation of ``web.explain_failure``.
2. **Entry chain** (every profile): one GET of the target, redirects followed like a browser (≤ 10 hops, cookies in
   the per-scan memory jar). The entry document is parsed into the light DOM and classified; a WAF challenge or a
   rate limit (gate G4) stops the optional fetches of steps 3, 5 and 6 for that scan.
3. **Standard and deep:** the http(s) counterpart chain (only on the default ports: another port is never contacted,
   §0.1), the cookieless CORS GET of the final entry URL, ``/robots.txt``, ``/.well-known/security.txt`` (and
   ``/security.txt`` only after a 404), the declared icon or ``/favicon.ico``, the sitemap (``--crawl`` only), up to 15
   same-site scripts/styles the entry document loads, and the DNS facts of the hosts the documents reference (WEB517).
4. **TLS** for every https host the entry or counterpart chain reached (``tls.collect``; quick or deep set).
5. **Crawl** (``crawl``): breadth-first over same-origin ``<a href>`` links, honouring robots.txt (unless the owner
   turned it off), :data:`SKIP_LINK`, ≤ 3 URLs per URL template, near-duplicate skip, ``max_pages`` and ``max_depth``.
6. **Deep:** technology detection, third-party scripts/styles (≤ 10), source maps (≤ 5), same-site JPEG images (≤ 10,
   also with ``crawl``), then exposure.py's fixed list with its soft-404 baselines and the policy files.
7. **Analysis:** classification and soft-404 marking, stage-1 facts (CSP, HSTS, cookies, ``sensitive``), every check
   module (stage 2), WEB990/WEB991 (scan meta), grouping, suppression and the sensitivity filter (stage 3), Findings
   with their evidence and mappings, the three grades, the coverage summary, the snapshot and the diff.

Only this module imports more than one check module (§4.2). Every request goes through the scan's single
:class:`~vulnscan.webscan.http.Fetcher` (budgets, politeness, SSRF guard, proxies, hostile-target limits); nothing here
opens a socket itself. A check module that raises is recorded as ``not_tested`` (reason ``error``) and the scan goes on:
one broken rule must never hide the others or crash the scan (``KASHIF_DEBUG=1`` re-raises, for development).

Import cost: this module is imported by ``vulnscan.web`` (and through ``cat_web2`` for its texts), so the check
modules, the fetcher and the TLS code are imported only inside :func:`scan`.
"""

from __future__ import annotations

import importlib
import os
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .rules import RULE_IDS, RULES, SEVERITIES, validate_issue
from .types import (CORS_PROBE_ORIGIN, PROFILES, SENSITIVITIES, Evidence, Issue, Page, Response,
                    ScanContext, ScanOptions, WebScanResult, cap, normalise_host, strip_controls, url_origin, utcnow)

# ----------------------------------------------------------------------------------------------- constants

# stage-2 check modules in run order: libs before domxss (the library list lets domxss skip library files), tech
# and the rest before exposure (exposure.run reads the technology inventory), tls is webscan/tls (assess)
CHECK_MODULES = ("transport", "csp", "headers", "cors", "cookies", "content", "libs", "domxss", "disclosure", "tls",
                 "tech", "exposure")
MAX_SAME_SITE_SUBRESOURCES = 15         # §0.1
MAX_THIRD_PARTY = 10                    # §0.1, deep
MAX_SOURCEMAPS = 5                      # §0.1, deep
MAX_IMAGES = 10                         # §0.1, deep or crawl
MAX_WELLKNOWN = 5                       # §0.1
SUBRESOURCE_HOPS = 3                    # a script or icon may redirect (≤ 4 extra hops in the standard budget)
NXDOMAIN_CONFIRM_CAP = 5                # WEB517: nxdomain answers confirmed ≥ 2 s later, at most this many
ANALYSIS_GRACE = 120.0                  # seconds of analysis allowed after the scan's time budget (§4.3)
SNIPPET_CAP = 120
PARAM_CAP = 300
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
RULE_ORDER = {r: i for i, r in enumerate(RULE_IDS)}
WELLKNOWN_ROBOTS = "/robots.txt"
WELLKNOWN_SECTXT = "/.well-known/security.txt"
WELLKNOWN_SECTXT_LEGACY = "/security.txt"
WELLKNOWN_FAVICON = "/favicon.ico"
WELLKNOWN_SITEMAP = "/sitemap.xml"
# 1.0.1 crawl filter, kept: state-changing words and non-HTML extensions are never followed
SKIP_LINK = re.compile(r"(?i)(logout|signout|sign-out|log-off|/delete|/remove|/destroy|action=delete|"
                       r"\.(zip|pdf|png|jpe?g|gif|svg|css|js|ico|woff2?|ttf|mp4|mp3)(\?|$))")
_JS_TYPES = frozenset({"", "text/javascript", "application/javascript", "module", "application/x-javascript",
                       "application/ecmascript", "text/ecmascript", "text/jscript"})
_PROBE_RULES = frozenset({"WEB062", "WEB082", "WEB083"})
_BLOCKED_KINDS = frozenset({"waf_challenge", "rate_limited"})
_PLATFORM_RULES = frozenset({"WEB080", "WEB081"})

# bilingual texts of the engine (scan notes, WEB990/WEB991 notes); ``{x}`` placeholders, counts via _count()
STR: dict[str, tuple[str, str]] = {
    "profile": ("Passive web scan, profile {profile}: {requests} sent, no active test.",
                "فحص ويب سلبي بالملف {profile}: أُرسل {requests}، بلا أي اختبار نشط."),
    "crawl": ("Crawled {pages} of the same site ({delay} s or more between requests to a host).",
              "زحف الفحص على {pages} من الموقع نفسه (بفاصل {delay} ثانية على الأقل بين الطلبات إلى المضيف الواحد)."),
    "crawl_failed": ("{pages} could not be fetched during the crawl and were not checked: {paths}",
                     "تعذّر جلب {pages} أثناء الزحف فلم تُفحص: {paths}"),
    "coverage": ("Coverage: {summary}", "التغطية: {summary}"),
    "grades": ("{summary}", "{summary}"),
    "offsite": ("The entry URL redirected to another site ({host}); that final host is the one judged.",
                "أعاد عنوان البدء التوجيه إلى موقع آخر ({host})؛ والمضيف النهائي هو الذي فُحص."),
    "blocked": ("The site answered with {what}; optional requests were not sent and the affected checks are "
                "inconclusive (WEB990).",
                "أجاب الموقع ب{what}؛ فلم تُرسل الطلبات الاختيارية، والفحوص المتأثرة غير حاسمة (WEB990)."),
    "waf_what": ("a {provider} challenge or block page", "صفحة تحدٍّ أو حظر من {provider}"),
    "rate_what": ("a rate limit (HTTP {status})", "تقييد لمعدل الطلبات (HTTP {status})"),
    "waf_provider": ("Detected provider: {provider}.", "المزوّد المكتشف: {provider}."),
    "rate_limited": ("The site limited the scan's request rate (HTTP 429/503); the remaining requests to {host} were not "
                     "sent.",
                     "قيّد الموقع معدل طلبات الفحص (HTTP 429/503)؛ فلم تُرسل بقية الطلبات إلى {host}."),
    "inconclusive_checks": ("Checks that could not run: {checks}", "فحوص تعذّر إجراؤها: {checks}"),
    "not_tested_checks": ("Not performed: {checks}", "لم تُجرَ: {checks}"),
    "and_more": ("and {n} more", "و{n} غيرها"),
    "module_error": ("Internal error in the {module} checks ({error}); they are marked not tested.",
                     "خطأ داخلي في فحوص {module} ({error})؛ فاعتُبرت غير مُجراة."),
    "time_budget": ("The scan's time budget was reached before the {module} checks; they are marked not tested.",
                    "بلغ الفحص حدّ الوقت قبل فحوص {module}؛ فاعتُبرت غير مُجراة."),
    "unreadable": ("The response from {url} could not be read ({error}); the checks that need it did not run on it.",
                   "تعذّرت قراءة الاستجابة من {url} ({error})؛ فلم تُجرَ عليها الفحوص التي تحتاج إليها."),
    "https_port": ("HTTPS was not checked: the target uses a non-default port and Kashif never contacts another port",
                   "لم يُفحص HTTPS: يستخدم الهدف منفذًا غير افتراضي، ولا يتصل كاشف بأي منفذ آخر"),
    "proxied": ("Scanning through a proxy: DNS checks are not tested and TLS is seen through the proxy.",
                "يمر الفحص عبر وكيل (proxy): لم تُجرَ فحوص DNS، ويُرى TLS عبر الوكيل."),
}
# count phrases: key → (English singular, English plural, Arabic five forms)
COUNT_FORMS: dict[str, tuple[str, str, tuple[str, str, str, str, str]]] = {
    "requests": ("{n} request", "{n} requests", ("طلب واحد", "طلبان", "{n} طلبات", "{n} طلبًا", "{n} طلب")),
    "pages": ("{n} page", "{n} pages", ("صفحة واحدة", "صفحتين", "{n} صفحات", "{n} صفحةً", "{n} صفحة")),
}


def _count(key: str, n: int, lang: str) -> str:
    one, many, forms = COUNT_FORMS[key]
    if lang == "ar":
        from ..i18n.plural import ar_count   # lazy: vulnscan.i18n imports webscan modules through cat_web2
        return ar_count(n, forms)
    return (one if n == 1 else many).replace("{n}", str(n))


def text(key: str, lang: str = "en", **params: Any) -> str:
    en, ar = STR[key]
    return (ar if lang == "ar" else en).format(**params)


def pair(key: str, **params: Any) -> tuple[str, str]:
    """``(en, ar)`` of ``key``; a parameter given as a ``(en, ar)`` tuple is used per language."""
    en_p = {k: (v[0] if isinstance(v, tuple) else v) for k, v in params.items()}
    ar_p = {k: (v[1] if isinstance(v, tuple) else v) for k, v in params.items()}
    return STR[key][0].format(**en_p), STR[key][1].format(**ar_p)


# ----------------------------------------------------------------------------------------------- errors

class WebUnreachable(Exception):
    """The entry URL could not be fetched, so nothing was scanned. Never reported as a clean result."""


def _explain(err: str, url: str, timeout: float) -> str:
    from ..web import explain_failure   # the 1.0.1 wording (and its English catalogue) lives in the facade
    return explain_failure(err, url, timeout)


# ----------------------------------------------------------------------------------------------- modules

def _module(name: str):
    return importlib.import_module(f".{name}", __package__)


def _debug() -> bool:
    return os.environ.get("KASHIF_DEBUG") == "1"


@dataclass
class _Run:
    """Per-scan bookkeeping that is not part of the frozen ScanContext."""
    ctx: ScanContext
    fetcher: Any
    notes: list[tuple[str, str]] = field(default_factory=list)       # (en, ar), in order
    problems: list[str] = field(default_factory=list)                # registry problems of issues (coerced)
    errors: list[dict] = field(default_factory=list)                 # module errors
    crawl_fetched: int = 0
    crawl_failed: list[str] = field(default_factory=list)
    blocked: str = ""                                                # "", "waf" or "rate_limited"

    def note(self, key: str, **params: Any) -> None:
        p = pair(key, **params)
        if p not in self.notes:
            self.notes.append(p)


# ----------------------------------------------------------------------------------------------- helpers

def _html_like(r: Response) -> bool:
    if not r.body or "opaque-coding" in r.flags or r.status is None:
        return False
    ess = r.essence
    if ess in ("text/html", "application/xhtml+xml"):
        return True
    if not ess:
        from . import classify
        return classify.sniff(r.body) == "text/html"
    return False


def _parse(r: Response):
    from . import htmlparse
    try:
        return htmlparse.parse_response(r)
    except Exception:   # noqa: BLE001 - htmlparse never raises on markup; a decoding surprise must not stop the scan
        if _debug():
            raise
        return None


def _classify(r: Response, doc=None) -> None:
    from . import classify
    for h in r.hops():
        classify.classify(h, doc if h is r else None)


def _page(r: Response, depth: int) -> Page:
    doc = _parse(r) if _html_like(r) else None
    _classify(r, doc)
    return Page(r, doc, depth)


def _received(r: Response | None) -> bool:
    return r is not None and r.status is not None


def _never_sent(r: Response) -> bool:
    """True for a response the fetcher refused before sending (budget, profile, robots, stopped host, SSRF)."""
    from .http import error_code
    return r.status is None and error_code(r) in ("budget", "time_budget", "byte_budget", "profile", "robots",
                                                   "host_stopped", "ssrf")


def _host(url: str) -> str:
    try:
        return normalise_host(urllib.parse.urlsplit(url).hostname or "")
    except ValueError:
        return ""


def _same_site(a: str, b: str) -> bool:
    from . import psl
    if not a or not b:
        return False
    if a == b:
        return True
    try:
        return psl.same_site(a, b)
    except Exception:   # noqa: BLE001 - PSL data missing: compare host names only
        return False


def _http_url(url: str) -> bool:
    return url.lower().startswith(("http://", "https://"))


def _default_port(url: str) -> bool:
    try:
        p = urllib.parse.urlsplit(url)
        return p.port is None or (p.scheme.lower(), p.port) in (("http", 80), ("https", 443))
    except ValueError:
        return False


def _origin_url(url: str, path: str) -> str:
    return url_origin(url) + path


def _subresource_refs(doc, *, scripts: bool = True, styles: bool = True) -> list[tuple[str, str]]:
    """``[(absolute URL, "script"|"style")]`` of the live external scripts and stylesheets a document loads."""
    out: list[tuple[str, str]] = []
    if doc is None:
        return out
    seen: set[str] = set()
    for el in doc.find_all("script", "link"):
        if el.tag == "script":
            if not scripts or not el.has("src"):
                continue
            typ = (el.get("type") or "").strip().lower().split(";", 1)[0].strip()
            if typ not in _JS_TYPES:
                continue
            kind = "script"
            raw = el.get("src")
        else:
            rel = el.tokens("rel")
            if "stylesheet" in rel and styles:
                kind = "style"
            elif rel & {"modulepreload"} and scripts:
                kind = "script"
            else:
                continue
            raw = el.get("href")
        if not raw or not raw.strip():
            continue
        try:
            url = urllib.parse.urldefrag(doc.resolve(raw))[0]
        except ValueError:
            continue
        if not _http_url(url) or url in seen:
            continue
        seen.add(url)
        out.append((url, kind))
    return out


def _icon_ref(doc) -> str | None:
    if doc is None:
        return None
    for el in doc.links():
        rel = el.tokens("rel")
        if rel & {"icon", "shortcut", "apple-touch-icon"} and "icon" in " ".join(rel) and el.get("href"):
            try:
                url = urllib.parse.urldefrag(doc.resolve(el.get("href")))[0]
            except ValueError:
                continue
            if _http_url(url):
                return url
    return None


def _links(doc) -> list[str]:
    """Absolute http(s) URLs of the live ``<a href>`` links of a document, fragment removed, in document order."""
    out: list[str] = []
    if doc is None:
        return out
    seen: set[str] = set()
    for el in doc.find_all("a"):
        href = (el.get("href") or "").strip()
        if not href or href.startswith("#") or href.lower().startswith(("mailto:", "tel:", "javascript:", "data:")):
            continue
        try:
            url = urllib.parse.urldefrag(doc.resolve(href))[0]
        except ValueError:
            continue
        if _http_url(url) and url not in seen:
            seen.add(url)
            out.append(url)
    return out


def _jpeg_refs(doc) -> list[str]:
    out: list[str] = []
    if doc is None:
        return out
    for el in doc.find_all("img"):
        raw = el.get("src")
        if not raw:
            continue
        try:
            url = urllib.parse.urldefrag(doc.resolve(raw))[0]
        except ValueError:
            continue
        path = urllib.parse.urlsplit(url).path.lower()
        if _http_url(url) and path.endswith((".jpg", ".jpeg")) and url not in out:
            out.append(url)
    return out


# ----------------------------------------------------------------------------------------------- fetch steps

def _stopped(run: _Run, url: str) -> bool:
    try:
        return bool(run.fetcher.host_stopped(_host(url)))
    except Exception:   # noqa: BLE001 - a fetcher double without the method
        return False


def _fetch(run: _Run, url: str, **kw: Any) -> Response | None:
    """One fetch through the scan's Fetcher; None when the host was already stopped (nothing sent)."""
    if _stopped(run, url):
        return None
    return run.fetcher.fetch(url, **kw)


def _fetch_counterpart(run: _Run) -> None:
    ctx = run.ctx
    target = ctx.target
    if not _default_port(target):
        return                                    # §0.1: never another port; transport.py notes "https not checked"
    p = urllib.parse.urlsplit(target)
    scheme = p.scheme.lower()
    other = "http" if scheme == "https" else "https"
    host = p.hostname or ""
    shown = f"[{host}]" if ":" in host else host
    url = urllib.parse.urlunsplit((other, shown, p.path or "/", p.query, ""))
    if other == "https" and ctx.entry is not None and any(
            h.scheme == "https" and h.host == _host(target) for h in ctx.entry.hops()):
        return                                    # the entry chain already reached https on the same host
    r = _fetch(run, url, source="https_probe" if other == "https" else "http_probe")
    if r is None:
        return
    _classify(r)
    if other == "https":
        ctx.https_probe = r
    else:
        ctx.http_probe = r


def _fetch_cors(run: _Run) -> None:
    ctx = run.ctx
    url = ctx.entry.url if _received(ctx.entry) else ctx.target
    if ctx.entry is not None and "deadline" in ctx.entry.flags:
        # the same URL just ran into the per-response deadline (a dripping or stalled server, §0.6): asking again
        # would only wait another deadline; the CORS checks become not_tested ("timeout")
        ctx.cors = Response(url=url, status=None, error="not sent: the entry URL hit the per-response deadline",
                            source="cors", flags=frozenset({"error:deadline"}))
        return
    r = _fetch(run, url, source="cors", origin=CORS_PROBE_ORIGIN, cookies=False)
    if r is not None and not _never_sent(r):
        _classify(r)
        ctx.cors = r


def _fetch_wellknown(run: _Run, crawl_seed: list[str]) -> None:
    from . import robots as _robots
    ctx = run.ctx
    base = ctx.entry.url if _received(ctx.entry) else ctx.target
    used = 0

    def get(key: str, url: str) -> Response | None:
        nonlocal used
        if used >= MAX_WELLKNOWN:
            return None
        r = _fetch(run, url, source="wellknown", max_hops=SUBRESOURCE_HOPS)
        if r is None:
            return None
        used += 1
        _classify(r)
        ctx.wellknown[key] = r
        return r

    rob = get(WELLKNOWN_ROBOTS, _origin_url(base, WELLKNOWN_ROBOTS))
    parsed = None
    if rob is not None and not _never_sent(rob):
        try:
            parsed = _robots.from_response(rob)
        except Exception:   # noqa: BLE001 - a robots file the parser cannot read is treated as absent
            if _debug():
                raise
            parsed = None
        if parsed is not None:
            ctx.robots = parsed
            run.fetcher.set_robots(base, parsed)
    sec = get(WELLKNOWN_SECTXT, _origin_url(base, WELLKNOWN_SECTXT))
    if sec is not None and sec.status == 404:
        get(WELLKNOWN_SECTXT_LEGACY, _origin_url(base, WELLKNOWN_SECTXT_LEGACY))
    entry_doc = ctx.pages[0].doc if ctx.pages and ctx.pages[0].response is ctx.entry else None
    icon = _icon_ref(entry_doc)
    if icon and _same_site(_host(icon), _host(base)) and not (url_origin(base).startswith("https:")
                                                                and icon.startswith("http:")):
        path = urllib.parse.urlsplit(icon).path or "/"
        get(WELLKNOWN_FAVICON if path == WELLKNOWN_FAVICON else f"icon:{path}", icon)
    else:
        get(WELLKNOWN_FAVICON, _origin_url(base, WELLKNOWN_FAVICON))
    if ctx.options.crawl:
        maps = []
        if parsed is not None:
            maps = [u for u in (getattr(parsed, "sitemaps", None) or []) if isinstance(u, str)]
        maps = [u for u in maps if _http_url(u) and _same_site(_host(u), _host(base))]
        sm = get(WELLKNOWN_SITEMAP, maps[0] if maps else _origin_url(base, WELLKNOWN_SITEMAP))
        if sm is not None and sm.status == 200 and sm.body and "opaque-coding" not in sm.flags:
            for loc in re.findall(r"<loc>\s*([^<\s]{1,2000})\s*</loc>", sm.text()[:500_000], re.I)[:500]:
                u = urllib.parse.urldefrag(loc.replace("&amp;", "&"))[0]
                if _http_url(u):
                    crawl_seed.append(u)


def _fetch_same_site_subresources(run: _Run) -> None:
    ctx = run.ctx
    if not ctx.pages or ctx.pages[0].response is not ctx.entry:
        return
    entry = ctx.entry
    secure = entry.is_https
    n = 0
    for url, _kind in _subresource_refs(ctx.pages[0].doc):
        if n >= MAX_SAME_SITE_SUBRESOURCES:
            break
        if not _same_site(_host(url), entry.host):
            continue
        if secure and url.lower().startswith("http:"):
            continue                              # a browser blocks active mixed content; it is never requested
        r = _fetch(run, url, source="subresource", max_hops=SUBRESOURCE_HOPS)
        if r is None or _never_sent(r):
            continue
        n += 1
        _classify(r)
        ctx.subresources.append(r)


def _resolve_referenced(run: _Run) -> None:
    """DNS of the hosts the documents reference (WEB517 and the resolver sanity guard), within the §0.1 bounds."""
    from . import content
    ctx = run.ctx
    fetcher = run.fetcher
    if not hasattr(fetcher, "lookup"):
        return
    try:
        hosts = content.dns_candidates(ctx.pages, ctx.target)
    except Exception:   # noqa: BLE001
        if _debug():
            raise
        return
    records = {}
    for h in hosts:
        records[h] = fetcher.lookup(h, purpose="referenced")
    trusted = any(rec.status == "ok" for rec in records.values())
    missing = [h for h, rec in records.items() if rec.status == "nxdomain"]
    if trusted:
        for h in missing[:NXDOMAIN_CONFIRM_CAP]:
            records[h] = fetcher.lookup(h, purpose="referenced", confirm_missing=True)
    for h, rec in records.items():
        if rec.status == "nxdomain":
            fetcher.lookup_registrable(h, purpose="referenced")


def _crawl(run: _Run, seeds: Iterable[str]) -> None:
    from . import classify
    from .group import CrawlPlanner
    ctx = run.ctx
    opts = ctx.options
    fetcher = run.fetcher
    entry = ctx.entry
    if not _received(entry):
        return
    origin = url_origin(entry.url)
    limit = max(0, min(int(opts.max_pages), 500) - 1)        # the entry page counts as one page (1.0.1 semantics)
    planner = CrawlPlanner()
    seen = {urllib.parse.urldefrag(entry.url)[0], urllib.parse.urldefrag(ctx.target)[0]}
    for h in entry.hops():
        seen.add(urllib.parse.urldefrag(h.url)[0])
    planner.allow(entry.url)
    if ctx.pages and ctx.pages[0].response is entry and entry.body:
        planner.near_duplicate(classify.signature(entry).simhash)
    frontier: list[tuple[str, int]] = []

    def push(url: str, depth: int) -> None:
        if url in seen or url_origin(url) != origin or SKIP_LINK.search(url):
            return
        seen.add(url)
        frontier.append((url, depth))

    first_doc = ctx.pages[0].doc if ctx.pages and ctx.pages[0].response is entry else None
    if opts.max_depth >= 1:
        for u in _links(first_doc):
            push(u, 1)
        for u in seeds:
            push(urllib.parse.urldefrag(u)[0], 1)
    while frontier and run.crawl_fetched < limit:
        url, depth = frontier.pop(0)
        if _stopped(run, url):
            break
        if opts.respect_robots and not fetcher.allowed_by_robots(url):
            continue                              # no request: the owner's robots.txt disallows it (§4.3)
        if not planner.allow(url):
            continue                              # ≤ 3 URLs per URL template (§3.5)
        r = fetcher.fetch(url, source="crawl")
        if _never_sent(r):
            if "error:host_stopped" in r.flags or "error:budget" in r.flags or "error:time_budget" in r.flags:
                break
            continue
        run.crawl_fetched += 1
        if r.status is None:
            run.crawl_failed.append(url)
            continue
        page = _page(r, depth)
        ctx.pages.append(page)
        dup = False
        if page.doc is not None and r.body:
            dup = planner.near_duplicate(classify.signature(r).simhash)
        if depth < opts.max_depth and not dup:
            for u in _links(page.doc):
                push(u, depth + 1)


def _fetch_third_party(run: _Run) -> None:
    ctx = run.ctx
    site_host = ctx.entry.host if _received(ctx.entry) else ctx.target_host
    have = {r.url for r in ctx.subresources}
    n = 0
    for p in ctx.pages:
        if p.doc is None or p.response.kind != "document":
            continue
        for url, _kind in _subresource_refs(p.doc):
            if n >= MAX_THIRD_PARTY:
                return
            if url in have or _same_site(_host(url), site_host):
                continue
            if p.response.is_https and url.lower().startswith("http:"):
                continue
            have.add(url)
            r = _fetch(run, url, source="subresource", max_hops=SUBRESOURCE_HOPS)
            if r is None or _never_sent(r):
                continue
            n += 1
            _classify(r)
            ctx.subresources.append(r)


def _fetch_sourcemaps(run: _Run) -> None:
    from . import disclosure
    ctx = run.ctx
    site_host = ctx.entry.host if _received(ctx.entry) else ctx.target_host
    have: set[str] = set()
    n = 0
    for r in list(ctx.subresources):
        if n >= MAX_SOURCEMAPS:
            return
        if r.status != 200 or not r.body or "opaque-coding" in r.flags or not _same_site(r.host, site_host):
            continue
        try:
            ref = disclosure.sourcemap_reference(r)
        except Exception:   # noqa: BLE001
            if _debug():
                raise
            ref = None
        if not ref or ref.lower().startswith("data:") or not _http_url(ref) or ref in have:
            continue
        if not _same_site(_host(ref), site_host):
            continue
        have.add(ref)
        m = _fetch(run, ref, source="sourcemap", max_hops=SUBRESOURCE_HOPS)
        if m is None or _never_sent(m):
            continue
        n += 1
        _classify(m)
        ctx.sourcemaps.append(m)


def _fetch_images(run: _Run) -> None:
    ctx = run.ctx
    site_host = ctx.entry.host if _received(ctx.entry) else ctx.target_host
    have: set[str] = set()
    n = 0
    for p in ctx.pages:
        if p.doc is None or p.response.kind != "document":
            continue
        for url in _jpeg_refs(p.doc):
            if n >= MAX_IMAGES:
                return
            if url in have or not _same_site(_host(url), site_host):
                continue
            if p.response.is_https and url.lower().startswith("http:"):
                continue
            have.add(url)
            r = _fetch(run, url, source="image", max_hops=SUBRESOURCE_HOPS)
            if r is None or _never_sent(r):
                continue
            n += 1
            _classify(r)
            ctx.images.append(r)


# ----------------------------------------------------------------------------------------------- analysis

def _stage1(run: _Run) -> None:
    from . import classify, cookies, csp, transport
    ctx = run.ctx
    for name, fn, attr in (("csp", csp.parse_all, "csp"), ("transport", transport.hsts_facts, "hsts"),
                           ("cookies", cookies.parse_and_classify, "cookies")):
        try:
            setattr(ctx, attr, fn(ctx))
        except Exception as e:   # noqa: BLE001 - the module's run() records its own coverage when it fails too
            if _debug():
                raise
            run.errors.append({"stage": 1, "module": name, "error": type(e).__name__})
    try:
        classify.mark_sensitive(ctx)
    except Exception as e:   # noqa: BLE001
        if _debug():
            raise
        run.errors.append({"stage": 1, "module": "classify", "error": type(e).__name__})


def _coerce(run: _Run, issue: Issue) -> Issue | None:
    """The issue with severity/confidence inside the registry's allowed sets (problems are recorded, not fatal)."""
    meta = RULES.get(issue.rule)
    if meta is None:
        run.problems.append(f"unknown rule {issue.rule!r}")
        return None
    problems = validate_issue(issue)
    if problems:
        run.problems.extend(problems)
        if issue.severity is not None and issue.severity not in meta.allowed_severities:
            issue.severity = None
        if issue.confidence not in meta.allowed_confidences:
            issue.confidence = meta.confidence
    if issue.evidence is None:
        issue.evidence = Evidence()
    if not issue.host:
        issue.host = _host(issue.url)
    return issue


def _out_of_time(run: _Run) -> bool:
    """True when the scan is past its time budget plus :data:`ANALYSIS_GRACE`: the analysis of what was already
    fetched still runs after the fetch budget ran out (a partial result is better than none), but not forever."""
    try:
        return float(run.fetcher.elapsed()) > float(run.ctx.options.time_budget) + ANALYSIS_GRACE
    except Exception:   # noqa: BLE001 - no fetcher (offline analysis) or a test double
        return False


def _run_modules(run: _Run) -> list[Issue]:
    ctx = run.ctx
    cov = ctx.coverage
    paranoid = ctx.options.paranoid
    issues: list[Issue] = []
    for name in CHECK_MODULES:
        mod = _module(name)
        checks = tuple(getattr(mod, "CHECKS", ()))
        cov.register(*checks)
        if _out_of_time(run):
            for c in checks:
                cov.not_tested(c, "time_budget")
            run.note("time_budget", module=name)
            continue
        try:
            found = list(mod.run(ctx) or [])
        except Exception as e:   # noqa: BLE001 - one module's bug must not hide the others (§3.8)
            if _debug():
                raise
            err = cap(strip_controls(f"{type(e).__name__}: {e}"), 200)
            run.errors.append({"stage": 2, "module": name, "error": err})
            for c in checks:
                cov.not_tested(c, "error", detail_en=type(e).__name__, detail_ar=type(e).__name__)
            run.note("module_error", module=name, error=type(e).__name__)
            continue
        for i in found:
            meta = RULES.get(getattr(i, "rule", ""))
            if meta is not None and meta.paranoid_only and not paranoid:
                continue                          # §3.6: paranoid-only rules are not reported below paranoid
            fixed = _coerce(run, i)
            if fixed is not None:
                issues.append(fixed)
    return issues


def _https_unchecked(run: _Run) -> None:
    """An http target whose https counterpart was never tried (another port is never contacted, §0.1; the minimal
    profile; a WAF/rate-limited entry) has *unknown* TLS, not "not applicable": the TLS checks are ``not_tested`` and
    the grade is provisional (§3.4 step 3)."""
    ctx = run.ctx
    if not ctx.target.lower().startswith("http://") or ctx.tls or ctx.https_probe is not None:
        return
    entry = ctx.entry
    if entry is not None and any(h.scheme == "https" for h in entry.hops()):
        return
    checks = tuple(getattr(_module("tls"), "CHECKS", ()))
    if ctx.options.profile == "minimal":
        reason, en, ar = "profile", "", ""
    elif run.blocked:
        reason, en, ar = run.blocked if run.blocked == "rate_limited" else "waf", "", ""
    else:
        reason = "not_run"
        en, ar = STR["https_port"]
    for c in checks:
        ctx.coverage.not_tested(c, reason, host=ctx.target_host, detail_en=en, detail_ar=ar)


def _check_list(states, lang: str, limit: int = 25) -> str:
    ids = [s.check_id for s in states]
    shown = ", ".join(ids[:limit])
    if len(ids) > limit:
        shown += (" " if lang == "en" else " ") + text("and_more", lang, n=len(ids) - limit)
    return shown


def _meta_issues(run: _Run) -> list[Issue]:
    """WEB990 (gate G4 / rate limit) and WEB991 (checks not performed for a reason other than the profile)."""
    from . import classify
    ctx = run.ctx
    cov = ctx.coverage
    out: list[Issue] = []
    entry = ctx.entry
    stopped = ""
    try:
        stopped = run.fetcher.host_stopped(ctx.target_host) if run.fetcher is not None else ""
    except Exception:   # noqa: BLE001
        stopped = ""
    blocked_entry = entry is not None and entry.kind in _BLOCKED_KINDS
    states = cov.states()
    if blocked_entry or stopped:
        notes: list[tuple[str, str]] = []
        name = "rate_limited"
        if entry is not None and entry.kind == "waf_challenge":
            prov = classify.waf_name(classify.waf_provider(entry)) or "WAF"
            notes.append(pair("waf_provider", provider=prov))
            name = prov
        else:
            notes.append(pair("rate_limited", host=ctx.target_host))
        inc = [s for s in states.values() if s.state == "inconclusive"]
        if inc:
            notes.append((text("inconclusive_checks", "en", checks=_check_list(inc, "en")),
                          text("inconclusive_checks", "ar", checks=_check_list(inc, "ar"))))
        src = entry if entry is not None else None
        ev = Evidence.for_response(src, where="header", name="waf" if name != "rate_limited" else "status",
                                   value=name if name != "rate_limited" else str(getattr(src, "status", "") or ""),
                                   now=ctx.now)
        out.append(Issue("WEB990", entry.url if entry is not None else ctx.target, "certain", ev, {},
                         group_value="inconclusive", notes=notes, host=ctx.target_host))
        cov.failed("WEB990", ctx.target_host)
    else:
        cov.passed("WEB990", ctx.target_host)
    skipped = [s for s in cov.skipped_for_limitations() if s.check_id not in ("WEB990", "WEB991")]
    stale: list[dict] = []
    try:
        data_mod = ctx.data or _module("data")
        stale = [s for s in data_mod.staleness(ctx.now) if s.get("rules")]
    except Exception:   # noqa: BLE001 - data module missing or a stub in tests
        stale = []
    if skipped or stale:
        notes = []
        if skipped:
            notes.append((text("not_tested_checks", "en", checks=_check_list(skipped, "en")),
                          text("not_tested_checks", "ar", checks=_check_list(skipped, "ar"))))
            for s in skipped[:10]:
                for _code, en, ar in s.reasons[:1]:
                    notes.append((f"{s.check_id}: {en}", f"{s.check_id}: {ar}"))
        for s in stale:
            notes.append((s["en"], s["ar"]))
        ev = Evidence.for_response(None, where="probe", name="coverage",
                                   value=", ".join(s.check_id for s in skipped[:40]), now=ctx.now)
        out.append(Issue("WEB991", ctx.entry.url if _received(ctx.entry) else ctx.target, "certain", ev, {},
                         group_value="coverage", notes=notes, host=ctx.target_host))
        cov.failed("WEB991", ctx.target_host)
    else:
        cov.passed("WEB991", ctx.target_host)
    return out


# ----------------------------------------------------------------------------------------------- findings

def _clean_params(params: dict | None) -> dict:
    out: dict = {}
    for k, v in (params or {}).items():
        if isinstance(v, str):
            out[k] = cap(strip_controls(v), PARAM_CAP)
        elif isinstance(v, (int, float, bool)) or v is None:
            out[k] = v
        elif isinstance(v, (list, tuple)):
            out[k] = ", ".join(cap(strip_controls(str(x)), 80) for x in list(v)[:20])
        else:
            out[k] = cap(strip_controls(str(v)), PARAM_CAP)
    return out


def _snippet(rule: str, issue: Issue, params: dict, status: int | None) -> str:
    if rule in _PROBE_RULES and params.get("path"):
        st = issue.evidence.status if issue.evidence is not None and issue.evidence.status else status
        return cap(f"{params['path']} → HTTP {st}" if st else str(params["path"]), SNIPPET_CAP)
    m = (issue.evidence.match if issue.evidence is not None else None) or {}
    value = m.get("value") or m.get("excerpt") or ""
    if value:
        return cap(strip_controls(str(value)), SNIPPET_CAP)
    if status:
        return f"HTTP {status}"
    return cap(strip_controls(str(m.get("name") or issue.url)), SNIPPET_CAP)


def _finding(g) -> Any:
    from ..model import Finding
    i = g.issue
    meta = RULES[g.rule]
    params = _clean_params(i.params)
    try:
        title_en = meta.title("en", **params)
        title_ar = meta.title("ar", **params)
        advice_ar = meta.advice("ar", **params)
        advice_en = meta.advice("en", **params)
    except (KeyError, ValueError, IndexError):
        title_en, title_ar = meta.name_en, meta.name_ar
        advice_ar, advice_en = meta.advice_ar, meta.advice_en
    title_1_0 = title_en
    if meta.title_1_0:
        try:
            title_1_0 = re.sub(r"\{([a-z_][a-z0-9_]*)\}", lambda m: str(params.get(m.group(1), "")), meta.title_1_0)
        except Exception:   # noqa: BLE001
            title_1_0 = title_en
    ev = i.evidence.to_dict() if i.evidence is not None else {}
    status = ev.get("status")
    try:
        netloc = urllib.parse.urlsplit(i.url).netloc or g.host
    except ValueError:
        netloc = g.host
    notes = [{"en": cap(strip_controls(str(en)), 2000), "ar": cap(strip_controls(str(ar)), 2000)} for en, ar in g.notes]
    extra: dict = {
        "confidence": g.confidence, "wstg": list(meta.wstg), "asvs4": list(meta.asvs4), "asvs5": list(meta.asvs5),
        "evidence": ev, **g.extra(), "role": sorted(g.roles), "remediation": list(meta.fix), "family": meta.family,
        "grade_family": meta.grade_family, "check": meta.check_id, "url": cap(i.url, 2000), "host": g.host,
        "notes": notes, "advice_en": advice_en, "params": params, "fp_title": title_1_0,
    }
    if i.ips:
        extra["ips"] = list(i.ips)
    if g.rule in _PLATFORM_RULES:                 # 1.0.1 extra fields of the platform findings
        extra["platform"] = params.get("name") or params.get("platform")
        extra["version"] = params.get("version")
    elif g.rule in ("WEB082", "WEB083") and params.get("platform"):
        extra["platform"] = params.get("platform")
    return Finding(g.rule, g.severity, title_en, title_ar, netloc, 0, _snippet(g.rule, i, params, status), advice_ar,
                   meta.cwe, source="web", extra=extra)


def _legacy_web000_url(findings: list, target: str) -> None:
    """1.0.1 fingerprinted WEB000 on the http:// URL exactly as the user typed it (``http://host`` without the ``/`` the
    fetcher adds): keep it in ``extra["fp_url"]`` so ``model.Finding.base_fingerprint`` still matches a 1.0.x baseline."""
    try:
        http_target = urllib.parse.urlsplit(target).scheme.lower() == "http"
    except ValueError:
        http_target = False
    if not http_target:
        return                        # 1.0.1 reported WEB000 for http:// targets only
    for f in findings:
        if f.rule_id == "WEB000":
            f.extra["fp_url"] = cap(strip_controls(target), 2000)


def to_findings(groups: Iterable[Any]) -> list:
    """Grouped issues (``group.Group``) → ``model.Finding``, most severe first, then registry order."""
    gs = [g for g in groups if g.rule in RULES]
    gs.sort(key=lambda g: (SEV_RANK.get(g.severity, 9), RULE_ORDER.get(g.rule, 9999)))
    return [_finding(g) for g in gs]


# ----------------------------------------------------------------------------------------------- pipeline

def _validate_target(target: str, timeout: float) -> str:
    t = (target or "").strip()
    try:
        p = urllib.parse.urlsplit(t)
        host = p.hostname
        p.port   # noqa: B018 - raises ValueError for a bad port
    except ValueError:
        raise WebUnreachable(_explain("invalid URL", t, timeout)) from None
    if p.scheme.lower() not in ("http", "https") or not host:
        raise WebUnreachable(_explain(f"unsupported URL (only http:// and https:// are scanned): {cap(t, 200)}", t,
                                      timeout))
    return t


def _check_options(opts: ScanOptions) -> None:
    if opts.profile not in PROFILES:
        raise ValueError(f"unknown web profile {opts.profile!r} (minimal, standard or deep)")
    if opts.sensitivity not in SENSITIVITIES:
        raise ValueError(f"unknown web sensitivity {opts.sensitivity!r} (strict, default or paranoid)")


def scan(target: str, options: ScanOptions | None = None, *, previous: dict | None = None, fetcher: Any = None,
         scan_id: str = "", environ: dict | None = None,
         progress: Callable[[str], None] | None = None) -> WebScanResult:
    """Run a passive scan of ``target`` (see the module docstring) and return the :class:`WebScanResult`.

    ``previous``: the ``web_snapshot`` of an earlier scan of the same target (``web.diff`` is then filled);
    ``fetcher``: an ``http.Fetcher`` (tests); ``environ``: environment for the test-only hooks (default
    ``os.environ``); ``progress``: called with a short step name before each pipeline step."""
    opts = options or ScanOptions()
    _check_options(opts)
    target = _validate_target(target, opts.timeout)
    from . import coverage as _coverage
    from . import data as _data
    from . import http
    own_fetcher = fetcher is None
    if fetcher is None:
        fetcher = http.Fetcher(opts, target, environ=environ)
    ctx = ScanContext(options=opts, target=target, data=_data, coverage=_coverage.Coverage(), now=utcnow())
    ctx.fetcher = fetcher
    try:
        ctx.proxied = bool(fetcher.proxied)
    except Exception:   # noqa: BLE001
        ctx.proxied = False
    run = _Run(ctx, fetcher)

    def step(name: str) -> None:
        if progress is not None:
            try:
                progress(name)
            except Exception:   # noqa: BLE001 - a UI callback must never break the scan
                pass

    try:
        return _pipeline(run, step, previous=previous, scan_id=scan_id)
    finally:
        if own_fetcher:
            fetcher.close()


def _pipeline(run: _Run, step: Callable[[str], None], *, previous: dict | None, scan_id: str) -> WebScanResult:
    from . import classify, grade, group
    from . import diff as _diff
    from . import tls as _tls
    ctx = run.ctx
    opts = ctx.options
    fetcher = run.fetcher
    # -- step 2: entry chain
    step("entry")
    entry = fetcher.fetch(ctx.target, source="entry")
    if not any(h.status is not None for h in entry.hops()):
        raise WebUnreachable(_explain(entry.error or "no response", ctx.target, opts.timeout))
    ctx.entry = entry
    first = _page(entry, 0)
    if first.doc is not None:
        ctx.pages.append(first)
    if entry.kind in _BLOCKED_KINDS:
        run.blocked = "waf" if entry.kind == "waf_challenge" else "rate_limited"
        what = pair("waf_what", provider=classify.waf_name(classify.waf_provider(entry)) or "WAF") \
            if run.blocked == "waf" else pair("rate_what", status=entry.status)
        run.note("blocked", what=what)
    if _received(entry) and not _same_site(entry.host, ctx.target_host):
        run.note("offsite", host=entry.host)
    if ctx.proxied:
        run.note("proxied")
    crawl_seed: list[str] = []
    # -- step 3: standard and deep
    if opts.profile != "minimal" and not run.blocked:
        step("counterpart")
        _fetch_counterpart(run)
        step("cors")
        _fetch_cors(run)
        step("wellknown")
        _fetch_wellknown(run, crawl_seed)
        step("subresources")
        _fetch_same_site_subresources(run)
    # -- step 4: TLS
    step("tls")
    try:
        _tls.collect(ctx)
    except Exception as e:   # noqa: BLE001 - tls.collect guards each host; this is a last resort
        if _debug():
            raise
        run.errors.append({"stage": "tls", "module": "tls", "error": type(e).__name__})
    # -- step 5: crawl
    if opts.crawl and not run.blocked:
        step("crawl")
        _crawl(run, crawl_seed)
        if run.crawl_failed:
            shown = "، ".join(urllib.parse.urlsplit(u).path or "/" for u in run.crawl_failed[:5])
            shown_en = ", ".join(urllib.parse.urlsplit(u).path or "/" for u in run.crawl_failed[:5])
            more = " …" if len(run.crawl_failed) > 5 else ""
            n = len(run.crawl_failed)
            run.notes.append((text("crawl_failed", "en", pages=_count("pages", n, "en"), paths=shown_en + more),
                              text("crawl_failed", "ar", pages=_count("pages", n, "ar"), paths=shown + more)))
    if opts.profile != "minimal" and not run.blocked:
        step("dns")
        _resolve_referenced(run)
    # -- step 6: deep
    classify.classify_context(ctx)
    if opts.deep and not run.blocked:
        step("deep")
        try:
            _module("tech").detect(ctx)
        except Exception as e:   # noqa: BLE001
            if _debug():
                raise
            run.errors.append({"stage": "deep", "module": "tech", "error": type(e).__name__})
        _fetch_third_party(run)
        _fetch_sourcemaps(run)
    if (opts.deep or opts.crawl) and not run.blocked:
        _fetch_images(run)
    if opts.deep and not run.blocked:
        try:
            _module("exposure").probe(ctx)
        except Exception as e:   # noqa: BLE001
            if _debug():
                raise
            run.errors.append({"stage": "deep", "module": "exposure", "error": type(e).__name__})
        for r in list(ctx.probes) + list(ctx.baselines):
            _classify(r)
    # -- step 7: analysis
    step("analysis")
    classify.classify_context(ctx)
    ctx.dns.update(getattr(fetcher, "dns", {}) or {})
    _stage1(run)
    issues = _run_modules(run)
    _https_unchecked(run)
    issues.extend(_meta_issues(run))
    result = group.process(issues, ctx)
    findings = to_findings(result.groups)
    _legacy_web000_url(findings, ctx.target)
    grades = grade.grades(ctx, result, _grade_states(ctx.coverage), sensitivity=opts.sensitivity)
    snapshot = _diff.snapshot(ctx, findings, grades, ctx.coverage, scan_id=scan_id)
    diff_out = _diff.diff(previous, snapshot) if previous is not None else None
    return _result(run, findings, result, grades, snapshot, diff_out)


_UNREADABLE = frozenset({"too_many_headers", "header_too_large", "bad_response"})


def _unreadable_notes(ctx: ScanContext, limit: int = 5) -> list[tuple[str, str]]:
    """Notes for responses that arrived but could not be read (more than 100 header lines, a header block over 64 KB,
    a malformed status line): never dropped silently (§0.6)."""
    from .http import error_code
    out: list[tuple[str, str]] = []
    for r in ctx.all_responses():
        if error_code(r) in _UNREADABLE:
            url = cap(strip_controls(r.url), 300)
            err = cap(strip_controls(r.error or error_code(r)), 200)
            p = pair("unreadable", url=url, error=err)
            if p not in out:
                out.append(p)
        if len(out) >= limit:
            break
    return out


def _grade_states(cov) -> dict[str, str]:
    """Check states for the grade (§3.4 step 3). A check that is ``not_tested`` only because it is paranoid-only
    (reason ``sensitivity``) is outside this scan's rule set (§3.6: not even evaluated below paranoid), so for the grade
    it is ``not_applicable``: it must not make a family "untested" and the grade provisional (``*``)."""
    out: dict[str, str] = {}
    for cid, st in cov.states().items():
        codes = {code for code, _en, _ar in st.reasons}
        out[cid] = "not_applicable" if st.state == "not_tested" and codes == {"sensitivity"} else st.state
    return out


def _result(run: _Run, findings: list, gres: Any, grades: dict, snapshot: dict, diff_out: dict | None) -> WebScanResult:
    from . import grade
    ctx = run.ctx
    opts = ctx.options
    fetcher = run.fetcher
    try:
        stats = fetcher.stats()
    except Exception:   # noqa: BLE001
        stats = {}
    requests = int(stats.get("requests", getattr(fetcher, "requests", 0)) or 0)
    notes: list[tuple[str, str]] = [(text("profile", "en", profile=opts.profile, requests=_count("requests", requests, "en")),
                                     text("profile", "ar", profile=opts.profile,
                                          requests=_count("requests", requests, "ar")))]
    if opts.crawl:
        pages = 1 + run.crawl_fetched
        notes.append((text("crawl", "en", pages=_count("pages", pages, "en"), delay=f"{max(opts.delay, 0.2):g}"),
                      text("crawl", "ar", pages=_count("pages", pages, "ar"), delay=f"{max(opts.delay, 0.2):g}")))
    notes.extend(run.notes)
    notes.extend(_unreadable_notes(ctx))
    for ev in getattr(fetcher, "events", None) or []:
        if isinstance(ev, dict) and ev.get("en") and ev.get("ar"):
            p = (strip_controls(ev["en"]), strip_controls(ev["ar"]))
            if p not in notes:
                notes.append(p)
    try:
        for s in ctx.data.staleness(ctx.now) if ctx.data is not None else []:
            if (s["en"], s["ar"]) not in notes:
                notes.append((s["en"], s["ar"]))
    except Exception:   # noqa: BLE001
        pass
    cov = ctx.coverage
    notes.append((text("coverage", "en", summary=cov.summary("en")), text("coverage", "ar", summary=cov.summary("ar"))))
    notes.append((grade.summary(grades, "en"), grade.summary(grades, "ar")))
    data_date = ""
    try:
        d = ctx.data.snapshot_date()
        data_date = d.isoformat() if d else ""
        notes.append((ctx.data.as_of("en"), ctx.data.as_of("ar")))
    except Exception:   # noqa: BLE001
        pass
    inv = dict(ctx.inventory) if isinstance(ctx.inventory, dict) else {}
    inv["notes"] = [{"en": en, "ar": ar} for en, ar in notes]
    inv["requests"] = stats
    inv["suppressed"] = gres.suppressed_summary()
    inv["noise_ratio"] = gres.noise_ratio
    inv["raw_issues"] = gres.raw_count
    inv["crawl_fetched"] = run.crawl_fetched
    inv["crawl_failed"] = [cap(u, 2000) for u in run.crawl_failed]
    inv["hidden_groups"] = len(gres.hidden)
    inv["coverage_summary"] = {"en": cov.summary("en"), "ar": cov.summary("ar")}
    inv["coverage_reasons"] = {"en": cov.reasons("en"), "ar": cov.reasons("ar")}
    inv["redirect_chain"] = [{"url": h.url, "status": h.status, "location": cap(h.headers.first("location"), 2000)}
                             for h in ctx.entry.hops()] if ctx.entry is not None else []
    try:
        from . import remediation
        inv["platforms"] = list(remediation.platforms_from_context(ctx))
    except Exception:   # noqa: BLE001
        inv["platforms"] = []
    if run.errors:
        inv["engine_errors"] = run.errors
    if run.problems:
        inv["engine_problems"] = sorted(set(run.problems))[:100]
    return WebScanResult(target=ctx.target, findings=findings, grades=grades, coverage=cov.to_dict(), inventory=inv,
                         notes=[ar for _en, ar in notes], snapshot=snapshot, diff=diff_out,
                         final_url=ctx.entry.url if ctx.entry is not None else "", profile=opts.profile,
                         requests=requests, bytes_received=int(stats.get("bytes", 0) or 0), data_date=data_date)


# ----------------------------------------------------------------------------------------------- offline analysis

def analyze_responses(target: str, entry: Response, options: ScanOptions | None = None, *,
                      modules: Iterable[str] = CHECK_MODULES, pages: Iterable[Response] = ()) -> tuple[list, ScanContext]:
    """Run the analysis half of the pipeline (classification, stage-1 facts, the given check modules, grouping) on
    responses that were already fetched — no network at all. Used by the 1.0.1 helper ``web._analyze_html`` and by
    tests. Returns ``(findings, ctx)``."""
    from . import classify, group
    from . import coverage as _coverage
    from . import data as _data
    opts = options or ScanOptions()
    ctx = ScanContext(options=opts, target=target, data=_data, coverage=_coverage.Coverage(), now=utcnow())
    ctx.entry = entry
    first = _page(entry, 0)
    if first.doc is not None:
        ctx.pages.append(first)
    for r in pages:
        ctx.pages.append(_page(r, 1))
    classify.classify_context(ctx)
    run = _Run(ctx, None)
    _stage1(run)
    issues: list[Issue] = []
    wanted = tuple(modules)
    for name in wanted:
        mod = _module(name)
        try:
            found = list(mod.run(ctx) or [])
        except Exception:   # noqa: BLE001
            if _debug():
                raise
            continue
        for i in found:
            meta = RULES.get(getattr(i, "rule", ""))
            if meta is not None and meta.paranoid_only and not opts.paranoid:
                continue
            fixed = _coerce(run, i)
            if fixed is not None:
                issues.append(fixed)
    result = group.process(issues, ctx)
    return to_findings(result.groups), ctx


# ----------------------------------------------------------------------------------------------- i18n

def i18n_catalog() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """``(CATALOG, PATTERNS)`` of the engine's Arabic texts for ``vulnscan/i18n/cat_web2.py`` (the ``STR`` table's
    templates, plus the count phrases)."""
    from .rules import template_patterns
    catalog: dict[str, str] = {}
    patterns: list[tuple[str, str]] = []
    for en, ar in STR.values():
        if "{" in ar:
            patterns.extend(template_patterns(ar, en))
        else:
            catalog[ar] = en
    for one, many, forms in COUNT_FORMS.values():
        catalog[forms[0]] = one.replace("{n}", "1")
        catalog[forms[1]] = many.replace("{n}", "2")
        for form in forms[2:]:
            rx = "^" + re.escape(form).replace(re.escape("{n}"), r"(?P<n>\d+)") + "$"
            patterns.append((rx, many.replace("{n}", r"\g<n>")))
    return catalog, patterns


__all__ = ["CHECK_MODULES", "SKIP_LINK", "STR", "COUNT_FORMS", "WebUnreachable", "scan", "to_findings",
           "analyze_responses", "i18n_catalog", "text", "pair"]
