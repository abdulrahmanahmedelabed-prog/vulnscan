"""Passive web scanning: the 1.0.x facade over the 1.1.0 scanner (``vulnscan.webscan``).

Only runs when the user asserts authorization (``--authorized``): every request is traffic against someone else's
system. The public API of 1.0.1 is unchanged — :func:`scan_url`, :func:`scan_site`, :class:`WebUnreachable`,
:func:`explain_failure`, ``USER_AGENT``, ``TRANSIENT``, ``DEFAULT_TIMEOUT``, ``DEFAULT_DELAY``, ``MAX_BODY`` and the
helpers ``_get``, ``_analyze_html``, ``_group`` and ``_same_origin_links`` — while the work is done by
``webscan.engine`` (spec §4.3): a profile-bounded set of GET requests through one polite fetcher, response
classification, every check module, grouping, grades and an honest coverage table. New code calls
:func:`scan_web` (the full :class:`~vulnscan.webscan.types.WebScanResult`) or ``vulnscan.webscan.scan``.

Profiles (spec §0.1): ``minimal`` is the 1.0.1 single request (the entry chain only); ``standard`` (the default) adds
the http(s) counterpart chain, one cookieless CORS GET, the well-known files and the page's own scripts and styles
(≤ 45 requests); ``deep`` (``deep=True``) adds the fixed list of commonly exposed files with soft-404 baselines,
third-party scripts, source maps and images (≤ 150). It never submits forms, sends payloads, fuzzes parameters or
tries to bypass anything: it only reads what the server already serves, with an honest User-Agent.
"""

from __future__ import annotations

import http.client
import re
import time   # noqa: F401 - kept for callers and tests that patch web.time (1.0.1 API)
import urllib.error
import urllib.parse
import urllib.request

from .model import Finding
from .webscan import engine as _engine
from .webscan.engine import SKIP_LINK, WebUnreachable
from .webscan.types import ACCEPT_DOCUMENT, ScanOptions, WebScanResult, user_agent

MAX_BODY = 2_000_000           # bytes of a document (the fetcher's document cap, spec §4.3)
DEFAULT_TIMEOUT = 20.0
DEFAULT_DELAY = 0.5            # seconds between two requests to one host (all requests; the floor is 0.2 s)
# Honest identification (spec §0.2): the scanner says what it is and links to the page that explains its traffic.
USER_AGENT = user_agent()

# Windows (WinError / WSA codes), Linux and macOS phrasings of the same network failures
_TIMEOUT = ("timed out", "timeout", "10060", "did not properly respond", "failed to respond", "wsaetimedout",
            "deadline exceeded")
_DNS = ("name or service not known", "nodename nor servname", "getaddrinfo", "no address associated", "11001", "11004",
        "temporary failure in name resolution", "name resolution", "wsahost_not_found", "no such host")
_REFUSED = ("refused", "10061", "wsaeconnrefused")
_RESET = ("reset", "aborted", "10054", "10053", "forcibly closed", "connection was closed", "remote end closed",
          "closed by the server")
_UNREACHABLE = ("unreachable", "10051", "10065", "no route to host")
TRANSIENT = _TIMEOUT + _RESET + ("temporarily",)


def explain_failure(err: str, url: str, timeout: float) -> str:
    """A clear Arabic explanation of why a site could not be reached (the raw error is kept at the end)."""
    low = (err or "").lower()
    try:
        host = urllib.parse.urlparse(url).hostname or url
    except ValueError:
        host = url
    other = "http://" if url.lower().startswith("https://") else "https://"
    if any(w in low for w in _TIMEOUT):
        why = (f"انتهت مهلة الاتصال بـ {host} بعد {int(timeout)} ثانية في محاولتين. الموقع لم يرد: قد يكون بطيئًا أو متوقفًا، "
               "أو يحجب الطلبات القادمة من شبكتك أو من خارج بلده (جدار حماية / حجب جغرافي). "
               f"جرّب: فتح الموقع من المتصفح على الجهاز نفسه، أو من شبكة أخرى (بيانات الجوال)، أو {other}{host}، أو زد المهلة من الإعدادات.")
    elif any(w in low for w in _DNS):
        why = f"تعذّر حلّ اسم النطاق {host}: تحقق من كتابة العنوان ومن اتصال الإنترنت أو إعدادات DNS."
    elif any(w in low for w in _REFUSED):
        why = f"رفض الخادم {host} الاتصال: المنفذ مغلق أو الخدمة متوقفة. جرّب {other}{host}."
    elif any(w in low for w in _UNREACHABLE):
        why = f"لا يوجد مسار شبكي إلى {host}: الشبكة أو الخادم غير قابلين للوصول من جهازك الآن."
    elif "certificate" in low or "ssl" in low or "tls" in low:
        why = f"فشل إنشاء اتصال TLS آمن مع {host} (شهادة غير صالحة أو إعداد TLS خاطئ). هذا بحد ذاته مشكلة أمنية تستحق المراجعة."
    elif any(w in low for w in _RESET):
        why = f"قطع الخادم {host} الاتصال أثناء الطلب: قد يكون جدار حماية تطبيقات الويب (WAF) يحجب الطلب."
    else:
        why = f"تعذّر الوصول إلى {host}."
    return f"لم يُفحص الموقع — {why} (التفاصيل: {err})"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _get(url: str, timeout: float, read_body: bool = False, retries: int = 0):
    """One GET without following redirects (1.0.1 helper, kept for callers; the scanner itself fetches through
    ``webscan.http.Fetcher``). On a timeout or dropped connection, retry with a doubled timeout.
    Returns ``(status, headers, body, error)``."""
    opener = urllib.request.build_opener(_NoRedirect)
    last = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": ACCEPT_DOCUMENT})  # nosec - the URL is the user's own, --authorized scan target (intentional outbound request)
        try:
            resp = opener.open(req, timeout=timeout * (2 ** attempt))
            body = resp.read(MAX_BODY) if read_body else b""
            return resp.status, resp.headers, body, None
        except urllib.error.HTTPError as e:
            body = e.read(MAX_BODY) if read_body else b""
            return e.code, e.headers, body, None
        except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
            last = str(getattr(e, "reason", None) or e)
            transient = any(w in last.lower() for w in TRANSIENT)
            if not transient:
                break
    return None, None, b"", last


# ----------------------------------------------------------------------------------------------- scanning

def options_for(*, timeout: float = DEFAULT_TIMEOUT, deep: bool = False, crawl: bool = False, max_pages: int = 20,
                max_depth: int = 2, delay: float = DEFAULT_DELAY, profile: str | None = None,
                sensitivity: str = "default", respect_robots: bool = True, third_party_lookups: bool = False,
                cookie_ignore=(), use_proxy: bool = True, max_requests: int | None = None,
                time_budget: float = 600.0, lang: str = "ar") -> ScanOptions:
    """``ScanOptions`` from the facade's keyword arguments: ``profile`` wins over ``deep`` (deep → ``"deep"``, else
    ``"standard"``, the 1.1.0 default)."""
    return ScanOptions(profile=profile or ("deep" if deep else "standard"), crawl=bool(crawl), max_pages=int(max_pages),
                       max_depth=int(max_depth), delay=float(delay), timeout=float(timeout), sensitivity=sensitivity,
                       respect_robots=bool(respect_robots), third_party_lookups=bool(third_party_lookups),
                       max_requests=max_requests, time_budget=float(time_budget),
                       cookie_ignore=tuple(cookie_ignore or ()), lang=lang, use_proxy=bool(use_proxy))


def scan_web(url: str, *, previous: dict | None = None, scan_id: str = "", progress=None,
             options: ScanOptions | None = None, **kw) -> WebScanResult:
    """The full 1.1.0 result (findings, grades, coverage, inventory, notes, snapshot, diff). ``kw`` are the
    arguments of :func:`options_for` (ignored when ``options`` is given). Raises :class:`WebUnreachable`."""
    opts = options or options_for(**kw)
    return _engine.scan(url, opts, previous=previous, scan_id=scan_id, progress=progress)


def scan_url(url: str, timeout: float = DEFAULT_TIMEOUT, deep: bool = False, **kw) -> tuple[list[Finding], str | None]:
    """Passive checks of one URL (no crawl). Raises WebUnreachable when the URL cannot be fetched at all.

    Returns ``(findings, None)`` as in 1.0.1; :func:`scan_site` and :func:`scan_web` also return the scan notes."""
    kw.pop("crawl", None)
    res = scan_web(url, timeout=timeout, deep=deep, crawl=False, **kw)
    return res.findings, None


def scan_site(url: str, timeout: float = DEFAULT_TIMEOUT, deep: bool = False,
              crawl: bool = False, max_pages: int = 20, max_depth: int = 2,
              delay: float = DEFAULT_DELAY, **kw) -> tuple:
    """Scan a web app. Returns ``(findings, note, pages)`` as in 1.0.1.

    Always scans the entry URL (and, in the default ``standard`` profile, its well-known files, the http(s)
    counterpart, one CORS GET and the page's own scripts). With ``crawl`` it also follows same-origin links
    breadth-first (robots.txt honoured), up to ``max_pages`` pages and ``max_depth`` deep. ``delay`` is the minimum gap
    between two requests to one host (every request, floor 0.2 s). ``note`` is the scan's notes, one per line: the
    profile and request count, anything that limited the scan, the coverage summary and the grades. ``pages`` counts
    the entry page plus the crawled pages fetched. Extra keyword arguments are those of :func:`options_for`
    (``profile``, ``sensitivity``, …) plus ``previous``/``scan_id``/``progress`` of :func:`scan_web`."""
    passthrough = {k: kw.pop(k) for k in ("previous", "scan_id", "progress", "options") if k in kw}
    res = scan_web(url, timeout=timeout, deep=deep, crawl=crawl, max_pages=max_pages, max_depth=max_depth,
                   delay=delay, **kw, **passthrough)
    pages = 1 + (int(res.inventory.get("crawl_fetched", 0) or 0) if crawl else 0)
    note = "\n".join(res.notes) if res.notes else None
    return res.findings, note, pages


# ----------------------------------------------------------------------------------------------- 1.0.1 helpers

def _analyze_html(html: str, parsed, label: str) -> list[Finding]:
    """Page-content checks of one HTML document already in hand (no network): mixed content, forms, password fields,
    SRI, libraries, directory listings and error pages — the content, libs and disclosure modules of 1.1.0."""
    from .webscan.types import HeaderList, Response
    url = parsed.geturl() if hasattr(parsed, "geturl") else str(parsed)
    resp = Response(url=url or "https://localhost/", status=200,
                    headers=HeaderList((("Content-Type", "text/html; charset=utf-8"),)),
                    body=(html or "").encode("utf-8", "replace"), source="entry")
    findings, _ctx = _engine.analyze_responses(resp.url, resp, ScanOptions(profile="minimal"),
                                               modules=("content", "libs", "disclosure"))
    for f in findings:
        f.file = label
    return findings


def _same_origin_links(html: str, base_url: str, origin) -> list:
    """Same-origin ``<a href>`` links of a page that the crawl may follow (state-changing and binary links skipped)."""
    out, seen = [], set()
    for m in _HREF.finditer(html):
        href = m.group(1).strip()
        if not href or href.lower().startswith(("mailto:", "tel:", "javascript:", "data:")):
            continue
        full = urllib.parse.urljoin(base_url, href)
        pr = urllib.parse.urlparse(full)
        if pr.scheme not in ("http", "https") or pr.netloc != origin.netloc:
            continue
        if SKIP_LINK.search(full):
            continue
        clean = pr._replace(fragment="").geturl()
        if clean not in seen:
            seen.add(clean)
            out.append(clean)
    return out


_HREF = re.compile(r"""<a\b[^<>]{0,2048}?\bhref\s*=\s*['"]([^'"#]+)['"]""", re.I)


def _group(findings: list[Finding]) -> list[Finding]:
    """1.0.1 grouping, kept for callers: collapse the same (rule, title, snippet) seen on many pages into one finding
    that lists where it occurred (``extra.pages``/``page_count``). The 1.1.0 engine groups systemically (§3.5)."""
    out: list[Finding] = []
    by_key: dict = {}
    for f in findings:
        key = (f.rule_id, f.title_ar, f.snippet)
        page = f.extra.get("page")
        if key in by_key:
            g = by_key[key]
            if page:
                g.extra.setdefault("pages", []).append(page)
            continue
        by_key[key] = f
        if page:
            f.extra.setdefault("pages", []).append(page)
        out.append(f)
    for f in out:
        pages = f.extra.get("pages")
        if pages:
            uniq_pages = list(dict.fromkeys(pages))
            f.extra["pages"] = uniq_pages
            f.extra["page_count"] = len(uniq_pages)
    return out


__all__ = ["scan_url", "scan_site", "scan_web", "options_for", "WebUnreachable", "explain_failure", "USER_AGENT",
           "TRANSIENT", "DEFAULT_TIMEOUT", "DEFAULT_DELAY", "MAX_BODY", "SKIP_LINK"]
