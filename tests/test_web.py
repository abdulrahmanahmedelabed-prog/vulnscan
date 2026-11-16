"""Passive web checks through the 1.0.1 facade (``vulnscan.web``), exercised against local throwaway HTTP servers.

Kashif 1.1.0 runs the same API on the ``vulnscan.webscan`` engine. Every request stays on 127.0.0.1: proxies are
removed from the environment and the test-only resolver hook (``KASHIF_TEST_RESOLVE=1``) answers every other name
with a documentation address, so no DNS query or connection leaves the machine.

Tests that were rewritten for 1.1.0 say why next to the change: either they asserted a 1.0.1 defect (spec §1.6,
named by its D-number) or they patched the 1.0.1 ``urllib`` transport (``web._get``), which the scanner no longer
uses (every request goes through ``webscan.http.Fetcher``, spec §4.1, §0.7).
"""
import json
import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from vulnscan.web import _analyze_html, scan_url

PAGE = b"""<!doctype html><html><head>
<script src="http://cdn.evil.example/a.js"></script>
<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
</head><body>
<img src="http://insecure.example/logo.png">
<form action="http://insecure.example/login" method="post">
<input type="password" name="pw"></form>
</body></html>"""

PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    """No proxy, no real DNS (test-only resolver hook), no user web data."""
    for k in PROXY_VARS:
        monkeypatch.delenv(k, raising=False)
    rmap = tmp_path / "resolve.json"
    rmap.write_text(json.dumps({"version": 1, "hosts": {},
                                "default": {"status": "ok", "addresses": ["192.0.2.1"], "public": True}}),
                    encoding="utf-8")
    monkeypatch.setenv("KASHIF_TEST_RESOLVE", "1")
    monkeypatch.setenv("KASHIF_TEST_RESOLVE_MAP", str(rmap))
    monkeypatch.delenv("KASHIF_TEST_CAFILE", raising=False)
    monkeypatch.setenv("KASHIF_HOME", str(tmp_path / "home"))
    from vulnscan.webscan import data
    data.clear_cache()
    yield
    data.clear_cache()


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "sid=abc; Path=/")
            self.send_header("Server", "TestServer/1.2.3")
            self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline' *")
            self.end_headers()
            self.wfile.write(PAGE)
        elif self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"SECRET_KEY=supersecretvalue\nDB_PASSWORD=hunter2\n")
        elif self.path == "/.git/HEAD":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ref: refs/heads/main\n")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")


def _serve(handler):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


@pytest.fixture
def site():
    httpd = _serve(H)
    yield f"http://127.0.0.1:{httpd.server_address[1]}/"
    httpd.shutdown()


def ids(findings):
    return {f.rule_id for f in findings}


def test_shallow_scan_is_one_request(site):
    findings, err = scan_url(site, deep=False)
    assert err is None
    got = ids(findings)
    # HTML analysis of the main page runs with no extra requests.
    assert "WEB051" in got          # form over http
    assert "WEB052" in got          # password field on http page
    assert "WEB053" in got          # external script without SRI
    assert "WEB054" in got          # outdated jQuery
    assert "WEB040" in got          # CSP unsafe-inline
    assert "WEB042" in got          # CSP wildcard
    assert "WEB021" in got          # cookie without HttpOnly
    assert "WEB010" in got          # server version
    # Exposed-path probes only happen in deep mode.
    assert "WEB062" not in got


def test_minimal_profile_is_the_1_0_1_single_request(site):
    """1.1.0 default is the ``standard`` profile (spec §4.3); ``minimal`` keeps the 1.0.1 one-request behaviour."""
    from vulnscan.web import scan_web
    res = scan_web(site, profile="minimal", delay=0.2)
    assert res.requests == 1 and res.profile == "minimal"
    assert {"WEB051", "WEB040", "WEB021"} <= ids(res.findings)


def test_mixed_content_on_https_page():
    # Mixed content is only meaningful on an https page; analyze directly.
    parsed = urllib.parse.urlparse("https://site.example/")
    html = '<img src="http://insecure.example/x.png"><script src="https://cdn.example/a.js"></script>'
    got = {f.rule_id for f in _analyze_html(html, parsed, "site.example")}
    assert "WEB050" in got          # mixed content
    assert "WEB053" in got          # external script without SRI


def test_deep_scan_probes_exposed_paths(site):
    findings, err = scan_url(site, deep=True, delay=0.2)
    assert err is None
    exposed = [f for f in findings if f.rule_id == "WEB062"]
    snippets = " ".join(f.snippet for f in exposed)
    assert ".env" in snippets and ".git/HEAD" in snippets
    assert any(f.severity == "critical" for f in exposed)   # .env is critical
    assert any(f.rule_id == "WEB060" for f in findings)     # no security.txt


MOODLE_HOME = b"""<!doctype html><html><head>
<meta name="keywords" content="moodle, course">
<title>Jamiah LMS</title></head><body>
<p>This site is using Moodle 3.5.2</p>
<a href="/course/view.php?id=1">Course</a>
<a href="/login/index.php">Login</a>
<a href="https://other.example/x">external</a>
<a href="/logout.php">Logout</a>
<img src="http://insecure.example/l.png">
</body></html>"""

MOODLE_COURSE = b"""<!doctype html><html><head><title>Course</title></head><body>
<form action="http://insecure.example/enrol" method="post"><input name=q></form>
</body></html>"""


class Moodle(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "MoodleSession=abc; Path=/")
        self.end_headers()
        if self.path.startswith("/course"):
            self.wfile.write(MOODLE_COURSE)
        else:
            self.wfile.write(MOODLE_HOME)


@pytest.fixture
def moodle():
    httpd = _serve(Moodle)
    yield f"http://127.0.0.1:{httpd.server_address[1]}/"
    httpd.shutdown()


class WordPress(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path != "/":
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b'<!doctype html><html><head><meta name="generator" content="WordPress 4.9">'
                         b'<link rel="stylesheet" href="/wp-content/themes/t/style.css"></head><body>Blog</body></html>')


def test_platform_detection(moodle):
    from vulnscan.web import scan_url
    findings, err = scan_url(moodle, deep=False)
    assert err is None
    plat = [f for f in findings if f.rule_id == "WEB080"]
    assert plat and plat[0].extra["platform"] == "Moodle"
    # Rewritten for D15 (spec §1.6): 1.0.1 read the version from page prose ("This site is using Moodle 3.5.2"),
    # which also fires on documentation and blog posts. Versions now come only from scoped signals (generator
    # meta, headers, asset paths); prose never makes a WEB081.
    assert not any(f.rule_id == "WEB081" for f in findings)


def test_outdated_platform_version_from_the_generator_meta():
    httpd = _serve(WordPress)
    try:
        findings, err = scan_url(f"http://127.0.0.1:{httpd.server_address[1]}/", deep=False)
    finally:
        httpd.shutdown()
    assert err is None
    old = [f for f in findings if f.rule_id == "WEB081"]
    assert old and old[0].extra["platform"] == "WordPress" and old[0].extra["version"].startswith("4.9")


def test_crawl_reaches_other_pages(moodle):
    from vulnscan.web import scan_site
    single, _, pages1 = scan_site(moodle, crawl=False, delay=0)
    crawled, _, pages = scan_site(moodle, crawl=True, max_pages=10, max_depth=2, delay=0)
    # The insecure form only exists on /course, so only the crawl finds it.
    assert not any(f.rule_id == "WEB051" for f in single)
    assert any(f.rule_id == "WEB051" for f in crawled)
    assert pages1 == 1 and pages >= 2               # the entry page plus at least one crawled page
    # A crawled finding records which page it came from.
    assert any(f.extra.get("pages") or f.extra.get("page") for f in crawled)


def test_crawl_skips_external_and_logout(moodle):
    from vulnscan.web import _same_origin_links
    import urllib.parse
    origin = urllib.parse.urlparse(moodle)
    links = _same_origin_links(MOODLE_HOME.decode(), moodle, origin)
    assert any("/course" in l for l in links)
    assert not any("other.example" in l for l in links)   # external skipped
    assert not any("logout" in l for l in links)          # logout skipped


class _BlackHole:
    """Accepts TCP connections and never answers (a site that times out); counts the connections."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.conns: list = []
        self.times: list[float] = []
        self._stop = threading.Event()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                c, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            self.conns.append(c)
            self.times.append(time.monotonic())

    def close(self):
        self._stop.set()
        for c in self.conns:
            c.close()
        self.sock.close()


def test_unreachable_site_is_an_error_not_a_clean_result():
    """A timed-out site must never look like a scan with zero findings.

    Rewritten for 1.1.0: the 1.0.1 test patched ``web._get`` (the urllib transport), which the scanner no longer
    uses; a local server that accepts and never answers gives the same timeout through the real fetcher."""
    from vulnscan import web
    hole = _BlackHole()
    try:
        with pytest.raises(web.WebUnreachable) as ei:
            web.scan_site(f"http://127.0.0.1:{hole.port}/", timeout=0.3, delay=0.2)
    finally:
        hole.close()
    msg = str(ei.value)
    assert "لم يُفحص" in msg and "انتهت مهلة" in msg and "timed out" in msg
    assert len(hole.times) == 2                # the entry request is retried once (with a doubled timeout)


def test_server_marks_unreachable_scan_as_error(tmp_path):
    from vulnscan import server
    from vulnscan.store import Store
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                   # nothing listens there: connection refused
    store = Store(tmp_path)
    scan = store.new_scan(f"http://127.0.0.1:{port}/", "web")
    server.run_scan(store, scan, {**store.settings(), "web_timeout": 2, "web_delay": 0.2}, True)
    saved = store.get_scan(scan["id"])
    assert saved["status"] == "error" and "لم يُفحص" in saved["error"]
    assert saved["summary"]["high"] == 0 and not saved["findings"]


def test_windows_error_messages_are_explained_and_retried():
    from vulnscan import web
    from vulnscan.webscan import http as whttp
    win = ("[WinError 10060] A connection attempt failed because the connected party did not properly respond after a "
           "period of time, or established connection failed because connected host has failed to respond")
    msg = web.explain_failure(win, "https://www.example.edu/", 20)
    assert "انتهت مهلة" in msg and "http://www.example.edu" in msg
    assert "رفض الخادم" in web.explain_failure("[WinError 10061] No connection could be made because the target machine actively refused it", "https://x/", 20)
    assert "اسم النطاق" in web.explain_failure("[Errno 11001] getaddrinfo failed", "https://x/", 20)
    assert "قطع الخادم" in web.explain_failure("[WinError 10054] An existing connection was forcibly closed by the remote host", "https://x/", 20)
    # Rewritten for 1.1.0 (the 1.0.1 test patched urllib's build_opener, no longer used): Windows raises
    # WinError 10060 as TimeoutError, which the fetcher classifies as a timeout (retried once, doubled timeout).
    code, text = whttp.classify_error(TimeoutError(10060, win))
    assert code == "timeout" and "انتهت مهلة" in web.explain_failure(text, "https://x/", 20)
    code, text = whttp.classify_error(ConnectionResetError(10054, "An existing connection was forcibly closed"))
    assert code == "reset" and any(w in text.lower() for w in web.TRANSIENT)


def test_vulnerable_library_versions_are_flagged():
    from vulnscan.web import _analyze_html
    import urllib.parse
    p = urllib.parse.urlparse("https://x/")
    # Rewritten for 1.1.0: versions come from retire.js's URL patterns, which read the file name, not a query-string
    # cache-buster (``handlebars.min.js?v=4.0.5`` names the site's build, not the library's version); names are
    # retire.js component names, so compare without case.
    html = ('<script src="/js/jquery-1.12.4.min.js"></script>'
            '<script src="/js/bootstrap-3.3.7.js"></script>'
            '<script src="/vendor/handlebars-4.0.5.min.js"></script>')
    ids = {(f.rule_id, f.title) for f in _analyze_html(html, p, "x")}
    titles = " ".join(t for _, t in ids).lower()
    assert "jquery 1.12.4" in titles and "bootstrap 3.3.7" in titles and "handlebars 4.0.5" in titles
    # a current version is not flagged
    ok = _analyze_html('<script src="/js/jquery-3.7.1.min.js"></script>', p, "x")
    assert not [f for f in ok if "jQuery" in f.title]


SITE_PAGES = {
    "/": b'<html><a href="/a">a</a><a href="/b">b</a><form action="http://site.example/x"></form></html>',
    "/a": b'<html><p>first page</p><form action="http://site.example/x"></form></html>',
    "/b": b'<html><p>second page, a little different</p><form action="http://site.example/x"></form></html>',
}


class Pages(BaseHTTPRequestHandler):
    times: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        Pages.times.append(time.monotonic())
        body = SITE_PAGES.get(self.path.split("?")[0])
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)


def test_crawl_groups_repeated_findings_and_counts_pages():
    """Rewritten for 1.1.0 (local server instead of the patched ``web._get``); grouping is systemic (D24)."""
    from vulnscan import web
    httpd = _serve(Pages)
    try:
        findings, note, count = web.scan_site(f"http://127.0.0.1:{httpd.server_address[1]}/", crawl=True,
                                              max_pages=10, delay=0.2)
    finally:
        httpd.shutdown()
    forms = [f for f in findings if f.rule_id == "WEB051"]
    assert len(forms) == 1                                  # the same HTTP form on 3 pages -> one grouped finding
    assert forms[0].extra.get("page_count", 1) >= 2 and forms[0].extra["instances"] >= 3
    assert count >= 3                                       # entry + /a + /b counted
    assert note and "التغطية" in note                       # the note carries the coverage summary


def test_crawl_delay_throttles_requests():
    """Rewritten for D25 (spec §1.6): 1.0.1 slept only between crawled pages; now every request to a host, well-known
    files and the CORS GET included, is at least ``delay`` apart (one global limiter)."""
    from vulnscan import web
    Pages.times = []
    httpd = _serve(Pages)
    try:
        web.scan_site(f"http://127.0.0.1:{httpd.server_address[1]}/", crawl=True, max_pages=3, delay=0.5)
    finally:
        httpd.shutdown()
    times = sorted(Pages.times)
    gaps = [b - a for a, b in zip(times, times[1:])]
    assert len(times) >= 5 and gaps and min(gaps) >= 0.45


def test_user_agent_identifies_the_scanner_and_does_not_impersonate():
    from vulnscan.web import USER_AGENT
    assert "vulnscan" in USER_AGENT.lower()                 # honest identification, no stealth
    assert USER_AGENT.startswith("Kashif/") and "Mozilla" not in USER_AGENT
