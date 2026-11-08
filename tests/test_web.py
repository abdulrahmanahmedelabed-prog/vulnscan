"""Deep passive web checks exercised against a local throwaway HTTP server."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import urllib.parse

from vulnscan.web import _analyze_html, scan_url

PAGE = b"""<!doctype html><html><head>
<script src="http://cdn.evil.example/a.js"></script>
<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
</head><body>
<img src="http://insecure.example/logo.png">
<form action="http://insecure.example/login" method="post">
<input type="password" name="pw"></form>
</body></html>"""


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


@pytest.fixture
def site():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
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


def test_mixed_content_on_https_page():
    # Mixed content is only meaningful on an https page; analyze directly.
    parsed = urllib.parse.urlparse("https://site.example/")
    html = '<img src="http://insecure.example/x.png"><script src="https://cdn.example/a.js"></script>'
    got = {f.rule_id for f in _analyze_html(html, parsed, "site.example")}
    assert "WEB050" in got          # mixed content
    assert "WEB053" in got          # external script without SRI


def test_deep_scan_probes_exposed_paths(site):
    findings, err = scan_url(site, deep=True)
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
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Moodle)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/"
    httpd.shutdown()


def test_platform_detection(moodle):
    from vulnscan.web import scan_url
    findings, err = scan_url(moodle, deep=False)
    assert err is None
    plat = [f for f in findings if f.rule_id == "WEB080"]
    assert plat and plat[0].extra["platform"] == "Moodle"
    assert any(f.rule_id == "WEB081" for f in findings)   # 3.5 < 3.9 -> outdated


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


def test_unreachable_site_is_an_error_not_a_clean_result(monkeypatch):
    """A timed-out site must never look like a scan with zero findings."""
    import pytest
    from vulnscan import web
    calls = []

    def fake_get(url, timeout, read_body=False, retries=0):
        calls.append((url, retries))
        return None, None, b"", "timed out"
    monkeypatch.setattr(web, "_get", fake_get)
    with pytest.raises(web.WebUnreachable) as ei:
        web.scan_site("https://example.invalid/", timeout=5)
    msg = str(ei.value)
    assert "لم يُفحص" in msg and "انتهت مهلة" in msg and "timed out" in msg
    assert calls and calls[0][1] == 1          # the entry request is retried


def test_server_marks_unreachable_scan_as_error(monkeypatch, tmp_path):
    from vulnscan import server, web
    from vulnscan.store import Store
    monkeypatch.setattr(web, "_get", lambda *a, **k: (None, None, b"", "timed out"))
    store = Store(tmp_path)
    scan = store.new_scan("https://example.invalid/", "web")
    server.run_scan(store, scan, store.settings(), True)
    saved = store.get_scan(scan["id"])
    assert saved["status"] == "error" and "لم يُفحص" in saved["error"]
    assert saved["summary"]["high"] == 0 and not saved["findings"]


def test_windows_error_messages_are_explained_and_retried(monkeypatch):
    import pytest
    from vulnscan import web
    win = ("[WinError 10060] A connection attempt failed because the connected party did not properly respond after a "
           "period of time, or established connection failed because connected host has failed to respond")
    msg = web.explain_failure(win, "https://www.example.edu/", 20)
    assert "انتهت مهلة" in msg and "http://www.example.edu" in msg
    assert "رفض الخادم" in web.explain_failure("[WinError 10061] No connection could be made because the target machine actively refused it", "https://x/", 20)
    assert "اسم النطاق" in web.explain_failure("[Errno 11001] getaddrinfo failed", "https://x/", 20)
    assert "قطع الخادم" in web.explain_failure("[WinError 10054] An existing connection was forcibly closed by the remote host", "https://x/", 20)
    calls = []

    class Opener:
        def open(self, req, timeout):
            calls.append(timeout)
            raise OSError(win)
    monkeypatch.setattr(web.urllib.request, "build_opener", lambda *a: Opener())
    with pytest.raises(web.WebUnreachable):
        web.scan_site("https://www.example.edu/", timeout=5)
    assert calls == [5, 10]                     # the Windows timeout is recognised as transient: retried with double timeout


def test_vulnerable_library_versions_are_flagged():
    from vulnscan.web import _analyze_html
    import urllib.parse
    p = urllib.parse.urlparse("https://x/")
    html = ('<script src="/js/jquery-1.12.4.min.js"></script>'
            '<script src="/js/bootstrap-3.3.7.js"></script>'
            '<script src="/vendor/handlebars.min.js?v=4.0.5"></script>')
    ids = {(f.rule_id, f.title) for f in _analyze_html(html, p, "x")}
    titles = " ".join(t for _, t in ids)
    assert "jQuery 1.12.4" in titles and "Bootstrap 3.3.7" in titles and "Handlebars 4.0.5" in titles
    # a current version is not flagged
    ok = _analyze_html('<script src="/js/jquery-3.7.1.min.js"></script>', p, "x")
    assert not [f for f in ok if "jQuery" in f.title]


def _hdrs(d):
    import email.message
    m = email.message.Message()
    for k, v in d.items():
        m[k] = v
    return m


def test_crawl_groups_repeated_findings_and_counts_pages(monkeypatch):
    from vulnscan import web
    pages = {
        "https://site/": b'<html><a href="/a">a</a><a href="/b">b</a><form action="http://site/x"></form></html>',
        "https://site/a": b'<html><form action="http://site/x"></form></html>',
        "https://site/b": b'<html><form action="http://site/x"></form></html>',
    }

    def fake_get(url, timeout, read_body=False, retries=0):
        body = pages.get(url.rstrip("/") if url != "https://site/" else url, pages["https://site/"])
        return 200, _hdrs({"content-type": "text/html"}), body, None
    monkeypatch.setattr(web, "_get", fake_get)
    findings, note, count = web.scan_site("https://site/", crawl=True, max_pages=10, delay=0)
    forms = [f for f in findings if f.rule_id == "WEB051"]
    assert len(forms) == 1                                  # the same HTTP form on 3 pages -> one grouped finding
    assert forms[0].extra.get("page_count", 1) >= 2
    assert count >= 3                                       # entry + /a + /b counted


def test_crawl_delay_throttles_requests(monkeypatch):
    from vulnscan import web
    slept = []
    monkeypatch.setattr(web.time, "sleep", lambda s: slept.append(s))
    monkeypatch.setattr(web, "_get", lambda *a, **k: (200, _hdrs({"content-type": "text/html"}), b'<a href="/p">p</a>', None))
    web.scan_site("https://site/", crawl=True, max_pages=3, delay=0.5)
    assert slept and all(abs(x - 0.5) < 1e-9 for x in slept)


def test_user_agent_identifies_the_scanner_and_does_not_impersonate():
    from vulnscan.web import USER_AGENT
    assert "vulnscan" in USER_AGENT.lower()                 # honest identification, no stealth
