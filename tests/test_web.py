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
    single, _ = scan_site(moodle, crawl=False)
    crawled, _ = scan_site(moodle, crawl=True, max_pages=10, max_depth=2)
    # The insecure form only exists on /course, so only the crawl finds it.
    assert not any(f.rule_id == "WEB051" for f in single)
    assert any(f.rule_id == "WEB051" for f in crawled)
    # A crawled finding records which page it came from.
    assert any(f.extra.get("page") for f in crawled)


def test_crawl_skips_external_and_logout(moodle):
    from vulnscan.web import _same_origin_links
    import urllib.parse
    origin = urllib.parse.urlparse(moodle)
    links = _same_origin_links(MOODLE_HOME.decode(), moodle, origin)
    assert any("/course" in l for l in links)
    assert not any("other.example" in l for l in links)   # external skipped
    assert not any("logout" in l for l in links)          # logout skipped
