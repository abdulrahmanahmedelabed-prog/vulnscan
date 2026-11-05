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
