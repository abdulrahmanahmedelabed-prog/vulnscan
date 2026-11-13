"""Information disclosure (spec §2.7, WP8): unit vectors per rule, the shared guards, data files, coverage states and
the corpus cases labelled with WP8 rules (C-DISC and the others), rendered offline in-process.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import importlib
import json
import struct
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

import pytest

from vulnscan.webscan import classify, coverage, data, disclosure, htmlparse
from vulnscan.webscan.rules import RULES, validate_issue
from vulnscan.webscan.types import CookieFact, HeaderList, Page, Response, ScanContext, ScanOptions

ROOT = Path(__file__).resolve().parents[2]
OWN = {r for r in RULES if RULES[r].module == "disclosure"}
URL = "https://example.test/"


def run(ctx):
    issues = disclosure.run(ctx)
    for i in issues:
        assert not validate_issue(i), validate_issue(i)
        assert i.host
    return issues


def by_rule(issues, options=None):
    out: dict[str, list] = {}
    for i in issues:
        if options is None or options.reports(i.confidence):
            out.setdefault(i.rule, []).append(i)
    return out


def sev(i):
    return i.severity or RULES[i.rule].severity


@pytest.fixture
def ctx_for(make_response, make_ctx):
    """``ctx_for(body, headers=..., status=..., content_type=..., **ctx fields)``: one entry response (parsed when HTML)."""
    def build(body="", headers=(), status=200, content_type="text/html; charset=utf-8", url=URL, sensitivity="default",
              profile="standard", **fields):
        r = make_response(url, status=status, headers=list(headers), body=body, content_type=content_type,
                          ip="203.0.113.7")
        doc = htmlparse.parse_response(r) if "html" in (content_type or "") and r.body else None
        classify.classify(r, doc)
        pages = [Page(r, doc)] if r.kind == "document" else []
        ctx = make_ctx(target=url, entry=None, sensitivity=sensitivity, profile=profile, pages=pages, **fields)
        ctx.entry = r
        ctx.coverage = coverage.Coverage()
        return ctx
    return build


# =============================================================================================== banners

@pytest.mark.parametrize("value, want", [
    ("Apache/2.4.49 (Unix)", "low"), ("nginx/1.18.0", "low"), ("Microsoft-IIS/10.0", "low"),
    ("Werkzeug/3.0.1 Python/3.12.3", "low"), ("Jetty(9.4.43.v20210629)", "low"), ("gunicorn 21.2.0", "low"),
    ("ECS (dcb/7F84)", None), ("nginx", None), ("cloudflare", None), ("AmazonS3", None),
])
def test_server_version_shapes(ctx_for, value, want):
    got = by_rule(run(ctx_for("<p>x</p>", headers=[("Server", value)])))
    if want is None:
        assert "WEB010" not in got
    else:
        (i,) = got["WEB010"]
        assert sev(i) == want and i.params["value"] == value and i.confidence == "certain"


def test_bare_server_is_info_at_paranoid_only(ctx_for):
    assert "WEB010" not in by_rule(run(ctx_for("<p>x</p>", headers=[("Server", "nginx")])))
    (i,) = by_rule(run(ctx_for("<p>x</p>", headers=[("Server", "nginx")], sensitivity="paranoid")))["WEB010"]
    assert sev(i) == "info"


def test_powered_by_low_with_version_info_without(ctx_for):
    (a,) = by_rule(run(ctx_for("<p>x</p>", headers=[("X-Powered-By", "PHP/7.4.3")])))["WEB011"]
    (b,) = by_rule(run(ctx_for("<p>x</p>", headers=[("X-Powered-By", "Express")])))["WEB011"]
    assert sev(a) == "low" and sev(b) == "info" and a.params["value"] == "PHP/7.4.3"


def test_header_rules_run_on_redirect_hops_and_errors(make_response, make_ctx):
    hop = make_response("https://example.test/", status=301, headers=[("Location", "/home"), ("Server", "nginx/1.25.3")])
    final = make_response("https://example.test/home", status=404, headers=[("X-Powered-By", "PHP/8.2.1")], body=b"no",
                          content_type="text/plain", chain=[hop])
    ctx = make_ctx(entry=final)
    got = by_rule(run(ctx))
    assert got["WEB010"][0].url == "https://example.test/" and got["WEB011"][0].url.endswith("/home")


def test_third_party_and_waf_responses_are_not_judged(make_response, make_ctx):
    third = make_response("https://cdn.other.test/x.js", headers=[("Server", "Apache/2.4.1")], body=b"var a;",
                          content_type="text/javascript", source="subresource")
    waf = make_response("https://example.test/", status=403, headers=[("Server", "Apache/2.4.1")], kind="waf_challenge")
    ctx = make_ctx(entry=waf, subresources=[third])
    ctx.coverage = coverage.Coverage()
    assert run(ctx) == []
    assert ctx.coverage.state("WEB010").state == "inconclusive"


def test_heartbleed_banner_and_backport_markers(ctx_for):
    (i,) = by_rule(run(ctx_for("<p/>", headers=[("Server", "Apache/2.2.22 (Unix) OpenSSL/1.0.1e")])))["WEB615"]
    assert i.confidence == "tentative" and sev(i) == "high"
    for value in ("Apache/2.4.6 (Red Hat Enterprise Linux) OpenSSL/1.0.1e-fips", "Apache/2.2.22 (Ubuntu) OpenSSL/1.0.1",
                  "Apache/2.4.7 OpenSSL/1.0.1g", "nginx OpenSSL/1.0.2k"):
        assert "WEB615" not in by_rule(run(ctx_for("<p/>", headers=[("Server", value)]))), value


# =============================================================================================== leak headers

def test_leak_headers_versioned_low_else_info(ctx_for):
    got = by_rule(run(ctx_for("<p/>", headers=[("X-AspNet-Version", "4.0.30319"), ("X-Drupal-Cache", "HIT"),
                                               ("X-Runtime", "0.012"), ("X-Kong-Upstream-Latency", "3")])))
    sevs = {i.params["header"]: sev(i) for i in got["WEB600"]}
    assert sevs == {"X-AspNet-Version": "low", "X-Drupal-Cache": "info", "X-Runtime": "info",
                    "X-Kong-Upstream-Latency": "info"}


@pytest.mark.parametrize("value, leaks", [
    ("db;dur=53, app;dur=47.2", True), ('cache;desc="redis hit";dur=1', True), ('origin;desc="pg-01.internal"', True),
    ("cdn-cache;desc=HIT, edge;dur=1, total;dur=12", False), ("cfRequestDuration;dur=12.3", False),
])
def test_server_timing(ctx_for, value, leaks):
    got = by_rule(run(ctx_for("<p/>", headers=[("Server-Timing", value)])))
    assert ("WEB600" in got) is leaks


def test_debug_headers_one_finding_with_decoded_chromelogger(ctx_for):
    payload = base64.b64encode(json.dumps({"rows": [["SELECT * FROM users"]]}).encode()).decode()
    got = by_rule(run(ctx_for("<p/>", headers=[("X-Debug-Token", "a1b2c3"), ("X-Debug-Token-Link", "/_profiler/a1b2c3"),
                                               ("X-ChromeLogger-Data", payload), ("X-Laravel-Query-Debug", "1")])))
    (i,) = got["WEB601"]
    assert sev(i) == "medium" and "X-Laravel-Query-Debug" in i.params["header"]
    assert any("SELECT * FROM users" in en for en, _ar in i.notes)


def test_etag_inode(ctx_for):
    assert "WEB604" in by_rule(run(ctx_for("<p/>", headers=[("ETag", '"4a1b2-2c-5c6e8f3a1b2c0"')])))
    assert "WEB604" in by_rule(run(ctx_for("<p/>", headers=[("ETag", 'W/"4a1b2-2c-5c6e8f3a1b2c0-gzip"')])))
    for v in ('"6729f1a0-2c"', '"33a64df551425fcc55e4d42a148795d9f25f89d4"', 'W/"0815"'):
        assert "WEB604" not in by_rule(run(ctx_for("<p/>", headers=[("ETag", v)]))), v


# =============================================================================================== internal IPs

@pytest.mark.parametrize("text, found", [
    ("server at 10.0.0.5 failed", ["10.0.0.5"]),
    ("backend 172.20.1.2:8080 timeout", ["172.20.1.2"]),
    ("redirect http://192.168.1.10/admin", ["192.168.1.10"]),
    ("node ip-10-0-56-78.ec2.internal", ["ip-10-0-56-78"]),
    ("link fe80::1ff:fe23:4567:890a and fd12:3456:789a::1", ["fe80::1ff:fe23:4567:890a", "fd12:3456:789a::1"]),
    ("metadata 169.254.169.254", ["169.254.169.254"]),
    ("Release v10.0.0.1 is out", []), ("version 10.1.2.3", []), ("1.10.0.0.1", []), ("10.0.0.1.2", []),
    ("10.0.0.1-2", []), ("public 8.8.8.8 and 172.32.0.1", []), ("css #fcfcfc", []), ("10.0.0.256", []),
])
def test_internal_ip_vectors(text, found):
    assert [a for a, _s, _e in disclosure.internal_ips(text)] == found


def test_internal_ip_header_firm_body_doc_tentative(ctx_for):
    got = by_rule(run(ctx_for("<p>Our router is at 192.168.0.1</p>", headers=[("Via", "1.1 10.1.2.3 (squid)"),
                                                                              ("X-Forwarded-For", "10.9.9.9")])))
    confs = sorted((i.evidence.match["where"], i.confidence) for i in got["WEB603"])
    assert confs == [("body", "tentative"), ("header", "firm")]
    assert not any("10.9.9.9" in i.group_value for i in got["WEB603"])       # client echo headers are ignored


def test_internal_ip_equal_to_target_is_skipped(ctx_for):
    ctx = ctx_for("<p>at 10.0.0.5</p>", url="https://10.0.0.5/", status=500)
    assert "WEB603" not in by_rule(run(ctx))


def test_internal_ip_error_page_body_is_firm(ctx_for):
    (i,) = by_rule(run(ctx_for("upstream 10.2.3.4:9000 refused", status=502, content_type="text/plain")))["WEB603"]
    assert i.confidence == "firm"


# =============================================================================================== serialized objects

JAVA = base64.b64encode(b"\xac\xed\x00\x05sr\x00\x13java.util.ArrayList").decode()


@pytest.mark.parametrize("value, fmt", [
    (JAVA, "Java"), (urllib.parse.quote(JAVA), "Java"), (b"\xac\xed\x00\x05sr", "Java"),
    ('O:8:"stdClass":1:{s:1:"a";i:1;}', "PHP"), ("a%3A2%3A%7Bi%3A0%3Bs%3A1%3A%22x%22%3B%7D", "PHP"),
    (base64.b64encode(b'a:1:{i:0;s:1:"x";}').decode(), "PHP"), (base64.b64encode(b'O:4:"User":0:{}').decode(), "PHP"),
    ("AAEAAAD/////AQAAAAAAAAAMAgAAAA==", ".NET BinaryFormatter"),
    (base64.b64encode(b"\x80\x04\x95\x10\x00\x00").decode(), "Python pickle"),
    ("YToxNjM0NTY3ODkwYWJjZGVm", None), ("rO0ABnotreallyjava", None), ("eyJhbGciOiJIUzI1NiJ9", None),
    ("hello", None), ("", None),
])
def test_serialized_formats(value, fmt):
    assert disclosure.serialized_format(value) == fmt


def test_serialized_cookie_header_hidden_input(ctx_for):
    html = f'<form><input type="hidden" name="state" value="{JAVA}"></form>'
    got = by_rule(run(ctx_for(html, headers=[("Set-Cookie", f"st={JAVA}; Path=/"), ("X-State", JAVA)])))
    wheres = sorted(i.group_value.split(":")[0] for i in got["WEB610"])
    assert wheres == ["cookie", "header", "hidden"]
    cookie = next(i for i in got["WEB610"] if i.group_value.startswith("cookie"))
    ev = cookie.evidence.to_dict()                                                 # cookie values stay redacted
    assert JAVA not in json.dumps(ev["match"]) and all(JAVA not in v for k, v in ev["headers"] if k == "Set-Cookie")


def test_serialized_uses_cookie_facts_when_present(ctx_for):
    ctx = ctx_for("<p/>")
    ctx.cookies = [CookieFact("s", JAVA, {}, f"s={JAVA}", ctx.entry, "example.test", True),
                   CookieFact("gone", JAVA, {}, f"gone={JAVA}; Max-Age=0", ctx.entry, "example.test", True, deletion=True)]
    (i,) = by_rule(run(ctx))["WEB610"]
    assert i.group_value.startswith("cookie:s:")


# =============================================================================================== error signatures

PY_TB = ('Traceback (most recent call last):\n  File "/srv/app/app.py", line 12, in view\n    x = int(v)\n'
         "ValueError: invalid literal for int()")
JAVA_TB = ("java.lang.IllegalStateException: boom\n\tat com.acme.web.Router.route(Router.java:42)\n"
           "\tat com.acme.web.Servlet.service(Servlet.java:17)\n")


def test_stack_trace_on_500_is_firm(ctx_for):
    (i,) = by_rule(run(ctx_for(f"<html><body><pre>{PY_TB}</pre></body></html>", status=500)))["WEB056"]
    assert i.confidence == "firm" and i.evidence.match["name"] == "Python"


def test_stack_trace_in_pre_on_200_doc_is_tentative_d16(ctx_for):
    issues = run(ctx_for(f"<h1>Reading errors</h1><pre><code>{PY_TB}</code></pre>"))
    (i,) = by_rule(issues)["WEB056"]
    assert i.confidence == "tentative" and any("documentation" in en for en, _ in i.notes)
    assert "WEB056" not in by_rule(issues, ScanOptions())


def test_stack_trace_outside_pre_on_200_is_firm(ctx_for):
    (i,) = by_rule(run(ctx_for(f"<div>{JAVA_TB}</div>")))["WEB056"]
    assert i.confidence == "firm"


@pytest.mark.parametrize("body", [
    'Error\n    at Object.<anonymous> (/srv/app/index.js:3:9)\n    at Module._compile (node:internal/modules/cjs/loader:1256:14)',
    "goroutine 1 [running]:\nmain.main()\n\t/app/main.go:12 +0x1d\npanic: boom",
    "<b>Fatal error</b>:  Uncaught Error: x in /var/www/a.php:3 Stack trace: #0 {main} thrown in <b>/var/www/a.php</b> "
    "on line <b>3</b>",
    "app/models/user.rb:12:in `save'\nNoMethodError: undefined method",
    "   at Acme.Web.Home.Index() in C:\\src\\Home.cs:line 42\n   at lambda_method(Closure , Object )\n--- End of stack trace",
    "   at Acme.Web.A.B(String s)\n   at Acme.Web.A.C()\n--- End of stack trace from previous location ---",
])
def test_stack_trace_platforms(ctx_for, body):
    assert "WEB056" in by_rule(run(ctx_for(body, status=500, content_type="text/plain")))


def test_no_stack_trace_in_ordinary_text(ctx_for):
    body = "<p>We were at home (at the office) and the error was fixed. Traceback is a word.</p>"
    assert not by_rule(run(ctx_for(body, status=500)))


def test_werkzeug_debugger_is_critical_and_absorbs_the_trace(ctx_for):
    body = ('<title>ValueError // Werkzeug Debugger</title><div class="debugger"><h3>Traceback <em>(most recent call last)'
            '</em></h3><h4>File <cite class="filename">"/srv/app/app.py"</cite>, line <em class="line">12</em></h4></div>'
            '<script src="?__debugger__=yes&amp;cmd=resource&amp;f=debugger.js"></script>')
    got = by_rule(run(ctx_for(body, status=500)))
    (i,) = got["WEB605"]
    assert sev(i) == "critical" and i.confidence == "certain" and "WEB056" not in got


def test_django_debug_404_is_high(ctx_for):
    body = ("<h1>Page not found</h1><p>Using the URLconf defined in <code>mysite.urls</code>, Django tried these URL "
            "patterns.</p><p>You’re seeing this error because you have <code>DEBUG = True</code> in your settings.</p>")
    (i,) = by_rule(run(ctx_for(body, status=404)))["WEB605"]
    assert sev(i) == "high"


def test_debug_phrase_quoted_in_docs_is_not_debug_mode(ctx_for):
    body = ("<p>Django says:</p><pre>You're seeing this error because you have DEBUG = True in your Django settings "
            "file. Django tried these URL patterns</pre>")
    assert "WEB605" not in by_rule(run(ctx_for(body)))


def test_database_errors(ctx_for):
    for body in ("SQLSTATE[42000]: Syntax error", "ORA-00933: SQL command not properly ended",
                 "You have an error in your SQL syntax; check the manual", "PG::UndefinedTable: ERROR",
                 "Unclosed quotation mark after the character string ''.", "sqlite3.OperationalError: no such table"):
        assert "WEB606" in by_rule(run(ctx_for(f"<p>{body}</p>", status=500))), body
    assert "WEB606" not in by_rule(run(ctx_for("<p>Fix</p><code>SQLSTATE[42000]</code>"))), "guarded docs"
    assert "WEB606" not in by_rule(run(ctx_for("<p>ORA-1234 flight and SQL tutorial</p>", status=500)))


def test_paths_only_on_error_responses(ctx_for):
    body = "<b>Warning</b>: include(x): failed in <b>/var/www/html/index.php</b> on line <b>12</b>"
    (i,) = by_rule(run(ctx_for(body, status=500, sensitivity="paranoid")))["WEB607"]
    assert i.confidence == "tentative"
    assert "WEB607" not in by_rule(run(ctx_for(body, status=200, sensitivity="paranoid")))
    assert "WEB607" not in by_rule(run(ctx_for('<a href="/home/about/team.html">x</a> Error 404', status=404)))
    assert "WEB607" in by_rule(run(ctx_for(r"Exception at C:\inetpub\wwwroot\app\web.config", status=500,
                                           content_type="text/plain")))


def test_banner_on_error_page(ctx_for):
    body = "<html><body><h1>404 Not Found</h1><hr><center>nginx/1.18.0</center></body></html>"
    (i,) = by_rule(run(ctx_for(body, status=404)))["WEB616"]
    assert i.confidence == "certain" and sev(i) == "low"
    assert "WEB616" not in by_rule(run(ctx_for("<p>We run nginx/1.18.0</p>")))


def test_default_pages_and_parking(ctx_for):
    (i,) = by_rule(run(ctx_for("<title>Welcome to nginx!</title><p>If you see this page, the nginx web server is "
                               "successfully installed</p>")))["WEB617"]
    assert sev(i) == "low"
    (p,) = by_rule(run(ctx_for('<script src="//img.sedoparking.com/js/park.js"></script>')))["WEB617"]
    assert sev(p) == "info"
    assert "WEB617" not in by_rule(run(ctx_for("<title>Welcome to nginx!</title>", status=404)))


def test_identical_error_on_many_responses_is_one_finding(make_response, make_ctx):
    body = f"<html><body><pre>{JAVA_TB}</pre></body></html>"
    entry = make_response(URL, status=500, body=body, content_type="text/html")
    probes = [make_response(URL + p, status=500, body=body, content_type="text/html", source="probe")
              for p in (".env", ".git/HEAD", "backup.zip")]
    base = make_response(URL + "kashif-404-0123456789abcdef", status=500, body=body, content_type="text/html",
                         source="baseline")
    ctx = make_ctx(entry=entry, probes=probes, baselines=[base], profile="deep")
    (i,) = by_rule(run(ctx))["WEB056"]
    assert i.url == URL and any("not-found page" in en for en, _ in i.notes)


def test_binary_and_opaque_bodies_are_skipped(ctx_for, make_response, make_ctx):
    assert disclosure.is_binary(b"\x89PNG\r\n\x1a\n" + b"x" * 100)
    assert disclosure.is_binary(b"abc\x00def")
    assert not disclosure.is_binary("Traceback (most recent call last)\n\t\x1b[31m".encode())
    ctx = ctx_for(b"\x00\x01\x02" + PY_TB.encode(), status=500, content_type="application/octet-stream")
    assert "WEB056" not in by_rule(run(ctx))
    r = make_response(URL, body=b"", headers=[("Content-Encoding", "br"), ("Server", "Apache/2.4.49")],
                      content_type="text/html", encoding="br", flags=frozenset({"opaque-coding"}), kind="document")
    ctx = make_ctx(entry=Page(r, None))
    ctx.coverage = coverage.Coverage()
    got = by_rule(run(ctx))
    assert "WEB010" in got and ctx.coverage.state("WEB056").state == "not_tested"
    assert ctx.coverage.state("WEB056").reasons[0][0] == "unsupported_coding"


def test_js_and_css_bodies_only_at_paranoid(make_response, make_page, make_ctx):
    js = make_response(URL + "app.js", body=f"// {JAVA_TB}".encode(), content_type="text/javascript",
                       source="subresource")
    for sens, want in (("default", False), ("paranoid", True)):
        ctx = make_ctx(entry=make_page("<p>x</p>"), subresources=[js], sensitivity=sens)
        assert ("WEB056" in by_rule(run(ctx))) is want


# =============================================================================================== listings

NGINX_INDEX = ('<html><head><title>Index of /files/</title></head><body><h1>Index of /files/</h1><hr><pre>'
               '<a href="../">../</a>\n<a href="backup/">backup/</a>\n<a href="report.pdf">report.pdf</a></pre></body></html>')


@pytest.mark.parametrize("html, platform", [
    (NGINX_INDEX, "nginx"),
    ('<title>Index of /x</title><h1>Index of /x</h1><a href="?C=N;O=D">Name</a><a href="/">Parent Directory</a>'
     '<a href="a.txt">a.txt</a>', "Apache httpd"),
    ('<title>h - /files/</title><pre><A HREF="/">[To Parent Directory]</A><br><A HREF="/files/a.pdf">a.pdf</A></pre>',
     "Microsoft IIS"),
    ('<title>Directory listing for /</title><h1>Directory listing for /</h1><ul><li><a href="a.py">a.py</a></li></ul>',
     "Python http.server"),
    ('<title>listing directory /</title><ul id="files"><li><a href="/a">a</a></li></ul>', "Express serve-index"),
    ("<title>Index of /blog</title><h1>Index of /blog posts</h1><p>An essay.</p>", None),
    ('<title>Index of /blog</title><h1>Index of /blog</h1><a href="/about">About</a>', None),
])
def test_listing_signatures(html, platform):
    assert disclosure.listing_platform(html) == platform


def test_listing_grouped_by_platform(make_page, make_ctx):
    a = make_page(NGINX_INDEX, url=URL + "files/")
    b = make_page(NGINX_INDEX.replace("/files/", "/img/"), url=URL + "img/", source="crawl")
    got = by_rule(run(make_ctx(entry=a, pages=[b])))["WEB055"]
    assert len(got) == 2 and {i.group_value for i in got} == {"nginx"}


# =============================================================================================== source code

def test_source_code_raw_vs_escaped(ctx_for):
    assert "WEB608" in by_rule(run(ctx_for("<body><?php $a = 1; echo $a; ?></body>")))
    assert "WEB608" not in by_rule(run(ctx_for("<p>&lt;?php echo $x; ?&gt;</p>")))
    assert "WEB608" not in by_rule(run(ctx_for("<pre><?php echo $x; ?></pre>", status=500)))
    assert "WEB608" in by_rule(run(ctx_for('<%@ Page Language="C#" %>', content_type="text/plain")))
    assert "WEB608" not in by_rule(run(ctx_for("<?php echo 1;", url=URL + "docs/a.txt", content_type="text/plain")))


def test_source_code_not_in_scripts(make_response, make_page, make_ctx):
    js = make_response(URL + "editor.js", body=b'var tpl = "<?php echo $x; ?>";', content_type="text/javascript",
                       source="subresource")
    assert "WEB608" not in by_rule(run(make_ctx(entry=make_page("<p/>"), subresources=[js], sensitivity="paranoid")))


# =============================================================================================== ViewState

def _vs(payload: bytes) -> str:
    return base64.b64encode(payload).decode()


def test_viewstate_mac_heuristic():
    body = b"\xff\x01\x0f\x0f\x05\x0b\x0a\x07\x0b0123456789abcdefghij"
    assert disclosure.viewstate_mac(body + b"dd" * 30) == "none"
    assert disclosure.viewstate_mac(body + b"dd" + bytes(range(20))) == "mac"
    assert disclosure.viewstate_mac(body + b"dd" + bytes(range(100, 132))) == "mac"
    assert disclosure.viewstate_mac(bytes(range(64))) == "unknown"


def test_viewstate_tentative_unless_old_aspnet(ctx_for):
    nomac = _vs(b"\xff\x01" + b"x" * 30 + b"dd")
    html = f'<form><input type="hidden" name="__VIEWSTATE" value="{nomac}"></form>'
    (i,) = by_rule(run(ctx_for(html)))["WEB611"]
    assert (sev(i), i.confidence) == ("medium", "tentative")
    (j,) = by_rule(run(ctx_for(html, headers=[("X-AspNet-Version", "2.0.50727")])))["WEB611"]
    assert j.confidence == "firm"
    (k,) = by_rule(run(ctx_for(html, headers=[("X-AspNet-Version", "4.0.30319")])))["WEB611"]
    assert k.confidence == "tentative"
    withmac = _vs(b"\xff\x01" + b"x" * 30 + b"dd" + bytes(range(20)))
    mac = f'<input type="hidden" name="__VIEWSTATE" value="{withmac}">'
    assert "WEB611" not in by_rule(run(ctx_for(mac)))
    enc = html + '<input type="hidden" name="__VIEWSTATEENCRYPTED" value="">'
    assert "WEB611" not in by_rule(run(ctx_for(enc)))


def test_split_viewstate(ctx_for):
    v = _vs(b"\xff\x01" + b"y" * 40 + b"dd")
    html = (f'<input type="hidden" name="__VIEWSTATEFIELDCOUNT" value="2"><input type="hidden" name="__VIEWSTATE" '
            f'value="{v[:20]}"><input type="hidden" name="__VIEWSTATE1" value="{v[20:]}">')
    assert "WEB611" in by_rule(run(ctx_for(html)))


def test_jsf_viewstate(ctx_for):
    state = base64.b64encode(gzip.compress(b"\xac\xed\x00\x05ur\x00\x13[Ljava.lang.Object;\x90\xceX\x9f")).decode()
    html = f'<input type="hidden" name="javax.faces.ViewState" id="j_id1:javax.faces.ViewState:0" value="{state}">'
    (i,) = by_rule(run(ctx_for(html)))["WEB611"]
    assert (sev(i), i.confidence) == ("high", "firm") and "java.lang.Object" in i.evidence.match["value"]
    server = '<input type="hidden" name="javax.faces.ViewState" value="-4573498573:8734598734">'
    assert "WEB611" not in by_rule(run(ctx_for(server)))


# =============================================================================================== hashes, cards, comments

BCRYPT = "$2y$10$" + "N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"


@pytest.mark.parametrize("text, kind", [
    (BCRYPT, "bcrypt"), ("$1$saltsalt$qjXMvbEw8oaL.CzflDugX/", "MD5-crypt"),
    ("$6$rounds=5000$usesomesillystri$D4IrlXatmP7rx3P3InaxBeoomnAihCKRVQP22JZ6EY47Wc6BkroIuUUBOov1i.S5KPgErtP/EN5mcO.ChWQW21",
     "SHA-512-crypt"),
    ("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG", "Argon2"),
    ("pbkdf2_sha256$600000$abcdefgh12345678$" + "A" * 43 + "=", "Django PBKDF2"),
])
def test_password_hash_vectors(text, kind):
    assert [k for k, *_ in disclosure.password_hashes(f'"{text}"')] == [kind]


@pytest.mark.parametrize("text", ["price $1$ and $2$", "3f2a1c9e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39",
                                  "$2y$10$short", "d41d8cd98f00b204e9800998ecf8427e"])
def test_not_password_hashes(text):
    assert disclosure.password_hashes(text) == []


def test_hash_in_json_is_redacted(ctx_for):
    (i,) = by_rule(run(ctx_for('{"password_hash": "' + BCRYPT + '"}', content_type="application/json")))["WEB612"]
    assert BCRYPT not in json.dumps(i.evidence.to_dict()) and BCRYPT not in i.group_value


@pytest.mark.parametrize("text, brand", [
    ("Card 4539 1488 0343 6467 ok", "Visa"), ("card 5555-5555-5555-4444", "Mastercard"),
    ("amex 378282246310005 here", "American Express"), ("visa 4539148803436467,", "Visa"),
    ("total 4539148803436468", None), ("phone +14539148803436467", None), ("v1.4539148803436467", None),
    ("id_4539148803436467", None), ("1e4539148803436467", None), ("4539 14 88 0343 6467", None),
    ("1234567890123456", None),
])
def test_card_vectors(text, brand):
    got = disclosure.card_numbers(text)
    assert ([b for b, *_ in got] or [None]) == [brand]


def test_cards_visible_text_only_and_test_numbers_info(ctx_for):
    issues = run(ctx_for('<p>Use 4111 1111 1111 1111.</p><input data-x="4539148803436467">'
                         "<style>.c{width:4539148803436467px}</style>"))
    (i,) = by_rule(issues)["WEB613"]
    assert sev(i) == "info" and "4111111111111111" not in json.dumps(i.evidence.to_dict())
    (j,) = by_rule(run(ctx_for("<script>var c = '4539148803436467';</script>")))["WEB613"]
    assert sev(j) == "medium" and j.evidence.match["value"] == "************6467"


def test_sensitive_comments_paranoid_only(ctx_for):
    html = "<!-- TODO: remove auth bypass before release --><!-- db host: db1.corp --><!-- layout v2 -->"
    assert "WEB614" not in by_rule(run(ctx_for(html)))
    ctx = ctx_for(html, sensitivity="paranoid")
    got = by_rule(run(ctx))["WEB614"]
    assert len(got) == 2 and all(i.confidence == "tentative" for i in got)
    ctx = ctx_for("<!-- password=hunter2secret -->", sensitivity="paranoid")
    (i,) = by_rule(run(ctx))["WEB614"]
    assert "hunter2secret" not in json.dumps(i.evidence.to_dict())


def test_comments_not_tested_below_paranoid(ctx_for):
    ctx = ctx_for("<p/>")
    run(ctx)
    st = ctx.coverage.state("WEB614")
    assert st.state == "not_tested" and st.reasons[0][0] == "sensitivity"


# =============================================================================================== secrets

SK = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc" + "Kq9Z"
PEM_BODY = "\n".join(base64.b64encode(hashlib.sha512(str(i).encode()).digest()).decode() for i in range(6))
PEM = "-----BEGIN " + "PRIVATE KEY-----\n" + PEM_BODY + "\n-----END " + "PRIVATE KEY-----"


def _secret_ctx(ctx_for, make_response, js=None, html="<p/>", **kw):
    subs = []
    if js is not None:
        subs.append(make_response(URL + "static/app.js", body=js, content_type="text/javascript", source="subresource"))
    return ctx_for(html, subresources=subs, **kw)


def _no_raw_secret(issues, secret):
    dump = json.dumps([{"ev": i.evidence.to_dict(), "gv": i.group_value, "notes": i.notes, "params": i.params}
                       for i in issues], ensure_ascii=False)
    assert secret not in dump


def test_stripe_secret_inline_high_and_redacted(ctx_for, make_response):
    issues = run(_secret_ctx(ctx_for, make_response, html=f'<script>var s = "{SK}";</script>'))
    (i,) = by_rule(issues)["WEB609"]
    assert (sev(i), i.confidence) == ("high", "firm") and i.evidence.match["value"] == SK[:4] + "…" + SK[-2:]
    _no_raw_secret(issues, SK)


def test_pem_private_key_is_critical_certain(ctx_for, make_response):
    issues = run(_secret_ctx(ctx_for, make_response, js="window.cfg = {key: `" + PEM + "`};"))
    (i,) = by_rule(issues)["WEB609"]
    assert (sev(i), i.confidence) == ("critical", "certain")
    _no_raw_secret(issues, PEM_BODY.split("\n")[0])
    escaped = "var k = '-----BEGIN PRIVATE KEY-----\\n" + PEM_BODY.replace("\n", "\\n") + "\\n-----END PRIVATE KEY-----';"
    assert "WEB609" in by_rule(run(_secret_ctx(ctx_for, make_response, js=escaped)))


def test_pem_header_constant_in_a_library_is_not_a_key(ctx_for, make_response):
    js = ('if (pem.indexOf("-----BEGIN PRIVATE KEY-----") === 0) { body = pem.split("-----END PRIVATE KEY-----"); }\n'
          "var re = /-----BEGIN RSA PRIVATE KEY-----([A-Za-z0-9+\\/=\\s]+)-----END RSA PRIVATE KEY-----/;")
    assert "WEB609" not in by_rule(run(_secret_ctx(ctx_for, make_response, js=js)))


@pytest.mark.parametrize("js, rule_sev", [
    ('const pk = "' + "pk_" + "live_51HkashifCorpusPublishableKey0Xy" + '";', None),
    ('firebase.initializeApp({apiKey: "AIza' + 'SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY", authDomain: "x.firebaseapp.com"});', None),
    ('maps.load("AIza' + 'SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY");', ("low", "tentative")),
    ('var t = "ghp_' + "Xx" * 18 + '";', None),                           # repeated pattern: placeholder
    ('var t = "ghp_' + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6" + '";', ("high", "firm")),
    ('db = "postgres://app:' + 'S3cr3tPassw0rd' + '@db.internal:5432/app";', ("critical", "firm")),
    ('db = "postgres://user:password@localhost/app";', None),
    ('var k = "AKIAIOSFODNN7EXAMPLE", s = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";', None),
    ('var k = "AKIA' + "QWERTYUIOPASDFGH" + '", s = "' + "u3Rk9fZ2pQ8vX1mN5bC7hJ0kL4tY6wE2rA9sD3fG" + '";', ("high", "firm")),
    ('twilio("AC' + "0123456789abcdef" * 2 + '")', None),
    ('var x = "sk_test_' + "4eC39HqLyjWDarjtT1zdp7dc" + '";', None),
])
def test_secret_vectors(ctx_for, make_response, js, rule_sev):
    got = by_rule(run(_secret_ctx(ctx_for, make_response, js=js)))
    if rule_sev is None:
        assert "WEB609" not in got, got.get("WEB609")
    else:
        (i,) = got["WEB609"]
        assert (sev(i), i.confidence) == rule_sev


def test_secret_in_data_attribute_and_json(ctx_for, make_response):
    html = f'<div data-config="{{&quot;key&quot;: &quot;{SK}&quot;}}"></div>'
    assert "WEB609" in by_rule(run(ctx_for(html)))
    assert "WEB609" in by_rule(run(ctx_for(f'{{"stripe": "{SK}"}}', content_type="application/json")))
    assert "WEB609" not in by_rule(run(ctx_for(f"<p>{SK}</p>"))), "visible text is not client-side code"


def test_same_secret_on_two_pages_is_one_finding(make_page, make_ctx):
    a = make_page(f'<script>var s="{SK}";</script>')
    b = make_page(f'<script>var s="{SK}";</script>', url=URL + "b", source="crawl")
    assert len(by_rule(run(make_ctx(entry=a, pages=[b])))["WEB609"]) == 1


def test_third_party_script_secret(make_page, make_response, make_ctx):
    js = make_response("https://cdn.other.test/w.js", body=f'var s="{SK}";'.encode(), content_type="text/javascript",
                       source="subresource")
    (i,) = by_rule(run(make_ctx(entry=make_page("<p/>"), subresources=[js], profile="deep")))["WEB609"]
    assert i.url == "https://cdn.other.test/w.js" and i.host == "example.test"


# =============================================================================================== source maps

def test_sourcemap_referenced_only_is_info(make_page, make_response, make_ctx):
    js = make_response(URL + "app.min.js", body=b"window.a=1;\n//# sourceMappingURL=app.min.js.map\n",
                       content_type="text/javascript", source="subresource")
    hdr = make_response(URL + "b.js", headers=[("SourceMap", "/b.js.map")], body=b"window.b=1;",
                        content_type="text/javascript", source="subresource")
    got = by_rule(run(make_ctx(entry=make_page("<p/>"), subresources=[js, hdr])))["WEB602"]
    assert {sev(i) for i in got} == {"info"} and {i.group_value for i in got} == {"referenced"} and len(got) == 2


def test_sourcemap_fetched_low_and_sources_content_scanned(make_page, make_response, make_ctx):
    js = make_response(URL + "app.min.js", body=b"window.a=1;\n//# sourceMappingURL=app.min.js.map",
                       content_type="text/javascript", source="subresource")
    m = {"version": 3, "sources": ["src/a.ts", "src/b.ts"], "sourcesContent": ["export const a = 1;",
                                                                                f'const key = "{SK}";'], "mappings": ""}
    smap = make_response(URL + "app.min.js.map", body=json.dumps(m).encode(), content_type="application/json",
                         source="sourcemap")
    issues = run(make_ctx(entry=make_page("<p/>"), subresources=[js], sourcemaps=[smap], profile="deep"))
    got = by_rule(issues)
    (i,) = got["WEB602"]
    assert sev(i) == "low" and any("2 original source files" in en for en, _ in i.notes)
    (s,) = got["WEB609"]
    assert "src/b.ts" in s.evidence.match["name"]
    _no_raw_secret(issues, SK)


def test_sourcemap_fetched_404_or_html_is_not_exposed(make_page, make_response, make_ctx):
    js = make_response(URL + "app.js", body=b"//# sourceMappingURL=app.js.map", content_type="text/javascript",
                       source="subresource")
    for smap in (make_response(URL + "app.js.map", status=404, body=b"nope", content_type="text/plain", source="sourcemap"),
                 make_response(URL + "app.js.map", body=b"<html>home</html>", content_type="text/html",
                               source="sourcemap")):
        assert "WEB602" not in by_rule(run(make_ctx(entry=make_page("<p/>"), subresources=[js], sourcemaps=[smap])))


def test_inline_sourcemap(make_page, make_response, make_ctx):
    m = base64.b64encode(json.dumps({"version": 3, "sources": ["a.ts"], "mappings": ""}).encode()).decode()
    js = make_response(URL + "app.js", body=f"x;\n//# sourceMappingURL=data:application/json;base64,{m}".encode(),
                       content_type="text/javascript", source="subresource")
    (i,) = by_rule(run(make_ctx(entry=make_page("<p/>"), subresources=[js])))["WEB602"]
    assert sev(i) == "low" and i.group_value == "inline"


# =============================================================================================== EXIF

def _jpeg_with_gps(lat=(31, 1), lon=(34, 1), little=True) -> bytes:
    e = "<" if little else ">"
    tiff = bytearray((b"II" if little else b"MM") + struct.pack(e + "HI", 42, 8))
    # IFD0: one entry (GPS pointer) at offset 8 → GPS IFD at 26
    gps_off = 8 + 2 + 12 + 4
    tiff += struct.pack(e + "H", 1) + struct.pack(e + "HHII", 0x8825, 4, 1, gps_off) + struct.pack(e + "I", 0)
    data_off = gps_off + 2 + 2 * 12 + 4
    tiff += struct.pack(e + "H", 2)
    tiff += struct.pack(e + "HHII", 2, 5, 3, data_off) + struct.pack(e + "HHII", 4, 5, 3, data_off + 24)
    tiff += struct.pack(e + "I", 0)
    for deg, den in (lat, lon):
        tiff += struct.pack(e + "IIIIII", deg, den, 0, 1, 0, 1)
    app1 = b"Exif\x00\x00" + bytes(tiff)
    return b"\xff\xd8" + b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1 + b"\xff\xda\x00\x02" + b"\x00" * 16


def test_exif_gps_parser():
    assert disclosure.exif_gps(_jpeg_with_gps())
    assert disclosure.exif_gps(_jpeg_with_gps(little=False))
    assert not disclosure.exif_gps(_jpeg_with_gps(lat=(0, 1), lon=(0, 1)))
    assert not disclosure.exif_gps(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9")
    assert not disclosure.exif_gps(b"not a jpeg")
    assert not disclosure.exif_gps(_jpeg_with_gps()[:40])                 # truncated: no crash


def test_exif_gps_rule_and_coverage(make_page, make_response, make_ctx):
    img = make_response(URL + "a.jpg", body=_jpeg_with_gps(), content_type="image/jpeg", source="image")
    ctx = make_ctx(entry=make_page("<p/>"), images=[img], profile="deep")
    (i,) = by_rule(run(ctx))["WEB619"]
    assert i.confidence == "certain" and i.url.endswith("a.jpg")
    ctx = make_ctx(entry=make_page("<p/>"))
    ctx.coverage = coverage.Coverage()
    run(ctx)
    assert ctx.coverage.state("WEB619").state == "not_tested"


# =============================================================================================== coverage, data, misc

def test_coverage_states(ctx_for):
    ctx = ctx_for("<p>fine</p>", headers=[("Server", "Apache/2.4.49")])
    run(ctx)
    assert ctx.coverage.state("WEB010").state == "fail"
    assert ctx.coverage.state("WEB011").state == "pass"
    assert ctx.coverage.state("WEB056").state == "pass"
    assert set(disclosure.CHECKS) == OWN


def test_missing_data_is_not_tested(ctx_for):
    class NoData:
        def load_json(self, name):
            raise FileNotFoundError(name)
    ctx = ctx_for("<p/>", data=NoData())
    run(ctx)
    for check in ("WEB056", "WEB600", "WEB609"):
        st = ctx.coverage.state(check)
        assert st.state == "not_tested" and st.reasons[0][0] == "data_missing", check


def test_hostile_values_are_stripped(ctx_for):
    evil = '<script>alert(1)</script>\x1b[31mApache/2.4.1\x1b[0m'
    (i,) = by_rule(run(ctx_for("<p/>", headers=[("Server", evil)])))["WEB010"]
    assert "\x1b" not in i.params["value"] and "\x1b" not in json.dumps(i.evidence.to_dict())


@pytest.mark.parametrize("name", ["error-signatures.json", "leak-headers.json", "secret-rules.json"])
def test_data_files_validate(name):
    obj = data.load_json(name)
    assert data.validate_data(name, obj) == []


def test_every_signature_compiles_and_has_a_known_rule():
    sigs = [disclosure.compile_signature(e) for e in data.load_json("error-signatures.json")["signatures"]]
    assert len({s.id for s in sigs}) == len(sigs)
    assert {s.rule for s in sigs} == {"WEB056", "WEB605", "WEB606", "WEB607", "WEB616", "WEB617"}
    assert all(s.debug_marker for s in sigs if s.rule == "WEB605")


def test_secret_rules_subset_exists_in_history():
    from vulnscan import history
    ids = {r.id for r in history.secret_rules()}
    wanted = set(data.load_json("secret-rules.json")["sec_rules"])
    assert wanted <= ids and not wanted & {"SEC002", "SEC004", "SEC005", "SEC011"}


def test_generator_is_deterministic():
    proc = subprocess.run([sys.executable, str(ROOT / "tools" / "webdata" / "errors.py"), "--check"],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr


def test_i18n_catalog_has_every_note():
    catalog, patterns = disclosure.i18n_catalog()
    assert catalog or patterns
    en, ar = disclosure._note("listing", platform="nginx")
    import re
    assert any(re.match(rx, ar) and re.sub(rx, repl, ar) == en for rx, repl in patterns)
    assert catalog[disclosure.STR["console"][1]] == disclosure.STR["console"][0]


def test_runs_fast_on_large_inputs(make_page, make_response, make_ctx):
    html = "<html><body>" + "<div><p>Lorem ipsum 10.0.0.1x dolor</p><a href='/x'>x</a></div>" * 20000 + "</body></html>"
    js = make_response(URL + "big.js", body=b"var a=function(b){return b+1};SK;AC;" * 80000,
                       content_type="text/javascript", source="subresource")
    ctx = make_ctx(entry=make_page(html), subresources=[js])
    t = time.perf_counter()
    run(ctx)
    assert time.perf_counter() - t < 3.0


HOSTILE = [
    "<?php" * 150000, "<title>" * 100000, "<h1>Index of /" * 50000, "<style>" * 100000, "<pre>" * 100000,
    "at " + "a." * 200000, "at " + "a " * 300000, "Traceback (most recent call last)" + " File \"x" * 30000,
    "4" * 500000, "4111 " * 100000, "10.0.0." * 100000, "fc00:" * 100000, "$2y$10$" * 100000,
    "-----BEGIN PRIVATE KEY-----" * 30000, "AKIA" + "A" * 16 + " " * 500000, "mysql://a:" * 50000,
    "<input type=hidden name=__VIEWSTATE value=/w" + "A" * 100000 + ">",
]


@pytest.mark.parametrize("n", range(len(HOSTILE)))
def test_hostile_bodies_are_fast(make_response, make_ctx, n):
    body = HOSTILE[n][:250_000].encode()        # big enough that a quadratic pattern would take minutes
    pages = [Page(make_response(URL, status=500, body=body, content_type="text/html"), None)]
    js = make_response(URL + "x.js", body=body, content_type="text/javascript", source="subresource")
    ctx = make_ctx(entry=pages[0], subresources=[js], sensitivity="paranoid")
    t = time.perf_counter()
    disclosure.run(ctx)
    assert time.perf_counter() - t < 4.0


@pytest.mark.parametrize("seed", range(25))
def test_random_bytes_never_crash(make_response, make_ctx, seed):
    import random
    rnd = random.Random(seed)
    body = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 4000)))
    hdrs = [("Server", body[:40].decode("latin-1")), ("ETag", body[40:60].decode("latin-1")),
            ("Set-Cookie", "a=" + base64.b64encode(body[:30]).decode()), ("SourceMap", "data:,%" + body[:5].hex())]
    ctype = rnd.choice(["text/html", "application/json", "text/plain", "text/javascript", "image/jpeg", ""])
    r = make_response(URL, status=rnd.choice([200, 404, 500]), headers=hdrs, body=b"\xff\xd8" + body if ctype ==
                      "image/jpeg" else body, content_type=ctype or None)
    ctx = make_ctx(entry=r, subresources=[r], sourcemaps=[r], images=[r], profile="deep", sensitivity="paranoid")
    run(ctx)


# =============================================================================================== corpus (offline)

sys.path.insert(0, str(ROOT / "bench" / "web"))
try:
    corpus = importlib.import_module("corpus")
except Exception:                                     # pragma: no cover - bench/ absent in a trimmed checkout
    corpus = None
CORPUS_CASES = [c for c in corpus.CASES if set(c.labels) & OWN] if corpus else []
_DEEP_PROBES = ("/.env", "/.git/HEAD", "/backup.zip")
_SCRIPT_SRC = __import__("re").compile(r"""<(?:script|link)\b[^>]*(?:src|href)\s*=\s*["']([^"']+)["']""", 2)


class _Sim:
    """Renders one corpus case in-process the way the engine would fetch it (no sockets): the entry chain with a
    cookie jar, the cookieless CORS GET, the well-known files, the same-site scripts/styles the entry references, and
    in the deep profile three probe paths, a soft-404 baseline and the referenced source maps."""

    def __init__(self, case):
        self.case = case
        self.srv = corpus.CorpusServer([case], mode="host", with_tls=False)
        self.srv.http_port, self.srv.https_port = 8080, 8443
        self.hosts = {h.lower(): a for h, a in case.all_hosts().items()}

    def url(self, path: str) -> str:
        return f"{self.case.scheme}://{self.case.host}:{self.srv.port_for(self.case, self.case.scheme)}{path}"

    def get(self, url: str, *, jar: dict | None, source: str = "entry", origin: str | None = None) -> Response:
        hops: list[Response] = []
        for _ in range(10):
            p = urllib.parse.urlsplit(url)
            alias = self.hosts.get((p.hostname or "").lower())
            if alias is None:
                break
            req_headers = [("User-Agent", "Kashif-test"), ("Accept", "*/*")]
            if origin:
                req_headers.append(("Origin", origin))
            hdrs = {k.lower(): [v] for k, v in req_headers}
            hits, case_hits = self.srv.count(self.case.id, alias, p.path or "/")
            req = corpus.Req(self.case, alias, p.path or "/", p.query, hdrs, p.scheme, hits, case_hits, self.srv, p.netloc)
            r = self.srv.respond(req)
            per: dict = {}
            hl = [(n, corpus._render(v, req, per) if isinstance(v, str) else v.decode("latin-1")) for n, v in r.headers]
            body = r.body if isinstance(r.body, bytes) else corpus._render(r.body, req, per).encode("utf-8")
            headers = HeaderList(tuple(hl))
            enc = (headers.first("content-encoding") or "").strip().lower() or None
            flags = frozenset()
            if enc and enc not in ("gzip", "x-gzip", "deflate", "identity"):
                body, flags = b"", frozenset({"opaque-coding"})          # http.py keeps unrequested codings opaque
            resp = Response(url=url, status=r.status, headers=headers, body=body, encoding=enc, flags=flags,
                            request_headers=HeaderList(tuple(req_headers)), source=source, ip="127.0.0.1")
            if jar is not None:
                for v in resp.headers.get_all("set-cookie"):
                    k, _, rest = v.partition("=")
                    jar[k.strip()] = rest.split(";", 1)[0]
            loc = resp.location
            if resp.status and 300 <= resp.status < 400 and loc:
                hops.append(resp)
                url = loc
                continue
            resp.chain = hops
            return resp
        last = hops.pop() if hops else Response(url=url, status=None, error="unroutable")
        last.chain = hops
        return last

    def context(self, make_ctx) -> ScanContext:
        c = self.case
        entry = self.get(self.url(c.path), jar={})
        kw: dict = {}
        if c.profile != "minimal":
            kw["cors"] = self.get(entry.url, jar=None, origin=corpus.CORS_PROBE_ORIGIN, source="cors")
            kw["wellknown"] = {p: self.get(self.url(p), jar=None, source="wellknown")
                               for p in ("/robots.txt", "/.well-known/security.txt", "/favicon.ico")}
            subs = []
            if entry.body and entry.status == 200:
                for ref in _SCRIPT_SRC.findall(entry.text()):
                    u = urllib.parse.urljoin(entry.url, ref)
                    if urllib.parse.urlsplit(u).hostname == c.host:
                        subs.append(self.get(u, jar=None, source="subresource"))
            kw["subresources"] = subs
            if c.profile == "deep":
                kw["probes"] = [self.get(self.url(p), jar=None, source="probe") for p in _DEEP_PROBES]
                kw["baselines"] = [self.get(self.url("/kashif-404-0123456789abcdef"), jar=None, source="baseline")]
                maps = []
                for s in subs:
                    ref = disclosure.sourcemap_reference(s)
                    if ref and not ref.startswith("data:"):
                        maps.append(self.get(ref, jar=None, source="sourcemap"))
                kw["sourcemaps"] = maps
        ctx = make_ctx(target=self.url(c.path), entry=None, profile=c.profile, sensitivity=c.sensitivity, **kw)
        ctx.entry = entry
        ctx.coverage = coverage.Coverage()
        for r in ctx.all_responses():
            doc = htmlparse.parse_response(r) if r.essence in ("text/html", "") and r.body else None
            classify.classify(r, doc)
            if r is entry and r.kind == "document":
                ctx.pages.append(Page(r, doc, 0))
        return ctx


@pytest.mark.skipif(corpus is None, reason="bench/web/corpus.py not present")
@pytest.mark.parametrize("case", CORPUS_CASES, ids=[c.id for c in CORPUS_CASES])
def test_corpus_case_labels(case, make_ctx):
    ctx = _Sim(case).context(make_ctx)
    issues = run(ctx)
    shown = by_rule(issues, ctx.options)
    for rule, want in case.labels.items():
        if rule in OWN:
            got = shown.get(rule, [])
            assert bool(got) is want, f"{case.id}: {rule} expected {'to fire' if want else 'silent'}, got {got!r}"
    order = ["info", "low", "medium", "high", "critical"]
    for rule, val in case.expect.get("severity", {}).items():
        if rule in OWN:
            assert max((sev(i) for i in shown[rule]), key=order.index) == val, (case.id, rule)
    for rule, val in case.expect.get("max_severity", {}).items():
        if rule in OWN:
            assert all(order.index(sev(i)) <= order.index(val) for i in shown.get(rule, [])), (case.id, rule)
    for rule, val in case.expect.get("count", {}).items():
        if rule in OWN:
            assert len({(i.host, i.group_value) for i in shown.get(rule, [])}) == val, (case.id, rule)


@pytest.mark.skipif(corpus is None, reason="bench/web/corpus.py not present")
def test_corpus_covers_the_c_disc_group():
    disc = {c.id for c in corpus.CASES if c.group == "C-DISC"}
    assert disc <= {c.id for c in CORPUS_CASES} and len(disc) >= 30
    labelled = {r for c in corpus.CASES if c.group == "C-DISC" for r in c.labels}
    assert {"WEB010", "WEB011", "WEB055", "WEB056", "WEB600", "WEB601", "WEB602", "WEB603", "WEB604", "WEB605", "WEB606",
            "WEB607", "WEB608", "WEB609", "WEB610", "WEB611", "WEB612", "WEB613", "WEB615", "WEB617"} <= labelled


# =============================================================================================== adversarial review

def _evidence_dump(issues) -> str:
    return json.dumps([{"ev": i.evidence.to_dict(), "gv": i.group_value, "notes": i.notes, "params": i.params}
                       for i in issues], ensure_ascii=False)


def test_excerpt_never_shows_a_neighbouring_card_hash_or_secret(ctx_for, make_response):
    cards = run(ctx_for("<table><tr><td>4539 1488 0343 6467</td><td>5425 2334 3010 9903</td></tr></table>"))
    assert len(by_rule(cards)["WEB613"]) == 2
    dump = _evidence_dump(cards)
    assert "4539 1488" not in dump and "5425 2334" not in dump
    h1, h2 = "$2b$12$" + "R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW", "$2b$12$" + "Q" * 22 + "abcDEF" * 5 + "x"
    hashes = run(ctx_for('[{"h":"' + h1 + '"},{"h":"' + h2 + '"}]', content_type="application/json"))
    assert len(by_rule(hashes)["WEB612"]) == 2
    assert h1 not in _evidence_dump(hashes) and h2 not in _evidence_dump(hashes)
    gh = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    secrets = run(_secret_ctx(ctx_for, make_response, html=f'<script>var a="{SK}";var b="{gh}";</script>'))
    assert len(by_rule(secrets)["WEB609"]) == 2
    _no_raw_secret(secrets, SK)
    _no_raw_secret(secrets, gh)


def test_excerpt_masks_and_window_edges():
    text = "aaaa SECRET1 bbbb TARGET cccc SECRET2 dddd"
    s = text.index("TARGET")
    masks = [(5, 12, "<m1>"), (s, s + 6, "<t>"), (30, 37, "<m2>")]
    assert disclosure._excerpt(text, s, s + 6, replace="<t>", masks=masks) == "aaaa <m1> bbbb <t> cccc <m2> dddd"
    # a mask straddling the window edge is cut off, never shown half in clear
    out = disclosure._excerpt(text, s, s + 6, replace="<t>", masks=masks, around=10)
    assert "SECRET" not in out and "<t>" in out


def test_firmer_sighting_replaces_a_tentative_duplicate(make_page, make_response, make_ctx):
    """A traceback quoted in a 2xx docs page (tentative) must not hide the same signature on a 500 page (firm)."""
    docs = make_page(f"<h1>Docs</h1><pre>{PY_TB}</pre>")
    boom = make_page(f"<div>{PY_TB}</div>", url=URL + "boom", status=500, kind="error_page", source="crawl")
    ctx = make_ctx(entry=docs, pages=[boom])
    ctx.coverage = coverage.Coverage()
    got = by_rule(run(ctx), ctx.options)
    (i,) = got["WEB056"]
    assert i.confidence == "firm" and i.url.endswith("/boom")
    assert ctx.coverage.state("WEB056").state == "fail"


@pytest.mark.parametrize("body", [
    "<article><p>The Werkzeug Debugger is great locally; never enable it in production.</p></article>",
    "<p>If you get “You're seeing this error because you have DEBUG = True” check your URLconf.</p>",
    "<p>Rails shows Action Controller: Exception caught when something breaks.</p>",
    "<p>Symfony is a PHP framework. The sf-toolbar shows Symfony\\Component\\ErrorHandler output.</p>",
    "<p>Server Error in '/' Application. Stack Trace: we explain the yellow screen of death.</p>",
    "<p>Spring Boot shows a Whitelabel Error Page; read at java.lang.Thread.run( in the log.</p>",
    "<p>Install spatie/laravel-ignition with composer.</p>",
    "<p>Whoops is an error handler: use Whoops\\Handler\\PrettyPageHandler.</p>",
])
def test_debug_page_prose_on_a_2xx_blog_is_not_debug_mode(ctx_for, body):
    assert "WEB605" not in by_rule(run(ctx_for(body)))


def test_debug_markup_still_detected_on_2xx(ctx_for):
    toolbar = '<p>app</p><div id="sfwdt3c2b1a" class="sf-toolbar sf-display-none" role="region"></div>'
    assert "WEB605" in by_rule(run(ctx_for(toolbar)))
    djdt = '<p>app</p><div id="djDebug" class="djdt-hidden" dir="ltr"></div>'
    assert "WEB605" in by_rule(run(ctx_for(djdt)))
    wz = ('<title>KeyError // Werkzeug Debugger</title><div class="debugger"><script src="?__debugger__=yes&amp;cmd='
          'resource&amp;f=debugger.js"></script></div>')
    (i,) = by_rule(run(ctx_for(wz)))["WEB605"]
    assert sev(i) == "critical"
    for body in ("<p>Rails: Action Controller: Exception caught</p>", "<p>Whoops\\Handler\\PrettyPageHandler</p>"):
        assert "WEB605" in by_rule(run(ctx_for(body, status=500))), body


@pytest.mark.parametrize("body", [
    "<p>The mysqli_query() function performs a query against the database.</p>",
    "<h1>Class SQLException</h1><p>java.sql.SQLException An exception that provides information</p>",
    "<p>PG::Connection is the main class of the pg gem.</p>",
    "<p>Throws SQLiteException if the database cannot be opened.</p>",
    "<p>The System.Data.SqlClient.SqlException class.</p>",
    "<p>Catch psycopg2.OperationalError and sqlalchemy.exc.OperationalError in your code.</p>",
    "<p>SQLITE_ERROR (1) is the generic result code.</p>",
])
def test_database_class_names_in_docs_are_not_errors(ctx_for, body):
    assert "WEB606" not in by_rule(run(ctx_for(body)))


@pytest.mark.parametrize("body", [
    "Warning: mysqli_query(): (HY000/1045): Access denied for user",
    "mysql_fetch_array() expects parameter 1 to be resource, boolean given",
    "java.sql.SQLSyntaxErrorException: Table 'shop.items' doesn't exist",
    "PG::UndefinedTable: ERROR:  relation \"users\" does not exist",
    "psycopg2.errors.UndefinedTable: relation \"x\" does not exist",
    "(sqlalchemy.exc.OperationalError) (sqlite3.OperationalError) no such table: users",
    "android.database.sqlite.SQLiteException: no such table: notes",
    "[SqlException (0x80131904): Invalid object name 'Users'.]",
    "System.Data.SqlClient.SqlException (0x80131904): Invalid object name 'Users'.",
    "Error: SQLITE_ERROR: no such table: users",
    "org.hibernate.exception.SQLGrammarException: could not extract ResultSet",
])
def test_database_error_messages_still_detected(ctx_for, body):
    assert "WEB606" in by_rule(run(ctx_for(f"<p>{body}</p>", status=500))), body


def test_raw_binary_serialized_body_is_detected(ctx_for):
    for body, ctype, fmt in ((b"\xac\xed\x00\x05sr\x00\x11java.util.HashMap", "application/x-java-serialized-object",
                              "Java"),
                             (b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00}\x94.", "application/octet-stream",
                              "Python pickle")):
        (i,) = by_rule(run(ctx_for(body, content_type=ctype)))["WEB610"]
        assert i.evidence.match["value"] == fmt
    assert "WEB610" not in by_rule(run(ctx_for(b"\x89PNG\r\n\x1a\n\x00\x00\x00", content_type="image/png")))


def test_aws_pair_needs_a_base64_secret_not_a_hex_digest(ctx_for, make_response):
    sha = "3f2a1c9e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39"
    js = 'var cfg={accessKeyId:"AKIA' + '2E0A8F3B244C9986",build:"' + sha + '"};'
    assert "WEB609" not in by_rule(run(_secret_ctx(ctx_for, make_response, js=js)))
    real = "tL9Qx2vR8mN4bK7pW1zY6cF3hJ5sD0gA8eU2iO4r"
    js = 'var cfg={accessKeyId:"AKIA' + '2E0A8F3B244C9986",secretAccessKey:"' + real + '"};'
    issues = run(_secret_ctx(ctx_for, make_response, js=js))
    assert "WEB609" in by_rule(issues)
    _no_raw_secret(issues, real)


def test_long_unseparated_digit_ids_are_not_cards():
    # int64 ids (Snowflake/Instagram style) are 17–19 digits; 1 in 10 is Luhn-valid by chance
    ids = ("3612345678901234001", "4000000000000000006", "353000000000000003")
    assert all(disclosure.luhn_ok(i) for i in ids)                    # each would pass the Luhn and brand checks
    assert disclosure.card_numbers('{"ids": [' + ", ".join(ids) + "]}") == []
    assert disclosure.card_numbers("Diners 3056 930902 5904") and disclosure.card_numbers("visa 4539148803436467")


@pytest.mark.parametrize("obj", [
    {"version": 3, "sections": [], "sources": 5},
    {"version": 3, "sources": ["a"], "sourcesContent": "x"},
    {"version": 3, "sections": [{"map": {"sources": 7, "sourcesContent": ["k"]}}]},
    {"sources": [], "sections": [{"map": {"sources": None, "sourcesContent": [1, "x"]}}]},
    {"sources": [], "sections": {"a": 1}},
])
def test_malformed_source_maps_do_not_crash(make_page, make_response, make_ctx, obj):
    smap = make_response(URL + "a.js.map", body=json.dumps(obj).encode(), content_type="application/json",
                         source="sourcemap")
    run(make_ctx(entry=make_page("<p/>"), sourcemaps=[smap], profile="deep"))


def test_deeply_nested_source_map_does_not_crash(make_page, make_response, make_ctx):
    deep = b"[" * 200_000
    smap = make_response(URL + "a.js.map", body=deep, content_type="application/json", source="sourcemap")
    assert disclosure.parse_sourcemap(deep.decode()) is None
    inline = make_response(URL + "a.js", content_type="text/javascript", source="subresource",
                           body=b"x;\n//# sourceMappingURL=data:application/json;base64," + base64.b64encode(deep))
    run(make_ctx(entry=make_page("<p/>"), sourcemaps=[smap], subresources=[inline], profile="deep"))


HOSTILE_2XX = [
    "<pre " * 60000, "<a " * 80000, "<div " * 60000, "<img " * 60000, "<script " * 40000, "<code a=" * 40000,
    "<!--" + "a." * 100000 + "-->", "<!--" + "0-" * 100000 + "-->",
]


@pytest.mark.parametrize("n", range(len(HOSTILE_2XX)))
def test_hostile_2xx_documents_are_fast(make_response, make_ctx, n):
    """The pre/code guard, listing and 2xx-only signatures are quadratic with an unbounded ``[^>]*`` / ``[\\w-]+``."""
    body = HOSTILE_2XX[n][:250_000].encode()
    r = make_response(URL, body=body, content_type="text/html", kind="document")
    ctx = make_ctx(entry=Page(r, None), sensitivity="paranoid")
    t = time.perf_counter()
    disclosure.run(ctx)
    assert time.perf_counter() - t < 4.0


@pytest.mark.parametrize("value", ['"' + "0-" * 32000 + '"', "ip-10" + "-1" * 30000, "0" * 65000, "a." * 32000])
def test_hostile_64k_header_values_are_fast(ctx_for, value):
    headers = [(n, value) for n in ("Server", "X-Powered-By", "X-Foo", "ETag", "Server-Timing", "X-Debug-Token",
                                    "Location", "X-AspNet-Version", "X-Generator")]
    ctx = ctx_for("<p>x</p>", headers=headers, sensitivity="paranoid")
    t = time.perf_counter()
    run(ctx)
    assert time.perf_counter() - t < 2.0


@pytest.mark.parametrize("seed", range(10))
def test_random_structured_documents_never_crash(make_response, make_ctx, seed):
    import random
    rnd = random.Random(1000 + seed)
    parts = ["<pre>", "</pre>", "<code>", "<input type=hidden name=__VIEWSTATE value=", "/wE", "rO0AB", "<!--", "-->",
             "Traceback (most recent call last)", 'File "/a.py", line 3', "at a.b(C.java:1)", "4539 1488 0343 6467",
             "$2b$12$", "10.0.0.", "fc00::1", "<?php", ";", "SQLSTATE[42000]", "sk_live_", "AKIA", "-----BEGIN ",
             "PRIVATE KEY-----", "<a href=../>", "<title>Index of /", "\x00", "ا", "%", "&#x27;", "javax.faces.ViewState",
             "<script>", "</script>", '"', "'", ">", "<", "\n"]
    html = "".join(rnd.choice(parts) + rnd.choice(["", "x", "A" * rnd.randint(1, 40), str(rnd.random())])
                   for _ in range(rnd.randint(1, 400)))
    status = rnd.choice([200, 404, 500])
    r = make_response(URL, status=status, body=html, content_type="text/html",
                      kind="document" if status == 200 else "error_page")
    ctx = make_ctx(entry=Page(r, htmlparse.parse_response(r)), sensitivity="paranoid", profile="deep")
    run(ctx)
