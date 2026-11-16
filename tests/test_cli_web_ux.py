"""Kashif 1.1.0 command line for web targets, UX pass: the progress line on a terminal, Ctrl+C, the explanations of an
unreachable site (surface, port, timeouts, proxies, the HTTPS-proxy-only hint) and their English catalogue, scheme and
option checks before any request, --ignore-rule and --fail-on-inconclusive for web targets, the minimal report of an
unreachable site, colour only on a terminal, pages instead of files, one budget note, and --list-rules.

Offline: every site is a server on 127.0.0.1 started by the test; the proxy errors are explained from the error texts
``webscan.http.classify_error`` writes, so no proxy is needed.
"""

from __future__ import annotations

import json
import os
import re
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from vulnscan import cli, web
from vulnscan.cli import main
from vulnscan.i18n import to_en
from vulnscan.i18n import cat_web
from vulnscan.i18n.bidi import LRI, LRM, PDI

PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
ARABIC = re.compile(r"[؀-ۿ]")
ANSI = re.compile(r"\x1b\[[0-9;]*m")


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    for k in PROXY_VARS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    rmap = tmp_path / "resolve.json"
    rmap.write_text(json.dumps({"version": 1, "hosts": {},
                                "default": {"status": "ok", "addresses": ["192.0.2.1"], "public": True}}),
                    encoding="utf-8")
    monkeypatch.setenv("KASHIF_TEST_RESOLVE", "1")
    monkeypatch.setenv("KASHIF_TEST_RESOLVE_MAP", str(rmap))
    monkeypatch.delenv("KASHIF_TEST_CAFILE", raising=False)
    monkeypatch.setenv("KASHIF_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VULNSCAN_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(cli, "_is_arabic_locale", lambda environ=None: False)
    from vulnscan.webscan import data
    data.clear_cache()
    yield
    data.clear_cache()


class Site(BaseHTTPRequestHandler):
    """A page with a password form over plain HTTP (WEB052) and two same-origin links; ``Site.waf`` answers every
    request with a Cloudflare challenge page instead (WEB990, no Kashif grade)."""
    waf = False
    requests: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        Site.requests.append(self.path)
        if Site.waf:
            body = (b"<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>"
                    b"<div id=challenge-running></div></body></html>")
            self.send_response(403)
            self.send_header("Server", "cloudflare")
            self.send_header("cf-ray", "8abc123-FRA")
            self.send_header("cf-mitigated", "challenge")
        elif self.path in ("/", "/a", "/b"):
            body = (b"<!doctype html><html><head><meta charset=utf-8><title>Shop</title></head><body>"
                    b"<a href=/a>a</a> <a href=/b>b</a>"
                    b"<form action=/login method=post><input type=password name=pw></form></body></html>")
            self.send_response(200)
        else:
            body = b""
            self.send_response(404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def site():
    Site.waf = False
    Site.requests = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/"
    httpd.shutdown()
    httpd.server_close()


# Windows answers a connection to a closed local port only after ~2 s of SYN retries (WSAECONNREFUSED), so a 1 s
# timeout would report a timeout there instead of the refusal these tests are about.
REFUSE_TIMEOUT = "6"


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ----------------------------------------------------------------------------------------------- 1. progress

def test_progress_line_on_a_terminal_only_and_cleared_before_the_report(site, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_isatty", lambda stream: stream is sys.stderr)
    assert main([site, "--authorized", "--web-profile", "minimal", "--lang", "en", "--no-color"]) == 0
    out, err = capsys.readouterr()
    assert "\r\x1b[K⏳ Fetching the page — " in err and re.search(r"⏳ [^\r]* — \d+/10", err)
    assert err.endswith("\r\x1b[K")                 # the line is cleared before the report prints
    assert "⏳" not in out and "\r" not in out
    # Arabic step names; the count is a left-to-right isolate
    assert main([site, "--authorized", "--web-profile", "minimal", "--lang", "ar", "--no-color"]) == 0
    err = capsys.readouterr().err
    assert "⏳ جلب الصفحة — " + LRI in err


def test_no_progress_without_a_terminal_or_with_machine_output_on_stdout(site, monkeypatch, capsys):
    assert main([site, "--authorized", "--web-profile", "minimal", "--lang", "en"]) == 0
    assert "⏳" not in capsys.readouterr().err
    monkeypatch.setattr(cli, "_isatty", lambda stream: stream is sys.stderr)
    assert main([site, "--authorized", "--web-profile", "minimal", "--lang", "en", "-f", "json"]) == 0
    out, err = capsys.readouterr()
    assert "⏳" not in err and json.loads(out)["target"] == site


# ----------------------------------------------------------------------------------------------- 2. Ctrl+C

@pytest.mark.parametrize("lang,text", [("ar", "✖ أُوقف الفحص بطلب المستخدم؛ لم يُكتب تقرير."),
                                       ("en", "✖ Scan interrupted by the user; no report written.")])
def test_ctrl_c_exits_130_and_saves_no_half_done_scan(site, monkeypatch, capsys, tmp_path, lang, text):
    def interrupted(*a, **kw):
        raise KeyboardInterrupt
    monkeypatch.setattr(web, "scan_web", interrupted)
    out = tmp_path / "r.json"
    code = main([site, "--authorized", "--compare-previous", "--lang", lang, "-f", "json", "-o", str(out)])
    assert code == 130 and text in capsys.readouterr().err
    from vulnscan.store import Store
    assert Store().list_scans() == [] and not out.exists()


# ----------------------------------------------------------------------------------------------- 3. explanations

def _matrix():
    """(error text, URL, timeout, surface, keyword arguments) covering every sentence sequence of explain_failure."""
    p = "http://127.0.0.1:3128"
    errs = ["timed out", "[Errno 111] Connection refused", "[Errno -2] Name or service not known",
            "[Errno 113] No route to host", "certificate verify failed: self-signed", "[Errno 104] Connection reset by peer",
            "response deadline exceeded (30 s): the server kept the response open", "something odd",
            f"the proxy {p} refused the tunnel (HTTP 403): Tunnel connection failed: 403 Forbidden",
            f"the proxy {p} refused the tunnel: Tunnel connection failed", f"the proxy {p} could not be reached: x",
            f"the proxy {p} closed the connection: [Errno 104] Connection reset by peer",
            "unsupported URL (only http:// and https:// are scanned): ftp://x/", "invalid URL"]
    for err in errs:
        for url in ("https://example.com/", "http://example.com:8080/app", "http://[2001:db8::1]/", "https://x.test:443/"):
            for t in (1, 2, 2.5, 20):
                for surface in ("cli", "ui"):
                    yield err, url, t, surface, {"proxies": {}}
    yield "timed out", "https://example.com/", 20, "cli", {"proxy": p}
    yield "[Errno 104] Connection reset by peer", "https://example.com/", 20, "ui", {"proxy": p, "code": "reset"}
    yield "[Errno -2] Name or service not known", "http://example.com/", 20, "cli", {"proxies": {"https": p}}
    yield "malformed HTTP response: x", "https://example.com/", 20, "cli", {"code": "bad_response"}


def test_every_explanation_has_the_same_english_through_the_catalogue():
    seen = set()
    for err, url, t, surface, kw in _matrix():
        d = web.describe_failure(err, url, t, surface, **kw)
        assert to_en(d["ar"]) == d["en"], (err, url, t, surface, d["ar"])
        assert not ARABIC.search(d["en"]) and d["raw"] == err
        assert d["ar"] == web.explain_failure(err, url, t, surface, **kw)
        seen.add(d["code"])
    assert {"timeout", "refused", "dns", "unreachable", "tls", "reset", "deadline", "network", "proxy_refused",
            "proxy_unreachable", "proxy_reset", "unsupported", "invalid", "bad_response"} <= seen


def test_every_combination_of_sentences_has_a_pattern():
    for combo in cat_web.FAILURE_COMBOS:
        assert all(k in cat_web.FAILURE for k in combo), combo
    for en, ar in cat_web.FAILURE.values():          # same placeholders in both languages
        assert sorted(re.findall(r"\{(\w+)\}", en)) == sorted(re.findall(r"\{(\w+)\}", ar)), en


def test_timeout_wording_surface_and_seconds_agree():
    cli_msg = web.describe_failure("timed out", "https://example.com/", 2, "cli")
    assert "no answer within 2 s, then 4 s on the retry" in cli_msg["en"]
    assert "خلال ثانيتين، ثم خلال 4 ثوانٍ في المحاولة الثانية" in cli_msg["ar"]
    assert "--timeout 20" in cli_msg["en"] and "Settings" not in cli_msg["en"]
    assert LRI + "--timeout 20" + PDI in cli_msg["ar"] and "الإعدادات" not in cli_msg["ar"]
    ui_msg = web.describe_failure("timed out", "https://example.com/", 20, "ui")
    assert "within 20 s, then 40 s" in ui_msg["en"] and "increase the timeout in Settings" in ui_msg["en"]
    assert "خلال 20 ثانيةً، ثم خلال 40 ثانيةً" in ui_msg["ar"] and "--timeout" not in ui_msg["en"]
    # the 1.0.1 call (three arguments) is the UI's wording
    assert web.explain_failure("timed out", "https://example.com/", 20) == ui_msg["ar"]


def test_alternative_url_keeps_the_port_rule():
    d = web.describe_failure("[Errno 111] Connection refused", "https://shop.example/cart", 20, "cli")
    assert "You can also try http://shop.example/cart." in d["en"] and LRI + "http://shop.example/cart" + PDI in d["ar"]
    d = web.describe_failure("[Errno 111] Connection refused", "http://127.0.0.1:8080/", 20, "cli")
    assert "Check that the service on port 8080 is running." in d["en"] and "https://" not in d["en"].split("(details")[0]
    assert "تحقّق من أن الخدمة على المنفذ " + LRI + "8080" + PDI + " تعمل." in d["ar"]
    d = web.describe_failure("[Errno 111] Connection refused", "http://example.com:80/", 20, "cli")
    assert "You can also try https://example.com." in d["en"]


@pytest.mark.parametrize("err,code,needle_en,needle_ar", [
    ("the proxy http://p:3128 could not be reached: [Errno 111] Connection refused", "proxy_unreachable",
     "Could not connect to the proxy http://p:3128 (from HTTP_PROXY/HTTPS_PROXY). Check the proxy, or run with --no-proxy.",
     "تعذّر الاتصال بالوكيل"),
    ("the proxy http://p:3128 refused the tunnel (HTTP 403): Tunnel connection failed: 403 Forbidden", "proxy_refused",
     "The proxy http://p:3128 refused to connect to example.com (HTTP 403), so Kashif did not reach the site.",
     "فلم يصل كاشِف إلى الموقع"),
    ("the proxy http://p:3128 closed the connection: [Errno 104] Connection reset by peer", "proxy_reset",
     "the proxy or the site closed it, and Kashif cannot tell which", "ولا يستطيع كاشِف معرفة أيهما"),
])
def test_proxy_failures_come_first_and_never_blame_the_site(err, code, needle_en, needle_ar):
    d = web.describe_failure(err, "https://example.com/", 20, "cli")
    why = d["en"].split(" (details:")[0]
    assert d["code"] == code and needle_en in d["en"] and needle_ar in d["ar"]
    assert "http://example.com" not in why and "firewall (WAF)" not in why and "You can also try" not in why
    assert LRM + "--no-proxy" in d["ar"]
    # the structured facts of WebUnreachable win over the text
    d = web.describe_failure("Tunnel connection failed", "https://example.com/", 20, "ui", code="proxy_refused",
                             proxy="http://q:8080", proxy_status=407)
    assert "The proxy http://q:8080 refused to connect to example.com (HTTP 407)" in d["en"]
    assert "Do not use the system's proxy" in d["en"] and "--no-proxy" not in d["en"].split(" (details:")[0]


def test_a_reset_through_a_proxy_is_not_called_a_waf():
    direct = web.describe_failure("[Errno 104] Connection reset by peer", "https://example.com/", 20, "cli")
    proxied = web.describe_failure("[Errno 104] Connection reset by peer", "https://example.com/", 20, "cli",
                                   code="reset", proxy="http://p:3128")
    assert "(WAF)" in direct["en"] and "(WAF)" not in proxied["en"] and "cannot tell which" in proxied["en"]


def test_dns_failure_of_an_http_url_with_only_an_https_proxy_says_why():
    hint = "Only an HTTPS proxy is set (HTTPS_PROXY), with no HTTP proxy (HTTP_PROXY)"
    err = "[Errno -2] Name or service not known"
    d = web.describe_failure(err, "http://intranet.example/", 20, "cli", proxies={"https": "http://p:3128"})
    assert hint in d["en"] and "or scan https://intranet.example." in d["en"] and LRI + "HTTPS_PROXY" + PDI in d["ar"]
    for url, kw in (("https://intranet.example/", {"proxies": {"https": "http://p:3128"}}),
                    ("http://intranet.example/", {"proxies": {"https": "http://p", "http": "http://p"}}),
                    ("http://intranet.example/", {"proxies": {"https": "http://p:3128"}, "use_proxy": False})):
        assert hint not in web.describe_failure(err, url, 20, "cli", **kw)["en"]


def test_cli_explains_an_unreachable_site_with_the_cli_wording(capsys):
    port = _closed_port()
    assert main([f"http://127.0.0.1:{port}/", "--authorized", "--timeout", REFUSE_TIMEOUT, "--lang", "both"]) == 2
    err = capsys.readouterr().err.splitlines()
    assert err[0].startswith("✖ لم يُفحص الموقع — رفض الخادم") and err[1].startswith("✖ The site was not scanned:")
    assert f"Check that the service on port {port} is running." in err[1] and "Try https://" not in err[1]


# ----------------------------------------------------------------------------------------------- 4. schemes

@pytest.mark.parametrize("lang,needle", [("en", "✖ Only http:// and https:// URLs can be scanned (got ftp://example.com/x)."),
                                         ("ar", "لا يمكن فحص إلا عناوين")])
def test_other_schemes_are_refused_before_the_path_check(lang, needle, capsys):
    assert main(["ftp://example.com/x", "--authorized", "--lang", lang]) == 2
    err = capsys.readouterr().err
    assert needle in err and "not found" not in err and "غير موجود" not in err


def test_upper_case_http_scheme_is_a_web_target(site, capsys):
    upper = site.replace("http://", "HTTP://")
    with pytest.raises(SystemExit) as e:                                        # web: --authorized is required
        main([upper, "--web-profile", "minimal", "--lang", "en"])
    assert e.value.code == 2 and "--authorized" in capsys.readouterr().err
    assert main([upper, "--authorized", "--web-profile", "minimal", "--lang", "en", "--no-color"]) == 0


# ----------------------------------------------------------------------------------------------- 5. web-only options

@pytest.mark.parametrize("argv,opt", [
    (["--web-profile", "deep"], "--web-profile"), (["--web-sensitivity", "strict"], "--web-sensitivity"),
    (["--third-party-lookups"], "--third-party-lookups"), (["--ignore-robots"], "--ignore-robots"),
    (["--web-cookie-ignore", "sid"], "--web-cookie-ignore"), (["--no-proxy"], "--no-proxy"),
    (["--fail-on-inconclusive"], "--fail-on-inconclusive")])
def test_web_only_options_on_a_local_path_are_usage_errors(tmp_path, argv, opt, capsys):
    with pytest.raises(SystemExit) as e:
        main([str(tmp_path), "--lang", "en", *argv])
    assert e.value.code == 2 and f"{opt} applies to http(s):// web targets only" in capsys.readouterr().err


def test_crawl_needs_a_profile_that_crawls(site, capsys):
    Site.requests = []
    with pytest.raises(SystemExit) as e:
        main([site, "--authorized", "--crawl", "--web-profile", "minimal", "--lang", "en"])
    assert e.value.code == 2 and "--crawl needs --web-profile standard or deep" in capsys.readouterr().err
    assert Site.requests == []


# ----------------------------------------------------------------------------------------------- 6. numbers

@pytest.mark.parametrize("argv,needle", [
    (["--timeout", "0"], "argument --timeout: must be a number of seconds greater than 0 (got 0)"),
    (["--timeout", "-3"], "greater than 0 (got -3)"), (["--timeout", "nan"], "greater than 0 (got nan)"),
    (["--max-pages", "-1"], "argument --max-pages: must be a whole number, 0 or more (got -1)"),
    (["--max-depth", "1.5"], "argument --max-depth: must be a whole number, 0 or more (got 1.5)"),
    (["--delay", "-0.1"], "argument --delay: must be a number of seconds, 0 or more (got -0.1)"),
    (["--delay", "inf"], "0 or more (got inf)")])
def test_numeric_options_are_validated_by_argparse(site, argv, needle, capsys):
    Site.requests = []
    with pytest.raises(SystemExit) as e:
        main([site, "--authorized", "--lang", "en", *argv])
    assert e.value.code == 2 and needle in capsys.readouterr().err and Site.requests == []


def test_numeric_errors_in_arabic(site, capsys):
    with pytest.raises(SystemExit):
        main([site, "--authorized", "--lang", "ar", "--timeout", "0"])
    assert "يجب أن تكون القيمة عددًا من الثواني أكبر من 0 (المُعطى: 0)" in capsys.readouterr().err


def test_delay_floor_note_and_max_pages_cap_warning(site, tmp_path, capsys):
    out = tmp_path / "r.json"
    assert main([site, "--authorized", "--crawl", "--max-pages", "600", "--delay", "0.05", "--lang", "en",
                 "-f", "json", "-o", str(out)]) == 0
    err = capsys.readouterr().err
    assert "--max-pages is capped at 500 pages; 600 was given" in err
    notes = [n["en"] for n in json.loads(out.read_text(encoding="utf-8"))["web"]["notes"]]
    assert "The delay between requests was raised to its 0.2 s floor (--delay 0.05 was given)." in notes
    assert any("at least 0.2 s between requests" in n for n in notes)


# ----------------------------------------------------------------------------------------------- 7. --ignore-rule

def test_ignore_rule_drops_web_findings_and_says_so(site, tmp_path):
    """Regression: --ignore-rule was passed to the code scanner only, so web findings of that rule stayed."""
    full, ignored = tmp_path / "full.json", tmp_path / "ign.json"
    assert main([site, "--authorized", "--web-profile", "minimal", "-f", "json", "-o", str(full)]) == 0
    assert main([site, "--authorized", "--web-profile", "minimal", "--ignore-rule", "WEB052", "-f", "json",
                 "-o", str(ignored)]) == 0
    a, b = (json.loads(p.read_text(encoding="utf-8")) for p in (full, ignored))
    assert any(f["rule_id"] == "WEB052" for f in a["findings"])
    assert not any(f["rule_id"] == "WEB052" for f in b["findings"])
    assert len(b["findings"]) == len(a["findings"]) - 1
    note = next(n for n in b["web"]["notes"] if "--ignore-rule" in n["en"])
    assert note["en"] == "Ignored with --ignore-rule: WEB052 (1 finding); the grades still count them."
    assert "نتيجة واحدة" in note["ar"] and note["ar"] in b["notes"]


# ----------------------------------------------------------------------------------------------- 8. CI gate

def test_fail_on_inconclusive(site, capsys):
    assert main([site, "--authorized", "--web-profile", "minimal", "--fail-on-inconclusive", "--lang", "en"]) == 0
    Site.waf = True
    assert main([site, "--authorized", "--web-profile", "minimal", "--lang", "en"]) == 0      # 0/1/2 kept without it
    capsys.readouterr()
    assert main([site, "--authorized", "--web-profile", "minimal", "--fail-on-inconclusive", "--lang", "en"]) == 1
    assert "inconclusive (no Kashif grade, WEB990)" in capsys.readouterr().err


# ----------------------------------------------------------------------------------------------- 9. unreachable report

@pytest.mark.parametrize("fmt", ["json", "sarif", "html", "markdown"])
def test_unreachable_site_still_writes_a_report_and_exits_2(fmt, tmp_path):
    out = tmp_path / f"r.{fmt}"
    url = f"http://127.0.0.1:{_closed_port()}/"
    assert main([url, "--authorized", "--timeout", REFUSE_TIMEOUT, "--lang", "en", "-f", fmt, "-o", str(out)]) == 2
    text = out.read_text(encoding="utf-8")
    if fmt == "json":
        doc = json.loads(text)
        assert doc["target"] == url and doc["findings"] == [] and doc["generated_at"]
        assert doc["web"]["status"] == "unreachable" and doc["web"]["schema"] >= 1
        err = doc["web"]["error"]
        assert err["code"] == "refused" and "refused" in err["raw"]   # Windows: "...actively refused it"
        assert to_en(err["ar"]) == err["en"]
    elif fmt == "sarif":
        run = json.loads(text)["runs"][0]
        inv = run["invocations"][0]
        assert run["results"] == [] and inv["executionSuccessful"] is False
        assert inv["toolExecutionNotifications"][0]["level"] == "error"
        assert "refused the connection" in inv["toolExecutionNotifications"][0]["message"]["text"]
    else:
        assert "refused the connection" in text and url in text


def test_unreachable_site_overwrites_a_console_output_file(tmp_path):
    out = tmp_path / "r.txt"
    out.write_text("stale report of an earlier scan", encoding="utf-8")
    url = f"http://127.0.0.1:{_closed_port()}/"
    assert main([url, "--authorized", "--timeout", "1", "--lang", "en", "-o", str(out)]) == 2
    text = out.read_text(encoding="utf-8")
    assert "stale" not in text and text.startswith("✖ The site was not scanned:") and "\x1b[" not in text


@pytest.mark.parametrize("lang,lines", [("ar", 1), ("both", 2)])
def test_authorized_message_keeps_the_flag_in_order(lang, lines, capsys):
    with pytest.raises(SystemExit) as e:
        main(["http://127.0.0.1:9/", "--lang", lang])
    assert e.value.code == 2
    err = capsys.readouterr().err.strip().splitlines()
    assert len(err) == lines and all(line.startswith("✖ ") for line in err)
    assert f"يتطلب {LRM}--authorized" in err[0]
    if lang == "both":
        assert err[1] == "✖ Scanning a web URL requires --authorized (confirmation that you are authorized to scan " \
                         "this target)."


# ----------------------------------------------------------------------------------------------- 10. colour

def test_colour_only_on_a_terminal_and_never_with_no_color(site, monkeypatch, capsys):
    argv = [site, "--authorized", "--web-profile", "minimal", "--lang", "en"]
    assert main(argv) == 0
    assert not ANSI.search(capsys.readouterr().out)                    # a pipe or a file: no escape codes
    monkeypatch.setattr(cli, "_isatty", lambda stream: stream is sys.stdout)
    assert main(argv) == 0
    assert ANSI.search(capsys.readouterr().out)
    monkeypatch.setenv("NO_COLOR", "1")
    assert main(argv) == 0
    assert not ANSI.search(capsys.readouterr().out)


# ----------------------------------------------------------------------------------------------- 11-13. meta and notes

def test_pages_and_requests_reach_the_report_and_one_budget_note(site, tmp_path):
    out = tmp_path / "r.json"
    assert main([site, "--authorized", "--crawl", "--delay", "0.2", "--lang", "en", "-f", "json", "-o", str(out)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    web_ = doc["web"]
    pages = 1 + web_["inventory"]["crawl_fetched"]
    assert pages == 3 and doc["files_scanned"] == pages and web_["pages"] == pages and web_["requests"] > 0
    en = [n["en"] for n in web_["notes"]]
    core = web_["inventory"]["requests"]["core_requests"]
    assert en[0] == (f"Passive scan, profile standard: {core} of at most 45 requests sent (plus 2 pages crawled on the "
                     "same origin); no active test.")
    assert not any(n.startswith(("Passive web scan, profile", "Profile standard")) for n in en)
    assert sum("no active test" in n for n in en) == 1
    assert any(n.startswith("The crawl stayed on the same origin (same scheme, host and port)") for n in en)
    ar = web_["notes"][0]["ar"]
    assert "نمط الفحص" in ar and "45 طلبًا" in ar and "صفحتين" in ar and "الأصل نفسه" in ar
    assert doc["notes"] == [n["ar"] for n in web_["notes"]]


def test_proxy_note_is_kept_once():
    from types import SimpleNamespace
    from vulnscan.web import options_for
    proxy = {"en": "Scanning through the proxy http://p:1; DNS checks are not tested.", "ar": "يمر الفحص عبر الوكيل"}
    res = SimpleNamespace(requests=3, inventory={"requests": {"core_requests": 3, "budget": 45}, "crawl_fetched": 0,
                                                 "notes": [proxy, dict(proxy, ar="x"), {"en": "Coverage: 1", "ar": "ت"}]})
    notes = cli.web_scan_notes(res, options_for())
    assert [n["en"] for n in notes].count(proxy["en"]) == 1 and len(notes) == 3


def test_crawl_help_says_same_origin():
    en, ar = build_help("en"), build_help("ar")
    assert "same-origin pages (same scheme, host and port)" in en
    assert "الأصل نفسه (المخطط والمضيف والمنفذ)" in ar and "نمط الفحص السلبي" in ar


def build_help(lang: str) -> str:
    return cli.build_parser(lang).format_help()


# ----------------------------------------------------------------------------------------------- 14. --list-rules

def test_list_rules_appends_the_web_rules(capsys):
    from vulnscan.webscan.rules import RULES as WEB_RULES
    assert main(["--list-rules", "--lang", "en"]) == 0
    out = capsys.readouterr().out
    sast, _, webpart = out.partition("Passive web rules (184):")
    assert webpart and len(WEB_RULES) == 184 and not re.search(r"^WEB", sast, re.M)
    rows = [ln for ln in webpart.splitlines() if ln.startswith("WEB")]
    assert len(rows) == 184 and {r.split()[0] for r in rows} == set(WEB_RULES)
    row = next(r for r in rows if r.startswith("WEB052 "))
    assert row.split()[1] == WEB_RULES["WEB052"].severity and WEB_RULES["WEB052"].cwe in row
    paranoid = [r for r in WEB_RULES.values() if r.paranoid_only]
    assert paranoid and all(any(r2.startswith(p.id + " ") and r2.endswith("[paranoid only]") for r2 in rows)
                            for p in paranoid)
    assert main(["--list-rules", "--lang", "ar"]) == 0
    out = capsys.readouterr().out
    assert "قواعد فحص الويب السلبي (184):" in out and WEB_RULES["WEB052"].name_ar in out


# ----------------------------------------------------------------------------------------------- 15. catalogue

def test_web_catalogue_agrees_with_the_rule_registry():
    """cat_web is read before cat_web2: an Arabic string both define must have the same English in both."""
    from vulnscan.i18n import cat_web2
    from vulnscan.i18n import _norm
    cat2 = {_norm(k): v for k, v in dict(cat_web2.load()[0]).items()}
    assert len(cat2) > 500
    shared = [ar for ar in cat_web.CATALOG if _norm(ar) in cat2]
    assert "ملف .DS_Store مكشوف" in shared and "ترويسة X-Powered-By تكشف التقنية" in shared
    for ar in shared:
        assert cat2[_norm(ar)] == cat_web.CATALOG[ar], ar


def test_old_saved_messages_are_still_translated():
    """Scans saved by earlier builds keep their English (the 1.0.1 timeout wording)."""
    old = ("لم يُفحص الموقع — رفض الخادم example.com الاتصال: المنفذ مغلق أو الخدمة متوقفة. جرّب http://example.com. "
           "(التفاصيل: [Errno 111] Connection refused)")
    assert to_en(old) == ("The site was not scanned: The server example.com refused the connection: the port is closed "
                          "or the service is down. Try http://example.com. (details: [Errno 111] Connection refused)")


def test_engine_message_is_the_ui_wording(monkeypatch):
    port = _closed_port()
    with pytest.raises(web.WebUnreachable) as ei:
        web.scan_web(f"http://127.0.0.1:{port}/", profile="minimal", timeout=float(REFUSE_TIMEOUT))
    msg = str(ei.value)
    assert f"تحقّق من أن الخدمة على المنفذ {LRI}{port}{PDI} تعمل" in msg and ei.value.code == "refused"
    assert os.linesep not in msg


def test_unsupported_proxy_has_its_own_code_and_names_the_proxy():
    from vulnscan.i18n import to_en
    from vulnscan.web import describe_failure
    from vulnscan.webscan.http import _unusable_proxy_message, unusable_proxy
    msg = _unusable_proxy_message(unusable_proxy("socks5://127.0.0.1:1080"))
    for surface in ("cli", "ui"):
        d = describe_failure(msg, "https://example.com/", 10, surface, code="proxy")
        assert d["code"] == "proxy_unsupported"
        assert "The proxy socks5://127.0.0.1:1080 (from" in d["en"] and "  " not in d["en"].split(" (details")[0]
        assert to_en(d["ar"]) == d["en"]


def test_unreachable_tls_probe_findings_are_printed(capsys):
    from vulnscan import cli
    from vulnscan.model import Finding
    from vulnscan.webscan.engine import WebUnreachable
    e = WebUnreachable("x", code="tls")
    e.notes = [("No page could be fetched, but the TLS handshake probes ran: WEB706",
                "تعذّر جلب أي صفحة، لكن فحوص مصافحة TLS أُجريت: WEB706")]
    e.findings = [Finding(rule_id="WEB706", severity="high", title="Weak cipher suites offered",
                          title_ar="مجموعات تشفير ضعيفة مسموحة", file="https://x.test/", line=0,
                          snippet="TLS_RSA_WITH_NULL_SHA256 (TLS 1.2)", advice="", cwe="CWE-327")]
    cli._print_unreachable_tls(e, "en")
    err = capsys.readouterr().err
    assert "TLS handshake probes ran" in err and "high: Weak cipher suites offered · WEB706 — TLS_RSA_WITH_NULL" in err
    cli._print_unreachable_tls(e, "ar")
    err = capsys.readouterr().err
    assert "عالٍ" in err and "⁦WEB706⁩" in err
