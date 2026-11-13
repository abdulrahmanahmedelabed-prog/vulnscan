"""Kashif 1.1.0 web scanning in the local UI (WP15b, spec §4.5): the web-scan form options and settings, the
server's web scan (options, saved ``web`` object and snapshot, diff against the previous scan of the site), the
``/api/scans/<id>/web`` view (grade card, coverage, inventory tabs, copy-paste fixes with platform tabs, diff), the
report downloads, and a smoke test of the panel's rendering code under Node.js with hostile site text.

Offline: the UI server and the scanned site both listen on 127.0.0.1.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from vulnscan import server as srv
from vulnscan.server import Handler
from vulnscan.store import DEFAULT_SETTINGS, Store

UI = pathlib.Path(__file__).resolve().parents[1] / "vulnscan" / "ui"
JS = (UI / "app.js").read_text(encoding="utf-8")
HTML = (UI / "index.html").read_text(encoding="utf-8")
PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
ARABIC = re.compile(r"[؀-ۿ]")
HOSTILE = '<img src=x onerror=alert(1)>"\'<script>alert("kashif-xss")</script>'


def _keys(lang: str) -> dict[str, str]:
    start = JS.index(f"\n  {lang}: {{")
    end = JS.index("\n  },", start)
    return dict(re.findall(r"'([a-z0-9]+\.[A-Za-z0-9_.]+)': '((?:[^'\\]|\\.)*)'", JS[start:end]))


AR, EN = _keys("ar"), _keys("en")


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    for k in PROXY_VARS:
        monkeypatch.delenv(k, raising=False)
    rmap = tmp_path / "resolve.json"
    rmap.write_text(json.dumps({"version": 1, "hosts": {},
                                "default": {"status": "ok", "addresses": ["192.0.2.1"], "public": True}}),
                    encoding="utf-8")
    monkeypatch.setenv("KASHIF_TEST_RESOLVE", "1")
    monkeypatch.setenv("KASHIF_TEST_RESOLVE_MAP", str(rmap))
    monkeypatch.setenv("KASHIF_HOME", str(tmp_path / "kh"))
    from vulnscan.webscan import data
    data.clear_cache()
    yield
    data.clear_cache()


# ----------------------------------------------------------------------------------------------- static UI

def test_web_strings_exist_in_both_languages():
    web_keys = [k for k in EN if k.startswith("web.")]
    assert len(web_keys) >= 30
    for k in web_keys + ["scan.profile", "scan.sens", "scan.compare", "scan.robots", "scan.thirdParty", "scan.noProxy",
                         "set.webProfile", "set.webSens", "set.webCompare", "set.webRobots", "set.web3p", "set.webProxy"]:
        assert k in AR and AR[k] and EN[k], k
        assert not ARABIC.search(EN[k]), (k, EN[k])
        assert ARABIC.search(AR[k]) or k in ("web.c_certain",), (k, AR[k])
    # the 1.0 "one request only" wording is gone from the form
    assert "single request" not in EN["scan.urlLabel"] and "طلب واحد فقط" not in AR["scan.urlLabel"]
    assert "طلب واحد فقط" not in HTML


def test_form_and_settings_controls_exist_and_are_sent():
    for el in ("url-profile", "url-sens", "url-compare", "url-robots", "url-3p", "url-noproxy", "findings-web"):
        assert f'id="{el}"' in HTML, el
    for name in ("web_profile", "web_sensitivity", "web_compare_previous", "web_respect_robots",
                 "web_third_party_lookups", "web_use_proxy"):
        assert f'name="{name}"' in HTML and name in DEFAULT_SETTINGS and f"{name}:" in JS, name
    send = JS[JS.index("$('#url-btn').onclick"):JS.index("let pending = [];")]
    for field in ("profile:", "sensitivity:", "crawl:", "compare_previous:", "ignore_robots:", "third_party_lookups:",
                  "use_proxy:"):
        assert field in send, field
    assert "/web?lang=${lang}" in JS


def test_web_panel_shows_site_text_only_as_escaped_text():
    sec = JS[JS.index("/* ------------------------------------------------------- web scan (1.1.0) */"):
             JS.index("/* -------------------------------------------------------------- triage */")]
    assert "innerHTML" not in sec and "<a " not in sec and "href=" not in sec    # no links to the scanned site
    # every value of the view (g., r., sn., b., p., tb. …) reaches the markup through esc(); tb.body is markup the
    # panel built itself from escaped parts
    raw = [m for m in re.findall(r"\$\{([a-z]+\.[A-Za-z_]+)\b(?!\()", sec) if m != "tb.body" and not m.endswith(".length")]
    assert not raw, raw
    # bidi() escapes too: engine text with Latin runs (grade labels, caps, posture) is isolated in Arabic (ux-i18n)
    assert "esc(g.grade" in sec and "esc(sn.caveat)" in sec and "esc(b.code)" in sec and "bidi(p.text)" in sec


NODE = shutil.which("node")


# ----------------------------------------------------------------------------------------------- server

class Site(BaseHTTPRequestHandler):
    csp = "script-src 'self' 'unsafe-inline'"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path != "/":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = (f"<!doctype html><html><head><meta charset=utf-8><title>{HOSTILE}</title></head><body>"
                "<form action=/login method=post><input type=password name=pw></form></body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", Site.csp)
        self.send_header("X-Powered-By", HOSTILE)
        self.send_header("Set-Cookie", "sessionid=0123456789abcdef0123456789abcdef; Path=/")
        self.end_headers()
        self.wfile.write(body)


def _start(handler):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


@pytest.fixture
def site():
    Site.csp = "script-src 'self' 'unsafe-inline'"
    httpd = _start(Site)
    yield f"http://127.0.0.1:{httpd.server_address[1]}/"
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def ui(tmp_path):
    Handler.store = Store(tmp_path / "home")
    httpd = _start(Handler)
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def _call(base, path, method="GET", data=None):
    req = urllib.request.Request(base + path, method=method, data=json.dumps(data).encode() if data is not None else None,
                                 headers={"Content-Type": "application/json", "Origin": base})
    try:
        with urllib.request.urlopen(req) as r:          # noqa: S310 - the test's own server on 127.0.0.1
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _json(base, path, method="GET", data=None):
    status, body = _call(base, path, method, data)
    return status, json.loads(body)


def _scan(ui, target, **opts):
    status, s = _json(ui, "/api/scan", "POST", {"target": target, "authorized": True, **opts})
    assert status == 202, s
    for _ in range(600):
        s = _json(ui, f"/api/scans/{s['id']}")[1]
        if s["status"] != "running":
            break
        time.sleep(0.05)
    assert s["status"] == "done", s
    return s


def test_scan_options_come_from_the_request_then_the_settings():
    settings = dict(DEFAULT_SETTINGS, web_profile="deep", web_sensitivity="strict", web_use_proxy=False)
    o = srv.web_scan_options({}, settings)
    assert o["profile"] == "deep" and o["sensitivity"] == "strict" and o["use_proxy"] is False
    assert o["compare_previous"] is True and o["respect_robots"] is True and o["crawl"] is False
    o = srv.web_scan_options({"profile": "minimal", "sensitivity": "paranoid", "crawl": True, "ignore_robots": True,
                              "third_party_lookups": True, "use_proxy": True, "compare_previous": False,
                              "cookie_ignore": ["a", 3, "b" * 500]}, settings)
    assert o == {"profile": "minimal", "sensitivity": "paranoid", "crawl": True, "respect_robots": False,
                 "third_party_lookups": True, "use_proxy": True, "compare_previous": False,
                 "cookie_ignore": ["a", "b" * 200]}
    bad = srv.web_scan_options({"profile": "../../x", "sensitivity": {"x": 1}, "crawl": "yes"}, DEFAULT_SETTINGS)
    assert bad["profile"] == "standard" and bad["sensitivity"] == "default" and bad["crawl"] is False
    assert srv.web_scan_options({"deep": True}, DEFAULT_SETTINGS)["profile"] == "deep"      # the 1.0 request body


def test_ui_web_scan_end_to_end(ui, site):
    _call(ui, "/api/settings", "POST", {"web_delay": 0.2})
    first = _scan(ui, site, profile="minimal", sensitivity="default")
    assert first["kind"] == "url" and first["web_options"]["profile"] == "minimal"
    web = first["web"]
    assert web["grades"]["kashif"]["grade"] and web["coverage"] and "snapshot" not in web
    assert first["notes"][0].startswith("ملف الفحص minimal") and first["notes_en"][0].startswith("Profile minimal")
    assert not any(ARABIC.search(n) for n in first["notes_en"])
    assert all(f["extra"].get("confidence") in ("certain", "firm", "tentative") for f in first["findings"])
    # the panels of the findings page, in both languages
    st, en = _json(ui, f"/api/scans/{first['id']}/web?lang=en")
    assert st == 200
    assert [g["key"] for g in en["grades"]] == ["kashif", "observatory", "ssllabs"]
    assert set(en["coverage"]["counts"]) == {"pass", "fail", "not_applicable", "not_tested", "inconclusive"}
    assert [t["id"] for t in en["inventory"]] == ["headers", "csp", "cookies", "tls", "technologies", "third_parties"]
    assert en["remediation"] and en["remediation"][0]["detected"] + en["remediation"][0]["other"]
    assert en["diff"] is None
    assert not ARABIC.search(json.dumps(en["coverage"]["states"]))
    st, ar = _json(ui, f"/api/scans/{first['id']}/web?lang=ar")
    assert ARABIC.search(ar["grades"][0]["name"]) and ARABIC.search(ar["inventory"][0]["label"])
    # second scan of the same site: compared with the first by default
    Site.csp = "script-src 'self'; object-src 'none'; base-uri 'none'"
    second = _scan(ui, site, profile="minimal")
    view = _json(ui, f"/api/scans/{second['id']}/web?lang=en")[1]
    assert view["diff"]["comparable"] is True
    assert any(r["rule"] == "WEB040" for r in view["diff"]["resolved"]) and view["diff"]["posture"]
    third = _scan(ui, site, profile="minimal", compare_previous=False)
    assert _json(ui, f"/api/scans/{third['id']}/web?lang=en")[1]["diff"] is None
    # report downloads carry the web sections
    st, body = _call(ui, f"/api/scans/{second['id']}/report.html?lang=en")
    html = body.decode()
    assert st == 200 and "Kashif Web Grade" in html and "Copy-paste fixes" in html and "Compared with the previous" in html
    assert '<script>alert("kashif-xss")' not in html and "<img src=x" not in html
    st, body = _call(ui, f"/api/scans/{second['id']}/report.md?lang=ar")
    assert st == 200 and "تغطية الفحوص" in body.decode()
    st, body = _call(ui, f"/api/scans/{second['id']}/report.json")
    doc = json.loads(body)
    assert doc["web"]["snapshot"]["checks"] and doc["web"]["diff"]["comparable"] is True
    st, body = _call(ui, f"/api/scans/{second['id']}/report.sarif?lang=en")
    sarif = json.loads(body)
    assert sarif["runs"][0]["properties"]["grades"]["kashif"]["grade"]
    assert all(r["properties"].get("precision") for r in sarif["runs"][0]["tool"]["driver"]["rules"])
    # the scan list stays small (no inventory or snapshot in the index)
    listed = _json(ui, "/api/scans")[1]
    assert all("web" not in s and "web_snapshot" not in s for s in listed)
    assert all(s["web_brief"]["kashif"]["grade"] for s in listed if s["id"] in (first["id"], second["id"]))


def test_web_view_of_a_source_scan_is_not_found(ui, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "a.py").write_text("x = 1\n", encoding="utf-8")
    _call(ui, "/api/settings", "POST", {"use_osv": False, "use_external": False})
    s = _scan(ui, str(proj))
    assert _call(ui, f"/api/scans/{s['id']}/web")[0] == 404
    assert "web" not in s and "web_options" not in s


def test_web_scan_still_needs_authorization(ui, site):
    status, body = _json(ui, "/api/scan", "POST", {"target": site, "profile": "deep"})
    assert status == 403 and body["error"] == "authorization required"


@pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
def test_panel_renders_hostile_text_escaped_under_node(ui, site):
    """Smoke test of the findings page's web panel: the real webPanelHTML/webDetailHTML code of app.js, run under
    Node.js with the view the server returns (and a finding whose evidence holds the site's hostile text)."""
    _call(ui, "/api/settings", "POST", {"web_delay": 0.2})
    first = _scan(ui, site, profile="minimal")
    Site.csp = "default-src 'self'"
    second = _scan(ui, site, profile="minimal")
    out = {}
    for lg in ("en", "ar"):
        out[lg] = _json(ui, f"/api/scans/{second['id']}/web?lang={lg}")[1]
    finding = next(f for f in second["findings"] if f["rule_id"] == "WEB011")
    prefix = JS[:JS.index("const sevName")]
    web = JS[JS.index("/* ------------------------------------------------------- web scan (1.1.0) */"):
             JS.index("/* -------------------------------------------------------------- triage */")]
    probe = prefix + """
;const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const ic = (name, cls = '') => `<svg class="i ${cls}"><use href="#i-${name}"/></svg>`;
const pill = (s) => `<span class="pill sev-${s}">${esc(s)}</span>`;
const copyBtn = (text) => `<button class="copy" data-copy="${esc(text)}"></button>`;
const $ = () => null; const $$ = () => [];
""" + JS[JS.index("const bidi = (text) =>"):JS.index("const ARABIC = /")] + web + """
const [vArg, fArg] = process.argv.slice(-2); const views = JSON.parse(vArg); const f = JSON.parse(fArg); const res = {};
for (const lg of ['en', 'ar']) { lang = lg; res[lg] = webPanelHTML(views[lg]); res[lg + '_detail'] = webDetailHTML(f); }
process.stdout.write(JSON.stringify(res));
"""
    r = subprocess.run([NODE, "-", json.dumps(out), json.dumps(finding)], input=probe, capture_output=True, text=True,
                       encoding="utf-8", timeout=60)
    assert r.returncode == 0, r.stderr
    got = json.loads(r.stdout)
    for key, html in got.items():
        assert "<script>alert" not in html and "<img src=x" not in html and "onerror=alert(1)>" not in html, key
    en, ar = got["en"], got["ar"]
    for needle in ("Grades", "Kashif Web Grade", "Check coverage", "Site inventory", "Copy-paste fixes",
                   "Compared with the previous scan", 'class="wtabs" data-wtabs="inv"', 'data-wtabs="rem0"',
                   'role="tab"', 'role="tabpanel"'):
        assert needle in en, needle
    assert "الدرجات" in ar and "جرد الموقع" in ar and "إصلاحات جاهزة للنسخ" in ar
    assert not ARABIC.search(en)
    assert "&lt;script&gt;" in got["en_detail"] or "curl" in got["en_detail"]
    assert first["id"] != second["id"]
