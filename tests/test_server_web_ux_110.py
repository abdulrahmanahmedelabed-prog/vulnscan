"""The UI server's web scans (vulnscan/server.py): the scan kind comes from the parsed URL scheme and a bad URL is
refused (never scanned as a path), progress and cancel, one running scan per target, failures explained, the delay
setting validated, and the extra keys of GET /api/scans/<id>/web. Offline: the UI and the sites listen on 127.0.0.1."""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from vulnscan import server as srv
from vulnscan.server import Handler
from vulnscan.store import Store

PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")


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


class Site(BaseHTTPRequestHandler):
    delay = 0.0

    def log_message(self, *a):
        pass

    def do_GET(self):
        time.sleep(self.delay)
        if self.path != "/":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"<!doctype html><html><head><title>t</title></head><body>hi</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(body)


class SlowSite(Site):
    delay = 0.8


def _start(handler):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


@pytest.fixture
def site():
    httpd = _start(Site)
    yield f"http://127.0.0.1:{httpd.server_address[1]}/"
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def slow_site():
    httpd = _start(SlowSite)
    yield f"http://127.0.0.1:{httpd.server_address[1]}/"
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def ui(tmp_path):
    Handler.store = Store(tmp_path / "home")
    httpd = _start(Handler)
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    _call(base, "/api/settings", "POST", {"web_delay": 0.2, "use_osv": False, "use_external": False})
    yield base
    httpd.shutdown()
    httpd.server_close()


def _call(base, path, method="GET", data=None):
    req = urllib.request.Request(base + path, method=method, data=json.dumps(data).encode() if data is not None else None,
                                 headers={"Content-Type": "application/json", "Origin": base})
    try:
        with urllib.request.urlopen(req) as r:          # noqa: S310 - the test's own server on 127.0.0.1
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _wait(ui, scan_id, until=lambda s: s["status"] != "running", timeout=60.0):
    end = time.time() + timeout
    while time.time() < end:
        s = _call(ui, f"/api/scans/{scan_id}")[1]
        if until(s):
            return s
        time.sleep(0.05)
    raise AssertionError(f"scan {scan_id} did not reach the state in {timeout} s: {s}")


# ------------------------------------------------------------------------------------------- kind of a target

def test_kind_comes_from_the_parsed_scheme():
    assert srv.url_kind("https://example.org/a") == "url" and srv.url_kind("HTTPS://Example.org") == "url"
    assert srv.url_kind("HtTp://127.0.0.1:8080/") == "url"
    for path in ("/home/me/proj", "C:\\Users\\me\\app.apk", "httpfoo", "http-server/src", "ftp://x.org/a",
                 "javascript:alert(1)", "http://", "https:///path", ""):
        assert srv.url_kind(path) == "path", path
    assert srv.normalise_url("HTTPS://Example.org/A?b=1") == "https://Example.org/A?b=1"


@pytest.mark.parametrize("target", ["ftp://example.org/", "javascript:alert(1)", "example.org", "/tmp", "http://",
                                    "file:///etc/passwd", "mailto:a@b.c"])
def test_a_url_request_with_a_bad_url_is_refused_and_never_a_path_scan(ui, target):
    status, body = _call(ui, "/api/scan", "POST", {"target": target, "kind": "url", "authorized": True})
    assert status == 400 and body == {"error": "invalid url"}
    assert _call(ui, "/api/scans")[1] == []                 # nothing was started


def test_an_upper_case_scheme_is_a_web_scan_not_a_path(ui):
    # 1.0 tested startswith("http"): "HTTPS://…" became a path scan of a file that does not exist
    status, body = _call(ui, "/api/scan", "POST", {"target": "HTTPS://Example.org/"})
    assert status == 403 and body["error"] == "authorization required"


def test_run_scan_never_scans_a_url_kind_as_a_path(tmp_path):
    store = Store(tmp_path / "h")
    scan = store.new_scan("ftp://example.org/", "url")
    srv.run_scan(store, scan, store.settings(), authorized=True)
    assert scan["status"] == "error" and scan["error"] == "invalid url"


def test_authorized_targets_are_compared_as_projects(ui, site):
    port = site.split(":")[2].rstrip("/")
    _call(ui, "/api/settings", "POST", {"authorized_targets": [f"HTTP://127.0.0.1:{port}"]})
    status, scan = _call(ui, "/api/scan", "POST", {"target": f"http://127.0.0.1:{port}/", "kind": "url", "profile": "minimal"})
    assert status == 202 and scan["kind"] == "url"
    assert _wait(ui, scan["id"])["status"] == "done"
    assert srv.authorized_target(f"https://127.0.0.1:{port}/", {"authorized_targets": [site]}) is False   # scheme differs


# ------------------------------------------------------------------------------- progress, cancel, one per target

def test_progress_cancel_and_one_running_scan_per_target(ui, slow_site):
    status, scan = _call(ui, "/api/scan", "POST", {"target": slow_site, "kind": "url", "authorized": True,
                                                   "profile": "standard"})
    assert status == 202
    running = _wait(ui, scan["id"], until=lambda s: (s.get("progress") or {}).get("step") not in (None, ""))
    p = running["progress"]
    assert running["status"] == "running" and p["budget"] == 45 and isinstance(p["requests"], int)
    assert p["label"] and p["label_en"] and p["label"] != p["label_en"]          # Arabic and English step names
    # the same normalised target while it runs: 409, nothing started
    status, body = _call(ui, "/api/scan", "POST", {"target": slow_site.upper().replace("HTTP", "http").rstrip("/"),
                                                   "kind": "url", "authorized": True})
    assert status == 409 and body["error"] == "scan already running" and body["scan"] == scan["id"]
    assert len(_call(ui, "/api/scans")[1]) == 1
    started = time.time()
    status, body = _call(ui, f"/api/scans/{scan['id']}/cancel", "POST", {})
    assert status == 202 and body["status"] == "cancelling"
    done = _wait(ui, scan["id"], timeout=30)
    assert done["status"] == "cancelled" and time.time() - started < 15
    assert done["findings"] == [] and "web" not in done and "web_snapshot" not in done and done["error"] is None
    assert _call(ui, f"/api/scans/{scan['id']}/cancel", "POST", {})[0] == 409          # not running any more
    assert _call(ui, "/api/scans/000000000000/cancel", "POST", {})[0] == 404
    assert _call(ui, "/api/scans/..%2f/cancel", "POST", {})[0] == 404
    # a cancelled scan is no baseline, and the target can be scanned again
    status, again = _call(ui, "/api/scan", "POST", {"target": slow_site, "kind": "url", "authorized": True,
                                                    "profile": "minimal"})
    assert status == 202
    again = _wait(ui, again["id"])
    assert again["status"] == "done" and again["web"]["compare"] == {"asked": True, "previous": False}


def test_an_unreachable_site_is_explained_with_the_raw_error_apart(ui):
    with socket.socket() as s:                       # a port nothing listens on
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    status, scan = _call(ui, "/api/scan", "POST", {"target": f"http://127.0.0.1:{port}/", "kind": "url",
                                                   "authorized": True, "profile": "minimal"})
    assert status == 202
    s = _wait(ui, scan["id"])
    assert s["status"] == "error" and s["error_raw"] and s["error_code"]
    assert s["error"].startswith("لم يُفحص الموقع") and s["error_en"].startswith("The site was not scanned")
    assert "Kashif settings" not in s["error_en"] or "--timeout" not in s["error_en"]     # surface "ui", not the CLI's options


# ------------------------------------------------------------------------------------------------ settings

@pytest.mark.parametrize("patch,field", [({"web_delay": 0.1}, "web_delay"), ({"web_delay": 0}, "web_delay"),
                                         ({"web_delay": "x"}, "web_delay"), ({"web_delay": True}, "web_delay"),
                                         ({"web_delay": 11}, "web_delay"), ({"web_timeout": 1}, "web_timeout"),
                                         ({"web_profile": "../x"}, "web_profile")])
def test_settings_refuse_out_of_range_values(ui, patch, field):
    before = _call(ui, "/api/settings")[1]
    status, body = _call(ui, "/api/settings", "POST", patch)
    assert status == 400 and body == {"error": "invalid setting", "fields": [field]}
    assert _call(ui, "/api/settings")[1] == before


def test_settings_accept_the_floor(ui):
    status, body = _call(ui, "/api/settings", "POST", {"web_delay": 0.2, "web_timeout": 5})
    assert status == 200 and body["web_delay"] == 0.2 and body["web_timeout"] == 5


# --------------------------------------------------------------------------------------- the web view's extras

def test_web_view_gives_requests_of_budget_compare_and_covered_notes(ui, site):
    status, scan = _call(ui, "/api/scan", "POST", {"target": site, "kind": "url", "authorized": True,
                                                   "profile": "minimal", "sensitivity": "strict"})
    first = _wait(ui, scan["id"])
    assert first["status"] == "done"
    v = _call(ui, f"/api/scans/{first['id']}/web?lang=en")[1]
    f = v["facts"]
    assert f["budget"] == 10 and f["core_requests"] >= 1 and f["sensitivity"] == "strict" and f["profile"] == "minimal"
    assert v["compare"] == {"asked": True, "previous": False}
    # no previous scan: the comparison panel says this scan becomes the baseline (report.web_view)
    assert v["diff"]["comparable"] is False and v["diff"].get("baseline") is True and "baseline" in v["diff"]["notes"][0]
    notes = first["notes_en"]
    assert 0 in v["notes_covered"] and notes[0].startswith("Passive scan, profile minimal")
    assert not any(notes[i].startswith(("Coverage:", "Grades:")) for i in range(len(notes)) if i not in v["notes_covered"])
    second = _wait(ui, _call(ui, "/api/scan", "POST", {"target": site, "kind": "url", "authorized": True,
                                                      "profile": "minimal"})[1]["id"])
    v2 = _call(ui, f"/api/scans/{second['id']}/web?lang=ar")[1]
    assert v2["compare"] == {"asked": True, "previous": True}
    assert v2["diff"]["comparable"] is True and isinstance(v2["diff"]["not_retested_rows"], list)
    assert v2["diff"]["not_retested"] == len(v2["diff"]["not_retested_rows"])
    off = _wait(ui, _call(ui, "/api/scan", "POST", {"target": site, "kind": "url", "authorized": True,
                                                   "profile": "minimal", "compare_previous": False})[1]["id"])
    assert _call(ui, f"/api/scans/{off['id']}/web?lang=en")[1]["diff"] is None


def test_not_retested_rows_are_filled_when_web_view_lacks_them():
    web = {"diff": {"findings": {"not_retested": [
        {"rule": "WEB062", "severity": "high", "title_en": "Exposed .git", "title_ar": "مجلد ‎.git‎ مكشوف",
         "reason": {"en": "deep profile only", "ar": "في النمط العميق فقط"}}, "junk"]}},
        "inventory": {"requests": {"core_requests": 7, "budget": 45}}, "sensitivity": "default"}
    v = srv._ui_web_view({"diff": {"comparable": True, "not_retested": 1}, "facts": {}}, web, {}, "ar")
    assert v["diff"]["not_retested"] == 1 and v["diff"]["not_retested_rows"] == [{"rule": "WEB062", "severity": "high", "title": "مجلد ‎.git‎ مكشوف",
                                          "reason": "في النمط العميق فقط"}]
    assert v["facts"] == {"core_requests": 7, "budget": 45, "sensitivity": "default"}
    assert v["compare"] == {"asked": False, "previous": False} and v["notes_covered"] == []
    # web_view's own keys win
    kept = srv._ui_web_view({"diff": {"not_retested": []}, "facts": {"budget": 1}, "compare": {"asked": True}}, web, {}, "en")
    assert kept["diff"]["not_retested"] == [] and "not_retested_rows" not in kept["diff"] and kept["facts"]["budget"] == 1 and kept["compare"] == {"asked": True}
