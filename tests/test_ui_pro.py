"""The 1.0 views of the local web UI (vulnscan/ui): fixes, exports, compliance, attack surface and triage.

Static checks on the UI files (strings in both languages, icons, endpoints, escaping rules), plus contract tests
that the JSON the UI reads from the server has the fields app.js uses.
"""

from __future__ import annotations

import json
import pathlib
import re
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from vulnscan.server import Handler
from vulnscan.store import Store

UI = pathlib.Path(__file__).resolve().parents[1] / "vulnscan" / "ui"
JS = (UI / "app.js").read_text(encoding="utf-8")
HTML = (UI / "index.html").read_text(encoding="utf-8")
CSS = (UI / "styles.css").read_text(encoding="utf-8")


def _keys(lang: str) -> dict[str, str]:
    start = JS.index(f"\n  {lang}: {{")
    end = JS.index("\n  },", start)
    return dict(re.findall(r"'([a-z0-9]+\.[A-Za-z0-9_.]+)': '((?:[^'\\]|\\.)*)'", JS[start:end]))


AR, EN = _keys("ar"), _keys("en")
ARABIC = re.compile(r"[؀-ۿ]")


def test_new_strings_exist_in_both_languages():
    assert set(AR) == set(EN), sorted(set(AR) ^ set(EN))
    for prefix in ("tri.", "comp.", "sf.", "exp."):
        keys = [k for k in EN if k.startswith(prefix)]
        assert len(keys) >= 5, prefix
        for k in keys:
            assert AR[k] and EN[k], k
            assert not ARABIC.search(EN[k]), (k, EN[k])
    # every Arabic string of the new views is Arabic (except names such as "OpenAPI")
    for k in AR:
        if k.startswith(("tri.", "comp.", "sf.", "exp.")) and k not in ("sf.openapi", "tri.by"):
            assert ARABIC.search(AR[k]), (k, AR[k])
    assert {"nav.compliance", "tri.showFp", "fix.badge", "fix.copy", "comp.audit", "sf.title"} <= set(EN)


def test_placeholders_match_between_languages():
    for k in EN:
        assert sorted(re.findall(r"\{(\w+)\}", EN[k])) == sorted(re.findall(r"\{(\w+)\}", AR[k])), k


def test_every_t_key_used_in_js_exists():
    used = set(re.findall(r"\bt\('([a-z0-9]+\.[A-Za-z0-9_.]+)'", JS))
    dynamic_prefixes = ("tri.act.", "comp.st_", "comp.r_", "sf.auth_", "upd.", "reach.")
    missing = {k for k in used if k not in EN and not k.startswith(dynamic_prefixes)}
    assert not missing, sorted(missing)
    for st in ("fail", "warn", "pass"):
        assert f"comp.st_{st}" in EN
    for r in ("none", "low", "moderate", "high", "critical"):
        assert f"comp.r_{r}" in EN
    for a in ("none", "public", "protected"):
        assert f"sf.auth_{a}" in EN
    for act in ("status", "comment", "severity", "expired", "regression", "auto"):
        assert f"tri.act.{act}" in EN


def test_control_without_findings_is_never_called_pass():
    assert EN["comp.st_pass"] == "No findings"
    assert AR["comp.st_pass"] == "لا نتائج"
    assert not any(v.strip().lower() in ("pass", "passed", "compliant") for v in EN.values())


def test_icons_and_i18n_attributes_resolve():
    icons = set(re.findall(r'<symbol id="i-([a-z-]+)"', HTML))
    assert {"compliance", "surface", "flag", "lock", "unlock", "wrench"} <= icons
    assert set(re.findall(r"\bic\('([a-z-]+)'", JS)) <= icons
    assert set(re.findall(r'href="#i-([a-z-]+)"', HTML + JS)) <= icons
    used = set(re.findall(r'data-i18n(?:-ph)?="([^"]+)"', HTML))
    assert used <= set(EN), sorted(used - set(EN))


def test_views_are_wired_to_the_1_0_endpoints():
    for needle in ("/api/export/formats", "/export?lang=", "/compliance?framework=all", "/audit.html?framework=",
                   "/api/triage?scan=", "/api/triage/", "/surface", "report.${x}", "'sarif'"):
        assert needle in JS, needle
    assert 'data-nav="compliance"' in HTML and 'id="page-compliance"' in HTML
    for el in ("export-btn", "export-menu", "triage-filter", "fix-filter", "show-fp", "fw-grid", "sf-card", "dl-sarif"):
        assert f'id="{el}"' in HTML, el
    assert "compliance: loadCompliance" in JS


def test_about_section_and_update_button_kept():
    assert "sdep@iugaza.edu.ps" in HTML
    assert 'data-i18n="about.by"' in HTML
    assert "الجامعة الإسلامية بغزة" in AR["about.by"] and "Islamic University of Gaza" in EN["about.by"]
    assert "Programming Department" in EN["about.by"]
    assert 'id="upd-check"' in HTML and 'id="upd-pill"' in HTML


def test_no_external_resources_or_new_network_destinations():
    # stylesheets, scripts, fonts and images are local; links to other sites only open on a click
    assert not re.search(r"<(?:script|link|img)[^>]+(?:src|href)=\"https?://", HTML)
    assert not re.search(r"url\((?!\"?data:)", CSS)
    assert "@import" not in CSS
    # fetch() only talks to this server
    for m in re.finditer(r"fetch\(([^,)]+)", JS):
        arg = m.group(1).strip()
        assert not arg.startswith(("'http", '"http', "`http")), arg
    hosts = set(re.findall(r"https://([a-z0-9.-]+)", JS))
    assert hosts <= {"cwe.mitre.org", "github.com"}, hosts


def test_triage_data_is_escaped_and_looked_up_safely():
    # fingerprints from the repository (e.g. "constructor") are looked up in Maps, never as object keys
    assert "tri.ann = new Map()" in JS and "tri.raw = new Map()" in JS
    assert "annotations[" not in JS and ".findings[fp" not in JS
    # the only innerHTML write goes through setHTML (callers escape with esc()/bidi())
    assert len(re.findall(r"\.innerHTML\s*=", JS)) == 1
    # ticket links: http(s) only, opened without an opener or referrer
    assert "isHttp(raw.ticket)" in JS
    assert 'rel="noopener noreferrer"' in JS
    # the triage section escapes justification, comments and authors
    sec = JS[JS.index("function triageHTML"):JS.index("const triMsg")]
    assert "${raw." not in sec.replace("${esc(raw.", "").replace("${bidi(raw.", "")
    assert "bidi(raw.justification)" in sec and "esc(x.author" in sec and "esc(text)" in sec


def test_post_requests_send_json():
    # the 1.0 POST endpoints need Content-Type: application/json (apiRaw sets it) and a JSON body
    assert "headers: {'Content-Type': 'application/json'}" in JS
    for path in ("/api/triage/${action === 'comment' ? 'comment' : 'set'}", "/surface`, {method: 'POST'"):
        assert path in JS, path
    assert "JSON.stringify(body)" in JS and "JSON.stringify({engine})" in JS


def test_narrow_screen_rules_exist():
    phone = CSS[CSS.rindex("@media (max-width:720px)"):]
    for sel in (".menu{", ".toolbar-end{", ".sf-stats{", ".fw-grid{", ".tri-texts{", ".f-side{"):
        assert sel in phone, sel


# ------------------------------------------------------------------------------------- API contract

APP = '''import os
import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/run", methods=["POST"])
def run():
    os.system(request.form.get("cmd"))
    return "ok"


@app.route("/load")
def load():
    return str(yaml.load(request.args.get("doc"), Loader=yaml.Loader))
'''


@pytest.fixture
def server(tmp_path):
    Handler.store = Store(tmp_path / "home")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def _call(base, path, method="GET", data=None):
    req = urllib.request.Request(base + path, method=method, data=json.dumps(data).encode() if data is not None else None,
                                 headers={"Content-Type": "application/json", "Origin": base})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def _json(base, path, method="GET", data=None):
    status, body, _ = _call(base, path, method, data)
    return status, json.loads(body)


@pytest.fixture
def scan(server, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text(APP, encoding="utf-8")
    _call(server, "/api/settings", "POST", {"use_osv": False, "use_external": False, "exclude": []})
    status, s = _json(server, "/api/scan", "POST", {"target": str(proj)})
    assert status == 202
    for _ in range(400):
        s = _json(server, f"/api/scans/{s['id']}")[1]
        if s["status"] != "running":
            break
        time.sleep(0.05)
    assert s["status"] == "done", s
    return s


def test_sarif_report_download(server, scan):
    status, body, headers = _call(server, f"/api/scans/{scan['id']}/report.sarif?lang=en")
    assert status == 200
    assert headers["Content-Type"].startswith("application/sarif+json")
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Content-Disposition"].endswith(f"{scan['id']}.sarif")
    doc = json.loads(body)
    assert doc["version"] == "2.1.0" and doc["runs"][0]["results"]


def test_shapes_the_ui_reads(server, scan):
    sid = scan["id"]
    # fixes: description (both languages) and a diff
    fix = next(f["fix"] for f in scan["findings"] if f.get("fix"))
    assert {"description", "description_ar", "diff", "edits"} <= set(fix)
    # export menu
    status, formats = _json(server, "/api/export/formats?lang=ar")
    assert status == 200 and len(formats) >= 12
    assert all({"id", "name", "description", "ext", "needs"} <= set(f) for f in formats)
    assert any(f["needs"] for f in formats)          # asff needs an AWS account and region
    for f in formats:
        if not f["needs"]:
            status, _, headers = _call(server, f"/api/scans/{sid}/export?lang=en&format={f['id']}")
            assert status == 200, f["id"]
            assert f"kashif-{sid}." in headers["Content-Disposition"]
    # compliance
    status, comp = _json(server, f"/api/scans/{sid}/compliance?framework=all&lang=en")
    assert status == 200
    assert {"disclaimer", "risk", "frameworks", "findings"} <= set(comp)
    assert {"score", "rating"} <= set(comp["risk"])
    assert len(comp["frameworks"]) >= 8
    for fw in comp["frameworks"].values():
        assert {"title", "short", "status", "controls_total", "controls_with_findings", "findings_mapped",
                "findings_unmapped", "rows", "note", "source"} <= set(fw)
        assert fw["status"] in ("fail", "warn", "pass")
        for row in fw["rows"]:
            assert {"control", "title", "counts", "total", "status", "findings"} <= set(row)
    assert all({"id", "fingerprint", "severity", "title", "file", "line"} <= set(f) for f in comp["findings"])
    status, body, headers = _call(server, f"/api/scans/{sid}/audit.html?framework=owasp-top10-2021&lang=ar")
    assert status == 200 and headers["Content-Type"].startswith("text/html")
    # triage
    status, tri = _json(server, f"/api/triage?scan={sid}&lang=ar")
    assert status == 200
    assert [s["id"] for s in tri["statuses"]][:5] == ["open", "confirmed", "false_positive", "accepted_risk", "fixed"]
    assert all({"label_en", "label_ar"} <= set(s) for s in tri["statuses"])
    assert {"file", "in_project", "annotations", "findings"} <= set(tri)
    fp = scan["findings"][0]["fingerprint"]
    status, res = _json(server, "/api/triage/set", "POST", {"scan": sid, "fingerprint": fp, "status": "false_positive",
                                                          "justification": "constant input", "comment": "checked"})
    assert status == 200 and res["ok"]
    status, tri = _json(server, f"/api/triage?scan={sid}")
    assert tri["annotations"][fp]["status"] == "false_positive"
    entry = tri["findings"][fp]
    assert entry["justification"] == "constant input" and entry["author"] and entry["updated"]
    assert sorted(x["action"] for x in entry["log"]) == ["comment", "status"]
    status, res = _json(server, "/api/triage/set", "POST", {"scan": sid, "fingerprint": fp, "status": "accepted_risk"})
    assert status == 400 and res["error"] and res["error_ar"]          # justification required: shown as is
    # attack surface
    status, res = _json(server, f"/api/scans/{sid}/surface", "POST", {"engine": False})
    assert status == 202
    for _ in range(400):
        status, sf = _json(server, f"/api/scans/{sid}/surface?lang=ar")
        if sf.get("status") != "running":
            break
        time.sleep(0.05)
    assert sf["status"] == "done", sf
    summary = sf["surface"]["summary"]
    assert {"entries", "unauthenticated", "unauthenticated_reaching_sink", "with_findings"} <= set(summary)
    assert sf["surface"]["entries"]
    for e in sf["surface"]["entries"]:
        assert {"kind", "method", "path", "handler", "file", "line", "auth", "risk", "risk_level", "reasons",
                "sink_categories", "findings", "unauthenticated"} <= set(e)
        assert e["auth"]["status"] in ("none", "public", "protected")
    assert isinstance(sf["openapi"], str)
    pid = _json(server, "/api/projects")[1][0]["id"]          # the project view reads the latest scan's map
    status, psf = _json(server, f"/api/projects/{pid}/surface?lang=en")
    assert status == 200 and psf["status"] == "done" and psf["scan"] == sid
