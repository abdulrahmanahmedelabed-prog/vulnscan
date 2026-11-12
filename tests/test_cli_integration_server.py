"""1.0 JSON API of the local web UI (vulnscan/server.py): exports, compliance, attack surface, triage, fixes.

The new endpoints keep the server's protections: a loopback Host header, no cross-site requests
(Sec-Fetch-Site), and for the endpoints that write files a JSON body from the same origin.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from vulnscan.server import Handler
from vulnscan.store import Store

APP = '''import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/users")
def users():
    name = request.args.get("name")
    con = sqlite3.connect("x.db")
    cur = con.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return str(cur.fetchall())


@app.route("/run")
def run():
    os.system(request.args.get("cmd"))
    return "ok"
'''


@pytest.fixture
def server(tmp_path):
    Handler.store = Store(tmp_path / "home")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield base
    httpd.shutdown()
    httpd.server_close()


def call(base, path, method="GET", data=None, headers=None):
    h = {"Content-Type": "application/json", "Origin": base, **(headers or {})}
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(base + path, data=body, method=method, headers=h)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def jcall(base, path, method="GET", data=None, headers=None):
    status, body, _ = call(base, path, method, data, headers)
    return status, json.loads(body)


@pytest.fixture
def done_scan(server, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text(APP, encoding="utf-8")
    call(server, "/api/settings", "POST", {"use_osv": False, "use_external": False, "exclude": []})
    status, scan = jcall(server, "/api/scan", "POST", {"target": str(proj)})
    assert status == 202
    for _ in range(400):
        scan = jcall(server, f"/api/scans/{scan['id']}")[1]
        if scan["status"] != "running":
            break
        time.sleep(0.05)
    assert scan["status"] == "done", scan
    return scan, proj


def test_scan_findings_carry_fixes(done_scan):
    scan, _ = done_scan
    fixed = [f for f in scan["findings"] if f.get("fix")]
    assert fixed, "autofix.attach_fixes must run before to_dict"
    assert any(e["file"] == "app.py" for f in fixed for e in f["fix"]["edits"])


# ----------------------------------------------------------------------------------------------- exports

def test_export_formats_listed_in_both_languages(server):
    status, formats = jcall(server, "/api/export/formats")
    assert status == 200
    ids = {f["id"] for f in formats}
    assert {"gitlab-sast", "codeclimate", "defectdojo", "sonarqube", "junit", "csv", "asff"} <= ids
    assert all({"id", "name", "description", "ext", "mime", "needs"} <= set(f) for f in formats)
    ar = jcall(server, "/api/export/formats?lang=ar")[1]
    assert next(f for f in ar if f["id"] == "gitlab-sast")["name"].startswith("تقرير")


def test_export_download(server, done_scan):
    scan, _ = done_scan
    status, body, headers = call(server, f"/api/scans/{scan['id']}/export?format=gitlab-sast")
    assert status == 200
    assert headers["Content-Type"].startswith("application/json")
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Content-Disposition"] == f"attachment; filename*=UTF-8''kashif-{scan['id']}.json"
    doc = json.loads(body)
    assert doc["scan"]["type"] == "sast" and doc["vulnerabilities"]
    status, body, headers = call(server, f"/api/scans/{scan['id']}/export?format=junit&lang=ar")
    assert status == 200 and headers["Content-Disposition"].endswith(f"kashif-{scan['id']}.xml") and b"<testsuite" in body
    assert call(server, f"/api/scans/{scan['id']}/export?format=../../etc")[0] == 400
    assert call(server, f"/api/scans/{scan['id']}/export")[0] == 400
    status, err = jcall(server, f"/api/scans/{scan['id']}/export?format=asff")
    assert status == 400 and "aws_account_id" in err["error"]
    status, body, _ = call(server, f"/api/scans/{scan['id']}/export?format=asff&aws_account_id=123456789012"
                                   "&aws_region=eu-west-1")
    assert status == 200 and json.loads(body)
    assert call(server, "/api/scans/nosuchscan/export?format=csv")[0] == 404


def test_export_carries_triage_decisions(server, done_scan):
    scan, _ = done_scan
    fp = next(f["fingerprint"] for f in scan["findings"] if f["severity"] == "critical")
    assert jcall(server, "/api/triage/set", "POST", {"scan": scan["id"], "fingerprint": fp, "status": "false_positive",
                                                     "justification": "test", "author": "t"})[0] == 200
    doc = json.loads(call(server, f"/api/scans/{scan['id']}/export?format=gitlab-sast")[1])
    assert len(doc["vulnerabilities"]) == len(scan["findings"]) - 1


# ------------------------------------------------------------------------------------------- compliance

def test_compliance_summary_and_audit_report(server, done_scan):
    scan, _ = done_scan
    status, frameworks = jcall(server, "/api/compliance/frameworks?lang=ar")
    assert status == 200 and any(f["id"] == "owasp-top10-2021" for f in frameworks)
    status, doc = jcall(server, f"/api/scans/{scan['id']}/compliance?framework=owasp,pci&lang=en")
    assert status == 200 and doc["schema"] == "kashif-compliance/1"
    assert set(doc["frameworks"]) == {"owasp-top10-2021", "pci-dss-4.0"}
    assert jcall(server, f"/api/scans/{scan['id']}/compliance?framework=nope")[0] == 400
    status, body, headers = call(server, f"/api/scans/{scan['id']}/audit.html?lang=ar")
    assert status == 200 and headers["Content-Type"].startswith("text/html")
    assert "default-src 'none'" in headers["Content-Security-Policy"] and headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Content-Disposition"].endswith(f"kashif-{scan['id']}-audit.html") and b"<script" not in body.lower()


# ---------------------------------------------------------------------------------------- attack surface

def test_attack_surface_job(server, done_scan):
    scan, _ = done_scan
    sid = scan["id"]
    status, doc = jcall(server, f"/api/scans/{sid}/surface")
    assert status == 404 and doc == {"status": "none", "scan": sid, "available": True}
    # starting a build writes a file: JSON only, same origin only
    assert call(server, f"/api/scans/{sid}/surface", "POST", {}, headers={"Content-Type": "text/plain"})[0] == 403
    assert call(server, f"/api/scans/{sid}/surface", "POST", {}, headers={"Origin": "http://evil.example"})[0] == 403
    status, doc = jcall(server, f"/api/scans/{sid}/surface", "POST", {"engine": True})
    assert status == 202 and doc["status"] == "running"
    for _ in range(600):
        status, doc = jcall(server, f"/api/scans/{sid}/surface")
        if doc["status"] != "running":
            break
        time.sleep(0.05)
    assert status == 200 and doc["status"] == "done", doc
    paths = {e["path"]: e for e in doc["surface"]["entries"]}
    assert {"/users", "/run"} <= set(paths) and paths["/run"]["reaches_sink"]
    assert doc["mermaid"].startswith("flowchart") and json.loads(doc["openapi"])["openapi"].startswith("3.1")
    ar = jcall(server, f"/api/scans/{sid}/surface?lang=ar")[1]
    assert ar["status"] == "done"
    proj = jcall(server, "/api/projects")[1][0]["id"]
    assert jcall(server, f"/api/projects/{proj}/surface")[1]["scan"] == sid
    # deleting the scan deletes its cached map
    assert call(server, f"/api/scans/{sid}", "DELETE")[0] == 200
    assert jcall(server, f"/api/scans/{sid}/surface")[0] == 404


def test_attack_surface_needs_a_local_source(server, done_scan, tmp_path):
    import shutil
    scan, proj = done_scan
    shutil.rmtree(proj)
    assert jcall(server, f"/api/scans/{scan['id']}/surface", "POST", {})[0] == 409


# ------------------------------------------------------------------------------------------------ triage

def test_triage_set_comment_severity_and_list(server, done_scan):
    scan, proj = done_scan
    sid = scan["id"]
    fp = next(f["fingerprint"] for f in scan["findings"] if f["severity"] == "critical")
    status, doc = jcall(server, f"/api/triage?scan={sid}")
    assert status == 200 and doc["in_project"] is True and doc["findings"] == {}
    assert [s["id"] for s in doc["statuses"]][:2] == ["open", "confirmed"]
    assert doc["annotations"][fp]["status"] == "open"
    # a decision that needs a justification
    status, err = jcall(server, "/api/triage/set", "POST", {"scan": sid, "fingerprint": fp, "status": "false_positive"})
    assert status == 400 and err["error"] and err["error_ar"]
    status, doc = jcall(server, "/api/triage/set", "POST", {"scan": sid, "fingerprint": fp, "status": "accepted_risk",
                                                            "justification": "behind the VPN", "expires": "+30d",
                                                            "ticket": "https://tracker.example/T-1", "author": "alice"})
    assert status == 200 and doc["ok"] and doc["entry"]["status"] == "accepted_risk"
    saved = json.loads((proj / ".kashif" / "triage.json").read_text(encoding="utf-8"))   # the project's own file
    assert saved["findings"][fp]["author"] == "alice" and saved["findings"][fp]["rule"]
    assert jcall(server, "/api/triage/comment", "POST", {"scan": sid, "fingerprint": fp, "text": "ok", "author": "bob"})[0] == 200
    status, doc = jcall(server, "/api/triage/severity", "POST", {"scan": sid, "fingerprint": fp, "severity": "high",
                                                                 "reason": "not reachable from the internet"})
    assert status == 200 and doc["entry"]["severity_override"]["severity"] == "high"
    status, doc = jcall(server, f"/api/triage?scan={sid}&lang=ar")
    ann = doc["annotations"][fp]
    assert ann["status"] == "accepted_risk" and ann["comments"] == 1 and ann["severity_original"] == "critical"
    assert doc["stats"]["by_status"]["accepted_risk"] == 1
    proj_id = jcall(server, "/api/projects")[1][0]["id"]
    assert jcall(server, f"/api/triage?project={proj_id}")[1]["scan"] == sid


def test_triage_requests_are_validated(server, done_scan):
    scan, proj = done_scan
    sid = scan["id"]
    fp = scan["findings"][0]["fingerprint"]
    ok = {"scan": sid, "fingerprint": fp, "status": "confirmed", "author": "t"}
    assert jcall(server, "/api/triage/set", "POST", dict(ok, fingerprint="0123456789abcdef:0"))[0] == 404
    assert jcall(server, "/api/triage/set", "POST", dict(ok, scan="nosuchscan"))[0] == 404
    assert jcall(server, "/api/triage/set", "POST", dict(ok, status="bogus"))[0] == 400
    assert jcall(server, "/api/triage/set", "POST", dict(ok, ticket="javascript:alert(1)"))[0] == 400
    # the browser never chooses the file: a "path" in the body is ignored
    assert jcall(server, "/api/triage/set", "POST", dict(ok, path="/tmp/evil.json", file="/tmp/evil.json"))[0] == 200
    assert (proj / ".kashif" / "triage.json").is_file()
    # cross-site, non-JSON, foreign Host and oversized requests are refused
    assert call(server, "/api/triage/set", "POST", ok, headers={"Origin": "http://evil.example"})[0] == 403
    assert call(server, "/api/triage/set", "POST", ok, headers={"Content-Type": "text/plain"})[0] == 403
    assert call(server, "/api/triage/set", "POST", ok, headers={"Sec-Fetch-Site": "cross-site"})[0] == 403
    assert call(server, "/api/triage/set", "POST", ok, headers={"Host": "attacker.example"})[0] == 403
    big = dict(ok, justification="x" * (1024 * 1024 + 10))
    try:
        status = call(server, "/api/triage/set", "POST", big)[0]
    except (ConnectionError, urllib.error.URLError):          # refused before the whole body was sent
        status = 413
    assert status == 413
    assert call(server, "/api/triage/set", "POST", None, headers={"Content-Length": "0"})[0] == 404   # {} -> no scan


def test_new_get_endpoints_refuse_cross_site_and_rebinding(server, done_scan):
    scan, _ = done_scan
    for path in (f"/api/scans/{scan['id']}/export?format=csv", f"/api/scans/{scan['id']}/compliance",
                 f"/api/scans/{scan['id']}/audit.html", f"/api/scans/{scan['id']}/surface",
                 f"/api/triage?scan={scan['id']}", "/api/export/formats", "/api/compliance/frameworks"):
        assert call(server, path, headers={"Sec-Fetch-Site": "cross-site"})[0] == 403, path
        assert call(server, path, headers={"Host": "attacker.example:80"})[0] == 403, path
        assert call(server, path, headers={"Sec-Fetch-Site": "same-origin"})[0] in (200, 404), path


def test_triage_of_an_upload_lives_in_the_store(server, tmp_path):
    import zipfile
    arc = tmp_path / "app.zip"
    with zipfile.ZipFile(arc, "w") as z:
        z.writestr("app.py", APP)
    boundary = "XXboundaryXX"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"app.zip\"\r\n"
            "Content-Type: application/zip\r\n\r\n").encode() + arc.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    call(server, "/api/settings", "POST", {"use_osv": False, "use_external": False})
    req = urllib.request.Request(server + "/api/upload", data=body, method="POST",
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "Origin": server})
    with urllib.request.urlopen(req) as r:
        scan = json.loads(r.read())
    for _ in range(400):
        scan = jcall(server, f"/api/scans/{scan['id']}")[1]
        if scan["status"] != "running":
            break
        time.sleep(0.05)
    fp = scan["findings"][0]["fingerprint"]
    status, doc = jcall(server, "/api/triage/set", "POST", {"scan": scan["id"], "fingerprint": fp, "status": "confirmed",
                                                            "author": "t"})
    assert status == 200 and doc["file"].startswith(str(Handler.store.home / "triage"))
    assert jcall(server, f"/api/triage?scan={scan['id']}")[1]["in_project"] is False
    assert jcall(server, f"/api/scans/{scan['id']}/surface", "POST", {})[0] == 409      # no source tree left
