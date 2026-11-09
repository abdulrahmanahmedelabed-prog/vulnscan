import json
import pathlib
import threading
import time
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer

import pytest

from vulnscan.server import Handler, parse_multipart
from vulnscan.store import Store


@pytest.fixture
def server(tmp_path):
    Handler.store = Store(tmp_path / "home")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield base
    httpd.shutdown()


def call(base, path, method="GET", data=None, headers=None, raw=False):
    h = {"Content-Type": "application/json", "Origin": base, **(headers or {})}
    body = data if raw else (json.dumps(data).encode() if data is not None else None)
    req = urllib.request.Request(base + path, data=body, method=method, headers=h)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def wait_done(base, sid):
    for _ in range(100):
        s = json.loads(call(base, f"/api/scans/{sid}")[1])
        if s["status"] != "running":
            return s
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def test_static_and_meta(server):
    status, body = call(server, "/")
    assert status == 200 and b"<title>" in body and b"vulnscan" in body
    assert call(server, "/../pyproject.toml")[0] == 404
    assert json.loads(call(server, "/api/meta")[1])["version"]


def test_scan_path_and_reports(server, tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "a.py").write_text("import pickle\npickle.loads(data)\n")
    call(server, "/api/settings", "POST", {"use_osv": False, "use_external": False})
    status, body = call(server, "/api/scan", "POST", {"target": str(proj)})
    assert status == 202
    scan = wait_done(server, json.loads(body)["id"])
    assert scan["status"] == "done" and scan["summary"]["critical"] == 1
    assert scan["findings"][0]["rule_id"] == "DES001"
    for fmt in ("md", "json", "html"):
        st, rep = call(server, f"/api/scans/{scan['id']}/report.{fmt}")
        assert st == 200 and b"DES001" in rep
    stats = json.loads(call(server, "/api/stats")[1])
    assert stats["latest"]["id"] == scan["id"] and stats["top_rules"][0]["rule_id"] == "DES001"
    assert call(server, f"/api/scans/{scan['id']}", "DELETE")[0] == 200
    assert call(server, f"/api/scans/{scan['id']}")[0] == 404


def test_csrf_and_url_authorization(server):
    status, _ = call(server, "/api/scan", "POST", {"target": "/tmp"}, headers={"Origin": "http://evil.example"})
    assert status == 403
    status, _ = call(server, "/api/scan", "POST", {"target": "https://example.com"})
    assert status == 403


def _multipart(files):
    boundary = "XXboundaryXX"
    out = b""
    for name, data in files:
        out += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n").encode() + data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return out, f"multipart/form-data; boundary={boundary}"


def test_parse_multipart():
    body, ctype = _multipart([("a.py", b"x=1"), ("dir/b.js", b"eval(x)")])
    assert parse_multipart(body, ctype) == [("a.py", b"x=1"), ("dir/b.js", b"eval(x)")]


def test_upload_archive_and_loose_files(server, tmp_path):
    call(server, "/api/settings", "POST", {"use_osv": False, "use_external": False})
    zpath = tmp_path / "b.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("src/a.py", "import pickle\npickle.loads(data)\n")
    body, ctype = _multipart([("b.zip", zpath.read_bytes())])
    status, resp = call(server, "/api/upload", "POST", body, {"Content-Type": ctype}, raw=True)
    assert status == 202
    scan = wait_done(server, json.loads(resp)["id"])
    assert scan["status"] == "done" and scan["summary"]["critical"] == 1 and scan["label"] == "b.zip"
    assert not pathlib.Path(scan["tmp_root"]).exists()  # cleaned up

    body, ctype = _multipart([("x/app.js", b"el.innerHTML = user;\n"), ("../../etc/passwd", b"nope")])
    status, resp = call(server, "/api/upload", "POST", body, {"Content-Type": ctype}, raw=True)
    scan = wait_done(server, json.loads(resp)["id"])
    assert scan["status"] == "done" and scan["summary"]["high"] == 1
    assert scan["findings"][0]["file"] == "x/app.js"


def test_settings_roundtrip(server):
    status, body = call(server, "/api/settings", "POST", {"min_severity": "high", "bogus": 1})
    data = json.loads(body)
    assert data["min_severity"] == "high" and "bogus" not in data
    assert json.loads(call(server, "/api/settings")[1])["min_severity"] == "high"
