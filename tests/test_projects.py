"""Multi-project dashboard: the store's project index, the /api/projects endpoints and the UI wiring."""

import json
import pathlib
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from vulnscan.server import Handler
from vulnscan.store import Store, finding_key, project_id, project_key, project_name

UI = pathlib.Path(__file__).resolve().parents[1] / "vulnscan" / "ui"


def _finding(rule, file, sev="high", fp=None, snippet="x"):
    d = {"rule_id": rule, "severity": sev, "title": rule, "title_ar": rule, "file": file, "line": 1,
         "snippet": snippet, "advice": "", "cwe": "", "source": "vulnscan", "extra": {}}
    if fp:
        d["fingerprint"] = fp
    return d


def _scan(store, target, findings, *, kind="path", at=None, status="done", label=None):
    scan = store.new_scan(target, kind)
    summary = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        summary[f["severity"]] += 1
    at = at or time.time()
    scan.update(status=status, started_at=at, finished_at=at + 1, summary=summary, findings=findings, files_scanned=3)
    if label:
        scan["label"] = label
    store.save_scan(scan)
    return scan["id"]


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "home")


# ------------------------------------------------------------------ keys
def test_path_targets_are_normalized(tmp_path):
    base = str(tmp_path / "shop")
    keys = {project_key({"target": t, "kind": "path"}) for t in (base, base + "/", base + "/./", base + "/api/..")}
    assert len(keys) == 1
    assert project_key({"target": base + "2", "kind": "path"}) not in keys
    assert project_name({"target": base + "/./", "kind": "path"}) == "shop"


def test_url_targets_are_normalized():
    same = ["https://Example.com", "https://example.com/", "https://example.com:443/", "https://example.com/?q=1#top"]
    assert len({project_key({"target": t, "kind": "url"}) for t in same}) == 1
    other = ["http://example.com", "https://example.com:8443", "https://example.com/app", "https://example.org"]
    keys = {project_key({"target": t, "kind": "url"}) for t in same + other}
    assert len(keys) == 1 + len(other)
    assert project_name({"target": "https://example.com/app/", "kind": "url"}) == "example.com/app"


def test_uploads_group_by_label_not_by_temp_folder():
    a = {"target": "/tmp/vulnscan-upload-aaa/upload/app.zip", "kind": "upload", "label": "app.zip"}
    b = {"target": "/tmp/vulnscan-upload-bbb/upload/app.zip", "kind": "upload", "label": "app.zip"}
    c = {"target": "/tmp/vulnscan-upload-ccc/upload/other.zip", "kind": "upload", "label": "other.zip"}
    assert project_key(a) == project_key(b) != project_key(c)
    assert project_name(a) == "app.zip"


def test_project_id_is_stable_and_url_safe():
    pid = project_id("path:/srv/shop")
    assert pid == project_id("path:/srv/shop") and pid.isalnum() and len(pid) == 12
    assert pid != project_id("path:/srv/shop2")


def test_finding_key_prefers_fingerprint_and_falls_back():
    assert finding_key(_finding("R1", "a.py", fp="abc")) == "abc"
    old = _finding("R1", "app.zip!src/a.py", snippet="eval(x)")
    assert finding_key(old) == "R1|src/a.py|eval(x)"


# ----------------------------------------------------------------- store
def test_projects_group_trend_and_diff(store, tmp_path):
    shop, blog = str(tmp_path / "shop"), str(tmp_path / "blog")
    t0 = 1_700_000_000
    _scan(store, shop, [_finding("R1", "a.py", fp="f1"), _finding("R2", "a.py", "critical", fp="f2"),
                        _finding("R3", "b.py", "low", fp="f3")], at=t0)
    _scan(store, blog, [_finding("R1", "x.py", fp="g1")], at=t0 + 10)
    last = _scan(store, shop + "/", [_finding("R1", "a.py", fp="f1"), _finding("R4", "c.py", "medium", fp="f4")], at=t0 + 20)

    projects = store.list_projects()
    assert [p["name"] for p in projects] == ["shop", "blog"]          # most recently scanned first
    p = projects[0]
    assert p["scans"] == 2 and p["done_scans"] == 2 and p["latest"] == last
    assert p["summary"] == {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0} and p["total"] == 2
    assert (p["new"], p["fixed"], p["delta"]) == (1, 2, -1)
    assert [x["total"] for x in p["trend"]] == [3, 2]                # oldest first
    assert p["last_scan_at"] == t0 + 21
    one = projects[1]
    assert one["scans"] == 1 and one["new"] is None and one["fixed"] is None and one["previous"] is None

    full = store.get_project(p["id"])
    assert [f["fingerprint"] for f in full["new_findings"]] == ["f4"]
    assert sorted(f["fingerprint"] for f in full["fixed_findings"]) == ["f2", "f3"]
    assert [s["id"] for s in full["scans"]][0] == last and all("findings" not in s for s in full["scans"])
    assert store.get_project("nope") is None and store.get_project("../x") is None


def test_running_and_failed_scans_do_not_count_as_results(store, tmp_path):
    shop = str(tmp_path / "shop")
    _scan(store, shop, [_finding("R1", "a.py", fp="f1")], at=100)
    _scan(store, shop, [], at=200, status="error")
    p = store.list_projects()[0]
    assert p["scans"] == 2 and p["done_scans"] == 1 and p["total"] == 1
    assert p["last_scan"]["status"] == "error" and p["new"] is None
    assert len(p["trend"]) == 1


def test_scans_saved_by_older_versions_are_indexed(store, tmp_path):
    """A scan file written before projects existed (no fingerprints, no index) is grouped and diffed."""
    for i, findings in enumerate(([_finding("R1", "a.py", snippet="eval(a)"), _finding("R2", "a.py", snippet="exec(b)")],
                                  [_finding("R1", "a.py", snippet="eval(a)")])):
        scan = {"id": f"old{i}", "target": str(tmp_path / "legacy"), "kind": "path", "status": "done",
                "started_at": 100.0 + i, "finished_at": 101.0 + i, "files_scanned": 1, "notes": [],
                "summary": {"critical": 0, "high": len(findings), "medium": 0, "low": 0, "info": 0},
                "findings": findings, "error": None}
        (store.scans_dir / f"old{i}.json").write_text(json.dumps(scan), encoding="utf-8")
    assert not store.index_path.exists()
    (p,) = store.list_projects()
    assert p["name"] == "legacy" and p["scans"] == 2 and (p["new"], p["fixed"]) == (0, 1)
    assert store.index_path.exists()
    assert [s["id"] for s in store.list_scans()] == ["old1", "old0"]
    assert all("findings" not in s and s["project"] == p["id"] for s in store.list_scans())


def test_index_follows_changes_and_survives_corruption(store, tmp_path):
    shop = str(tmp_path / "shop")
    a = _scan(store, shop, [_finding("R1", "a.py", fp="f1")], at=100)
    b = _scan(store, shop, [_finding("R1", "a.py", fp="f1"), _finding("R2", "a.py", fp="f2")], at=200)
    assert store.list_projects()[0]["new"] == 1
    # a second Store on the same home (another process) reads the saved index
    again = Store(store.home)
    assert again.list_projects()[0]["new"] == 1
    # a scan rewritten on disk is re-read
    scan = store.get_scan(b)
    scan["findings"].append(_finding("R3", "a.py", fp="f3"))
    scan["summary"]["high"] = 3
    store.save_scan(scan)
    assert store.list_projects()[0]["new"] == 2 and again.list_projects()[0]["total"] == 3
    # deleting a scan removes it from its project; deleting the last one removes the project
    assert store.delete_scan(a)
    p = store.list_projects()[0]
    assert p["scans"] == 1 and p["new"] is None
    # a corrupt index or a stray file is ignored, not fatal
    store.index_path.write_text("{not json", encoding="utf-8")
    (store.scans_dir / "junk.json").write_text("[1, 2]", encoding="utf-8")
    assert Store(store.home).list_projects()[0]["scans"] == 1
    assert store.delete_scan(b) and store.list_projects() == []


def test_list_scans_filters_by_project(store, tmp_path):
    a = _scan(store, str(tmp_path / "one"), [], at=100)
    b = _scan(store, str(tmp_path / "two"), [], at=200)
    assert [s["id"] for s in store.list_scans()] == [b, a]
    pid = store.list_scans()[1]["project"]
    assert [s["id"] for s in store.list_scans(pid)] == [a]


def _write_raw(store, sid, target, findings, at, **extra):
    scan = {"id": sid, "target": target, "kind": "path", "status": "done", "started_at": at, "finished_at": at + 1,
            "files_scanned": 1, "notes": [], "error": None, "findings": findings,
            "summary": {"critical": 0, "high": len(findings), "medium": 0, "low": 0, "info": 0}, **extra}
    (store.scans_dir / f"{sid}.json").write_text(json.dumps(scan), encoding="utf-8")


def test_identical_legacy_findings_count_one_by_one(store, tmp_path):
    """Two old-style findings with the same rule, file and code are two findings: one disappearing is a fix."""
    twice = [_finding("R1", "a.py", snippet="eval(a)"), _finding("R1", "a.py", snippet="eval(a)")]
    _write_raw(store, "old0", str(tmp_path / "legacy"), twice, 100.0)
    _write_raw(store, "old1", str(tmp_path / "legacy"), twice[:1], 200.0)
    (p,) = store.list_projects()
    assert (p["new"], p["fixed"]) == (0, 1)
    full = store.get_project(p["id"])
    assert len(full["fixed_findings"]) == p["fixed"] and full["new_findings"] == []


def test_fingerprinted_scan_next_to_a_legacy_scan_is_not_all_new(store, tmp_path):
    target = str(tmp_path / "mixed")
    _write_raw(store, "old0", target, [_finding("R1", "a.py", snippet="eval(a)"), _finding("R2", "b.py", snippet="x")], 100.0)
    _write_raw(store, "new1", target, [_finding("R1", "a.py", fp="f1", snippet="eval(a)")], 200.0)
    (p,) = store.list_projects()
    assert (p["new"], p["fixed"]) == (0, 1)                            # compared by rule|file|code, not "1 new, 2 fixed"
    full = store.get_project(p["id"])
    assert full["new_findings"] == [] and [f["rule_id"] for f in full["fixed_findings"]] == ["R2"]


def test_counts_and_lists_agree_for_fingerprinted_scans(store, tmp_path):
    shop = str(tmp_path / "shop")
    _scan(store, shop, [_finding("R1", "a.py", fp=f"f{i}") for i in range(5)], at=100)
    _scan(store, shop, [_finding("R1", "a.py", fp=f"f{i}") for i in range(3, 9)], at=200)
    p = store.list_projects()[0]
    full = store.get_project(p["id"])
    assert (p["new"], p["fixed"]) == (4, 3) == (len(full["new_findings"]), len(full["fixed_findings"]))


def test_hostile_or_partial_scan_files_do_not_break_projects(store, tmp_path):
    target = str(tmp_path / "odd")
    _write_raw(store, "odd0", target, [_finding("R1", "a.py", fp="f1"), "junk", 3], 100.0, summary=["x"])
    _write_raw(store, "odd1", target, "not a list", 200.0, summary={"high": "many", "low": -4, "info": None})
    _write_raw(store, "odd2", target, [], 300.0, status="running", id="something-else")
    (p,) = store.list_projects()
    assert p["scans"] == 3 and p["done_scans"] == 2 and p["summary"] == dict.fromkeys(p["summary"], 0)
    assert p["last_scan"]["id"] == "odd2"                              # the file name is the id
    assert (p["new"], p["fixed"]) == (0, 1)
    assert store.get_project(p["id"])["fixed_findings"][0]["fingerprint"] == "f1"
    assert store.get_scan("../odd0") is None and store.get_scan("") is None


def test_index_written_by_the_previous_version_is_rebuilt(store, tmp_path):
    shop = str(tmp_path / "shop")
    _scan(store, shop, [_finding("R1", "a.py", fp="f1")], at=100)
    _scan(store, shop, [_finding("R1", "a.py", fp="f1"), _finding("R2", "a.py", fp="f2")], at=200)
    store.list_projects()                                             # writes the index
    data = json.loads(store.index_path.read_text(encoding="utf-8"))
    for e in data["scans"].values():                                  # the 0.9 index layout: no legacy keys
        e.pop("lks"), e.pop("fp_all")
    data["version"] = 1
    store.index_path.write_text(json.dumps(data), encoding="utf-8")
    again = Store(store.home)
    assert again.list_projects()[0]["new"] == 1
    assert json.loads(store.index_path.read_text(encoding="utf-8"))["version"] == 2


# ------------------------------------------------------------------- API
@pytest.fixture
def server(tmp_path):
    Handler.store = Store(tmp_path / "home")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _get(base, path):
    try:
        with urllib.request.urlopen(base + path) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _post_scan(base, target):
    req = urllib.request.Request(base + "/api/scan", data=json.dumps({"target": target}).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Origin": base})
    with urllib.request.urlopen(req) as r:
        sid = json.loads(r.read())["id"]
    for _ in range(400):
        s = _get(base, f"/api/scans/{sid}")[1]
        if s["status"] != "running":
            return s
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def test_projects_api_end_to_end(server, tmp_path):
    Handler.store.save_settings({"use_osv": False, "use_external": False})
    assert _get(server, "/api/projects") == (200, [])
    proj = tmp_path / "svc"
    proj.mkdir()
    (proj / "app.py").write_text("import hashlib\n\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n", encoding="utf-8")
    first = _post_scan(server, str(proj))
    assert first["status"] == "done" and first["findings"]
    # the vulnerable file is fixed and another weakness is introduced
    (proj / "app.py").write_text("import hashlib\nimport subprocess\n\n\ndef digest(data):\n    return hashlib.sha256(data).hexdigest()\n\n\n"
                                 "def run(cmd):\n    return subprocess.run('ls ' + cmd, shell=True)\n", encoding="utf-8")
    second = _post_scan(server, str(proj) + "/")
    other = tmp_path / "clean"
    other.mkdir()
    (other / "ok.py").write_text("print('hello')\n", encoding="utf-8")
    _post_scan(server, str(other))

    status, projects = _get(server, "/api/projects")
    assert status == 200 and {p["name"] for p in projects} == {"svc", "clean"}
    svc = next(p for p in projects if p["name"] == "svc")
    assert svc["scans"] == 2 and svc["latest"] == second["id"] and svc["previous"] == first["id"]
    old = {f["fingerprint"] for f in first["findings"]}
    new = {f["fingerprint"] for f in second["findings"]}
    assert svc["new"] == len(new - old) > 0 and svc["fixed"] == len(old - new) > 0

    status, full = _get(server, f"/api/projects/{svc['id']}")
    assert status == 200 and len(full["scans"]) == 2
    assert {f["fingerprint"] for f in full["new_findings"]} == new - old
    assert {f["fingerprint"] for f in full["fixed_findings"]} == old - new
    assert _get(server, "/api/projects/doesnotexist")[0] == 404

    # the dashboard's project switcher: stats and scans of one project only
    stats = _get(server, f"/api/stats?project={svc['id']}")[1]
    assert stats["total_scans"] == 2 and stats["latest"]["id"] == second["id"]
    assert _get(server, "/api/stats")[1]["total_scans"] == 3
    assert len(_get(server, f"/api/scans?project={svc['id']}")[1]) == 2 and len(_get(server, "/api/scans")[1]) == 3


def test_dashboard_stats_survive_scans_with_missing_keys(server, tmp_path):
    store = Handler.store
    _write_raw(store, "old0", str(tmp_path / "legacy"), [_finding("R1", "a.py"), {"rule_id": "R9"}], 100.0)
    scan = json.loads((store.scans_dir / "old0.json").read_text(encoding="utf-8"))
    del scan["finished_at"], scan["summary"]
    (store.scans_dir / "old0.json").write_text(json.dumps(scan), encoding="utf-8")
    status, stats = _get(server, "/api/stats")
    assert status == 200 and stats["latest"]["id"] == "old0" and stats["trend"][0]["at"] == 100.0
    assert [r["rule_id"] for r in stats["top_rules"]] == ["R1"]
    status, projects = _get(server, "/api/projects")
    assert status == 200 and projects[0]["total"] == 0


def test_scan_attaches_suggested_fix(server, tmp_path):
    """The web UI's scans carry the same "fix" contract as the CLI's JSON: {description, description_ar, diff, edits}."""
    Handler.store.save_settings({"use_osv": False, "use_external": False})
    proj = tmp_path / "fixme"
    proj.mkdir()
    (proj / "app.py").write_text("import hashlib\n\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n", encoding="utf-8")
    (proj / "safe.py").write_text("import hashlib\n\n\ndef digest(data):\n    return hashlib.sha256(data).hexdigest()\n", encoding="utf-8")
    scan = _post_scan(server, str(proj))
    fixes = [f for f in scan["findings"] if f.get("fix")]
    assert fixes and all(f["file"] == "app.py" for f in fixes)            # the safe twin has nothing to fix
    fix = fixes[0]["fix"]
    assert set(fix) >= {"description", "description_ar", "diff", "edits"}
    assert "-    return hashlib.md5(data).hexdigest()" in fix["diff"] and "+    return hashlib.sha256(data).hexdigest()" in fix["diff"]
    assert not any(f["file"] == "safe.py" for f in scan["findings"])
    # reports rendered from the stored scan still work with the extra key
    with urllib.request.urlopen(f"{server}/api/scans/{scan['id']}/report.json") as r:
        assert r.status == 200


def test_projects_api_requires_loopback_host(server):
    req = urllib.request.Request(server + "/api/projects", headers={"Host": "attacker.example"})
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 403


# -------------------------------------------------------------------- UI
def _i18n_keys(js: str, lang: str) -> set[str]:
    import re
    start = js.index(f"\n  {lang}: {{")
    end = js.index("\n  },", start)
    return set(re.findall(r"'([a-z0-9]+\.[A-Za-z0-9_.]+)':", js[start:end]))


def test_ui_strings_exist_in_both_languages():
    js = (UI / "app.js").read_text(encoding="utf-8")
    ar, en = _i18n_keys(js, "ar"), _i18n_keys(js, "en")
    assert ar == en, sorted(ar ^ en)
    needed = {"nav.projects", "proj.title", "proj.newN", "proj.fixedN", "fix.title", "fix.copy",
              "reach.imported", "reach.not_imported", "reach.vulnerable_function_called"}
    assert needed <= en


def test_ui_html_uses_only_known_strings_and_icons():
    import re
    html = (UI / "index.html").read_text(encoding="utf-8")
    js = (UI / "app.js").read_text(encoding="utf-8")
    keys = _i18n_keys(js, "en")
    used = set(re.findall(r'data-i18n(?:-ph)?="([^"]+)"', html))
    assert used <= keys, sorted(used - keys)
    icons = set(re.findall(r'<symbol id="i-([a-z-]+)"', html))
    assert set(re.findall(r'href="#i-([a-z-]+)"', html)) <= icons
    assert set(re.findall(r"\bic\('([a-z-]+)'", js)) <= icons
    for needed in ('id="page-projects"', 'id="dash-project"', 'data-nav="projects"'):
        assert needed in html
    for needed in ("/api/projects", "data-patch", "reachability"):
        assert needed in js
