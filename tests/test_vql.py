"""VQL query language: parsing, evaluation, built-in queries, user queries, error handling."""
import pathlib

import pytest

from vulnscan.scanner import scan_path
from vulnscan.vql import Query, QueryError, build_database, run_queries
from vulnscan.taint import analyze_project_full


def test_parse_and_evaluate_operators():
    db = {"call": [
        {"id": 1, "name": "requests.get", "func": "get", "args": "u, verify=False", "kwargs": "verify=False", "line": 3, "file": "a.py", "nargs": 1},
        {"id": 2, "name": "requests.get", "func": "get", "args": "u", "kwargs": "", "line": 4, "file": "a.py", "nargs": 1},
        {"id": 3, "name": "os.system", "func": "system", "args": "c", "kwargs": "", "line": 5, "file": "a.py", "nargs": 1},
    ]}
    q = Query('// @id vql/t\n// @severity high\nfrom call c\nwhere (c.name matches "^requests\\\\." and c.kwargs contains "verify=False") or c.func in ("system", "popen")\nselect c, "hit " + c.name', "t.vql")
    rows = q.run(db)
    assert [r["c"]["id"] for r in rows] == [1, 3]
    f = q.findings(db)
    assert {x.line for x in f} == {3, 5} and f[0].rule_id == "vql/t" and f[0].severity == "high"
    assert f[0].snippet == "hit requests.get"


def test_joins_and_not_and_comparisons():
    db = {"func": [{"id": 1, "name": "v", "is_entry": True, "decorators": "route", "file": "a.py", "line": 1, "nparams": 2},
                   {"id": 2, "name": "w", "is_entry": False, "decorators": "", "file": "a.py", "line": 5, "nparams": 0}],
          "call": [{"id": 3, "name": "os.system", "in_func": "v", "file": "a.py", "line": 2},
                   {"id": 4, "name": "print", "in_func": "w", "file": "a.py", "line": 6}]}
    q = Query('from func f, call c\nwhere f.is_entry and c.in_func = f.name and not c.name = "print" and f.nparams >= 1\nselect c, "sink in entry " + f.name', "j.vql")
    rows = q.run(db)
    assert len(rows) == 1 and rows[0]["c"]["id"] == 3


def test_query_errors_are_reported_not_raised():
    with pytest.raises(QueryError):
        Query("from call c where select c", "bad.vql")


def test_builtin_queries_end_to_end(tmp_path: pathlib.Path):
    (tmp_path / "a.py").write_text(
        "import requests, yaml, jwt, random\n"
        "requests.get('https://x', verify=False)\n"
        "requests.get('https://x')\n"
        "data = yaml.load(open('f'))\n"
        "safe = yaml.load(open('f'), Loader=yaml.SafeLoader)\n"
        "jwt.decode(tok, options={'verify_signature': False})\n"
        "token = random.randint(0, 9)\n"
        "@app.route('/open')\n"
        "def open_view():\n"
        "    return 'x'\n"
        "@app.route('/safe')\n"
        "@login_required\n"
        "def safe_view():\n"
        "    return 'x'\n"
    )
    findings, _ = scan_path(tmp_path)
    vq = {(f.rule_id, f.line) for f in findings if f.source == "vql"}
    assert ("vql/tls-verify-disabled", 2) in vq and ("vql/tls-verify-disabled", 3) not in vq
    assert ("vql/yaml-load-without-loader", 4) in vq and ("vql/yaml-load-without-loader", 5) not in vq
    assert ("vql/jwt-weak-verification", 6) in vq
    assert ("vql/random-for-secret", 7) in vq
    assert ("vql/entry-point-without-auth", 9) in vq and ("vql/entry-point-without-auth", 13) not in vq


def test_user_query_over_flow_relation(tmp_path: pathlib.Path):
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "app.py").write_text("import os\ndef v(request):\n    os.system(request.args['c'])\n")
    qdir = tmp_path / "q"
    qdir.mkdir()
    (qdir / "cmd-flows.vql").write_text(
        "// @id vql/cmd-flows\n// @severity critical\n// @cwe CWE-78\n"
        "from flow f\nwhere f.rule = \"DF002\" and f.source contains \"request\"\n"
        "select f, \"Command injection from \" + f.source\n")
    (qdir / "broken.vql").write_text("from where select\n")
    notes = []
    findings, _ = scan_path(proj, notes=notes, query_paths=[str(qdir)])
    hits = [f for f in findings if f.rule_id == "vql/cmd-flows"]
    assert hits and hits[0].line == 3 and hits[0].severity == "critical" and "request.args" in hits[0].snippet
    assert any("broken.vql" in n for n in notes)


def test_js_query_and_database_fields():
    files = {"a.js": "setTimeout(\"alert(1)\", 10);\nsetTimeout(() => go(), 10);\n"}
    projects, flows = analyze_project_full(files)
    db = build_database(projects, flows)
    calls = [c for c in db["call"] if c["name"] == "setTimeout"]
    assert len(calls) == 2 and calls[0]["arg0"].startswith("'") or calls[0]["arg0"].startswith('"')
    findings, _ = run_queries(projects, flows)
    assert {(f.rule_id, f.line) for f in findings} == {("vql/js-settimeout-string", 1)}
