"""Inter-procedural, cross-file data-flow (taint) analysis tests."""
import pathlib

from vulnscan.scanner import scan_path
from vulnscan.taint import analyze, analyze_project


def ids(findings):
    return {f.rule_id for f in findings}


def test_multi_step_command_injection():
    code = ("import os\n"
            "def handler(request):\n"
            "    name = request.args['q']\n"
            "    cmd = 'echo ' + name\n"
            "    os.system(cmd)\n")
    f = analyze("a.py", code)
    assert "DF002" in ids(f)
    assert f[0].extra["analysis"] == "dataflow"
    assert "request.args" in f[0].snippet


def test_sql_injection_fstring():
    code = ("def view(request, cur):\n"
            "    uid = request.GET['id']\n"
            "    q = f\"SELECT * FROM users WHERE id={uid}\"\n"
            "    cur.execute(q)\n")
    assert "DF004" in ids(analyze("a.py", code))


def test_sanitized_is_not_flagged():
    code = ("import os, shlex\n"
            "def f(request):\n"
            "    name = shlex.quote(request.args['q'])\n"
            "    os.system('echo ' + name)\n")
    assert "DF002" not in ids(analyze("a.py", code))


def test_constant_sink_is_not_flagged():
    code = ("import os\n"
            "def f():\n"
            "    os.system('ls -la')\n"
            "    eval('1 + 1')\n")
    assert analyze("a.py", code) == []


def test_interprocedural_same_file_via_wrapper():
    # Caller passes untrusted data to a wrapper that reaches the sink.
    code = ("import os\n"
            "def run(cmd):\n"
            "    os.system(cmd)\n"
            "def view(request):\n"
            "    run(request.args['x'])\n")
    f = analyze("a.py", code)
    assert "DF002" in ids(f)
    hit = [x for x in f if x.rule_id == "DF002"][0]
    assert hit.extra.get("interprocedural") is True
    assert hit.extra.get("callee") == "run"
    assert hit.line == 5          # reported at the call site in view()


def test_interprocedural_returned_source():
    # A helper returns untrusted data; the caller sinks it.
    code = ("import os\n"
            "def get_q(request):\n"
            "    return request.args['q']\n"
            "def view(request):\n"
            "    eval(get_q(request))\n")
    assert "DF001" in ids(analyze("a.py", code))


def test_cross_file_flow():
    files = {
        "io_mod.py": "from flask import request\ndef read_name():\n    return request.args['name']\n",
        "exec_mod.py": "import os\ndef run(cmd):\n    os.system(cmd)\n",
        "views.py": "from io_mod import read_name\nfrom exec_mod import run\ndef handler():\n    run(read_name())\n",
    }
    f = analyze_project(files)
    df = [x for x in f if x.rule_id == "DF002"]
    assert df, "expected a cross-file command-injection finding"
    assert df[0].file == "views.py" and df[0].line == 4
    assert df[0].extra.get("interprocedural") is True


def test_cross_file_three_hops():
    files = {
        "src.py": "from flask import request\ndef taint():\n    return request.form['d']\n",
        "mid.py": "from src import taint\ndef wrap():\n    return taint()\n",
        "sink.py": "import pickle\nfrom mid import wrap\ndef load():\n    return pickle.loads(wrap())\n",
    }
    assert "DF006" in ids(analyze_project(files))


def test_integrated_via_scan_path(tmp_path: pathlib.Path):
    (tmp_path / "helpers.py").write_text(
        "from flask import request\ndef user_path():\n    return request.args['path']\n")
    (tmp_path / "app.py").write_text(
        "import os\nfrom helpers import user_path\ndef h():\n    os.system('cat ' + user_path())\n")
    findings, _ = scan_path(tmp_path)
    got = ids(findings)
    assert "DF002" in got
    assert any(f.source == "taint" and f.extra.get("interprocedural") for f in findings)


def test_syntax_error_is_safe():
    assert analyze("bad.py", "def (:\n  pass\n") == []
