"""Data-flow (taint) analysis tests."""
import pathlib

from vulnscan.scanner import scan_path
from vulnscan.taint import analyze


def ids(findings):
    return {f.rule_id for f in findings}


def test_multi_step_command_injection():
    code = (
        "import os\n"
        "def handler(request):\n"
        "    name = request.args['q']\n"
        "    cmd = 'echo ' + name\n"
        "    os.system(cmd)\n"
    )
    f = analyze("a.py", code)
    assert "DF002" in ids(f)
    assert f[0].extra["analysis"] == "dataflow"
    assert "request.args" in f[0].snippet


def test_sql_injection_fstring():
    code = (
        "def view(request, cur):\n"
        "    uid = request.GET['id']\n"
        "    q = f\"SELECT * FROM users WHERE id={uid}\"\n"
        "    cur.execute(q)\n"
    )
    assert "DF004" in ids(analyze("a.py", code))


def test_eval_and_pickle_and_redirect():
    code = (
        "import pickle\n"
        "def f(request):\n"
        "    data = request.form['d']\n"
        "    eval(data)\n"
        "    pickle.loads(request.data)\n"
        "    redirect(request.args['next'])\n"
    )
    got = ids(analyze("a.py", code))
    assert {"DF001", "DF006", "DF008"} <= got


def test_sanitized_is_not_flagged():
    code = (
        "import os, shlex\n"
        "def f(request):\n"
        "    name = shlex.quote(request.args['q'])\n"
        "    os.system('echo ' + name)\n"
    )
    # shlex.quote neutralizes the taint -> no command-injection finding.
    assert "DF002" not in ids(analyze("a.py", code))


def test_constant_sink_is_not_flagged():
    code = (
        "import os\n"
        "def f():\n"
        "    os.system('ls -la')\n"
        "    eval('1 + 1')\n"
    )
    assert analyze("a.py", code) == []


def test_integrated_via_scan_path(tmp_path: pathlib.Path):
    (tmp_path / "app.py").write_text(
        "import os\n"
        "def h(request):\n"
        "    p = request.args['path']\n"
        "    open(p).read()\n"
        "    os.system('cat ' + p)\n"
    )
    findings, _ = scan_path(tmp_path)
    got = ids(findings)
    assert "DF005" in got and "DF002" in got
    assert any(f.source == "taint" for f in findings)


def test_syntax_error_is_safe():
    assert analyze("bad.py", "def (:\n  pass\n") == []
