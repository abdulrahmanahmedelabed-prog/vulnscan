"""Gap-closing features: models-as-data, entry points, barrier guards, flow paths, resolution."""
import json
import pathlib

from vulnscan.taint import analyze, analyze_project


def ids(findings):
    return {f.rule_id for f in findings}


def by_line(findings):
    return {f.line: f.rule_id for f in findings}


def test_flask_route_params_are_sources():
    code = (
        "import os\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/u/<name>')\n"
        "def user(name):\n"
        "    os.system('id ' + name)\n"
        "def helper(name):\n"
        "    os.system('id ' + name)\n"
    )
    f = analyze("a.py", code)
    assert by_line(f).get(6) == "DF002"      # routed param is a source
    assert 8 not in by_line(f)               # plain function param is not


def test_fastapi_and_class_based_view_params():
    code = (
        "import os\n"
        "@router.get('/x')\n"
        "async def x(q: str):\n"
        "    os.system(q)\n"
        "class V(View):\n"
        "    def post(self, request, pk):\n"
        "        os.system(pk)\n"
        "class NotAView:\n"
        "    def post(self, pk):\n"
        "        os.system(pk)\n"
    )
    bl = by_line(analyze("a.py", code))
    assert bl.get(4) == "DF002" and bl.get(7) == "DF002" and 10 not in bl


def test_barrier_guard_membership_and_regex():
    code = (
        "import os, re\n"
        "ALLOWED = {'ls', 'id'}\n"
        "def a(request):\n"
        "    c = request.args['c']\n"
        "    if c in ALLOWED:\n"
        "        os.system(c)\n"              # guarded -> clean
        "    os.system(c)\n"                  # not guarded -> flagged
        "def b(request):\n"
        "    c = request.args['c']\n"
        "    if re.fullmatch(r'[a-z]+', c):\n"
        "        os.system(c)\n"              # guarded
        "def d(request):\n"
        "    c = request.args['c']\n"
        "    if not c.isalnum():\n"
        "        return 'bad'\n"
        "    os.system(c)\n"                  # early-return guard -> clean
    )
    bl = by_line(analyze("a.py", code))
    assert 6 not in bl and bl.get(7) == "DF002" and 11 not in bl and 16 not in bl


def test_guard_inside_helper_does_not_propagate_sink():
    code = (
        "import os\n"
        "def run(c):\n"
        "    if c in ('ls', 'id'):\n"
        "        os.system(c)\n"
        "def view(request):\n"
        "    run(request.args['c'])\n"
    )
    assert analyze("a.py", code) == []


def test_flow_path_steps_across_files():
    files = {
        "io_mod.py": "from flask import request\ndef read_name():\n    return request.args['name']\n",
        "exec_mod.py": "import os\ndef run(cmd):\n    os.system(cmd)\n",
        "views.py": "from io_mod import read_name\nfrom exec_mod import run\ndef handler():\n    n = read_name()\n    run(n)\n",
    }
    f = [x for x in analyze_project(files) if x.rule_id == "DF002"]
    assert f and f[0].file == "views.py" and f[0].line == 5
    path = f[0].extra["path"]
    files_in_path = [st["file"] for st in path]
    assert "io_mod.py" in files_in_path          # the return in the source helper
    assert "views.py" in files_in_path           # the assignment / call site
    assert files_in_path[-1] == "exec_mod.py"    # the deep sink
    assert path[-1]["line"] == 3


def test_import_alias_canonicalisation_ssrf():
    code = (
        "import requests as rq\n"
        "import urllib.request as ur\n"
        "def view(request):\n"
        "    rq.get(request.args['url'])\n"
        "    ur.urlopen(request.args['url'])\n"
        "    rq.get('https://fixed.example')\n"
    )
    bl = by_line(analyze("a.py", code))
    assert bl.get(4) == "DF010" and bl.get(5) == "DF010" and 6 not in bl


def test_relative_import_resolution():
    files = {
        "pkg/__init__.py": "",
        "pkg/util.py": "import os\ndef run(c):\n    os.system(c)\n",
        "pkg/views.py": "from .util import run\ndef v(request):\n    run(request.args['c'])\n",
    }
    f = [x for x in analyze_project(files) if x.rule_id == "DF002"]
    assert f and f[0].file == "pkg/views.py"


def test_varargs_wrapper_and_function_alias_and_partial():
    code = (
        "import os, functools\n"
        "def run(*parts):\n"
        "    os.system(' '.join(parts))\n"
        "def view(request):\n"
        "    run('echo', request.args['x'])\n"      # through *args
        "    h = run\n"
        "    h(request.args['x'])\n"                # function value
        "    p = functools.partial(run, 'echo')\n"
        "    p(request.args['x'])\n"                # partial
    )
    bl = by_line(analyze("a.py", code))
    assert bl.get(5) == "DF002" and bl.get(7) == "DF002" and bl.get(9) == "DF002"


def test_reflected_return_from_entry_point():
    code = (
        "from flask import render_template\n"
        "@app.route('/a')\n"
        "def a(request):\n"
        "    return 'Hello ' + request.args['n']\n"           # reflected
        "@app.route('/b')\n"
        "def b(request):\n"
        "    return render_template('x.html', n=request.args['n'])\n"  # auto-escaped template
        "def c(request):\n"
        "    return 'Hello ' + request.args['n']\n"           # not an entry point
    )
    bl = by_line(analyze("a.py", code))
    assert bl.get(4) == "DF013" and 7 not in bl and 9 not in bl


def test_shell_string_sink_getoutput_and_arg_injection_split():
    code = (
        "import subprocess as sp\n"
        "def view(request):\n"
        "    sp.getoutput('ls ' + request.args['p'])\n"      # shell string -> DF002
        "    sp.run(['ls', request.args['p']])\n"             # fixed program -> DF009
    )
    bl = by_line(analyze("a.py", code))
    assert bl.get(3) == "DF002" and bl.get(4) == "DF009"


def test_user_models_add_sink_and_sanitizer(tmp_path: pathlib.Path):
    models = {
        "sinks": [{"rule": "DF901", "severity": "high", "cwe": "CWE-999", "label": "my.dangerous",
                   "names": ["mylib.dangerous"], "title": "custom sink", "title_ar": "نقطة خطر مخصصة",
                   "advice": "لا تفعل.", "args": [0]}],
        "sanitizers": ["mylib.clean"],
    }
    (tmp_path / "m.json").write_text(json.dumps(models))
    code = (
        "import mylib\n"
        "def view(request):\n"
        "    mylib.dangerous(request.args['x'])\n"            # custom sink
        "    mylib.dangerous(mylib.clean(request.args['x']))\n"  # custom sanitizer
    )
    bl = by_line(analyze("a.py", code, models_dirs=[str(tmp_path)]))
    assert bl.get(3) == "DF901" and 4 not in bl
    assert "DF901" not in ids(analyze("a.py", code))           # not without the models dir


def test_new_builtin_sinks_dynamic_import_and_fs_ops():
    code = (
        "import importlib, shutil\n"
        "def view(request):\n"
        "    importlib.import_module(request.args['m'])\n"
        "    shutil.rmtree(request.args['d'])\n"
    )
    bl = by_line(analyze("a.py", code))
    assert bl.get(3) == "DF012" and bl.get(4) == "DF011"
