"""Real vulnerabilities that an independent adversarial review showed the 0.7 precision work had hidden.

Each file under tests/data/regress is a small, realistic vulnerable program (loops with flags, aliasing,
try/except, deny-lists that are not validation, prefix checks, escaped + raw concatenation, Flask get_json, Java
switch/collections, ...), plus the second review round (PHP operators, interpolation and heredocs, procedural
mysqli, JS switch/++/coercion, Java switch expressions, helpers returning several parameters, setters and
builders, Tornado, Django URL parameters, permissive regexes). Every one must stay reported: precision work may
never silence a real flaw."""

import json
import pathlib
import shutil

import pytest

from vulnscan.scanner import scan_path

DATA = pathlib.Path(__file__).parent / "data" / "regress"
EXPECTED = json.loads((DATA / "expected.json").read_text())


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_still_reported(tmp_path, name):
    shutil.copy(DATA / name, tmp_path / name)
    findings = scan_path(tmp_path, [], set())[0]
    got = {f.rule_id for f in findings} | {f"{f.rule_id}:{f.line}" for f in findings}
    # an entry is a rule id ("DF002") or a rule id at a line ("DF002:7")
    assert set(EXPECTED[name]) <= got, (name, sorted(got))


def test_safe_counterparts_stay_quiet(tmp_path):
    """The precise side of the same fixes: a strict regex, a constant URL template and a dead `switch` arm
    must not be reported."""
    (tmp_path / "safe.py").write_text(
        "import os\nimport re\nimport requests\nfrom flask import Flask, request\napp = Flask(__name__)\n"
        "SAFE_RE = re.compile(r\"[a-z0-9]{1,16}\")\nAPI = \"https://api.example.com/\"\n"
        "@app.route('/a')\ndef a():\n    f = request.args['f']\n    if SAFE_RE.fullmatch(f):\n"
        "        return open(os.path.join('/srv', f)).read()\n    return 'no'\n"
        "@app.route('/s')\ndef s():\n    return requests.get(API + request.args['id']).text\n")
    (tmp_path / "dead.js").write_text(
        "const { exec } = require('child_process');\nconst app = require('express')();\n"
        "app.get('/d', (req, res) => {\n  let k = 2;\n  switch (k) {\n    case 1: exec(req.query.h); break;\n"
        "    default: res.send('ok');\n  }\n  let n = 0;\n  n++;\n  if (n === 0) { exec(req.query.z); }\n});\n")
    got = {(f.file, f.rule_id, f.line) for f in scan_path(tmp_path, [], set())[0]}
    assert not {g for g in got if g[1] in ("DF005", "DF010")}, got
    assert not {g for g in got if g[0] == "dead.js" and g[1] == "DF002"}, got


def test_list_layout_survives_element_reads(tmp_path):
    """Reading an element into a variable (`bar = lst[1]`) or passing it to a call does not make the list's layout
    unknown; only mutating that element does. And a pattern finding on a string handed to eval() stays gated."""
    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import Flask, request\napp = Flask(__name__)\n@app.route('/x')\ndef x():\n"
        "    param = request.form.get('p')\n    lst = ['safe', param, 'moresafe']\n    lst.pop(0)\n"
        "    bar = lst[1]\n    os.system(bar)\n    eval(bar)\n")
    got = {(f.rule_id, f.line) for f in scan_path(tmp_path, [], set())[0]}
    assert not {g for g in got if g[0].startswith(("DF", "EXE"))}, got


def test_map_reads_keep_precision(tmp_path):
    """An element read out of a map and then used as a key, put in a list literal, stored in the session or passed
    to a call is not a write into the map: the safe key's constant value is kept."""
    (tmp_path / "app.py").write_text(
        "import flask\nimport lxml.etree\nfrom flask import Flask, request\napp = Flask(__name__)\n"
        "@app.route('/x')\ndef x():\n    m = {}\n    m['a'] = 'a-Value'\n    m['b'] = request.form.get('p')\n"
        "    bar = m['a']\n    flask.session[bar] = '1'\n    flask.session['k'] = bar\n"
        "    q = ''.join(['/E[@id=', bar, ']'])\n    root = lxml.etree.parse('f.xml')\n    root.xpath(q)\n"
        "    d = {}\n    d['bar'] = bar\n    return '{0[bar]}'.format(d)\n")
    got = {(f.rule_id, f.line) for f in scan_path(tmp_path, [], set())[0]}
    assert not {g for g in got if g[0].startswith("DF")}, got


def test_helper_returning_list_element_keeps_precision(tmp_path):
    """`return lst[1]` hands an element to the caller; it is not a write into the list."""
    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import Flask, request\napp = Flask(__name__)\n"
        "def pick(p):\n    lst = ['safe', p, 'moresafe']\n    lst.pop(0)\n    bar = lst[1]\n    return bar\n"
        "@app.route('/x')\ndef x():\n    os.system(pick(request.args['c']))\n")
    got = {(f.rule_id, f.line) for f in scan_path(tmp_path, [], set())[0]}
    assert not {g for g in got if g[0].startswith("DF")}, got
