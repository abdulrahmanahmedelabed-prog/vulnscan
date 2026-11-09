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
