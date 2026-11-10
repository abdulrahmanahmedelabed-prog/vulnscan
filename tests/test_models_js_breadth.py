"""JavaScript / TypeScript library models: framework sources, entry points, sinks and sanitizers (breadth set).

Every program under tests/data/models_js/ states on its first line what the data-flow engine must report:

* ``// expect: DF004``             -- a vulnerable program: the rule must be reported.
* ``// expect-none: DF004 DF005``  -- a safe twin (sanitized, parameterized or constant) or a look-alike API:
                                      none of the listed rules may be reported.

Vulnerable programs are named ``<case>__vuln.<ext>`` and have a ``<case>__safe.<ext>`` twin.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from vulnscan.i18n import translated
from vulnscan.taint import DEFAULT_JS_MODELS, analyze_project, load_models

DATA = pathlib.Path(__file__).resolve().parent / "data" / "models_js"
FILES = sorted(p for p in DATA.iterdir() if p.suffix in {".js", ".ts"})


def _expectation(path: pathlib.Path) -> tuple[str, set[str]]:
    head = path.read_text(encoding="utf-8").splitlines()[0]
    kind, _, rules = head.lstrip("/ ").partition(":")
    return kind.strip(), set(rules.split())


def _findings(path: pathlib.Path):
    return analyze_project({path.name: path.read_text(encoding="utf-8")})


def _case(path: pathlib.Path) -> str:
    return path.name.rsplit("__", 1)[0]


def test_corpus_is_paired():
    vuln = {_case(p) for p in FILES if p.stem.endswith("__vuln")}
    safe = {_case(p) for p in FILES if p.stem.endswith("__safe")}
    assert len(vuln) >= 60
    assert vuln == safe, f"cases without a twin: {sorted(vuln ^ safe)}"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.stem)
def test_model_case(path):
    kind, rules = _expectation(path)
    assert kind in {"expect", "expect-none"} and rules, f"{path.name}: bad header"
    found = {f.rule_id for f in _findings(path)}
    if kind == "expect":
        assert rules <= found, f"{path.name}: expected {sorted(rules)}, got {sorted(found)}"
    else:
        assert not rules & found, f"{path.name}: must not report {sorted(rules & found)} (got {sorted(found)})"


@pytest.mark.parametrize("case, needle", [
    ("knex_where_raw", "whereRaw"),
    ("insert_adjacent_html", "insertAdjacentHTML"),
    ("express_status_send", "status(200).send"),
    ("jquery_append", ".append("),
])
def test_vulnerable_twin_reports_at_the_sink_line(case, needle):
    """The finding points at the sink call of the vulnerable program, not at an unrelated line."""
    path = DATA / f"{case}__vuln.js"
    _, rules = _expectation(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    hits = [f for f in _findings(path) if f.rule_id in rules]
    assert hits and all(needle in lines[f.line - 1] for f in hits), [(f.rule_id, f.line) for f in hits]


def test_insert_adjacent_html_position_is_not_the_sink():
    """insertAdjacentHTML(position, html): only the markup (argument 1) is dangerous."""
    src = ("function f() {\n"
           "  const pos = location.hash.slice(1);\n"
           "  document.body.insertAdjacentHTML(pos, '<b>static</b>');\n"
           "}\n")
    assert not [f for f in analyze_project({"a.js": src}) if f.rule_id == "DF013"]


def test_receiver_constrained_sinks_ignore_look_alikes():
    """Bare method names (all/get/run/append/send) are sinks only on the receivers that make them dangerous."""
    src = ("module.exports = (req, res) => {\n"
           "  const q = req.query.q;\n"
           "  Promise.all([q]);\n"
           "  cache.get(q);\n"
           "  job.run(q);\n"
           "  params.append('q', q);\n"
           "  socket.send(q);\n"
           "  reply.send(q);\n"
           "};\n")
    assert not {f.rule_id for f in analyze_project({"a.js": src})} & {"DF004", "DF013"}


@pytest.mark.parametrize("name, src, rules", [
    # koa-send resolves the path inside `root` (resolve-path rejects `..` and absolute paths): not a traversal sink
    ("koa_send.js", "const send = require('koa-send');\n"
                    "module.exports = async (ctx) => { await send(ctx, ctx.path, { root: 'public' }); };\n", {"DF005"}),
    # @hapi/inert h.file() confines to the route's relativeTo directory by default (confine: true)
    ("hapi_file.js", "const handler = (request, h) => h.file(request.query.name);\n"
                     "module.exports = { method: 'GET', path: '/f', handler };\n", {"DF005"}),
    # Angular Router.navigateByUrl only navigates between in-app routes: no open redirect
    ("nav.ts", "export class C {\n  constructor(private route: ActivatedRoute, private router: Router) {}\n"
               "  go() { this.router.navigateByUrl(this.route.snapshot.queryParams.next); }\n}\n", {"DF008"}),
    # a key-value store `db.get(key)` (LevelDB, lowdb) is not SQL
    ("kv.js", "const db = require('level')('./kv');\n"
              "module.exports = async (req, res) => { res.json(await db.get(req.params.key)); };\n", {"DF004"}),
])
def test_confined_or_non_sql_look_alikes_are_not_sinks(name, src, rules):
    assert not {f.rule_id for f in analyze_project({name: src})} & rules


def test_escape_id_is_a_sql_sanitizer_only_on_a_mysql_handle():
    """A project's own `escapeId` helper is not HTML escaping; mysql's connection.escapeId quotes SQL identifiers."""
    xss = ("function escapeId(s) { return s; }\n"
           "module.exports = (req, res) => { res.send('<b>' + escapeId(req.query.x) + '</b>'); };\n")
    assert "DF013" in {f.rule_id for f in analyze_project({"a.js": xss})}


def test_js_models_are_well_formed_and_translated():
    data = json.loads(pathlib.Path(DEFAULT_JS_MODELS).read_text(encoding="utf-8"))
    for s in data["sinks"] + data["attr_sinks"]:
        assert s.get("names") or s.get("attrs"), s
        assert s.get("cwe", "").startswith("CWE-"), s
        assert translated(s.get("advice", "")), s["advice"]
        names = s.get("names", [])
        assert len(names) == len(set(names)), s["label"]
    m = load_models((), DEFAULT_JS_MODELS, "javascript")
    assert len(m["sinks"]) == len(data["sinks"])
    assert len(m["sinks"]) >= 35 and len(m["sanitizers"]) >= 40
