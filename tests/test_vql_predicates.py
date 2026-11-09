"""VQL predicates: user-defined, recursive, value variables, built-in reachability query."""
import pathlib

from vulnscan.scanner import scan_path
from vulnscan.vql import Query


DB = {"call": [{"id": 1, "in_func": "a", "func": "b", "name": "b"}, {"id": 2, "in_func": "b", "func": "c", "name": "c"},
               {"id": 3, "in_func": "c", "func": "system", "name": "os.system"}, {"id": 4, "in_func": "z", "func": "print", "name": "print"}],
      "func": [{"id": 10, "name": "a", "is_entry": True}, {"id": 11, "name": "z", "is_entry": True}, {"id": 12, "name": "b", "is_entry": False}]}


def test_recursive_transitive_closure():
    q = Query('predicate calls(f, g) { from call c where c.in_func = f and c.func = g }\n'
              'predicate reaches(f, g) { calls(f, g) or from value h where calls(f, h) and reaches(h, g) }\n'
              'from func e where e.is_entry and reaches(e.name, "system") select e, "x"', "t.vql")
    rows = q.run(DB)
    assert [r["e"]["name"] for r in rows] == ["a"]
    assert ("a", "system") in q.tuples["reaches"] and ("a", "c") in q.tuples["reaches"]
    assert ("z", "system") not in q.tuples["reaches"]


def test_value_variable_join_in_main_query():
    q = Query('predicate calls(f, g) { from call c where c.in_func = f and c.func = g }\n'
              'from func e, value g where e.is_entry and calls(e.name, g) select e, "calls " + g', "t.vql")
    f = q.findings(DB)
    assert {x.snippet for x in f} == {"calls b", "calls print"}


def test_non_recursive_predicate_membership_and_negation():
    q = Query('predicate noisy(f) { from call c where c.in_func = f and c.func = "print" }\n'
              'from func e where e.is_entry and not noisy(e.name) select e, "quiet"', "t.vql")
    assert [r["e"]["name"] for r in q.run(DB)] == ["a"]


def test_builtin_reachability_query_end_to_end(tmp_path: pathlib.Path):
    (tmp_path / "app.py").write_text(
        "import os\n"
        "def deep(c):\n    os.system(c)\n"
        "def mid(c):\n    deep(c)\n"
        "@app.route('/x')\n"
        "def view():\n    mid('ls')\n"
        "@app.route('/y')\n"
        "def other():\n    return 'ok'\n"
    )
    findings, _ = scan_path(tmp_path, audit=True)          # reachability leads are audit-profile findings
    hits = {(f.rule_id, f.line) for f in findings if f.rule_id == "vql/entry-reaches-shell"}
    assert ("vql/entry-reaches-shell", 7) in hits and ("vql/entry-reaches-shell", 10) not in hits
