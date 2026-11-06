"""VQL classes (characteristic predicates, member predicates, getters) and aggregates."""
from vulnscan.taint import analyze_project_full
from vulnscan.vql import Query, QueryError, build_database

CODE = (
    "import os, subprocess\n"
    "def a(request):\n"
    "    os.system(request.args['c'])\n"
    "    os.system('ls')\n"
    "    subprocess.call(['ls'])\n"
    "def b():\n"
    "    print('x')\n"
    "    print('y')\n"
    "    print('z')\n"
)


def db_for(code=CODE):
    projects, flows = analyze_project_full({"a.py": code})
    return build_database(projects, flows)


def run(text, db=None):
    return Query(text, "t.vql").run(db or db_for())


def test_class_with_characteristic_predicate_and_member_predicate():
    q = (
        'class ShellCall extends call {\n'
        '  ShellCall() { this.name in ("os.system", "subprocess.call") }\n'
        '  predicate isDynamic() { not this.arg0 matches "^[\\"\'\\[]" }\n'
        '  string target() { result = this.arg0 }\n'
        '}\n'
        'from ShellCall c where c.isDynamic() select c, "dynamic shell: " + c.target()\n'
    )
    rows = run(q)
    assert [r["c"]["line"] for r in rows] == [3]
    fs = Query(q, "t.vql").findings(db_for())
    assert fs and "request.args" in fs[0].snippet


def test_class_inheritance_and_member_with_parameter():
    q = (
        'class Shell extends call { Shell() { this.name = "os.system" } }\n'
        'class LiteralShell extends Shell {\n'
        '  LiteralShell() { this.arg0 matches "^\'" }\n'
        '  predicate inFunc(f) { this.in_func = f }\n'
        '}\n'
        'from LiteralShell c where c.inFunc("a") select c, "literal"\n'
    )
    rows = run(q)
    assert [r["c"]["line"] for r in rows] == [4]


def test_count_and_exists_aggregates():
    q = 'from func f where count(call c | c.in_func = f.name and c.name = "print") >= 3 select f, "noisy"\n'
    rows = run(q)
    assert [r["f"]["name"] for r in rows] == ["b"]
    q2 = 'from func f where not exists(call c | c.in_func = f.name and c.name = "os.system") select f, "clean"\n'
    assert [r["f"]["name"] for r in run(q2)] == ["b"]


def test_sum_max_any_and_aggregate_in_select():
    q = 'from func f where sum(call c | c.in_func = f.name | c.nargs) > 2 and f.name = "a" select f, "args: " + count(call c | c.in_func = f.name)\n'
    fs = Query(q, "t.vql").findings(db_for())
    assert [f.line for f in fs] == [2] and fs[0].snippet.endswith("args: 3")
    q2 = 'from func f where max(call c | c.in_func = f.name | c.line) = 9 select f, any(call c | c.in_func = f.name | c.name)\n'
    rows = run(q2)
    assert [r["f"]["name"] for r in rows] == ["b"]


def test_strictcount_of_empty_set_has_no_value():
    q = 'from func f where strictcount(call c | c.in_func = f.name and c.name = "nothing") = 0 select f, "x"\n'
    assert run(q) == []


def test_class_errors_are_reported():
    try:
        run('class X extends nothing { X() { this.name = "a" } }\nfrom X x select x, "y"\n')
    except QueryError as e:
        assert "unknown base" in str(e)
    else:
        raise AssertionError("expected QueryError")
