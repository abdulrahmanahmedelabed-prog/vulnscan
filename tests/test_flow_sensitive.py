"""Flow-sensitive locals (SSA versions) and k=2 call-string contexts in the points-to analysis."""
import ast

from vulnscan import pointsto
from vulnscan.taint import DEFAULT_MODELS, Project, analyze, load_models


def by_line(findings):
    return {f.line: f.rule_id for f in findings}


def _pt(code):
    proj = Project(load_models((), DEFAULT_MODELS, "python"))
    proj.add_file("a", "a.py", code)
    proj.link()
    return proj, pointsto.PointsTo(proj)


def _call_node(proj, line):
    for n in ast.walk(proj.files["a"]["tree"]):
        if isinstance(n, ast.Call) and getattr(n, "lineno", 0) == line:
            return n
    raise AssertionError("no call at line %d" % line)


def test_strong_update_kills_the_old_object():
    code = (
        "class Shell:\n    def run(self, c): pass\n"
        "class Logger:\n    def run(self, c): pass\n"
        "def f():\n"
        "    h = Shell()\n"
        "    h = Logger()\n"
        "    h.run('x')\n"
    )
    proj, pt = _pt(code)
    call = _call_node(proj, 8)
    assert pt.classes_for(call.func.value) == {"a::Logger"}


def test_branches_merge_and_loop_header_feeds_back():
    code = (
        "class A:\n    pass\nclass B:\n    pass\nclass C:\n    pass\n"
        "def f(flag, xs):\n"
        "    h = A()\n"
        "    if flag:\n"
        "        h = B()\n"
        "    use(h)\n"
        "    for x in xs:\n"
        "        use2(h)\n"
        "        h = C()\n"
        "    use3(h)\n"
    )
    proj, pt = _pt(code)
    assert pt.classes_for(_call_node(proj, 11).args[0]) == {"a::A", "a::B"}
    assert pt.classes_for(_call_node(proj, 13).args[0]) == {"a::A", "a::B", "a::C"}   # header phi: entry or end of body
    assert pt.classes_for(_call_node(proj, 15).args[0]) == {"a::A", "a::B", "a::C"}   # zero or more iterations


def test_flow_sensitivity_removes_a_false_positive():
    # The tainted Task object is replaced by a clean one before the sink: insensitive analysis would report line 10.
    code = (
        "import os\n"
        "class Task:\n"
        "    def go(self):\n"
        "        os.system(self.cmd)\n"
        "def view(request):\n"
        "    t = Task()\n"
        "    t.cmd = request.args['c']\n"
        "    t = Task()\n"
        "    t.cmd = 'ls'\n"
        "    t.go()\n"
    )
    assert 10 not in by_line(analyze("a.py", code))


def test_k2_keeps_callers_of_a_wrapper_apart():
    # make() is reached through wrap(); with k=1 both callers of wrap() share wrap's single context for make(),
    # so the Task of `unsafe` and `safe` would be the same object. k=2 distinguishes them.
    code = (
        "import os\n"
        "class Task:\n"
        "    def go(self):\n"
        "        os.system(self.cmd)\n"
        "def make():\n"
        "    return Task()\n"
        "def wrap():\n"
        "    return make()\n"
        "def unsafe(request):\n"
        "    t = wrap()\n"
        "    t.cmd = request.args['c']\n"
        "    t.go()\n"
        "def safe():\n"
        "    u = wrap()\n"
        "    u.cmd = 'ls'\n"
        "    u.go()\n"
    )
    proj, pt = _pt(code)
    a = pt.objs(_call_node(proj, 10))
    b = pt.objs(_call_node(proj, 14))
    assert a and b and not (a & b), (a, b)
    bl = by_line(analyze("a.py", code))
    assert bl.get(12) == "DF002" and 16 not in bl, bl


def test_depth_is_configurable_and_k0_is_insensitive():
    code = (
        "class Task:\n    pass\n"
        "def make():\n    return Task()\n"
        "def a():\n    return make()\n"
        "def b():\n    return make()\n"
    )
    proj, pt0 = _pt(code)
    pt0 = pointsto.PointsTo(proj, k=0)
    assert pt0.objs(_call_node(proj, 6)) == pt0.objs(_call_node(proj, 8))
    pt1 = pointsto.PointsTo(proj, k=1)
    assert not (pt1.objs(_call_node(proj, 6)) & pt1.objs(_call_node(proj, 8)))
    assert pt1.stats()["k"] == 1 and not pt1.timed_out
