"""Context sensitivity: per-call-site callbacks and heap cloning of factory objects."""
from vulnscan.taint import analyze


def by_line(findings):
    return {f.line: f.rule_id for f in findings}


def test_callback_parameter_is_resolved_per_call_site():
    # The context-insensitive union would make run_all's `data` a sink for every caller.
    code = (
        "import os\n"
        "def shell_exec(c):\n"
        "    os.system(c)\n"
        "def log_it(c):\n"
        "    print(len(c))\n"
        "def run_all(handler, data):\n"
        "    handler(data)\n"
        "def unsafe(request):\n"
        "    run_all(shell_exec, request.args['c'])\n"
        "def safe(request):\n"
        "    run_all(log_it, request.args['c'])\n"
    )
    bl = by_line(analyze("a.py", code))
    assert bl.get(9) == "DF002", bl
    assert 11 not in bl, bl


def test_factory_objects_are_cloned_per_call_site():
    # make() is called from two places: with heap cloning the two Task objects are distinct.
    code = (
        "import os\n"
        "class Task:\n"
        "    def go(self):\n"
        "        os.system(self.cmd)\n"
        "def make():\n"
        "    return Task()\n"
        "def a(request):\n"
        "    t = make()\n"
        "    t.cmd = request.args['c']\n"
        "    t.go()\n"
        "def b():\n"
        "    u = make()\n"
        "    u.cmd = 'ls'\n"
        "    u.go()\n"
    )
    bl = by_line(analyze("a.py", code))
    assert bl.get(10) == "DF002", bl
    assert 14 not in bl, bl


def test_callback_with_real_source_inside_helper():
    # The helper itself reads the source and hands it to the callback it was given.
    code = (
        "import os\n"
        "def shell_exec(c):\n"
        "    os.system(c)\n"
        "def log_it(c):\n"
        "    print(len(c))\n"
        "def dispatch(handler, request):\n"
        "    handler(request.args['c'])\n"
        "def v1(request):\n"
        "    dispatch(shell_exec, request)\n"
        "def v2(request):\n"
        "    dispatch(log_it, request)\n"
    )
    bl = by_line(analyze("a.py", code))
    assert bl.get(9) == "DF002", bl
    assert 11 not in bl, bl
