"""Points-to: aliasing through globals/containers, callbacks via parameters, dispatch on objects."""
from vulnscan.taint import analyze


def by_line(findings):
    return {f.line: f.rule_id for f in findings}


def test_object_taint_through_global_container_across_functions():
    code = (
        "import os\n"
        "STORE = []\n"
        "class Task:\n"
        "    pass\n"
        "def collect(request):\n"
        "    t = Task()\n"
        "    t.cmd = request.args['c']\n"
        "    STORE.append(t)\n"
        "def flush():\n"
        "    for t in STORE:\n"
        "        os.system(t.cmd)\n"           # alias of the tainted object via a global list
    )
    assert by_line(analyze("a.py", code)).get(11) == "DF002"


def test_callback_passed_as_parameter_is_resolved():
    code = (
        "import os\n"
        "def shell_exec(c):\n"
        "    os.system(c)\n"
        "def run_all(handler, data):\n"
        "    handler(data)\n"
        "def view(request):\n"
        "    run_all(shell_exec, request.args['c'])\n"   # callback resolves through points-to
    )
    bl = by_line(analyze("a.py", code))
    assert bl.get(7) == "DF002"


def test_dispatch_on_object_in_dict_registry():
    code = (
        "import os\n"
        "class Shell:\n"
        "    def run(self, c):\n"
        "        os.system(c)\n"
        "class Logger:\n"
        "    def run(self, c):\n"
        "        print(len(c))\n"
        "HANDLERS = {'sh': Shell(), 'log': Logger()}\n"
        "def view(request):\n"
        "    HANDLERS['sh'].run(request.args['c'])\n"       # object from a dict element -> dispatch
    )
    assert by_line(analyze("a.py", code)).get(10) == "DF002"


def test_allocation_sites_stay_separate():
    code = (
        "import os\n"
        "class Task:\n"
        "    def go(self):\n"
        "        os.system(self.cmd)\n"
        "def a(request):\n"
        "    t = Task()\n"
        "    t.cmd = request.args['c']\n"
        "    t.go()\n"                                    # tainted object
        "def b():\n"
        "    u = Task()\n"
        "    u.cmd = 'ls'\n"
        "    u.go()\n"                                    # different allocation site, clean
    )
    bl = by_line(analyze("a.py", code))
    assert bl.get(8) == "DF002" and 12 not in bl


def test_function_value_returned_from_factory():
    code = (
        "import os\n"
        "def danger(c):\n"
        "    os.system(c)\n"
        "def pick():\n"
        "    return danger\n"
        "def view(request):\n"
        "    f = pick()\n"
        "    f(request.args['c'])\n"
    )
    assert by_line(analyze("a.py", code)).get(8) == "DF002"
