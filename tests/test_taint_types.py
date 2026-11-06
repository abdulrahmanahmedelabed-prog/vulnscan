"""Type-aware taint: receiver types, inheritance, virtual dispatch, fields, ctors, containers."""
from vulnscan.taint import analyze, analyze_project


def ids(findings):
    return {f.rule_id for f in findings}


def test_receiver_type_disambiguates_same_method_name():
    # Two classes define run(); only Shell.run sinks. A Logger receiver must NOT be flagged.
    code = (
        "import os\n"
        "class Shell:\n"
        "    def run(self, c):\n"
        "        os.system(c)\n"
        "class Logger:\n"
        "    def run(self, c):\n"
        "        print(len(c))\n"
        "def safe(request):\n"
        "    lg = Logger()\n"
        "    lg.run(request.args['x'])\n"
        "def unsafe(request):\n"
        "    sh = Shell()\n"
        "    sh.run(request.args['x'])\n"
    )
    f = analyze("a.py", code)
    lines = {x.line for x in f if x.rule_id == "DF002"}
    assert 13 in lines          # sh.run(...) in unsafe()
    assert 10 not in lines      # lg.run(...) in safe() is clean


def test_inherited_method_via_mro():
    code = (
        "import os\n"
        "class Base:\n"
        "    def run(self, c):\n"
        "        os.system(c)\n"
        "class Child(Base):\n"
        "    pass\n"
        "def view(request):\n"
        "    Child().run(request.args['x'])\n"
    )
    assert "DF002" in ids(analyze("a.py", code))


def test_virtual_dispatch_on_base_typed_param():
    # Static type is Base (whose run is harmless); Child overrides run with a sink.
    code = (
        "import os\n"
        "class Base:\n"
        "    def run(self, c):\n"
        "        return len(c)\n"
        "class Child(Base):\n"
        "    def run(self, c):\n"
        "        os.system(c)\n"
        "def view(request, r: Base):\n"
        "    r.run(request.args['x'])\n"
    )
    assert "DF002" in ids(analyze("a.py", code))


def test_field_flow_between_methods():
    code = (
        "import os\n"
        "class Job:\n"
        "    def load(self, request):\n"
        "        self.cmd = request.args['cmd']\n"
        "    def go(self):\n"
        "        os.system(self.cmd)\n"
    )
    f = analyze("a.py", code)
    hit = [x for x in f if x.rule_id == "DF002"]
    assert hit and hit[0].line == 6 and "request.args" in hit[0].snippet
    assert any("self.cmd" in st["text"] for st in hit[0].extra["path"])   # field hop is in the path


def test_constructor_argument_to_field_to_sink():
    code = (
        "import os\n"
        "class Task:\n"
        "    def __init__(self, cmd):\n"
        "        self.cmd = cmd\n"
        "    def run(self):\n"
        "        os.system(self.cmd)\n"
        "def view(request):\n"
        "    t = Task(request.args['c'])\n"
        "    t.run()\n"
        "def fine():\n"
        "    t = Task('ls')\n"
        "    t.run()\n"
    )
    f = analyze("a.py", code)
    lines = {x.line for x in f if x.rule_id == "DF002"}
    assert 9 in lines and 12 not in lines


def test_container_append_is_argument_injection():
    # Fixed program, tainted later element, no shell -> argument injection (medium), not command injection.
    code = (
        "import subprocess\n"
        "def view(request):\n"
        "    args = ['ls']\n"
        "    args.append(request.args['p'])\n"
        "    subprocess.run(args)\n"
    )
    got = ids(analyze("a.py", code))
    assert "DF009" in got and "DF003" not in got


def test_command_injection_when_program_or_shell_is_tainted():
    code = (
        "import subprocess\n"
        "def a(request):\n"
        "    subprocess.run('ls ' + request.args['p'], shell=True)\n"   # shell string
        "def b(request):\n"
        "    subprocess.run([request.args['prog'], '-v'])\n"             # tainted program
        "def c(request):\n"
        "    subprocess.run(['ls', request.args['p']])\n"                # tainted argument only
    )
    f = analyze("a.py", code)
    by_line = {x.line: x.rule_id for x in f}
    assert by_line.get(3) == "DF003" and by_line.get(5) == "DF003" and by_line.get(7) == "DF009"


def test_nosec_suppresses_taint_finding():
    code = (
        "import os\n"
        "def view(request):\n"
        "    os.system(request.args['x'])  # nosec - validated upstream\n"
    )
    assert analyze("a.py", code) == []


def test_return_type_chaining():
    code = (
        "import os\n"
        "class Runner:\n"
        "    def run(self, c):\n"
        "        os.system(c)\n"
        "def make() -> Runner:\n"
        "    return Runner()\n"
        "def view(request):\n"
        "    make().run(request.args['x'])\n"
    )
    assert "DF002" in ids(analyze("a.py", code))


def test_typed_field_receiver_across_files():
    files = {
        "shell.py": "import os\nclass Shell:\n    def run(self, c):\n        os.system(c)\n",
        "svc.py": ("from shell import Shell\n"
                   "class Service:\n"
                   "    def __init__(self):\n"
                   "        self.sh = Shell()\n"
                   "    def handle(self, request):\n"
                   "        self.sh.run(request.form['c'])\n"),
    }
    f = analyze_project(files)
    hit = [x for x in f if x.rule_id == "DF002"]
    assert hit and hit[0].file == "svc.py" and hit[0].line == 6


def test_chained_temporary_receiver():
    # Task(t).run() with no variable in between; Logger().run(t) must stay clean.
    code = (
        "import os\n"
        "class Task:\n"
        "    def __init__(self, cmd):\n"
        "        self.cmd = cmd\n"
        "    def run(self):\n"
        "        os.system(self.cmd)\n"
        "class Logger:\n"
        "    def run(self, c):\n"
        "        print(len(c))\n"
        "def h(request):\n"
        "    Task(request.args['c']).run()\n"
        "    Logger().run(request.args['c'])\n"
        "    Task('ls').run()\n"
    )
    lines = {f.line for f in analyze("a.py", code) if f.rule_id == "DF002"}
    assert lines == {11}
