"""Intra-procedural taint (data-flow) analysis for Python.  (vulnscan: ignore-file — contains sink names that match the pattern rules)

Unlike the regex rules, this parses the file into an AST and tracks data
flowing from untrusted *sources* (request parameters, input(), os.environ,
sys.argv, ...) through assignments and expressions to dangerous *sinks*
(eval/exec, os.system, subprocess with shell, cursor.execute, open, pickle,
render_template_string, redirect, ...). Flow is tracked within each function
with a fixpoint over assignments, so multi-step flows like

    name = request.args["q"]
    cmd = "echo " + name
    os.system(cmd)              # <- reported: tainted value reaches os.system

are caught, while a constant reaching the same sink is not. It is
intra-procedural (one function at a time) and Python-only; it complements,
not replaces, the pattern rules.
"""

from __future__ import annotations

import ast

from .model import Finding

# Attributes on `request`/`flask.request` that carry untrusted input.
REQUEST_ATTRS = {"args", "form", "values", "json", "data", "cookies", "headers",
                 "files", "GET", "POST", "query_params", "body"}
# Calls that return untrusted input: dotted name -> short label.
SOURCE_CALLS = {
    "input": "input()", "os.environ.get": "os.environ", "os.getenv": "os.getenv",
    "request.get_json": "request.get_json()", "request.get_data": "request.get_data()",
}
# Callables that sanitize/neutralize their argument -> result is not tainted.
SANITIZERS = {"int", "float", "bool", "len", "shlex.quote", "html.escape", "escape",
              "markupsafe.escape", "urllib.parse.quote", "quote", "re.escape", "hash",
              "hashlib.sha256", "bleach.clean"}


def _dotted(node: ast.AST) -> str:
    """Best-effort dotted name for a Name/Attribute/Call func."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _is_source(node: ast.AST) -> str | None:
    """Return a human label if the expression is an untrusted source."""
    # request.args[...] / request.form.get(...) / flask.request.values[...]
    cur = node
    # unwrap subscripts and .get()/.getlist() calls
    if isinstance(cur, ast.Call):
        f = cur.func
        if isinstance(f, ast.Attribute) and f.attr in {"get", "getlist", "getall", "get_argument"}:
            cur = f.value
    if isinstance(cur, ast.Subscript):
        cur = cur.value
    if isinstance(cur, ast.Attribute) and cur.attr in REQUEST_ATTRS:
        root = _dotted(cur.value)
        if root == "request" or root.endswith(".request") or root == "self" or root.endswith("request"):
            return f"request.{cur.attr}"
    # sys.argv[...]
    if isinstance(node, ast.Subscript) and _dotted(node.value) == "sys.argv":
        return "sys.argv"
    if _dotted(node) == "sys.argv":
        return "sys.argv"
    # known source calls
    if isinstance(node, ast.Call):
        name = _dotted(node.func)
        for key, label in SOURCE_CALLS.items():
            if name == key or name.endswith("." + key.split(".")[-1]) and key in ("input",):
                return label
        if name in SOURCE_CALLS:
            return SOURCE_CALLS[name]
        if name == "input":
            return "input()"
    return None


class _Analyzer:
    def __init__(self, path: str):
        self.path = path
        self.findings: list[Finding] = []

    # ---- taint of an expression given the set of tainted names ----
    def _taint_src(self, node: ast.AST, tainted: set[str]) -> str | None:
        """Return a source label if the expression carries taint, else None."""
        src = _is_source(node)
        if src:
            return src
        if isinstance(node, ast.Name):
            return tainted.get(node.id) if isinstance(tainted, dict) else (node.id if node.id in tainted else None)
        if isinstance(node, (ast.BinOp,)):
            return self._taint_src(node.left, tainted) or self._taint_src(node.right, tainted)
        if isinstance(node, ast.BoolOp):
            for v in node.values:
                s = self._taint_src(v, tainted)
                if s:
                    return s
            return None
        if isinstance(node, ast.IfExp):
            return self._taint_src(node.body, tainted) or self._taint_src(node.orelse, tainted)
        if isinstance(node, ast.JoinedStr):  # f-string
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    s = self._taint_src(v.value, tainted)
                    if s:
                        return s
            return None
        if isinstance(node, (ast.Subscript, ast.Starred)):
            return self._taint_src(node.value, tainted)
        if isinstance(node, ast.Attribute):
            return self._taint_src(node.value, tainted)
        if isinstance(node, ast.Call):
            fname = _dotted(node.func)
            if fname in SANITIZERS or fname.split(".")[-1] in {"quote", "escape"}:
                return None
            # method call on a tainted value, e.g. tainted.format(...) / "x".join(tainted)
            if isinstance(node.func, ast.Attribute):
                s = self._taint_src(node.func.value, tainted)
                if s:
                    return s
            for a in list(node.args) + [k.value for k in node.keywords]:
                s = self._taint_src(a, tainted)
                if s:
                    return s
            return None
        return None

    # ---- collect tainted names in a function (fixpoint) ----
    def _tainted_names(self, body: list[ast.stmt]) -> dict:
        tainted: dict = {}
        changed = True
        passes = 0
        while changed and passes < 8:
            changed = False
            passes += 1
            for node in ast.walk(ast.Module(body=body, type_ignores=[])):
                targets = []
                value = None
                if isinstance(node, ast.Assign):
                    targets, value = node.targets, node.value
                elif isinstance(node, ast.AnnAssign) and node.value is not None:
                    targets, value = [node.target], node.value
                elif isinstance(node, ast.AugAssign):
                    targets, value = [node.target], node.value
                elif isinstance(node, (ast.For, ast.AsyncFor)):
                    targets, value = [node.target], node.iter
                else:
                    continue
                label = None if value is None else self._taint_src(value, tainted)
                if label is None:
                    continue
                for tgt in targets:
                    for nm in self._names_in_target(tgt):
                        if nm not in tainted:
                            tainted[nm] = label
                            changed = True
        return tainted

    @staticmethod
    def _names_in_target(tgt: ast.AST) -> list[str]:
        out = []
        for n in ast.walk(tgt):
            if isinstance(n, ast.Name):
                out.append(n.id)
        return out

    # ---- sinks ----
    def _check_sinks(self, body: list[ast.stmt], tainted: set[str]) -> None:
        for node in ast.walk(ast.Module(body=body, type_ignores=[])):
            if not isinstance(node, ast.Call):
                continue
            fname = _dotted(node.func)
            short = fname.split(".")[-1]
            args = node.args
            kw = {k.arg: k.value for k in node.keywords}

            def arg(i):
                return args[i] if len(args) > i else None

            def tainted_arg(*idxs):
                for i in idxs:
                    a = arg(i)
                    if a is not None:
                        s = self._taint_src(a, tainted)
                        if s:
                            return s
                return None

            line = node.lineno

            if short in {"eval", "exec"} and fname in {"eval", "exec"}:
                s = tainted_arg(0)
                if s:
                    self._add("DF001", "critical", "Tainted data reaches eval/exec", "بيانات غير موثوقة تصل إلى eval/exec",
                              line, s, "لا تمرّر مدخلات المستخدم إلى eval/exec؛ استخدم منطقًا صريحًا أو ast.literal_eval.", "CWE-95")
            elif fname in {"os.system", "os.popen"}:
                s = tainted_arg(0)
                if s:
                    self._add("DF002", "critical", f"Tainted data reaches {fname}", f"بيانات غير موثوقة تصل إلى {fname}",
                              line, s, "لا تبنِ أوامر النظام من المدخلات؛ استخدم قائمة وسائط بلا shell وتحقق منها.", "CWE-78")
            elif short in {"call", "run", "Popen", "check_output", "check_call"} and ("subprocess" in fname or short in {"Popen"}):
                shell_true = isinstance(kw.get("shell"), ast.Constant) and kw["shell"].value is True
                s = tainted_arg(0) or (self._taint_src(kw["args"], tainted) if "args" in kw else None)
                if s and shell_true:
                    self._add("DF003", "high", "Tainted data reaches subprocess with shell=True", "بيانات غير موثوقة تصل إلى subprocess بـ shell=True",
                              line, s, "استخدم قائمة وسائط بلا shell=True ولا تبنِ الأمر من المدخلات.", "CWE-78")
                elif s:
                    self._add("DF003", "high", "Tainted data reaches subprocess argument", "بيانات غير موثوقة تصل إلى وسيط subprocess",
                              line, s, "تحقق من الوسائط بقائمة بيضاء ولا تمرّر مدخلات خام.", "CWE-78")
            elif short in {"execute", "executemany", "executescript"}:
                s = tainted_arg(0)
                if s:
                    self._add("DF004", "high", "Tainted data reaches SQL execute()", "بيانات غير موثوقة تصل إلى تنفيذ SQL",
                              line, s, "استخدم استعلامات مُعَلَّمة (parameters) بدل بناء نص الاستعلام من المدخلات.", "CWE-89")
            elif fname == "open" or short in {"send_file", "send_from_directory"}:
                s = tainted_arg(0)
                if s:
                    self._add("DF005", "high", f"Tainted data reaches {short}() path", f"بيانات غير موثوقة تصل إلى مسار {short}",
                              line, s, "طبّع المسار وتحقق أنه داخل المجلد المسموح (resolve + is_relative_to).", "CWE-22")
            elif fname in {"pickle.loads", "pickle.load", "yaml.load", "marshal.loads", "dill.loads"}:
                s = tainted_arg(0)
                if s:
                    self._add("DF006", "critical", f"Tainted data reaches {fname}", f"بيانات غير موثوقة تصل إلى {fname}",
                              line, s, "لا تفك تسلسل بيانات غير موثوقة؛ استخدم JSON أو yaml.safe_load.", "CWE-502")
            elif short == "render_template_string":
                s = tainted_arg(0)
                if s:
                    self._add("DF007", "high", "Tainted data reaches render_template_string", "بيانات غير موثوقة تصل إلى قالب ديناميكي",
                              line, s, "استخدم قوالب ثابتة ومرّر البيانات كمتغيرات (SSTI).", "CWE-1336")
            elif short == "redirect":
                s = tainted_arg(0)
                if s:
                    self._add("DF008", "medium", "Tainted data reaches redirect()", "بيانات غير موثوقة تصل إلى redirect",
                              line, s, "تحقق أن وجهة التحويل ضمن قائمة بيضاء (Open Redirect).", "CWE-601")

    def _add(self, rid, sev, title, title_ar, line, source, advice, cwe):
        self.findings.append(Finding(rid, sev, title, title_ar, self.path, line,
                                     f"المصدر: {source}", advice, cwe, source="taint",
                                     extra={"analysis": "dataflow", "taint_source": source}))

    def run(self, tree: ast.AST) -> list[Finding]:
        funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        scopes = funcs if funcs else [tree]
        for scope in scopes:
            body = scope.body if hasattr(scope, "body") else [scope]
            tainted = self._tainted_names(body)
            if tainted or any(_is_source(n) for n in ast.walk(ast.Module(body=body, type_ignores=[]))):
                self._check_sinks(body, tainted)
        return self.findings


def analyze(path: str, text: str) -> list[Finding]:
    """Run taint analysis on one Python source file. Returns [] on syntax errors."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    return _Analyzer(path).run(tree)
