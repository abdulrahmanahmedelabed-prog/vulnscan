"""Inter-procedural, cross-file taint (data-flow) analysis for Python.  (vulnscan: ignore-file)

Builds one model of the whole scanned project: every Python file is parsed,
functions are indexed globally, and imports are resolved so a call to a
function defined in another file is followed. Per-function summaries record
whether a function returns untrusted data and which of its parameters reach a
dangerous sink; they are computed to a fixpoint so taint composes across any
number of hops and across files, e.g.

    # io.py
    def read_name():            return request.args["name"]      # returns untrusted
    # exec.py
    def run(cmd):               os.system(cmd)                   # param -> sink
    # views.py
    from io import read_name
    from exec import run
    def handler():              run(read_name())                 # <- flagged

Sources: request.args/form/json/..., input(), os.environ, sys.argv.
Sinks: eval/exec, os.system/popen, subprocess, cursor.execute (SQL),
open/send_file (path traversal), pickle/yaml.load, render_template_string
(SSTI), redirect (open redirect). Sanitizers (shlex.quote, html.escape,
int, ...) clear taint. Call resolution across files is by name/import and is
an approximation, not a full type-aware engine, but it follows real flows
through helpers and wrappers that line patterns cannot see.
"""

from __future__ import annotations

import ast

from .model import Finding

REQUEST_ATTRS = {"args", "form", "values", "json", "data", "cookies", "headers",
                 "files", "GET", "POST", "query_params", "body"}
SANITIZERS = {"int", "float", "bool", "len", "shlex.quote", "html.escape", "escape",
              "markupsafe.escape", "urllib.parse.quote", "quote", "re.escape", "hash",
              "hashlib.sha256", "bleach.clean", "secure_filename"}
MAX_PASSES = 16


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _is_source(node: ast.AST) -> str | None:
    cur = node
    if isinstance(cur, ast.Call):
        f = cur.func
        if isinstance(f, ast.Attribute) and f.attr in {"get", "getlist", "getall", "get_argument"}:
            cur = f.value
    if isinstance(cur, ast.Subscript):
        cur = cur.value
    if isinstance(cur, ast.Attribute) and cur.attr in REQUEST_ATTRS:
        root = _dotted(cur.value)
        if root == "request" or root.endswith("request") or root == "self":
            return f"request.{cur.attr}"
    if isinstance(node, ast.Subscript) and _dotted(node.value) == "sys.argv":
        return "sys.argv"
    if _dotted(node) == "sys.argv":
        return "sys.argv"
    if isinstance(node, ast.Call):
        name = _dotted(node.func)
        short = name.split(".")[-1]
        if short == "input":
            return "input()"
        if name in {"os.getenv", "os.environ.get", "getenv"}:
            return "os.environ"
        if name in {"request.get_json", "request.get_data"}:
            return f"{name}()"
    return None


def _sink_info(call: ast.Call):
    """(rule, severity, title_en, title_ar, advice, cwe, label, [arg indices]) or None."""
    fname = _dotted(call.func)
    short = fname.split(".")[-1]
    if fname in {"eval", "exec"}:
        return ("DF001", "critical", "Tainted data reaches eval/exec", "بيانات غير موثوقة تصل إلى eval/exec",
                "لا تمرّر مدخلات المستخدم إلى eval/exec؛ استخدم منطقًا صريحًا أو ast.literal_eval.", "CWE-95", "eval/exec", [0])
    if fname in {"os.system", "os.popen"}:
        return ("DF002", "critical", f"Tainted data reaches {fname}", f"بيانات غير موثوقة تصل إلى {fname}",
                "لا تبنِ أوامر النظام من المدخلات؛ استخدم قائمة وسائط بلا shell وتحقق منها.", "CWE-78", fname, [0])
    if short in {"call", "run", "Popen", "check_output", "check_call"} and ("subprocess" in fname or short == "Popen"):
        return ("DF003", "high", "Tainted data reaches subprocess", "بيانات غير موثوقة تصل إلى subprocess",
                "استخدم قائمة وسائط بلا shell=True ولا تبنِ الأمر من المدخلات.", "CWE-78", "subprocess", [0])
    if short in {"execute", "executemany", "executescript"}:
        return ("DF004", "high", "Tainted data reaches SQL execute()", "بيانات غير موثوقة تصل إلى تنفيذ SQL",
                "استخدم استعلامات مُعَلَّمة (parameters) بدل بناء نص الاستعلام من المدخلات.", "CWE-89", "SQL execute", [0])
    if fname == "open" or short in {"send_file", "send_from_directory"}:
        return ("DF005", "high", f"Tainted data reaches {short}() path", f"بيانات غير موثوقة تصل إلى مسار {short}",
                "طبّع المسار وتحقق أنه داخل المجلد المسموح (resolve + is_relative_to).", "CWE-22", f"{short}()", [0])
    if fname in {"pickle.loads", "pickle.load", "yaml.load", "marshal.loads", "dill.loads"}:
        return ("DF006", "critical", f"Tainted data reaches {fname}", f"بيانات غير موثوقة تصل إلى {fname}",
                "لا تفك تسلسل بيانات غير موثوقة؛ استخدم JSON أو yaml.safe_load.", "CWE-502", fname, [0])
    if short == "render_template_string":
        return ("DF007", "high", "Tainted data reaches render_template_string", "بيانات غير موثوقة تصل إلى قالب ديناميكي",
                "استخدم قوالب ثابتة ومرّر البيانات كمتغيرات (SSTI).", "CWE-1336", "render_template_string", [0])
    if short == "redirect":
        return ("DF008", "medium", "Tainted data reaches redirect()", "بيانات غير موثوقة تصل إلى redirect",
                "تحقق أن وجهة التحويل ضمن قائمة بيضاء (Open Redirect).", "CWE-601", "redirect()", [0])
    return None


def _params(fn: ast.AST) -> list[str]:
    a = fn.args
    return [p.arg for p in (a.posonlyargs + a.args)]


class Project:
    """Whole-project taint model across many Python files."""

    def __init__(self):
        self.files: dict[str, dict] = {}        # mod -> {path, tree, aliases, funcs}
        self.gfuncs: dict[str, dict] = {}       # qual "mod::name" -> {node, mod, name, path}
        self.simple: dict[str, list[str]] = {}  # name -> [qual, ...]
        self.summaries: dict[str, dict] = {}
        self.findings: list[Finding] = []

    # ---- building ----
    def add_file(self, mod: str, path: str, text: str) -> bool:
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            return False
        aliases = self._aliases(tree)
        funcs = {}
        self.files[mod] = {"path": path, "tree": tree, "aliases": aliases, "funcs": funcs}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = f"{mod}::{node.name}"
                self.gfuncs[qual] = {"node": node, "mod": mod, "name": node.name, "path": path}
                funcs[node.name] = qual
                self.simple.setdefault(node.name, []).append(qual)
        return True

    @staticmethod
    def _aliases(tree: ast.AST) -> dict:
        """local name -> ('from', module, origname) | ('mod', module)."""
        al = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for a in node.names:
                    al[a.asname or a.name] = ("from", module, a.name)
            elif isinstance(node, ast.Import):
                for a in node.names:
                    al[a.asname or a.name] = ("mod", a.name)
        return al

    def _resolve(self, mod: str, func: ast.AST) -> str | None:
        file = self.files.get(mod)
        if file is None:
            return None
        name = _dotted(func)
        short = name.split(".")[-1]
        # same-file function (bare name or self.name)
        if short in file["funcs"] and (name == short or name.startswith("self.") or name.startswith("cls.")):
            return file["funcs"][short]
        # imported symbol: from m import short [as name]
        tgt = file["aliases"].get(name) or file["aliases"].get(short)
        if tgt and tgt[0] == "from":
            q = self._match(tgt[2], tgt[1])
            if q:
                return q
        # module alias / dotted: a.b.func()
        if "." in name:
            parts = name.split(".")
            q = self._match(parts[-1], ".".join(parts[:-1]))
            if q:
                return q
        # unique simple name, preferring same file
        cands = self.simple.get(short)
        if cands:
            same = [q for q in cands if q.split("::")[0] == mod]
            if same:
                return same[0]
            if len(cands) == 1:
                return cands[0]
        return None

    def _match(self, name: str, modhint: str) -> str | None:
        cands = self.simple.get(name)
        if not cands:
            return None
        hint = modhint.lstrip(".")
        best = [q for q in cands if hint and (q.split("::")[0].endswith(hint) or hint.endswith(q.split("::")[0]))]
        if best:
            return best[0]
        return cands[0] if len(cands) == 1 else None

    # ---- taint of an expression (origin tuple or None) ----
    def _taint(self, mod: str, node: ast.AST, tainted: dict):
        src = _is_source(node)
        if src:
            return ("source", src)
        if isinstance(node, ast.Name):
            return tainted.get(node.id)
        if isinstance(node, ast.BinOp):
            return self._taint(mod, node.left, tainted) or self._taint(mod, node.right, tainted)
        if isinstance(node, ast.BoolOp):
            for v in node.values:
                o = self._taint(mod, v, tainted)
                if o:
                    return o
            return None
        if isinstance(node, ast.IfExp):
            return self._taint(mod, node.body, tainted) or self._taint(mod, node.orelse, tainted)
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    o = self._taint(mod, v.value, tainted)
                    if o:
                        return o
            return None
        if isinstance(node, (ast.Subscript, ast.Starred, ast.Await)):
            return self._taint(mod, node.value, tainted)
        if isinstance(node, ast.Attribute):
            return self._taint(mod, node.value, tainted)
        if isinstance(node, ast.Call):
            fname = _dotted(node.func)
            short = fname.split(".")[-1]
            if fname in SANITIZERS or short in SANITIZERS or short in {"quote", "escape"}:
                return None
            q = self._resolve(mod, node.func)
            if q and q in self.summaries:
                summ = self.summaries[q]
                if summ["source_return"]:
                    return ("retsource", self.gfuncs[q]["name"])
                mapping = self._map_args(node, q)
                for pname in summ["ret_params"]:
                    arg = mapping.get(pname)
                    if arg is not None:
                        o = self._taint(mod, arg, tainted)
                        if o:
                            return o
                return None
            if isinstance(node.func, ast.Attribute):
                o = self._taint(mod, node.func.value, tainted)
                if o:
                    return o
            for a in list(node.args) + [k.value for k in node.keywords]:
                o = self._taint(mod, a, tainted)
                if o:
                    return o
            return None
        return None

    def _map_args(self, call: ast.Call, qual: str) -> dict:
        fn = self.gfuncs[qual]["node"]
        names = _params(fn)
        offset = 1 if (names and names[0] in {"self", "cls"} and isinstance(call.func, ast.Attribute)) else 0
        m = {}
        for i, arg in enumerate(call.args):
            j = i + offset
            if j < len(names):
                m[names[j]] = arg
        for kw in call.keywords:
            if kw.arg in names:
                m[kw.arg] = kw.value
        return m

    def _tainted_names(self, mod: str, fn: ast.AST, seed_params: bool) -> dict:
        tainted: dict = {}
        if seed_params:
            for p in _params(fn):
                if p not in {"self", "cls"}:
                    tainted[p] = ("param", p)
        body = ast.Module(body=list(fn.body), type_ignores=[])
        changed, passes = True, 0
        while changed and passes < MAX_PASSES:
            changed, passes = False, passes + 1
            for node in ast.walk(body):
                targets, value = None, None
                if isinstance(node, ast.Assign):
                    targets, value = node.targets, node.value
                elif isinstance(node, ast.AnnAssign) and node.value is not None:
                    targets, value = [node.target], node.value
                elif isinstance(node, ast.AugAssign):
                    targets, value = [node.target], node.value
                elif isinstance(node, (ast.For, ast.AsyncFor)):
                    targets, value = [node.target], node.iter
                if value is None:
                    continue
                o = self._taint(mod, value, tainted)
                if o is None:
                    continue
                for tgt in targets or []:
                    for n in ast.walk(tgt):
                        if isinstance(n, ast.Name) and n.id not in tainted:
                            tainted[n.id] = o
                            changed = True
        return tainted

    @staticmethod
    def _calls(fn: ast.AST):
        for node in ast.walk(ast.Module(body=list(fn.body), type_ignores=[])):
            if isinstance(node, ast.Call):
                yield node

    # ---- summaries fixpoint ----
    def build(self):
        for q in self.gfuncs:
            self.summaries[q] = {"source_return": False, "ret_params": set(), "sink_params": {}}
        changed, passes = True, 0
        while changed and passes < MAX_PASSES:
            changed, passes = False, passes + 1
            for q, info in self.gfuncs.items():
                mod, fn = info["mod"], info["node"]
                summ = self.summaries[q]
                tainted = self._tainted_names(mod, fn, seed_params=True)
                src_ret = summ["source_return"]
                ret_params = set(summ["ret_params"])
                sink_params = {k: list(v) for k, v in summ["sink_params"].items()}
                body = ast.Module(body=list(fn.body), type_ignores=[])
                for node in ast.walk(body):
                    if isinstance(node, ast.Return) and node.value is not None:
                        o = self._taint(mod, node.value, tainted)
                        if o and o[0] in {"source", "retsource"}:
                            src_ret = True
                        elif o and o[0] == "param":
                            ret_params.add(o[1])
                for call in self._calls(fn):
                    si = _sink_info(call)
                    if si:
                        for idx in si[7]:
                            if idx < len(call.args):
                                o = self._taint(mod, call.args[idx], tainted)
                                if o and o[0] == "param":
                                    sink_params.setdefault(o[1], [])
                                    if si not in sink_params[o[1]]:
                                        sink_params[o[1]].append(si)
                    cq = self._resolve(mod, call.func)
                    if cq and cq in self.summaries:
                        mapping = self._map_args(call, cq)
                        for pname, infos in self.summaries[cq]["sink_params"].items():
                            arg = mapping.get(pname)
                            if arg is None:
                                continue
                            o = self._taint(mod, arg, tainted)
                            if o and o[0] == "param":
                                for si2 in infos:
                                    sink_params.setdefault(o[1], [])
                                    if si2 not in sink_params[o[1]]:
                                        sink_params[o[1]].append(si2)
                if src_ret != summ["source_return"] or ret_params != summ["ret_params"] or sink_params != summ["sink_params"]:
                    summ.update(source_return=src_ret, ret_params=ret_params, sink_params=sink_params)
                    changed = True

    # ---- reporting ----
    def report(self) -> list[Finding]:
        scopes = [(info["mod"], info["node"], info["path"]) for info in self.gfuncs.values()]
        for mod, file in self.files.items():
            scopes.append((mod, file["tree"], file["path"]))  # module top-level
        for mod, fn, path in scopes:
            tainted = self._tainted_names(mod, fn, seed_params=False)
            for call in self._calls(fn):
                si = _sink_info(call)
                if si:
                    for idx in si[7]:
                        if idx < len(call.args):
                            o = self._taint(mod, call.args[idx], tainted)
                            if o and o[0] in {"source", "retsource"}:
                                self._emit(si, path, call.lineno, self._label(o), None, o)
                                break
                cq = self._resolve(mod, call.func)
                if cq and cq in self.summaries:
                    mapping = self._map_args(call, cq)
                    for pname, infos in self.summaries[cq]["sink_params"].items():
                        arg = mapping.get(pname)
                        if arg is None:
                            continue
                        o = self._taint(mod, arg, tainted)
                        if o and o[0] in {"source", "retsource"}:
                            self._emit(infos[0], path, call.lineno, self._label(o), self.gfuncs[cq]["name"], o)
        seen, uniq = set(), []
        for f in self.findings:
            k = (f.rule_id, f.file, f.line, f.snippet)
            if k not in seen:
                seen.add(k)
                uniq.append(f)
        return uniq

    @staticmethod
    def _label(origin) -> str:
        if origin[0] == "source":
            return origin[1]
        if origin[0] == "retsource":
            return f"قيمة من {origin[1]}()"
        return origin[1]

    def _emit(self, si, path, line, source_label, callee, origin=None):
        rule, sev, title, title_ar, advice, cwe, label, _idx = si
        interproc = bool(callee) or (origin is not None and origin[0] == "retsource")
        if callee:
            title = f"Tainted data flows through {callee}() into {label}"
            title_ar = f"بيانات غير موثوقة تمرّ عبر {callee}() وتصل إلى {label}"
            snippet = f"المصدر: {source_label} ← {callee}()"
            extra = {"analysis": "dataflow", "interprocedural": True, "taint_source": source_label, "callee": callee}
        else:
            snippet = f"المصدر: {source_label}"
            extra = {"analysis": "dataflow", "taint_source": source_label}
            if interproc:
                extra["interprocedural"] = True
        self.findings.append(Finding(rule, sev, title, title_ar, path, line, snippet, advice, cwe,
                                     source="taint", extra=extra))


def _module_name(rel: str) -> str:
    rel = rel[:-3] if rel.endswith(".py") else rel
    rel = rel[:-9] if rel.endswith("/__init__") else rel
    return rel.replace("/", ".").replace("\\", ".")


def analyze_project(files: dict[str, str]) -> list[Finding]:
    """Analyze many files together. ``files`` maps relative path -> source text."""
    proj = Project()
    for rel, text in files.items():
        proj.add_file(_module_name(rel), rel, text)
    if not proj.files:
        return []
    proj.build()
    return proj.report()


def analyze(path: str, text: str) -> list[Finding]:
    """Convenience: analyze a single file as a one-module project."""
    return analyze_project({path: text})
