"""Type-aware, inter-procedural, cross-file taint analysis for Python.  (vulnscan: ignore-file)

One model is built for the whole scanned project:

* every Python file is parsed; functions, classes and methods are indexed
  globally and imports are resolved, so calls are followed across files;
* a light type inference assigns a class to variables (constructor calls,
  annotations, ``self``, fields typed from ``self.x = Cls()``, functions whose
  return type is known), and method calls are resolved on the **receiver's
  type** through the class hierarchy (MRO) -- including *virtual dispatch*:
  when the static type is a base class, overriding methods in subclasses are
  considered too, as CodeQL does;
* analysis is **field-sensitive**: ``self.cmd = request.args[...]`` in one
  method and ``os.system(self.cmd)`` in another is a flow, and so is
  ``Foo(request.args[...]).run()`` when ``__init__`` stores the argument in a
  field that ``run`` sinks;
* taint flows through containers (``lst.append(t)``, ``d[k] = t``, literals);
* per-function summaries (returns untrusted data / which params or fields
  reach a sink / return type) are computed to a fixpoint so flows compose
  across any number of hops and files.

Sanitizers (shlex.quote, html.escape, int, ...) clear taint and constants are
never reported. This is still a pragmatic engine, not CodeQL: there is no
full points-to analysis, no query language and no library models beyond the
sources and sinks listed here.
"""

from __future__ import annotations

import ast
import re

from .model import Finding

REQUEST_ATTRS = {"args", "form", "values", "json", "data", "cookies", "headers",
                 "files", "GET", "POST", "query_params", "body"}
SANITIZERS = {"int", "float", "bool", "len", "shlex.quote", "html.escape", "escape",
              "markupsafe.escape", "urllib.parse.quote", "quote", "re.escape", "hash",
              "hashlib.sha256", "bleach.clean", "secure_filename"}
CONTAINER_WRITES = {"append", "extend", "insert", "add", "update", "put", "setdefault"}
MAX_PASSES = 16
SUPPRESS = re.compile(r"(nosec|vulnscan:\s*ignore|noqa:\s*S\d+)", re.I)
# Tainted element of an argv list after a fixed program, with no shell: argument
# injection (CWE-88) rather than command injection. CodeQL draws the same line.
ARG_INJECTION = ("DF009", "medium", "Tainted data reaches a subprocess argument",
                 "بيانات غير موثوقة تصل إلى وسيط لأمر خارجي",
                 "تحقّق من الوسيط بقائمة بيضاء، وارفض القيم التي تبدأ بـ -، ولا تمرّر مسارات غير مُطبَّعة.",
                 "CWE-88", "subprocess argument", [0])


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


def _scope_nodes(fn: ast.AST):
    """Nodes of a scope's body, without descending into nested functions, classes or lambdas."""
    stack = list(reversed(getattr(fn, "body", []) or []))
    while stack:
        n = stack.pop()
        yield n
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(n))))


# Catalogue of the data-flow rules, for the UI rules page and --list-rules.
TAINT_RULES = [
    {"id": "DF001", "severity": "critical", "cwe": "CWE-95", "title": "Tainted data reaches eval/exec",
     "title_ar": "بيانات غير موثوقة تصل إلى eval/exec", "advice": "لا تمرّر مدخلات المستخدم إلى eval/exec."},
    {"id": "DF002", "severity": "critical", "cwe": "CWE-78", "title": "Tainted data reaches os.system/popen",
     "title_ar": "بيانات غير موثوقة تصل إلى os.system", "advice": "لا تبنِ أوامر النظام من المدخلات."},
    {"id": "DF003", "severity": "high", "cwe": "CWE-78", "title": "Tainted command/program reaches subprocess",
     "title_ar": "أمر أو برنامج ملوّث يصل إلى subprocess", "advice": "قائمة وسائط بلا shell=True وبرنامج ثابت."},
    {"id": "DF004", "severity": "high", "cwe": "CWE-89", "title": "Tainted data reaches SQL execute()",
     "title_ar": "بيانات غير موثوقة تصل إلى تنفيذ SQL", "advice": "استخدم استعلامات مُعَلَّمة."},
    {"id": "DF005", "severity": "high", "cwe": "CWE-22", "title": "Tainted data reaches a file path (open/send_file)",
     "title_ar": "بيانات غير موثوقة تصل إلى مسار ملف", "advice": "طبّع المسار وتحقق أنه داخل المجلد المسموح."},
    {"id": "DF006", "severity": "critical", "cwe": "CWE-502", "title": "Tainted data reaches pickle/yaml.load",
     "title_ar": "بيانات غير موثوقة تصل إلى فك تسلسل", "advice": "استخدم JSON أو yaml.safe_load."},
    {"id": "DF007", "severity": "high", "cwe": "CWE-1336", "title": "Tainted data reaches render_template_string",
     "title_ar": "بيانات غير موثوقة تصل إلى قالب ديناميكي", "advice": "قوالب ثابتة ومرّر البيانات كمتغيرات."},
    {"id": "DF008", "severity": "medium", "cwe": "CWE-601", "title": "Tainted data reaches redirect()",
     "title_ar": "بيانات غير موثوقة تصل إلى redirect", "advice": "قائمة بيضاء لوجهات التحويل."},
    {"id": "DF009", "severity": "medium", "cwe": "CWE-88", "title": "Tainted subprocess argument (fixed program)",
     "title_ar": "وسيط ملوّث لأمر خارجي ثابت", "advice": "تحقّق من الوسيط وارفض القيم التي تبدأ بـ -."},
]


def _params(fn: ast.AST) -> list[str]:
    a = fn.args
    return [p.arg for p in (a.posonlyargs + a.args)]


def _annotation_name(ann: ast.AST | None) -> str | None:
    if ann is None:
        return None
    if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
        return ann.value
    if isinstance(ann, ast.Subscript):          # Optional[Foo], list[Foo] -> Foo
        return _annotation_name(ann.slice)
    if isinstance(ann, ast.BinOp):              # Foo | None
        return _annotation_name(ann.left) or _annotation_name(ann.right)
    name = _dotted(ann)
    return name or None


class _Env:
    """Per-function environment: taint origins, static types, instance fields."""
    __slots__ = ("tainted", "types", "inst", "elem")

    def __init__(self):
        self.tainted: dict = {}     # var -> origin
        self.types: dict = {}       # var -> class qual
        self.inst: dict = {}        # var -> {field: origin}  (object created with tainted ctor args)
        self.elem: set = set()      # vars tainted only through a non-head container element


class Project:
    def __init__(self):
        self.files: dict[str, dict] = {}
        self.gfuncs: dict[str, dict] = {}     # qual -> {node, mod, name, cls, path}
        self.classes: dict[str, dict] = {}    # cqual -> {node, mod, name, bases, methods, subclasses, ...}
        self.simple_funcs: dict[str, list] = {}
        self.simple_methods: dict[str, list] = {}
        self.simple_classes: dict[str, list] = {}
        self.summaries: dict[str, dict] = {}
        self.lines_by_path: dict[str, list] = {}
        self.findings: list[Finding] = []

    # ------------------------------------------------------------ building
    def add_file(self, mod: str, path: str, text: str) -> bool:
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            return False
        file = {"path": path, "tree": tree, "aliases": self._aliases(tree), "funcs": {}, "classes": {},
                "lines": text.splitlines()}
        self.files[mod] = file
        self.lines_by_path[path] = file["lines"]

        def visit(node, cls_qual):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ClassDef):
                    cq = f"{mod}::{child.name}"
                    self.classes[cq] = {"node": child, "mod": mod, "name": child.name, "path": path,
                                        "base_names": [_dotted(b) for b in child.bases], "bases": [],
                                        "methods": {}, "subclasses": set(), "field_types": {},
                                        "tainted_fields": set(), "ctor_param_fields": {}}
                    file["classes"][child.name] = cq
                    self.simple_classes.setdefault(child.name, []).append(cq)
                    visit(child, cq)
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if cls_qual:
                        q = f"{cls_qual}.{child.name}"
                        self.classes[cls_qual]["methods"][child.name] = q
                        self.simple_methods.setdefault(child.name, []).append(q)
                    else:
                        q = f"{mod}::{child.name}"
                        file["funcs"][child.name] = q
                        self.simple_funcs.setdefault(child.name, []).append(q)
                    self.gfuncs[q] = {"node": child, "mod": mod, "name": child.name, "cls": cls_qual, "path": path}
                    visit(child, None if not cls_qual else None)
                else:
                    visit(child, cls_qual)

        visit(tree, None)
        return True

    @staticmethod
    def _aliases(tree: ast.AST) -> dict:
        al = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for a in node.names:
                    al[a.asname or a.name] = ("from", node.module or "", a.name)
            elif isinstance(node, ast.Import):
                for a in node.names:
                    al[a.asname or a.name] = ("mod", a.name)
        return al

    def link(self):
        """Resolve base classes and build the subclass map (after all files are added)."""
        for cq, c in self.classes.items():
            for bname in c["base_names"]:
                bq = self._resolve_class(c["mod"], bname)
                if bq and bq != cq:
                    c["bases"].append(bq)
                    self.classes[bq]["subclasses"].add(cq)

    # ---------------------------------------------------------- resolution
    def _match(self, index: dict, name: str, modhint: str) -> str | None:
        cands = index.get(name)
        if not cands:
            return None
        hint = modhint.lstrip(".")
        if hint:
            best = [q for q in cands if q.split("::")[0].endswith(hint) or hint.endswith(q.split("::")[0])]
            if best:
                return best[0]
        return cands[0] if len(cands) == 1 else None

    def _resolve_class(self, mod: str, name: str) -> str | None:
        if not name:
            return None
        file = self.files.get(mod, {})
        short = name.split(".")[-1]
        if short in file.get("classes", {}) and (name == short):
            return file["classes"][short]
        tgt = file.get("aliases", {}).get(name) or file.get("aliases", {}).get(name.split(".")[0])
        if tgt and tgt[0] == "from":
            q = self._match(self.simple_classes, tgt[2] if name == (tgt[2] if False else name) else short, tgt[1])
            if q:
                return q
        if "." in name:
            parts = name.split(".")
            q = self._match(self.simple_classes, parts[-1], ".".join(parts[:-1]))
            if q:
                return q
        cands = self.simple_classes.get(short)
        if cands:
            same = [q for q in cands if q.split("::")[0] == mod]
            if same:
                return same[0]
            if len(cands) == 1:
                return cands[0]
        return None

    def _resolve_function(self, mod: str, name: str) -> str | None:
        file = self.files.get(mod, {})
        short = name.split(".")[-1]
        if short in file.get("funcs", {}) and name == short:
            return file["funcs"][short]
        tgt = file.get("aliases", {}).get(name) or file.get("aliases", {}).get(short)
        if tgt and tgt[0] == "from":
            q = self._match(self.simple_funcs, tgt[2], tgt[1])
            if q:
                return q
        if "." in name:
            parts = name.split(".")
            q = self._match(self.simple_funcs, parts[-1], ".".join(parts[:-1]))
            if q:
                return q
        cands = self.simple_funcs.get(short)
        if cands:
            same = [q for q in cands if q.split("::")[0] == mod]
            if same:
                return same[0]
            if len(cands) == 1:
                return cands[0]
        return None

    def _mro(self, cq: str) -> list[str]:
        out, stack = [], [cq]
        while stack:
            c = stack.pop(0)
            if c in out or c not in self.classes:
                continue
            out.append(c)
            stack.extend(self.classes[c]["bases"])
        return out

    def _all_subclasses(self, cq: str) -> set[str]:
        out, stack = set(), [cq]
        while stack:
            c = stack.pop()
            for s in self.classes.get(c, {}).get("subclasses", ()):
                if s not in out:
                    out.add(s)
                    stack.append(s)
        return out

    def _class_fields(self, cq: str, key: str) -> dict | set:
        """Union of a per-class field table over the MRO."""
        merged: dict | set = {} if key != "tainted_fields" else set()
        for c in reversed(self._mro(cq)):
            val = self.classes[c][key]
            if isinstance(merged, set):
                merged |= val
            else:
                merged.update(val)
        return merged

    def _lookup_method(self, cq: str, name: str) -> list[str]:
        """Method on the receiver's static type via MRO, plus overrides in subclasses (virtual dispatch)."""
        found = []
        for c in self._mro(cq):
            q = self.classes[c]["methods"].get(name)
            if q:
                found.append(q)
                break
        for s in self._all_subclasses(cq):
            q = self.classes[s]["methods"].get(name)
            if q and q not in found:
                found.append(q)
        return found

    def _callees(self, mod: str, cls: str | None, call: ast.Call, env: _Env) -> tuple[list[str], str | None]:
        """Candidate callee quals for a call, and the class qual if it is a constructor call."""
        f = call.func
        if isinstance(f, ast.Name):
            cq = self._resolve_class(mod, f.id)
            if cq:
                return self._lookup_method(cq, "__init__"), cq
            q = self._resolve_function(mod, f.id)
            return ([q] if q else []), None
        if isinstance(f, ast.Attribute):
            recv = f.value
            rtype = None
            if isinstance(recv, ast.Name) and recv.id in {"self", "cls"} and cls:
                rtype = cls
            else:
                rtype = self._type_of(mod, cls, recv, env)
            if rtype:
                return self._lookup_method(rtype, f.attr), None
            # module alias: mod.func()
            if isinstance(recv, ast.Name):
                tgt = self.files.get(mod, {}).get("aliases", {}).get(recv.id)
                if tgt and tgt[0] == "mod":
                    q = self._match(self.simple_funcs, f.attr, tgt[1])
                    if q:
                        return [q], None
                    cq = self._match(self.simple_classes, f.attr, tgt[1])
                    if cq:
                        return self._lookup_method(cq, "__init__"), cq
            # dotted path to a function in another module
            name = _dotted(f)
            if "." in name:
                q = self._resolve_function(mod, name)
                if q:
                    return [q], None
            # receiver of unknown type: only an unambiguous method name is followed
            cands = self.simple_methods.get(f.attr, [])
            if len(cands) == 1:
                return cands, None
            same = [q for q in cands if q.split("::")[0] == mod]
            if len(same) == 1:
                return same, None
        return [], None

    # ---------------------------------------------------------------- types
    def _type_of(self, mod: str, cls: str | None, node: ast.AST, env: _Env) -> str | None:
        if isinstance(node, ast.Name):
            if node.id in {"self", "cls"} and cls:
                return cls
            return env.types.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self._type_of(mod, cls, node.value, env)
            if base:
                return self._class_fields(base, "field_types").get(node.attr)
            return None
        if isinstance(node, ast.Call):
            callees, ctor = self._callees(mod, cls, node, env)
            if ctor:
                return ctor
            for q in callees:
                rt = self.summaries.get(q, {}).get("ret_type")
                if rt:
                    return rt
            return None
        if isinstance(node, ast.Await):
            return self._type_of(mod, cls, node.value, env)
        return None

    # ---------------------------------------------------------------- taint
    def _map_args(self, call: ast.Call, qual: str) -> dict:
        fn = self.gfuncs[qual]["node"]
        names = _params(fn)
        offset = 1 if (names and names[0] in {"self", "cls"}) else 0
        m = {}
        for i, arg in enumerate(call.args):
            j = i + offset
            if j < len(names):
                m[names[j]] = arg
        for kw in call.keywords:
            if kw.arg in names:
                m[kw.arg] = kw.value
        return m

    def _ctor_inst_fields(self, mod: str, cls: str | None, call: ast.Call, env: _Env) -> dict:
        """{field: origin} for an object built by this constructor call with tainted arguments."""
        callees, ctor = self._callees(mod, cls, call, env)
        if not ctor:
            return {}
        out: dict = {}
        pf = self._class_fields(ctor, "ctor_param_fields")
        for q in callees:
            mapping = self._map_args(call, q)
            for pname, fld in pf.items():
                arg = mapping.get(pname)
                if arg is None:
                    continue
                o = self._taint(mod, cls, arg, env)
                if o and fld not in out:
                    out[fld] = o
        return out

    def _receiver_fields(self, mod: str, cls: str | None, call: ast.Call, env: _Env) -> tuple[set, bool]:
        """(fields of the receiver known to be tainted, receiver is self)."""
        f = call.func
        if not isinstance(f, ast.Attribute):
            return set(), False
        recv = f.value
        if isinstance(recv, ast.Name) and recv.id in {"self", "cls"} and cls:
            return set(self._class_fields(cls, "tainted_fields")), True
        fields = set()
        if isinstance(recv, ast.Name) and recv.id in env.inst:
            fields |= set(env.inst[recv.id].keys())
        if isinstance(recv, ast.Call):
            fields |= set(self._ctor_inst_fields(mod, cls, recv, env).keys())
        rtype = self._type_of(mod, cls, recv, env)
        if rtype:
            fields |= set(self._class_fields(rtype, "tainted_fields"))
        return fields, False

    def _taint(self, mod: str, cls: str | None, node: ast.AST, env: _Env):
        src = _is_source(node)
        if src:
            return ("source", src)
        if isinstance(node, ast.Name):
            return env.tainted.get(node.id)
        if isinstance(node, ast.BinOp):
            return self._taint(mod, cls, node.left, env) or self._taint(mod, cls, node.right, env)
        if isinstance(node, ast.BoolOp):
            for v in node.values:
                o = self._taint(mod, cls, v, env)
                if o:
                    return o
            return None
        if isinstance(node, ast.IfExp):
            return self._taint(mod, cls, node.body, env) or self._taint(mod, cls, node.orelse, env)
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    o = self._taint(mod, cls, v.value, env)
                    if o:
                        return o
            return None
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for e in node.elts:
                o = self._taint(mod, cls, e, env)
                if o:
                    return o
            return None
        if isinstance(node, ast.Dict):
            for e in list(node.keys) + list(node.values):
                if e is not None:
                    o = self._taint(mod, cls, e, env)
                    if o:
                        return o
            return None
        if isinstance(node, (ast.Subscript, ast.Starred, ast.Await)):
            return self._taint(mod, cls, node.value, env)
        if isinstance(node, ast.Attribute):
            recv = node.value
            # self.field
            if isinstance(recv, ast.Name) and recv.id in {"self", "cls"} and cls:
                if node.attr in self._class_fields(cls, "tainted_fields"):
                    return ("source", f"self.{node.attr}")
                return ("field", node.attr)
            # obj.field where obj was built with tainted ctor args, or its class has a tainted field
            if isinstance(recv, ast.Name) and recv.id in env.inst and node.attr in env.inst[recv.id]:
                return env.inst[recv.id][node.attr]
            if isinstance(recv, ast.Call):
                tmp = self._ctor_inst_fields(mod, cls, recv, env)
                if node.attr in tmp:
                    return tmp[node.attr]
            rtype = self._type_of(mod, cls, recv, env)
            if rtype and node.attr in self._class_fields(rtype, "tainted_fields"):
                return ("source", f"{_dotted(recv)}.{node.attr}")
            return self._taint(mod, cls, recv, env)
        if isinstance(node, ast.Call):
            fname = _dotted(node.func)
            short = fname.split(".")[-1]
            if fname in SANITIZERS or short in SANITIZERS or short in {"quote", "escape"}:
                return None
            callees, ctor = self._callees(mod, cls, node, env)
            if ctor:
                return None  # an object, not a string; its tainted fields are tracked in env.inst
            if callees:
                fields, _ = self._receiver_fields(mod, cls, node, env)
                for q in callees:
                    summ = self.summaries.get(q)
                    if not summ:
                        continue
                    if summ["source_return"]:
                        return ("retsource", self.gfuncs[q]["name"])
                    mapping = self._map_args(node, q)
                    for pname in summ["ret_params"]:
                        arg = mapping.get(pname)
                        if arg is not None:
                            o = self._taint(mod, cls, arg, env)
                            if o:
                                return o
                    for fld in summ["ret_fields"]:
                        if fld in fields:
                            return ("source", f"field {fld} via {self.gfuncs[q]['name']}()")
                        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) \
                                and node.func.value.id in {"self", "cls"}:
                            return ("field", fld)
                return None
            if isinstance(node.func, ast.Attribute):
                o = self._taint(mod, cls, node.func.value, env)
                if o:
                    return o
            for a in list(node.args) + [k.value for k in node.keywords]:
                o = self._taint(mod, cls, a, env)
                if o:
                    return o
            return None
        return None

    # --------------------------------------------------------- environment
    def _env(self, mod: str, cls: str | None, fn: ast.AST, seed_params: bool) -> _Env:
        env = _Env()
        is_func = isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
        if is_func:
            for p in fn.args.posonlyargs + fn.args.args:
                if p.arg in {"self", "cls"}:
                    continue
                t = self._resolve_class(mod, _annotation_name(p.annotation) or "")
                if t:
                    env.types[p.arg] = t
                if seed_params:
                    env.tainted[p.arg] = ("param", p.arg)
        changed, passes = True, 0
        while changed and passes < MAX_PASSES:
            changed, passes = False, passes + 1
            for node in _scope_nodes(fn):
                targets, value, ann = None, None, None
                if isinstance(node, ast.Assign):
                    targets, value = node.targets, node.value
                elif isinstance(node, ast.AnnAssign):
                    targets, value, ann = [node.target], node.value, node.annotation
                elif isinstance(node, ast.AugAssign):
                    targets, value = [node.target], node.value
                elif isinstance(node, (ast.For, ast.AsyncFor)):
                    targets, value = [node.target], node.iter
                elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                    targets, value = [node.optional_vars], node.context_expr
                elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                    # container writes: x.append(t) / x.update(t) ...
                    c = node.value
                    if isinstance(c.func, ast.Attribute) and c.func.attr in CONTAINER_WRITES \
                            and isinstance(c.func.value, ast.Name):
                        for a in list(c.args) + [k.value for k in c.keywords]:
                            o = self._taint(mod, cls, a, env)
                            if o and c.func.value.id not in env.tainted:
                                env.tainted[c.func.value.id] = o
                                env.elem.add(c.func.value.id)
                                changed = True
                    continue
                else:
                    continue
                for tgt in targets or []:
                    # types
                    t = None
                    if ann is not None:
                        t = self._resolve_class(mod, _annotation_name(ann) or "")
                    if t is None and value is not None:
                        t = self._type_of(mod, cls, value, env)
                    if t and isinstance(tgt, ast.Name) and env.types.get(tgt.id) != t:
                        env.types[tgt.id] = t
                        changed = True
                    # instances built with tainted constructor args
                    if value is not None and isinstance(tgt, ast.Name) and isinstance(value, ast.Call):
                        for fld, o in self._ctor_inst_fields(mod, cls, value, env).items():
                            if fld not in env.inst.setdefault(tgt.id, {}):
                                env.inst[tgt.id][fld] = o
                                changed = True
                    if value is not None and isinstance(tgt, ast.Name) and isinstance(value, ast.Name) \
                            and value.id in env.inst and tgt.id not in env.inst:
                        env.inst[tgt.id] = dict(env.inst[value.id])
                        changed = True
                    # taint
                    if value is None:
                        continue
                    o = self._taint(mod, cls, value, env)
                    if o is None:
                        continue
                    if isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name):
                        names, elem = [tgt.value.id], True
                    else:
                        names = [n.id for n in ast.walk(tgt) if isinstance(n, ast.Name)]
                        if isinstance(node, ast.AugAssign) or isinstance(value, ast.Dict):
                            elem = True
                        elif isinstance(value, (ast.List, ast.Tuple)):
                            elem = bool(value.elts) and self._taint(mod, cls, value.elts[0], env) is None
                        else:
                            elem = False
                    for nm in names:
                        if nm not in env.tainted:
                            env.tainted[nm] = o
                            if elem:
                                env.elem.add(nm)
                            changed = True
                        elif not elem and nm in env.elem:
                            env.elem.discard(nm)   # a whole-value taint dominates
                            changed = True
        return env

    def _subprocess_elem_only(self, mod, cls, call: ast.Call, env: _Env) -> bool:
        """True when only a non-program argv element is tainted and no shell is used."""
        kw = {k.arg: k.value for k in call.keywords}
        if isinstance(kw.get("shell"), ast.Constant) and kw["shell"].value is True:
            return False
        arg = call.args[0] if call.args else kw.get("args")
        if arg is None:
            return False
        if isinstance(arg, (ast.List, ast.Tuple)):
            return bool(arg.elts) and self._taint(mod, cls, arg.elts[0], env) is None
        if isinstance(arg, ast.Name):
            return arg.id in env.elem
        return False

    def _sink(self, mod, cls, call: ast.Call, env: _Env):
        si = _sink_info(call)
        if si and si[0] == "DF003" and self._subprocess_elem_only(mod, cls, call, env):
            return ARG_INJECTION
        return si

    @staticmethod
    def _calls(fn: ast.AST):
        for node in _scope_nodes(fn):
            if isinstance(node, ast.Call):
                yield node

    # ------------------------------------------------------------ summaries
    def build(self):
        self.link()
        for q in self.gfuncs:
            self.summaries[q] = {"source_return": False, "ret_params": set(), "sink_params": {},
                                 "sink_fields": {}, "ret_fields": set(), "ret_type": None}
        changed, passes = True, 0
        while changed and passes < MAX_PASSES:
            changed, passes = False, passes + 1
            for q, info in self.gfuncs.items():
                mod, fn, cls = info["mod"], info["node"], info["cls"]
                summ = self.summaries[q]
                env = self._env(mod, cls, fn, seed_params=True)
                new = {"source_return": summ["source_return"], "ret_params": set(summ["ret_params"]),
                       "sink_params": {k: list(v) for k, v in summ["sink_params"].items()},
                       "sink_fields": {k: list(v) for k, v in summ["sink_fields"].items()},
                       "ret_fields": set(summ["ret_fields"]), "ret_type": summ["ret_type"]}
                # return annotation as type
                rt = self._resolve_class(mod, _annotation_name(getattr(fn, "returns", None)) or "")
                if rt:
                    new["ret_type"] = rt
                for node in _scope_nodes(fn):
                    if isinstance(node, ast.Return) and node.value is not None:
                        o = self._taint(mod, cls, node.value, env)
                        if o and o[0] in {"source", "retsource"}:
                            new["source_return"] = True
                        elif o and o[0] == "param":
                            new["ret_params"].add(o[1])
                        elif o and o[0] == "field":
                            new["ret_fields"].add(o[1])
                        if new["ret_type"] is None:
                            t = self._type_of(mod, cls, node.value, env)
                            if t:
                                new["ret_type"] = t
                    # self.attr = ... : class field tables
                    if cls and isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                        tgts = node.targets if isinstance(node, ast.Assign) else [node.target]
                        for tgt in tgts:
                            if isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name) and tgt.value.id == "self":
                                c = self.classes[cls]
                                o = self._taint(mod, cls, node.value, env)
                                if o and o[0] in {"source", "retsource"} and tgt.attr not in c["tainted_fields"]:
                                    c["tainted_fields"].add(tgt.attr)
                                    changed = True
                                if o and o[0] == "param" and info["name"] == "__init__" and c["ctor_param_fields"].get(o[1]) != tgt.attr:
                                    c["ctor_param_fields"][o[1]] = tgt.attr
                                    changed = True
                                t = self._type_of(mod, cls, node.value, env)
                                if t and c["field_types"].get(tgt.attr) != t:
                                    c["field_types"][tgt.attr] = t
                                    changed = True
                for call in self._calls(fn):
                    self._absorb_sinks(mod, cls, call, env, new)
                if new != summ:
                    summ.update(new)
                    changed = True

    def _absorb_sinks(self, mod, cls, call, env, new):
        """Record which params/fields of the current function reach a sink via this call."""
        def record(origin, si):
            if origin[0] == "param":
                lst = new["sink_params"].setdefault(origin[1], [])
            elif origin[0] == "field":
                lst = new["sink_fields"].setdefault(origin[1], [])
            else:
                return
            if si not in lst:
                lst.append(si)

        si = self._sink(mod, cls, call, env)
        if si:
            for idx in si[7]:
                if idx < len(call.args):
                    o = self._taint(mod, cls, call.args[idx], env)
                    if o:
                        record(o, si)
        callees, ctor = self._callees(mod, cls, call, env)
        if ctor:
            return
        fields, is_self = self._receiver_fields(mod, cls, call, env)
        for q in callees:
            summ = self.summaries.get(q)
            if not summ:
                continue
            mapping = self._map_args(call, q)
            for pname, infos in summ["sink_params"].items():
                arg = mapping.get(pname)
                if arg is None:
                    continue
                o = self._taint(mod, cls, arg, env)
                if o:
                    for si2 in infos:
                        record(o, si2)
            if is_self:
                for fld, infos in summ["sink_fields"].items():
                    for si2 in infos:
                        record(("field", fld), si2)

    # ------------------------------------------------------------ reporting
    def report(self) -> list[Finding]:
        scopes = [(i["mod"], i["cls"], i["node"], i["path"]) for i in self.gfuncs.values()]
        for mod, file in self.files.items():
            scopes.append((mod, None, file["tree"], file["path"]))
        for mod, cls, fn, path in scopes:
            env = self._env(mod, cls, fn, seed_params=False)
            for call in self._calls(fn):
                si = self._sink(mod, cls, call, env)
                if si:
                    for idx in si[7]:
                        if idx < len(call.args):
                            o = self._taint(mod, cls, call.args[idx], env)
                            if o and o[0] in {"source", "retsource"}:
                                self._emit(si, path, call.lineno, self._label(o), None, o)
                                break
                callees, ctor = self._callees(mod, cls, call, env)
                if ctor:
                    continue
                fields, _ = self._receiver_fields(mod, cls, call, env)
                for q in callees:
                    summ = self.summaries.get(q)
                    if not summ:
                        continue
                    name = self.gfuncs[q]["name"]
                    mapping = self._map_args(call, q)
                    done = False
                    for pname, infos in summ["sink_params"].items():
                        arg = mapping.get(pname)
                        if arg is None:
                            continue
                        o = self._taint(mod, cls, arg, env)
                        if o and o[0] in {"source", "retsource"}:
                            self._emit(infos[0], path, call.lineno, self._label(o), name, o)
                            done = True
                            break
                    if done:
                        continue
                    for fld, infos in summ["sink_fields"].items():
                        if fld in fields:
                            self._emit(infos[0], path, call.lineno, f"الحقل {fld}", name, ("source", fld))
                            break
        seen, uniq = set(), []
        for f in self.findings:
            k = (f.rule_id, f.file, f.line)
            if k not in seen:
                seen.add(k)
                uniq.append(f)
        return uniq

    @staticmethod
    def _label(origin) -> str:
        if origin[0] == "retsource":
            return f"قيمة من {origin[1]}()"
        return origin[1]

    def _emit(self, si, path, line, source_label, callee, origin=None):
        lines = self.lines_by_path.get(path) or []
        if 0 < line <= len(lines) and SUPPRESS.search(lines[line - 1]):
            return
        rule, sev, title, title_ar, advice, cwe, label, _idx = si
        interproc = bool(callee) or (origin is not None and origin[0] == "retsource")
        extra = {"analysis": "dataflow", "taint_source": source_label}
        if callee:
            title = f"Tainted data flows through {callee}() into {label}"
            title_ar = f"بيانات غير موثوقة تمرّ عبر {callee}() وتصل إلى {label}"
            snippet = f"المصدر: {source_label} ← {callee}()"
            extra.update(interprocedural=True, callee=callee)
        else:
            snippet = f"المصدر: {source_label}"
            if interproc:
                extra["interprocedural"] = True
        self.findings.append(Finding(rule, sev, title, title_ar, path, line, snippet, advice, cwe,
                                     source="taint", extra=extra))


def _module_name(rel: str) -> str:
    rel = rel[:-3] if rel.endswith(".py") else rel
    rel = rel[:-9] if rel.endswith("/__init__") else rel
    return rel.replace("/", ".").replace("\\", ".")


def analyze_project(files: dict[str, str]) -> list[Finding]:
    proj = Project()
    for rel, text in files.items():
        proj.add_file(_module_name(rel), rel, text)
    if not proj.files:
        return []
    proj.build()
    return proj.report()


def analyze(path: str, text: str) -> list[Finding]:
    return analyze_project({path: text})
