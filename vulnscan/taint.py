"""Type-aware, inter-procedural, cross-file taint analysis for Python.  (vulnscan: ignore-file)

Design (the parts that mirror CodeQL):

* **Models as data** -- sources, sinks, sanitizers, framework entry points and
  validators are declared in JSON (``vulnscan/models/python.json``); users add
  their own files with ``--models DIR``. No code change is needed to model a
  new library.
* **Whole-program model**: every file is parsed, functions/classes/methods are
  indexed globally and imports (absolute, aliased and relative) are resolved,
  so calls are followed across files. Names are canonicalised through the
  import aliases (``import subprocess as sp; sp.run`` matches ``subprocess.run``).
* **Type-aware call resolution**: variables get a class from constructors,
  annotations, ``self``, typed fields and known return types; methods are
  resolved through the MRO with virtual dispatch over subclass overrides.
  Function values (``h = helper``, ``functools.partial``) are followed too.
* **Field- and container-sensitive flow**: ``self.x`` across methods,
  constructor arguments into fields, ``append``/subscript stores/literals.
* **Framework entry points**: parameters of routed handlers (Flask/FastAPI/
  Django views, class-based views, CLI commands) are sources.
* **Barrier guards** (path sensitivity): a sink under ``if x in ALLOWED`` /
  ``x.isalnum()`` / ``re.fullmatch(..., x)`` / after ``if not valid(x): return``
  is not reported.
* **Flow paths**: every finding carries the step-by-step path from the source,
  through assignments and calls, to the sink.
* Summaries (returns-untrusted, params/fields that reach a sink, return type,
  return location) are computed to a fixpoint so flows compose across hops.

Still not CodeQL: no full points-to analysis, no query language (models are
declarative JSON, not QL), Python only.
"""

from __future__ import annotations

import ast
import json
import pathlib
import re

from .model import Finding

MAX_PASSES = 16
SUPPRESS = re.compile(r"(nosec|vulnscan:\s*ignore|noqa:\s*S\d+)", re.I)
DEFAULT_MODELS = pathlib.Path(__file__).parent / "models" / "python.json"
DEFAULT_JS_MODELS = pathlib.Path(__file__).parent / "models" / "javascript.json"
PY_EXTS = (".py",)
JS_EXTS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
CFAMILY = {".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".cs": "csharp", ".go": "go", ".php": "php", ".phtml": "php"}
MODELS_DIR = pathlib.Path(__file__).parent / "models"
CONTAINER_WRITES = {"append", "extend", "insert", "add", "update", "put", "setdefault"}
ARG_INJECTION = ("DF009", "medium", "Tainted data reaches a subprocess argument",
                 "بيانات غير موثوقة تصل إلى وسيط لأمر خارجي",
                 "تحقّق من الوسيط بقائمة بيضاء، وارفض القيم التي تبدأ بـ -، ولا تمرّر مسارات غير مُطبَّعة.",
                 "CWE-88", "subprocess argument", [0], False)
REFLECTED_RETURN = ("DF013", "medium", "Tainted data returned in an HTTP response (reflected XSS)",
                    "بيانات غير موثوقة تُعاد في استجابة HTTP (XSS انعكاسي)",
                    "هرّب المخرجات (html.escape / markupsafe) أو استخدم قوالب تُهرِّب تلقائيًا.",
                    "CWE-79", "HTTP response", [0], False)


# ------------------------------------------------------------------ models
def load_models(extra_dirs=(), base=None, language="python") -> dict:
    """Merge the built-in models for a language with every *.json in the given directories."""
    m = {"attr_sources": [], "call_sources": [], "name_sources": [], "entry_decorators": set(),
         "view_bases": set(), "view_methods": set(), "request_params": {"request", "req", "self"},
         "sinks": [], "attr_sinks": [], "sanitizers": set(), "safe_return_calls": set(), "validators": set(),
         "language": language}
    paths = [base or DEFAULT_MODELS]
    for d in extra_dirs or ():
        p = pathlib.Path(d)
        if p.is_file() and p.suffix == ".json":
            paths.append(p)
        elif p.is_dir():
            paths.extend(sorted(p.glob("*.json")))
    for path in paths:
        try:
            data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        langs = data.get("languages")
        if langs and language not in langs:
            continue
        for a in data.get("attr_sinks", []):
            m["attr_sinks"].append(((a["rule"], a.get("severity", "medium"), a.get("title", a["rule"]), a.get("title_ar", a.get("title", a["rule"])),
                                     a.get("advice", ""), a.get("cwe", ""), a.get("label", a["rule"]), [0], False), set(a.get("attrs", []))))
        for s in data.get("sources", []):
            kind = s.get("kind")
            if kind == "attr":
                m["attr_sources"].append((set(s.get("roots", [])), set(s.get("attrs", [])), s.get("label", "request.{attr}")))
            elif kind == "call":
                m["call_sources"].append((list(s.get("names", [])), s.get("label", "{name}()")))
            elif kind == "name":
                m["name_sources"].append((list(s.get("names", [])), s.get("label", "{name}")))
        for e in data.get("entry_points", []):
            m["entry_decorators"] |= set(e.get("decorators", []))
            m["view_bases"] |= set(e.get("view_bases", []))
            m["view_methods"] |= set(e.get("methods", []))
            m["request_params"] |= set(e.get("param_names", []))
        for k in data.get("sinks", []):
            m["sinks"].append((k["rule"], k.get("severity", "high"), k.get("title", k["rule"]), k.get("title_ar", k.get("title", k["rule"])),
                               k.get("advice", ""), k.get("cwe", ""), k.get("label", k["rule"]), list(k.get("args", [0])),
                               bool(k.get("shell", False)), list(k.get("names", []))))
        m["sanitizers"] |= set(data.get("sanitizers", []))
        m["safe_return_calls"] |= set(data.get("safe_return_calls", []))
        m["validators"] |= set(data.get("validators", []))
    return m


def _name_matches(canon: str, name: str) -> bool:
    """Model-name matching: 'builtins.open' = bare call only; 'pkg.fn' = dotted suffix; 'fn' = any last segment."""
    if name.startswith("builtins."):
        return canon == name[len("builtins."):]
    if "." in name:
        return canon == name or canon.endswith("." + name)
    return canon.split(".")[-1] == name


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


_SCOPE_CACHE: dict = {}


def _scope_nodes(fn: ast.AST):
    """Nodes of a scope's body, without descending into nested functions, classes or lambdas (cached per node)."""
    key = id(fn)
    hit = _SCOPE_CACHE.get(key)
    if hit is not None and hit[0] is fn:
        return hit[1]
    out = []
    stack = list(reversed(getattr(fn, "body", []) or []))
    while stack:
        n = stack.pop()
        out.append(n)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(n))))
    _SCOPE_CACHE[key] = (fn, out)
    return out


def _param_names(fn: ast.AST) -> list[str]:
    a = fn.args
    names = [p.arg for p in (a.posonlyargs + a.args + a.kwonlyargs)]
    if a.vararg:
        names.append(a.vararg.arg)
    if a.kwarg:
        names.append(a.kwarg.arg)
    return names


def _annotation_name(ann: ast.AST | None) -> str | None:
    if ann is None:
        return None
    if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
        return ann.value
    if isinstance(ann, ast.Subscript):
        return _annotation_name(ann.slice)
    if isinstance(ann, ast.BinOp):
        return _annotation_name(ann.left) or _annotation_name(ann.right)
    return _dotted(ann) or None


def _exits(stmts: list) -> bool:
    return bool(stmts) and isinstance(stmts[-1], (ast.Return, ast.Raise, ast.Continue, ast.Break))


class _Env:
    __slots__ = ("tainted", "types", "inst", "elem", "funcs")

    def __init__(self):
        self.tainted: dict = {}   # var -> origin  (kind, label, trail)
        self.types: dict = {}     # var -> class qual
        self.inst: dict = {}      # var -> {field: origin}
        self.elem: set = set()    # vars tainted only through a non-head container element
        self.funcs: dict = {}     # var -> function qual (h = helper / partial)


def _step(path, line, text):
    return {"file": path, "line": line, "text": text}


def _trail(o):
    return o[2] if len(o) > 2 else ()


def _with_step(o, step):
    return (o[0], o[1], _trail(o) + (step,))


class Project:
    def __init__(self, models: dict | None = None):
        self.m = models or load_models()
        self.files: dict[str, dict] = {}
        self.gfuncs: dict[str, dict] = {}
        self.classes: dict[str, dict] = {}
        self.simple_funcs: dict[str, list] = {}
        self.simple_methods: dict[str, list] = {}
        self.simple_classes: dict[str, list] = {}
        self.summaries: dict[str, dict] = {}
        self.lines_by_path: dict[str, list] = {}
        self._parents_cache: dict[int, dict] = {}
        self._calls_cache: dict = {}
        self._sink_cache: dict = {}
        self._source_cache: dict = {}
        self._sanitizer_cache: dict = {}
        self._resolve_cache: dict = {}
        self.findings: list[Finding] = []

    # ------------------------------------------------------------ building
    def add_file(self, mod: str, path: str, text: str, is_pkg: bool = False, tree: ast.AST | None = None) -> bool:
        if tree is None:
            try:
                tree = ast.parse(text)
            except (SyntaxError, ValueError):
                return False
        file = {"path": path, "tree": tree, "aliases": self._aliases(tree, mod, is_pkg), "funcs": {},
                "classes": {}, "lines": text.splitlines(), "assign_aliases": []}
        self.files[mod] = file
        self.lines_by_path[path] = file["lines"]
        for st in tree.body:
            if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name) \
                    and isinstance(st.value, (ast.Name, ast.Attribute)):
                local, dotted = st.targets[0].id, _dotted(st.value)
                file["assign_aliases"].append((local, dotted))
                # name aliases of imported things: fs = __req1 / run = subprocess.run / exec = cp.exec
                first, _, rest = dotted.partition(".")
                tgt = file["aliases"].get(first)
                if tgt and local not in file["aliases"]:
                    base = tgt[1] if tgt[0] == "mod" else (f"{tgt[1]}.{tgt[2]}" if tgt[1] else tgt[2])
                    full = f"{base}.{rest}" if rest else base
                    modpart, _, name = full.rpartition(".")
                    file["aliases"][local] = ("from", modpart, name) if modpart else ("mod", full)

        def visit(node, cls_qual, parent_func=None):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ClassDef):
                    cq = f"{mod}::{child.name}"
                    self.classes[cq] = {"node": child, "mod": mod, "name": child.name, "path": path,
                                        "base_names": [_dotted(b) for b in child.bases], "bases": [],
                                        "methods": {}, "subclasses": set(), "field_types": {},
                                        "tainted_fields": {}, "ctor_param_fields": {}}
                    file["classes"][child.name] = cq
                    self.simple_classes.setdefault(child.name, []).append(cq)
                    visit(child, cq, parent_func)
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if cls_qual:
                        q = f"{cls_qual}.{child.name}"
                        self.classes[cls_qual]["methods"][child.name] = q
                        self.simple_methods.setdefault(child.name, []).append(q)
                    else:
                        q = f"{mod}::{child.name}"
                        file["funcs"][child.name] = q
                        self.simple_funcs.setdefault(child.name, []).append(q)
                    self.gfuncs[q] = {"node": child, "mod": mod, "name": child.name, "cls": cls_qual, "path": path,
                                      "enclosing": ([parent_func] + self.gfuncs[parent_func]["enclosing"]) if parent_func else []}
                    visit(child, None, q)
                else:
                    visit(child, cls_qual, parent_func)

        visit(tree, None, None)
        return True

    @staticmethod
    def _aliases(tree: ast.AST, mod: str, is_pkg: bool) -> dict:
        al = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level:
                    base = mod if is_pkg else ".".join(mod.split(".")[:-1])
                    for _ in range(node.level - 1):
                        base = ".".join(base.split(".")[:-1])
                    module = f"{base}.{module}" if module and base else (base or module)
                for a in node.names:
                    al[a.asname or a.name] = ("from", module, a.name)
            elif isinstance(node, ast.Import):
                for a in node.names:
                    al[a.asname or a.name] = ("mod", a.name)
        return al

    def link(self):
        for cq, c in self.classes.items():
            for bname in c["base_names"]:
                bq = self._resolve_class(c["mod"], bname)
                if bq and bq != cq:
                    c["bases"].append(bq)
                    self.classes[bq]["subclasses"].add(cq)
        for mod, file in self.files.items():
            for local, target in file["assign_aliases"]:
                q = self._resolve_function(mod, target)
                if q and local not in file["funcs"]:
                    file["funcs"][local] = q

    # ---------------------------------------------------------- resolution
    def _canon(self, mod: str, node: ast.AST) -> str:
        """Dotted name with import aliases expanded (sp.run -> subprocess.run)."""
        name = _dotted(node)
        if not name:
            return ""
        first, _, rest = name.partition(".")
        tgt = self.files.get(mod, {}).get("aliases", {}).get(first)
        if tgt:
            base = tgt[1] if tgt[0] == "mod" else (f"{tgt[1]}.{tgt[2]}" if tgt[1] else tgt[2])
            return f"{base}.{rest}" if rest else base
        return name

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
        key = ("c", mod, name)
        if key in self._resolve_cache:
            return self._resolve_cache[key]
        res = self._resolve_class_uncached(mod, name)
        self._resolve_cache[key] = res
        return res

    def _resolve_class_uncached(self, mod: str, name: str) -> str | None:
        file = self.files.get(mod, {})
        short = name.split(".")[-1]
        if name == short and short in file.get("classes", {}):
            return file["classes"][short]
        tgt = file.get("aliases", {}).get(name) or file.get("aliases", {}).get(name.split(".")[0])
        if tgt and tgt[0] == "from":
            q = self._match(self.simple_classes, tgt[2] if name == name.split(".")[0] else short, tgt[1])
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
        key = ("f", mod, name)
        if key in self._resolve_cache:
            return self._resolve_cache[key]
        res = self._resolve_function_uncached(mod, name)
        self._resolve_cache[key] = res
        return res

    def _resolve_function_uncached(self, mod: str, name: str) -> str | None:
        file = self.files.get(mod, {})
        short = name.split(".")[-1]
        if name == short and short in file.get("funcs", {}):
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

    def _class_fields(self, cq: str, key: str) -> dict:
        merged: dict = {}
        for c in reversed(self._mro(cq)):
            merged.update(self.classes[c][key])
        return merged

    def _lookup_method(self, cq: str, name: str) -> list[str]:
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
        """Static resolution (types, imports, names) unioned with points-to resolution (objects, function values)."""
        static, ctor = self._callees_static(mod, cls, call, env)
        pt = getattr(self, "pt", None)
        if pt is not None and not ctor:
            extra = [q for q in pt.callees_for_call(call) if q not in static and q in self.gfuncs]
            if extra:
                return static + sorted(extra), None
        return static, ctor

    def _dotted_safe(self, node) -> str:
        return _dotted(node)

    def _callees_static(self, mod: str, cls: str | None, call: ast.Call, env: _Env) -> tuple[list[str], str | None]:
        f = call.func
        if isinstance(f, ast.Name):
            if f.id in env.funcs:
                return [env.funcs[f.id]], None
            cq = self._resolve_class(mod, f.id)
            if cq:
                return self._lookup_method(cq, "__init__"), cq
            q = self._resolve_function(mod, f.id)
            return ([q] if q else []), None
        if isinstance(f, ast.Attribute):
            recv = f.value
            rtype = cls if (isinstance(recv, ast.Name) and recv.id in {"self", "cls"} and cls) else self._type_of(mod, cls, recv, env)
            if rtype:
                return self._lookup_method(rtype, f.attr), None
            if isinstance(recv, ast.Name):
                tgt = self.files.get(mod, {}).get("aliases", {}).get(recv.id)
                if tgt and tgt[0] == "mod":
                    q = self._match(self.simple_funcs, f.attr, tgt[1])
                    if q:
                        return [q], None
                    cq = self._match(self.simple_classes, f.attr, tgt[1])
                    if cq:
                        return self._lookup_method(cq, "__init__"), cq
            name = _dotted(f)
            if "." in name:
                q = self._resolve_function(mod, name)
                if q:
                    return [q], None
            cands = self.simple_methods.get(f.attr, [])
            if len(cands) == 1:
                return cands, None
            same = [q for q in cands if q.split("::")[0] == mod]
            if len(same) == 1:
                return same, None
        return [], None

    # ---------------------------------------------------------------- types
    def _type_of(self, mod, cls, node, env) -> str | None:
        t = self._type_of_static(mod, cls, node, env)
        if t is None:
            pt = getattr(self, "pt", None)
            if pt is not None:
                cs = pt.classes_for(node)
                if len(cs) == 1:
                    return next(iter(cs))
        return t

    def _type_of_static(self, mod, cls, node, env) -> str | None:
        if isinstance(node, ast.Name):
            if node.id in {"self", "cls"} and cls:
                return cls
            return env.types.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self._type_of(mod, cls, node.value, env)
            return self._class_fields(base, "field_types").get(node.attr) if base else None
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

    # -------------------------------------------------------------- sources
    def _is_source(self, mod: str, node: ast.AST) -> str | None:
        key = (mod, id(node))
        hit = self._source_cache.get(key)
        if hit is not None and hit[0] is node:
            return hit[1]
        res = self._is_source_uncached(mod, node)
        self._source_cache[key] = (node, res)
        return res

    def _is_source_uncached(self, mod: str, node: ast.AST) -> str | None:
        cur = node
        if isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute) \
                and cur.func.attr in {"get", "getlist", "getall", "get_argument", "getone"}:
            cur = cur.func.value
        if isinstance(cur, ast.Subscript):
            cur = cur.value
        if isinstance(cur, ast.Attribute):
            root = _dotted(cur.value)
            for roots, attrs, label in self.m["attr_sources"]:
                if cur.attr in attrs and (root in roots or root in self.m["request_params"]
                                          or any(root.endswith("." + r) for r in roots)):
                    return label.replace("{attr}", cur.attr)
        canon = self._canon(mod, node) if isinstance(node, (ast.Name, ast.Attribute, ast.Call)) else ""
        if isinstance(node, ast.Subscript):
            canon = self._canon(mod, node.value)
        if canon:
            for names, label in self.m["name_sources"]:
                if any(canon == n for n in names):
                    return label.replace("{name}", canon)
            if isinstance(node, ast.Call):
                for names, label in self.m["call_sources"]:
                    if any(_name_matches(canon, n) for n in names):
                        return label.replace("{name}", canon)
        return None

    def _is_sanitizer(self, canon: str) -> bool:
        hit = self._sanitizer_cache.get(canon)
        if hit is None:
            hit = self._sanitizer_cache[canon] = any(_name_matches(canon, s) for s in self.m["sanitizers"])
        return hit

    # ---------------------------------------------------------------- sinks
    def _sink_info(self, mod: str, call: ast.Call):
        key = (mod, id(call))
        hit = self._sink_cache.get(key)
        if hit is not None and hit[0] is call:
            return hit[1]
        canon = self._canon(mod, call.func)
        res = None
        if canon:
            for entry in self.m["sinks"]:
                if any(_name_matches(canon, n) for n in entry[9]):
                    res = entry[:9]
                    break
        self._sink_cache[key] = (call, res)
        return res

    def _subprocess_elem_only(self, mod, cls, call, env) -> bool:
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

    def _attr_sink(self, node):
        """Assignment to a modelled attribute (e.g. innerHTML) -> (sink info, value expr) or None."""
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            return None
        tgts = node.targets if isinstance(node, ast.Assign) else [node.target]
        for tgt in tgts:
            if isinstance(tgt, ast.Attribute):
                for si, attrs in self.m["attr_sinks"]:
                    if tgt.attr in attrs:
                        return si, node.value
        return None

    def _sink(self, mod, cls, call, env):
        si = self._sink_info(mod, call)
        if si and si[0] == "DF003" and not si[8] and self._subprocess_elem_only(mod, cls, call, env):
            return ARG_INJECTION
        return si

    # ---------------------------------------------------------------- taint
    def _map_args(self, call: ast.Call, qual: str) -> dict:
        fn = self.gfuncs[qual]["node"]
        a = fn.args
        pos = [p.arg for p in (a.posonlyargs + a.args)]
        offset = 1 if (pos and pos[0] in {"self", "cls"}) else 0
        m = {}
        extra_pos, extra_kw = [], []
        for i, arg in enumerate(call.args):
            j = i + offset
            if j < len(pos):
                m[pos[j]] = arg
            elif a.vararg:
                extra_pos.append(arg)
        kwonly = {p.arg for p in a.kwonlyargs}
        for kw in call.keywords:
            if kw.arg in pos or kw.arg in kwonly:
                m[kw.arg] = kw.value
            elif a.kwarg:
                extra_kw.append(kw.value)
        if extra_pos:
            m[a.vararg.arg] = ast.Tuple(elts=extra_pos, ctx=ast.Load())
        if extra_kw:
            m[a.kwarg.arg] = ast.Dict(keys=[None] * len(extra_kw), values=extra_kw)
        return m

    def _ctor_inst_fields(self, mod, cls, call, env) -> dict:
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

    def _receiver_fields(self, mod, cls, call, env) -> tuple[dict, bool]:
        f = call.func
        if not isinstance(f, ast.Attribute):
            return {}, False
        recv = f.value
        if isinstance(recv, ast.Name) and recv.id in {"self", "cls"} and cls:
            return dict(self._class_fields(cls, "tainted_fields")), True
        fields: dict = {}
        if isinstance(recv, ast.Name) and recv.id in env.inst:
            fields.update(env.inst[recv.id])
        if isinstance(recv, ast.Call):
            fields.update(self._ctor_inst_fields(mod, cls, recv, env))
        rtype = self._type_of(mod, cls, recv, env)
        if rtype:
            fields.update(self._class_fields(rtype, "tainted_fields"))
        pt = getattr(self, "pt", None)
        if pt is not None:
            for o in pt.objs(recv):
                for (oid, attr), origin in self.obj_taint.items():
                    if oid == id(o) and attr not in fields:
                        fields[attr] = origin
        return fields, False

    def _taint(self, mod, cls, node, env):
        src = self._is_source(mod, node)
        if src:
            return ("source", src, ())
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
            if isinstance(recv, ast.Name) and recv.id in {"self", "cls"} and cls:
                tf = self._class_fields(cls, "tainted_fields")
                if node.attr in tf:
                    return tf[node.attr]
                return ("field", node.attr, ())
            if isinstance(recv, ast.Name) and recv.id in env.inst and node.attr in env.inst[recv.id]:
                return env.inst[recv.id][node.attr]
            if isinstance(recv, ast.Call):
                tmp = self._ctor_inst_fields(mod, cls, recv, env)
                if node.attr in tmp:
                    return tmp[node.attr]
            pt = getattr(self, "pt", None)
            if pt is not None:
                for o in pt.objs(recv):
                    hit = self.obj_taint.get((id(o), node.attr))
                    if hit:
                        return hit
            rtype = self._type_of(mod, cls, recv, env)
            if rtype:
                tf = self._class_fields(rtype, "tainted_fields")
                if node.attr in tf:
                    return tf[node.attr]
            return self._taint(mod, cls, recv, env)
        if isinstance(node, ast.Call):
            canon = self._canon(mod, node.func)
            if self._is_sanitizer(canon):
                return None
            callees, ctor = self._callees(mod, cls, node, env)
            if ctor:
                return None
            if callees:
                fields, is_self = self._receiver_fields(mod, cls, node, env)
                for q in callees:
                    summ = self.summaries.get(q)
                    if not summ:
                        continue
                    if summ["source_return"]:
                        o = summ["source_return"]
                        return ("retsource", self.gfuncs[q]["name"], _trail(o) + (
                            _step(self.gfuncs[q]["path"], summ["ret_line"], f"return من {self.gfuncs[q]['name']}()"),))
                    mapping = self._map_args(node, q)
                    for pname in summ["ret_params"]:
                        arg = mapping.get(pname)
                        if arg is not None:
                            o = self._taint(mod, cls, arg, env)
                            if o:
                                return _with_step(o, _step(self.gfuncs[q]["path"], summ["ret_line"],
                                                           f"يمرّ عبر {self.gfuncs[q]['name']}() ويُعاد"))
                    for fld in summ["ret_fields"]:
                        if fld in fields:
                            return fields[fld]
                        if is_self:
                            return ("field", fld, ())
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

    # ---------------------------------------------------------- entry points
    def _is_entry(self, mod, cls, fn) -> bool:
        """A routed handler / CLI command / framework view method, with or without parameters."""
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        for d in fn.decorator_list:
            dn = _dotted(d.func if isinstance(d, ast.Call) else d).split(".")[-1]
            if dn in self.m["entry_decorators"]:
                return True
        if cls and fn.name in self.m["view_methods"]:
            bases = set()
            for c in self._mro(cls):
                bases |= {b.split(".")[-1] for b in self.classes[c]["base_names"]}
            if bases & self.m["view_bases"]:
                return True
        return False

    def _entry_params(self, mod, cls, fn) -> list[str]:
        if not self._is_entry(mod, cls, fn):
            return []
        return [p for p in _param_names(fn) if p not in {"self", "cls"}]

    # --------------------------------------------------------- environment
    def _env(self, mod, cls, fn, path, seed_params: bool, entry: bool = False) -> _Env:
        env = _Env()
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            entry_params = set(self._entry_params(mod, cls, fn)) if entry else set()
            for p in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs:
                if p.arg in {"self", "cls"}:
                    continue
                t = self._resolve_class(mod, _annotation_name(p.annotation) or "")
                if t:
                    env.types[p.arg] = t
                if seed_params:
                    env.tainted[p.arg] = ("param", p.arg, ())
                elif p.arg in entry_params or p.arg in self.m["request_params"] - {"self"}:
                    env.tainted[p.arg] = ("source", f"معامل نقطة الدخول {p.arg}", (_step(path, fn.lineno, f"def {fn.name}({p.arg})"),))
            for extra in (fn.args.vararg, fn.args.kwarg):
                if extra is not None and seed_params:
                    env.tainted[extra.arg] = ("param", extra.arg, ())
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
                    c = node.value
                    if isinstance(c.func, ast.Attribute) and c.func.attr in CONTAINER_WRITES and isinstance(c.func.value, ast.Name):
                        for a in list(c.args) + [k.value for k in c.keywords]:
                            o = self._taint(mod, cls, a, env)
                            if o and c.func.value.id not in env.tainted:
                                env.tainted[c.func.value.id] = _with_step(o, _step(path, node.lineno, f"{c.func.value.id}.{c.func.attr}(...)"))
                                env.elem.add(c.func.value.id)
                                changed = True
                    continue
                else:
                    continue
                line = getattr(node, "lineno", None) or getattr(getattr(node, "context_expr", None), "lineno", 0) or 0
                for tgt in targets or []:
                    # function values: h = helper / partial(helper, ...)
                    if value is not None and isinstance(tgt, ast.Name):
                        fq = None
                        if isinstance(value, (ast.Name, ast.Attribute)):
                            fq = self._resolve_function(mod, _dotted(value))
                            if fq is None and isinstance(value, ast.Attribute):
                                cands, _ = self._callees(mod, cls, ast.Call(func=value, args=[], keywords=[]), env)
                                fq = cands[0] if cands else None
                        elif isinstance(value, ast.Call) and self._canon(mod, value.func).split(".")[-1] == "partial" and value.args:
                            fq = self._resolve_function(mod, _dotted(value.args[0]))
                        if fq and env.funcs.get(tgt.id) != fq:
                            env.funcs[tgt.id] = fq
                            changed = True
                    # types
                    t = self._resolve_class(mod, _annotation_name(ann) or "") if ann is not None else None
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
                            env.tainted[nm] = _with_step(o, _step(path, line, f"{nm} = …"))
                            if elem:
                                env.elem.add(nm)
                            changed = True
                        elif not elem and nm in env.elem:
                            env.elem.discard(nm)
                            changed = True
        return env

    def _calls(self, fn: ast.AST):
        key = id(fn)
        hit = self._calls_cache.get(key)
        if hit is not None and hit[0] is fn:
            return hit[1]
        out = [n for n in _scope_nodes(fn) if isinstance(n, ast.Call)]
        self._calls_cache[key] = (fn, out)
        return out

    # ------------------------------------------------------------- guards
    def _parents(self, fn) -> dict:
        key = id(fn)
        if key in self._parents_cache:
            return self._parents_cache[key]
        parents: dict = {}
        stack = list(getattr(fn, "body", []) or [])
        for st in stack:
            parents[st] = fn
        while stack:
            n = stack.pop()
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)) and n is not fn:
                continue
            for ch in ast.iter_child_nodes(n):
                parents[ch] = n
                stack.append(ch)
        self._parents_cache[key] = parents
        return parents

    def _validated(self, mod, test, positive: bool) -> set:
        if not positive:
            if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                return self._validated(mod, test.operand, True)
            return set()
        if isinstance(test, ast.BoolOp):
            parts = [self._validated(mod, v, True) for v in test.values]
            if isinstance(test.op, ast.And):
                return set().union(*parts)
            return set.intersection(*parts) if parts else set()
        if isinstance(test, ast.Compare):
            out = set()
            if isinstance(test.left, ast.Name) and any(isinstance(op, (ast.In, ast.Eq)) for op in test.ops):
                out.add(test.left.id)
            return out
        if isinstance(test, ast.Call):
            fname = self._canon(mod, test.func).split(".")[-1]
            names = {n.id for a in list(test.args) + [k.value for k in test.keywords] for n in ast.walk(a) if isinstance(n, ast.Name)}
            if isinstance(test.func, ast.Attribute) and isinstance(test.func.value, ast.Name):
                names.add(test.func.value.id)
            if fname in self.m["validators"] or any(v in fname for v in ("valid", "safe", "allowed", "check", "verify")):
                return names
        return set()

    def _guarded(self, mod, fn, call, names: set) -> bool:
        """True when every tainted name feeding the sink was validated on the path to it."""
        if not names:
            return False
        parents = self._parents(fn)
        validated: set = set()
        node = call
        while node in parents:
            parent = parents[node]
            if isinstance(parent, ast.If):
                in_body = any(node is x for x in parent.body)
                validated |= self._validated(mod, parent.test, positive=in_body)
            for field in ("body", "orelse", "finalbody"):
                block = getattr(parent, field, None)
                if isinstance(block, list) and any(node is x for x in block):
                    idx = next(i for i, x in enumerate(block) if x is node)
                    for prev in block[:idx]:
                        if isinstance(prev, ast.If) and _exits(prev.body) and not prev.orelse:
                            validated |= self._validated(mod, prev.test, positive=False)
            node = parent
        return names <= validated

    def _tainted_names_in(self, expr, env) -> set:
        return {n.id for n in ast.walk(expr) if isinstance(n, ast.Name) and n.id in env.tainted}

    # ------------------------------------------------------------ summaries
    def build(self):
        self._resolve_cache.clear()
        self.link()
        self._resolve_cache.clear()
        self.obj_taint: dict = {}
        try:
            from .pointsto import PointsTo
            self.pt = PointsTo(self)
        except Exception:  # noqa: BLE001 - points-to is an enhancement; never block the scan
            self.pt = None
        for q in self.gfuncs:
            self.summaries[q] = {"source_return": None, "ret_params": set(), "sink_params": {},
                                 "sink_fields": {}, "ret_fields": set(), "ret_type": None, "ret_line": 0, "cb_calls": []}
        changed, passes = True, 0
        while changed and passes < MAX_PASSES:
            changed, passes = False, passes + 1
            for q, info in self.gfuncs.items():
                mod, fn, cls, path = info["mod"], info["node"], info["cls"], info["path"]
                summ = self.summaries[q]
                env = self._env(mod, cls, fn, path, seed_params=True)
                new = {"source_return": summ["source_return"], "ret_params": set(summ["ret_params"]),
                       "sink_params": {k: list(v) for k, v in summ["sink_params"].items()},
                       "sink_fields": {k: list(v) for k, v in summ["sink_fields"].items()},
                       "ret_fields": set(summ["ret_fields"]), "ret_type": summ["ret_type"], "ret_line": summ["ret_line"],
                       "cb_calls": list(summ["cb_calls"])}
                rt = self._resolve_class(mod, _annotation_name(getattr(fn, "returns", None)) or "")
                if rt:
                    new["ret_type"] = rt
                for node in _scope_nodes(fn):
                    if isinstance(node, ast.Return) and node.value is not None:
                        o = self._taint(mod, cls, node.value, env)
                        if o and o[0] in {"source", "retsource"} and not new["source_return"]:
                            new["source_return"] = o
                            new["ret_line"] = node.lineno
                        elif o and o[0] == "param":
                            new["ret_params"].add(o[1])
                            new["ret_line"] = new["ret_line"] or node.lineno
                        elif o and o[0] == "field":
                            new["ret_fields"].add(o[1])
                        if new["ret_type"] is None:
                            t = self._type_of(mod, cls, node.value, env)
                            if t:
                                new["ret_type"] = t
                    if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None and self.pt is not None:
                        for tgt in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                            if isinstance(tgt, ast.Attribute):
                                o = self._taint(mod, cls, node.value, env)
                                if o and o[0] in {"source", "retsource"}:
                                    for obj in self.pt.objs(tgt.value):
                                        key = (id(obj), tgt.attr)
                                        if key not in self.obj_taint:
                                            self.obj_taint[key] = _with_step(o, _step(path, node.lineno, f"{_dotted(tgt.value)}.{tgt.attr} = …"))
                                            changed = True
                    if cls and isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                        tgts = node.targets if isinstance(node, ast.Assign) else [node.target]
                        for tgt in tgts:
                            if isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name) and tgt.value.id == "self":
                                c = self.classes[cls]
                                o = self._taint(mod, cls, node.value, env)
                                if o and o[0] in {"source", "retsource"} and tgt.attr not in c["tainted_fields"]:
                                    c["tainted_fields"][tgt.attr] = _with_step(o, _step(path, node.lineno, f"self.{tgt.attr} = …"))
                                    changed = True
                                if o and o[0] == "param" and info["name"] == "__init__" and c["ctor_param_fields"].get(o[1]) != tgt.attr:
                                    c["ctor_param_fields"][o[1]] = tgt.attr
                                    changed = True
                                t = self._type_of(mod, cls, node.value, env)
                                if t and c["field_types"].get(tgt.attr) != t:
                                    c["field_types"][tgt.attr] = t
                                    changed = True
                for call in self._calls(fn):
                    self._absorb_sinks(mod, cls, fn, path, call, env, new)
                for node in _scope_nodes(fn):
                    hit = self._attr_sink(node)
                    if hit:
                        si, value = hit
                        o = self._taint(mod, cls, value, env)
                        if o and o[0] in {"param", "field"} and not self._suppressed(path, node.lineno):
                            lst = (new["sink_params"] if o[0] == "param" else new["sink_fields"]).setdefault(o[1], [])
                            if (si, path, node.lineno) not in lst:
                                lst.append((si, path, node.lineno))
                if new != summ:
                    summ.update(new)
                    changed = True

    def _absorb_sinks(self, mod, cls, fn, path, call, env, new):
        def record(origin, entry):
            if origin[0] == "param":
                lst = new["sink_params"].setdefault(origin[1], [])
            elif origin[0] == "field":
                lst = new["sink_fields"].setdefault(origin[1], [])
            else:
                return
            if entry not in lst:
                lst.append(entry)

        si = self._sink(mod, cls, call, env)
        if si and not self._suppressed(path, call.lineno):
            for idx in si[7]:
                if idx < len(call.args):
                    o = self._taint(mod, cls, call.args[idx], env)
                    if o and not self._guarded(mod, fn, call, self._tainted_names_in(call.args[idx], env)):
                        record(o, (si, path, call.lineno))
        cb_param = self._callback_param(fn, call)
        if cb_param is not None:
            pos = [(i, self._taint(mod, cls, a, env)) for i, a in enumerate(call.args)]
            kwo = {k.arg: self._taint(mod, cls, k.value, env) for k in call.keywords if k.arg}
            entry = (cb_param, [(i, o) for i, o in pos if o], {k: o for k, o in kwo.items() if o}, path, call.lineno)
            if entry not in new["cb_calls"]:
                new["cb_calls"].append(entry)
            return
        callees, ctor = self._callees(mod, cls, call, env)
        if ctor:
            return
        fields, is_self = self._receiver_fields(mod, cls, call, env)
        for q in callees:
            summ = self.summaries.get(q)
            if not summ:
                continue
            mapping = self._map_args(call, q)
            for pname, entries in summ["sink_params"].items():
                arg = mapping.get(pname)
                if arg is None:
                    continue
                o = self._taint(mod, cls, arg, env)
                if o and not self._guarded(mod, fn, call, self._tainted_names_in(arg, env)):
                    for e in entries:
                        record(o, e)
            if is_self:
                for fld, entries in summ["sink_fields"].items():
                    for e in entries:
                        record(("field", fld, ()), e)
            # the callee itself calls one of ITS parameters: resolve the function value passed here, per call site
            for cb in summ["cb_calls"]:
                self._apply_callback(mod, cls, fn, path, call, env, q, cb, record, None)

    @staticmethod
    def _callback_param(fn, call):
        """Name of the parameter of fn that this call invokes (f(x) where f is a parameter), else None."""
        if isinstance(call.func, ast.Name) and isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if call.func.id in _param_names(fn):
                return call.func.id
        return None

    def _func_values(self, mod, cls, expr, env) -> list[str]:
        """Function quals an argument expression may evaluate to (static name or points-to function objects)."""
        out = []
        if isinstance(expr, (ast.Name, ast.Attribute)):
            q = self._resolve_function(mod, _dotted(expr))
            if q:
                out.append(q)
            if isinstance(expr, ast.Name) and expr.id in env.funcs:
                out.append(env.funcs[expr.id])
        pt = getattr(self, "pt", None)
        if pt is not None:
            out.extend(q for q in pt.funcs_for(expr) if q in self.gfuncs)
        return sorted(set(out))

    def _apply_callback(self, mod, cls, fn, path, call, env, q, cb, record, emit_ctx):
        """At a call site of q, resolve the function value passed for q's callback parameter and
        propagate its sinks: per call site, so run_all(shell, t) and run_all(logger, t) differ."""
        cb_param, pos_origins, kw_origins, cb_path, cb_line = cb
        mapping = self._map_args(call, q)
        cb_arg = mapping.get(cb_param)
        if cb_arg is None:
            return
        for q2 in self._func_values(mod, cls, cb_arg, env):
            summ2 = self.summaries.get(q2)
            if not summ2:
                continue
            fn2 = self.gfuncs[q2]["node"]
            a2 = fn2.args
            pos2 = [p.arg for p in (a2.posonlyargs + a2.args)]
            off2 = 1 if (pos2 and pos2[0] in {"self", "cls"} and isinstance(cb_arg, ast.Attribute)) else 0
            def actual(origin):
                # origin inside q: a param of q -> the argument passed here; a real source -> itself
                if origin[0] == "param":
                    arg = mapping.get(origin[1])
                    return self._taint(mod, cls, arg, env) if arg is not None else None
                return origin
            bindings = []
            for i, o in pos_origins:
                j = i + off2
                if j < len(pos2):
                    bindings.append((pos2[j], actual(o)))
                elif a2.vararg:
                    bindings.append((a2.vararg.arg, actual(o)))
            for k, o in kw_origins.items():
                bindings.append((k, actual(o)))
            for pname2, o in bindings:
                if not o:
                    continue
                for e in summ2["sink_params"].get(pname2, []):
                    if emit_ctx is None:
                        record(o, e)
                    elif o[0] in {"source", "retsource"}:
                        self._emit(e[0], emit_ctx[0], emit_ctx[1], o, self.gfuncs[q2]["name"], e)

    # ------------------------------------------------------------ reporting
    def report(self) -> list[Finding]:
        scopes = [(i["mod"], i["cls"], i["node"], i["path"]) for i in self.gfuncs.values()]
        for mod, file in self.files.items():
            scopes.append((mod, None, file["tree"], file["path"]))
        for mod, cls, fn, path in scopes:
            env = self._env(mod, cls, fn, path, seed_params=False, entry=True)
            is_entry = self._is_entry(mod, cls, fn)
            for call in self._calls(fn):
                si = self._sink(mod, cls, call, env)
                if si:
                    for idx in si[7]:
                        if idx < len(call.args):
                            o = self._taint(mod, cls, call.args[idx], env)
                            if o and o[0] in {"source", "retsource"} \
                                    and not self._guarded(mod, fn, call, self._tainted_names_in(call.args[idx], env)):
                                self._emit(si, path, call.lineno, o, None, None)
                                break
                if self._callback_param(fn, call) is not None:
                    continue
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
                    for pname, entries in summ["sink_params"].items():
                        arg = mapping.get(pname)
                        if arg is None:
                            continue
                        o = self._taint(mod, cls, arg, env)
                        if o and o[0] in {"source", "retsource"} \
                                and not self._guarded(mod, fn, call, self._tainted_names_in(arg, env)):
                            self._emit(entries[0][0], path, call.lineno, o, name, entries[0])
                            done = True
                            break
                    if done:
                        continue
                    for fld, entries in summ["sink_fields"].items():
                        if fld in fields:
                            self._emit(entries[0][0], path, call.lineno, fields[fld], name, entries[0])
                            break
                    for cb in summ["cb_calls"]:
                        self._apply_callback(mod, cls, fn, path, call, env, q, cb, None, (path, call.lineno))
            for node in _scope_nodes(fn):
                hit = self._attr_sink(node)
                if hit:
                    si, value = hit
                    o = self._taint(mod, cls, value, env)
                    if o and o[0] in {"source", "retsource"} and not self._guarded(mod, fn, node, self._tainted_names_in(value, env)):
                        self._emit(si, path, node.lineno, o, None, None)
            # reflected output from an entry point: `return tainted`
            if is_entry:
                for node in _scope_nodes(fn):
                    if isinstance(node, ast.Return) and node.value is not None:
                        v = node.value
                        if isinstance(v, ast.Call) and any(_name_matches(self._canon(mod, v.func), s) for s in self.m["safe_return_calls"]):
                            continue
                        o = self._taint(mod, cls, v, env)
                        if o and o[0] in {"source", "retsource"} \
                                and not self._guarded(mod, fn, node, self._tainted_names_in(v, env)):
                            self._emit(REFLECTED_RETURN, path, node.lineno, o, None, None)
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

    def _suppressed(self, path, line) -> bool:
        lines = self.lines_by_path.get(path) or []
        return 0 < line <= len(lines) and bool(SUPPRESS.search(lines[line - 1]))

    def _emit(self, si, path, line, origin, callee, deep):
        if self._suppressed(path, line) or (deep and self._suppressed(deep[1], deep[2])):
            return
        rule, sev, title, title_ar, advice, cwe, label = si[:7]
        source_label = self._label(origin)
        steps = list(_trail(origin))
        steps.append(_step(path, line, f"استدعاء {callee}()" if callee else f"نقطة الخطر: {label}"))
        if deep and (deep[1], deep[2]) != (path, line):
            steps.append(_step(deep[1], deep[2], f"نقطة الخطر: {label}"))
        extra = {"analysis": "dataflow", "taint_source": source_label, "path": steps}
        if callee:
            title = f"Tainted data flows through {callee}() into {label}"
            title_ar = f"بيانات غير موثوقة تمرّ عبر {callee}() وتصل إلى {label}"
            snippet = f"المصدر: {source_label} ← {callee}()"
            extra.update(interprocedural=True, callee=callee)
        else:
            snippet = f"المصدر: {source_label}"
            if origin[0] == "retsource":
                extra["interprocedural"] = True
        self.findings.append(Finding(rule, sev, title, title_ar, path, line, snippet, advice, cwe,
                                     source="taint", extra=extra))


def _module_name(rel: str) -> str:
    rel = rel.replace("\\", "/")
    rel = rel[:-3] if rel.endswith(".py") else rel
    rel = rel[:-9] if rel.endswith("/__init__") else rel
    return rel.replace("/", ".")


def _language(rel: str) -> str | None:
    low = rel.lower()
    if low.endswith(PY_EXTS):
        return "python"
    if low.endswith(JS_EXTS) and not low.endswith((".d.ts", ".min.js")):
        return "javascript"
    for ext, lang in CFAMILY.items():
        if low.endswith(ext):
            return lang
    return None


def load_models_for(language: str, extra_dirs=()) -> dict:
    """Built-in models for a language (Kotlin layers on Java), plus user model dirs."""
    base = {"python": DEFAULT_MODELS, "javascript": DEFAULT_JS_MODELS}.get(language, MODELS_DIR / f"{language}.json")
    m = load_models(extra_dirs, base, language)
    if language == "kotlin":
        j = load_models(extra_dirs, MODELS_DIR / "java.json", "kotlin")
        for k in ("attr_sources", "call_sources", "name_sources", "sinks", "attr_sinks"):
            m[k] = m[k] + [x for x in j[k] if x not in m[k]]
        for k in ("entry_decorators", "view_bases", "view_methods", "request_params", "sanitizers", "safe_return_calls", "validators"):
            m[k] = m[k] | j[k]
    return m


def analyze_project(files: dict[str, str], models_dirs=None) -> list[Finding]:
    """Analyze a whole project: Python natively, JavaScript/TypeScript through the lowering frontend."""
    return analyze_project_full(files, models_dirs)[1]


def analyze_project_full(files: dict[str, str], models_dirs=None):
    """Like analyze_project but also returns the built Project models (for VQL queries)."""
    projects: list = []
    groups: dict[str, dict[str, str]] = {}
    for rel, text in files.items():
        lang = _language(rel)
        if lang:
            groups.setdefault(lang, {})[rel] = text
    findings: list[Finding] = []
    if "python" in groups:
        proj = Project(load_models(models_dirs or (), DEFAULT_MODELS, "python"))
        for rel, text in groups["python"].items():
            proj.add_file(_module_name(rel), rel, text, is_pkg=rel.replace("\\", "/").endswith("__init__.py"))
        if proj.files:
            proj.build()
            findings.extend(proj.report())
            projects.append(proj)
    if "javascript" in groups:
        from . import js_frontend
        proj = Project(load_models(models_dirs or (), DEFAULT_JS_MODELS, "javascript"))
        for rel, text in groups["javascript"].items():
            if len(text) > 600_000 or any(len(l) > 5000 for l in text.splitlines()[:50]):
                continue  # bundles / minified
            tree = js_frontend.parse_js(text, rel)
            proj.add_file(js_frontend.module_name(rel), rel, text, tree=tree)
        if proj.files:
            proj.build()
            findings.extend(proj.report())
            projects.append(proj)
    for lang in ("java", "kotlin", "csharp", "go", "php"):
        if lang not in groups:
            continue
        from . import cfamily_frontend
        proj = Project(load_models_for(lang, models_dirs or ()))
        for rel, text in groups[lang].items():
            if len(text) > 600_000:
                continue
            tree = cfamily_frontend.parse_cfamily(text, rel, lang)
            proj.add_file(cfamily_frontend.module_name(rel), rel, text, tree=tree)
        if proj.files:
            proj.build()
            findings.extend(proj.report())
            projects.append(proj)
    return projects, findings


def analyze(path: str, text: str, models_dirs=None) -> list[Finding]:
    return analyze_project({path: text}, models_dirs)


def _catalogue() -> list[dict]:
    seen, out = set(), []
    entries = load_models()["sinks"] + load_models((), DEFAULT_JS_MODELS, "javascript")["sinks"]
    for e in entries + [ARG_INJECTION + (None,), REFLECTED_RETURN + (None,)]:
        if e[0] in seen:
            continue
        seen.add(e[0])
        out.append({"id": e[0], "severity": e[1], "cwe": e[5], "title": e[2], "title_ar": e[3], "advice": e[4]})
    return sorted(out, key=lambda d: d["id"])


TAINT_RULES = _catalogue()
