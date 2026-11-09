"""VQL — a small declarative query language over the program database.  (vulnscan: ignore-file)

Inspired by CodeQL's ``from … where … select``: a query declares variables
over relations of the program database (calls, functions, classes,
assignments, strings, imports, decorators, arguments and the taint *flows*
the data-flow engine computed), filters them with a boolean ``where``
clause, and ``select``s a location and a message. Metadata in ``@`` comments
gives the finding its id, severity, CWE and advice, as CodeQL queries do::

    // @id vql/tls-verify-disabled
    // @name TLS verification disabled
    // @severity high
    // @cwe CWE-295
    // @advice Enable certificate verification.
    from call c
    where c.name matches "requests\\.(get|post|request)" and c.args contains "verify=False"
    select c, "TLS verification disabled in " + c.name

Relations (fields):
  call      id name func receiver file line in_func in_class nargs args arg0 arg1 arg2 arg3 kwargs
  func      id name qual file line nparams params decorators class is_entry is_method
  class     id name file line bases decorators
  assign    id target value file line in_func
  string    id value file line in_func
  import    id module name alias file line
  decorator id name func file line
  attr      id base name file line in_func
  flow      id rule severity cwe source label file line callee interprocedural hops sink_file sink_line
Operators: = != < > <= >= matches (regex, search) contains (substring) in (list)
           and or not ( )  ;  string "+" concatenation in select.

Predicates (user-defined, recursive, Datalog-style, evaluated bottom-up to a fixpoint)::

    predicate calls(f, g) { from call c where c.in_func = f and c.func = g }
    predicate reaches(f, g) { calls(f, g) or from value h where calls(f, h) and reaches(h, g) }
    from func e where e.is_entry and reaches(e.name, "system") select e, "reaches os.system"

A predicate body is one or more clauses joined by ``or``; a clause is
``[from <decls> where] <conjunction>``. ``value x`` declares a free variable
bound by a predicate atom or an equality. Atoms with unbound arguments join
against the predicate's current tuples, so transitive closures and other
recursive relations work.

Classes are derived relations with a characteristic predicate, member
predicates and getters, as in QL::

    class ShellCall extends call {
      ShellCall() { this.name in ("os.system", "subprocess.call") }
      predicate isDynamic() { not this.arg0 matches "^[\"'\\[]" }
      string target() { result = this.arg0 }
    }
    from ShellCall c where c.isDynamic() select c, "dynamic shell: " + c.target()

``this`` is the current row; a subclass narrows its base with a further
characteristic predicate. Aggregates range over a sub-query::

    from func f
    where count(call c | c.in_func = f.name and c.name = "print") > 5
    select f, "noisy: " + count(call c | c.in_func = f.name)

Supported: ``count``/``strictcount``/``sum``/``max``/``min``/``avg`` and the
quantifiers ``exists``/``any``, each as ``agg(<decls> | <condition> | <value>)``.
This is a large working subset of QL; it still lacks QL's module/import
system, parameterised types and the full standard library.
"""

from __future__ import annotations

import ast
import pathlib
import re
import time

from .model import Finding

DEFAULT_QUERIES = pathlib.Path(__file__).parent / "queries"


# ============================================================ program database
def build_database(projects, flows) -> dict[str, list[dict]]:
    """Build relation tables from the taint projects' ASTs and the computed flows."""
    db: dict[str, list[dict]] = {k: [] for k in ("call", "func", "class", "assign", "string", "import", "decorator", "attr", "flow")}
    ids = {"n": 0}

    def nid():
        ids["n"] += 1
        return ids["n"]

    encoded: dict = {}   # one encoding per source file, even when an APEX export is split into many modules
    for proj in projects:
        for mod, file in proj.files.items():
            path, tree = file["path"], file["tree"]
            lines = file["lines"]
            blines = encoded.get(id(lines))
            if blines is None:
                blines = encoded[id(lines)] = [l.encode("utf-8") for l in lines]   # col offsets are UTF-8 byte offsets

            def src(node):
                seg = _segment(blines, node)
                if seg:
                    return seg.strip()
                return _unparse(node)

            # context tracking: which function / class encloses a node

            def visit(node, cur_func, cur_cls):
                if isinstance(node, ast.ClassDef):
                    cid = nid()
                    db["class"].append({"id": cid, "name": node.name, "file": path, "line": node.lineno,
                                        "bases": ", ".join(proj._canon(mod, b) for b in node.bases),
                                        "decorators": ", ".join(proj._canon(mod, d.func if isinstance(d, ast.Call) else d) for d in node.decorator_list)})
                    for d in node.decorator_list:
                        db["decorator"].append({"id": nid(), "name": proj._canon(mod, d.func if isinstance(d, ast.Call) else d), "func": node.name, "file": path, "line": node.lineno})
                    for ch in node.body:
                        visit(ch, cur_func, node.name)
                    return
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fid = nid()
                    qual = f"{cur_cls}.{node.name}" if cur_cls else node.name
                    is_entry = proj._is_entry(mod, f"{mod}::{cur_cls}" if cur_cls else None, node)
                    decs = [proj._canon(mod, d.func if isinstance(d, ast.Call) else d) for d in node.decorator_list]
                    params = [a.arg for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
                    db["func"].append({"id": fid, "name": node.name, "qual": qual, "file": path, "line": node.lineno,
                                       "nparams": len(params), "params": ", ".join(params), "decorators": ", ".join(decs),
                                       "class": cur_cls or "", "is_entry": is_entry, "is_method": bool(cur_cls)})
                    for d in decs:
                        db["decorator"].append({"id": nid(), "name": d, "func": node.name, "file": path, "line": node.lineno})
                    for ch in node.body:
                        visit(ch, node.name, cur_cls)
                    return
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    for a in node.names:
                        db["import"].append({"id": nid(), "module": getattr(node, "module", None) or a.name if isinstance(node, ast.ImportFrom) else a.name,
                                             "name": a.name, "alias": a.asname or a.name, "file": path, "line": node.lineno})
                if isinstance(node, ast.Call):
                    fname = proj._canon(mod, node.func)
                    args_text = [src(a) for a in node.args]
                    kws = ", ".join(f"{k.arg}={src(k.value)}" for k in node.keywords if k.arg)
                    row = {"id": nid(), "name": fname, "func": fname.split(".")[-1],
                           "receiver": fname.rsplit(".", 1)[0] if "." in fname else "",
                           "file": path, "line": getattr(node, "lineno", 0), "in_func": cur_func or "", "in_class": cur_cls or "",
                           "nargs": len(node.args), "args": ", ".join(args_text + ([kws] if kws else [])), "kwargs": kws}
                    for i in range(4):
                        row[f"arg{i}"] = args_text[i] if i < len(args_text) else ""
                    db["call"].append(row)
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and getattr(node, "value", None) is not None:
                    tgts = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for t in tgts:
                        db["assign"].append({"id": nid(), "target": src(t), "value": src(node.value), "file": path,
                                             "line": node.lineno, "in_func": cur_func or ""})
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) >= 1:
                    db["string"].append({"id": nid(), "value": node.value, "file": path, "line": getattr(node, "lineno", 0), "in_func": cur_func or ""})
                if isinstance(node, ast.Attribute):
                    db["attr"].append({"id": nid(), "base": proj._canon(mod, node.value) if isinstance(node.value, (ast.Name, ast.Attribute)) else "",
                                       "name": node.attr, "file": path, "line": getattr(node, "lineno", 0), "in_func": cur_func or ""})
                for ch in ast.iter_child_nodes(node):
                    visit(ch, cur_func, cur_cls)

            for st in tree.body:
                visit(st, "", "")

    for f in flows:
        path = f.extra.get("path") or []
        db["flow"].append({"id": nid(), "rule": f.rule_id, "severity": f.severity, "cwe": f.cwe,
                           "source": f.extra.get("taint_source", ""), "label": f.title, "file": f.file, "line": f.line,
                           "callee": f.extra.get("callee", ""), "interprocedural": bool(f.extra.get("interprocedural")),
                           "hops": len(path), "sink_file": path[-1]["file"] if path else f.file,
                           "sink_line": path[-1]["line"] if path else f.line})
    return db


def _segment(blines, node) -> str | None:
    """Source text of a node from precomputed byte lines (O(size of node), unlike ast.get_source_segment)."""
    try:
        l1, c1, l2, c2 = node.lineno, node.col_offset, node.end_lineno, node.end_col_offset
    except AttributeError:
        return None
    if not l1 or not l2 or l1 < 1 or l2 > len(blines) or (l1 == l2 and c2 <= c1):
        return None
    try:
        if l1 == l2:
            return blines[l1 - 1][c1:c2].decode("utf-8", "replace")
        parts = [blines[l1 - 1][c1:]] + blines[l1:l2 - 1] + [blines[l2 - 1][:c2]]
        return b"\n".join(parts).decode("utf-8", "replace")
    except (IndexError, ValueError):
        return None


def _unparse(node) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # noqa: BLE001
        return type(node).__name__


# =================================================================== parser
TOKEN = re.compile(r"""\s*(?:(?P<str>"(?:\\.|[^"\\])*")|(?P<num>\d+)|(?P<id>[A-Za-z_][\w]*)|(?P<op>!=|<=|>=|[=<>(),.+{}|]))""")
KEYWORDS = {"from", "where", "select", "and", "or", "not", "matches", "contains", "in", "predicate", "value", "class", "extends"}
AGGREGATES = {"count", "strictcount", "sum", "max", "min", "avg", "exists", "any"}
GETTER_TYPES = {"string", "int", "boolean", "float", "value"}
MAX_MEMBER_DEPTH = 64


class QueryError(Exception):
    pass


class Query:
    def __init__(self, text: str, name: str = "query"):
        self.name = name
        self.meta = {"id": f"vql/{pathlib.Path(name).stem}", "severity": "medium", "cwe": "", "name": "", "name_ar": "", "advice": ""}
        for m in re.finditer(r"^\s*(?://|#)\s*@(\w+)\s+(.*)$", text, re.M):
            self.meta[m.group(1)] = m.group(2).strip()
        body = re.sub(r"^\s*(?://|#).*$", "", text, flags=re.M)
        self.toks = self._tokenize(body)
        self.i = 0
        self.vars: list[tuple[str, str]] = []
        self.where = None
        self.select: list = []
        self.predicates: dict = {}     # name -> (params, [clauses]) ; clause = (vars, cond)
        self.classes: dict = {}        # name -> {"base", "charpred", "members": {name: (kind, params, clauses)}}
        self._member_depth = 0
        self._parse()

    @staticmethod
    def _tokenize(body: str):
        toks, i = [], 0
        while i < len(body):
            m = TOKEN.match(body, i)
            if not m or m.end() == i:
                if body[i:].strip():
                    raise QueryError(f"bad token near: {body[i:i+20]!r}")
                break
            i = m.end()
            if m.group("str") is not None:
                raw = m.group("str")[1:-1]
                toks.append(("str", re.sub(r'\\(["\\nt])', lambda mm: {'"': '"', "\\": "\\", "n": "\n", "t": "\t"}[mm.group(1)], raw)))
            elif m.group("num") is not None:
                toks.append(("num", int(m.group("num"))))
            elif m.group("id") is not None:
                v = m.group("id")
                toks.append(("kw", v) if v in KEYWORDS else ("id", v))
            else:
                toks.append(("op", m.group("op")))
        toks.append(("eof", None))
        return toks

    def _peek(self):
        return self.toks[self.i]

    def _eat(self, kind=None, val=None):
        t = self.toks[self.i]
        if (kind and t[0] != kind) or (val is not None and t[1] != val):
            raise QueryError(f"expected {val or kind}, got {t[1]!r}")
        self.i += 1
        return t

    def _decls(self):
        out = []
        while True:
            t = self._peek()
            rel = self._eat("kw", "value")[1] if t == ("kw", "value") else self._eat("id")[1]
            var = self._eat("id")[1]
            out.append((rel, var))
            if self._peek() == ("op", ","):
                self.i += 1
                continue
            break
        return out

    def _clause(self):
        """A predicate clause (Datalog rule): [from decls where] <conjunction>. `or` separates clauses."""
        decls = []
        if self._peek() == ("kw", "from"):
            self.i += 1
            decls = self._decls()
            self._eat("kw", "where")
        return (decls, self._and())

    def _params(self):
        self._eat("op", "(")
        params = []
        while self._peek() != ("op", ")"):
            params.append(self._eat("id")[1])
            if self._peek() == ("op", ","):
                self.i += 1
        self._eat("op", ")")
        return params

    def _clauses(self):
        self._eat("op", "{")
        clauses = [self._clause()]
        while self._peek() == ("kw", "or"):
            self.i += 1
            clauses.append(self._clause())
        self._eat("op", "}")
        return clauses

    def _parse_class(self):
        """class Name extends Base { Name() { charpred } predicate m(..) { .. } string g(..) { result = .. } }"""
        self._eat("kw", "class")
        name = self._eat("id")[1]
        self._eat("kw", "extends")
        base = self._eat("id")[1]
        cls = {"base": base, "charpred": None, "members": {}}
        self._eat("op", "{")
        while self._peek() != ("op", "}"):
            t = self._peek()
            if t == ("id", name) and self.toks[self.i + 1] == ("op", "("):
                self.i += 1
                self._eat("op", "(")
                self._eat("op", ")")
                self._eat("op", "{")
                cls["charpred"] = self._or()
                self._eat("op", "}")
            elif t == ("kw", "predicate"):
                self.i += 1
                mname = self._eat("id")[1]
                params = self._params()
                cls["members"][mname] = ("predicate", params, self._clauses())
            elif t[0] in ("id", "kw") and t[1] in GETTER_TYPES:
                self.i += 1
                mname = self._eat("id")[1]
                params = self._params()
                cls["members"][mname] = ("getter", params, self._clauses())
            else:
                raise QueryError(f"unexpected {t[1]!r} in class {name}")
        self._eat("op", "}")
        self.classes[name] = cls

    def _parse(self):
        while self._peek() in (("kw", "predicate"), ("kw", "class")):
            if self._peek() == ("kw", "class"):
                self._parse_class()
                continue
            self.i += 1
            name = self._eat("id")[1]
            params = self._params()
            self.predicates[name] = (params, self._clauses())
        self._eat("kw", "from")
        self.vars = self._decls()
        if self._peek() == ("kw", "where"):
            self.i += 1
            self.where = self._or()
        self._eat("kw", "select")
        while True:
            self.select.append(self._concat())
            if self._peek() == ("op", ","):
                self.i += 1
                continue
            break

    # expression grammar
    def _or(self):
        left = self._and()
        while self._peek() == ("kw", "or"):
            self.i += 1
            left = ("or", left, self._and())
        return left

    def _and(self):
        left = self._not()
        while self._peek() == ("kw", "and"):
            self.i += 1
            left = ("and", left, self._not())
        return left

    def _not(self):
        if self._peek() == ("kw", "not"):
            self.i += 1
            return ("not", self._not())
        return self._cmp()

    def _cmp(self):
        if self._peek() == ("op", "("):
            self.i += 1
            e = self._or()
            self._eat("op", ")")
            return e
        left = self._concat()
        t = self._peek()
        if t[0] == "op" and t[1] in ("=", "!=", "<", ">", "<=", ">="):
            self.i += 1
            return ("cmp", t[1], left, self._concat())
        if t == ("kw", "matches") or t == ("kw", "contains"):
            self.i += 1
            return (t[1], left, self._concat())
        if t == ("kw", "in"):
            self.i += 1
            self._eat("op", "(")
            items = [self._concat()]
            while self._peek() == ("op", ","):
                self.i += 1
                items.append(self._concat())
            self._eat("op", ")")
            return ("in", left, items)
        if left[0] == "pred" and not (t[0] == "op" and t[1] in ("=", "!=", "<", ">", "<=", ">=")) \
                and t not in (("kw", "matches"), ("kw", "contains"), ("kw", "in")):
            return left
        if t == ("kw", "not") and self.toks[self.i + 1] == ("kw", "in"):
            self.i += 2
            self._eat("op", "(")
            items = [self._concat()]
            while self._peek() == ("op", ","):
                self.i += 1
                items.append(self._concat())
            self._eat("op", ")")
            return ("not", ("in", left, items))
        return ("truthy", left)

    def _concat(self):
        left = self._atom()
        while self._peek() == ("op", "+"):
            self.i += 1
            left = ("+", left, self._atom())
        return left

    def _atom(self):
        t = self._peek()
        if t[0] == "str":
            self.i += 1
            return ("lit", t[1])
        if t[0] == "num":
            self.i += 1
            return ("lit", t[1])
        if t[0] == "id" and t[1] in AGGREGATES and self.toks[self.i + 1] == ("op", "("):
            return self._aggregate()
        if t[0] == "id":
            self.i += 1
            if self._peek() == ("op", "."):
                self.i += 1
                ft = self._peek()
                if ft[0] not in ("id", "kw"):
                    raise QueryError(f"expected field name, got {ft[1]!r}")
                self.i += 1
                if self._peek() == ("op", "("):      # member predicate / getter call: c.isShell(), c.target()
                    self.i += 1
                    args = []
                    while self._peek() != ("op", ")"):
                        args.append(self._concat())
                        if self._peek() == ("op", ","):
                            self.i += 1
                    self._eat("op", ")")
                    return ("method", t[1], ft[1], args)
                return ("field", t[1], ft[1])
            if self._peek() == ("op", "("):
                self.i += 1
                args = []
                while self._peek() != ("op", ")"):
                    args.append(self._concat())
                    if self._peek() == ("op", ","):
                        self.i += 1
                self._eat("op", ")")
                return ("pred", t[1], args)
            return ("var", t[1])
        if t == ("op", "("):
            self.i += 1
            e = self._or()
            self._eat("op", ")")
            return e
        raise QueryError(f"unexpected {t[1]!r}")

    def _aggregate(self):
        """count(call c | cond) · sum/max/min/avg(call c | cond | expr) · exists(call c | cond) · any(call c | cond | expr)"""
        fn = self._eat("id")[1]
        self._eat("op", "(")
        decls = self._decls()
        cond, expr = None, None
        if self._peek() == ("op", "|"):
            self.i += 1
            if self._peek() != ("op", "|") and self._peek() != ("op", ")"):
                cond = self._or()
        if self._peek() == ("op", "|"):
            self.i += 1
            expr = self._concat()
        self._eat("op", ")")
        if fn in ("sum", "max", "min", "avg", "any") and expr is None:
            raise QueryError(f"{fn}(...) needs a value expression after a second '|'")
        return ("agg", fn, decls, cond, expr)

    # evaluation
    def _agg_val(self, e, env):
        _, fn, decls, cond, expr = e
        self._check_budget()
        rows = self._solve_clause(self.db, decls, cond, env0=env)
        if fn == "exists":
            return bool(rows)
        if fn in ("count", "strictcount"):
            if fn == "strictcount" and not rows:
                return None
            return len(rows)
        vals = [self._val(expr, r) for r in rows]
        if fn == "any":
            return vals[0] if vals else ""
        nums = []
        for v in vals:
            try:
                nums.append(float(v))
            except (TypeError, ValueError):
                pass
        if not nums:
            return 0 if fn == "sum" else None
        if fn == "sum":
            return int(sum(nums)) if all(n.is_integer() for n in nums) else sum(nums)
        if fn == "max":
            return max(nums)
        if fn == "min":
            return min(nums)
        return sum(nums) / len(nums)

    def _class_chain(self, cname):
        out = []
        while cname in self.classes:
            out.append(cname)
            cname = self.classes[cname]["base"]
        return out

    def _member(self, var, name, env):
        """Resolve c.name(...) against the class the variable was declared with (or its ancestors)."""
        for cname in self._class_chain(self.var_class.get(var, "")):
            m = self.classes[cname]["members"].get(name)
            if m:
                return m
        raise QueryError(f"unknown member {var}.{name}()")

    def _method(self, e, env, want_value):
        _, var, name, args = e
        kind, params, clauses = self._member(var, name, env)
        if len(params) != len(args):
            raise QueryError(f"{var}.{name}() takes {len(params)} arguments")
        if self._member_depth > MAX_MEMBER_DEPTH:
            raise QueryError(f"member {name}() recursion too deep (member predicates are evaluated on demand)")
        inner = {"this": env[var]}
        self.var_class["this"] = self._class_chain(self.var_class.get(var, ""))[0] if self._class_chain(self.var_class.get(var, "")) else ""
        for p, a in zip(params, args):
            inner[p] = self._val(a, env)
        self._member_depth += 1
        try:
            values = []
            for decls, cond in clauses:
                if kind == "getter":
                    decls = list(decls) + [("value", "result")]
                for r in self._solve_clause(self.db, decls, cond, env0=inner):
                    if kind == "predicate":
                        return True
                    if "result" in r:
                        values.append(r["result"])
        finally:
            self._member_depth -= 1
        if kind == "predicate":
            return False
        if not want_value:
            return bool(values)
        return values[0] if values else ""

    def _val(self, e, env):
        k = e[0]
        if k == "lit":
            return e[1]
        if k == "var":
            return env[e[1]]
        if k == "pred":
            return self._bool(e, env)
        if k == "field":
            row = env.get(e[1])
            if row is None:
                raise QueryError(f"unknown variable {e[1]}")
            if isinstance(row, dict):
                return row.get(e[2], "")
            return ""
        if k == "method":
            return self._method(e, env, True)
        if k == "agg":
            return self._agg_val(e, env)
        if k == "+":
            return f"{self._val(e[1], env)}{self._val(e[2], env)}"
        return self._bool(e, env)

    def _bool(self, e, env) -> bool:
        k = e[0]
        if k == "and":
            return self._bool(e[1], env) and self._bool(e[2], env)
        if k == "or":
            return self._bool(e[1], env) or self._bool(e[2], env)
        if k == "not":
            return not self._bool(e[1], env)
        if k == "truthy":
            inner = e[1]
            if isinstance(inner, tuple) and inner[0] == "method":
                return self._method(inner, env, False)
            return bool(self._val(inner, env))
        if k == "method":
            return self._method(e, env, False)
        if k == "pred":
            tup = tuple(self._val(a, env) for a in e[2])
            return tup in self.tuples.get(e[1], set())
        if k == "cmp":
            a, b = self._val(e[2], env), self._val(e[3], env)
            if a is None or b is None:
                return e[1] == "!=" and (a is None) != (b is None)
            if e[1] in ("<", ">", "<=", ">="):
                try:
                    a, b = float(a), float(b)
                except (TypeError, ValueError):
                    return False
            return {"=": a == b, "!=": a != b, "<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b}[e[1]]
        if k == "matches":
            return re.search(str(self._val(e[2], env)), str(self._val(e[1], env))) is not None
        if k == "contains":
            return str(self._val(e[2], env)) in str(self._val(e[1], env))
        if k == "in":
            v = self._val(e[1], env)
            return any(v == self._val(it, env) for it in e[2])
        return bool(self._val(e, env))

    def _vars_in(self, e, acc: set):
        if not isinstance(e, tuple):
            return acc
        if e[0] in ("field", "var", "method"):
            acc.add(e[1])
        if e[0] == "agg":
            inner: set = set()
            self._vars_in(e[3], inner)
            self._vars_in(e[4], inner)
            acc |= inner - {v for _, v in e[2]}
            return acc
        for x in e[1:]:
            if isinstance(x, tuple):
                self._vars_in(x, acc)
            elif isinstance(x, list):
                for y in x:
                    self._vars_in(y, acc)
        return acc

    @staticmethod
    def _split(e, out):
        if isinstance(e, tuple) and e[0] == "and":
            Query._split(e[1], out)
            Query._split(e[2], out)
        elif e is not None:
            out.append(e)
        return out

    def _solve_clause(self, db, decls, cond, env0=None):
        """Enumerate relation rows, then bind free variables (value vars / predicate params)
        through equalities and predicate atoms, filtering with the remaining conjuncts."""
        conjuncts = self._split(cond, [])
        rel_vars = [(r, v) for r, v in decls if r != "value"]
        free = {v for r, v in decls if r == "value"}
        results = []

        def solve(env, pending):
            if not pending:
                results.append(dict(env))
                return
            for idx, c in enumerate(pending):
                rest = pending[:idx] + pending[idx + 1:]
                vs = self._vars_in(c, set())
                unbound = {v for v in vs if v not in env}
                if not unbound:
                    if self._bool(c, env):
                        solve(env, rest)
                    return
                # x = expr  (bind x)
                if c[0] == "cmp" and c[1] == "=":
                    for a, b in ((c[2], c[3]), (c[3], c[2])):
                        if a[0] == "var" and a[1] in unbound and not (self._vars_in(b, set()) - set(env)):
                            env2 = dict(env)
                            env2[a[1]] = self._val(b, env)
                            solve(env2, rest)
                            return
                # P(args) with unbound args: join against the predicate's tuples (indexed on bound positions)
                if c[0] == "truthy" and isinstance(c[1], tuple) and c[1][0] == "pred":
                    c = c[1]
                if c[0] == "pred":
                    self._check_budget()
                    bound_pos = [i for i, a in enumerate(c[2]) if not (a[0] == "var" and a[1] not in env)
                                 and not (self._vars_in(a, set()) - set(env))]
                    if bound_pos:
                        key = tuple(bound_pos)
                        vals = tuple(self._val(c[2][i], env) for i in bound_pos)
                        cands = self._index(c[1], key).get(vals, ())
                    else:
                        cands = self.tuples.get(c[1], set())
                    for tup in list(cands):
                        if len(tup) != len(c[2]):
                            continue
                        env2 = dict(env)
                        ok = True
                        for a, val in zip(c[2], tup):
                            if a[0] == "var" and a[1] not in env2:
                                env2[a[1]] = val
                            elif self._vars_in(a, set()) - set(env2):
                                ok = False
                                break
                            elif self._val(a, env2) != val:
                                ok = False
                                break
                        if ok:
                            solve(env2, rest)
                    return
            # no conjunct could make progress: unbound variables remain -> no solutions
            return

        def rec(i, env):
            if i == len(rel_vars):
                solve(env, list(conjuncts))
                return
            rel, var = rel_vars[i]
            rows = db.get(rel)
            if rows is None:
                raise QueryError(f"unknown relation {rel}")
            bound_after = set(env) | {var}
            ready = [c for c in conjuncts if self._vars_in(c, set()) <= bound_after and not (self._vars_in(c, set()) & free)]
            for row in rows:
                env[var] = row
                if all(self._bool(c, env) for c in ready):
                    rec(i + 1, env)
            env.pop(var, None)
            if i == 0:
                self._check_budget()

        rec(0, dict(env0 or {}))
        return results

    def _index(self, pred, positions):
        """Hash index of a predicate's tuples on the given argument positions (rebuilt when tuples grow)."""
        tuples = self.tuples.get(pred, set())
        key = (pred, positions)
        cached = self._indexes.get(key)
        if cached is not None and cached[0] == len(tuples):
            return cached[1]
        idx: dict = {}
        for tup in tuples:
            idx.setdefault(tuple(tup[i] for i in positions if i < len(tup)), []).append(tup)
        self._indexes[key] = (len(tuples), idx)
        return idx

    def _check_budget(self):
        if time.monotonic() > self._deadline:
            raise QueryError("time budget exceeded")

    def _eval_predicates(self, db):
        self.tuples = {name: set() for name in self.predicates}
        self._indexes = {}
        for _ in range(64):
            grown = False
            self._check_budget()
            for name, (params, clauses) in self.predicates.items():
                for decls, cond in clauses:
                    for env in self._solve_clause(db, decls, cond):
                        try:
                            tup = tuple(env[p] if not isinstance(env[p], dict) else env[p].get("id") for p in params)
                        except KeyError:
                            continue
                        if tup not in self.tuples[name]:
                            self.tuples[name].add(tup)
                            grown = True
                            if len(self.tuples[name]) > 200_000:
                                raise QueryError(f"predicate {name} too large")
            if not grown:
                break

    BUDGET_SECONDS = 20.0

    def _materialise_classes(self, db):
        """A class is a derived relation: the rows of its base (relation or class) satisfying the characteristic
        predicate, evaluated with `this` bound to the row. Rows are shared with the base so locations work."""
        out = dict(db)
        for name, cls in self.classes.items():
            base = out.get(cls["base"])
            if base is None:
                raise QueryError(f"class {name}: unknown base {cls['base']}")
            if cls["charpred"] is None:
                out[name] = list(base)
                continue
            rows = []
            self.var_class["this"] = name
            for row in base:
                if self._bool(cls["charpred"], {"this": row}):
                    rows.append(row)
            out[name] = rows
            self._check_budget()
        return out

    def run(self, db: dict) -> list[dict]:
        self.tuples = {}
        self._indexes = {}
        self._deadline = time.monotonic() + self.BUDGET_SECONDS
        self.var_class = {v: r for r, v in self.vars if r in self.classes}
        for _, clauses in self.predicates.values():
            for decls, _c in clauses:
                self.var_class.update({v: r for r, v in decls if r in self.classes})
        for cls in self.classes.values():
            for _k, _p, clauses in cls["members"].values():
                for decls, _c in clauses:
                    self.var_class.update({v: r for r, v in decls if r in self.classes})
        self.db = self._materialise_classes(db) if self.classes else db
        if self.predicates:
            self._eval_predicates(self.db)
        return self._solve_clause(self.db, self.vars, self.where)

    def findings(self, db: dict) -> list[Finding]:
        out, seen = [], set()
        for env in self.run(db):
            loc = None
            msg_parts = []
            for sel in self.select:
                if sel[0] == "var":
                    loc = env[sel[1]]
                else:
                    msg_parts.append(str(self._val(sel, env)))
            if loc is None:
                loc = env[self.vars[0][1]]
            msg = " ".join(msg_parts) or self.meta.get("name") or self.meta["id"]
            key = (self.meta["id"], loc.get("file"), loc.get("line"), msg)
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(self.meta["id"], self.meta.get("severity", "medium"), self.meta.get("name") or msg,
                               self.meta.get("name_ar") or self.meta.get("name") or msg, loc.get("file", ""), loc.get("line", 0),
                               msg[:200], self.meta.get("advice", ""), self.meta.get("cwe", ""), source="vql",
                               extra={"query": self.name}))
        return out


def load_queries(paths, builtin: bool = True) -> list:
    files: list[pathlib.Path] = sorted(DEFAULT_QUERIES.glob("*.vql")) if builtin else []
    for p in paths or ():
        p = pathlib.Path(p)
        if p.is_dir():
            files.extend(sorted(p.glob("*.vql")))
        elif p.is_file():
            files.append(p)
    out = []
    for f in files:
        try:
            out.append(Query(f.read_text(encoding="utf-8"), f.name))
        except (OSError, QueryError) as e:
            out.append(QueryError(f"{f.name}: {e}"))
    return out


def run_queries(projects, flows, query_paths=None, builtin=True) -> tuple[list[Finding], list[str]]:
    """Run built-in and user queries over the database. Returns (findings, notes)."""
    notes: list[str] = []
    queries = load_queries(query_paths, builtin)
    if not queries:
        return [], notes
    db = build_database(projects, flows)
    findings: list[Finding] = []
    for q in queries:
        if isinstance(q, QueryError):
            notes.append(f"VQL: {q}")
            continue
        try:
            findings.extend(q.findings(db))
        except QueryError as e:
            notes.append(f"VQL {q.name}: {e}")
    return findings, notes


def catalogue() -> list[dict]:
    out = []
    for q in load_queries(()):
        if isinstance(q, Query):
            out.append({"id": q.meta["id"], "severity": q.meta.get("severity", "medium"), "cwe": q.meta.get("cwe", ""),
                        "title": q.meta.get("name", q.name), "title_ar": q.meta.get("name_ar", q.meta.get("name", q.name)),
                        "advice": q.meta.get("advice", "")})
    return out
