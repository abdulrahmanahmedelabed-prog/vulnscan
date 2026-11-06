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
It is a relational subset, not QL: no recursion, no user-defined predicates, no classes.
"""

from __future__ import annotations

import ast
import pathlib
import re

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

    for proj in projects:
        for mod, file in proj.files.items():
            path, tree = file["path"], file["tree"]
            lines = file["lines"]

            def src(node):
                try:
                    seg = ast.get_source_segment("\n".join(lines), node)
                except Exception:  # noqa: BLE001
                    seg = None
                if seg:
                    return seg.strip()
                return _unparse(node)

            # context tracking: which function / class encloses a node
            stack: list[tuple[str, str]] = []  # (func name, class name)

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
                    cq = f"{mod}::{cur_cls}.{node.name}" if cur_cls else f"{mod}::{node.name}"
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


def _unparse(node) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # noqa: BLE001
        return type(node).__name__


# =================================================================== parser
TOKEN = re.compile(r"""\s*(?:(?P<str>"(?:\\.|[^"\\])*")|(?P<num>\d+)|(?P<id>[A-Za-z_][\w]*)|(?P<op>!=|<=|>=|[=<>(),.+]))""")
KEYWORDS = {"from", "where", "select", "and", "or", "not", "matches", "contains", "in"}


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

    def _parse(self):
        self._eat("kw", "from")
        while True:
            rel = self._eat("id")[1]
            var = self._eat("id")[1]
            self.vars.append((rel, var))
            if self._peek() == ("op", ","):
                self.i += 1
                continue
            break
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
        if t[0] == "id":
            self.i += 1
            if self._peek() == ("op", "."):
                self.i += 1
                field = self._eat("id")[1]
                return ("field", t[1], field)
            return ("var", t[1])
        if t == ("op", "("):
            self.i += 1
            e = self._or()
            self._eat("op", ")")
            return e
        raise QueryError(f"unexpected {t[1]!r}")

    # evaluation
    def _val(self, e, env):
        k = e[0]
        if k == "lit":
            return e[1]
        if k == "var":
            return env[e[1]]
        if k == "field":
            row = env.get(e[1])
            if row is None:
                raise QueryError(f"unknown variable {e[1]}")
            return row.get(e[2], "")
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
            return bool(self._val(e[1], env))
        if k == "cmp":
            a, b = self._val(e[2], env), self._val(e[3], env)
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
        if e[0] in ("field", "var"):
            acc.add(e[1])
        for x in e[1:]:
            if isinstance(x, tuple):
                self._vars_in(x, acc)
            elif isinstance(x, list):
                for y in x:
                    self._vars_in(y, acc)
        return acc

    def run(self, db: dict) -> list[dict]:
        # split the where clause into conjuncts; evaluate each as soon as its variables are bound
        conjuncts: list = []

        def split(e):
            if isinstance(e, tuple) and e[0] == "and":
                split(e[1])
                split(e[2])
            elif e is not None:
                conjuncts.append(e)
        split(self.where)
        needs = [self._vars_in(c, set()) for c in conjuncts]
        results = []
        order = list(self.vars)

        def rec(idx, env, done):
            if idx == len(order):
                results.append(dict(env))
                return
            rel, var = order[idx]
            rows = db.get(rel)
            if rows is None:
                raise QueryError(f"unknown relation {rel}")
            bound = set(env) | {var}
            ready = [i for i, c in enumerate(conjuncts) if i not in done and needs[i] <= bound]
            for row in rows:
                env[var] = row
                ok = True
                for i in ready:
                    if not self._bool(conjuncts[i], env):
                        ok = False
                        break
                if ok:
                    rec(idx + 1, env, done | set(ready))
            env.pop(var, None)
        rec(0, {}, set())
        return results

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
            key = (self.meta["id"], loc.get("file"), loc.get("line"))
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
