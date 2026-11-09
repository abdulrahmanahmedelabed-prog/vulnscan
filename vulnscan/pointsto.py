"""Context- and flow-sensitive Andersen-style points-to analysis.  (vulnscan: ignore-file)

Inclusion-based, field-sensitive, allocation-site based, and

* **call-site sensitive with heap cloning, k = 2** (configurable): a
  function's pointer nodes are instantiated once per calling context (the
  last ``K`` call sites on the stack), and objects allocated inside it are
  distinct per context, so a factory called from two places returns two
  different abstract objects, a callback parameter bound at one call site is
  not confused with the one bound at another, and a wrapper around the
  factory still keeps its callers apart (that is what k = 2 buys over k = 1).
  A function reached from more than ``MAX_CTX`` contexts falls back to one
  shared context (``"*"``) so the analysis stays bounded.

* **flow-sensitive for local variables**: locals are renamed into SSA-style
  versions while the constraints are collected. Every assignment creates a
  new version (a strong update: ``x = A(); x = B(); use(x)`` sees only ``B``),
  branches of ``if`` / ``try`` / ``match`` are merged with φ-copies, and loop
  headers get φ-versions fed back from the end of the body. Heap fields,
  globals and closure variables stay flow-insensitive (the usual trade-off:
  a field write may alias anything the base points to).

Constraints are collected once per scope as *templates* (context-free) and
instantiated lazily for each (scope, context) pair discovered through calls.
Globals and class this-objects are context-free.

The taint engine uses the result for call resolution on the objects a
receiver may point to (function values, callbacks, objects in containers and
globals) and for heap aliasing of tainted fields.
"""

from __future__ import annotations

import ast
import time
from collections import deque

MAX_CTX = 32
K = 2            # call-string depth for pointer nodes
HEAP_K = 2       # call-string depth for allocated objects (heap cloning)
BUDGET_SECONDS = 30.0


class Obj:
    __slots__ = ("kind", "cls", "site", "qual", "ctx")

    def __init__(self, kind, cls=None, site=None, qual=None, ctx=()):
        self.kind, self.cls, self.site, self.qual, self.ctx = kind, cls, site, qual, ctx

    def __repr__(self):
        return f"Obj({self.kind},{self.cls or self.qual or ''}@{self.site},ctx={self.ctx})"


def _param_list(fn):
    a = fn.args
    return [p.arg for p in (a.posonlyargs + a.args + a.kwonlyargs)] + ([a.vararg.arg] if a.vararg else []) + ([a.kwarg.arg] if a.kwarg else [])


_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def _assigned_names(stmts) -> set:
    """Local names (re)bound anywhere in a list of statements, not descending into nested scopes."""
    names: set = set()
    stack = list(stmts)
    while stack:
        n = stack.pop()
        if isinstance(n, _DEFS):
            if not isinstance(n, ast.Lambda):
                names.add(n.name)
            continue
        if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                names |= {x.id for x in ast.walk(t) if isinstance(x, ast.Name)}
        elif isinstance(n, (ast.For, ast.AsyncFor)):
            names |= {x.id for x in ast.walk(n.target) if isinstance(x, ast.Name)}
        elif isinstance(n, ast.withitem) and n.optional_vars is not None:
            names |= {x.id for x in ast.walk(n.optional_vars) if isinstance(x, ast.Name)}
        elif isinstance(n, ast.ExceptHandler) and n.name:
            names.add(n.name)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            names |= {(a.asname or a.name).split(".")[0] for a in n.names}
        stack.extend(ast.iter_child_nodes(n))
    return names


class PointsTo:
    def __init__(self, proj, k: int | None = None):
        self.p = proj
        self.k = K if k is None else max(0, int(k))
        self.templates: dict = {}        # scope -> list of template constraints
        self.instances: dict = {}        # scope -> set of contexts
        self.pts: dict = {}              # concrete key -> set[Obj]
        self.node_key: dict = {}         # id(ast expr) -> (scope, template key)
        self.objs_cache: dict = {}       # (kind, site, cls, qual, ctx) -> Obj
        self.func_obj: dict = {}
        self.this_obj: dict = {}
        self.locals: dict = {}
        self.globals_decl: dict = {}
        self._method_cache: dict = {}
        self._layout_cache: dict = {}
        self._readers: dict = {}         # pointer node -> constraints that read it (worklist solver)
        self._field_watch: dict = {}     # ("f", id(obj), attr) -> loads to re-run when the field grows
        self._fw_seen: set = set()
        self._pending: deque = deque()
        self._queued: set = set()        # ids of constraints currently in the worklist
        self.timed_out = False
        self.tmp = 0
        self.ver_counter = 0
        self._ver: dict = {}             # current SSA version of each local in the scope being collected
        self._cur_scope = None
        self._collect()
        self._solve()

    # ------------------------------------------------------------ helpers
    def _new(self):
        self.tmp += 1
        return ("t", self._cur_scope, self.tmp)

    def _obj(self, kind, cls=None, site=None, qual=None, ctx=()):
        k = (kind, site, cls, qual, ctx)
        o = self.objs_cache.get(k)
        if o is None:
            o = self.objs_cache[k] = Obj(kind, cls, site, qual, ctx)
        return o

    def _fobj(self, qual):
        o = self.func_obj.get(qual)
        if o is None:
            info = self.p.gfuncs[qual]
            o = self.func_obj[qual] = self._obj("func", site=(info["path"], info["node"].lineno), qual=qual)
        return o

    def _tobj(self, cq):
        o = self.this_obj.get(cq)
        if o is None:
            c = self.p.classes[cq]
            o = self.this_obj[cq] = self._obj("this", cls=cq, site=(c["path"], c["node"].lineno))
        return o

    @staticmethod
    def _concrete(key, ctx):
        if key[0] == "g":
            return key
        return key + (ctx,)

    def _add(self, ckey, obj):
        return self._grow(ckey, {obj})

    # SSA versions ---------------------------------------------------------
    def _local_key(self, scope, name, ver=0):
        return ("v", scope, name, ver)

    def _read(self, chain, name):
        """Key read for a name: current SSA version of a local; enclosing-function or module variables are
        context-free, flow-insensitive globals."""
        if name in self.locals.get(chain[0], ()):
            return self._local_key(chain[0], name, self._ver.get(name, 0))
        for scope in chain[1:]:
            if name in self.locals.get(scope, ()):
                return ("g", scope, name)
        return ("g", chain[-1], name)

    def _write(self, chain, name):
        """Key written by an assignment: a fresh SSA version for a local (strong update)."""
        if name in self.locals.get(chain[0], ()):
            self.ver_counter += 1
            self._ver[name] = self.ver_counter
            return self._local_key(chain[0], name, self.ver_counter)
        return self._read(chain, name)

    def _fresh_version(self, scope, name):
        self.ver_counter += 1
        self._ver[name] = self.ver_counter
        return self._local_key(scope, name, self.ver_counter)

    def _merge(self, scope, states: list):
        """φ: join several end-of-branch version maps into the current one."""
        states = [s for s in states if s is not None]
        if not states:
            return
        names = set()
        for s in states:
            names |= set(s)
        for name in names:
            vers = {s.get(name, 0) for s in states}
            if len(vers) == 1:
                self._ver[name] = vers.pop()
                continue
            dst = self._fresh_version(scope, name)
            for v in vers:
                self._emit(("copy", self._local_key(scope, name, v), dst))

    # ------------------------------------------------------------ collect
    def _enclosing(self, q):
        return list(self.p.gfuncs[q].get("enclosing", []))

    def _collect(self):
        for q, info in self.p.gfuncs.items():
            fn = info["node"]
            names = set(_param_list(fn)) | _assigned_names(fn.body)
            gl = set()
            for n in ast.walk(fn):
                if isinstance(n, (ast.Global, ast.Nonlocal)):
                    gl |= set(n.names)
            self.locals[q] = names - gl
            self.globals_decl[q] = gl
        for mod in self.p.files:
            self.locals[mod] = set()
        for mod, file in self.p.files.items():
            self._cur_scope = mod
            self.templates[mod] = []
            self._ver = {}
            self._stmts(file["tree"].body, mod, None, [mod], file["path"], None)
            self.instances[mod] = {()}
        for q, info in self.p.gfuncs.items():
            self._cur_scope = q
            self.templates[q] = []
            self._ver = {}
            chain = [q] + self._enclosing(q) + [info["mod"]]
            self._stmts(info["node"].body, info["mod"], info["cls"], chain, info["path"], q)
            self.instances[q] = {()}   # entry/uncalled functions are analysed in the empty context
        # function definitions are function values in their enclosing scope (context-free globals)
        for q, info in self.p.gfuncs.items():
            if info["cls"] is None:
                enc = self._enclosing(q)
                scope = enc[0] if enc else info["mod"]
                self._add(("g", scope, info["name"]), self._fobj(q))

    def _emit(self, c):
        self.templates[self._cur_scope].append(c)

    def _nested_qual(self, mod, cls, node):
        if cls:
            return f"{cls}.{node.name}"
        return f"{mod}::{node.name}"

    def _stmts(self, body, mod, cls, chain, path, qual):
        for n in body:
            self._stmt(n, mod, cls, chain, path, qual)

    def _stmt(self, n, mod, cls, chain, path, qual):
        scope = chain[0]
        ev = lambda e: self._eval(e, mod, cls, chain, path)  # noqa: E731
        if isinstance(n, ast.Assign):
            src = ev(n.value)
            for t in n.targets:
                self._assign(t, src, mod, cls, chain, path)
        elif isinstance(n, ast.AnnAssign):
            if n.value is not None:
                self._assign(n.target, ev(n.value), mod, cls, chain, path)
        elif isinstance(n, ast.AugAssign):
            src = ev(n.value)
            if isinstance(n.target, ast.Name):
                old = self._read(chain, n.target.id)
                dst = self._write(chain, n.target.id)
                self._emit(("copy", old, dst))
                self._emit(("copy", src, dst))
            else:
                self._assign(n.target, src, mod, cls, chain, path)
        elif isinstance(n, (ast.For, ast.AsyncFor)):
            it = ev(n.iter)
            tmp = self._new()
            self._emit(("load", it, "<elem>", tmp))
            self._loop(scope, n.body, [lambda: self._assign(n.target, tmp, mod, cls, chain, path)], mod, cls, chain, path, qual)
            self._stmts(n.orelse, mod, cls, chain, path, qual)
        elif isinstance(n, ast.While):
            self._loop(scope, n.body, [lambda: ev(n.test)], mod, cls, chain, path, qual)
            self._stmts(n.orelse, mod, cls, chain, path, qual)
        elif isinstance(n, (ast.With, ast.AsyncWith)):
            for item in n.items:
                v = ev(item.context_expr)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, v, mod, cls, chain, path)
            self._stmts(n.body, mod, cls, chain, path, qual)
        elif isinstance(n, ast.If):
            ev(n.test)
            before = dict(self._ver)
            self._stmts(n.body, mod, cls, chain, path, qual)
            s1 = dict(self._ver)
            self._ver = dict(before)
            self._stmts(n.orelse, mod, cls, chain, path, qual)
            s2 = dict(self._ver)
            self._merge(scope, [s1, s2])
        elif isinstance(n, ast.Try) or (hasattr(ast, "TryStar") and isinstance(n, ast.TryStar)):
            before = dict(self._ver)
            self._stmts(n.body, mod, cls, chain, path, qual)
            after_body = dict(self._ver)
            ends = []
            self._ver = dict(after_body)
            self._stmts(n.orelse, mod, cls, chain, path, qual)
            ends.append(dict(self._ver))
            for h in n.handlers:
                # an exception may be raised anywhere in the body: the handler sees either state
                self._ver = dict(before)
                self._merge(scope, [before, after_body])
                if h.type is not None:
                    ev(h.type)
                if h.name:
                    self._write(chain, h.name)
                self._stmts(h.body, mod, cls, chain, path, qual)
                ends.append(dict(self._ver))
            self._merge(scope, ends)
            self._stmts(n.finalbody, mod, cls, chain, path, qual)
        elif hasattr(ast, "Match") and isinstance(n, ast.Match):
            subj = ev(n.subject)
            before = dict(self._ver)
            ends = [before]
            for case in n.cases:
                self._ver = dict(before)
                for x in ast.walk(case.pattern):
                    if isinstance(x, (ast.MatchAs, ast.MatchStar)) and x.name:
                        self._emit(("copy", subj, self._write(chain, x.name)))
                    elif isinstance(x, ast.MatchMapping) and x.rest:
                        self._write(chain, x.rest)
                if case.guard is not None:
                    ev(case.guard)
                self._stmts(case.body, mod, cls, chain, path, qual)
                ends.append(dict(self._ver))
            self._merge(scope, ends)
        elif isinstance(n, ast.Return):
            if n.value is not None and qual:
                self._emit(("copy", ev(n.value), ("r", qual)))
        elif isinstance(n, ast.Expr):
            ev(n.value)
        elif isinstance(n, (ast.Raise, ast.Assert)):
            for child in ast.iter_child_nodes(n):
                if isinstance(child, ast.expr):
                    ev(child)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            q = self._nested_qual(mod, cls, n)
            if q in self.p.gfuncs and n.name in self.locals.get(scope, ()):
                self._emit(("alloc", ("func", None, None, q), self._write(chain, n.name)))
        elif isinstance(n, ast.ClassDef):
            pass   # classes are resolved statically by the engine
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                nm = (a.asname or a.name).split(".")[0]
                if nm in self.locals.get(scope, ()):
                    self._write(chain, nm)
        elif isinstance(n, ast.Delete):
            pass

    def _loop(self, scope, body, header_actions, mod, cls, chain, path, qual):
        """Loop header φ-versions: each local assigned in the loop gets a version fed from the entry state and
        from the end of the body; the state after the loop is the header state (zero or more iterations)."""
        assigned = _assigned_names(body) & self.locals.get(scope, set())
        phis = {}
        for name in assigned:
            entry = self._local_key(scope, name, self._ver.get(name, 0))
            dst = self._fresh_version(scope, name)
            self._emit(("copy", entry, dst))
            phis[name] = dst
        header = dict(self._ver)
        for act in header_actions:
            act()
        self._stmts(body, mod, cls, chain, path, qual)
        for name, dst in phis.items():
            self._emit(("copy", self._local_key(scope, name, self._ver.get(name, 0)), dst))
        self._ver = header
        # header actions (for-target binding, loop test) may bind names too: re-run them so the
        # post-loop state includes their final binding
        for act in header_actions:
            act()

    def _assign(self, target, src, mod, cls, chain, path):
        if isinstance(target, ast.Name):
            self._emit(("copy", src, self._write(chain, target.id)))
        elif isinstance(target, ast.Attribute):
            self._emit(("store", self._eval(target.value, mod, cls, chain, path), target.attr, src))
        elif isinstance(target, ast.Subscript):
            self._emit(("store", self._eval(target.value, mod, cls, chain, path), "<elem>", src))
        elif isinstance(target, (ast.Tuple, ast.List)):
            tmp = self._new()
            self._emit(("load", src, "<elem>", tmp))
            for e in target.elts:
                self._assign(e, tmp, mod, cls, chain, path)
        elif isinstance(target, ast.Starred):
            self._assign(target.value, src, mod, cls, chain, path)

    def _eval(self, e, mod, cls, chain, path):
        key = self._eval_inner(e, mod, cls, chain, path)
        self.node_key[id(e)] = (self._cur_scope, key)
        return key

    def _eval_inner(self, e, mod, cls, chain, path):
        if isinstance(e, ast.Name):
            if e.id in ("self", "cls") and chain[0] in self.p.gfuncs:
                return ("v", chain[0], "self")
            return self._read(chain, e.id)
        if isinstance(e, ast.Attribute):
            base = self._eval(e.value, mod, cls, chain, path)
            return self._attr_from(e, base, mod)
        if isinstance(e, ast.Subscript):
            base = self._eval(e.value, mod, cls, chain, path)
            tmp = self._new()
            self._emit(("load", base, "<elem>", tmp))
            if isinstance(e.slice, (ast.Name, ast.Attribute, ast.Call, ast.Subscript)):
                self._eval(e.slice, mod, cls, chain, path)
            return tmp
        if isinstance(e, ast.Call):
            return self._eval_call(e, mod, cls, chain, path)
        if isinstance(e, (ast.List, ast.Tuple, ast.Set)):
            tmp = self._new()
            self._emit(("alloc", ("container", None, (path, getattr(e, "lineno", 0)), None), tmp))
            for el in e.elts:
                self._emit(("store", tmp, "<elem>", self._eval(el, mod, cls, chain, path)))
            return tmp
        if isinstance(e, ast.Dict):
            tmp = self._new()
            self._emit(("alloc", ("container", None, (path, getattr(e, "lineno", 0)), None), tmp))
            for v in e.values:
                if v is not None:
                    self._emit(("store", tmp, "<elem>", self._eval(v, mod, cls, chain, path)))
            return tmp
        if isinstance(e, ast.BinOp):
            tmp = self._new()
            self._emit(("copy", self._eval(e.left, mod, cls, chain, path), tmp))
            self._emit(("copy", self._eval(e.right, mod, cls, chain, path), tmp))
            return tmp
        if isinstance(e, ast.BoolOp):
            tmp = self._new()
            for v in e.values:
                self._emit(("copy", self._eval(v, mod, cls, chain, path), tmp))
            return tmp
        if isinstance(e, ast.IfExp):
            tmp = self._new()
            self._eval(e.test, mod, cls, chain, path)
            self._emit(("copy", self._eval(e.body, mod, cls, chain, path), tmp))
            self._emit(("copy", self._eval(e.orelse, mod, cls, chain, path), tmp))
            return tmp
        if isinstance(e, ast.NamedExpr):
            src = self._eval(e.value, mod, cls, chain, path)
            self._assign(e.target, src, mod, cls, chain, path)
            return src
        if isinstance(e, (ast.Await, ast.Starred)):
            return self._eval(e.value, mod, cls, chain, path)
        if isinstance(e, ast.JoinedStr):
            for v in e.values:
                if isinstance(v, ast.FormattedValue):
                    self._eval(v.value, mod, cls, chain, path)
            return self._new()
        if isinstance(e, ast.Compare):
            self._eval(e.left, mod, cls, chain, path)
            for c in e.comparators:
                self._eval(c, mod, cls, chain, path)
            return self._new()
        if isinstance(e, ast.UnaryOp):
            self._eval(e.operand, mod, cls, chain, path)
            return self._new()
        if isinstance(e, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            # a comprehension builds a container of its element expression; its iterables are evaluated
            tmp = self._new()
            self._emit(("alloc", ("container", None, (path, getattr(e, "lineno", 0)), None), tmp))
            for g in e.generators:
                self._eval(g.iter, mod, cls, chain, path)
            elt = e.value if isinstance(e, ast.DictComp) else e.elt
            self._emit(("store", tmp, "<elem>", self._eval(elt, mod, cls, chain, path)))
            return tmp
        return self._new()

    def _attr_from(self, e, base, mod):
        tmp = self._new()
        d = _dotted(e)
        q = self.p._resolve_function(mod, d) if "." in d else None
        if q:
            self._emit(("alloc", ("func", None, None, q), tmp))
        self._emit(("load", base, e.attr, tmp))
        return tmp

    def _eval_call(self, call, mod, cls, chain, path):
        dst = self._new()
        args = [self._eval(a, mod, cls, chain, path) for a in call.args]
        kws = {k.arg: self._eval(k.value, mod, cls, chain, path) for k in call.keywords if k.arg}
        func_key, recv = None, None
        if isinstance(call.func, ast.Name):
            func_key = self._read(chain, call.func.id)
            self.node_key[id(call.func)] = (self._cur_scope, func_key)
        elif isinstance(call.func, ast.Attribute):
            recv = self._eval(call.func.value, mod, cls, chain, path)
            # build the method value from the receiver just evaluated: evaluating call.func again would re-walk
            # the receiver, doubling the work at every link of a chain (a.b().c().d()… was exponential)
            func_key = self._attr_from(call.func, recv, mod)
            self.node_key[id(call.func)] = (self._cur_scope, func_key)
            if call.func.attr in ("append", "add", "insert", "extend", "update", "put", "setdefault"):
                for an in args:
                    self._emit(("store", recv, "<elem>", an))
        static, ctor = self._static(mod, cls, call)
        if ctor:
            self._emit(("alloc", ("inst", ctor, (path, getattr(call, "lineno", 0)), None), dst))
            recv = dst
        self._emit(("call", call, func_key, recv, args, kws, dst, tuple(static), bool(ctor)))
        return dst

    def _static(self, mod, cls, call):
        try:
            from .taint import _Env
            return self.p._callees_static(mod, cls, call, _Env())
        except Exception:  # noqa: BLE001
            return [], None

    # ------------------------------------------------------------- solve
    def _ensure(self, scope, ctx):
        s = self.instances.setdefault(scope, set())
        if ctx in s:
            return False
        if len(s) >= MAX_CTX:
            ctx = ("*",)
            if ctx in s:
                return False
        s.add(ctx)
        self._instantiate(scope, ctx)
        # self of a method points to the class this-objects in every context
        info = self.p.gfuncs.get(scope)
        if info and info["cls"]:
            for k in self.p._mro(info["cls"]):
                self._add(self._concrete(("v", scope, "self"), ctx), self._tobj(k))
        return True

    def _callee_ctx(self, callee, call_ctx, call):
        if self.k == 0:
            return ()
        new = ((id(call),) + tuple(c for c in call_ctx if c != "*"))[:self.k]
        s = self.instances.get(callee, set())
        if len(s) >= MAX_CTX and new not in s:
            return ("*",)
        return new

    # Worklist solver -------------------------------------------------------
    # Constraints are indexed by the pointer node they read; when a node's set grows the constraints
    # reading it are re-queued, so each iteration only revisits what can actually change.
    def _instantiate(self, scope, ctx):
        """Concrete constraints for one (scope, context): allocations applied once; the rest indexed by input."""
        for c in self.templates.get(scope, ()):
            kind = c[0]
            if kind == "copy":
                src, dst = self._concrete(c[1], ctx), self._concrete(c[2], ctx)
                self._watch(src, ("copy", src, dst))
            elif kind == "alloc":
                k, ocls, site, qual = c[1]
                o = self._fobj(qual) if k == "func" else self._obj(k, ocls, site, None, ctx[:HEAP_K])
                self._grow(self._concrete(c[2], ctx), {o})
            elif kind == "load":
                base, dst = self._concrete(c[1], ctx), self._concrete(c[3], ctx)
                self._watch(base, ("load", base, c[2], dst))
            elif kind == "store":
                base, src = self._concrete(c[1], ctx), self._concrete(c[3], ctx)
                cc = ("store", base, c[2], src)
                self._watch(base, cc)
                self._watch(src, cc)
            elif kind == "call":
                entry = [c, ctx, None]
                cc = ("call", entry)
                _, call, func_key, recv, args, kws, dst, static, is_ctor = c
                for key in [func_key, recv] + list(args) + list(kws.values()):
                    if key is not None:
                        self._watch(self._concrete(key, ctx), cc)
                self._queue(cc)

    def _watch(self, key, cc):
        self._readers.setdefault(key, []).append(cc)
        self._queue(cc)

    def _queue(self, cc):
        i = id(cc)
        if i not in self._queued:
            self._queued.add(i)
            self._pending.append(cc)

    def _queue_all(self, ccs):
        q, pend = self._queued, self._pending
        for cc in ccs:
            i = id(cc)
            if i not in q:
                q.add(i)
                pend.append(cc)

    def _grow(self, key, objs) -> bool:
        """Add objects to a node; queue the constraints that read it when it grew."""
        if not objs:
            return False
        d = self.pts.get(key)
        if d is None:
            self.pts[key] = set(objs)
            grew = True
        else:
            before = len(d)
            d |= objs
            grew = len(d) != before
        if grew:
            rd = self._readers.get(key)
            if rd:
                self._queue_all(rd)
            fw = self._field_watch.get(key)
            if fw:
                self._queue_all(fw)
        return grew

    def _solve(self):
        for scope, ctxs in list(self.instances.items()):
            for ctx in list(ctxs):
                self.instances[scope].discard(ctx)
                self._ensure(scope, ctx)
        pts = self.pts
        steps = 0
        deadline = time.monotonic() + BUDGET_SECONDS
        while self._pending:
            cc = self._pending.popleft()
            self._queued.discard(id(cc))
            steps += 1
            if steps & 1023 == 0 and time.monotonic() > deadline:
                self.timed_out = True   # partial result: still usable for call resolution, just less complete
                break
            kind = cc[0]
            if kind == "copy":
                so = pts.get(cc[1])
                if so:
                    self._grow(cc[2], so)
            elif kind == "load":
                _, base, attr, dst = cc
                bo = pts.get(base)
                if bo:
                    acc = set()
                    for o in bo:
                        fk = ("f", id(o), attr)
                        fo = pts.get(fk)
                        if fo:
                            acc |= fo
                        mark = (fk, id(cc))
                        if mark not in self._fw_seen:
                            self._fw_seen.add(mark)
                            self._field_watch.setdefault(fk, []).append(cc)
                    self._grow(dst, acc)
            elif kind == "store":
                _, base, attr, src = cc
                bo, so = pts.get(base), pts.get(src)
                if bo and so:
                    for o in list(bo):
                        self._grow(("f", id(o), attr), so)
            elif kind == "call":
                self._do_call(cc[1], cc)
        self.steps = steps
        self._readers = {}
        self._field_watch = {}
        self._fw_seen = set()
        self._pending.clear()
        self._queued.clear()

    def _resolve(self, call, func_key, recv, static, ctx):
        quals = set(static)
        if func_key is not None:
            for o in self.pts.get(self._concrete(func_key, ctx), ()):
                if o.kind == "func":
                    quals.add(o.qual)
        if recv is not None and isinstance(call.func, ast.Attribute):
            attr = call.func.attr
            for o in self.pts.get(self._concrete(recv, ctx), ()):
                if o.cls:
                    quals.update(self._methods(o.cls, attr))
        return quals

    def _methods(self, cq, name):
        key = (cq, name)
        hit = self._method_cache.get(key)
        if hit is None:
            hit = self._method_cache[key] = tuple(self.p._lookup_method(cq, name))
        return hit

    def _layout(self, q):
        lay = self._layout_cache.get(q)
        if lay is None:
            a = self.p.gfuncs[q]["node"].args
            pos = [p.arg for p in (a.posonlyargs + a.args)]
            offset = 1 if (pos and pos[0] in ("self", "cls")) else 0
            lay = self._layout_cache[q] = (pos, offset, {p.arg for p in a.kwonlyargs},
                                           a.vararg.arg if a.vararg else None, a.kwarg.arg if a.kwarg else None)
        return lay

    def _do_call(self, entry, cc=None):
        """Propagate one call in one context. `entry` is [constraint, ctx, last_signature]; the call is
        skipped when none of its inputs (callee set, argument/receiver sets, callee returns) grew."""
        c, ctx, last = entry
        _, call, func_key, recv, args, kws, dst, static, is_ctor = c
        pts = self.pts
        quals = self._resolve(call, func_key, recv, static, ctx)
        recv_set = pts.get(self._concrete(recv, ctx), ()) if recv is not None else ()
        arg_sets = [pts.get(self._concrete(an, ctx), ()) for an in args]
        kw_sets = {k: pts.get(self._concrete(an, ctx), ()) for k, an in kws.items()}
        sig = [len(quals), len(recv_set), tuple(len(s) for s in arg_sets), tuple(len(s) for s in kw_sets.values())]
        changed = False
        rets = 0
        for q in quals:
            info = self.p.gfuncs.get(q)
            if not info:
                continue
            cctx = self._callee_ctx(q, ctx, call)
            changed |= self._ensure(q, cctx)
            rk = self._concrete(("r", q), cctx)
            rets += len(pts.get(rk, ()))
            if cc is not None:
                mark = (rk, id(cc))
                if mark not in self._fw_seen:
                    self._fw_seen.add(mark)
                    self._readers.setdefault(rk, []).append(cc)
        sig.append(rets)
        sig = tuple(sig)
        if sig == last and not changed:
            return False
        entry[2] = sig
        for q in quals:
            info = self.p.gfuncs.get(q)
            if not info:
                continue
            cctx = self._callee_ctx(q, ctx, call)
            pos, offset, kwonly, vararg, kwarg = self._layout(q)
            if offset and recv_set:
                changed |= self._grow(self._concrete(self._local_key(q, pos[0]), cctx), recv_set)
            for i, aset in enumerate(arg_sets):
                if not aset:
                    continue
                j = i + offset
                name = pos[j] if j < len(pos) else vararg
                if name:
                    changed |= self._grow(self._concrete(self._local_key(q, name), cctx), aset)
            for k, kset in kw_sets.items():
                if not kset:
                    continue
                name = k if (k in pos or k in kwonly) else kwarg
                if name:
                    changed |= self._grow(self._concrete(self._local_key(q, name), cctx), kset)
            rs = pts.get(self._concrete(("r", q), cctx))
            if rs:
                changed |= self._grow(self._concrete(dst, ctx), rs)
        return changed

    # ---------------------------------------------------------------- API
    def objs(self, node) -> set:
        hit = self.node_key.get(id(node))
        if hit is None:
            return set()
        scope, key = hit
        out = set()
        if key[0] == "g":
            return set(self.pts.get(key, ()))
        for ctx in self.instances.get(scope, ()):
            out |= self.pts.get(self._concrete(key, ctx), set())
        return out

    def classes_for(self, node) -> set:
        return {o.cls for o in self.objs(node) if o.cls}

    def funcs_for(self, node) -> set:
        return {o.qual for o in self.objs(node) if o.kind == "func"}

    def callees_for_call(self, call) -> set:
        quals = set()
        if isinstance(call.func, ast.Name):
            quals |= self.funcs_for(call.func)
        elif isinstance(call.func, ast.Attribute):
            quals |= self.funcs_for(call.func)
            for cq in self.classes_for(call.func.value):
                quals |= set(self.p._lookup_method(cq, call.func.attr))
        return quals

    def stats(self) -> dict:
        return {"k": self.k, "heap_k": HEAP_K, "contexts": sum(len(s) for s in self.instances.values()),
                "scopes": len(self.instances), "nodes": len(self.pts), "steps": getattr(self, "steps", 0),
                "timed_out": self.timed_out}


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        b = _dotted(node.value)
        return f"{b}.{node.attr}" if b else node.attr
    return ""
