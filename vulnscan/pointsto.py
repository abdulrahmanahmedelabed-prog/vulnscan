"""Context-sensitive (1-call-site) Andersen-style points-to analysis.  (vulnscan: ignore-file)

Inclusion-based, flow-insensitive, field-sensitive, allocation-site based,
and **call-site sensitive with heap cloning** (k = 1): a function's pointer
nodes are instantiated once per calling context, and objects allocated inside
it are distinct per context, so a factory called from two places returns two
different abstract objects and a callback parameter bound at one call site
is not confused with the one bound at another.

Constraints are collected once per scope as *templates* (context-free) and
instantiated lazily for each (scope, context) pair discovered through calls.
Globals and class this-objects are context-free. A function reached from
more than MAX_CTX call sites falls back to one shared context ("*") so the
analysis stays bounded.

The taint engine uses the result for call resolution on the objects a
receiver may point to (function values, callbacks, objects in containers and
globals) and for heap aliasing of tainted fields.
"""

from __future__ import annotations

import ast

MAX_ITER = 80
MAX_CTX = 24
K = 1


class Obj:
    __slots__ = ("kind", "cls", "site", "qual", "ctx")

    def __init__(self, kind, cls=None, site=None, qual=None, ctx=()):
        self.kind, self.cls, self.site, self.qual, self.ctx = kind, cls, site, qual, ctx

    def __repr__(self):
        return f"Obj({self.kind},{self.cls or self.qual or ''}@{self.site},ctx={self.ctx})"


def _param_list(fn):
    a = fn.args
    return [p.arg for p in (a.posonlyargs + a.args + a.kwonlyargs)] + ([a.vararg.arg] if a.vararg else []) + ([a.kwarg.arg] if a.kwarg else [])


class PointsTo:
    def __init__(self, proj):
        self.p = proj
        self.templates: dict = {}        # scope -> list of template constraints
        self.instances: dict = {}        # scope -> set of contexts
        self.pts: dict = {}              # concrete key -> set[Obj]
        self.node_key: dict = {}         # id(ast expr) -> (scope, template key)
        self.objs_cache: dict = {}       # (kind, site, cls, qual, ctx) -> Obj
        self.func_obj: dict = {}
        self.this_obj: dict = {}
        self.locals: dict = {}
        self.tmp = 0
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
        s = self.pts.setdefault(ckey, set())
        if obj not in s:
            s.add(obj)
            return True
        return False

    def _var(self, chain, name):
        """Variable key: innermost scope defining it; enclosing-function or module variables are context-free globals."""
        if name in self.locals.get(chain[0], ()):
            return ("v", chain[0], name)
        for scope in chain[1:]:
            if name in self.locals.get(scope, ()):
                return ("g", scope, name)
        return ("g", chain[-1], name)

    # ------------------------------------------------------------ collect
    @staticmethod
    def _scope_nodes(fn):
        stack = list(reversed(getattr(fn, "body", []) or []))
        while stack:
            n = stack.pop()
            yield n
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            stack.extend(reversed(list(ast.iter_child_nodes(n))))

    def _enclosing(self, q):
        return list(self.p.gfuncs[q].get("enclosing", []))

    def _collect(self):
        for q, info in self.p.gfuncs.items():
            names = set(_param_list(info["node"]))
            for n in self._scope_nodes(info["node"]):
                if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                        names |= {x.id for x in ast.walk(t) if isinstance(x, ast.Name)}
                elif isinstance(n, (ast.For, ast.AsyncFor)):
                    names |= {x.id for x in ast.walk(n.target) if isinstance(x, ast.Name)}
                elif isinstance(n, ast.withitem) and n.optional_vars is not None:
                    names |= {x.id for x in ast.walk(n.optional_vars) if isinstance(x, ast.Name)}
                elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    names.add(n.name)
            self.locals[q] = names
        for mod in self.p.files:
            self.locals[mod] = set()
        for mod, file in self.p.files.items():
            self._cur_scope = mod
            self.templates[mod] = []
            self._collect_scope(file["tree"], mod, None, [mod], file["path"], None)
            self.instances[mod] = {()}
        for q, info in self.p.gfuncs.items():
            self._cur_scope = q
            self.templates[q] = []
            chain = [q] + self._enclosing(q) + [info["mod"]]
            self._collect_scope(info["node"], info["mod"], info["cls"], chain, info["path"], q)
            self.instances[q] = {()}   # entry/uncalled functions are analysed in the empty context
        # function definitions are function values in their enclosing scope (context-free globals)
        for q, info in self.p.gfuncs.items():
            if info["cls"] is None:
                enc = self._enclosing(q)
                scope = enc[0] if enc else info["mod"]
                self._add(("g", scope, info["name"]), self._fobj(q))

    def _emit(self, c):
        self.templates[self._cur_scope].append(c)

    def _collect_scope(self, fn, mod, cls, chain, path, qual):
        for n in self._scope_nodes(fn):
            if isinstance(n, ast.Assign):
                src = self._eval(n.value, mod, cls, chain, path)
                for t in n.targets:
                    self._assign(t, src, mod, cls, chain, path)
            elif isinstance(n, ast.AnnAssign) and n.value is not None:
                self._assign(n.target, self._eval(n.value, mod, cls, chain, path), mod, cls, chain, path)
            elif isinstance(n, ast.AugAssign):
                self._assign(n.target, self._eval(n.value, mod, cls, chain, path), mod, cls, chain, path)
            elif isinstance(n, (ast.For, ast.AsyncFor)):
                it = self._eval(n.iter, mod, cls, chain, path)
                tmp = self._new()
                self._emit(("load", it, "<elem>", tmp))
                self._assign(n.target, tmp, mod, cls, chain, path)
            elif isinstance(n, ast.withitem) and n.optional_vars is not None:
                self._assign(n.optional_vars, self._eval(n.context_expr, mod, cls, chain, path), mod, cls, chain, path)
            elif isinstance(n, ast.Return) and n.value is not None and qual:
                self._emit(("copy", self._eval(n.value, mod, cls, chain, path), ("r", qual)))
            elif isinstance(n, ast.Expr):
                self._eval(n.value, mod, cls, chain, path)
            elif isinstance(n, (ast.If, ast.While)):
                self._eval(n.test, mod, cls, chain, path)

    def _assign(self, target, src, mod, cls, chain, path):
        if isinstance(target, ast.Name):
            self._emit(("copy", src, self._var(chain, target.id)))
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
            return self._var(chain, e.id)
        if isinstance(e, ast.Attribute):
            base = self._eval(e.value, mod, cls, chain, path)
            tmp = self._new()
            q = self.p._resolve_function(mod, _dotted(e)) if "." in _dotted(e) else None
            if q:
                self._emit(("alloc", ("func", None, None, q), tmp))
            self._emit(("load", base, e.attr, tmp))
            return tmp
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
            self._emit(("copy", self._eval(e.body, mod, cls, chain, path), tmp))
            self._emit(("copy", self._eval(e.orelse, mod, cls, chain, path), tmp))
            self._eval(e.test, mod, cls, chain, path)
            return tmp
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
        return self._new()

    def _eval_call(self, call, mod, cls, chain, path):
        dst = self._new()
        args = [self._eval(a, mod, cls, chain, path) for a in call.args]
        kws = {k.arg: self._eval(k.value, mod, cls, chain, path) for k in call.keywords if k.arg}
        func_key, recv = None, None
        if isinstance(call.func, ast.Name):
            func_key = self._var(chain, call.func.id)
            self.node_key[id(call.func)] = (self._cur_scope, func_key)
        elif isinstance(call.func, ast.Attribute):
            recv = self._eval(call.func.value, mod, cls, chain, path)
            func_key = self._eval(call.func, mod, cls, chain, path)
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
        site = (id(call),)
        s = self.instances.get(callee, set())
        if len(s) >= MAX_CTX and site not in s:
            return ("*",)
        return site[:K]

    def _instantiate(self, scope, ctx):
        """Concrete constraints for one (scope, context): allocations applied once; copies/loads/stores/calls stored."""
        copies, loads, stores, calls = [], [], [], []
        for c in self.templates.get(scope, ()):
            kind = c[0]
            if kind == "copy":
                copies.append((self._concrete(c[1], ctx), self._concrete(c[2], ctx)))
            elif kind == "alloc":
                k, ocls, site, qual = c[1]
                o = self._fobj(qual) if k == "func" else self._obj(k, ocls, site, None, ctx)
                self._add(self._concrete(c[2], ctx), o)
            elif kind == "load":
                loads.append((self._concrete(c[1], ctx), c[2], self._concrete(c[3], ctx)))
            elif kind == "store":
                stores.append((self._concrete(c[1], ctx), c[2], self._concrete(c[3], ctx)))
            elif kind == "call":
                calls.append((c, ctx))
        self.concrete.append((copies, loads, stores, calls))

    def _solve(self):
        self.concrete = []
        for scope, ctxs in list(self.instances.items()):
            for ctx in list(ctxs):
                self.instances[scope].discard(ctx)
                self._ensure(scope, ctx)
        pts = self.pts
        for _ in range(MAX_ITER):
            changed = False
            for copies, loads, stores, calls in list(self.concrete):
                for src, dst in copies:
                    so = pts.get(src)
                    if so:
                        d = pts.setdefault(dst, set())
                        before = len(d)
                        d |= so
                        changed |= len(d) != before
                for base, attr, dst in loads:
                    bo = pts.get(base)
                    if bo:
                        d = pts.setdefault(dst, set())
                        before = len(d)
                        for o in bo:
                            fo = pts.get(("f", id(o), attr))
                            if fo:
                                d |= fo
                        changed |= len(d) != before
                for base, attr, src in stores:
                    bo, so = pts.get(base), pts.get(src)
                    if bo and so:
                        for o in list(bo):
                            d = pts.setdefault(("f", id(o), attr), set())
                            before = len(d)
                            d |= so
                            changed |= len(d) != before
                for c, ctx in calls:
                    changed |= self._do_call(c, ctx)
            if not changed:
                break

    def _resolve(self, call, func_key, recv, static, ctx):
        quals = set(static)
        if func_key is not None:
            for o in self.pts.get(self._concrete(func_key, ctx), ()):
                if o.kind == "func":
                    quals.add(o.qual)
        if recv is not None and isinstance(call.func, ast.Attribute):
            for o in self.pts.get(self._concrete(recv, ctx), ()):
                if o.cls:
                    quals.update(self.p._lookup_method(o.cls, call.func.attr))
        return quals

    def _do_call(self, c, ctx):
        _, call, func_key, recv, args, kws, dst, static, is_ctor = c
        changed = False
        for q in self._resolve(call, func_key, recv, static, ctx):
            info = self.p.gfuncs.get(q)
            if not info:
                continue
            cctx = self._callee_ctx(q, ctx, call)
            changed |= self._ensure(q, cctx)
            fn = info["node"]
            a = fn.args
            pos = [p.arg for p in (a.posonlyargs + a.args)]
            offset = 1 if (pos and pos[0] in ("self", "cls")) else 0
            if offset and recv is not None:
                for o in list(self.pts.get(self._concrete(recv, ctx), ())):
                    changed |= self._add(self._concrete(("v", q, pos[0]), cctx), o)
            for i, an in enumerate(args):
                j = i + offset
                tgt = ("v", q, pos[j]) if j < len(pos) else (("v", q, a.vararg.arg) if a.vararg else None)
                if tgt:
                    for o in list(self.pts.get(self._concrete(an, ctx), ())):
                        changed |= self._add(self._concrete(tgt, cctx), o)
            kwonly = {p.arg for p in a.kwonlyargs}
            for k, an in kws.items():
                tgt = ("v", q, k) if (k in pos or k in kwonly) else (("v", q, a.kwarg.arg) if a.kwarg else None)
                if tgt:
                    for o in list(self.pts.get(self._concrete(an, ctx), ())):
                        changed |= self._add(self._concrete(tgt, cctx), o)
            for o in list(self.pts.get(self._concrete(("r", q), cctx), ())):
                changed |= self._add(self._concrete(dst, ctx), o)
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


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        b = _dotted(node.value)
        return f"{b}.{node.attr}" if b else node.attr
    return ""
