"""Andersen-style points-to analysis for the taint engine.  (vulnscan: ignore-file)

Inclusion-based, flow-insensitive, context-insensitive, field-sensitive and
allocation-site based: every constructor call, container literal and function
value is an abstract object; variables, object fields, container elements and
function returns are pointer nodes; assignments, field loads/stores, calls
(argument -> parameter, return -> result, receiver -> self) and iteration
generate inclusion constraints that are solved to a fixpoint.

The taint engine uses the result for
* call resolution on the *objects* a receiver may point to (not only its
  static type), including function values stored in variables, passed as
  callbacks or kept in containers;
* heap aliasing: taint stored into a field of an object is visible through
  every alias of that object, in any function, also via globals and
  containers.
It is not context-sensitive: a function's parameter node merges all callers.
"""

from __future__ import annotations

import ast

MAX_ITER = 60


class Obj:
    __slots__ = ("kind", "cls", "site", "qual")

    def __init__(self, kind, cls=None, site=None, qual=None):
        self.kind, self.cls, self.site, self.qual = kind, cls, site, qual

    def __repr__(self):
        return f"Obj({self.kind},{self.cls or self.qual or ''}@{self.site})"


def _param_list(fn):
    a = fn.args
    return [p.arg for p in (a.posonlyargs + a.args + a.kwonlyargs)] + ([a.vararg.arg] if a.vararg else []) + ([a.kwarg.arg] if a.kwarg else [])


class PointsTo:
    def __init__(self, proj):
        self.p = proj
        self.pts: dict = {}                  # node key -> set[Obj]
        self.copies: list = []               # (src, dst)
        self.loads: list = []                # (base, attr, dst)
        self.stores: list = []               # (base, attr, src)
        self.calls: list = []                # (call ast, mod, cls, scope chain, func_node, arg nodes, kw nodes, dst, recv node)
        self.node_of: dict = {}              # id(ast node) -> node key
        self.this_obj: dict = {}             # class qual -> Obj
        self.func_obj: dict = {}             # function qual -> Obj
        self.locals: dict = {}               # scope -> set of local names
        self.tmp = 0
        self._collect()
        self._solve()

    # ---------------------------------------------------------------- nodes
    def _new(self):
        self.tmp += 1
        return ("t", self.tmp)

    def _add(self, node, obj):
        s = self.pts.setdefault(node, set())
        if obj not in s:
            s.add(obj)
            return True
        return False

    def _var(self, chain, name):
        """Resolve a name to the scope that defines it: innermost function with that local, else module."""
        for scope in chain:
            if name in self.locals.get(scope, ()):
                return ("v", scope, name)
        return ("v", chain[-1], name)

    def _fobj(self, qual):
        o = self.func_obj.get(qual)
        if o is None:
            info = self.p.gfuncs[qual]
            o = self.func_obj[qual] = Obj("func", site=(info["path"], info["node"].lineno), qual=qual)
        return o

    def _tobj(self, cq):
        o = self.this_obj.get(cq)
        if o is None:
            c = self.p.classes[cq]
            o = self.this_obj[cq] = Obj("this", cls=cq, site=(c["path"], c["node"].lineno))
        return o

    # -------------------------------------------------------------- collect
    def _collect(self):
        # local-name sets per scope
        for q, info in self.p.gfuncs.items():
            names = set(_param_list(info["node"]))
            for n in self._scope_nodes(info["node"]):
                if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    tg = n.targets if isinstance(n, ast.Assign) else [n.target]
                    for t in tg:
                        names |= {x.id for x in ast.walk(t) if isinstance(x, ast.Name)}
                elif isinstance(n, (ast.For, ast.AsyncFor)):
                    names |= {x.id for x in ast.walk(n.target) if isinstance(x, ast.Name)}
                elif isinstance(n, ast.withitem) and n.optional_vars is not None:
                    names |= {x.id for x in ast.walk(n.optional_vars) if isinstance(x, ast.Name)}
                elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    names.add(n.name)
            self.locals[q] = names
        for mod, file in self.p.files.items():
            self.locals[mod] = set()
        # module scopes
        for mod, file in self.p.files.items():
            self._collect_scope(file["tree"], mod, None, [mod], file["path"])
        # function scopes (with enclosing chain)
        for q, info in self.p.gfuncs.items():
            fn, mod, cls = info["node"], info["mod"], info["cls"]
            chain = [q] + self._enclosing(q) + [mod]
            self._collect_scope(fn, mod, cls, chain, info["path"], q)
        # a function definition is a function value in its enclosing scope; methods are reachable via classes
        for q, info in self.p.gfuncs.items():
            fo = self._fobj(q)
            if info["cls"] is None:
                enc = self._enclosing(q)
                scope = enc[0] if enc else info["mod"]
                self._add(("v", scope, info["name"]), fo)
        # self of every method points to the class's this-object (and its bases', so fields unify across the hierarchy)
        for cq, c in self.p.classes.items():
            for mname, q in c["methods"].items():
                for k in self.p._mro(cq):
                    self._add(("v", q, "self"), self._tobj(k))

    def _enclosing(self, q):
        """Enclosing function quals for nested defs (by source containment)."""
        info = self.p.gfuncs[q]
        out = []
        for oq, oi in self.p.gfuncs.items():
            if oq != q and oi["mod"] == info["mod"] and oi["node"] is not info["node"]:
                n = oi["node"]
                if n.lineno <= info["node"].lineno and getattr(n, "end_lineno", n.lineno) >= getattr(info["node"], "end_lineno", info["node"].lineno) \
                        and any(ch is info["node"] for ch in ast.walk(n)):
                    out.append(oq)
        return sorted(out, key=lambda oq: -self.p.gfuncs[oq]["node"].lineno)

    @staticmethod
    def _scope_nodes(fn):
        stack = list(reversed(getattr(fn, "body", []) or []))
        while stack:
            n = stack.pop()
            yield n
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            stack.extend(reversed(list(ast.iter_child_nodes(n))))

    def _collect_scope(self, fn, mod, cls, chain, path, qual=None):
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
                self.loads.append((it, "<elem>", tmp))
                self._assign(n.target, tmp, mod, cls, chain, path)
            elif isinstance(n, ast.withitem) and n.optional_vars is not None:
                self._assign(n.optional_vars, self._eval(n.context_expr, mod, cls, chain, path), mod, cls, chain, path)
            elif isinstance(n, ast.Return) and n.value is not None and qual:
                self.copies.append((self._eval(n.value, mod, cls, chain, path), ("r", qual)))
            elif isinstance(n, ast.Expr):
                self._eval(n.value, mod, cls, chain, path)
            elif isinstance(n, (ast.If, ast.While)):
                self._eval(n.test, mod, cls, chain, path)

    def _assign(self, target, src, mod, cls, chain, path):
        if isinstance(target, ast.Name):
            self.copies.append((src, self._var(chain, target.id)))
        elif isinstance(target, ast.Attribute):
            base = self._eval(target.value, mod, cls, chain, path)
            self.stores.append((base, target.attr, src))
        elif isinstance(target, ast.Subscript):
            base = self._eval(target.value, mod, cls, chain, path)
            self.stores.append((base, "<elem>", src))
        elif isinstance(target, (ast.Tuple, ast.List)):
            tmp = self._new()
            self.loads.append((src, "<elem>", tmp))
            for e in target.elts:
                self._assign(e, tmp, mod, cls, chain, path)
        elif isinstance(target, ast.Starred):
            self._assign(target.value, src, mod, cls, chain, path)

    def _eval(self, e, mod, cls, chain, path):
        """Evaluate an expression to a pointer node (creating constraints)."""
        key = self._eval_inner(e, mod, cls, chain, path)
        self.node_of[id(e)] = key
        return key

    def _eval_inner(self, e, mod, cls, chain, path):
        if isinstance(e, ast.Name):
            if e.id in ("self", "cls") and chain and chain[0] in self.p.gfuncs:
                return ("v", chain[0], "self")
            return self._var(chain, e.id)
        if isinstance(e, ast.Attribute):
            base = self._eval(e.value, mod, cls, chain, path)
            # module attribute: m.func -> function object
            q = self.p._resolve_function(mod, self.p._dotted_safe(e)) if hasattr(self.p, "_dotted_safe") else None
            tmp = self._new()
            if q:
                self._add(tmp, self._fobj(q))
            self.loads.append((base, e.attr, tmp))
            return tmp
        if isinstance(e, ast.Subscript):
            base = self._eval(e.value, mod, cls, chain, path)
            tmp = self._new()
            self.loads.append((base, "<elem>", tmp))
            if isinstance(e.slice, (ast.Name, ast.Attribute, ast.Call, ast.Subscript)):
                self._eval(e.slice, mod, cls, chain, path)
            return tmp
        if isinstance(e, ast.Call):
            return self._eval_call(e, mod, cls, chain, path)
        if isinstance(e, (ast.List, ast.Tuple, ast.Set)):
            tmp = self._new()
            self._add(tmp, Obj("container", site=(path, getattr(e, "lineno", 0))))
            for el in e.elts:
                self.stores.append((tmp, "<elem>", self._eval(el, mod, cls, chain, path)))
            return tmp
        if isinstance(e, ast.Dict):
            tmp = self._new()
            self._add(tmp, Obj("container", site=(path, getattr(e, "lineno", 0))))
            for v in e.values:
                if v is not None:
                    self.stores.append((tmp, "<elem>", self._eval(v, mod, cls, chain, path)))
            return tmp
        if isinstance(e, (ast.BinOp,)):
            tmp = self._new()
            self.copies.append((self._eval(e.left, mod, cls, chain, path), tmp))
            self.copies.append((self._eval(e.right, mod, cls, chain, path), tmp))
            return tmp
        if isinstance(e, ast.BoolOp):
            tmp = self._new()
            for v in e.values:
                self.copies.append((self._eval(v, mod, cls, chain, path), tmp))
            return tmp
        if isinstance(e, ast.IfExp):
            tmp = self._new()
            self.copies.append((self._eval(e.body, mod, cls, chain, path), tmp))
            self.copies.append((self._eval(e.orelse, mod, cls, chain, path), tmp))
            self._eval(e.test, mod, cls, chain, path)
            return tmp
        if isinstance(e, (ast.Await, ast.Starred)):
            return self._eval(e.value, mod, cls, chain, path)
        if isinstance(e, ast.Lambda):
            return self._new()
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
        func_node = None
        recv = None
        if isinstance(call.func, ast.Name):
            func_node = self._var(chain, call.func.id)
            self.node_of[id(call.func)] = func_node
        elif isinstance(call.func, ast.Attribute):
            recv = self._eval(call.func.value, mod, cls, chain, path)
            func_node = self._eval(call.func, mod, cls, chain, path)
            # container writes: x.append(v) / x.extend(v) / d.update(v) store into the element field
            if call.func.attr in ("append", "add", "insert", "extend", "update", "put", "setdefault"):
                for an in args:
                    self.stores.append((recv, "<elem>", an))
        # static resolution (constructor / plain function / module function)
        static_callees, ctor = self._static(mod, cls, call)
        if ctor:
            self._add(dst, Obj("inst", cls=ctor, site=(path, getattr(call, "lineno", 0))))
            recv = dst  # self of __init__ is the new object
        self.calls.append((call, mod, cls, chain, func_node, args, kws, dst, recv, static_callees, bool(ctor)))
        return dst

    def _static(self, mod, cls, call):
        try:
            from .taint import _Env
            return self.p._callees_static(mod, cls, call, _Env())
        except Exception:  # noqa: BLE001
            return [], None

    # ---------------------------------------------------------------- solve
    def _solve(self):
        for _ in range(MAX_ITER):
            changed = False
            for src, dst in self.copies:
                for o in list(self.pts.get(src, ())):
                    changed |= self._add(dst, o)
            for base, attr, dst in self.loads:
                for o in list(self.pts.get(base, ())):
                    for x in list(self.pts.get(("f", id(o), attr), ())):
                        changed |= self._add(dst, x)
            for base, attr, src in self.stores:
                for o in list(self.pts.get(base, ())):
                    for x in list(self.pts.get(src, ())):
                        changed |= self._add(("f", id(o), attr), x)
            for call, mod, cls, chain, func_node, args, kws, dst, recv, static, is_ctor in self.calls:
                for q in self._resolve_call(call, func_node, recv, static):
                    changed |= self._bind(q, args, kws, dst, recv, call)
            if not changed:
                break

    def _resolve_call(self, call, func_node, recv, static):
        quals = set(static)
        if func_node is not None:
            for o in self.pts.get(func_node, ()):
                if o.kind == "func":
                    quals.add(o.qual)
        if recv is not None and isinstance(call.func, ast.Attribute):
            for o in self.pts.get(recv, ()):
                if o.cls:
                    for q in self.p._lookup_method(o.cls, call.func.attr):
                        quals.add(q)
        return quals

    def _bind(self, q, args, kws, dst, recv, call):
        info = self.p.gfuncs.get(q)
        if not info:
            return False
        fn = info["node"]
        a = fn.args
        pos = [p.arg for p in (a.posonlyargs + a.args)]
        offset = 1 if (pos and pos[0] in ("self", "cls")) else 0
        changed = False
        if offset and recv is not None:
            for o in list(self.pts.get(recv, ())):
                changed |= self._add(("v", q, pos[0]), o)
        for i, an in enumerate(args):
            j = i + offset
            tgt = ("v", q, pos[j]) if j < len(pos) else (("v", q, a.vararg.arg) if a.vararg else None)
            if tgt:
                for o in list(self.pts.get(an, ())):
                    changed |= self._add(tgt, o)
        kwonly = {p.arg for p in a.kwonlyargs}
        for k, an in kws.items():
            tgt = ("v", q, k) if (k in pos or k in kwonly) else (("v", q, a.kwarg.arg) if a.kwarg else None)
            if tgt:
                for o in list(self.pts.get(an, ())):
                    changed |= self._add(tgt, o)
        for o in list(self.pts.get(("r", q), ())):
            changed |= self._add(dst, o)
        return changed

    # ------------------------------------------------------------------ API
    def objs(self, node) -> set:
        key = self.node_of.get(id(node))
        return set(self.pts.get(key, ())) if key is not None else set()

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
