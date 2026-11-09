"""Flow-sensitive refinement of the Python taint engine.

The main engine (taint.Project) computes, per function, the set of names that are *ever* tainted: it is
flow-insensitive, which is fast and sound but imprecise. This module interprets a function's statements in
order and records, for every call / return / attribute-sink node, the abstract state that holds *at that
point*:

* **strong updates** — ``bar = param; bar = "safe"`` leaves ``bar`` clean;
* **constant folding and dead branches** — ``num = 86; if 7 * 42 - num > 200: bar = "ok" else: bar = param``
  only takes the first branch, and ``x if <constant> else y`` picks one side;
* **constant-key field sensitivity** for dicts — ``m["a"] = param; bar = m["b"]`` is clean;
* **paths that end** (``return`` / ``raise`` / ``continue`` / ``break``) do not flow into what follows.

Expressions are still evaluated by the main engine (sources, sanitizers, summaries, instance fields …), with
an environment whose tainted names, constants and dict maps come from this state. The refinement therefore
only ever *removes* taint the main engine could not rule out; code it cannot place falls back to the main
engine's answer.
"""

from __future__ import annotations

import ast
import copy
import operator

_MISSING = object()
MAX_LOOP_ITER = 4

_BINOPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.FloorDiv: operator.floordiv,
           ast.Mod: operator.mod, ast.Div: operator.truediv, ast.BitAnd: operator.and_, ast.BitOr: operator.or_,
           ast.BitXor: operator.xor, ast.LShift: operator.lshift, ast.RShift: operator.rshift}
_CMPOPS = {ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt, ast.LtE: operator.le, ast.Gt: operator.gt,
           ast.GtE: operator.ge, ast.Is: operator.is_, ast.IsNot: operator.is_not,
           ast.In: lambda a, b: a in b, ast.NotIn: lambda a, b: a not in b}
_CONST_TYPES = (int, float, str, bool, type(None), bytes)


def fold(node: ast.AST, consts: dict):
    """Evaluate a side-effect-free expression over literals and known constants. Returns _MISSING if unknown."""
    try:
        return _fold(node, consts)
    except Exception:  # noqa: BLE001 - any evaluation problem just means "unknown"
        return _MISSING


def _fold(node, consts):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return consts.get(node.id, _MISSING)
    if isinstance(node, ast.UnaryOp):
        v = _fold(node.operand, consts)
        if v is _MISSING:
            return _MISSING
        if isinstance(node.op, ast.Not):
            return not v
        if isinstance(node.op, ast.USub):
            return -v
        if isinstance(node.op, ast.UAdd):
            return +v
        if isinstance(node.op, ast.Invert):
            return ~v
        return _MISSING
    if isinstance(node, ast.BinOp) and type(node.op) in _BINOPS:
        a, b = _fold(node.left, consts), _fold(node.right, consts)
        if a is _MISSING or b is _MISSING:
            return _MISSING
        if isinstance(node.op, (ast.Mult, ast.LShift)) and _too_big(a, b):
            return _MISSING
        r = _BINOPS[type(node.op)](a, b)
        return r if isinstance(r, _CONST_TYPES) and not (isinstance(r, (str, bytes)) and len(r) > 10_000) else _MISSING
    if isinstance(node, ast.Compare):
        left = _fold(node.left, consts)
        if left is _MISSING:
            return _MISSING
        for op, comp in zip(node.ops, node.comparators):
            right = _fold(comp, consts)
            if right is _MISSING or type(op) not in _CMPOPS:
                return _MISSING
            if not _CMPOPS[type(op)](left, right):
                return False
            left = right
        return True
    if isinstance(node, ast.BoolOp):
        vals = [_fold(v, consts) for v in node.values]
        if isinstance(node.op, ast.And):
            for v in vals:
                if v is _MISSING:
                    return _MISSING
                if not v:
                    return v
            return vals[-1]
        for v in vals:
            if v is _MISSING:
                return _MISSING
            if v:
                return v
        return vals[-1]
    if isinstance(node, ast.IfExp):
        t = _fold(node.test, consts)
        if t is _MISSING:
            return _MISSING
        return _fold(node.body if t else node.orelse, consts)
    return _MISSING


def _too_big(a, b) -> bool:
    try:
        return (isinstance(a, (str, bytes)) and isinstance(b, int) and len(a) * b > 10_000) or \
               (isinstance(b, (str, bytes)) and isinstance(a, int) and len(b) * a > 10_000) or \
               (isinstance(a, int) and isinstance(b, int) and abs(a) > 10 ** 9 and abs(b) > 10 ** 9)
    except TypeError:
        return True


class State:
    """Abstract state at one program point."""

    __slots__ = ("tainted", "consts", "dk")

    def __init__(self, tainted=None, consts=None, dk=None):
        self.tainted: dict = tainted if tainted is not None else {}   # name -> origin
        self.consts: dict = consts if consts is not None else {}      # name -> python constant
        self.dk: dict = dk if dk is not None else {}                  # name -> ({const key: origin|None}, other origin|None)

    def copy(self) -> "State":
        return State(dict(self.tainted), dict(self.consts), {k: (dict(m), o) for k, (m, o) in self.dk.items()})

    def same(self, other: "State") -> bool:
        return (set(self.tainted) == set(other.tainted) and self.consts == other.consts
                and {k: (set(k2 for k2, v in m.items() if v), bool(o)) for k, (m, o) in self.dk.items()}
                == {k: (set(k2 for k2, v in m.items() if v), bool(o)) for k, (m, o) in other.dk.items()})


def join(a: State | None, b: State | None) -> State | None:
    if a is None:
        return b.copy() if b is not None else None
    if b is None:
        return a.copy()
    tainted = dict(b.tainted)
    tainted.update(a.tainted)
    consts = {k: v for k, v in a.consts.items() if k in b.consts and b.consts[k] == v and type(b.consts[k]) is type(v)}
    dk = {}
    for name in set(a.dk) & set(b.dk):
        (ma, oa), (mb, ob) = a.dk[name], b.dk[name]
        m = {}
        for key in set(ma) | set(mb):
            va = ma.get(key, oa)
            vb = mb.get(key, ob)
            m[key] = va or vb
        dk[name] = (m, oa or ob)
    return State(tainted, consts, dk)


class _Exit(Exception):
    pass


class FlowInterpreter:
    """Runs one function body in order and records the state before each node of interest."""

    def __init__(self, proj, mod, cls, fn, base_env):
        self.proj, self.mod, self.cls, self.fn, self.base = proj, mod, cls, fn, base_env
        self.snap: dict = {}          # id(node) -> State (joined over every visit)
        self.dead: set = set()        # id(stmt) of statements proven unreachable
        self.loop_exits: list = []    # states flowing out of `break` in the innermost loop
        self.loop_conts: list = []

    # ---------------------------------------------------------------- driver
    def run(self) -> "FlowInterpreter":
        body = self.fn.body if isinstance(self.fn, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)) else []
        assigned = _assigned(body)
        # names the function receives from outside (parameters, closure/global taint known to the main engine)
        init = State({n: o for n, o in self.base.tainted.items() if n not in assigned or _is_param(self.fn, n)})
        self.block(body, init)
        return self

    def env_for(self, st: State):
        env = copy.copy(self.base)
        env.tainted = st.tainted
        env.consts = st.consts
        env.dk = st.dk
        return env

    def taint(self, expr, st: State):
        return self.proj._taint(self.mod, self.cls, expr, self.env_for(st))

    # ---------------------------------------------------------------- recording
    def record(self, stmt, st: State):
        for n in _nodes_of(stmt):
            prev = self.snap.get(id(n))
            self.snap[id(n)] = st.copy() if prev is None else join(prev, st)

    def mark_dead(self, stmts):
        for s in stmts:
            self.dead.add(id(s))
            for n in ast.walk(s):
                if isinstance(n, ast.stmt):
                    self.dead.add(id(n))

    # ---------------------------------------------------------------- statements
    def block(self, stmts, st: State | None) -> State | None:
        for i, s in enumerate(stmts):
            if st is None:
                self.mark_dead(stmts[i:])
                return None
            st = self.stmt(s, st)
        return st

    def stmt(self, s, st: State) -> State | None:
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self.record(s, st)
            return st
        if isinstance(s, (ast.Return, ast.Raise)):
            self.record(s, st)
            return None
        if isinstance(s, ast.Break):
            self.loop_exits.append(st.copy())
            return None
        if isinstance(s, ast.Continue):
            self.loop_conts.append(st.copy())
            return None
        if isinstance(s, ast.If):
            return self.if_(s, st)
        if isinstance(s, (ast.For, ast.AsyncFor, ast.While)):
            return self.loop(s, st)
        if isinstance(s, ast.Try) or s.__class__.__name__ == "TryStar":
            return self.try_(s, st)
        if isinstance(s, (ast.With, ast.AsyncWith)):
            self.record_header(s, st)
            for item in s.items:
                if item.optional_vars is not None:
                    st = self.assign(item.optional_vars, item.context_expr, st)
            return self.block(s.body, st)
        if s.__class__.__name__ == "Match":
            self.record_header(s, st)
            out = None
            for case in s.cases:
                out = join(out, self.block(case.body, st.copy()))
            return join(out, st)               # no case may match
        self.record(s, st)
        if isinstance(s, ast.Assign):
            for tgt in s.targets:
                st = self.assign(tgt, s.value, st)
            return st
        if isinstance(s, ast.AnnAssign):
            return self.assign(s.target, s.value, st) if s.value is not None else st
        if isinstance(s, ast.AugAssign):
            return self.aug(s, st)
        if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call):
            return self.container_write(s.value, st)
        if isinstance(s, ast.Delete):
            for t in s.targets:
                if isinstance(t, ast.Name):
                    st.tainted.pop(t.id, None)
                    st.consts.pop(t.id, None)
                    st.dk.pop(t.id, None)
            return st
        return st

    def record_header(self, s, st):
        """Record the state for nodes in a compound statement's header (test / iter / items), not its body."""
        heads = []
        if isinstance(s, (ast.If, ast.While)):
            heads = [s.test]
        elif isinstance(s, (ast.For, ast.AsyncFor)):
            heads = [s.iter]
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            heads = [i.context_expr for i in s.items]
        elif s.__class__.__name__ == "Match":
            heads = [s.subject]
        for h in heads:
            self.record(h, st)

    def if_(self, s: ast.If, st: State) -> State | None:
        self.record_header(s, st)
        t = fold(s.test, st.consts)
        if t is not _MISSING:
            if t:
                self.mark_dead(s.orelse)
                return self.block(s.body, st)
            self.mark_dead(s.body)
            return self.block(s.orelse, st)
        a = self.block(s.body, st.copy())
        b = self.block(s.orelse, st.copy())
        return join(a, b)

    def loop(self, s, st: State) -> State | None:
        self.record_header(s, st)
        is_while = isinstance(s, ast.While)
        if is_while:
            t = fold(s.test, st.consts)
            if t is not _MISSING and not t:
                self.mark_dead(s.body)
                return self.block(s.orelse, st)
        saved = (self.loop_exits, self.loop_conts)
        self.loop_exits, self.loop_conts = [], []
        head = st.copy()
        out = st.copy()                               # zero iterations
        for _ in range(MAX_LOOP_ITER):
            body_in = head.copy()
            if not is_while:
                body_in = self.assign(s.target, s.iter, body_in)
            body_out = self.block(s.body, body_in)
            for c in self.loop_conts:
                body_out = join(body_out, c)
            self.loop_conts = []
            new_head = join(head, body_out)
            out = join(out, body_out)
            if new_head is None or new_head.same(head):
                break
            head = new_head
            self.record_header(s, head)
        breaks = self.loop_exits
        self.loop_exits, self.loop_conts = saved
        if is_while and fold(s.test, st.consts) is not _MISSING and fold(s.test, st.consts):
            out = None                                 # `while True:` only leaves through break
        out = self.block(s.orelse, out) if out is not None else None
        for b in breaks:
            out = join(out, b)
        return out

    def try_(self, s, st: State) -> State | None:
        after_body = self.block(s.body, st.copy())
        after_else = self.block(s.orelse, after_body) if after_body is not None else None
        # a handler can start from any point of the body: approximate with the join of entry and exit states
        h_in = join(st, after_body)
        out = after_else
        for h in s.handlers:
            hs = h_in.copy()
            if h.name:
                hs.tainted.pop(h.name, None)
            out = join(out, self.block(h.body, hs))
        if s.finalbody:
            fin_in = join(out, h_in)
            fin_out = self.block(s.finalbody, fin_in)
            return fin_out if out is not None else None
        return out

    # ---------------------------------------------------------------- assignments
    def assign(self, tgt, value, st: State) -> State:
        if isinstance(tgt, ast.Name):
            o = self.taint(value, st)
            st = st.copy()
            if o:
                st.tainted[tgt.id] = o
            else:
                st.tainted.pop(tgt.id, None)
            c = fold(value, st.consts)
            if c is not _MISSING and isinstance(c, _CONST_TYPES):
                st.consts[tgt.id] = c
            else:
                st.consts.pop(tgt.id, None)
            if isinstance(value, ast.Dict) and all(isinstance(k, ast.Constant) for k in value.keys):
                st.dk[tgt.id] = ({k.value: self.taint(v, st) for k, v in zip(value.keys, value.values)}, None)
            elif isinstance(value, ast.Name) and value.id in st.dk:
                m, other = st.dk[value.id]
                st.dk[tgt.id] = (dict(m), other)
            elif isinstance(value, ast.Call) and _is_empty_dict_call(value):
                st.dk[tgt.id] = ({}, None)
            else:
                st.dk.pop(tgt.id, None)
            return st
        if isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name):
            name = tgt.value.id
            o = self.taint(value, st)
            st = st.copy()
            key = fold(tgt.slice, st.consts)
            if name in st.dk:
                m, other = st.dk[name]
                if key is not _MISSING and _hashable(key):
                    m[key] = o                       # strong update of one known key
                elif o:
                    st.dk[name] = (m, o)             # unknown key: may be any key
                    m, other = st.dk[name]
                if any(m.values()) or other:
                    st.tainted[name] = next((v for v in list(m.values()) + [other] if v), None)
                else:
                    st.tainted.pop(name, None)
            elif o and name not in st.tainted:
                st.tainted[name] = o                 # weak update of an untracked container
            st.consts.pop(name, None)
            return st
        if isinstance(tgt, (ast.Tuple, ast.List)):
            if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(tgt.elts) \
                    and not any(isinstance(e, ast.Starred) for e in tgt.elts + value.elts):
                pairs = list(zip(tgt.elts, value.elts))
                vals = [(t, self.taint(v, st), fold(v, st.consts)) for t, v in pairs]
                st = st.copy()
                for t, o, c in vals:
                    if isinstance(t, ast.Name):
                        _set(st, t.id, o, c)
                    else:
                        st = self.assign(t, ast.Constant(value=None) if not o else value, st)
                return st
            o = self.taint(value, st)
            st = st.copy()
            for n in ast.walk(tgt):
                if isinstance(n, ast.Name):
                    _set(st, n.id, o, _MISSING)
            return st
        if isinstance(tgt, ast.Starred):
            return self.assign(tgt.value, value, st)
        return st                                     # attribute targets: handled by the main engine

    def aug(self, s: ast.AugAssign, st: State) -> State:
        if isinstance(s.target, ast.Name):
            name = s.target.id
            o = st.tainted.get(name) or self.taint(s.value, st)
            c = fold(ast.BinOp(left=ast.Name(id=name, ctx=ast.Load()), op=s.op, right=s.value), st.consts)
            st = st.copy()
            _set(st, name, o, c)
            st.dk.pop(name, None)
            return st
        if isinstance(s.target, ast.Subscript):
            return self.assign(s.target, ast.BinOp(left=s.target, op=s.op, right=s.value), st)
        return st

    def container_write(self, call: ast.Call, st: State) -> State:
        f = call.func
        if not (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)):
            return st
        name = f.value.id
        args = list(call.args) + [k.value for k in call.keywords]
        if f.attr in ("update",) and name in st.dk and args and isinstance(args[0], ast.Dict) \
                and all(isinstance(k, ast.Constant) for k in args[0].keys):
            st = st.copy()
            m, other = st.dk[name]
            for k, v in zip(args[0].keys, args[0].values):
                m[k.value] = self.taint(v, st)
            if any(m.values()) or other:
                st.tainted[name] = next(v for v in list(m.values()) + [other] if v)
            return st
        if f.attr in ("append", "extend", "insert", "add", "update", "appendleft", "setdefault", "put", "push", "set",
                      "setProperty", "__setitem__",
                      "write", "add_all", "addAll"):
            o = None
            for a in args:
                o = o or self.taint(a, st)
            if o:
                st = st.copy()
                st.tainted.setdefault(name, o)
                st.consts.pop(name, None)
                if name in st.dk:
                    m, other = st.dk[name]
                    st.dk[name] = (m, other or o)
            return st
        if f.attr == "clear":
            st = st.copy()
            st.tainted.pop(name, None)
            if name in st.dk:
                st.dk[name] = ({}, None)
            return st
        return st


def _set(st: State, name, origin, const):
    if origin:
        st.tainted[name] = origin
    else:
        st.tainted.pop(name, None)
    if const is not _MISSING and isinstance(const, _CONST_TYPES):
        st.consts[name] = const
    else:
        st.consts.pop(name, None)
    st.dk.pop(name, None)


def _hashable(v) -> bool:
    try:
        hash(v)
        return True
    except TypeError:
        return False


def _is_empty_dict_call(call: ast.Call) -> bool:
    return isinstance(call.func, ast.Name) and call.func.id == "dict" and not call.args and not call.keywords


def _is_param(fn, name) -> bool:
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    a = fn.args
    return any(p.arg == name for p in a.posonlyargs + a.args + a.kwonlyargs) or \
        any(p is not None and p.arg == name for p in (a.vararg, a.kwarg))


def _assigned(stmts) -> set:
    out = set()
    for s in stmts:
        for n in ast.walk(s):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)) and n not in stmts:
                continue
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                out.add(n.id)
            elif isinstance(n, ast.ExceptHandler) and n.name:
                out.add(n.name)
    return out


def _nodes_of(stmt):
    """Every node of a simple statement (or header expression), not descending into nested scopes."""
    stack = [stmt]
    while stack:
        n = stack.pop()
        yield n
        for ch in ast.iter_child_nodes(n):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(ch, ast.stmt):
                continue                              # nested statements are recorded when they execute
            stack.append(ch)
