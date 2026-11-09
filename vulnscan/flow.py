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
import math
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
_STR_METHODS = {   # side-effect-free string methods (Python and Java/C#/JS spellings) usable in constant folding
    "charAt": lambda s, i: s[i], "substring": lambda s, a, b=None: s[a:b], "length": len, "len": len,
    "toUpperCase": str.upper, "toLowerCase": str.lower, "upper": str.upper, "lower": str.lower, "trim": str.strip,
    "strip": str.strip, "equals": lambda s, o: s == o, "contains": lambda s, o: o in s, "startsWith": str.startswith,
    "endsWith": str.endswith, "startswith": str.startswith, "endswith": str.endswith, "indexOf": str.find,
    "find": str.find, "isEmpty": lambda s: not s, "equalsIgnoreCase": lambda s, o: s.lower() == str(o).lower(),
}


def _same_eq_semantics(mode, a, b) -> bool:
    """Whether Python's comparison of two folded values means what the source language's comparison means.
    "loose": JS/PHP `==`, which coerce across types ("1" == 1); "ref": Java `==`, which compares string identity."""
    def family(v):
        return "num" if isinstance(v, (int, float)) and not isinstance(v, bool) else type(v).__name__
    if mode == "loose":
        return family(a) == family(b)
    if mode == "strict":                      # PHP `===`: 1 === 1.0 is false
        return type(a) is type(b)
    if mode == "ref":
        return not isinstance(a, str) and not isinstance(b, str)
    return True


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
        if getattr(node, "numeric_only", False) and not all(isinstance(v, (int, float)) for v in (a, b)):
            return _MISSING                       # JS `"3" * 2` coerces to 6, Python repeats the string
        if isinstance(node.op, (ast.Mult, ast.LShift)) and _too_big(a, b):
            return _MISSING
        mode = getattr(node, "int_div", None)
        if mode and isinstance(node.op, (ast.Div, ast.Mod)):
            if not all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in (a, b)) or b == 0:
                return _MISSING
            if isinstance(a, int) and isinstance(b, int):
                if mode == "floor":
                    return a // b if isinstance(node.op, ast.Div) else a % b
                q = abs(a) // abs(b) * (1 if (a >= 0) == (b >= 0) else -1)     # truncates toward zero
                return q if isinstance(node.op, ast.Div) else a - q * b
            if isinstance(node.op, ast.Div):
                return a / b                      # a floating-point operand: true division
            return math.fmod(a, b) if mode == "trunc" else a % b
        r = _BINOPS[type(node.op)](a, b)
        return r if isinstance(r, _CONST_TYPES) and not (isinstance(r, (str, bytes)) and len(r) > 10_000) else _MISSING
    if isinstance(node, ast.Compare):
        left = _fold(node.left, consts)
        if left is _MISSING:
            return _MISSING
        eq_mode = getattr(node, "eq_mode", None)
        for op, comp in zip(node.ops, node.comparators):
            right = _fold(comp, consts)
            if right is _MISSING or type(op) not in _CMPOPS:
                return _MISSING
            if eq_mode and not _same_eq_semantics(eq_mode, left, right):
                return _MISSING
            if not _CMPOPS[type(op)](left, right):
                return False
            left = right
        return True
    if isinstance(node, ast.BoolOp):
        vals = [_fold(v, consts) for v in node.values]
        if getattr(node, "nullish", False):       # `a ?? b` / Kotlin `a ?: b`: only null falls through, not 0 or ""
            for v in vals:
                if v is _MISSING:
                    return _MISSING
                if v is not None:
                    return v
            return vals[-1]
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
    if isinstance(node, ast.Subscript):
        base = _fold(node.value, consts)
        if isinstance(base, (str, bytes, tuple)):
            if isinstance(node.slice, ast.Slice):
                lo = _fold(node.slice.lower, consts) if node.slice.lower else None
                hi = _fold(node.slice.upper, consts) if node.slice.upper else None
                st = _fold(node.slice.step, consts) if node.slice.step else None
                if _MISSING in (lo, hi, st):
                    return _MISSING
                return base[lo:hi:st]
            idx = _fold(node.slice, consts)
            if isinstance(idx, int):
                return base[idx]
        return _MISSING
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in _STR_METHODS \
            and not node.keywords:
        recv = _fold(node.func.value, consts)
        if isinstance(recv, str):
            args = [_fold(a, consts) for a in node.args]
            if _MISSING in args:
                return _MISSING
            args = [int(a) if isinstance(a, float) and a.is_integer() else a for a in args]
            return _STR_METHODS[node.func.attr](recv, *args)
        return _MISSING
    if isinstance(node, (ast.Tuple,)) :
        vals = tuple(_fold(e, consts) for e in node.elts)
        return _MISSING if _MISSING in vals else vals
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

    __slots__ = ("tainted", "consts", "dk", "lk")

    def __init__(self, tainted=None, consts=None, dk=None, lk=None):
        self.tainted: dict = tainted if tainted is not None else {}   # name -> origin
        self.consts: dict = consts if consts is not None else {}      # name -> python constant
        self.dk: dict = dk if dk is not None else {}                  # name -> ({const key: origin|None}, other origin|None)
        self.lk: dict = lk if lk is not None else {}                  # name -> [origin|None, ...] (list, known length)

    def copy(self) -> "State":
        return State(dict(self.tainted), dict(self.consts), {k: (dict(m), o) for k, (m, o) in self.dk.items()},
                     {k: list(v) for k, v in self.lk.items()})

    def same(self, other: "State") -> bool:
        return (set(self.tainted) == set(other.tainted) and self.consts == other.consts
                and {k: tuple(bool(x) for x in v) for k, v in self.lk.items()} ==
                {k: tuple(bool(x) for x in v) for k, v in other.lk.items()}
                and {k: (set(k2 for k2, v in m.items() if v), bool(o)) for k, (m, o) in self.dk.items()}
                == {k: (set(k2 for k2, v in m.items() if v), bool(o)) for k, (m, o) in other.dk.items()})


def join(a: State | None, b: State | None) -> State | None:
    if a is None:
        return b.copy() if b is not None else None
    if b is None:
        return a.copy()
    tainted = dict(b.tainted)
    for k, oa in a.tainted.items():
        ob = b.tainted.get(k)
        tainted[k] = _merge_origin(oa, ob) if ob else oa
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
    lk = {}
    for name in set(a.lk) & set(b.lk):
        la, lb = a.lk[name], b.lk[name]
        if len(la) == len(lb):
            lk[name] = [x or y for x, y in zip(la, lb)]
    return State(tainted, consts, dk, lk)


def _merge_origin(a, b):
    """Two origins reaching one name: keep a's trail but only what BOTH were escaped for."""
    sa = a[3] if len(a) > 3 else frozenset()
    sb = b[3] if len(b) > 3 else frozenset()
    pa = (frozenset({a[1]}) | frozenset(a[4] if len(a) > 4 else ())) if a[0] == "param" else frozenset()
    pb = (frozenset({b[1]}) | frozenset(b[4] if len(b) > 4 else ())) if b[0] == "param" else frozenset()
    if sa == sb and pb <= pa:
        return a
    extra = (pa | pb) - {a[1]} if a[0] == "param" else frozenset(a[4] if len(a) > 4 else ())
    return (a[0], a[1], a[2] if len(a) > 2 else (), sa & sb, frozenset(extra))


class _Exit(Exception):
    pass


class FlowInterpreter:
    """Runs one function body in order and records the state before each node of interest."""

    def __init__(self, proj, mod, cls, fn, base_env, path: str = ""):
        self.proj, self.mod, self.cls, self.fn, self.base, self.path = proj, mod, cls, fn, base_env, path
        self.snap: dict = {}          # id(node) -> State (joined over every visit)
        self.dead: set = set()        # id(stmt) of statements proven unreachable
        self.loop_exits: list = []    # states flowing out of `break` in the innermost loop
        self.loop_conts: list = []
        self.weak = 0                 # inside a try body with handlers/finally: assignments never drop taint
        self.labeled_exits: list = []  # states leaving through `break label;` / `continue label;`
        # per-function facts and per-statement node lists are cached on the project (they live as long as the trees)
        self.cache = proj.__dict__.setdefault("_flow_struct", {})
        key = ("fn", id(fn))
        hit = self.cache.get(key)
        if hit is None or hit[0] is not fn:
            body = fn.body if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)) else []
            hit = (fn, _alias_groups(body), _rebound_elsewhere(fn), _assigned(body), _escaping(fn), _containers(body))
            self.cache[key] = hit
        _, self.alias, self.volatile, self.assigned_in_body, self.escaped, self.containers = hit

    # ---------------------------------------------------------------- driver
    def run(self) -> "FlowInterpreter":
        body = self.fn.body if isinstance(self.fn, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)) else []
        assigned = self.assigned_in_body
        # names the function receives from outside (parameters, closure/global taint known to the main engine)
        init = State({n: o for n, o in self.base.tainted.items() if n not in assigned or _is_param(self.fn, n)})
        self.block(body, init)
        return self

    def env_for(self, st: State):
        env = copy.copy(self.base)
        env.tainted = st.tainted
        env.consts = st.consts
        env.dk = dict(st.dk)
        for name, elems in st.lk.items():         # a list of known length reads like a dict with int keys
            env.dk[name] = ({i: o for i, o in enumerate(elems)} | {i - len(elems): o for i, o in enumerate(elems)}, None)
        return env

    def taint(self, expr, st: State):
        return self.proj._taint(self.mod, self.cls, expr, self.env_for(st))

    # ---------------------------------------------------------------- recording
    def record(self, stmt, st: State):
        """Remember the state before the nodes the engine asks about (calls, returns, assignments). One snapshot
        is shared by all of them: states are never mutated after being recorded (every update copies)."""
        key = ("rec", id(stmt))
        hit = self.cache.get(key)
        if hit is None or hit[0] is not stmt:
            hit = (stmt, [n for n in _nodes_of(stmt) if isinstance(n, _QUERIED)])
            self.cache[key] = hit
        targets = hit[1]
        if not targets:
            return
        shared = None
        for n in targets:
            prev = self.snap.get(id(n))
            if prev is None:
                if shared is None:
                    shared = st.copy()
                self.snap[id(n)] = shared
            elif prev is not st:
                self.snap[id(n)] = join(prev, st)

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
        if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call) and isinstance(s.value.func, ast.Name) \
                and s.value.func.id == "__labeled_exit__":
            self.labeled_exits.append(st.copy())     # joined after every enclosing loop (an over-approximation)
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
            suppressing = any(isinstance(i.context_expr, ast.Call) and _callee_name(i.context_expr).endswith("suppress")
                              for i in s.items)
            self.weak += suppressing                  # contextlib.suppress(...): any statement may be the last
            try:
                out = self.block(s.body, st)
            finally:
                self.weak -= suppressing
            return join(out, st) if suppressing else out
        if s.__class__.__name__ == "Match":
            self.record_header(s, st)
            subj = fold(s.subject, st.consts)
            if subj is not _MISSING:
                for i, case in enumerate(s.cases):
                    hit = _case_matches(case, subj, st.consts)
                    if hit is None:
                        break                          # undecidable pattern: fall back to every case
                    if hit:
                        self.mark_dead([c2 for c in s.cases[:i] + s.cases[i + 1:] for c2 in c.body])
                        return self.block(case.body, st)
                else:
                    self.mark_dead([c2 for c in s.cases for c2 in c.body])
                    return st                          # no case matches
            out = None
            for case in s.cases:
                out = join(out, self.block(case.body, st.copy()))
            return join(out, st)               # no case may match
        self.record(s, st)
        if isinstance(s, ast.Assign):
            for tgt in s.targets:
                st = self.assign(tgt, s.value, st)
            return self.side_effects(s.value, st)
        if isinstance(s, ast.AnnAssign):
            return self.side_effects(s.value, self.assign(s.target, s.value, st)) if s.value is not None else st
        if isinstance(s, ast.AugAssign):
            return self.side_effects(s.value, self.aug(s, st))
        if isinstance(s, ast.Expr):
            return self.side_effects(s.value, st)
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
        converged = False
        for it in range(MAX_LOOP_ITER + 1):
            if it == MAX_LOOP_ITER:
                # not converged: widen every name the loop assigns to what the flow-insensitive engine knows,
                # forget their constants and layouts, and run the body once more so its sinks see that state
                head = self.widen(head, self._assigned_cached(s) | (_assigned([s.target]) if not is_while else set()))
            body_in = head.copy()
            if not is_while:
                body_in = self.loop_target(s.target, s.iter, body_in)
            body_out = self.block(s.body, body_in)
            for c in self.loop_conts:
                body_out = join(body_out, c)
            self.loop_conts = []
            new_head = join(head, body_out)
            out = join(out, body_out)
            if new_head is None or new_head.same(head):
                converged = True
                break
            head = new_head
            self.record_header(s, head)
        if not converged:
            out = self.widen(out, self._assigned_cached(s)) if out is not None else None
        breaks = self.loop_exits
        self.loop_exits, self.loop_conts = saved
        if is_while and isinstance(s.test, ast.Constant) and s.test.value:
            out = None                                 # literal `while True:` only leaves through break
        out = self.block(s.orelse, out) if out is not None else None
        for b in breaks:
            out = join(out, b)
        for b in self.labeled_exits:
            out = join(out, b)
        return out

    def try_(self, s, st: State) -> State | None:
        guarded = bool(s.handlers or s.finalbody)
        self.weak += guarded                      # an exception can leave the body after ANY statement
        try:
            after_body = self.block(s.body, st.copy())
        finally:
            self.weak -= guarded
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

    def _assigned_cached(self, loop) -> set:
        key = ("asg", id(loop))
        hit = self.cache.get(key)
        if hit is None or hit[0] is not loop:
            hit = (loop, _assigned(loop.body))
            self.cache[key] = hit
        return hit[1]

    def loop_target(self, tgt, it, st: State) -> State:
        """Bind a for-loop target: it carries the iterable's taint but is never one constant (`for c in "rw"`)."""
        o = self.taint(it, st)
        st = st.copy()
        for n in ast.walk(tgt):
            if isinstance(n, ast.Name):
                _set(st, n.id, self.stepped(o, n.id, it) if o else None, _MISSING)
        return st

    def widen(self, st: State, names) -> State:
        st = st.copy()
        for n in names:
            o = self.base.tainted.get(n)
            if o and n not in st.tainted:
                st.tainted[n] = o
            st.consts.pop(n, None)
            st.dk.pop(n, None)
            st.lk.pop(n, None)
        return st

    def may_alias(self, name) -> set:
        return self.alias.get(name, {name})

    def taint_group(self, st: State, name, o) -> None:
        """A write through `name` is visible through every name that may share its container."""
        for n in self.may_alias(name):
            if o and n not in st.tainted:
                st.tainted[n] = o
            if n != name:
                st.dk.pop(n, None)
                st.lk.pop(n, None)

    # ---------------------------------------------------------------- assignments
    def stepped(self, o, name, value):
        """Record the assignment in the origin's trail, so a finding shows the path source -> … -> sink."""
        if not o:
            return o
        line = getattr(value, "lineno", 0) or 0
        trail = o[2] if len(o) > 2 else ()
        if trail and trail[-1].get("line") == line and trail[-1].get("file") == self.path:
            return o
        text = f"{name} = {o[1]}" if not trail and o[0] in ("source", "retsource") else f"{name} = …"
        return (o[0], o[1], tuple(trail) + ({"file": self.path, "line": line, "text": text},)) + tuple(o[3:])

    def assign(self, tgt, value, st: State) -> State:
        if isinstance(tgt, ast.Name):
            name = tgt.id
            o = self.stepped(self.taint(value, st), name, value)
            st = st.copy()
            if o:
                st.tainted[name] = o
            elif not self.weak:
                st.tainted.pop(name, None)            # (inside a guarded try body the old taint may survive)
            trackable = name not in self.volatile and name not in self.escaped and len(self.may_alias(name)) == 1
            c = fold(value, st.consts) if name not in self.volatile else _MISSING
            if c is not _MISSING and isinstance(c, _CONST_TYPES) and not (self.weak and name in st.tainted):
                st.consts[name] = c
            else:
                st.consts.pop(name, None)
            st.dk.pop(name, None)
            st.lk.pop(name, None)
            if trackable:
                if isinstance(value, ast.Dict) and all(isinstance(k, ast.Constant) for k in value.keys):
                    st.dk[name] = ({k.value: self.taint(v, st) for k, v in zip(value.keys, value.values)}, None)
                elif isinstance(value, ast.Call) and _is_empty_dict_call(value):
                    st.dk[name] = ({}, None)
                elif isinstance(value, ast.List) and not any(isinstance(e, ast.Starred) for e in value.elts):
                    st.lk[name] = [self.taint(e, st) for e in value.elts]
                elif isinstance(value, ast.Call) and isinstance(value.func, (ast.Name, ast.Attribute)) and not value.args \
                        and (value.func.id if isinstance(value.func, ast.Name) else value.func.attr) in _NEW_LIST:
                    st.lk[name] = []
            return st
        if isinstance(tgt, ast.Subscript) and not isinstance(tgt.value, ast.Name):
            # rows[0][1] = x / cfg["db"]["q"] = x / self.items[k] = x: the root container now holds x
            root = tgt.value
            while isinstance(root, (ast.Subscript, ast.Attribute)):
                root = root.value
            o = self.taint(value, st)
            st = st.copy()
            if isinstance(root, ast.Name):
                st.lk.pop(root.id, None)
                st.dk.pop(root.id, None)
                self.taint_group(st, root.id, o)
            return st
        if isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name):
            name = tgt.value.id
            o = self.taint(value, st)
            st = st.copy()
            if self.weak and not o:
                return st                            # inside a guarded try: an exception may skip this overwrite
            key = fold(tgt.slice, st.consts)
            if isinstance(key, float) and key.is_integer():
                key = int(key)
            if name in st.lk:
                elems = st.lk[name]
                if isinstance(key, int) and not isinstance(key, bool) and -len(elems) <= key < len(elems):
                    elems[key] = o                   # strong update of one known slot
                else:
                    st.lk.pop(name)                  # slice / unknown index: the layout is unknown now
                    self.taint_group(st, name, o)
            elif name in st.dk:
                m, other = st.dk[name]
                if key is not _MISSING and _hashable(key):
                    m[key] = o                       # strong update of one known key
                elif o:
                    st.dk[name] = (m, o)             # unknown key: may be any key
                    m, other = st.dk[name]
            else:
                self.taint_group(st, name, o)        # weak update of an untracked container
            self._retaint(st, name)
            st.consts.pop(name, None)
            return st
        if isinstance(tgt, (ast.Tuple, ast.List)):
            if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(tgt.elts) \
                    and not any(isinstance(e, ast.Starred) for e in tgt.elts + value.elts):
                for t, v in zip(tgt.elts, value.elts):
                    st = self.assign(t, v, st)
                return st
            o = self.taint(value, st)
            st = st.copy()
            for n in ast.walk(tgt):
                if isinstance(n, ast.Name):
                    _set(st, n.id, o, _MISSING, keep_taint=bool(self.weak))
            return st
        if isinstance(tgt, ast.Starred):
            return self.assign(tgt.value, value, st)
        return st                                     # attribute targets: handled by the main engine

    def _retaint(self, st: State, name) -> None:
        """Name-level taint of a container with a known layout = any tainted slot (never dropped in a try body)."""
        live = None
        if name in st.lk:
            live = next((o for o in st.lk[name] if o), None)
        elif name in st.dk:
            m, other = st.dk[name]
            live = next((v for v in list(m.values()) + [other] if v), None)
        else:
            return
        if live:
            st.tainted[name] = live
        elif not self.weak:
            st.tainted.pop(name, None)

    def aug(self, s: ast.AugAssign, st: State) -> State:
        if isinstance(s.target, ast.Name):
            name = s.target.id
            o = st.tainted.get(name) or self.taint(s.value, st)
            c = fold(ast.BinOp(left=ast.Name(id=name, ctx=ast.Load()), op=s.op, right=s.value), st.consts) \
                if name not in self.volatile else _MISSING
            st = st.copy()
            _set(st, name, o, c)
            if o:
                self.taint_group(st, name, o)
            return st
        if isinstance(s.target, ast.Subscript):
            return self.assign(s.target, ast.BinOp(left=s.target, op=s.op, right=s.value), st)
        return st

    def side_effects(self, expr, st: State) -> State:
        """Mutating calls nested in an expression (`v = lst.pop(0)`, `n = d.update(x) or 1`), and containers
        handed to another function, which may store any of the other arguments in them (`fill(buf, x)`)."""
        key = ("calls", id(expr))
        hit = self.cache.get(key)
        if hit is None or hit[0] is not expr:
            hit = (expr, [n for n in ast.walk(expr) if isinstance(n, ast.Call)] if expr is not None else [])
            self.cache[key] = hit
        for n in hit[1]:
            if isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.attr not in _READ_ONLY:
                st = self.container_write(n, st)
            elif isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Call) and n.func.attr in _CONTAINER_ADDS:
                # sb.append(a).append(x) / list.add(a).add(x): fluent writes land in the innermost receiver
                root = n.func.value
                while isinstance(root, ast.Call) and isinstance(root.func, ast.Attribute):
                    root = root.func.value
                if isinstance(root, ast.Name):
                    o = next((self.taint(a, st) for a in list(n.args) + [k.value for k in n.keywords] if self.taint(a, st)), None)
                    st = st.copy()
                    st.lk.pop(root.id, None)
                    st.dk.pop(root.id, None)
                    self.taint_group(st, root.id, o)
            fname = n.func.id if isinstance(n.func, ast.Name) else n.func.attr if isinstance(n.func, ast.Attribute) else ""
            if fname in _PURE_CALLS:
                continue
            args = list(n.args) + [k.value for k in n.keywords]
            passed = [a.id for a in args if isinstance(a, ast.Name)
                      and (a.id in st.lk or a.id in st.dk or a.id in self.containers)]
            if not passed:
                continue
            o = next((self.taint(a, st) for a in args if self.taint(a, st)), None)
            st = st.copy()
            for name in passed:                      # the callee may store the other arguments in the container
                st.lk.pop(name, None)
                st.dk.pop(name, None)
                if o:
                    self.taint_group(st, name, o)
        return st

    def container_write(self, call: ast.Call, st: State) -> State:
        f = call.func
        if not (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)):
            return st
        name = f.value.id
        args = list(call.args)
        kwargs = [k for k in call.keywords]
        if f.attr in _READ_ONLY:
            return st
        st = st.copy()
        if name in st.lk:
            elems = st.lk[name]
            idx_of = (lambda a: (lambda v: int(v) if isinstance(v, float) and v.is_integer() else v)(fold(a, st.consts)))
            if f.attr in ("append", "add", "push", "addLast", "offer", "offerLast") and len(args) == 1 and not kwargs:
                elems.append(self.taint(args[0], st))
            elif f.attr in ("insert", "add") and len(args) == 2 and isinstance(idx_of(args[0]), int) \
                    and 0 <= idx_of(args[0]) <= len(elems):
                elems.insert(idx_of(args[0]), self.taint(args[1], st))
            elif f.attr in ("addFirst", "appendleft", "unshift", "offerFirst", "push_front") and len(args) == 1:
                elems.insert(0, self.taint(args[0], st))
            elif f.attr in ("pop", "remove", "removeFirst", "removeLast", "shift", "poll", "pollFirst", "pollLast", "popleft") \
                    and len(args) <= 1 and not kwargs:
                idx = idx_of(args[0]) if args else (0 if f.attr in ("removeFirst", "shift", "poll", "pollFirst", "popleft")
                                                    else -1 if f.attr in ("pop", "removeLast", "pollLast") else _MISSING)
                if isinstance(idx, int) and not isinstance(idx, bool) and elems and -len(elems) <= idx < len(elems) \
                        and not (f.attr == "remove" and not isinstance(args[0], ast.Constant)):
                    elems.pop(idx)
                else:
                    st.lk.pop(name)                    # remove(value) / unknown index: forget the layout
            elif f.attr == "clear" and not args:
                st.lk[name] = []
            else:
                st.lk.pop(name)                        # extend / set / sort / unknown mutation: layout unknown
                o = next((self.taint(a, st) for a in args + [k.value for k in kwargs] if self.taint(a, st)), None)
                self.taint_group(st, name, o)
            self._retaint(st, name)
            return st
        if name in st.dk:
            m, other = st.dk[name]
            if f.attr in ("put", "setProperty", "set", "__setitem__", "Add", "putIfAbsent", "setdefault") and len(args) == 2:
                key = fold(args[0], st.consts)
                if key is not _MISSING and _hashable(key):
                    if not (f.attr in ("putIfAbsent", "setdefault") and m.get(key)):
                        m[key] = self.taint(args[1], st)   # strong update of one known key
                    self._retaint(st, name)
                    return st
            if f.attr == "update" and not args and kwargs and all(k.arg for k in kwargs):
                for k in kwargs:                       # d.update(a=x): constant keys
                    m[k.arg] = self.taint(k.value, st)
                self._retaint(st, name)
                return st
            if f.attr == "update" and len(args) == 1 and not kwargs and isinstance(args[0], ast.Dict) \
                    and all(isinstance(k, ast.Constant) for k in args[0].keys):
                for k, v in zip(args[0].keys, args[0].values):
                    m[k.value] = self.taint(v, st)
                self._retaint(st, name)
                return st
            if f.attr in ("clear",) and not args:
                st.dk[name] = ({}, None)
                self._retaint(st, name)
                return st
            # any other write (update(other), putAll, merge, compute ...): every key may now hold that data
            o = next((self.taint(a, st) for a in args + [k.value for k in kwargs] if self.taint(a, st)), None)
            if o:
                st.dk[name] = ({k: (v or o) for k, v in m.items()}, other or o)
            if f.attr not in _KNOWN_DICT_WRITES:
                st.dk.pop(name, None)
            self.taint_group(st, name, o)
            self._retaint(st, name)
            return st
        if f.attr in _CONTAINER_ADDS:
            o = next((self.taint(a, st) for a in args + [k.value for k in kwargs] if self.taint(a, st)), None)
            if o:
                self.taint_group(st, name, o)
                st.consts.pop(name, None)
        elif f.attr == "clear" and not args and len(self.may_alias(name)) == 1 and not self.weak:
            st.tainted.pop(name, None)
        return st


_READ_ONLY = {"get", "getOrDefault", "keys", "values", "items", "copy", "index", "count", "size", "isEmpty", "contains",
              "containsKey", "containsValue", "peek", "peekFirst", "peekLast", "getFirst", "getLast", "toString",
              "__len__", "__getitem__", "startswith", "endswith", "find", "first", "last", "length", "indexOf",
              "has", "hasOwnProperty", "includes", "at", "slice", "toArray", "stream", "iterator", "equals", "hashCode",
              "format", "join", "split", "strip", "lower", "upper", "encode", "decode", "getProperty", "getAttribute"}
_PURE_CALLS = {"len", "str", "int", "float", "bool", "repr", "print", "isinstance", "type", "id", "hash", "sorted", "list",
               "tuple", "set", "dict", "min", "max", "sum", "any", "all", "abs", "round", "format", "range", "enumerate",
               "zip", "map", "filter", "iter", "next", "reversed", "getattr", "hasattr", "valueOf", "toString", "equals",
               "println", "print_r", "var_dump", "echo", "size", "length", "count", "join", "contains", "startswith"}
_ALL_CONTAINER_METHODS = None   # filled below (union of the known container method names)
_KNOWN_DICT_WRITES = {"update", "putAll", "merge", "setdefault", "put", "set", "setProperty", "__setitem__", "Add"}
_CONTAINER_ADDS = {"append", "extend", "insert", "add", "update", "appendleft", "setdefault", "put", "push", "set",
                   "setProperty", "__setitem__", "addAll", "putAll", "write", "add_all", "offer", "addFirst", "addLast",
                   "unshift", "merge", "Add", "AddRange"}


_NEW_LIST = {"list", "ArrayList", "LinkedList", "deque", "ArrayDeque", "Vector", "Stack", "Array", "newArrayList"}


def _case_matches(case, subj, consts):
    """True / False if a match-case pattern decides on a constant subject; None if it cannot tell."""
    if case.guard is not None:
        return None
    return _pat(case.pattern, subj, consts)


def _pat(p, subj, consts):
    k = p.__class__.__name__
    if k == "MatchValue":
        v = fold(p.value, consts)
        return None if v is _MISSING else subj == v
    if k == "MatchSingleton":
        return subj is p.value
    if k == "MatchAs":
        return True if p.pattern is None else _pat(p.pattern, subj, consts)
    if k == "MatchOr":
        res = [_pat(x, subj, consts) for x in p.patterns]
        if any(r is True for r in res):
            return True
        return None if any(r is None for r in res) else False
    return None


def _set(st: State, name, origin, const, keep_taint: bool = False):
    if origin:
        st.tainted[name] = origin
    elif not keep_taint:
        st.tainted.pop(name, None)
    if const is not _MISSING and isinstance(const, _CONST_TYPES):
        st.consts[name] = const
    else:
        st.consts.pop(name, None)
    st.dk.pop(name, None)
    st.lk.pop(name, None)


def _alias_groups(stmts) -> dict:
    """Names that may refer to the same object: `b = a`, `a, b = b, a`, `x = y = []` (flow-insensitive union)."""
    parent: dict = {}

    def find(x):
        while parent.get(x, x) != x:
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb
    for s in stmts:
        for n in ast.walk(s):
            if isinstance(n, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
                names = [t.id for t in tgts if isinstance(t, ast.Name)]
                if isinstance(n.value, ast.Name):
                    names.append(n.value.id)
                elif len(names) < 2:
                    continue
                for a in names[1:]:
                    union(names[0], a)
    groups: dict = {}
    for x in list(parent):
        groups.setdefault(find(x), set()).add(x)
    out = {}
    for g in groups.values():
        g |= {find(next(iter(g)))}
        for x in g:
            out[x] = g
    return out


def _containers(stmts) -> set:
    """Names bound to a mutable container literal or constructor somewhere in the function."""
    out = set()
    for s in stmts:
        for n in ast.walk(s):
            if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
                v = n.value
                if isinstance(v, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)) or \
                        (isinstance(v, ast.Call) and _callee_name(v) in _NEW_LIST | _NEW_MAP | {"set", "bytearray", "StringBuilder",
                                                                                               "StringBuffer", "HashSet", "TreeSet"}):
                    for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                        if isinstance(t, ast.Name):
                            out.add(t.id)
    return out


def _callee_name(call) -> str:
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""


_INNER_RETURNING = {"setdefault", "get", "pop", "getOrDefault", "computeIfAbsent", "getFirst", "getLast", "peek",
                    "peekFirst", "peekLast", "poll", "popleft", "first", "last", "__getitem__", "at", "find"}


def _escaping(fn, include_passed: bool = True) -> set:
    """Names whose container may be reached some other way than through the name itself, so their layout must
    not be tracked: passed to functions, stored, returned, put in literals, aliased by any expression, captured by
    nested functions, or whose elements are taken out (`opts = conf["opts"]`, `d.setdefault(k, []).append(x)`)."""
    body = fn.body if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)) else []
    parents: dict = {}
    stack = [(st, fn) for st in body]
    nested = []
    while stack:
        n, par = stack.pop()
        parents[n] = par
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            nested.append(n)
            continue
        for ch in ast.iter_child_nodes(n):
            stack.append((ch, n))
    out = set()
    taken: list = []        # (container, names bound to one of its elements): escapes only if that element is mutated
    mutated: set = set()    # names written through: x.append(…), x[k] = …, x.f = …
    passed: set = set()     # names passed as call arguments (a callee may mutate them, e.g. fill(buf, x))
    called: set = set()     # names used as the receiver of a non-container method or attribute
    stored: list = []       # (name, containers it was stored in)
    for n in parents:
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) \
                and n.func.attr in _ALL_CONTAINER_METHODS and n.func.attr not in _READ_ONLY:
            mutated.add(n.func.value.id)
        elif isinstance(n, (ast.Subscript, ast.Attribute)) and isinstance(n.ctx, (ast.Store, ast.Del)) \
                and isinstance(n.value, ast.Name):
            mutated.add(n.value.id)

    def bound_names(use):
        tg = use.targets if isinstance(use, ast.Assign) else [use.target]
        return [t.id for t in tg if isinstance(t, ast.Name)] if all(isinstance(t, ast.Name) for t in tg) else None

    def take(x, use):
        """`y = x[k]` / `y = x.get(k)`: x escapes when y is later used as a container (or bound in another way)."""
        names = bound_names(use) if isinstance(use, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) else None
        if names is None:
            out.add(x)
        else:
            taken.append((x, names))

    for d in nested:                                   # captured by a closure / lambda
        out.update(x.id for x in ast.walk(d) if isinstance(x, ast.Name))
    for n, p in parents.items():
        if isinstance(n, (ast.Global, ast.Nonlocal)):
            out.update(n.names)
        if not (isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)):
            continue
        x = n.id
        if isinstance(p, ast.Attribute) and p.value is n:
            gp = parents.get(p)
            if isinstance(gp, ast.Call) and gp.func is p and p.attr in _ALL_CONTAINER_METHODS:
                if p.attr in _INNER_RETURNING:
                    use = parents.get(gp)
                    if isinstance(use, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                        take(x, use)                  # the inner container may be taken out and mutated
                    elif isinstance(use, ast.Attribute) or (isinstance(use, ast.Subscript) and use.value is gp):
                        out.add(x)
                continue
            called.add(x)                             # x.method(…) / x.attr: escapes, but writes no container slot
            continue
        if isinstance(p, ast.Subscript) and p.slice is n:
            continue                                  # used as an index / key: read only
        if isinstance(p, ast.Subscript) and p.value is n:
            gp = parents.get(p)
            if isinstance(p.ctx, ast.Load):
                if isinstance(gp, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and getattr(gp, "value", None) is p:
                    take(x, gp)                       # element taken out: may alias a sub-container
                elif isinstance(gp, ast.Attribute) or (isinstance(gp, ast.Subscript) and gp.value is p):
                    out.add(x)                        # nested access x[k].append(…) / x[a][b]
            continue
        if isinstance(p, ast.Compare) or (isinstance(p, (ast.For, ast.AsyncFor, ast.comprehension)) and p.iter is n):
            continue                                  # `k in x`, iteration: reads only
        if isinstance(p, ast.Call) and p.func is not n and _callee_name(p) in _PURE_CALLS:
            continue                                  # len(x), str(x) …
        if isinstance(p, ast.FormattedValue) or isinstance(p, ast.BinOp):
            continue
        if (isinstance(p, ast.Call) and n in p.args) or isinstance(p, (ast.keyword, ast.Starred)):
            passed.add(x)                             # handed to a function: escapes, but is not stored anywhere here
            continue
        if isinstance(p, (ast.Return, ast.Yield, ast.YieldFrom)):
            called.add(x)                             # handed to the caller: nothing here can write through it later
            continue
        if isinstance(p, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            called.add(x)                             # put in a literal: aliased there, no slot of x is written
            continue
        if isinstance(p, ast.Assign) and p.value is n and p.targets and all(
                isinstance(t, (ast.Subscript, ast.Attribute)) and _root_name(t) for t in p.targets):
            called.add(x)                             # d[k] = x / o.f = x / flask.session[k] = x: aliased there
            stored.append((x, [_root_name(t) for t in p.targets]))
            continue
        out.add(x)
    local = _assigned(body) | {a.arg for a in ast.walk(fn.args) if isinstance(a, ast.arg)} \
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) else _assigned(body)
    changed = True
    while changed:                                    # an element bound to a name that is mutated or stored elsewhere
        changed = False
        # stored in a local container that is itself written through (module objects such as flask.session are
        # not containers of this function)
        holders = {y for y, roots in stored if any(r in out and r in local for r in roots)}
        for x, names in taken:
            if x not in out and any(y in mutated or y in out or y in holders for y in names):
                out.add(x)
                changed = True
    out |= called
    return out | passed if include_passed else out


def _root_name(node):
    """`a.b[c].d` -> "a"; None when the chain does not start at a plain name."""
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _rebound_elsewhere(fn) -> set:
    """Names that a nested function rebinds with nonlocal/global (or, for a module, any `global` declaration)."""
    out = set()
    for n in ast.walk(fn):
        if isinstance(n, (ast.Nonlocal, ast.Global)) and n is not fn:
            out.update(n.names)
    return out


def _hashable(v) -> bool:
    try:
        hash(v)
        return True
    except TypeError:
        return False


_NEW_MAP = {"dict", "HashMap", "LinkedHashMap", "TreeMap", "Hashtable", "ConcurrentHashMap", "Properties", "Map",
            "OrderedDict", "defaultdict", "Dictionary", "SortedDictionary", "mutableMapOf", "hashMapOf"}


def _is_empty_dict_call(call: ast.Call) -> bool:
    f = call.func
    name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
    return name in _NEW_MAP and not call.keywords and (not call.args or name == "defaultdict")


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


_QUERIED = (ast.Call, ast.Return, ast.Assign, ast.AnnAssign)


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


_ALL_CONTAINER_METHODS = (_READ_ONLY | _CONTAINER_ADDS | _KNOWN_DICT_WRITES | _INNER_RETURNING |
                          {"pop", "remove", "removeFirst", "removeLast", "shift", "poll", "pollFirst", "pollLast",
                           "popleft", "clear", "insert", "addFirst", "appendleft", "unshift", "offerFirst", "push_front",
                           "sort", "reverse", "putIfAbsent"})
