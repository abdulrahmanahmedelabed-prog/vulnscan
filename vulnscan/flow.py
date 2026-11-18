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

    __slots__ = ("tainted", "consts", "dk", "lk", "facts")

    def __init__(self, tainted=None, consts=None, dk=None, lk=None, facts=None):
        self.tainted: dict = tainted if tainted is not None else {}   # name -> origin
        self.consts: dict = consts if consts is not None else {}      # name -> python constant
        self.dk: dict = dk if dk is not None else {}                  # name -> ({const key: origin|None}, other origin|None)
        self.lk: dict = lk if lk is not None else {}                  # name -> [origin|None, ...] (list, known length)
        # name -> frozenset of facts a guard established about the name's CURRENT value (see FlowInterpreter.refine):
        # "absent:<s>" (the text has no <s>), "starts:<s>" / "ends:<s>", "nomid:<c>" (no <c> between the first and
        # last character), "resolved" (an absolute, normalised path), "confined" (a resolved path checked against a
        # directory prefix), "urlof:<n>" (urlparse(<n>)), "hostok" (the URL's host passed an allow-list)
        self.facts: dict = facts if facts is not None else {}

    def copy(self) -> "State":
        return State(dict(self.tainted), dict(self.consts), {k: (dict(m), o) for k, (m, o) in self.dk.items()},
                     {k: list(v) for k, v in self.lk.items()}, dict(self.facts))

    def same(self, other: "State") -> bool:
        return (set(self.tainted) == set(other.tainted) and self.consts == other.consts and self.facts == other.facts
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
    facts = {}
    for name in set(a.facts) & set(b.facts):        # a fact holds after the join only if it holds on both paths
        f = a.facts[name] & b.facts[name]
        if f:
            facts[name] = f
    return State(tainted, consts, dk, lk, facts)


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
            hit = _fn_struct(fn)
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
        env.facts = st.facts
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
            if st.facts and not (isinstance(s, ast.AugAssign) and isinstance(s.target, ast.Name)):
                st = self.drop_facts(st, self._stores_cached(s))     # (`s += x` updates its own facts: aug)
            st = self.stmt(s, st)
        return st

    # ---------------------------------------------------------------- guard facts
    def _stores_cached(self, s) -> frozenset:
        key = ("stores", id(s))
        hit = self.cache.get(key)
        if hit is None or hit[0] is not s:
            hit = (s, _shallow_stores(s))
            self.cache[key] = hit
        return hit[1]

    @staticmethod
    def drop_facts(st: State, names) -> State:
        """Names (re)bound by the next statement lose what a guard proved about their old value, and so does a parsed
        URL whose source text is rebound."""
        hit = [n for n in st.facts if n in names or any(f.startswith("urlof:") and f[6:] in names for f in st.facts[n])]
        if not hit:
            return st
        st = st.copy()
        for n in hit:
            st.facts.pop(n, None)
        return st

    def refine(self, test, positive: bool, st: State) -> State:
        """The state on the branch where `test` is `positive`, with the facts the test proves (Python only)."""
        if self.proj.m.get("language") != "python":
            return st
        try:
            got = self._facts_of(test, positive, st)
        except RecursionError:
            return st
        got = {n: f for n, f in got.items() if f and n not in self.volatile}
        if not got:
            return st
        st = st.copy()
        for n, f in got.items():
            st.facts[n] = st.facts.get(n, frozenset()) | f
        return st

    def _facts_of(self, test, positive: bool, st: State) -> dict:
        """name -> facts that hold where `test` evaluates to `positive`."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self._facts_of(test.operand, not positive, st)
        if isinstance(test, ast.BoolOp):
            parts = [self._facts_of(v, positive, st) for v in test.values]
            if isinstance(test.op, ast.And) == positive:
                out: dict = {}            # every part holds (a and b true / a or b false): all their facts
                for p in parts:
                    for n, f in p.items():
                        out[n] = out.get(n, frozenset()) | f
                return out
            common = set.intersection(*[set(p) for p in parts]) if parts else set()
            return {n: frozenset.intersection(*[p[n] for p in parts]) for n in common}
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            op, left, right = test.ops[0], test.left, test.comparators[0]
            # `"x" in name` false / `"x" not in name` true: the text has no "x"
            if isinstance(op, (ast.In, ast.NotIn)) and isinstance(op, ast.NotIn) == positive \
                    and isinstance(left, ast.Constant) and isinstance(left.value, str) and left.value:
                if isinstance(right, ast.Name):
                    # on a list (getlist, JSON) `in` tests membership and str(list) adds quotes and brackets: the
                    # text is known to lack the substring only when the value is known to be a str
                    if "str" not in st.facts.get(right.id, ()):
                        return {}
                    return {right.id: frozenset({"absent:" + left.value})}
                # `q in name[1:-1]` false: no q between the first and the last character
                if isinstance(right, ast.Subscript) and isinstance(right.value, ast.Name) and len(left.value) == 1 \
                        and isinstance(right.slice, ast.Slice) and right.slice.step is None \
                        and _int_const(right.slice.lower) == 1 and _int_const(right.slice.upper) == -1:
                    return {right.value.id: frozenset({"nomid:" + left.value})}
            # `name.find("x") == -1` / `< 0` true, `!= -1` / `>= 0` / `> -1` false; `name.count("x") == 0` true
            if isinstance(left, ast.Call) and isinstance(left.func, ast.Attribute) and isinstance(left.func.value, ast.Name) \
                    and left.func.attr in ("find", "count") and len(left.args) == 1 and not left.keywords \
                    and isinstance(left.args[0], ast.Constant) and isinstance(left.args[0].value, str) and left.args[0].value:
                k = _int_const(right)
                none = {"find": -1, "count": 0}[left.func.attr]
                holds = None
                if isinstance(op, ast.Eq) and k == none:
                    holds = positive
                elif isinstance(op, ast.NotEq) and k == none:
                    holds = not positive
                elif left.func.attr == "find" and isinstance(op, ast.Lt) and k == 0:
                    holds = positive
                elif isinstance(op, ast.GtE) and k == none + 1:
                    holds = not positive
                elif isinstance(op, ast.Gt) and k == none:
                    holds = not positive
                # (list.count / a project .find count or search elements: only a str's say nothing is in the text)
                if holds and "str" in st.facts.get(left.func.value.id, ()):
                    return {left.func.value.id: frozenset({"absent:" + left.args[0].value})}
            # `u.netloc not in ALLOWED` false / `u.netloc == "host"` true, with u = urlparse(name)
            # (not u.hostname: "https://evil.example\\@good.example" has hostname good.example, and browsers read the
            # backslash as "/", going to evil.example; urlparse's netloc keeps the whole authority)
            if isinstance(left, ast.Attribute) and left.attr == "netloc" and isinstance(left.value, ast.Name):
                allowed = (isinstance(op, ast.In) and positive) or (isinstance(op, ast.NotIn) and not positive)
                if isinstance(op, (ast.In, ast.NotIn)):
                    allowed = allowed and isinstance(right, (ast.List, ast.Tuple, ast.Set)) and bool(right.elts) \
                        and all(isinstance(e, ast.Constant) and isinstance(e.value, str) and e.value for e in right.elts)
                else:
                    allowed = ((isinstance(op, ast.Eq) and positive) or (isinstance(op, ast.NotEq) and not positive)) \
                        and isinstance(right, ast.Constant) and isinstance(right.value, str) and bool(right.value)
                if allowed:
                    srcs = [f[6:] for f in st.facts.get(left.value.id, ()) if f.startswith("urlof:")]
                    return {n: frozenset({"hostok"}) for n in srcs}
            return {}
        if isinstance(test, ast.Call) and isinstance(test.func, ast.Name) and test.func.id == "isinstance" and positive \
                and len(test.args) == 2 and isinstance(test.args[0], ast.Name) and isinstance(test.args[1], ast.Name) \
                and test.args[1].id == "str":
            return {test.args[0].id: frozenset({"str"})}
        if isinstance(test, ast.Call) and isinstance(test.func, ast.Attribute) and positive \
                and test.func.attr in ("startswith", "endswith") and len(test.args) == 1 and not test.keywords:
            recv, arg = test.func.value, test.args[0]
            if isinstance(recv, ast.Call) and isinstance(recv.func, ast.Name) and recv.func.id in ("str", "os.fspath") \
                    and len(recv.args) == 1 and not recv.keywords:
                recv = recv.args[0]          # str(p).startswith(...)
            if not isinstance(recv, ast.Name):
                return {}
            out = set()
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value and recv is test.func.value:
                out.add(("starts:" if test.func.attr == "startswith" else "ends:") + arg.value)
            if test.func.attr == "startswith" and "resolved" in st.facts.get(recv.id, ()) \
                    and _dir_prefix(arg, lambda x: self._nonempty_dir(x, st)) and not self.taint(arg, st):
                out.add("confined")      # a normalised absolute path inside an (untainted) directory/ prefix
            return {recv.id: frozenset(out)} if out else {}
        return {}

    def _nonempty_dir(self, e, st: State) -> bool:
        """`e` is text that is neither empty nor only separators, so `e + os.sep` names a directory (an empty
        `base` would make the prefix "/" and admit every absolute path)."""
        if isinstance(e, ast.Call) and _dotted_name(e.func) in ("str", "os.fspath") and len(e.args) == 1:
            e = e.args[0]
        if isinstance(e, ast.Name) and "resolved" in st.facts.get(e.id, ()):
            return True                  # resolve() / realpath / abspath / normpath never return "" (at least ".")
        if isinstance(e, ast.Call) and _value_facts(e) == frozenset({"resolved"}):
            return True
        text = self.proj._str_const_of(self.mod, e, self.env_for(st))
        return bool(text) and bool(text.rstrip("/\\"))

    def _is_str(self, e, st: State, depth: int = 0) -> bool:
        """Is the value of `e` certainly a str (or does evaluating it raise)? Literals, f-strings, str methods,
        slices of a str, the str-returning request accessors (`request.args.get(k)`, `.form`, `.cookies`, `.headers`,
        `.values`, `get_data(as_text=True)`), urllib unquote."""
        if depth > 8:
            return False
        if isinstance(e, ast.Constant):
            return isinstance(e.value, str)
        if isinstance(e, ast.JoinedStr):
            return True
        if isinstance(e, ast.Name):
            return "str" in st.facts.get(e.id, ()) or isinstance(st.consts.get(e.id), str)
        if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Add):
            return self._is_str(e.left, st, depth + 1) and self._is_str(e.right, st, depth + 1)
        if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Mod):
            return isinstance(e.left, ast.Constant) and isinstance(e.left.value, str)
        if isinstance(e, ast.IfExp):
            return self._is_str(e.body, st, depth + 1) and self._is_str(e.orelse, st, depth + 1)
        if isinstance(e, ast.BoolOp):
            return all(self._is_str(v, st, depth + 1) for v in e.values)
        if isinstance(e, ast.Subscript):
            if self._is_str(e.value, st, depth + 1):
                return True                  # a slice or a character of a str
            if ((isinstance(e.value, ast.Name) and "strlist" in st.facts.get(e.value.id, ()))
                    or self._request_getlist(e.value)) and not isinstance(e.slice, ast.Slice):
                return True                  # one item of request.args.getlist(k)
            v = e.value                      # one item of s.split(...): a str
            return not isinstance(e.slice, ast.Slice) and isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute) \
                and v.func.attr in ("split", "rsplit", "splitlines", "partition", "rpartition") \
                and self._is_str(v.func.value, st, depth + 1)
        if not isinstance(e, ast.Call):
            return False
        f = e.func
        if isinstance(f, ast.Name) and f.id == "str":
            return True
        if _dotted_name(f).split(".")[-1] in ("unquote", "unquote_plus") and _dotted_name(f) in (
                "unquote", "unquote_plus", "urllib.parse.unquote", "urllib.parse.unquote_plus", "parse.unquote",
                "parse.unquote_plus"):
            return True
        if not isinstance(f, ast.Attribute):
            return False
        if f.attr == "decode":
            return self._is_bytes(f.value, st, depth + 1)   # bytes.decode (jwt.decode / JSONDecoder().decode return objects)
        if f.attr in _STR_RESULT_METHODS:
            return self._is_str(f.value, st, depth + 1)
        if f.attr == "get" and isinstance(f.value, ast.Attribute) and f.value.attr in ("args", "form", "cookies", "headers", "values") \
                and self._flask_request(f.value.value) and len(e.args) in (1, 2) \
                and not e.keywords and (len(e.args) == 1 or (isinstance(e.args[1], ast.Constant)
                                                            and (e.args[1].value is None or isinstance(e.args[1].value, str)))):
            return True                      # werkzeug MultiDict / Headers .get(k[, str default])
        if f.attr == "get_data" and self._flask_request(f.value) and any(
                k.arg == "as_text" and isinstance(k.value, ast.Constant) and k.value.value is True for k in e.keywords):
            return True
        return False

    def _safe_built(self, value, st: State) -> frozenset:
        """"safe:<cwe>" facts for a name assigned a built string whose tainted pieces all sit where they cannot
        harm that sink (taint.Project._built_safe_cwes), or a plain alias of such a name. Nothing else carries them:
        any call or further building in between may undo the protection (unquote turns %2e%2e into ..)."""
        if self.proj.m.get("language") != "python":
            return frozenset()
        if isinstance(value, ast.Name):
            return frozenset(f for f in st.facts.get(value.id, ()) if f.startswith("safe:"))
        if isinstance(value, (ast.JoinedStr, ast.BinOp, ast.Call)) and (st.facts or any(
                isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "replace"
                for n in ast.walk(value))):
            return frozenset("safe:" + c for c in self.proj._built_safe_cwes(self.mod, self.cls, value, self.env_for(st)))
        return frozenset()

    def _flask_request(self, e) -> bool:
        """`e` is Flask's / Quart's global request (werkzeug MultiDicts of str), not another framework's request
        object (Twisted's request.args holds lists of bytes)."""
        return self.proj._canon(self.mod, e) in ("flask.request", "quart.request", "flask.globals.request")

    def _request_getlist(self, e) -> bool:
        """request.args / form / headers / cookies / values .getlist(k) without type=: a fresh list of str."""
        return isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and e.func.attr == "getlist" \
            and len(e.args) == 1 and not e.keywords and isinstance(e.func.value, ast.Attribute) \
            and e.func.value.attr in ("args", "form", "cookies", "headers", "values") \
            and self._flask_request(e.func.value.value)

    def _is_bytes(self, e, st: State, depth: int = 0) -> bool:
        """A value certainly bytes: a b"" literal, str.encode() on a known str, base64 output, Flask's
        request.get_data() / .data / .query_string."""
        if isinstance(e, ast.Constant):
            return isinstance(e.value, bytes)
        if isinstance(e, ast.Attribute):
            return e.attr in ("query_string", "data") and self._flask_request(e.value)
        if not isinstance(e, ast.Call):
            return False
        if self.proj._canon(self.mod, e.func) in ("base64.b64decode", "base64.b64encode", "base64.urlsafe_b64decode",
                                                  "base64.urlsafe_b64encode"):
            return True
        if isinstance(e.func, ast.Attribute) and e.func.attr == "encode" and not e.keywords and len(e.args) <= 2:
            return self._is_str(e.func.value, st, depth + 1)
        return isinstance(e.func, ast.Attribute) and e.func.attr == "get_data" and not e.keywords and not e.args \
            and self._flask_request(e.func.value)

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
        a = self.block(s.body, self.refine(s.test, True, st).copy())
        b = self.block(s.orelse, self.refine(s.test, False, st).copy())
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
        return self.drop_facts(st, frozenset(names))   # (no fixpoint was reached: what guards proved may not hold)

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
            is_str = self.proj.m.get("language") == "python" and self._is_str(value, st)
            safe = self._safe_built(value, st)
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
            st.facts.pop(name, None)
            if name not in self.volatile and self.proj.m.get("language") == "python":
                fct = _value_facts(value) | ({"str"} if is_str else frozenset()) \
                    | ({"strlist"} if self._request_getlist(value) else frozenset()) | safe
                if fct:
                    st.facts[name] = frozenset(fct)
            if trackable:
                if isinstance(value, ast.Call) and _is_config_parser(value) \
                        and self.proj._canon(self.mod, value.func).startswith("configparser."):
                    st.dk[name] = ({_CFG: None}, None)   # configparser: (section, option) -> value
                elif isinstance(value, ast.Dict) and all(isinstance(k, ast.Constant) for k in value.keys):
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
            if name in st.dk and _CFG in st.dk[name][0]:
                st.dk.pop(name)                      # conf["section"] = {...}: a whole section, layout unknown
                self.taint_group(st, name, o)
                return st
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
        if isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name) and tgt.value.id in st.dk \
                and _CFG in st.dk[tgt.value.id][0]:
            st = st.copy()                            # conf.optionxform = ...: option names may now map differently
            st.dk.pop(tgt.value.id, None)
            return st
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
            # `s += x` on a str / number / bytes value builds a new object and rebinds s: a name that shared the
            # old value (`copy = s`) still holds it, unlike `lst += x`, which extends the list in place
            immutable = name in st.consts and name not in self.volatile
            c = fold(ast.BinOp(left=ast.Name(id=name, ctx=ast.Load()), op=s.op, right=s.value), st.consts) \
                if name not in self.volatile else _MISSING
            keep_str = isinstance(s.op, ast.Add) and self._is_str(s.target, st) and self._is_str(s.value, st)
            # every name the statement binds, the target and any `(n := …)` in the value
            st = self.drop_facts(st, self._stores_cached(s)).copy()
            _set(st, name, o, c)
            if keep_str and name not in self.volatile:
                st.facts[name] = frozenset({"str"})     # str + str
            if o and not immutable:
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
            if isinstance(n.func, ast.Name) and n.func.id in ("setattr", "delattr") and n.args \
                    and isinstance(n.args[0], ast.Name) and n.args[0].id in st.dk and _CFG in st.dk[n.args[0].id][0]:
                st = st.copy()                   # setattr(conf, "optionxform", f): option names may map differently
                st.dk.pop(n.args[0].id, None)
                continue
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
        if name in st.dk and _CFG in st.dk[name][0]:
            return self.config_write(name, f.attr, args, kwargs, st)
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


    def config_write(self, name, attr, args, kwargs, st: State) -> State:
        """A call on a tracked configparser (st was copied by the caller). `set(section, option, value)` with a
        constant section and option is a strong update of that slot; adding or querying sections changes no value.
        Anything else, or a value that interpolation could expand (not a %-free constant), forgets the layout."""
        m, other = st.dk[name]
        vals = args + [k.value for k in kwargs]
        o = next((self.taint(a, st) for a in vals if self.taint(a, st)), None)
        if attr in _CFG_QUERIES and not o:
            return st
        if attr == "set" and len(args) == 3 and not kwargs:
            key = cfg_key(fold(args[0], st.consts), fold(args[1], st.consts))
            v = fold(args[2], st.consts)
            vo = self.taint(args[2], st)
            # a constant with no interpolation syntax (BasicInterpolation "%(x)s", ExtendedInterpolation "${x}")
            if key is not _MISSING and (vo or (isinstance(v, str) and "%" not in v and "$" not in v)):
                if vo or not self.weak:          # (inside a guarded try the write may be skipped: keep the old value)
                    m[key] = vo
                self._retaint(st, name)
                return st
        st.dk.pop(name, None)
        self.taint_group(st, name, o)
        return st


_CFG_QUERIES = {"add_section", "has_section", "has_option", "sections", "options"}

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


_CFG = ("<configparser>",)     # dk marker: the container is a configparser.ConfigParser keyed by (section, option)
_CFG_CLASSES = {"ConfigParser", "RawConfigParser", "SafeConfigParser"}
_CFG_SAFE_KW = {"allow_no_value", "delimiters", "comment_prefixes", "inline_comment_prefixes", "strict",
                "empty_lines_in_values", "interpolation", "dict_type"}


def _is_config_parser(call: ast.Call) -> bool:
    """`configparser.ConfigParser()` with no defaults and the standard DEFAULT section (both would add keys)."""
    return _callee_name(call) in _CFG_CLASSES and not call.args and all(k.arg in _CFG_SAFE_KW for k in call.keywords)


def cfg_key(section, option):
    """The slot of (section, option): option names are case-folded by the default optionxform."""
    if isinstance(section, str) and isinstance(option, str):
        return (section, option.lower())
    return _MISSING


def _int_const(e):
    if isinstance(e, ast.Constant) and isinstance(e.value, int) and not isinstance(e.value, bool):
        return e.value
    if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.USub) and isinstance(e.operand, ast.Constant) \
            and isinstance(e.operand.value, int) and not isinstance(e.operand.value, bool):
        return -e.operand.value
    return None


_SEP_ATTRS = {"os.sep", "os.path.sep", "posixpath.sep"}


_STR_RESULT_METHODS = {"replace", "strip", "lstrip", "rstrip", "lower", "upper", "casefold", "title", "capitalize",
                       "swapcase", "format", "zfill", "center", "ljust", "rjust", "expandtabs", "translate",
                       "removeprefix", "removesuffix", "join"}


def _dir_prefix(e, nonempty) -> bool:
    """An expression whose text is a directory followed by a separator: "/srv/data/", base + os.sep,
    f"{base}/", os.path.join(base, ""). A prefix check against it confines a normalised path to that directory
    (without the trailing separator "/srv/data" would also admit "/srv/data-old/…")."""
    def sep(x):
        if isinstance(x, ast.Constant) and isinstance(x.value, str):
            return x.value in ("/", "\\")
        return _dotted_name(x) in _SEP_ATTRS
    if isinstance(e, ast.Constant) and isinstance(e.value, str):
        return len(e.value) > 1 and e.value[-1] in "/\\" and bool(e.value.rstrip("/\\"))
    if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Add):
        if sep(e.right):
            return nonempty(e.left)
        return isinstance(e.right, ast.Constant) and isinstance(e.right.value, str) and len(e.right.value) > 1 \
            and e.right.value[-1] in "/\\" and bool(e.right.value.strip("/\\"))
    if isinstance(e, ast.JoinedStr) and len(e.values) > 1:
        last = e.values[-1]
        head = e.values[:-1]
        return isinstance(last, ast.Constant) and isinstance(last.value, str) and last.value[-1:] in ("/", "\\") and (
            bool(last.value.strip("/\\")) or (len(head) == 1 and isinstance(head[0], ast.FormattedValue)
                                               and head[0].conversion == -1 and head[0].format_spec is None
                                               and nonempty(head[0].value)))
    if isinstance(e, ast.Call) and _dotted_name(e.func) in ("os.path.join", "posixpath.join") and len(e.args) == 2 \
            and isinstance(e.args[-1], ast.Constant) and e.args[-1].value == "":
        return nonempty(e.args[0])
    return False


def _dotted_name(e) -> str:
    parts = []
    while isinstance(e, ast.Attribute):
        parts.append(e.attr)
        e = e.value
    if isinstance(e, ast.Name):
        return ".".join([e.id] + parts[::-1])
    return ""


_NORMALISERS = {"os.path.realpath", "os.path.abspath", "os.path.normpath", "posixpath.realpath", "posixpath.abspath",
                "posixpath.normpath", "realpath", "abspath", "normpath"}


def _value_facts(value) -> frozenset:
    """Facts a value carries from how it was computed: a normalised path, a parsed URL."""
    if not isinstance(value, ast.Call):
        return frozenset()
    f = value.func
    if isinstance(f, ast.Attribute) and f.attr == "resolve" and not value.args \
            and all(k.arg == "strict" for k in value.keywords):
        return frozenset({"resolved"})                 # pathlib.Path.resolve(): absolute, no "..", links followed
    if _dotted_name(f) in _NORMALISERS and len(value.args) == 1 and not value.keywords:
        return frozenset({"resolved"})
    if _callee_name(value) in ("urlparse", "urlsplit") and len(value.args) == 1 and not value.keywords \
            and isinstance(value.args[0], ast.Name):
        return frozenset({"urlof:" + value.args[0].id})
    return frozenset()


def _shallow_stores(s) -> frozenset:
    """Names a statement binds itself (its own targets and header, not the statements nested in its body)."""
    out = set()
    if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return frozenset({s.name})
    if isinstance(s, (ast.Import, ast.ImportFrom)):
        return frozenset((a.asname or a.name).split(".")[0] for a in s.names)
    for n in _nodes_of(s):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            out.add(n.id)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            out.add(n.name)
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            out.update(n.names)
        elif n.__class__.__name__ in ("MatchAs", "MatchStar") and getattr(n, "name", None):
            out.add(n.name)
        elif n.__class__.__name__ == "MatchMapping" and getattr(n, "rest", None):
            out.add(n.rest)
    return frozenset(out)


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


def _fn_struct(fn) -> tuple:
    """Per-function facts of FlowInterpreter: (fn, alias groups, names rebound elsewhere, assigned names, escaping
    names, container names). One walk of the body feeds the helpers that would each walk it again."""
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
        return (fn, _alias_groups([]), _rebound_elsewhere(fn), _assigned([]), _escaping(fn), _containers([]))
    body = fn.body
    nodes = [n for s in body for n in ast.walk(s)]
    assigned = _assigned(body, nodes)
    # global / nonlocal are statements: inside a def or module they can only appear in its body (walked above)
    rebound = set()
    for n in nodes:
        if isinstance(n, (ast.Nonlocal, ast.Global)):
            rebound.update(n.names)
    return (fn, _alias_groups(body, nodes), rebound, assigned, _escaping(fn, assigned=assigned), _containers(body, nodes))


def _body_nodes(stmts, nodes):
    if nodes is not None:
        return nodes
    return [n for s in stmts for n in ast.walk(s)]


def _alias_groups(stmts, nodes=None) -> dict:
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
    for n in _body_nodes(stmts, nodes):
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


def _containers(stmts, nodes=None) -> set:
    """Names bound to a mutable container literal or constructor somewhere in the function."""
    out = set()
    for n in _body_nodes(stmts, nodes):
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


def _escaping(fn, include_passed: bool = True, assigned: set | None = None) -> set:
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
    if assigned is None:
        assigned = _assigned(body)
    local = assigned | {a.arg for a in ast.walk(fn.args) if isinstance(a, ast.arg)} \
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) else assigned
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


def _assigned(stmts, nodes=None) -> set:
    """Names bound (or deleted) anywhere under `stmts`, nested functions included (ast.walk descends into them)."""
    out = set()
    for n in _body_nodes(stmts, nodes):
        if isinstance(n, ast.Name):
            if isinstance(n.ctx, (ast.Store, ast.Del)):
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


_ALL_CONTAINER_METHODS = (_READ_ONLY | _CONTAINER_ADDS | _KNOWN_DICT_WRITES | _INNER_RETURNING | _CFG_QUERIES |
                          {"pop", "remove", "removeFirst", "removeLast", "shift", "poll", "pollFirst", "pollLast",
                           "popleft", "clear", "insert", "addFirst", "appendleft", "unshift", "offerFirst", "push_front",
                           "sort", "reverse", "putIfAbsent"})
