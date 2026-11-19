"""Missing authorization check inconsistent with sibling routines (APX024, CWE-862).  (vulnscan: ignore-file)

A PL/SQL package whose public routines check the caller's authorization themselves (they call the package's access
check, `apex_authorization.is_authorized`, …) but where one public routine that reads, changes or sends data does
not: any code in the same schema (another APEX page, a job, a REST handler) can call that routine directly, whatever
the application around it checks first.

The rule is about inconsistency, not a guess that every routine needs a check, and it stays conservative:

1. Public routines: the ones the package spec declares when the scan holds it (any file); without a spec, the body's
   routines minus those other routines of the package call (private helpers) and those declared forward in the body.
2. The guard: a call whose name looks like an authorization / access check, reached (directly or through routines
   of the same package) on every path to the data access by at least 3 public routines and by at least 60% of the
   public routines that access data or call it. No guard: no finding.
3. Flagged: a public routine that reads data with a query and can return it, changes data (DML, dynamic SQL) or
   writes to the browser (htp, wpg_docload), itself or through a routine of the package that does so unchecked, and
   where some path reaches that access without passing an authorization-like call (the package's guard or another):
   no such call at all, or one only in a branch of IF / ELSIF / CASE, in a loop, in an exception handler, after the
   access. A call in a condition counts for the whole statement (`if not can_view(…) then raise …; end if;` covers
   what follows, as RETURN / RAISE / raise_application_error end their path), and a read counts where what was read
   can leave the routine (each RETURN after it, the end of a procedure), so querying the row's owner before the check
   is fine. Pure computation (no SQL, no output) is never flagged.

The analysis reads tokens of plain PL/SQL (.pkb/.pks/.sql files, scripts inside XML changelogs and, since
1.4.0, the Supporting Objects installation scripts of APEX exports, at their export lines) and follows the
statements of each routine (_flow). apex_context() then adds what the export says about the APEX components that
call the routine and their authorization schemes. A body it cannot follow (an
unexpected construct, or a check / access inside a nested sub-program) gets the earlier lexical answer: any
authorization-like call anywhere keeps the routine quiet, and a sibling counts when its first guard call comes before
its first access. Not modelled: GOTO, the value a check returns (`if can_view(…)` and `if not can_view(…)` are both
a check), whether a helper of the package calls the guard on all its own paths.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .plsql_frontend import blank_java_sources, blank_wrapped, tokenize, wrapped_units

RULE = "APX024"
MIN_ROUTINES = 3
MIN_SHARE = 0.6

_AUTH_EXACT = {"apex_authorization.is_authorized", "apex_util.public_check_authorization"}
_AUTH_WORD = re.compile(r"auth|access|privs?$|privileges?$|^privilege|permission|perms?$|allowed|^role|roles?$|acl$")
_ASSERT_PREFIX = re.compile(r"^(?:assert|check|require|verify|ensure)_(.+)$")
_ACCESS_RELATED = re.compile(r"user|admin|right|grant|owner|session|login|logged|acl|secur|sec$|role|priv|perm|access|"
                             r"auth|allow|can_|entitle|manager|member")
_KEYWORDS = {"if", "then", "else", "elsif", "end", "begin", "loop", "case", "when", "return", "and", "or", "not", "in",
             "is", "as", "null", "true", "false", "select", "from", "where", "into", "values", "insert", "update",
             "delete", "merge", "exception", "raise", "for", "while", "exit", "open", "fetch", "close", "declare",
             "commit", "rollback", "execute", "immediate", "using", "procedure", "function", "cursor", "type",
             "subtype", "pragma", "constant", "default", "out", "nocopy", "exists", "like", "between", "with", "set",
             "goto", "continue", "forall", "bulk", "collect", "limit", "returning", "distinct", "order", "group", "by",
             "having", "union", "all", "minus", "intersect", "join", "on", "left", "right", "inner", "outer", "full"}
_LOB_TYPES = {"blob", "clob", "nclob", "bfile", "xmltype"}
_STMT_START = {";", "begin", "then", "else", "loop", "is", "as", "exception"}


@dataclass
class Routine:
    name: str                   # lower case
    kind: str                   # procedure | function
    line: int                   # header line (absolute)
    returns: str = ""           # return type (lower case) of a function
    refs: list = field(default_factory=list)       # [(token index, canonical callee, local routine name or None)]
    own_sinks: list = field(default_factory=list)  # [(token index, kind, object)]
    reads: list = field(default_factory=list)      # [(token index, object)]
    return_pos: list = field(default_factory=list)  # token indexes of RETURN statements
    end: int = 0
    lines: dict = field(default_factory=dict)       # token index of each fact above (and of `end`) -> absolute line
    flow: tuple | None = None   # statement tree of the body for the path check (see _flow); None: lexical answer only


@dataclass
class Package:
    name: str
    rel: str
    line: int
    routines: list = field(default_factory=list)
    forward: set = field(default_factory=set)


def _looks_auth(canon: str) -> bool:
    """A callee name that reads as an authorization / access check (any case, schema-qualified or not)."""
    canon = canon.lower()
    if canon in _AUTH_EXACT:
        return True
    last = canon.rsplit(".", 1)[-1]
    if last.startswith("can_"):
        return True
    m = re.match(r"(?:is|has|user_has|user_is)_(.+)$", last)
    if m and re.search(r"admin|right|grant|owner|role|priv|perm|access|auth|allow|member|entitle", m.group(1)):
        return True
    m = _ASSERT_PREFIX.match(last)
    if m and _ACCESS_RELATED.search(m.group(1)):
        return True
    words = [w for part in canon.split(".") for w in part.split("_") if w]
    return any(_AUTH_WORD.search(w) for w in words) and not last.startswith(("get_", "set_", "log_", "write_"))


def _qualified(toks, j):
    """[schema.]name at j -> (last part, index after it)."""
    name = toks[j].val
    j += 1
    while toks[j].kind == "punct" and toks[j].val == "." and toks[j + 1].kind == "id":
        name = toks[j + 1].val
        j += 2
    return name, j


def _qualified_raw(toks, j) -> str:
    """[schema.]name at j -> the name as written (last part)."""
    raw = toks[j].raw or toks[j].val
    j += 1
    while toks[j].kind == "punct" and toks[j].val == "." and toks[j + 1].kind == "id":
        raw = toks[j + 1].raw or toks[j + 1].val
        j += 2
    return raw


def _header(toks, j):
    """At `procedure|function name …`: -> (kind, name, return type, index of IS/AS or ';', header line)."""
    kind, line = toks[j].val, toks[j].line
    name, j = _qualified(toks, j + 1)
    depth, ret = 0, ""
    while toks[j].kind != "eof":
        t = toks[j]
        if t.kind == "punct" and t.val == "(":
            depth += 1
        elif t.kind == "punct" and t.val == ")":
            depth -= 1
        elif depth == 0 and t.kind == "punct" and t.val == ";":
            break
        elif depth == 0 and t.kind == "id" and t.val in ("is", "as"):
            break
        elif depth == 0 and t.kind == "id" and t.val == "return" and not ret and toks[j + 1].kind == "id":
            ret = toks[j + 1].val
        j += 1
    return kind, name, ret, j, line


def _routine_end(toks, k):
    """First token after IS/AS of a routine -> index just after its closing `end [name];`."""
    depth, seen_begin = 0, False
    while toks[k].kind != "eof":
        t = toks[k]
        if t.kind == "id":
            v = t.val
            if depth == 0 and not seen_begin and v in ("procedure", "function"):
                k = _skip_subprogram(toks, k)
                continue
            if v == "end":
                nxt = toks[k + 1]
                if nxt.kind == "id" and nxt.val in ("if", "loop", "case"):
                    depth -= 1
                    k += 2
                    continue
                depth -= 1
                k += 1
                if depth <= 0 and seen_begin:
                    if toks[k].kind == "id" and toks[k + 1].kind == "punct" and toks[k + 1].val == ";":
                        k += 1
                    if toks[k].kind == "punct" and toks[k].val == ";":
                        k += 1
                    return k
                continue
            if v == "begin":
                if depth == 0:
                    seen_begin = True
                depth += 1
            elif v in ("if", "loop", "case"):
                depth += 1
        elif t.kind == "punct" and t.val == "/" and t.nl and toks[k + 1].nl and depth <= 0:
            return k                                     # SQL*Plus terminator: the unit is over whatever we counted
        k += 1
    return k


def _skip_subprogram(toks, k):
    _kind, _name, _ret, j, _line = _header(toks, k)
    if toks[j].kind != "id":                             # ';': forward declaration
        return j + 1
    j += 1
    if toks[j].kind == "id" and toks[j].val in ("language", "external", "mle"):
        while toks[j].kind != "eof" and not (toks[j].kind == "punct" and toks[j].val == ";"):
            j += 1
        return j + 1
    return _routine_end(toks, j)


def _skip_statement(toks, j):
    depth = 0
    while toks[j].kind != "eof":
        t = toks[j]
        if t.kind == "punct" and t.val == "(":
            depth += 1
        elif t.kind == "punct" and t.val == ")":
            depth -= 1
        elif depth <= 0 and t.kind == "punct" and t.val == ";":
            return j + 1
        j += 1
    return j


def _parse_spec(toks, j) -> tuple[set, int]:
    names, depth = set(), 0
    while toks[j].kind != "eof":
        t = toks[j]
        if t.kind == "punct" and t.val == "(":
            depth += 1
        elif t.kind == "punct" and t.val == ")":
            depth -= 1
        elif depth == 0 and t.kind == "id" and t.val in ("procedure", "function") and toks[j + 1].kind == "id":
            names.add(toks[j + 1].val)
        elif depth == 0 and t.kind == "id" and t.val == "end" and (
                (toks[j + 1].kind == "punct" and toks[j + 1].val == ";") or toks[j + 2].val == ";"):
            return names, j + 1
        j += 1
    return names, j


def _table_after(toks, j, end, word):
    """The object named after `word` (from / into / update …) in a statement starting at j."""
    k = j
    while k < end and k < j + 400:
        t = toks[k]
        if t.kind == "punct" and t.val == ";":
            return ""
        if t.kind == "id" and t.val == word and toks[k + 1].kind == "id" and toks[k + 1].val not in ("select", "with"):
            return _qualified_raw(toks, k + 1)
        k += 1
    return ""


def _analyse_body(toks, b, e, r: Routine, local_names: set, pkg: str):
    j = b
    sql_end = -1                 # inside a static SQL statement up to here: only name(…) is a call there
    while j < e:
        t = toks[j]
        if t.kind != "id":
            j += 1
            continue
        prev = toks[j - 1]
        if (prev.kind == "punct" and prev.val == ".") or (prev.kind == "id" and prev.val == "end"):
            j += 1                                       # part of a dotted name, or the name after `end`
            continue
        v = t.val
        nxt = toks[j + 1]
        if v in ("select", "insert", "update", "delete", "merge") and j > sql_end:
            sql_end = _skip_statement(toks, j)
        # ---- data access
        if v == "select":
            r.reads.append((j, _table_after(toks, j, e, "from")))
        elif v in ("open", "fetch") and prev.val in _STMT_START:
            r.reads.append((j, ""))
        elif v == "insert" and nxt.kind == "id" and nxt.val == "into":
            r.own_sinks.append((j, "dml", _table_after(toks, j, e, "into")))
        elif v == "merge" and nxt.kind == "id" and nxt.val == "into":
            r.own_sinks.append((j, "dml", _table_after(toks, j, e, "into")))
        elif v == "update" and nxt.kind == "id" and prev.val not in ("for", "of") and nxt.val not in ("of", "nowait"):
            r.own_sinks.append((j, "dml", _qualified_raw(toks, j + 1)))
        elif v == "delete" and nxt.kind == "id" and (nxt.val == "from" or prev.val in _STMT_START):
            r.own_sinks.append((j, "dml", _table_after(toks, j, e, "from") if nxt.val == "from" else _qualified_raw(toks, j + 1)))
        elif v == "execute" and nxt.kind == "id" and nxt.val == "immediate":
            r.own_sinks.append((j, "dynamic", ""))
        elif v == "return" and (prev.kind != "id" or prev.val in _STMT_START):
            r.return_pos.append(j)
        if v in _KEYWORDS:
            j += 1
            continue
        # ---- references to routines
        parts = [v]
        k = j + 1
        while toks[k].kind == "punct" and toks[k].val == "." and toks[k + 1].kind == "id":
            parts.append(toks[k + 1].val)
            k += 2
        after = toks[k]
        if after.kind == "punct" and after.val == ":=":
            j = k
            continue
        if len(parts) >= 3:
            parts = parts[-2:]                           # schema.package.routine
        local = None
        if len(parts) == 2 and parts[0] == pkg and parts[1] in local_names:
            local = parts[1]
        elif len(parts) == 1 and parts[0] in local_names:
            local = parts[0]
        canon = ".".join(parts)
        if local is not None:
            canon = local
        # a call: name(…), a routine of this package, a bare procedure call statement, or a parameterless function
        # in a condition (`if pkg.is_admin then`); dotted column references inside SQL are not calls
        if j < sql_end and not (after.kind == "punct" and after.val == "("):
            j = k                                        # a column, table or alias of the SQL statement
            continue
        call_like = (after.kind == "punct" and after.val == "(") or local is not None or (
            prev.val in _STMT_START and after.kind == "punct" and after.val == ";") or (
            len(parts) > 1 and prev.val in ("if", "elsif", "not", "and", "or") and after.val in ("then", "and", "or"))
        if call_like:
            r.refs.append((j, canon, local))
            if canon.startswith(("htp.", "wpg_docload.")):
                r.own_sinks.append((j, "output", canon))
            elif canon in ("dbms_sql.execute", "dbms_sql.parse"):
                r.own_sinks.append((j, "dynamic", ""))
        j = k


# ------------------------------------------------------------------------------------------------ statement tree
# The body of a routine as a small tree over token ranges, enough to ask "can this token be reached on a path that
# passes no guard call?":
#   ("s", lo, hi, leaves)        a statement (or an IF/WHEN condition, a loop header) over tokens [lo, hi); leaves:
#                                RETURN / RAISE / raise_application_error, nothing runs after it on that path
#   ("x",)                       an unconditional EXIT / CONTINUE: the rest of the loop body is not reached that way
#   ("seq", [nodes])
#   ("br", head, [(cond, body)], else_body | None, falls_through)   IF / ELSIF / ELSE and CASE (a CASE without ELSE
#                                raises CASE_NOT_FOUND when no WHEN matches, so it does not fall through)
#   ("loop", head, body)         LOOP / WHILE / FOR: the body may run zero times (or leave early)
#   ("blk", body, [(others, handler)])   BEGIN … EXCEPTION: a handler starts from any statement of the body that
#                                raises; a guard that fails raises too, but only WHEN OTHERS catches that
class _Bad(Exception):
    pass


_STOPS = {"end", "exception", "elsif", "else", "when"}


def _is(t, *vals) -> bool:
    return t.kind == "id" and t.val in vals


def _stmt_end(toks, j, e):
    """Index just after the `;` that ends the simple statement at j."""
    depth = 0
    while j < e:
        t = toks[j]
        if t.kind == "punct" and t.val == "(":
            depth += 1
        elif t.kind == "punct" and t.val == ")":
            depth -= 1
        elif depth <= 0 and t.kind == "punct" and t.val == ";":
            return j + 1
        j += 1
    raise _Bad


def _until(toks, j, e, word):
    """Index of the keyword `word` that ends the condition / header starting at j (CASE expressions skipped)."""
    depth = cases = 0
    while j < e:
        t = toks[j]
        if t.kind == "punct" and t.val == "(":
            depth += 1
        elif t.kind == "punct" and t.val == ")":
            depth -= 1
        elif t.kind == "punct" and t.val == ";" and depth <= 0:
            raise _Bad
        elif t.kind == "id" and depth <= 0:
            if t.val == "case":
                cases += 1
            elif t.val == "end" and cases:
                cases -= 1
            elif t.val == word and not cases:
                return j
        j += 1
    raise _Bad


def _close(toks, j, e, *words):
    """At `end [words]`: expect them, an optional label and `;` -> index after it."""
    if not _is(toks[j], "end"):
        raise _Bad
    j += 1
    for w in words:
        if not _is(toks[j], w):
            raise _Bad
        j += 1
    if toks[j].kind == "id" and toks[j + 1].kind == "punct" and toks[j + 1].val == ";":
        j += 1
    if not (toks[j].kind == "punct" and toks[j].val == ";"):
        raise _Bad
    if j >= e:
        raise _Bad
    return j + 1


def _decl(toks, j, e, nested):
    """Declarations up to the BEGIN of their block -> ([statement nodes], index of BEGIN)."""
    out = []
    while j < e:
        t = toks[j]
        if _is(t, "begin"):
            return out, j
        if _is(t, "procedure", "function"):
            k = _skip_subprogram(toks, j)
            nested.append((j, k))
            j = k
            continue
        if _is(t, "end"):
            raise _Bad
        k = _stmt_end(toks, j, e)
        out.append(("s", j, k, False))
        j = k
    raise _Bad


def _stmts(toks, j, e, nested):
    out = []
    while True:
        if j >= e:
            raise _Bad
        if _is(toks[j], *_STOPS):
            return ("seq", out), j
        node, j = _stmt(toks, j, e, nested)
        out.append(node)


def _block(toks, j, e, nested):
    """At BEGIN -> (("blk", body, handlers), index of its END)."""
    body, j = _stmts(toks, j + 1, e, nested)
    handlers = []
    if _is(toks[j], "exception"):
        j += 1
        while _is(toks[j], "when"):
            k = _until(toks, j + 1, e, "then")
            others = any(_is(toks[x], "others") for x in range(j + 1, k))
            h, j = _stmts(toks, k + 1, e, nested)
            handlers.append((others, h))
    if not _is(toks[j], "end"):
        raise _Bad
    return ("blk", body, handlers), j


def _stmt(toks, j, e, nested):
    t = toks[j]
    if t.kind == "punct" and t.val == "<<":                  # <<label>>
        while j < e and not (toks[j].kind == "punct" and toks[j].val == ">>"):
            j += 1
        return ("seq", []), j + 1
    if t.kind == "punct" and t.val == ";":
        return ("seq", []), j + 1
    v = t.val if t.kind == "id" else ""
    if v in ("begin", "declare"):
        decl = []
        if v == "declare":
            decl, j = _decl(toks, j + 1, e, nested)
        blk, j = _block(toks, j, e, nested)
        return ("seq", decl + [blk]), _close(toks, j, e)
    if v == "if":
        arms, other = [], None
        while True:
            k = _until(toks, j + 1, e, "then")
            cond = ("s", j, k + 1, False)
            body, j = _stmts(toks, k + 1, e, nested)
            arms.append((cond, body))
            if _is(toks[j], "elsif"):
                continue
            if _is(toks[j], "else"):
                other, j = _stmts(toks, j + 1, e, nested)
            return ("br", None, arms, other, True), _close(toks, j, e, "if")
    if v == "case":
        head = None
        if not _is(toks[j + 1], "when"):
            k = _until(toks, j + 1, e, "when")
            head, j = ("s", j, k, False), k
        else:
            j += 1
        arms, other = [], None
        while _is(toks[j], "when"):
            k = _until(toks, j + 1, e, "then")
            body, nj = _stmts(toks, k + 1, e, nested)
            arms.append((("s", j, k + 1, False), body))
            j = nj
        if not arms:
            raise _Bad
        if _is(toks[j], "else"):
            other, j = _stmts(toks, j + 1, e, nested)
        return ("br", head, arms, other, False), _close(toks, j, e, "case")
    if v in ("loop", "while", "for"):
        k = j if v == "loop" else _until(toks, j + 1, e, "loop")
        body, nj = _stmts(toks, k + 1, e, nested)
        return ("loop", ("s", j, k + 1, False), body), _close(toks, nj, e, "loop")
    k = _stmt_end(toks, j, e)
    if v in ("exit", "continue") and (k == j + 2 or (k == j + 3 and toks[j + 1].kind == "id" and toks[j + 1].val != "when")):
        return ("x",), k
    name, n = v, j + 1
    while toks[n].kind == "punct" and toks[n].val == "." and toks[n + 1].kind == "id":
        name, n = toks[n + 1].val, n + 2
    leaves = v in ("return", "raise") or name == "raise_application_error"
    return ("s", j, k, leaves), k


def _flow(toks, b, e):
    """Statement tree of a routine body (tokens [b, e) after its IS / AS) -> (tree, index of the END of its main
    block, [(lo, hi)] of nested sub-programs); None when the body does not parse (the check is lexical then)."""
    try:
        nested: list = []
        decl, j = _decl(toks, b, e, nested)
        blk, j = _block(toks, j, e, nested)
        return ("seq", decl + [blk]), j, nested
    except (_Bad, IndexError, RecursionError):
        return None


def _unguarded(r: Routine, guards, accesses):
    """Token positions in accesses that some path from the start of r reaches without passing a position in guards
    (a guard anywhere in a statement or condition covers that statement); [] when every path passes a guard first;
    None when that is not known (the body did not parse, or a position is inside a nested sub-program)."""
    if r.flow is None:
        return None
    tree, main_end, nested = r.flow
    guards, accesses = set(guards), set(accesses)
    events = guards | accesses
    if any(lo <= p < hi for p in events for lo, hi in nested):
        return None
    seen, hits = set(), []
    raising: list = []                  # per enclosing BEGIN … EXCEPTION: [a free statement may raise, a free
                                        # non-guard statement may raise]

    def run(node, free):                 # free: some path reaches this point without having passed a guard
        tag = node[0]
        if tag == "s":
            _t, lo, hi, leaves = node
            here = [p for p in events if lo <= p < hi]
            seen.update(here)
            guarded = any(p in guards for p in here)
            if free:
                for flags in raising:
                    flags[0] = True
                    flags[1] = flags[1] or not guarded
            if guarded:
                free = False
            elif free:
                hits.extend(p for p in here if p in accesses)
            return False if leaves else free
        if tag == "x":
            return False
        if tag == "seq":
            for n in node[1]:
                free = run(n, free)
            return free
        if tag == "br":
            _t, head, arms, other, falls = node
            if head is not None:
                free = run(head, free)
            outs = []
            for cond, body in arms:
                free = run(cond, free)
                outs.append(run(body, free))
            if other is not None:
                outs.append(run(other, free))
            elif falls:
                outs.append(free)
            return any(outs)
        if tag == "loop":
            free = run(node[1], free)
            return run(node[2], free) or free
        if tag == "blk":
            flags = [False, False]
            raising.append(flags)
            try:
                outs = [run(node[1], free)]
            finally:
                raising.pop()
            outs.extend(run(h, flags[0] if others else flags[1]) for others, h in node[2])
            return any(outs)
        raise _Bad

    try:
        end_free = run(tree, True)
    except (_Bad, RecursionError):
        return None
    if any(p not in seen and p < main_end for p in events):
        return None
    if end_free:
        hits.extend(p for p in accesses if p >= main_end)
    return sorted(set(hits))


def _parse_body(toks, j, pkg: str, rel: str, line: int, delta: int) -> tuple[Package, int]:
    p = Package(pkg, rel, line + delta)
    spans = []
    while toks[j].kind != "eof":
        t = toks[j]
        if t.kind == "id" and t.val in ("procedure", "function"):
            kind, name, ret, k, hline = _header(toks, j)
            if toks[k].kind != "id":                     # forward declaration
                p.forward.add(name)
                j = k + 1
                continue
            k += 1
            if toks[k].kind == "id" and toks[k].val in ("language", "external", "mle"):
                j = _skip_statement(toks, k)
                continue
            end = _routine_end(toks, k)
            spans.append((Routine(name, kind, hline + delta, ret, end=end), k, end))
            j = end
            continue
        if t.kind == "id" and t.val in ("begin", "end"):
            j = _routine_end(toks, j) if t.val == "begin" else _skip_statement(toks, j)
            break
        if t.kind == "punct" and t.val == "/" and t.nl and toks[j + 1].nl:
            break
        j = _skip_statement(toks, j)
    names = {r.name for r, _b, _e in spans}
    for r, b, e in spans:
        _analyse_body(toks, b, e, r, names, pkg)
        r.flow = _flow(toks, b, e)
        for pos in [x[0] for x in r.refs + r.own_sinks + r.reads] + r.return_pos:
            r.lines[pos] = toks[pos].line + delta
        r.lines[e] = toks[max(b, e - 1)].line + delta
        p.routines.append(r)
    return p, j


def collect(text: str, rel: str, delta: int = 0) -> tuple[dict, list]:
    """Package specs ({name: {routine names}}) and package bodies (Package) of one plain PL/SQL text."""
    specs: dict = {}
    bodies: list = []
    if not re.search(r"\bpackage\b", text, re.I):
        return specs, bodies
    try:
        src = blank_java_sources(text)
        if wrapped_units(src):
            src = blank_wrapped(src)
        toks = tokenize(src)
        i = 0
        while toks[i].kind != "eof":
            t = toks[i]
            if not (t.kind == "id" and t.val == "create"):
                i += 1
                continue
            j = i + 1
            while toks[j].kind == "id" and toks[j].val in ("or", "replace", "editionable", "noneditionable", "force",
                                                           "noforce"):
                j += 1
            if not (toks[j].kind == "id" and toks[j].val == "package"):
                i = j
                continue
            j += 1
            is_body = toks[j].kind == "id" and toks[j].val == "body"
            if is_body:
                j += 1
            if toks[j].kind != "id":
                i = j
                continue
            name, j = _qualified(toks, j)
            while toks[j].kind != "eof" and not (toks[j].kind == "id" and toks[j].val in ("is", "as")) \
                    and not (toks[j].kind == "punct" and toks[j].val == ";"):
                j += 1
            if toks[j].kind != "id":
                i = j
                continue
            if is_body:
                pkg, i = _parse_body(toks, j + 1, name, rel, t.line, delta)
                bodies.append(pkg)
            else:
                names, i = _parse_spec(toks, j + 1)
                specs.setdefault(name, set()).update(names)
    except (IndexError, RecursionError):                 # malformed text: no finding rather than a failed scan
        return specs, bodies
    return specs, bodies


# ------------------------------------------------------------------------------------------------ the check
class _Pkg:
    """One package body with the guard-dependent facts of its routines."""

    def __init__(self, pkg: Package, public: set):
        self.pkg = pkg
        self.public = [r for r in pkg.routines if r.name in public]
        self.callers: dict = {}                          # routine name -> names of the routines that call it
        for r in pkg.routines:
            for _p, _c, loc in r.refs:
                if loc is not None and loc != r.name:
                    self.callers.setdefault(loc, set()).add(r.name)
        self.own: dict = {}                              # id(routine) -> its own sinks (see sinks())
        for r in pkg.routines:
            s = list(r.own_sinks)
            if r.reads:                                  # where what was read can leave: each RETURN after the
                first_read = min(p for p, _o in r.reads)  # first read, and the end of a procedure (OUT parameters)
                rets = [p for p in r.return_pos if p > first_read]
                obj = next((o for _p, o in r.reads if o), "")
                if r.kind != "function" or not rets:
                    rets.append(r.end)
                s.extend((p, "read", obj) for p in rets)
            self.own[id(r)] = s

    def _closure(self, seeds: set, stop: set = frozenset()) -> set:
        """seeds plus every routine that calls one of them, transitively (not through names in stop)."""
        out, todo = set(seeds), list(seeds)
        while todo:
            for caller in self.callers.get(todo.pop(), ()):
                if caller not in out and caller not in stop:
                    out.add(caller)
                    todo.append(caller)
        return out

    def reach(self, is_guard) -> set:
        """Names of the package's routines that call a guard (is_guard(canonical name)), directly or transitively."""
        return self._closure({r.name for r in self.pkg.routines if any(is_guard(c) for _p, c, _l in r.refs)})

    def guard_positions(self, r: Routine, is_guard, reached: set) -> list:
        return [p for p, c, loc in r.refs if is_guard(c) or (loc is not None and loc in reached and loc != r.name)]

    def sinks(self, reached: set) -> dict:
        """Routine id -> [(position, kind, object)] where it returns, changes or sends data: its own sinks (the end
        of the work of a routine that reads: its first RETURN after the first read, else its end), and calls to
        routines of the package that access data and never reach the guard."""
        seeds = {r.name for r in self.pkg.routines if self.own[id(r)] and r.name not in reached}
        unguarded = self._closure(seeds, stop=reached)
        return {id(r): self.own[id(r)] + [(p, "via", loc) for p, _c, loc in r.refs if loc in unguarded and loc != r.name]
                for r in self.pkg.routines}


def _guard_candidates(pkg: Package) -> set:
    out = set()
    for r in pkg.routines:
        for _p, c, _loc in r.refs:
            if _looks_auth(c):
                out.add(c)
    return out


def _covered(r: Routine, guards: list, sinks: list) -> bool:
    """Every path to every data access of r passes a guard position first (lexically: the first guard comes before
    the first access, when the body could not be followed path by path)."""
    left = _unguarded(r, guards, [p for p, _k, _o in sinks])
    if left is None:
        return min(guards) < min(p for p, _k, _o in sinks)
    return not left


def _evaluate(view: _Pkg, guard: str):
    def is_guard(c):
        return c == guard
    reached = view.reach(is_guard)
    sinks = view.sinks(reached)
    relevant, checked = [], []
    for r in view.public:
        if r.name == guard or _looks_auth(r.name):
            continue
        s = sinks[id(r)]
        gp = view.guard_positions(r, is_guard, reached)
        if not s and not gp:
            continue
        relevant.append(r)
        if gp and (not s or _covered(r, gp, s)):
            checked.append(r)
    return relevant, checked, sinks


def _describe(r: Routine, sinks: list) -> tuple[str, str, list]:
    """(Arabic phrase, English phrase, objects) for what an unchecked routine accesses; the most sensitive first."""
    kinds = {k for _p, k, _o in sinks}
    objs: list = []
    for _p, k, o in sinks:
        if o and o not in objs and k != "output":
            objs.append(o)
    lob = r.returns.lower() if r.kind == "function" and r.returns.lower() in _LOB_TYPES else ""
    if "read" in kinds and r.kind == "function" and lob:
        ar, en = f"يُعيد قيمة {lob.upper()} مقروءة باستعلام", f"returns a {lob.upper()} value read by a query"
    elif "read" in kinds and r.kind == "function":
        ar, en = "يُعيد بيانات مقروءة باستعلام", "returns data read by a query"
    elif "output" in kinds:
        ar, en = "يكتب بيانات إلى المتصفح (htp / wpg_docload)", "writes data to the browser (htp / wpg_docload)"
    elif "dml" in kinds:
        ar, en = "يعدّل البيانات (DML)", "changes data (DML)"
    elif "dynamic" in kinds:
        ar, en = "ينفّذ SQL ديناميكيًا", "runs dynamic SQL"
    elif "read" in kinds:
        ar, en = "يقرأ البيانات باستعلام", "reads data with a query"
    else:
        helper = next(o for _p, k, o in sinks if k == "via")
        ar, en = f"يستدعي {helper} الذي يصل إلى البيانات دون تحقق", f"calls {helper}, which accesses data without a check"
        objs = []
    return ar, en, [o for o in objs if re.fullmatch(r"[\w$#.]+", o)][:3]


def findings(specs: dict, bodies: list, lines_by_file: dict) -> list:
    """APX024 findings over every package body of the scan (specs may come from any file)."""
    from .apex_export import CONFIG_RULES, _finding
    out = []
    sev, cwe, title, title_ar, _adv = CONFIG_RULES[RULE]
    for pkg in bodies:
        if len(pkg.routines) < MIN_ROUTINES:
            continue
        names = {r.name for r in pkg.routines}
        if pkg.name in specs:
            public = specs[pkg.name] & names
        else:
            called = {loc for r in pkg.routines for _p, _c, loc in r.refs if loc is not None and loc != r.name}
            public = names - called - pkg.forward
        if len(public) < MIN_ROUTINES + 1:
            continue
        view = _Pkg(pkg, public)
        best = None
        for g in sorted(_guard_candidates(pkg)):
            relevant, checked, sinks = _evaluate(view, g)
            if len(checked) >= MIN_ROUTINES and len(checked) >= MIN_SHARE * len(relevant):
                # the most routines; on a tie the check they call themselves (hdr_ui.check_access), not the one it wraps
                direct = sum(1 for r in checked if any(c == g for _p, c, _loc in r.refs))
                if best is None or (len(checked), direct) > best[0]:
                    best = ((len(checked), direct), g, relevant, checked, sinks)
        if best is None:
            continue
        _score, guard, relevant, checked, sinks = best
        any_auth = view.reach(_looks_auth)
        done = {id(x) for x in checked}
        for r in view.public:
            if id(r) in done or r.name == guard or _looks_auth(r.name):
                continue
            s = sinks[id(r)]
            if not s:
                continue                                 # pure computation: nothing to protect
            # any authorization-like call, of the package's guard or another, directly or through a package routine
            own_checks = [p for p, c, loc in r.refs if _looks_auth(c) or (loc is not None and loc in any_auth and loc != r.name)]
            gap = None
            if own_checks:
                left = _unguarded(r, own_checks, [p for p, _k, _o in s])
                if not left:                             # every path is checked, or not known: the lexical answer
                    continue
                gap = r.lines.get(left[0], r.line)
                s = [x for x in s if x[0] in left]
            ar, en, objs = _describe(r, s)
            where_ar = ar + (f" ({', '.join(objs)})" if objs else "")
            where_en = en + (f" ({', '.join(objs)})" if objs else "")
            rname = f"{pkg.name}.{r.name}".upper()
            gname = guard.upper() if "." in guard else f"{pkg.name}.{guard}".upper()
            k, n = len(checked), len(relevant)
            if gap is None:
                advice = (f"{rname} لا يتحقق من الصلاحية، بينما تستدعي {k} من {n} من الروتينات العامة في الحزمة "
                          f"{gname} قبل عملها. وهو {where_ar}. أضف التحقق نفسه ({gname}) في بدايته كما تفعل الروتينات "
                          f"الشقيقة؛ فأي كود في المخطط نفسه (صفحة APEX أخرى مثلًا) يمكنه استدعاؤه مباشرة.")
            else:
                advice = (f"{rname} يتحقق من الصلاحية في بعض المسارات فقط: يمكن الوصول إلى البيانات في السطر {gap} دون "
                          f"المرور بالتحقق، بينما تستدعي {k} من {n} من الروتينات العامة في الحزمة {gname} قبل عملها. "
                          f"وهو {where_ar}. اجعل التحقق ({gname}) قبل كل وصول إلى البيانات، في بدايته أو في شرط يخرج "
                          f"من الروتين (raise أو return) حين يفشل، لا في فرع واحد أو في معالج استثناء أو بعد الوصول.")
            lines = lines_by_file.get(pkg.rel) or []
            snippet = lines[r.line - 1] if 0 < r.line <= len(lines) else f"{r.kind} {r.name}"
            f = _finding(RULE, sev, title, title_ar, pkg.rel, r.line, snippet, advice, cwe, "")
            f.extra.update({"confidence": "tentative", "package": pkg.name.upper(), "routine": r.name.upper(),
                            "guard": gname, "guarded_siblings": k, "siblings": n, "accesses": where_en,
                            "spec_seen": pkg.name in specs, "coverage": "none" if gap is None else "partial",
                            "unguarded_line": gap})
            out.append(f)
    return out


# ------------------------------------------------------------------------- what APEX itself enforces (1.4.0)
_CODE_KINDS = ("plsql", "plsql_decls", "plsql_fn", "plsql_fn_sql", "plsql_fn_html", "plsql_expr", "sql")


def apex_context(found: list, sites: list, sec: dict) -> None:
    """Add to each APX024 finding what the scanned APEX export(s) say about the routine's callers: the components
    (page processes, region sources, AJAX callbacks / application processes, dynamic action server code, …) that
    call PACKAGE.ROUTINE and whether an authorization scheme protects each (component, page or application scheme;
    MUST_NOT_BE_PUBLIC_USER and negated schemes do not count).

    Every call site protected: the finding stays as it is, and says that the protection covers only those callers.
    Some call site unprotected (public page, component without a scheme, application process without one): the
    finding names it and its severity becomes high. No call site in the scan: unchanged.
    sites: [(rel, apex_export.Block, application id)]; sec: application id -> {app_scheme, schemes, pages}."""
    from .apex_export import call_site_protection, call_sites
    if not found or not sites:
        return
    for f in found:
        pkg, routine = str(f.extra.get("package") or ""), str(f.extra.get("routine") or "")
        if not pkg or not routine:
            continue
        calls = []
        for rel, b, app in sites:
            if b.kind not in _CODE_KINDS or routine.lower() not in b.code.lower():
                continue
            lines = call_sites(b, pkg, routine)
            if not lines:
                continue
            prot, what = call_site_protection(b, sec.get(app, {}))
            for ln in lines:
                calls.append({"component": b.label, "file": rel, "line": ln, "protected": prot,
                              ("scheme" if prot else "reason"): what})
        if not calls:
            continue
        calls.sort(key=lambda c: (c["file"], c["line"]))
        rname = f"{pkg}.{routine}"
        n = len(calls)
        open_ = [c for c in calls if not c["protected"]]
        f.extra["apex_call_sites"] = calls
        if open_:
            u = open_[0]
            f.extra["apex_protection"] = "unprotected"
            f.extra["severity_before_apex"] = f.severity
            f.severity = "high"
            f.advice += (f" ويُستدعى {rname} في تطبيق APEX المفحوص من مكوّن غير محمي: «{u['component']}» في السطر "
                         f"{u['line']} من {u['file']} ({u['reason']})؛ المواضع غير المحمية {len(open_)} من {n}. فيمكن لأي "
                         f"مستخدم يصل إلى هذا المكوّن تشغيل الروتين دون تحقق، ولذلك رُفعت الخطورة إلى «عالية».")
        else:
            names = []
            for c in calls:
                if c["scheme"] not in names:
                    names.append(c["scheme"])
            first = calls[0]
            f.extra["apex_protection"] = "all_protected"
            f.extra["apex_schemes"] = names
            f.advice += (f" وفي تطبيق APEX المفحوص لا يُستدعى {rname} إلا من مكوّنات محمية بمخطط التفويض "
                         f"{', '.join(names)} (مواضع الاستدعاء: {n}، أولها «{first['component']}» في السطر "
                         f"{first['line']} من {first['file']})؛ لكن هذه الحماية لا تشمل أي مستدعٍ آخر للحزمة (صفحة "
                         f"أخرى أو تطبيق آخر أو صلاحية EXECUTE ممنوحة مباشرة)، فيبقى التحقق داخل الروتين لازمًا.")
