"""Missing authorization check inconsistent with sibling routines (APX024, CWE-862).  (vulnscan: ignore-file)

A PL/SQL package whose public routines check the caller's authorization themselves (they call the package's access
check, `apex_authorization.is_authorized`, …) but where one public routine that reads, changes or sends data does
not: any code in the same schema (another APEX page, a job, a REST handler) can call that routine directly, whatever
the application around it checks first.

The rule is about inconsistency, not a guess that every routine needs a check, and it stays conservative:

1. Public routines: the ones the package spec declares when the scan holds it (any file); without a spec, the body's
   routines minus those other routines of the package call (private helpers) and those declared forward in the body.
2. The guard: a call whose name looks like an authorization / access check, called (directly or through routines
   of the same package) before the first data access in the code by at least 3 public routines and by at least 60%
   of the public routines that access data or call it (the 1.3 criterion: a sibling that checks on some paths only
   still shows which check the package uses, and is reported itself). No guard: no finding. The message gives that
   count and how many of those siblings the guard covers on every path.
3. Flagged: a public routine that reads data with a query and can return it, changes data (DML, dynamic SQL) or
   writes to the browser (htp, wpg_docload), itself or through a routine of the package that does so unchecked, and
   where some path reaches that access without passing an authorization-like call (the package's guard or another):
   no such call at all ("none"), or one only in a branch of IF / ELSIF / CASE or of a `$if` (conditional
   compilation), in a loop, in an exception handler, after the access, skipped by a GOTO ("partial", with the line).
   A check called as a statement (`check_access('X');`) covers what follows; a check whose answer is a value
   (`can_view(…)`, `apex_authorization.is_authorized(…)`) covers the statement it is in and, through a condition,
   either the branch that runs only when it passed (`if can_view(…) then`, `= TRUE`, `!= FALSE`, `= 'Y'`, `> 0`) or
   what follows when the branch that runs whenever it failed leaves the routine (`if not can_view(…) then raise…`,
   `= FALSE`, `!= TRUE`, `NOT (…)`, `NVL(…, FALSE) = FALSE`, `= 'N'`, `… OR x`, `CASE WHEN NOT …`), also through a
   variable that holds the answer (1.5.0: the condition is parsed with AND / OR / NOT / comparisons; `not can_view(…)
   and x`, `can_view(…) or x` and a comparison with another expression guard nothing; only the call itself, a
   variable holding its answer, or NVL / COALESCE of one with a failing default (FALSE / 0 / 'N') carries the
   answer, not NVL(…, 'Y'), GREATEST, arithmetic or DECODE; of the orderings only > 0 / >= 1 pass and <= 0 / < 1
   fail); an answer
   nobody acts on covers nothing. RETURN / RAISE / raise_application_error end their path. A read
   counts where what was read can leave the routine (each RETURN of a non-constant after it, the end of a
   procedure), so querying the row's owner before the check is fine. Pure computation is never flagged.
4. A routine of the package is a check itself (a call to it covers like a guard call; an authorization-like name
   that calls an authorization check on some of its paths only does not count either) only when every path to its
   normal exit (the end of a procedure, a RETURN of anything but FALSE / NULL / 0 / 'N') passes the guard (1.5.0,
   _Pkg.covering); a helper that calls it on some paths only covers nothing, and the message says so.

The analysis reads tokens of plain PL/SQL (.pkb/.pks/.sql files, scripts inside XML changelogs and the Supporting
Objects installation, upgrade and deinstallation scripts of APEX exports, at their export lines) and follows the
statements of each routine (_flow). apex_context() then adds what the export says about the APEX components that
call the routine and their authorization schemes (through synonyms, schema-qualified names, constant dynamic SQL,
Invoke API processes and other package routines; see there). A body it cannot follow (an unexpected construct, a
check or access inside a nested sub-program, a GOTO backwards) gets the lexical answer: any authorization-like call
anywhere keeps the routine quiet. Not modelled: SQL NULL answers (`if not can_view(…)` with a NULL answer skips the
branch), an exception raised before the check that a handler other than WHEN OTHERS catches is assumed possible;
the guard is still elected as in 1.3 (a sibling counts when its first call to the guard, or to a helper reaching
it on any path, comes before its first data access in the code).
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
    exits: list = field(default_factory=list)       # RETURN statements that can report success (all but
    #                                                 `return false / null / 0 / 'N';`): the helper check (_Pkg.covering)
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
                (toks[j + 1].kind == "punct" and toks[j + 1].val == ";") or (toks[j + 2].val == ";" and toks[j + 1].val != "if")):
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
            const = toks[j + 2].kind == "punct" and toks[j + 2].val == ";" and (
                nxt.kind in ("num", "str") or (nxt.kind == "id" and nxt.val in ("null", "true", "false")))
            if not const:
                r.return_pos.append(j)                   # `return null;` / `return 0;` gives nothing away
            if not (const and (nxt.val in ("null", "false") or nxt.val.strip().lower() in _FALSY)):
                r.exits.append(j)
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
#   ("s", lo, hi, leaves, var)   a statement or declaration over tokens [lo, hi); leaves: RETURN / RAISE /
#                                raise_application_error, nothing runs after it on that path; var: the variable it
#                                assigns (`l_ok := can_view(…)`, `l_ok boolean := …`), or None
#   ("c", lo, hi, expr)          an IF / ELSIF / WHEN condition or a loop header; expr its boolean structure
#                                (_parse_or), None when it does not parse
#   ("x",)                       an unconditional EXIT / CONTINUE: the rest of the loop body is not reached that way
#   ("lbl", name) / ("goto", name)
#   ("seq", [nodes])
#   ("br", head, [(cond, body)], else_body | None, falls_through)   IF / ELSIF / ELSE and CASE (a CASE without ELSE
#                                raises CASE_NOT_FOUND when no WHEN matches, so it does not fall through); a `$if`
#                                of conditional compilation is an IF whose condition is unknown (plsql_frontend)
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


def _simple(toks, lo, hi, leaves=False, decl=False):
    """A statement node; var: what `var := …` (or a declaration `var type := …`) assigns."""
    var = None
    if toks[lo].kind == "id":
        if toks[lo + 1].kind == "punct" and toks[lo + 1].val == ":=":
            var = toks[lo].val
        elif decl and any((t.kind == "punct" and t.val == ":=") or _is(t, "default") for t in toks[lo + 1:hi]):
            var = toks[lo].val
    return ("s", lo, hi, leaves, var)


_CMP_OPS = {"=", "!=", "<>", "^=", "~=", "<", ">", "<=", ">="}
_TRUTHY = {"true", "y", "yes", "t", "1"}
_FALSY = {"false", "n", "no", "f", "0"}


def _cond(toks, lo, hi):
    """An IF / ELSIF / WHEN condition or a loop header over tokens [lo, hi) (its keyword .. THEN / LOOP) -> ("c",
    lo, hi, expr), expr the boolean structure the path check needs (see _parse_cond); None when it does not parse."""
    try:
        k = lo + 1 if toks[lo].kind == "id" and toks[lo].val in ("if", "elsif", "when", "while") else lo
        end = hi - 1 if hi - 1 > k and toks[hi - 1].kind == "id" and toks[hi - 1].val in ("then", "loop") else hi
        expr, j = _parse_or(toks, k, end)
        if j != end:
            expr = None
    except (_Bad, IndexError, RecursionError):
        expr = None
    return ("c", lo, hi, expr)


# A condition as a tree: ("or", [e…]) / ("and", [e…]) / ("not", e) / ("cmp", e, op, e, lit_left, lit_right) /
# ("atom", lo, hi, names, flags). lit_*: "T" / "F" for a literal TRUE / FALSE / 'Y' / 'N' / 1 / 0, "X" for another
# literal, None for an expression. shape: see _shape (only a bare call / name, or nvl of one with a failing
# default, can carry the check's answer).
def _parse_or(toks, j, e):
    a, j = _parse_and(toks, j, e)
    items = [a]
    while j < e and _is(toks[j], "or"):
        b, j = _parse_and(toks, j + 1, e)
        items.append(b)
    return (items[0] if len(items) == 1 else ("or", items)), j


def _parse_and(toks, j, e):
    a, j = _parse_not(toks, j, e)
    items = [a]
    while j < e and _is(toks[j], "and"):
        b, j = _parse_not(toks, j + 1, e)
        items.append(b)
    return (items[0] if len(items) == 1 else ("and", items)), j


def _parse_not(toks, j, e):
    if j < e and _is(toks[j], "not"):
        x, j = _parse_not(toks, j + 1, e)
        return ("not", x), j
    left, j = _parse_primary(toks, j, e)
    if j < e and toks[j].kind == "punct" and toks[j].val in _CMP_OPS:
        op = toks[j].val
        right, j = _parse_primary(toks, j + 1, e)
        return ("cmp", left, op, right, _literal(left, toks), _literal(right, toks)), j
    return left, j


def _parse_primary(toks, j, e):
    if j >= e:
        raise _Bad
    if toks[j].kind == "punct" and toks[j].val == "(":
        inner, k = _parse_or(toks, j + 1, e)
        if k < e and toks[k].kind == "punct" and toks[k].val == ")":
            return inner, k + 1
        # not a parenthesised condition (a row constructor, `(a, b) in …`): an atom from here
    lo, depth, between = j, 0, False
    while j < e:
        t = toks[j]
        if t.kind == "punct" and t.val == "(":
            depth += 1
        elif t.kind == "punct" and t.val == ")":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0:
            if t.kind == "punct" and t.val in _CMP_OPS:
                break
            if t.kind == "id" and t.val == "between":
                between = True
            elif t.kind == "id" and t.val == "and" and between:
                between = False
            elif t.kind == "id" and t.val in ("and", "or"):
                break
        j += 1
    if j == lo:
        raise _Bad
    names = frozenset(toks[x].val for x in range(lo, j) if toks[x].kind == "id")
    return ("atom", lo, j, names, _shape(toks, lo, j)), j


def _call_end(toks, lo, hi):
    """`name[.name…][(balanced args)]` starting at lo -> index after it (≤ hi), or None."""
    if toks[lo].kind != "id":
        return None
    k = lo + 1
    while k + 1 < hi and toks[k].kind == "punct" and toks[k].val == "." and toks[k + 1].kind == "id":
        k += 2
    if k < hi and toks[k].kind == "punct" and toks[k].val == "(":
        depth = 0
        while k < hi:
            if toks[k].kind == "punct" and toks[k].val == "(":
                depth += 1
            elif toks[k].kind == "punct" and toks[k].val == ")":
                depth -= 1
                if depth == 0:
                    return k + 1
            k += 1
        return None
    return k


def _shape(toks, lo, hi):
    """What an atom of a condition is, for the check's polarity (1.5.0): ("call", lo) a call or a name alone (the
    check itself, or a variable holding its answer, when that is what lo is), ("nvl", lo) nvl / coalesce of such a
    call or name with a default that counts as FAILING (FALSE / 0 / 'N'), or None: anything else (nvl(…, 'Y'),
    greatest(…), arithmetic, decode(…), nvl(x, <expression>)) says nothing about which way the check went."""
    if _call_end(toks, lo, hi) == hi:
        if toks[lo].val in ("nvl", "coalesce") and hi - lo >= 6 and toks[lo + 1].val == "(":
            inner = _call_end(toks, lo + 2, hi - 1)
            if inner is not None and inner + 2 == hi - 1 and toks[inner].kind == "punct" and toks[inner].val == "," \
                    and _literal(("atom", inner + 1, inner + 2), toks) in ("F", "0"):
                return ("nvl", lo + 2, toks[lo + 2].val if inner == lo + 3 else None)
            return None
        return ("call", lo, toks[lo].val if hi == lo + 1 else None)
    return None


def _literal(node, toks):
    if node[0] != "atom" or node[2] - node[1] != 1:
        return None
    t = toks[node[1]]
    if t.kind == "id" and t.val in ("true", "false"):
        return "T" if t.val == "true" else "F"
    if t.kind == "num" and t.val.strip() in ("0", "1"):
        return t.val.strip()                         # "0" / "1": a number of the check (see polarity)
    if t.kind in ("num", "str"):
        v = t.val.strip().lower()
        return "T" if v in _TRUTHY else "F" if v in _FALSY else "X"
    return None


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
        if _is(t, "if"):                                 # `$if` of conditional compilation around declarations
            node, j = _stmt(toks, j, e, nested, decl=True)
            out.append(node)
            continue
        if _is(t, "end"):
            raise _Bad
        k = _stmt_end(toks, j, e)
        out.append(_simple(toks, j, k, decl=True))
        j = k
    raise _Bad


def _stmts(toks, j, e, nested, decl=False):
    out = []
    while True:
        if j >= e:
            raise _Bad
        if _is(toks[j], *_STOPS):
            return ("seq", out), j
        node, j = _stmt(toks, j, e, nested, decl)
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


def _stmt(toks, j, e, nested, decl=False):
    t = toks[j]
    if t.kind == "punct" and t.val == "<<":                  # <<label>>
        name = toks[j + 1].val
        while j < e and not (toks[j].kind == "punct" and toks[j].val == ">>"):
            j += 1
        return ("lbl", name), j + 1
    if t.kind == "punct" and t.val == ";":
        return ("seq", []), j + 1
    v = t.val if t.kind == "id" else ""
    if v in ("begin", "declare"):
        decls = []
        if v == "declare":
            decls, j = _decl(toks, j + 1, e, nested)
        blk, j = _block(toks, j, e, nested)
        return ("seq", decls + [blk]), _close(toks, j, e)
    if v == "if":
        arms, other = [], None
        while True:
            k = _until(toks, j + 1, e, "then")
            cond = _cond(toks, j, k + 1)
            body, j = _stmts(toks, k + 1, e, nested, decl)
            arms.append((cond, body))
            if _is(toks[j], "elsif"):
                continue
            if _is(toks[j], "else"):
                other, j = _stmts(toks, j + 1, e, nested, decl)
            return ("br", None, arms, other, True), _close(toks, j, e, "if")
    if decl:
        k = _stmt_end(toks, j, e)
        return _simple(toks, j, k, decl=True), k
    if v == "case":
        head = None
        if not _is(toks[j + 1], "when"):
            k = _until(toks, j + 1, e, "when")
            head, j = _simple(toks, j, k), k
        else:
            j += 1
        arms, other = [], None
        while _is(toks[j], "when"):
            k = _until(toks, j + 1, e, "then")
            body, nj = _stmts(toks, k + 1, e, nested)
            arms.append((_cond(toks, j, k + 1), body))
            j = nj
        if not arms:
            raise _Bad
        if _is(toks[j], "else"):
            other, j = _stmts(toks, j + 1, e, nested)
        return ("br", head, arms, other, False), _close(toks, j, e, "case")
    if v in ("loop", "while", "for"):
        k = j if v == "loop" else _until(toks, j + 1, e, "loop")
        body, nj = _stmts(toks, k + 1, e, nested)
        return ("loop", _cond(toks, j, k + 1), body), _close(toks, nj, e, "loop")
    k = _stmt_end(toks, j, e)
    if v in ("exit", "continue") and (k == j + 2 or (k == j + 3 and toks[j + 1].kind == "id" and toks[j + 1].val != "when")):
        return ("x",), k
    if v == "goto" and k == j + 3 and toks[j + 1].kind == "id":
        return ("goto", toks[j + 1].val), k
    name, n = v, j + 1
    while toks[n].kind == "punct" and toks[n].val == "." and toks[n + 1].kind == "id":
        name, n = toks[n + 1].val, n + 2
    return _simple(toks, j, k, leaves=v in ("return", "raise") or name == "raise_application_error"), k


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
    """Token positions in accesses that some path from the start of r reaches without passing a check; [] when
    every path passes one first; None when that is not known (the body did not parse, a position is inside a nested
    sub-program, a GOTO goes back).

    guards are positions of calls to a check. A call that is a statement of its own (`check_access('X');`, a
    procedure that raises when it fails) covers what follows. A call inside an expression (a function returning the
    answer) covers the statement it is in, and through a condition: `if not can_view(…) then <leaves> end if;` covers
    what follows (the failing branch leaves the routine), `if can_view(…) then <access> end if;` covers its branch.
    Its result in a variable (`l_ok := can_view(…)`) counts where a condition tests the variable. A result nobody
    tests (`l_ok := can_view(…);` alone, `if not can_view(…) then null; end if;`) covers nothing after it."""
    if r.flow is None:
        return None
    tree, main_end, nested = r.flow
    guards, accesses = set(guards), set(accesses)
    events = guards | accesses
    if any(lo <= p < hi for p in events for lo, hi in nested):
        return None
    seen, hits = set(), []
    raising: list = []                  # per enclosing BEGIN … EXCEPTION: [a free statement may raise, a free
    #                                     non-guard statement may raise]
    guard_vars: set = set()             # variables holding the answer of a check
    pending: dict = {}                  # label -> some GOTO reaches it without a check
    labels: set = set()

    def visit(lo, hi, free):
        here = [p for p in events if lo <= p < hi]
        seen.update(here)
        gs = [p for p in here if p in guards]
        if free:
            for flags in raising:
                flags[0] = True
                flags[1] = flags[1] or not gs
            if not gs:
                hits.extend(p for p in here if p in accesses)
        return gs

    def holds(x) -> bool:
        """The sub-condition contains a check (a call to it, or a variable holding its answer)."""
        tag = x[0]
        if tag == "atom":
            return any(x[1] <= p < x[2] for p in guards) or bool(x[3] & guard_vars)
        if tag == "not":
            return holds(x[1])
        if tag == "cmp":
            return holds(x[1]) or holds(x[3])
        return any(holds(y) for y in x[1])

    def polarity(x):
        """(x true implies the check passed, the check failing implies x true)."""
        tag = x[0]
        if tag == "atom":
            # only the check itself, a variable holding its answer, or nvl(either, FALSE / 0 / 'N')
            if not holds(x) or x[4] is None:
                return False, False
            _kind, at, name = x[4]
            if at in guards or (name is not None and name in guard_vars):
                return True, False
            return False, False
        if tag == "not":
            a, b = polarity(x[1])
            return b, a
        if tag == "and":
            ps = [polarity(y) for y in x[1]]
            return any(a for a, _b in ps), all(b for _a, b in ps)
        if tag == "or":
            ps = [polarity(y) for y in x[1]]
            return all(a for a, _b in ps), any(b for _a, b in ps)
        _t, left, op, right, lit_l, lit_r = x
        if holds(left) and not holds(right):
            base, lit = polarity(left), lit_r
        elif holds(right) and not holds(left):
            base, lit = polarity(right), lit_l
            op = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}.get(op, op)      # `0 < can_x(…)`
        else:
            return False, False
        if lit is None:
            return False, False                         # compared with another expression: not known
        if op in ("=", "!=", "<>", "^=", "~="):
            same = (op == "=") != (lit in ("F", "0"))   # = TRUE / 'Y' / 'ADMIN' / 1, != FALSE / 'N' / 0
            return base if same else (base[1], base[0])
        # an ordering compares a count / level: > 0 and >= 1 pass, <= 0 and < 1 fail; anything else (>= 0, < 0,
        # > 1, <= 1, an ordering of TRUE / 'Y') says nothing
        if (lit, op) in (("0", ">"), ("1", ">=")):
            return base
        if (lit, op) in (("0", "<="), ("1", "<")):
            return base[1], base[0]
        return False, False

    def cond(node, free):
        """-> "pos" (the branch runs only when the check passed), "neg" (it runs whenever the check fails) or
        None (the condition says neither: `if can_view(…) or p_public then`, `if not can_view(…) and p_x then`)."""
        _t, lo, hi, expr = node
        gs = visit(lo, hi, free)
        if expr is None:
            return "pos" if gs else None               # a condition that does not parse: as in 1.4
        if not holds(expr):
            return None
        implies, failing = polarity(expr)
        if implies:
            return "pos"
        if failing:
            return "neg"
        return None

    def run(node, free):                 # free: some path reaches this point without having passed a check
        tag = node[0]
        if tag == "s":
            _t, lo, hi, leaves, var = node
            gs = visit(lo, hi, free)
            if gs and var:
                guard_vars.add(var)
            if lo in gs:                 # a statement of its own: the call raises when the check fails
                free = False
            return False if leaves else free
        if tag == "x":
            return False
        if tag == "lbl":
            labels.add(node[1])
            return free or pending.pop(node[1], False)
        if tag == "goto":
            if node[1] in labels:
                raise _Bad
            pending[node[1]] = pending.get(node[1], False) or free
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
            for c, body in arms:
                pol = cond(c, free)
                if pol == "pos":
                    outs.append(run(body, False))
                elif pol == "neg":
                    outs.append(run(body, free))
                    free = False
                else:
                    outs.append(run(body, free))
            if other is not None:
                outs.append(run(other, free))
            elif falls:
                outs.append(free)
            return any(outs)
        if tag == "loop":
            pol = cond(node[1], free)
            return run(node[2], False if pol == "pos" else free) or free
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
    if pending or any(p not in seen and p < main_end for p in events):
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
        for pos in [x[0] for x in r.refs + r.own_sinks + r.reads] + r.return_pos + r.exits:
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
        toks = tokenize(src, cc_branches=True)
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

    def covering(self, is_guard) -> set:
        """Names of the package's routines that are checks themselves: every path to their normal exit (the end of
        a procedure, a RETURN of anything but FALSE / NULL / 0 / 'N') passes a guard call or a call to another such
        routine (1.5.0). A helper that calls the guard on some paths only (`if p_strict then check_access; end if;`)
        is not one: calling it covers nothing. Unknown paths (a body that does not parse): the lexical answer, a
        guard call before the first exit."""
        out: set = set()
        changed = True
        while changed:
            changed = False
            for r in self.pkg.routines:
                if r.name in out:
                    continue
                gp = [p for p, c, loc in r.refs if is_guard(c) or (loc is not None and loc in out and loc != r.name)]
                if not gp:
                    continue
                exits = list(r.exits) + [r.end]
                left = _unguarded(r, gp, exits)
                if (min(gp) < min(exits)) if left is None else not left:
                    out.add(r.name)
                    changed = True
        return out

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
    the first access, when the body cannot be followed path by path)."""
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
        if gp and (not s or min(gp) < min(p for p, _k, _o in s)):
            checked.append(r)                            # 1.3 criterion: a guard call comes first in the code
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
        # the guard is elected as in 1.3 (siblings whose first call to it comes before their first data access in the
        # code); whether it covers every path decides what is reported, and how many siblings it covers is stated
        # what covers a path (1.5.0): a call to the guard, or to a routine of the package that is a check itself on
        # every path to its normal exit (_Pkg.covering); a helper that calls it on some paths only covers nothing
        reached = view.covering(lambda c: c == guard)
        sinks = view.sinks(reached)
        covering = sum(1 for x in checked if not sinks[id(x)] or _covered(
            x, view.guard_positions(x, lambda c: c == guard, reached), sinks[id(x)]))
        any_auth = view.covering(_looks_auth)
        loose_auth = view.reach(_looks_auth)
        for r in view.public:
            if r.name == guard or _looks_auth(r.name):
                continue
            s = sinks[id(r)]
            if not s:
                continue                                 # pure computation: nothing to protect
            # any authorization-like call, of the package's guard or another, directly or through a package routine
            # a routine of the package counts when it is a check on every path to its normal exit; one that calls
            # an authorization check on some paths only does not, whatever its name (`can_view` that returns TRUE
            # without asking in one branch); a check with no authorization call of its own counts by its name
            own_checks = [p for p, c, loc in r.refs
                          if (loc is not None and loc != r.name and loc in any_auth)
                          or (_looks_auth(c) and not (loc is not None and loc in loose_auth and loc not in any_auth))]
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
            # helpers it calls that reach a check on some of their paths only (1.4 counted such a call as a check)
            partial = sorted({loc for _p, _c, loc in r.refs if loc is not None and loc != r.name and loc in loose_auth
                              and loc not in any_auth})
            k, n = len(checked), len(relevant)
            siblings = (f"تستدعي {k} من {n} من الروتينات العامة في الحزمة {gname} قبل أول وصول إلى البيانات في "
                        f"نصّها ({covering} منها على كل المسارات)")
            if gap is None:
                advice = (f"{rname} لا يتحقق من الصلاحية، بينما {siblings}. وهو {where_ar}. أضف التحقق نفسه ({gname}) "
                          f"في بدايته كما تفعل الروتينات الشقيقة؛ فأي كود في المخطط نفسه (صفحة APEX أخرى مثلًا) يمكنه "
                          f"استدعاؤه مباشرة.")
            else:
                advice = (f"{rname} يتحقق من الصلاحية في بعض المسارات فقط: يمكن الوصول إلى البيانات في السطر {gap} دون "
                          f"المرور بالتحقق، بينما {siblings}. وهو {where_ar}. اجعل التحقق ({gname}) قبل كل وصول إلى "
                          f"البيانات، في بدايته أو في شرط يخرج من الروتين (raise أو return) حين يفشل، لا في فرع واحد "
                          f"أو في معالج استثناء أو بعد الوصول.")
            if partial:
                h = f"{pkg.name}.{partial[0]}".upper()
                advice += f" ولا يُحتسب استدعاؤه {h} تحققًا: {h} نفسه لا يتحقق من الصلاحية إلا في بعض مساراته."
            lines = lines_by_file.get(pkg.rel) or []
            snippet = lines[r.line - 1] if 0 < r.line <= len(lines) else f"{r.kind} {r.name}"
            f = _finding(RULE, sev, title, title_ar, pkg.rel, r.line, snippet, advice, cwe, "")
            f.extra.update({"confidence": "tentative", "package": pkg.name.upper(), "routine": r.name.upper(),
                            "guard": gname, "guarded_siblings": k, "covering_siblings": covering, "siblings": n,
                            "accesses": where_en,
                            "spec_seen": pkg.name in specs, "coverage": "none" if gap is None else "partial",
                            "unguarded_line": gap})
            if partial:
                f.extra["partial_helpers"] = [f"{pkg.name}.{x}".upper() for x in partial]
            out.append(f)
    return out


# ------------------------------------------------------------------------- what APEX itself enforces (1.4.0)
_CODE_KINDS = ("plsql", "plsql_decls", "plsql_fn", "plsql_fn_sql", "plsql_fn_html", "plsql_expr", "sql", "invoke")


_SYNONYM = re.compile(r"\bcreate\s+(?:or\s+replace\s+)?(?:(?:editionable|noneditionable)\s+)?(?:public\s+)?synonym\s+"
                      r"(?:\"?[\w$#]+\"?\s*\.\s*)?\"?([\w$#]+)\"?\s+for\s+(?:\"?[\w$#]+\"?\s*\.\s*)?\"?([\w$#]+)\"?", re.I)


def synonyms(text: str) -> dict:
    """`create [or replace] [public] synonym [owner.]s for [owner.]target[@link]` in plain SQL -> {s: target} (lower
    case). Comments and string literals are blanked first, so a synonym in a comment or a dynamic SQL string is
    not one."""
    if "synonym" not in text.lower():
        return {}
    code = re.sub(r"--[^\n]*|/\*.*?\*/|'(?:[^']|'')*'", " ", text, flags=re.S)
    return {m.group(1).lower(): m.group(2).lower() for m in _SYNONYM.finditer(code)}


def _aliases(pkg: str, syns: dict) -> set:
    """Names that refer to package pkg: synonyms of it, and synonyms of those."""
    out, todo = set(), [pkg.lower()]
    while todo:
        target = todo.pop()
        for s, t in syns.items():
            if t == target and s not in out and s != pkg.lower():
                out.add(s)
                todo.append(s)
    return out


def _callers(pkg: str, routine: str, bodies: list, syns: dict, depth: int = 3) -> list:
    """Package routines of the scan that call pkg.routine (directly, or through such callers up to depth hops) on a
    path that passes no authorization-like check of their own first: [(caller package, caller routine, hops)]. A
    caller that checks before the call protects pkg.routine on that path itself, so its callers are not added."""
    pkg, routine = pkg.lower(), routine.lower()
    names = {pkg} | _aliases(pkg, syns)
    out, seen, frontier = [], {(pkg, routine)}, [(pkg, routine, names)]
    for hop in range(1, depth + 1):
        nxt = []
        for tpkg, troutine, tnames in frontier:
            for body in bodies:
                local = body.name.lower() == tpkg
                view = None
                for r in body.routines:
                    if (body.name.lower(), r.name) in seen:
                        continue
                    calls = [p for p, c, loc in r.refs
                             if (local and loc == troutine) or ("." in c and c.split(".")[-1] == troutine
                                                                 and c.split(".")[-2] in tnames)]
                    if not calls:
                        continue
                    if view is None:
                        view = _Pkg(body, {x.name for x in body.routines})
                        checks = view.covering(_looks_auth)
                    gp = [p for p, c, loc in r.refs if _looks_auth(c) or (loc is not None and loc in checks and loc != r.name)]
                    if gp:
                        left = _unguarded(r, gp, calls)
                        if (min(gp) < min(calls)) if left is None else not left:
                            continue                     # checked before every call: not an open way in
                    seen.add((body.name.lower(), r.name))
                    out.append((body.name.lower(), r.name, hop))
                    nxt.append((body.name.lower(), r.name, {body.name.lower()} | _aliases(body.name, syns)))
        frontier = nxt
        if not frontier:
            break
    return out


def apex_context(found: list, sites: list, sec: dict, bodies: list = (), syns: dict | None = None) -> None:
    """Add to each APX024 finding what the scanned APEX export(s) say about the routine's callers: the components
    (page processes, region sources, AJAX callbacks / application processes, dynamic action server code, Invoke
    API processes …) that call PACKAGE.ROUTINE and whether an authorization scheme protects each (component,
    inherited, page or application scheme; MUST_NOT_BE_PUBLIC_USER and negated schemes do not count).

    A call site is `pkg.routine`, `owner.pkg.routine`, `syn.routine` for a synonym of the package created in the
    scanned SQL (1.5.0), or a constant `execute immediate 'begin pkg.routine; end;'`; comments and other strings are
    not. Since 1.5.0 a component that calls another package routine of the scan which calls PACKAGE.ROUTINE (up to
    3 hops, through callers that do not check authorization first) is a call site too, labelled "indirectly via
    PKG.CALLER". A component in both the .sql and the YAML export of one application counts once (the YAML
    export's application id from the nearest f<id>.yaml; unknown, it matches only a scan of one .sql application).
    A process that runs When Button Pressed is not protected by the button's scheme (a crafted submit
    with that REQUEST runs it): the message names the button and its scheme and says to put it on the component.

    Every call site protected: the finding stays as it is, and says that the protection covers only those callers.
    Some call site unprotected (public page, component without a scheme, application process without one): the
    finding names it and its severity becomes high. No call site in the scan: unchanged.
    sites: [(rel, apex_export.Block, application id[, "sql" | "yaml"])]; sec: application id -> {app_scheme,
    schemes, pages}; bodies: the package bodies of the scan (plsql_authz.collect); syns: synonyms()."""
    from .apex_export import call_site_protection, call_sites, scheme_name
    if not found or not sites:
        return
    syns = syns or {}
    sites = [(x + ("sql",))[:4] for x in sites]
    sql_labels = {(app, b.label) for _r, b, app, fmt in sites if fmt == "sql"}
    sql_apps = {app for _r, _b, app, fmt in sites if fmt == "sql"}
    only = next(iter(sql_apps)) if len(sql_apps) == 1 else None      # a YAML export of unknown application
    sites = [x for x in sites if x[3] != "yaml" or (x[2] if x[2] is not None else only, x[1].label) not in sql_labels]
    for f in found:
        pkg, routine = str(f.extra.get("package") or ""), str(f.extra.get("routine") or "")
        if not pkg or not routine:
            continue
        targets = [(pkg, routine, "")]
        targets += [(p, r, f"{p}.{r}".upper()) for p, r, _hop in _callers(pkg, routine, bodies, syns)]
        calls = []
        for tpkg, troutine, via in targets:
            aliases = _aliases(tpkg, syns)
            for rel, b, app, _fmt in sites:
                if b.kind not in _CODE_KINDS or troutine.lower() not in b.code.lower():
                    continue
                lines = call_sites(b, tpkg, troutine, aliases)
                if not lines:
                    continue
                prot, what = call_site_protection(b, sec.get(app, {}))
                label = f"{b.label} (بشكل غير مباشر عبر {via})" if via else b.label
                for ln in lines:
                    c = {"component": label, "file": rel, "line": ln, "protected": prot,
                         ("scheme" if prot else "reason"): what}
                    if via:
                        c["via"] = via
                    if b.button and not prot:
                        c["button"], c["button_scheme"] = b.button[0], scheme_name(b.button[1], sec.get(app, {}).get("schemes", {}))
                    calls.append(c)
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
            btn = next((c for c in open_ if c.get("button")), None)
            if btn is not None:
                # a When Button Pressed compares the submitted REQUEST with the button's name: hiding the button
                # (its authorization scheme) does not stop a crafted submit with that request
                f.extra["apex_button_not_protection"] = {"component": btn["component"], "button": btn["button"],
                                                         "scheme": btn["button_scheme"]}
                f.advice += (f" ويعمل «{btn['component']}» عند الضغط على الزر {btn['button']} الذي يحميه المخطط "
                             f"{btn['button_scheme']}، لكن إخفاء الزر لا يمنع إرسال الصفحة بطلب (REQUEST) يحمل اسمه؛ "
                             f"أسند {btn['button_scheme']} إلى المكوّن نفسه لحمايته.")
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
