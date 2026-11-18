"""Missing authorization check inconsistent with sibling routines (APX024, CWE-862).  (vulnscan: ignore-file)

A PL/SQL package whose public routines check the caller's authorization themselves (they call the package's access
check, `apex_authorization.is_authorized`, …) but where one public routine that reads, changes or sends data does
not: any code in the same schema (another APEX page, a job, a REST handler) can call that routine directly, whatever
the application around it checks first.

The rule is about inconsistency, not a guess that every routine needs a check, and it stays conservative:

1. Public routines: the ones the package spec declares when the scan holds it (any file); without a spec, the body's
   routines minus those other routines of the package call (private helpers) and those declared forward in the body.
2. The guard: a call whose name looks like an authorization / access check, reached (directly or through routines
   of the same package) before the first data access by at least 3 public routines and by at least 60% of the public
   routines that access data or call it. No guard: no finding.
3. Flagged: a public routine that reads data with a query and can return it, changes data (DML, dynamic SQL) or
   writes to the browser (htp, wpg_docload), itself or through a routine of the package that does so unchecked, and
   that reaches no authorization-like call at all (so a guard on any path, or a different check, keeps it quiet).
   Pure computation (no SQL, no output) is never flagged.

The analysis is lexical (tokens of plain PL/SQL: .pkb/.pks/.sql files and scripts inside XML changelogs); code inside
APEX export strings is not read here.
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
def _first(positions):
    return min(positions) if positions else None


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
            if r.reads:
                first_read = min(p for p, _o in r.reads)
                ret = _first([p for p in r.return_pos if p > first_read])
                obj = next((o for _p, o in r.reads if o), "")
                s.append((ret if ret is not None else r.end, "read", obj))
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
            if id(r) in done or r.name == guard or _looks_auth(r.name) or r.name in any_auth:
                continue
            if any(_looks_auth(c) for _p, c, _loc in r.refs):
                continue
            s = sinks[id(r)]
            if not s:
                continue                                 # pure computation: nothing to protect
            ar, en, objs = _describe(r, s)
            where_ar = ar + (f" ({', '.join(objs)})" if objs else "")
            where_en = en + (f" ({', '.join(objs)})" if objs else "")
            rname = f"{pkg.name}.{r.name}".upper()
            gname = guard.upper() if "." in guard else f"{pkg.name}.{guard}".upper()
            k, n = len(checked), len(relevant)
            advice = (f"{rname} لا يتحقق من الصلاحية، بينما تستدعي {k} من {n} من الروتينات العامة في الحزمة "
                      f"{gname} قبل عملها. وهو {where_ar}. أضف التحقق نفسه ({gname}) في بدايته كما تفعل الروتينات "
                      f"الشقيقة؛ فأي كود في المخطط نفسه (صفحة APEX أخرى مثلًا) يمكنه استدعاؤه مباشرة.")
            lines = lines_by_file.get(pkg.rel) or []
            snippet = lines[r.line - 1] if 0 < r.line <= len(lines) else f"{r.kind} {r.name}"
            f = _finding(RULE, sev, title, title_ar, pkg.rel, r.line, snippet, advice, cwe, "")
            f.extra.update({"confidence": "tentative", "package": pkg.name.upper(), "routine": r.name.upper(),
                            "guard": gname, "guarded_siblings": k, "siblings": n, "accesses": where_en,
                            "spec_seen": pkg.name in specs})
            out.append(f)
    return out
