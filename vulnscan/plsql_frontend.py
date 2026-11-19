"""PL/SQL frontend: lowers Oracle PL/SQL (packages, procedures, functions, triggers, anonymous blocks) into the
engine's Python ``ast``.  (vulnscan: ignore-file)

What data flow needs is kept; everything else is skipped and reported:

* units -- ``create [or replace] package body`` (one module per package), standalone ``procedure`` /
  ``function``, ``trigger`` bodies, ``type body`` members and anonymous ``declare``/``begin`` blocks;
* declarations with initialisers, nested sub-programs, ``:=`` assignments, ``if``/``case``/loops/``forall``,
  ``begin … exception … end`` (lowered to ``try``), ``return``;
* expressions: ``||`` concatenation, comparisons (``in``, ``like``, ``between``, ``is null``), ``case``
  expressions, calls with positional and named (``p_x => v``) arguments, ``%`` attributes;
* dynamic SQL: ``execute immediate e`` -> ``execute_immediate(e)``, ``open c for e`` -> ``open_for(e)``
  (``using`` binds are safe and dropped; static SQL/cursors are bound and skipped);
* APEX session state: ``:P1_X``, ``v('P1_X')``, ``nv('P1_X')`` and ``apex_util.get_session_state('P1_X')``
  become ``apex_item.P1_X`` so a finding names the page item. ``:APP_ID``-style built-ins are not sources.

Identifiers are case-insensitive and lowered. A statement the parser cannot handle is recorded (line +
reason) and skipped, so nothing is dropped silently. ``create … java source`` blocks are returned
separately so the Java frontend can analyse them.
"""

from __future__ import annotations

import ast
import copy
import re

from .js_frontend import _args, _const, _mk, _name

PLSQL_EXTS = (".sql", ".pks", ".pkb", ".pls", ".plb", ".pck", ".prc", ".fnc", ".trg", ".tps", ".tpb", ".bdy", ".spc")
BUILTIN_BINDS = {"app_id", "app_page_id", "app_session", "app_user", "app_alias", "app_page_alias", "workspace_id", "app_images",
                 "image_prefix", "debug", "printer_friendly", "app_version", "app_title", "new", "old", "parent", "browser_language_x"}
SESSION_GETTERS = {"v", "nv", "apex_util.get_session_state", "apex_util.get_numeric_session_state", "sys.v"}
SQLPLUS_CMDS = {"set", "prompt", "spool", "whenever", "define", "undefine", "column", "col", "rem", "remark", "connect", "conn", "show",
                "variable", "var", "print", "host", "exit", "quit", "pause", "accept", "ttitle", "btitle", "break", "compute", "clear", "timing"}
SKIP_STMTS = {"select", "insert", "update", "delete", "merge", "with", "fetch", "close", "commit", "rollback", "savepoint", "lock",
              "goto", "null", "exit", "continue", "pipe", "set", "dbms_output_put"}
STOP_BODY = {"end", "exception", "elsif", "else", "when"}
RAISE_APP_ERROR = {"raise_application_error", "sys.raise_application_error", "dbms_standard.raise_application_error",
                   "sys.dbms_standard.raise_application_error"}
# owa_util procedures with a bclose_header parameter -> its position; `false` leaves the HTTP header open
HEADER_OPENERS = {"owa_util.mime_header": 1, "owa_util.status_line": 2, "owa_util.redirect_url": 1}
HTP_WRITES = {"htp.p", "htp.prn", "htp.print", "htp.prints", "htp.ps", "sys.htp.p", "sys.htp.prn", "sys.htp.print",
              "sys.htp.prints", "sys.htp.ps"}
HEADER_WRITE = "owa_header_write"     # lowered name of an htp call that writes an HTTP header line
SQL_DML = {"select", "insert", "update", "delete", "merge", "with"}
# words that may precede '(' in SQL without being a function call
SQL_NON_FUNCS = {"in", "exists", "values", "over", "as", "from", "where", "and", "or", "not", "select", "when", "then", "else",
                 "case", "using", "on", "into", "by", "set", "join", "any", "all", "some", "between", "like", "partition",
                 "within", "keep", "returning", "group", "order", "having", "connect", "start", "union", "intersect", "minus",
                 "except", "fetch", "offset", "for", "of", "update", "insert", "delete", "merge", "with", "is", "default",
                 "check", "unique", "primary", "foreign", "references", "constraint", "pivot", "unpivot", "model", "lateral",
                 "cross", "outer", "inner", "left", "right", "full", "natural", "apply", "tablesample", "sample", "rows", "range",
                 "nulls", "first", "last", "only", "ties", "percent", "columns", "path", "nested", "match_recognize", "measures",
                 "pattern", "define", "subset", "search", "cycle", "siblings", "prior", "level", "rownum", "distinct", "unique"}

_TOKEN = re.compile(r"""
    (?P<nl>\n) | (?P<ws>[ \t\r\f\v]+) | (?P<lc>--[^\n]*) | (?P<bc>/\*.*?\*/) |
    (?P<qstr>[nN]?[qQ]'.) |
    (?P<str>[nN]?'(?:''|[^'])*') |
    (?P<num>(?:\d+(?:\.\d+)?|(?<![\w$#)\]"])\.\d+)(?:[eE][+-]?\d+)?[fFdD]?\b) |
    (?P<qid>"[^"\n]+") |
    (?P<punct>:=|=>|\|\||\.\.|<>|!=|\^=|~=|<=|>=|\*\*|<<|>>) |
    (?P<bind>:[A-Za-z_][\w$#]*|:"[^"\n]+") |
    (?P<cc>\$\$?[A-Za-z_][\w$#]*) |
    (?P<id>[A-Za-z_][\w$#]*) |
    (?P<one>[-+*/%(),;.=<>@:&|\[\]{}!?^~])
""", re.S | re.X)
_QPAIRS = {"[": "]", "{": "}", "(": ")", "<": ">"}
# A unit obfuscated by Oracle's wrap utility: `create [or replace] [editionable] <unit type> [schema.]name wrapped`, then
# the wrapped text (a000000, a version line, 15 x abcd, a type code, lengths, base64-like lines) up to a `/` line.
_WRAPPED_HEAD = re.compile(
    r"""^[ \t]*create\s+(?:or\s+replace\s+)?(?:(?:non)?editionable\s+)?"""
    r"""(package\s+body|package|procedure|function|type\s+body|type|trigger|library)\s+"""
    r"""((?:"[^"\n]+"|[A-Za-z_][\w$#]*)(?:\s*\.\s*(?:"[^"\n]+"|[A-Za-z_][\w$#]*))?)\s+wrapped\b[ \t]*\r?$""", re.I | re.M)
_WRAPPED_END = re.compile(r"^[ \t]*/[ \t]*\r?$", re.M)
# what wrap writes after the header: `a000000` (10g and later) or `0` (9i), a version line, then `abcd` lines; never `;`
_WRAPPED_BODY = re.compile(r"[ \t]*\r?\n(?:a000000|0)[ \t]*\r?\n(?:[^\n]*\r?\n)?(?:[ \t]*\r?\n)*abcd[ \t]*\r?$", re.M)
_JAVA_SRC = re.compile(r"create\s+(?:or\s+replace\s+)?(?:and\s+(?:resolve|compile)\s+)?(?:noforce\s+)?java\s+source\s+named\s+"
                       r"(\"[^\"]+\"|\S+)\s+(?:as|is)\s*?\n(.*?)^\s*/\s*$", re.I | re.S | re.M)


class Tok:
    __slots__ = ("kind", "val", "line", "nl", "raw")

    def __init__(self, kind, val, line, nl, raw=None):
        self.kind, self.val, self.line, self.nl, self.raw = kind, val, line, nl, raw

    def __repr__(self):
        return f"Tok({self.kind},{self.val!r},{self.line})"


def tokenize(src: str, cc_branches: bool = False) -> list[Tok]:
    toks: list[Tok] = []
    i, n, line, nl = 0, len(src), 1, True
    while i < n:
        m = _TOKEN.match(src, i)
        if not m:
            i += 1
            continue
        kind, text = m.lastgroup, m.group(0)
        if kind == "nl":
            line += 1
            nl = True
            i = m.end()
            continue
        if kind in ("ws", "lc"):
            i = m.end()
            continue
        if kind == "bc":
            line += text.count("\n")
            i = m.end()
            continue
        if kind == "qstr":   # q'[ ... ]'  /  q'! ... !'
            open_ = text[-1]
            close = _QPAIRS.get(open_, open_)
            end = src.find(close + "'", m.end())
            if end < 0:
                end = n - 2
            body = src[m.end():end]
            toks.append(Tok("str", body, line, nl))
            line += body.count("\n")
            nl = False
            i = end + 2
            continue
        if kind == "str":
            body = text[text.index("'") + 1:-1].replace("''", "'")
            toks.append(Tok("str", body, line, nl))
            line += text.count("\n")
        elif kind == "num":
            toks.append(Tok("num", text, line, nl))
        elif kind == "qid":
            toks.append(Tok("id", text[1:-1].lower(), line, nl, text[1:-1]))
        elif kind == "bind":                 # :P1_X, or quoted :"P1_X"
            name = text[1:].strip('"')
            toks.append(Tok("bind", name.lower(), line, nl, name))
        elif kind == "cc":
            toks.append(Tok("cc", text.lower(), line, nl, text))
        elif kind == "id":
            toks.append(Tok("id", text.lower(), line, nl, text))
        else:
            toks.append(Tok("punct", text, line, nl))
        nl = False
        i = m.end()
    toks.append(Tok("eof", "", line, True))
    return _conditional(toks, cc_branches) if any(t.kind == "cc" for t in toks) else toks


CC_COND = "__cc__"                       # the unknown condition of a `$if` lowered to an IF (see _conditional)
_CC_BOUNDARY = {"begin", "then", "else", "loop", "declare", "is", "as"}
_CC_NOT_FIRST = {"when", "elsif", "else", "exception", "end"}


def _conditional(toks: list[Tok], branches: bool = False) -> list[Tok]:
    """Conditional compilation: which branch is compiled depends on the database, so EVERY branch is kept. An inquiry
    directive (`$$plsql_unit`, `$$my_flag`) is a compile-time constant; `$error … $end` is dropped.

    By default the directives (`$if cond $then`, `$elsif cond $then`, `$else`, `$end`) are dropped and the branches
    follow each other. With branches=True a `$if` whose branches are whole statements or declarations (it starts where
    a statement may start, and each branch ends with `;`) becomes `if __cc__ then … elsif __cc__ then … else … end if;`,
    so that one branch runs, not all of them in a row (in `$if … $then l_sql := a; $else l_sql := b; $end` the second
    assignment does not overwrite the first). Any other `$if` (inside an expression, a list) is dropped as by default."""
    out: list[Tok] = []
    groups: list = []                    # [[(index in out, directive)], structured so far]
    stack: list = []
    k, n = 0, len(toks)
    while k < n:
        t = toks[k]
        if t.kind != "cc":
            out.append(t)
            k += 1
            continue
        if t.val.startswith("$$"):
            out.append(Tok("str", t.raw[2:], t.line, t.nl))
            k += 1
            continue
        d = t.val
        stop = {"$if": "$then", "$elsif": "$then", "$error": "$end"}.get(d)
        k += 1
        if stop:
            while k < n and toks[k].kind != "eof" and not (toks[k].kind == "cc" and toks[k].val == stop):
                k += 1
            if k < n and toks[k].kind == "cc":
                k += 1
        if not branches or d not in ("$if", "$elsif", "$else", "$end"):
            continue
        if d == "$if":
            prev = out[-1] if out else None
            ok = prev is None or (prev.kind == "punct" and prev.val == ";") or (prev.kind == "id" and prev.val in _CC_BOUNDARY) \
                or prev.kind == "ccm"
            g = [[], ok]
            groups.append(g)
            stack.append(g)
        elif not stack:
            continue
        g = stack[-1]
        if d != "$if":                   # the branch before this directive must end a statement (or be empty)
            prev = out[-1]
            if not ((prev.kind == "punct" and prev.val == ";") or (prev.kind == "ccm" and (prev.val == "$end" or
                                                                                          prev is g[0][-1][1]))):
                g[1] = False
        marker = Tok("ccm", d, t.line, t.nl)
        g[0].append((len(out), marker))
        out.append(marker)
        if d == "$end":
            stack.pop()
    if not groups:
        return out
    for g in groups:                     # a branch starting with `when` / `else` … is part of a larger construct
        if g[1]:
            for idx, _m in g[0][:-1]:
                nxt = out[idx + 1] if idx + 1 < len(out) else None
                if nxt is not None and nxt.kind == "id" and nxt.val in _CC_NOT_FIRST:
                    g[1] = False
        if len(g[0]) < 2 or g[0][-1][1].val != "$end":
            g[1] = False
        for _idx, m in g[0]:
            m.raw = "keep" if g[1] else None
    res: list[Tok] = []
    for t in out:
        if t.kind != "ccm":
            res.append(t)
        elif t.raw == "keep":
            ln, nl = t.line, t.nl
            words = {"$if": ["if", CC_COND, "then"], "$elsif": ["elsif", CC_COND, "then"], "$else": ["else"],
                     "$end": ["end", "if", ";"]}[t.val]
            res.extend(Tok("punct" if w == ";" else "id", w, ln, nl) for w in words)
    return res


class ParseError(Exception):
    pass


def _item(name: str, line: int) -> ast.AST:
    """An APEX page item reference -> apex_item.<NAME> (a source named after the item)."""
    return _mk(ast.Attribute, line, value=_name("apex_item", line), attr=name.upper(), ctx=ast.Load())


def _call(func, args, line, kws=()):
    if isinstance(func, str):
        parts = func.split(".")
        node = _name(parts[0], line)
        for p in parts[1:]:
            node = _mk(ast.Attribute, line, value=node, attr=p, ctx=ast.Load())
        func = node
    return _mk(ast.Call, line, func=func, args=list(args), keywords=list(kws))


def _dotted(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        b = _dotted(node.value)
        return f"{b}.{node.attr}" if b else ""
    return ""


class Unit:
    """One top-level PL/SQL program unit."""

    def __init__(self, kind: str, name: str, body: list, line: int):
        self.kind, self.name, self.body, self.line = kind, name, body, line


class Parser:
    def __init__(self, src: str):
        self.toks = tokenize(src, cc_branches=True)
        self.i = 0
        self.diagnostics: list = []
        self.n_skipped = 0               # every skipped statement (diagnostics keeps the first 500 of them)
        self.n_statements = 0
        self.anon = 0
        self.pending_pre: list = []
        self.cursors: dict = {}          # cursor name -> select info (for rows read through it)
        # between owa_util.mime_header(…, false) and owa_util.http_header_close: True; "maybe" when only some branches
        # leading here opened (or closed) the header
        self.header_open = False

    # ---------------------------------------------------------------- helpers
    @property
    def t(self) -> Tok:
        return self.toks[self.i]

    def peek(self, k=1) -> Tok:
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def at(self, *vals) -> bool:
        t = self.t
        return t.kind in ("id", "punct") and t.val in vals

    def eat(self, v=None) -> Tok:
        t = self.t
        if v is not None and not (t.kind in ("id", "punct") and t.val == v):
            raise ParseError(f"expected {v!r}, found {t.raw or t.val!r}")
        self.i += 1
        return t

    def opt(self, *vals) -> bool:
        if self.at(*vals):
            self.i += 1
            return True
        return False

    def skip_to_semicolon(self):
        depth = 0
        while self.t.kind != "eof":
            if self.at("(", "["):
                depth += 1
            elif self.at(")", "]"):
                depth = max(0, depth - 1)
            elif self.at(";") and depth == 0:
                self.i += 1
                return
            elif self.at("/") and self.t.nl and self.peek().nl and depth == 0:
                return
            self.i += 1

    def skip_balanced(self):
        """At '(' : skip to the matching ')'."""
        depth = 0
        while self.t.kind != "eof":
            if self.at("("):
                depth += 1
            elif self.at(")"):
                depth -= 1
                if depth == 0:
                    self.i += 1
                    return
            self.i += 1

    def record(self, line, msg, start=None, where="body"):
        """A skipped statement: (line, "{kind} message"), the kind of the statement that starts at token `start`."""
        self.n_skipped += 1
        if len(self.diagnostics) < 500:
            kind = self.stmt_kind(start, where) if start is not None else ""
            self.diagnostics.append((line, f"{{{kind}}} {msg}" if kind else msg))

    def stmt_kind(self, start: int, where: str = "body") -> str:
        """What a skipped statement is, from its first tokens: SQL UPDATE, assignment, procedure call, IF, loop,
        declaration, CREATE PACKAGE BODY … (an English code; scanner.STMT_KINDS gives the Arabic)."""
        try:
            t = self.toks[start]
            v = t.val if t.kind == "id" else ""
            if where == "top":
                if v == "create":
                    words, k = [], start + 1
                    while self.toks[k].kind == "id" and self.toks[k].val in ("or", "replace", "editionable", "noneditionable",
                                                                             "force", "noforce", "and", "resolve", "compile",
                                                                             "public", "editioning"):
                        k += 1
                    while self.toks[k].kind == "id" and len(words) < 2 and self.toks[k].val in (
                            "package", "body", "procedure", "function", "trigger", "type", "view", "table", "java",
                            "source", "synonym", "sequence", "index"):
                        words.append(self.toks[k].val)
                        k += 1
                    return "CREATE " + " ".join(words).upper() if words else "CREATE"
                if v in ("declare", "begin"):
                    return "anonymous block"
                return v.upper() if v.isalpha() else ""
            if v in ("procedure", "function") and where == "decls":
                return f"{v} declaration"
            if where == "decls":
                return "cursor declaration" if v == "cursor" else "type declaration" if v in ("type", "subtype") \
                    else "declaration"
            if v in SQL_DML:
                return f"SQL {'SELECT' if v == 'with' else v.upper()}"
            if v in ("if", "case", "return", "raise", "goto", "exit", "null", "commit", "rollback", "savepoint"):
                return v.upper()
            if v in ("loop", "while", "for", "forall"):
                return "loop"
            if v == "execute":
                return "EXECUTE IMMEDIATE"
            if v in ("open", "fetch", "close"):
                return f"cursor {v.upper()}"
            if v in ("begin", "declare"):
                return "block"
            if t.kind in ("id", "bind"):
                k = start + 1
                depth = 0
                while self.toks[k].kind != "eof" and k < start + 400:
                    x = self.toks[k]
                    if x.kind == "punct" and x.val in ("(", "["):
                        depth += 1
                    elif x.kind == "punct" and x.val in (")", "]"):
                        depth -= 1
                    elif depth <= 0 and x.kind == "punct" and x.val in (":=", ";"):
                        return "assignment" if x.val == ":=" else "procedure call"
                    k += 1
                return "procedure call"
        except IndexError:
            pass
        return ""

    def skip_type(self, stops):
        """Skip a type (varchar2(100), t.c%type, number(10,2), …) up to a stop token at depth 0."""
        while self.t.kind != "eof" and not (self.t.kind in ("id", "punct") and self.t.val in stops):
            if self.at("("):
                self.skip_balanced()
                continue
            self.i += 1

    # --------------------------------------------------------------- program
    def parse_program(self) -> list[Unit]:
        units: list[Unit] = []
        while self.t.kind != "eof":
            start = self.i
            try:
                u = self.parse_top()
                if u is not None:
                    units.append(u)
            except ParseError as e:
                self.record(self.toks[start].line, str(e), start, "top")
                self.i = start + 1 if self.i == start else self.i
                self.skip_to_semicolon()
        return units

    def parse_top(self):
        t = self.t
        if t.kind == "punct" and t.val in ("/", ";"):
            self.i += 1
            return None
        if t.kind == "punct" and t.val in ("@", "<<"):
            self._skip_line()
            return None
        if t.kind == "punct" and t.val == "." and t.nl and self.peek().nl:
            self.i += 1                                         # SQL*Plus: `.` alone on a line ends the buffer
            return None
        if t.kind != "id":
            raise ParseError(f"unexpected {t.raw or t.val!r}")
        v = t.val
        if v in SQLPLUS_CMDS and t.nl:
            self._skip_line()
            return None
        if v in ("exec", "execute") and t.nl and self.peek().val != "immediate":
            self.i += 1
            line = self.t.line
            if self.at("begin", "declare"):                     # exec begin … end;
                return Unit("anonymous", f"exec_{line}", self.parse_anonymous(), line)
            target = self.parse_postfix()
            if self.opt(":="):                                  # exec :bind := f(…);
                body = self.assign(target, self.parse_expr(), line)
            else:
                body = [_mk(ast.Expr, line, value=self._as_call(target, line))]
            self.opt(";")
            return Unit("anonymous", f"exec_{line}", body, line)
        if v in ("declare", "begin"):
            line = t.line
            self.header_open = False
            body = self.parse_anonymous()
            self.anon += 1
            return Unit("anonymous", f"anonymous_block_{line}", body, line)
        if v == "create":
            return self.parse_create()
        self.skip_to_semicolon()      # DDL / DML / grant / alter …
        return None

    def _skip_line(self):
        line = self.t.line
        while self.t.kind != "eof" and self.t.line == line:
            self.i += 1

    def parse_create(self):
        line = self.t.line
        self.eat("create")
        while self.at("or", "replace", "editionable", "noneditionable", "force", "noforce", "and", "resolve", "compile", "public", "editioning"):
            self.i += 1
        kind = self.t.val
        if kind in ("procedure", "function"):
            fn = self.parse_subprogram()
            return Unit("standalone", fn.name, [fn], line) if fn is not None else None
        if kind == "package":
            self.i += 1
            if self.opt("body"):
                return self.parse_package_body(line)
            self._skip_unit_end()
            return None
        if kind == "trigger":
            return self.parse_trigger(line)
        if kind == "type":
            self.i += 1
            if self.opt("body"):
                return self.parse_package_body(line, type_body=True)
            self.skip_to_semicolon()
            return None
        self.skip_to_semicolon()      # table, view, sequence, index, synonym, java (handled separately) …
        return None

    def _skip_unit_end(self):
        """Skip a package spec: up to `end [name];` at the outer level."""
        depth = 0
        while self.t.kind != "eof":
            if self.at("record", "object") or (self.at("(") ):
                if self.at("("):
                    self.skip_balanced()
                    continue
            if self.at("end") and (self.peek().val == ";" or (self.peek().kind == "id" and self.peek().val != "if"
                                                               and self.peek(2).val == ";")):
                self.i += 1
                if self.t.kind == "id":
                    self.i += 1
                self.opt(";")
                return
            if self.at("/") and self.t.nl and depth == 0:
                return
            self.i += 1

    def _qualified_name(self) -> str:
        name = self.eat().val
        while self.at("."):
            self.i += 1
            name = self.eat().val
        return name

    # ------------------------------------------------------------ sub-programs
    def parse_subprogram(self):
        """procedure/function name[(params)] [return type] [modifiers] (is|as) decls begin … end; -> FunctionDef or None (spec)."""
        line = self.t.line
        kind = self.eat().val
        name = self._qualified_name()
        params = self.parse_params() if self.at("(") else []
        if kind == "function" and self.opt("return"):
            self.skip_type({"is", "as", ";", "pipelined", "deterministic", "result_cache", "parallel_enable", "authid",
                            "aggregate", "accessible", "sharing", "default", "sql_macro"})
        while self.at("authid", "deterministic", "pipelined", "parallel_enable", "result_cache", "accessible", "sharing", "default",
                      "aggregate", "sql_macro"):
            self.i += 1
            if self.at("current_user", "definer", "metadata", "none", "collation", "using_nls_comp", "by"):
                self.i += 1
            while self.at("current_user", "definer", "using_nls_comp"):
                self.i += 1
            if self.at("="):
                self.i += 2
            if self.at("("):
                self.skip_balanced()
            if self.at("relies_on"):
                self.i += 1
                self.skip_balanced()
            if self.at("cluster", "order") and self.peek(2).val == "by":   # parallel_enable(…) cluster c by (col)
                self.i += 3
                if self.at("("):
                    self.skip_balanced()
        if self.at("using") and self.peek().kind == "id":
            self.skip_to_semicolon()                  # pipelined / aggregate `using impl_type`: implemented by a type
            return None
        if self.opt(";"):
            return None                               # forward declaration / spec
        if not self.opt("is", "as"):
            raise ParseError(f"expected IS/AS in {name}")
        if self.at("language") and self.peek().val == "java" and self.peek(2).val == "name" and self.peek(3).kind == "str":
            # Java call spec: forward to the Java method so flows continue into the Java source
            target = self.peek(3).val.split("(")[0].strip()
            self.skip_to_semicolon()
            if "." in target:
                cls, meth = target.rsplit(".", 1)
                call = _call(_mk(ast.Attribute, line, value=_name(cls.rsplit(".", 1)[-1], line), attr=meth, ctx=ast.Load()),
                             [_name(p, line) for p in params], line)
                return _mk(ast.FunctionDef, line, name=name, args=_args(params, line),
                           body=[_mk(ast.Return, line, value=call)], decorator_list=[], returns=None, type_params=[])
            return None
        if self.at("language", "external", "mle"):
            self.skip_to_semicolon()
            return None
        saved, self.header_open = self.header_open, False
        try:
            body = self.decls_and_body(name)
        finally:
            self.header_open = saved
        return _mk(ast.FunctionDef, line, name=name, args=_args(params, line), body=body or [_mk(ast.Pass, line)],
                   decorator_list=[], returns=None, type_params=[])

    def parse_params(self) -> list[str]:
        self.eat("(")
        names = []
        while not self.at(")") and self.t.kind != "eof":
            names.append(self.eat().val)
            self.skip_type({",", ")", ":=", "default"})
            if self.opt(":=", "default"):
                self.parse_expr()
            if not self.opt(","):
                break
        self.eat(")")
        return names

    def decls_and_body(self, name) -> list:
        """Declaration section (incl. nested sub-programs), then `begin … [exception …] end [name];`."""
        out = self.parse_decls({"begin", "end"})
        if self.opt("begin"):
            out.extend(self.parse_block_rest())
        else:
            self.eat("end")
            if self.t.kind == "id":
                self.i += 1
            self.opt(";")
        return out

    def parse_decls(self, stops) -> list:
        out = []
        while self.t.kind != "eof" and not self.at(*stops):
            start = self.i
            line = self.t.line
            try:
                if self.at("if") and self.peek().kind == "id" and self.peek().val == CC_COND:
                    out.extend(self.parse_cc_decls())
                    continue
                if self.at("procedure", "function"):
                    fn = self.parse_subprogram()
                    if fn is not None:
                        out.append(fn)
                    continue
                if self.at("member", "static", "constructor", "map", "order", "final", "instantiable", "overriding", "not"):
                    self.i += 1
                    continue
                if self.at("cursor"):
                    start = self.i
                    cname = self.peek().val
                    self.skip_to_semicolon()
                    sel = next((k for k in range(start, self.i) if self.toks[k].val in ("select", "with") and self.toks[k].kind == "id"), None)
                    if sel is not None:
                        self.cursors[cname] = self.select_info(sel, self.i)
                    out.extend(self.sql_calls(start, self.i))
                    continue
                if self.at("type", "subtype", "pragma"):
                    self.skip_to_semicolon()
                    continue
                if self.t.kind != "id":
                    raise ParseError(f"unexpected {self.t.raw or self.t.val!r} in declarations")
                var = self.eat().val
                if self.at("exception"):
                    self.skip_to_semicolon()
                    continue
                self.opt("constant")
                self.skip_type({":=", "default", ";"})
                if self.opt(":=", "default"):
                    val = self.parse_expr()
                    out.append(_mk(ast.Assign, line, targets=[_name(var, line, store=True)], value=val))
                self.eat(";")
                self.n_statements += 1
            except ParseError as e:
                self.record(line, str(e), start, "decls")
                if self.i == start:
                    self.i += 1
                self.skip_to_semicolon()
        return out

    def parse_cc_decls(self) -> list:
        """Declarations under conditional compilation (`$if … $then <decls> [$elsif …] [$else <decls>] $end`, lowered
        to `if __cc__ then … end if;` by tokenize): an If over their initialisers, one branch or the other. Sub-programs
        declared in a branch stay at the level of the declarations (each branch's are kept)."""
        line = self.t.line
        self.eat("if")
        self.eat(CC_COND)
        self.eat("then")
        arms = [self.parse_decls({"elsif", "else", "end"})]
        other: list = []
        while self.at("elsif"):
            self.i += 1
            self.eat(CC_COND)
            self.eat("then")
            arms.append(self.parse_decls({"elsif", "else", "end"}))
        if self.opt("else"):
            other = self.parse_decls({"end"})
        self.eat("end")
        self.eat("if")
        self.eat(";")
        if any(isinstance(x, ast.FunctionDef) for arm in arms + [other] for x in arm):
            return [x for arm in arms + [other] for x in arm]
        for arm in reversed(arms):
            other = [_mk(ast.If, line, test=_name(CC_COND, line), body=arm or [_mk(ast.Pass, line)], orelse=other)]
        return other

    def parse_package_body(self, line, type_body=False) -> Unit:
        name = self._qualified_name()
        while not self.at("is", "as") and self.t.kind != "eof":
            self.i += 1
        self.eat()
        body = self.parse_decls({"begin", "end"})
        if self.opt("begin"):
            init = self.parse_block_rest()
            if init:
                body.append(_mk(ast.FunctionDef, line, name="__package_init__", args=_args([], line), body=init,
                                decorator_list=[], returns=None, type_params=[]))
        else:
            self.eat("end")
            if self.t.kind == "id":
                self.i += 1
            self.opt(";")
        return Unit("type" if type_body else "package", name, body, line)

    def parse_trigger(self, line) -> Unit:
        self.eat("trigger")
        name = self._qualified_name()
        while self.t.kind != "eof" and not self.at("declare", "begin", "compound"):
            if self.at("("):
                self.skip_balanced()
                continue
            self.i += 1
        if self.opt("compound"):
            self.eat("trigger")
            body = []
            while self.t.kind != "eof" and not (self.at("end") and self.peek().kind == "id" and self.peek().val == name):
                if self.at("before", "after", "instead"):
                    while not self.at("is") and self.t.kind != "eof":
                        self.i += 1
                    self.eat("is")
                    body.extend(self.decls_and_body(name))
                    continue
                body.extend(self.parse_decls({"before", "after", "instead", "end"}))
            self.skip_to_semicolon()
        else:
            body = self.parse_anonymous()
        fn = _mk(ast.FunctionDef, line, name=name, args=_args([], line), body=body or [_mk(ast.Pass, line)],
                 decorator_list=[], returns=None, type_params=[])
        return Unit("standalone", name, [fn], line)

    def parse_anonymous(self) -> list:
        out = []
        if self.opt("declare"):
            out.extend(self.parse_decls({"begin"}))
        self.eat("begin")
        out.extend(self.parse_block_rest())
        return out

    def parse_block_rest(self) -> list:
        """After `begin`: statements, optional exception handlers, `end [label];`."""
        line = self.t.line
        body = self.parse_stmts({"end", "exception"})
        handlers = []
        if self.opt("exception"):
            while self.opt("when"):
                while not self.at("then") and self.t.kind != "eof":
                    self.i += 1
                self.eat("then")
                hb = self.parse_stmts({"when", "end"})
                handlers.append(_mk(ast.ExceptHandler, line, type=None, name=None, body=hb or [_mk(ast.Pass, line)]))
        self.eat("end")
        if self.t.kind == "id" and not self.at("if", "loop", "case"):
            self.i += 1
        self.opt(";")
        if handlers:
            return [_mk(ast.Try, line, body=body or [_mk(ast.Pass, line)], handlers=handlers, orelse=[], finalbody=[])]
        return body

    # -------------------------------------------------------------- statements
    def parse_stmts(self, stops) -> list:
        out = []
        while self.t.kind != "eof" and not self.at(*stops):
            start = self.i
            line = self.t.line
            try:
                out.extend(self.parse_stmt())
                self.n_statements += 1
            except ParseError as e:
                self.record(line, str(e), start)
                if self.i == start:
                    self.i += 1
                self.skip_to_semicolon()
        return out

    def parse_stmt(self) -> list:
        t = self.t
        line = t.line
        if t.kind == "punct":
            if t.val == ";":
                self.i += 1
                return []
            if t.val == "<<":
                while not self.at(">>") and self.t.kind != "eof":
                    self.i += 1
                self.opt(">>")
                return []
        if t.kind == "id":
            v = t.val
            if v == "begin":
                self.i += 1
                return self.parse_block_rest()
            if v == "declare":
                return self.parse_anonymous()
            if v == "if":
                return [self.parse_if()]
            if v == "case":
                return [self.parse_case_stmt()]
            if v == "loop":
                self.i += 1
                return [_mk(ast.While, line, test=_const(True, line), body=self.loop_body(), orelse=[])]
            if v == "while":
                self.i += 1
                test = self.parse_expr()
                self.eat("loop")
                return [_mk(ast.While, line, test=test, body=self.loop_body(), orelse=[])]
            if v in ("for", "forall"):
                return [self.parse_for(v)]
            if v == "execute" and self.peek().val == "immediate":
                self.i += 2
                e = self.parse_expr()
                self.skip_to_semicolon()
                return [_mk(ast.Expr, line, value=_call("execute_immediate", [e], line))]
            if v == "open":
                self.i += 1
                self.parse_postfix()
                if self.opt("for"):
                    if self.at("select", "with") or (self.at("(") and self.peek().val in ("select", "with")):
                        self.skip_to_semicolon()
                        return []
                    e = self.parse_expr()
                    self.skip_to_semicolon()
                    return [_mk(ast.Expr, line, value=_call("open_for", [e], line))]
                self.skip_to_semicolon()
                return []
            if v == "return":
                self.i += 1
                val = None if self.at(";") else self.parse_expr()
                self.eat(";")
                return [_mk(ast.Return, line, value=val)]
            if v == "raise" and self._raise_name_end():
                self.skip_to_semicolon()
                return [_mk(ast.Raise, line, exc=None, cause=None)]
            if v in SQL_DML:
                start = self.i
                self.skip_to_semicolon()
                end = self.i
                # static SQL: binds are safe, but functions it calls are not, and what it writes / reads is tracked
                return self.sql_effects(start, end) + self.sql_calls(start, end)
            if v == "fetch":
                start = self.i
                self.skip_to_semicolon()
                return self.fetch_effects(start, self.i)
            if v in SKIP_STMTS or (v == "pragma" and self.peek().kind == "id"):   # pragma inline(f, 'YES');
                self.skip_to_semicolon()
                return []
        if t.kind not in ("id", "bind") and not (t.kind == "punct" and t.val == "("):   # (self as t).m(…);
            raise ParseError(f"unexpected {t.raw or t.val!r}")
        target = self.parse_postfix()
        if self.opt(":="):
            value = self.parse_expr()
            self.eat(";")
            return self.assign(target, value, line)
        self.eat(";")
        call = self._as_call(target, line)
        name = _dotted(call.func) if isinstance(call, ast.Call) else ""
        if name.split(".")[-1] == "raise_application_error" and name in RAISE_APP_ERROR:
            return [_mk(ast.Raise, line, exc=None, cause=None)]   # ends the block like `raise`: the guard before it holds
        self._header_state(name, call)
        if self.header_open is True and name in HTP_WRITES:
            call.func = _name(HEADER_WRITE, line)                 # htp.p while the HTTP header is open writes a header line
        elif self.header_open and name in HTP_WRITES:              # open on some paths only: a header line or HTML
            hdr = copy.deepcopy(call)
            hdr.func = _name(HEADER_WRITE, line)
            return [_mk(ast.Expr, line, value=hdr), _mk(ast.Expr, line, value=call)]
        return [_mk(ast.Expr, line, value=call)]

    def _raise_name_end(self) -> bool:
        """At `raise`: re-raise (`raise;`) or a [qualified] exception name (`raise pkg.e_failed;`)."""
        k = 1
        if self.peek(k).kind == "id":
            k += 1
            while self.peek(k).val == "." and self.peek(k + 1).kind == "id":
                k += 2
        return self.peek(k).val == ";"

    def _merge_header(self, *states) -> None:
        """The header state after branches that ended in `states`: the same on every path, or "maybe"."""
        self.header_open = states[0] if all(x == states[0] for x in states) else "maybe"

    def _header_state(self, name: str, call) -> None:
        """owa_util.mime_header / status_line / redirect_url with bclose_header => false leave the HTTP header open;
        owa_util.http_header_close closes it. What htp writes in between is header text, not HTML."""
        short = name[4:] if name.startswith("sys.") else name
        if short == "owa_util.http_header_close":
            self.header_open = False
            return
        pos = HEADER_OPENERS.get(short)
        if pos is None:
            return
        arg = next((k.value for k in call.keywords if (k.arg or "").lower() == "bclose_header"), None)
        if arg is None and len(call.args) > pos:
            arg = call.args[pos]
        if isinstance(arg, ast.Constant) and arg.value is False:
            self.header_open = True
        elif arg is None or (isinstance(arg, ast.Constant) and arg.value is True):
            self.header_open = False                              # bclose_header => true (the default) closes it
        else:
            self.header_open = "maybe"                            # bclose_header => l_flag: open or closed

    @staticmethod
    def _as_call(e, line):
        """A bare procedure name used as a statement is a call."""
        if isinstance(e, (ast.Name, ast.Attribute)):
            return _call(e, [], line)
        return e

    def assign(self, target, value, line) -> list:
        if isinstance(target, ast.Name):
            return [_mk(ast.Assign, line, targets=[_name(target.id, line, store=True)], value=value)]
        if isinstance(target, ast.Attribute):
            if _dotted(target).startswith("apex_item."):          # :P1_X := v  (session state write)
                if target.attr == "FORWARD_LOCATION":              # ORDS: redirects the client to this URL
                    return [_mk(ast.Expr, line, value=_call("ords_forward_location", [value], line))]
                return [_mk(ast.Expr, line, value=_call("apex_util.set_session_state", [_const(target.attr, line), value], line))]
            target.ctx = ast.Store()
            return [_mk(ast.Assign, line, targets=[target], value=value)]
        if isinstance(target, ast.Call) and target.args:          # arr(i) := v   -> arr[i] = v
            sub = _mk(ast.Subscript, line, value=target.func, slice=target.args[0], ctx=ast.Store())
            return [_mk(ast.Assign, line, targets=[sub], value=value)]
        return [_mk(ast.Expr, line, value=value)]

    def loop_body(self) -> list:
        s0 = self.header_open
        body = self.parse_stmts({"end"})
        self._merge_header(s0, self.header_open)          # the body may run zero times
        self.eat("end")
        self.opt("loop")
        if self.t.kind == "id":
            self.i += 1
        self.eat(";")
        return body or [_mk(ast.Pass, self.t.line)]

    def parse_if(self):
        line = self.t.line
        self.eat("if")
        test = self.parse_expr()
        self.eat("then")
        s0 = self.header_open
        body = self.parse_stmts({"elsif", "else", "end"})
        s_body, self.header_open = self.header_open, s0
        orelse = []
        if self.at("elsif"):
            self.t.val = "if"
            orelse = [self.parse_if_tail()]
            self._merge_header(s_body, self.header_open)
            return _mk(ast.If, line, test=test, body=body or [_mk(ast.Pass, line)], orelse=orelse)
        if self.opt("else"):
            orelse = self.parse_stmts({"end"})
        self._merge_header(s_body, self.header_open)
        self.eat("end")
        self.eat("if")
        self.eat(";")
        return _mk(ast.If, line, test=test, body=body or [_mk(ast.Pass, line)], orelse=orelse)

    def parse_if_tail(self):
        """An `elsif` chain shares the final `end if;` of the outer `if`."""
        line = self.t.line
        self.eat("if")
        test = self.parse_expr()
        self.eat("then")
        s0 = self.header_open
        body = self.parse_stmts({"elsif", "else", "end"})
        s_body, self.header_open = self.header_open, s0
        orelse = []
        if self.at("elsif"):
            self.t.val = "if"
            orelse = [self.parse_if_tail()]
            self._merge_header(s_body, self.header_open)
        else:
            if self.opt("else"):
                orelse = self.parse_stmts({"end"})
            self._merge_header(s_body, self.header_open)
            self.eat("end")
            self.eat("if")
            self.eat(";")
        return _mk(ast.If, line, test=test, body=body or [_mk(ast.Pass, line)], orelse=orelse)

    def parse_case_stmt(self):
        line = self.t.line
        self.eat("case")
        subj = _const(True, line)
        if not self.at("when"):
            subj = self.parse_expr()
        body = []
        s0, ends = self.header_open, []
        while self.opt("when"):
            self.parse_expr()
            self.eat("then")
            self.header_open = s0
            body.extend(self.parse_stmts({"when", "else", "end"}))
            ends.append(self.header_open)
        self.header_open = s0
        if self.opt("else"):
            body.extend(self.parse_stmts({"end"}))
        self._merge_header(*ends, self.header_open)
        self.eat("end")
        self.eat("case")
        if self.t.kind == "id":
            self.i += 1
        self.eat(";")
        return _mk(ast.If, line, test=subj, body=body or [_mk(ast.Pass, line)], orelse=[])

    def parse_for(self, kw):
        line = self.t.line
        self.i += 1
        var = self.eat().val
        row_info = None
        self.eat("in")
        self.opt("reverse")
        if self.at("indices", "values") and self.peek().val == "of":
            self.i += 2
            it = self.parse_expr()
        elif self.at("(") and self.peek().val in ("select", "with"):
            start = self.i
            self.skip_balanced()                     # implicit cursor over static SQL (bound, safe) …
            pre = self.sql_calls(start, self.i)      # … except the PL/SQL functions it calls
            row_info = self.select_info(start + 1, self.i - 1)
            it = _const("", line)
            if pre:
                self.pending_pre.extend(pre)
        else:
            lo = self.parse_expr()
            if self.opt(".."):
                hi = self.parse_expr()
                it = _call("range", [lo, hi], line)
            else:
                it = lo
                cur = lo.func if isinstance(lo, ast.Call) else lo
                if isinstance(cur, ast.Name) and cur.id in self.cursors:
                    row_info = self.cursors[cur.id]
        if kw == "forall":
            self.opt("save")
            self.opt("exceptions")
            body = self.parse_stmt()
        else:
            self.eat("loop")
            body = self.loop_body()
        if row_info:
            body = self.row_loads(var, row_info, line) + (body or [])
        loop = _mk(ast.For, line, target=_name(var, line, store=True), iter=it, body=body or [_mk(ast.Pass, line)],
                   orelse=[], type_comment=None)
        if self.pending_pre:
            pre, self.pending_pre = self.pending_pre, []
            return _mk(ast.If, line, test=_const(True, line), body=pre + [loop], orelse=[])
        return loop

    # ------------------------------------------------------- table effects
    def _path(self, j, end):
        """id(.id)* at token j -> (last name upper, qualifier or None, next j)."""
        parts = [self.toks[j].val]
        j += 1
        while j + 1 < end and self.toks[j].val == "." and self.toks[j + 1].kind == "id":
            parts.append(self.toks[j + 1].val)
            j += 2
        return parts[-1].upper(), (parts[-2] if len(parts) > 1 else None), j

    def select_info(self, sel: int, end: int) -> dict:
        """A static SELECT (token range starting at `select`/`with`) -> columns read, into-targets and tables."""
        toks = self.toks
        while sel < end and not (toks[sel].kind == "id" and toks[sel].val == "select"):
            sel += 1
        items, into, frm = [[]], [[]], []
        state, depth = "list", 0
        for k in range(sel + 1, end):
            t = toks[k]
            if t.kind == "punct" and t.val == "(":
                depth += 1
            elif t.kind == "punct" and t.val == ")":
                depth -= 1
                if depth < 0:
                    break
            if depth == 0 and t.kind == "id":
                if t.val in ("bulk", "collect", "distinct", "unique", "all") and state in ("list", "into"):
                    continue
                if t.val == "into" and state == "list":
                    state = "into"
                    continue
                if t.val == "from" and state in ("list", "into"):
                    state = "from"
                    continue
                if state == "from" and t.val in ("where", "group", "order", "connect", "start", "having", "union", "minus",
                                                  "intersect", "fetch", "for", "offset", "model", "window"):
                    break
            if depth == 0 and t.kind == "punct" and t.val in (",", ";"):
                if t.val == ";":
                    break
                if state == "list":
                    items.append([])
                elif state == "into":
                    into.append([])
                else:
                    frm.append(t)
                continue
            (items[-1] if state == "list" else into[-1] if state == "into" else frm).append(t)
        tables, first = {}, None
        seg: list = []
        for t in frm + [Tok("punct", ",", 0, False)]:
            if (t.kind == "punct" and t.val == ",") or (t.kind == "id" and t.val in ("join", "on", "using")):
                if seg and seg[0].kind == "id" and seg[0].val not in ("inner", "left", "right", "full", "cross", "natural", "outer", "lateral", "table", "json_table", "xmltable"):
                    parts = [x for x in seg if x.kind == "id"]
                    dots = [x for x in seg if x.kind == "punct" and x.val == "."]
                    name = parts[len(dots)].val if len(parts) > len(dots) else parts[0].val
                    tbl = parts[min(len(dots), len(parts) - 1)].val.upper()
                    alias = parts[len(dots) + 1].val if len(parts) > len(dots) + 1 else name
                    tables[alias] = tbl
                    tables.setdefault(tbl.lower(), tbl)
                    first = first or tbl
                seg = []
                continue
            if t.kind == "id" and t.val in ("inner", "left", "right", "full", "cross", "natural", "outer", "lateral"):
                continue
            seg.append(t)
        cols = []
        for it in items:
            ids = [x for x in it if x.kind == "id" and x.val != "as"]
            simple = it and it[0].kind == "id" and all(x.kind == "id" or (x.kind == "punct" and x.val == ".") for x in it)
            if not simple or not ids:
                cols.append(None)
                continue
            dotted = any(x.kind == "punct" for x in it)
            col = (ids[1] if dotted else ids[0]).val.upper()
            qual = ids[0].val if dotted else None
            alias = (ids[2] if dotted and len(ids) > 2 else ids[1] if not dotted and len(ids) > 1 else None)
            tbl = tables.get(qual) if qual else (first if len({v for v in tables.values()}) == 1 else first)
            cols.append((tbl, col, (alias.val if alias else col.lower())) if tbl else None)
        targets = []
        for tv in into:
            ids = [x for x in tv if x.kind in ("id", "bind")]
            targets.append(tv if ids else None)
        return {"cols": cols, "into": targets}

    @staticmethod
    def _load(table: str, col: str, line: int):
        return _mk(ast.Attribute, line, value=_mk(ast.Attribute, line, value=_name("stored_db", line), attr=table, ctx=ast.Load()),
                   attr=col, ctx=ast.Load())

    def _target(self, toks_, line):
        """into-target tokens (v / rec.f / :P1_X) -> assignment target."""
        if len(toks_) == 1 and toks_[0].kind == "id":
            return _name(toks_[0].val, line, store=True)
        if len(toks_) == 3 and toks_[0].kind == "id" and toks_[1].val == "." and toks_[2].kind == "id":
            return _mk(ast.Attribute, line, value=_name(toks_[0].val, line), attr=toks_[2].val, ctx=ast.Store())
        return None

    def row_loads(self, var: str, info: dict, line: int) -> list:
        """Rows of a cursor loop: rec.<column alias> holds the stored column value."""
        out = []
        for c in info.get("cols", []):
            if c:
                tbl, col, alias = c
                out.append(_mk(ast.Assign, line, targets=[_mk(ast.Attribute, line, value=_name(var, line), attr=alias, ctx=ast.Store())],
                               value=self._load(tbl, col, line)))
        return out

    def sql_effects(self, start: int, end: int) -> list:
        """What a static INSERT / UPDATE writes into table columns, and what SELECT … INTO reads from them."""
        toks, line = self.toks, self.toks[start].line
        v = toks[start].val
        save = self.i
        out: list = []
        try:
            if v in ("select", "with"):
                info = self.select_info(start, end)
                for c, tgt in zip(info["cols"], info["into"]):
                    t = self._target(tgt, line) if (c and tgt) else None
                    if t is not None:
                        out.append(_mk(ast.Assign, line, targets=[t], value=self._load(c[0], c[1], line)))
            elif v == "insert" and start + 2 < end and toks[start + 1].val == "into" and toks[start + 2].kind == "id":
                table, _, j = self._path(start + 2, end)
                if j < end and toks[j].kind == "id" and toks[j].val not in ("values", "select", "with"):
                    j += 1                                           # alias
                if j < end and toks[j].val == "(":
                    cols, j = [], j + 1
                    while j < end and toks[j].val != ")":
                        if toks[j].kind == "id":
                            cols.append(toks[j].val.upper())
                        j += 1
                    j += 1
                    exprs = []
                    if j < end and toks[j].val == "values" and j + 1 < end and toks[j + 1].val == "(":
                        self.i = j + 2
                        while not self.at(")") and self.t.kind != "eof" and self.i < end:
                            exprs.append(self.parse_expr())
                            if not self.opt(","):
                                break
                    elif j < end and toks[j].val in ("select", "with"):
                        info = self.select_info(j, end)              # table-to-table copies carry the stored value
                        self.i = j + 1
                        while self.i < end and toks[self.i].val in ("select", "distinct", "all", "unique"):
                            self.i += 1
                        k = 0
                        while self.i < end and not self.at("from", ";"):
                            e = self.parse_expr()
                            c = info["cols"][k] if k < len(info["cols"]) else None
                            exprs.append(self._load(c[0], c[1], line) if c else e)
                            k += 1
                            self.opt("as")
                            if self.t.kind == "id" and not self.at("from"):
                                self.i += 1                          # column alias
                            if not self.opt(","):
                                break
                    for col, e in zip(cols, exprs):
                        out.append(_mk(ast.Expr, line, value=_call(f"stored_db_write__{table}__{col}", [e], line)))
            elif v == "update" and start + 1 < end and toks[start + 1].kind == "id":
                table, _, j = self._path(start + 1, end)
                if j < end and toks[j].kind == "id" and toks[j].val != "set":
                    j += 1
                if j < end and toks[j].val == "set":
                    self.i = j + 1
                    while self.i < end and self.t.kind == "id":
                        col, _, k = self._path(self.i, end)
                        self.i = k
                        if not self.opt("="):
                            break
                        e = self.parse_expr()
                        out.append(_mk(ast.Expr, line, value=_call(f"stored_db_write__{table}__{col}", [e], line)))
                        if not self.opt(","):
                            break
        except ParseError:
            pass
        self.i = save
        return out

    def fetch_effects(self, start: int, end: int) -> list:
        """fetch c [bulk collect] into a, b — positions map to the cursor's select list."""
        toks, line = self.toks, self.toks[start].line
        if start + 1 >= end or toks[start + 1].kind != "id":
            return []
        info = self.cursors.get(toks[start + 1].val)
        if not info:
            return []
        j = start + 2
        while j < end and toks[j].val != "into":
            j += 1
        targets, cur = [], []
        for t in toks[j + 1:end]:
            if t.kind == "id" and t.val == "limit":
                break
            if t.kind == "punct" and t.val in (",", ";"):
                targets.append(cur)
                cur = []
                continue
            cur.append(t)
        if cur:
            targets.append(cur)
        out = []
        for c, tg in zip(info["cols"], targets):
            t = self._target(tg, line) if c else None
            if t is not None:
                out.append(_mk(ast.Assign, line, targets=[t], value=self._load(c[0], c[1], line)))
        return out

    def sql_calls(self, start: int, end: int) -> list:
        """Function calls inside a static SQL statement (token range) -> expression statements.

        `select pkg.f(:P1_X) from dual` binds :P1_X safely for SQL, but pkg.f still receives the value: if it builds
        dynamic SQL from it, that is injection. Calls with only constant arguments are dropped."""
        out, j, save = [], start, self.i
        toks = self.toks
        while j < end:
            t = toks[j]
            if t.kind == "id" and t.val not in SQL_NON_FUNCS and not (j > start and toks[j - 1].val in (".", "into", "update", "table")):
                k = j + 1
                while k + 1 < end and toks[k].val == "." and toks[k + 1].kind == "id":
                    k += 2
                if k < end and toks[k].kind == "punct" and toks[k].val == "(":
                    self.i = j
                    try:
                        e = self.parse_postfix()
                        if self.i > j and any(isinstance(n, (ast.Name, ast.Attribute)) for a in getattr(e, "args", []) + [k.value for k in getattr(e, "keywords", [])]
                                              for n in ast.walk(a)):
                            out.append(_mk(ast.Expr, t.line, value=e))
                        j = max(self.i, j + 1)
                        continue
                    except ParseError:
                        pass
            j += 1
        self.i = save
        return out

    # -------------------------------------------------------------- expressions
    def parse_expr(self):
        return self.parse_or()

    def parse_or(self):
        left = self.parse_and()
        vals = [left]
        while self.opt("or"):
            vals.append(self.parse_and())
        return vals[0] if len(vals) == 1 else _mk(ast.BoolOp, getattr(left, "lineno", self.t.line), op=ast.Or(), values=vals)

    def parse_and(self):
        left = self.parse_not()
        vals = [left]
        while self.opt("and"):
            vals.append(self.parse_not())
        return vals[0] if len(vals) == 1 else _mk(ast.BoolOp, getattr(left, "lineno", self.t.line), op=ast.And(), values=vals)

    def parse_not(self):
        if self.at("not"):
            line = self.t.line
            self.i += 1
            return _mk(ast.UnaryOp, line, op=ast.Not(), operand=self.parse_not())
        return self.parse_cmp()

    def parse_cmp(self):
        left = self.parse_concat()
        line = getattr(left, "lineno", self.t.line)
        ops = {"=": ast.Eq(), "<>": ast.NotEq(), "!=": ast.NotEq(), "^=": ast.NotEq(), "~=": ast.NotEq(),
               "<": ast.Lt(), ">": ast.Gt(), "<=": ast.LtE(), ">=": ast.GtE()}
        if self.t.kind == "punct" and self.t.val in ops:
            op = ops[self.eat().val]
            if self.at("any", "some", "all"):
                self.i += 1
            return _mk(ast.Compare, line, left=left, ops=[op], comparators=[self.parse_concat()])
        if self.opt("is"):
            neg = self.opt("not")
            if self.at("a"):
                self.i += 2
            elif not self.at("of"):
                self.i += 1                      # null / empty / json / dangling / infinite / nan …
            if self.opt("of"):                   # x is [not] of [type] (t1, only t2)
                self.opt("type")
                if self.at("("):
                    self.skip_balanced()
            return _mk(ast.Compare, line, left=left, ops=[ast.IsNot() if neg else ast.Is()], comparators=[_const(None, line)])
        neg = self.opt("not")
        if self.at("like", "like2", "like4", "likec"):
            self.i += 1
            pat = self.parse_concat()
            if self.opt("escape"):
                self.parse_concat()
            return _mk(ast.Compare, line, left=left, ops=[ast.NotEq() if neg else ast.Eq()], comparators=[pat])
        if self.opt("in"):
            if self.at("(") and self.peek().val in ("select", "with"):
                self.skip_balanced()
                return _mk(ast.Compare, line, left=left, ops=[ast.NotIn() if neg else ast.In()], comparators=[_mk(ast.List, line, elts=[], ctx=ast.Load())])
            self.eat("(")
            elts = []
            while not self.at(")") and self.t.kind != "eof":
                elts.append(self.parse_expr())
                if not self.opt(","):
                    break
            self.eat(")")
            return _mk(ast.Compare, line, left=left, ops=[ast.NotIn() if neg else ast.In()], comparators=[_mk(ast.List, line, elts=elts, ctx=ast.Load())])
        if self.opt("between"):
            lo = self.parse_concat()
            self.eat("and")
            hi = self.parse_concat()
            return _mk(ast.BoolOp, line, op=ast.And(), values=[
                _mk(ast.Compare, line, left=left, ops=[ast.GtE()], comparators=[lo]),
                _mk(ast.Compare, line, left=left, ops=[ast.LtE()], comparators=[hi])])
        if self.at("member", "submultiset"):
            self.i += 1
            self.opt("of")
            return _mk(ast.Compare, line, left=left, ops=[ast.In()], comparators=[self.parse_concat()])
        if neg:
            raise ParseError("dangling NOT")
        return left

    def parse_concat(self):
        left = self.parse_mul()
        while (self.t.kind == "punct" and self.t.val in ("||", "+", "-")) or (
                self.at("multiset") and self.peek().val in ("union", "intersect", "except")):
            line = self.eat().line
            if self.opt("union", "intersect", "except"):       # a multiset b: elements of both
                self.opt("all", "distinct")
            left = _mk(ast.BinOp, line, left=left, op=ast.Add(), right=self.parse_mul())
        return left

    def parse_mul(self):
        left = self.parse_unary()
        while (self.t.kind == "punct" and self.t.val in ("*", "/")) or self.at("mod", "rem"):
            if self.at("/") and self.t.nl and self.peek().nl:
                break                                # SQL*Plus `/` on its own line
            line = self.eat().line
            left = _mk(ast.BinOp, line, left=left, op=ast.Mult(), right=self.parse_unary())
        return left

    def parse_unary(self):
        if self.t.kind == "punct" and self.t.val in ("-", "+"):
            self.i += 1
            return self.parse_unary()
        if self.at("prior", "distinct", "all"):
            self.i += 1
        e = self.parse_postfix()
        if self.opt("**"):
            e = _mk(ast.BinOp, getattr(e, "lineno", self.t.line), left=e, op=ast.Pow(), right=self.parse_unary())
        return e

    def parse_postfix(self):
        e = self.parse_primary()
        while True:
            t = self.t
            if t.kind == "punct" and t.val == "." and self.peek().kind in ("id", "str"):
                self.i += 1
                nm = self.eat()
                e = _mk(ast.Attribute, nm.line, value=e, attr=nm.val, ctx=ast.Load())
            elif t.kind == "punct" and t.val == "(":
                e = self.parse_call(e, t.line)
            elif t.kind == "punct" and t.val == "%":
                self.i += 1
                attr = self.eat().val
                e = _mk(ast.Attribute, t.line, value=e, attr=attr, ctx=ast.Load()) if attr == "rowtype" else _const(0, t.line)
            elif self.at("at") and self.peek().val in ("time", "local"):
                self.i += 1                           # ts at local / ts at time zone tz: the same value, in another zone
                if self.opt("time"):
                    self.eat("zone")
                    zone = self.parse_unary()
                    e = _mk(ast.BinOp, t.line, left=e, op=ast.Add(), right=zone)
                else:
                    self.i += 1
            elif t.kind == "punct" and t.val == "@" and self.peek().kind == "id":
                self.i += 2                           # remote call over a db link
            elif self.at("within", "over", "keep") and self.peek().val in ("group", "(", "dense_rank"):
                self.i += 1
                if self.at("group", "dense_rank"):
                    self.i += 1
                if self.at("("):
                    self.skip_balanced()
            else:
                return e

    def parse_call(self, func, line):
        self.eat("(")
        args, kws = [], []
        while not self.at(")") and self.t.kind != "eof":
            if self.at("*") and self.peek().val == ")":
                self.i += 1
                break
            if self.t.kind == "id" and self.peek().val == "=>":
                k = self.eat().val
                self.i += 1
                kws.append(ast.keyword(arg=k, value=self.parse_expr()))
            else:
                self.opt("distinct", "all", "unique")
                # trim(both|leading|trailing [c] from s); json_object(key 'k' value v)
                if self.at("both", "leading", "trailing", "key") and self.peek().kind in ("str", "bind", "num", "id"):
                    self.i += 1
                    if self.opt("from"):
                        args.append(self.parse_expr())
                        self._arg_tail(args)
                        if not self.opt(","):
                            break
                        continue
                args.append(self.parse_expr())
                self._arg_tail(args)
            if not self.opt(","):
                break
        self.eat(")")
        canon = _dotted(func)
        if canon in SESSION_GETTERS and len(args) == 1 and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
            name = args[0].value.strip().upper()
            if name.lower() not in BUILTIN_BINDS and re.match(r"^[A-Z][A-Z0-9_$#]*$", name):
                return _item(name, line)              # v('P1_X') -> apex_item.P1_X
        return _mk(ast.Call, line, func=func, args=args, keywords=kws)

    def _arg_tail(self, args) -> None:
        """What may follow an argument before `,` or `)`: another value that keeps its data (json_object's
        `'k' : v` / `'k' value v`, trim's / extract's `from s`), or a clause with no data to follow (cast's `as t`,
        `format json`, `absent on null`, `returning t`, `order by …`, `default … on conversion error`), skipped."""
        while not self.at(",", ")") and self.t.kind != "eof":
            if self.at(":", "value", "from"):
                self.i += 1
                args.append(self.parse_expr())
            elif self.t.kind == "bind":            # 'k':v written without a space: v is a variable, unless a page item
                tok = self.eat()
                args.append(_item(tok.raw, tok.line) if re.match(r"(?i)^p\d+_", tok.raw) else _name(tok.val, tok.line))
            elif self.at("("):
                self.skip_balanced()
            else:
                self.i += 1

    def parse_primary(self):
        t = self.t
        line = t.line
        if t.kind == "num":
            self.i += 1
            try:
                return _const(float(t.val.rstrip("fFdD")), line)
            except ValueError:
                return _const(0, line)
        if t.kind == "str":
            self.i += 1
            return _const(t.val, line)
        if t.kind == "bind":
            self.i += 1
            if t.val in BUILTIN_BINDS:
                return _name(t.val, line)
            return _item(t.raw, line)
        if t.kind == "punct" and t.val == "(":
            if self.peek().val in ("select", "with"):
                self.skip_balanced()                  # scalar sub-query: static SQL
                return _const("", line)
            self.i += 1
            first = self.parse_expr()
            if self.opt("as"):                        # (self as supertype): the same object, seen as its supertype
                self.skip_type({")"})
            elts = [first]
            while self.opt(","):
                elts.append(self.parse_expr())
            self.eat(")")
            return first if len(elts) == 1 else _mk(ast.Tuple, line, elts=elts, ctx=ast.Load())
        if t.kind == "punct" and t.val == "&":
            raise ParseError("substitution variable in code")
        if t.kind != "id":
            raise ParseError(f"unexpected {t.raw or t.val!r}")
        v = t.val
        if v == "case":
            return self.parse_case_expr()
        if v in ("true", "false"):
            self.i += 1
            return _const(v == "true", line)
        if v == "null":
            self.i += 1
            return _const(None, line)
        if v in ("date", "timestamp", "interval") and self.peek().kind == "str":
            self.i += 2
            while self.at("day", "hour", "minute", "second", "year", "month", "to"):
                self.i += 1
            return _const("", line)
        if v == "new" and self.peek().kind == "id":
            self.i += 1
            return self.parse_primary()
        if v in ("cast", "treat", "extract", "trim", "xmlcast"):
            self.i += 1
            if self.at("("):
                return self.parse_call(_name(v, line), line)
            return _name(v, line)
        if v == "multiset":
            self.i += 1
            if self.at("("):
                self.skip_balanced()
            return _const("", line)
        if v in ("exists",) and self.peek().val == "(":
            self.i += 1
            self.skip_balanced()
            return _const(True, line)
        if v in ("then", "else", "end", "loop", "when", "is", "as", "begin", "exception", ";"):
            raise ParseError(f"unexpected {t.raw or v!r}")
        self.i += 1
        return _name(v, line)

    def parse_case_expr(self):
        line = self.t.line
        self.eat("case")
        if not self.at("when"):
            self.parse_expr()
        results = []
        while self.opt("when"):
            self.parse_expr()
            self.eat("then")
            results.append(self.parse_expr())
        if self.opt("else"):
            results.append(self.parse_expr())
        self.eat("end")
        if not results:
            return _const(None, line)
        return results[0] if len(results) == 1 else _mk(ast.BoolOp, line, op=ast.Or(), values=results)


def java_sources(text: str) -> list[tuple[str, int, str]]:
    """`create … and compile java source named "X" as …` blocks -> [(name, first line, java text)]."""
    out = []
    for m in _JAVA_SRC.finditer(text):
        start = text.count("\n", 0, m.start(2)) + 1
        out.append((m.group(1).strip('"'), start, m.group(2)))
    return out


def wrapped_units(text: str) -> list[tuple[int, int, str, str]]:
    """Units obfuscated by Oracle's wrap utility -> [(header line, last line, unit type, name)]. The wrapped text is
    base64-like by design: it cannot be analysed, and it is not a secret. The unit ends at the next line holding only
    `/` (a wrapped line may start with `/`, never consist of it); without one, at the end of the file."""
    if not re.search(r"wrapped", text, re.I):
        return []
    out = []
    pos = 0
    while True:
        m = _WRAPPED_HEAD.search(text, pos)
        if not m:
            return out
        start = text.count("\n", 0, m.start()) + 1
        e = _WRAPPED_END.search(text, m.end())
        stop = e.end() if e else len(text)
        body = text[m.end():e.start() if e else len(text)]
        if not _WRAPPED_BODY.match(body) or ";" in body:
            # not the output of wrap (a header in a comment or a string, or source code with the word): read it as code
            pos = m.end()
            continue
        end = text.count("\n", 0, stop) + 1
        if not e and text.endswith("\n"):
            end -= 1
        kind = " ".join(m.group(1).lower().split())
        name = re.sub(r"\s+", "", m.group(2)).replace('"', "")
        out.append((start, max(start, end), kind, name))
        pos = stop


def blank_wrapped(text: str) -> str:
    """Blank wrapped units (keeping every line) so the parser neither reads their text nor reports it as skipped."""
    units = wrapped_units(text)
    if not units:
        return text
    lines = text.split("\n")
    for start, end, _k, _n in units:
        for k in range(start - 1, min(end, len(lines))):
            lines[k] = ""
    return "\n".join(lines)


def blank_java_sources(text: str) -> str:
    """Remove Java source blocks (keeping line numbers) so the PL/SQL parser does not trip over them."""
    return _JAVA_SRC.sub(lambda m: "\n" * m.group(0).count("\n"), text)


def parse_plsql(text: str):
    """Parse PL/SQL source. Returns (units, diagnostics)."""
    diag = {"language": "plsql", "statements": 0, "skipped": 0, "lines": [], "wrapped": []}
    try:
        diag["wrapped"] = wrapped_units(text)
        p = Parser(blank_wrapped(blank_java_sources(text)) if diag["wrapped"] else blank_java_sources(text))
        units = p.parse_program()
        diag["statements"] = p.n_statements
        diag["skipped"] = p.n_skipped
        diag["lines"] = list(p.diagnostics)
        return units, diag
    except Exception as e:  # noqa: BLE001 - never abort a scan on a frontend bug
        diag["skipped"] = 1
        diag["lines"] = [(1, f"frontend failure: {type(e).__name__}: {e}")]
        return [], diag


def sql_call_units(sql: str, unit: str) -> tuple[list, dict]:
    """A static SQL query (APEX report / LOV source, ORDS query handler) -> a unit holding the PL/SQL calls it makes."""
    diag = {"language": "sql", "statements": 0, "skipped": 0, "lines": []}
    try:
        p = Parser(sql)
        calls = p.sql_calls(0, len(p.toks) - 1)
    except Exception as e:  # noqa: BLE001
        diag["skipped"] = 1
        diag["lines"] = [(1, f"sql frontend failure: {type(e).__name__}: {e}")]
        return [], diag
    diag["statements"] = len(calls)
    if not calls:
        return [], diag
    fn = _mk(ast.FunctionDef, 1, name=unit, args=_args([], 1), body=calls, decorator_list=[], returns=None, type_params=[])
    return [Unit("standalone", unit, [fn], 1)], diag


def shift_lines(tree: ast.AST, delta: int) -> ast.AST:
    """Move every node of a lowered tree down by `delta` lines (code extracted from inside a larger file)."""
    if delta:
        for n in ast.walk(tree):
            if hasattr(n, "lineno") and isinstance(getattr(n, "lineno", None), int):
                n.lineno += delta
                if isinstance(getattr(n, "end_lineno", None), int):
                    n.end_lineno += delta
    return tree


def build_modules(units_by_file: list[tuple[str, list[Unit]]], external: dict | None = None) -> list[tuple[str, str, ast.Module]]:
    """Turn parsed units into engine modules and cross-link them.

    Every package (or type) body becomes a module named after it, so `pkg.proc(x)` resolves; standalone
    sub-programs and anonymous blocks live in a module per source file and are imported by name everywhere.
    Returns [(module name, rel path, module)].
    """
    mods: list[tuple[str, str, list]] = []
    packages: dict[str, str] = {}
    standalone: dict[str, str] = {}
    used: set = set()

    def uniq(base):
        name = re.sub(r"[^\w]", "_", base) or "plsql"
        cand, k = name, 1
        while cand in used:
            k += 1
            cand = f"{name}_{k}"
        used.add(cand)
        return cand

    for rel, units in units_by_file:
        file_mod = None
        for u in units:
            if u.kind in ("package", "type"):
                mname = uniq(u.name)
                packages.setdefault(u.name, mname)
                mods.append((mname, rel, list(u.body)))
            else:
                if file_mod is None:
                    file_mod = (uniq("plsql_" + re.sub(r"\W", "_", rel.rsplit("/", 1)[-1].rsplit(".", 1)[0]).lower()), rel, [])
                    mods.append(file_mod)
                if u.kind == "anonymous":
                    fn = _mk(ast.FunctionDef, u.line, name=u.name, args=_args([], u.line), body=u.body or [_mk(ast.Pass, u.line)],
                             decorator_list=[], returns=None, type_params=[])
                    file_mod[2].append(fn)
                else:
                    file_mod[2].extend(u.body)
                    standalone.setdefault(u.name, file_mod[0])
    out = []
    for mname, rel, body in mods:
        # import only what this module references (an APEX export can hold thousands of units)
        used_names = {n.id for st in body for n in ast.walk(st) if isinstance(n, ast.Name)}
        imports = []
        for pkg in sorted(used_names & packages.keys()):
            if packages[pkg] != mname:
                imports.append(_mk(ast.Import, 1, names=[ast.alias(name=packages[pkg], asname=pkg)]))
        for fname in sorted(used_names & standalone.keys()):
            if standalone[fname] != mname:
                imports.append(_mk(ast.ImportFrom, 1, module=standalone[fname], names=[ast.alias(name=fname, asname=None)], level=0))
        for cname in sorted(used_names & (external or {}).keys()):      # Java classes behind call specs
            imports.append(_mk(ast.ImportFrom, 1, module=external[cname], names=[ast.alias(name=cname, asname=None)], level=0))
        out.append((mname, rel, ast.Module(body=imports + body, type_ignores=[])))
    return out
