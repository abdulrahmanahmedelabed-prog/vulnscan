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
    (?P<num>\d+(?:\.\d+)?(?:[eE][+-]?\d+)?[fFdD]?\b) |
    (?P<qid>"[^"\n]+") |
    (?P<punct>:=|=>|\|\||\.\.|<>|!=|\^=|~=|<=|>=|\*\*|<<|>>) |
    (?P<bind>:[A-Za-z_][\w$#]*) |
    (?P<id>[A-Za-z_][\w$#]*) |
    (?P<one>[-+*/%(),;.=<>@:&|\[\]{}!?^~])
""", re.S | re.X)
_QPAIRS = {"[": "]", "{": "}", "(": ")", "<": ">"}
_JAVA_SRC = re.compile(r"create\s+(?:or\s+replace\s+)?(?:and\s+(?:resolve|compile)\s+)?(?:noforce\s+)?java\s+source\s+named\s+"
                       r"(\"[^\"]+\"|\S+)\s+(?:as|is)\s*?\n(.*?)^\s*/\s*$", re.I | re.S | re.M)


class Tok:
    __slots__ = ("kind", "val", "line", "nl", "raw")

    def __init__(self, kind, val, line, nl, raw=None):
        self.kind, self.val, self.line, self.nl, self.raw = kind, val, line, nl, raw

    def __repr__(self):
        return f"Tok({self.kind},{self.val!r},{self.line})"


def tokenize(src: str) -> list[Tok]:
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
        elif kind == "bind":
            toks.append(Tok("bind", text[1:].lower(), line, nl, text[1:]))
        elif kind == "id":
            toks.append(Tok("id", text.lower(), line, nl, text))
        else:
            toks.append(Tok("punct", text, line, nl))
        nl = False
        i = m.end()
    toks.append(Tok("eof", "", line, True))
    return toks


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
        self.toks = tokenize(src)
        self.i = 0
        self.diagnostics: list = []
        self.n_statements = 0
        self.anon = 0
        self.pending_pre: list = []

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

    def record(self, line, msg):
        if len(self.diagnostics) < 500:
            self.diagnostics.append((line, msg))

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
                self.record(self.toks[start].line, str(e))
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
        if t.kind != "id":
            raise ParseError(f"unexpected {t.raw or t.val!r}")
        v = t.val
        if v in SQLPLUS_CMDS and t.nl:
            self._skip_line()
            return None
        if v in ("exec", "execute") and t.nl and self.peek().val != "immediate":
            self.i += 1
            line = self.t.line
            e = self.parse_expr()
            self.opt(";")
            return Unit("anonymous", f"exec_{line}", [_mk(ast.Expr, line, value=self._as_call(e, line))], line)
        if v in ("declare", "begin"):
            line = t.line
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
            if self.at("end") and (self.peek().val == ";" or (self.peek().kind == "id" and self.peek(2).val == ";")):
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
        body = self.decls_and_body(name)
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
                    self.skip_to_semicolon()
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
                self.record(line, str(e))
                if self.i == start:
                    self.i += 1
                self.skip_to_semicolon()
        return out

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
                self.record(line, str(e))
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
            if v == "raise" and self.peek().val in (";",) or (v == "raise" and self.peek().kind == "id" and self.peek(2).val == ";"):
                self.skip_to_semicolon()
                return [_mk(ast.Raise, line, exc=None, cause=None)]
            if v in SQL_DML:
                start = self.i
                self.skip_to_semicolon()
                return self.sql_calls(start, self.i)      # static SQL: binds are safe, but functions it calls are not
            if v in SKIP_STMTS:
                self.skip_to_semicolon()
                return []
        if t.kind not in ("id", "bind"):
            raise ParseError(f"unexpected {t.raw or t.val!r}")
        target = self.parse_postfix()
        if self.opt(":="):
            value = self.parse_expr()
            self.eat(";")
            return self.assign(target, value, line)
        self.eat(";")
        return [_mk(ast.Expr, line, value=self._as_call(target, line))]

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
        body = self.parse_stmts({"end"})
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
        body = self.parse_stmts({"elsif", "else", "end"})
        orelse = []
        if self.at("elsif"):
            self.t.val = "if"
            orelse = [self.parse_if_tail()]
            return _mk(ast.If, line, test=test, body=body or [_mk(ast.Pass, line)], orelse=orelse)
        if self.opt("else"):
            orelse = self.parse_stmts({"end"})
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
        body = self.parse_stmts({"elsif", "else", "end"})
        orelse = []
        if self.at("elsif"):
            self.t.val = "if"
            orelse = [self.parse_if_tail()]
        else:
            if self.opt("else"):
                orelse = self.parse_stmts({"end"})
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
        while self.opt("when"):
            self.parse_expr()
            self.eat("then")
            body.extend(self.parse_stmts({"when", "else", "end"}))
        if self.opt("else"):
            body.extend(self.parse_stmts({"end"}))
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
        self.eat("in")
        self.opt("reverse")
        if self.at("indices", "values") and self.peek().val == "of":
            self.i += 2
            it = self.parse_expr()
        elif self.at("(") and self.peek().val in ("select", "with"):
            start = self.i
            self.skip_balanced()                     # implicit cursor over static SQL (bound, safe) …
            pre = self.sql_calls(start, self.i)      # … except the PL/SQL functions it calls
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
        if kw == "forall":
            self.opt("save")
            self.opt("exceptions")
            body = self.parse_stmt()
        else:
            self.eat("loop")
            body = self.loop_body()
        loop = _mk(ast.For, line, target=_name(var, line, store=True), iter=it, body=body or [_mk(ast.Pass, line)],
                   orelse=[], type_comment=None)
        if self.pending_pre:
            pre, self.pending_pre = self.pending_pre, []
            return _mk(ast.If, line, test=_const(True, line), body=pre + [loop], orelse=[])
        return loop

    def sql_calls(self, start: int, end: int) -> list:
        """Function calls inside a static SQL statement (token range) -> expression statements.

        `select pkg.f(:P1_X) from dual` binds :P1_X safely for SQL, but pkg.f still receives the value: if it builds
        dynamic SQL from it, that is injection. Calls with only constant arguments are dropped."""
        out, j, save = [], start, self.i
        toks = self.toks
        while j < end:
            t = toks[j]
            if t.kind == "id" and t.val not in SQL_NON_FUNCS and not (j > start and toks[j - 1].val == "."):
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
            else:
                self.i += 1                      # null / empty / json / of …
            if self.at("of"):
                self.i += 1
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
        while self.t.kind == "punct" and self.t.val in ("||", "+", "-"):
            line = self.eat().line
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
                self.opt("distinct", "all")
                args.append(self.parse_expr())
                if self.at("as") or self.at("from") or self.at("using") or self.at("returning") or self.at("default"):
                    while not self.at(",", ")") and self.t.kind != "eof":   # cast(x as t) / extract(y from d) / trim(x from y)
                        if self.at("("):
                            self.skip_balanced()
                            continue
                        self.i += 1
            if not self.opt(","):
                break
        self.eat(")")
        canon = _dotted(func)
        if canon in SESSION_GETTERS and len(args) == 1 and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
            name = args[0].value.strip().upper()
            if name.lower() not in BUILTIN_BINDS and re.match(r"^[A-Z][A-Z0-9_$#]*$", name):
                return _item(name, line)              # v('P1_X') -> apex_item.P1_X
        return _mk(ast.Call, line, func=func, args=args, keywords=kws)

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


def blank_java_sources(text: str) -> str:
    """Remove Java source blocks (keeping line numbers) so the PL/SQL parser does not trip over them."""
    return _JAVA_SRC.sub(lambda m: "\n" * m.group(0).count("\n"), text)


def parse_plsql(text: str):
    """Parse PL/SQL source. Returns (units, diagnostics)."""
    diag = {"language": "plsql", "statements": 0, "skipped": 0, "lines": []}
    try:
        p = Parser(blank_java_sources(text))
        units = p.parse_program()
        diag["statements"] = p.n_statements
        diag["skipped"] = len(p.diagnostics)
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
