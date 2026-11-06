"""JavaScript / TypeScript frontend: a tolerant parser that lowers JS/TS into Python ``ast`` nodes.

The taint engine only depends on the *shape* of the program (functions,
classes, calls, assignments, attributes, returns, ifs, imports), so other
languages are supported by lowering them into the same AST the engine
already understands. This module handles ES2020+ and the TypeScript syntax
that matters for data flow (type annotations are skipped, decorators and
parameter properties are kept). It is tolerant: an unparseable statement is
skipped and parsing resumes at the next statement, so real-world files never
abort the analysis.

Lowering rules worth knowing:
* ``const fs = require('fs')`` -> ``import fs``; ``const {exec} = require('m')`` -> ``from m import exec``;
  ``import x from './m'`` / ``import {a as b} from 'm'`` -> import aliases (relative specifiers resolved).
* ``const run = (c) => {...}`` and callbacks passed to ``app.get(...)`` etc. become named functions;
  route callbacks get a ``route`` decorator so their parameters are entry-point sources.
* ``class C { constructor(x) { this.x = x } m() {...} }`` -> a Python class with ``self``.
* ``obj.innerHTML = v`` stays an attribute assignment (modelled as an attribute sink).
* Template literals -> f-strings, ``a + b`` -> BinOp, ``a ? b : c`` -> IfExp, ``&&``/``||`` -> BoolOp.
"""

from __future__ import annotations

import ast
import re

KEYWORDS = {
    "var", "let", "const", "function", "class", "extends", "return", "if", "else", "for", "while", "do",
    "try", "catch", "finally", "throw", "new", "this", "super", "import", "export", "default", "from", "as",
    "async", "await", "typeof", "instanceof", "in", "of", "delete", "void", "switch", "case", "break",
    "continue", "null", "undefined", "true", "false", "yield", "static", "get", "set", "interface", "type",
    "enum", "declare", "namespace", "module", "implements", "public", "private", "protected", "readonly",
    "abstract", "override", "constructor", "with", "debugger",
}
ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "all", "use", "route", "handle", "ws", "head", "options"}
TOKEN_RE = re.compile(r"""
    (?P<ws>[ \t\r\f\v]+) | (?P<nl>\n) | (?P<lc>//[^\n]*) | (?P<bc>/\*.*?\*/) |
    (?P<num>0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+|(?:\d[\d_]*\.?[\d_]*|\.\d[\d_]*)(?:[eE][+-]?\d+)?n?) |
    (?P<str>"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*') |
    (?P<tpl>`) |
    (?P<id>[A-Za-z_$][\w$]*) |
    (?P<punct>>>>=|\.\.\.|===|!==|\*\*=|<<=|>>=|>>>|&&=|\|\|=|\?\?=|=>|\?\.|\?\?|==|!=|<=|>=|&&|\|\||\+\+|--|\+=|-=|\*=|/=|%=|&=|\|=|\^=|\*\*|<<|>>|[{}()\[\];,<>+\-*/%&|^!~?:=.@#])
""", re.S | re.X)


class Tok:
    __slots__ = ("kind", "val", "line", "nl_before")

    def __init__(self, kind, val, line, nl_before=False):
        self.kind, self.val, self.line, self.nl_before = kind, val, line, nl_before

    def __repr__(self):
        return f"Tok({self.kind},{self.val!r},{self.line})"


def tokenize(src: str) -> list[Tok]:
    toks: list[Tok] = []
    i, line, n = 0, 1, len(src)
    nl_before = False

    def prev_allows_regex():
        if not toks:
            return True
        t = toks[-1]
        if t.kind in ("num", "str", "tpl", "regex"):
            return False
        if t.kind == "id":
            return t.val in {"return", "typeof", "case", "in", "of", "new", "delete", "void", "throw", "do", "else", "instanceof", "await", "yield"}
        return t.val not in (")", "]", "}")

    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] not in "/*" and prev_allows_regex():
            j, in_cls = i + 1, False
            while j < n and (src[j] != "/" or in_cls) and src[j] != "\n":
                if src[j] == "\\":
                    j += 1
                elif src[j] == "[":
                    in_cls = True
                elif src[j] == "]":
                    in_cls = False
                j += 1
            j += 1
            while j < n and src[j].isalpha():
                j += 1
            toks.append(Tok("regex", src[i:j], line, nl_before))
            nl_before = False
            i = j
            continue
        m = TOKEN_RE.match(src, i)
        if not m:
            i += 1
            continue
        kind = m.lastgroup
        text = m.group(0)
        if kind == "nl":
            line += 1
            nl_before = True
            i = m.end()
            continue
        if kind in ("ws", "lc"):
            i = m.end()
            continue
        if kind == "bc":
            line += text.count("\n")
            i = m.end()
            continue
        if kind == "tpl":
            j = i + 1
            parts: list = []
            buf = ""
            start_line = line
            while j < n and src[j] != "`":
                if src[j] == "\\":
                    buf += src[j:j + 2]
                    j += 2
                    continue
                if src[j] == "$" and j + 1 < n and src[j + 1] == "{":
                    parts.append(("str", buf))
                    buf = ""
                    depth, k = 1, j + 2
                    while k < n and depth:
                        if src[k] == "{":
                            depth += 1
                        elif src[k] == "}":
                            depth -= 1
                        elif src[k] == "`":  # nested template: skip to its end
                            k += 1
                            while k < n and src[k] != "`":
                                k += 1
                        k += 1
                    parts.append(("expr", src[j + 2:k - 1], line))
                    line += src[j:k].count("\n")
                    j = k
                    continue
                if src[j] == "\n":
                    line += 1
                buf += src[j]
                j += 1
            parts.append(("str", buf))
            toks.append(Tok("tpl", parts, start_line, nl_before))
            nl_before = False
            i = j + 1
            continue
        toks.append(Tok(kind, text, line, nl_before))
        nl_before = False
        i = m.end()
    toks.append(Tok("eof", "", line, True))
    return toks


class ParseError(Exception):
    pass


def _mk(cls, line, **kw):
    node = cls(**kw)
    node.lineno = node.end_lineno = line
    node.col_offset = node.end_col_offset = 0
    return node


def _name(ident, line, store=False):
    return _mk(ast.Name, line, id=ident, ctx=ast.Store() if store else ast.Load())


def _const(v, line):
    return _mk(ast.Constant, line, value=v)


def _args(names, line, annotations=None):
    annotations = annotations or {}
    return ast.arguments(posonlyargs=[], args=[_mk(ast.arg, line, arg=n, annotation=annotations.get(n)) for n in names],
                         vararg=None, kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[])


def module_name(rel: str) -> str:
    rel = rel.replace("\\", "/")
    rel = re.sub(r"\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)$", "", rel)
    if rel.endswith("/index"):
        rel = rel[:-6]
    return rel.replace("/", ".")


def resolve_specifier(spec: str, cur_mod: str) -> str:
    """'./util' from 'src.routes.users' -> 'src.routes.util'; '../lib/x' -> 'src.lib.x'; 'fs/promises' -> 'fs.promises'."""
    spec = re.sub(r"\.(js|jsx|mjs|cjs|ts|tsx|json)$", "", spec)
    if spec.startswith("."):
        base = cur_mod.split(".")[:-1]
        parts = spec.split("/")
        for p in parts:
            if p == ".":
                continue
            if p == "..":
                if base:
                    base.pop()
            elif p:
                base.append(p)
        if base and base[-1] == "index":
            base.pop()
        return ".".join(base)
    spec = spec.lstrip("@")
    if spec.endswith("/index"):
        spec = spec[:-6]
    return spec.replace("/", ".")


class Parser:
    def __init__(self, src: str, rel: str = "file.js"):
        self.toks = tokenize(src)
        self.i = 0
        self.mod = module_name(rel)
        self.hoisted: list = []       # statements to prepend to the current statement
        self.imports: list = []       # module-level imports produced by require()
        self.req_counter = 0
        self.cls_stack: list = []
        self.anon = 0

    # ------------------------------------------------------------ helpers
    @property
    def t(self) -> Tok:
        return self.toks[self.i]

    def peek(self, k=1) -> Tok:
        j = min(self.i + k, len(self.toks) - 1)
        return self.toks[j]

    def at(self, val, kind=None) -> bool:
        t = self.t
        return (kind is None or t.kind == kind) and t.val == val and t.kind != "str" and t.kind != "tpl"

    def at_kw(self, val) -> bool:
        return self.t.kind == "id" and self.t.val == val

    def eat(self, val=None) -> Tok:
        t = self.t
        if val is not None and t.val != val:
            raise ParseError(f"expected {val!r} got {t.val!r} at line {t.line}")
        self.i += 1
        return t

    def opt(self, val) -> bool:
        if self.t.kind != "str" and self.t.kind != "tpl" and self.t.val == val:
            self.i += 1
            return True
        return False

    def skip_semi(self):
        while self.opt(";"):
            pass

    def sync(self):
        """Error recovery: skip to the end of the current statement."""
        depth = 0
        while self.t.kind != "eof":
            v = self.t.val if self.t.kind == "punct" else None
            if v in ("(", "[", "{"):
                depth += 1
            elif v in (")", "]", "}"):
                if depth == 0:
                    if v == "}":
                        return
                    self.i += 1
                    continue
                depth -= 1
            elif v == ";" and depth == 0:
                self.i += 1
                return
            elif depth == 0 and self.t.nl_before and self.i > 0:
                return
            self.i += 1

    # ------------------------------------------------------------ program
    def parse_program(self) -> ast.Module:
        body = self.parse_statements(top=True)
        return ast.Module(body=self.imports + body, type_ignores=[])

    def parse_statements(self, top=False) -> list:
        out = []
        while self.t.kind != "eof" and not (not top and self.at("}")):
            start = self.i
            try:
                stmts = self.parse_statement()
                out.extend(self.hoisted)
                self.hoisted = []
                out.extend(stmts)
            except ParseError:
                self.hoisted = []
                self.sync()
                if self.i == start:
                    self.i += 1
        return out

    def block(self) -> list:
        self.eat("{")
        body = self.parse_statements()
        self.eat("}")
        return body or [_mk(ast.Pass, self.t.line)]

    def body_or_stmt(self) -> list:
        if self.at("{"):
            return self.block()
        stmts = self.parse_statement()
        pre, self.hoisted = self.hoisted, []
        return (pre + stmts) or [_mk(ast.Pass, self.t.line)]

    # ------------------------------------------------------- statements
    def parse_decorators(self) -> list:
        decs = []
        while self.at("@"):
            self.eat("@")
            decs.append(self.parse_postfix(no_call=False))
        return decs

    def parse_statement(self) -> list:
        t = self.t
        line = t.line
        decs = self.parse_decorators() if self.at("@") else []
        t = self.t
        if t.kind == "punct":
            if t.val == ";":
                self.i += 1
                return []
            if t.val == "{":
                return self.block()
        if t.kind == "id":
            v = t.val
            if v == "import" and self.peek().val not in ("(", "."):
                return self.parse_import()
            if v == "export":
                return self.parse_export(decs)
            if v in ("var", "let", "const") and self.peek().kind == "id" or (v in ("var", "let", "const") and self.peek().val in ("{", "[")):
                return self.parse_var_decl()
            if v == "function" or (v == "async" and self.peek().val == "function"):
                return [self.parse_function_decl(decs)]
            if v == "class" or (v == "abstract" and self.peek().val == "class"):
                if v == "abstract":
                    self.i += 1
                return [self.parse_class(decs)]
            if v == "return":
                self.i += 1
                val = None
                if not self.t.nl_before and not self.at(";") and not self.at("}") and self.t.kind != "eof":
                    val = self.parse_expression()
                self.skip_semi()
                return [_mk(ast.Return, line, value=val)]
            if v == "throw":
                self.i += 1
                val = self.parse_expression()
                self.skip_semi()
                return [_mk(ast.Raise, line, exc=val, cause=None)]
            if v == "if":
                return [self.parse_if()]
            if v == "for":
                return [self.parse_for()]
            if v == "while":
                self.i += 1
                self.eat("(")
                test = self.parse_expression()
                self.eat(")")
                body = self.body_or_stmt()
                return [_mk(ast.While, line, test=test, body=body, orelse=[])]
            if v == "do":
                self.i += 1
                body = self.body_or_stmt()
                self.eat("while")
                self.eat("(")
                test = self.parse_expression()
                self.eat(")")
                self.skip_semi()
                return [_mk(ast.While, line, test=test, body=body, orelse=[])]
            if v == "try":
                return [self.parse_try()]
            if v == "switch":
                self.i += 1
                self.eat("(")
                subj = self.parse_expression()
                self.eat(")")
                self.eat("{")
                body = []
                while not self.at("}") and self.t.kind != "eof":
                    if self.at_kw("case"):
                        self.i += 1
                        self.parse_expression()
                        self.eat(":")
                    elif self.at_kw("default"):
                        self.i += 1
                        self.eat(":")
                    else:
                        body.extend(self.parse_statement())
                self.eat("}")
                return [_mk(ast.If, line, test=subj, body=body or [_mk(ast.Pass, line)], orelse=[])]
            if v in ("break", "continue"):
                self.i += 1
                self.skip_semi()
                return [_mk(ast.Continue if v == "continue" else ast.Break, line)]
            if v in ("interface", "type", "enum", "declare", "namespace") and self.peek().kind == "id":
                self.skip_ts_declaration()
                return []
            if v == "debugger":
                self.i += 1
                self.skip_semi()
                return []
        expr = self.parse_expression()
        self.skip_semi()
        return self.expr_statement(expr, line)

    def expr_statement(self, expr, line) -> list:
        # assignments are parsed into a marker tuple by parse_assignment
        if isinstance(expr, tuple) and expr[0] == "assign":
            _, target, op, value, aline = expr
            return self.make_assign(target, op, value, aline)
        if isinstance(expr, tuple):
            expr = self.untuple(expr)
        return [_mk(ast.Expr, line, value=expr)]

    def untuple(self, e):
        if isinstance(e, tuple) and e[0] == "assign":
            _, target, op, value, aline = e
            # assignment used as an expression: emit the statement, yield the target
            self.hoisted.extend(self.make_assign(target, op, value, aline))
            return self.to_load(target)
        return e

    def to_load(self, n):
        if isinstance(n, ast.Name):
            return _name(n.id, n.lineno)
        return n

    def make_assign(self, target, op, value, line) -> list:
        value = self.untuple(value)
        # exports.x = v / module.exports.x = v  ->  x = v
        if isinstance(target, ast.Attribute):
            base = self.dotted(target.value)
            if base in ("exports", "module.exports"):
                target = _name(target.attr, line, store=True)
                if isinstance(value, (ast.Lambda,)) or (isinstance(value, ast.Name) and value.id.startswith("_fn_")):
                    pass
        if isinstance(target, ast.Attribute) and self.dotted(target) == "module.exports":
            return []
        # function values assigned to names become named functions (resolvable callees)
        if op == "=" and isinstance(target, ast.Name) and isinstance(value, ast.Name) and value.id.startswith("_fn_"):
            fn = self.pop_hoisted_function(value.id)
            if fn is not None:
                fn.name = target.id
                if target.id == "handler":
                    fn.decorator_list.append(_name("handler", line))
                return [fn]
        if op == "=":
            if isinstance(target, (ast.Name, ast.Attribute, ast.Subscript)):
                self.set_store(target)
                return [_mk(ast.Assign, line, targets=[target], value=value)]
            return [_mk(ast.Expr, line, value=value)]
        self.set_store(target)
        return [_mk(ast.AugAssign, line, target=target, op=ast.Add(), value=value)]

    def set_store(self, n):
        if isinstance(n, (ast.Name, ast.Attribute, ast.Subscript)):
            n.ctx = ast.Store()

    def pop_hoisted_function(self, name):
        for idx, st in enumerate(self.hoisted):
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)) and st.name == name:
                return self.hoisted.pop(idx)
        return None

    def dotted(self, n) -> str:
        if isinstance(n, ast.Name):
            return n.id
        if isinstance(n, ast.Attribute):
            b = self.dotted(n.value)
            return f"{b}.{n.attr}" if b else n.attr
        return ""

    def parse_var_decl(self) -> list:
        line = self.t.line
        self.i += 1  # var/let/const
        out = []
        while True:
            target = self.parse_binding_target()
            self.skip_type_annotation()
            if self.opt("="):
                value = self.parse_assignment()
                out.extend(self.lower_declarator(target, value, line))
            elif isinstance(target, ast.Name):
                pass
            if not self.opt(","):
                break
        self.skip_semi()
        return out

    def lower_declarator(self, target, value, line) -> list:
        value = self.untuple(value)
        # const x = require('m')
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "require" \
                and value.args and isinstance(value.args[0], ast.Constant) and isinstance(value.args[0].value, str):
            modname = resolve_specifier(value.args[0].value, self.mod)
            if isinstance(target, ast.Name):
                return [_mk(ast.Import, line, names=[ast.alias(name=modname, asname=target.id)])]
            if isinstance(target, tuple) and target[0] == "obj":
                names = [ast.alias(name=k, asname=v) for k, v in target[1]]
                return [_mk(ast.ImportFrom, line, module=modname, names=names, level=0)]
        if isinstance(target, ast.Name) and isinstance(value, ast.Name) and value.id.startswith("_fn_"):
            fn = self.pop_hoisted_function(value.id)
            if fn is not None:
                fn.name = target.id
                return [fn]
        if isinstance(target, ast.Name):
            return [_mk(ast.Assign, line, targets=[_name(target.id, line, store=True)], value=value)]
        if isinstance(target, tuple):
            tmp = f"_d{line}_{self.anon}"
            self.anon += 1
            out = [_mk(ast.Assign, line, targets=[_name(tmp, line, store=True)], value=value)]
            out.extend(self.destructure(target, _name(tmp, line), line))
            return out
        return [_mk(ast.Expr, line, value=value)]

    def destructure(self, pattern, src, line) -> list:
        out = []
        if pattern[0] == "obj":
            for key, local in pattern[1]:
                out.append(_mk(ast.Assign, line, targets=[_name(local, line, store=True)],
                               value=_mk(ast.Attribute, line, value=src, attr=key, ctx=ast.Load())))
        elif pattern[0] == "arr":
            for idx, local in enumerate(pattern[1]):
                if local is None:
                    continue
                out.append(_mk(ast.Assign, line, targets=[_name(local, line, store=True)],
                               value=_mk(ast.Subscript, line, value=src, slice=_const(idx, line), ctx=ast.Load())))
        return out

    def parse_binding_target(self):
        """Name node, or ('obj', [(key, local)...]) / ('arr', [local|None...]) patterns."""
        t = self.t
        if t.kind == "id":
            self.i += 1
            return _name(t.val, t.line)
        if self.at("{"):
            self.eat("{")
            pairs = []
            while not self.at("}") and self.t.kind != "eof":
                if self.opt("..."):
                    rest = self.eat()
                    pairs.append((rest.val, rest.val))
                else:
                    k = self.eat()
                    key = k.val.strip("'\"") if k.kind == "str" else k.val
                    local = key
                    if self.opt(":"):
                        sub = self.parse_binding_target()
                        local = sub.id if isinstance(sub, ast.Name) else key
                    if self.opt("="):
                        self.parse_assignment()
                    pairs.append((key, local))
                if not self.opt(","):
                    break
            self.eat("}")
            return ("obj", pairs)
        if self.at("["):
            self.eat("[")
            items = []
            while not self.at("]") and self.t.kind != "eof":
                if self.at(","):
                    items.append(None)
                else:
                    self.opt("...")
                    sub = self.parse_binding_target()
                    items.append(sub.id if isinstance(sub, ast.Name) else None)
                    if self.opt("="):
                        self.parse_assignment()
                if not self.opt(","):
                    break
            self.eat("]")
            return ("arr", items)
        raise ParseError(f"bad binding at line {t.line}")

    def parse_import(self) -> list:
        line = self.t.line
        self.eat("import")
        if self.at_kw("type"):
            self.i += 1
        names: list = []
        default = None
        ns = None
        if self.t.kind == "str":
            spec = self.t.val.strip("'\"")
            self.i += 1
            self.skip_semi()
            return [_mk(ast.Import, line, names=[ast.alias(name=resolve_specifier(spec, self.mod), asname=None)])]
        if self.t.kind == "id" and self.t.val not in ("{",):
            default = self.eat().val
            self.opt(",")
        if self.opt("*"):
            self.eat("as")
            ns = self.eat().val
        elif self.at("{"):
            self.eat("{")
            while not self.at("}") and self.t.kind != "eof":
                if self.at_kw("type"):
                    self.i += 1
                n = self.eat().val
                asname = None
                if self.at_kw("as"):
                    self.i += 1
                    asname = self.eat().val
                names.append(ast.alias(name=n, asname=asname))
                if not self.opt(","):
                    break
            self.eat("}")
        self.eat("from")
        spec = self.eat().val.strip("'\"")
        self.skip_semi()
        modname = resolve_specifier(spec, self.mod)
        out = []
        if default:
            out.append(_mk(ast.Import, line, names=[ast.alias(name=modname, asname=default)]))
        if ns:
            out.append(_mk(ast.Import, line, names=[ast.alias(name=modname, asname=ns)]))
        if names:
            out.append(_mk(ast.ImportFrom, line, module=modname, names=names, level=0))
        return out

    def parse_export(self, decs) -> list:
        self.eat("export")
        if self.at_kw("default"):
            self.i += 1
            if self.at_kw("function") or (self.at_kw("async") and self.peek().val == "function"):
                return [self.parse_function_decl(decs, default_name="default_export")]
            if self.at_kw("class"):
                return [self.parse_class(decs)]
            expr = self.parse_expression()
            self.skip_semi()
            return self.expr_statement(expr, self.t.line)
        if self.at("{") or self.at("*"):
            self.sync()
            return []
        if self.at_kw("type") or self.at_kw("interface") or self.at_kw("enum") or self.at_kw("declare"):
            self.skip_ts_declaration()
            return []
        return self.parse_statement_after_decorators(decs)

    def parse_statement_after_decorators(self, decs) -> list:
        if self.at_kw("class") or (self.at_kw("abstract") and self.peek().val == "class"):
            if self.at_kw("abstract"):
                self.i += 1
            return [self.parse_class(decs)]
        if self.at_kw("function") or (self.at_kw("async") and self.peek().val == "function"):
            return [self.parse_function_decl(decs)]
        return self.parse_statement()

    def skip_ts_declaration(self):
        # interface X {...} | type X = ... ; | enum X {...} | declare ... | namespace X {...}
        self.i += 1
        depth = 0
        while self.t.kind != "eof":
            v = self.t.val if self.t.kind == "punct" else None
            if v == "{":
                depth += 1
            elif v == "}":
                depth -= 1
                if depth <= 0:
                    self.i += 1
                    return
            elif v == ";" and depth == 0:
                self.i += 1
                return
            elif depth == 0 and self.t.nl_before and self.t.kind == "id" and self.t.val in ("export", "import", "const", "let", "var", "function", "class", "interface", "type", "enum"):
                return
            self.i += 1

    def skip_type_annotation(self):
        if self.opt("?"):
            pass
        if self.opt("!"):
            pass
        if self.at(":"):
            self.eat(":")
            self.skip_type()

    def skip_type(self):
        """Consume a TS type expression."""
        while True:
            if self.at_kw("readonly") or self.at_kw("keyof") or self.at_kw("typeof") or self.at_kw("new"):
                self.i += 1
                continue
            break
        t = self.t
        if t.kind in ("id", "str", "num"):
            self.i += 1
            while self.opt("."):
                self.i += 1
            if self.at("<"):
                self.skip_balanced("<", ">")
            if t.kind == "id" and self.at("(") and False:
                pass
        elif self.at("{"):
            self.skip_balanced("{", "}")
        elif self.at("("):
            self.skip_balanced("(", ")")
            if self.opt("=>"):
                self.skip_type()
        elif self.at("["):
            self.skip_balanced("[", "]")
        elif self.at("<"):
            self.skip_balanced("<", ">")
            if self.at("("):
                self.skip_balanced("(", ")")
                if self.opt("=>"):
                    self.skip_type()
        while self.at("["):
            self.skip_balanced("[", "]")
        if self.at("|") or self.at("&"):
            self.i += 1
            self.skip_type()
        if self.at_kw("extends"):
            self.i += 1
            self.skip_type()
            if self.opt("?"):
                self.skip_type()
                self.eat(":")
                self.skip_type()

    def skip_balanced(self, open_, close):
        depth = 0
        while self.t.kind != "eof":
            if self.at(open_):
                depth += 1
            elif self.at(close):
                depth -= 1
                if depth == 0:
                    self.i += 1
                    return
            elif close == ">" and self.at(">>"):
                depth -= 2
                self.i += 1
                if depth <= 0:
                    return
                continue
            self.i += 1

    def parse_params(self) -> tuple[list, list, dict]:
        """Returns (param names, prologue statements for destructuring/param-properties, annotations)."""
        self.eat("(")
        names, prologue, annotations = [], [], {}
        while not self.at(")") and self.t.kind != "eof":
            self.parse_decorators()
            prop = False
            while self.t.kind == "id" and self.t.val in ("public", "private", "protected", "readonly", "override"):
                self.i += 1
                prop = True
            rest = self.opt("...")
            tgt = self.parse_binding_target()
            if self.opt("?"):
                pass
            ann = None
            if self.at(":"):
                self.eat(":")
                start = self.i
                self.skip_type()
                ann_tok = self.toks[start]
                if ann_tok.kind == "id":
                    ann = _name(ann_tok.val, ann_tok.line)
            if self.opt("="):
                self.parse_assignment()
            if isinstance(tgt, ast.Name):
                names.append(tgt.id)
                if ann is not None:
                    annotations[tgt.id] = ann
                if prop:
                    line = tgt.lineno
                    prologue.append(_mk(ast.Assign, line, targets=[_mk(ast.Attribute, line, value=_name("self", line), attr=tgt.id, ctx=ast.Store())],
                                        value=_name(tgt.id, line)))
            else:
                tmp = f"_p{len(names)}"
                names.append(tmp)
                prologue.extend(self.destructure(tgt, _name(tmp, self.t.line), self.t.line))
            if not self.opt(","):
                break
        self.eat(")")
        return names, prologue, annotations

    def parse_function_decl(self, decs, default_name=None):
        line = self.t.line
        is_async = False
        if self.at_kw("async"):
            is_async = True
            self.i += 1
        self.eat("function")
        self.opt("*")
        name = default_name or f"_fn_{line}_{self.anon}"
        if self.t.kind == "id" and not self.at("("):
            name = self.eat().val
        if self.at("<"):
            self.skip_balanced("<", ">")
        params, prologue, ann = self.parse_params()
        self.skip_type_annotation()
        body = prologue + self.block() if self.at("{") else prologue + [_mk(ast.Pass, line)]
        return self.make_function(name, params, body, line, decs, is_async, ann)

    def make_function(self, name, params, body, line, decs, is_async, ann=None, method=False):
        if method:
            params = ["self"] + [p for p in params if p != "self"]
        cls = ast.AsyncFunctionDef if is_async else ast.FunctionDef
        fn = _mk(cls, line, name=name, args=_args(params, line, ann), body=body or [_mk(ast.Pass, line)],
                 decorator_list=list(decs), returns=None, type_params=[])
        return fn

    def parse_class(self, decs) -> ast.ClassDef:
        line = self.t.line
        self.eat("class")
        name = self.eat().val if self.t.kind == "id" and not self.at("{") and not self.at_kw("extends") else f"_cls_{line}"
        if self.at("<"):
            self.skip_balanced("<", ">")
        bases = []
        if self.at_kw("extends"):
            self.i += 1
            bases.append(self.parse_postfix(no_call=True))
            if self.at("<"):
                self.skip_balanced("<", ">")
        if self.at_kw("implements"):
            self.i += 1
            self.skip_type()
            while self.opt(","):
                self.skip_type()
        self.eat("{")
        self.cls_stack.append(name)
        methods = []
        field_inits = []
        ctor = None
        while not self.at("}") and self.t.kind != "eof":
            if self.opt(";"):
                continue
            mdecs = self.parse_decorators() if self.at("@") else []
            is_async, is_static = False, False
            while self.t.kind == "id" and self.t.val in ("static", "public", "private", "protected", "readonly", "abstract", "override", "declare", "async", "get", "set") \
                    and self.peek().kind in ("id", "str", "num") or (self.t.kind == "id" and self.t.val in ("static", "public", "private", "protected", "readonly", "abstract", "override", "async") and self.peek().val in ("[", "#", "*")):
                if self.t.val == "async":
                    is_async = True
                if self.t.val == "static":
                    is_static = True
                self.i += 1
            self.opt("*")
            self.opt("#")
            if self.at("["):
                self.eat("[")
                self.parse_expression()
                self.eat("]")
                mname = f"_computed_{self.t.line}"
            else:
                mt = self.eat()
                mname = mt.val.strip("'\"") if mt.kind == "str" else mt.val
            self.opt("?")
            self.opt("!")
            mline = self.t.line
            if self.at("<"):
                self.skip_balanced("<", ">")
            if self.at("("):
                params, prologue, ann = self.parse_params()
                self.skip_type_annotation()
                body = prologue + (self.block() if self.at("{") else [_mk(ast.Pass, mline)])
                self.opt(";")
                pyname = "__init__" if mname == "constructor" else mname
                fn = self.make_function(pyname, params, body, mline, mdecs, is_async, ann, method=True)
                if pyname == "__init__":
                    ctor = fn
                else:
                    methods.append(fn)
            else:
                self.skip_type_annotation()
                if self.opt("="):
                    val = self.untuple(self.parse_assignment())
                    field_inits.append(_mk(ast.Assign, mline, targets=[_mk(ast.Attribute, mline, value=_name("self", mline), attr=mname, ctx=ast.Store())], value=val))
                self.opt(";")
        self.eat("}")
        self.cls_stack.pop()
        if field_inits:
            if ctor is None:
                ctor = self.make_function("__init__", [], [], line, [], False, method=True)
            ctor.body = field_inits + [s for s in ctor.body if not isinstance(s, ast.Pass)] or [_mk(ast.Pass, line)]
        body = ([ctor] if ctor else []) + methods
        return _mk(ast.ClassDef, line, name=name, bases=bases, keywords=[], body=body or [_mk(ast.Pass, line)],
                   decorator_list=list(decs), type_params=[])

    def parse_if(self):
        line = self.t.line
        self.eat("if")
        self.eat("(")
        test = self.untuple(self.parse_expression())
        self.eat(")")
        body = self.body_or_stmt()
        orelse = []
        if self.at_kw("else"):
            self.i += 1
            orelse = self.body_or_stmt() if not self.at_kw("if") else [self.parse_if()]
        return _mk(ast.If, line, test=test, body=body, orelse=orelse)

    def parse_for(self):
        line = self.t.line
        self.eat("for")
        self.opt("await")
        self.eat("(")
        target = None
        if self.t.kind == "id" and self.t.val in ("var", "let", "const"):
            self.i += 1
            target = self.parse_binding_target()
            if self.at_kw("of") or self.at_kw("in"):
                self.i += 1
                it = self.untuple(self.parse_assignment())
                self.eat(")")
                body = self.body_or_stmt()
                if isinstance(target, ast.Name):
                    target.ctx = ast.Store()
                    return _mk(ast.For, line, target=target, iter=it, body=body, orelse=[], type_comment=None)
                tmp = _name(f"_it{line}", line, store=True)
                pre = self.destructure(target, _name(f"_it{line}", line), line)
                return _mk(ast.For, line, target=tmp, iter=it, body=pre + body, orelse=[], type_comment=None)
            init = []
            if self.opt("="):
                v = self.untuple(self.parse_assignment())
                init = self.lower_declarator(target, v, line)
            while self.opt(","):
                self.parse_assignment()
            self.eat(";")
        else:
            if not self.at(";"):
                e = self.parse_expression()
                init = self.expr_statement(e, line)
            else:
                init = []
            if self.at_kw("of") or self.at_kw("in"):
                self.i += 1
                self.parse_assignment()
                self.eat(")")
                body = self.body_or_stmt()
                return _mk(ast.While, line, test=_const(True, line), body=init + body, orelse=[])
            self.eat(";")
        test = _const(True, line) if self.at(";") else self.untuple(self.parse_expression())
        self.eat(";")
        update = []
        if not self.at(")"):
            e = self.parse_expression()
            update = self.expr_statement(e, line)
        self.eat(")")
        body = self.body_or_stmt()
        self.hoisted = init + self.hoisted
        return _mk(ast.While, line, test=test, body=body + update, orelse=[])

    def parse_try(self):
        line = self.t.line
        self.eat("try")
        body = self.block()
        handlers, final = [], []
        if self.at_kw("catch"):
            self.i += 1
            nm = None
            if self.opt("("):
                tgt = self.parse_binding_target()
                nm = tgt.id if isinstance(tgt, ast.Name) else None
                self.skip_type_annotation()
                self.eat(")")
            hb = self.block()
            handlers.append(_mk(ast.ExceptHandler, line, type=None, name=nm, body=hb))
        if self.at_kw("finally"):
            self.i += 1
            final = self.block()
        if not handlers and not final:
            handlers.append(_mk(ast.ExceptHandler, line, type=None, name=None, body=[_mk(ast.Pass, line)]))
        return _mk(ast.Try, line, body=body, handlers=handlers, orelse=[], finalbody=final)

    # ------------------------------------------------------- expressions
    def parse_expression(self):
        e = self.parse_assignment()
        while self.at(","):
            self.i += 1
            e = self.untuple(e)
            e2 = self.parse_assignment()
            e = self.untuple(e2)
        return e

    def parse_assignment(self):
        # arrow functions
        if self.is_arrow_start():
            return self.parse_arrow(False)
        if self.at_kw("async") and (self.peek().val == "(" or (self.peek().kind == "id" and self.peek(2).val == "=>")):
            save = self.i
            self.i += 1
            if self.is_arrow_start():
                return self.parse_arrow(True)
            self.i = save
        if self.at_kw("yield"):
            self.i += 1
            if self.at(";") or self.at(")") or self.t.nl_before:
                return _const(None, self.t.line)
            return self.parse_assignment()
        left = self.parse_conditional()
        t = self.t
        if t.kind == "punct" and t.val in ("=", "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "|=", "^=", "&&=", "||=", "??="):
            self.i += 1
            right = self.parse_assignment()
            left = self.untuple(left)
            return ("assign", left, "=" if t.val == "=" else "+=", right, t.line)
        return left

    def is_arrow_start(self) -> bool:
        t = self.t
        if t.kind == "id" and t.val not in KEYWORDS and self.peek().val == "=>":
            return True
        if self.at("("):
            depth, j = 0, self.i
            while j < len(self.toks):
                tk = self.toks[j]
                if tk.kind == "punct":
                    if tk.val == "(":
                        depth += 1
                    elif tk.val == ")":
                        depth -= 1
                        if depth == 0:
                            nxt = self.toks[j + 1] if j + 1 < len(self.toks) else None
                            if nxt is None:
                                return False
                            if nxt.val == "=>":
                                return True
                            if nxt.val == ":":  # (a): T => ...
                                k = j + 2
                                d2 = 0
                                while k < len(self.toks):
                                    v = self.toks[k].val if self.toks[k].kind == "punct" else None
                                    if v in ("(", "<", "[", "{"):
                                        d2 += 1
                                    elif v in (")", ">", "]", "}"):
                                        d2 -= 1
                                    elif d2 == 0 and v == "=>":
                                        return True
                                    elif d2 == 0 and v in (";", ",", ")") or (d2 == 0 and self.toks[k].nl_before and self.toks[k].kind != "punct"):
                                        return False
                                    k += 1
                            return False
                j += 1
        if self.at("<") and False:
            return True
        return False

    def parse_arrow(self, is_async):
        line = self.t.line
        if self.t.kind == "id":
            params, prologue, ann = [self.eat().val], [], {}
        else:
            params, prologue, ann = self.parse_params()
            self.skip_type_annotation()
        self.eat("=>")
        if self.at("{"):
            body = prologue + self.block()
        else:
            e = self.untuple(self.parse_assignment())
            body = prologue + [_mk(ast.Return, line, value=e)]
        name = f"_fn_{line}_{self.anon}"
        self.anon += 1
        fn = self.make_function(name, params, body, line, [], is_async, ann)
        self.hoisted.append(fn)
        return _name(name, line)

    def parse_conditional(self):
        cond = self.parse_binary(0)
        if self.at("?") and not self.at("?."):
            line = self.t.line
            self.i += 1
            a = self.untuple(self.parse_assignment())
            self.eat(":")
            b = self.untuple(self.parse_assignment())
            return _mk(ast.IfExp, line, test=self.untuple(cond), body=a, orelse=b)
        return cond

    BIN_PREC = {"??": 1, "||": 1, "&&": 2, "|": 3, "^": 4, "&": 5, "==": 6, "!=": 6, "===": 6, "!==": 6,
                "<": 7, ">": 7, "<=": 7, ">=": 7, "instanceof": 7, "in": 7, "<<": 8, ">>": 8, ">>>": 8,
                "+": 9, "-": 9, "*": 10, "/": 10, "%": 10, "**": 11}

    def parse_binary(self, min_prec):
        left = self.parse_unary()
        while True:
            t = self.t
            op = t.val if (t.kind == "punct" or (t.kind == "id" and t.val in ("instanceof", "in"))) else None
            if op not in self.BIN_PREC or self.BIN_PREC[op] < min_prec:
                break
            if op == "<" and self.looks_like_generic_call():
                break
            prec = self.BIN_PREC[op]
            self.i += 1
            right = self.parse_binary(prec + 1)
            left, right = self.untuple(left), self.untuple(right)
            line = t.line
            if op in ("&&", "||", "??"):
                left = _mk(ast.BoolOp, line, op=ast.And() if op == "&&" else ast.Or(), values=[left, right])
            elif op in ("==", "!=", "===", "!==", "<", ">", "<=", ">=", "instanceof", "in"):
                pyop = {"==": ast.Eq(), "===": ast.Eq(), "!=": ast.NotEq(), "!==": ast.NotEq(), "<": ast.Lt(), ">": ast.Gt(),
                        "<=": ast.LtE(), ">=": ast.GtE(), "instanceof": ast.Is(), "in": ast.In()}[op]
                left = _mk(ast.Compare, line, left=left, ops=[pyop], comparators=[right])
            else:
                left = _mk(ast.BinOp, line, left=left, op=ast.Add() if op == "+" else ast.BitOr(), right=right)
        return left

    def looks_like_generic_call(self) -> bool:
        # foo<T>(...) in TS: '<' ... '>' '('
        j, depth = self.i, 0
        while j < len(self.toks) and j < self.i + 40:
            v = self.toks[j].val if self.toks[j].kind == "punct" else None
            if v == "<":
                depth += 1
            elif v == ">":
                depth -= 1
                if depth == 0:
                    return j + 1 < len(self.toks) and self.toks[j + 1].val == "("
            elif v in (";", "{", "}") or (self.toks[j].kind == "str"):
                return False
            j += 1
        return False

    def parse_unary(self):
        t = self.t
        line = t.line
        if t.kind == "punct" and t.val in ("!", "-", "+", "~", "++", "--"):
            self.i += 1
            operand = self.untuple(self.parse_unary())
            if t.val == "!":
                return _mk(ast.UnaryOp, line, op=ast.Not(), operand=operand)
            return operand
        if t.kind == "id" and t.val in ("typeof", "void", "delete"):
            self.i += 1
            return self.untuple(self.parse_unary())
        if t.kind == "id" and t.val == "await":
            self.i += 1
            return _mk(ast.Await, line, value=self.untuple(self.parse_unary()))
        return self.parse_postfix()

    def parse_postfix(self, no_call=False):
        e = self.parse_primary()
        while True:
            t = self.t
            if t.kind != "punct":
                if t.kind == "id" and t.val == "as":
                    self.i += 1
                    self.skip_type()
                    continue
                if t.kind == "tpl":  # tagged template
                    tpl = self.parse_template(self.eat())
                    e = _mk(ast.Call, t.line, func=self.untuple(e), args=[tpl], keywords=[])
                    continue
                break
            if t.val in (".", "?."):
                self.i += 1
                if self.at("[") or self.at("("):
                    continue
                nm = self.eat()
                e = _mk(ast.Attribute, nm.line, value=self.untuple(e), attr=nm.val, ctx=ast.Load())
            elif t.val == "[":
                self.i += 1
                idx = self.untuple(self.parse_expression())
                self.eat("]")
                e = _mk(ast.Subscript, t.line, value=self.untuple(e), slice=idx, ctx=ast.Load())
            elif t.val == "(" and not no_call:
                e = self.parse_call(self.untuple(e), t.line)
            elif t.val == "<" and self.looks_like_generic_call():
                self.skip_balanced("<", ">")
            elif t.val in ("++", "--"):
                self.i += 1
            elif t.val == "!":
                self.i += 1  # TS non-null
            else:
                break
        return e

    def parse_call(self, func, line):
        self.eat("(")
        args = []
        fn_args = []
        while not self.at(")") and self.t.kind != "eof":
            spread = self.opt("...")
            a = self.untuple(self.parse_assignment())
            if spread:
                a = _mk(ast.Starred, line, value=a, ctx=ast.Load())
            if isinstance(a, ast.Name) and a.id.startswith("_fn_"):
                fn_args.append(a.id)
            args.append(a)
            if not self.opt(","):
                break
        self.eat(")")
        # require('m') in expression position -> synthetic import alias
        if isinstance(func, ast.Name) and func.id == "require" and args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
            modname = resolve_specifier(args[0].value, self.mod)
            alias = f"__req{self.req_counter}"
            self.req_counter += 1
            self.imports.append(_mk(ast.Import, line, names=[ast.alias(name=modname, asname=alias)]))
            return _name(alias, line)
        # route registrations: callbacks become entry points
        member = func.attr if isinstance(func, ast.Attribute) else (func.id if isinstance(func, ast.Name) else "")
        if member in ROUTE_METHODS and fn_args:
            for st in self.hoisted:
                if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)) and st.name in fn_args:
                    st.decorator_list.append(_name("route", line))
        return _mk(ast.Call, line, func=func, args=args, keywords=[])

    def parse_template(self, tok) -> ast.AST:
        values = []
        for part in tok.val:
            if part[0] == "str":
                if part[1]:
                    values.append(_const(part[1], tok.line))
            else:
                sub = Parser(part[1], "inline.js")
                sub.mod = self.mod
                try:
                    e = sub.untuple(sub.parse_expression())
                except ParseError:
                    e = _const("", tok.line)
                self.hoisted.extend(sub.hoisted)
                self.imports.extend(sub.imports)
                values.append(_mk(ast.FormattedValue, tok.line, value=e, conversion=-1, format_spec=None))
        return _mk(ast.JoinedStr, tok.line, values=values)

    def parse_primary(self):
        t = self.t
        line = t.line
        if t.kind == "num":
            self.i += 1
            try:
                v = float(t.val.rstrip("n").replace("_", "")) if not t.val.startswith(("0x", "0X", "0b", "0B", "0o", "0O")) else int(t.val.rstrip("n"), 0)
            except ValueError:
                v = 0
            return _const(v, line)
        if t.kind == "str":
            self.i += 1
            return _const(bytes(t.val[1:-1], "utf-8").decode("unicode_escape", errors="ignore") if "\\" in t.val else t.val[1:-1], line)
        if t.kind == "tpl":
            self.i += 1
            return self.parse_template(t)
        if t.kind == "regex":
            self.i += 1
            return _mk(ast.Call, line, func=_mk(ast.Attribute, line, value=_name("re", line), attr="compile", ctx=ast.Load()),
                       args=[_const(t.val, line)], keywords=[])
        if t.kind == "punct":
            if t.val == "(":
                self.i += 1
                e = self.untuple(self.parse_expression())
                self.eat(")")
                return e
            if t.val == "[":
                self.i += 1
                elts = []
                while not self.at("]") and self.t.kind != "eof":
                    if self.at(","):
                        self.i += 1
                        continue
                    spread = self.opt("...")
                    e = self.untuple(self.parse_assignment())
                    elts.append(_mk(ast.Starred, line, value=e, ctx=ast.Load()) if spread else e)
                    self.opt(",")
                self.eat("]")
                return _mk(ast.List, line, elts=elts, ctx=ast.Load())
            if t.val == "{":
                return self.parse_object()
            if t.val == "#":
                self.i += 1
                return self.parse_primary()
        if t.kind == "id":
            v = t.val
            if v == "function" or (v == "async" and self.peek().val == "function"):
                fn = self.parse_function_decl([])
                self.hoisted.append(fn)
                return _name(fn.name, line)
            if v == "class":
                cls = self.parse_class([])
                self.hoisted.append(cls)
                return _name(cls.name, line)
            if v == "new":
                self.i += 1
                target = self.parse_postfix(no_call=True)
                if self.at("<"):
                    self.skip_balanced("<", ">")
                if self.at("("):
                    return self.parse_call(self.untuple(target), line)
                return _mk(ast.Call, line, func=self.untuple(target), args=[], keywords=[])
            if v == "this":
                self.i += 1
                return _name("self", line)
            if v == "super":
                self.i += 1
                return _name("super", line)
            if v in ("true", "false"):
                self.i += 1
                return _const(v == "true", line)
            if v in ("null", "undefined"):
                self.i += 1
                return _const(None, line)
            self.i += 1
            return _name(v, line)
        raise ParseError(f"unexpected {t.val!r} at line {line}")

    def parse_object(self):
        line = self.t.line
        self.eat("{")
        keys, values = [], []
        while not self.at("}") and self.t.kind != "eof":
            if self.opt("..."):
                v = self.untuple(self.parse_assignment())
                keys.append(None)
                values.append(v)
            else:
                is_async = False
                if self.at_kw("async") and self.peek().kind in ("id", "str"):
                    is_async = True
                    self.i += 1
                if (self.at_kw("get") or self.at_kw("set")) and self.peek().kind in ("id", "str"):
                    self.i += 1
                if self.at("["):
                    self.eat("[")
                    k = self.untuple(self.parse_assignment())
                    self.eat("]")
                else:
                    kt = self.eat()
                    k = _const(kt.val.strip("'\"") if kt.kind == "str" else kt.val, kt.line)
                if self.at("("):  # method shorthand
                    params, prologue, ann = self.parse_params()
                    self.skip_type_annotation()
                    body = prologue + self.block()
                    kname = k.value if isinstance(k, ast.Constant) and isinstance(k.value, str) else f"m{line}"
                    fn = self.make_function(f"_obj_{kname}_{line}", params, body, line, [], is_async, ann)
                    self.hoisted.append(fn)
                    v = _name(fn.name, line)
                elif self.opt(":"):
                    v = self.untuple(self.parse_assignment())
                else:  # shorthand {a}
                    v = _name(k.value, line) if isinstance(k, ast.Constant) and isinstance(k.value, str) else k
                keys.append(k)
                values.append(v)
            if not self.opt(","):
                break
        self.eat("}")
        return _mk(ast.Dict, line, keys=keys, values=values)


def parse_js(text: str, rel: str = "file.js") -> ast.Module:
    """Parse JavaScript/TypeScript source into a Python-``ast`` Module the taint engine understands."""
    try:
        return Parser(text, rel).parse_program()
    except Exception:  # noqa: BLE001 - never let a frontend bug abort a scan
        return ast.Module(body=[], type_ignores=[])
