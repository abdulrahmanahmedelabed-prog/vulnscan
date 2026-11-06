"""C-family frontend: lowers Java, Kotlin, C#, Go and PHP into the engine's Python ``ast``.

One tolerant tokenizer/parser with per-language switches. Like the JS
frontend it never aborts on unknown syntax: an unparseable statement is
skipped and parsing resumes at the next statement boundary. What is kept is
exactly what data flow needs: functions/methods (with ``self`` receivers),
classes/structs with bases, field and local assignments, calls, member
access (``.``, ``->``, ``::``), ``new``, returns, ``if``/loops/``try``,
string concatenation (``+`` / ``.``) and interpolation (``"$x"``, ``"${x}"``,
``$"{x}"``), imports/using/use (lowered to Python imports so the engine's
canonicalisation and cross-file resolution work), annotations/attributes
(lowered to decorators so framework entry points are recognised), and Go
handler signatures (``*http.Request`` params make the function an entry point).
Type annotations, generics and visibility modifiers are skipped.
"""

from __future__ import annotations

import ast
import re

from .js_frontend import Tok, _args, _const, _mk, _name  # reuse node helpers

LANG_EXTS = {".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".cs": "csharp", ".go": "go", ".php": "php", ".phtml": "php"}
TOKEN_RE = re.compile(r"""
    (?P<ws>[ \t\r\f\v]+) | (?P<nl>\n) | (?P<lc>//[^\n]*|\#[^\n]*) | (?P<bc>/\*.*?\*/) |
    (?P<tstr>\"\"\".*?\"\"\") |
    (?P<vstr>@"(?:""|[^"])*") |
    (?P<istr>\$@?"(?:\\.|[^"\\])*"|\$'(?:\\.|[^'\\])*') |
    (?P<str>"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`[^`]*`) |
    (?P<num>0[xX][0-9a-fA-F_]+|(?:\d[\d_]*\.?[\d_]*|\.\d[\d_]*)(?:[eE][+-]?\d+)?[fFdDlLmMuU]*) |
    (?P<id>\$?[A-Za-z_][\w]*) |
    (?P<punct>\.\.\.|->|=>|::|\?\.|\?:|!!|\+\+|--|<<=|>>=|<=|>=|==|!=|&&|\|\||\+=|-=|\*=|/=|%=|&=|\|=|\^=|\?\?|:=|\.\.|[{}()\[\];,<>+\-*/%&|^!~?:=.@#$\\])
""", re.S | re.X)
MODIFIERS = {"public", "private", "protected", "internal", "static", "final", "abstract", "override", "open", "sealed",
             "virtual", "async", "readonly", "const", "volatile", "transient", "synchronized", "native", "default",
             "unsafe", "extern", "partial", "inline", "suspend", "operator", "infix", "tailrec", "external", "lateinit",
             "data", "inner", "enum", "annotation", "companion", "crossinline", "noinline", "reified", "vararg"}
TYPE_KW = {"void", "int", "long", "short", "byte", "char", "boolean", "bool", "float", "double", "string", "var", "val",
           "object", "dynamic", "decimal", "uint", "ulong", "String", "Integer", "Boolean", "Object", "List", "Map", "Set",
           "Task", "IActionResult", "ActionResult", "error", "any", "Unit", "Nothing"}
STMT_START = {"return", "if", "for", "while", "do", "try", "throw", "switch", "break", "continue", "var", "val", "let",
              "func", "fun", "function", "class", "struct", "interface", "import", "package", "using", "namespace",
              "public", "private", "protected", "static", "echo", "print", "foreach", "defer", "go", "case", "default",
              "else", "catch", "finally", "type", "const", "when", "override", "internal", "abstract", "final", "open",
              "require", "include", "require_once", "include_once", "use", "@", "#"}


def tokenize(src: str, lang: str) -> list[Tok]:
    toks: list[Tok] = []
    i, line, n = 0, 1, len(src)
    nl_before = False
    if lang == "php":
        # keep only PHP code regions (<?php ... ?>); HTML outside is ignored
        parts = re.split(r"(<\?(?:php|=)?|\?>)", src)
        out, keep, lines_so_far = [], False, ""
        for part in parts:
            if part in ("<?php", "<?", "<?="):
                keep = True
                continue
            if part == "?>":
                keep = False
                out.append(";")
                continue
            out.append(part if keep else "\n" * part.count("\n"))
        src = "".join(out)
        n = len(src)
    while i < n:
        m = TOKEN_RE.match(src, i)
        if not m:
            i += 1
            continue
        kind, text = m.lastgroup, m.group(0)
        if kind == "nl":
            line += 1
            nl_before = True
        elif kind in ("ws", "lc"):
            if kind == "lc" and text.startswith("#") and lang != "php" and not text.startswith("#!"):
                # C#: #region/#if directives ; Go/Java: none; treat as comment
                pass
        elif kind == "bc" or kind == "tstr" or kind == "vstr":
            line += text.count("\n")
            if kind != "bc":
                toks.append(Tok("str", '"' + text.strip('@"') + '"', line, nl_before))
                nl_before = False
        else:
            if kind == "istr":
                toks.append(Tok("istr", text, line, nl_before))
            else:
                toks.append(Tok(kind, text, line, nl_before))
            nl_before = False
        i = m.end()
    toks.append(Tok("eof", "", line, True))
    return toks


class ParseError(Exception):
    pass


class Parser:
    def __init__(self, src: str, rel: str, lang: str):
        self.lang = lang
        self.toks = tokenize(src, lang)
        self.i = 0
        self.mod = module_name(rel)
        self.hoisted: list = []
        self.anon = 0
        self.cls_stack: list = []
        self.pkg = ""

    # ------------------------------------------------------------ helpers
    @property
    def t(self):
        return self.toks[self.i]

    def peek(self, k=1):
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def at(self, v):
        t = self.t
        return t.kind in ("punct", "id") and t.val == v

    def at_kw(self, v):
        return self.t.kind == "id" and self.t.val == v

    def eat(self, v=None):
        t = self.t
        if v is not None and t.val != v:
            raise ParseError(f"expected {v!r} got {t.val!r} line {t.line}")
        self.i += 1
        return t

    def opt(self, v):
        if self.t.kind in ("punct", "id") and self.t.val == v:
            self.i += 1
            return True
        return False

    def end_stmt(self):
        """Statement terminator: ';' or (Go/Kotlin) a newline before the next token, or '}'."""
        if self.opt(";"):
            while self.opt(";"):
                pass
            return
        if self.at("}") or self.t.kind == "eof" or self.t.nl_before:
            return
        if self.lang in ("go", "kotlin"):
            return
        raise ParseError(f"missing ';' at line {self.t.line}")

    def sync(self):
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
            elif depth == 0 and self.t.nl_before and self.t.kind == "id" and self.t.val in STMT_START:
                return
            self.i += 1

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

    # -------------------------------------------------------------- types
    def skip_type(self):
        """Consume a type (identifiers with dots/generics/arrays, pointers, nullable, function types)."""
        while self.t.kind == "punct" and self.t.val in ("*", "&", "[", "]", "?", "!"):
            if self.t.val == "[":
                self.skip_balanced("[", "]")
            else:
                self.i += 1
        if self.lang == "go" and self.at_kw("map"):
            self.i += 1
            self.skip_balanced("[", "]")
            self.skip_type()
            return
        if self.lang == "go" and (self.at_kw("func") or self.at_kw("chan") or self.at_kw("interface") or self.at_kw("struct")):
            self.i += 1
            if self.at("("):
                self.skip_balanced("(", ")")
                if self.at("(") or self.t.kind == "id":
                    self.skip_type()
            if self.at("{"):
                self.skip_balanced("{", "}")
            return
        if self.at("("):
            self.skip_balanced("(", ")")
            if self.opt("->") or self.opt("=>"):
                self.skip_type()
            return
        if self.t.kind == "id":
            self.i += 1
            while self.at(".") or self.at("::") or self.at("\\"):
                self.i += 1
                if self.t.kind == "id":
                    self.i += 1
            if self.at("<"):
                self.skip_balanced("<", ">")
        while self.t.kind == "punct" and self.t.val in ("[", "?", "!", "*"):
            if self.t.val == "[":
                self.skip_balanced("[", "]")
            else:
                self.i += 1
        if self.lang == "kotlin" and self.at("->"):
            self.i += 1
            self.skip_type()

    def looks_like_type_then_name(self) -> bool:
        """Java/C#: `Type name` (declaration) vs expression. Scan a type then expect an identifier."""
        save = self.i
        try:
            if self.t.kind != "id" or self.t.val in ("return", "new", "throw", "this", "super", "base"):
                return False
            self.skip_type()
            ok = self.t.kind == "id" and self.t.val not in ("instanceof", "is", "as", "in") and not self.t.nl_before
            return ok
        except Exception:  # noqa: BLE001
            return False
        finally:
            self.i = save

    # ------------------------------------------------------------ program
    def parse_program(self) -> ast.Module:
        body = self.parse_statements(top=True)
        return ast.Module(body=body, type_ignores=[])

    def parse_statements(self, top=False) -> list:
        out = []
        while self.t.kind != "eof" and not (not top and self.at("}")):
            start = self.i
            try:
                st = self.parse_statement()
                out.extend(self.hoisted)
                self.hoisted = []
                out.extend(st)
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
        st = self.parse_statement()
        pre, self.hoisted = self.hoisted, []
        return (pre + st) or [_mk(ast.Pass, self.t.line)]

    # ---------------------------------------------------------- decorators
    def parse_decorators(self) -> list:
        decs = []
        while True:
            if self.at("@") and self.peek().kind == "id":
                self.i += 1
                d = self.parse_postfix(no_call=False)
                decs.append(d)
            elif self.lang == "csharp" and self.at("[") and self.peek().kind == "id":
                self.i += 1
                while not self.at("]") and self.t.kind != "eof":
                    if self.t.kind == "id" and self.peek().val == ":":   # [return: X]
                        self.i += 2
                        continue
                    decs.append(self.parse_postfix(no_call=False))
                    if not self.opt(","):
                        break
                self.eat("]")
            elif self.lang == "php" and self.at("#") and self.peek().val == "[":
                self.i += 2
                while not self.at("]") and self.t.kind != "eof":
                    decs.append(self.parse_postfix(no_call=False))
                    if not self.opt(","):
                        break
                self.eat("]")
            else:
                return decs

    # ----------------------------------------------------------- statements
    def parse_statement(self) -> list:
        decs = self.parse_decorators()
        line = self.t.line
        t = self.t
        if t.kind == "punct":
            if t.val == ";":
                self.i += 1
                return []
            if t.val == "{":
                return self.block()
            if t.val == "<":   # stray generic / html
                raise ParseError("stray <")
        if t.kind == "id":
            v = t.val
            if v in ("package", "namespace"):
                self.i += 1
                self.pkg = self.parse_dotted_name()
                if self.at("{"):
                    return self.block()
                self.end_stmt()
                return []
            if v in ("import", "using") and self.lang != "php" or (v == "use" and self.lang == "php" and not self.cls_stack):
                return self.parse_import()
            if v == "declare" and self.lang == "php":
                self.sync()
                return []
            mods = self.parse_modifiers()
            if mods and self.t.kind == "eof":
                return []
            v = self.t.val if self.t.kind == "id" else ""
            if v in ("class", "struct", "interface", "trait", "record", "enum", "object") and self.peek().kind == "id":
                return [self.parse_class(decs)]
            if v == "type" and self.lang == "go":
                return self.parse_go_type(decs)
            if v in ("func", "fun", "function") and (self.peek().kind == "id" or self.peek().val in ("(", "<")):
                return [self.parse_function(decs)]
            if v == "return":
                self.i += 1
                val = None
                if not self.at(";") and not self.at("}") and not self.t.nl_before and self.t.kind != "eof":
                    val = self.untuple(self.parse_expression())
                self.end_stmt()
                return [_mk(ast.Return, line, value=val)]
            if v in ("throw", "panic"):
                self.i += 1
                e = self.untuple(self.parse_expression()) if not self.at(";") else None
                self.end_stmt()
                return [_mk(ast.Raise, line, exc=e, cause=None)]
            if v == "if":
                return [self.parse_if()]
            if v in ("for", "foreach"):
                return [self.parse_for(v)]
            if v == "while":
                self.i += 1
                test = self.parse_cond()
                body = self.body_or_stmt()
                return [_mk(ast.While, line, test=test, body=body, orelse=[])]
            if v == "do":
                self.i += 1
                body = self.body_or_stmt()
                self.eat("while")
                test = self.parse_cond()
                self.end_stmt()
                return [_mk(ast.While, line, test=test, body=body, orelse=[])]
            if v == "try":
                return [self.parse_try()]
            if v in ("switch", "when", "match"):
                return [self.parse_switch()]
            if v in ("break", "continue", "goto", "fallthrough"):
                self.i += 1
                if self.t.kind == "id" and not self.t.nl_before:
                    self.i += 1
                self.end_stmt()
                return []
            if v in ("echo", "print") and self.lang == "php":
                self.i += 1
                args = [self.untuple(self.parse_assignment())]
                while self.opt(","):
                    args.append(self.untuple(self.parse_assignment()))
                self.end_stmt()
                return [_mk(ast.Expr, line, value=_mk(ast.Call, line, func=_name(v, line), args=args, keywords=[]))]
            if v in ("include", "require", "include_once", "require_once") and self.lang == "php":
                self.i += 1
                self.opt("(")
                arg = self.untuple(self.parse_assignment())
                self.opt(")")
                self.end_stmt()
                return [_mk(ast.Expr, line, value=_mk(ast.Call, line, func=_name(v, line), args=[arg], keywords=[]))]
            if v in ("defer", "go") and self.lang == "go":
                self.i += 1
                e = self.untuple(self.parse_expression())
                self.end_stmt()
                return [_mk(ast.Expr, line, value=e)]
            if v in ("var", "val", "let", "const") and self.lang != "go":
                self.i += 1
                return self.parse_var_decl(line)
            if v in ("var", "const") and self.lang == "go":
                self.i += 1
                if self.at("("):
                    self.eat("(")
                    out = []
                    while not self.at(")") and self.t.kind != "eof":
                        out.extend(self.parse_go_var(line))
                    self.eat(")")
                    return out
                return self.parse_go_var(line)
            if v == "init" and self.lang == "kotlin" and self.peek().val == "{":
                self.i += 1
                body = self.block()
                return [_mk(ast.FunctionDef, line, name="__init__", args=_args(["self"], line), body=body, decorator_list=[], returns=None, type_params=[])]
            if v == "static" and self.peek().val == "{":
                self.i += 1
                return self.block()
            # Java/C#: `Type name = expr;` / `Type name(params) {}` (method); Kotlin: handled via fun/val/var
            if self.lang in ("java", "csharp") and self.looks_like_type_then_name():
                return self.parse_typed_decl(decs, line)
        expr = self.parse_expression()
        self.end_stmt()
        return self.expr_statement(expr, line)

    def parse_modifiers(self) -> list:
        mods = []
        while self.t.kind == "id" and self.t.val in MODIFIERS and self.peek().kind == "id":
            # Kotlin/PHP: 'data class', 'enum class', 'final class' ...; C#: 'public static'
            mods.append(self.eat().val)
        return mods

    def parse_dotted_name(self) -> str:
        parts = []
        while self.t.kind == "id":
            parts.append(self.eat().val)
            if self.at(".") or self.at("\\") or self.at("::"):
                self.i += 1
                continue
            break
        return ".".join(parts)

    def parse_import(self) -> list:
        line = self.t.line
        self.i += 1  # import/using/use
        if self.at_kw("static") or self.at_kw("function") or self.at_kw("const"):
            self.i += 1
        if self.lang == "go":
            specs = []
            if self.at("("):
                self.eat("(")
                while not self.at(")") and self.t.kind != "eof":
                    alias = self.eat().val if self.t.kind == "id" else None
                    spec = self.eat().val.strip('"`')
                    specs.append((spec, alias))
                    self.opt(";")
                self.eat(")")
            else:
                alias = self.eat().val if self.t.kind == "id" else None
                spec = self.eat().val.strip('"`')
                specs.append((spec, alias))
            self.end_stmt()
            out = []
            for spec, alias in specs:
                modname = spec.replace("/", ".").replace("-", "_")
                out.append(_mk(ast.Import, line, names=[ast.alias(name=modname, asname=alias or modname.split(".")[-1])]))
            return out
        # Java/Kotlin/C#/PHP dotted names, possibly with alias and wildcard
        if self.lang == "csharp" and self.t.kind == "id" and self.peek().val == "=":
            alias = self.eat().val
            self.eat("=")
            target = self.parse_dotted_name()
            self.end_stmt()
            return [_mk(ast.Import, line, names=[ast.alias(name=target, asname=alias)])]
        name = self.parse_dotted_name()
        wildcard = False
        if self.at("*"):
            self.i += 1
            wildcard = True
        asname = None
        if self.at_kw("as"):
            self.i += 1
            asname = self.eat().val
        if self.at("{"):   # PHP group use: use A\{B, C};
            self.eat("{")
            names = []
            while not self.at("}") and self.t.kind != "eof":
                names.append(ast.alias(name=self.eat().val, asname=None))
                self.opt(",")
            self.eat("}")
            self.end_stmt()
            return [_mk(ast.ImportFrom, line, module=name.rstrip("."), names=names, level=0)]
        self.end_stmt()
        if wildcard or self.lang == "csharp":
            return [_mk(ast.Import, line, names=[ast.alias(name=name, asname=asname)])]
        modpart, _, last = name.rpartition(".")
        if modpart:
            return [_mk(ast.ImportFrom, line, module=modpart, names=[ast.alias(name=last, asname=asname)], level=0)]
        return [_mk(ast.Import, line, names=[ast.alias(name=name, asname=asname)])]

    def parse_typed_decl(self, decs, line) -> list:
        """Java/C#: `Type name = expr;` or `Type name(params) { }` or `Type name;`"""
        self.skip_type()
        name = self.eat().val
        if self.at("<"):
            self.skip_balanced("<", ">")
        if self.at("("):
            prev_in, self.in_function = self.in_function, True
            params, prologue, ann = self.parse_params()
            self.skip_throws()
            body = prologue + (self.block() if self.at("{") else self.arrow_body())
            self.in_function = prev_in
            is_ctor = bool(self.cls_stack) and name == self.cls_stack[-1]
            return [self.make_function("__init__" if is_ctor else name, params, body, line, decs, ann, method=bool(self.cls_stack))]
        if self.lang == "csharp" and self.at("{"):      # property { get; set; }
            self.skip_balanced("{", "}")
            if self.opt("="):
                v = self.untuple(self.parse_assignment())
                self.end_stmt()
                return self.field_or_local(name, v, line)
            self.opt(";")
            return []
        if self.lang == "csharp" and self.at("=>"):     # expression-bodied property
            self.i += 1
            v = self.untuple(self.parse_assignment())
            self.end_stmt()
            return self.field_or_local(name, v, line)
        out = []
        while True:
            if self.cls_stack and not self.in_function and self.field_names_stack:
                self.field_names_stack[-1].add(name)
            if self.opt("="):
                v = self.untuple(self.parse_assignment())
                out.extend(self.field_or_local(name, v, line))
            if self.opt(","):
                name = self.eat().val
                continue
            break
        self.end_stmt()
        return out

    def field_or_local(self, name, value, line) -> list:
        if self.cls_stack and not self.in_function:
            tgt = _mk(ast.Attribute, line, value=_name("self", line), attr=name, ctx=ast.Store())
            return [_mk(ast.Assign, line, targets=[tgt], value=value)]
        if isinstance(value, ast.Name) and value.id.startswith("_fn_"):
            fn = self.pop_hoisted_function(value.id)
            if fn is not None:
                fn.name = name
                return [fn]
        return [_mk(ast.Assign, line, targets=[_name(name, line, store=True)], value=value)]

    in_function = False

    def parse_var_decl(self, line) -> list:
        out = []
        while True:
            if self.at("("):   # kotlin destructuring val (a, b) = ...
                self.eat("(")
                names = []
                while not self.at(")"):
                    names.append(self.eat().val)
                    self.opt(",")
                self.eat(")")
                self.skip_type_annotation()
                if self.opt("="):
                    v = self.untuple(self.parse_assignment())
                    tmp = f"_d{line}"
                    out.append(_mk(ast.Assign, line, targets=[_name(tmp, line, store=True)], value=v))
                    for k, nm in enumerate(names):
                        out.append(_mk(ast.Assign, line, targets=[_name(nm, line, store=True)],
                                       value=_mk(ast.Subscript, line, value=_name(tmp, line), slice=_const(k, line), ctx=ast.Load())))
                break
            name = self.eat().val.lstrip("$")
            self.skip_type_annotation()
            if self.cls_stack and not self.in_function and self.field_names_stack:
                self.field_names_stack[-1].add(name)
            if self.opt("="):
                v = self.untuple(self.parse_assignment())
                out.extend(self.field_or_local(name, v, line))
            if not self.opt(","):
                break
        self.end_stmt()
        return out

    def parse_go_var(self, line) -> list:
        names = [self.eat().val]
        while self.opt(","):
            names.append(self.eat().val)
        if not self.at("="):
            self.skip_type()
        out = []
        if self.opt("="):
            v = self.untuple(self.parse_expression_list())
            out.extend(self.multi_assign(names, v, line))
        self.end_stmt()
        return out

    def multi_assign(self, names, value, line) -> list:
        if len(names) == 1:
            return self.field_or_local(names[0], value, line)
        tmp = f"_m{line}"
        out = [_mk(ast.Assign, line, targets=[_name(tmp, line, store=True)], value=value)]
        for k, nm in enumerate(names):
            if nm == "_":
                continue
            out.append(_mk(ast.Assign, line, targets=[_name(nm, line, store=True)],
                           value=_mk(ast.Subscript, line, value=_name(tmp, line), slice=_const(k, line), ctx=ast.Load())))
        return out

    def skip_type_annotation(self):
        if self.at(":"):
            self.eat(":")
            self.skip_type()
        elif self.lang == "go" and self.t.kind == "id" and not self.at("="):
            pass

    def skip_throws(self):
        if self.at_kw("throws"):
            self.i += 1
            self.parse_dotted_name()
            while self.opt(","):
                self.parse_dotted_name()
        if self.at(":"):   # kotlin return type / c# ctor initializer
            self.eat(":")
            if self.lang == "csharp" and (self.at_kw("base") or self.at_kw("this")):
                self.i += 1
                self.skip_balanced("(", ")")
            else:
                self.skip_type()
        if self.at_kw("where"):   # C# generic constraints
            while not self.at("{") and not self.at(";") and self.t.kind != "eof":
                self.i += 1

    def arrow_body(self) -> list:
        line = self.t.line
        if self.opt("=>") or self.opt("="):
            e = self.untuple(self.parse_expression())
            self.opt(";")
            return [_mk(ast.Return, line, value=e)]
        self.opt(";")
        return [_mk(ast.Pass, line)]

    def parse_params(self):
        """Returns (names, prologue, annotations). Handles Go (name Type), Kotlin/PHP (name: Type / $name), Java/C# (Type name)."""
        self.eat("(")
        names, prologue, ann = [], [], {}
        while not self.at(")") and self.t.kind != "eof":
            self.parse_decorators()
            prop = False
            while self.t.kind == "id" and self.t.val in ("final", "params", "ref", "out", "in", "this", "vararg", "val", "var", "private", "public", "protected", "override"):
                if self.t.val in ("val", "var", "private", "public", "protected"):
                    prop = True
                self.i += 1
            self.opt("...")
            if self.lang in ("java", "csharp"):
                # Type name  (type may be generic/array/nullable)
                start = self.i
                self.skip_type()
                if self.t.kind == "id":
                    tname = self.toks[start].val
                    name = self.eat().val
                else:
                    self.i = start
                    name = self.eat().val
                    tname = None
                self.opt("...")
            elif self.lang == "go":
                name = self.eat().val
                tname = None
                if not self.at(",") and not self.at(")"):
                    start = self.i
                    self.opt("...")
                    self.skip_type()
                    tname = "".join(tk.val for tk in self.toks[start:self.i])
            else:  # kotlin / php
                name = self.eat().val.lstrip("$")
                tname = None
                if self.at(":"):
                    self.eat(":")
                    start = self.i
                    self.skip_type()
                    tname = self.toks[start].val
                if self.lang == "php" and self.t.kind == "id" and self.peek().kind == "id" and self.peek().val.startswith("$"):
                    pass
            if self.opt("="):
                self.parse_assignment()
            names.append(name)
            if tname and re.match(r"[A-Za-z_][\w.]*$", tname.split(".")[-1] or ""):
                ann[name] = _name(tname.split(".")[-1].strip("*&"), self.t.line)
            if tname and self.lang == "go" and "http.Request" in tname or (tname and ("gin.Context" in tname or "echo.Context" in tname or "fiber.Ctx" in tname)):
                self.go_request_param = True
            if prop:
                line = self.t.line
                prologue.append(_mk(ast.Assign, line, targets=[_mk(ast.Attribute, line, value=_name("self", line), attr=name, ctx=ast.Store())], value=_name(name, line)))
            if not self.opt(","):
                break
        self.eat(")")
        return names, prologue, ann

    go_request_param = False

    def make_function(self, name, params, body, line, decs, ann=None, method=False, is_async=False):
        if method:
            params = ["self"] + [p for p in params if p != "self"]
        fn = _mk(ast.AsyncFunctionDef if is_async else ast.FunctionDef, line, name=name, args=_args(params, line, ann),
                 body=body or [_mk(ast.Pass, line)], decorator_list=list(decs), returns=None, type_params=[])
        return fn

    def parse_function(self, decs):
        line = self.t.line
        kw = self.eat().val   # func / fun / function
        receiver_cls = None
        self.go_request_param = False
        if self.lang == "go" and self.at("("):           # func (r *T) name(...)
            self.eat("(")
            if self.t.kind == "id" and self.peek().kind == "id" or self.peek().val == "*":
                self.i += 1
            self.opt("*")
            receiver_cls = self.eat().val
            self.eat(")")
        name = f"_fn_{line}_{self.anon}"
        if self.t.kind == "id" and not self.at("("):
            name = self.eat().val
            while self.at(".") and self.lang == "kotlin":   # extension fun T.name
                self.i += 1
                name = self.eat().val
        if self.at("<"):
            self.skip_balanced("<", ">")
        prev_in, self.in_function = self.in_function, True
        params, prologue, ann = self.parse_params()
        # Go results / Kotlin return type / PHP return type
        if self.lang == "go":
            if self.at("("):
                self.skip_balanced("(", ")")
            elif not self.at("{"):
                self.skip_type()
        else:
            self.skip_throws()
            if self.at(":"):
                self.eat(":")
                self.skip_type()
        if self.lang == "php" and self.at_kw("use"):
            self.i += 1
            self.skip_balanced("(", ")")
        body = prologue + (self.block() if self.at("{") else self.arrow_body())
        self.in_function = prev_in
        method = bool(self.cls_stack) or receiver_cls is not None
        fn = self.make_function("__init__" if name in ("__construct", "constructor") else name, params, body, line, decs, ann, method=method)
        if self.go_request_param:
            fn.decorator_list.append(_name("route", line))
        if receiver_cls is not None:
            self.go_methods.setdefault(receiver_cls, []).append(fn)
            return _mk(ast.Pass, line)
        return fn

    go_methods: dict = {}
    field_names_stack: list = []

    def parse_go_type(self, decs) -> list:
        line = self.t.line
        self.eat("type")
        name = self.eat().val
        if self.at_kw("struct"):
            self.i += 1
            self.skip_balanced("{", "}")
            cls = _mk(ast.ClassDef, line, name=name, bases=[], keywords=[], body=[_mk(ast.Pass, line)], decorator_list=list(decs), type_params=[])
            self.go_structs[name] = cls
            return [cls]
        if self.at_kw("interface"):
            self.i += 1
            self.skip_balanced("{", "}")
            return [_mk(ast.ClassDef, line, name=name, bases=[], keywords=[], body=[_mk(ast.Pass, line)], decorator_list=[], type_params=[])]
        self.skip_type()
        self.end_stmt()
        return []

    go_structs: dict = {}

    def parse_class(self, decs) -> ast.ClassDef:
        line = self.t.line
        kind = self.eat().val
        name = self.eat().val
        if self.at("<"):
            self.skip_balanced("<", ">")
        bases = []
        ctor_prologue, ctor_params, ctor_ann = [], [], {}
        if self.lang == "kotlin" and self.at("("):           # primary constructor
            ctor_params, ctor_prologue, ctor_ann = self.parse_params()
        if self.lang == "csharp" and self.at("("):           # record Foo(int x)
            ctor_params, ctor_prologue, ctor_ann = self.parse_params()
            for p in ctor_params:
                ctor_prologue.append(_mk(ast.Assign, line, targets=[_mk(ast.Attribute, line, value=_name("self", line), attr=p, ctx=ast.Store())], value=_name(p, line)))
        while self.t.kind == "id" and self.t.val in ("extends", "implements") or self.at(":"):
            self.i += 1
            while True:
                b = self.parse_postfix(no_call=True)
                if self.at("("):
                    self.skip_balanced("(", ")")
                if self.at("<"):
                    self.skip_balanced("<", ">")
                bases.append(b)
                if not self.opt(","):
                    break
        if self.at_kw("where"):
            while not self.at("{") and self.t.kind != "eof":
                self.i += 1
        if kind in ("enum",) and self.at("{"):
            self.skip_balanced("{", "}")
            return _mk(ast.ClassDef, line, name=name, bases=bases, keywords=[], body=[_mk(ast.Pass, line)], decorator_list=list(decs), type_params=[])
        if not self.at("{"):
            self.opt(";")
            return _mk(ast.ClassDef, line, name=name, bases=bases, keywords=[], body=[_mk(ast.Pass, line)], decorator_list=list(decs), type_params=[])
        self.cls_stack.append(name)
        self.field_names_stack.append({p for p in ctor_params} if (ctor_prologue or self.lang == "csharp") else set())
        prev_in, self.in_function = self.in_function, False
        body = self.block()
        self.in_function = prev_in
        self.cls_stack.pop()
        field_names = self.field_names_stack.pop()
        fields = [s for s in body if isinstance(s, ast.Assign) and isinstance(s.targets[0], ast.Attribute)]
        for f in fields:
            field_names.add(f.targets[0].attr)
        for st in ctor_prologue:
            if isinstance(st, ast.Assign) and isinstance(st.targets[0], ast.Attribute):
                field_names.add(st.targets[0].attr)
        methods = [s for s in body if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))]
        if field_names and self.lang in ("java", "kotlin", "csharp"):
            for m in methods:
                _rewrite_implicit_this(m, field_names)
        ctor = next((m for m in methods if m.name == "__init__"), None)
        if (ctor_params or ctor_prologue or fields) and ctor is None:
            ctor = self.make_function("__init__", ctor_params, [], line, [], ctor_ann, method=True)
            methods.insert(0, ctor)
        if ctor is not None:
            ctor.body = fields + ctor_prologue + [s for s in ctor.body if not isinstance(s, ast.Pass)] or [_mk(ast.Pass, line)]
        others = [s for s in body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) and s not in fields]
        return _mk(ast.ClassDef, line, name=name, bases=bases, keywords=[], body=(methods + others) or [_mk(ast.Pass, line)],
                   decorator_list=list(decs), type_params=[])

    def parse_cond(self):
        if self.at("("):
            self.eat("(")
            e = self.untuple(self.parse_expression())
            self.eat(")")
            return e
        # Go / Kotlin-when without parens; Go `if x := f(); cond`
        e = self.untuple(self.parse_expression())
        if isinstance(e, tuple):
            e = self.untuple(e)
        if self.opt(";"):
            e = self.untuple(self.parse_expression())
        return e

    def parse_if(self):
        line = self.t.line
        self.eat("if")
        test = self.parse_cond()
        body = self.body_or_stmt()
        orelse = []
        if self.at_kw("else"):
            self.i += 1
            if self.at_kw("if"):
                orelse = [self.parse_if()]
            else:
                orelse = self.body_or_stmt()
        elif self.lang == "php" and self.at_kw("elseif"):
            self.toks[self.i].val = "if"
            orelse = [self.parse_if()]
        return _mk(ast.If, line, test=test, body=body, orelse=orelse)

    def parse_for(self, kw):
        line = self.t.line
        self.i += 1
        paren = self.opt("(")
        init = []
        target = None
        # foreach ($arr as $k => $v) / for (T x : xs) / for (var x in xs) / for k, v := range xs / for (x in xs)
        save = self.i
        try:
            if self.lang == "php":
                it = self.untuple(self.parse_assignment())
                self.eat("as")
                a = self.eat().val.lstrip("$")
                if self.opt("=>"):
                    b = self.eat().val.lstrip("$")
                    target = (a, b)
                else:
                    target = (a,)
                if paren:
                    self.eat(")")
                body = self.body_or_stmt()
                tgt = _name(target[-1], line, store=True)
                return _mk(ast.For, line, target=tgt, iter=it, body=body, orelse=[], type_comment=None)
            if self.lang == "go":
                if self.at("{"):
                    return _mk(ast.While, line, test=_const(True, line), body=self.block(), orelse=[])
                names = []
                j = self.i
                while self.toks[j].kind == "id" and self.toks[j + 1].val in (",", ":=", "="):
                    names.append(self.toks[j].val)
                    if self.toks[j + 1].val == ",":
                        j += 2
                        continue
                    j += 1
                    break
                if names and self.toks[j].val in (":=", "=") and self.toks[j + 1].val == "range":
                    self.i = j + 2
                    it = self.untuple(self.parse_expression())
                    body = self.block()
                    tgt = _name(names[-1] if names[-1] != "_" else names[0], line, store=True)
                    return _mk(ast.For, line, target=tgt, iter=it, body=body, orelse=[], type_comment=None)
                if self.at_kw("range"):
                    self.i += 1
                    it = self.untuple(self.parse_expression())
                    body = self.block()
                    return _mk(ast.For, line, target=_name("_", line, store=True), iter=it, body=body, orelse=[], type_comment=None)
                # classic for init; cond; post {
                if not self.at(";"):
                    init = self.expr_statement(self.parse_expression(), line)
                self.eat(";")
                test = _const(True, line) if self.at(";") else self.untuple(self.parse_expression())
                self.eat(";")
                post = [] if self.at("{") else self.expr_statement(self.parse_expression(), line)
                body = self.block()
                self.hoisted = init + self.hoisted
                return _mk(ast.While, line, test=test, body=body + post, orelse=[])
            # Java enhanced for / C# foreach / Kotlin for (x in xs)
            if self.lang in ("java", "csharp"):
                if self.looks_like_type_then_name() or self.at_kw("var") or self.at_kw("final"):
                    while self.at_kw("final"):
                        self.i += 1
                    if self.at_kw("var"):
                        self.i += 1
                    else:
                        self.skip_type()
            name = self.eat().val
            if self.at(":") or self.at_kw("in"):
                self.i += 1
                it = self.untuple(self.parse_expression())
                if paren:
                    self.eat(")")
                body = self.body_or_stmt()
                return _mk(ast.For, line, target=_name(name, line, store=True), iter=it, body=body, orelse=[], type_comment=None)
            if self.lang == "kotlin" and self.at(","):
                self.i += 1
                name2 = self.eat().val
                self.eat("in")
                it = self.untuple(self.parse_expression())
                if paren:
                    self.eat(")")
                body = self.body_or_stmt()
                return _mk(ast.For, line, target=_name(name2, line, store=True), iter=it, body=body, orelse=[], type_comment=None)
            self.i = save
        except ParseError:
            self.i = save
        # classic for(init; cond; post)
        if self.lang in ("java", "csharp") and self.looks_like_type_then_name():
            self.skip_type()
        if not self.at(";"):
            e = self.parse_expression()
            init = self.expr_statement(e, line)
        self.eat(";")
        test = _const(True, line) if self.at(";") else self.untuple(self.parse_expression())
        self.eat(";")
        post = []
        if not self.at(")"):
            post = self.expr_statement(self.parse_expression(), line)
        if paren:
            self.eat(")")
        body = self.body_or_stmt()
        self.hoisted = init + self.hoisted
        return _mk(ast.While, line, test=test, body=body + post, orelse=[])

    def parse_try(self):
        line = self.t.line
        self.eat("try")
        if self.at("("):   # java try-with-resources / c# none
            self.eat("(")
            while not self.at(")") and self.t.kind != "eof":
                if self.looks_like_type_then_name():
                    self.skip_type()
                nm = self.eat().val
                if self.opt("="):
                    v = self.untuple(self.parse_assignment())
                    self.hoisted.append(_mk(ast.Assign, line, targets=[_name(nm, line, store=True)], value=v))
                self.opt(";")
            self.eat(")")
        body = self.block()
        handlers, final = [], []
        while self.at_kw("catch"):
            self.i += 1
            nm = None
            if self.opt("("):
                while not self.at(")") and self.t.kind != "eof":
                    tk = self.eat()
                    if tk.kind == "id" and not tk.val.startswith("$") and self.at(")"):
                        nm = tk.val
                    elif tk.val.startswith("$"):
                        nm = tk.val.lstrip("$")
                self.eat(")")
            hb = self.block()
            handlers.append(_mk(ast.ExceptHandler, line, type=None, name=nm, body=hb))
        if self.at_kw("finally"):
            self.i += 1
            final = self.block()
        if not handlers and not final:
            handlers.append(_mk(ast.ExceptHandler, line, type=None, name=None, body=[_mk(ast.Pass, line)]))
        return _mk(ast.Try, line, body=body, handlers=handlers, orelse=[], finalbody=final)

    def parse_switch(self):
        line = self.t.line
        self.i += 1
        subj = _const(True, line)
        if self.at("("):
            self.eat("(")
            subj = self.untuple(self.parse_expression())
            self.eat(")")
        elif not self.at("{"):
            subj = self.untuple(self.parse_expression())
        self.eat("{")
        body = []
        depth = 0
        while not self.at("}") and self.t.kind != "eof":
            if self.at_kw("case") or self.at_kw("default"):
                self.i += 1
                while not self.at(":") and not self.at("->") and not self.at("{") and self.t.kind != "eof":
                    self.i += 1
                if self.at(":") or self.at("->"):
                    self.i += 1
                continue
            if self.lang in ("kotlin",) and (self.at("->") or self.at("else")):
                self.i += 1
                continue
            if self.lang == "kotlin" and not self.at("{"):
                # `expr -> stmt`  : skip the pattern
                while not self.at("->") and not self.at("}") and not self.t.nl_before and self.t.kind != "eof":
                    self.i += 1
                if self.opt("->"):
                    body.extend(self.body_or_stmt())
                    continue
            body.extend(self.parse_statement())
        self.eat("}")
        return _mk(ast.If, line, test=subj, body=body or [_mk(ast.Pass, line)], orelse=[])

    # ----------------------------------------------------------- expressions
    def expr_statement(self, expr, line) -> list:
        if isinstance(expr, tuple) and expr[0] == "assign":
            _, target, op, value, aline = expr
            return self.make_assign(target, op, value, aline)
        if isinstance(expr, tuple) and expr[0] == "multi":
            _, names, value, aline = expr
            return self.multi_assign(names, self.untuple(value), aline)
        return [_mk(ast.Expr, line, value=self.untuple(expr))]

    def untuple(self, e):
        if isinstance(e, tuple) and e[0] == "assign":
            _, target, op, value, aline = e
            self.hoisted.extend(self.make_assign(target, op, value, aline))
            return _name(target.id, aline) if isinstance(target, ast.Name) else target
        if isinstance(e, tuple) and e[0] == "multi":
            _, names, value, aline = e
            self.hoisted.extend(self.multi_assign(names, self.untuple(value), aline))
            return _name(names[0], aline)
        return e

    def make_assign(self, target, op, value, line) -> list:
        value = self.untuple(value)
        if isinstance(target, ast.Name):
            return self.field_or_local(target.id, value, line) if op == "=" else [_mk(ast.AugAssign, line, target=_name(target.id, line, store=True), op=ast.Add(), value=value)]
        if isinstance(target, (ast.Attribute, ast.Subscript)):
            target.ctx = ast.Store()
            if op == "=":
                return [_mk(ast.Assign, line, targets=[target], value=value)]
            return [_mk(ast.AugAssign, line, target=target, op=ast.Add(), value=value)]
        return [_mk(ast.Expr, line, value=value)]

    def pop_hoisted_function(self, name):
        for idx, st in enumerate(self.hoisted):
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)) and st.name == name:
                return self.hoisted.pop(idx)
        return None

    def parse_expression_list(self):
        e = self.parse_assignment()
        if self.at(","):
            elts = [self.untuple(e)]
            while self.opt(","):
                elts.append(self.untuple(self.parse_assignment()))
            return _mk(ast.Tuple, elts[0].lineno if hasattr(elts[0], "lineno") else self.t.line, elts=elts, ctx=ast.Load())
        return e

    def parse_expression(self):
        e = self.parse_assignment()
        # Go multi-assign:  a, b := f()
        if self.lang == "go" and self.at(",") and isinstance(e, ast.Name):
            names = [e.id]
            save = self.i
            while self.opt(","):
                if self.t.kind == "id":
                    names.append(self.eat().val)
                else:
                    break
            if self.at(":=") or self.at("="):
                self.i += 1
                v = self.parse_expression_list()
                return ("multi", names, v, e.lineno)
            self.i = save
        return e

    def parse_assignment(self):
        if self.lang == "php" and self.at_kw("fn") and self.peek().val == "(":
            self.i += 1
            return self.parse_lambda_params_body(self.t.line, arrow="=>")
        if self.lang == "php" and self.at_kw("function") and self.peek().val == "(":
            fn = self.parse_function([])
            self.hoisted.append(fn)
            return _name(fn.name, fn.lineno)
        if self.lang == "go" and self.at_kw("func") and self.peek().val == "(":
            fn = self.parse_function([])
            self.hoisted.append(fn)
            return _name(fn.name, fn.lineno)
        if self.lang in ("java", "csharp") and self.is_lambda_start():
            return self.parse_lambda_params_body(self.t.line, arrow="->" if self.lang == "java" else "=>")
        left = self.parse_conditional()
        t = self.t
        if t.kind == "punct" and t.val in ("=", ":=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", "??=", ".="):
            self.i += 1
            right = self.parse_assignment()
            left = self.untuple(left)
            if isinstance(left, ast.Name) and left.id.startswith("$"):
                left = _name(left.id.lstrip("$"), left.lineno)
            return ("assign", left, "=" if t.val in ("=", ":=") else "+=", right, t.line)
        return left

    def is_lambda_start(self) -> bool:
        arrow = "->" if self.lang == "java" else "=>"
        t = self.t
        if t.kind == "id" and self.peek().val == arrow:
            return True
        if self.at("("):
            j, depth = self.i, 0
            while j < len(self.toks):
                v = self.toks[j].val if self.toks[j].kind == "punct" else None
                if v == "(":
                    depth += 1
                elif v == ")":
                    depth -= 1
                    if depth == 0:
                        return j + 1 < len(self.toks) and self.toks[j + 1].val == arrow
                j += 1
        return False

    def parse_lambda_params_body(self, line, arrow):
        if self.t.kind == "id" and not self.at("("):
            params, prologue, ann = [self.eat().val.lstrip("$")], [], {}
        else:
            params, prologue, ann = self.parse_params()
        if self.lang == "php" and self.at_kw("use"):
            self.i += 1
            self.skip_balanced("(", ")")
        self.eat(arrow)
        if self.at("{"):
            body = prologue + self.block()
        else:
            e = self.untuple(self.parse_assignment())
            body = prologue + [_mk(ast.Return, line, value=e)]
        name = f"_fn_{line}_{self.anon}"
        self.anon += 1
        fn = self.make_function(name, params, body, line, [], ann)
        self.hoisted.append(fn)
        return _name(name, line)

    def parse_conditional(self):
        cond = self.parse_binary(0)
        if self.at("?") and not self.at("?."):
            line = self.t.line
            self.i += 1
            if self.at(":"):   # PHP ?: elvis
                self.i += 1
                b = self.untuple(self.parse_assignment())
                return _mk(ast.BoolOp, line, op=ast.Or(), values=[self.untuple(cond), b])
            a = self.untuple(self.parse_assignment())
            self.eat(":")
            b = self.untuple(self.parse_assignment())
            return _mk(ast.IfExp, line, test=self.untuple(cond), body=a, orelse=b)
        if self.at("?:"):
            line = self.t.line
            self.i += 1
            b = self.untuple(self.parse_assignment())
            return _mk(ast.BoolOp, line, op=ast.Or(), values=[self.untuple(cond), b])
        return cond

    BIN_PREC = {"??": 1, "||": 1, "or": 1, "&&": 2, "and": 2, "|": 3, "^": 4, "&": 5, "==": 6, "!=": 6, "===": 6, "!==": 6,
                "<": 7, ">": 7, "<=": 7, ">=": 7, "instanceof": 7, "is": 7, "as": 7, "in": 7, "<<": 8, ">>": 8,
                "+": 9, "-": 9, ".": 9, "*": 10, "/": 10, "%": 10, "..": 9}

    def parse_binary(self, min_prec):
        left = self.parse_unary()
        while True:
            t = self.t
            op = t.val if (t.kind == "punct" or (t.kind == "id" and t.val in ("instanceof", "is", "as", "in", "and", "or"))) else None
            if op == "." and self.lang != "php":
                break
            if op not in self.BIN_PREC or self.BIN_PREC[op] < min_prec:
                break
            if op == "<" and self.looks_like_generic():
                break
            prec = self.BIN_PREC[op]
            self.i += 1
            if op in ("is", "as", "instanceof"):
                self.skip_type()
                continue
            right = self.parse_binary(prec + 1)
            left, right = self.untuple(left), self.untuple(right)
            line = t.line
            if op in ("&&", "||", "??", "and", "or"):
                left = _mk(ast.BoolOp, line, op=ast.And() if op in ("&&", "and") else ast.Or(), values=[left, right])
            elif op in ("==", "!=", "===", "!==", "<", ">", "<=", ">=", "in"):
                pyop = {"==": ast.Eq(), "===": ast.Eq(), "!=": ast.NotEq(), "!==": ast.NotEq(), "<": ast.Lt(), ">": ast.Gt(),
                        "<=": ast.LtE(), ">=": ast.GtE(), "in": ast.In()}[op]
                left = _mk(ast.Compare, line, left=left, ops=[pyop], comparators=[right])
            else:
                left = _mk(ast.BinOp, line, left=left, op=ast.Add() if op in ("+", ".", "..") else ast.BitOr(), right=right)
        return left

    def looks_like_generic(self) -> bool:
        j, depth = self.i, 0
        while j < len(self.toks) and j < self.i + 30:
            v = self.toks[j].val if self.toks[j].kind == "punct" else None
            if v == "<":
                depth += 1
            elif v == ">":
                depth -= 1
                if depth == 0:
                    nxt = self.toks[j + 1].val if j + 1 < len(self.toks) else ""
                    return nxt in ("(", ".", "{", "[", "::") or self.toks[j + 1].kind == "id"
            elif v in (";", "{", "}", "(", ")") or self.toks[j].kind in ("str", "num"):
                return False
            j += 1
        return False

    def parse_unary(self):
        t = self.t
        line = t.line
        if t.kind == "punct" and t.val in ("!", "-", "+", "~", "++", "--", "*", "&", "@", "<-"):
            self.i += 1
            operand = self.untuple(self.parse_unary())
            if t.val == "!":
                return _mk(ast.UnaryOp, line, op=ast.Not(), operand=operand)
            return operand
        if t.kind == "id" and t.val in ("typeof", "sizeof", "await", "new", "clone", "print", "not", "yield", "throw"):
            if t.val == "new":
                return self.parse_new()
            self.i += 1
            if t.val == "await":
                return _mk(ast.Await, line, value=self.untuple(self.parse_unary()))
            if t.val == "print":
                e = self.untuple(self.parse_unary())
                return _mk(ast.Call, line, func=_name("print", line), args=[e], keywords=[])
            return self.untuple(self.parse_unary())
        # C-style cast: (Type) expr
        if self.at("(") and self.lang in ("java", "csharp", "php"):
            save = self.i
            self.i += 1
            if self.t.kind == "id":
                try:
                    self.skip_type()
                    if self.at(")") and (self.peek().kind in ("id", "str", "num", "istr") or self.peek().val in ("(", "$", "!", "-")) and not (self.peek().kind == "id" and self.peek().val in ("instanceof", "is", "as", "and", "or", "in")):
                        # looks like a cast if the type name is a known type keyword or capitalised and followed by an operand
                        tn = self.toks[save + 1].val
                        if tn in TYPE_KW or tn[:1].isupper() or tn in ("int", "float", "string", "array", "bool", "object"):
                            self.i += 1
                            return self.untuple(self.parse_unary())
                except ParseError:
                    pass
            self.i = save
        return self.parse_postfix()

    def parse_new(self):
        line = self.t.line
        self.eat("new")
        if self.at("("):   # C# target-typed new(...)
            return self.parse_call(_name("_new", line), line)
        target = self.parse_postfix(no_call=True)
        if self.at("<"):
            self.skip_balanced("<", ">")
        if self.at("["):   # array creation
            self.skip_balanced("[", "]")
            if self.at("{"):
                return self.parse_array_literal()
            return _mk(ast.List, line, elts=[], ctx=ast.Load())
        if self.at("("):
            call = self.parse_call(self.untuple(target), line)
            if self.at("{"):   # anonymous class / object initializer
                self.skip_balanced("{", "}")
            return call
        if self.at("{"):
            self.skip_balanced("{", "}")
        return _mk(ast.Call, line, func=self.untuple(target), args=[], keywords=[])

    def parse_array_literal(self):
        line = self.t.line
        self.eat("{")
        elts = []
        while not self.at("}") and self.t.kind != "eof":
            if self.at("{"):
                elts.append(self.parse_array_literal())
            else:
                elts.append(self.untuple(self.parse_assignment()))
            if not self.opt(","):
                break
        self.eat("}")
        return _mk(ast.List, line, elts=elts, ctx=ast.Load())

    def parse_postfix(self, no_call=False):
        e = self.parse_primary()
        while True:
            t = self.t
            if t.kind == "punct" and t.val in (".", "->", "::", "?.", "?->") and not (t.val == "." and self.lang == "php"):
                self.i += 1
                if self.at("<"):   # explicit generic method call
                    self.skip_balanced("<", ">")
                if self.at("("):   # kotlin/scala (expr).(...) unusual
                    continue
                if self.at("{"):   # PHP ->{$x}
                    self.skip_balanced("{", "}")
                    continue
                if self.at("*"):   # import.* handled elsewhere
                    self.i += 1
                    continue
                nm = self.eat()
                attr = nm.val.lstrip("$") if nm.kind == "id" else str(nm.val)
                if t.val == "::" and self.lang == "java" and isinstance(e, (ast.Name, ast.Attribute)):
                    # method reference Foo::bar -> treat as attribute
                    pass
                e = _mk(ast.Attribute, nm.line, value=self.untuple(e), attr=attr, ctx=ast.Load())
            elif t.kind == "punct" and t.val == "[":
                self.i += 1
                if self.at("]"):
                    self.i += 1
                    e = _mk(ast.Subscript, t.line, value=self.untuple(e), slice=_const(0, t.line), ctx=ast.Load())
                    continue
                idx = self.untuple(self.parse_expression())
                while self.opt(","):
                    self.parse_expression()
                if self.at(":"):
                    self.i += 1
                    if not self.at("]"):
                        self.parse_expression()
                self.eat("]")
                e = _mk(ast.Subscript, t.line, value=self.untuple(e), slice=idx, ctx=ast.Load())
            elif t.kind == "punct" and t.val == "(" and not no_call:
                e = self.parse_call(self.untuple(e), t.line)
            elif t.kind == "punct" and t.val == "{" and self.lang == "kotlin" and isinstance(e, (ast.Name, ast.Attribute, ast.Call)) and not no_call:
                # trailing lambda: list.forEach { x -> ... }
                lam = self.parse_kotlin_lambda()
                if isinstance(e, ast.Call):
                    e.args.append(lam)
                else:
                    e = _mk(ast.Call, t.line, func=e, args=[lam], keywords=[])
            elif t.kind == "punct" and t.val == "<" and self.looks_like_generic() and not no_call:
                self.skip_balanced("<", ">")
            elif t.kind == "punct" and t.val in ("++", "--", "!!", "!"):
                self.i += 1
            elif t.kind == "istr" or (t.kind == "str" and self.lang == "kotlin" and False):
                break
            else:
                break
        return e

    def parse_kotlin_lambda(self):
        line = self.t.line
        self.eat("{")
        params = []
        # { a, b -> body } or { body } (implicit 'it')
        j = self.i
        names = []
        while self.toks[j].kind == "id" and self.toks[j + 1].val in (",", "->", ":"):
            names.append(self.toks[j].val)
            k = j + 1
            if self.toks[k].val == ":":
                k += 1
                while self.toks[k].val not in (",", "->") and self.toks[k].kind != "eof":
                    k += 1
            if self.toks[k].val == ",":
                j = k + 1
                continue
            if self.toks[k].val == "->":
                self.i = k + 1
                params = names
            break
        if not params:
            params = ["it"]
        body = self.parse_statements()
        self.eat("}")
        name = f"_fn_{line}_{self.anon}"
        self.anon += 1
        fn = self.make_function(name, params, body or [_mk(ast.Pass, line)], line, [])
        self.hoisted.append(fn)
        return _name(name, line)

    def parse_call(self, func, line):
        self.eat("(")
        args, kws = [], []
        while not self.at(")") and self.t.kind != "eof":
            if self.t.kind == "id" and self.peek().val in ("=", ":") and self.lang in ("kotlin", "csharp", "php") and self.peek(2).val != "=":
                # named argument name = expr / name: expr
                kname = self.eat().val
                self.i += 1
                kws.append(ast.keyword(arg=kname, value=self.untuple(self.parse_assignment())))
            else:
                if self.lang == "csharp" and self.t.kind == "id" and self.t.val in ("out", "ref", "in") and self.peek().kind == "id":
                    self.i += 1
                    if self.at_kw("var"):
                        self.i += 1
                self.opt("...")
                a = self.untuple(self.parse_assignment())
                args.append(a)
            if not self.opt(","):
                break
        self.eat(")")
        if self.lang == "kotlin" and self.at("{"):
            args.append(self.parse_kotlin_lambda())
        return _mk(ast.Call, line, func=func, args=args, keywords=kws)

    def parse_interpolated(self, tok) -> ast.AST:
        """Kotlin "$x ${expr}", PHP "$x {$expr}", C# $"{expr}" -> JoinedStr."""
        raw = tok.val
        if raw.startswith("$"):
            raw = raw[1:]
        raw = raw.lstrip("@")
        inner = raw[1:-1]
        values = []
        buf = ""
        i = 0
        while i < len(inner):
            c = inner[i]
            if c == "\\" and i + 1 < len(inner):
                buf += inner[i:i + 2]
                i += 2
                continue
            if (self.lang in ("kotlin", "php") and c == "$") or (self.lang == "csharp" and c == "{") or (self.lang == "php" and c == "{" and i + 1 < len(inner) and inner[i + 1] == "$"):
                if self.lang == "csharp" and inner[i:i + 2] == "{{":
                    buf += "{"
                    i += 2
                    continue
                expr_src = None
                if c == "{" or (c == "$" and i + 1 < len(inner) and inner[i + 1] == "{"):
                    start = i + (2 if c == "$" else 1)
                    depth, k = 1, start
                    while k < len(inner) and depth:
                        if inner[k] == "{":
                            depth += 1
                        elif inner[k] == "}":
                            depth -= 1
                        k += 1
                    expr_src = inner[start:k - 1]
                    i = k
                else:
                    m = re.match(r"\$([A-Za-z_][\w]*(?:(?:->|\.)[A-Za-z_]\w*|\[[^\]]*\])*)", inner[i:])
                    if not m:
                        buf += c
                        i += 1
                        continue
                    expr_src = ("$" if self.lang == "php" else "") + m.group(1)
                    i += m.end()
                if buf:
                    values.append(_const(buf, tok.line))
                    buf = ""
                sub = Parser(expr_src, "inline", self.lang)
                sub.mod = self.mod
                try:
                    e = sub.untuple(sub.parse_expression())
                except ParseError:
                    e = _const("", tok.line)
                self.hoisted.extend(sub.hoisted)
                values.append(_mk(ast.FormattedValue, tok.line, value=e, conversion=-1, format_spec=None))
                continue
            buf += c
            i += 1
        if buf:
            values.append(_const(buf, tok.line))
        return _mk(ast.JoinedStr, tok.line, values=values)

    def parse_primary(self):
        t = self.t
        line = t.line
        if t.kind == "num":
            self.i += 1
            try:
                v = float(re.sub(r"[fFdDlLmMuU_]", "", t.val))
            except ValueError:
                v = 0
            return _const(v, line)
        if t.kind == "istr":
            self.i += 1
            return self.parse_interpolated(t)
        if t.kind == "str":
            self.i += 1
            raw = t.val
            if raw.startswith("`"):
                return _const(raw[1:-1], line)
            if raw.startswith('"') and (self.lang in ("kotlin", "php")) and ("$" in raw):
                return self.parse_interpolated(t)
            return _const(raw[1:-1], line)
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
                    if self.opt("...") or self.at(","):
                        self.opt(",")
                        continue
                    k = self.untuple(self.parse_assignment())
                    if self.opt("=>"):   # php assoc
                        k = self.untuple(self.parse_assignment())
                    elts.append(k)
                    self.opt(",")
                self.eat("]")
                return _mk(ast.List, line, elts=elts, ctx=ast.Load())
            if t.val == "{":   # Go composite literal / block as expr
                return self.parse_array_literal()
            if t.val == "$" and self.lang == "php":   # $$var
                self.i += 1
                return self.parse_primary()
            if t.val == "@":   # java annotation in expression position / php silence
                self.i += 1
                return self.parse_primary()
            if t.val == "&" or t.val == "*":
                self.i += 1
                return self.parse_unary()
        if t.kind == "id":
            v = t.val
            if v == "new":
                return self.parse_new()
            if v in ("this", "$this", "self", "static", "parent", "base"):
                self.i += 1
                return _name("self" if v in ("this", "$this", "self", "static") else "super", line)
            if v == "super":
                self.i += 1
                return _name("super", line)
            if v in ("true", "false", "True", "False", "TRUE", "FALSE"):
                self.i += 1
                return _const(v.lower() == "true", line)
            if v in ("null", "nil", "NULL", "None"):
                self.i += 1
                return _const(None, line)
            if v == "array" and self.lang == "php" and self.peek().val == "(":
                self.i += 1
                self.eat("(")
                elts = []
                while not self.at(")") and self.t.kind != "eof":
                    k = self.untuple(self.parse_assignment())
                    if self.opt("=>"):
                        k = self.untuple(self.parse_assignment())
                    elts.append(k)
                    if not self.opt(","):
                        break
                self.eat(")")
                return _mk(ast.List, line, elts=elts, ctx=ast.Load())
            if v == "func" and self.lang == "go":
                fn = self.parse_function([])
                self.hoisted.append(fn)
                return _name(fn.name, line)
            if v in ("function", "fn") and self.lang == "php":
                return self.parse_assignment()
            if v == "object" and self.lang == "kotlin" and self.peek().val in (":", "{"):
                self.i += 1
                if self.opt(":"):
                    self.skip_type()
                    if self.at("("):
                        self.skip_balanced("(", ")")
                self.skip_balanced("{", "}")
                return _name("_object", line)
            self.i += 1
            name = v.lstrip("$") if (v.startswith("$") and v not in ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER", "$_FILES", "$_ENV", "$argv", "$HTTP_RAW_POST_DATA", "$GLOBALS", "$_SESSION")) else v
            return _name(name, line)
        raise ParseError(f"unexpected {t.val!r} line {line}")


def _rewrite_implicit_this(fn, field_names: set) -> None:
    """Inside a method, a bare name that is a class field (and not a parameter/local) means this.field."""
    locals_ = {a.arg for a in fn.args.args}
    for n in ast.walk(fn):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            locals_.add(n.id)
        elif isinstance(n, (ast.For,)) and isinstance(n.target, ast.Name):
            locals_.add(n.target.id)

    class R(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in field_names and node.id not in locals_ and node.id != "self":
                return _mk(ast.Attribute, node.lineno, value=_name("self", node.lineno), attr=node.id, ctx=node.ctx)
            return node
    R().visit(fn)


def module_name(rel: str) -> str:
    rel = rel.replace("\\", "/")
    rel = re.sub(r"\.(java|kt|kts|cs|go|php|phtml)$", "", rel)
    return rel.replace("/", ".")


def parse_cfamily(text: str, rel: str, lang: str) -> ast.Module:
    try:
        p = Parser(text, rel, lang)
        mod = p.parse_program()
        # Go: attach receiver methods to their struct classes
        if lang == "go":
            classes = {n.name: n for n in mod.body if isinstance(n, ast.ClassDef)}
            for cname, fns in p.go_methods.items():
                cls = classes.get(cname)
                if cls is None:
                    cls = _mk(ast.ClassDef, 1, name=cname, bases=[], keywords=[], body=[], decorator_list=[], type_params=[])
                    mod.body.insert(0, cls)
                cls.body = [s for s in cls.body if not isinstance(s, ast.Pass)] + fns
                if not cls.body:
                    cls.body = [_mk(ast.Pass, 1)]
        return mod
    except Exception:  # noqa: BLE001 - never abort a scan on a frontend bug
        return ast.Module(body=[], type_ignores=[])
