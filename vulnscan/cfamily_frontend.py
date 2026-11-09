"""C-family frontend: lowers Java, Kotlin, C#, Go, PHP, C/C++, Rust, Swift and Ruby into the engine's Python ``ast``.

One recovering tokenizer/parser with per-language switches. Ruby (``def … end``
blocks) is handled by the same parser through keyword-terminated blocks.
Every statement the parser cannot understand is recorded as a diagnostic
(line + reason) and skipped, so a scan reports exactly what the frontend did
not see instead of dropping it silently (``Parser.diagnostics``,
``parse_cfamily_ex``). Like the JS
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

from .js_frontend import Tok, _args, _const, _ends, _mk, _name, _strip_switch_breaks  # reuse node helpers

LANG_EXTS = {".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".cs": "csharp", ".go": "go", ".php": "php", ".phtml": "php",
             ".c": "cpp", ".h": "cpp", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp",
             ".rs": "rust", ".swift": "swift", ".rb": "ruby", ".rake": "ruby"}
TYPED_LANGS = ("java", "csharp", "cpp")            # `Type name` declarations
COLON_TYPED_LANGS = ("kotlin", "php", "rust", "swift", "ruby")   # `name: Type` parameters
BRACE_LAMBDA_LANGS = ("kotlin", "swift")           # trailing `{ … }` closures on calls
NEWLINE_TERMINATED = ("go", "kotlin", "swift", "ruby", "rust")
TOKEN_RE = re.compile(r"""
    (?P<ws>[ \t\r\f\v]+) | (?P<nl>\n) | (?P<lc>//[^\n]*|\#[^\n]*) | (?P<bc>/\*.*?\*/) |
    (?P<tstr>\"\"\".*?\"\"\") |
    (?P<vstr>@"(?:""|[^"])*") |
    (?P<istr>\$@?"(?:\\.|[^"\\])*"|\$'(?:\\.|[^'\\])*') |
    (?P<str>"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`[^`]*`) |
    (?P<num>0[xX][0-9a-fA-F_]+|(?:\d[\d_]*\.?[\d_]*|\.\d[\d_]*)(?:[eE][+-]?\d+)?[fFdDlLmMuU]*) |
    (?P<id>\$?[A-Za-z_][\w]*) |
    (?P<punct>===|!==|<=>|\?\?=|\*\*=|\.=(?!=)|\.\.\.|->|=>|::|\?\.|\?:|!!|\+\+|--|<<=|>>=|<=|>=|==|!=|&&|\|\||\|\|=|&&=|\+=|-=|\*=|/=|%=|&=|\|=|\^=|\?\?|:=|\.\.|&\.|[{}()\[\];,<>+\-*/%&|^!~?:=.@#$\\])
""", re.S | re.X)
# Ruby: `#` comments only, symbols (:name), instance variables (@x / @@x), method names ending in ? or !
RUBY_TOKEN_RE = re.compile(r"""
    (?P<ws>[ \t\r\f\v]+) | (?P<nl>\n) | (?P<lc>\#[^\n]*) |
    (?P<tstr>\"\"\".*?\"\"\") |
    (?P<str>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`[^`]*`) |
    (?P<num>0[xX][0-9a-fA-F_]+|(?:\d[\d_]*\.?[\d_]*|\.\d[\d_]*)(?:[eE][+-]?\d+)?) |
    (?P<ivar>@@?[A-Za-z_]\w*) |
    (?P<sym>(?<![\w)\]"'])\:[A-Za-z_]\w*[?!]?) |
    (?P<id>\$?[A-Za-z_]\w*(?:[?!](?![=~]))?) |
    (?P<punct>\.\.\.|->|=>|::|&\.|<=>|\*\*|\+\+|--|<<=|>>=|<=|>=|==|!=|=~|!~|&&|\|\||\|\|=|&&=|\+=|-=|\*=|/=|%=|&=|\|=|\^=|\.\.|[{}()\[\];,<>+\-*/%&|^!~?:=.@#$\\])
""", re.S | re.X)
RUBY_HEREDOC_RE = re.compile(r"<<[~-]?(['\"]?)([A-Z_][A-Z0-9_]*)\1(.*?)\n(.*?)^[ \t]*\2[ \t]*$", re.S | re.M)
RUBY_KW = {"def", "end", "if", "unless", "elsif", "else", "while", "until", "for", "in", "do", "then", "case", "when", "begin",
           "rescue", "ensure", "return", "class", "module", "and", "or", "not", "yield", "next", "break", "redo", "retry", "self",
           "nil", "true", "false", "super", "alias", "undef", "defined?", "lambda", "proc", "loop", "raise", "require",
           "require_relative", "include", "extend", "private", "protected", "public", "attr_reader", "attr_writer", "attr_accessor"}
RUBY_ROUTES = {"get", "post", "put", "patch", "delete", "options", "head", "route", "namespace", "before", "after"}
MODIFIERS = {"public", "private", "protected", "internal", "static", "final", "abstract", "override", "open", "sealed",
             "virtual", "async", "readonly", "const", "volatile", "transient", "synchronized", "native", "default",
             "unsafe", "extern", "partial", "inline", "suspend", "operator", "infix", "tailrec", "external", "lateinit",
             "data", "inner", "enum", "annotation", "companion", "crossinline", "noinline", "reified", "vararg",
             # C/C++
             "constexpr", "explicit", "friend", "mutable", "register", "signed", "unsigned", "typename", "thread_local", "noexcept",
             # Rust
             "pub", "mut", "crate", "move",
             # Swift
             "fileprivate", "mutating", "nonmutating", "convenience", "required", "lazy", "weak", "unowned", "indirect",
             "nonisolated", "dynamic", "optional", "throwing"}
TYPE_KW = {"void", "int", "long", "short", "byte", "char", "boolean", "bool", "float", "double", "string", "var", "val",
           "object", "dynamic", "decimal", "uint", "ulong", "String", "Integer", "Boolean", "Object", "List", "Map", "Set",
           "Task", "IActionResult", "ActionResult", "error", "any", "Unit", "Nothing"}
STMT_START = {"return", "if", "for", "while", "do", "try", "throw", "switch", "break", "continue", "var", "val", "let",
              "func", "fun", "function", "class", "struct", "interface", "import", "package", "using", "namespace",
              "public", "private", "protected", "static", "echo", "print", "foreach", "defer", "go", "case", "default",
              "else", "catch", "finally", "type", "const", "when", "override", "internal", "abstract", "final", "open",
              "require", "include", "require_once", "include_once", "use", "@", "#",
              "fn", "let", "impl", "pub", "match", "loop", "mod", "def", "end", "unless", "until", "begin", "rescue", "ensure",
              "module", "elsif", "guard", "extension", "protocol", "typedef", "template", "trait", "struct", "enum", "init"}


PHP_HEREDOC_RE = re.compile(r"<<<[ \t]*([\"']?)([A-Za-z_]\w*)\1[ \t]*\r?\n(.*?)\r?\n[ \t]*\2\b", re.S)


def _php_heredoc_token(m) -> str:
    """PHP heredoc (interpolating, like "…") / nowdoc (<<<'X', literal, like '…') -> one string literal on one
    line, followed by the newlines it spanned so later line numbers stay right."""
    body = m.group(3)
    if m.group(1) == "'":
        lit = "'" + body.replace("\\", "\\\\").replace("'", "\\'").replace("\n", " ") + "'"
    else:
        lit = '"' + body.replace('"', '\\"').replace("\r", "").replace("\n", "\\n") + '"'
    return lit + "\n" * m.group(0).count("\n")


def tokenize(src: str, lang: str) -> list[Tok]:
    toks: list[Tok] = []
    i, line, n = 0, 1, len(src)
    nl_before = False
    regex = TOKEN_RE
    if lang == "ruby":
        regex = RUBY_TOKEN_RE
        # =begin … =end comments and heredocs become one string token each, line count preserved
        src = re.sub(r"^=begin.*?^=end[^\n]*$", lambda m: "\n" * m.group(0).count("\n"), src, flags=re.S | re.M)
        src = RUBY_HEREDOC_RE.sub(_heredoc_token, src)
        n = len(src)
    if lang == "php":
        # keep only PHP code regions (<?php ... ?>); HTML outside is ignored
        parts = re.split(r"(<\?(?:php|=)?|\?>)", src)
        out, keep, _lines_so_far = [], False, ""
        for part in parts:
            if part in ("<?php", "<?", "<?="):
                keep = True
                if part == "<?=":
                    out.append(" echo ")         # `<?= $x ?>` prints its value
                continue
            if part == "?>":
                keep = False
                out.append(";")
                continue
            out.append(part if keep else "\n" * part.count("\n"))
        src = PHP_HEREDOC_RE.sub(_php_heredoc_token, "".join(out))
        n = len(src)
    while i < n:
        m = regex.match(src, i)
        if not m:
            i += 1
            continue
        kind, text = m.lastgroup, m.group(0)
        if kind == "nl":
            line += 1
            nl_before = True
        elif kind == "lc" and text.startswith("#") and lang == "rust":
            # Rust attributes: #[derive(..)], #[get("/x")] -- '#' is punctuation, not a comment
            toks.append(Tok("punct", "#", line, nl_before))
            nl_before = False
            i += 1
            continue
        elif kind in ("ws", "lc"):
            pass   # C preprocessor directives, C# #region and Ruby/PHP comments are skipped
        elif kind == "bc" or kind == "tstr" or kind == "vstr":
            line += text.count("\n")
            if kind != "bc":
                toks.append(Tok("str", '"' + text.strip('@"') + '"', line, nl_before))
                nl_before = False
        else:
            if kind == "istr":
                toks.append(Tok("istr", text, line, nl_before))
            elif kind == "str" and text.startswith('"') and "\n" in text:
                toks.append(Tok(kind, text, line, nl_before))
                line += text.count("\n")
            else:
                toks.append(Tok(kind, text, line, nl_before))
            nl_before = False
        i = m.end()
    toks.append(Tok("eof", "", line, True))
    return toks


def _heredoc_token(m) -> str:
    """Replace a Ruby heredoc with a one-line string token followed by the rest of its opening line and blank lines."""
    body = m.group(4).replace("\\", "/").replace('"', "'").replace("\n", " ")
    nl = m.group(0).count("\n")
    return '"' + body + '"' + m.group(3) + "\n" * nl



# word operators per language: `in`, `is`, `as`, `and`, `or` are ordinary identifiers in Java/C/C++/Go
_WORD_OPS = {"java": ("instanceof",), "csharp": ("is", "as"), "kotlin": ("is", "as", "in"), "swift": ("is", "as"),
             "php": ("instanceof", "as", "and", "or"), "ruby": ("and", "or"), "rust": ("as",), "go": (), "c": (), "cpp": ()}

_BINOP = {"+": ast.Add, ".": ast.Add, "..": ast.Add, "-": ast.Sub, "*": ast.Mult, "/": ast.Div, "%": ast.Mod,
          "**": ast.Pow, "&": ast.BitAnd, "|": ast.BitOr, "^": ast.BitXor, "<<": ast.LShift, ">>": ast.RShift,
          ">>>": ast.RShift}


def _num_value(text: str):
    """A numeric literal as int when it is written as an integer (12, 0x1F, 0b101, 10L), else float (1.5, 2e3, 5.0f)."""
    raw = text.replace("_", "").replace("'", "")
    is_hex = raw[:2].lower() in ("0x", "0b", "0o")
    if not is_hex and (re.search(r"[.eE]", raw) or re.search(r"[fFdDmM]$", raw)):
        try:
            return float(re.sub(r"[fFdDmM]$", "", raw))
        except ValueError:
            return 0
    try:
        return int(re.sub(r"[lLuUnN]+$", "", raw), 0)
    except ValueError:
        try:
            return int(re.sub(r"[lLuUnN]+$", "", raw).lstrip("0") or "0")
        except ValueError:
            return 0


_AUG = {"+=": ast.Add, "-=": ast.Sub, "*=": ast.Mult, "/=": ast.Div, "%=": ast.Mod, "**=": ast.Pow, "&=": ast.BitAnd,
        "|=": ast.BitOr, "^=": ast.BitXor, "<<=": ast.LShift, ">>=": ast.RShift, ">>>=": ast.RShift}


def _aug_op(op):
    return _AUG.get(op, ast.Add)()       # .=, ??=, ||= … keep the concatenating / propagating meaning


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
        self.diagnostics: list = []      # (line, reason) for every statement that was skipped
        self.n_statements = 0
        self.ext_methods: dict = {}      # Go receiver methods / Rust impl / Swift extension -> class name -> [FunctionDef]
        self.go_structs: dict = {}
        self.no_brace_call = 0           # >0 while parsing an if/for/while/match head: `x {` is a block, not a closure
        self.ruby_locals: set = set()
        self.yield_targets: list = []   # Java switch expressions being parsed: the temporaries their arms assign
        self.class_fields: dict = {}
        self.in_command_args = 0
        self._swift_static = False
        self.typed = lang in TYPED_LANGS

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
        if self.lang in NEWLINE_TERMINATED:
            return
        if self.lang == "ruby" and self.t.kind == "id" and self.t.val in ("end", "else", "elsif", "rescue", "ensure", "when", "then", "do"):
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
                if v == "}" and depth == 0:
                    self.i += 1
                    if not (self.t.kind == "id" and self.t.val in ("else", "catch", "finally", "while", "elsif", "rescue", "ensure")):
                        return
                    continue
            elif v == ";" and depth == 0:
                self.i += 1
                return
            elif depth == 0 and self.t.nl_before and self.t.kind == "id" and self.t.val in STMT_START:
                return
            elif depth == 0 and self.lang == "ruby" and self.t.kind == "id" and self.t.val in ("end", "else", "elsif", "rescue", "ensure", "when"):
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
        """Consume a type (identifiers with dots/generics/arrays, pointers, references, nullable, function types)."""
        while self.t.kind == "punct" and self.t.val in ("*", "&", "&&", "[", "]", "?", "!") or \
                (self.t.kind == "id" and self.t.val in ("mut", "dyn", "impl", "some", "any", "inout", "const", "unsigned", "signed", "struct", "typename")):
            if self.t.val == "[":
                self.skip_balanced("[", "]")
            else:
                self.i += 1
        if self.lang == "ruby":
            return
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
        while self.t.kind == "punct" and self.t.val in ("[", "?", "!", "*", "&", "&&"):
            if self.t.val == "[":
                self.skip_balanced("[", "]")
            else:
                self.i += 1
        if self.lang in ("kotlin", "swift") and self.at("->"):
            self.i += 1
            self.skip_type()

    def looks_like_type_then_name(self) -> bool:
        """Java/C#: `Type name` (declaration) vs expression. Scan a type then expect an identifier."""
        save = self.i
        try:
            if self.t.kind != "id" or self.t.val in ("return", "new", "throw", "this", "super", "base"):
                return False
            self.skip_type()
            ok = self.t.kind == "id" and self.t.val not in ("instanceof",) + _WORD_OPS.get(self.lang, ("is", "as", "in")) \
                and not self.t.nl_before
            if not ok and self.lang == "cpp" and self.at("(") and any(tk.val == "::" for tk in self.toks[save:self.i]):
                j, depth = self.i, 0
                while j < len(self.toks):
                    v = self.toks[j].val if self.toks[j].kind == "punct" else None
                    if v == "(":
                        depth += 1
                    elif v == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                nxt = self.toks[j + 1] if j + 1 < len(self.toks) else self.toks[-1]
                ok = nxt.val in ("{", ":", "const", "override", "noexcept", "->", "final", "throw")
            return ok
        except Exception:  # noqa: BLE001
            return False
        finally:
            self.i = save

    # ------------------------------------------------------------ program
    def parse_program(self) -> ast.Module:
        body = self.parse_statements(top=True)
        return ast.Module(body=body, type_ignores=[])

    def parse_statements(self, top=False, stop=()) -> list:
        out = []
        while self.t.kind != "eof" and not (not top and self.at("}")) and not (stop and self.t.kind == "id" and self.t.val in stop):
            start = self.i
            try:
                st = self.parse_statement()
                self.n_statements += 1
                out.extend(self.hoisted)
                self.hoisted = []
                out.extend(st)
            except ParseError as e:
                self.hoisted = []
                if len(self.diagnostics) < 500:
                    self.diagnostics.append((self.toks[start].line, str(e)))
                self.sync()
                if self.i == start:
                    self.i += 1
        return out

    def ruby_block(self, stop=("end",), eat_end=True) -> list:
        """Ruby: statements up to one of the terminator keywords; `end` is consumed when eat_end."""
        body = self.parse_statements(stop=stop)
        if eat_end and self.at_kw("end"):
            self.i += 1
        return body or [_mk(ast.Pass, self.t.line)]

    def block(self) -> list:
        if self.lang == "ruby" and not self.at("{"):
            self.opt("do")
            return self.ruby_block()
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
            elif self.lang in ("php", "rust") and self.at("#") and self.peek().val == "[":
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
            if self.lang == "ruby":
                st = self.parse_ruby_statement(decs, line)
                if st is not None:
                    return st
            elif self.lang == "cpp":
                st = self.parse_cpp_statement(decs, line, v)
                if st is not None:
                    return st
            elif self.lang == "rust":
                st = self.parse_rust_statement(decs, line, v)
                if st is not None:
                    return st
            elif self.lang == "swift":
                st = self.parse_swift_statement(decs, line, v)
                if st is not None:
                    return st
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
            self._swift_static = "static" in mods or "class" in mods
            if mods and self.t.kind == "eof":
                return []
            v = self.t.val if self.t.kind == "id" else ""
            if v in ("class", "struct", "interface", "trait", "record", "enum", "object", "protocol", "union") and self.peek().kind == "id" \
                    and not (v == "object" and self.lang != "kotlin") and not (v == "record" and self.lang == "csharp"
                                                                             and self.peek(2).val in ("=", ";", ")")):
                return [self.parse_class(decs)]
            # constructor declared with the class name: Foo(int x) { ... }  (Java, C#, C++)
            if self.typed and self.cls_stack and v == self.cls_stack[-1] and self.peek().val == "(" and not self.in_function:
                self.i += 1
                prev_in, self.in_function = self.in_function, True
                params, prologue, ann = self.parse_params()
                if self.lang == "cpp":
                    prologue = prologue + self.parse_cpp_init_list()
                self.skip_throws()
                body = prologue + (self.block() if self.at("{") else self.arrow_body())
                self.in_function = prev_in
                return [self.make_function("__init__", params, body, line, decs, ann, method=True)]
            if v == "type" and self.lang == "go":
                return self.parse_go_type(decs)
            if v in ("func", "fun", "function", "fn") and (self.peek().kind == "id" or self.peek().val in ("(", "<")):
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
            if v == "yield" and self.yield_targets and self.lang == "java":
                self.i += 1                     # `yield e;` inside a switch expression: the switch's value
                value = self.untuple(self.parse_expression())
                self.end_stmt()
                return [_mk(ast.Assign, line, targets=[_name(self.yield_targets[-1], line, store=True)], value=value)]
            if v in ("switch", "when", "match"):
                if self.yield_targets:          # a nested switch statement does not yield to the outer expression
                    saved, self.yield_targets = self.yield_targets, []
                    try:
                        return [self.parse_switch()]
                    finally:
                        self.yield_targets = saved
                return [self.parse_switch()]
            if self.lang in ("java", "c", "cpp", "csharp", "go", "kotlin", "swift") and self.peek().val == ":" \
                    and self.peek(2).kind == "id" and self.peek(2).val in ("for", "while", "do", "switch") \
                    and v not in ("case", "default"):
                self.i += 2                    # `outer: for (…)`: a statement label
                return self.parse_statement()
            if v in ("break", "continue", "goto", "fallthrough"):
                line = self.t.line
                self.i += 1
                labeled = self.t.kind == "id" and not self.t.nl_before
                if labeled:
                    self.i += 1
                self.end_stmt()
                if labeled:
                    # `break outer;` / `continue outer;`: leaves enclosing loops; the flow analysis joins this state
                    # into what follows every enclosing loop
                    return [_mk(ast.Expr, line, value=_mk(ast.Call, line, func=_name("__labeled_exit__", line), args=[], keywords=[]))]
                if v == "break":
                    return [_mk(ast.Break, line)]
                if v == "continue":
                    return [_mk(ast.Continue, line)]
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
                if self.lang == "rust" and self.at_kw("mut"):
                    self.i += 1
                return self.parse_var_decl(line, decs)
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
            # Java/C#/C++: `Type name = expr;` / `Type name(params) {}` (method); Kotlin: handled via fun/val/var
            if self.typed and self.looks_like_type_then_name():
                return self.parse_typed_decl(decs, line)
        expr = self.parse_expression()
        if self.lang == "ruby":
            return self.ruby_modifiers(self.expr_statement(expr, line), line)
        self.end_stmt()
        return self.expr_statement(expr, line)

    # ------------------------------------------------- C/C++ statements
    def parse_cpp_statement(self, decs, line, v):
        if v in ("public", "private", "protected") and self.peek().val == ":":
            self.i += 2
            return []
        if v == "template":
            self.i += 1
            if self.at("<"):
                self.skip_balanced("<", ">")
            return self.parse_statement()
        if v in ("typedef", "friend", "goto", "asm"):
            self.sync()
            return []
        if v == "extern" and self.peek().kind == "str":
            self.i += 2
            return self.block() if self.at("{") else self.parse_statement()
        if v == "using" and self.peek().val == "namespace":
            self.i += 2
            self.parse_dotted_name()
            self.end_stmt()
            return []
        return None

    def parse_cpp_init_list(self) -> list:
        """C++ constructor initializer list `: a(x), b{y}` -> self.a = x; self.b = y."""
        out = []
        while self.t.kind == "id" and self.t.val in ("const", "override", "noexcept", "final"):
            self.i += 1
        if not self.at(":"):
            return out
        self.i += 1
        while self.t.kind == "id":
            line = self.t.line
            name = self.parse_dotted_name().split(".")[-1]
            if self.at("<"):
                self.skip_balanced("<", ">")
            if self.at("(") or self.at("{"):
                close = ")" if self.at("(") else "}"
                self.i += 1
                args = []
                while not self.at(close) and self.t.kind != "eof":
                    args.append(self.untuple(self.parse_assignment()))
                    if not self.opt(","):
                        break
                self.eat(close)
                if args:
                    out.append(_mk(ast.Assign, line, targets=[_mk(ast.Attribute, line, value=_name("self", line), attr=name, ctx=ast.Store())], value=args[0]))
            if not self.opt(","):
                break
        return out

    # --------------------------------------------------- Rust statements
    def parse_rust_statement(self, decs, line, v):
        if v == "pub" and self.peek().val == "(":
            self.i += 1
            self.skip_balanced("(", ")")
            return self.parse_statement()
        if v == "impl":
            return self.parse_impl(decs)
        if v == "mod":
            self.i += 1
            self.pkg = self.eat().val
            if self.at("{"):
                return self.block()
            self.end_stmt()
            return []
        if v == "loop":
            self.i += 1
            return [_mk(ast.While, line, test=_const(True, line), body=self.block(), orelse=[])]
        if v in ("type", "macro_rules", "extern") or (v == "static" and self.peek().kind == "id" and self.peek(2).val == ":"):
            self.sync()
            return []
        if v == "unsafe" and self.peek().val == "{":
            self.i += 1
            return self.block()
        return None

    # -------------------------------------------------- Swift statements
    def parse_swift_statement(self, decs, line, v):
        if v == "try":
            expr = self.parse_expression()
            self.end_stmt()
            return self.expr_statement(expr, line)
        if v == "extension":
            return self.parse_impl(decs)
        if v == "guard":
            self.i += 1
            test = self.parse_cond()
            self.eat("else")
            body = self.block()
            return [_mk(ast.If, line, test=_mk(ast.UnaryOp, line, op=ast.Not(), operand=test), body=body, orelse=[])]
        if v == "do" and self.peek().val == "{":
            self.i += 1
            body = self.block()
            handlers = []
            while self.at_kw("catch"):
                self.i += 1
                nm = None
                if self.at_kw("let"):
                    self.i += 1
                    nm = self.eat().val
                while not self.at("{") and self.t.kind != "eof":
                    self.i += 1
                handlers.append(_mk(ast.ExceptHandler, line, type=None, name=nm, body=self.block()))
            if not handlers:
                handlers.append(_mk(ast.ExceptHandler, line, type=None, name=None, body=[_mk(ast.Pass, line)]))
            return [_mk(ast.Try, line, body=body, handlers=handlers, orelse=[], finalbody=[])]
        if v == "defer" and self.peek().val == "{":
            self.i += 1
            return self.block()
        if v == "repeat" and self.peek().val == "{":
            self.i += 1
            body = self.block()
            self.eat("while")
            test = self.parse_cond()
            return [_mk(ast.While, line, test=test, body=body, orelse=[])]
        if v in ("init", "deinit", "subscript") and self.peek().val in ("(", "{", "?", "!"):
            return [self.parse_function(decs)]
        if v in ("typealias", "associatedtype", "operator", "precedencegroup"):
            self.sync()
            return []
        return None

    # --------------------------------------- Rust impl / Swift extension
    def parse_type_name(self) -> str:
        parts = []
        while self.t.kind == "id":
            parts.append(self.eat().val)
            if self.at("<"):
                self.skip_balanced("<", ">")
            if self.at("::") or self.at("."):
                self.i += 1
                continue
            break
        return parts[-1] if parts else ""

    def parse_impl(self, decs) -> list:
        """`impl [Trait for] Type { fns }` / `extension Type[: Protos] { funcs }`: methods are attached to the class."""
        line = self.t.line
        self.i += 1
        if self.at("<"):
            self.skip_balanced("<", ">")
        name = self.parse_type_name()
        if self.at_kw("for"):
            self.i += 1
            name = self.parse_type_name()
        if self.at(":"):
            self.i += 1
            while True:
                self.skip_type()
                if not self.opt(","):
                    break
        if self.at_kw("where"):
            while not self.at("{") and self.t.kind != "eof":
                self.i += 1
        if not name:
            raise ParseError(f"impl without a type at line {line}")
        self.cls_stack.append(name)
        self.field_names_stack.append(set())
        prev_in, self.in_function = self.in_function, False
        body = self.block()
        self.in_function = prev_in
        self.cls_stack.pop()
        self.field_names_stack.pop()
        fns = [st for st in body if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef))]
        self.ext_methods.setdefault(name, []).extend(fns)
        return [_mk(ast.Pass, line)]

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
        """Java/C#/C++: `Type name = expr;` or `Type name(params) { }` or `Type name;` or C++ `Type Cls::name(params) { }`"""
        start = self.i
        self.skip_type()
        owner = None
        if self.t.kind == "id":
            name = self.eat().val
        elif self.lang == "cpp" and self.at("("):
            ids = [tk.val for tk in self.toks[start:self.i] if tk.kind == "id"]
            name = ids[-1]
            owner = ids[-2] if len(ids) >= 2 else None
        else:
            raise ParseError(f"expected a name at line {line}")
        if self.at("<"):
            self.skip_balanced("<", ">")
        while self.lang == "cpp" and self.at("::") and self.peek().kind == "id":
            owner = name
            self.i += 1
            name = self.eat().val
        while self.lang == "cpp" and self.at("["):
            self.skip_balanced("[", "]")
        if self.lang == "cpp" and self.at("(") and self.in_function and owner is None:
            # inside a function, `Type name(args);` constructs an object: name = Type(args)
            j, depth = self.i, 0
            while j < len(self.toks):
                v = self.toks[j].val if self.toks[j].kind == "punct" else None
                if v == "(":
                    depth += 1
                elif v == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if j + 1 < len(self.toks) and self.toks[j + 1].val == ";":
                tname = self.toks[start].val
                for tk in self.toks[start + 1:]:
                    if tk.kind == "id" and tk.val not in MODIFIERS and tk.val != name:
                        tname = tk.val
                    if tk is self.toks[self.i - 1]:
                        break
                call = self.parse_call(_name(tname, line), line)
                self.end_stmt()
                return self.field_or_local(name, call, line)
        if self.at("("):
            prev_in, self.in_function = self.in_function, True
            params, prologue, ann = self.parse_params()
            if self.lang == "cpp":
                prologue = prologue + self.parse_cpp_init_list()
            self.skip_throws()
            if self.lang == "cpp" and self.at(";"):     # prototype / forward declaration: no body
                self.i += 1
                self.in_function = prev_in
                return []
            body = prologue + (self.block() if self.at("{") else self.arrow_body())
            self.in_function = prev_in
            cls_name = owner or (self.cls_stack[-1] if self.cls_stack else None)
            is_ctor = cls_name is not None and name == cls_name
            fn = self.make_function("__init__" if is_ctor else name, params, body, line, decs, ann, method=bool(self.cls_stack) or owner is not None)
            if owner is not None:
                self.ext_methods.setdefault(owner, []).append(fn)
                return [_mk(ast.Pass, line)]
            return [fn]
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
        cfg = _config_annotation(decs, line)
        while True:
            if self.cls_stack and not self.in_function and self.field_names_stack:
                self.field_names_stack[-1].add(name)
            if self.opt("="):
                v = self.untuple(self.parse_assignment())
                out.extend(self.field_or_local(name, v, line))
            elif cfg is not None:
                out.extend(self.field_or_local(name, cfg, line))
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

    def parse_var_decl(self, line, decs=()) -> list:
        out = []
        cfg = _config_annotation(decs, line)
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
            if self.lang == "rust" and self.at_kw("mut"):
                self.i += 1
            name = self.eat().val.lstrip("$")
            if self.lang == "rust" and self.at("("):       # let Some(x) = …  (pattern): bind the inner names
                inner = []
                self.eat("(")
                while not self.at(")") and self.t.kind != "eof":
                    if self.t.kind == "id":
                        inner.append(self.eat().val)
                    else:
                        self.i += 1
                self.eat(")")
                if self.opt("="):
                    v = self.untuple(self.parse_assignment())
                    for nm in inner:
                        out.extend(self.field_or_local(nm, v, line))
                if self.at_kw("else"):
                    self.i += 1
                    self.skip_balanced("{", "}")
                break
            self.skip_type_annotation()
            if self.lang == "swift" and self.at("{") and not self.in_function:   # computed property / observers
                self.skip_balanced("{", "}")
                break
            if self.cls_stack and not self.in_function and self.field_names_stack:
                self.field_names_stack[-1].add(name)
            if not self.at("=") and cfg is not None:
                out.extend(self.field_or_local(name, cfg, line))
            if self.opt("="):
                v = self.untuple(self.parse_assignment())
                out.extend(self.field_or_local(name, v, line))
                if self.lang == "rust" and self.at_kw("else"):
                    self.i += 1
                    self.skip_balanced("{", "}")
                if self.lang == "swift" and self.at("{") and not self.t.nl_before and not self.in_function:
                    self.skip_balanced("{", "}")
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
        while self.t.kind == "id" and self.t.val in ("throws", "rethrows", "async", "const", "override", "noexcept", "final", "mutating"):
            if self.t.val == "throws" and self.lang != "swift":
                self.i += 1
                self.parse_dotted_name()
                while self.opt(","):
                    self.parse_dotted_name()
                continue
            self.i += 1
        if self.at("->") and self.lang in ("rust", "swift"):
            self.i += 1
            self.skip_type()
        if self.lang == "cpp" and self.at(":"):   # ctor initializer list
            while not self.at("{") and not self.at(";") and self.t.kind != "eof":
                self.i += 1
            return
        if self.lang == "rust" and self.at_kw("where"):
            while not self.at("{") and not self.at(";") and self.t.kind != "eof":
                self.i += 1
            return
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
            while self.t.kind == "id" and self.t.val in ("final", "params", "ref", "out", "in", "this", "vararg", "val", "var", "private", "public", "protected", "override",
                                                         "mut", "inout", "const", "unsigned", "signed", "struct", "register", "volatile", "borrowing", "consuming") \
                    or (self.lang == "rust" and self.t.kind == "punct" and self.t.val in ("&", "&&")):
                if self.t.val in ("val", "var", "private", "public", "protected"):
                    prop = True
                self.i += 1
                if self.lang == "rust" and self.t.kind == "id" and self.t.val == "mut":
                    self.i += 1
            self.opt("...")
            if self.lang == "swift":
                # `_ name: T` / `label name: T`
                if self.t.val == "_" and self.peek().kind == "id":
                    self.i += 1
                elif self.t.kind == "id" and self.peek().kind == "id" and self.peek(2).val == ":":
                    self.i += 1
            if self.typed:
                # Type name  (type may be generic/array/nullable)
                start = self.i
                self.skip_type()
                if self.t.kind == "id":
                    tname = self.toks[start].val
                    name = self.eat().val
                    while self.lang == "cpp" and self.at("["):
                        self.skip_balanced("[", "]")
                elif self.lang == "cpp" and self.at(")") and self.i > start:   # f(void) / unnamed parameter
                    if self.toks[start].val == "void":
                        break
                    name = f"_p{len(names)}"
                    tname = self.toks[start].val
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
            else:  # kotlin / php / rust / swift
                name = self.eat().val.lstrip("$")
                tname = None
                if self.at(":"):
                    self.eat(":")
                    start = self.i
                    self.skip_type()
                    tname = "".join(tk.val for tk in self.toks[start:self.i] if tk.kind == "id" or tk.val in (".", "::"))
                    self.opt("...")
                if self.lang == "php" and self.t.kind == "id" and self.peek().kind == "id" and self.peek().val.startswith("$"):
                    pass
            if self.opt("="):
                self.parse_assignment()
            names.append(name)
            if tname:
                simple = re.split(r"[.:]", tname.strip("*&"))[-1]
                if re.match(r"[A-Za-z_]\w*$", simple or ""):
                    ann[name] = _name(simple, self.t.line)
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
        kw = self.eat().val   # func / fun / function / fn / init
        receiver_cls = None
        is_init = kw in ("init", "deinit", "subscript")
        self.go_request_param = False
        if self.lang == "go" and self.at("("):           # func (r *T) name(...)
            self.eat("(")
            if self.t.kind == "id" and self.peek().kind == "id" or self.peek().val == "*":
                self.i += 1
            self.opt("*")
            receiver_cls = self.eat().val
            self.eat(")")
        name = f"_fn_{line}_{self.anon}"
        if is_init:
            name = "__init__" if kw == "init" else kw
            if self.at("?") or self.at("!"):
                self.i += 1
        elif self.t.kind == "id" and not self.at("("):
            name = self.eat().val
            while self.at(".") and self.lang in ("kotlin", "swift"):   # extension fun T.name
                self.i += 1
                name = self.eat().val
        if self.at("<"):
            self.skip_balanced("<", ">")
        prev_in, self.in_function = self.in_function, True
        params, prologue, ann = self.parse_params() if self.at("(") else ([], [], {})
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
        if self.lang == "rust":
            _tail_return(body)
        self.in_function = prev_in
        method = bool(self.cls_stack) or receiver_cls is not None
        decs = list(decs)
        if method and self.lang in ("rust", "swift") and "self" not in params and name != "__init__" and (self.lang == "rust" or self._swift_static):
            # Rust associated function / Swift static func: no receiver
            method = False
            decs.append(_name("staticmethod", line))
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
                while self.t.kind == "id" and self.t.val in ("public", "private", "protected", "virtual"):
                    self.i += 1
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
        if self.lang == "rust" and self.at_kw("where"):
            while not self.at("{") and not self.at(";") and self.t.kind != "eof":
                self.i += 1
        if (kind in ("enum",) or (self.lang == "rust" and kind in ("struct", "union"))) and self.at("{"):
            self.skip_balanced("{", "}")
            self.opt(";")
            return _mk(ast.ClassDef, line, name=name, bases=bases, keywords=[], body=[_mk(ast.Pass, line)], decorator_list=list(decs), type_params=[])
        if self.lang == "rust" and kind == "struct" and self.at("("):   # tuple struct
            self.skip_balanced("(", ")")
            self.opt(";")
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
        self.class_fields[name] = set(field_names)
        if field_names and self.lang in ("java", "kotlin", "csharp", "swift", "cpp"):
            for m in methods:
                _rewrite_implicit_this(m, field_names)
        ctor = next((m for m in methods if m.name == "__init__"), None)
        if (ctor_params or ctor_prologue or fields) and ctor is None:
            ctor = self.make_function("__init__", ctor_params, [], line, [], ctor_ann, method=True)
            methods.insert(0, ctor)
        if ctor is not None:
            ctor.body = fields + ctor_prologue + [s for s in ctor.body if not isinstance(s, ast.Pass)] or [_mk(ast.Pass, line)]
        others = [s for s in body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) and s not in fields]
        if self.lang == "cpp":
            self.opt(";")
        return _mk(ast.ClassDef, line, name=name, bases=bases, keywords=[], body=(methods + others) or [_mk(ast.Pass, line)],
                   decorator_list=list(decs), type_params=[])

    def parse_cond(self):
        if self.at("(") and self.lang not in ("swift", "rust", "go", "kotlin", "ruby"):
            self.eat("(")
            e = self.untuple(self.parse_expression())
            self.eat(")")
            return e
        self.no_brace_call += 1
        try:
            parts = []
            while True:
                if self.lang in ("swift", "rust") and self.t.kind == "id" and self.t.val in ("let", "var", "case"):
                    # `if let x = y` / `if case .some(let x) = y` / `while let Some(x) = it.next()`: bind the pattern names
                    self.i += 1
                    if self.lang == "rust" and self.at_kw("mut"):
                        self.i += 1
                    e = self.parse_assignment()
                    if isinstance(e, tuple) and e[0] == "assign":
                        _, target, op, value, aline = e
                        value = self.untuple(value)
                        names = [n for n in ast.walk(target) if isinstance(n, ast.Name) and n.id[:1].islower()] if not isinstance(target, ast.Name) else [target]
                        for n in names:
                            self.hoisted.extend(self.field_or_local(n.id, value, aline))
                        e = value
                    else:
                        e = self.untuple(e)
                else:
                    e = self.untuple(self.parse_expression())
                if isinstance(e, tuple):
                    e = self.untuple(e)
                parts.append(e)
                if self.lang == "swift" and self.opt(","):
                    continue
                break
            if self.opt(";"):   # Go `if x := f(); cond`
                parts = [self.untuple(self.parse_expression())]
            if self.lang == "ruby":
                self.opt("then")
            return parts[0] if len(parts) == 1 else _mk(ast.BoolOp, parts[0].lineno if hasattr(parts[0], "lineno") else self.t.line, op=ast.And(), values=parts)
        finally:
            self.no_brace_call -= 1

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
            # Java enhanced for / C# foreach / C++ range-for / Kotlin, Swift, Rust for (x in xs)
            if self.typed:
                if self.looks_like_type_then_name() or self.at_kw("var") or self.at_kw("final") or self.at_kw("const") or self.at_kw("auto"):
                    while self.at_kw("final") or self.at_kw("const"):
                        self.i += 1
                    if self.at_kw("var"):
                        self.i += 1
                    else:
                        self.skip_type()
            if self.lang == "rust" and self.at_kw("mut"):
                self.i += 1
            name = self.eat().val
            if self.at(":") or self.at_kw("in"):
                self.i += 1
                self.no_brace_call += 1
                try:
                    it = self.untuple(self.parse_expression())
                finally:
                    self.no_brace_call -= 1
                if paren:
                    self.eat(")")
                if self.lang == "swift" and self.at_kw("where"):
                    self.i += 1
                    self.no_brace_call += 1
                    try:
                        self.parse_expression()
                    finally:
                        self.no_brace_call -= 1
                body = self.body_or_stmt()
                return _mk(ast.For, line, target=_name(name, line, store=True), iter=it, body=body, orelse=[], type_comment=None)
            if self.lang in ("kotlin", "swift", "rust") and self.at(","):
                names = [name]
                while self.opt(","):
                    if self.lang == "rust" and self.at_kw("mut"):
                        self.i += 1
                    names.append(self.eat().val)
                if paren and self.at(")"):
                    self.eat(")")
                    paren = False
                self.eat("in")
                self.no_brace_call += 1
                try:
                    it = self.untuple(self.parse_expression())
                finally:
                    self.no_brace_call -= 1
                if paren:
                    self.eat(")")
                body = self.body_or_stmt()
                tmp = f"_m{line}"
                self.hoisted.append(_mk(ast.Assign, line, targets=[_name(tmp, line, store=True)], value=_name(names[-1], line)))
                tgt = _mk(ast.Tuple, line, elts=[_name(n, line, store=True) for n in names], ctx=ast.Store())
                return _mk(ast.For, line, target=tgt, iter=it, body=body, orelse=[], type_comment=None)
            self.i = save
        except ParseError:
            self.i = save
        # classic for(init; cond; post)
        if self.typed and self.looks_like_type_then_name():
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

    def parse_case_switch(self, subj, line):
        """C-family `switch (x) { case A: …; break; case B: case C: …; default: … }` as a match statement, one
        case per label group, with fall-through bodies copied in (Java/C/C#/PHP; Go and Swift do not fall
        through). Returns None (after rewinding) when the layout is not recognised, so the caller can fall back."""
        start = self.i
        groups = []                     # [labels (list of exprs, None = default), stmts, ends_with_break]
        try:
            while not self.at("}") and self.t.kind != "eof":
                if self.at_kw("case") or self.at_kw("default"):
                    is_default = self.at_kw("default")
                    self.i += 1
                    labels = None
                    self.in_case_label = True
                    try:
                        if not is_default:
                            labels = [self.untuple(self.parse_expression())]
                            while self.opt(","):
                                labels.append(self.untuple(self.parse_expression()))
                    finally:
                        self.in_case_label = False
                    arrow_arm = self.opt("->")
                    if not (arrow_arm or self.opt(":")):
                        raise ValueError("case without ':'")
                    if arrow_arm:
                        # Java 14+ `case X -> stmt;` / `case X -> { … }`: one arm, never falls through
                        braced = self.at("{")
                        arm = self.block() if braced else self.parse_statement()
                        if self.yield_targets and not braced and len(arm) == 1 and isinstance(arm[0], ast.Expr):
                            arm = [_mk(ast.Assign, arm[0].lineno, targets=[_name(self.yield_targets[-1], arm[0].lineno, store=True)],
                                       value=arm[0].value)]           # switch-expression arm: its value
                        groups.append([labels, arm, True])
                        continue
                    if groups and not groups[-1][1] and groups[-1][0] is not None and labels is not None:
                        groups[-1][0].extend(labels)         # `case A: case B:` share one body
                    else:
                        groups.append([labels, [], False])
                    continue
                if not groups:
                    raise ValueError("statement before first case")
                if self.at_kw("break"):
                    self.i += 1
                    self.opt(";")
                    groups[-1][2] = True
                    continue
                stmts = self.parse_statement()
                groups[-1][1].extend(stmts)
                if self.yield_targets and stmts and isinstance(stmts[-1], ast.Assign) and \
                        isinstance(stmts[-1].targets[0], ast.Name) and stmts[-1].targets[0].id == self.yield_targets[-1]:
                    groups[-1][2] = True        # `case A: yield x;` leaves the switch expression
            if not groups:
                raise ValueError("empty switch")
        except Exception:  # noqa: BLE001 - unusual layout: let the generic parser handle it
            self.i = start
            return None
        self.eat("}")
        falls = self.lang in ("java", "c", "cpp", "csharp", "php", "javascript")
        for g in groups:                      # a `break` of this switch anywhere in the case (in a block, an if …)
            if _strip_switch_breaks(g[1]):
                g[2] = True
        cases = []
        for gi, (labels, stmts, brk) in enumerate(groups):
            body = list(stmts)
            j = gi
            while falls and not groups[j][2] and j + 1 < len(groups) and not _ends(groups[j][1]):
                j += 1
                body.extend(groups[j][1])               # fall through into the next case
            if labels is None:
                pattern = ast.MatchAs(pattern=None, name=None)
            else:
                pats = [ast.MatchValue(value=lab) for lab in labels]
                pattern = pats[0] if len(pats) == 1 else ast.MatchOr(patterns=pats)
            cases.append(ast.match_case(pattern=pattern, guard=None, body=body or [_mk(ast.Pass, line)]))
        # Python requires the wildcard last; C-family allows `default` anywhere
        cases.sort(key=lambda c: isinstance(c.pattern, ast.MatchAs) and c.pattern.pattern is None)
        return _mk(ast.Match, line, subject=subj, cases=cases)

    def parse_switch(self):
        line = self.t.line
        self.i += 1
        subj = _const(True, line)
        self.no_brace_call += 1
        try:
            if self.at("(") and self.lang not in ("swift", "rust"):
                self.eat("(")
                subj = self.untuple(self.parse_expression())
                self.eat(")")
            elif not self.at("{"):
                subj = self.untuple(self.parse_expression())
        finally:
            self.no_brace_call -= 1
        self.eat("{")
        arrow = "=>" if self.lang == "rust" else "->"
        if self.lang not in ("kotlin", "rust"):
            m = self.parse_case_switch(subj, line)
            if m is not None:
                return m
        arms: list = [[]]               # one list of statements per arm; a new arm at each case / pattern
        depth = 0
        while not self.at("}") and self.t.kind != "eof":
            if self.at_kw("case") or self.at_kw("default"):
                self.i += 1
                label = []
                while not self.at(":") and not self.at("->") and not self.at("{") and self.t.kind != "eof":
                    label.append(self.t)
                    self.i += 1
                if self.at(":") or self.at("->"):
                    self.i += 1
                if arms[-1]:
                    arms.append([])
                # type pattern `case String s ->` / `case Foo f when …`: s is the subject
                core = [t for t in label]
                if "when" in [t.val for t in core]:
                    core = core[:[t.val for t in core].index("when")]
                if len(core) >= 2 and core[-1].kind == "id" and core[-2].kind in ("id",) or \
                        (len(core) >= 2 and core[-1].kind == "id" and core[-2].val in (">", "]")):
                    arms[-1].append(_mk(ast.Assign, line, targets=[_name(core[-1].val, line, store=True)], value=subj))
                continue
            if self.lang in ("kotlin", "rust") and (self.at(arrow) or self.at("else") or self.at(",")):
                self.i += 1
                continue
            if self.lang in ("kotlin", "rust") and not self.at("{"):
                # `pattern -> stmt` / `pattern => expr,` : skip the pattern (incl. guards), parse the arm body
                depth = 0
                while not (self.at(arrow) and depth == 0) and not (self.at("}") and depth == 0) and self.t.kind != "eof":
                    if self.at("(") or self.at("["):
                        depth += 1
                    elif self.at(")") or self.at("]"):
                        depth -= 1
                    if self.lang == "kotlin" and self.t.nl_before and depth == 0:
                        break
                    self.i += 1
                if self.opt(arrow):
                    if arms[-1]:
                        arms.append([])
                    if self.at("{"):
                        arms[-1].extend(self.block())
                    else:
                        e = self.parse_expression()
                        arms[-1].extend(self.expr_statement(e, self.t.line))
                    self.opt(",")
                    continue
            arms[-1].extend(self.parse_statement())
        self.eat("}")
        arms = [a for a in arms if a]
        for a in arms:
            _strip_switch_breaks(a)
        if not arms:
            return _mk(ast.Pass, line)
        # arms whose patterns were not understood: each one MAY run (never one after another, which would let a
        # later arm overwrite an earlier arm's value)
        unknown = ast.MatchValue(value=_mk(ast.Attribute, line, value=_name("__pattern__", line), attr="unknown", ctx=ast.Load()))
        return _mk(ast.Match, line, subject=subj,
                   cases=[ast.match_case(pattern=unknown, guard=None, body=a) for a in arms])

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
            self.ruby_locals.add(target.id)
            return self.field_or_local(target.id, value, line) if op == "=" else [_mk(ast.AugAssign, line, target=_name(target.id, line, store=True), op=_aug_op(op), value=value)]
        if isinstance(target, (ast.Attribute, ast.Subscript)):
            target.ctx = ast.Store()
            if op == "=":
                return [_mk(ast.Assign, line, targets=[target], value=value)]
            return [_mk(ast.AugAssign, line, target=target, op=_aug_op(op), value=value)]
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
        if self.lang in ("go", "ruby") and self.at(",") and isinstance(e, ast.Name):
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
        if t.kind == "punct" and t.val in ("=", ":=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", "??=", ".=", "||=", "&&=", "**="):
            self.i += 1
            right = self.parse_assignment()
            left = self.untuple(left)
            if isinstance(left, ast.Name) and left.id.startswith("$"):
                left = _name(left.id.lstrip("$"), left.lineno)
            return ("assign", left, "=" if t.val in ("=", ":=") else t.val, right, t.line)
        return left

    def is_lambda_start(self) -> bool:
        if getattr(self, "in_case_label", False):
            return False                  # `case 1 -> {…}`: the arrow ends the label, it is not a lambda
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
            node = _mk(ast.BoolOp, line, op=ast.Or(), values=[self.untuple(cond), b])
            node.nullish = self.lang in ("kotlin", "swift", "csharp")    # Kotlin elvis: null only; PHP ?: is truthiness
            return node
        return cond

    BIN_PREC = {"??": 1, "||": 1, "or": 1, "&&": 2, "and": 2, "|": 3, "^": 4, "&": 5, "==": 6, "!=": 6, "===": 6, "!==": 6,
                "=~": 6, "!~": 6, "<=>": 6, "<": 7, ">": 7, "<=": 7, ">=": 7, "instanceof": 7, "is": 7, "as": 7, "in": 7, "<<": 8, ">>": 8,
                "+": 9, "-": 9, ".": 9, "*": 10, "/": 10, "%": 10, "..": 9, "...": 9, "**": 11}

    def parse_binary(self, min_prec):
        left = self.parse_unary()
        while True:
            t = self.t
            op = t.val if (t.kind == "punct" or (t.kind == "id" and t.val in _WORD_OPS.get(self.lang, ()))) else None
            if op == "." and self.lang != "php":
                break
            if op == "..." and self.lang != "ruby":
                break
            if op == "as" and self.lang == "php":
                break                                   # foreach ($rows as $r): not a cast
            extra = 0
            if op in ("<", ">") and self.peek().kind == "punct" and self.peek().val == op:
                # the lexer splits << and >> (generics: List<List<X>>); two in a row in an expression are a shift
                extra = 1
                if op == ">" and self.i + 2 < len(self.toks) and self.toks[self.i + 2].val == ">":
                    extra = 2
                op = op * 2
            if op not in self.BIN_PREC or self.BIN_PREC[op] < min_prec:
                break
            if self.lang == "ruby" and op == "<<" and not self.t.nl_before:
                # `arr << x` appends: lower to arr.append(x) so the container model sees the flow
                self.i += 1
                right = self.untuple(self.parse_binary(self.BIN_PREC[op] + 1))
                left = _mk(ast.Call, t.line, func=_mk(ast.Attribute, t.line, value=self.untuple(left), attr="append", ctx=ast.Load()), args=[right], keywords=[])
                continue
            if op == "<" and self.looks_like_generic():
                break
            prec = self.BIN_PREC[op]
            self.i += 1 + extra
            if op in ("is", "as", "instanceof"):
                self.skip_type()
                # C# `o is string s` / Java 16 `o instanceof String s`: a pattern variable bound to the operand
                if op in ("is", "instanceof") and self.t.kind == "id" and self.t.val not in _WORD_OPS.get(self.lang, ()) \
                        and self.t.val not in ("and", "or", "not") and not self.t.nl_before:
                    var = self.eat()
                    self.hoisted.append(_mk(ast.Assign, var.line, targets=[_name(var.val, var.line, store=True)],
                                            value=self.untuple(left)))
                continue
            right = self.parse_binary(prec + 1)
            left, right = self.untuple(left), self.untuple(right)
            line = t.line
            if op in ("&&", "||", "??", "and", "or"):
                left = _mk(ast.BoolOp, line, op=ast.And() if op in ("&&", "and") else ast.Or(), values=[left, right])
                left.nullish = op == "??"
            elif op in ("==", "!=", "===", "!==", "<", ">", "<=", ">=", "in"):
                pyop = {"==": ast.Eq(), "===": ast.Eq(), "!=": ast.NotEq(), "!==": ast.NotEq(), "<": ast.Lt(), ">": ast.Gt(),
                        "<=": ast.LtE(), ">=": ast.GtE(), "in": ast.In()}[op]
                left = _mk(ast.Compare, line, left=left, ops=[pyop], comparators=[right])
                if self.lang == "php":
                    left.eq_mode = "strict" if op in ("===", "!==") else "loose"
                elif self.lang == "java" or (self.lang == "kotlin" and op in ("===", "!==")):
                    left.eq_mode = "ref"           # Java `==` compares string identity, not contents
            else:
                left = _mk(ast.BinOp, line, left=left, op=_BINOP.get(op, ast.BitOr)(), right=right)
                if op in ("/", "%") and not (self.lang == "php" and op == "/"):
                    # integer / and % truncate toward zero in C-family languages (PHP %), floor in Ruby
                    left.int_div = "floor" if self.lang == "ruby" else "trunc"
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
            if t.val in ("++", "--") and isinstance(operand, (ast.Name, ast.Attribute, ast.Subscript)):
                return ("assign", operand, "+=" if t.val == "++" else "-=", _const(1, line), line)
            if t.val == "-":
                return _mk(ast.UnaryOp, line, op=ast.USub(), operand=operand)
            return operand
        if self.lang == "rust" and (self.at("|") or self.at("||") or (t.kind == "id" and t.val in ("move", "async") and self.peek().val in ("|", "||"))):
            return self.parse_rust_closure()
        if self.lang == "swift" and t.kind == "id" and t.val == "try":
            self.i += 1
            if self.at("?") or self.at("!"):
                self.i += 1
            return self.untuple(self.parse_unary())
        if t.kind == "id" and (t.val in ("typeof", "sizeof", "await", "new", "clone", "not", "yield", "throw", "delete", "mut", "box", "co_await")
                               or (t.val == "print" and self.lang == "php")):
            if t.val == "new":
                # `new Test().doSomething(x)` / `new StringBuilder().append(a).toString()`: keep the postfix chain
                return self.parse_postfix(base=self.parse_new())
            if t.val == "yield" and self.lang == "ruby":
                self.i += 1
                args, kws = self.parse_ruby_command_args() if self.ruby_arg_start() else ([], [])
                return _mk(ast.Call, line, func=_name("yield", line), args=args, keywords=kws)
            self.i += 1
            if t.val == "await":
                return _mk(ast.Await, line, value=self.untuple(self.parse_unary()))
            if t.val == "print" and self.lang == "php":
                e = self.untuple(self.parse_unary())
                return _mk(ast.Call, line, func=_name("print", line), args=[e], keywords=[])
            if t.val == "not":
                return _mk(ast.UnaryOp, line, op=ast.Not(), operand=self.untuple(self.parse_unary()))
            return self.untuple(self.parse_unary())
        # C-style cast: (Type) expr
        if self.at("(") and self.lang in ("java", "csharp", "php", "cpp"):
            save = self.i
            self.i += 1
            if self.t.kind == "id":
                try:
                    self.skip_type()
                    if self.at(")") and (self.peek().kind in ("id", "str", "num", "istr") or self.peek().val in ("(", "$", "!", "-")) and not (self.peek().kind == "id" and self.peek().val in ("instanceof",) + _WORD_OPS.get(self.lang, ("is", "as", "and", "or", "in"))):
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
        if isinstance(target, ast.Subscript):     # `new T[]{a, b}` / `new T[n]`: the brackets are the array type
            if self.at("{"):
                return self.parse_array_literal()
            return _mk(ast.List, line, elts=[], ctx=ast.Load())
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

    def parse_postfix(self, no_call=False, base=None):
        e = self.parse_primary() if base is None else base
        while True:
            t = self.t
            if t.kind == "punct" and t.val in (".", "->", "::", "?.", "?->", "&.") and not (t.val == "." and self.lang == "php") \
                    and not (t.val == "->" and self.lang in ("ruby", "rust", "swift", "java", "kotlin")):
                if t.val == "::" and self.lang == "ruby" and self.peek().val == "<":
                    break
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
                if self.lang == "ruby" and attr != "new" and t.val != "::" and not (isinstance(e.value, ast.Name) and e.value.id == "self") \
                        and not self.at("(") and not (self.t.kind == "punct" and self.t.val in ("=", "+=", "-=", "||=", "&&=", "*=", "/=", "<<=")) \
                        and not self.ruby_arg_start() and not attr[:1].isupper():
                    # Ruby has no public fields: `x.y` is the zero-argument call y()
                    e = _mk(ast.Call, nm.line, func=e, args=[], keywords=[])
                if self.lang == "ruby" and attr == "new":
                    # Foo.new(args) -> Foo(args): the engine's constructor model
                    e = e.value
                    if not self.at("("):
                        if self.ruby_arg_start():
                            args, kws = self.parse_ruby_command_args()
                            e = _mk(ast.Call, nm.line, func=e, args=args, keywords=kws)
                        else:
                            e = _mk(ast.Call, nm.line, func=e, args=[], keywords=[])
            elif t.nl_before and t.kind == "punct" and t.val in ("(", "[", "{") and self.lang in ("ruby", "swift", "kotlin", "go", "rust"):
                break   # a new statement starts here (no semicolons in these languages)
            elif self.lang == "ruby" and not no_call and isinstance(e, (ast.Name, ast.Attribute, ast.Call)) \
                    and ((t.kind == "id" and t.val == "do" and self.in_command_args == 0) or (t.kind == "punct" and t.val == "{" and (self.peek().val == "|" or isinstance(e, ast.Call)))) \
                    and self.no_brace_call == 0:
                blk = self.parse_ruby_block_fn(t.line, t.val == "{")
                if not isinstance(e, ast.Call):
                    e = _mk(ast.Call, t.line, func=self.untuple(e), args=[], keywords=[])
                e.args.append(blk)
                fname = e.func.id if isinstance(e.func, ast.Name) else (e.func.attr if isinstance(e.func, ast.Attribute) else "")
                if fname in RUBY_ROUTES:
                    fn = next((h for h in self.hoisted if isinstance(h, ast.FunctionDef) and h.name == blk.id), None)
                    if fn is not None:
                        fn.decorator_list.append(_name("route", t.line))
            elif self.lang == "ruby" and not no_call and isinstance(e, (ast.Name, ast.Attribute)) and not t.nl_before and self.ruby_arg_start() \
                    and not (isinstance(e, ast.Name) and (e.id in self.ruby_locals or e.id[:1].isupper() or e.id in RUBY_KW or e.id in ("self", "super"))):
                args, kws = self.parse_ruby_command_args()
                e = _mk(ast.Call, t.line, func=self.untuple(e), args=args, keywords=kws)
            elif self.lang == "rust" and t.kind == "punct" and t.val == "?":
                self.i += 1
            elif self.lang == "rust" and t.kind == "punct" and t.val == "{" and isinstance(e, ast.Name) and e.id[:1].isupper() and self.no_brace_call == 0 and not no_call:
                # struct literal Point { x: 1, y: f() } -> Point(x=1, y=f())
                self.i += 1
                kws = []
                while not self.at("}") and self.t.kind != "eof":
                    if self.opt(".."):
                        self.parse_assignment()
                    elif self.t.kind == "id" and self.peek().val == ":":
                        k = self.eat().val
                        self.i += 1
                        kws.append(ast.keyword(arg=k, value=self.untuple(self.parse_assignment())))
                    elif self.t.kind == "id":
                        k = self.eat().val
                        kws.append(ast.keyword(arg=k, value=_name(k, t.line)))
                    else:
                        raise ParseError(f"bad struct literal at line {t.line}")
                    if not self.opt(","):
                        break
                self.eat("}")
                e = _mk(ast.Call, t.line, func=e, args=[], keywords=kws)
            elif self.lang == "rust" and t.kind == "punct" and t.val == "!" and self.peek().val in ("(", "[", "{") and isinstance(e, (ast.Name, ast.Attribute)):
                # macro invocation: name!(..) / vec![..] / name!{..}
                self.i += 1
                if self.at("("):
                    e = self.parse_call(self.untuple(e), t.line)
                    mname = e.func.id if isinstance(e.func, ast.Name) else getattr(e.func, "attr", "")
                    if mname in ("format", "format_args") and e.args:
                        # format!("{} {}", a, b) -> f-string so the engine sees the concatenation
                        vals = []
                        for a in e.args:
                            vals.append(a if isinstance(a, (ast.Constant, ast.JoinedStr)) and isinstance(getattr(a, "value", ""), str) or isinstance(a, ast.JoinedStr)
                                        else _mk(ast.FormattedValue, t.line, value=a, conversion=-1, format_spec=None))
                        flat = []
                        for v in vals:
                            flat.extend(v.values if isinstance(v, ast.JoinedStr) else [v])
                        e = _mk(ast.JoinedStr, t.line, values=flat)
                elif self.at("["):
                    self.i += 1
                    elts = []
                    while not self.at("]") and self.t.kind != "eof":
                        elts.append(self.untuple(self.parse_assignment()))
                        if self.at(";"):
                            self.i += 1
                            self.parse_assignment()
                        if not self.opt(","):
                            break
                    self.eat("]")
                    e = _mk(ast.List, t.line, elts=elts, ctx=ast.Load())
                else:
                    self.skip_balanced("{", "}")
                    e = _mk(ast.Call, t.line, func=self.untuple(e), args=[], keywords=[])
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
            elif t.kind == "punct" and t.val == "{" and self.lang in BRACE_LAMBDA_LANGS and isinstance(e, (ast.Name, ast.Attribute, ast.Call)) and not no_call \
                    and self.no_brace_call == 0:
                # trailing lambda: list.forEach { x -> ... } / xs.map { $0 } / run { x in ... }
                lam = self.parse_kotlin_lambda()
                if isinstance(e, ast.Call):
                    e.args.append(lam)
                else:
                    e = _mk(ast.Call, t.line, func=e, args=[lam], keywords=[])
                self._mark_route(e, lam, t.line)
            elif t.kind == "punct" and t.val == "<" and self.looks_like_generic() and not no_call:
                self.skip_balanced("<", ">")
            elif t.kind == "punct" and t.val in ("++", "--") and isinstance(e, (ast.Name, ast.Attribute, ast.Subscript)):
                self.i += 1
                return ("assign", e, "+=" if t.val == "++" else "-=", _const(1, t.line), t.line)
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
        if self.lang == "swift":
            return self.parse_swift_closure_body(line)
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

    def parse_swift_closure_body(self, line):
        """After `{`: [capture list] (a, b) [-> T] in … / a, b in … / … ($0)."""
        if self.at("["):
            self.skip_balanced("[", "]")
        params = []
        j = self.i
        names = []
        if self.toks[j].val == "(":
            k = j + 1
            while k < len(self.toks) and self.toks[k].val != ")" and self.toks[k].kind != "eof":
                if self.toks[k].kind == "id" and self.toks[k + 1].val in (",", ")", ":"):
                    names.append(self.toks[k].val)
                k += 1
            k += 1
            while k < len(self.toks) and self.toks[k].val not in ("in", "{", "}") and self.toks[k].kind != "eof":
                k += 1
            if self.toks[k].val == "in":
                self.i = k + 1
                params = names
        else:
            while self.toks[j].kind == "id" and self.toks[j + 1].val in (",", "in", "->"):
                names.append(self.toks[j].val)
                if self.toks[j + 1].val == ",":
                    j += 2
                    continue
                k = j + 1
                if self.toks[k].val == "->":
                    while k < len(self.toks) and self.toks[k].val not in ("in", "{", "}") and self.toks[k].kind != "eof":
                        k += 1
                if self.toks[k].val == "in":
                    self.i = k + 1
                    params = names
                break
        if not params:
            params = ["$0"]
        body = self.parse_statements()
        self.eat("}")
        if len(body) == 1:
            _tail_return(body)
        name = f"_fn_{line}_{self.anon}"
        self.anon += 1
        fn = self.make_function(name, params, body or [_mk(ast.Pass, line)], line, [])
        self.hoisted.append(fn)
        return _name(name, line)

    def parse_rust_closure(self):
        """|a, b| expr  /  |a| { … }  /  move || …"""
        line = self.t.line
        if self.t.kind == "id":
            self.i += 1
        params = []
        if self.opt("||"):
            pass
        else:
            self.eat("|")
            while not self.at("|") and self.t.kind != "eof":
                if self.at("&") or self.at_kw("mut"):
                    self.i += 1
                    continue
                if self.at("("):
                    self.eat("(")
                    while not self.at(")") and self.t.kind != "eof":
                        if self.t.kind == "id":
                            params.append(self.eat().val)
                        else:
                            self.i += 1
                    self.eat(")")
                elif self.t.kind == "id":
                    params.append(self.eat().val)
                else:
                    self.i += 1
                if self.at(":"):
                    self.i += 1
                    self.skip_type()
                self.opt(",")
            self.eat("|")
        if self.at("->"):
            self.i += 1
            self.skip_type()
        if self.at("{"):
            body = self.block()
            _tail_return(body)
        else:
            e = self.untuple(self.parse_assignment())
            body = [_mk(ast.Return, line, value=e)]
        name = f"_fn_{line}_{self.anon}"
        self.anon += 1
        fn = self.make_function(name, params, body, line, [])
        self.hoisted.append(fn)
        return _name(name, line)

    def parse_call(self, func, line):
        self.eat("(")
        args, kws = [], []
        while not self.at(")") and self.t.kind != "eof":
            if self.lang == "swift" and self.t.kind == "id" and self.peek().val == ":" and self.peek(2).val != ":":
                self.i += 2      # argument label: positional for the models (`arguments:`, `atPath:` …)
                args.append(self.untuple(self.parse_assignment()))
            elif self.lang == "ruby" and self.t.kind == "sym" and self.peek().val == "=>":
                kname = self.eat().val[1:]
                self.i += 1
                kws.append(ast.keyword(arg=kname, value=self.untuple(self.parse_assignment())))
            elif self.t.kind == "id" and self.peek().val in ("=", ":") and self.lang in ("kotlin", "csharp", "php", "ruby") and self.peek(2).val not in ("=", ":"):
                # named argument name = expr / name: expr
                kname = self.eat().val
                self.i += 1
                kws.append(ast.keyword(arg=kname, value=self.untuple(self.parse_assignment())))
            else:
                if self.lang == "ruby" and (self.at("*") or self.at("**") or self.at("&")):
                    self.i += 1
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
        call = _mk(ast.Call, line, func=func, args=args, keywords=kws)
        if self.lang in BRACE_LAMBDA_LANGS and self.at("{") and not self.t.nl_before and self.no_brace_call == 0:
            lam = self.parse_kotlin_lambda()
            args.append(lam)
            self._mark_route(call, lam, line)
        return call

    def _mark_route(self, call, lam, line):
        """A closure handed to app.get/post/… (Vapor, Sinatra, Ktor) is a request handler: mark it as an entry point."""
        fname = call.func.id if isinstance(call.func, ast.Name) else (call.func.attr if isinstance(call.func, ast.Attribute) else "")
        if fname in RUBY_ROUTES and isinstance(lam, ast.Name):
            fn = next((h for h in self.hoisted if isinstance(h, ast.FunctionDef) and h.name == lam.id), None)
            if fn is not None and not any(isinstance(d, ast.Name) and d.id == "route" for d in fn.decorator_list):
                fn.decorator_list.append(_name("route", line))

    def parse_interpolated(self, tok) -> ast.AST:
        """Kotlin/PHP "$x ${expr}", C# $"{expr}", Ruby "#{expr}", Swift "\\(expr)", Rust "{name}" -> JoinedStr."""
        raw = tok.val
        if raw.startswith("$"):
            raw = raw[1:]
        raw = raw.lstrip("@")
        inner = raw[1:-1]
        values = []
        buf = ""
        i = 0
        lang = self.lang

        def balanced(start, open_, close):
            depth, k = 1, start
            while k < len(inner) and depth:
                if inner[k] == open_:
                    depth += 1
                elif inner[k] == close:
                    depth -= 1
                k += 1
            return inner[start:k - 1], k

        while i < len(inner):
            c = inner[i]
            nxt = inner[i + 1] if i + 1 < len(inner) else ""
            expr_src = None
            if c == "\\" and nxt:
                if lang == "swift" and nxt == "(":
                    expr_src, i = balanced(i + 2, "(", ")")
                else:
                    buf += inner[i:i + 2]
                    i += 2
                    continue
            elif lang in ("kotlin", "php") and c == "$":
                if nxt == "{":
                    expr_src, i = balanced(i + 2, "{", "}")
                else:
                    m = re.match(r"\$([A-Za-z_][\w]*(?:(?:->|\.)[A-Za-z_]\w*|\[[^\]]*\])*)", inner[i:])
                    if not m:
                        buf += c
                        i += 1
                        continue
                    expr_src = ("$" if lang == "php" else "") + m.group(1)
                    i += m.end()
            elif lang == "php" and c == "{" and nxt == "$":
                expr_src, i = balanced(i + 1, "{", "}")
            elif lang == "csharp" and c == "{":
                if nxt == "{":
                    buf += "{"
                    i += 2
                    continue
                expr_src, i = balanced(i + 1, "{", "}")
                expr_src = expr_src.split(":")[0]
            elif lang == "ruby" and c == "#" and nxt == "{":
                expr_src, i = balanced(i + 2, "{", "}")
            elif lang == "rust" and c == "{":
                if nxt == "{":
                    buf += "{"
                    i += 2
                    continue
                body, i = balanced(i + 1, "{", "}")
                name = body.split(":")[0].strip()
                if re.match(r"[A-Za-z_]\w*(\.[A-Za-z_]\w*)*$", name):
                    expr_src = name
                else:
                    buf += "{" + body + "}"
                    continue
            else:
                buf += c
                i += 1
                continue
            if buf:
                values.append(_const(buf, tok.line))
                buf = ""
            sub = Parser(("<?php " + expr_src) if lang == "php" else expr_src, "inline", lang)   # PHP code starts at <?php
            sub.mod = self.mod
            sub.ruby_locals = self.ruby_locals
            try:
                e = sub.untuple(sub.parse_expression())
            except ParseError:
                e = _const("", tok.line)
            self.hoisted.extend(sub.hoisted)
            values.append(_mk(ast.FormattedValue, tok.line, value=e, conversion=-1, format_spec=None))
        if buf:
            values.append(_const(buf, tok.line))
        return _mk(ast.JoinedStr, tok.line, values=values)

    # ----------------------------------------------------------------- Ruby
    def ruby_arg_start(self) -> bool:
        """Does the current token start an argument of a parenthesis-less command call (`puts x`, `system cmd`)?"""
        t = self.t
        if t.nl_before:
            return False
        if t.kind in ("str", "istr", "num", "sym", "ivar"):
            return True
        if t.kind == "id":
            if t.val in RUBY_KW and t.val not in ("nil", "true", "false", "self", "lambda", "proc", "defined?"):
                return False
            nxt = self.peek().val
            return not (nxt in ("=", "+=", "-=", "||=", "&&=") and not self.peek().nl_before)
        if t.kind == "punct" and t.val in ("->", "::"):
            return True
        if t.kind == "punct" and t.val == "[" and self.toks[self.i - 1].kind == "id":
            # `puts [1, 2]` vs `x [0]`: an index never follows a space-separated identifier in idiomatic Ruby,
            # but we cannot see spaces; treat as index (safer for taint).
            return False
        return False

    def parse_ruby_command_args(self):
        args, kws = [], []
        self.in_command_args += 1
        try:
            return self._ruby_command_args(args, kws)
        finally:
            self.in_command_args -= 1

    def _ruby_command_args(self, args, kws):
        while True:
            if self.t.kind == "id" and self.peek().kind == "punct" and self.peek().val == ":" and self.peek(2).val != ":":
                k = self.eat().val
                self.i += 1
                kws.append(ast.keyword(arg=k, value=self.untuple(self.parse_assignment())))
            elif self.t.kind == "sym" and self.peek().val == "=>":
                k = self.eat().val[1:]
                self.i += 1
                kws.append(ast.keyword(arg=k, value=self.untuple(self.parse_assignment())))
            else:
                if self.at("*") or self.at("**") or self.at("&"):
                    self.i += 1
                a = self.untuple(self.parse_assignment())
                if self.opt("=>"):
                    v = self.untuple(self.parse_assignment())
                    kws.append(ast.keyword(arg=str(getattr(a, "value", "k")), value=v))
                else:
                    args.append(a)
            if not self.opt(","):
                break
        return args, kws

    def parse_ruby_block_fn(self, line, brace):
        """`do |a, b| … end` or `{ |a| … }` -> hoisted function, returned as a Name (callback argument)."""
        self.i += 1
        params = []
        if self.at("|"):
            self.i += 1
            while not self.at("|") and self.t.kind != "eof":
                if self.at("*") or self.at("**") or self.at("&"):
                    self.i += 1
                    continue
                if self.at("("):
                    self.eat("(")
                    while not self.at(")") and self.t.kind != "eof":
                        if self.t.kind == "id":
                            params.append(self.eat().val)
                        else:
                            self.i += 1
                    self.eat(")")
                elif self.t.kind == "id":
                    params.append(self.eat().val)
                    if self.at(":"):
                        self.i += 1
                    if self.opt("="):
                        self.parse_assignment()
                else:
                    self.i += 1
                self.opt(",")
            self.eat("|")
        prev_locals = set(self.ruby_locals)
        self.ruby_locals |= set(params)
        prev_in, self.in_function = self.in_function, True
        if brace:
            body = self.parse_statements()
            self.eat("}")
        else:
            body = self.parse_ruby_body(line)
        self.in_function = prev_in
        self.ruby_locals = prev_locals
        name = f"_fn_{line}_{self.anon}"
        self.anon += 1
        fn = self.make_function(name, params, body or [_mk(ast.Pass, line)], line, [])
        self.hoisted.append(fn)
        return _name(name, line)

    def parse_ruby_lambda(self):
        line = self.t.line
        self.eat("->")
        params = []
        if self.at("("):
            self.eat("(")
            while not self.at(")") and self.t.kind != "eof":
                if self.t.kind == "id":
                    params.append(self.eat().val)
                else:
                    self.i += 1
            self.eat(")")
        elif self.t.kind == "id":
            while self.t.kind == "id":
                params.append(self.eat().val)
                if not self.opt(","):
                    break
        if not (self.at("{") or self.at_kw("do")):
            raise ParseError(f"lambda body expected at line {line}")
        brace = self.at("{")
        # reuse the block parser: it expects to consume `{`/`do` and optional |params|
        save_params = params
        blk = self.parse_ruby_block_fn(line, brace)
        fn = next((h for h in self.hoisted if isinstance(h, ast.FunctionDef) and h.name == blk.id), None)
        if fn is not None and save_params:
            fn.args = _args(save_params, line)
        return blk

    def parse_ruby_hash(self):
        line = self.t.line
        self.eat("{")
        keys, values = [], []
        while not self.at("}") and self.t.kind != "eof":
            if self.at("**"):
                self.i += 1
                values.append(self.untuple(self.parse_assignment()))
                keys.append(None)
            elif self.t.kind == "id" and self.peek().val == ":":
                keys.append(_const(self.eat().val, line))
                self.i += 1
                values.append(self.untuple(self.parse_assignment()))
            elif self.t.kind == "str" and self.peek().val == ":":
                keys.append(_const(self.eat().val[1:-1], line))
                self.i += 1
                values.append(self.untuple(self.parse_assignment()))
            else:
                k = self.untuple(self.parse_assignment())
                if self.opt("=>"):
                    keys.append(k)
                    values.append(self.untuple(self.parse_assignment()))
                else:
                    keys.append(None)
                    values.append(k)
            if not self.opt(","):
                break
        self.eat("}")
        return _mk(ast.Dict, line, keys=keys, values=values)

    def parse_ruby_params(self, close):
        names = []
        while self.t.kind != "eof":
            if close and self.at(close):
                break
            if close is None and (self.t.nl_before or self.at(";") or self.at("=")):
                break
            if self.at("*") or self.at("**") or self.at("&"):
                self.i += 1
            if self.at("("):      # destructuring (a, b)
                self.eat("(")
                while not self.at(")") and self.t.kind != "eof":
                    if self.t.kind == "id":
                        names.append(self.eat().val)
                    else:
                        self.i += 1
                self.eat(")")
            elif self.t.kind == "id":
                names.append(self.eat().val)
                if self.at(":"):          # keyword parameter, maybe with a default
                    self.i += 1
                    if not self.at(",") and not (close and self.at(close)) and not self.t.nl_before:
                        self.parse_assignment()
                elif self.opt("="):
                    self.parse_assignment()
            else:
                raise ParseError(f"bad parameter {self.t.val!r} at line {self.t.line}")
            if not self.opt(","):
                break
        if close:
            self.eat(close)
        return names

    def parse_ruby_body(self, line) -> list:
        """Statements up to `end`, with optional rescue/else/ensure clauses (def, do-block, begin)."""
        body = self.parse_statements(stop=("end", "rescue", "ensure", "else"))
        handlers, orelse, final = [], [], []
        while self.at_kw("rescue"):
            self.i += 1
            nm = None
            while not self.t.nl_before and self.t.kind != "eof" and not self.at_kw("then"):
                if self.at("=>"):
                    self.i += 1
                    nm = self.eat().val
                else:
                    self.i += 1
            self.opt("then")
            hb = self.parse_statements(stop=("end", "rescue", "ensure", "else"))
            handlers.append(_mk(ast.ExceptHandler, line, type=None, name=nm, body=hb or [_mk(ast.Pass, line)]))
        if self.at_kw("else"):
            self.i += 1
            orelse = self.parse_statements(stop=("end", "ensure"))
        if self.at_kw("ensure"):
            self.i += 1
            final = self.parse_statements(stop=("end",))
        if self.at_kw("end"):
            self.i += 1
        else:
            raise ParseError(f"missing 'end' for block opened at line {line}")
        if handlers or final or orelse:
            if not handlers:
                handlers.append(_mk(ast.ExceptHandler, line, type=None, name=None, body=[_mk(ast.Pass, line)]))
            return [_mk(ast.Try, line, body=body or [_mk(ast.Pass, line)], handlers=handlers, orelse=orelse, finalbody=final)]
        return body or [_mk(ast.Pass, line)]

    def parse_ruby_def(self, decs):
        line = self.t.line
        self.eat("def")
        name = self.eat().val
        if name == "self" and self.at("."):
            self.i += 1
            name = self.eat().val
        while self.at(".") and self.t.kind == "punct":
            self.i += 1
            name = self.eat().val
        if self.at("=") and self.peek().val == "(" and not self.peek().nl_before:
            self.i += 1
            name += "="
        params = []
        if self.at("("):
            self.i += 1
            params = self.parse_ruby_params(")")
        elif not self.t.nl_before and self.t.kind == "id" and not self.at("="):
            params = self.parse_ruby_params(None)
        prev_locals, self.ruby_locals = self.ruby_locals, set(params)
        prev_in, self.in_function = self.in_function, True
        if self.opt("="):     # endless method
            e = self.untuple(self.parse_expression())
            body = [_mk(ast.Return, line, value=e)]
        else:
            body = self.parse_ruby_body(line)
        self.in_function = prev_in
        self.ruby_locals = prev_locals
        return self.make_function("__init__" if name == "initialize" else name, params, body, line, decs, method=bool(self.cls_stack))

    def parse_ruby_class(self, decs) -> list:
        line = self.t.line
        self.eat().val
        if self.at("<<"):     # class << self … end : singleton methods, keep as plain statements
            self.i += 1
            self.parse_expression()
            return self.ruby_block()
        name = self.parse_dotted_name().split(".")[-1]
        bases = []
        if self.at("<"):
            self.i += 1
            bases.append(self.untuple(self.parse_expression()))
        self.cls_stack.append(name)
        self.field_names_stack.append(set())
        prev_in, self.in_function = self.in_function, False
        body = self.parse_ruby_body(line)
        self.in_function = prev_in
        self.cls_stack.pop()
        self.field_names_stack.pop()
        if len(body) == 1 and isinstance(body[0], ast.Try):
            body = body[0].body + [h for hb in body[0].handlers for h in hb.body]
        return [_mk(ast.ClassDef, line, name=name, bases=bases, keywords=[], body=body or [_mk(ast.Pass, line)],
                    decorator_list=list(decs), type_params=[])]

    def parse_ruby_if(self):
        line = self.t.line
        kw = self.eat().val
        test = self.parse_cond()
        if kw == "unless":
            test = _mk(ast.UnaryOp, line, op=ast.Not(), operand=test)
        body = self.parse_statements(stop=("elsif", "else", "end"))
        orelse = []
        if self.at_kw("elsif"):
            self.toks[self.i].val = "if"
            orelse = [self.parse_ruby_if()]
        elif self.at_kw("else"):
            self.i += 1
            orelse = self.parse_statements(stop=("end",))
            if not self.opt("end"):
                raise ParseError(f"missing 'end' for if at line {line}")
        elif not self.opt("end"):
            raise ParseError(f"missing 'end' for if at line {line}")
        return _mk(ast.If, line, test=test, body=body or [_mk(ast.Pass, line)], orelse=orelse)

    def parse_ruby_case(self):
        line = self.t.line
        self.eat("case")
        subj = _const(True, line)
        if not self.t.nl_before:
            subj = self.untuple(self.parse_expression())
        body = []
        while self.at_kw("when") or self.at_kw("in"):
            self.i += 1
            try:
                self.no_brace_call += 1
                while not self.t.nl_before and not self.at_kw("then") and self.t.kind != "eof":
                    self.parse_assignment()
                    if not self.opt(","):
                        break
            except ParseError:
                while not self.t.nl_before and not self.at_kw("then") and self.t.kind != "eof":
                    self.i += 1
            finally:
                self.no_brace_call -= 1
            self.opt("then")
            body.extend(self.parse_statements(stop=("when", "in", "else", "end")))
        if self.at_kw("else"):
            self.i += 1
            body.extend(self.parse_statements(stop=("end",)))
        if not self.opt("end"):
            raise ParseError(f"missing 'end' for case at line {line}")
        return _mk(ast.If, line, test=subj, body=body or [_mk(ast.Pass, line)], orelse=[])

    def ruby_modifiers(self, stmts, line) -> list:
        """Statement modifiers: `stmt if cond` / `stmt unless cond` / `stmt while cond` / `stmt rescue x`."""
        while self.t.kind == "id" and self.t.val in ("if", "unless", "while", "until", "rescue") and not self.t.nl_before:
            kw = self.eat().val
            if kw == "rescue":
                self.parse_expression()
                continue
            test = self.untuple(self.parse_expression())
            if kw in ("unless", "until"):
                test = _mk(ast.UnaryOp, line, op=ast.Not(), operand=test)
            if kw in ("if", "unless"):
                stmts = [_mk(ast.If, line, test=test, body=stmts or [_mk(ast.Pass, line)], orelse=[])]
            else:
                stmts = [_mk(ast.While, line, test=test, body=stmts or [_mk(ast.Pass, line)], orelse=[])]
        self.end_stmt()
        return stmts

    def parse_ruby_statement(self, decs, line):
        v = self.t.val
        if v == "def":
            return [self.parse_ruby_def(decs)]
        if v in ("class", "module") and (self.peek().kind == "id" or self.peek().val in ("<<", "::")):
            return self.parse_ruby_class(decs)
        if v in ("if", "unless"):
            return [self.parse_ruby_if()]
        if v in ("while", "until"):
            self.i += 1
            test = self.parse_cond()
            if v == "until":
                test = _mk(ast.UnaryOp, line, op=ast.Not(), operand=test)
            self.opt("do")
            body = self.parse_statements(stop=("end",))
            if not self.opt("end"):
                raise ParseError(f"missing 'end' for while at line {line}")
            return [_mk(ast.While, line, test=test, body=body or [_mk(ast.Pass, line)], orelse=[])]
        if v == "for":
            self.i += 1
            names = [self.eat().val]
            while self.opt(","):
                names.append(self.eat().val)
            self.eat("in")
            it = self.parse_cond()
            self.opt("do")
            self.ruby_locals |= set(names)
            body = self.parse_statements(stop=("end",))
            if not self.opt("end"):
                raise ParseError(f"missing 'end' for for at line {line}")
            return [_mk(ast.For, line, target=_name(names[-1], line, store=True), iter=it, body=body or [_mk(ast.Pass, line)], orelse=[], type_comment=None)]
        if v == "case":
            return [self.parse_ruby_case()]
        if v == "begin":
            self.i += 1
            return self.parse_ruby_body(line)
        if v in ("return", "next", "break", "redo", "retry"):
            self.i += 1
            val = None
            if v == "return" and not self.t.nl_before and self.t.kind != "eof" and not self.at(";") and not (self.t.kind == "id" and self.t.val in ("if", "unless", "end")):
                val = self.untuple(self.parse_expression_list())
            st = [_mk(ast.Return, line, value=val)] if v == "return" else []
            return self.ruby_modifiers(st, line)
        if v == "raise":
            self.i += 1
            exc = None
            if not self.t.nl_before and self.t.kind != "eof" and not (self.t.kind == "id" and self.t.val in ("if", "unless")):
                args, kws = self.parse_ruby_command_args()
                exc = args[0] if args else None
            return self.ruby_modifiers([_mk(ast.Raise, line, exc=exc, cause=None)], line)
        if v in ("require", "require_relative", "load"):
            self.i += 1
            self.opt("(")
            arg = self.untuple(self.parse_assignment())
            self.opt(")")
            self.end_stmt()
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                modname = arg.value.replace("/", ".").replace("-", "_")
                return [_mk(ast.Import, line, names=[ast.alias(name=modname, asname=modname.split(".")[-1])])]
            return [_mk(ast.Expr, line, value=_mk(ast.Call, line, func=_name(v, line), args=[arg], keywords=[]))]
        if v in ("private", "protected", "public", "module_function", "private_constant") and (self.peek().nl_before or self.peek().kind == "eof"):
            self.i += 1
            return []
        if v in ("alias", "alias_method", "undef", "__END__"):
            if v == "__END__":
                self.i = len(self.toks) - 1
                return []
            while not self.t.nl_before and self.t.kind != "eof":
                self.i += 1
            return []
        if v in ("end", "elsif", "else", "when", "rescue", "ensure", "then", "do"):
            raise ParseError(f"stray '{v}' at line {line}")
        return None

    def parse_primary(self):
        t = self.t
        line = t.line
        if t.kind == "num":
            self.i += 1
            return _const(_num_value(t.val), line)
        if t.kind == "istr":
            self.i += 1
            return self.parse_interpolated(t)
        if t.kind == "str":
            self.i += 1
            raw = t.val
            if raw.startswith("`"):
                if self.lang == "ruby":   # `cmd #{x}` runs a shell command
                    inner = Tok("str", '"' + raw[1:-1].replace('"', "'") + '"', line)
                    arg = self.parse_interpolated(inner) if "#{" in raw else _const(raw[1:-1], line)
                    return _mk(ast.Call, line, func=_name("system", line), args=[arg], keywords=[])
                return _const(raw[1:-1], line)
            if raw.startswith('"') and ((self.lang in ("kotlin", "php") and "$" in raw) or (self.lang == "ruby" and "#{" in raw)
                                        or (self.lang == "swift" and "\\(" in raw) or (self.lang == "rust" and re.search(r"\{[A-Za-z_]", raw))):
                return self.parse_interpolated(t)
            return _const(raw[1:-1], line)
        if t.kind == "ivar":        # Ruby @x / @@x -> self.x
            self.i += 1
            return _mk(ast.Attribute, line, value=_name("self", line), attr=t.val.lstrip("@"), ctx=ast.Load())
        if t.kind == "sym":         # Ruby :name -> "name"
            self.i += 1
            return _const(t.val[1:], line)
        if t.kind == "punct":
            if t.val == "(":
                self.i += 1
                e = self.untuple(self.parse_expression())
                self.eat(")")
                return e
            if t.val == "[":
                self.i += 1
                elts = []
                keys, keyed = [], False
                while not self.at("]") and self.t.kind != "eof":
                    if self.opt("...") or self.at(","):
                        self.opt(",")
                        continue
                    k = self.untuple(self.parse_assignment())
                    key = None
                    if self.opt("=>"):   # php assoc
                        key, k, keyed = k, self.untuple(self.parse_assignment()), True
                    keys.append(key)
                    elts.append(k)
                    self.opt(",")
                self.eat("]")
                if keyed:
                    return _mk(ast.Dict, line, keys=[kk if kk is not None else _const(i, line) for i, kk in enumerate(keys)], values=elts)
                return _mk(ast.List, line, elts=elts, ctx=ast.Load())
            if t.val == "{":
                if self.lang in BRACE_LAMBDA_LANGS:          # closure value: val f = { x -> ... } / { x in ... }
                    return self.parse_kotlin_lambda()
                if self.lang == "ruby":                       # hash literal
                    return self.parse_ruby_hash()
                if self.lang == "rust":                       # block expression: hoist its statements
                    body = self.block()
                    self.hoisted.extend(st for st in body if not isinstance(st, ast.Pass))
                    return _name("_block", line)
                return self.parse_array_literal()             # Go composite literal / C array initialiser
            if t.val == "->" and self.lang == "ruby":         # ->(x) { ... } lambda
                return self.parse_ruby_lambda()
            if t.val == "::" and self.lang in ("ruby", "rust", "cpp"):   # ::Foo / ::std::x
                self.i += 1
                return self.parse_primary()
            if t.val == "$" and self.lang == "swift" and self.peek().kind == "num":   # $0
                self.i += 1
                return _name("$" + self.eat().val, line)
            if t.val == "#" and self.lang == "swift":         # #available(...) / #selector(...)
                self.i += 1
                if self.t.kind == "id":
                    self.i += 1
                if self.at("("):
                    self.skip_balanced("(", ")")
                return _const(True, line)
            if t.val == "|" and self.lang == "ruby":
                raise ParseError(f"unexpected '|' at line {line}")
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
            if v == "switch" and self.lang == "java" and self.peek().val == "(":
                # `x = switch (m) { case A -> e; default -> { …; yield f; } }`: hoist the switch as a statement whose
                # arms assign one temporary, and use the temporary as the expression's value
                tmp = f"__switch_{line}_{self.i}"
                self.yield_targets.append(tmp)
                try:
                    st = self.parse_switch()
                finally:
                    self.yield_targets.pop()
                self.hoisted.append(st)
                return _name(tmp, line)
            if v == "new":
                return self.parse_new()
            if v in ("this", "$this", "self", "static") or (v in ("parent", "base") and self.lang in ("php", "csharp")):
                self.i += 1
                return _name("self" if v in ("this", "$this", "self", "static") else "super", line)
            if v == "super":
                self.i += 1
                return _name("super", line)
            if v in ("true", "false", "True", "False", "TRUE", "FALSE"):
                self.i += 1
                return _const(v.lower() == "true", line)
            if v in ("null", "nil", "NULL", "None", "nullptr"):
                self.i += 1
                return _const(None, line)
            if v in ("lambda", "proc") and self.lang == "ruby" and self.peek().val in ("{", "do"):
                self.i += 1
                blk = self.parse_ruby_block_fn(line, self.at("{"))
                return blk
            if v == "Self" and self.lang == "rust" and self.cls_stack:
                self.i += 1
                return _name(self.cls_stack[-1], line)
            if v == "array" and self.lang == "php" and self.peek().val == "(":
                self.i += 1
                self.eat("(")
                elts, keys, keyed = [], [], False
                while not self.at(")") and self.t.kind != "eof":
                    k = self.untuple(self.parse_assignment())
                    key = None
                    if self.opt("=>"):
                        key, k, keyed = k, self.untuple(self.parse_assignment()), True
                    keys.append(key)
                    elts.append(k)
                    if not self.opt(","):
                        break
                self.eat(")")
                if keyed:
                    return _mk(ast.Dict, line, keys=[kk if kk is not None else _const(i, line) for i, kk in enumerate(keys)], values=elts)
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


def _config_annotation(decs, line):
    """@Value("${app.table}") / @ConfigProperty(name = "x") -> config_value("…") for the annotated field."""
    for d in decs or ():
        if isinstance(d, ast.Call):
            name = d.func.id if isinstance(d.func, ast.Name) else (d.func.attr if isinstance(d.func, ast.Attribute) else "")
            if name in ("Value", "ConfigProperty", "ConfigurationProperty"):
                key = None
                for a in list(d.args) + [k.value for k in d.keywords if k.arg in ("name", "value", "key")]:
                    if isinstance(a, ast.Constant) and isinstance(a.value, str):
                        key = a.value
                    elif isinstance(a, ast.JoinedStr):            # Kotlin "\${app.table}" lowered to an f-string
                        key = "".join(v.value for v in a.values if isinstance(v, ast.Constant))
                if key:
                    return _mk(ast.Call, line, func=_name("config_value", line), args=[_const(key, line)], keywords=[])
    return None


def _tail_return(body: list) -> None:
    """Rust / Swift single-expression bodies: the last expression statement is the function's value."""
    if body and isinstance(body[-1], ast.Expr):
        e = body[-1]
        body[-1] = _mk(ast.Return, e.lineno, value=e.value)


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
    rel = re.sub(r"\.(java|kt|kts|cs|go|php|phtml|c|h|cc|cpp|cxx|hpp|hh|hxx|rs|swift|rb|rake)$", "", rel)
    return rel.replace("/", ".")


def parse_cfamily_ex(text: str, rel: str, lang: str):
    """Parse and return (module, diagnostics). diagnostics = {"language", "statements", "skipped", "lines": [(line, reason)...]}."""
    diag = {"language": lang, "statements": 0, "skipped": 0, "lines": []}
    try:
        p = Parser(text, rel, lang)
        mod = p.parse_program()
        # Go receiver methods / Rust impl / Swift extension / C++ out-of-class definitions: attach to their classes
        ext = dict(p.go_methods)
        for k, v in p.ext_methods.items():
            ext.setdefault(k, []).extend(v)
        if ext:
            classes = {n.name: n for n in mod.body if isinstance(n, ast.ClassDef)}
            for cname, fns in ext.items():
                fields = p.class_fields.get(cname)
                if fields and lang in ("cpp", "swift"):
                    for fn in fns:
                        _rewrite_implicit_this(fn, fields)
                cls = classes.get(cname)
                if cls is None:
                    cls = _mk(ast.ClassDef, fns[0].lineno if fns else 1, name=cname, bases=[], keywords=[], body=[], decorator_list=[], type_params=[])
                    mod.body.insert(0, cls)
                    classes[cname] = cls
                cls.body = [s for s in cls.body if not isinstance(s, ast.Pass)] + fns
                if not cls.body:
                    cls.body = [_mk(ast.Pass, 1)]
        diag["statements"] = p.n_statements
        diag["skipped"] = len(p.diagnostics)
        diag["lines"] = list(p.diagnostics)
        return mod, diag
    except Exception as e:  # noqa: BLE001 - never abort a scan on a frontend bug
        diag["skipped"] = 1
        diag["lines"] = [(1, f"frontend failure: {type(e).__name__}: {e}")]
        return ast.Module(body=[], type_ignores=[]), diag


def parse_cfamily(text: str, rel: str, lang: str) -> ast.Module:
    mod, diag = parse_cfamily_ex(text, rel, lang)
    mod.vulnscan_diagnostics = diag
    return mod
