"""Deterministic automatic fixes ("autofix") for findings.

Every fix is a small, rule-based rewrite of the exact code a finding points at. Nothing here guesses: a fixer
recognises one strict shape (through the syntax tree for Python, through anchored token patterns for the other
languages) and declines when the code deviates from it. A fix is offered only when

* the rewritten file still parses (``ast.parse`` for Python; bracket balance for JavaScript / Java; indentation
  sanity for YAML; ``json.loads`` for JSON), and
* the line rule that raised the finding no longer matches the rewritten lines.

The fix of a finding is a dict (``finding.extra["fix"]``, surfaced as the top-level ``"fix"`` key of
``Finding.to_dict()``)::

    {"description": str,            # English
     "description_ar": str,         # Arabic
     "diff": str,                   # unified diff of the file ("" for a description-only suggestion)
     "edits": [{"file": str, "start_line": int, "end_line": int, "replacement": str}]}

``start_line`` / ``end_line`` are 1-based and inclusive; ``replacement`` is the complete new text of those lines,
line terminators included, and is never empty (an insertion or a deletion is expressed by rewriting a neighbouring
line). An empty ``edits`` list means "advice only": the change needs a refactoring that cannot be automated safely.

Standard library only.
"""

from __future__ import annotations

import ast
import difflib
import json
import os
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass, field
from functools import lru_cache

from .i18n import localize, to_en
from .model import Finding
from .rules import RULES

__all__ = ["FIXERS", "FixReport", "apply_edits", "apply_fixes", "attach_fixes", "compute_fix", "fix_text",
           "fixable_rules", "git_dirty", "run_cli", "split_lines"]

_LINE_RE = re.compile(r"[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+")
_EOL_RE = re.compile(r"(?:\r\n|\r|\n)$")
_LINE_RULES = {r.id: r for r in RULES}
_SOURCES = frozenset({"vulnscan", "taint", "vql"})       # the engine's own findings (not OSV / external tools / web)

PY_EXT = frozenset({".py", ".pyw"})
JS_EXT = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})
WEB_EXT = JS_EXT | frozenset({".html", ".htm", ".vue", ".svelte"})
JAVA_EXT = frozenset({".java"})
JVM_EXT = frozenset({".java", ".kt", ".kts", ".scala", ".groovy"})
YAML_EXT = frozenset({".yml", ".yaml"})
DOCKER = frozenset({"<dockerfile>"})


class _Skip(Exception):
    """The code does not have the exact shape a fixer needs: no fix."""


def split_lines(text: str) -> list[str]:
    """Lines with their terminators, split exactly where Python's tokenizer does (\\n, \\r\\n, \\r)."""
    return _LINE_RE.findall(text)


def _body(line: str) -> str:
    return _EOL_RE.sub("", line)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


# ====================================================================== descriptions (Arabic; English in cat_autofix)

D = {
    "yaml": "استبدال yaml.load بـ yaml.safe_load الذي لا ينشئ كائنات Python عشوائية.",
    "shell": "تحويل الأمر الثابت إلى قائمة وسائط وإزالة shell=True حتى لا يمرّ عبر مفسّر الأوامر.",
    "os_system": "استبدال os.system بـ subprocess.run مع قائمة وسائط حتى لا يمرّ الأمر عبر مفسّر الأوامر.",
    "verify": "إزالة verify=False ليعود التحقق من شهادة TLS إلى وضعه الافتراضي (مفعّل).",
    "verify_attr": "ضبط verify على True لإعادة تفعيل التحقق من شهادة TLS.",
    "hash": "استبدال MD5/SHA-1 بـ SHA-256. تنبيه: القيم المحسوبة سابقًا بالخوارزمية القديمة لن تطابق الجديدة.",
    "random": "استبدال مولّد random القابل للتوقع بمولّد secrets المشفّر.",
    "jwt": "إزالة خيار تعطيل التحقق من توقيع JWT ليُتحقق من التوقيع دائمًا.",
    "debug": "تعطيل وضع التصحيح (debug=False).",
    "xxe_flags": "تعطيل الكيانات الخارجية وDTD في محلل XML.",
    "defusedxml": "استخدام defusedxml بدل محلل XML في المكتبة القياسية. تنبيه: يضيف هذا الاعتمادية defusedxml "
                  "(pip install defusedxml).",
    "mark_safe": "تهريب القيمة بـ escape() قبل تعليمها آمنة بـ mark_safe.",
    "cookie": "ضبط علامتي secure وhttponly على الكوكي.",
    "cookie_httponly": "ضبط httponly=True حتى لا يقرأ JavaScript الكوكي.",
    "cookie_js": "ضبط secure وhttpOnly على true في خيارات الكوكي.",
    "cookie_java": "ضبط setSecure(true) حتى لا تُرسل الكوكي عبر HTTP غير مشفّر.",
    "sql": "تحويل الاستعلام إلى استعلام مُعَلَّم: القيمة تُمرَّر وسيطًا منفصلًا بدل تضمينها في نص SQL.",
    "sql_java": "اقتراح دون تعديل آلي: استبدل Statement بـ PreparedStatement وضع ? مكان كل قيمة ثم اربطها "
                "بـ setString/setInt؛ هذا التحويل يحتاج إعادة هيكلة يدوية.",
    "exec_js": "استبدال exec بـ execFile مع قائمة وسائط حتى لا يمرّ الأمر عبر مفسّر الأوامر؛ المتغيّر يُمرَّر وسيطًا "
               "واحدًا.",
    "innerhtml": "استبدال innerHTML بـ textContent حتى تُعرض القيمة نصًا لا HTML.",
    "eval_json": "استبدال eval بـ JSON.parse. تنبيه: JSON.parse يقبل JSON الصارم فقط.",
    "tls_js": "ضبط rejectUnauthorized على true لإعادة تفعيل التحقق من شهادة TLS.",
    "digest_java": "استبدال خوارزمية التجزئة الضعيفة بـ SHA-256. تنبيه: القيم المحسوبة سابقًا لن تطابق الجديدة.",
    "random_java": "استبدال java.util.Random بـ java.security.SecureRandom.",
    "dbf_java": "إضافة إعدادات الحماية من XXE إلى DocumentBuilderFactory (منع DOCTYPE وتعطيل XInclude وتوسيع الكيانات).",
    "docker_user": "إضافة تعليمة USER برقم مستخدم غير root. تنبيه: تأكد أن ملفات التطبيق قابلة للقراءة لهذا المستخدم.",
    "k8s_ape": "ضبط allowPrivilegeEscalation على false.",
    "k8s_nonroot": "ضبط runAsNonRoot على true.",
    "k8s_add_nonroot": "إضافة securityContext على مستوى الـ Pod يفرض runAsNonRoot: true. تنبيه: الصورة التي تعمل "
                       "بصلاحيات root لن تبدأ حتى يُحدَّد لها مستخدم غير root.",
    "gha_env": "نقل تعبير GitHub غير الموثوق من run: إلى env: واستخدامه كمتغير بيئة في السكربت.",
}


@dataclass
class _Out:
    text: str            # the whole rewritten file ("" unchanged for an advice-only fix)
    key: str             # description key in D
    advice_only: bool = False


# ====================================================================== C-like lexing (JavaScript, Java, Kotlin ...)

def _code_map(text: str, js: bool) -> list[bool]:
    """Per character of `text`: False inside a comment or a string literal (quotes included), True elsewhere.
    Handles // and /* */ comments, '...' and "..." strings, JavaScript template literals (as a whole, ${...}
    included) and JVM text blocks. A JavaScript regular-expression literal is not recognised: a quote inside one
    can make the rest of its line look like a string (or a string look like code); every fixer still matches one
    strict shape, so the map is a second guard, not the only one."""
    n = len(text)
    code = [True] * n
    i = 0
    while i < n:
        ch = text[i]
        if ch == "/" and text.startswith("//", i):
            j = i
            while j < n and text[j] not in "\r\n":
                j += 1
        elif ch == "/" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
        elif not js and text.startswith('"""', i):
            j = text.find('"""', i + 3)
            j = n if j < 0 else j + 3
        elif ch in "'\"" or (js and ch == "`"):
            j = i + 1
            while j < n and text[j] != ch:
                if text[j] == "\\":
                    j += 1
                elif ch != "`" and text[j] in "\r\n":
                    break
                elif ch == "`" and text.startswith("${", j):        # ${ ... } may hold a nested template
                    depth, j = 1, j + 2
                    while j < n and depth:
                        depth += {"{": 1, "}": -1}.get(text[j], 0)
                        j += 1
                    continue
                j += 1
            j = min(j + 1, n)
        else:
            i += 1
            continue
        for k in range(i, j):
            code[k] = False
        i = j
    return code


# ====================================================================== context

class _Ctx:
    def __init__(self, finding: Finding, text: str, rel: str, line: int):
        self.f = finding
        self.text = text
        self.rel = rel.replace("\\", "/")
        self.line = line
        self.lines = split_lines(text)
        self.name = self.rel.rsplit("/", 1)[-1]
        self.ext = pathlib.PurePosixPath(self.name).suffix.lower()
        self.eol = "\r\n" if "\r\n" in text else "\n"
        self._py: _PyDoc | None = None
        self._code: list[list[bool]] | None = None

    @property
    def kinds(self) -> set[str]:
        out = {self.ext}
        low = self.name.lower()
        if low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile"):
            out.add("<dockerfile>")
        return out

    @property
    def py(self) -> "_PyDoc":
        if self._py is None:
            if self.text.startswith("\ufeff"):
                raise _Skip
            try:
                self._py = _pydoc(self.text, self.eol)
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                raise _Skip from None
        return self._py

    def cur(self) -> str:
        """The finding's line, without its terminator."""
        if not 1 <= self.line <= len(self.lines):
            raise _Skip
        return _body(self.lines[self.line - 1])

    def with_line(self, index: int, new_body: str) -> str:
        """The file with the body of 0-based line `index` replaced (terminator kept)."""
        old = self.lines[index]
        lines = list(self.lines)
        lines[index] = new_body + old[len(_body(old)):]
        return "".join(lines)

    def code(self, index: int) -> list[bool]:
        """Per character of the body of 0-based line `index`: True where it is code (not inside a comment or a
        string literal) for a C-like language. A page (.html, .vue ...) is lexed from the line alone, a source file
        from its start (block comments and text blocks span lines)."""
        if self._code is None:
            js = self.ext in WEB_EXT
            if self.ext in JS_EXT | JVM_EXT:
                full = _code_map(self.text, js)
                self._code, pos = [], 0
                for ln in self.lines:
                    self._code.append(full[pos:pos + len(_body(ln))])
                    pos += len(ln)
            else:
                self._code = [_code_map(_body(ln), js) for ln in self.lines]
        return self._code[index]

    def in_code(self, index: int, col: int) -> bool:
        m = self.code(index)
        return 0 <= col < len(m) and m[col]

    def sub_once(self, pattern: str, repl, flags: int = 0, at: int | None = None) -> str:
        """Rewrite the single match of `pattern` on the finding's line; skip when there is not exactly one, or when
        it is not code: the match start (or, with `at`, the end of group `at`: the token that changes) must not lie
        in a comment or a string literal, where a rewrite changes nothing or changes data."""
        cur = self.cur()
        hits = list(re.finditer(pattern, cur, flags))
        if len(hits) != 1 or not self.in_code(self.line - 1, hits[0].end(at) if at else hits[0].start()):
            raise _Skip
        m = hits[0]
        new = repl(m) if callable(repl) else m.expand(repl)
        return self.with_line(self.line - 1, cur[:m.start()] + new + cur[m.end():])


# ====================================================================== Python: exact source spans from the AST

class _PyDoc:
    """A parsed Python file with byte-exact node spans (ast column offsets are UTF-8 byte offsets)."""

    def __init__(self, text: str, eol: str = "\n"):
        self.tree = ast.parse(text)
        self.data = text.encode("utf-8")
        self.eol = eol
        self.starts = [0] + [m.end() for m in re.finditer(rb"\r\n|\r|\n", self.data)]
        self.alias: dict[str, str] = {}          # local name -> dotted module / module.attr it is bound to
        self.import_names: set[str] = set()
        self.rebound: set[str] = set()           # names also bound by something that is not an import
        self.parent: dict[int, ast.AST] = {}
        for node in ast.walk(self.tree):
            for child in ast.iter_child_nodes(node):
                self.parent[id(child)] = node
            if isinstance(node, ast.Import):
                for a in node.names:
                    local = a.asname or a.name.split(".")[0]
                    self.alias[local] = a.name if a.asname else local
                    self.import_names.add(local)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for a in node.names:
                    if a.name != "*":
                        self.alias[a.asname or a.name] = f"{node.module}.{a.name}"
                        self.import_names.add(a.asname or a.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                self.rebound.add(node.id)
            elif isinstance(node, ast.arg):
                self.rebound.add(node.arg)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.rebound.add(node.name)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                self.rebound.add(node.name)

    # ---- positions
    def off(self, lineno: int, col: int) -> int:
        return self.starts[lineno - 1] + col

    def span(self, node) -> tuple[int, int]:
        return self.off(node.lineno, node.col_offset), self.off(node.end_lineno, node.end_col_offset)

    def src(self, node) -> str:
        s, e = self.span(node)
        return self.data[s:e].decode("utf-8")

    def apply(self, spans: list[tuple[int, int, str]]) -> str:
        if not spans:
            raise _Skip
        data = self.data
        last = len(data) + 1
        for s, e, new in sorted(set(spans), key=lambda t: (t[0], t[1]), reverse=True):
            if e > last or s > e:
                raise _Skip                       # overlapping rewrites: do not guess
            data = data[:s] + new.encode("utf-8") + data[e:]
            last = s
        return data.decode("utf-8")

    # ---- lookup
    def calls_at(self, line: int) -> list[ast.Call]:
        """Calls whose source covers `line`, innermost (smallest) first."""
        hits = [n for n in ast.walk(self.tree) if isinstance(n, ast.Call) and n.lineno <= line <= n.end_lineno]
        return sorted(hits, key=lambda n: (n.end_lineno - n.lineno, self.span(n)[1] - self.span(n)[0]))

    def stmt_at(self, line: int) -> ast.stmt:
        hits = [n for n in ast.walk(self.tree) if isinstance(n, ast.stmt) and n.lineno <= line <= n.end_lineno]
        if not hits:
            raise _Skip
        return min(hits, key=lambda n: (n.end_lineno - n.lineno, -n.lineno))

    @staticmethod
    def dotted(node) -> str | None:
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return None
        parts.append(node.id)
        return ".".join(reversed(parts))

    def qual(self, node) -> str | None:
        """Fully qualified name of a Name/Attribute chain whose root is an imported module or name."""
        d = self.dotted(node)
        if d is None:
            return None
        root, _, rest = d.partition(".")
        if root not in self.alias or root in self.rebound:
            return None
        return self.alias[root] + ("." + rest if rest else "")

    def items(self, call: ast.Call) -> list:
        """Positional and keyword arguments in source order."""
        return sorted(list(call.args) + list(call.keywords), key=lambda n: self._start(n))

    def _start(self, node) -> int:
        if isinstance(node, ast.keyword):
            return self.kw_span(node)[0]
        return self.span(node)[0]

    def kw_span(self, kw: ast.keyword) -> tuple[int, int]:
        if hasattr(kw, "lineno") and kw.end_lineno is not None:
            return self.span(kw)
        raise _Skip

    def item_span(self, node) -> tuple[int, int]:
        return self.kw_span(node) if isinstance(node, ast.keyword) else self.span(node)

    def remove_item(self, spans: list[tuple[int, int]], idx: int, close: int) -> tuple[int, int, str]:
        """The rewrite that drops element `idx` of a comma-separated list whose closing bracket is at `close`."""
        s, e = spans[idx]
        whole = self._own_lines(s, e, spans[idx - 1][1] if idx > 0 else None,
                                spans[idx + 1][0] if idx + 1 < len(spans) else close)
        if whole is not None:
            return whole
        if idx > 0:
            pe = spans[idx - 1][1]
            if not re.fullmatch(rb"\s*,\s*", self.data[pe:s]):
                raise _Skip
            return (pe, e, "")
        if len(spans) > 1:
            ns = spans[1][0]
            if not re.fullmatch(rb"\s*,\s*", self.data[e:ns]):
                raise _Skip
            return (s, ns, "")
        if not re.fullmatch(rb"\s*,?\s*", self.data[e:close]):
            raise _Skip
        return (s, close, "")

    def _own_lines(self, s: int, e: int, prev_end: int | None, nxt: int) -> tuple[int, int, str] | None:
        """An element written on line(s) of its own (`    Loader=yaml.Loader,  # why` between the neighbours'
        lines) is removed with those whole lines, its comma and trailing comment included, so that no comment
        moves onto a neighbouring line and no other line changes. None when it shares a line with anything."""
        ls = self.data.rfind(b"\n", 0, s) + 1
        ls = max(ls, self.data.rfind(b"\r", 0, s) + 1)
        m = re.compile(rb"[ \t]*,?[ \t]*(?:#[^\r\n]*)?(\r\n|\r|\n)").match(self.data, e)
        if not m or not re.fullmatch(rb"[ \t]*", self.data[ls:s]) or nxt < m.end():
            return None
        if prev_end is not None:
            if prev_end > ls or not re.fullmatch(rb"\s*,[ \t]*(?:#[^\r\n]*)?(?:\r\n|\r|\n)[ \t]*",
                                                 self.data[prev_end:s]):
                return None                               # (the previous element must end with its own comma)
        return (ls, m.end(), "")

    def remove_arg(self, call: ast.Call, node) -> tuple[int, int, str]:
        items = self.items(call)
        spans = [self.item_span(i) for i in items]
        return self.remove_item(spans, items.index(node), self.span(call)[1] - 1)

    def append_args(self, call: ast.Call, extra: list[str]) -> tuple[int, int, str]:
        items = self.items(call)
        if not items:
            raise _Skip
        end = self.item_span(items[-1])[1]
        if not re.fullmatch(rb"\s*,?\s*", self.data[end:self.span(call)[1] - 1]):
            raise _Skip
        return (end, end, "".join(f", {x}" for x in extra))

    @staticmethod
    def plain_call(call: ast.Call) -> bool:
        """No *args / **kwargs: the argument list is fully visible."""
        return not any(isinstance(a, ast.Starred) for a in call.args) and all(k.arg for k in call.keywords)

    @staticmethod
    def kw(call: ast.Call, name: str):
        return next((k for k in call.keywords if k.arg == name), None)

    # ---- imports
    def _import_span(self, stmt: str) -> tuple[int, int, str]:
        """Insert `stmt` on a line of its own after the file's leading imports (after its docstring and
        `from __future__` imports), so that it runs before any module-level code: an import added after the last
        import of the file could come after a module-level statement that already uses the name."""
        body = list(self.tree.body)
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                and isinstance(body[0].value.value, str):
            head = [body.pop(0)]
        else:
            head = []
        while body and isinstance(body[0], (ast.Import, ast.ImportFrom)):
            head.append(body.pop(0))
        if body:                                          # the first statement the new line must precede
            first = body[0]
            nxt = min([first.lineno] + [d.lineno for d in getattr(first, "decorator_list", [])])
        else:
            nxt = None
        if head:
            line = head[-1].end_lineno                    # 0-based index of the line after the leading block
            if nxt is not None and nxt <= line:
                raise _Skip                               # `import os; os.system(...)`: no line in between
        else:
            line = nxt - 1 if nxt is not None else len(self.starts)
        if line < len(self.starts) and (self.starts[line] < len(self.data) or self.data.endswith((b"\n", b"\r"))
                                        or not self.data):
            off = self.starts[line]
            prev = self.data[self.starts[line - 1]:off] if line > 0 else b""
            m = re.search(rb"\r\n|\r|\n$", prev)
            return (off, off, stmt + (m.group(0).decode() if m else self.eol))   # the neighbouring line's terminator
        off = len(self.data)
        return (off, off, self.eol + stmt)

    def need_module(self, module: str) -> tuple[str, list]:
        """(local name of `module`, rewrites that import it when it is not imported yet)."""
        for local, full in self.alias.items():
            if full == module and local not in self.rebound:
                return local, []
        if module in self.rebound or module in self.import_names:
            raise _Skip
        return module, [self._import_span(f"import {module}")]

    def need_name(self, module: str, name: str) -> tuple[str, list]:
        for local, full in self.alias.items():
            if full == f"{module}.{name}" and local not in self.rebound:
                return local, []
        if name in self.rebound or name in self.import_names:
            raise _Skip
        return name, [self._import_span(f"from {module} import {name}")]


@lru_cache(maxsize=4)
def _pydoc(text: str, eol: str) -> _PyDoc:
    """Several findings of one file share its parse (a _PyDoc is never mutated)."""
    return _PyDoc(text, eol)


def _const(node, value) -> bool:
    return isinstance(node, ast.Constant) and node.value is value


# ---------------------------------------------------------------------- shell command safety
_SHELL_BUILTINS = frozenset("""cd export source alias unalias set unset ulimit umask eval exec exit read wait trap shift type
command builtin hash fg bg jobs history pushd popd dirs let declare local return time echo printf test true false
dir copy del erase move ren rename md rd cls start mklink assoc ver vol title pause call if for""".split())


def _safe_argv(cmd: str) -> list[str] | None:
    """The argument vector of a constant command line, or None unless splitting it is trivially equivalent to what
    a shell would do: plain words only (no quoting, expansion, redirection, pipes, globs, env assignments) and a
    real program as the first word (no shell builtin)."""
    if not cmd.strip() or re.search(r"[^A-Za-z0-9_./:@,+= -]", cmd):
        return None
    argv = cmd.split()
    if "=" in argv[0] or argv[0].lower() in _SHELL_BUILTINS or argv[0].startswith("-"):
        return None
    return argv


def _list_literal(items: list[str]) -> str:
    return "[" + ", ".join(json.dumps(a) for a in items) + "]"


# ====================================================================== Python fixers

_UNSAFE_LOADERS = {"yaml.Loader", "yaml.FullLoader", "yaml.UnsafeLoader", "yaml.CLoader", "yaml.CFullLoader",
                   "yaml.CUnsafeLoader"}


def _py_yaml(c: _Ctx) -> _Out:
    doc = c.py
    for call in doc.calls_at(c.line):
        q = doc.qual(call.func)
        if q not in ("yaml.load", "yaml.load_all") or not isinstance(call.func, ast.Attribute) or not doc.plain_call(call):
            continue
        loader = None
        if len(call.args) == 2 and not call.keywords:
            loader = call.args[1]
        elif len(call.args) == 1 and len(call.keywords) == 1 and call.keywords[0].arg == "Loader":
            loader = call.keywords[0]
        elif not (len(call.args) == 1 and not call.keywords):
            continue
        spans = []
        if loader is not None:
            value = loader.value if isinstance(loader, ast.keyword) else loader
            if doc.qual(value) not in _UNSAFE_LOADERS:
                continue
            spans.append(doc.remove_arg(call, loader))
        end = doc.span(call.func)[1]
        attr = call.func.attr
        spans.append((end - len(attr), end, "safe_" + attr))
        return _Out(doc.apply(spans), "yaml")
    raise _Skip


_SUBPROCESS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call"}


def _py_shell(c: _Ctx) -> _Out:
    doc = c.py
    for call in doc.calls_at(c.line):
        q = doc.qual(call.func)
        if not doc.plain_call(call) or not call.args:
            continue
        cmd = call.args[0]
        if not (isinstance(cmd, ast.Constant) and isinstance(cmd.value, str)):
            continue
        argv = _safe_argv(cmd.value)
        if argv is None:
            continue
        if q in _SUBPROCESS:
            shell = doc.kw(call, "shell")
            if shell is None or not _const(shell.value, True) or doc.kw(call, "executable") is not None:
                continue
            s, e = doc.span(cmd)
            return _Out(doc.apply([(s, e, _list_literal(argv)), doc.remove_arg(call, shell)]), "shell")
        if q == "os.system" and len(call.args) == 1 and not call.keywords:
            parent = doc.parent.get(id(call))
            if not isinstance(parent, ast.Expr):           # the exit status is used: not the same value
                continue
            name, spans = doc.need_module("subprocess")
            s, e = doc.span(call)
            return _Out(doc.apply(spans + [(s, e, f"{name}.run({_list_literal(argv)})")]), "os_system")
    raise _Skip


_HTTP_ATTRS = {"get", "post", "put", "patch", "delete", "head", "options", "request", "send", "stream",
               "Client", "AsyncClient", "Session"}


def _py_verify(c: _Ctx) -> _Out:
    doc = c.py
    for call in doc.calls_at(c.line):
        kw = doc.kw(call, "verify")
        if kw is None or not _const(kw.value, False) or not doc.plain_call(call):
            continue
        q = doc.qual(call.func) or ""
        attr = call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", "")
        if q.startswith("jwt."):
            continue
        if q.split(".")[0] in ("requests", "httpx") or attr in _HTTP_ATTRS:
            return _Out(doc.apply([doc.remove_arg(call, kw)]), "verify")
    stmt = doc.stmt_at(c.line)
    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Attribute) \
            and stmt.targets[0].attr == "verify" and _const(stmt.value, False):
        s, e = doc.span(stmt.value)
        return _Out(doc.apply([(s, e, "True")]), "verify_attr")
    raise _Skip


def _py_hash(c: _Ctx) -> _Out:
    doc = c.py
    spans = []
    for call in doc.calls_at(c.line):
        q = doc.qual(call.func)
        if q in ("hashlib.md5", "hashlib.sha1") and isinstance(call.func, ast.Attribute):
            end = doc.span(call.func)[1]
            spans.append((end - len(call.func.attr), end, "sha256"))
        elif q == "hashlib.new" and call.args and isinstance(call.args[0], ast.Constant) \
                and str(call.args[0].value).lower() in ("md5", "sha1", "md4", "md2"):
            s, e = doc.span(call.args[0])
            quote = doc.data[s:s + 1].decode()
            if quote not in "'\"":
                continue
            spans.append((s, e, f"{quote}sha256{quote}"))
    return _Out(doc.apply(spans), "hash")


_SIMPLE = (ast.Name, ast.Attribute, ast.Constant)


def _py_random(c: _Ctx) -> _Out:
    doc = c.py
    stmt = doc.stmt_at(c.line)
    weak = [n for n in ast.walk(stmt) if isinstance(n, ast.Call) and (doc.qual(n.func) or "").startswith("random.")
            and doc.qual(n.func) != "random.SystemRandom"]
    if not weak:
        raise _Skip
    sec, spans = doc.need_module("secrets")
    done: set[int] = set()
    # "%032x" % random.getrandbits(128)  ->  secrets.token_hex(16)
    for node in ast.walk(stmt):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant) \
                and isinstance(node.left.value, str) and isinstance(node.right, ast.Call) \
                and doc.qual(node.right.func) == "random.getrandbits" and len(node.right.args) == 1 \
                and not node.right.keywords and isinstance(node.right.args[0], ast.Constant):
            m = re.fullmatch(r"%0(\d+)x", node.left.value)
            bits = node.right.args[0].value
            if m and isinstance(bits, int) and bits == 4 * int(m.group(1)) and bits % 8 == 0 and bits > 0:
                s, e = doc.span(node)
                spans.append((s, e, f"{sec}.token_hex({bits // 8})"))
                done.add(id(node.right))
    rename = {"random.choice": "choice", "random.randrange": "randbelow", "random.getrandbits": "randbits",
              "random.randbytes": "token_bytes"}
    for call in weak:
        if id(call) in done:
            continue
        q = doc.qual(call.func)
        if not doc.plain_call(call):
            raise _Skip
        fs, fe = doc.span(call.func)
        if q in rename and len(call.args) == 1 and not call.keywords:
            spans.append((fs, fe, f"{sec}.{rename[q]}"))
        elif q == "random.randint" and len(call.args) == 2 and not call.keywords:
            try:
                lo, hi = (ast.literal_eval(a) for a in call.args)
            except (ValueError, SyntaxError):
                raise _Skip from None
            if not (type(lo) is int and type(hi) is int and lo <= hi):
                raise _Skip
            s, e = doc.span(call)
            core = f"{sec}.randbelow({hi - lo + 1})"
            spans.append((s, e, core if lo == 0 else f"({core} + {lo})" if lo > 0 else f"({core} - {-lo})"))
        elif q == "random.choices" and len(call.args) == 1 and len(call.keywords) == 1 and call.keywords[0].arg == "k" \
                and isinstance(call.args[0], _SIMPLE) and isinstance(call.keywords[0].value, _SIMPLE) \
                and "_" not in (doc.src(call.args[0]), doc.src(call.keywords[0].value)):
            s, e = doc.span(call)
            spans.append((s, e, f"[{sec}.choice({doc.src(call.args[0])}) for _ in range({doc.src(call.keywords[0].value)})]"))
        else:
            raise _Skip                              # random(), uniform(), sample() ...: no exact secrets equivalent
    return _Out(doc.apply(spans), "random")


def _py_jwt(c: _Ctx) -> _Out:
    doc = c.py
    for call in doc.calls_at(c.line):
        if doc.qual(call.func) != "jwt.decode" or not doc.plain_call(call):
            continue
        if doc.kw(call, "algorithms") is None or not (len(call.args) >= 2 or doc.kw(call, "key") is not None):
            continue                                 # verification could not succeed afterwards: leave it to a human
        spans = []
        verify = doc.kw(call, "verify")
        if verify is not None and _const(verify.value, False):
            spans.append(doc.remove_arg(call, verify))
        options = doc.kw(call, "options")
        if options is not None and isinstance(options.value, ast.Dict) and all(k is not None for k in options.value.keys):
            d = options.value
            bad = [i for i, (k, v) in enumerate(zip(d.keys, d.values))
                   if isinstance(k, ast.Constant) and k.value == "verify_signature" and _const(v, False)]
            if len(bad) == 1 and len(d.keys) == 1:
                spans.append(doc.remove_arg(call, options))
            elif len(bad) == 1:
                pairs = [(doc.span(k)[0], doc.span(v)[1]) for k, v in zip(d.keys, d.values)]
                spans.append(doc.remove_item(pairs, bad[0], doc.span(d)[1] - 1))
        if spans:
            return _Out(doc.apply(spans), "jwt")
    raise _Skip


def _py_debug(c: _Ctx) -> _Out:
    doc = c.py
    for call in doc.calls_at(c.line):
        kw = doc.kw(call, "debug")
        if isinstance(call.func, ast.Attribute) and call.func.attr == "run" and kw is not None and _const(kw.value, True):
            s, e = doc.span(kw.value)
            return _Out(doc.apply([(s, e, "False")]), "debug")
    raise _Skip


def _py_xxe_flags(c: _Ctx) -> _Out:
    doc = c.py
    spans = []
    for call in doc.calls_at(c.line):
        for name, bad, good in (("resolve_entities", True, "False"), ("load_dtd", True, "False"),
                                ("no_network", False, "True")):
            kw = doc.kw(call, name)
            if kw is not None and _const(kw.value, bad):
                s, e = doc.span(kw.value)
                spans.append((s, e, good))
        if isinstance(call.func, ast.Attribute) and call.func.attr == "setFeature" and len(call.args) == 2 \
                and (doc.dotted(call.args[0]) or "").rsplit(".", 1)[-1] in ("feature_external_ges", "feature_external_pes") \
                and isinstance(call.args[1], ast.Constant) and call.args[1].value in (True, 1):
            s, e = doc.span(call.args[1])
            spans.append((s, e, "False"))
    return _Out(doc.apply(spans), "xxe_flags")


_DEFUSED = {
    "xml.etree.ElementTree": ("defusedxml.ElementTree", {"parse", "iterparse", "fromstring", "XML", "XMLParser",
                                                         "XMLTreeBuilder", "tostring", "ParseError"}),
    "xml.etree.cElementTree": ("defusedxml.cElementTree", {"parse", "iterparse", "fromstring", "XML", "XMLParser",
                                                           "XMLTreeBuilder", "tostring", "ParseError"}),
    "xml.dom.minidom": ("defusedxml.minidom", {"parse", "parseString"}),
    "xml.dom.pulldom": ("defusedxml.pulldom", {"parse", "parseString"}),
    "xml.sax": ("defusedxml.sax", {"parse", "parseString", "make_parser"}),
}


def _py_defusedxml(c: _Ctx) -> _Out:
    doc = c.py
    module = local = None
    for call in doc.calls_at(c.line):                         # the flagged call must go through a direct import
        d = doc.dotted(call.func)
        q = doc.qual(call.func)
        if not d or not q:
            continue
        for mod in _DEFUSED:
            if q.startswith(mod + ".") and q.count(".") == mod.count(".") + 1:
                module, local = mod, d.split(".")[0]
        if module:
            break
    if not module:
        raise _Skip
    new_mod, allowed = _DEFUSED[module]
    for node in ast.walk(doc.tree):
        s, e = (doc.span(node) if isinstance(node, (ast.Import, ast.ImportFrom)) else (0, 0))
        if isinstance(node, ast.Import) and len(node.names) == 1 and node.names[0].name == module \
                and node.names[0].asname == local:
            old, new, attr_use = module, new_mod, True
        elif isinstance(node, ast.ImportFrom) and not node.level and len(node.names) == 1 \
                and f"{node.module}.{node.names[0].name}" == module and (node.names[0].asname or node.names[0].name) == local:
            old, new, attr_use = node.module, new_mod.rsplit(".", 1)[0], True
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module == module \
                and any((a.asname or a.name) == local for a in node.names):
            if not all(a.name in allowed for a in node.names):
                raise _Skip
            old, new, attr_use = module, new_mod, False
        else:
            continue
        if attr_use:                                          # every use of the alias must exist in defusedxml
            for n in ast.walk(doc.tree):
                if isinstance(n, ast.Name) and n.id == local:
                    p = doc.parent.get(id(n))
                    if not (isinstance(p, ast.Attribute) and p.attr in allowed) or not isinstance(n.ctx, ast.Load):
                        raise _Skip
        src = doc.data[s:e].decode("utf-8")
        if src.count(old) != 1:
            raise _Skip
        return _Out(doc.apply([(s, e, src.replace(old, new))]), "defusedxml")
    raise _Skip


def _py_mark_safe(c: _Ctx) -> _Out:
    doc = c.py
    for call in doc.calls_at(c.line):
        if doc.qual(call.func) != "django.utils.safestring.mark_safe" or len(call.args) != 1 or call.keywords:
            continue
        arg = call.args[0]
        if not isinstance(arg, (ast.Name, ast.Attribute, ast.Subscript)):
            continue
        name, spans = doc.need_name("django.utils.html", "escape")
        s, e = doc.span(arg)
        return _Out(doc.apply(spans + [(s, s, f"{name}("), (e, e, ")")]), "mark_safe")
    raise _Skip


def _py_cookie(c: _Ctx) -> _Out:
    doc = c.py
    for call in doc.calls_at(c.line):
        if not (isinstance(call.func, ast.Attribute) and call.func.attr in ("set_cookie", "set_signed_cookie")):
            continue
        if not doc.plain_call(call) or len(call.args) > 6 or not call.args and not call.keywords:
            continue
        spans, extra = [], []
        httponly = doc.kw(call, "httponly")
        if c.f.rule_id == "COOK002":
            if httponly is None or not _const(httponly.value, False):
                continue
            s, e = doc.span(httponly.value)
            return _Out(doc.apply([(s, e, "True")]), "cookie_httponly")
        secure = doc.kw(call, "secure")
        if secure is None:
            extra.append("secure=True")
        elif isinstance(secure.value, ast.Constant) and not secure.value.value:
            s, e = doc.span(secure.value)
            spans.append((s, e, "True"))
        else:
            continue
        key = call.args[0] if call.args else getattr(doc.kw(call, "key"), "value", None)
        csrf = not isinstance(key, ast.Constant) or re.search(r"(?i)csrf|xsrf", str(key.value))
        if httponly is None and not csrf:                     # a CSRF cookie is read by the page's script on purpose
            extra.append("httponly=True")
        if extra:
            spans.append(doc.append_args(call, extra))
        return _Out(doc.apply(spans), "cookie")
    raise _Skip


_PARAMSTYLE = {"sqlite3": "?", "aiosqlite": "?", "pyodbc": "?", "psycopg2": "%s", "psycopg": "%s", "pymysql": "%s",
               "MySQLdb": "%s", "mysql": "%s", "pymssql": "%s", "django": "%s", "cx_Oracle": ":1", "oracledb": ":1"}


_ESCAPER = re.compile(r"(?i)escape|quote|saniti|clean|encode|adapt|literal|mogrify|\?")


def _sql_parts(doc: _PyDoc, arg):
    """(text before, value expression, text after) when the query is one constant with exactly one interpolation."""
    if isinstance(arg, ast.JoinedStr):
        vals = [v for v in arg.values if isinstance(v, ast.FormattedValue)]
        if len(vals) != 1 or vals[0].conversion != -1 or vals[0].format_spec is not None:
            return None
        if "{{" in doc.src(arg) or "}}" in doc.src(arg):
            return None
        i = arg.values.index(vals[0])
        text = ["".join(v.value for v in part if isinstance(v, ast.Constant) and isinstance(v.value, str))
                for part in (arg.values[:i], arg.values[i + 1:])]
        return text[0], vals[0].value, text[1]
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        flat, stack = [], [arg]
        while stack:
            n = stack.pop()
            if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
                stack += [n.right, n.left]
            else:
                flat.append(n)
        dyn = [n for n in flat if not (isinstance(n, ast.Constant) and isinstance(n.value, str))]
        if len(dyn) != 1:
            return None
        i = flat.index(dyn[0])
        return "".join(n.value for n in flat[:i]), dyn[0], "".join(n.value for n in flat[i + 1:])
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod) and isinstance(arg.left, ast.Constant) \
            and isinstance(arg.left.value, str):
        s = arg.left.value
        if s.count("%") != 1 or s.count("%s") != 1:
            return None
        value = arg.right
        if isinstance(value, ast.Tuple):
            if len(value.elts) != 1:
                return None
            value = value.elts[0]
        pre, post = s.split("%s")
        return pre, value, post
    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format" \
            and isinstance(arg.func.value, ast.Constant) and isinstance(arg.func.value.value, str) \
            and len(arg.args) == 1 and not arg.keywords:
        s = arg.func.value.value
        m = re.search(r"\{0?\}", s)
        if not m or s.count("{") != 1 or s.count("}") != 1:
            return None
        return s[:m.start()], arg.args[0], s[m.end():]
    return None


def _py_sql(c: _Ctx) -> _Out:
    doc = c.py
    drivers = {full.split(".")[0] for full in doc.alias.values()} & set(_PARAMSTYLE)
    if drivers - {"django"}:
        drivers.discard("django")                             # a driver imported directly owns the cursor
    styles = {_PARAMSTYLE[d] for d in drivers}
    if len(styles) != 1:
        raise _Skip                                           # driver (so placeholder syntax) unknown or ambiguous
    style = next(iter(styles))
    for call in doc.calls_at(c.line):
        if not (isinstance(call.func, ast.Attribute) and call.func.attr == "execute" and len(call.args) == 1
                and not call.keywords and doc.plain_call(call)):
            continue
        fe, (qs, qe), ce = doc.span(call.func)[1], doc.span(call.args[0]), doc.span(call)[1]
        if not (re.fullmatch(rb"\s*\(\s*", doc.data[fe:qs]) and re.fullmatch(rb"\s*,?\s*\)", doc.data[qe:ce])):
            continue                                          # execute(("..." + v)): a tuple would become the query
        parts = _sql_parts(doc, call.args[0])
        if parts is None:
            continue
        pre, value, post = parts
        if not isinstance(value, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)):
            continue
        if any(isinstance(n, ast.Call) and _ESCAPER.search(doc.dotted(n.func) or "?") for n in ast.walk(value)):
            continue                                          # already escaped for SQL text: binding it would escape twice
        for quote in "'\"":
            if pre.endswith(quote) and post.startswith(quote):
                pre, post = pre[:-1], post[1:]
                break
        if pre.count("'") % 2 or pre.count('"') % 2 or post.count("'") % 2 or post.count('"') % 2:
            continue                                          # the value sits inside a larger SQL string literal
        if not re.search(r"(?i)(?:[=<>]|\blike)\s*$", pre) or (post and post[0] not in " \t\r\n);,"):
            continue                                          # not in value position (identifier, IN list, LIMIT ...)
        rest = pre + post
        if (style == "?" and "?" in rest) or (style == "%s" and "%" in rest) or (style == ":1" and re.search(r":\w", rest)):
            continue
        sql = pre + style + post
        if "\n" in sql or "\r" in sql:
            if '"""' in sql or "\\" in sql or sql.endswith('"'):
                continue
            lit = '"""' + sql + '"""'
        elif '"' not in sql and "\\" not in sql and sql.isprintable():
            lit = '"' + sql + '"'
        else:
            lit = repr(sql)
        s, e = doc.span(call.args[0])
        new = doc.apply([(s, e, f"{lit}, ({doc.src(value)},)")])
        return _Out(new, "sql")
    raise _Skip


# ====================================================================== JavaScript / TypeScript (token level)

_JS_ID = r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*"
_JS_EXEC = re.compile(
    r"(?<![\w$])(?:(?P<obj>[A-Za-z_$][\w$]*)\.)?(?P<fn>exec|execSync)\(\s*(?:"
    r"(?P<q>[\"'])(?P<lit>[^\"'\\`$]*)(?P=q)(?:\s*\+\s*(?P<id>" + _JS_ID + r"))?"
    r"|`(?P<tlit>[^`$\\]*)\$\{\s*(?P<tid>" + _JS_ID + r")\s*\}`"
    r")\s*(?=[,)])")
_JS_CP = r"[\"'](?:node:)?child_process[\"']"


def _js_exec(c: _Ctx) -> _Out:
    cur = c.cur()
    if len(re.findall(r"(?<![\w$])(?:exec|execSync)\s*\(", cur)) != 1:
        raise _Skip
    m = _JS_EXEC.search(cur)
    if not m or not c.in_code(c.line - 1, m.start()):
        raise _Skip
    if re.search(r"(?<![\w$])shell(?![\w$])", cur[m.end():]):
        raise _Skip                                           # execFile with a shell option still runs a shell
    lit = m.group("lit") if m.group("lit") is not None else m.group("tlit")
    ident = m.group("id") or m.group("tid")
    if ident and not lit.endswith(" "):
        raise _Skip                                           # the variable continues a word: not its own argument
    argv = _safe_argv(lit)
    if argv is None:
        raise _Skip
    fn = m.group("fn")
    new_fn = "execFile" if fn == "exec" else "execFileSync"
    args = [json.dumps(a) for a in argv[1:]] + ([ident] if ident else [])
    obj = m.group("obj")
    call = f"{obj + '.' if obj else ''}{new_fn}({json.dumps(argv[0])}, [{', '.join(args)}]"
    lines = list(c.lines)
    i = c.line - 1
    lines[i] = cur[:m.start()] + call + cur[m.end():] + c.lines[i][len(cur):]
    if obj:
        if not re.search(r"(?m)\b" + re.escape(obj) + r"\s*=\s*require\(\s*" + _JS_CP + r"\s*\)|import\s+(?:\*\s+as\s+)?"
                         + re.escape(obj) + r"\s+from\s+" + _JS_CP, c.text):
            raise _Skip
        return _Out("".join(lines), "exec_js")
    imports = [(j, mm) for j, ln in enumerate(c.lines)
               for mm in [re.search(r"(?:\b(?:const|let|var)\s*\{(?P<a>[^}]*)\}\s*=\s*require\(\s*" + _JS_CP + r"\s*\)"
                                    r"|\bimport\s*\{(?P<b>[^}]*)\}\s*from\s*" + _JS_CP + ")", ln)]
               if mm and c.in_code(j, mm.start())]
    if len(imports) != 1 or imports[0][0] == i:
        raise _Skip
    j, mm = imports[0]
    group = "a" if mm.group("a") is not None else "b"
    names = [n.strip() for n in mm.group(group).split(",") if n.strip()]
    if fn not in names:
        raise _Skip                                           # renamed on import ({ exec: run }) or not imported here
    if new_fn not in names:
        inner = mm.group(group)
        pos = mm.start(group) + re.search(r"(?<![\w$])" + fn + r"(?![\w$])", inner).end()
        ln = lines[j]
        lines[j] = ln[:pos] + ", " + new_fn + ln[pos:]
    return _Out("".join(lines), "exec_js")


def _js_innerhtml(c: _Ctx) -> _Out:
    cur = c.cur()
    m = re.fullmatch(r"(?P<pre>.*?)\.innerHTML(?P<eq>\s*=\s*)(?P<rhs>" + _JS_ID + r")\s*;?\s*", cur)
    if not m or cur.count(".innerHTML") != 1 or not c.in_code(c.line - 1, m.end("pre")):
        raise _Skip
    if re.search(r"(?i)html|markup|template|svg|sanitiz|purify|render|icon", m.group("rhs")):
        raise _Skip                                           # the value is HTML on purpose
    return _Out(c.with_line(c.line - 1, cur.replace(".innerHTML", ".textContent")), "innerhtml")


def _js_eval(c: _Ctx) -> _Out:
    pat = r"(?<![\w$.])eval\(\s*([\"'])\(\1\s*\+\s*(" + _JS_ID + r")\s*\+\s*([\"'])\)\3\s*\)"
    if len(re.findall(r"(?<![\w$.])eval\s*\(", c.cur())) != 1:
        raise _Skip                                           # (sub_once also requires the eval to be code)
    return _Out(c.sub_once(pat, lambda m: f"JSON.parse({m.group(2)})"), "eval_json")


def _js_cookie(c: _Ctx) -> _Out:
    """secure / httpOnly: false -> true, only inside the argument list of the one cookie(...) call on the finding's
    line (followed over at most 12 lines), and only in code: an unrelated object literal after the call, or text in
    a string or a comment, is left alone."""
    i0 = c.line - 1
    calls = [m for m in re.finditer(r"(?<![\w$])cookie\s*\(", c.cur()) if c.in_code(i0, m.start())]
    if len(calls) != 1:
        raise _Skip
    lines = list(c.lines)
    depth, changed, start = 0, False, calls[0].end() - 1
    for i in range(i0, min(len(lines), i0 + 12)):
        body = _body(lines[i])
        code = c.code(i)
        end = len(body)
        for k in range(start if i == i0 else 0, len(body)):
            if code[k] and body[k] in "()":
                depth += 1 if body[k] == "(" else -1
                if depth == 0:
                    end = k
                    break
        lo = start if i == i0 else 0
        new = body[:lo] + re.sub(r"(?<![\w$])(secure|httpOnly)(\s*:\s*)false\b",
                                 lambda m: m.expand(r"\1\2true") if code[lo + m.start()] else m.group(0),
                                 body[lo:end]) + body[end:]
        if new != body:
            lines[i] = new + lines[i][len(body):]
            changed = True
        if depth == 0:
            break
    else:
        raise _Skip                                           # the call does not close where it can be followed
    if not changed:
        raise _Skip
    return _Out("".join(lines), "cookie_js")


def _js_tls(c: _Ctx) -> _Out:
    return _Out(c.sub_once(r"(?<![\w$])(rejectUnauthorized\s*:\s*)false\b", r"\1true", at=1), "tls_js")


# ====================================================================== Java (token level)

def _java_digest(c: _Ctx) -> _Out:
    return _Out(c.sub_once(r"(?i)(MessageDigest\s*\.\s*getInstance\s*\(\s*\")(?:MD2|MD4|MD5|SHA-?1|SHA)(\")",
                           r"\1SHA-256\2"), "digest_java")


def _java_random(c: _Ctx) -> _Out:
    # A plain `Random` must be java.util.Random: not a class of the project's own (imported, nested or declared
    # in the package), which SecureRandom would not be assignable to. An anonymous subclass keeps its overrides
    # on a different superclass: left to a human.
    if re.search(r"(?m)^\s*import\s+(?!java\.util\.Random\s*;)[\w.]*\.Random\s*;"
                 r"|\b(?:class|interface|enum|record)\s+Random\b", c.text):
        cur = c.cur()
        if not re.search(r"\bnew\s+java\.util\.Random\s*\(", cur):
            raise _Skip
    pat = r"\bnew\s+(?:java\.util\.)?Random\s*\(\s*\)(?!\s*\{)"
    return _Out(c.sub_once(pat, "new java.security.SecureRandom()"), "random_java")


def _java_cookie(c: _Ctx) -> _Out:
    return _Out(c.sub_once(r"(\.\s*setSecure\s*\(\s*)false(\s*\))", r"\1true\2", at=1), "cookie_java")


_JAVA_XXE = [(r"(disallow-doctype-decl\"\s*,\s*)false\b", r"\1true"),
             (r"(external-(?:general|parameter)-entities\"\s*,\s*)true\b", r"\1false"),
             (r"(setExpandEntityReferences\s*\(\s*)true\b", r"\1false"),
             (r"(FEATURE_SECURE_PROCESSING\s*,\s*)false\b", r"\1true"),
             (r"(IS_SUPPORTING_EXTERNAL_ENTITIES\s*,\s*)true\b", r"\1false"),
             (r"(IS_SUPPORTING_EXTERNAL_ENTITIES\s*,\s*)Boolean\.TRUE\b", r"\1Boolean.FALSE")]


def _java_xxe_flags(c: _Ctx) -> _Out:
    cur = c.cur()
    hits = sorted((m.start(), m.end(), m.expand(repl)) for pat, repl in _JAVA_XXE for m in re.finditer(pat, cur)
                  if c.in_code(c.line - 1, m.end(1)))      # the flipped token must be code (not comment / string)
    if not hits or any(a[1] > b[0] for a, b in zip(hits, hits[1:])):
        raise _Skip
    new = cur
    for s, e, text in reversed(hits):
        new = new[:s] + text + new[e:]
    return _Out(c.with_line(c.line - 1, new), "xxe_flags")


def _java_dbf(c: _Ctx) -> _Out:
    """Insert the hardening calls right before `factory.newDocumentBuilder()`: that statement already handles the
    ParserConfigurationException which setFeature() declares, and the factory is in scope there."""
    created = None
    for i in range(min(c.line, len(c.lines)) - 1, max(-1, c.line - 80), -1):
        m = re.search(r"\bDocumentBuilderFactory\s+(\w+)\s*=\s*DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\)\s*;",
                      c.lines[i])
        if m and c.in_code(i, m.start()):
            created = (i, m.group(1))
            break
    if created is None:
        raise _Skip
    i, var = created
    v = re.escape(var)
    if re.search(v + r"\s*\.\s*(setFeature|setExpandEntityReferences|setXIncludeAware|setAttribute)\s*\(", c.text):
        raise _Skip                                           # already configured by hand: do not second-guess it
    for j in range(i + 1, min(len(c.lines), i + 60)):
        body = _body(c.lines[j])
        nb = re.search(r"\b" + v + r"\s*\.\s*newDocumentBuilder\s*\(\s*\)", body)
        if not nb or not c.in_code(j, nb.start()):
            continue                                          # (a mention in a comment is not the call)
        prev = next((_body(c.lines[k]).strip() for k in range(j - 1, i - 1, -1) if c.lines[k].strip()), "")
        if not body.rstrip().endswith(";") or not prev.endswith((";", "{", "}")) or re.match(r"\s*(\.|\+|\))", body):
            raise _Skip                                       # not a statement of its own line
        pad = re.match(r"[ \t]*", body).group(0)
        add = [f'{pad}{var}.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
               f"{pad}{var}.setXIncludeAware(false);", f"{pad}{var}.setExpandEntityReferences(false);"]
        lines = list(c.lines)
        lines[j:j] = [a + c.eol for a in add]
        return _Out("".join(lines), "dbf_java")
    raise _Skip


def _java_sql_note(c: _Ctx) -> _Out:
    return _Out(c.text, "sql_java", advice_only=True)


# ====================================================================== Dockerfile / Kubernetes / GitHub Actions

def _docker_user(c: _Ctx) -> _Out:
    lines = list(c.lines)
    bodies = [_body(ln) for ln in lines]
    froms = [i for i, b in enumerate(bodies) if re.match(r"^\s*FROM\s", b, re.I)]
    if not froms or "<<" in c.text:
        raise _Skip
    if re.search(r"(?i)windows|nanoserver|servercore", bodies[froms[-1]]):
        raise _Skip                                           # a numeric uid means nothing to a Windows container
    if any(re.match(r"^\s*USER\s+(?!root\b|0\b|0:)\S+", b, re.I) for b in bodies):
        raise _Skip
    if any(re.match(r"^\s*USER\s", b, re.I) for b in bodies[froms[-1]:]):
        raise _Skip                                           # an explicit USER root in the final stage: a decision
    at = next((i for i in range(froms[-1] + 1, len(bodies)) if re.match(r"^\s*(CMD|ENTRYPOINT)\b", bodies[i], re.I)),
              len(bodies))
    prev = next((bodies[k] for k in range(at - 1, -1, -1) if bodies[k].strip()), "")
    if prev.rstrip().endswith("\\") or prev.rstrip().endswith("`"):
        raise _Skip                                           # inside a continued instruction
    if at == len(lines) and lines and not _EOL_RE.search(lines[-1]):
        lines[-1] += c.eol
    lines[at:at] = ["USER 10001" + c.eol]
    return _Out("".join(lines), "docker_user")


def _in_block_scalar(bodies: list[str], i: int) -> bool:
    """Line `i` of a YAML file is text inside a block scalar (`key: |` / `key: >` / `- |`), e.g. a manifest
    embedded in a ConfigMap: data, not structure, so no fixer may rewrite it."""
    indent = _indent(bodies[i]) if bodies[i].strip() else 1 << 30
    for j in range(i - 1, -1, -1):
        b = bodies[j]
        if not b.strip() or b.lstrip().startswith("#") or _indent(b) >= indent:
            continue
        if re.search(r"(?:^|:|-)\s*[|>][+-]?\d?[+-]?\s*(?:#.*)?$", b):
            return True
        indent = _indent(b)
        if indent == 0:
            return False
    return False


def _yaml_line(c: _Ctx) -> None:
    if not 1 <= c.line <= len(c.lines) or _in_block_scalar([_body(ln) for ln in c.lines], c.line - 1):
        raise _Skip


def _k8s_ape(c: _Ctx) -> _Out:
    _yaml_line(c)
    return _Out(c.sub_once(r"^(\s*allowPrivilegeEscalation\s*:\s*['\"]?)true\b", r"\1false"), "k8s_ape")


def _k8s_nonroot(c: _Ctx) -> _Out:
    _yaml_line(c)
    return _Out(c.sub_once(r"^(\s*runAsNonRoot\s*:\s*['\"]?)false\b", r"\1true"), "k8s_nonroot")


def _k8s_add_nonroot(c: _Ctx) -> _Out:
    bodies = [_body(ln) for ln in c.lines]
    if not 1 <= c.line <= len(bodies):
        raise _Skip
    a = max([i + 1 for i in range(c.line - 1) if re.match(r"^---(\s|$)", bodies[i])] or [0])
    b = next((i for i in range(c.line, len(bodies)) if re.match(r"^---(\s|$)", bodies[i])), len(bodies))
    doc = bodies[a:b]
    if any("{{" in ln or "\t" in ln for ln in doc):
        raise _Skip
    conts = [i for i, ln in enumerate(doc) if re.match(r"^ *containers\s*:\s*(#.*)?$", ln)]
    if len(conts) != 1 or _in_block_scalar(bodies, a + conts[0]):
        raise _Skip
    pad = _indent(doc[conts[0]])
    if pad == 0 or any(re.match(r"^ {%d}securityContext\s*:" % pad, ln) for ln in doc):
        raise _Skip
    if any(re.match(r"^\s*(runAsNonRoot|runAsUser)\s*:", ln) for ln in doc):
        raise _Skip
    at = a + conts[0]
    lines = list(c.lines)
    lines[at:at] = [" " * pad + "securityContext:" + c.eol, " " * (pad + 2) + "runAsNonRoot: true" + c.eol]
    return _Out("".join(lines), "k8s_add_nonroot")


_GHA_EXPR = re.compile(r"\$\{\{\s*(github\.(?:event(?:\.[A-Za-z_][\w-]*)+|head_ref))\s*\}\}")
_ENV_RESERVED = {"PATH", "HOME", "USER", "SHELL", "PWD", "CI", "LANG", "TERM", "HOSTNAME", "IFS", "ACTION", "REF"}


def _gha_var(expr: str) -> str:
    parts = expr.split(".")[1:]
    if parts[0] == "event":
        parts = parts[1:]
    name = re.sub(r"[^A-Z0-9]+", "_", "_".join(parts).upper().replace("PULL_REQUEST", "PR")).strip("_") or "VALUE"
    return "EVENT_" + name if name in _ENV_RESERVED or name[0].isdigit() else name


def _gha_env(c: _Ctx) -> _Out:
    if "windows" in c.text.lower() or re.search(r"(?mi)^\s*shell\s*:\s*['\"]?(?!bash\b|sh\b)\w", c.text):
        raise _Skip                                           # "$VAR" is POSIX shell syntax
    bodies = [_body(ln) for ln in c.lines]
    at = c.line - 1
    if not 0 <= at < len(bodies) or any("\t" in b[:len(b) - len(b.lstrip())] for b in bodies):
        raise _Skip
    run = None
    for i in range(at, max(-1, at - 300), -1):
        m = re.match(r"^( *)(- +)?run\s*:(.*)$", bodies[i])
        if m:
            run = (i, len(m.group(1)) + len(m.group(2) or ""), m.group(3).strip(), m.start(3))
            break
    if run is None:
        raise _Skip
    ri, col, value, vpos = run
    if "<<" in value or any("<<" in bodies[j] for j in range(ri + 1, at + 1)):
        raise _Skip                                           # a heredoc: the text is data, "$VAR" may stay literal
    if any(bodies[j].strip() and _indent(bodies[j]) <= col for j in range(ri + 1, at + 1)):
        raise _Skip                                           # the expression is not inside this run: script
    if value[:1] in ("'", '"'):
        raise _Skip
    block = bool(re.fullmatch(r"[|>][+-]?\d?(\s+#.*)?", value))
    end = next((j for j in range(ri + 1, len(bodies)) if bodies[j].strip() and _indent(bodies[j]) <= col), len(bodies))
    while end - 1 > ri and not bodies[end - 1].strip():
        end -= 1
    # the step: its "- " line and the sibling keys at the same column
    top = ri
    if not re.match(r"^ *- ", bodies[ri]):
        while True:
            top -= 1
            if top < 0:
                raise _Skip
            if bodies[top].strip() and _indent(bodies[top]) < col:
                if not re.match(r"^ {%d}- " % max(col - 2, 0), bodies[top]):
                    raise _Skip
                break
    bottom = end
    while bottom < len(bodies) and (not bodies[bottom].strip() or _indent(bodies[bottom]) >= col):
        bottom += 1
    env_line = None
    taken = set(re.findall(r"(?m)^\s*(?:- +)?([A-Za-z_]\w*)\s*:", c.text))    # no clash with any key / variable
    for j in range(top, bottom):
        m = re.match(r"^( *)(- +)?env\s*:(.*)$", bodies[j])
        if m and len(m.group(1)) + len(m.group(2) or "") == col:
            if m.group(3).strip() and not m.group(3).strip().startswith("#"):
                raise _Skip                                   # inline mapping: env: {A: b}
            env_line = j
    names: dict[str, str] = {}
    new = list(bodies)
    for j in ([ri] if not block else []) + list(range(ri + 1, end)):
        start = vpos if j == ri else 0
        text = bodies[j]
        out, pos, quote = [text[:start]], start, ""
        for m in re.finditer(r"\\.|['\"]|\$\{\{.*?\}\}", text[start:]):
            s, e = m.start() + start, m.end() + start
            tok = m.group(0)
            out.append(text[pos:s])
            pos = e
            if tok in ("'", '"'):
                quote = "" if quote == tok else (quote or tok)
                out.append(tok)
                continue
            em = _GHA_EXPR.fullmatch(tok)
            if not em:
                out.append(tok)
                continue
            if quote == "'":
                raise _Skip                                   # a shell variable is not expanded in single quotes
            expr = em.group(1)
            if expr not in names:
                var, n = _gha_var(expr), 2
                base = var
                while var in taken or var in names.values():
                    var, n = f"{base}_{n}", n + 1
                names[expr] = var
            out.append("${%s}" % names[expr] if quote else '"${%s}"' % names[expr])
        if quote:
            raise _Skip                                       # a quoted string spans lines: context unknown
        out.append(text[pos:])
        new[j] = "".join(out)
    if not names:
        raise _Skip
    entries = [f"{var}: ${{{{ {expr} }}}}" for expr, var in names.items()]
    eols = [ln[len(_body(ln)):] or c.eol for ln in c.lines]
    lines = [b + e for b, e in zip(new, eols)]
    if lines and not _EOL_RE.search(lines[-1]):
        lines[-1] += c.eol
    if env_line is not None:
        k = env_line + 1
        child = _indent(bodies[k]) if k < len(bodies) and bodies[k].strip() and _indent(bodies[k]) > col else col + 2
        lines[k:k] = [" " * child + x + c.eol for x in entries]
    else:
        lines[end:end] = [" " * col + "env:" + c.eol] + [" " * (col + 2) + x + c.eol for x in entries]
    return _Out("".join(lines), "gha_env")


# ====================================================================== registry

@dataclass(frozen=True)
class Fixer:
    name: str
    func: object
    kinds: frozenset                      # file extensions (or "<dockerfile>")
    rules: frozenset = frozenset()        # rule ids it answers
    cwes: frozenset = frozenset()         # ... or any rule with this CWE (for rules added later)
    recheck: bool = True                  # the raising line rule must no longer match the rewritten lines
    file_level: bool = False              # works for findings without a line


def _fx(name, func, kinds, rules=(), cwes=(), **kw) -> Fixer:
    return Fixer(name, func, frozenset(kinds), frozenset(rules), frozenset(cwes), **kw)


FIXERS: list[Fixer] = [
    _fx("py-yaml-safe-load", _py_yaml, PY_EXT, ("DES002", "vql/yaml-load-without-loader", "DF006")),
    _fx("py-subprocess-argv", _py_shell, PY_EXT, ("EXE004",)),
    _fx("py-jwt-verify", _py_jwt, PY_EXT, ("CFG007", "vql/jwt-weak-verification")),
    _fx("py-tls-verify", _py_verify, PY_EXT, ("CRY002", "CFG007", "vql/tls-verify-disabled")),
    _fx("py-strong-hash", _py_hash, PY_EXT, ("CRY001",)),
    _fx("py-secrets-random", _py_random, PY_EXT, ("RND001", "CRY005", "vql/random-for-secret")),
    _fx("py-flask-debug", _py_debug, PY_EXT, ("CFG001",)),
    _fx("py-xxe-flags", _py_xxe_flags, PY_EXT, ("XXE001",)),
    _fx("py-defusedxml", _py_defusedxml, PY_EXT, (), ("CWE-611",)),
    _fx("py-mark-safe-escape", _py_mark_safe, PY_EXT, ("DF013", "DF024", "DF021")),
    _fx("py-cookie-flags", _py_cookie, PY_EXT, ("COOK001", "COOK002")),
    _fx("py-sql-parameters", _py_sql, PY_EXT, ("INJ001", "DF004", "DF023", "vql/sql-built-with-format")),
    _fx("js-execfile", _js_exec, JS_EXT, ("EXE005", "DF002", "DF003")),
    _fx("js-textcontent", _js_innerhtml, WEB_EXT, ("INJ004", "DF013", "DF021", "DF024")),
    _fx("js-json-parse", _js_eval, WEB_EXT, ("EXE002", "DF001")),
    _fx("js-cookie-flags", _js_cookie, JS_EXT, ("vql/js-cookie-insecure",)),
    _fx("js-tls-verify", _js_tls, JS_EXT, ("CRY002",)),
    _fx("java-sha256", _java_digest, JVM_EXT, ("CRY001", "CRY102")),
    _fx("java-securerandom", _java_random, JAVA_EXT, ("RND001", "CRY005")),
    _fx("java-cookie-secure", _java_cookie, JVM_EXT, ("COOK001",)),
    _fx("java-xxe-flags", _java_xxe_flags, JVM_EXT, ("XXE001",)),
    _fx("java-xxe-harden-factory", _java_dbf, JAVA_EXT, (), ("CWE-611",)),
    _fx("java-sql-prepared-advice", _java_sql_note, JVM_EXT, ("INJ002", "DF004", "DF023")),
    _fx("dockerfile-user", _docker_user, DOCKER, ("DKR000", "DKR013"), file_level=True),
    _fx("k8s-no-privilege-escalation", _k8s_ape, YAML_EXT, ("K8S001",)),
    _fx("k8s-run-as-non-root", _k8s_nonroot, YAML_EXT, ("K8S006",)),
    _fx("k8s-add-run-as-non-root", _k8s_add_nonroot, YAML_EXT, ("K8S010",)),
    # CI001 is a plain line pattern that also matches the env: entry the remediation itself creates, so its
    # re-check is skipped (the script line is what gets fixed); GHA002 is key-aware and is re-checked.
    _fx("gha-untrusted-context-to-env", _gha_env, YAML_EXT, ("GHA002",)),
    _fx("gha-event-context-to-env", _gha_env, YAML_EXT, ("CI001",), recheck=False),
]


def fixable_rules(auto_only: bool = False) -> list[str]:
    """Rule ids that have a fixer (auto_only: leave out the advice-only ones)."""
    out: set[str] = set()
    for fx in FIXERS:
        if auto_only and fx.func is _java_sql_note:
            continue
        out |= fx.rules
    if auto_only:
        out -= {"INJ002"}
    return sorted(out)


# ====================================================================== verification

def _balance(text: str) -> tuple[int, int, int]:
    return (text.count("(") - text.count(")"), text.count("[") - text.count("]"), text.count("{") - text.count("}"))


def _parses(ctx: _Ctx, new: str, changed: list[str]) -> bool:
    """The rewritten file is still well-formed for its language."""
    if ctx.ext in PY_EXT:
        try:
            ast.parse(new)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return False
        return True
    if ctx.ext == ".json":
        try:
            json.loads(new)
        except ValueError:
            return False
        return True
    if ctx.ext in YAML_EXT:
        return not any("\t" in ln[:len(ln) - len(ln.lstrip())] for ln in changed)
    if ctx.ext in WEB_EXT | JVM_EXT:
        return _balance(new) == _balance(ctx.text)
    return True


def _still_flagged(rule_id: str, changed: list[str]) -> bool:
    rule = _LINE_RULES.get(rule_id)
    if rule is None:
        return False
    return any(rule.pattern.search(ln) and not (rule.skip and rule.skip.search(ln)) for ln in changed)


def _opcodes(old: list[str], new: list[str]):
    """Line opcodes old -> new, trimmed of the common prefix / suffix first (files are mostly unchanged)."""
    pre = 0
    while pre < len(old) and pre < len(new) and old[pre] == new[pre]:
        pre += 1
    suf = 0
    while suf < len(old) - pre and suf < len(new) - pre and old[-1 - suf] == new[-1 - suf]:
        suf += 1
    a, b = old[pre:len(old) - suf], new[pre:len(new) - suf]
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag != "equal":
            yield i1 + pre, i2 + pre, j1 + pre, j2 + pre


def _edits(rel: str, old: list[str], new: list[str]) -> list[dict]:
    out = []
    for i1, i2, j1, j2 in _opcodes(old, new):
        repl = "".join(new[j1:j2])
        if i1 == i2 or not repl:                 # insertion / deletion: rewrite a neighbouring line with it
            if i2 < len(old):
                repl += old[i2]
                i2 += 1
            elif i1 > 0:
                i1 -= 1
                prev = old[i1]
                repl = (prev if _EOL_RE.search(prev) or not repl else prev + "\n") + repl
            else:
                continue
        out.append({"file": rel, "start_line": i1 + 1, "end_line": i2, "replacement": repl})
    return out


def _diff(rel: str, old: list[str], new: list[str]) -> str:
    lines = difflib.unified_diff([_body(x) for x in old], [_body(x) for x in new], f"a/{rel}", f"b/{rel}", lineterm="")
    text = "\n".join(lines)
    return text + "\n" if text else ""


def apply_edits(text: str, edits: list[dict]) -> str:
    """Apply a fix's edits (1-based inclusive full-line replacements) to a file's text."""
    lines = split_lines(text)
    last = len(lines) + 1
    for e in sorted(edits, key=lambda e: e["start_line"], reverse=True):
        s, t = int(e["start_line"]), int(e["end_line"])
        if not (1 <= s <= t < last):
            raise ValueError("overlapping or out-of-range edits")
        lines[s - 1:t] = [e["replacement"]]
        last = s
    return "".join(lines)


# ====================================================================== public API

def _run_fixers(finding: Finding, text: str, rel: str, line: int) -> tuple[str, str, bool] | None:
    ctx = _Ctx(finding, text, rel, line)
    kinds = ctx.kinds
    for fx in FIXERS:
        if not (fx.kinds & kinds) or not (finding.rule_id in fx.rules or (finding.cwe and finding.cwe in fx.cwes)):
            continue
        if line <= 0 and not fx.file_level:
            continue
        try:
            out = fx.func(ctx)
        except _Skip:
            continue
        except (IndexError, KeyError, ValueError, TypeError, AttributeError, RecursionError, UnicodeError):
            continue                                  # an unexpected shape is "no fix", never a crashed scan
        if out.advice_only:
            return text, out.key, True
        if out.text == text:
            continue
        old, new = ctx.lines, split_lines(out.text)
        changed = [_body(new[j]) for _, _, j1, j2 in _opcodes(old, new) for j in range(j1, j2)]
        if not _parses(ctx, out.text, changed):
            continue
        if fx.recheck and _still_flagged(finding.rule_id, changed):
            continue
        return out.text, out.key, False
    return None


def compute_fix(finding: Finding, text: str, rel: str | None = None, line: int | None = None) -> dict | None:
    """The fix for `finding` in a file whose current content is `text`, or None when no safe fix exists.

    `line` overrides the finding's line (an editor buffer, or a file other fixes already changed)."""
    rel = (rel or finding.file).replace("\\", "/")
    if finding.source not in _SOURCES or finding.extra.get("archive_member") or "!" in rel:
        return None
    res = _run_fixers(finding, text, rel, finding.line if line is None else line)
    if res is None:
        return None
    new_text, key, advice_only = res
    ar = D[key]
    fix = {"description": to_en(ar), "description_ar": ar, "diff": "", "edits": []}
    if not advice_only:
        old, new = split_lines(text), split_lines(new_text)
        fix["edits"] = _edits(rel, old, new)
        fix["diff"] = _diff(rel, old, new)
        if not fix["edits"] or apply_edits(text, fix["edits"]) != new_text:
            return None
    return fix


def _base(root) -> tuple[pathlib.Path, pathlib.Path | None]:
    """(directory findings are relative to, the only file that may be touched when the target is one file)."""
    root = pathlib.Path(root)
    return (root.parent, root) if root.is_file() else (root, None)


def _safe_path(root, rel: str) -> pathlib.Path | None:
    """The real file of a finding, only when it lies inside the scan root (no archive member, no symlink out)."""
    base, only = _base(root)
    if not rel or "!" in rel or rel.startswith(("http://", "https://")):
        return None
    try:
        base_r = base.resolve()
        path = (only if only is not None and pathlib.PurePath(rel).name == only.name else base / rel)
        real = path.resolve()
        if only is not None and real != only.resolve():
            return None
        if not real.is_file() or path.is_symlink() or not real.is_relative_to(base_r):
            return None
    except (OSError, ValueError):
        return None
    return real


def _read(path: pathlib.Path) -> str | None:
    try:
        raw = path.read_bytes()
        if len(raw) > 2_000_000 or b"\0" in raw:
            return None
        return raw.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _candidate(f: Finding) -> bool:
    if f.source not in _SOURCES:
        return False
    return any(f.rule_id in fx.rules or (f.cwe and f.cwe in fx.cwes) for fx in FIXERS)


def attach_fixes(findings: list[Finding], root) -> int:
    """Compute the fix of every finding under `root` and store it in ``finding.extra["fix"]``.
    Returns how many findings got one. Never raises: a file that cannot be read simply has no fixes."""
    texts: dict[str, str | None] = {}
    n = 0
    for f in findings:
        f.extra.pop("fix", None)
        if not _candidate(f):
            continue
        if f.file not in texts:
            path = _safe_path(root, f.file)
            texts[f.file] = _read(path) if path else None
        text = texts[f.file]
        if text is None:
            continue
        try:
            fix = compute_fix(f, text)
        except Exception:  # noqa: BLE001 - a fixer bug must never break a scan
            fix = None
        if fix:
            f.extra["fix"] = fix
            n += 1
    return n


def fix_text(text: str, rel: str, findings: list[Finding]) -> tuple[str, dict[int, str]]:
    """Apply the fixes of several findings of one file, one after the other, following each finding's line through
    the earlier rewrites. Returns (new text, {index in `findings`: "fixed" | "covered" | "advice" | "none"});
    "covered" = its line was already rewritten by the fix of another finding (several rules often flag one line)."""
    cur = text
    n = len(split_lines(text))
    pos: list[int | None] = list(range(n + 1))             # original 1-based line -> current line
    status: dict[int, str] = {}
    for idx in sorted(range(len(findings)), key=lambda i: (findings[i].line, findings[i].rule_id)):
        f = findings[idx]
        if not 0 <= f.line <= n:
            status[idx] = "none"                           # a stale line number: nothing to fix (not "covered")
            continue
        line = pos[f.line]
        if line is None:
            status[idx] = "covered"
            continue
        fix = compute_fix(f, cur, rel, line=line)
        if fix is None:
            status[idx] = "none"
            continue
        if not fix["edits"]:
            status[idx] = "advice"
            continue
        new = apply_edits(cur, fix["edits"])
        old_lines, new_lines = split_lines(cur), split_lines(new)
        move: dict[int, int | None] = {}
        prev_i = prev_j = 0
        for i1, i2, j1, j2 in list(_opcodes(old_lines, new_lines)) + [(len(old_lines), len(old_lines), len(new_lines), len(new_lines))]:
            for k in range(i1 - prev_i):
                move[prev_i + k + 1] = prev_j + k + 1
            for k in range(i1, i2):
                move[k + 1] = None
            prev_i, prev_j = i2, j2
        pos = [0] + [move.get(p) if p is not None else None for p in pos[1:]]
        cur = new
        status[idx] = "fixed"
    return cur, status


@dataclass
class FixReport:
    files: dict[str, tuple[str, str]] = field(default_factory=dict)    # rel -> (old text, new text), changed files
    fixed: list[Finding] = field(default_factory=list)
    covered: list[Finding] = field(default_factory=list)
    advice: list[Finding] = field(default_factory=list)
    unfixable: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)                     # files that could not be written

    def diff(self) -> str:
        return "".join(_diff(rel, split_lines(old), split_lines(new)) for rel, (old, new) in sorted(self.files.items()))


def apply_fixes(findings: list[Finding], root, dry_run: bool = False) -> FixReport:
    """Fix every fixable finding under `root` in place (or only compute the result with dry_run).
    Files outside the scan root, archive members and unreadable / non-UTF-8 files are never touched."""
    rep = FixReport()
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        if _candidate(f):
            by_file.setdefault(f.file, []).append(f)
        else:
            rep.unfixable.append(f)
    for rel, group in sorted(by_file.items()):
        path = _safe_path(root, rel)
        text = _read(path) if path else None
        if text is None:
            rep.unfixable += group
            continue
        try:
            new, status = fix_text(text, rel, group)
        except Exception:  # noqa: BLE001
            rep.unfixable += group
            continue
        ctx = _Ctx(group[0], text, rel, 0)
        if new != text and not _parses(ctx, new, split_lines(new)):
            rep.unfixable += group                       # the combination does not parse: leave the file alone
            continue
        if new != text and not dry_run:
            try:
                st = path.stat()
                if not st.st_mode & 0o222 or st.st_nlink > 1:
                    # read-only (even for root, who could write it anyway) or a hard link: an in-place write
                    # would also change the other names of the file, possibly outside the scan root
                    raise PermissionError(rel)
                if _read(path) != text:
                    raise OSError(rel)                     # changed since it was read: never overwrite it
                path.write_bytes(new.encode("utf-8"))
            except OSError:
                rep.errors.append(rel)
                rep.unfixable += group
                continue
        if new != text:
            rep.files[rel] = (text, new)
        for i, f in enumerate(group):
            {"fixed": rep.fixed, "covered": rep.covered, "advice": rep.advice}.get(status.get(i, "none"),
                                                                                  rep.unfixable).append(f)
    return rep


def git_dirty(root, files: list[str] | None = None) -> list[str] | None:
    """Uncommitted paths that make an in-place fix unsafe to undo: tracked files with changes anywhere under the
    scan root, plus any of `files` (the ones about to be rewritten) that is untracked, ignored or modified.
    None when the root is not inside a git work tree (or git is unavailable); [] when clean."""
    base, _only = _base(root)
    # The scanned tree may carry a hostile .git/config (an unpacked archive can ship one): "git status" would run
    # its core.fsmonitor command, and a content filter (filter.<name>.clean / process) on any file whose index
    # entry is stale. The command line switches off what can be switched off; filters cannot be, so a repository
    # that defines one (other than Git LFS) is reported by git_unsafe() and git status is not run at all.
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_NO_LAZY_FETCH="1", GIT_ALLOW_PROTOCOL="none",
               GIT_TERMINAL_PROMPT="0")
    hardening = ["-c", "core.fsmonitor=false", "-c", f"core.hooksPath={os.devnull}", "-c", "core.pager=cat",
                 "-c", "diff.external=", "--no-pager"]

    def git(*args) -> str | None:
        try:
            p = subprocess.run(["git", *hardening, "--literal-pathspecs", "-C", str(base), *args],
                               capture_output=True, text=True, timeout=30, env=env, stdin=subprocess.DEVNULL,
                               encoding="utf-8", errors="replace")
        except (OSError, subprocess.SubprocessError):
            return None
        return p.stdout if p.returncode == 0 else None

    if (git("rev-parse", "--is-inside-work-tree") or "").strip() != "true":
        return None
    risky = git_unsafe(root)
    if risky:                        # fail closed: never run git status there, and never call the tree clean
        return [f".git/config: {key}" for key in risky]
    out = git("status", "--porcelain", "--untracked-files=no", "--", ".")
    if out is None:
        return None
    dirty = [ln[3:] for ln in out.splitlines() if ln.strip()]
    if files:
        # untracked or git-ignored: no committed copy to go back to
        out = git("status", "--porcelain", "--untracked-files=all", "--ignored=matching", "--", *files)
        dirty += [ln[3:] for ln in (out or "").splitlines() if ln.strip()]
    return sorted(set(dirty))


def git_unsafe(root) -> list[str]:
    """Keys of the repository's own git configuration that would make ``git status`` run a command and that no
    command-line switch can turn off: content filters other than Git LFS. Reading the configuration runs nothing."""
    from .mcp import _repo_git_commands                  # the same check guards the MCP server's diff_base
    base, _only = _base(root)
    try:
        return _repo_git_commands(str(base))
    except Exception:  # noqa: BLE001 - cannot tell: treat as unsafe rather than run git on a hostile tree
        return ["filter.?"]


# ====================================================================== command line (--fix / --fix-dry-run)

MSG = {
    "dirty": "رُفض --fix: في شجرة git تغييرات غير مودَعة؛ أودِعها أولًا أو استخدم --fix-force.",
    "unsafe_git": "رُفض --fix: إعدادات git في هذا المستودع تعرّف مرشّح محتوى يشغّل أمرًا، فلم يُشغَّل git للتحقق من "
                  "التغييرات غير المودَعة؛ راجع ‎.git/config أو استخدم --fix-force.",
    "rescan": "أعد الفحص للتحقق من النتائج المتبقية.",
    "local_only": "--fix و--fix-dry-run يحتاجان مجلدًا أو ملفًا محليًا (لا عنوان ويب ولا أرشيفًا).",
}


def run_cli(findings: list[Finding], target: str, dry_run: bool, force: bool = False, lang: str = "both") -> int:
    """`vulnscan PATH --fix` / `--fix-dry-run`. The dry run prints the unified diffs on stdout (a valid patch) and
    the summary on stderr; --fix rewrites the files and prints the summary. Returns the process exit code."""
    def m(text: str) -> str:
        return localize(text, lang)

    rep = apply_fixes(findings, target, dry_run=True)            # plan first: nothing is written yet
    if not dry_run and rep.files:
        if not force:
            risky = git_unsafe(target)
            if risky:
                print(f"✖ {m(MSG['unsafe_git'])}", file=sys.stderr)
                for name in risky[:20]:
                    print(f"    {name}", file=sys.stderr)
                return 2
            dirty = git_dirty(target, sorted(rep.files))
            if dirty:
                print(f"✖ {m(MSG['dirty'])}", file=sys.stderr)
                for name in dirty[:20]:
                    print(f"    {name}", file=sys.stderr)
                return 2
        rep = apply_fixes(findings, target)
    out = sys.stderr if dry_run else sys.stdout
    if dry_run:
        sys.stdout.write(rep.diff())
        print(m(f"إصلاح آلي (تجربة دون تعديل): {len(rep.fixed)} إصلاحًا متاحًا في {len(rep.files)} ملفًا."), file=out)
    else:
        print(m(f"إصلاح آلي: طُبّق {len(rep.fixed)} إصلاحًا في {len(rep.files)} ملفًا."), file=out)
    for rel in sorted(rep.files):
        print(f"  ✔ {rel}", file=out)
    if rep.covered:
        print(m(f"نتائج أُصلحت ضمن إصلاح آخر على السطر نفسه: {len(rep.covered)}."), file=out)
    if rep.advice:
        print(m(f"نتائج لها اقتراح يدوي فقط: {len(rep.advice)}."), file=out)
    if rep.unfixable:
        print(m(f"نتائج بلا إصلاح آلي: {len(rep.unfixable)}."), file=out)
    if rep.errors:
        print("✖ " + m(f"تعذّرت الكتابة إلى: {', '.join(rep.errors)}"), file=sys.stderr)
        return 2
    if rep.files and not dry_run:
        print(m(MSG["rescan"]), file=out)
    return 0
