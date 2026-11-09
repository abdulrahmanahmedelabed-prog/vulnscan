"""Semantic (syntax-tree) checks that a line pattern cannot express reliably.

* COOK001 / COOK002 — cookies set without ``secure`` / with ``httponly`` explicitly off (calls often span lines).
* RND001 — a value from a non-cryptographic random generator used as a security value: stored in a session or
  cookie, or bound to a name like ``token`` / ``secret`` / ``password`` / ``nonce`` / ``salt``.

Python only for now (the AST is exact); other languages keep their line rules (CRY005 and friends).
"""

from __future__ import annotations

import ast
import re

from .model import Finding

SECURITY_NAME = re.compile(r"(?i)(session|cookie|token|secret|passw|pwd|nonce|salt|otp|csrf|xsrf|remember|api_?key|"
                           r"auth|credential|signature|(^|_)key$|(^|_)iv$|reset_?code|verification)")
# random-module functions are all predictable (Mersenne Twister); SystemRandom is the exception
_SAFE_RANDOM = {"SystemRandom"}

CATALOGUE = [
    {"id": "COOK001", "severity": "medium", "cwe": "CWE-614", "title": "Cookie set without the Secure flag",
     "title_ar": "كوكي بدون علامة Secure"},
    {"id": "COOK002", "severity": "low", "cwe": "CWE-1004", "title": "Cookie readable by JavaScript (httponly=False)",
     "title_ar": "كوكي يقرؤها JavaScript (httponly=False)"},
    {"id": "RND001", "severity": "medium", "cwe": "CWE-330", "title": "Predictable random value used for security",
     "title_ar": "قيمة عشوائية قابلة للتوقع تُستخدم لغرض أمني"},
]

_COOKIE_ADVICE = ("اضبط secure=True (وhttponly=True وsamesite) عند إنشاء الكوكي، وفعّل SESSION_COOKIE_SECURE "
                  "حتى لا تُرسل الكوكي عبر HTTP غير مشفّر.")
_RND_ADVICE = "استخدم secrets (token_urlsafe / token_hex / randbelow) أو random.SystemRandom للقيم الأمنية."


def check_python(rel: str, tree: ast.AST, ignore: set) -> list[Finding]:
    out: list[Finding] = []
    if "COOK001" not in ignore or "COOK002" not in ignore:
        out.extend(_cookies(rel, tree, ignore))
    if "RND001" not in ignore:
        out.extend(_weak_random(rel, tree))
    return out


# ------------------------------------------------------------------ cookies
def _cookies(rel, tree, ignore):
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("set_cookie", "set_signed_cookie")):
            continue
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        if any(k.arg is None for k in node.keywords):
            continue                                   # **options: cannot tell
        secure = kw.get("secure")
        if "COOK001" not in ignore and (secure is None or (isinstance(secure, ast.Constant) and not secure.value)):
            why = "secure=False" if secure is not None else "no secure flag"
            out.append(Finding("COOK001", "medium", f"Cookie set without the Secure flag ({why})",
                               "كوكي بدون علامة Secure", rel, node.lineno, _src(node), _COOKIE_ADVICE, "CWE-614"))
        httponly = kw.get("httponly")
        if "COOK002" not in ignore and isinstance(httponly, ast.Constant) and httponly.value is False:
            out.append(Finding("COOK002", "low", "Cookie readable by JavaScript (httponly=False)",
                               "كوكي يقرؤها JavaScript (httponly=False)", rel, node.lineno, _src(node),
                               _COOKIE_ADVICE, "CWE-1004"))
    return out


# ------------------------------------------------------------------ weak random
def _weak_random(rel, tree):
    random_mods, random_funcs = {"random"}, set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "random":
                    random_mods.add(a.asname or "random")
        elif isinstance(node, ast.ImportFrom) and node.module == "random":
            for a in node.names:
                if a.name not in _SAFE_RANDOM:
                    random_funcs.add(a.asname or a.name)

    def weak_call(n) -> bool:
        if not isinstance(n, ast.Call):
            return False
        f = n.func
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in random_mods:
            return f.attr not in _SAFE_RANDOM
        if isinstance(f, ast.Name) and f.id in random_funcs:
            return True
        # numpy.random.* / np.random.*
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Attribute) and f.value.attr == "random" \
                and isinstance(f.value.value, ast.Name) and f.value.value.id in ("np", "numpy"):
            return True
        return False

    def uses_weak(expr, names) -> bool:
        for n in ast.walk(expr):
            if weak_call(n) or (isinstance(n, ast.Name) and n.id in names):
                return True
        return False

    out, seen_lines = [], set()
    scopes = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))] + [tree]
    for scope in scopes:
        stmts = [n for n in _own_nodes(scope) if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Expr, ast.Return))]
        weak: set = set()
        changed = True
        while changed:                                  # names holding a weak random value (flow-insensitive)
            changed = False
            for s in stmts:
                if isinstance(s, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and s.value is not None:
                    tgts = s.targets if isinstance(s, ast.Assign) else [s.target]
                    if uses_weak(s.value, weak):
                        for t in tgts:
                            if isinstance(t, ast.Name) and t.id not in weak:
                                weak.add(t.id)
                                changed = True
        for s in stmts:
            hit = None
            if isinstance(s, (ast.Assign, ast.AnnAssign)) and s.value is not None and uses_weak(s.value, weak):
                for t in (s.targets if isinstance(s, ast.Assign) else [s.target]):
                    if isinstance(t, ast.Subscript) and SECURITY_NAME.search(_dotted(t.value)):
                        hit = f"stored in {_dotted(t.value)}[…]"
                    elif isinstance(t, ast.Name) and SECURITY_NAME.search(t.id):
                        hit = f"assigned to {t.id}"
                    elif isinstance(t, ast.Attribute) and SECURITY_NAME.search(t.attr):
                        hit = f"assigned to .{t.attr}"
            if hit is None:
                for c in ast.walk(s):
                    if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr in ("set_cookie", "set_signed_cookie"):
                        if any(uses_weak(a, weak) for a in list(c.args[1:]) + [k.value for k in c.keywords if k.arg == "value"]):
                            hit = "used as a cookie value"
            if hit and s.lineno not in seen_lines:
                seen_lines.add(s.lineno)
                out.append(Finding("RND001", "medium", f"Predictable random value used for security ({hit})",
                                   "قيمة عشوائية قابلة للتوقع تُستخدم لغرض أمني", rel, s.lineno, _src(s), _RND_ADVICE,
                                   "CWE-330"))
    return out


# ------------------------------------------------------------------ helpers
def _own_nodes(scope):
    """Nodes of a scope, not descending into nested functions / classes."""
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield n
        stack.extend(ast.iter_child_nodes(n))


def _dotted(node) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # noqa: BLE001
        return ""


def _src(node) -> str:
    try:
        return " ".join(ast.unparse(node).split())[:200]
    except Exception:  # noqa: BLE001
        return ""
