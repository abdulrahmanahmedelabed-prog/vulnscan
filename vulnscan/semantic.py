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


# ================================================================== Java / Kotlin
_J_PROP = re.compile(r'(\w+)\s*=\s*[\w.]*getProperty\(\s*"([^"]+)"\s*(?:,\s*"([^"]*)")?\s*\)')
_J_ASSIGN_LIT = re.compile(r'\b(?:String\s+|val\s+|var\s+)?(\w+)\s*=\s*"([^"]*)"\s*;?')
_J_GETINSTANCE = re.compile(r'\b(Cipher|KeyGenerator|SecretKeyFactory|MessageDigest)\s*\.\s*getInstance\s*\(\s*("([^"]*)"|(\w+))')
_WEAK_CIPHER = re.compile(r"(?i)^(des|desede|tripledes|3des|rc2|rc4|arcfour|blowfish)\b|/ecb\b")
_WEAK_HASH = re.compile(r"(?i)^(md2|md4|md5|sha|sha-?1|sha1prng)$")
_J_WEAK_RANDOM = re.compile(r"\bnew\s+(?:java\.util\.)?Random\s*\(|\bMath\s*\.\s*random\s*\(|\bThreadLocalRandom\s*\.\s*current\s*\(|"
                            r"\bRandomStringUtils\s*\.\s*random|\bRandomUtils\s*\.\s*next")
_J_SECURITY_CTX = re.compile(r"(?i)Cookie|getSession|token|secret|password|passwd|nonce|salt|otp|csrf|rememberMe|api_?key|"
                             r"sessionId|resetCode|verification")
_J_SET_SECURE_FALSE = re.compile(r"\.\s*setSecure\s*\(\s*false\s*\)")

CATALOGUE += [
    {"id": "CRY101", "severity": "medium", "cwe": "CWE-327", "title": "Weak cipher or mode (DES/3DES/RC4/Blowfish/ECB)",
     "title_ar": "خوارزمية أو نمط تشفير ضعيف (DES/3DES/RC4/Blowfish/ECB)"},
    {"id": "CRY102", "severity": "medium", "cwe": "CWE-328", "title": "Weak hash algorithm (MD5/SHA-1)",
     "title_ar": "خوارزمية تجزئة ضعيفة (MD5/SHA-1)"},
]


def check_java(rel: str, text: str, config: dict, ignore: set) -> list[Finding]:
    """Algorithm names are often read from configuration (`props.getProperty("hashAlg1", "SHA-512")`): resolve
    them from the project's own .properties / .yml values first, then the default, then literals in the method."""
    out: list[Finding] = []
    lines = text.splitlines()
    for start, end in _java_methods(text):
        body = text[start:end]
        base = text.count("\n", 0, start)
        values: dict = {}
        for m in _J_PROP.finditer(body):
            var, key, default = m.group(1), m.group(2), m.group(3)
            values[var] = config.get(key) or config.get(key.lower()) or default
        for m in _J_ASSIGN_LIT.finditer(body):
            values.setdefault(m.group(1), m.group(2))
        for m in _J_GETINSTANCE.finditer(body):
            kind, alg = m.group(1), m.group(3) if m.group(3) is not None else values.get(m.group(4))
            if not alg:
                continue
            ln = base + body.count("\n", 0, m.start()) + 1
            src = lines[ln - 1].strip()[:200] if ln <= len(lines) else ""
            via = "" if m.group(3) is not None else f" (resolved {m.group(4)} = {alg})"
            if kind == "MessageDigest" and _WEAK_HASH.match(alg) and "CRY102" not in ignore:
                out.append(Finding("CRY102", "medium", f"Weak hash algorithm {alg}{via}", "خوارزمية تجزئة ضعيفة",
                                   rel, ln, src, "استخدم SHA-256 أو أقوى، ولكلمات المرور PBKDF2/bcrypt/argon2.", "CWE-328"))
            elif kind != "MessageDigest" and _WEAK_CIPHER.search(alg) and "CRY101" not in ignore:
                out.append(Finding("CRY101", "medium", f"Weak cipher or mode {alg}{via}", "خوارزمية أو نمط تشفير ضعيف",
                                   rel, ln, src, "استخدم AES-GCM (أو ChaCha20-Poly1305) بمفتاح 128/256 بت ومتجه تهيئة عشوائي.",
                                   "CWE-327"))
        if "RND001" not in ignore and _J_SECURITY_CTX.search(body):
            for m in _J_WEAK_RANDOM.finditer(body):
                ln = base + body.count("\n", 0, m.start()) + 1
                out.append(Finding("RND001", "medium", "Predictable random value used in a security context",
                                   "قيمة عشوائية قابلة للتوقع تُستخدم لغرض أمني", rel, ln,
                                   lines[ln - 1].strip()[:200] if ln <= len(lines) else "",
                                   "استخدم java.security.SecureRandom (أو SecureRandom.getInstanceStrong()).", "CWE-330"))
                break
        if "COOK001" not in ignore:
            for m in _J_SET_SECURE_FALSE.finditer(body):
                ln = base + body.count("\n", 0, m.start()) + 1
                out.append(Finding("COOK001", "medium", "Cookie set without the Secure flag (setSecure(false))",
                                   "كوكي بدون علامة Secure", rel, ln, lines[ln - 1].strip()[:200] if ln <= len(lines) else "",
                                   _COOKIE_ADVICE, "CWE-614"))
    return out


_J_METHOD = re.compile(r"(?m)^[ \t]*(?:@\w+(?:\([^)]*\))?\s*)*(?:(?:public|private|protected|static|final|synchronized|"
                       r"abstract|override|suspend|internal|open|fun)\s+)+[\w<>\[\],.? ]*\s*\w+\s*\([^;{]*\)\s*"
                       r"(?:throws [\w., ]+)?(?::\s*[\w<>?, .]+)?\s*\{")


def _java_methods(text: str):
    """(start, end) offsets of method bodies, by brace matching (strings and comments skipped)."""
    spans = []
    for m in _J_METHOD.finditer(text):
        i, depth, n = m.end(), 1, len(text)
        while i < n and depth:
            c = text[i]
            if c == '"' or c == "'":
                q = c
                i += 1
                while i < n and text[i] != q:
                    i += 2 if text[i] == "\\" else 1
            elif text.startswith("//", i):
                j = text.find("\n", i)
                i = n if j < 0 else j
            elif text.startswith("/*", i):
                j = text.find("*/", i + 2)
                i = n if j < 0 else j + 1
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        spans.append((m.end(), i))
    return spans or [(0, len(text))]
