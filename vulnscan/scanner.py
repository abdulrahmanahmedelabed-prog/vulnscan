"""Walks a target (directory, file or archive) and applies the built-in rules."""

from __future__ import annotations

import fnmatch
import math
import os
import pathlib
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

from .model import Finding
from .rules import RULES, SENSITIVE_FILES, Rule
from . import taint, vql
from .plsql_frontend import PLSQL_EXTS
from . import apex_export, stored

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__",
    ".dart_tool", "build", "dist", "target", ".gradle", ".idea", ".vscode", "Pods",
    ".next", ".nuxt", "coverage", ".pytest_cache", ".mypy_cache", ".tox", "vendor",
    "third_party", "site-packages", ".terraform", "bin", "obj",
}
SKIP_FILE_GLOBS = (
    "*.min.js", "*.min.css", "*.map", "*.lock", "package-lock.json", "yarn.lock",
    "pnpm-lock.yaml", "*.svg", "*.ttf", "*.otf", "*.woff*", "*.png", "*.jpg",
    "*.jpeg", "*.gif", "*.ico", "*.pdf", "*.mp3", "*.wav", "*.mp4", "*.zip",
    "*.gz", "*.bin", "*.so", "*.dylib", "*.dll", "*.class", "*.jar", "*.pyc",
    "*.wasm", "*.dex", "*.vql", "go.sum",
)
ARCHIVE_EXTS = (".zip", ".jar", ".war", ".ear", ".apk", ".aar", ".whl", ".ipa", ".nupkg",
                ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_PLSQL_BYTES = 64 * 1024 * 1024
# Binary bundles jadx can decompile (Java/Kotlin bytecode and Android packages).
JADX_EXTS = (".apk", ".jar", ".aar", ".war", ".ear", ".dex", ".class", ".aab", ".xapk")
# Third-party packages inside decompiled bundles: scanning them floods the
# report with issues the user cannot fix. Disabled with jadx_include_libs.
JADX_LIB_EXCLUDES = [
    "sources/android/*", "sources/androidx/*", "sources/kotlin/*", "sources/kotlinx/*", "sources/java/*",
    "sources/javax/*", "sources/com/google/*", "sources/com/android/*", "sources/okhttp3/*", "sources/okio/*",
    "sources/io/flutter/*", "sources/org/apache/*", "sources/com/squareup/*", "sources/retrofit2/*",
    "sources/dagger/*", "sources/io/reactivex/*", "sources/org/jetbrains/*", "sources/com/facebook/*",
    "sources/org/intellij/*", "sources/com/fasterxml/*", "sources/org/json/*", "sources/io/sentry/*",
    "sources/com/bumptech/*", "sources/coil/*", "sources/timber/*", "sources/org/slf4j/*", "sources/ch/qos/*",
    "sources/org/springframework/*", "sources/io/netty/*", "sources/scala/*", "sources/org/bouncycastle/*",
    "sources/io/grpc/*", "sources/com/unity3d/*", "sources/com/adjust/*", "sources/com/onesignal/*",
    "resources/META-INF/*", "resources/kotlin/*",
]
MAX_LINE_LEN = 4000
SUPPRESS = re.compile(r"(nosec|vulnscan:\s*ignore|noqa:\s*S\d+)", re.I)
FILE_SUPPRESS = re.compile(r"vulnscan:\s*ignore-file", re.I)

# Rules that apply to CI workflow files only (not every YAML file).
CI_RULE_IDS = {"CI001", "CI002", "CI003", "CI004", "CI005"}


def _ext_keys(path: pathlib.Path) -> set[str]:
    """Keys used to match ``Rule.langs``: the extension and the base name."""
    name = path.name
    keys = {path.suffix.lower(), name}
    if name.startswith("Dockerfile") or name.endswith(".dockerfile"):
        keys.add("Dockerfile")
    if name == ".env" or name.startswith(".env."):
        keys.add(".env")
    return keys


def _is_text(sample: bytes) -> bool:
    return b"\x00" not in sample


def _is_workflow(rel: str) -> bool:
    return rel.startswith(".github/workflows/") or "/.github/workflows/" in rel or rel.startswith(".gitlab-ci")


def iter_files(root: pathlib.Path, excludes: list[str]):
    """Yield (absolute path, relative posix path) for scannable files."""
    if root.is_file():
        yield root, root.name
        return
    for dirpath, dirnames, filenames in os.walk(root):  # nosec - operates on the user's own scan target / our temp dir by design
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not _excluded(d, excludes))
        for fn in sorted(filenames):
            p = pathlib.Path(dirpath) / fn
            rel = p.relative_to(root).as_posix()
            if _excluded(rel, excludes) or _excluded(fn, excludes):
                continue
            yield p, rel


def _excluded(rel: str, excludes: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, pat) for pat in excludes)


# The value must be bound to a secret-like NAME. Supported bindings (the name is checked as a whole identifier,
# by its LAST word, so `author_id`, `secretName`, `token_env`, `R.id.authButton`, i18n keys and imports do not count):
#   name = v · name: v · name => v · name := v · name: Type = v · name: &'static str = v · var name Type = v
#   Type name = v · char name[] = v · #define NAME v · ENV NAME v · ("name", v) · define('NAME', v)
#   key="name" value=v · <name>v</name> · <string name="name">v · Name { get; set; } = v
#   process.env.NAME || v · NAME ?? v · fetch('NAME') { v } · ${name:v} · Authorization: Bearer|Basic|Token v
# An optional call wrapper (`String::from(`, `Some(`) and string prefix (b"", r'', @"", f"") may precede the value.
_NAME = r"(?<![\w.$@\-])([A-Za-z_$@][\w.\-]*)"
_TYPE = r"(?::\s*&?(?:'\w+\s+)?(?:mut\s+)?[\w.:<>\[\]|?]+\s*)?"
_BIND = re.compile(r"""(?x)(?:
      """ + _NAME + r"""(?:\[\d*\])?['"\]]*\s*""" + _TYPE + r"""(?:=|:=|=>|:)               # name [: Type] =
    | """ + _NAME + r"""\s+([\w.<>\[\]*]+)(?:\[\d*\])?\s*=                         # Go `name Type =` / C `Type name =`
    | """ + _NAME + r"""\s*\{\s*(?:get|set|init)\b[^}]*\}\s*=                      # C# auto-property initializer
    | """ + _NAME + r"""\s*(?:\|\||\?\?|\bor\b)                                    # env lookup with a literal fallback
    | ['"]""" + _NAME + r"""['"]\s*,                                                # ("name", value)
    | ['"]""" + _NAME + r"""['"]\s*\)\s*\{                                          # Ruby fetch('NAME') { value }
    | \$\{""" + _NAME + r""":                                                       # Spring ${name:default}
    | \#\s*define\s+""" + _NAME + r"""\s                                            # C #define NAME value
    | \bENV\s+""" + _NAME + r"""\s                                                  # Dockerfile ENV NAME value
    | \b(?:key|name)\s*=\s*['"]""" + _NAME + r"""['"]\s+[\w:\-]*value\s*=          # key="X" value= / android:name= android:value=
    | <\w+\s+name\s*=\s*['"]""" + _NAME + r"""['"][^>]*>                            # <string name="api_key">v
    | <""" + _NAME + r"""(?:\s[^>]*)?>                                               # <password>v</password>
    | \b(?:bearer|basic|token)\s                                                    # Authorization scheme
  )\s*(?:[\w.:]+\(\s*)?(?:@|[bBrRuUfF]{1,2})?['"`]?$""", re.I)
_SECRET_WORDS = frozenset({"secret", "secrets", "token", "password", "passwd", "pwd", "passphrase", "apikey", "auth",
                           "credential", "credentials", "pat", "accesskey", "privatekey", "secretkey", "clientsecret",
                           "authtoken", "pass"})
# `<anything>_KEY` is a key (STRIPE_KEY, OPENAI_KEY, api.key) unless the qualifier makes it a data-structure key.
_NOT_SECRET_KEY = frozenset({"cache", "sort", "primary", "foreign", "partition", "row", "lookup", "hash", "map", "dict",
                             "index", "group", "react", "unique", "composite", "public", "idempotency", "object",
                             "translation", "i18n", "locale", "route", "query", "field", "column", "table", "node",
                             "item", "list", "entry", "event", "message", "storage_path", "dedup", "sharding", "shard",
                             "redis", "lock", "session_cache", "bucket", "s3", "registry", "label", "tag", "id"})
_TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{16,}={0,2}")
_LITERAL = re.compile(r"""(['"`])([^'"`\s]{16,300})\1""")
# Placeholder words are checked against the candidate VALUE only, never the whole line (a comment saying
# "latest" or "contest" must not hide a real key).
_PLACEHOLDER = re.compile(r"(?i)(example|sample|placeholder|changeme|your[_-]|xxxx|dummy|fake|redacted|lorem|"
                          r"00000|12345|abcdef|aaaa|^test|_test_|^sha(?:1|256|384|512)-)")
# Context immediately before the value that marks it as not-a-literal: templating, data URI, Go module sum,
# SOPS-encrypted value (`ENC[AES256_GCM,data:…,iv:…]`).
_VALUE_CONTEXT_SKIP = re.compile(r"(\$\{|\{\{|base64,|\bh1:)\s*$|ENC\[[^\]]*$")
_HEXONLY = re.compile(r"^[0-9a-fA-F]+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SLUG_SHAPE = re.compile(r"^/?[a-z0-9]+(?:[/._\-][a-z0-9]+){2,}/?$|^/?[a-z0-9._\-]*/[a-z0-9._\-/]*$")
# A route or file path made of words (`/api/v2/users-list/ProfileSettings2`): base64 has '/' but no word segments.
_ROUTE_PATH = re.compile(r"^\.{0,2}/|(?:^|/)[a-z]{4,}(?:[-_][a-z0-9]+)*/")
# A secret embedded in a URL's userinfo: scheme://[user]:SECRET@host
_URL_PASSWORD = re.compile(r"://[^\s:/@'\"]*:([^\s@/'\"]{8,})@[\w.\-]")
# Multi-line bindings: the secret's name is on the previous line (k8s env, Terraform variable).
_PREV_NAME = re.compile(r"""^\s*(?:-\s*)?name\s*:\s*['"]?([\w.\-]+)['"]?\s*$|^\s*variable\s+['"]([\w.\-]+)['"]\s*\{""")
_CTX_VALUE = re.compile(r"""^\s*(?:value|default)\s*[:=]\s*['"]?$""")


def _is_slug(tok: str) -> bool:
    """Lowercase path or kebab/snake slug made of words (`emails/password_reset_v2`, `my-app-tls-cert-2024`). A
    segment that is long and mixes letters and digits is random, not a word, so the value is not a slug."""
    if not _SLUG_SHAPE.match(tok):
        return False
    return not any(len(seg) >= 10 and re.search(r"[a-z]", seg) and re.search(r"\d", seg)
                   for seg in re.split(r"[/._\-]+", tok))


def _split_ident(name: str) -> list[str]:
    name = re.sub(r"[^\w.\-]", "", name)                         # `api_key[]`, `$password`, `@token`
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)      # APIToken -> API_Token, DBPassword -> DB_Password
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)          # apiKey -> api_Key
    words = [re.sub(r"(?<=[a-z]{3})\d+$", "", w) for w in re.split(r"[_\-.]+", name.lower())]   # SECRET_KEY2 -> key
    return [w for w in words if w]


def _is_secret_ident(name: str | None) -> bool:
    words = _split_ident(name or "")
    if not words:
        return False
    last = words[-1]
    return last in _SECRET_WORDS or (last == "key" and len(words) > 1 and words[-2] not in _NOT_SECRET_KEY)


def _secret_name(prefix: str, ctx_name: str | None = None) -> bool:
    """Is the text immediately before a value a binding to a secret-like name? Only the last 120 characters
    are examined, so the cost per token is bounded however long the line is."""
    tail = prefix[-120:]
    if ctx_name and _CTX_VALUE.search(tail) and _is_secret_ident(ctx_name):
        return True
    m = _BIND.search(tail)
    if not m:
        return False
    names = [g for g in m.groups() if g]
    return not names or any(_is_secret_ident(n) for n in names)    # no names => the Authorization-scheme form


def _in_url(line: str, start: int) -> bool:
    """Does the token at `start` sit inside a URL (or a path that is part of one)?"""
    head = line[max(0, start - 300):start]
    word_start = max(head.rfind(c) for c in " \t'\"(<>=,`") + 1
    return "://" in head[word_start:] or head[word_start:].startswith("www.")


# Catalogue entry for the entropy detector (it is a function, not a regex Rule, so it is listed explicitly).
ENTROPY_RULE = {"id": "SEC011", "severity": "high", "cwe": "CWE-798",
                "title": "High-entropy string (possible secret)", "title_ar": "سلسلة عالية العشوائية (سرّ محتمل)",
                "advice": "تحقّق: إن كان سرًّا حقيقيًا فأبطله وانقله إلى متغير بيئة أو مدير أسرار."}


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts: dict = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_random(val: str) -> tuple[bool, float]:
    if _PLACEHOLDER.search(val) or _UUID.match(val) or _is_slug(val) or "${" in val or "{{" in val:
        return False, 0.0
    if not any(c.isdigit() for c in val):
        return False, 0.0                 # every trigger needs a digit; words and identifiers are skipped cheaply
    ent = _shannon(val)
    return ent >= 3.5, ent


def _sec011(rel: str, lineno: int, line: str, ent: float, reason: str) -> list[Finding]:
    return [Finding("SEC011", "high", "High-entropy string (possible secret)",
                    "سلسلة عالية العشوائية (سرّ محتمل)", rel, lineno, line.strip()[:200],
                    "تحقّق: إن كان سرًّا حقيقيًا فأبطله وانقله إلى متغير بيئة أو مدير أسرار. "
                    "إن كان قيمة مشروعة (تجزئة، معرّف) فاستثنِ السطر بـ # nosec.",
                    "CWE-798", extra={"entropy": round(ent, 2), "why": reason})]


def _entropy_findings(rel: str, lineno: int, line: str, ctx_name: str | None = None) -> list[Finding]:
    """Generic high-entropy secret detection (gitleaks / trufflehog style), for keys from providers we have no
    explicit pattern for. Triggers:
      1. a random-looking value bound to a secret-like name (`api_key = "…"`, `<password>…`, `ENV TOKEN …`);
         a quoted value is taken whole, so keys with symbols (Django `SECRET_KEY`) are evaluated as one string;
      2. a password in a URL's userinfo (`redis://:…@host`, `https://user:…@github.com`);
      3. a standalone, very-high-entropy base62/base64 run of 40+ characters (not hex, not in a URL, not a cert).
    ``ctx_name`` is a secret name carried over from the previous line (k8s `- name: X` / `value: …`).
    """
    if "-----BEGIN" in line and "PRIVATE" not in line:
        return []                         # one-line PEM certificate / public key (private keys have their own rule)
    # 1a. whole quoted literals bound to a secret name
    for m in _LITERAL.finditer(line):
        val = m.group(2)
        before = line[max(0, m.start() - 120):m.start() + 1]
        if _VALUE_CONTEXT_SKIP.search(before[:-1]) or not _secret_name(before, ctx_name):
            continue
        ok, ent = _looks_random(val)
        if ok:
            return _sec011(rel, lineno, line, ent, "token assigned to a secret-like name")
    # 2. password inside a URL
    for m in _URL_PASSWORD.finditer(line):
        ok, ent = _looks_random(m.group(1))
        if ok or (ent >= 3.0 and len(m.group(1)) >= 12):
            return _sec011(rel, lineno, line, ent, "password embedded in a URL")
    # 1b / 3. bare tokens (YAML, .env, properties, XML text, unquoted values)
    for m in _TOKEN.finditer(line):
        tok = m.group(0)
        if len(tok) < 20 or len(tok) > 200:
            continue
        ok, ent = _looks_random(tok)
        if not ok:
            continue
        before = line[max(0, m.start() - 120):m.start()]
        if _VALUE_CONTEXT_SKIP.search(before):
            continue
        if _secret_name(before, ctx_name):
            return _sec011(rel, lineno, line, ent, "token assigned to a secret-like name")
        mixed = any(c.isupper() for c in tok) and any(c.islower() for c in tok)
        if (mixed and ent >= 4.2 and len(tok) >= 40 and not _HEXONLY.match(tok) and not tok.startswith("MII")
                and not _in_url(line, m.start()) and not _ROUTE_PATH.search(tok)):
            return _sec011(rel, lineno, line, ent, "standalone high-entropy token")
    return []


_PEM_BEGIN = re.compile(r"-----BEGIN ((?:[A-Z0-9]+ )*)(CERTIFICATE|PUBLIC KEY|X509 CRL|CERTIFICATE REQUEST|"
                        r"PGP PUBLIC KEY BLOCK|PGP SIGNATURE|PGP MESSAGE|DH PARAMETERS|EC PARAMETERS)-----")
_PEM_END = re.compile(r"-----END [A-Z0-9 ]+-----")
# Encrypted-at-rest secret stores: the values are ciphertext, safe to commit by design.
_ENCRYPTED_STORE = re.compile(r"(?m)^kind:\s*SealedSecret\b|^sops:\s*$|^\s+mac:\s*ENC\[|ANSIBLE_VAULT;")


def scan_file(path: pathlib.Path, rel: str, rules: list[Rule], ignore_rules: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    if any(fnmatch.fnmatch(path.name, g) for g in SKIP_FILE_GLOBS):
        return findings
    try:
        size = path.stat().st_size
        if size == 0 or size > MAX_FILE_BYTES:
            return findings
        raw = path.read_bytes()
    except OSError:
        return findings
    if not _is_text(raw[:8192]):
        return findings
    text = raw.decode("utf-8", errors="replace")
    if FILE_SUPPRESS.search(text[:2000]):
        return findings
    keys = _ext_keys(path)
    workflow = _is_workflow(rel)
    applicable = [
        r for r in rules
        if r.id not in ignore_rules
        and (r.langs is None or keys & r.langs)
        and (r.id not in CI_RULE_IDS or workflow)
    ]
    if not applicable:
        return findings
    entropy_on = "SEC011" not in ignore_rules and not _ENCRYPTED_STORE.search(text)
    in_pem = False
    ctx_name = None
    for lineno, line in enumerate(text.splitlines(), 1):
        # PEM-armored certificates / public keys: their base64 body is public data, not a secret
        if _PEM_BEGIN.search(line):
            in_pem = not _PEM_END.search(line)
            continue
        if in_pem:
            if _PEM_END.search(line):
                in_pem = False
            continue
        prev_ctx = ctx_name                  # a secret name declared on the line just above (k8s env, Terraform)
        m = _PREV_NAME.search(line)
        ctx_name = (m.group(1) or m.group(2)) if m else None
        if len(line) > MAX_LINE_LEN or SUPPRESS.search(line):
            continue
        line_hits = 0
        for rule in applicable:
            if rule.pattern.search(line) and not (rule.skip and rule.skip.search(line)):
                line_hits += 1
                findings.append(Finding(
                    rule_id=rule.id, severity=rule.severity, title=rule.title, title_ar=rule.title_ar,
                    file=rel, line=lineno, snippet=line.strip()[:200], advice=rule.advice, cwe=rule.cwe,
                ))
        # generic entropy check only if no explicit secret rule already matched this line
        if not line_hits and entropy_on:
            findings.extend(_entropy_findings(rel, lineno, line, prev_ctx))
    return findings


def scan_sensitive_names(rel: str, ignore_rules: set[str]) -> list[Finding]:
    out = []
    for i, (pat, sev, title, title_ar, advice) in enumerate(SENSITIVE_FILES, 1):
        rid = f"FILE{i:03d}"
        if rid in ignore_rules:
            continue
        if pat.search(rel):
            out.append(Finding(rid, sev, title, title_ar, rel, 0, "(file name)", advice, "CWE-538"))
    return out


_DUMP_MARKERS = re.compile(r"^-- (MySQL dump|PostgreSQL database dump|Dumped (from|by) )|^COPY [\w.\"]+ .*FROM stdin;|"
                           r"^-- Oracle (Data Pump|export)|^INSERT INTO ", re.M | re.I)


def scan_sql_dump(rel: str, text: str, ignore_rules: set[str]) -> list[Finding]:
    """A .sql file is only a data dump when its content says so (dump headers, COPY … FROM stdin, many INSERTs);
    PL/SQL packages and APEX exports are source code, not dumps."""
    from .rules import SENSITIVE_FILES as _SF
    rid = next((f"FILE{i:03d}" for i, e in enumerate(_SF, 1) if e[2] == "Database dump/file"), "FILE006")
    if rid in ignore_rules:
        return []
    hits = _DUMP_MARKERS.findall(text[:2_000_000])
    header = re.search(r"^-- (MySQL dump|PostgreSQL database dump|Oracle (Data Pump|export))|FROM stdin;", text[:200_000], re.M | re.I)
    if header or len(hits) >= 50:
        return [Finding(rid, "medium", "Database dump/file", "ملف قاعدة بيانات أو نسخة", rel, 0, "(data dump content)",
                        "لا تضع نسخ قواعد البيانات في المستودع أو الحزمة؛ قد تحتوي بيانات حساسة.", "CWE-538")]
    return []


def scan_project_hygiene(root: pathlib.Path, ignore_rules: set[str]) -> list[Finding]:
    """Checks that look at the project as a whole."""
    out = []
    if not root.is_dir():
        return out
    gi = root / ".gitignore"
    if (root / ".git").exists() and "HYG001" not in ignore_rules:
        patterns = gi.read_text(errors="replace").split() if gi.exists() else []
        if not any(p.strip().rstrip("/") in (".env", "*.env", ".env*") for p in patterns):
            out.append(Finding("HYG001", "low", ".env not ignored by git", "ملف .env غير مُستثنى في .gitignore",
                               ".gitignore", 0, "(project)", "أضف .env إلى .gitignore.", "CWE-538"))
    for name in ("Dockerfile", "server/Dockerfile", "docker/Dockerfile"):
        df = root / name
        if df.exists() and "DKR000" not in ignore_rules:
            txt = df.read_text(errors="replace")
            if not re.search(r"^\s*USER\s+(?!root\b|0\b)\S+", txt, re.M):
                out.append(Finding("DKR000", "medium", "Dockerfile has no USER instruction (runs as root)",
                                   "Dockerfile بلا تعليمة USER (يعمل بصلاحيات root)", name, 0, "(no USER)",
                                   "أضف مستخدمًا غير root وبدّل إليه بتعليمة USER.", "CWE-250"))
    return out


def extract_archive(archive: pathlib.Path) -> pathlib.Path:
    """Extract a zip/tar based archive into a fresh temp directory (safe paths only)."""
    dest = pathlib.Path(tempfile.mkdtemp(prefix="vulnscan-"))
    name = archive.name.lower()
    if name.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
        with tarfile.open(archive) as tf:  # nosec - operates on the user's own scan target / our temp dir by design
            for m in tf.getmembers():
                target = (dest / m.name).resolve()
                if not str(target).startswith(str(dest.resolve())) or m.issym() or m.islnk():
                    continue
                tf.extract(m, dest)  # nosec - operates on the user's own scan target / our temp dir by design
    else:
        with zipfile.ZipFile(archive) as zf:  # nosec - operates on the user's own scan target / our temp dir by design
            for info in zf.infolist():
                target = (dest / info.filename).resolve()
                if not str(target).startswith(str(dest.resolve())):
                    continue
                zf.extract(info, dest)  # nosec - operates on the user's own scan target / our temp dir by design
    return dest


def jadx_available() -> str | None:
    """Path to the jadx CLI if installed (needs a Java runtime)."""
    return shutil.which("jadx")


def decompile_with_jadx(bundle: pathlib.Path, timeout: int = 600) -> tuple[pathlib.Path | None, str]:
    """Decompile an APK/JAR/AAR/DEX with jadx into a fresh temp dir.

    Returns (output directory or None, human note). The caller removes the
    directory when done.
    """
    exe = jadx_available()
    if not exe:
        return None, "jadx غير مثبّت؛ لم يُفكّ تجميع الكود الثنائي (فُحصت الملفات النصية فقط)."
    out = pathlib.Path(tempfile.mkdtemp(prefix="vulnscan-jadx-"))
    cmd = [exe, "-q", "--no-debug-info", "-d", str(out), str(bundle)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        shutil.rmtree(out, ignore_errors=True)  # nosec - operates on the user's own scan target / our temp dir by design
        return None, f"jadx تجاوز المهلة ({timeout} ثانية)؛ جرّب مهلة أكبر."
    except OSError as e:
        shutil.rmtree(out, ignore_errors=True)  # nosec - operates on the user's own scan target / our temp dir by design
        return None, f"تعذّر تشغيل jadx: {e}"
    n_java = sum(1 for _ in out.rglob("*.java"))
    if n_java == 0 and not (out / "resources").exists():
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        shutil.rmtree(out, ignore_errors=True)  # nosec - operates on the user's own scan target / our temp dir by design
        return None, "jadx لم يُنتج أي ملفات" + (f": {err[-1][:160]}" if err else ".")
    note = f"jadx: فُكّ تجميع {n_java} ملف Java"
    if proc.returncode != 0:
        note += " (مع أخطاء جزئية في بعض الدوال)"
    return out, note + "."


def is_jadx_bundle(path: pathlib.Path) -> bool:
    return path.is_file() and path.name.lower().endswith(JADX_EXTS)


def is_archive(path: pathlib.Path) -> bool:
    return path.is_file() and path.name.lower().endswith(ARCHIVE_EXTS)


def frontend_notes(projects) -> list[str]:
    """What the language frontends could not parse: one note per file with skipped statements, so nothing is dropped silently."""
    out: list[str] = []
    for proj in projects:
        for rel, d in sorted(getattr(proj, "diagnostics", {}).items()):
            if not d.get("skipped"):
                continue
            lines = ", ".join(str(ln) for ln, _ in d["lines"][:8])
            more = f" …+{d['skipped'] - 8}" if d["skipped"] > 8 else ""
            total = d["statements"] + d["skipped"]
            out.append(f"الواجهة الأمامية ({d['language']}): تخطّت {d['skipped']} من {total} عبارة في {rel} (الأسطر {lines}{more}) — "
                       f"frontend skipped {d['skipped']}/{total} statements in {rel}")
    return out


def scan_path(target: pathlib.Path, excludes: list[str] | None = None,
              ignore_rules: set[str] | None = None, rules: list[Rule] | None = None,
              jadx: bool = True, jadx_timeout: int = 600, jadx_include_libs: bool = False,
              notes: list[str] | None = None, models_dirs: list[str] | None = None,
              query_paths: list[str] | None = None, queries: bool = True) -> tuple[list[Finding], int]:
    """Scan a directory, a single file or an archive. Returns (findings, files_scanned).

    For APK/JAR/AAR/DEX bundles, when ``jadx`` is True and the jadx CLI is
    installed, the bytecode is decompiled and the Java sources plus decoded
    Android resources are scanned too (paths prefixed ``bundle!decompiled/``).
    Human-readable notes about that step are appended to ``notes``.
    """
    excludes = excludes or []
    ignore_rules = ignore_rules or set()
    rules = rules or RULES
    tmp = None
    root = target
    if is_archive(target):
        tmp = extract_archive(target)
        root = tmp
    jadx_dir = None
    try:
        findings: list[Finding] = []
        count = 0
        py_sources: dict[str, str] = {}
        config_values: dict = {}
        if not (root.is_file() and is_jadx_bundle(root)):  # a bare .dex/.class has nothing to walk
            for p, rel in iter_files(root, excludes):
                count += 1
                findings.extend(scan_sensitive_names(rel, ignore_rules))
                findings.extend(scan_file(p, rel, rules, ignore_rules))
                if p.suffix.lower() in (".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
                                        ".java", ".kt", ".kts", ".cs", ".go", ".php", ".phtml",
                                        ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".rs", ".swift", ".rb", ".rake") + PLSQL_EXTS \
                        and not p.name.endswith((".min.js", ".d.ts")):
                    try:
                        # APEX application exports are routinely tens of MB; PL/SQL gets a larger limit
                        limit = MAX_PLSQL_BYTES if p.suffix.lower() in PLSQL_EXTS else MAX_FILE_BYTES
                        if p.stat().st_size <= limit:
                            py_sources[rel] = p.read_text("utf-8", errors="replace")
                            if p.suffix.lower() == ".sql":
                                findings.extend(scan_sql_dump(rel, py_sources[rel], ignore_rules))
                    except OSError:
                        pass
                if stored.is_config_file(rel):
                    try:
                        if p.stat().st_size <= 1_000_000:
                            config_values.update(stored.parse_config(rel, p.read_text("utf-8", errors="replace")))
                    except OSError:
                        pass
                if p.suffix.lower() in (".yaml", ".yml", ".xml", ".json") and not p.name.endswith(".min.json") and rel not in py_sources:
                    # APEX readable exports, Liquibase/SQLcl changelogs and ORDS definitions carry Oracle code
                    try:
                        if p.stat().st_size <= MAX_PLSQL_BYTES:
                            text = p.read_text("utf-8", errors="replace")
                            if apex_export.is_oracle_container(text, rel):
                                py_sources[rel] = text
                    except OSError:
                        pass
            findings.extend(scan_project_hygiene(root, ignore_rules))
            if py_sources:  # whole-project cross-file data-flow (taint) analysis: Python + JS/TS, then VQL queries
                projects, flows = taint.analyze_project_full(py_sources, models_dirs, config_values)
                findings.extend(f for f in flows if f.rule_id not in ignore_rules)
                if notes is not None:
                    notes.extend(frontend_notes(projects))
                if queries or query_paths:
                    qf, qnotes = vql.run_queries(projects, flows, query_paths, builtin=queries)
                    findings.extend(f for f in qf if f.rule_id not in ignore_rules)
                    if notes is not None:
                        notes.extend(qnotes)
        if tmp is not None:
            for f in findings:
                f.extra.setdefault("archive_member", f.file)      # stable identity across artifact versions
                f.file = f"{target.name}!{f.file}"
        if jadx and is_jadx_bundle(target):
            jadx_dir, note = decompile_with_jadx(target, jadx_timeout)
            if notes is not None:
                notes.append(note)
            if jadx_dir is not None:
                jadx_ex = excludes + ([] if jadx_include_libs else JADX_LIB_EXCLUDES)
                for p, rel in iter_files(jadx_dir, jadx_ex):
                    count += 1
                    for f in scan_sensitive_names(rel, ignore_rules) + scan_file(p, rel, rules, ignore_rules):
                        f.extra.setdefault("archive_member", f"decompiled/{f.file}")
                        f.file = f"{target.name}!decompiled/{f.file}"
                        f.extra["decompiled"] = True
                        findings.append(f)
        seen = set()
        unique = []
        for f in findings:
            if f.key() not in seen:
                seen.add(f.key())
                unique.append(f)
        return unique, count
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)  # nosec - operates on the user's own scan target / our temp dir by design
        if jadx_dir is not None:
            shutil.rmtree(jadx_dir, ignore_errors=True)  # nosec - operates on the user's own scan target / our temp dir by design
