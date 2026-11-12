"""Walks a target (directory, file or archive) and applies the built-in rules."""

from __future__ import annotations

import fnmatch
import hashlib
import io
import json
import math
import os
import pathlib
import re
import shutil
import subprocess
import sys
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


# --------------------------------------------------------------- path classification (test / docs / vendored)
_TEST_DIRS = frozenset({"test", "tests", "testing", "__tests__", "__test__", "spec", "specs", "e2e", "cypress",
                        "fixtures", "__fixtures__", "testdata", "test_data", "test-data", "__mocks__", "testsuite",
                        "integration-tests", "integration_tests", "unittests", "unit_tests", "functional_tests"})
_DOC_DIRS = frozenset({"doc", "docs", "docs_src", "documentation", "_docs", "site-docs"})
_EXAMPLE_DIRS = frozenset({"example", "examples", "sample", "samples", "demo", "demos", "tutorial", "tutorials",
                           "benchmarks", "sandbox"})
_TEST_FILE = re.compile(r"(?:^test_.*\.py|.*_test\.(?:py|go|rb|exs?)|^conftest\.py|.*\.(?:test|spec|e2e)\.[cm]?[jt]sx?"
                        r"|.*(?:Test|Tests|IT|Spec)\.(?:java|kt|scala|groovy|cs|php|swift)|.*_spec\.rb|.*Tests?\.cs)$")
_VENDOR_DIRS = frozenset({"compiled", "bower_components", "jspm_packages", "web_modules", "external", "externals"})
_VENDOR_STATIC_DIRS = frozenset({"lib", "libs", "vendor", "vendors", "plugins", "third-party", "thirdparty", "3rdparty"})
_VENDOR_NAMES = re.compile(r"(?i)^(?:jquery|bootstrap|materialize|lodash|underscore|backbone|angular|react(?:-dom)?|vue|"
                           r"moment|d3|chart|highcharts|popper|select2|datatables|modernizr|require|handlebars|knockout|"
                           r"ember|prototype|mootools|three|leaflet|codemirror|ace|tinymce|ckeditor|fontawesome|"
                           r"font-awesome|swiper|slick|socket\.io|axios|semantic|foundation|uikit|zepto)"
                           r"(?:[.\-_][\w.\-]*)?\.(?:js|css)$")
_BUNDLE_NAME = re.compile(r"\.(?:production|development|prod|umd|bundle|min)\.[cm]?js$")
_LICENSE_BANNER = re.compile(r"/\*[!*]?[^*]{0,200}?\bv?\d+\.\d+(?:\.\d+)?\b.{0,200}?(?:licen[sc]e|\(c\)|copyright|@preserve)",
                             re.I | re.S)


def path_kind(rel: str) -> str | None:
    """Classify a scanned path: "test", "docs", "example" or None (production code). Directory names are matched
    as whole segments; file names by the usual test-file conventions (test_x.py, x_test.go, x.spec.ts, XTest.java)."""
    parts = rel.replace("\\", "/").split("/")
    dirs, name = [p.lower() for p in parts[:-1]], parts[-1]
    if any(d in _TEST_DIRS for d in dirs) or (dirs and dirs[0] == "t") or _TEST_FILE.match(name):
        return "test"
    if any(d in _EXAMPLE_DIRS for d in dirs):
        return "example"
    if any(d in _DOC_DIRS for d in dirs):
        return "docs"
    return None


def is_vendored(rel: str, head: str = "") -> bool:
    """Third-party code copied into the project (bundles, static libraries): analysed as dependencies, not as the
    project's own code. `head` is the start of the file (a license banner with a version marks a library build)."""
    parts = rel.replace("\\", "/").split("/")
    dirs, name = [p.lower() for p in parts[:-1]], parts[-1]
    if any(d in _VENDOR_DIRS for d in dirs):
        return True
    if not name.lower().endswith((".js", ".cjs", ".mjs", ".css")):
        return False
    if _BUNDLE_NAME.search(name):
        return True
    in_static = any(d in ("static", "public", "assets", "wwwroot", "webroot", "js", "scripts") for d in dirs)
    if in_static and (any(d in _VENDOR_STATIC_DIRS for d in dirs) or _VENDOR_NAMES.match(name)):
        return True
    if head:
        first = "\n".join(head.splitlines()[:5])
        if _LICENSE_BANNER.search(first) and (in_static or len(head) >= 4000 and max(map(len, head.splitlines()[:50] or [""])) > 500):
            return True
    return False


# In test, documentation and example code these rules report fixtures, sample values and illustrations, not
# vulnerabilities in the shipped product: dropped there by default (kept with include_tests).
TEST_NOISE_RULES = frozenset({"SEC011", "SEC004", "NET001", "CFG005", "CFG004", "CRY006", "CRY002", "CFG007", "COOK001",
                              "DF013", "DES003", "RND001", "LOG001", "MOB006", "HYG001", "CI004", "FILE003", "INJ010",
                              "vql/entry-point-without-auth", "vql/hardcoded-password-kwarg", "vql/tls-verify-disabled",
                              "vql/entry-reaches-shell"})


def apply_path_policy(findings: list[Finding], include_tests: bool) -> list[Finding]:
    """Default: findings in test / docs / example code are tagged (extra.path_kind) and lowered to info, and the
    fixture-noise rules are dropped there. include_tests keeps every finding at its own severity."""
    if include_tests:
        return findings
    out = []
    kinds: dict = {}
    for f in findings:
        rel = f.extra.get("archive_member") or f.file
        kind = kinds.get(rel)
        if kind is None:
            kind = kinds[rel] = path_kind(rel) or ""
        if not kind or f.source == "dynamic":
            out.append(f)
            continue
        if f.rule_id in TEST_NOISE_RULES:
            continue
        f.extra["path_kind"] = kind
        f.extra["test"] = True
        if f.severity != "info":
            f.extra["original_severity"] = f.severity
            f.severity = "info"
        out.append(f)
    return out


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


_PATH_LIKE = re.compile(r"^[\w.\-]*(?:/[\w.\-]+){1,}\.(?:html?|jinja2?|j2|txt|md|py|js|ts|css|json|ya?ml|xml|png|jpe?g|gif|svg|"
                        r"pdf|csv|tpl|twig|erb|ejs|hbs|php|rb|java|go|cs|sql|log|ini|cfg|conf)$|^(?:[\w.\-]+/){2,}[\w.\-]*$")


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


# A regular expression, not a key: a character class with a range (`[A-Za-z0-9+/]`), an inline flag group
# (`(?i)`) or a class escape (`\d`, `\w`). Base64/base62/hex secrets never contain `[`, `(` or a backslash.
_REGEX_LIKE = re.compile(r"\[[^\]\s]*[A-Za-z0-9]-[A-Za-z0-9][^\]\s]*\]|\(\?[a-zA-Z:<=!P]|\\[dwsDWS]")


def _looks_random(val: str) -> tuple[bool, float]:
    if _PLACEHOLDER.search(val) or _UUID.match(val) or _is_slug(val) or "${" in val or "{{" in val:
        return False, 0.0
    if _REGEX_LIKE.search(val):
        return False, 0.0                 # a regex literal (`re.compile(r"[A-Za-z0-9+/]{20,}")`), a pattern, not a key
    if _PATH_LIKE.match(val):
        return False, 0.0                 # a file path / template name (`Lab_2021/A2_Crypto/x.html`), not a key
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


# A public Ethereum address (EIP-55 mixed-case checksum): an identifier, not a secret (a private key is 64 hex).
_ETH_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_WORD_SEG = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")


def _wordy(tok: str) -> bool:
    """Is a bare token made of words (`getBase64UrlSafeWithoutPaddingEncodedString`, `Lucky-Waving-Green-Cat-1_25oz`)?
    Random base62/base64 text breaks into short fragments; identifiers and slugs into words of 3+ letters."""
    words = sum(len(s) for s in _WORD_SEG.findall(tok) if len(s) >= 3 and s.isalpha() and not s.isupper())
    return words >= 0.75 * sum(c.isalnum() for c in tok)


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
                and not _in_url(line, m.start()) and not _ROUTE_PATH.search(tok) and not _ETH_ADDRESS.match(tok)
                and not _wordy(tok)):
            return _sec011(rel, lineno, line, ent, "standalone high-entropy token")
    return []


_PEM_BEGIN = re.compile(r"-----BEGIN ((?:[A-Z0-9]+ )*)(CERTIFICATE|PUBLIC KEY|X509 CRL|CERTIFICATE REQUEST|"
                        r"PGP PUBLIC KEY BLOCK|PGP SIGNATURE|PGP MESSAGE|DH PARAMETERS|EC PARAMETERS)-----")
_PEM_END = re.compile(r"-----END [A-Z0-9 ]+-----")
# Encrypted-at-rest secret stores: the values are ciphertext, safe to commit by design.
_ENCRYPTED_STORE = re.compile(r"(?m)^kind:\s*SealedSecret\b|^sops:\s*$|^\s+mac:\s*ENC\[|ANSIBLE_VAULT;")


_PEM_KEY_BEGIN = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
_SCRIPT_OPEN = re.compile(r"(?i)<script\b[^>]*>")
_SCRIPT_CLOSE = re.compile(r"(?i)</script\s*>")
_ON_ATTR = re.compile(r"""(?i)\son[a-z]+\s*=\s*["']|javascript:""")


# Python rules whose pattern describes a CALL or a keyword argument in Python code. A match that starts inside
# a string literal or a comment of a .py file is prose about the construct (a fix description, a message, an
# example), not the construct itself. Value: what the matched text must look like for that to apply (None =
# any match of the rule); CRY002 also matches quoted 'CERT_NONE' and `curl -k`/`--insecure` inside strings on
# purpose, so only its code alternatives are dropped there.
_PY_CODE_ONLY: dict = {
    "CRY002": re.compile(r"verify\s*=\s*False|_create_unverified_context|^(ssl\.)?CERT_NONE$"),
    "CFG007": re.compile(r"verify\s*=\s*False"),
    "CRY001": re.compile(r"^hashlib\.(md5|sha1)$"),     # the name in a string (`q in ("hashlib.md5", …)`), not a call
    "EXE001": None, "EXE004": None, "DES001": None, "DES002": None, "TLS001": None, "TLS007": None,
}
_ODD_NEWLINES = re.compile("[\x0b\x0c\x1c-\x1e\x85\u2028\u2029]|\r(?!\n)")


def _py_inert_spans(text: str) -> dict | None:
    """Per line, the column spans of a Python file's comments ("c") and string literals ("s"). None when the
    file cannot be tokenized, or when its line numbering differs from str.splitlines (odd line separators)."""
    import tokenize
    if _ODD_NEWLINES.search(text):
        return None
    kinds = {tokenize.COMMENT: "c", tokenize.STRING: "s"}
    for name in ("FSTRING_MIDDLE", "TSTRING_MIDDLE"):
        if hasattr(tokenize, name):
            kinds[getattr(tokenize, name)] = "s"
    spans: dict = {}
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            kind = kinds.get(tok.type)
            if kind is None:
                continue
            (sl, sc), (el, ec) = tok.start, tok.end
            for ln in range(sl, el + 1):
                spans.setdefault(ln, []).append((sc if ln == sl else 0, ec if ln == el else 1 << 30, kind))
    except (tokenize.TokenError, SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    return spans


def _py_inert_match(rule: Rule, m: re.Match, spans: list) -> bool:
    """Does this match of `rule` start inside a comment (any non-secret rule) or, for a Python code-construct
    rule, inside a string literal?"""
    pos = m.start()
    for a, b, kind in spans:
        if a <= pos < b:
            if kind == "c":
                return not rule.id.startswith("SEC")
            if rule.id in _PY_CODE_ONLY:
                want = _PY_CODE_ONLY[rule.id]
                return want is None or bool(want.search(m.group(0)))
            return False
    return False


def _script_lines(text: str) -> set:
    """Line numbers of an HTML page that hold JavaScript: <script> bodies and on*= / javascript: attributes."""
    out, inside = set(), False
    for n, line in enumerate(text.splitlines(), 1):
        if inside:
            out.add(n)
            if _SCRIPT_CLOSE.search(line):
                inside = False
            continue
        m = _SCRIPT_OPEN.search(line)
        if m:
            out.add(n)
            inside = not _SCRIPT_CLOSE.search(line, m.end())
        elif _ON_ATTR.search(line):
            out.add(n)
    return out


def _line(text: str, lineno: int) -> str:
    lines = text.splitlines()
    return lines[lineno - 1] if 0 < lineno <= len(lines) else ""


def _skipped_name(name: str) -> bool:
    return any(fnmatch.fnmatch(name, g) for g in SKIP_FILE_GLOBS)


def scan_file(path: pathlib.Path, rel: str, rules: list[Rule], ignore_rules: set[str]) -> list[Finding]:
    if _skipped_name(path.name):
        return []
    try:
        size = path.stat().st_size
        if size == 0 or size > MAX_FILE_BYTES:
            return []
        raw = path.read_bytes()
    except OSError:
        return []
    return _scan_bytes(path, rel, raw, rules, ignore_rules)


def _scan_bytes(path: pathlib.Path, rel: str, raw: bytes, rules: list[Rule], ignore_rules: set[str],
                tree_out: list | None = None) -> list[Finding]:
    """scan_file on content already read (the caller checked the name, the size and that the read worked).
    `tree_out` receives the parsed Python module, so the data-flow step does not parse the file again."""
    findings: list[Finding] = []
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
    doc_lines: set = set()          # lines of Python docstrings: prose / examples, not executed code
    py_tree_ok = False              # a parsed .py file: comments and string literals can be told apart from code
    py_spans: dict | None = None    # computed lazily, on the first rule match on a line with a comment or a quote
    if path.suffix.lower() == ".py":
        try:
            import ast as _ast
            from . import semantic
            tree = _ast.parse(text)
            py_tree_ok = True
            if tree_out is not None:
                tree_out.append((text, tree))
            findings.extend(f for f in semantic.check_python(rel, tree, ignore_rules)
                            if not SUPPRESS.search(_line(text, f.line)))
            for n in _ast.walk(tree):
                if isinstance(n, (_ast.Module, _ast.ClassDef, _ast.FunctionDef, _ast.AsyncFunctionDef)) and n.body \
                        and isinstance(n.body[0], _ast.Expr) and isinstance(n.body[0].value, _ast.Constant) \
                        and isinstance(n.body[0].value.value, str):
                    d = n.body[0]
                    doc_lines.update(range(d.lineno, (d.end_lineno or d.lineno) + 1))
        except (SyntaxError, ValueError, MemoryError, RecursionError):
            pass
    entropy_on = "SEC011" not in ignore_rules and not _ENCRYPTED_STORE.search(text)
    in_pem = False
    in_key = False                   # inside a private-key block: SEC001 reports the block once
    ctx_name = None
    script_lines = _script_lines(text) if path.suffix.lower() in (".html", ".htm", ".xhtml") else None
    for lineno, line in enumerate(text.splitlines(), 1):
        # PEM-armored certificates / public keys: their base64 body is public data, not a secret
        if _PEM_BEGIN.search(line):
            in_pem = not _PEM_END.search(line)
            continue
        if in_pem:
            if _PEM_END.search(line):
                in_pem = False
            continue
        if _PEM_KEY_BEGIN.search(line):
            in_key = not _PEM_END.search(line)
        elif in_key and _PEM_END.search(line):
            in_key = False
            continue
        prev_ctx = ctx_name                  # a secret name declared on the line just above (k8s env, Terraform)
        m = _PREV_NAME.search(line)
        ctx_name = (m.group(1) or m.group(2)) if m else None
        if len(line) > MAX_LINE_LEN or SUPPRESS.search(line):
            continue
        line_hits = 0
        for rule in applicable:
            if lineno in doc_lines and not rule.id.startswith("SEC"):
                continue                    # code examples in docstrings are not code (secrets still count)
            if script_lines is not None and rule.langs is not None and ".js" in rule.langs and lineno not in script_lines:
                continue                    # JavaScript rules in an HTML page: <script> blocks and on*= handlers only
            m = rule.pattern.search(line)
            if m and not (rule.skip and rule.skip.search(line)):
                if py_tree_ok and ("#" in line or "'" in line or '"' in line):
                    if py_spans is None:
                        py_spans = _py_inert_spans(text) or {}
                    sp = py_spans.get(lineno)
                    if sp and _py_inert_match(rule, m, sp) and \
                            all(_py_inert_match(rule, m2, sp) for m2 in rule.pattern.finditer(line)):
                        continue            # only in a comment / in prose inside a string, never as code
                line_hits += 1
                findings.append(Finding(
                    rule_id=rule.id, severity=rule.severity, title=rule.title, title_ar=rule.title_ar,
                    file=rel, line=lineno, snippet=line.strip()[:200], advice=rule.advice, cwe=rule.cwe,
                ))
        # generic entropy check only if no explicit secret rule already matched this line
        if not line_hits and entropy_on and not in_key:
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
    # absolute paths: a file named "-x.apk" can never be read by jadx as an option
    cmd = [exe, "-q", "--no-debug-info", "-d", str(out.resolve()), str(bundle.resolve())]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)  # nosec - absolute paths, no shell
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


# Pattern rules for injection sinks (eval, shell, SQL, deserialization, …) flag the dangerous CALL whatever its
# argument. Where the data-flow engine analyzed the line, it decides instead: a real injection is reported by the
# data-flow rule with its source→sink path; the pattern hit is an audit lead, shown only with --audit (the same
# split as CodeQL's default vs. security-extended suites and Semgrep's audit rules).
AUDIT_WHEN_DATAFLOW = frozenset({
    "EXE001", "EXE002", "EXE003", "EXE004", "EXE005", "EXE006", "EXE007",
    "INJ001", "INJ002", "INJ003", "INJ004", "INJ006", "INJ007", "INJ008",
    "DES001", "DES002", "DES003", "DES004", "DES005",
    "vql/subprocess-shell-true-dynamic", "vql/sql-built-with-format",
})   # yaml.load without a Loader stays on: it is unsafe API misuse whatever the data (PyYAML >= 6 rejects it)


BUDGET_NOTE = ("تجاوز تحليل تدفق البيانات ميزانيته الزمنية فاكتمل بدقة أقل (ملخّصات أقل بين الدوال)؛ نتائج القواعد والأسرار "
               "وما اكتمل من نتائج التدفق محفوظة")
# Structural leads with no data-flow evidence at all (call-graph reachability): audit profile only.
AUDIT_ONLY = frozenset({"vql/entry-reaches-shell"})


def apply_audit_profile(findings: list[Finding], projects, audit: bool) -> list[Finding]:
    """Default profile: drop a pattern injection hit when the data-flow engine analyzed its line and found that the
    dangerous call's argument comes neither from an untrusted source (that is reported by the data-flow rule, with
    its path) nor from a parameter of the enclosing function (a wrapper like `def run(cmd): os.system(cmd)` stays
    reported: its callers control the argument). --audit keeps every hit, marked as an audit lead."""
    analyzed: dict[str, set] = {}
    trees: dict = {}
    param_reach: set = set()        # (path, line) of sinks reachable from a parameter of their function
    for proj in projects or ():
        for summ in (getattr(proj, "summaries", {}) or {}).values():
            for entries in list(summ.get("sink_params", {}).values()) + list(summ.get("sink_fields", {}).values()):
                for e in entries:
                    if len(e) >= 3:
                        param_reach.add((e[1], e[2]))
        diags = getattr(proj, "diagnostics", {}) or {}
        for f in getattr(proj, "files", {}).values():
            path = f.get("path") if isinstance(f, dict) else None
            if path:
                d = diags.get(path) or {}
                analyzed[path] = {ln for ln, _ in d.get("lines", [])}     # skipped lines
                trees[path] = f.get("tree")
    bound_cache: dict = {}
    out = []
    for f in findings:
        if f.rule_id in AUDIT_ONLY:
            if audit:
                f.extra["audit"] = True
                out.append(f)
            continue
        if f.rule_id in AUDIT_WHEN_DATAFLOW and f.file in analyzed and f.line not in analyzed[f.file] \
                and (f.file, f.line) not in param_reach and _all_names_known(trees.get(f.file), f.line, bound_cache):
            if not audit:
                continue
            f.extra["audit"] = True
            f.extra["audit_note"] = "audit lead: no untrusted source was traced to this call by data-flow analysis"
        out.append(f)
    return out


_CONTAINER_CTORS = {"list", "dict", "set", "bytearray", "deque", "defaultdict", "OrderedDict", "Counter", "ChainMap",
                    "SimpleNamespace", "array"}
_MUTATORS = {"append", "extend", "insert", "add", "update", "setdefault", "appendleft", "extendleft", "push", "put",
             "__setitem__", "remove", "pop", "popitem", "clear", "discard", "sort", "reverse"}


def _container_like(fn) -> set:
    """Names in `fn` that may hold a mutable container: bound to a container literal, comprehension or constructor,
    taken out of another value (`opts = conf["opts"]`, `x = obj.items`), mutated in place (`x.append(…)`, `x[k] = …`,
    `x.attr = …`), or bound by unpacking / iteration / with / parameters."""
    import ast as _ast
    out = set()
    a = getattr(fn, "args", None)
    if a is not None:
        out |= {x.arg for x in a.posonlyargs + a.args + a.kwonlyargs + [a.vararg, a.kwarg] if x is not None}
    for n in _ast.walk(fn):
        if isinstance(n, (_ast.Assign, _ast.AnnAssign, _ast.NamedExpr)) and getattr(n, "value", None) is not None:
            v = n.value
            tgts = n.targets if isinstance(n, _ast.Assign) else [n.target]
            mutable = isinstance(v, (_ast.List, _ast.Dict, _ast.Set, _ast.ListComp, _ast.DictComp, _ast.SetComp,
                                     _ast.Subscript, _ast.Attribute, _ast.Name, _ast.Starred, _ast.IfExp, _ast.BoolOp,
                                     _ast.Await, _ast.Yield, _ast.YieldFrom)) or \
                (isinstance(v, _ast.Call) and _call_tail(v) in _CONTAINER_CTORS)
            if isinstance(v, _ast.Subscript) and isinstance(v.slice, _ast.Slice):
                mutable = False                  # a slice is a fresh copy
            for t in tgts:
                if not isinstance(t, _ast.Name):
                    out.update(x.id for x in _ast.walk(t) if isinstance(x, _ast.Name))   # unpacking, x[k] = …
                elif mutable:
                    out.add(t.id)
        elif isinstance(n, (_ast.For, _ast.AsyncFor, _ast.comprehension)):
            out.update(x.id for x in _ast.walk(n.target) if isinstance(x, _ast.Name))
        elif isinstance(n, _ast.withitem) and n.optional_vars is not None:
            out.update(x.id for x in _ast.walk(n.optional_vars) if isinstance(x, _ast.Name))
        elif isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute) and isinstance(n.func.value, _ast.Name) \
                and n.func.attr in _MUTATORS:
            out.add(n.func.value.id)
        elif isinstance(n, (_ast.Subscript, _ast.Attribute)) and isinstance(n.ctx, (_ast.Store, _ast.Del)) \
                and isinstance(n.value, _ast.Name):
            out.add(n.value.id)
    return out


def _call_tail(call) -> str:
    import ast as _ast
    f = call.func
    return f.id if isinstance(f, _ast.Name) else f.attr if isinstance(f, _ast.Attribute) else ""


def _all_names_known(tree, line: int, cache: dict) -> bool:
    """True only when every value read on `line` comes from a plain assignment or a parameter of the enclosing
    function, i.e. a definition the flow-sensitive dataflow analysis actually evaluates. Globals, imported values,
    comprehension / walrus / match-capture variables and nonlocal names are not traced, so they keep the
    pattern finding. Module names used as a call receiver (`os` in os.system) are not values."""
    import ast as _ast
    import builtins
    if tree is None:
        return False
    key = id(tree)
    if key not in cache:
        scopes = []                                    # (first line, last line, well-defined names, depth)
        imports = set()
        for n in _ast.walk(tree):
            if isinstance(n, (_ast.Import, _ast.ImportFrom)):
                for a in n.names:
                    imports.add((a.asname or a.name).split(".")[0])
        for fn in [n for n in _ast.walk(tree) if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef))] + [tree]:
            good, bad = set(), set()
            if isinstance(fn, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                a = fn.args
                good |= {x.arg for x in a.posonlyargs + a.args + a.kwonlyargs + [a.vararg, a.kwarg] if x is not None}
            stack = list(_ast.iter_child_nodes(fn))
            while stack:
                n = stack.pop()
                if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef, _ast.Lambda)):
                    if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
                        good.add(n.name)
                    continue
                if isinstance(n, (_ast.Assign, _ast.AnnAssign, _ast.AugAssign, _ast.For, _ast.AsyncFor, _ast.withitem)):
                    tgts = n.targets if isinstance(n, _ast.Assign) else [getattr(n, "target", None) or getattr(n, "optional_vars", None)]
                    for t in tgts:
                        for x in _ast.walk(t) if t is not None else ():
                            if isinstance(x, _ast.Name):
                                good.add(x.id)
                elif isinstance(n, (_ast.comprehension, _ast.NamedExpr)):
                    for x in _ast.walk(n.target):
                        if isinstance(x, _ast.Name):
                            bad.add(x.id)
                elif isinstance(n, (_ast.Global, _ast.Nonlocal)):
                    bad.update(n.names)
                elif n.__class__.__name__ in ("MatchAs", "MatchStar") and getattr(n, "name", None):
                    bad.add(n.name)
                elif isinstance(n, _ast.ExceptHandler) and n.name:
                    good.add(n.name)
                stack.extend(_ast.iter_child_nodes(n))
            try:
                from .flow import _escaping
                # aliased / captured / stored containers: a write through another name may be invisible to the
                # dataflow analysis. Strings and numbers cannot be changed through an alias, so only names that
                # hold (or are used as) a container count.
                # (a container handed to a call is modelled by the flow analysis: the callee may store into it)
                bad |= _escaping(fn, include_passed=False) & _container_like(fn)
            except Exception:  # noqa: BLE001 - be conservative: keep the pattern finding
                good = set()
            lo = getattr(fn, "lineno", 1)
            hi = max(getattr(fn, "end_lineno", None) or lo,
                     max((getattr(x, "end_lineno", None) or getattr(x, "lineno", lo) or lo for x in _ast.walk(fn)), default=lo))
            scopes.append((lo, hi, good - bad))
        receivers = set()                               # id() of names used as `x.f(...)` / `X.f` receivers
        by_line: dict = {}
        for n in _ast.walk(tree):
            if isinstance(n, _ast.Attribute) and isinstance(n.value, _ast.Name):
                receivers.add(id(n.value))
        for n in _ast.walk(tree):
            if isinstance(n, _ast.Name) and isinstance(n.ctx, _ast.Load) and getattr(n, "lineno", None):
                is_module_receiver = id(n) in receivers and (n.id in imports or n.id[:1].isupper())
                if not is_module_receiver and not hasattr(builtins, n.id) and n.id not in ("self", "cls", "this"):
                    by_line.setdefault(n.lineno, set()).add(n.id)
        cache[key] = (sorted(scopes, key=lambda x: x[1] - x[0]), by_line)
    scopes, by_line = cache[key]
    names = by_line.get(line)
    if names is None:
        return False                      # nothing on that line the analysis saw: keep the pattern hit
    scope = next((sc for sc in scopes if sc[0] <= line <= sc[1]), None)
    return scope is not None and names <= scope[2]


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


# ------------------------------------------------------------------ per-file stage: parallel workers + incremental cache
# Everything that looks at one file alone (reading, pattern rules, secrets, Python semantic checks, configuration
# values, picking the files the data-flow engine needs) runs per file: in a process pool with --jobs, and served from
# the incremental cache with --cache. The inter-procedural analysis then runs once, over every file, in this process.
_DATAFLOW_EXTS = (".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".java", ".kt", ".kts", ".cs", ".go",
                  ".php", ".phtml", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".rs", ".swift", ".rb",
                  ".rake") + PLSQL_EXTS
_SERVER_TEMPLATE_EXTS = (".html", ".htm", ".jinja", ".jinja2", ".j2", ".tmpl", ".djhtml")
_VENDOR_CHECK_EXTS = (".js", ".cjs", ".mjs", ".css")
# Below this many files a process pool costs more than it saves (tests lower it to exercise the pool).
PARALLEL_MIN_FILES = 64
CACHE_FORMAT = 1


def _decode_text(raw: bytes) -> str:
    """Exactly what ``Path.read_text("utf-8", errors="replace")`` returns for these bytes (universal newlines)."""
    return io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8", errors="replace").read()


def _file_stage(p: pathlib.Path, rel: str, rules: list[Rule], ignore_rules: set[str], include_tests: bool,
                raw: bytes | None, want_tree: bool = False, preparse: bool = False) -> dict:
    """The per-file part of a scan. Returns a record of plain data:
    vendored (skipped as a bundled library) · findings · src (text the data-flow engine needs, else None) ·
    config (key/values of a configuration file, else None) · tree (an already parsed module, else None)."""
    suffix, name = p.suffix.lower(), p.name
    rec: dict = {"vendored": False, "findings": [], "src": None, "config": None, "tree": None}
    if not include_tests and suffix in _VENDOR_CHECK_EXTS:
        if raw is not None:
            head_b = raw[:8192]
        else:
            try:
                with open(p, "rb") as fh:
                    head_b = fh.read(8192)
            except OSError:
                head_b = b""
        if is_vendored(rel, head_b.decode("utf-8", "replace")):
            rec["vendored"] = True
            return rec
    findings = scan_sensitive_names(rel, ignore_rules)
    rec["findings"] = findings
    if raw is None:
        return rec
    trees: list = []
    if not _skipped_name(name) and 0 < len(raw) <= MAX_FILE_BYTES:
        findings.extend(_scan_bytes(p, rel, raw, rules, ignore_rules, trees if want_tree else None))
    text = None

    def get_text():
        nonlocal text
        if text is None:
            text = _decode_text(raw)
        return text
    src = None
    if suffix in _DATAFLOW_EXTS and not name.endswith((".min.js", ".d.ts")):
        # APEX application exports are routinely tens of MB; PL/SQL gets a larger limit
        if len(raw) <= (MAX_PLSQL_BYTES if suffix in PLSQL_EXTS else MAX_FILE_BYTES):
            src = get_text()
            if suffix == ".sql":
                findings.extend(scan_sql_dump(rel, src, ignore_rules))
    if suffix in _SERVER_TEMPLATE_EXTS and src is None and len(raw) <= 512_000:
        t = get_text()               # server-side templates: the data-flow engine checks what they print unescaped
        if "{{" in t or "{%" in t:
            src = t
    if stored.is_config_file(rel) and len(raw) <= 1_000_000:
        rec["config"] = stored.parse_config(rel, get_text())
    if suffix in (".yaml", ".yml", ".xml", ".json") and not name.endswith(".min.json") and src is None \
            and len(raw) <= MAX_PLSQL_BYTES:
        t = get_text()               # APEX readable exports, Liquibase/SQLcl changelogs and ORDS definitions carry Oracle code
        if apex_export.is_oracle_container(t, rel):
            src = t
    rec["src"] = src
    if src is not None:
        if trees and trees[0][0] == src:
            rec["tree"] = trees[0][1]          # the Python module semantic checks parsed: same text, same tree
        elif preparse:
            rec["tree"] = taint.preparse(rel, src)
    return rec


def _read_for_stage(p: pathlib.Path) -> bytes | None:
    """The file's bytes when some per-file check reads them (nothing reads more than MAX_PLSQL_BYTES)."""
    try:
        if p.stat().st_size > MAX_PLSQL_BYTES:
            return None
        return p.read_bytes()
    except OSError:
        return None


# --------------------------------------------------------------------------------------- cache codec (plain JSON)
class _NotPlain(Exception):
    pass


def _enc(v):
    """Plain data -> JSON, keeping tuples, sets and non-string dict keys distinct (findings must come back identical).
    Anything else is refused: the cache never stores (and so never loads) objects, only data."""
    t = type(v)
    if v is None or t in (bool, int, float, str):
        return v
    if t is list:
        return [_enc(x) for x in v]
    if t is tuple:
        return {"\u0000t": [_enc(x) for x in v]}
    if t in (set, frozenset):
        return {"\u0000s" if t is set else "\u0000f": [_enc(x) for x in v]}
    if t is dict:
        if all(type(k) is str and not k.startswith("\u0000") for k in v):
            return {k: _enc(x) for k, x in v.items()}
        return {"\u0000d": [[_enc(k), _enc(x)] for k, x in v.items()]}
    raise _NotPlain(t.__name__)


def _dec(v):
    t = type(v)
    if t is list:
        return [_dec(x) for x in v]
    if t is dict:
        if len(v) == 1:
            (k, x), = v.items()
            if k == "\u0000t":
                return tuple(_dec(y) for y in x)
            if k == "\u0000s":
                return {_dec(y) for y in x}
            if k == "\u0000f":
                return frozenset(_dec(y) for y in x)
            if k == "\u0000d":
                return {_dec(a): _dec(b) for a, b in x}
        return {k: _dec(x) for k, x in v.items()}
    return v


_FINDING_FIELDS = ("rule_id", "severity", "title", "title_ar", "file", "line", "snippet", "advice", "cwe", "source")


def _enc_finding(f: Finding) -> list:
    return [getattr(f, k) for k in _FINDING_FIELDS] + [_enc(f.extra)]


def _dec_finding(row) -> Finding:
    if not isinstance(row, list) or len(row) != len(_FINDING_FIELDS) + 1:
        raise ValueError("bad finding row")
    vals = row[:-1]
    if not all(isinstance(x, str) for i, x in enumerate(vals) if i != 5) or type(vals[5]) is not int:
        raise ValueError("bad finding field")
    extra = _dec(row[-1])
    if not isinstance(extra, dict):
        raise ValueError("bad finding extra")
    return Finding(*vals, extra=extra)


class ScanCache:
    """Incremental scan cache under a directory. Entries are JSON files of plain data, written atomically (temp file +
    rename) and keyed by a SHA-256 of everything that decides them: file content, path, kashif version and code,
    rules, models and options. An entry that is missing, unreadable, corrupt or of another format is a miss."""

    def __init__(self, root):
        self.root = pathlib.Path(root)
        self.hits = self.misses = 0

    def _path(self, kind: str, key: str) -> pathlib.Path:
        return self.root / f"v{CACHE_FORMAT}" / kind / key[:2] / f"{key}.json"

    def get(self, kind: str, key: str):
        try:
            with open(self._path(kind, key), "rb") as fh:
                doc = json.loads(fh.read().decode("utf-8"))
            if not isinstance(doc, dict) or doc.get("format") != CACHE_FORMAT or doc.get("key") != key:
                raise ValueError("foreign entry")
            self.hits += 1
            return doc["data"]
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            self.misses += 1
            return None

    def put(self, kind: str, key: str, data) -> bool:
        path = self._path(kind, key)
        try:
            body = json.dumps({"format": CACHE_FORMAT, "key": key, "data": data}, ensure_ascii=False,
                              separators=(",", ":")).encode("utf-8")
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(body)
                os.replace(tmp, path)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
            return True
        except (OSError, ValueError, TypeError, RecursionError):
            return False                 # a read-only or full disk only costs speed


def default_cache_dir() -> pathlib.Path:
    """``$KASHIF_HOME/cache/scan``, else ``$VULNSCAN_HOME/cache/scan``, else ``~/.vulnscan/cache/scan`` (the UI and
    the language server keep their incremental scan cache here)."""
    home = os.environ.get("KASHIF_HOME") or os.environ.get("VULNSCAN_HOME")
    return (pathlib.Path(home) if home else pathlib.Path.home() / ".vulnscan") / "cache" / "scan"


_ENGINE_HASH: list = []


def _engine_hash() -> str:
    """Identity of this kashif build: version plus the package's code, rules, models and queries (a development tree
    edited without a version bump must not reuse old entries). A frozen binary hashes its own executable instead."""
    if _ENGINE_HASH:
        return _ENGINE_HASH[0]
    from . import __version__
    h = hashlib.sha256(f"kashif {__version__} cache {CACHE_FORMAT} py {sys.version_info[:2]}".encode())
    pkg = pathlib.Path(__file__).resolve().parent
    found = 0
    for dirpath, dirnames, filenames in os.walk(pkg):  # nosec - our own package directory
        dirnames[:] = sorted(d for d in dirnames if d not in ("__pycache__", "ui"))
        for fn in sorted(filenames):
            if fn.endswith((".py", ".json", ".vql")):
                fp = pathlib.Path(dirpath, fn)
                try:
                    h.update(fp.relative_to(pkg).as_posix().encode() + b"\0" + fp.read_bytes() + b"\0")
                    found += fn.endswith(".py")
                except OSError:
                    pass
    if not found or getattr(sys, "frozen", False):
        try:
            st = os.stat(sys.executable)
            h.update(f"{sys.executable}:{st.st_size}:{st.st_mtime_ns}".encode())
        except OSError:
            pass
    _ENGINE_HASH.append(h.hexdigest())
    return _ENGINE_HASH[0]


def _rules_hash(rules: list[Rule]) -> str:
    if rules is RULES:
        return "builtin"                  # covered by the engine hash
    rows = [(r.id, r.severity, r.title, r.title_ar, r.pattern.pattern, r.pattern.flags, r.advice, r.cwe,
             sorted(r.langs) if r.langs is not None else None,
             (r.skip.pattern, r.skip.flags) if r.skip is not None else None) for r in rules]
    return hashlib.sha256(json.dumps(rows, ensure_ascii=False, default=str).encode()).hexdigest()


def _paths_hash(paths) -> list:
    """Content identity of user model / query files and directories."""
    out = []
    for raw_path in paths or ():
        p = pathlib.Path(raw_path)
        files = [p] if p.is_file() else sorted(x for x in p.rglob("*") if x.is_file()) if p.is_dir() else []
        for f in files:
            try:
                out.append([str(f), hashlib.sha256(f.read_bytes()).hexdigest()])
            except OSError:
                out.append([str(f), None])
        if not files:
            out.append([str(p), None])
    return out


def _file_key(salt: str, rel: str, raw: bytes) -> str:
    h = hashlib.sha256(salt.encode())
    h.update(b"\0" + rel.encode("utf-8", "surrogatepass") + b"\0")
    h.update(raw)
    return h.hexdigest()


def _stage_cached(p: pathlib.Path, rel: str, rules, ignore_rules, include_tests, cache: ScanCache | None, salt: str,
                  want_tree: bool, preparse: bool):
    """_file_stage through the cache. Returns (record, content digest or None)."""
    raw = _read_for_stage(p)
    if cache is None or raw is None:
        return _file_stage(p, rel, rules, ignore_rules, include_tests, raw, want_tree, preparse), \
            (hashlib.sha256(raw).hexdigest() if raw is not None and cache is not None else None)
    key = _file_key(salt, rel, raw)
    data = cache.get("file", key)
    if data is not None:
        try:
            rec = {"vendored": bool(data["vendored"]), "findings": [_dec_finding(r) for r in data["findings"]],
                   "src": _decode_text(raw) if data["src"] else None, "config": _dec(data["config"]), "tree": None}
            if rec["config"] is not None and not isinstance(rec["config"], dict):
                raise ValueError("bad config")
            if preparse and rec["src"] is not None:
                rec["tree"] = taint.preparse(rel, rec["src"])
            return rec, key
        except (KeyError, TypeError, ValueError, RecursionError):
            pass                          # corrupt entry: recompute (and overwrite it)
    rec = _file_stage(p, rel, rules, ignore_rules, include_tests, raw, want_tree, preparse)
    try:
        cache.put("file", key, {"vendored": rec["vendored"], "findings": [_enc_finding(f) for f in rec["findings"]],
                                "src": rec["src"] is not None, "config": _enc(rec["config"])})
    except _NotPlain:
        pass
    return rec, key


_WORKER: dict = {}


def _worker_init(rules, ignore_rules, include_tests, cache_dir, salt):
    _WORKER.update(rules=RULES if rules is None else rules, ignore_rules=ignore_rules, include_tests=include_tests,
                   cache=ScanCache(cache_dir) if cache_dir else None, salt=salt)


def _worker_run(item):
    path, rel = item
    w = _WORKER
    try:
        return _stage_cached(pathlib.Path(path), rel, w["rules"], w["ignore_rules"], w["include_tests"], w["cache"],
                             w["salt"], False, True)
    except (RecursionError, MemoryError):
        return None                       # handled again in the parent, where it fails the same way it always did


def _mp_context():
    """fork where it is safe and fast (Linux, no other threads); spawn on macOS and Windows, inside frozen binaries
    started from threads (the UI and the language server scan in worker threads), and wherever fork is missing."""
    import multiprocessing as mp
    import threading
    forced = os.environ.get("KASHIF_MP_START", "").strip().lower()     # diagnostics: spawn / fork / forkserver
    if forced in mp.get_all_start_methods():
        return mp.get_context(forced)
    if sys.platform in ("darwin", "win32") or threading.active_count() > 1 or "fork" not in mp.get_all_start_methods():
        return mp.get_context("spawn")
    return mp.get_context("fork")


def resolve_jobs(jobs) -> int:
    """--jobs N: None/0 = one per CPU, 1 = no worker processes."""
    if not jobs:
        try:
            jobs = len(os.sched_getaffinity(0))
        except (AttributeError, OSError):
            jobs = os.cpu_count() or 1
    return max(1, int(jobs))


def _collect(items: list, rules, ignore_rules, include_tests, jobs: int, cache: ScanCache | None, salt: str) -> list:
    """Run the per-file stage over `items` [(path, rel)], in order. Returns [(record, digest)]."""
    out: list = [None] * len(items)
    if jobs > 1 and len(items) >= max(PARALLEL_MIN_FILES, 2):
        try:
            ctx = _mp_context()
            n = min(jobs, len(items))
            chunk = max(1, min(32, len(items) // (n * 8)))
            with ctx.Pool(n, initializer=_worker_init,
                          initargs=(None if rules is RULES else rules, ignore_rules, include_tests,
                                    str(cache.root) if cache is not None else None, salt)) as pool:
                for i, res in enumerate(pool.imap(_worker_run, [(str(p), rel) for p, rel in items], chunksize=chunk)):
                    out[i] = res
        except (OSError, ImportError, RuntimeError, ValueError, EOFError) as e:   # no pool here: run in-process
            out = [None] * len(items)
            _POOL_ERRORS.append(f"{type(e).__name__}: {e}")
    for i, (p, rel) in enumerate(items):
        if out[i] is None:
            out[i] = _stage_cached(p, rel, rules, ignore_rules, include_tests, cache, salt, True, False)
    return out


_POOL_ERRORS: list = []


def scan_path(target: pathlib.Path, excludes: list[str] | None = None,
              ignore_rules: set[str] | None = None, rules: list[Rule] | None = None,
              jadx: bool = True, jadx_timeout: int = 600, jadx_include_libs: bool = False,
              notes: list[str] | None = None, models_dirs: list[str] | None = None,
              query_paths: list[str] | None = None, queries: bool = True,
              audit: bool = False, include_tests: bool | None = None,
              jobs: int | None = 1, cache_dir: str | os.PathLike | None = None) -> tuple[list[Finding], int]:
    """Scan a directory, a single file or an archive. Returns (findings, files_scanned).

    For APK/JAR/AAR/DEX bundles, when ``jadx`` is True and the jadx CLI is
    installed, the bytecode is decompiled and the Java sources plus decoded
    Android resources are scanned too (paths prefixed ``bundle!decompiled/``).
    Human-readable notes about that step are appended to ``notes``.

    ``jobs``: worker processes for the per-file stage (None or 0 = one per CPU, 1 = none). The whole-program
    data-flow analysis always runs in this process, over every file; results do not depend on ``jobs``.
    ``cache_dir``: incremental cache (see ScanCache); None disables it.
    """
    excludes = excludes or []
    ignore_rules = ignore_rules or set()
    if include_tests is None:
        include_tests = os.environ.get("VULNSCAN_INCLUDE_TESTS", "").lower() in ("1", "true", "yes")
    rules = rules or RULES
    jobs = resolve_jobs(jobs)
    cache = ScanCache(cache_dir) if cache_dir else None
    tmp = None
    root = target
    if is_archive(target):
        tmp = extract_archive(target)
        root = tmp
    jadx_dir = None
    try:
        findings: list[Finding] = []
        count = 0
        vendored = 0
        py_sources: dict[str, str] = {}
        trees: dict = {}
        config_values: dict = {}
        if not (root.is_file() and is_jadx_bundle(root)):  # a bare .dex/.class has nothing to walk
            items = list(iter_files(root, excludes))
            count = len(items)
            salt = json.dumps([_engine_hash(), _rules_hash(rules), sorted(ignore_rules), bool(include_tests)]) \
                if cache is not None else ""
            hygiene = scan_project_hygiene(root, ignore_rules)
            pkey = None
            if cache is not None:
                # the whole result is decided by the files (paths + contents) and the options: an unchanged project
                # is answered from the cache without any analysis
                h = hashlib.sha256(json.dumps(["project", salt, _paths_hash(models_dirs), _paths_hash(query_paths),
                                               bool(queries), bool(audit), [_enc_finding(f) for f in hygiene]],
                                              ensure_ascii=False).encode())
                for p, rel in items:
                    raw = _read_for_stage(p)
                    h.update(rel.encode("utf-8", "surrogatepass") + b"\0" +
                             (hashlib.sha256(raw).digest() if raw is not None else b"-") + b"\0")
                pkey = h.hexdigest()
                hit = cache.get("project", pkey)
                if hit is not None:
                    try:
                        cached = [_dec_finding(r) for r in hit["findings"]]
                        cached_notes = [str(x) for x in hit["notes"]]
                        vendored = int(hit["vendored"])
                        findings = cached
                        if notes is not None:
                            notes.extend(cached_notes)
                    except (KeyError, TypeError, ValueError, RecursionError):
                        pkey_hit = False
                    else:
                        pkey_hit = True
                else:
                    pkey_hit = False
            else:
                pkey_hit = False
            if not pkey_hit:
                block_notes: list[str] = []
                for (p, rel), (rec, _digest) in zip(items, _collect(items, rules, ignore_rules, include_tests, jobs,
                                                                    cache, salt)):
                    if rec["vendored"]:
                        vendored += 1
                        continue
                    findings.extend(rec["findings"])
                    if rec["src"] is not None:
                        py_sources[rel] = rec["src"]
                        if rec["tree"] is not None:
                            trees[rel] = rec["tree"]
                    if rec["config"] is not None:
                        config_values.update(rec["config"])
                findings.extend(hygiene)
                findings = _dataflow_stage(findings, py_sources, trees, config_values, models_dirs, query_paths,
                                           queries, audit, ignore_rules, block_notes)
                del py_sources, trees
                if notes is not None:
                    notes.extend(block_notes)
                if cache is not None and pkey is not None and not any(n == BUDGET_NOTE for n in block_notes):
                    try:                 # (a result cut short by the time budget is not kept: the next run may finish)
                        cache.put("project", pkey, {"findings": [_enc_finding(f) for f in findings],
                                                    "notes": block_notes, "vendored": vendored})
                    except _NotPlain:
                        pass
        findings = apply_path_policy(findings, include_tests)
        if vendored and notes is not None:
            notes.append(f"تُركت {vendored} ملفات مكتبات مضمَّنة (vendored) خارج التحليل — {vendored} vendored library files skipped")
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


def _dataflow_stage(findings, py_sources, trees, config_values, models_dirs, query_paths, queries, audit, ignore_rules,
                    notes: list[str]) -> list[Finding]:
    """Project-wide checks over every file: Java/Kotlin configuration checks, cross-file data-flow (taint) analysis,
    VQL queries, then the audit profile."""
    from . import semantic as _sem
    for rel_j, text_j in py_sources.items():         # Java/Kotlin checks that need project configuration
        if rel_j.endswith((".java", ".kt")):
            findings.extend(_sem.check_java(rel_j, text_j, config_values, ignore_rules))
    if not py_sources:
        return findings
    try:          # whole-project cross-file data-flow (taint) analysis: Python + JS/TS + …, then VQL queries
        projects, flows = taint.analyze_project_full(py_sources, models_dirs, config_values, trees=trees)
    except (RecursionError, MemoryError) as e:   # never lose the pattern findings to one hostile file
        projects, flows = [], []
        notes.append(f"تعذّر تحليل تدفق البيانات ({type(e).__name__})؛ عُرضت نتائج القواعد فقط — "
                     f"dataflow analysis failed, pattern results only")
    trees.clear()
    findings.extend(f for f in flows if f.rule_id not in ignore_rules)
    notes.extend(frontend_notes(projects))
    if any(getattr(proj, "budget_hit", False) for proj in projects):
        notes.append(BUDGET_NOTE)
    deep = sorted({p for proj in projects for p in getattr(proj, "too_deep", [])})
    if deep:
        notes.append(f"ملفات متداخلة بعمق غير طبيعي (مولَّدة أو عدائية) استُثنيت من تحليل التدفق: {', '.join(deep[:5])}"
                     f"{' …' if len(deep) > 5 else ''} — too deeply nested for dataflow analysis")
    if queries or query_paths:
        try:
            qf, qnotes = vql.run_queries(projects, flows, query_paths, builtin=queries,
                                         skip_ids=() if audit else AUDIT_ONLY)
        except (RecursionError, MemoryError):
            qf, qnotes = [], ["تعذّر تشغيل استعلامات VQL — VQL queries failed"]
        findings.extend(f for f in qf if f.rule_id not in ignore_rules)
        notes.extend(qnotes)
    try:
        return apply_audit_profile(findings, projects, audit)
    finally:
        taint.release_caches()
