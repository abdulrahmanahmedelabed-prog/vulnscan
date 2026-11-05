"""Walks a target (directory, file or archive) and applies the built-in rules."""

from __future__ import annotations

import fnmatch
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
from . import taint

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
    "*.wasm", "*.dex",
)
ARCHIVE_EXTS = (".zip", ".jar", ".war", ".ear", ".apk", ".aar", ".whl", ".ipa", ".nupkg",
                ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")
MAX_FILE_BYTES = 2 * 1024 * 1024
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
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not _excluded(d, excludes))
        for fn in sorted(filenames):
            p = pathlib.Path(dirpath) / fn
            rel = p.relative_to(root).as_posix()
            if _excluded(rel, excludes) or _excluded(fn, excludes):
                continue
            yield p, rel


def _excluded(rel: str, excludes: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, pat) for pat in excludes)


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
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > MAX_LINE_LEN or SUPPRESS.search(line):
            continue
        for rule in applicable:
            if rule.pattern.search(line) and not (rule.skip and rule.skip.search(line)):
                findings.append(Finding(
                    rule_id=rule.id, severity=rule.severity, title=rule.title, title_ar=rule.title_ar,
                    file=rel, line=lineno, snippet=line.strip()[:200], advice=rule.advice, cwe=rule.cwe,
                ))
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
        with tarfile.open(archive) as tf:
            for m in tf.getmembers():
                target = (dest / m.name).resolve()
                if not str(target).startswith(str(dest.resolve())) or m.issym() or m.islnk():
                    continue
                tf.extract(m, dest)
    else:
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                target = (dest / info.filename).resolve()
                if not str(target).startswith(str(dest.resolve())):
                    continue
                zf.extract(info, dest)
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
        shutil.rmtree(out, ignore_errors=True)
        return None, f"jadx تجاوز المهلة ({timeout} ثانية)؛ جرّب مهلة أكبر."
    except OSError as e:
        shutil.rmtree(out, ignore_errors=True)
        return None, f"تعذّر تشغيل jadx: {e}"
    n_java = sum(1 for _ in out.rglob("*.java"))
    if n_java == 0 and not (out / "resources").exists():
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        shutil.rmtree(out, ignore_errors=True)
        return None, "jadx لم يُنتج أي ملفات" + (f": {err[-1][:160]}" if err else ".")
    note = f"jadx: فُكّ تجميع {n_java} ملف Java"
    if proc.returncode != 0:
        note += " (مع أخطاء جزئية في بعض الدوال)"
    return out, note + "."


def is_jadx_bundle(path: pathlib.Path) -> bool:
    return path.is_file() and path.name.lower().endswith(JADX_EXTS)


def is_archive(path: pathlib.Path) -> bool:
    return path.is_file() and path.name.lower().endswith(ARCHIVE_EXTS)


def scan_path(target: pathlib.Path, excludes: list[str] | None = None,
              ignore_rules: set[str] | None = None, rules: list[Rule] | None = None,
              jadx: bool = True, jadx_timeout: int = 600, jadx_include_libs: bool = False,
              notes: list[str] | None = None) -> tuple[list[Finding], int]:
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
        if not (root.is_file() and is_jadx_bundle(root)):  # a bare .dex/.class has nothing to walk
            for p, rel in iter_files(root, excludes):
                count += 1
                findings.extend(scan_sensitive_names(rel, ignore_rules))
                findings.extend(scan_file(p, rel, rules, ignore_rules))
                if p.suffix.lower() == ".py":
                    try:
                        if p.stat().st_size <= MAX_FILE_BYTES:
                            py_sources[rel] = p.read_text("utf-8", errors="replace")
                    except OSError:
                        pass
            findings.extend(scan_project_hygiene(root, ignore_rules))
            if py_sources:  # whole-project cross-file data-flow (taint) analysis
                for f in taint.analyze_project(py_sources):
                    if f.rule_id not in ignore_rules:
                        findings.append(f)
        if tmp is not None:
            for f in findings:
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
            shutil.rmtree(tmp, ignore_errors=True)
        if jadx_dir is not None:
            shutil.rmtree(jadx_dir, ignore_errors=True)
