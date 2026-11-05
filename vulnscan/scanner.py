"""Walks a target (directory, file or archive) and applies the built-in rules."""

from __future__ import annotations

import fnmatch
import os
import pathlib
import re
import shutil
import tarfile
import tempfile
import zipfile

from .model import Finding
from .rules import RULES, SENSITIVE_FILES, Rule

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


def is_archive(path: pathlib.Path) -> bool:
    return path.is_file() and path.name.lower().endswith(ARCHIVE_EXTS)


def scan_path(target: pathlib.Path, excludes: list[str] | None = None,
              ignore_rules: set[str] | None = None, rules: list[Rule] | None = None) -> tuple[list[Finding], int]:
    """Scan a directory, a single file or an archive. Returns (findings, files_scanned)."""
    excludes = excludes or []
    ignore_rules = ignore_rules or set()
    rules = rules or RULES
    tmp = None
    root = target
    if is_archive(target):
        tmp = extract_archive(target)
        root = tmp
    try:
        findings: list[Finding] = []
        count = 0
        for p, rel in iter_files(root, excludes):
            count += 1
            findings.extend(scan_sensitive_names(rel, ignore_rules))
            findings.extend(scan_file(p, rel, rules, ignore_rules))
        findings.extend(scan_project_hygiene(root, ignore_rules))
        if tmp is not None:
            for f in findings:
                f.file = f"{target.name}!{f.file}"
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
