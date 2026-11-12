"""Diff-aware reporting: keep only the findings a change introduced.

The scan itself always covers the whole target, so cross-file data flow stays correct (a sink in an unchanged
helper reached from a changed request handler is still found). Only the *report* is narrowed, to findings that:

* sit on a line added or modified relative to the merge-base with the base ref (``git diff --unified=0``), or
* have a data-flow trail with a step on such a line (the change created or re-routed the flow), or
* are file-level (line 0) in a file the change touched, or anywhere in a changed binary file / new untracked file.

Lines next to a pure deletion count for trails only: deleting a sanitizer call between a source and a sink
creates a flow whose sink line did not change.

This is what Semgrep (``--baseline-commit``), CodeQL PR checks and Snyk Code PR checks call "new findings only".
git is always run with an argument list (no shell), an absolute path to the binary, and a validated ref.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess  # nosec B404 - fixed git invocations with argument lists, never a shell
from dataclasses import dataclass, field

EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"     # git's well-known empty tree (initial commit)

# A ref, SHA, remote branch or revision expression (HEAD~1, origin/main, v1.2^{commit}). Option-looking values,
# ranges ("a..b"), whitespace, control characters and the reflog/pathspec syntax that could reach files are refused.
_REF_RX = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./@^~{}+-]{0,254}")
_HUNK_RX = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class DiffScopeError(Exception):
    """The diff could not be computed (not a git repository, unknown ref, git missing). Message is Arabic."""


@dataclass
class DiffScope:
    repo_root: pathlib.Path
    base: str                                    # the ref as given
    base_commit: str                             # what the diff was taken against (merge-base, base or empty tree)
    changed: dict[str, set[int]] = field(default_factory=dict)   # repo-relative path -> added/modified lines
    near: dict[str, set[int]] = field(default_factory=dict)      # lines adjacent to pure deletions (trails only)
    whole: set[str] = field(default_factory=set)                 # binary or untracked files: every line is new
    notes: list[str] = field(default_factory=list)

    def touches_file(self, path: str) -> bool:
        return path in self.whole or bool(self.changed.get(path)) or bool(self.near.get(path))

    def line_changed(self, path: str, line: int) -> bool:
        return path in self.whole or line in self.changed.get(path, ())

    def line_touched(self, path: str, line: int) -> bool:
        return self.line_changed(path, line) or line in self.near.get(path, ())


def validate_ref(ref: str) -> str:
    ref = (ref or "").strip()
    if not _REF_RX.fullmatch(ref) or ".." in ref or "@{" in ref or ref.endswith((".lock", "/", ".")):
        raise DiffScopeError(f"مرجع git غير صالح: {ref!r}")
    return ref


def _git_binary() -> str:
    git = shutil.which("git")
    if not git:
        raise DiffScopeError("git غير مثبّت؛ الفحص المقيّد بالتغييرات يحتاج git.")
    return str(pathlib.Path(git).resolve())


def _git(git: str, cwd: pathlib.Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    # The scanned tree may carry a hostile .git/config (an unpacked archive can ship one): switch off everything
    # in it that would make git run a command and that a switch can turn off (fsmonitor, hooks, pager, external
    # diff, transports). Content filters cannot be switched off; scope() refuses a repository that defines one.
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C", "GIT_OPTIONAL_LOCKS": "0",
           "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "none"}
    for k in ("GIT_EXTERNAL_DIFF", "GIT_DIFF_OPTS", "GIT_PAGER", "PAGER"):
        env.pop(k, None)
    try:
        proc = subprocess.run([git, "--no-pager", "-c", "core.fsmonitor=false", "-c", f"core.hooksPath={os.devnull}",  # nosec B603
                               "-c", "core.pager=cat", "-c", "diff.external=",
                               "-c", "core.quotepath=false", "-c", "diff.noprefix=false",
                               "-c", "diff.mnemonicPrefix=false", "-c", "diff.relative=false", *args],
                              cwd=str(cwd), capture_output=True, env=env, timeout=300, check=False,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        raise DiffScopeError(f"فشل أمر git: {args[0]}") from None
    # Decoded without universal-newline translation: a lone "\r" inside changed code must not split a diff line.
    proc.stdout = proc.stdout.decode("utf-8", "replace")
    if check and proc.returncode != 0:
        raise DiffScopeError(f"فشل أمر git: {args[0]}")
    return proc


def _unquote(path: str) -> str:
    """git's C-style quoting of unusual paths ("a\\tb", octal UTF-8 bytes)."""
    if not (len(path) >= 2 and path[0] == '"' and path[-1] == '"'):
        return path
    raw, out, i = path[1:-1], bytearray(), 0
    simple = {"n": 10, "t": 9, "r": 13, '"': 34, "\\": 92, "a": 7, "b": 8, "f": 12, "v": 11}
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            if nxt in simple:
                out.append(simple[nxt])
                i += 2
                continue
            if re.fullmatch(r"[0-7]{3}", raw[i + 1:i + 4]):
                out.append(int(raw[i + 1:i + 4], 8))
                i += 4
                continue
        out += ch.encode("utf-8")
        i += 1
    return out.decode("utf-8", "replace")


def parse_unified_diff(text: str) -> tuple[dict[str, set[int]], dict[str, set[int]], set[str]]:
    """Parse ``git diff --unified=0`` output into (changed lines, lines next to deletions, binary files),
    keyed by the new-side path. Deleted files are ignored (nothing left to report on).

    Hunk bodies are consumed by the line counts of their ``@@`` header, so changed code that looks like a diff
    header (an added line ``++ b/x.py`` shows as ``+++ b/x.py``) cannot re-attribute the hunks that follow."""
    changed: dict[str, set[int]] = {}
    near: dict[str, set[int]] = {}
    binary: set[str] = set()
    current: str | None = None
    pending_b: str | None = None
    old_left = new_left = 0                      # body lines still expected in the current hunk
    for line in text.split("\n"):
        if old_left > 0 or new_left > 0:         # inside a hunk body: never a header
            if line.startswith("\\"):           # "\ No newline at end of file"
                continue
            if line.startswith("-"):
                old_left -= 1
            elif line.startswith("+"):
                new_left -= 1
            else:                                # context line (diff.interHunkContext)
                old_left, new_left = old_left - 1, new_left - 1
            continue
        line = line.rstrip("\r")
        if line.startswith("diff --git "):
            current, pending_b = None, None
            m = re.match(r'diff --git (?:"a/.*"|a/\S.*?) ("b/.*"|b/.*)$', line)
            if m:
                pending_b = _unquote(m.group(1))[2:] if m.group(1).startswith('"') else m.group(1)[2:]
        elif line.startswith("+++ "):
            target = line[4:].rstrip("\t")
            current = None if target == "/dev/null" else (_unquote(target)[2:] if target.startswith('"') else target[2:])
        elif line.startswith("Binary files ") and pending_b and not line.endswith("/dev/null differ"):
            binary.add(pending_b)
        elif current is not None:
            m = _HUNK_RX.match(line)
            if m:
                start, count = int(m.group(2)), int(m.group(3) if m.group(3) is not None else 1)
                old_left = int(m.group(1) if m.group(1) is not None else 1)
                new_left = count
                if count:
                    changed.setdefault(current, set()).update(range(start, start + count))
                else:          # pure deletion after line `start`: the lines around the gap
                    near.setdefault(current, set()).update({max(1, start), start + 1})
    return changed, near, binary


def compute(target: str | os.PathLike, base: str | None = None, staged: bool = False) -> DiffScope:
    """The changed lines of the git repository holding `target`.

    * ``base`` given: merge-base(base, HEAD) against the working tree, plus untracked (not ignored) files.
      In a shallow clone without the merge-base, the diff is taken against `base` itself (noted).
    * ``staged``: the index against HEAD (pre-commit semantics; empty tree before the first commit)."""
    git = _git_binary()
    path = pathlib.Path(target).resolve()
    cwd = path if path.is_dir() else path.parent
    top = _git(git, cwd, "rev-parse", "--show-toplevel", check=False)
    if top.returncode != 0 or not top.stdout.strip():
        raise DiffScopeError("الهدف ليس داخل مستودع git؛ لا يمكن تقييد النتائج بالتغييرات.")
    repo = pathlib.Path(top.stdout.strip()).resolve()
    from .mcp import _repo_git_commands              # the same check guards the MCP server's diff_base and --fix
    try:
        risky = _repo_git_commands(str(repo))
    except Exception:  # noqa: BLE001 - cannot tell: fail closed rather than run git diff on a hostile tree
        risky = ["filter.?"]
    if risky:
        raise DiffScopeError("إعدادات git في هذا المستودع تعرّف مرشّح محتوى يشغّل أمرًا (" + ", ".join(risky[:3])
                             + ")؛ لم يُشغَّل git diff. راجع ‎.git/config أو افحص دون تقييد بالتغييرات.")
    notes: list[str] = []
    if staged:
        head = _git(git, repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", check=False)
        base_commit = head.stdout.strip() if head.returncode == 0 else EMPTY_TREE
        diff = _git(git, repo, "diff", "--cached", "--unified=0", "--no-color", "--no-ext-diff", "--no-textconv", "-M",
                    "--inter-hunk-context=0", "--src-prefix=a/", "--dst-prefix=b/",
                    base_commit, "--")
        label = "HEAD"
    else:
        label = validate_ref(base or "")
        rev = _git(git, repo, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{label}^{{commit}}", check=False)
        if rev.returncode != 0 or not rev.stdout.strip():
            raise DiffScopeError(f"المرجع غير موجود في المستودع: {label} (اجلبه أولًا، مثلًا git fetch origin {label})")
        base_sha = rev.stdout.strip()
        mb = _git(git, repo, "merge-base", base_sha, "HEAD", check=False)
        if mb.returncode == 0 and mb.stdout.strip():
            base_commit = mb.stdout.strip()
        else:
            base_commit = base_sha
            notes.append("تعذّر حساب نقطة التفرّع (نسخة سطحية؟)؛ قورن مع المرجع الأساس مباشرة.")
        diff = _git(git, repo, "diff", "--unified=0", "--no-color", "--no-ext-diff", "--no-textconv", "-M",
                    "--inter-hunk-context=0", "--src-prefix=a/", "--dst-prefix=b/",
                    base_commit, "--")
    changed, near, whole = parse_unified_diff(diff.stdout)
    if not staged:
        untracked = _git(git, repo, "ls-files", "--others", "--exclude-standard", "-z", check=False)
        whole |= {p for p in untracked.stdout.split("\0") if p}
    notes.append(f"تقييد بالتغييرات منذ {label}: {len(set(changed) | whole)} ملفًا متغيّرًا.")
    return DiffScope(repo, label, base_commit, changed, near, whole, notes)


def _repo_path(scope: DiffScope, scan_root: pathlib.Path, rel: str) -> str:
    rel = rel.split("!", 1)[0]                   # archive member: the archive file itself
    p = (scan_root / rel)
    try:
        return p.resolve().relative_to(scope.repo_root).as_posix()
    except ValueError:
        return os.path.relpath(p, scope.repo_root).replace(os.sep, "/")


def filter_findings(findings: list, scope: DiffScope, target: str | os.PathLike) -> tuple[list, int]:
    """Keep the findings the change introduced. Returns (kept, dropped count). Each kept finding is marked
    ``extra['diff']`` = "line" (on a changed line), "trail" (its data-flow trail crosses one) or "file"."""
    t = pathlib.Path(target).resolve()
    root = t if t.is_dir() else t.parent
    kept, dropped = [], 0
    for f in findings:
        path = _repo_path(scope, root, f.file)
        why = None
        if f.line and scope.line_changed(path, f.line):
            why = "line"
        elif not f.line and scope.touches_file(path):
            why = "file"
        else:
            for st in f.extra.get("path") or []:
                if isinstance(st, dict) and st.get("line"):
                    sp = _repo_path(scope, root, str(st.get("file") or f.file))
                    try:
                        ln = int(st["line"])
                    except (TypeError, ValueError):
                        continue
                    if scope.line_touched(sp, ln):
                        why = "trail"
                        break
        if why:
            f.extra["diff"] = why
            kept.append(f)
        else:
            dropped += 1
    return kept, dropped
