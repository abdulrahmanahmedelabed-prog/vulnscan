"""Secrets in git history: every credential that was ever committed, even if a later commit deleted it.

INTEGRATION NOTES (for the step that wires this module into the product; nothing here edits shared files)
---------------------------------------------------------------------------------------------------------
CLI (cli.py)
    Add a sub-command ``history`` (alias ``secrets-history``) that forwards its arguments to
    ``vulnscan.history.main(argv)``::

        kashif history /path/to/repo [--since 2024-01-01] [--until DATE] [--max-commits N]
                       [--branch NAME ...] [--include-unreachable] [--exclude GLOB ...]
                       [--no-entropy] [--no-suppress] [--only present|removed]
                       [-f console|json] [-o FILE] [--lang en|ar] [--timeout SEC] [--exit-zero]

    Alternatively add ``--history`` to the normal scan and merge ``scan_history(root).findings`` into the
    finding list before ``assign_fingerprints`` (they are ordinary ``vulnscan.model.Finding`` objects with
    ``source="git-history"``, so SARIF/HTML/Markdown/baseline/triage work unchanged). Exit codes follow the CLI:
    0 = clean, 1 = findings, 2 = usage or git error.
UI (server.py / ui/)
    * ``POST /api/history`` with ``{"path": ..., "since": ..., "max_commits": ...}`` returning
      ``result_to_dict(scan_history(...), lang)``; run it in the existing job thread (it streams, so pass
      ``progress=`` to update the job status with the number of commits processed).
    * A "Git history" tab: one row per finding using ``extra.commit_short``, ``extra.date``, ``extra.author``,
      ``extra.secret_redacted``, ``extra.status`` (present / removed / not-at-head) and ``extra.removed_in``;
      show ``result["remediation"][lang]`` as the guidance panel. The full secret is never in the payload.
    * The server must apply to ``path`` the same checks as for a normal scan (it starts git in that
      directory) and should pass a ``timeout``; file names, author names and snippets come from the repository
      and must be HTML-escaped like any other finding text.
vulnscan.spec
    add ``"vulnscan.history"`` to ``hiddenimports``.
i18n
    All text of this module is in ``STR`` below (en + ar); ``Finding.advice`` reuses the advice of the matching
    built-in rule, which is already in the shared catalogs, so ``tests/test_i18n.py`` needs no new entries.
README suggestions
    "Secrets in git history (the job of gitleaks' git mode, built in): ``kashif history .`` walks every
    non-merge commit of every ref with Kashif's own secret rules and entropy detector, reports each secret
    once with the commit that introduced it, whether it is still at HEAD, and the commit that removed it.
    Secrets are always redacted (at most a third of the characters is shown). Offline: detected secrets are
    not verified against their provider. No dependencies beyond the ``git`` executable."

How it works
------------
``git log -p`` is started once (argument list, absolute repository path, no shell) and its output is consumed as
a stream, one line at a time, so memory stays flat on very large repositories. Commits are visited oldest first
(``--date-order --reverse``), which makes the "introduced in" commit the first one seen and the output
deterministic. Only added lines are reported; removed lines are run through the same detector to learn which
commit deleted a secret. Whether a secret is still present is decided exactly, by reading the HEAD version of the
files it ever lived in (renames followed) through one ``git cat-file --batch`` process.

Unreachable objects (optional, ``include_unreachable`` / ``--include-unreachable``): adds ``--reflog`` to the walk
and asks ``git fsck --unreachable`` for dangling commits (walked like any other) and dangling blobs (for example
a file that was staged with ``git add`` and never committed), which are scanned whole. ``git fsck --lost-found``
is deliberately NOT used: it writes files into ``.git/lost-found``, and this module never modifies the repository.
fsck reads every object, so this option is slow on big repositories.

Limits
------
* Merge commits are not diffed (same as ``git log -p``): a secret typed while resolving a conflict is missed.
* With ``--since`` / ``--max-commits`` only the commits in the window are examined; a secret added before the
  window is not reported even if it is still at HEAD (run the normal scan for the working tree).
* "Still present" refers to HEAD only. A secret deleted on the HEAD branch may survive on another branch or tag;
  status ``not-at-head`` means it is absent from HEAD and no examined commit deleted it.
* Shallow clones contain only part of the history (a note is emitted).
* Detection is line based, exactly like the built-in secret rules; binary files are skipped.
* Lines longer than 4000 characters (minified bundles, one-line dumps) are not examined, like in the normal
  scan; a note reports how many were skipped.
* Lines carrying ``nosec`` / ``vulnscan: ignore`` are skipped by default; an audit of a repository you do not
  trust should pass ``--no-suppress`` (``honor_suppressions=False``).
* When a secret was copied into a very large number of files, the HEAD check may be incomplete (a note says so).
* A removed secret is still compromised. The report says so: rotate first, rewrite history second.

Untrusted repositories
----------------------
The repository's own ``.git/config`` is attacker-controlled input. git is therefore started with external diff
drivers, textconv filters, the pager, fsmonitor, signature display, replace refs and every transport protocol
disabled (``GIT_ALLOW_PROTOCOL=`` empty and ``GIT_NO_LAZY_FETCH=1``: a partial clone cannot make git contact,
or execute, a "remote"), diff prefixes are forced, and ``GIT_DIR``-style variables inherited from a calling git
hook are dropped so that the repository examined is the one named. Control and bidirectional-override characters
in file names, author names, subjects and code are neutralised in the console report.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field

from . import scanner as _scanner
from .model import Finding, assign_fingerprints, sort_findings
from .rules import RULES

__all__ = ["HistoryError", "HistoryResult", "scan_history", "redact", "render_console", "render_json",
           "result_to_dict", "remediation", "secret_rules", "STR", "main"]

# ------------------------------------------------------------------------------------------------ text (en / ar)
STR = {
    "en": {
        "title": "Kashif: secrets in git history",
        "repo": "Repository",
        "head": "HEAD",
        "no_head": "(no commits)",
        "commits": "commits examined",
        "lines": "changed lines examined",
        "secrets": "secrets found",
        "present_n": "still present at HEAD",
        "removed_n": "removed from HEAD, still in history",
        "elapsed": "time",
        "none": "No secrets found in the examined history.",
        "file": "file",
        "commit": "introduced in",
        "secret": "secret",
        "chars": "chars",
        "status": "status",
        "present": "STILL PRESENT at HEAD",
        "removed": "removed in",
        "not_at_head": "not at HEAD (lives on another branch, tag or unreachable object)",
        "unreachable": "unreachable object",
        "seen": "occurrences",
        "also": "also matches",
        "notes": "Notes",
        "remediation": "What to do",
        "rem_1": "1. Rotate first. Revoke every secret listed here at its provider and issue a new one. A secret "
                 "that was ever pushed must be treated as compromised, including the ones already deleted: "
                 "anyone with a clone, a fork, a CI cache or a mirror still has it.",
        "rem_2": "2. Check the provider's audit log for use of the old credential between the introducing commit "
                 "date and the rotation.",
        "rem_3": "3. Remove the secrets that are still at HEAD and load them from the environment or a secret "
                 "manager.",
        "rem_4": "4. Only then, if policy requires it, rewrite history: `git filter-repo --replace-text "
                 "replacements.txt` (or `--invert-paths --path FILE` to drop a whole file), or BFG Repo-Cleaner "
                 "`--replace-text`. Force-push all branches and tags, ask every collaborator to re-clone, and ask "
                 "the hosting service to purge cached views and dangling commits. Rewriting does not reach forks "
                 "or existing clones, which is why step 1 comes first.",
        "rem_5": "5. Prevent a repeat: run `kashif` as a pre-commit hook and in CI.",
        "e_git": "git executable not found; install git to scan history",
        "e_repo": "not a git repository: {path}",
        "e_branch": "invalid branch or revision name: {name}",
        "e_fail": "git failed: {msg}",
        "n_shallow": "shallow clone: only part of the history is available (run `git fetch --unshallow`).",
        "n_timeout": "stopped after {sec} s (time limit); results are partial.",
        "n_cap": "finding limit reached ({n}); further secrets were not recorded.",
        "n_entropy": "entropy detector unavailable in this build; only pattern rules were applied.",
        "n_fsck": "git fsck failed; unreachable objects were not examined.",
        "n_window": "history window limited by --since/--until/--max-commits: older secrets are not reported.",
        "n_long": "{n} changed lines longer than {limit} characters were not examined.",
        "n_paths": "some secrets appear in too many files to track them all; 'still at HEAD' may be incomplete.",
        "e_write": "cannot write {path}: {msg}",
        "h_desc": "Find secrets in the git history of a repository (every commit, every branch).",
        "h_repo": "path to the git repository (default: current directory)",
        "h_since": "only commits newer than this date (git date syntax, e.g. 2024-01-01)",
        "h_until": "only commits older than this date",
        "h_max": "examine at most N commits (the N most recent)",
        "h_branch": "branch, tag or revision to walk instead of all refs (repeatable)",
        "h_unreach": "also examine reflog entries and unreachable (dangling) commits and blobs; slow",
        "h_exclude": "skip files matching this glob (repeatable)",
        "h_entropy": "disable the high-entropy detector (pattern rules only)",
        "h_suppress": "report lines even when they carry a nosec / vulnscan: ignore comment",
        "h_only": "show only secrets still present at HEAD, or only those removed from it",
        "h_format": "output format",
        "h_output": "write the report to this file instead of standard output",
        "h_lang": "language of the report",
        "h_exit": "always exit with 0, even when secrets are found",
        "h_timeout": "stop after this many seconds and report partial results",
    },
    "ar": {
        "title": "كاشِف: الأسرار في سجل git",
        "repo": "المستودع",
        "head": "HEAD",
        "no_head": "(لا توجد إيداعات)",
        "commits": "إيداعات فُحصت",
        "lines": "أسطر متغيّرة فُحصت",
        "secrets": "أسرار وُجدت",
        "present_n": "ما زالت موجودة في HEAD",
        "removed_n": "أُزيلت من HEAD وباقية في السجل",
        "elapsed": "الزمن",
        "none": "لم يُعثر على أسرار في السجل المفحوص.",
        "file": "الملف",
        "commit": "أُدخل في",
        "secret": "السرّ",
        "chars": "حرفًا",
        "status": "الحالة",
        "present": "ما زال موجودًا في HEAD",
        "removed": "أُزيل في",
        "not_at_head": "غير موجود في HEAD (موجود في فرع أو وسم آخر أو كائن غير مرتبط)",
        "unreachable": "كائن غير مرتبط",
        "seen": "مرات الظهور",
        "also": "يطابق أيضًا",
        "notes": "ملاحظات",
        "remediation": "ما العمل",
        "rem_1": "1. بدّل السرّ أولًا. أبطل كل سرّ مذكور هنا لدى مزوّده وأصدر غيره. أي سرّ دُفع إلى مستودع ولو مرة "
                 "يُعدّ مكشوفًا، حتى الذي حُذف لاحقًا: كل من لديه نسخة أو تفريع أو ذاكرة CI أو مرآة ما زال يملكه.",
        "rem_2": "2. راجع سجل التدقيق لدى المزوّد بحثًا عن استخدام للسرّ القديم بين تاريخ إيداعه وتاريخ تبديله.",
        "rem_3": "3. احذف الأسرار التي ما زالت في HEAD واقرأها من متغيرات البيئة أو من مدير أسرار.",
        "rem_4": "4. بعد ذلك فقط، وإن اقتضت السياسة، أعد كتابة السجل: `git filter-repo --replace-text "
                 "replacements.txt` (أو `--invert-paths --path FILE` لحذف ملف كامل)، أو BFG Repo-Cleaner "
                 "`--replace-text`. ادفع كل الفروع والوسوم قسرًا، واطلب من كل المساهمين إعادة الاستنساخ، واطلب من "
                 "خدمة الاستضافة حذف النسخ المخبّأة والإيداعات المعلّقة. إعادة الكتابة لا تصل إلى التفريعات "
                 "والنسخ الموجودة، ولهذا يأتي التبديل أولًا.",
        "rem_5": "5. امنع التكرار: شغّل `kashif` قبل كل إيداع (pre-commit) وفي CI.",
        "e_git": "برنامج git غير موجود؛ ثبّته لفحص السجل",
        "e_repo": "ليس مستودع git: {path}",
        "e_branch": "اسم فرع أو مراجعة غير صالح: {name}",
        "e_fail": "فشل git: {msg}",
        "n_shallow": "نسخة سطحية: جزء من السجل فقط متاح (نفّذ `git fetch --unshallow`).",
        "n_timeout": "توقّف الفحص بعد {sec} ثانية (حدّ الزمن)؛ النتائج جزئية.",
        "n_cap": "بلغ عدد النتائج الحدّ الأقصى ({n})؛ لم تُسجَّل أسرار أخرى.",
        "n_entropy": "كاشف العشوائية غير متاح في هذه النسخة؛ طُبّقت قواعد الأنماط فقط.",
        "n_fsck": "فشل git fsck؛ لم تُفحص الكائنات غير المرتبطة.",
        "n_window": "نافذة السجل محدودة بـ --since/--until/--max-commits: الأسرار الأقدم لا تظهر.",
        "n_long": "لم يُفحص {n} سطرًا متغيّرًا أطول من {limit} حرفًا.",
        "n_paths": "بعض الأسرار يظهر في ملفات كثيرة جدًا يتعذّر تتبّعها كلها؛ قد يكون فحص «ما زال في HEAD» ناقصًا.",
        "e_write": "تعذّرت الكتابة في {path}: {msg}",
        "h_desc": "ابحث عن الأسرار في سجل git لمستودع (كل إيداع وكل فرع).",
        "h_repo": "مسار مستودع git (الافتراضي: المجلد الحالي)",
        "h_since": "الإيداعات الأحدث من هذا التاريخ فقط (بصيغة git، مثل 2024-01-01)",
        "h_until": "الإيداعات الأقدم من هذا التاريخ فقط",
        "h_max": "افحص N إيداعًا على الأكثر (الأحدث)",
        "h_branch": "فرع أو وسم أو مراجعة تُفحص بدل كل المراجع (يمكن تكراره)",
        "h_unreach": "افحص أيضًا reflog والإيداعات والملفات غير المرتبطة؛ بطيء",
        "h_exclude": "تجاهل الملفات المطابقة لهذا النمط (يمكن تكراره)",
        "h_entropy": "عطّل كاشف العشوائية العالية (قواعد الأنماط فقط)",
        "h_suppress": "أبلغ عن الأسطر حتى لو حملت تعليق nosec أو vulnscan: ignore",
        "h_only": "اعرض الأسرار الموجودة في HEAD فقط، أو المُزالة منه فقط",
        "h_format": "صيغة المخرجات",
        "h_output": "اكتب التقرير في هذا الملف بدل المخرج القياسي",
        "h_lang": "لغة التقرير",
        "h_exit": "اخرج دائمًا بالرمز 0 حتى عند وجود أسرار",
        "h_timeout": "توقّف بعد هذا العدد من الثواني وأعطِ نتائج جزئية",
    },
}


def _t(lang: str, key: str, **kw) -> str:
    text = STR.get(lang, STR["en"]).get(key) or STR["en"][key]
    return text.format(**kw) if kw else text


def remediation(lang: str = "en") -> list[str]:
    """The remediation steps (rotate first, then history rewrite) in the given language."""
    return [_t(lang, f"rem_{i}") for i in range(1, 6)]


# ------------------------------------------------------------------------------------------------ detection
class HistoryError(Exception):
    """git is missing, the path is not a repository, or git reported an error.

    ``args`` is ``(key of STR, {format arguments})``; ``str(exc)`` is the English message and
    :func:`error_text` gives it in a chosen language."""

    def __str__(self) -> str:
        return error_text(self, "en")


_MAX_LINE = getattr(_scanner, "MAX_LINE_LEN", 4000)
_SUPPRESS = getattr(_scanner, "SUPPRESS", re.compile(r"(nosec|vulnscan:\s*ignore)", re.I))
_SKIP_GLOBS = tuple(getattr(_scanner, "SKIP_FILE_GLOBS", ()))
_PREV_NAME = getattr(_scanner, "_PREV_NAME", None)
_PEM_BEGIN = getattr(_scanner, "_PEM_BEGIN", None)
_PEM_END = getattr(_scanner, "_PEM_END", None)
_ENTROPY = getattr(_scanner, "_entropy_findings", None)
_ENTROPY_RULE = getattr(_scanner, "ENTROPY_RULE", {"id": "SEC011"})

_NO_VALUE_RULES = frozenset({"SEC009"})                  # a marker line, the secret is the rest of the file
_BOUND_VALUE = re.compile(r"""[:=]\s*['"]?([^'"\s]{6,}?)['"]?$""")
_URL_PASS = re.compile(r"://[^:/\s'\"]*:([^@\s'\"]{3,})@")
_ACCOUNT_KEY = re.compile(r"(?i)AccountKey=([A-Za-z0-9+/]{20,}={0,2})")
_KEY_BODY = re.compile(r"[A-Za-z0-9+/=]{24,}")
_LONG_TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{20,}={0,2}")
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_REV_OK = re.compile(r"^[^\-\s][^\s\x00-\x1f\x7f]*$")


def secret_rules() -> list:
    """The built-in secret rules (ids starting with SEC) this module applies to every changed line."""
    return [r for r in RULES if r.id.startswith("SEC")]


def redact(secret: str) -> str:
    """Redacted form of a secret, showing at most a third of it: first and last 4 characters from 24
    characters up, first and last 2 from 12 up, nothing below that.

    >>> redact("abcdefghijklmnopqrstuvwxyz")
    'abcd****wxyz'
    >>> redact("abcdefghijklmnop")
    'ab****op'
    """
    n = len(secret)
    if n >= 24:
        return f"{secret[:4]}****{secret[-4:]}"
    if n >= 12:
        return f"{secret[:2]}****{secret[-2:]}"
    return "****"


_UNSAFE_CHARS = re.compile("[\x00-\x08\x0a-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def _clean(text) -> str:
    """Text safe to print: control characters (terminal escape sequences) and bidirectional overrides taken
    from the repository (file names, author names, subjects, code) are replaced by ``?``."""
    return _UNSAFE_CHARS.sub("?", str(text)).replace("\t", " ")


@dataclass
class _Hit:
    rule_id: str
    severity: str
    title: str
    title_ar: str
    advice: str
    cwe: str
    value: str | None            # the secret text; None when the rule marks a file rather than a value
    extra: dict = field(default_factory=dict)
    needs_body: bool = False     # private-key header: the next line of the same kind is the identity


def _value_of(rule_id: str, match: re.Match, line: str) -> str | None:
    text = match.group(0)
    if rule_id in _NO_VALUE_RULES or text.startswith("PuTTY-User-Key-File"):
        return None
    if rule_id == "SEC010":
        m = _ACCOUNT_KEY.search(line)
        return m.group(1) if m else None
    if "://" in text:
        m = _URL_PASS.search(text)
        return m.group(1) if m and rule_id == "SEC006" else text
    m = _BOUND_VALUE.search(text)
    if m and re.search(r"[:=]", text):
        return m.group(1)
    return text if len(text) >= 6 else None


def _entropy_value(line: str, ctx: str | None) -> str | None:
    """Locate the token the entropy detector fired on (it returns the line, not the value)."""
    s = _scanner
    try:
        for m in s._LITERAL.finditer(line):
            before = line[max(0, m.start() - 120):m.start() + 1]
            if s._VALUE_CONTEXT_SKIP.search(before[:-1]) or not s._secret_name(before, ctx):
                continue
            if s._looks_random(m.group(2))[0]:
                return m.group(2)
        for m in s._URL_PASSWORD.finditer(line):
            ok, ent = s._looks_random(m.group(1))
            if ok or (ent >= 3.0 and len(m.group(1)) >= 12):
                return m.group(1)
        fallback = None
        for m in s._TOKEN.finditer(line):
            tok = m.group(0)
            if not 20 <= len(tok) <= 200 or not s._looks_random(tok)[0]:
                continue
            before = line[max(0, m.start() - 120):m.start()]
            if s._VALUE_CONTEXT_SKIP.search(before):
                continue
            if s._secret_name(before, ctx) or len(tok) >= 40:
                return tok
            fallback = fallback or tok
        if fallback:
            return fallback
    except AttributeError:
        pass
    cands = _LONG_TOKEN.findall(line)
    return max(cands, key=len) if cands else None


def _detect(line: str, rules: list, ctx: str | None, entropy: bool, suppress: bool) -> list[_Hit]:
    """Secrets on one line of text: pattern rules first, the entropy detector when none matched."""
    if len(line) > _MAX_LINE or len(line) < 8 or (suppress and _SUPPRESS.search(line)):
        return []
    hits: list[_Hit] = []
    for rule in rules:
        m = rule.pattern.search(line)
        if not m or (rule.skip and rule.skip.search(line)):
            continue
        hit = _Hit(rule.id, rule.severity, rule.title, rule.title_ar, rule.advice, rule.cwe, _value_of(rule.id, m, line))
        if "PRIVATE KEY" in m.group(0):
            rest = line[m.end():].replace("\\n", "").replace("\\r", "")
            body = _KEY_BODY.search(rest)
            if body:
                hit.value = body.group(0)[:64]            # one-line key (JSON / env): the body is on this line
            else:
                hit.value, hit.needs_body = None, True
        hits.append(hit)
    if not hits and entropy and _ENTROPY is not None:
        for f in _ENTROPY("", 0, line, ctx):
            val = _entropy_value(line, ctx)
            if val:
                hits.append(_Hit(f.rule_id, f.severity, f.title, f.title_ar, f.advice, f.cwe, val, dict(f.extra)))
    # one secret matched by several rules is one secret: keep the first (most specific order = catalogue order)
    out: list[_Hit] = []
    for h in hits:
        twin = next((o for o in out if o.value is not None and o.value == h.value), None)
        if twin is None:
            out.append(h)
        elif h.rule_id not in twin.extra.setdefault("also_rules", []) and h.rule_id != twin.rule_id:
            twin.extra["also_rules"].append(h.rule_id)
    return out


def _mask_line(line: str, values: list[str]) -> str:
    """The line with every detected secret, and any other random-looking long token, redacted."""
    out = line.strip()
    for v in sorted({v for v in values if v}, key=len, reverse=True):
        out = out.replace(v, redact(v))
    looks = getattr(_scanner, "_looks_random", None)

    def _tok(m: re.Match) -> str:
        tok = m.group(0)
        if "****" in tok:
            return tok
        try:
            rnd = looks(tok)[0] if looks else True
        except Exception:                # noqa: BLE001 - masking must never fail
            rnd = True
        return redact(tok) if rnd or key_line else tok
    key_line = "PRIVATE KEY" in out
    return _clean(_LONG_TOKEN.sub(_tok, out)[:200])


# ------------------------------------------------------------------------------------------------ git plumbing
@dataclass(frozen=True)
class _Commit:
    hash: str
    date: str
    author: str
    email: str
    subject: str


@dataclass
class _Record:
    key: tuple
    hit: _Hit
    commit: _Commit
    file: str
    line: int
    snippet: str
    order: int
    occurrences: int = 1
    files: dict = field(default_factory=dict)     # path -> None, insertion ordered, capped (for display)
    paths: set = field(default_factory=set)       # every path the secret was added to (for the HEAD check)
    unreachable: bool = False


@dataclass
class HistoryResult:
    """Outcome of :func:`scan_history`.

    ``findings`` are ``vulnscan.model.Finding`` objects (``source="git-history"``), sorted and fingerprinted.
    Each carries in ``extra``: ``commit``, ``commit_short``, ``date`` (author date, ISO 8601), ``author``,
    ``author_email``, ``subject``, ``secret_redacted``, ``secret_length``, ``still_present`` (bool),
    ``status`` (``present`` | ``removed`` | ``not-at-head``), ``head_file`` / ``head_line`` when present,
    ``removed_in`` (``{"commit", "commit_short", "date", "author"}`` or None), ``occurrences``, ``files``,
    ``secret_group`` (ordinal of the secret in order of first appearance), ``also_rules`` and ``unreachable``.
    The secret itself is never stored on a finding.
    """
    repo: str
    head: str | None
    findings: list
    commits_scanned: int = 0
    lines_scanned: int = 0
    elapsed: float = 0.0
    notes: list = field(default_factory=list)       # note keys of STR (with arguments), see notes_text()
    options: dict = field(default_factory=dict)

    @property
    def present(self) -> list:
        return [f for f in self.findings if f.extra.get("still_present")]

    @property
    def removed(self) -> list:
        return [f for f in self.findings if not f.extra.get("still_present")]

    def notes_text(self, lang: str = "en") -> list[str]:
        return [_t(lang, key, **kw) for key, kw in self.notes]


# Variables a calling git hook (pre-commit, pre-push ...) exports: they would silently redirect git to another
# repository than the one named, or re-enable an external diff program.
_ENV_DROP = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_NAMESPACE", "GIT_PREFIX",
             "GIT_EXTERNAL_DIFF", "GIT_DIFF_OPTS", "GIT_GRAFT_FILE", "GIT_REPLACE_REF_BASE")


def _git_env() -> dict:
    env = {k: v for k, v in os.environ.items() if k.upper() not in _ENV_DROP}
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_PAGER": "cat", "LC_ALL": "C",
                "GIT_ASKPASS": "", "GIT_FLUSH": "0",
                # A hostile .git/config can declare a partial clone whose "remote" is a command (ext::sh -c ...)
                # that git would run to fetch a missing object. Forbid lazy fetching (git >= 2.45 and patched
                # older releases) and, for every version, every transport protocol.
                "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "",
                "GIT_NO_REPLACE_OBJECTS": "1"})          # report the real objects, not refs/replace stand-ins
    return env


def _git_base(repo: pathlib.Path) -> list[str]:
    exe = shutil.which("git")
    if not exe:
        raise HistoryError("e_git")
    return [exe, "-C", str(repo), "--no-pager", "-c", "core.quotePath=false", "-c", "diff.renames=true",
            "-c", "core.fsmonitor=false", "-c", "log.showSignature=false", "-c", "diff.noprefix=false",
            "-c", "diff.mnemonicPrefix=false", "-c", "diff.relative=false", "-c", "color.ui=false"]


def _git_out(repo: pathlib.Path, *args: str, timeout: float = 120) -> tuple[int, str]:
    try:
        p = subprocess.run(_git_base(repo) + list(args), capture_output=True, env=_git_env(), timeout=timeout,
                           stdin=subprocess.DEVNULL, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return p.returncode, (p.stdout if p.returncode == 0 else p.stderr).decode("utf-8", "replace").strip()


def _unquote(path: str) -> str:
    """Undo git's C-style quoting of unusual path names."""
    path = path.rstrip("\t")
    if not (len(path) >= 2 and path.startswith('"') and path.endswith('"')):
        return path
    raw = bytearray()
    body = path[1:-1].encode("utf-8", "surrogateescape")
    i = 0
    simple = {ord("n"): 10, ord("t"): 9, ord("r"): 13, ord('"'): 34, ord("\\"): 92, ord("a"): 7, ord("b"): 8,
              ord("f"): 12, ord("v"): 11}
    while i < len(body):
        c = body[i]
        if c == 92 and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt in simple:
                raw.append(simple[nxt])
                i += 2
                continue
            if 48 <= nxt <= 55 and i + 3 < len(body) and all(48 <= b <= 55 for b in body[i + 1:i + 4]):
                raw.append(int(body[i + 1:i + 4], 8) & 0xFF)
                i += 4
                continue
        raw.append(c)
        i += 1
    return raw.decode("utf-8", "replace")


def _strip_prefix(path: str, prefix: str) -> str | None:
    """Path of a ``---`` / ``+++`` line without the (forced) ``a/`` or ``b/`` prefix; None for /dev/null."""
    path = _unquote(path)
    if path == "/dev/null":
        return None
    return path[2:] if path.startswith(prefix) else path


def _read_lines(stream, limit: int):
    """Lines of a binary stream as text, without ever holding an over-long line in memory.

    Yields ``(text, overlong)``; for an over-long line only its first ``limit`` bytes are returned."""
    while True:
        chunk = stream.readline(limit + 2)
        if not chunk:
            return
        overlong = not chunk.endswith(b"\n") and len(chunk) >= limit + 2
        if overlong:
            while True:                              # drain the rest of the line
                more = stream.readline(65536)
                if not more or more.endswith(b"\n"):
                    break
        yield chunk.rstrip(b"\r\n").decode("utf-8", "replace"), overlong


class _Walker:
    """State of one history walk: parses the ``git log -p`` stream and collects one record per secret."""

    def __init__(self, entropy: bool, suppress: bool, excludes: list[str], max_findings: int):
        self.rules = secret_rules()
        self.entropy = entropy
        self.suppress = suppress
        self.excludes = excludes
        self.max_findings = max_findings
        self.records: dict[tuple, _Record] = {}
        self.removals: dict[tuple, _Commit] = {}
        self.renames: dict[str, set] = {}
        self.commits = 0
        self.lines = 0
        self.long_lines = 0
        self.capped = False
        self.path_budget = 200000                 # paths remembered over all records (memory bound)
        self.paths_capped = False
        self._rule_cache: dict[tuple, list] = {}
        self._skip_cache: dict[str, bool] = {}

    # -- per file -------------------------------------------------------------------------------------------
    def rules_for(self, path: str) -> list:
        p = pathlib.PurePosixPath(path)
        try:
            keys = frozenset(_scanner._ext_keys(p))
        except Exception:                # noqa: BLE001 - private helper of another module; fall back
            keys = frozenset({p.suffix.lower(), p.name})
        got = self._rule_cache.get(keys)
        if got is None:
            got = self._rule_cache[keys] = [r for r in self.rules if r.langs is None or keys & r.langs]
        return got

    def skipped(self, path: str) -> bool:
        got = self._skip_cache.get(path)
        if got is None:
            name = path.rsplit("/", 1)[-1]
            got = (any(fnmatch.fnmatch(name, g) for g in _SKIP_GLOBS)
                   or any(fnmatch.fnmatch(path, g) or fnmatch.fnmatch(name, g) for g in self.excludes))
            if len(self._skip_cache) > 50000:
                self._skip_cache.clear()
            self._skip_cache[path] = got
        return got

    # -- recording ------------------------------------------------------------------------------------------
    @staticmethod
    def key_of(hit: _Hit, path: str) -> tuple:
        return ("v", hit.value) if hit.value else ("f", hit.rule_id, path)

    def add(self, hit: _Hit, commit: _Commit, path: str, lineno: int, line: str, values: list[str],
            unreachable: bool = False) -> None:
        key = self.key_of(hit, path)
        rec = self.records.get(key)
        if rec is None:
            if len(self.records) >= self.max_findings:
                self.capped = True
                return
            rec = self.records[key] = _Record(key, hit, commit, path, lineno, _mask_line(line, values),
                                              len(self.records), unreachable=unreachable)
        else:
            rec.occurrences += 1
            for rid in [hit.rule_id] + hit.extra.get("also_rules", []):
                also = rec.hit.extra.setdefault("also_rules", [])
                if rid != rec.hit.rule_id and rid not in also:
                    also.append(rid)
        if len(rec.files) < 20:
            rec.files.setdefault(path, None)
        if path not in rec.paths:
            if self.path_budget > 0:
                self.path_budget -= 1
                rec.paths.add(path)
            else:
                self.paths_capped = True

    def removed(self, hit: _Hit, commit: _Commit, path: str) -> None:
        """Remember the (latest) commit that deleted a line holding an already recorded secret."""
        key = self.key_of(hit, path)
        if key in self.records:                  # oldest first: the addition is always seen before the removal
            self.removals[key] = commit

    # -- stream ---------------------------------------------------------------------------------------------
    def feed(self, stream, deadline: float | None, progress=None) -> bool:
        """Consume a ``git log -p`` stream. Returns False when the deadline stopped it early."""
        commit: _Commit | None = None
        old_path = new_path = None
        rules: list = []
        skip = True
        old_left = new_left = 0
        new_no = 0
        ctx: str | None = None
        in_pem = False
        pending: dict[str, tuple | None] = {"+": None, "-": None}
        in_key = {"+": False, "-": False}            # inside the body of a private key on that side of the diff

        def flush(sign: str | None = None) -> None:
            for s in ((sign,) if sign else ("+", "-")):
                item = pending[s]
                if item is None:
                    continue
                pending[s] = None
                hit, path, lineno, line = item
                if s == "+":
                    self.add(hit, commit, path, lineno, line, [])
                else:
                    self.removed(hit, commit, path)

        seen = 0
        for text, overlong in _read_lines(stream, _MAX_LINE + 8):
            seen += 1
            if deadline and seen % 2000 == 0 and time.monotonic() > deadline:      # one commit can be huge
                return False
            if old_left <= 0 and new_left <= 0:                       # between hunks: headers
                if text.startswith("\x01"):
                    flush()
                    parts = text[1:].split("\x02")
                    parts += [""] * (5 - len(parts))
                    commit = _Commit(*parts[:5])
                    self.commits += 1
                    old_path = new_path = None
                    if progress and self.commits % 200 == 0:
                        progress(self.commits)
                    if deadline and self.commits % 20 == 0 and time.monotonic() > deadline:
                        return False
                elif text.startswith("@@ "):
                    flush()
                    m = _HUNK.match(text)
                    if m:
                        in_key["+"] = in_key["-"] = False
                        old_left = int(m.group(2)) if m.group(2) is not None else 1
                        new_no = int(m.group(3))
                        new_left = int(m.group(4)) if m.group(4) is not None else 1
                        ctx, in_pem = None, False
                elif text.startswith("diff --git "):
                    flush()
                    old_path = new_path = None
                    skip = True
                elif text.startswith("--- "):
                    old_path = _strip_prefix(text[4:], "a/")
                elif text.startswith("+++ "):
                    new_path = _strip_prefix(text[4:], "b/")
                    path = new_path or old_path
                    skip = path is None or self.skipped(path)
                    rules = [] if skip else self.rules_for(path)
                elif text.startswith("rename from "):
                    old_path = _unquote(text[12:])
                elif text.startswith("rename to "):
                    new_path = _unquote(text[10:])
                    if old_path and new_path:
                        self.renames.setdefault(old_path, set()).add(new_path)
                continue
            # inside a hunk
            sign, body = (text[0], text[1:]) if text else (" ", "")
            if sign == "\\":
                continue
            if sign == "+":
                new_left -= 1
                lineno, new_no = new_no, new_no + 1
            elif sign == "-":
                old_left -= 1
                lineno = 0
            else:
                old_left -= 1
                new_left -= 1
                new_no += 1
                flush()
                in_key["+"] = in_key["-"] = False
                if _PREV_NAME is not None:
                    m = _PREV_NAME.search(body)
                    ctx = (m.group(1) or m.group(2)) if m else None
                if old_left <= 0 and new_left <= 0:
                    flush()
                continue
            if overlong and not skip:
                self.long_lines += 1
            if not skip and commit is not None and not overlong:
                self.lines += 1
                path = (new_path or old_path) if sign == "+" else (old_path or new_path)
                item = pending[sign]
                if item is not None:                    # the line after a private-key header is the key body
                    m = _KEY_BODY.fullmatch(body.strip().strip("\"',\\n"))
                    if m:
                        item[0].value = m.group(0)[:64]
                    flush(sign)
                    in_key[sign] = bool(m)
                    if m:
                        if sign == "+":
                            ctx = None
                        if old_left <= 0 and new_left <= 0:
                            flush()
                        continue
                pem = False
                if in_key[sign]:                        # remaining body lines of a private key: one finding only
                    if _KEY_BODY.fullmatch(body.strip().strip("\"',\\n")):
                        continue_key = True
                    else:
                        continue_key = "-----END" in body
                        in_key[sign] = False
                    if continue_key:
                        if old_left <= 0 and new_left <= 0:
                            flush()
                        continue
                if sign == "+" and _PEM_BEGIN is not None:
                    if _PEM_BEGIN.search(body):
                        in_pem = not _PEM_END.search(body)
                        pem = True
                    elif in_pem:
                        pem = True
                        if _PEM_END.search(body):
                            in_pem = False
                if not pem:
                    hits = _detect(body, rules, ctx if sign == "+" else None, self.entropy, self.suppress)
                    values = [h.value for h in hits if h.value]
                    for hit in hits:
                        if hit.needs_body:
                            flush(sign)
                            pending[sign] = (hit, path, lineno, body)
                        elif sign == "+":
                            self.add(hit, commit, path, lineno, body, values)
                        else:
                            self.removed(hit, commit, path)
                if sign == "+" and _PREV_NAME is not None:
                    m = _PREV_NAME.search(body)
                    ctx = (m.group(1) or m.group(2)) if m else None
            if old_left <= 0 and new_left <= 0:
                flush()
        flush()
        if progress:
            progress(self.commits)
        return True

    def feed_blob(self, sha: str, text: str) -> None:
        """Scan the whole content of an unreachable blob."""
        commit = _Commit("", "", "", "", "")
        path = f"<unreachable blob {sha[:12]}>"
        ctx = None
        in_key = False
        lines = text.split("\n")                 # not splitlines(): keep git's notion of a line
        for i, line in enumerate(lines, 1):
            line = line.rstrip("\r")
            self.lines += 1
            if len(line) > _MAX_LINE:
                self.long_lines += 1
            if in_key:
                if _KEY_BODY.fullmatch(line.strip()):
                    continue
                in_key = False
                if "-----END" in line:
                    continue
            hits = _detect(line, self.rules, ctx, self.entropy, self.suppress)
            values = [h.value for h in hits if h.value]
            for hit in hits:
                if hit.needs_body and i < len(lines):
                    m = _KEY_BODY.fullmatch(lines[i].strip())
                    hit.value = m.group(0)[:64] if m else None
                    in_key = bool(m)
                self.add(hit, commit, path, i, line, values, unreachable=True)
            if _PREV_NAME is not None:
                m = _PREV_NAME.search(line)
                ctx = (m.group(1) or m.group(2)) if m else None


class _CatFile:
    """One ``git cat-file --batch`` process answering content requests."""

    def __init__(self, repo: pathlib.Path):
        self.proc = subprocess.Popen(_git_base(repo) + ["cat-file", "--batch"], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=_git_env())

    def get(self, spec: str, max_bytes: int = 5 * 1024 * 1024) -> str | None:
        """Text of ``spec`` (``HEAD:path`` or an object id); None when missing, binary, not a blob or too big."""
        if "\n" in spec or "\r" in spec:
            return None
        try:
            self.proc.stdin.write(spec.encode("utf-8", "surrogateescape") + b"\n")
            self.proc.stdin.flush()
            head = self.proc.stdout.readline().decode("utf-8", "replace").rstrip("\n")
        except (OSError, ValueError):
            return None
        parts = head.rsplit(" ", 2)
        if len(parts) != 3 or not parts[2].isdigit():
            return None                                   # "<spec> missing" / ambiguous
        size, kind = int(parts[2]), parts[1]
        data = bytearray()
        left = size + 1                                   # content is followed by a newline
        while left > 0:
            chunk = self.proc.stdout.read(min(left, 1 << 20))
            if not chunk:
                break
            left -= len(chunk)
            if len(data) <= max_bytes:
                data += chunk
        if kind != "blob" or size > max_bytes or b"\x00" in data[:8192]:
            return None
        return bytes(data[:size]).decode("utf-8", "replace")

    def close(self) -> None:
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            self.proc.kill()
        finally:
            for s in (self.proc.stdout,):
                try:
                    s.close()
                except OSError:
                    pass


def _closure(paths, renames: dict) -> list[str]:
    seen, todo = set(), list(paths)
    while todo:
        p = todo.pop()
        if p in seen:
            continue
        seen.add(p)
        todo.extend(renames.get(p, ()))
    return sorted(seen)


def _head_presence(repo: pathlib.Path, walker: _Walker) -> dict[tuple, tuple]:
    """Which recorded secrets are in the HEAD tree: key -> (file, line)."""
    by_path: dict[str, list] = {}
    for rec in walker.records.values():
        if rec.unreachable and not any(not f.startswith("<") for f in rec.paths):
            continue
        for p in _closure([f for f in rec.paths if not f.startswith("<")], walker.renames):
            by_path.setdefault(p, []).append(rec)
    found: dict[tuple, tuple] = {}
    if not by_path:
        return found
    cat = _CatFile(repo)
    try:
        for path in sorted(by_path):
            recs = [r for r in by_path[path] if r.key not in found]
            if not recs:
                continue
            text = cat.get(f"HEAD:{path}")
            if text is None:
                continue
            lines = None
            for rec in recs:
                if rec.hit.value:
                    pos = text.find(rec.hit.value)
                    if pos >= 0:
                        found[rec.key] = (path, text.count("\n", 0, pos) + 1)
                    continue
                rule = next((r for r in walker.rules if r.id == rec.hit.rule_id), None)
                if rule is None:
                    continue
                lines = lines if lines is not None else text.split("\n")
                for i, line in enumerate(lines, 1):
                    if len(line) <= _MAX_LINE and rule.pattern.search(line):
                        found[rec.key] = (path, i)
                        break
    finally:
        cat.close()
    return found


def _unreachable(repo: pathlib.Path, timeout: float = 3600) -> tuple[list[str], list[str]] | None:
    """(commit ids, blob ids) that no ref or reflog reaches. ``git fsck --unreachable`` only reads the repository."""
    rc, out = _git_out(repo, "fsck", "--unreachable", "--no-progress", "--no-dangling", timeout=timeout)
    if rc != 0:
        return None
    commits, blobs = [], []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == "unreachable" and re.fullmatch(r"[0-9a-f]{40,64}", parts[2]):
            if parts[1] == "commit":
                commits.append(parts[2])
            elif parts[1] == "blob":
                blobs.append(parts[2])
    return sorted(commits), sorted(blobs)


def scan_history(repo, since: str | None = None, until: str | None = None, max_commits: int | None = None,
                 branches: list[str] | None = None, include_unreachable: bool = False,
                 excludes: list[str] | None = None, entropy: bool = True, honor_suppressions: bool = True,
                 max_findings: int = 5000, timeout: float | None = None, progress=None) -> HistoryResult:
    """Find every secret ever committed to the git repository at ``repo``.

    repo                 path to a work tree or bare repository (made absolute; never passed through a shell)
    since / until        git date expressions limiting the commits examined (``"2024-01-01"``, ``"3 months ago"``)
    max_commits          examine only the N most recent commits
    branches             revisions to walk; default is every ref (``--all``)
    include_unreachable  also walk the reflog and dangling commits, and scan dangling blobs (slow: runs git fsck)
    excludes             file globs to skip, matched against the path and the base name
    entropy              apply the high-entropy detector (SEC011) to lines no pattern rule matched
    honor_suppressions   skip lines carrying ``nosec`` / ``vulnscan: ignore``, like the normal scan does
    max_findings         stop recording new secrets after this many (a note is added)
    timeout              seconds after which the walk stops with partial results (a note is added)
    progress             optional callable receiving the number of commits processed so far

    Returns a :class:`HistoryResult`. Raises :class:`HistoryError` (its message is a key of ``STR`` plus
    arguments; ``str(exc)`` is English, :func:`error_text` any language) when git is missing, the path
    is not a repository or git fails. Scanned content is never executed, and the repository is never modified.
    """
    started = time.monotonic()
    root = pathlib.Path(repo).expanduser().resolve()
    if not root.is_dir():
        raise HistoryError("e_repo", {"path": str(root)})
    rc, out = _git_out(root, "rev-parse", "--git-dir")
    if rc != 0:
        if "dubious ownership" in out or "safe.directory" in out:       # git refuses: say why, not "no repository"
            raise HistoryError("e_fail", {"msg": _clean(out.splitlines()[0])})
        raise HistoryError("e_repo", {"path": str(root)})
    for name in branches or []:
        if not _REV_OK.match(name or ""):
            raise HistoryError("e_branch", {"name": name})
    rc, head = _git_out(root, "rev-parse", "--verify", "-q", "HEAD^{commit}")
    head = head if rc == 0 and head else None
    notes: list = []
    if _git_out(root, "rev-parse", "--is-shallow-repository")[1] == "true":
        notes.append(("n_shallow", {}))
    if since or until or max_commits:
        notes.append(("n_window", {}))
    if entropy and _ENTROPY is None:
        notes.append(("n_entropy", {}))

    walker = _Walker(entropy, honor_suppressions, list(excludes or []), max_findings)
    revs: list[str] = list(branches or [])
    blobs: list[str] = []
    deadline = started + timeout if timeout else None
    if include_unreachable:
        got = _unreachable(root, max(1.0, min(3600.0, timeout)) if timeout else 3600)
        if got is None:
            notes.append(("n_fsck", {}))
        else:
            revs += got[0]
            blobs = got[1]

    if True:
        args = ["log", "-p", "-U1", "-M", "--no-color", "--no-ext-diff", "--no-textconv", "--date-order", "--reverse",
                "--src-prefix=a/", "--dst-prefix=b/", "--submodule=short",
                "--format=%x01%H%x02%aI%x02%an%x02%ae%x02%s"]
        if since:
            args.append(f"--since={since}")
        if until:
            args.append(f"--until={until}")
        if max_commits:
            args.append(f"--max-count={int(max_commits)}")
        if not branches:
            args.append("--all")
        if include_unreachable:
            args.append("--reflog")
        args.append("--stdin")
        with tempfile.TemporaryFile() as err, tempfile.TemporaryFile() as revin:
            revin.write(("\n".join(revs) + "\n").encode() if revs else b"")
            revin.seek(0)
            proc = subprocess.Popen(_git_base(root) + args, stdin=revin, stdout=subprocess.PIPE, stderr=err,
                                    env=_git_env(), bufsize=1 << 20)
            finished = True
            try:
                finished = walker.feed(proc.stdout, deadline, progress)
            finally:
                if not finished or sys.exc_info()[0] is not None:
                    proc.kill()
                proc.stdout.close()
                rc = proc.wait()
            if not finished:
                notes.append(("n_timeout", {"sec": int(timeout or 0)}))
            elif rc != 0:
                err.seek(0)
                msg = err.read(2000).decode("utf-8", "replace").strip().splitlines()
                raise HistoryError("e_fail", {"msg": _clean(msg[-1]) if msg else f"exit {rc}"})

    if blobs:
        cat = _CatFile(root)
        try:
            for sha in blobs:
                if deadline and time.monotonic() > deadline:
                    if ("n_timeout", {"sec": int(timeout or 0)}) not in notes:
                        notes.append(("n_timeout", {"sec": int(timeout or 0)}))
                    break
                text = cat.get(sha, max_bytes=getattr(_scanner, "MAX_FILE_BYTES", 2 * 1024 * 1024))
                if text:
                    walker.feed_blob(sha, text)
        finally:
            cat.close()
    if walker.capped:
        notes.append(("n_cap", {"n": max_findings}))
    if walker.long_lines:
        notes.append(("n_long", {"n": walker.long_lines, "limit": _MAX_LINE}))
    if walker.paths_capped:
        notes.append(("n_paths", {}))

    present = _head_presence(root, walker) if head else {}
    findings: list[Finding] = []
    for group, rec in enumerate(sorted(walker.records.values(), key=lambda r: r.order), 1):
        hit, c = rec.hit, rec.commit
        at_head = present.get(rec.key)
        gone = None if at_head else walker.removals.get(rec.key)
        extra = {k: v for k, v in hit.extra.items() if k != "also_rules"}
        if hit.extra.get("also_rules"):
            extra["also_rules"] = sorted(hit.extra["also_rules"])
        extra.update({
            "commit": c.hash, "commit_short": c.hash[:10], "date": c.date, "author": c.author,
            "author_email": c.email, "subject": c.subject[:200],
            "secret_redacted": redact(hit.value) if hit.value else "",
            "secret_length": len(hit.value) if hit.value else 0,
            "still_present": bool(at_head),
            "status": "present" if at_head else ("removed" if gone else "not-at-head"),
            "head_file": at_head[0] if at_head else None, "head_line": at_head[1] if at_head else None,
            "removed_in": ({"commit": gone.hash, "commit_short": gone.hash[:10], "date": gone.date,
                            "author": gone.author} if gone else None),
            "occurrences": rec.occurrences, "files": list(rec.files), "secret_group": group,
            "unreachable": rec.unreachable, "history": True,
        })
        findings.append(Finding(hit.rule_id, hit.severity, hit.title, hit.title_ar, rec.file, rec.line, rec.snippet,
                                hit.advice, hit.cwe, source="git-history", extra=extra))
    findings = sort_findings(findings)
    assign_fingerprints(findings)
    return HistoryResult(str(root), head, findings, walker.commits, walker.lines, round(time.monotonic() - started, 3),
                         notes, {"since": since, "until": until, "max_commits": max_commits,
                                 "branches": list(branches or []), "include_unreachable": include_unreachable,
                                 "excludes": list(excludes or []), "entropy": entropy,
                                 "honor_suppressions": honor_suppressions})


def error_text(exc: HistoryError, lang: str = "en") -> str:
    """Human-readable message of a :class:`HistoryError` in the given language."""
    key = exc.args[0] if exc.args else "e_fail"
    kw = exc.args[1] if len(exc.args) > 1 and isinstance(exc.args[1], dict) else {}
    if key not in STR["en"]:
        return str(key)
    try:
        return _t(lang, key, **kw)
    except (KeyError, IndexError):
        return _t(lang, key)


# ------------------------------------------------------------------------------------------------ renderers
def result_to_dict(result: HistoryResult, lang: str = "en") -> dict:
    """JSON-serialisable form of a result. Findings use ``Finding.to_dict()`` (the format of the JSON report)."""
    return {
        "tool": "kashif-history", "schema": 1, "repo": result.repo, "head": result.head, "lang": lang,
        "stats": {"commits": result.commits_scanned, "lines": result.lines_scanned, "secrets": len(result.findings),
                  "still_present": len(result.present), "removed": len(result.removed), "elapsed": result.elapsed},
        "options": result.options,
        "notes": result.notes_text(lang),
        "remediation": {"en": remediation("en"), "ar": remediation("ar")},
        "findings": [f.to_dict() for f in result.findings],
    }


def render_json(result: HistoryResult, lang: str = "en") -> str:
    """The result as a JSON document (deterministic key order apart from timing)."""
    return json.dumps(result_to_dict(result, lang), ensure_ascii=False, indent=2)


def render_console(result: HistoryResult, lang: str = "en") -> str:
    """Plain-text report. Secrets appear only in redacted form."""
    L = lambda k, **kw: _t(lang, k, **kw)      # noqa: E731
    out = [L("title"), "=" * 60,
           f"{L('repo')}: {_clean(result.repo)}",
           f"{L('head')}: {result.head[:10] if result.head else L('no_head')}",
           f"{L('commits')}: {result.commits_scanned}   {L('lines')}: {result.lines_scanned}   "
           f"{L('elapsed')}: {result.elapsed:.2f}s",
           f"{L('secrets')}: {len(result.findings)}   {L('present_n')}: {len(result.present)}   "
           f"{L('removed_n')}: {len(result.removed)}", ""]
    if not result.findings:
        out.append(L("none"))
    for f in result.findings:
        x = f.extra
        title = f.title_ar if lang == "ar" else f.title
        out.append(f"[{f.severity.upper()}] {f.rule_id} {title}" + (f" ({f.cwe})" if f.cwe else ""))
        out.append(f"  {L('file')}: {_clean(f.file)}:{f.line}")
        if x.get("commit"):
            out.append(f"  {L('commit')}: {x['commit_short']}  {x['date']}  {_clean(x['author'])}")
        else:
            out.append(f"  {L('commit')}: {L('unreachable')}")
        if x.get("secret_redacted"):
            out.append(f"  {L('secret')}: {x['secret_redacted']} ({x['secret_length']} {L('chars')})")
        out.append(f"    {_clean(f.snippet)}")
        if x["status"] == "present":
            status = f"{L('present')} ({_clean(x['head_file'])}:{x['head_line']})"
        elif x["status"] == "removed":
            r = x["removed_in"]
            status = f"{L('removed')} {r['commit_short']}  {r['date']}  {_clean(r['author'])}"
        else:
            status = L("not_at_head")
        out.append(f"  {L('status')}: {status}")
        if x.get("occurrences", 1) > 1:
            out.append(f"  {L('seen')}: {x['occurrences']} ({', '.join(_clean(p) for p in x['files'][:5])})")
        if x.get("also_rules"):
            out.append(f"  {L('also')}: {', '.join(x['also_rules'])}")
        out.append("")
    notes = result.notes_text(lang)
    if notes:
        out.append(f"{L('notes')}:")
        out += [f"  - {n}" for n in notes]
        out.append("")
    if result.findings:
        out.append(f"{L('remediation')}:")
        out += [f"  {s}" for s in remediation(lang)]
    return "\n".join(out).rstrip() + "\n"


# ------------------------------------------------------------------------------------------------ command line
def _default_lang() -> str:
    env = (os.environ.get("KASHIF_LANG") or os.environ.get("VULNSCAN_LANG") or "").lower()
    return "ar" if env.startswith("ar") else "en"


def build_parser(lang: str = "en") -> argparse.ArgumentParser:
    """The argument parser of the ``history`` command (reusable by cli.py)."""
    H = lambda k: _t(lang, k)                  # noqa: E731
    p = argparse.ArgumentParser(prog="kashif history", description=H("h_desc"))
    p.add_argument("repo", nargs="?", default=".", help=H("h_repo"))
    p.add_argument("--since", help=H("h_since"))
    p.add_argument("--until", help=H("h_until"))
    p.add_argument("--max-commits", type=int, metavar="N", help=H("h_max"))
    p.add_argument("--branch", action="append", default=[], metavar="NAME", help=H("h_branch"))
    p.add_argument("--include-unreachable", action="store_true", help=H("h_unreach"))
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help=H("h_exclude"))
    p.add_argument("--no-entropy", action="store_true", help=H("h_entropy"))
    p.add_argument("--no-suppress", action="store_true", help=H("h_suppress"))
    p.add_argument("--only", choices=("present", "removed"), help=H("h_only"))
    p.add_argument("-f", "--format", choices=("console", "json"), default="console", help=H("h_format"))
    p.add_argument("-o", "--output", metavar="FILE", help=H("h_output"))
    p.add_argument("--lang", choices=("en", "ar"), default=lang, help=H("h_lang"))
    p.add_argument("--timeout", type=float, metavar="SEC", help=H("h_timeout"))
    p.add_argument("--exit-zero", action="store_true", help=H("h_exit"))
    return p


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point. Returns 0 (clean), 1 (secrets found) or 2 (error)."""
    argv = list(sys.argv[1:] if argv is None else argv)
    lang = _default_lang()
    for i, a in enumerate(argv):                       # the help text follows --lang, so look for it first
        if a == "--lang" and i + 1 < len(argv) and argv[i + 1] in STR:
            lang = argv[i + 1]
        elif a.startswith("--lang=") and a[7:] in STR:
            lang = a[7:]
    for stream in (sys.stdout, sys.stderr):            # a legacy console code page must not crash the report
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    try:
        args = build_parser(lang).parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 2)
    try:
        # by design: the operator's own command line chooses the repository and revisions; git runs as an
        # argv list (no shell), options are fixed `--x=value` forms and revisions go through --stdin
        result = scan_history(args.repo, since=args.since, until=args.until, max_commits=args.max_commits,  # nosec
                              branches=args.branch, include_unreachable=args.include_unreachable,
                              excludes=args.exclude, entropy=not args.no_entropy,
                              honor_suppressions=not args.no_suppress, timeout=args.timeout)
    except HistoryError as exc:
        print(f"kashif history: {error_text(exc, args.lang)}", file=sys.stderr)
        return 2
    if args.only:
        keep = args.only == "present"
        result.findings = [f for f in result.findings if bool(f.extra.get("still_present")) == keep]
    text = render_json(result, args.lang) if args.format == "json" else render_console(result, args.lang)
    if args.output:
        try:
            pathlib.Path(args.output).write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"kashif history: {_t(args.lang, 'e_write', path=args.output, msg=exc.strerror or exc)}",
                  file=sys.stderr)
            return 2
    else:
        try:
            sys.stdout.write(text if text.endswith("\n") else text + "\n")
        except UnicodeEncodeError:
            sys.stdout.buffer.write((text + "\n").encode("utf-8", "replace"))
    return 1 if result.findings and not args.exit_zero else 0


if __name__ == "__main__":
    sys.exit(main())
