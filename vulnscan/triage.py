"""Finding triage lifecycle: a reviewable, committable audit trail of what the team decided about each finding.

INTEGRATION NOTES
=================
(For the integration step. This module edits no existing file and is usable today as
``python3 -m vulnscan.triage ...``.)

CLI (vulnscan/cli.py)
---------------------
* Add a sub-command ``vulnscan triage ...`` that forwards to ``triage.main(argv)`` (set | comment | severity |
  list | show | stats | expire-check | sync | import | diff | merge). ``main`` returns the process exit code.
* Add scan flags:
    ``--triage [FILE]``        after ``assign_fingerprints`` and before filtering / ``--fail-on``::

        tri = triage.load(triage.default_path(target))
        changes = triage.sync(findings, tri, complete=<not a --diff / partial scan>)
        triage.save(tri, path)        # only with --triage-update, never on PR builds; no-op when nothing changed
        res = triage.apply(findings, tri)
        findings = res.visible                               # reports and --fail-on use the filtered view

    ``--triage-update``         persist first-seen / auto-fixed / regression / expiry (CI on the main branch only)
    ``--triage-show STATUS,..`` statuses kept in the report (default ``open,confirmed``; ``all`` keeps everything)
    ``--sla critical=7,high=30,...`` and ``--fail-on-sla`` -> ``triage.stats(tri, sla_days=...)["sla"]["breaches"]``
* A partial scan (``--diff``, single file) must pass ``complete=False`` or ``scanned_files=...`` to ``sync`` so
  that findings outside the scanned scope are not marked fixed.
* Print ``res.expired`` ("risk acceptance expired") and ``res.regressions`` prominently; both are release blockers
  for most teams.
* SECURITY - pull-request builds. The triage file is part of the scanned repository, so whoever opens a pull
  request can add a ``false_positive`` entry or a severity override for the very finding the pull request
  introduces (exactly like an inline ``nosec``). When the scan gates a pull request, either load the triage of
  the target branch (``git show <base>:.kashif/triage.json``) instead of the working tree's, or keep the working
  tree's and fail / request a security review when ``triage.decision_changes(base_triage, head_triage)`` is not
  empty (CLI: ``vulnscan triage diff base.json --fail-on-change``). Never run ``--triage-update`` on such builds.
* "fixed (auto)" means "absent from a complete scan", nothing more: a rule that was disabled, an excluded
  directory or a file that failed to parse also makes findings absent. Only call ``sync(complete=True)`` after a
  scan with the full rule set and no scan errors; otherwise pass ``complete=False``. A wrongly auto-fixed entry
  comes back as a regression on the next complete scan.
* ``apply`` accepts ``show`` as a tuple of statuses or as the command-line text (``"open,confirmed"``, ``"all"``).
  An unknown status name raises ``TriageError`` (a typo must not hide every finding and pass the gate): catch it
  with the other ``TriageError`` cases and exit 2.
* ``triage.load`` raises ``TriageError`` for a malformed file and ``update`` raises it when ``<file>.lock`` is held
  for more than 10 s (a ``.lock`` file committed to a hostile repository does that until it is 60 s old). Treat
  both as a scan error (exit 2), never as "no triage".

Reports (vulnscan/report.py)
----------------------------
* ``apply`` writes ``finding.extra["triage"]`` (see ``apply`` for the keys); ``Finding.to_dict`` already carries
  ``extra`` to JSON/HTML. Suggested rendering: a status badge, the justification, the ticket link (already
  validated as http/https), "expired" and "regression" flags, and ``severity_original`` next to an overridden
  severity.
* SARIF: map hidden findings to ``suppressions`` — ``false_positive``/``wont_fix``/``accepted_risk`` ->
  ``{"kind": "external", "status": "accepted", "justification": ...}``; ``ApplyResult.hidden`` holds them.

Web UI / server (vulnscan/server.py, vulnscan/ui/*)
---------------------------------------------------
* ``GET  /api/triage?root=...``          -> ``triage.load(...)`` plus ``triage.stats(...)``
* ``POST /api/triage/set``               -> ``triage.update(path, lambda t: triage.set_status(t, fp, ...))``
* ``POST /api/triage/comment|severity``  -> ``add_comment`` / ``override_severity`` through ``triage.update``
* ``apply`` accepts the saved-scan dict form (``Finding.to_dict()``) as well as ``Finding`` objects, so a stored
  scan can be re-annotated without rescanning.
* UI hooks: a status drop-down and a justification box on the finding card, a "Triage" filter chip row
  (statuses from ``STATUSES``; labels from ``status_label(status, lang)``), a dashboard card fed by ``stats``
  (MTTR per severity, age buckets, SLA breaches, acceptances expiring soon, noisiest rules by false-positive
  rate).
* Always HTML-escape every value taken from the triage file in the UI (justification, comments, author, rule,
  file, title, ticket): the file comes from the scanned repository. Render the ticket as a link only with
  ``rel="noopener noreferrer"``.
* Fingerprint keys are restricted to ``[0-9A-Za-z][0-9A-Za-z_.:-]*``, which still allows names such as
  ``constructor``: in the UI's JavaScript, look entries up with ``Object.hasOwn`` / a ``Map``, not ``obj[key]``.
* ``find_inline_suppressions`` masks quoted literals, but its ``text`` is still source code: escape it too.
* The server must derive the triage path from the scanned project root on its side (``default_path(root)``),
  never from a path sent by the browser, and should require the same CSRF/Origin protection as its other
  state-changing endpoints: these calls write a file.

LSP / MCP (optional)
--------------------
* LSP quick fix "Mark as false positive..." -> ``triage.update`` + ``set_status``.
* MCP tool ``triage_set`` / ``triage_stats`` with the same arguments as the CLI.

Packaging (vulnscan.spec)
-------------------------
* ``hiddenimports += ["vulnscan.triage"]`` (it is imported lazily by the CLI). No data files.

README suggestions
------------------
EN: "**Triage that lives in your repository.** `.kashif/triage.json` records every decision (false positive,
accepted risk with an expiry date, won't fix, fixed) with its author, justification, ticket and an audit
log. It is sorted and stable, so decisions are reviewed in pull requests like code. Fixed findings are
detected automatically, regressions are flagged, expired risk acceptances re-open, and `vulnscan triage stats`
reports MTTR, open-finding age and SLA breaches — locally, offline, with no server and no account."
AR: «**فرز يعيش داخل مستودعك.** يسجّل الملف `.kashif/triage.json` كل قرار (إنذار كاذب، قبول خطر بتاريخ انتهاء،
لن يُصلَح، أُصلِح) مع صاحبه ومبرّره وتذكرته وسجل تدقيق. الملف مرتّب وثابت فتُراجَع القرارات في
طلبات الدمج كما يُراجَع الكود. تُكتشَف الإصلاحات تلقائيًا، ويُنبَّه على الارتداد، ويُعاد فتح قبول الخطر المنتهي،
ويعرض `vulnscan triage stats` متوسط زمن الإصلاح وأعمار النتائج المفتوحة وتجاوزات مهلة الإصلاح — محليًا
ودون اتصال ودون خادم أو حساب.»
Add ``.kashif/*.lock`` and ``.kashif/*.tmp`` to the project's ``.gitignore`` suggestions (short-lived files of
``update`` / ``save``; normally gone within milliseconds).

Git merge driver (optional, documents well in the README)::

    # .gitattributes
    .kashif/triage.json merge=kashif-triage
    # once per clone
    git config merge.kashif-triage.driver "kashif triage merge %A %B --base %O -o %A"

    Use the console script, not "python3 -m vulnscan.triage": git runs the driver in the work tree, and "python -m"
    puts that directory first on sys.path, so a json.py committed to the repository would run on every merge.

OVERVIEW
========
The triage file is JSON, schema ``kashif-triage/1``, keyed by finding fingerprint (``Finding.fingerprint()``)::

    {"schema": "kashif-triage/1",
     "findings": {"<fingerprint>": {
         "status": "accepted_risk", "justification": "...", "author": "...", "updated": "2026-01-02T03:04:05Z",
         "expires": "2026-06-30", "ticket": "https://...",
         "severity_override": {"severity": "low", "reason": "...", "author": "...", "at": "..."},
         "first_seen": "...", "fixed_at": "...", "regressions": 1, "regression": true, "expired": true,
         "rule": "PY001", "file": "app.py", "severity": "high", "title": "...",
         "log": [{"at": "...", "author": "...", "action": "status", "from": "open", "to": "accepted_risk"}]}}}

The audit log is append-only as far as this module's API goes; it is a plain file, so its integrity is that of
the git history it is committed to (``decision_changes`` reports log items that disappeared between two
versions). It is not a tamper-proof record.

Limits: identity is ``Finding.fingerprint()``. Moving or renaming a file, or editing the flagged line, gives a
new fingerprint: the old entry is closed as fixed (or reported stale) and the finding starts again as new,
without its decision. Identical findings in one file differ only by an index, so when one of two is removed the
decision stays with index 0, whichever of the two is left. Expiry dates are compared in UTC.

Keys are sorted, empty values are omitted and nothing volatile (no "last seen", no tool version) is stored, so
re-saving an unchanged triage produces a byte-identical file and a decision shows up as a small diff.

Nothing here executes scanned code or uses the network. The file is untrusted input (it lives in the scanned
project): it must be a regular file, is size-capped and validated, control and bidirectional-override characters
are removed from every string, and ticket URLs are restricted to http/https without credentials.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import getpass
import json
import os
import pathlib
import re
import secrets
import stat as _stat
import statistics
import sys
import time
from dataclasses import dataclass, field

from .model import SEVERITIES, SEVERITY_AR, SEVERITY_RANK, Finding, ensure_fingerprints

__all__ = [
    "SCHEMA", "STATUSES", "DEFAULT_PATH", "DEFAULT_SLA_DAYS", "TriageError", "ApplyResult", "SyncResult",
    "new_triage", "default_path", "load", "loads", "dumps", "save", "update", "set_status", "add_comment",
    "override_severity", "apply", "sync", "stats", "expire_check", "merge", "import_baseline",
    "find_inline_suppressions", "resolve_fingerprint", "status_label", "decision_changes", "main",
]

SCHEMA = "kashif-triage/1"
_SCHEMA_FAMILY = "kashif-triage/"
DEFAULT_PATH = ".kashif/triage.json"

STATUSES = ("open", "confirmed", "false_positive", "accepted_risk", "fixed", "wont_fix")
#: Statuses that hide a finding and therefore need a written reason.
JUSTIFICATION_REQUIRED = frozenset({"false_positive", "accepted_risk", "wont_fix"})
#: Statuses that still count as work to do (shown by default, aged, subject to SLA).
ACTIVE = frozenset({"open", "confirmed"})
#: Days allowed from first-seen to fixed, per severity. ``info`` has no SLA.
DEFAULT_SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}
AGE_BUCKETS = (("0-7", 0, 7), ("8-30", 8, 30), ("31-90", 31, 90), ("91+", 91, None))
SYSTEM_AUTHOR = "kashif"

MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TEXT = 4000
_FP_RE = re.compile(r"^[0-9a-f]{16}:\d{1,6}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# C0/C1 control characters (terminal escape sequences), line/paragraph separators and the bidirectional
# embedding / override / isolate characters of "Trojan Source" (CVE-2021-42574). Written with escapes on purpose:
# this source file must not contain such characters itself. Tab, LF and CR are kept.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")
# Keys of "findings": Finding.fingerprint() is 16 hex digits, ':' and an index; a little slack for other tools.
_KEY_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z_.:\-]{0,127}$")
MAX_DEPTH = 12
MAX_REPORT_BYTES = 256 * 1024 * 1024
# When two edits carry the same timestamp, the one that keeps the finding visible wins.
_CONSERVATIVE = {s: i for i, s in enumerate(("open", "confirmed", "accepted_risk", "wont_fix", "false_positive", "fixed"))}
_STATE_KEYS = ("status", "justification", "author", "updated", "expires", "ticket", "fixed_at", "auto", "regression",
               "expired")
_CONTEXT_KEYS = ("rule", "file", "severity", "title")

STR = {
    "en": {
        "open": "Open", "confirmed": "Confirmed", "false_positive": "False positive",
        "accepted_risk": "Accepted risk", "fixed": "Fixed", "wont_fix": "Won't fix",
        "expired_flag": "risk acceptance expired", "regression_flag": "regression",
        "e_status": "unknown status {status!r}; use one of: {choices}",
        "e_justification": "status {status!r} needs a justification (--justification)",
        "e_author": "an author is required (--author or KASHIF_AUTHOR)",
        "e_expires_status": "an expiry date only applies to accepted_risk",
        "e_expires_format": "expiry must be YYYY-MM-DD or +Nd, got {value!r}",
        "e_expires_past": "expiry {value} is not in the future",
        "e_expires_max": "expiry {value} is more than {days} days ahead (policy limit)",
        "e_ticket": "ticket must be an http(s) URL, got {value!r}",
        "e_severity": "unknown severity {value!r}; use one of: {choices}",
        "e_reason": "a severity override needs a reason (--reason)",
        "e_fp_unknown": "no triaged finding matches {fp!r}; give the full fingerprint (16 hex digits, ':', index)",
        "e_fp_ambiguous": "{fp!r} matches {n} fingerprints; give more characters",
        "e_comment": "a comment cannot be empty",
        "e_expires_required": "an accepted risk needs an expiry (--expires) of at most {days} days (policy limit)",
        "e_fp_invalid": "{fp!r} is not a fingerprint (16 hex digits, ':', index)",
        "e_locked": "the triage file is locked by another process ({path}); retry, or delete the lock if it is stale",
        "h_changes": "{n} decision change(s) to review",
        "change_row": "{fp} {rule} {file}: {kind} ({old} -> {new}) by {author}",
        "e_malformed": "malformed triage file {path}: {why}",
        "e_too_big": "triage file {path} is larger than {mb} MB",
        "e_report": "cannot read findings from {path}: {why}",
        "e_sla": "bad --sla value {value!r}; expected e.g. critical=7,high=30",
        "saved": "saved {path}",
        "unchanged": "no change",
        "set_done": "{fp}: {old} -> {new}",
        "comment_done": "{fp}: comment added",
        "sev_done": "{fp}: severity {old} -> {new}",
        "sev_cleared": "{fp}: severity override removed",
        "none": "(nothing to show)",
        "h_list": "{n} triaged finding(s)",
        "h_stats": "Triage statistics",
        "by_status": "By status",
        "open_by_sev": "Open by severity",
        "age": "Open by age (days)",
        "mttr": "Mean time to remediate (days)",
        "mttr_row": "{sev}: mean {mean}, median {median} over {n} fixed",
        "sla": "SLA breaches",
        "sla_row": "{fp} {sev} {rule} {file}: open {age}d, SLA {sla}d, overdue {over}d",
        "noisy": "Noisiest rules (false-positive share)",
        "regressions": "Regressions",
        "expired": "Expired risk acceptances",
        "expiring": "Risk acceptances expiring within {days} day(s)",
        "exp_row": "{fp} {rule} {file}: expires {date} ({days}d)",
        "expired_row": "{fp} {rule} {file}: expired {date} ({days}d ago) - re-opened",
        "sync_done": "new {new}, fixed {fixed}, regressions {reg}, expired {exp}, stale decisions {stale}",
        "import_done": "baseline: {added} imported, {skipped} already tracked",
        "inline": "{n} inline suppression comment(s) (informational, not imported)",
        "merge_done": "merged: {n} finding(s), {c} conflicting edit(s) resolved",
        "conflict_row": "conflict {fp} [{field}]: kept {chosen}",
        "conflict_markers": "git conflict markers found and resolved by merging both sides",
    },
    "ar": {
        "open": "مفتوحة", "confirmed": "مؤكَّدة", "false_positive": "إنذار كاذب",
        "accepted_risk": "خطر مقبول", "fixed": "أُصلحت", "wont_fix": "لن تُصلَح",
        "expired_flag": "انتهى قبول الخطر", "regression_flag": "ارتداد",
        "e_status": "حالة غير معروفة {status!r}؛ المتاح: {choices}",
        "e_justification": "الحالة {status!r} تتطلب مبرّرًا (--justification)",
        "e_author": "اسم صاحب القرار مطلوب (--author أو KASHIF_AUTHOR)",
        "e_expires_status": "تاريخ الانتهاء يخص حالة accepted_risk فقط",
        "e_expires_format": "صيغة تاريخ الانتهاء YYYY-MM-DD أو +Nd، والمُدخل {value!r}",
        "e_expires_past": "تاريخ الانتهاء {value} ليس في المستقبل",
        "e_expires_max": "تاريخ الانتهاء {value} يتجاوز الحد المسموح ({days} يومًا)",
        "e_ticket": "رابط التذكرة يجب أن يكون http(s)، والمُدخل {value!r}",
        "e_severity": "خطورة غير معروفة {value!r}؛ المتاح: {choices}",
        "e_reason": "تعديل الخطورة يتطلب سببًا (--reason)",
        "e_fp_unknown": "لا توجد نتيجة مفروزة تطابق {fp!r}؛ أدخل البصمة كاملة (16 خانة ست عشرية ثم ':' ثم الفهرس)",
        "e_fp_ambiguous": "{fp!r} تطابق {n} بصمات؛ أدخل خانات أكثر",
        "e_comment": "التعليق لا يكون فارغًا",
        "e_expires_required": "قبول الخطر يتطلب تاريخ انتهاء (--expires) لا يتجاوز {days} يومًا (حد السياسة)",
        "e_fp_invalid": "{fp!r} ليست بصمة (16 خانة ست عشرية ثم ':' ثم الفهرس)",
        "e_locked": "ملف الفرز مقفل من عملية أخرى ({path})؛ أعد المحاولة أو احذف القفل إن كان متروكًا",
        "h_changes": "{n} تغيير في القرارات يحتاج مراجعة",
        "change_row": "{fp} {rule} {file}: {kind} ({old} ← {new}) بواسطة {author}",
        "e_malformed": "ملف الفرز {path} تالف: {why}",
        "e_too_big": "ملف الفرز {path} أكبر من {mb} ميغابايت",
        "e_report": "تعذّرت قراءة النتائج من {path}: {why}",
        "e_sla": "قيمة --sla غير صحيحة {value!r}؛ مثال: critical=7,high=30",
        "saved": "حُفظ {path}",
        "unchanged": "لا تغيير",
        "set_done": "{fp}: {old} ← {new}",
        "comment_done": "{fp}: أُضيف التعليق",
        "sev_done": "{fp}: الخطورة {old} ← {new}",
        "sev_cleared": "{fp}: أُزيل تعديل الخطورة",
        "none": "(لا شيء للعرض)",
        "h_list": "{n} نتيجة مفروزة",
        "h_stats": "إحصاءات الفرز",
        "by_status": "حسب الحالة",
        "open_by_sev": "المفتوحة حسب الخطورة",
        "age": "المفتوحة حسب العمر (بالأيام)",
        "mttr": "متوسط زمن الإصلاح (بالأيام)",
        "mttr_row": "{sev}: المتوسط {mean}، الوسيط {median} من {n} مُصلَحة",
        "sla": "تجاوزات مهلة الإصلاح",
        "sla_row": "{fp} {sev} {rule} {file}: مفتوحة منذ {age} يومًا، المهلة {sla} يومًا، التأخير {over} يومًا",
        "noisy": "أكثر القواعد ضجيجًا (نسبة الإنذارات الكاذبة)",
        "regressions": "الارتدادات",
        "expired": "قبول خطر منتهٍ",
        "expiring": "قبول خطر ينتهي خلال {days} يومًا",
        "exp_row": "{fp} {rule} {file}: ينتهي {date} (بعد {days} يومًا)",
        "expired_row": "{fp} {rule} {file}: انتهى {date} (منذ {days} يومًا) - أُعيد فتحها",
        "sync_done": "جديدة {new}، أُصلحت {fixed}، ارتدادات {reg}، منتهية {exp}، قرارات بلا نتيجة {stale}",
        "import_done": "خط الأساس: استُورد {added}، و{skipped} متتبَّعة سابقًا",
        "inline": "{n} تعليق كتم داخل الكود (للعلم فقط، لم تُستورد)",
        "merge_done": "دُمج: {n} نتيجة، وحُلّ {c} تعارض",
        "conflict_row": "تعارض {fp} [{field}]: اعتُمد {chosen}",
        "conflict_markers": "وُجدت علامات تعارض git وحُلّت بدمج الطرفين",
    },
}


def _t(lang: str, key: str, **kw) -> str:
    table = STR.get(lang) or STR["en"]
    text = table.get(key) or STR["en"][key]
    return text.format(**kw) if kw else text


def severity_label(severity: str, lang: str = "en") -> str:
    """Human label of a severity: the Arabic name in "ar" (as in the reports), else the severity itself."""
    return SEVERITY_AR.get(severity, severity) if lang == "ar" else severity


def status_label(status: str, lang: str = "en") -> str:
    """Human label of a status in ``lang`` ("en" or "ar")."""
    return _t(lang, status) if status in STATUSES else status


class TriageError(ValueError):
    """Invalid triage input: a malformed file, an unknown status, a missing justification, ...

    ``key`` and ``params`` identify the message in ``STR`` so a caller can re-render it with ``message(lang)``."""

    def __init__(self, key: str, **params):
        self.key = key
        self.params = params
        super().__init__(_t("en", key, **params))

    def message(self, lang: str = "en") -> str:
        return _t(lang, self.key, **self.params)


# --------------------------------------------------------------------------------------------- time helpers

def _now(now=None) -> _dt.datetime:
    """Normalise ``now`` (None, aware/naive datetime, date, or ISO string) to an aware UTC datetime."""
    if now is None:
        return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    if isinstance(now, str):
        parsed = _parse_ts(now)
        if parsed is None:
            raise ValueError(f"bad timestamp {now!r}")
        return parsed
    if isinstance(now, _dt.datetime):
        if now.tzinfo is None:
            now = now.replace(tzinfo=_dt.timezone.utc)
        return now.astimezone(_dt.timezone.utc).replace(microsecond=0)
    if isinstance(now, _dt.date):
        return _dt.datetime(now.year, now.month, now.day, tzinfo=_dt.timezone.utc)
    raise TypeError(f"now must be a datetime, date, ISO string or None, not {type(now).__name__}")


def _stamp(now: _dt.datetime) -> str:
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_ts(value) -> _dt.datetime | None:
    """Parse a stored timestamp (``...Z`` or an ISO offset, or a bare date). None when it is unusable."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = _dt.datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.timezone.utc)
        return parsed.astimezone(_dt.timezone.utc)
    except (ValueError, OverflowError):          # OverflowError: year 1 / 9999 with an offset
        return None


def _parse_date(value) -> _dt.date | None:
    if not isinstance(value, str) or not _DATE_RE.match(value):
        return None
    try:
        return _dt.date.fromisoformat(value)
    except ValueError:
        return None


def _days_between(start, end: _dt.datetime) -> float | None:
    a = _parse_ts(start)
    if a is None:
        return None
    return max(0.0, (end - a).total_seconds() / 86400.0)


def _clean(text, limit: int = MAX_TEXT) -> str:
    """Trim, drop control / bidi-override characters (terminal and review spoofing) and cap the length."""
    if text is None:
        return ""
    return _CONTROL.sub("", str(text)).strip()[:limit]


# ------------------------------------------------------------------------------------------------ file model

def new_triage() -> dict:
    """An empty triage document."""
    return {"schema": SCHEMA, "findings": {}}


def default_path(root=".") -> pathlib.Path:
    """``<root>/.kashif/triage.json`` (for a file target: next to the file)."""
    base = pathlib.Path(root)
    if base.is_file():
        base = base.parent
    return base / DEFAULT_PATH


def redirected(path) -> bool:
    """True when the default ``.kashif/triage.json`` of a project would be written through a symbolic link (or
    a Windows junction) to somewhere else: a hostile checkout can commit ``.kashif`` as a link."""
    path = pathlib.Path(path)
    try:
        if path.is_symlink() or path.parent.is_symlink():
            return True
        if not path.parent.exists():
            return False
        real = os.path.normcase(str(path.parent.resolve()))
        expected = os.path.normcase(str(path.parent.parent.resolve() / path.parent.name))
    except (OSError, RuntimeError):
        return True
    return real != expected


def _validate(data, path: str) -> dict:
    def bad(why: str) -> TriageError:
        return TriageError("e_malformed", path=path, why=why)

    if not isinstance(data, dict):
        raise bad("top level is not an object")
    schema = data.get("schema")
    if not isinstance(schema, str) or not schema.startswith(_SCHEMA_FAMILY):
        raise bad(f"schema is {schema!r}, expected {SCHEMA!r}")
    if schema != SCHEMA:
        raise bad(f"schema {schema!r} is newer than this version of Kashif understands ({SCHEMA}); upgrade Kashif")
    raw = data.get("findings")
    for fp, entry in (raw.items() if isinstance(raw, dict) else ()):
        # Checked before control characters are stripped: stripping must never turn a bad URL into a "valid" one.
        if isinstance(entry, dict) and "ticket" in entry and not _valid_ticket(entry["ticket"]):
            raise bad(f"entry {_clean(fp, 60)!r} has a ticket that is not an http(s) URL")
    try:
        data = _sanitize(data)
    except ValueError as exc:
        raise bad(str(exc)) from None
    findings = data.get("findings", {})
    if not isinstance(findings, dict):
        raise bad("'findings' is not an object")
    for fp, entry in findings.items():
        name = _clean(fp, 60)
        if not _KEY_RE.match(fp):
            raise bad(f"{name!r} is not a fingerprint")
        if not isinstance(entry, dict):
            raise bad(f"entry {name!r} is not an object")
        status = entry.get("status", "open")
        if not isinstance(status, str) or status not in STATUSES:
            raise bad(f"entry {name!r} has unknown status {_clean(status, 60)!r}")
        for key in _STRING_KEYS:
            if key in entry and not isinstance(entry[key], str):
                raise bad(f"entry {name!r}: {key!r} is not a string")
        for key in ("regression", "expired", "auto"):
            if key in entry and not isinstance(entry[key], bool):
                raise bad(f"entry {name!r}: {key!r} is not true/false")
        count = entry.get("regressions", 0)
        if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= 1_000_000:
            raise bad(f"entry {name!r}: 'regressions' is not a small non-negative integer")
        if status in JUSTIFICATION_REQUIRED and not _clean(entry.get("justification")):
            raise bad(f"entry {name!r} is {status} without a justification")
        log = entry.get("log", [])
        if not isinstance(log, list) or any(
                not isinstance(item, dict) or any(not isinstance(item.get(k, ""), str) for k in ("at", "author", "action"))
                for item in log):
            raise bad(f"entry {name!r} has a malformed log")
        override = entry.get("severity_override")
        if override is not None and (
                not isinstance(override, dict) or not isinstance(override.get("severity"), str)
                or override["severity"] not in SEVERITIES
                or any(not isinstance(override.get(k, ""), str) for k in ("reason", "author", "at"))):
            raise bad(f"entry {name!r} has a malformed severity_override")
        if "expires" in entry and _parse_date(entry["expires"]) is None:
            raise bad(f"entry {name!r} has a malformed expiry date {_clean(entry['expires'], 60)!r}")
        if "ticket" in entry and not _valid_ticket(entry["ticket"]):
            raise bad(f"entry {name!r} has a ticket that is not an http(s) URL")
    data["findings"] = findings
    return data


_STRING_KEYS = ("justification", "author", "updated", "expires", "ticket", "first_seen", "fixed_at", "rule", "file",
                "severity", "title")


def _sanitize(value, depth: int = 0):
    """Copy of parsed JSON with control / bidi-override characters removed from every string and key, so that
    nothing read from a (possibly hostile) triage file can drive a terminal or spoof a review. Raises
    ``ValueError`` for nesting deeper than ``MAX_DEPTH`` and for NaN / Infinity (not JSON)."""
    if isinstance(value, str):
        return _CONTROL.sub("", value) if _CONTROL.search(value) else value
    if isinstance(value, float) and value != value or value in (float("inf"), float("-inf")):
        raise ValueError("NaN / Infinity is not valid JSON")
    if isinstance(value, (dict, list)):
        if depth >= MAX_DEPTH:
            raise ValueError(f"nested deeper than {MAX_DEPTH} levels")
        if isinstance(value, list):
            return [_sanitize(v, depth + 1) for v in value]
        return {_sanitize(k): _sanitize(v, depth + 1) for k, v in value.items()}
    return value


def _split_conflict(text: str) -> tuple[str, str] | None:
    """Split text with git conflict markers into the (ours, theirs) versions; None when there are none."""
    if "\n<<<<<<< " not in "\n" + text:
        return None
    ours, theirs, side = [], [], None
    for line in text.splitlines(keepends=True):
        if line.startswith("<<<<<<< "):
            side = "ours"
        elif line.startswith("||||||| ") and side == "ours":
            side = "base"
        elif line.startswith("=======") and side in ("ours", "base"):
            side = "theirs"
        elif line.startswith(">>>>>>> ") and side == "theirs":
            side = None
        elif side is None:
            ours.append(line)
            theirs.append(line)
        elif side == "ours":
            ours.append(line)
        elif side == "theirs":
            theirs.append(line)
    return "".join(ours), "".join(theirs)


def loads(text: str, path: str = "<string>", info: dict | None = None) -> dict:
    """Parse triage JSON text. Raises ``TriageError`` when it is malformed.

    A file left with git conflict markers is not an error: both sides are parsed and combined with ``merge``
    (``info["conflict_markers"]`` is set to True and ``info["conflicts"]`` to the resolved conflicts)."""
    if not text.strip():
        return new_triage()
    sides = _split_conflict(text)
    if sides is not None:
        ours, theirs = (loads(side, path) for side in sides)
        merged, conflicts = merge(ours, theirs)
        if info is not None:
            info["conflict_markers"] = True
            info["conflicts"] = conflicts
        return merged
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise TriageError("e_malformed", path=path, why=str(exc)) from None
    return _validate(data, path)


def _read_bounded(path, limit: int) -> str | None:
    """Text of a regular file of at most ``limit`` bytes (UTF-8, BOM tolerated, newlines normalised to LF).
    None when it does not exist. Raises OSError / ValueError otherwise; a device, FIFO or directory (e.g. a
    ``triage.json`` symlinked to ``/dev/zero`` in a hostile repository) is refused rather than read."""
    p = pathlib.Path(path)
    try:
        info = p.stat()
    except FileNotFoundError:
        return None
    if not _stat.S_ISREG(info.st_mode):
        raise OSError("not a regular file")
    if info.st_size > limit:
        raise OverflowError
    with open(p, "rb") as fh:
        raw = fh.read(limit + 1)
    if len(raw) > limit:
        raise OverflowError
    return raw.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")


def _read_text(path) -> str | None:
    try:
        return _read_bounded(path, MAX_FILE_BYTES)
    except OverflowError:
        raise TriageError("e_too_big", path=str(path), mb=MAX_FILE_BYTES // (1024 * 1024)) from None
    except (OSError, ValueError) as exc:
        raise TriageError("e_malformed", path=str(path), why=str(exc)) from None


def _read_json(path, limit: int = MAX_REPORT_BYTES):
    """Parsed JSON of a user-supplied input file (report, baseline). Raises OSError / ValueError."""
    try:
        text = _read_bounded(path, limit)
    except OverflowError:
        raise ValueError(f"larger than {limit // (1024 * 1024)} MB") from None
    if text is None:
        raise FileNotFoundError("no such file")
    try:
        return json.loads(text)
    except RecursionError:
        raise ValueError("nested too deeply") from None


def load(path, info: dict | None = None) -> dict:
    """Load a triage file. A missing file gives an empty triage; a malformed one raises ``TriageError``
    (decisions are an audit record, so they are never silently discarded). See ``loads`` for ``info``."""
    text = _read_text(path)
    return new_triage() if text is None else loads(text, str(path), info)


def _log_key(item: dict) -> tuple:
    return (str(item.get("at", "")), json.dumps(item, sort_keys=True, ensure_ascii=False))


def _prune(value):
    """Drop empty values (None, "", [], {}, False, 0) so that the file holds only what was decided."""
    if isinstance(value, dict):
        out = {k: _prune(v) for k, v in value.items()}
        return {k: v for k, v in out.items() if v not in (None, "", [], {}, False, 0)}
    if isinstance(value, list):
        return [_prune(v) for v in value]
    return value


def dumps(triage: dict) -> str:
    """Canonical text of a triage: sorted keys, two-space indent, UTF-8 kept readable, one trailing newline,
    empty values omitted and each audit log in chronological order. Equal triages give byte-identical text."""
    findings = {}
    for fp, entry in (triage.get("findings") or {}).items():
        item = _prune(dict(entry))
        if "log" in item:
            item["log"] = sorted(item["log"], key=_log_key)
        item.setdefault("status", "open")
        findings[str(fp)] = item
    extra = {k: v for k, v in triage.items() if k not in ("schema", "findings")}
    doc = {**extra, "schema": SCHEMA, "findings": findings}
    return json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def save(triage: dict, path, expect: str | None = None) -> bool:
    """Write the triage atomically (temp file in the same directory, fsync, ``os.replace``): a crash or a full
    disk leaves the previous file intact. Returns False, and touches nothing, when the file already has exactly
    this content.

    ``expect`` is the text the caller loaded. When the file on disk has changed since (someone else saved in
    the meantime), the two versions are merged with the loaded text as the common base instead of overwriting."""
    target = pathlib.Path(path)
    current = _read_text(target)
    if expect is not None and current is not None and current != expect:
        merged, _ = merge(triage, loads(current, str(target)), base=loads(expect, str(target)))
        triage.clear()
        triage.update(merged)
    text = dumps(triage)
    if current == text:
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = str(target.parent / f"{target.name}.{secrets.token_hex(6)}.tmp")
    # O_EXCL: never follows a planted symlink. Mode 0666 & ~umask like any file the user creates (mkstemp's
    # 0600 would make a committed file unreadable for the rest of the team / the CI user); O_BINARY keeps LF
    # on Windows.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o666)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        if current is not None:
            try:                                           # keep the permissions of the file being replaced
                os.chmod(tmp, _stat.S_IMODE(os.stat(target).st_mode))
            except OSError:
                pass
        for attempt in range(6):
            try:
                os.replace(tmp, target)
                break
            except PermissionError:                        # Windows: an editor / antivirus has the file open
                if os.name != "nt" or attempt == 5:
                    raise
                time.sleep(0.05 * (attempt + 1))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return True


@contextlib.contextmanager
def _locked(target: pathlib.Path, timeout: float = 10.0, stale: float = 60.0):
    """Advisory lock (``<file>.lock``, created with O_EXCL) serialising ``update`` calls on one triage file
    across processes and threads. A lock older than ``stale`` seconds is taken to be left by a crashed process
    and is removed. Raises ``TriageError("e_locked")`` after ``timeout`` seconds."""
    made_dir = not target.parent.exists()
    target.parent.mkdir(parents=True, exist_ok=True)
    lock = str(target) + ".lock"
    deadline = time.monotonic() + timeout
    while True:
        try:
            fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
            break
        except (FileExistsError, PermissionError) as exc:  # PermissionError: Windows, lock is being deleted
            if isinstance(exc, PermissionError) and not os.path.exists(lock):
                raise                                      # the directory itself is not writable
            try:
                if time.time() - os.stat(lock).st_mtime > stale:
                    os.unlink(lock)
                    continue
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise TriageError("e_locked", path=lock) from None
            time.sleep(0.05)
    try:
        yield
    finally:
        os.close(fd)
        try:
            os.unlink(lock)
        except OSError:
            pass
        if made_dir and not target.exists():
            try:
                target.parent.rmdir()                      # nothing was saved: leave no empty .kashif behind
            except OSError:
                pass


def update(path, fn) -> dict:
    """Load ``path``, call ``fn(triage)``, save. Returns the saved triage. This is the entry point for the
    UI/LSP/CLI, where several edits may race:

    * ``update`` calls on the same file are serialised with a lock file (``<file>.lock``), across processes;
    * a save made meanwhile by something that does not take the lock (an editor, ``git``, a plain ``save``) is
      detected when it lands before our write and merged rather than lost (see ``save``). A write landing in
      the few milliseconds between that check and the rename is not detected.

    ``fn`` must not call ``update`` on the same file (it would wait for its own lock)."""
    target = pathlib.Path(path)
    with _locked(target):
        before = _read_text(target)
        triage = new_triage() if before is None else loads(before, str(target))
        fn(triage)
        save(triage, target, expect=before if before is not None else "")
    return triage


# -------------------------------------------------------------------------------------------- finding access

def _fingerprint(finding) -> str:
    if isinstance(finding, dict):
        return str(finding.get("fingerprint") or "")
    return finding.fingerprint()


def _attr(finding, name: str, default=""):
    return finding.get(name, default) if isinstance(finding, dict) else getattr(finding, name, default)


def _prior(finding) -> dict:
    """``extra["triage"]`` left by an earlier ``apply`` ({} when absent or not of the expected shape)."""
    extra = _attr(finding, "extra", None)
    prior = extra.get("triage") if isinstance(extra, dict) else None
    return prior if isinstance(prior, dict) else {}


def _prepare(findings) -> None:
    objects = [f for f in findings if isinstance(f, Finding)]
    if objects:
        ensure_fingerprints(objects)


def _context(finding) -> dict:
    """What a reviewer needs to recognise the finding in a diff of the triage file (no code is stored)."""
    if finding is None:
        return {}
    severity = _prior(finding).get("severity_original") or _attr(finding, "severity")
    return {"rule": _clean(_attr(finding, "rule_id"), 120), "file": _clean(_attr(finding, "file"), 1000),
            "severity": severity if severity in SEVERITIES else "", "title": _clean(_attr(finding, "title"), 300)}


def _entry(triage: dict, fp: str, now: _dt.datetime, finding=None) -> dict:
    findings = triage.setdefault("findings", {})
    entry = findings.get(fp)
    if entry is None:
        if not isinstance(fp, str) or not _KEY_RE.match(fp):
            raise TriageError("e_fp_invalid", fp=_clean(fp, 60))
        entry = findings[fp] = {"status": "open", "first_seen": _stamp(now), "log": []}
    entry.setdefault("log", [])
    for key, value in _context(finding).items():
        if value:
            entry[key] = value
    return entry


def _log(entry: dict, now: _dt.datetime, author: str, action: str, **detail) -> None:
    entry.setdefault("log", []).append(_prune({"at": _stamp(now), "author": author, "action": action, **detail}))


def resolve_fingerprint(triage: dict, text: str) -> str:
    """Resolve a fingerprint or a unique prefix of one. A fingerprint not yet in the file is accepted only in
    its full form. Raises ``TriageError`` when unknown or ambiguous."""
    text = str(text or "").strip()
    known = triage.get("findings") or {}
    if text in known:
        return text
    text = text.lower()
    if text in known:
        return text
    matches = [fp for fp in known if fp.startswith(text)] if len(text) >= 4 else []
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise TriageError("e_fp_ambiguous", fp=text, n=len(matches))
    if _FP_RE.match(text):
        return text
    raise TriageError("e_fp_unknown", fp=text)


def _valid_ticket(url) -> bool:
    """An http(s) URL that is safe to print and to render as a link: no whitespace, quotes, angle brackets,
    backslashes or control characters, and no ``user:password@`` part (a credential must not end up in a
    committed file)."""
    if not isinstance(url, str) or len(url) > 2000 or _CONTROL.search(url):
        return False
    if not re.match(r"^https?://[^\s<>\"'`\\]+$", url):
        return False
    authority = re.split(r"[/?#]", url.split("://", 1)[1], maxsplit=1)[0]
    return bool(authority) and "@" not in authority


def _expiry(value, now: _dt.datetime, max_days: int | None) -> str:
    text = str(value).strip()
    rel = re.match(r"^\+(\d{1,5})d$", text)
    date = (now.date() + _dt.timedelta(days=int(rel.group(1)))) if rel else _parse_date(text)
    if date is None:
        raise TriageError("e_expires_format", value=text)
    if date <= now.date():
        raise TriageError("e_expires_past", value=date.isoformat())
    if max_days is not None and (date - now.date()).days > max_days:
        raise TriageError("e_expires_max", value=date.isoformat(), days=max_days)
    return date.isoformat()


# ------------------------------------------------------------------------------------------------- mutations

def set_status(triage: dict, fingerprint: str, status: str, *, author: str, justification: str = "",
               expires=None, ticket: str | None = None, comment: str = "", now=None, finding=None,
               max_accept_days: int | None = None) -> dict:
    """Record a triage decision and append it to the finding's audit log. Returns the entry.

    * ``false_positive``, ``accepted_risk`` and ``wont_fix`` require a ``justification``.
    * ``expires`` (``YYYY-MM-DD`` or ``+90d``) is only valid for ``accepted_risk`` and must lie in the future;
      ``max_accept_days`` enforces a policy ceiling and then makes ``expires`` mandatory for ``accepted_risk``.
      The acceptance is valid through the expiry day (UTC).
    * ``ticket`` must be an http(s) URL without credentials; ``None`` keeps the current one, ``""`` removes it.
    * ``fingerprint`` must be a full fingerprint (``resolve_fingerprint`` expands a prefix).
    * ``finding`` (a ``Finding`` or its dict form) adds rule/file/severity/title context to the entry.
    Raises ``TriageError`` on invalid input; the triage is not modified in that case."""
    ts = _now(now)
    author = _clean(author, 200)
    justification = _clean(justification)
    if status not in STATUSES:
        raise TriageError("e_status", status=status, choices=", ".join(STATUSES))
    if not author:
        raise TriageError("e_author")
    if status in JUSTIFICATION_REQUIRED and not justification:
        raise TriageError("e_justification", status=status)
    if expires and status != "accepted_risk":
        raise TriageError("e_expires_status")
    if status == "accepted_risk" and max_accept_days is not None and not expires:
        raise TriageError("e_expires_required", days=max_accept_days)     # no expiry would bypass the ceiling
    expiry = _expiry(expires, ts, max_accept_days) if expires else ""
    if ticket and not _valid_ticket(ticket):
        raise TriageError("e_ticket", value=ticket)

    entry = _entry(triage, fingerprint, ts, finding)
    old = entry.get("status", "open")
    entry.update(status=status, justification=justification, author=author, updated=_stamp(ts), expires=expiry)
    if ticket is not None:
        entry["ticket"] = ticket
    for flag in ("regression", "expired", "auto"):
        entry.pop(flag, None)
    if status == "fixed":
        entry["fixed_at"] = _stamp(ts)
    else:
        entry.pop("fixed_at", None)
    _log(entry, ts, author, "status", **{"from": old, "to": status, "justification": justification,
                                         "expires": expiry, "ticket": ticket or ""})
    if _clean(comment):
        _log(entry, ts, author, "comment", text=_clean(comment))
    return entry


def add_comment(triage: dict, fingerprint: str, text: str, *, author: str, now=None, finding=None) -> dict:
    """Append a comment to the finding's audit log (the log is append-only: nothing here edits or removes)."""
    ts = _now(now)
    author, text = _clean(author, 200), _clean(text)
    if not author:
        raise TriageError("e_author")
    if not text:
        raise TriageError("e_comment")
    entry = _entry(triage, fingerprint, ts, finding)
    _log(entry, ts, author, "comment", text=text)
    return entry


def override_severity(triage: dict, fingerprint: str, severity: str | None, *, reason: str = "", author: str,
                      now=None, finding=None) -> dict:
    """Override the severity the scanner assigned (``apply`` then reports the override and keeps the original
    in ``extra.triage.severity_original``). A reason is required. ``severity=None`` removes the override."""
    ts = _now(now)
    author, reason = _clean(author, 200), _clean(reason)
    if not author:
        raise TriageError("e_author")
    if severity is not None and severity not in SEVERITIES:
        raise TriageError("e_severity", value=severity, choices=", ".join(SEVERITIES))
    if severity is not None and not reason:
        raise TriageError("e_reason")
    entry = _entry(triage, fingerprint, ts, finding)
    old = (entry.get("severity_override") or {}).get("severity") or entry.get("severity", "")
    if severity is None:
        entry.pop("severity_override", None)
    else:
        entry["severity_override"] = {"severity": severity, "reason": reason, "author": author, "at": _stamp(ts)}
    _log(entry, ts, author, "severity", **{"from": old, "to": severity or "", "reason": reason})
    return entry


# ----------------------------------------------------------------------------------------------- apply / sync

def _is_expired(entry: dict, now: _dt.datetime) -> bool:
    date = _parse_date(entry.get("expires"))
    return entry.get("status") == "accepted_risk" and date is not None and now.date() > date


def _effective_status(entry: dict | None, now: _dt.datetime) -> tuple[str, bool]:
    """(status as of ``now``, whether a risk acceptance has lapsed)."""
    if entry is None:
        return "open", False
    if _is_expired(entry, now):
        return "open", True
    return entry.get("status", "open"), bool(entry.get("expired"))


def _effective_severity(entry: dict) -> str:
    severity = (entry.get("severity_override") or {}).get("severity") or entry.get("severity")
    return severity if severity in SEVERITIES else ""


@dataclass
class ApplyResult:
    """Outcome of ``apply``. ``findings`` is every finding (annotated); ``visible`` is the filtered view."""
    findings: list = field(default_factory=list)
    visible: list = field(default_factory=list)
    hidden: list = field(default_factory=list)
    expired: list = field(default_factory=list)        # risk acceptance lapsed -> shown again
    regressions: list = field(default_factory=list)    # was fixed, is back
    counts: dict = field(default_factory=dict)          # effective status -> number of findings


def apply(findings: list, triage: dict, now=None, *, show=("open", "confirmed"), lang: str = "en") -> ApplyResult:
    """Annotate findings with their triage state and return a filtered view.

    ``findings`` may hold ``Finding`` objects or their ``to_dict()`` form (a saved scan). Each one gets
    ``extra["triage"]``::

        {"status": effective status, "tracked": bool, "justification", "author", "updated", "expires",
         "ticket", "first_seen", "age_days", "comments": n, "regressions": n,
         "expired": True, "regression": True, "flags": ["risk acceptance expired", ...],
         "severity_original", "severity_reason"}            # (absent keys mean "not set")

    and, when a severity override exists, its ``severity`` is replaced by the override. The fingerprint does
    not depend on severity, so identities are unchanged.

    ``visible`` keeps the findings whose effective status is in ``show`` (default: open and confirmed; pass
    ``STATUSES`` for everything; an unknown status name raises ``TriageError``). An ``accepted_risk`` past its expiry counts as ``open`` and is flagged
    "risk acceptance expired"; a ``fixed`` finding that is present again counts as ``open`` and is flagged as
    a regression. The triage itself is not modified — use ``sync`` to persist those transitions."""
    ts = _now(now)
    if isinstance(show, str):                               # "open,confirmed" or "all", as typed on a command line
        show = STATUSES if show.strip() == "all" else [s.strip() for s in show.split(",") if s.strip()]
    show = set(show)
    for name in sorted(show - set(STATUSES), key=str):      # a typo would hide every finding: fail, never fail open
        raise TriageError("e_status", status=_clean(name, 60), choices=", ".join(STATUSES))
    _prepare(findings)
    entries = triage.get("findings") or {}
    result = ApplyResult(findings=list(findings))
    for f in findings:
        entry = entries.get(_fingerprint(f))
        status, expired = _effective_status(entry, ts)
        regression = bool(entry and (entry.get("regression") or entry.get("status") == "fixed"))
        if regression and status == "fixed":
            status = "open"
        info: dict = {"status": status, "tracked": entry is not None}
        if entry is not None:
            for key in ("justification", "author", "updated", "ticket", "first_seen"):
                if entry.get(key):
                    info[key] = entry[key]
            if entry.get("expires"):
                info["expires"] = entry["expires"]
            age = _days_between(entry.get("first_seen"), ts)
            if age is not None:
                info["age_days"] = int(age)
            comments = sum(1 for item in entry.get("log", []) if item.get("action") == "comment")
            if comments:
                info["comments"] = comments
            if entry.get("regressions") or regression:
                info["regressions"] = int(entry.get("regressions") or 0) + (1 if entry.get("status") == "fixed" else 0)
            override = entry.get("severity_override") or {}
            current = _prior(f).get("severity_original") or _attr(f, "severity")    # apply() may run twice
            wanted = override.get("severity") if override.get("severity") in SEVERITIES else current
            if wanted != current:
                info["severity_original"] = current
                info["severity_reason"] = override.get("reason", "")
            if wanted != _attr(f, "severity"):
                if isinstance(f, dict):
                    f["severity"] = wanted
                    if "severity_ar" in f:
                        f["severity_ar"] = SEVERITY_AR.get(wanted, wanted)
                else:
                    f.severity = wanted
        flags = []
        if expired:
            info["expired"] = True
            flags.append(_t(lang, "expired_flag"))
            result.expired.append(f)
        if regression:
            info["regression"] = True
            flags.append(_t(lang, "regression_flag"))
            result.regressions.append(f)
        if flags:
            info["flags"] = flags
        if isinstance(f, dict):
            if not isinstance(f.get("extra"), dict):
                f["extra"] = {}
            f["extra"]["triage"] = info
        else:
            f.extra["triage"] = info
        result.counts[status] = result.counts.get(status, 0) + 1
        (result.visible if status in show else result.hidden).append(f)
    return result


@dataclass
class SyncResult:
    """Outcome of ``sync``: lists of fingerprints. ``changed`` tells whether the triage needs saving."""
    new: list = field(default_factory=list)            # first time this finding is seen
    fixed: list = field(default_factory=list)          # open/confirmed and absent from the scan -> fixed
    regressions: list = field(default_factory=list)    # fixed and present again -> open + regression flag
    expired: list = field(default_factory=list)        # accepted_risk past its expiry -> open + expired flag
    stale: list = field(default_factory=list)          # suppression whose finding no longer exists (unchanged)

    @property
    def changed(self) -> bool:
        return bool(self.new or self.fixed or self.regressions or self.expired)

    def to_dict(self) -> dict:
        return {"new": self.new, "fixed": self.fixed, "regressions": self.regressions, "expired": self.expired,
                "stale": self.stale}


def sync(findings: list, triage: dict, now=None, *, complete: bool = True, scanned_files=None,
         track_new: bool = True) -> SyncResult:
    """Reconcile the triage with a scan (in place) and return what changed.

    * a finding seen for the first time is recorded as ``open`` with ``first_seen`` (``track_new=False`` skips
      this and keeps the file to explicit decisions only, at the price of age/MTTR statistics);
    * an ``open``/``confirmed`` entry whose fingerprint is absent from the scan becomes ``fixed``
      (``fixed_at`` is set, the log notes it was detected automatically);
    * a ``fixed`` entry whose fingerprint is present again is re-opened with ``regression: true`` and its
      ``regressions`` counter incremented (this includes a finding someone marked fixed by hand while the
      code still has it: the scan is the source of truth for "fixed");
    * an ``accepted_risk`` past its ``expires`` date is re-opened with ``expired: true``;
    * a ``false_positive``/``accepted_risk``/``wont_fix`` entry whose finding is gone is reported as ``stale``
      and left alone (deleting a decision is a human's call).

    Absence only means "fixed" when the scan covered the finding: pass ``complete=False`` for a partial scan,
    or ``scanned_files`` (paths relative to the scan root) to limit the check to entries in those files.
    Nothing volatile is written, so syncing an unchanged project leaves the triage byte-identical."""
    ts = _now(now)
    _prepare(findings)
    entries = triage.setdefault("findings", {})
    result = SyncResult()
    present: dict[str, object] = {}
    for f in findings:
        if isinstance(f, dict) and not isinstance(f.get("fingerprint") or "", str):
            raise TriageError("e_fp_invalid", fp=_clean(f.get("fingerprint"), 60))
        fp = _fingerprint(f)
        if fp:
            present.setdefault(fp, f)
    files = None if scanned_files is None else {str(p).replace("\\", "/") for p in scanned_files}

    for fp, f in present.items():
        entry = entries.get(fp)
        if entry is None:
            if track_new:
                entry = _entry(triage, fp, ts, f)
                result.new.append(fp)
            continue
        _entry(triage, fp, ts, f)                       # keep the reviewer context (title, severity) current
        if entry.get("status") == "fixed":
            entry["status"] = "open"
            entry["regression"] = True
            entry["regressions"] = int(entry.get("regressions") or 0) + 1
            previous = entry.pop("fixed_at", "")
            entry.pop("auto", None)
            entry["updated"] = _stamp(ts)
            _log(entry, ts, SYSTEM_AUTHOR, "regression", fixed_at=previous)
            result.regressions.append(fp)

    for fp, entry in entries.items():
        if _is_expired(entry, ts):
            _log(entry, ts, SYSTEM_AUTHOR, "expired", expires=entry.get("expires", ""),
                 justification=entry.get("justification", ""))
            entry.update(status="open", expired=True, updated=_stamp(ts))
            entry.pop("expires", None)
            entry.pop("justification", None)
            result.expired.append(fp)
        if fp in present:
            continue
        covered = complete and (files is None or str(entry.get("file", "")).replace("\\", "/") in files)
        if not covered:
            continue
        if entry.get("status", "open") in ACTIVE:
            was = entry.get("status", "open")
            entry.update(status="fixed", fixed_at=_stamp(ts), auto=True, updated=_stamp(ts))
            for flag in ("regression", "expired"):
                entry.pop(flag, None)
            _log(entry, ts, SYSTEM_AUTHOR, "auto_fixed", **{"from": was})
            result.fixed.append(fp)
        elif entry.get("status") in JUSTIFICATION_REQUIRED:
            result.stale.append(fp)
    for name in ("new", "fixed", "regressions", "expired", "stale"):
        getattr(result, name).sort()
    return result


# ------------------------------------------------------------------------------------------------- statistics

def _brief(fp: str, entry: dict) -> dict:
    return {"fingerprint": fp, "rule": entry.get("rule", ""), "file": entry.get("file", ""),
            "severity": _effective_severity(entry), "status": entry.get("status", "open")}


def expire_check(triage: dict, now=None, within_days: int = 0) -> dict:
    """Risk acceptances that have lapsed or are about to.

    Returns ``{"expired": [...], "expiring": [...]}``; each item has fingerprint, rule, file, severity,
    ``expires`` and ``days`` (days overdue for expired, days left for expiring). ``expired`` also lists entries
    that ``sync`` already re-opened and that nobody has re-triaged since."""
    ts = _now(now)
    expired, expiring = [], []
    for fp, entry in sorted((triage.get("findings") or {}).items()):
        date = _parse_date(entry.get("expires"))
        if entry.get("status") == "accepted_risk" and date is not None:
            left = (date - ts.date()).days
            if left < 0:
                expired.append({**_brief(fp, entry), "expires": entry["expires"], "days": -left})
            elif left <= within_days:
                expiring.append({**_brief(fp, entry), "expires": entry["expires"], "days": left})
        elif entry.get("expired") and entry.get("status", "open") in ACTIVE:
            when = next((item.get("expires", "") for item in reversed(entry.get("log", []))
                         if item.get("action") == "expired"), "")
            date = _parse_date(when)
            expired.append({**_brief(fp, entry), "expires": when, "days": (ts.date() - date).days if date else 0})
    return {"expired": expired, "expiring": expiring}


def stats(triage: dict, now=None, sla_days: dict | None = None, expiring_within: int = 14) -> dict:
    """Programme metrics computed from the triage file alone (no scan needed).

    Returns::

        {"total": n, "by_status": {status: n},                    # expired acceptances count as open
         "open_by_severity": {severity: n},
         "open_by_age": {"0-7": n, "8-30": n, "31-90": n, "91+": n},
         "mttr_days": {severity: {"count", "mean", "median"}, "all": {...}},   # first_seen -> fixed_at
         "sla": {"days": {...}, "breaches": [{fingerprint, rule, file, severity, age_days, sla_days,
                                              overdue_days}]},
         "regressions": n, "expired": [...], "expiring": [...],   # see expire_check
         "false_positive_rules": [{"rule", "total", "false_positive", "rate"}]}

    Severities are the effective ones (an override wins). ``sla_days`` maps severity -> days allowed from
    first-seen for a finding that is still open/confirmed (default ``DEFAULT_SLA_DAYS``; a severity without an
    entry has no SLA). Entries without a usable ``first_seen`` are left out of age/MTTR/SLA figures."""
    ts = _now(now)
    sla = dict(DEFAULT_SLA_DAYS if sla_days is None else sla_days)
    by_status = {s: 0 for s in STATUSES}
    open_by_sev = {s: 0 for s in SEVERITIES}
    ages = {name: 0 for name, _, _ in AGE_BUCKETS}
    durations: dict[str, list[float]] = {}
    breaches, regressions = [], 0
    rules: dict[str, list[int]] = {}
    entries = triage.get("findings") or {}
    for fp, entry in sorted(entries.items()):
        status, _ = _effective_status(entry, ts)
        by_status[status] += 1
        severity = _effective_severity(entry)
        regressions += int(entry.get("regressions") or 0)
        if entry.get("rule"):
            tally = rules.setdefault(entry["rule"], [0, 0])
            tally[0] += 1
            tally[1] += status == "false_positive"
        if status in ACTIVE:
            if severity:
                open_by_sev[severity] += 1
            age = _days_between(entry.get("first_seen"), ts)
            if age is None:
                continue
            days = int(age)
            for name, low, high in AGE_BUCKETS:
                if days >= low and (high is None or days <= high):
                    ages[name] += 1
            limit = sla.get(severity)
            if limit is not None and days > limit:          # whole days, so "overdue_days" is never 0
                breaches.append({**_brief(fp, entry), "status": status, "age_days": days, "sla_days": limit,
                                 "overdue_days": days - int(limit)})
        elif status == "fixed":
            fixed = _parse_ts(entry.get("fixed_at"))
            took = _days_between(entry.get("first_seen"), fixed) if fixed else None
            if took is not None:
                durations.setdefault(severity or "unknown", []).append(took)
                durations.setdefault("all", []).append(took)
    mttr = {key: {"count": len(vals), "mean": round(statistics.fmean(vals), 1),
                  "median": round(statistics.median(vals), 1)}
            for key, vals in sorted(durations.items(), key=lambda kv: SEVERITY_RANK.get(kv[0], 99))}
    breaches.sort(key=lambda b: (SEVERITY_RANK.get(b["severity"], 99), -b["overdue_days"], b["fingerprint"]))
    noisy = [{"rule": rule, "total": total, "false_positive": fps, "rate": round(fps / total, 2)}
             for rule, (total, fps) in rules.items() if fps]
    noisy.sort(key=lambda r: (-r["false_positive"], -r["rate"], r["rule"]))
    return {"total": len(entries), "by_status": by_status, "open_by_severity": open_by_sev, "open_by_age": ages,
            "mttr_days": mttr, "sla": {"days": sla, "breaches": breaches}, "regressions": regressions,
            **expire_check(triage, ts, expiring_within), "false_positive_rules": noisy[:20]}


# ------------------------------------------------------------------------------------------------------ merge

def _state(entry: dict) -> dict:
    return _prune({k: entry.get(k) for k in _STATE_KEYS})


def _pick(ours, theirs, base, stamp, rank):
    """Three-way choice between two values (``base`` is the common ancestor, or the untouched default when
    there is none). Returns (chosen, conflict?)."""
    if ours == theirs:
        return ours, False
    if ours == base:                           # only the other side changed it
        return theirs, False
    if theirs == base:
        return ours, False
    a, b = stamp(ours), stamp(theirs)
    if a != b:
        return (ours if a > b else theirs), True
    ka = (rank(ours), json.dumps(ours, sort_keys=True, ensure_ascii=False))
    kb = (rank(theirs), json.dumps(theirs, sort_keys=True, ensure_ascii=False))
    return (ours if ka <= kb else theirs), True


def merge(ours: dict, theirs: dict, base: dict | None = None) -> tuple[dict, list[dict]]:
    """Combine two versions of a triage (two branches, or two concurrent saves). Returns (merged, conflicts).

    * A finding triaged on one side only is kept as is.
    * Audit logs are unioned (never dropped, duplicates removed, chronological).
    * ``first_seen`` is the earlier one; the ``regressions`` counter the larger one.
    * For the decision itself (status, justification, author, expiry, ticket, ...) and for the severity
      override: if only one side changed it relative to ``base``, that side wins. If both changed it — or there
      is no base — the later edit wins; on equal timestamps the more conservative one does (the one that keeps
      the finding visible / the higher severity). Such cases are listed in ``conflicts`` as
      ``{"fingerprint", "field", "ours", "theirs", "chosen"}`` so a human can review them.

    The result is deterministic and symmetric: ``merge(a, b)`` and ``merge(b, a)`` give the same triage. The
    inputs are not modified."""
    a_all, b_all = ours.get("findings") or {}, theirs.get("findings") or {}
    base_all = (base or {}).get("findings") or {}
    merged = {}
    for key in sorted((set(ours) | set(theirs)) - {"schema", "findings"}):       # unknown top-level keys
        options = [json.dumps(side[key], sort_keys=True, ensure_ascii=False) for side in (ours, theirs) if key in side]
        merged[key] = json.loads(min(options))                                   # same pick whichever side is "ours"
    merged.update(schema=SCHEMA, findings={})
    conflicts: list[dict] = []
    for fp in sorted(set(a_all) | set(b_all)):
        a, b = a_all.get(fp), b_all.get(fp)
        if a is None or b is None:
            merged["findings"][fp] = json.loads(json.dumps(a if b is None else b))
            continue
        old = base_all.get(fp)
        state, clash = _pick(_state(a), _state(b), _state(old) if old is not None else {"status": "open"},
                             lambda s: _parse_ts(s.get("updated")) or _dt.datetime.min.replace(tzinfo=_dt.timezone.utc),
                             lambda s: _CONSERVATIVE.get(s.get("status", "open"), 0))
        if clash:
            conflicts.append({"fingerprint": fp, "field": "status", "ours": _state(a).get("status", "open"),
                              "theirs": _state(b).get("status", "open"), "chosen": state.get("status", "open")})
        canon_a, canon_b = (json.dumps(x, sort_keys=True, ensure_ascii=False) for x in (a, b))
        a_wins = state == _state(a) and (state != _state(b) or canon_a <= canon_b)
        winner, loser = (a, b) if a_wins else (b, a)
        out = {**loser, **winner}
        for key in _STATE_KEYS:
            out.pop(key, None)
        out.update(state)
        out.setdefault("status", "open")
        over, clash = _pick(a.get("severity_override") or {}, b.get("severity_override") or {},
                            (old.get("severity_override") or {}) if old is not None else {},
                            lambda s: _parse_ts(s.get("at")) or _dt.datetime.min.replace(tzinfo=_dt.timezone.utc),
                            lambda s: SEVERITY_RANK.get(s.get("severity"), 99))
        if clash:
            conflicts.append({"fingerprint": fp, "field": "severity_override",
                              "ours": (a.get("severity_override") or {}).get("severity", ""),
                              "theirs": (b.get("severity_override") or {}).get("severity", ""),
                              "chosen": over.get("severity", "")})
        out.pop("severity_override", None)
        if over:
            out["severity_override"] = dict(over)
        seen = [s for s in (a.get("first_seen"), b.get("first_seen")) if _parse_ts(s)]
        if seen:
            out["first_seen"] = min(seen, key=_parse_ts)
        out["regressions"] = max(int(a.get("regressions") or 0), int(b.get("regressions") or 0))
        log: dict[tuple, dict] = {}
        for item in list(a.get("log", [])) + list(b.get("log", [])):
            log.setdefault(_log_key(item), item)
        out["log"] = [dict(log[key]) for key in sorted(log)]
        merged["findings"][fp] = json.loads(json.dumps(_prune(out)))
    return merged, conflicts


# ------------------------------------------------------------------------------------- review of a change

def decision_changes(base: dict, head: dict) -> list[dict]:
    """Changes between two versions of a triage that can make a finding disappear from a report, for a human
    (or a CI gate) to review. The triage file lives in the repository, so the author of a pull request can
    edit it in the same pull request that introduces a vulnerability; compare the target branch's file
    (``base``) with the branch's (``head``) and require a security reviewer when the list is not empty.

    Each item is ``{"fingerprint", "rule", "file", "kind", "from", "to", "author"}`` with ``kind`` one of:

    * ``suppressed``        status became false_positive / accepted_risk / wont_fix (also for a new entry);
    * ``expiry_extended``   an accepted risk's expiry moved later or was removed;
    * ``severity_lowered``  a severity override was added or changed to something lower than the severity
                            recorded in ``base`` — or ``base`` records none, so it cannot be compared (then
                            every override below ``critical`` is listed, ``from`` is ``"?"``);
    * ``log_removed``       audit-log items present in ``base`` are missing (``from`` is how many);
    * ``entry_removed``     the whole entry is gone (its history with it)."""
    b_all, h_all = base.get("findings") or {}, head.get("findings") or {}
    out: list[dict] = []
    for fp in sorted(set(b_all) | set(h_all)):
        old, new = b_all.get(fp), h_all.get(fp)
        ref = new if new is not None else old

        def add(kind: str, before, after, ref=ref, fp=fp) -> None:
            out.append({"fingerprint": fp, "rule": ref.get("rule", ""), "file": ref.get("file", ""), "kind": kind,
                        "from": before, "to": after, "author": ref.get("author", "")})

        if new is None:
            add("entry_removed", old.get("status", "open"), "")
            continue
        old = old or {}
        was, now_ = old.get("status", "open"), new.get("status", "open")
        if now_ in JUSTIFICATION_REQUIRED and now_ != was:
            add("suppressed", was, now_)
        elif now_ == "accepted_risk" and old.get("expires") and (new.get("expires") or "9999-99-99") > old["expires"]:
            add("expiry_extended", old["expires"], new.get("expires") or "never")
        override = (new.get("severity_override") or {}).get("severity")
        if override in SEVERITIES and override != (old.get("severity_override") or {}).get("severity"):
            # Only ``base`` is trusted for the previous severity: the "severity" context field of ``head`` is
            # written by the same person as the override. Unknown previous severity -> flagged, unless the
            # override is the highest severity (which cannot be a lowering).
            before = _effective_severity(old)
            if (SEVERITY_RANK[override] > SEVERITY_RANK[before]) if before else override != SEVERITIES[0]:
                add("severity_lowered", before or "?", override)
        kept = {_log_key(item) for item in new.get("log", [])}
        missing = sum(1 for item in old.get("log", []) if _log_key(item) not in kept)
        if missing:
            add("log_removed", missing, "")
    return out


# ---------------------------------------------------------------------------------- import of old suppressions

def import_baseline(triage: dict, baseline_path, *, author: str, now=None, status: str = "open",
                    justification: str = "") -> dict:
    """Bring the fingerprints of a baseline file (``vulnscan --write-baseline``) under triage.

    A baseline says "this existed when we adopted the tool", not "this is safe", so entries are imported as
    ``open`` by default; pass e.g. ``status="accepted_risk"`` with a ``justification`` to import them as
    decisions. Fingerprints already in the triage are not touched. Returns ``{"added": n, "skipped": n}``.
    Raises ``TriageError`` when the baseline cannot be read."""
    ts = _now(now)
    author = _clean(author, 200)
    if not author:
        raise TriageError("e_author")
    if status not in STATUSES:
        raise TriageError("e_status", status=status, choices=", ".join(STATUSES))
    if status in JUSTIFICATION_REQUIRED and not _clean(justification):
        raise TriageError("e_justification", status=status)
    try:
        data = _read_json(baseline_path)
        items = data["fingerprints"] if isinstance(data, dict) else None
        if not isinstance(items, list):
            raise TypeError("'fingerprints' is not a list")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise TriageError("e_report", path=str(baseline_path), why=str(exc) or type(exc).__name__) from None
    entries = triage.setdefault("findings", {})
    added = skipped = 0
    source = _clean(pathlib.Path(baseline_path).name, 200)
    for item in items:
        fp = item.get("fp") if isinstance(item, dict) else None
        if not isinstance(fp, str) or not _KEY_RE.match(fp):
            continue
        if fp in entries:
            skipped += 1
            continue
        context = {"rule_id": item.get("rule", ""), "file": item.get("file", ""), "severity": item.get("severity", "")}
        entry = _entry(triage, fp, ts, context)
        if status != "open":
            entry.update(status=status, justification=_clean(justification), author=author, updated=_stamp(ts))
            if status == "fixed":
                entry["fixed_at"] = _stamp(ts)
        _log(entry, ts, author, "import", source=source, to=status)
        added += 1
    return {"added": added, "skipped": skipped}


# Exactly what vulnscan/scanner.py honours (SUPPRESS and FILE_SUPPRESS); keep in step with it.
_INLINE = re.compile(r"(nosec|vulnscan:\s*ignore(?:-file)?|noqa:\s*S\d+)", re.I)
_SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
                        ".tox", ".mypy_cache", ".ruff_cache", ".kashif", "target", "vendor"})


_LITERAL = re.compile(r"""(["'`])((?:\\.|(?!\1)[^\\]){8,})\1""")     # no ambiguous alternative: linear time


def _mask_literals(line: str) -> str:
    """Hide the body of quoted literals of 8+ characters: a suppressed line is often a hard-coded credential
    (``password = "..."  # nosec``) and this listing ends up in terminals and CI logs."""
    return _LITERAL.sub(lambda m: f"{m.group(1)}{m.group(2)[:2]}***{m.group(1)}", line)


def find_inline_suppressions(root, max_results: int = 5000, max_file_bytes: int = 1024 * 1024) -> list[dict]:
    """List inline suppression comments (``# nosec``, ``// vulnscan: ignore``, ``vulnscan: ignore-file``,
    ``# noqa: S...``) under ``root``, as ``{"file", "line", "kind": "line"|"file", "marker", "text"}``.

    Informational only: an inline comment has no author, date or expiry, so it cannot be turned into a triage
    decision — the list is what an auditor reviews to move them into the triage file. Files are only read as
    text; binary and oversized files, VCS and dependency directories are skipped. The match is textual (the
    scanner's own rule), so a marker inside a string literal is listed too. Quoted literals of 8+ characters
    are masked in ``text`` (suppressed lines are often hard-coded credentials); ``kind`` is ``"file"`` only where
    the scanner would honour ``ignore-file`` (within the first 2000 characters of the file)."""
    base = pathlib.Path(root)
    out: list[dict] = []
    paths = [base] if base.is_file() else None
    walker = [(str(base.parent), [], [base.name])] if paths else os.walk(base)
    for dirpath, dirnames, filenames in walker:
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for name in sorted(filenames):
            p = pathlib.Path(dirpath) / name
            try:
                if p.is_symlink() or not p.is_file() or p.stat().st_size > max_file_bytes:
                    continue
                raw = p.read_bytes()
            except OSError:
                continue
            if b"\0" in raw[:2048]:
                continue
            rel = _one_line(name if paths else p.relative_to(base).as_posix())    # file names are hostile too
            offset = 0
            for number, line in enumerate(raw.decode("utf-8", "replace").splitlines(keepends=True), 1):
                start, offset = offset, offset + len(line)
                m = _INLINE.search(line)
                if not m:
                    continue
                marker = re.sub(r"\s+", " ", m.group(1).lower())
                # the scanner honours "ignore-file" only within the first 2000 characters of a file; later it
                # is just a line suppression ("vulnscan: ignore" matches as a prefix)
                whole = marker.endswith("ignore-file") and start + m.end() <= 2000
                out.append({"file": rel, "line": number, "kind": "file" if whole else "line",
                            "marker": marker, "text": _clean(_mask_literals(line[:2000]), 200)})
                if len(out) >= max_results:
                    return out
    return out


# -------------------------------------------------------------------------------------------------------- CLI

def _read_report(path: str) -> list[dict]:
    """Findings (dict form, with ``fingerprint``) from a Kashif JSON report or a saved scan."""
    try:
        data = _read_json(path)
        items = data["findings"] if isinstance(data, dict) else data
        if not isinstance(items, list) or any(
                not isinstance(d, dict) or not isinstance(d.get("fingerprint"), str)
                or not _KEY_RE.match(d["fingerprint"]) for d in items):
            raise TypeError("expected a list of findings with a 'fingerprint'")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise TriageError("e_report", path=path, why=str(exc) or type(exc).__name__) from None
    return items


def _parse_sla(text: str | None) -> dict | None:
    if not text:
        return None
    out = {}
    for part in text.split(","):
        name, _, days = part.strip().partition("=")
        if name not in SEVERITIES or not days.isdigit():
            raise TriageError("e_sla", value=part)
        out[name] = int(days)
    return out


def _one_line(text) -> str:
    return re.sub(r"\s+", " ", _clean(text))


# --help in English and Arabic ("both": the Arabic line, then the English line; see vulnscan/i18n/cliargs.py)
_HELP = {
    "en": {
        "desc": "Kashif finding triage: decisions, audit log, fix deadlines (SLA) and MTTR.",
        "file": "triage file (default: <root>/.kashif/triage.json)",
        "root": "project root (default: current directory)",
        "author": "who makes the change (default: $KASHIF_AUTHOR, then the OS user)",
        "lang": "message language: en or ar",
        "json": "machine-readable output",
        "set": "record a decision for a finding",
        "fingerprint": "fingerprint of the finding (from the report; a unique prefix is enough)",
        "status": "the decision",
        "justification": "why (required for false_positive, accepted_risk and wont_fix)",
        "expires": "accepted_risk only: YYYY-MM-DD or +90d",
        "max_accept": "policy ceiling for --expires (days)",
        "ticket": "http(s) URL of the tracking ticket",
        "comment": "a comment for the audit log",
        "report": "Kashif JSON report: adds rule/file/severity context to the entry",
        "c_comment": "append a comment to the audit log",
        "text": "the comment",
        "severity": "override the severity (or 'none' to remove)",
        "new_severity": "the new severity, or none",
        "reason": "why the severity changes",
        "list": "list triaged findings",
        "f_status": "show only this status (repeatable)",
        "f_severity": "show only this severity (repeatable)",
        "show": "one finding with its full audit log",
        "stats": "MTTR, age buckets, fix-deadline (SLA) breaches",
        "sla": "fix deadline in days per severity, e.g. critical=7,high=30,medium=90,low=180",
        "fail_breach": "exit 1 when a fix deadline is exceeded",
        "expire": "expired risk acceptances (exit 1 when any)",
        "within": "also list acceptances expiring within N days (default 14)",
        "apply": "re-open the expired ones in the file",
        "sync": "reconcile with a scan: first-seen, auto-fixed, regressions",
        "sync_report": "Kashif JSON report (kashif PATH --format json)",
        "partial": "the scan did not cover the whole project: mark nothing as fixed",
        "dry_run": "show the result without saving the file",
        "import": "import existing suppressions",
        "baseline": "baseline file written by --write-baseline",
        "i_status": "status of the imported findings (default: open)",
        "i_justification": "justification recorded with the imported findings",
        "inline": "list inline nosec / vulnscan: ignore comments",
        "diff": "decision changes since BASE (PR gate): new suppressions, extended expiries, lowered severities, "
                "removed history",
        "base": "the triage file of the target branch, e.g. from "
                "'git show origin/main:.kashif/triage.json > base.json' (missing/empty = no triage yet)",
        "fail_change": "exit 1 when there is anything to review",
        "merge": "merge two triage files (usable as a git merge driver)",
        "ours": "our version of the triage file",
        "theirs": "their version of the triage file",
        "m_base": "the common ancestor (git merge driver: %%O)",
        "output": "where to write (default: standard output)",
    },
    "ar": {
        "desc": "فرز نتائج كاشِف: القرارات وسجل التدقيق ومهلة الإصلاح ومتوسط زمن الإصلاح.",
        "file": "ملف الفرز (الافتراضي: ‎<root>/.kashif/triage.json)",
        "root": "جذر المشروع (الافتراضي: المجلد الحالي)",
        "author": "صاحب التغيير (الافتراضي: ‎$KASHIF_AUTHOR، ثم مستخدم النظام)",
        "lang": "لغة الرسائل: en أو ar",
        "json": "مخرجات آلية بصيغة JSON",
        "set": "سجّل قرارًا لنتيجة",
        "fingerprint": "بصمة النتيجة (من التقرير؛ تكفي بداية فريدة منها)",
        "status": "القرار",
        "justification": "المبرّر (مطلوب لحالات false_positive وaccepted_risk وwont_fix)",
        "expires": "لحالة accepted_risk فقط: YYYY-MM-DD أو ‎+90d",
        "max_accept": "أقصى مدة تسمح بها السياسة لـ --expires (بالأيام)",
        "ticket": "رابط http(s) لتذكرة المتابعة",
        "comment": "تعليق يُضاف إلى سجل التدقيق",
        "report": "تقرير JSON من كاشِف: يضيف إلى القيد القاعدة والملف والخطورة",
        "c_comment": "أضِف تعليقًا إلى سجل التدقيق",
        "text": "نص التعليق",
        "severity": "عدّل الخطورة (أو none لإزالة التعديل)",
        "new_severity": "الخطورة الجديدة، أو none",
        "reason": "سبب تعديل الخطورة",
        "list": "اعرض النتائج المفروزة",
        "f_status": "اعرض هذه الحالة فقط (يمكن تكراره)",
        "f_severity": "اعرض هذه الخطورة فقط (يمكن تكراره)",
        "show": "نتيجة واحدة مع سجل تدقيقها كاملًا",
        "stats": "متوسط زمن الإصلاح، وأعمار النتائج المفتوحة، وتجاوزات مهلة الإصلاح",
        "sla": "مهلة الإصلاح بالأيام لكل خطورة، مثل critical=7,high=30,medium=90,low=180",
        "fail_breach": "أعد رمز خروج 1 إذا تجاوزت نتيجة مهلة إصلاحها",
        "expire": "قبول الخطر المنتهي (رمز خروج 1 إن وُجد)",
        "within": "اعرض أيضًا ما ينتهي قبوله خلال N يومًا (الافتراضي 14)",
        "apply": "أعد فتح المنتهية في ملف الفرز",
        "sync": "طابِق مع فحص: أول ظهور، والإصلاح التلقائي، والارتداد",
        "sync_report": "تقرير JSON من كاشِف (kashif PATH --format json)",
        "partial": "الفحص لم يشمل المشروع كله: لا تَعُدّ أي نتيجة مُصلَحة",
        "dry_run": "اعرض النتيجة دون حفظ الملف",
        "import": "استورد الكتم الموجود",
        "baseline": "ملف خط أساس كتبه --write-baseline",
        "i_status": "حالة النتائج المستوردة (الافتراضي: open)",
        "i_justification": "المبرّر المسجَّل مع النتائج المستوردة",
        "inline": "اعرض تعليقات الكتم داخل الكود (nosec و vulnscan: ignore)",
        "diff": "تغييرات القرارات منذ BASE (بوابة لطلبات الدمج): كتم جديد، وتمديد انتهاء القبول، وخفض الخطورة، "
                "وحذف السجل",
        "base": "ملف الفرز في الفرع الهدف، مثلًا من "
                "'git show origin/main:.kashif/triage.json > base.json' (غيابه أو فراغه = لا فرز بعد)",
        "fail_change": "أعد رمز خروج 1 إذا وُجد ما يحتاج مراجعة",
        "merge": "ادمج ملفَّي فرز (يصلح مشغّلَ دمج لـ git)",
        "ours": "نسختنا من ملف الفرز",
        "theirs": "نسختهم من ملف الفرز",
        "m_base": "السلف المشترك (في مشغّل دمج git: ‎%%O)",
        "output": "مكان الكتابة (الافتراضي: الخرج القياسي)",
    },
}


def _parser(lang: str = "en") -> argparse.ArgumentParser:
    from .i18n.cliargs import HelpFormatter, pick

    def h(key: str) -> str:
        return pick(lang, _HELP["ar"][key], _HELP["en"][key])

    common = argparse.ArgumentParser(add_help=False)
    s = argparse.SUPPRESS
    common.add_argument("--file", "-f", default=s, help=h("file"))
    common.add_argument("--root", default=s, help=h("root"))
    common.add_argument("--author", default=s, help=h("author"))
    common.add_argument("--lang", choices=("en", "ar", "both"), default=s, metavar="{en,ar}", help=h("lang"))
    common.add_argument("--json", action="store_true", default=s, help=h("json"))
    common.add_argument("--now", default=s, help=argparse.SUPPRESS)       # tests / reproducible runs

    p = argparse.ArgumentParser(prog="kashif triage", parents=[common], description=h("desc"),
                                formatter_class=HelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)

    def command(name: str, key: str):
        return sub.add_parser(name, parents=[common], help=h(key), description=h(key), formatter_class=HelpFormatter)

    c = command("set", "set")
    c.add_argument("fingerprint", help=h("fingerprint"))
    c.add_argument("status", choices=STATUSES, help=h("status"))
    c.add_argument("--justification", "-j", default="", help=h("justification"))
    c.add_argument("--expires", help=h("expires"))
    c.add_argument("--max-accept-days", type=int, help=h("max_accept"))
    c.add_argument("--ticket", help=h("ticket"))
    c.add_argument("--comment", default="", help=h("comment"))
    c.add_argument("--report", help=h("report"))

    c = command("comment", "c_comment")
    c.add_argument("fingerprint", help=h("fingerprint"))
    c.add_argument("text", help=h("text"))

    c = command("severity", "severity")
    c.add_argument("fingerprint", help=h("fingerprint"))
    c.add_argument("severity", choices=SEVERITIES + ("none",), help=h("new_severity"))
    c.add_argument("--reason", default="", help=h("reason"))

    c = command("list", "list")
    c.add_argument("--status", action="append", choices=STATUSES, help=h("f_status"))
    c.add_argument("--severity", action="append", choices=SEVERITIES, help=h("f_severity"))

    c = command("show", "show")
    c.add_argument("fingerprint", help=h("fingerprint"))

    c = command("stats", "stats")
    c.add_argument("--sla", help=h("sla"))
    c.add_argument("--fail-on-breach", action="store_true", help=h("fail_breach"))

    c = command("expire-check", "expire")
    c.add_argument("--within", type=int, default=14, help=h("within"))
    c.add_argument("--apply", action="store_true", help=h("apply"))

    c = command("sync", "sync")
    c.add_argument("--report", required=True, help=h("sync_report"))
    c.add_argument("--partial", action="store_true", help=h("partial"))
    c.add_argument("--dry-run", action="store_true", help=h("dry_run"))

    c = command("import", "import")
    c.add_argument("--baseline", help=h("baseline"))
    c.add_argument("--status", choices=STATUSES, default="open", help=h("i_status"))
    c.add_argument("--justification", "-j", default="", help=h("i_justification"))
    c.add_argument("--inline", action="store_true", help=h("inline"))

    c = command("diff", "diff")
    c.add_argument("base", help=h("base"))
    c.add_argument("--fail-on-change", action="store_true", help=h("fail_change"))

    c = command("merge", "merge")
    c.add_argument("ours", help=h("ours"))
    c.add_argument("theirs", help=h("theirs"))
    c.add_argument("--base", help=h("m_base"))
    c.add_argument("--output", "-o", help=h("output"))
    return p


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point. Exit codes: 0 ok; 1 policy signal (expired acceptance, SLA breach with
    ``--fail-on-breach``, decision changes with ``diff --fail-on-change``); 2 usage, input or I/O error."""
    for stream in (sys.stdout, sys.stderr):                # Arabic output on a cp1252 Windows console (as cli.py)
        try:
            if (getattr(stream, "encoding", "") or "").lower().replace("-", "") != "utf8":
                stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    from .i18n.cliargs import help_lang, localized_argparse
    argv = list(sys.argv[1:] if argv is None else argv)
    env = "ar" if os.environ.get("KASHIF_LANG", "").lower().startswith("ar") else "en"
    hlang = help_lang(argv, default=env)          # --help and usage errors follow --lang (en, ar or both)
    with localized_argparse(hlang):
        args = _parser(hlang).parse_args(argv)
    lang = getattr(args, "lang", None) or env
    lang = "ar" if lang == "ar" else "en"          # "both": English messages, as from a "both" scan
    prefix = "خطأ" if lang == "ar" else "error"
    try:
        return _run(args, lang)
    except TriageError as exc:
        print(f"{prefix}: {exc.message(lang)}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:                   # unwritable directory, full disk, bad --now, ...
        print(f"{prefix}: {_one_line(exc)}", file=sys.stderr)
        return 2


def _run(args, lang: str) -> int:
    as_json = bool(getattr(args, "json", False))
    root = getattr(args, "root", ".")
    path = pathlib.Path(getattr(args, "file", None) or default_path(root))
    now = _now(getattr(args, "now", None))
    out = sys.stdout

    def author() -> str:
        name = getattr(args, "author", None) or os.environ.get("KASHIF_AUTHOR", "")
        if not name:
            try:
                name = getpass.getuser()
            except (OSError, KeyError, ImportError):
                name = ""
        return name

    def emit(payload: dict, lines: list[str]) -> None:
        if as_json:
            print(json.dumps(payload, ensure_ascii=False, indent=2), file=out)
        else:
            print("\n".join(lines) if lines else _t(lang, "none"), file=out)

    def load_file() -> dict:
        info: dict = {}
        triage = load(path, info)
        if info.get("conflict_markers"):
            print(_t(lang, "conflict_markers"), file=sys.stderr)
        return triage

    def row(fp: str, entry: dict) -> str:
        status, expired = _effective_status(entry, now)
        flags = ([_t(lang, "expired_flag")] if expired else []) + ([_t(lang, "regression_flag")]
                                                                   if entry.get("regression") else [])
        parts = [fp, f"{severity_label(_effective_severity(entry) or '-', lang):8}", f"{status_label(status, lang):15}",
                 _one_line(entry.get("rule", "")), _one_line(entry.get("file", ""))]
        if entry.get("expires") and not expired:
            parts.append(f"<= {entry['expires']}")
        if flags:
            parts.append("[" + ", ".join(flags) + "]")
        if entry.get("justification") and not expired:
            parts.append("- " + _one_line(entry["justification"])[:80])
        return "  ".join(p for p in parts if p)

    cmd = args.command
    if cmd in ("set", "comment", "severity"):
        who = author()
        result: dict = {}

        def change(triage: dict) -> None:
            fp = resolve_fingerprint(triage, args.fingerprint)
            old = (triage.get("findings") or {}).get(fp, {})
            result.update(fingerprint=fp)
            if cmd == "set":
                finding = None
                if args.report:
                    finding = next((d for d in _read_report(args.report) if d.get("fingerprint") == fp), None)
                before = old.get("status", "open")
                entry = set_status(triage, fp, args.status, author=who, justification=args.justification,
                                   expires=args.expires, ticket=args.ticket, comment=args.comment, now=now,
                                   finding=finding, max_accept_days=args.max_accept_days)
                result["line"] = _t(lang, "set_done", fp=fp, old=status_label(before, lang),
                                    new=status_label(args.status, lang))
            elif cmd == "comment":
                entry = add_comment(triage, fp, args.text, author=who, now=now)
                result["line"] = _t(lang, "comment_done", fp=fp)
            else:
                before = _effective_severity(old) or "-"
                new = None if args.severity == "none" else args.severity
                entry = override_severity(triage, fp, new, reason=args.reason, author=who, now=now)
                result["line"] = (_t(lang, "sev_done", fp=fp, old=severity_label(before, lang),
                                     new=severity_label(new, lang)) if new
                                  else _t(lang, "sev_cleared", fp=fp))
            result["entry"] = entry

        update(path, change)
        emit({"fingerprint": result["fingerprint"], "entry": _prune(result["entry"]), "file": str(path)},
             [result["line"], _t(lang, "saved", path=path)])
        return 0

    if cmd == "list":
        triage = load_file()
        rows = []
        for fp, entry in sorted((triage.get("findings") or {}).items(),
                                key=lambda kv: (SEVERITY_RANK.get(_effective_severity(kv[1]), 99), kv[0])):
            status, _ = _effective_status(entry, now)
            if args.status and status not in args.status:
                continue
            if args.severity and _effective_severity(entry) not in args.severity:
                continue
            rows.append((fp, entry))
        emit({"findings": {fp: _prune(dict(entry, status=_effective_status(entry, now)[0])) for fp, entry in rows}},
             [_t(lang, "h_list", n=len(rows))] + [row(fp, entry) for fp, entry in rows])
        return 0

    if cmd == "show":
        triage = load_file()
        fp = resolve_fingerprint(triage, args.fingerprint)
        entry = (triage.get("findings") or {}).get(fp)
        if entry is None:
            raise TriageError("e_fp_unknown", fp=args.fingerprint)
        lines = [row(fp, entry)]
        if entry.get("ticket"):
            lines.append("  " + entry["ticket"])
        for item in sorted(entry.get("log", []), key=_log_key):
            detail = ", ".join(f"{k}={_one_line(v)}" for k, v in sorted(item.items())
                               if k not in ("at", "author", "action"))
            lines.append(f"  {_one_line(item.get('at', ''))}  {_one_line(item.get('author', ''))}  "
                         f"{_one_line(item.get('action', ''))}  {detail}")
        emit({"fingerprint": fp, "entry": _prune(entry)}, lines)
        return 0

    if cmd == "stats":
        triage = load_file()
        data = stats(triage, now, _parse_sla(args.sla))
        comma = "، " if lang == "ar" else ", "
        lines = [_t(lang, "h_stats") + f" ({data['total']})", _t(lang, "by_status") + ": " + comma.join(
            f"{status_label(s, lang)} {n}" for s, n in data["by_status"].items())]
        lines.append(_t(lang, "open_by_sev") + ": " + comma.join(f"{severity_label(s, lang)} {n}"
                                                                 for s, n in data["open_by_severity"].items()))
        lines.append(_t(lang, "age") + ": " + comma.join(f"{k}: {n}" for k, n in data["open_by_age"].items()))
        lines.append(_t(lang, "mttr") + ":" + ("" if data["mttr_days"] else " -"))
        lines += ["  " + _t(lang, "mttr_row", sev=severity_label(sev, lang), mean=m["mean"], median=m["median"],
                            n=m["count"]) for sev, m in data["mttr_days"].items()]
        lines.append(_t(lang, "regressions") + f": {data['regressions']}")
        lines.append(_t(lang, "sla") + f": {len(data['sla']['breaches'])}")
        lines += ["  " + _t(lang, "sla_row", fp=b["fingerprint"], sev=severity_label(b["severity"], lang),
                            rule=_one_line(b["rule"]),
                            file=_one_line(b["file"]), age=b["age_days"], sla=b["sla_days"], over=b["overdue_days"])
                  for b in data["sla"]["breaches"]]
        lines.append(_t(lang, "expired") + f": {len(data['expired'])}")
        lines.append(_t(lang, "expiring", days=14) + f": {len(data['expiring'])}")
        if data["false_positive_rules"]:
            lines.append(_t(lang, "noisy") + ": " + comma.join(
                f"{_one_line(r['rule'])} {r['false_positive']}/{r['total']}" for r in data["false_positive_rules"][:8]))
        emit(data, lines)
        return 1 if args.fail_on_breach and data["sla"]["breaches"] else 0

    if cmd == "expire-check":
        triage = load_file()
        data = expire_check(triage, now, max(0, args.within))
        if args.apply and data["expired"]:
            update(path, lambda t: sync([], t, now, complete=False))
        lines = [_t(lang, "expired") + f": {len(data['expired'])}"]
        lines += ["  " + _t(lang, "expired_row", fp=e["fingerprint"], rule=_one_line(e["rule"]),
                            file=_one_line(e["file"]), date=e["expires"], days=e["days"]) for e in data["expired"]]
        lines.append(_t(lang, "expiring", days=args.within) + f": {len(data['expiring'])}")
        lines += ["  " + _t(lang, "exp_row", fp=e["fingerprint"], rule=_one_line(e["rule"]), file=_one_line(e["file"]),
                            date=e["expires"], days=e["days"]) for e in data["expiring"]]
        emit(data, lines)
        return 1 if data["expired"] else 0

    if cmd == "sync":
        findings = _read_report(args.report)
        holder: dict = {}
        if args.dry_run:
            holder["result"] = sync(findings, load_file(), now, complete=not args.partial)
        else:
            update(path, lambda t: holder.update(result=sync(findings, t, now, complete=not args.partial)))
        res: SyncResult = holder["result"]
        emit(res.to_dict(), [_t(lang, "sync_done", new=len(res.new), fixed=len(res.fixed), reg=len(res.regressions),
                                exp=len(res.expired), stale=len(res.stale))])
        return 0

    if cmd == "import":
        payload: dict = {}
        lines = []
        if args.baseline:
            who = author()
            update(path, lambda t: payload.update(baseline=import_baseline(
                t, args.baseline, author=who, now=now, status=args.status, justification=args.justification)))
            lines.append(_t(lang, "import_done", **payload["baseline"]))
        if args.inline or not args.baseline:
            found = find_inline_suppressions(root)
            payload["inline"] = found
            lines.append(_t(lang, "inline", n=len(found)))
            lines += [f"  {i['file']}:{i['line']}  [{i['marker']}]  {i['text']}" for i in found]
        emit(payload, lines)
        return 0

    if cmd == "diff":
        changes = decision_changes(load(args.base), load_file())
        emit({"changes": changes}, [_t(lang, "h_changes", n=len(changes))] + [
            "  " + _t(lang, "change_row", fp=c["fingerprint"], rule=_one_line(c["rule"]) or "-",
                      file=_one_line(c["file"]) or "-", kind=c["kind"], old=c["from"], new=c["to"] or "-",
                      author=_one_line(c["author"]) or "-") for c in changes])
        return 1 if args.fail_on_change and changes else 0

    if cmd == "merge":
        base = load(args.base) if args.base else None
        merged, conflicts = merge(load(args.ours), load(args.theirs), base)
        if args.output:
            save(merged, args.output)
        else:
            out.write(dumps(merged))
        report = [_t(lang, "merge_done", n=len(merged["findings"]), c=len(conflicts))]
        report += ["  " + _t(lang, "conflict_row", fp=c["fingerprint"], field=c["field"], chosen=c["chosen"] or "-")
                   for c in conflicts]
        print("\n".join(report), file=sys.stderr)
        return 0                 # conflicts are resolved deterministically; a git merge driver must succeed
    return 2


if __name__ == "__main__":
    sys.exit(main())
