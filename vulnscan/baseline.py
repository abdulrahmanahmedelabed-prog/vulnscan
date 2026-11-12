"""Baseline support: record the findings that exist today, then on later scans report only what is new.

This is how teams adopt a scanner on an existing codebase without drowning in pre-existing findings — the
same idea as Semgrep ``--baseline``, CodeQL's baseline, and Snyk's ignore policy. A baseline is a small JSON
file of stable fingerprints (see ``Finding.fingerprint``); it does not store code, only identities, so it is
safe to commit. Matching is by fingerprint (rule + file + normalized snippet + dedup index), so a finding
survives edits that shift its line or reformat it. Identical findings in the same file (same rule, same
normalized code) are told apart only by count: if a file had two and now has three, one is reported as new,
but which of the three carries the label is not meaningful.
"""

from __future__ import annotations

import json
import os
import pathlib
import stat

from . import __version__
from .model import Finding, ensure_fingerprints

SCHEMA = "vulnscan-baseline/1"
MAX_BASELINE_BYTES = 64_000_000


def read_baseline_text(path) -> str | None:
    """Text of a baseline file (UTF-8, BOM tolerated), or None when there is no such file. The path can come from
    the scanned repository (``.kashif-baseline.json`` in the editor, ``gate.baseline`` in ``kashif.yml``), so only a
    regular file of at most ``MAX_BASELINE_BYTES`` is read: a device, FIFO or directory (e.g. a committed
    ``.kashif-baseline.json`` symlinked to ``/dev/zero``) raises OSError instead of exhausting memory or blocking,
    and a larger file raises ValueError. Bad UTF-8 raises ValueError."""
    try:
        info = os.stat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise OSError(f"{path}: not a regular file")
    if info.st_size > MAX_BASELINE_BYTES:
        raise ValueError(f"{path}: larger than {MAX_BASELINE_BYTES} bytes")
    with open(path, "rb") as fh:
        raw = fh.read(MAX_BASELINE_BYTES + 1)
    if len(raw) > MAX_BASELINE_BYTES:
        raise ValueError(f"{path}: larger than {MAX_BASELINE_BYTES} bytes")
    return raw.decode("utf-8-sig")


def save_baseline(findings: list[Finding], path: str) -> int:
    """Write the current findings' fingerprints to ``path``. Returns how many were recorded."""
    ensure_fingerprints(findings)
    entries = []
    for f in sorted(findings, key=lambda f: f.fingerprint()):
        entries.append({"fp": f.fingerprint(), "rule": f.rule_id, "file": f.file, "severity": f.severity})
    data = {"schema": SCHEMA, "tool_version": __version__, "count": len(entries), "fingerprints": entries}
    pathlib.Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return len(entries)


def baseline_problem(path: str) -> str | None:
    """Why ``path`` cannot serve as a baseline, checked before a scan uses it: ``None`` (a baseline file, possibly
    with no fingerprints), ``"missing"`` (no such file: the first run of a pipeline; every finding is new),
    ``"unreadable"`` (the file exists but cannot be read or is not JSON) or ``"shape"`` (JSON, but not a file
    written by ``--write-baseline``: no ``fingerprints`` list)."""
    try:
        text = read_baseline_text(path)
    except (OSError, ValueError):                         # a device / FIFO / directory, too large, bad UTF-8
        return "unreadable"
    if text is None:
        return "missing"
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return "unreadable"
    if not (isinstance(data, dict) and isinstance(data.get("fingerprints"), list)):
        return "shape"
    return None


def load_baseline(path: str) -> set[str]:
    """Return the set of fingerprints in a baseline file, or an empty set if it does not exist / is unreadable."""
    try:
        text = read_baseline_text(path)
        data = json.loads(text) if text is not None else None
    except (OSError, ValueError, RecursionError):
        return set()
    if isinstance(data, dict) and isinstance(data.get("fingerprints"), list):
        # fingerprints are strings: a list or object in "fp" (a hand-edited or hostile file) is skipped, not hashed
        return {e["fp"] for e in data["fingerprints"] if isinstance(e, dict) and isinstance(e.get("fp"), str) and e["fp"]}
    return set()


def apply_baseline(findings: list[Finding], path: str) -> tuple[list[Finding], int, int]:
    """Split findings against a baseline. Returns (new_findings, suppressed_count, baseline_size).

    A finding in the baseline is dropped (it was known); a finding not in the baseline is kept and marked
    ``extra['new'] = True`` so a report can highlight it. The baseline itself is never modified here."""
    known = load_baseline(path)
    ensure_fingerprints(findings)
    if not known:
        for f in findings:
            f.extra["new"] = True
        return findings, 0, 0
    kept, suppressed = [], 0
    for f in findings:
        if f.fingerprint() in known:
            suppressed += 1
        else:
            f.extra["new"] = True
            kept.append(f)
    return kept, suppressed, len(known)
