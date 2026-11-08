"""Baseline support: record the findings that exist today, then on later scans report only what is new.

This is how teams adopt a scanner on an existing codebase without drowning in pre-existing findings — the
same idea as Semgrep ``--baseline``, CodeQL's baseline, and Snyk's ignore policy. A baseline is a small JSON
file of stable fingerprints (see ``Finding.fingerprint``); it does not store code, only identities, so it is
safe to commit. Matching is by fingerprint (rule + file + normalized snippet + dedup index), so a finding
survives edits that shift its line, and a genuinely new issue is never accidentally suppressed.
"""

from __future__ import annotations

import json
import pathlib

from . import __version__
from .model import Finding, assign_fingerprints

SCHEMA = "vulnscan-baseline/1"


def save_baseline(findings: list[Finding], path: str) -> int:
    """Write the current findings' fingerprints to ``path``. Returns how many were recorded."""
    assign_fingerprints(findings)
    entries = []
    for f in sorted(findings, key=lambda f: f.fingerprint()):
        entries.append({"fp": f.fingerprint(), "rule": f.rule_id, "file": f.file, "severity": f.severity})
    data = {"schema": SCHEMA, "tool_version": __version__, "count": len(entries), "fingerprints": entries}
    pathlib.Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return len(entries)


def load_baseline(path: str) -> set[str]:
    """Return the set of fingerprints in a baseline file, or an empty set if it does not exist / is unreadable."""
    try:
        data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    if isinstance(data, dict) and isinstance(data.get("fingerprints"), list):
        return {e.get("fp") for e in data["fingerprints"] if isinstance(e, dict) and e.get("fp")}
    return set()


def apply_baseline(findings: list[Finding], path: str) -> tuple[list[Finding], int, int]:
    """Split findings against a baseline. Returns (new_findings, suppressed_count, baseline_size).

    A finding in the baseline is dropped (it was known); a finding not in the baseline is kept and marked
    ``extra['new'] = True`` so a report can highlight it. The baseline itself is never modified here."""
    known = load_baseline(path)
    assign_fingerprints(findings)
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
