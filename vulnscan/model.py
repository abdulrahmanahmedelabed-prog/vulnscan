"""Shared data types."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict

# Ordered from most to least severe. Reports are sorted with this order.
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEVERITY_AR = {
    "critical": "حرج",
    "high": "عالٍ",
    "medium": "متوسط",
    "low": "منخفض",
    "info": "معلوماتي",
}


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str            # English title
    title_ar: str         # Arabic title
    file: str             # path relative to the scanned root
    line: int             # 1-based, 0 when the finding is file-level
    snippet: str          # the offending line (trimmed) or a short note
    advice: str           # remediation, Arabic
    cwe: str = ""
    source: str = "vulnscan"   # vulnscan | osv | bandit | semgrep | ...
    extra: dict = field(default_factory=dict)

    def key(self) -> tuple:
        return (self.rule_id, self.file, self.line)

    def base_fingerprint(self) -> str:
        """Stable identity across line shifts: rule + file + normalized snippet, independent of line number.

        A deduplication index (added by assign_fingerprints) distinguishes identical findings in one file."""
        norm = re.sub(r"\s+", "", (self.snippet or "")).lower()   # ignore all whitespace: survives reformatting
        raw = f"{self.rule_id}\x00{self.file}\x00{norm}"
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity_ar"] = SEVERITY_AR[self.severity]
        d["fingerprint"] = self.fingerprint()
        return d

    def fingerprint(self) -> str:
        """Full stable fingerprint, including the dedup index set by assign_fingerprints (default 0)."""
        return f"{self.base_fingerprint()}:{self.extra.get('fp_index', 0)}"


# SARIF severity ↔ level (SARIF has only error/warning/note/none).
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
# A numeric security-severity (SARIF/GitHub convention, 0.0–10.0) so code-scanning sorts findings.
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def assign_fingerprints(findings: "list[Finding]") -> None:
    """Give each finding a stable fingerprint, numbering identical ones in the same file 0,1,2,… so a
    file with the same issue twice yields two distinct, reproducible fingerprints (needed for baselines)."""
    counts: dict[str, int] = {}
    for f in sort_findings(findings):
        base = f.base_fingerprint()
        idx = counts.get(base, 0)
        counts[base] = idx + 1
        f.extra["fp_index"] = idx


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Highest severity first, then by file and line for stable output."""
    return sorted(findings, key=lambda f: (SEVERITY_RANK[f.severity], f.file, f.line, f.rule_id))
