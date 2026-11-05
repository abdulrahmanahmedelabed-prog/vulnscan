"""Shared data types."""

from __future__ import annotations

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

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity_ar"] = SEVERITY_AR[self.severity]
        return d


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Highest severity first, then by file and line for stable output."""
    return sorted(findings, key=lambda f: (SEVERITY_RANK[f.severity], f.file, f.line, f.rule_id))
