"""Shared data types."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict

from .i18n import to_en

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
SEVERITY_EN = {s: s.capitalize() for s in SEVERITIES}


# Cookie rules fingerprint on the title (it names the cookie), never on the Set-Cookie value. 1.1.0: + WEB400–WEB414.
_COOKIE_RULES = frozenset({"WEB020", "WEB021", "WEB022"} | {f"WEB{n}" for n in range(400, 415)})
# Web rules of 1.0.1 whose 1.0.1 snippet the 1.1.0 scanner can reproduce exactly: they keep their 1.0.1 fingerprint
# (title + the snippet below), so baselines and triage decisions taken on 1.0.x stay valid. Every other web finding
# that carries ``extra["fp_key"]`` (rule|host|kind|normalised value, spec §3.5) fingerprints on it instead.
_LEGACY_WEB_SNIPPETS = {
    "WEB-strict-transport-security": "HTTP", "WEB-content-security-policy": "HTTP", "WEB-x-frame-options": "HTTP",
    "WEB-x-content-type-options": "HTTP", "WEB-referrer-policy": "HTTP", "WEB-permissions-policy": "HTTP",
    "WEB040": "script-src 'unsafe-inline'", "WEB041": "script-src 'unsafe-eval'", "WEB042": "script-src *",
    "WEB043": None, "WEB010": None, "WEB011": None,     # None: the snippet itself (the CSP or header value, ≤ 120)
    # page and probe rules whose 1.0.1 snippet was a constant
    "WEB052": "<input type=password>", "WEB055": "Index of /", "WEB056": "stack trace",
    "WEB060": "/.well-known/security.txt",
    "WEB000": "",                    # the 1.0.1 snippet was the http:// URL as typed (extra["fp_url"], engine)
}
_LEGACY_COOKIE_RULES = frozenset({"WEB020", "WEB021", "WEB022"})   # 1.0.1 snippet: the title (names the cookie)


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

        * Whitespace is ignored entirely, so reformatting does not create a "new" finding.
        * For findings inside an archive (``app-1.2.apk!src/x.java``) the archive's own name is dropped, so a
          baseline taken on one release of an artifact still applies to the next.
        * Web findings fingerprint on the title plus a snippet with volatile values removed (cookie values,
          HTTP status codes), so an unchanged site is not reported as new on every run. 1.1.0 web findings that carry
          ``extra["fp_key"]`` fingerprint on it (rule, host, response kind and normalised value: no nonces, dates
          or counts); the 1.0.1 rules whose 1.0.1 snippet can be rebuilt (headers, CSP, cookies, WEB000, WEB052,
          WEB055, WEB056, WEB060) keep their 1.0.1 fingerprints (``extra["fp_title"]``).
        A deduplication index (added by assign_fingerprints) distinguishes identical findings in one file."""
        file = self.extra.get("archive_member") or self.file
        snippet = self.snippet or ""
        if self.source == "web":
            fp_key, fp_title = self.extra.get("fp_key"), self.extra.get("fp_title")
            title = self.title
            if isinstance(fp_title, str) and fp_title and (self.rule_id in _LEGACY_WEB_SNIPPETS
                                                           or self.rule_id in _LEGACY_COOKIE_RULES):
                title = fp_title                          # the 1.0.1 title: a 1.0.x baseline still matches
                if self.rule_id == "WEB000":
                    snippet = str(self.extra.get("fp_url") or self.extra.get("url") or snippet)
                else:
                    snippet = _LEGACY_WEB_SNIPPETS.get(self.rule_id) or snippet
            elif isinstance(fp_key, str) and fp_key:      # 1.1.0 grouping key: stable across reruns (spec §3.5)
                raw = f"{self.rule_id}\x00{file.replace(chr(92), '/')}\x00fp:{fp_key}"
                return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]
            title = re.sub(r"\b\d+ days\b", "N days", title)   # "expires in 9 days" must not change identity
            if self.rule_id in _COOKIE_RULES:
                snippet = title                  # exact cookie name is in the title; values and Expires vary
            else:                                # drop status codes and query/attribute values (?v=1699 cache-busters)
                snippet = title + "|" + re.sub(r"=[^&;\s\"']*", "=", re.sub(r"\bHTTP \d{3}\b", "HTTP", snippet))
        norm = re.sub(r"\s+", "", snippet).lower()   # ignore all whitespace: survives reformatting
        raw = f"{self.rule_id}\x00{file.replace(chr(92), '/')}\x00{norm}"
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]

    def to_dict(self) -> dict:
        """JSON form shared by the UI, the JSON report and saved scans. English counterparts of the Arabic
        engine text are added next to it (advice_en, snippet_en, extra.path[*].text_en,
        extra.taint_source_en, extra.apex_component_en) and, when vulnscan.autofix found one, the
        automatic fix as "fix" ({description, description_ar, diff, edits}); the Arabic itself
        is never altered, so fingerprints stay stable. asdict() deep-copies, so the finding is not mutated."""
        d = asdict(self)
        d["severity_ar"] = SEVERITY_AR[self.severity]
        d["fingerprint"] = self.fingerprint()
        d["advice_en"] = to_en(self.advice)
        d["snippet_en"] = to_en(self.snippet)
        path = d["extra"].get("path")
        if isinstance(path, list):
            d["extra"]["path"] = [{**st, "text_en": to_en(st.get("text", ""))} if isinstance(st, dict) else st
                                  for st in path]
        for key in ("taint_source", "apex_component"):
            val = d["extra"].get(key)
            if isinstance(val, str):
                d["extra"][f"{key}_en"] = to_en(val)
        fix = d["extra"].pop("fix", None)       # an automatic fix (vulnscan.autofix) is a top-level key, not extra
        if isinstance(fix, dict):
            d["fix"] = fix
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


def ensure_fingerprints(findings: "list[Finding]") -> None:
    """Assign fingerprints only if some finding has none yet. The CLI assigns them once, on the complete
    finding list, before any filtering; reports and baselines must reuse that assignment rather than
    renumbering a filtered subset (which would hand a new finding the index of a suppressed one)."""
    if any("fp_index" not in f.extra for f in findings):
        assign_fingerprints(findings)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Highest severity first, then by file and line for stable output."""
    return sorted(findings, key=lambda f: (SEVERITY_RANK[f.severity], f.file, f.line, f.rule_id))
