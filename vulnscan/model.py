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


# ------------------------------------------------------------------------------------------------- root-cause groups
_LABEL_PREFIX = re.compile(r"^\[[^\]]*\]\s*")
_SQL_STRING_LINE = re.compile(r"^'(.*)'\s*(?:,|\)\)?\s*;?)?\s*$")       # a code line inside an APEX export string


def _norm_code(text: str) -> str:
    text = _LABEL_PREFIX.sub("", str(text or "").strip())
    m = _SQL_STRING_LINE.match(text)
    if m:
        text = m.group(1).replace("''", "'")
    return re.sub(r"\s+", " ", text).strip().lower()


def _is_flow(f: "Finding") -> bool:
    return f.extra.get("analysis") == "dataflow" or bool(f.extra.get("taint_source"))


def group_key(f: "Finding", code: "str | None" = None) -> str:
    """What makes two findings the same root cause: the same rule on the same code. A data-flow finding's snippet
    names its source, so its code is the sink line (``code``); without it, its location. Web findings are grouped
    by the web scanner itself (one finding per issue with its pages) and keep their own identity."""
    if f.source == "web":
        return f"web\x00{f.fingerprint()}"
    if _is_flow(f):
        norm = _norm_code(code) if code else ""
        return f"{f.rule_id}\x00code:{norm}" if norm else f"{f.rule_id}\x00at:{f.file}:{f.line}"
    norm = _norm_code(f.snippet)
    return f"{f.rule_id}\x00snippet:{norm}" if norm and f.line else f"{f.rule_id}\x00at:{f.file}:{f.line}"


def assign_groups(findings: "list[Finding]", code_of=None) -> None:
    """Group findings by root cause (rule + the code pattern): one pattern repeated in several places — the same
    plug-in code copied into several plug-ins, one helper reached from many callers — is one thing to fix.
    Members of a group of two or more get ``extra["group_id"]`` ("G-" + 8 hex, stable) and ``extra["group_size"]``;
    a finding alone keeps no group keys. Fingerprints are not affected. ``code_of(finding)`` returns the source line
    of a data-flow finding's sink, or None."""
    keys: dict[int, str] = {}
    sizes: dict[str, int] = {}
    for f in findings:
        f.extra.pop("group_id", None)
        f.extra.pop("group_size", None)
        code = None
        if code_of is not None and _is_flow(f) and f.source != "web":
            try:
                code = code_of(f)
            except (OSError, ValueError):
                code = None
        k = group_key(f, code)
        keys[id(f)] = k
        sizes[k] = sizes.get(k, 0) + 1
    for f in findings:
        k = keys[id(f)]
        if sizes[k] > 1:
            f.extra["group_id"] = "G-" + hashlib.sha256(k.encode("utf-8", "replace")).hexdigest()[:8]
            f.extra["group_size"] = sizes[k]


def finding_groups(findings: "list[Finding]") -> list[dict]:
    """The root-cause groups among ``findings`` (from ``extra["group_id"]``, counted on the findings present):
    [{"id", "rule_id", "severity", "title", "title_ar", "cwe", "count", "locations": [{"file", "line",
    "fingerprint", "component"}]}], most severe and largest first; groups of one are left out."""
    by: dict[str, list] = {}
    for f in findings:
        gid = f.extra.get("group_id")
        if isinstance(gid, str) and gid:
            by.setdefault(gid, []).append(f)
    out = []
    for gid, members in by.items():
        if len(members) < 2:
            continue
        members = sort_findings(members)
        head = members[0]
        out.append({"id": gid, "rule_id": head.rule_id, "severity": head.severity, "title": head.title,
                    "title_ar": head.title_ar, "cwe": head.cwe, "count": len(members),
                    "locations": [{"file": m.file, "line": m.line, "fingerprint": m.fingerprint(),
                                   "component": m.extra.get("apex_component", "")} for m in members]})
    out.sort(key=lambda g: (SEVERITY_RANK.get(g["severity"], 9), -g["count"], g["rule_id"], g["id"]))
    return out
