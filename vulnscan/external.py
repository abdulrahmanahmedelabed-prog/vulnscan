"""Optional integration with third-party scanners when they are installed.

Nothing here is required: vulnscan works with the standard library alone.
If ``bandit``, ``semgrep``, ``gitleaks`` or ``npm`` are on PATH their results
are merged into the same report.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess

from .model import Finding

_BANDIT_SEV = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
_NPM_SEV = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low", "info": "info"}


def _run(cmd: list[str], cwd: pathlib.Path, timeout: int = 600) -> str | None:
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None


def available() -> list[str]:
    return [t for t in ("bandit", "semgrep", "gitleaks", "npm") if shutil.which(t)]


def run_external(root: pathlib.Path, tools: list[str] | None = None) -> tuple[list[Finding], list[str]]:
    """Returns (findings, names of tools that ran)."""
    if not root.is_dir():
        return [], []
    tools = tools if tools is not None else available()
    out: list[Finding] = []
    ran: list[str] = []
    if "bandit" in tools and shutil.which("bandit"):
        txt = _run(["bandit", "-q", "-r", ".", "-f", "json"], root)
        if txt:
            try:
                for r in json.loads(txt).get("results", []):
                    out.append(Finding(f"bandit:{r['test_id']}", _BANDIT_SEV.get(r["issue_severity"], "low"),
                                       r["issue_text"], r["issue_text"], r["filename"].lstrip("./"), r["line_number"],
                                       (r.get("code") or "").strip().splitlines()[0][:200] if r.get("code") else "",
                                       r.get("more_info", ""), r.get("issue_cwe", {}).get("id", "") and f"CWE-{r['issue_cwe']['id']}",
                                       source="bandit"))
                ran.append("bandit")
            except (ValueError, KeyError):
                pass
    if "semgrep" in tools and shutil.which("semgrep"):
        txt = _run(["semgrep", "--config", "auto", "--json", "--quiet", "."], root)
        if txt:
            try:
                for r in json.loads(txt).get("results", []):
                    ex = r.get("extra", {})
                    out.append(Finding(f"semgrep:{r['check_id']}", _SEMGREP_SEV.get(ex.get("severity", "INFO"), "low"),
                                       ex.get("message", r["check_id"])[:120], ex.get("message", "")[:120],
                                       r["path"], r["start"]["line"], (ex.get("lines") or "").strip()[:200],
                                       ex.get("metadata", {}).get("references", [""])[0] if ex.get("metadata", {}).get("references") else "",
                                       ",".join(ex.get("metadata", {}).get("cwe", [])) if isinstance(ex.get("metadata", {}).get("cwe"), list) else str(ex.get("metadata", {}).get("cwe", "")),
                                       source="semgrep"))
                ran.append("semgrep")
            except (ValueError, KeyError):
                pass
    if "gitleaks" in tools and shutil.which("gitleaks"):
        rep = root / ".vulnscan-gitleaks.json"
        _run(["gitleaks", "detect", "--no-git", "--source", ".", "--report-format", "json", "--report-path", str(rep), "--exit-code", "0"], root)
        if rep.exists():
            try:
                for r in json.loads(rep.read_text() or "[]"):
                    out.append(Finding(f"gitleaks:{r.get('RuleID')}", "high", r.get("Description", "Secret detected"),
                                       "سر مكتشف بواسطة gitleaks", r.get("File", ""), r.get("StartLine", 0),
                                       (r.get("Match") or "")[:80] + "…", "أبطل السر وأزله من التاريخ.", "CWE-798", source="gitleaks"))
                ran.append("gitleaks")
            except ValueError:
                pass
            finally:
                rep.unlink(missing_ok=True)
    if "npm" in tools and shutil.which("npm") and (root / "package-lock.json").exists():
        txt = _run(["npm", "audit", "--json"], root)
        if txt:
            try:
                for name, v in (json.loads(txt).get("vulnerabilities") or {}).items():
                    via = [x for x in v.get("via", []) if isinstance(x, dict)]
                    title = via[0].get("title", "") if via else ""
                    out.append(Finding(f"npm:{name}", _NPM_SEV.get(v.get("severity"), "medium"),
                                       f"Vulnerable npm package {name} ({v.get('range')}) {title}".strip(),
                                       f"حزمة npm مصابة: {name}", "package-lock.json", 0, via[0].get("url", "") if via else "",
                                       f"حدّث {name} (npm audit fix).", "", source="npm"))
                ran.append("npm")
            except ValueError:
                pass
    return out, ran
