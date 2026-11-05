"""Dependency manifests -> known vulnerabilities via the OSV.dev API (online only)."""

from __future__ import annotations

import json
import pathlib
import re
import urllib.error
import urllib.request

from .model import Finding

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
MAX_DETAIL_LOOKUPS = 60


def _req(req: str) -> tuple[str, str] | None:
    m = re.match(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*==\s*([A-Za-z0-9_.\-+!]+)", req)
    if not m:
        return None
    return re.sub(r"\[.*\]", "", m.group(1)).lower(), m.group(2)


def collect_packages(root: pathlib.Path) -> list[tuple[str, str, str, str]]:
    """Return (ecosystem, name, version, manifest) for pinned dependencies we can find."""
    pkgs: list[tuple[str, str, str, str]] = []
    if not root.is_dir():
        return pkgs
    for path in root.rglob("*"):
        rel = path.relative_to(root).as_posix()
        if any(part in {"node_modules", ".git", ".venv", "venv", "build"} for part in path.parts):
            continue
        name = path.name
        try:
            if name.startswith("requirements") and name.endswith(".txt"):
                for line in path.read_text(errors="replace").splitlines():
                    r = _req(line.split("#")[0])
                    if r:
                        pkgs.append(("PyPI", r[0], r[1], rel))
            elif name == "package-lock.json":
                data = json.loads(path.read_text(errors="replace"))
                for key, meta in (data.get("packages") or {}).items():
                    if key and meta.get("version"):
                        pkgs.append(("npm", key.split("node_modules/")[-1], meta["version"], rel))
                for dep, meta in (data.get("dependencies") or {}).items():
                    if meta.get("version"):
                        pkgs.append(("npm", dep, meta["version"], rel))
            elif name == "package.json":
                data = json.loads(path.read_text(errors="replace"))
                for section in ("dependencies", "devDependencies"):
                    for dep, ver in (data.get(section) or {}).items():
                        if re.fullmatch(r"\d+\.\d+\.\d+", str(ver)):
                            pkgs.append(("npm", dep, ver, rel))
            elif name == "pubspec.lock":
                txt = path.read_text(errors="replace")
                for m in re.finditer(r"^  ([a-z0-9_]+):\n(?:    .*\n)*?    version: \"([^\"]+)\"", txt, re.M):
                    pkgs.append(("Pub", m.group(1), m.group(2), rel))
            elif name == "go.mod":
                for m in re.finditer(r"^\s*([\w./\-]+)\s+v([\w.\-+]+)", path.read_text(errors="replace"), re.M):
                    pkgs.append(("Go", m.group(1), m.group(2), rel))
            elif name == "Gemfile.lock":
                for m in re.finditer(r"^    ([\w\-]+) \(([\d.]+)\)", path.read_text(errors="replace"), re.M):
                    pkgs.append(("RubyGems", m.group(1), m.group(2), rel))
            elif name == "composer.lock":
                data = json.loads(path.read_text(errors="replace"))
                for p in data.get("packages") or []:
                    pkgs.append(("Packagist", p["name"], str(p.get("version", "")).lstrip("v"), rel))
        except (OSError, ValueError, KeyError):
            continue
    seen, out = set(), []
    for p in pkgs:
        if p[:3] not in seen:
            seen.add(p[:3])
            out.append(p)
    return out


def _post(url: str, payload: dict, timeout: float) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def _get(url: str, timeout: float) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.load(resp)


def _severity_from_vuln(v: dict) -> str:
    score = None
    for s in v.get("severity") or []:
        m = re.search(r"CVSS:(3\.\d|4\.0)/", s.get("score", ""))
        if m:
            score = _cvss_score(s["score"])
    if score is None:
        for aff in v.get("affected") or []:
            sev = (aff.get("ecosystem_specific") or {}).get("severity") or (aff.get("database_specific") or {}).get("severity")
            if isinstance(sev, str):
                sev = sev.lower()
                if sev in ("critical", "high", "medium", "moderate", "low"):
                    return "medium" if sev == "moderate" else sev
        sev = (v.get("database_specific") or {}).get("severity")
        if isinstance(sev, str) and sev.lower() in ("critical", "high", "medium", "moderate", "low"):
            return "medium" if sev.lower() == "moderate" else sev.lower()
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _cvss_score(vector: str) -> float | None:
    """Very small CVSS v3 base-score calculator (enough to bucket severities)."""
    if not vector.startswith("CVSS:3"):
        return None
    m = dict(part.split(":") for part in vector.split("/")[1:] if ":" in part)
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
    except KeyError:
        return None
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploit = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    import math
    raw = min(1.08 * (impact + exploit), 10) if changed else min(impact + exploit, 10)
    return math.ceil(raw * 10) / 10


def audit_dependencies(root: pathlib.Path, timeout: float = 20.0) -> tuple[list[Finding], str | None]:
    """Query OSV for every pinned package. Returns (findings, error message or None)."""
    pkgs = collect_packages(root)
    if not pkgs:
        return [], None
    queries = [{"package": {"name": n, "ecosystem": eco}, "version": v} for eco, n, v, _ in pkgs]
    findings: list[Finding] = []
    try:
        results = []
        for i in range(0, len(queries), 500):
            results.extend(_post(OSV_BATCH, {"queries": queries[i:i + 500]}, timeout).get("results", []))
    except (urllib.error.URLError, OSError, ValueError) as e:
        return [], f"OSV lookup failed: {e}"
    cache: dict[str, dict] = {}
    lookups = 0
    for (eco, name, ver, manifest), res in zip(pkgs, results):
        for v in res.get("vulns") or []:
            vid = v["id"]
            detail = cache.get(vid)
            if detail is None and lookups < MAX_DETAIL_LOOKUPS:
                lookups += 1
                try:
                    detail = _get(OSV_VULN.format(id=vid), timeout)
                except (urllib.error.URLError, OSError, ValueError):
                    detail = {}
                cache[vid] = detail
            detail = detail or {}
            aliases = ", ".join(detail.get("aliases") or [])
            fixed = _fixed_version(detail, name)
            findings.append(Finding(
                rule_id=f"OSV:{vid}", severity=_severity_from_vuln(detail),
                title=f"Vulnerable dependency {name} {ver} ({vid}{', ' + aliases if aliases else ''})",
                title_ar=f"اعتمادية مصابة بثغرة معروفة: {name} {ver}",
                file=manifest, line=0,
                snippet=(detail.get("summary") or detail.get("details") or "")[:200],
                advice=f"حدّث {name} إلى {fixed}." if fixed else f"حدّث {name} إلى إصدار مُصحَّح (راجع https://osv.dev/vulnerability/{vid}).",
                source="osv", extra={"ecosystem": eco, "url": f"https://osv.dev/vulnerability/{vid}"},
            ))
    return findings, None


def _fixed_version(detail: dict, name: str) -> str | None:
    for aff in detail.get("affected") or []:
        if (aff.get("package") or {}).get("name", "").lower() != name.lower():
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if "fixed" in ev:
                    return ev["fixed"]
    return None
