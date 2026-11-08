"""Console / Markdown / JSON / HTML reports, ordered from highest to lowest severity."""

from __future__ import annotations

import html
import json
import pathlib
import urllib.parse
from datetime import datetime, timezone

from . import __version__
from .model import (SARIF_LEVEL, SECURITY_SEVERITY, SEVERITIES, SEVERITY_AR, Finding,
                    ensure_fingerprints, sort_findings)

REPO_URL = "https://github.com/abdulrahmanahmedelabed-prog/vulnscan"

COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[1;33m",
          "low": "\033[1;36m", "info": "\033[1;37m"}
RESET = "\033[0m"
BADGE = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}


def summary_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1
    return counts


def _meta(target: str, files: int, notes: list[str]) -> dict:
    return {"target": target, "files_scanned": files, "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "notes": notes}


def render_console(findings: list[Finding], target: str, files: int, notes: list[str], color: bool = True) -> str:
    findings = sort_findings(findings)
    counts = summary_counts(findings)
    c = (lambda s, t: f"{COLORS[s]}{t}{RESET}") if color else (lambda s, t: t)
    lines = [f"vulnscan — {target}  ({files} ملفًا مفحوصًا، {len(findings)} نتيجة)", ""]
    lines.append("الملخص (من الأعلى خطورة إلى الأقل):")
    for s in SEVERITIES:
        lines.append(f"  {c(s, SEVERITY_AR[s].rjust(9))}  {s.upper():<8} {counts[s]}")
    for n in notes:
        lines.append(f"  ℹ {n}")
    lines.append("")
    if not findings:
        lines.append("✔ لم تُكتشف أي ثغرة بالقواعد المتاحة.")
        return "\n".join(lines)
    current = None
    for f in findings:
        if f.severity != current:
            current = f.severity
            lines.append(c(current, f"━━ {SEVERITY_AR[current]} / {current.upper()} ({counts[current]}) ━━"))
        loc = f"{f.file}:{f.line}" if f.line else f.file
        cwe = f" [{f.cwe}]" if f.cwe else ""
        lines.append(f"  {BADGE[f.severity]} {f.rule_id}{cwe} {f.title_ar} — {f.title}")
        lines.append(f"     📄 {loc}")
        if f.snippet:
            lines.append(f"     ▸ {f.snippet[:140]}")
        lines.append(f"     💡 {f.advice}")
        for i, st in enumerate(f.extra.get("path") or [], 1):
            lines.append(f"       {i}. {st['file']}:{st['line']}  {st['text']}")
    return "\n".join(lines)


def render_markdown(findings: list[Finding], target: str, files: int, notes: list[str]) -> str:
    findings = sort_findings(findings)
    counts = summary_counts(findings)
    meta = _meta(target, files, notes)
    md = [f"# تقرير الفحص الأمني — `{target}`", "",
          f"- التاريخ: {meta['generated_at']}", f"- الملفات المفحوصة: {files}", f"- إجمالي النتائج: {len(findings)}", ""]
    for n in notes:
        md.append(f"- ملاحظة: {n}")
    md += ["", "## الملخص التنفيذي", "", "| الخطورة | Severity | العدد |", "|---|---|---|"]
    for s in SEVERITIES:
        md.append(f"| {BADGE[s]} {SEVERITY_AR[s]} | {s} | {counts[s]} |")
    md.append("")
    if not findings:
        md.append("✔ لم تُكتشف أي ثغرة بالقواعد المتاحة.")
        return "\n".join(md) + "\n"
    top = [f for f in findings if f.severity in ("critical", "high")][:10]
    if top:
        md += ["### أهم ما يجب إصلاحه أولًا", ""]
        for i, f in enumerate(top, 1):
            loc = f"{f.file}:{f.line}" if f.line else f.file
            md.append(f"{i}. **{f.title_ar}** (`{f.rule_id}`) — `{loc}`")
        md.append("")
    md += ["## النتائج مرتبة حسب الخطورة", ""]
    current = None
    for f in findings:
        if f.severity != current:
            current = f.severity
            md += [f"### {BADGE[current]} {SEVERITY_AR[current]} / {current.upper()} ({counts[current]})", ""]
        loc = f"{f.file}:{f.line}" if f.line else f.file
        cwe = f" · {f.cwe}" if f.cwe else ""
        md.append(f"#### {f.title_ar} — {f.title}")
        md.append(f"- المعرّف: `{f.rule_id}`{cwe} · المصدر: {f.source}")
        md.append(f"- الموضع: `{loc}`")
        if f.snippet:
            md.append(f"- المقتطف: `{f.snippet.replace('`', 'ˋ')[:160]}`")
        md.append(f"- الإصلاح: {f.advice}")
        if f.extra.get("path"):
            md.append("- مسار التدفق:")
            for i, st in enumerate(f.extra["path"], 1):
                md.append(f"  {i}. `{st['file']}:{st['line']}` — {st['text']}")
        if f.extra.get("url"):
            md.append(f"- المرجع: {f.extra['url']}")
        md.append("")
    return "\n".join(md) + "\n"


def render_json(findings: list[Finding], target: str, files: int, notes: list[str]) -> str:
    findings = sort_findings(findings)
    ensure_fingerprints(findings)
    return json.dumps({**_meta(target, files, notes), "summary": summary_counts(findings),
                       "findings": [f.to_dict() for f in findings]}, ensure_ascii=False, indent=2)


def render_html(findings: list[Finding], target: str, files: int, notes: list[str]) -> str:
    findings = sort_findings(findings)
    counts = summary_counts(findings)
    e = html.escape
    rows = []
    for f in findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        rows.append(f"<tr class='{f.severity}'><td><span class='b {f.severity}'>{e(SEVERITY_AR[f.severity])}</span></td>"
                    f"<td><code>{e(f.rule_id)}</code><br><small>{e(f.cwe)}</small></td>"
                    f"<td><b>{e(f.title_ar)}</b><br><small>{e(f.title)}</small></td>"
                    f"<td><code>{e(loc)}</code><br><small>{e(f.snippet[:140])}</small>"
                    + ("<ol class='flow'>" + "".join(f"<li><code>{e(st['file'])}:{st['line']}</code> {e(st['text'])}</li>" for st in f.extra.get('path') or []) + "</ol>" if f.extra.get("path") else "")
                    + f"</td><td>{e(f.advice)}</td></tr>")
    summary = "".join(f"<div class='tile {s}'><div class='n'>{counts[s]}</div><div>{e(SEVERITY_AR[s])}<br><small>{s}</small></div></div>"
                      for s in SEVERITIES)
    notes_html = "".join(f"<li>{e(n)}</li>" for n in notes)
    return f"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<title>vulnscan — {e(target)}</title>
<style>
body{{font-family:system-ui,Segoe UI,Tahoma,sans-serif;margin:2rem;background:#fafafa;color:#222}}
.tiles{{display:flex;gap:.75rem;flex-wrap:wrap;margin:1rem 0}}
.tile{{padding:.75rem 1.25rem;border-radius:.5rem;color:#fff;min-width:7rem;text-align:center}}
.tile .n{{font-size:2rem;font-weight:700}}
.critical{{background:#7f1d1d}}.high{{background:#c2410c}}.medium{{background:#a16207}}.low{{background:#0e7490}}.info{{background:#52525b}}
table{{border-collapse:collapse;width:100%;background:#fff}}
th,td{{border:1px solid #ddd;padding:.5rem;vertical-align:top;text-align:right}}
tr.critical td:first-child,tr.high td:first-child{{font-weight:700}}
.b{{padding:.15rem .5rem;border-radius:.25rem;color:#fff;white-space:nowrap}}
code{{direction:ltr;unicode-bidi:embed;font-size:.85em}}\n.flow{{margin:.4rem 0 0;padding-inline-start:1.2rem;font-size:.8em;color:#555}}
</style></head><body>
<h1>تقرير الفحص الأمني — <code>{e(target)}</code></h1>
<p>الملفات المفحوصة: {files} · النتائج: {len(findings)} · {e(_meta(target, files, notes)['generated_at'])}</p>
<ul>{notes_html}</ul>
<div class="tiles">{summary}</div>
<h2>النتائج من الأعلى خطورة إلى الأقل</h2>
<table><thead><tr><th>الخطورة</th><th>القاعدة</th><th>الثغرة</th><th>الموضع</th><th>الإصلاح</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=5>✔ لا نتائج</td></tr>'}</tbody></table>
</body></html>"""


def _uri(path: str) -> str:
    """A relative path as an RFC 3986 URI reference: forward slashes, everything else percent-encoded
    (spaces, Arabic, '#', '%', ':' …) so viewers resolve it to the right file."""
    return urllib.parse.quote(path.replace("\\", "/"), safe="/")


def _root_uri(target: str) -> str:
    try:
        p = pathlib.Path(target).resolve()
        return (p if p.is_dir() else p.parent).as_uri() + "/"
    except (OSError, ValueError):
        return "file:///"


def render_sarif(findings: list[Finding], target: str, files: int, notes: list[str]) -> str:
    """SARIF 2.1.0 — the OASIS standard consumed by GitHub Code Scanning, VS Code's SARIF viewer,
    Azure DevOps and others. Rules carry CWE tags and a GitHub security-severity; each result carries
    a stable partialFingerprint so the platform can track an issue across commits."""
    findings = sort_findings(findings)
    ensure_fingerprints(findings)
    web_base = urllib.parse.urlsplit(target) if target.startswith(("http://", "https://")) else None
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        if f.rule_id not in rules:
            props = {"security-severity": SECURITY_SEVERITY.get(f.severity, "0")}
            tags = ["security", f.source]
            if f.cwe:
                tags.append(f.cwe.lower().replace("cwe-", "external/cwe/cwe-"))
            props["tags"] = tags
            rule = {"id": f.rule_id, "name": f.rule_id,
                    "shortDescription": {"text": f.title or f.rule_id},
                    "fullDescription": {"text": f.title_ar or f.title or f.rule_id},
                    "helpUri": f.extra.get("url") or f"{REPO_URL}#{f.rule_id}",
                    "help": {"text": f.advice or ""},
                    "defaultConfiguration": {"level": SARIF_LEVEL.get(f.severity, "warning")},
                    "properties": props}
            if f.cwe:
                rule["relationships"] = [{"target": {"id": f.cwe, "toolComponent": {"name": "CWE"}}}]
            rules[f.rule_id] = rule
        if f.source == "web" and web_base is not None:
            # a web finding has no source file: point at the page URL itself, with no line region
            page = f.file if f.file.startswith("/") else "/"
            host = web_base.netloc if f.file.startswith("/") else (f.file or web_base.netloc)
            phys = {"artifactLocation": {"uri": f"{web_base.scheme}://{host}{_uri(page)}"}}
        else:
            phys = {"artifactLocation": {"uri": _uri(f.file), "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(1, f.line or 1)}}
        result = {
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.title}: {f.snippet}".strip(": ") or f.rule_id},
            "locations": [{"physicalLocation": phys}],
            "partialFingerprints": {"vulnscan/v1": f.fingerprint()},
            "properties": {"severity": f.severity, "title_ar": f.title_ar, "advice": f.advice},
        }
        path = f.extra.get("path")
        if path:   # a data-flow finding: emit the source→sink trail as a SARIF codeFlow
            locs = [{"location": {"physicalLocation": {
                "artifactLocation": {"uri": _uri(str(st.get("file", f.file))), "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": max(1, int(st.get("line", 1) or 1))}},
                "message": {"text": str(st.get("text", ""))}}} for st in path]
            result["codeFlows"] = [{"threadFlows": [{"locations": locs}]}]
        results.append(result)
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "vulnscan",
                "fullName": "vulnscan (كاشِف) security scanner",
                "version": __version__,
                "informationUri": REPO_URL,
                "rules": list(rules.values()),
            }},
            "results": results,
            **({} if web_base else {"originalUriBaseIds": {"%SRCROOT%": {"uri": _root_uri(target)}}}),
            "properties": {"target": target, "filesScanned": files, "notes": notes},
        }],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)
