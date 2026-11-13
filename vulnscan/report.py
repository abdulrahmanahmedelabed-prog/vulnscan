"""Console / Markdown / JSON / HTML reports, ordered from highest to lowest severity."""

from __future__ import annotations

import html
import json
import pathlib
import urllib.parse
from datetime import datetime, timezone

from . import __version__
from .i18n import to_en
from .i18n.plural import FILES_SCANNED, FINDINGS, ar_count
from .model import (SARIF_LEVEL, SECURITY_SEVERITY, SEVERITIES, SEVERITY_AR, Finding,
                    ensure_fingerprints, sort_findings)

REPO_URL = "https://github.com/abdulrahmanahmedelabed-prog/vulnscan"

COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[1;33m",
          "low": "\033[1;36m", "info": "\033[1;37m"}
RESET = "\033[0m"
BADGE = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}


LANGS = ("ar", "en", "both")

# Report labels: (Arabic, English). "both" keeps the historical Arabic labels (with English titles alongside).
_LABELS = {
    "scanned": ("{files_ar}، {n_ar}", "{files_en}, {n_en}"),                     # see _scanned()
    "summary": ("الملخص (من الأعلى خطورة إلى الأقل):", "Summary (highest severity first):"),
    "none": ("✔ لم تُكتشف أي ثغرة بالقواعد المتاحة.", "✔ No vulnerabilities found by the available rules."),
    "md_title": ("تقرير الفحص الأمني", "Security scan report"),
    "date": ("التاريخ", "Date"),
    "files": ("الملفات المفحوصة", "Files scanned"),
    "total": ("إجمالي النتائج", "Total findings"),
    "note": ("ملاحظة", "Note"),
    "exec": ("الملخص التنفيذي", "Executive summary"),
    "sev_col": ("الخطورة", "Severity"),
    "count_col": ("العدد", "Count"),
    "top": ("أهم ما يجب إصلاحه أولًا", "Fix these first"),
    "by_sev": ("النتائج مرتبة حسب الخطورة", "Findings by severity"),
    "rule": ("المعرّف", "Rule"),
    "source": ("المصدر", "Source"),
    "location": ("الموضع", "Location"),
    "snippet": ("المقتطف", "Snippet"),
    "fix": ("الإصلاح", "Remediation"),
    "flow": ("مسار التدفق", "Data flow"),
    "ref": ("المرجع", "Reference"),
    "findings": ("النتائج", "Findings"),
    "html_by_sev": ("النتائج من الأعلى خطورة إلى الأقل", "Findings, highest severity first"),
    "col_rule": ("القاعدة", "Rule"),
    "col_vuln": ("الثغرة", "Vulnerability"),
    "no_results": ("✔ لا نتائج", "✔ No findings"),
    "autofix": ("إصلاح مقترح", "Suggested fix"),
}


class _Lang:
    """Picks the Arabic or English side of report text for one of LANGS."""

    def __init__(self, lang: str):
        self.lang = lang if lang in LANGS else "both"
        self.en = self.lang == "en"

    def __call__(self, key: str, **kw) -> str:
        text = _LABELS[key][1 if self.en else 0]
        return text.format(**kw) if kw else text

    def sev(self, s: str) -> str:
        """Severity name for a heading/badge: Arabic, or English in "en"."""
        return s.capitalize() if self.en else SEVERITY_AR[s]

    def sev_pair(self, s: str) -> str:
        return s.upper() if self.en else f"{SEVERITY_AR[s]} / {s.upper()}"

    def title(self, f: Finding) -> str:
        if self.en:
            return f.title or to_en(f.title_ar)
        if self.lang == "ar":
            return f.title_ar or f.title
        return f"{f.title_ar} — {f.title}"

    def text(self, t: str) -> str:
        """Engine text (advice, notes, trail steps, snippets that are notes): English in "en", else as emitted."""
        return to_en(t) if self.en else t


def _fix_html(f: Finding, L: "_Lang") -> str:
    fix = _fix(f)
    if not fix:
        return ""
    e = html.escape
    rows = []
    for ln in str(fix.get("diff") or "").splitlines():
        cls = "add" if ln.startswith("+") and not ln.startswith("+++") else \
            "del" if ln.startswith("-") and not ln.startswith("---") else "ctx"
        rows.append(f"<span class='{cls}'>{e(ln)}</span>")
    diff = f"<pre class='diff'>{chr(10).join(rows)}</pre>" if rows else ""
    return (f"<details class='fix'><summary>{e(L('autofix'))}</summary><div>{e(_fix_text(fix, L))}</div>{diff}</details>")


def summary_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1
    return counts


def _meta(target: str, files: int, notes: list[str]) -> dict:
    return {"target": target, "files_scanned": files, "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "notes": notes}


def _steps(f: Finding) -> list[dict]:
    return [st for st in (f.extra.get("path") or []) if isinstance(st, dict)]


def _fix(f: Finding) -> dict | None:
    """The automatic fix attached by vulnscan.autofix, if any ({description, description_ar, diff, edits})."""
    fix = f.extra.get("fix")
    return fix if isinstance(fix, dict) and (fix.get("description") or fix.get("description_ar")) else None


def _fix_text(fix: dict, L: "_Lang") -> str:
    return str((fix.get("description") or fix.get("description_ar")) if L.en else
               (fix.get("description_ar") or fix.get("description")))


def _scanned(L: "_Lang", files: int, n: int) -> str:
    """"12 files scanned, 1 finding", with nouns that agree with their numbers ("ملفان مفحوصان، 3 نتائج")."""
    return L("scanned", files_ar=ar_count(files, FILES_SCANNED), n_ar=ar_count(n, FINDINGS),
             files_en=f"{files} file{'' if files == 1 else 's'} scanned", n_en=f"{n} finding{'' if n == 1 else 's'}")


def render_console(findings: list[Finding], target: str, files: int, notes: list[str], color: bool = True,
                   lang: str = "both") -> str:
    L = _Lang(lang)
    findings = sort_findings(findings)
    counts = summary_counts(findings)
    c = (lambda s, t: f"{COLORS[s]}{t}{RESET}") if color else (lambda s, t: t)
    lines = [f"Kashif — {target}  ({_scanned(L, files, len(findings))})", ""]
    lines.append(L("summary"))
    for s in SEVERITIES:
        if L.en:
            lines.append(f"  {c(s, s.upper().ljust(9))} {counts[s]}")
        else:
            lines.append(f"  {c(s, SEVERITY_AR[s].rjust(9))}  {s.upper():<8} {counts[s]}")
    for n in notes:
        lines.append(f"  ℹ {L.text(n)}")
    lines.append("")
    if not findings:
        lines.append(L("none"))
        return "\n".join(lines)
    current = None
    for f in findings:
        if f.severity != current:
            current = f.severity
            lines.append(c(current, f"━━ {L.sev_pair(current)} ({counts[current]}) ━━"))
        loc = f"{f.file}:{f.line}" if f.line else f.file
        cwe = f" [{f.cwe}]" if f.cwe else ""
        lines.append(f"  {BADGE[f.severity]} {f.rule_id}{cwe} {L.title(f)}")
        lines.append(f"     📄 {loc}")
        if f.snippet:
            lines.append(f"     ▸ {L.text(f.snippet)[:140]}")
        lines.append(f"     💡 {L.text(f.advice)}")
        if _fix(f):
            lines.append(f"     🔧 {L('autofix')}: {_fix_text(_fix(f), L)}")
        for i, st in enumerate(_steps(f), 1):
            lines.append(f"       {i}. {st.get('file', '')}:{st.get('line', '')}  {L.text(st.get('text', ''))}")
    return "\n".join(lines)


def render_markdown(findings: list[Finding], target: str, files: int, notes: list[str], lang: str = "both") -> str:
    L = _Lang(lang)
    findings = sort_findings(findings)
    counts = summary_counts(findings)
    meta = _meta(target, files, notes)
    md = [f"# {L('md_title')} — `{target}`", "",
          f"- {L('date')}: {meta['generated_at']}", f"- {L('files')}: {files}", f"- {L('total')}: {len(findings)}", ""]
    for n in notes:
        md.append(f"- {L('note')}: {L.text(n)}")
    if L.en:
        md += ["", f"## {L('exec')}", "", "| Severity | Count |", "|---|---|"]
        for s in SEVERITIES:
            md.append(f"| {BADGE[s]} {s} | {counts[s]} |")
    else:
        md += ["", f"## {L('exec')}", "", "| الخطورة | Severity | العدد |", "|---|---|---|"]
        for s in SEVERITIES:
            md.append(f"| {BADGE[s]} {SEVERITY_AR[s]} | {s} | {counts[s]} |")
    md.append("")
    if not findings:
        md.append(L("none"))
        return "\n".join(md) + "\n"
    top = [f for f in findings if f.severity in ("critical", "high")][:10]
    if top:
        md += [f"### {L('top')}", ""]
        for i, f in enumerate(top, 1):
            loc = f"{f.file}:{f.line}" if f.line else f.file
            name = f.title if L.en else f.title_ar
            md.append(f"{i}. **{name}** (`{f.rule_id}`) — `{loc}`")
        md.append("")
    md += [f"## {L('by_sev')}", ""]
    current = None
    for f in findings:
        if f.severity != current:
            current = f.severity
            md += [f"### {BADGE[current]} {L.sev_pair(current)} ({counts[current]})", ""]
        loc = f"{f.file}:{f.line}" if f.line else f.file
        cwe = f" · {f.cwe}" if f.cwe else ""
        md.append(f"#### {L.title(f)}")
        md.append(f"- {L('rule')}: `{f.rule_id}`{cwe} · {L('source')}: {f.source}")
        md.append(f"- {L('location')}: `{loc}`")
        if f.snippet:
            md.append(f"- {L('snippet')}: `{L.text(f.snippet).replace('`', 'ˋ')[:160]}`")
        md.append(f"- {L('fix')}: {L.text(f.advice)}")
        fix = _fix(f)
        if fix:
            md.append(f"- {L('autofix')}: {_fix_text(fix, L)}")
            if fix.get("diff"):
                fence = "````" if "```" in fix["diff"] else "```"
                md += ["", f"  {fence}diff"] + [f"  {ln}" for ln in str(fix["diff"]).splitlines()] + [f"  {fence}", ""]
        if _steps(f):
            md.append(f"- {L('flow')}:")
            for i, st in enumerate(_steps(f), 1):
                md.append(f"  {i}. `{st.get('file', '')}:{st.get('line', '')}` — {L.text(st.get('text', ''))}")
        if f.extra.get("url"):
            md.append(f"- {L('ref')}: {f.extra['url']}")
        md.append("")
    return "\n".join(md) + "\n"


def render_json(findings: list[Finding], target: str, files: int, notes: list[str],
                scanners: list[str] | None = None) -> str:
    """The JSON report. ``scanners`` (optional) names the analyses that ran (sast, secrets, deps, external); the
    policy gate (``kashif policy check``) reads it to verify ``required_scanners``."""
    findings = sort_findings(findings)
    ensure_fingerprints(findings)
    meta = {**_meta(target, files, notes), "notes_en": [to_en(n) for n in notes]}
    if scanners is not None:
        meta["scanners"] = sorted(set(scanners))
    return json.dumps({**meta, "summary": summary_counts(findings),
                       "findings": [f.to_dict() for f in findings]}, ensure_ascii=False, indent=2)


def render_html(findings: list[Finding], target: str, files: int, notes: list[str], lang: str = "both") -> str:
    L = _Lang(lang)
    findings = sort_findings(findings)
    counts = summary_counts(findings)
    e = html.escape
    rows = []
    for f in findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        if L.en:
            title_html = f"<b>{e(L.title(f))}</b>"
        elif L.lang == "ar":
            title_html = f"<b>{e(f.title_ar or f.title)}</b>"
        else:
            title_html = f"<b>{e(f.title_ar)}</b><br><small>{e(f.title)}</small>"
        steps = _steps(f)
        # engine text (snippets, trail steps) mixes code and Arabic: each piece takes the direction of its first
        # letter, isolated from the cell around it
        rows.append(f"<tr class='{f.severity}'><td><span class='b {f.severity}'>{e(L.sev(f.severity))}</span></td>"
                    f"<td><code>{e(f.rule_id)}</code><br><small>{e(f.cwe)}</small></td>"
                    f"<td>{title_html}</td>"
                    f"<td><code>{e(loc)}</code><br><small dir='auto'>{e(L.text(f.snippet)[:140])}</small>"
                    + ("<ol class='flow'>" + "".join(f"<li><code>{e(str(st.get('file', '')))}:{st.get('line', '')}</code> "
                                                     f"<bdi>{e(L.text(st.get('text', '')))}</bdi></li>" for st in steps) + "</ol>"
                       if steps else "")
                    + f"</td><td>{e(L.text(f.advice))}{_fix_html(f, L)}</td></tr>")
    summary = "".join(f"<div class='tile {s}'><div class='n'>{counts[s]}</div><div>{e(L.sev(s))}"
                      + ("" if L.en else f"<br><small>{s}</small>") + "</div></div>"
                      for s in SEVERITIES)
    notes_html = "".join(f"<li>{e(L.text(n))}</li>" for n in notes)
    empty = f"<tr><td colspan=5>{e(L('no_results'))}</td></tr>"
    html_lang, html_dir, align = ("en", "ltr", "left") if L.en else ("ar", "rtl", "right")
    return f"""<!doctype html><html lang="{html_lang}" dir="{html_dir}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kashif — {e(target)}</title>
<style>
body{{font-family:system-ui,Segoe UI,Tahoma,sans-serif;margin:2rem;background:#fafafa;color:#222}}
.tiles{{display:flex;gap:.75rem;flex-wrap:wrap;margin:1rem 0}}
.tile{{padding:.75rem 1.25rem;border-radius:.5rem;color:#fff;min-width:7rem;text-align:center}}
.tile .n{{font-size:2rem;font-weight:700}}
.tile.critical,.b.critical{{background:#7f1d1d}}.tile.high,.b.high{{background:#c2410c}}.tile.medium,.b.medium{{background:#a16207}}
.tile.low,.b.low{{background:#0e7490}}.tile.info,.b.info{{background:#52525b}}
table{{border-collapse:collapse;width:100%;background:#fff}}
th,td{{border:1px solid #ddd;padding:.5rem;vertical-align:top;text-align:{align}}}
tr.critical td:first-child,tr.high td:first-child{{font-weight:700}}
.b{{padding:.15rem .5rem;border-radius:.25rem;color:#fff;white-space:nowrap}}
code{{direction:ltr;unicode-bidi:isolate;font-size:.85em;overflow-wrap:anywhere}}
h1{{overflow-wrap:anywhere}}
.tw{{max-width:100%;overflow-x:auto}}
td{{min-width:5rem}}td:nth-child(3),td:nth-child(4),td:nth-child(5){{min-width:12rem}}
@media (max-width:640px){{body{{margin:1rem}}h1{{font-size:1.4rem}}.tile{{min-width:5rem;padding:.5rem .8rem}}}}
.fix{{margin-top:.5rem}}.fix summary{{cursor:pointer;font-weight:600;color:#166534}}
.diff{{direction:ltr;text-align:left;background:#f6f8fa;padding:.5rem;overflow:auto;font-size:.8em;margin:.3rem 0 0}}
.diff span{{display:block}}.diff .add{{background:#dcfce7}}.diff .del{{background:#fee2e2}}\n.flow{{margin:.4rem 0 0;padding-inline-start:1.2rem;font-size:.8em;color:#555}}
</style></head><body>
<h1>{e(L('md_title'))} — <code dir="ltr">{e(target)}</code></h1>
<p>{e(L('files'))}: {files} · {e(L('findings'))}: {len(findings)} · <bdi dir="ltr">{e(_meta(target, files, notes)['generated_at'])}</bdi></p>
<ul>{notes_html}</ul>
<div class="tiles">{summary}</div>
<h2>{e(L('html_by_sev'))}</h2>
<div class="tw"><table><thead><tr><th>{e(L('sev_col'))}</th><th>{e(L('col_rule'))}</th><th>{e(L('col_vuln'))}</th><th>{e(L('location'))}</th><th>{e(L('fix'))}</th></tr></thead>
<tbody>{''.join(rows) or empty}</tbody></table></div>
</body></html>"""


def _uri(path: str) -> str:
    """A relative path as an RFC 3986 URI reference: forward slashes, everything else percent-encoded
    (spaces, Arabic, '#', '%', ':' …) so viewers resolve it to the right file."""
    return urllib.parse.quote(path.replace("\\", "/"), safe="/")


def _norm_url(url: str) -> str:
    """A fetched URL as a valid RFC 3986 URI: percent-encode what needs it, keep existing %XX escapes."""
    parts = urllib.parse.urlsplit(url)
    safe = "/%:@!$&'()*+,;=-._~"
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, urllib.parse.quote(parts.path, safe=safe),
                                    urllib.parse.quote(parts.query, safe=safe + "?"),
                                    urllib.parse.quote(parts.fragment, safe=safe + "?")))


def _file_location(path: str, line: int, base_id: str, target: str) -> dict:
    """physicalLocation for a source finding. APEX exports expose embedded files as virtual paths
    (`f100.sql!Static/app.js`) whose lines count from the decoded file, not the export: point at the real
    export file, without a region, and name the embedded file in the location's properties."""
    if "!" in path and not (pathlib.Path(target) / path).exists():
        real, virtual = path.split("!", 1)
        return {"artifactLocation": {"uri": _uri(real), "uriBaseId": base_id},
                "properties": {"embeddedFile": virtual, "embeddedLine": max(1, line or 1)}}
    return {"artifactLocation": {"uri": _uri(path), "uriBaseId": base_id}, "region": {"startLine": max(1, line or 1)}}


def _root_uri(target: str) -> str:
    try:
        p = pathlib.Path(target).resolve()
        return (p if p.is_dir() else p.parent).as_uri() + "/"
    except (OSError, ValueError):
        return "file:///"


def _base_ids(target: str, findings: list[Finding]) -> dict:
    """%SRCROOT% is the scanned directory. Findings inside an archive are relative to %ARCHIVEROOT%, which is
    described (not resolved to a directory: the files only exist inside the archive)."""
    ids = {"%SRCROOT%": {"uri": _root_uri(target)}}
    if any(f.extra.get("archive_member") for f in findings):
        ids["%ARCHIVEROOT%"] = {"description": {"text": f"Root of the scanned archive {pathlib.Path(target).name}"}}
    return ids


def _cwe_link(cwe: str) -> str:
    num = cwe.upper().removeprefix("CWE-")
    return f"[{cwe}](https://cwe.mitre.org/data/definitions/{num}.html)" if num.isdigit() else cwe


def _help_markdown(title: str, advice_en: str, cwe: str) -> str:
    md = [f"**{title}**", "", f"**Remediation:** {advice_en}" if advice_en else ""]
    if cwe:
        md += ["", f"Weakness: {_cwe_link(cwe)}"]
    return "\n".join(md).strip() + "\n"


def _sarif_fixes(f: Finding, base_id: str, en_only: bool) -> list | None:
    """SARIF 2.1.0 §3.55 fix objects from an automatic fix: one artifactChange per file, one replacement per edit.
    An edit rewrites whole lines, so its deletedRegion runs from column 1 of the first line to the end of the last
    one (endColumn omitted = end of line, newline excluded) and insertedContent is the new text without its
    final line terminator."""
    fix = _fix(f)
    if not fix or not fix.get("edits"):
        return None
    by_file: dict[str, list] = {}
    try:
        for ed in fix["edits"]:
            text = str(ed["replacement"])
            text = text[:-2] if text.endswith("\r\n") else text[:-1] if text.endswith(("\n", "\r")) else text
            by_file.setdefault(str(ed["file"]), []).append({
                "deletedRegion": {"startLine": int(ed["start_line"]), "startColumn": 1, "endLine": int(ed["end_line"])},
                "insertedContent": {"text": text}})
    except (KeyError, TypeError, ValueError):
        return None
    out = {"description": {"text": str(fix.get("description") or to_en(fix.get("description_ar", "")))},
           "artifactChanges": [{"artifactLocation": {"uri": _uri(path), "uriBaseId": base_id}, "replacements": reps}
                               for path, reps in by_file.items()]}
    if not en_only and fix.get("description_ar"):
        out["properties"] = {"description_ar": fix["description_ar"]}
    return [out]


def render_sarif(findings: list[Finding], target: str, files: int, notes: list[str], lang: str = "both",
                 suppressed: list[Finding] | None = None) -> str:
    """SARIF 2.1.0 — the OASIS standard consumed by GitHub Code Scanning, VS Code's SARIF viewer,
    Azure DevOps and others. Rules carry CWE tags and a GitHub security-severity; each result carries
    a stable partialFingerprint so the platform can track an issue across commits.

    Every message is English (what code-scanning platforms display). The Arabic title and advice are kept in
    the rule and result properties (title_ar, advice_ar) unless lang is "en", which emits English only.

    ``suppressed``: findings hidden by a triage decision (false positive, accepted risk, won't fix ...). They are
    written as results carrying a SARIF ``suppressions`` entry (kind "external", status "accepted", with the
    justification), so code-scanning platforms close the alert instead of losing track of it."""
    en_only = lang == "en"
    hidden = {id(f) for f in suppressed or []}
    findings = sort_findings(list(findings) + [f for f in suppressed or [] if f is not None])
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
            title_en = f.title or to_en(f.title_ar) or f.rule_id
            advice_en = to_en(f.advice or "")
            if not en_only:
                props["title_ar"] = f.title_ar
                props["advice_ar"] = f.advice or ""
            rule = {"id": f.rule_id, "name": f.rule_id,
                    "shortDescription": {"text": title_en},
                    "fullDescription": {"text": title_en},
                    "helpUri": f.extra.get("url") or f"{REPO_URL}#{f.rule_id}",
                    "help": {"text": advice_en, "markdown": _help_markdown(title_en, advice_en, f.cwe)},
                    "defaultConfiguration": {"level": SARIF_LEVEL.get(f.severity, "warning")},
                    "properties": props}
            if f.cwe:
                rule["relationships"] = [{"target": {"id": f.cwe, "toolComponent": {"name": "CWE"}}}]
            rules[f.rule_id] = rule
        member = f.extra.get("archive_member")
        base_id = "%ARCHIVEROOT%" if member else "%SRCROOT%"     # inside an archive: relative to the archive root
        if f.source == "web" and web_base is not None:
            # a web finding has no source file: point at the exact page that was fetched (already a valid URL),
            # falling back to the scanned URL itself; no line region
            # (a grouped finding raised on the entry page keeps the entry URL; extra.pages lists the others)
            page_url = f.extra.get("page") or target
            phys = {"artifactLocation": {"uri": _norm_url(page_url)}}
        else:
            phys = _file_location(member or f.file, f.line, base_id, target)
        result = {
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.title or to_en(f.title_ar)}: {to_en(f.snippet or '')}".strip(": ") or f.rule_id},
            "locations": [{"physicalLocation": phys}],
            "partialFingerprints": {"vulnscan/v1": f.fingerprint()},
            "properties": ({"severity": f.severity, "advice": to_en(f.advice or "")} if en_only else
                           {"severity": f.severity, "title_ar": f.title_ar, "advice": to_en(f.advice or ""),
                            "advice_ar": f.advice or ""}),
        }
        path = f.extra.get("path")
        if path:   # a data-flow finding: emit the source→sink trail as a SARIF codeFlow
            locs = [{"location": {"physicalLocation": _file_location(
                str(st.get("file") or member or f.file), int(st.get("line", 1) or 1), base_id, target),
                "message": {"text": to_en(str(st.get("text", "")))}}} for st in path if isinstance(st, dict)]
            result["codeFlows"] = [{"threadFlows": [{"locations": locs}]}]
        fixes = _sarif_fixes(f, base_id, en_only) if not member and f.source != "web" else None
        if fixes:
            result["fixes"] = fixes
        if id(f) in hidden:
            tri = f.extra.get("triage") if isinstance(f.extra.get("triage"), dict) else {}
            sup = {"kind": "external", "status": "accepted"}
            reason = " ".join(str(x) for x in (tri.get("status", ""), tri.get("justification", "")) if x).strip()
            if reason:
                sup["justification"] = reason[:1000]
            result["suppressions"] = [sup]
        results.append(result)
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "vulnscan",
                "fullName": "vulnscan (Kashif) security scanner" if en_only else "vulnscan (كاشِف) security scanner",
                "version": __version__,
                "informationUri": REPO_URL,
                "rules": list(rules.values()),
            }},
            "results": results,
            **({} if web_base else {"originalUriBaseIds": _base_ids(target, findings)}),
            "properties": ({"target": target, "filesScanned": files, "notes": [to_en(n) for n in notes]} if en_only else
                           {"target": target, "filesScanned": files, "notes": notes, "notes_en": [to_en(n) for n in notes]}),
        }],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)
