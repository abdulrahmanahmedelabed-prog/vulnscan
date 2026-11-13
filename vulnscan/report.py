"""Console / Markdown / JSON / HTML reports, ordered from highest to lowest severity."""

from __future__ import annotations

import html
import json
import pathlib
import re
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
                   lang: str = "both", web: dict | None = None) -> str:
    """The terminal report. ``web``: the ``web`` object of a web scan (:func:`web_section`): grades and the diff
    summary are added under the notes. Text from a scanned site never carries control characters or ANSI escape
    sequences to the terminal."""
    L = _Lang(lang)
    web = web if _web_ok(web) else None
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
        lines.append(f"  ℹ {_note(L, n, web)}")
    if web:
        lines += _web_console(web, L)
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
        if f.source == "web":                    # target-controlled text: no control characters to the terminal
            conf = f" ({_wl(L, 'c_' + _conf(f))})" if _conf(f) else ""
            lines.append(f"  {BADGE[f.severity]} {f.rule_id}{cwe} {clean_text(L.title(f), 300)}{conf}")
            lines.append(f"     📄 {clean_text(loc, 300)}")
            if f.snippet:
                lines.append(f"     ▸ {clean_text(L.text(f.snippet), 140)}")
            lines.append(f"     💡 {clean_text(L.text(f.advice), 2000)}")
            continue
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


def render_markdown(findings: list[Finding], target: str, files: int, notes: list[str], lang: str = "both",
                    web: dict | None = None) -> str:
    """The Markdown report. ``web`` (:func:`web_section`) adds the web scan sections: grades, coverage and the diff
    before the findings; the inventory and the copy-paste fixes after them."""
    L = _Lang(lang)
    web = web if _web_ok(web) else None
    findings = sort_findings(findings)
    counts = summary_counts(findings)
    meta = _meta(target, files, notes)
    md = [f"# {L('md_title')} — `{_md_code(target, 500) if web else target}`", "",
          f"- {L('date')}: {meta['generated_at']}", f"- {L('files')}: {files}", f"- {L('total')}: {len(findings)}", ""]
    for n in notes:
        md.append(f"- {L('note')}: {_md_cell(_note(L, n, web), 2000) if web else L.text(n)}")
    if L.en:
        md += ["", f"## {L('exec')}", "", "| Severity | Count |", "|---|---|"]
        for s in SEVERITIES:
            md.append(f"| {BADGE[s]} {s} | {counts[s]} |")
    else:
        md += ["", f"## {L('exec')}", "", "| الخطورة | Severity | العدد |", "|---|---|---|"]
        for s in SEVERITIES:
            md.append(f"| {BADGE[s]} {SEVERITY_AR[s]} | {s} | {counts[s]} |")
    md.append("")
    if web:
        md += _web_markdown(findings, web, L, "top") + [""]
    if not findings:
        md.append(L("none"))
        if web:
            md += [""] + _web_markdown(findings, web, L, "bottom")
        return "\n".join(md) + "\n"
    top = [f for f in findings if f.severity in ("critical", "high")][:10]
    if top:
        md += [f"### {L('top')}", ""]
        for i, f in enumerate(top, 1):
            loc = f"{f.file}:{f.line}" if f.line else f.file
            name = f.title if L.en else f.title_ar
            if f.source == "web":
                name = _md_cell(name, 300)
            md.append(f"{i}. **{name}** (`{f.rule_id}`) — `{_md_code(loc, 300) if f.source == 'web' else loc}`")
        md.append("")
    md += [f"## {L('by_sev')}", ""]
    current = None
    for f in findings:
        if f.severity != current:
            current = f.severity
            md += [f"### {BADGE[current]} {L.sev_pair(current)} ({counts[current]})", ""]
        loc = f"{f.file}:{f.line}" if f.line else f.file
        cwe = f" · {f.cwe}" if f.cwe else ""
        if f.source == "web":                      # every value can come from the scanned site (spec §0.6)
            md.append(f"#### {_md_cell(L.title(f), 300)}")
            md.append(f"- {L('rule')}: `{f.rule_id}`{cwe} · {L('source')}: web"
                      + (f" · {_wl(L, 'confidence')}: {_wl(L, 'c_' + _conf(f))}" if _conf(f) else ""))
            md.append(f"- {L('location')}: `{_md_code(loc, 300)}`")
            if f.snippet:
                md.append(f"- {L('snippet')}: `{_md_code(L.text(f.snippet), 160)}`")
            md.append(f"- {L('fix')}: {_md_cell(L.text(f.advice), 2000)}")
            if f.extra.get("url"):
                md.append(f"- {_wl(L, 'page_url')}: `{_md_code(f.extra['url'], 500)}`")
            pages = f.extra.get("page_count") or f.extra.get("instances")
            if isinstance(pages, int) and pages > 1:
                md.append(f"- ×{pages}")
            md.append("")
            continue
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
    if web:
        md += _web_markdown(findings, web, L, "bottom")
    return "\n".join(md) + "\n"


def render_json(findings: list[Finding], target: str, files: int, notes: list[str],
                scanners: list[str] | None = None, web: dict | None = None) -> str:
    """The JSON report. ``scanners`` (optional) names the analyses that ran (sast, secrets, deps, external); the
    policy gate (``kashif policy check``) reads it to verify ``required_scanners``. ``web`` (a web scan) is written
    as the ``web`` key: grades, coverage, inventory, diff and the snapshot (:func:`web_section`)."""
    findings = sort_findings(findings)
    ensure_fingerprints(findings)
    web = web if _web_ok(web) else None
    meta = {**_meta(target, files, notes), "notes_en": _notes_en(notes, web)}
    if scanners is not None:
        meta["scanners"] = sorted(set(scanners))
    doc = {**meta, "summary": summary_counts(findings), "findings": [f.to_dict() for f in findings]}
    if web:
        doc["web"] = web
    return _json_text(json.dumps(doc, ensure_ascii=False, indent=2, default=str))


_C1 = re.compile("[\x80-\x9f]")


def _json_text(text: str) -> str:
    """JSON text with C1 control characters written as ``\\u00XX`` escapes (§0.6). ``json.dumps`` escapes C0 only, so
    a scanned site's ``\\x9b`` (CSI) would reach the terminal raw on ``-f json``; the parsed value is unchanged."""
    return _C1.sub(lambda m: f"\\u{ord(m.group()):04x}", text)


def render_html(findings: list[Finding], target: str, files: int, notes: list[str], lang: str = "both",
                web: dict | None = None) -> str:
    """The HTML report (one self-contained file, no script). ``web`` (:func:`web_section`) adds the confidence
    column and the web sections: grades, coverage, diff, then after the findings the inventory tabs and the
    copy-paste fixes with platform tabs."""
    L = _Lang(lang)
    web = web if _web_ok(web) else None
    show_conf = any(_conf(f) for f in findings)
    findings = sort_findings(findings)
    counts = summary_counts(findings)
    rows = []
    for f in findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        # a web finding's text can come from the scanned site: escaped, and stripped of control characters / ANSI
        e = (lambda s: html.escape(clean_text(s, 2000))) if f.source == "web" else html.escape
        if L.en:
            title_html = f"<b>{e(L.title(f))}</b>"
        elif L.lang == "ar":
            title_html = f"<b>{e(f.title_ar or f.title)}</b>"
        else:
            title_html = f"<b>{e(f.title_ar)}</b><br><small>{e(f.title)}</small>"
        steps = _steps(f)
        # engine text (snippets, trail steps) mixes code and Arabic: each piece takes the direction of its first
        # letter, isolated from the cell around it
        conf_cell = (f"<td>{e(_wl(L, 'c_' + _conf(f))) if _conf(f) else ''}</td>" if show_conf else "")
        rows.append(f"<tr class='{f.severity}'><td><span class='b {f.severity}'>{e(L.sev(f.severity))}</span></td>{conf_cell}"
                    f"<td><code>{e(f.rule_id)}</code><br><small>{e(f.cwe)}</small></td>"
                    f"<td>{title_html}</td>"
                    f"<td><code>{e(loc)}</code><br><small dir='auto'>{e(L.text(f.snippet)[:140])}</small>"
                    + ("<ol class='flow'>" + "".join(f"<li><code>{e(str(st.get('file', '')))}:{st.get('line', '')}</code> "
                                                     f"<bdi>{e(L.text(st.get('text', '')))}</bdi></li>" for st in steps) + "</ol>"
                       if steps else "")
                    + f"</td><td>{e(L.text(f.advice))}{_fix_html(f, L)}</td></tr>")
    e = (lambda s: html.escape(clean_text(s, 2000))) if web else html.escape
    summary = "".join(f"<div class='tile {s}'><div class='n'>{counts[s]}</div><div>{e(L.sev(s))}"
                      + ("" if L.en else f"<br><small>{s}</small>") + "</div></div>"
                      for s in SEVERITIES)
    notes_html = "".join(f"<li>{_bidi_html(L, _note(L, n, web)) if web else e(_note(L, n, web))}</li>" for n in notes)
    empty = f"<tr><td colspan={6 if show_conf else 5}>{e(L('no_results'))}</td></tr>"
    conf_head = f"<th>{e(_wl(L, 'confidence'))}</th>" if show_conf else ""
    web_top = _web_html(findings, web, L, "top") if web else ""
    web_bottom = _web_html(findings, web, L, "bottom") if web else ""
    web_css = (_WEB_CSS + _TAB_CSS) if web else ""
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
{web_css}</style></head><body>
<h1>{e(L('md_title'))} — <code dir="ltr">{e(target)}</code></h1>
<p>{e(L('files'))}: {files} · {e(L('findings'))}: {len(findings)} · <bdi dir="ltr">{e(_meta(target, files, notes)['generated_at'])}</bdi></p>
<ul>{notes_html}</ul>
<div class="tiles">{summary}</div>
{web_top}
<h2>{e(L('html_by_sev'))}</h2>
<div class="tw"><table><thead><tr><th>{e(L('sev_col'))}</th>{conf_head}<th>{e(L('col_rule'))}</th><th>{e(L('col_vuln'))}</th><th>{e(L('location'))}</th><th>{e(L('fix'))}</th></tr></thead>
<tbody>{''.join(rows) or empty}</tbody></table></div>
{web_bottom}
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
                 suppressed: list[Finding] | None = None, web: dict | None = None) -> str:
    """SARIF 2.1.0 — the OASIS standard consumed by GitHub Code Scanning, VS Code's SARIF viewer,
    Azure DevOps and others. Rules carry CWE tags and a GitHub security-severity; each result carries
    a stable partialFingerprint so the platform can track an issue across commits.

    Every message is English (what code-scanning platforms display). The Arabic title and advice are kept in
    the rule and result properties (title_ar, advice_ar) unless lang is "en", which emits English only.

    ``suppressed``: findings hidden by a triage decision (false positive, accepted risk, won't fix ...). They are
    written as results carrying a SARIF ``suppressions`` entry (kind "external", status "accepted", with the
    justification), so code-scanning platforms close the alert instead of losing track of it.

    Web findings (1.1.0) also carry ``properties.precision`` (confidence certain → very-high, firm → high,
    tentative → low) on the rule and the result, and the tags ``wstg:…``, ``asvs4:…`` and ``asvs5:…`` of the rule's
    analyst mapping; a rule's ``security-severity`` is that of its most severe result (findings are sorted by
    severity, so the first one) and its ``precision`` that of its most certain result. ``web`` adds the three grades and the coverage counts to ``run.properties``."""
    en_only = lang == "en"
    hidden = {id(f) for f in suppressed or []}
    findings = sort_findings(list(findings) + [f for f in suppressed or [] if f is not None])
    ensure_fingerprints(findings)
    web_base = urllib.parse.urlsplit(target) if target.startswith(("http://", "https://")) else None
    rules: dict[str, dict] = {}
    results = []
    best_conf: dict[str, int] = {}
    for f in findings:                      # a rule's precision: its most certain result
        if _conf(f):
            rank = CONFIDENCES.index(_conf(f))
            best_conf[f.rule_id] = min(rank, best_conf.get(f.rule_id, rank))
    for f in findings:
        if f.rule_id not in rules:
            props = {"security-severity": SECURITY_SEVERITY.get(f.severity, "0")}
            tags = ["security", f.source]
            if f.cwe:
                tags.append(f.cwe.lower().replace("cwe-", "external/cwe/cwe-"))
            if f.source == "web":
                for scheme in ("wstg", "asvs4", "asvs5"):
                    ids = f.extra.get(scheme)
                    for rid in ids if isinstance(ids, list) else []:
                        tag = f"{scheme}:{clean_text(rid, 40)}"
                        if tag not in tags:
                            tags.append(tag)
            if f.rule_id in best_conf:
                props["precision"] = SARIF_PRECISION[CONFIDENCES[best_conf[f.rule_id]]]
            props["tags"] = tags
            title_en = f.title or to_en(f.title_ar) or f.rule_id
            advice_en = to_en(f.advice or "")
            if not en_only:
                props["title_ar"] = f.title_ar
                props["advice_ar"] = f.advice or ""
            rule = {"id": f.rule_id, "name": f.rule_id,
                    "shortDescription": {"text": title_en},
                    "fullDescription": {"text": title_en},
                    "helpUri": (f.extra.get("url") if f.source != "web" else None) or f"{REPO_URL}#{f.rule_id}",
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
            page_url = f.extra.get("page") or f.extra.get("url") or target
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
        if f.source == "web" and _conf(f):
            result["properties"]["confidence"] = _conf(f)
            result["properties"]["precision"] = SARIF_PRECISION[_conf(f)]
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
            "properties": ({"target": target, "filesScanned": files, "notes": _notes_en(notes, web)} if en_only else
                           {"target": target, "filesScanned": files, "notes": notes, "notes_en": _notes_en(notes, web)}),
        }],
    }
    if _web_ok(web):
        sarif["runs"][0]["properties"].update(_sarif_web_properties(web))

    return _json_text(json.dumps(sarif, ensure_ascii=False, indent=2))


# ----------------------------------------------------------------------------------------------------------------
# Passive web scan (1.1.0): the "web" object of the JSON report and the web sections of the HTML / Markdown /
# console reports (grades, coverage, inventory, remediation snippets, diff against the previous scan).
# Every value that came from the scanned site is untrusted (spec §0.6): HTML-escaped, Markdown-escaped and stripped
# of control characters and ANSI escape sequences before it reaches any report.
# ----------------------------------------------------------------------------------------------------------------

CONFIDENCES = ("certain", "firm", "tentative")
SARIF_PRECISION = {"certain": "very-high", "firm": "high", "tentative": "low"}     # spec §0.5
WEB_SCHEMA = 1
INVENTORY_TABS = ("headers", "csp", "cookies", "tls", "technologies", "third_parties")

_WEB_LABELS = {
    "confidence": ("الثقة", "Confidence"),
    "c_certain": ("مؤكَّدة", "certain"), "c_firm": ("مرجَّحة", "firm"), "c_tentative": ("محتملة", "tentative"),
    "grades": ("الدرجات", "Grades"),
    "g_kashif": ("درجة كاشِف للويب", "Kashif Web Grade"),
    "g_observatory": ("متوافقة مع MDN Observatory", "MDN Observatory-compatible"),
    "g_ssllabs": ("متوافقة مع SSL Labs", "SSL Labs-compatible"),
    "g_none": ("لم تُحسب", "not computed"),
    "g_caps": ("حدود الدرجة", "Grade caps"),
    "g_provisional": ("درجة مؤقتة (*): بعض المجموعات لم تُفحص فلم تُحسب", "Provisional grade (*): some families were not tested and do not count"),
    "coverage": ("تغطية الفحوص", "Check coverage"),
    "cov_state": ("الحالة", "State"), "cov_count": ("العدد", "Count"), "cov_check": ("الفحص", "Check"),
    "cov_reason": ("السبب", "Reason"), "cov_details": ("الفحوص التي لم تنجح أو لم تُجرَ", "Checks that did not pass or did not run"),
    "s_pass": ("ناجح", "passed"), "s_fail": ("فاشل", "failed"), "s_not_applicable": ("غير منطبق", "not applicable"),
    "s_not_tested": ("لم يُجرَ", "not tested"), "s_inconclusive": ("غير حاسم", "inconclusive"),
    "cov_never_pass": ("الفحص الذي لم يُجرَ أو كان غير حاسم لا يُعدّ ناجحًا ولا يدخل في الدرجة.",
                       "A check that was not tested or was inconclusive is never shown as passed and never counts in a grade."),
    "inventory": ("جرد الموقع", "Site inventory"),
    "t_headers": ("ترويسات الأمان", "Security headers"), "t_csp": ("CSP", "CSP"), "t_cookies": ("الكوكيز", "Cookies"),
    "t_tls": ("TLS", "TLS"), "t_technologies": ("التقنيات", "Technologies"), "t_third_parties": ("أطراف ثالثة", "Third parties"),
    "inv_empty": ("لا شيء", "nothing recorded"),
    "h_header": ("الترويسة", "Header"), "h_value": ("القيمة", "Value"), "h_verdict": ("الحكم", "Verdict"),
    "h_url": ("العنوان", "URL"), "h_origin": ("المصدر", "Origin"), "h_policy": ("السياسة", "Policy"),
    "h_name": ("الاسم", "Name"), "h_host": ("المضيف", "Host"), "h_class": ("الصنف", "Class"),
    "h_attrs": ("الخصائص", "Attributes"), "h_version": ("الإصدار", "Version"), "h_kind": ("النوع", "Kind"),
    "h_protocols": ("البروتوكولات", "Protocols"), "h_suites": ("التشفير المختار", "Chosen cipher suites"),
    "h_cert": ("الشهادة", "Certificate"), "h_expires": ("تنتهي", "Expires"), "h_ip": ("العنوان IP", "IP"),
    "h_vulnerable": ("ثغرات معروفة", "Known vulnerabilities"), "yes": ("نعم", "yes"), "no": ("لا", "no"),
    "remediation": ("إصلاحات جاهزة للنسخ", "Copy-paste fixes"),
    "rem_other": ("منصّات أخرى", "Other platforms"),
    "rem_detected": ("المنصّات المكتشفة أولًا", "Detected platforms first"),
    "diff": ("مقارنة بالفحص السابق", "Compared with the previous scan"),
    "d_new": ("نتائج جديدة", "New findings"), "d_resolved": ("نتائج حُلّت", "Resolved findings"),
    "d_unchanged": ("نتائج لم تتغير", "Unchanged findings"), "d_posture": ("تغييرات في الوضع الأمني", "Posture changes"),
    "d_grade": ("تغيّر الدرجات", "Grade changes"), "d_none": ("لا تغييرات", "no changes"),
    "d_regression": ("تراجع", "regression"), "d_change": ("تغيير", "change"), "d_improvement": ("تحسّن", "improvement"),
    "d_previous": ("الفحص السابق", "Previous scan"),
    "web_summary": ("ملخص فحص الموقع", "Web scan summary"),
    "w_profile": ("ملف الفحص", "Profile"), "w_requests": ("الطلبات", "Requests"), "w_final": ("العنوان النهائي", "Final URL"),
    "w_data": ("بيانات الويب بتاريخ", "Web data as of"),
    "page_url": ("الصفحة", "Page"),
}
_STATE_ORDER = ("pass", "fail", "not_applicable", "not_tested", "inconclusive")
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]|\x9b[0-?]*[ -/]*[@-~]")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")


def _wl(L: "_Lang", key: str) -> str:
    ar, en = _WEB_LABELS[key]
    return en if L.en else ar


# Arabic names of the inventory's own tokens (header verdicts, cookie classes, third-party and technology kinds);
# values that are header syntax (DENY, nosniff, strict-origin, same-origin …) stay as sent
_INV_AR = {
    "missing": "مفقودة", "invalid": "غير صالحة", "present": "موجودة", "unrecognised": "غير معروفة",
    "multi": "مكررة", "ignored-on-http": "مُهمَلة عبر HTTP", "frame-ancestors-broad": "frame-ancestors واسع",
    "session": "جلسة", "auth": "مصادقة", "csrf": "رمز CSRF", "preference": "تفضيلات", "analytics": "تحليلات",
    "lb": "موازن حمل", "cdn_bot": "CDN أو حماية من البوتات", "consent": "موافقة", "unknown": "غير معروفة",
    "unknown_secret": "غير معروفة (قيمة عشوائية)",
    "script": "سكربت", "style": "ملف أنماط", "frame": "إطار", "image": "صورة", "other": "أخرى", "server": "خادم",
    "web-server": "خادم ويب", "web-framework": "إطار ويب", "javascript-framework": "إطار JavaScript",
    "javascript-library": "مكتبة JavaScript", "ui-framework": "إطار واجهات", "language": "لغة برمجة",
    "cms": "نظام إدارة محتوى", "ecommerce": "تجارة إلكترونية", "collaboration": "تعاون", "cdn": "شبكة توزيع محتوى",
    "hosting": "استضافة", "admin-panel": "لوحة إدارة", "static-site-generator": "مولّد مواقع ثابتة", "waf": "جدار حماية",
    "blog": "مدونة", "wiki": "ويكي", "forum": "منتدى", "monitoring": "مراقبة", "webmail": "بريد ويب",
    "lms": "نظام إدارة تعلّم", "low-code": "منصة low-code", "database-admin": "إدارة قواعد بيانات", "devops": "DevOps",
    "ci": "تكامل مستمر", "portal": "بوابة", "page-builder": "منشئ صفحات", "database": "قاعدة بيانات", "proxy": "وكيل",
    "cache": "تخزين مؤقت", "load-balancer": "موازن حمل", "tag-manager": "مدير وسوم",
    "security": "أمان", "font": "خطوط",
}


def _inv(L: "_Lang", token) -> str:
    """An inventory token in the report language (Arabic name when one is known, else the token as recorded)."""
    text = clean_text(token, 80)
    return text if L.en else _INV_AR.get(text, text)


_BIDI_WORD = r"(?:--?)?[A-Za-z0-9_$./~][A-Za-z0-9_$:/.~-]*[+*]*(?:\([^()؀-ۿ]*\))*"
_BIDI_RUN = re.compile(rf"{_BIDI_WORD}(?:\.? +{_BIDI_WORD})*")


def _bidi_html(L: "_Lang", text: str) -> str:
    """Escaped engine text for an Arabic page with every Latin run isolated left-to-right (the UI's bidi()): without
    it "كاشف F* · Observatory 0 (F)" displays the Observatory grade beside "كاشف", and "A+" as "+A"."""
    text = str(text or "")
    if L.en or not re.search("[؀-ۿ]", text):
        return html.escape(text)
    out, last = [], 0
    for m in _BIDI_RUN.finditer(text):
        run = m.group().rstrip(".:,;-")
        if not re.search("[A-Za-z]", run):
            continue
        out.append(html.escape(text[last:m.start()]) + f"<bdi dir='ltr'>{html.escape(run)}</bdi>")
        last = m.start() + len(run)
    return "".join(out) + html.escape(text[last:])


def _pair(L: "_Lang", value) -> str:
    """An {en, ar} text (or an (en, ar) pair, or plain text) in the report language."""
    if isinstance(value, dict):
        return str((value.get("en") if L.en else value.get("ar")) or value.get("en") or value.get("ar") or "")
    if isinstance(value, (list, tuple)) and len(value) == 2 and all(isinstance(x, str) for x in value):
        return value[0] if L.en else value[1]
    return "" if value is None else str(value)


def clean_text(value, limit: int = 300) -> str:
    """Target-controlled text made inert for any report: ANSI escape sequences and C0/C1/bidi control characters
    removed, whitespace collapsed, length capped."""
    text = _ANSI.sub("", "" if value is None else str(value))
    text = _CTRL.sub(" ", text)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


_TAG_START = re.compile(r"<(?!redacted:)(?=[A-Za-z/!?])")


def _md_code(value, limit: int = 300) -> str:
    """Untrusted text for an inline code span. CommonMark keeps a code span literal, but a renderer that allows raw
    HTML may not: a backtick cannot close the span and nothing that could open a tag stays (``<redacted:N bytes>``,
    Kashif's own marker, is kept)."""
    return _TAG_START.sub("&lt;", clean_text(value, limit).replace("`", "ˋ"))


def _note(L: "_Lang", note: str, web: dict | None) -> str:
    """A scan note in the report language: the engine's own English text for a web scan's notes, else to_en."""
    if L.en and web:
        for n in web.get("notes") or []:
            if isinstance(n, dict) and n.get("ar") == note and n.get("en"):
                return clean_text(n["en"], 2000)
    return clean_text(L.text(note), 2000) if web else L.text(note)


def _notes_en(notes: list[str], web: dict | None) -> list[str]:
    web = web if _web_ok(web) else None
    return [_note(_Lang("en"), n, web) for n in notes] if web else [to_en(n) for n in notes]


def _md_cell(value, limit: int = 300) -> str:
    """Untrusted text for a Markdown table cell or inline code: no pipes, backticks, newlines or markup."""
    text = clean_text(value, limit)
    for ch, rep in (("\\", "\\\\"), ("|", "\\|"), ("`", "ˋ"), ("<", "&lt;"), (">", "&gt;"), ("*", "\\*"),
                    ("_", "\\_"), ("[", "\\["), ("]", "\\]")):
        text = text.replace(ch, rep)
    return text


def _conf(f: Finding) -> str:
    c = f.extra.get("confidence") if isinstance(f.extra, dict) else None
    return c if c in CONFIDENCES else ""


def _check_rules() -> dict[str, list[str]]:
    try:
        from .webscan.rules import RULES as WEB_RULES
    except ImportError:                                          # pragma: no cover - the package always ships it
        return {}
    out: dict[str, list[str]] = {}
    for rid, meta in WEB_RULES.items():
        out.setdefault(meta.check_id or rid, []).append(rid)
    return out


def web_section(result, *, sensitivity: str | None = None) -> dict:
    """The ``web`` object of the JSON report (and of a saved UI scan) from a ``webscan.types.WebScanResult``.

    Keys: ``schema``, ``profile``, ``sensitivity``, ``target``, ``final_url``, ``requests``, ``bytes_received``,
    ``data_date``, ``grades`` (kashif / observatory / ssllabs, spec §3.4), ``coverage`` (one record per check:
    ``check``, ``rules``, ``state``, ``reason``, ``reasons`` [{code, en, ar}], ``hosts``), ``coverage_counts``,
    ``coverage_summary`` {en, ar}, ``inventory`` (§3.9), ``notes`` [{en, ar}], ``diff`` (§3.7, or None) and
    ``snapshot`` (what ``--compare FILE`` reads back)."""
    cov = getattr(result, "coverage", None) or {}
    rules_of = _check_rules()
    checks = []
    for c in cov.get("checks") or []:
        if not isinstance(c, dict):
            continue
        cid = str(c.get("check") or "")
        reasons = [r for r in c.get("reasons") or [] if isinstance(r, dict)]
        checks.append({"check": cid, "rules": rules_of.get(cid, [cid]), "state": c.get("state"),
                       "reason": "; ".join(str(r.get("en") or r.get("code") or "") for r in reasons),
                       "reasons": reasons, "hosts": c.get("hosts") or {}})
    inv = getattr(result, "inventory", None) or {}
    inv = dict(inv) if isinstance(inv, dict) else {}
    notes = inv.get("notes") if isinstance(inv.get("notes"), list) else []
    return {"schema": WEB_SCHEMA, "profile": getattr(result, "profile", ""), "sensitivity": sensitivity or "",
            "target": getattr(result, "target", ""), "final_url": getattr(result, "final_url", ""),
            "requests": getattr(result, "requests", 0), "bytes_received": getattr(result, "bytes_received", 0),
            "data_date": getattr(result, "data_date", ""), "grades": getattr(result, "grades", None) or {},
            "coverage": checks, "coverage_counts": dict(cov.get("counts") or {}),
            "coverage_summary": inv.get("coverage_summary") or {}, "inventory": inv, "notes": notes,
            "diff": getattr(result, "diff", None), "snapshot": getattr(result, "snapshot", None) or {}}


def _web_ok(web) -> bool:
    return isinstance(web, dict) and isinstance(web.get("grades", {}), dict)


def _grade_rows(web: dict, L: "_Lang") -> list[dict]:
    """[{key, name, grade, score, max, label, caps, notes, provisional}] for the three algorithms (``notes``: why
    there is no grade, which families made it provisional, what A+ still needs)."""
    g = web.get("grades") if isinstance(web.get("grades"), dict) else {}
    rows = []
    for key in ("kashif", "observatory", "ssllabs"):
        d = g.get(key) if isinstance(g.get(key), dict) else {}
        grade = d.get("grade") or d.get("letter")
        caps = [clean_text(_pair(L, c), 200) for c in d.get("caps") or [] if isinstance(c, dict)]
        rows.append({"key": key, "name": _wl(L, f"g_{key}"), "grade": clean_text(grade, 8) if grade else "",
                     "score": d.get("score") if isinstance(d.get("score"), (int, float)) else None,
                     "max": d.get("max_score") if isinstance(d.get("max_score"), (int, float)) else None,
                     "label": clean_text(_pair(L, d.get("label")), 300), "caps": caps,
                     "notes": [clean_text(_pair(L, n), 300) for n in d.get("notes") or [] if isinstance(n, dict)],
                     "provisional": bool(d.get("provisional"))})
    return rows


def _coverage_counts(web: dict) -> dict[str, int]:
    counts = web.get("coverage_counts") if isinstance(web.get("coverage_counts"), dict) else {}
    out = {}
    for s in _STATE_ORDER:
        try:
            out[s] = int(counts.get(s) or 0)
        except (TypeError, ValueError):
            out[s] = 0
    return out


def _coverage_problems(web: dict, L: "_Lang", limit: int = 400) -> list[tuple[str, str, str]]:
    """(check, state, reason) of every check that did not pass (not applicable is left out: it is not a gap)."""
    out = []
    for c in web.get("coverage") or []:
        if not isinstance(c, dict) or c.get("state") not in ("fail", "not_tested", "inconclusive"):
            continue
        reasons = [clean_text(_pair(L, r), 200) for r in c.get("reasons") or [] if isinstance(r, dict)]
        out.append((clean_text(c.get("check"), 60), str(c.get("state")), ("; " if L.en else "؛ ").join(x for x in reasons if x)))
        if len(out) >= limit:
            break
    return out


def _yn(L: "_Lang", value) -> str:
    return _wl(L, "yes") if value is True else _wl(L, "no") if value is False else clean_text(value, 40)


def inventory_tables(web: dict, L: "_Lang") -> dict[str, tuple[list[str], list[list[str]]]]:
    """The inventory tabs as plain tables: {tab: (header row, rows)}; every cell is cleaned untrusted text."""
    inv = web.get("inventory") if isinstance(web.get("inventory"), dict) else {}
    out: dict[str, tuple[list[str], list[list[str]]]] = {}
    rows = []
    for entry in inv.get("security_headers") or []:
        if not isinstance(entry, dict):
            continue
        for name, d in (entry.get("headers") or {}).items():
            d = d if isinstance(d, dict) else {"value": d}
            rows.append([clean_text(entry.get("url"), 200), clean_text(name, 80), clean_text(d.get("value"), 300) or "—",
                         _inv(L, d.get("verdict"))])
    out["headers"] = ([_wl(L, "h_url"), _wl(L, "h_header"), _wl(L, "h_value"), _wl(L, "h_verdict")], rows[:300])
    rows = []
    for entry in inv.get("csp") or []:
        if not isinstance(entry, dict):
            continue
        for pol in list(entry.get("policies") or []) + list(entry.get("report_only") or []):
            if isinstance(pol, dict):
                rows.append([clean_text(entry.get("url"), 200), clean_text(pol.get("origin"), 30),
                             clean_text(pol.get("raw"), 1000)])
    out["csp"] = ([_wl(L, "h_url"), _wl(L, "h_origin"), _wl(L, "h_policy")], rows[:100])
    rows = []
    for c in inv.get("cookies") or []:
        if not isinstance(c, dict):
            continue
        attrs = [a for a in ("secure", "httponly", "partitioned") if c.get(a) is True]
        if c.get("samesite"):
            attrs.append(f"SameSite={c['samesite']}")
        for k in ("domain", "path"):
            if c.get(k):
                attrs.append(f"{k.capitalize()}={c[k]}")
        if c.get("persistent_days"):
            attrs.append(f"{c['persistent_days']}d")
        rows.append([clean_text(c.get("name"), 80), clean_text(c.get("host"), 120), _inv(L, c.get("class")),
                     clean_text("; ".join(str(a) for a in attrs), 300)])
    out["cookies"] = ([_wl(L, "h_name"), _wl(L, "h_host"), _wl(L, "h_class"), _wl(L, "h_attrs")], rows[:300])
    rows = []
    tls = inv.get("tls") if isinstance(inv.get("tls"), dict) else {}
    for hostkey, rep in tls.items():
        if not isinstance(rep, dict):
            continue
        for ip, d in (rep.get("ips") or {}).items():
            if not isinstance(d, dict):
                continue
            protos = [p for p, v in (d.get("protocols") or {}).items() if v == "yes"]
            chosen = [f"{p}: {s}" for p, s in (d.get("chosen") or {}).items() if s]
            chain = [x for x in d.get("chain") or [] if isinstance(x, dict)]
            leaf = chain[0] if chain else {}
            cert = " · ".join(str(x) for x in (leaf.get("subject"), leaf.get("issuer"), leaf.get("key")) if x)
            rows.append([clean_text(hostkey, 120), clean_text(ip, 60), clean_text(", ".join(protos), 120),
                         clean_text("; ".join(chosen), 300), clean_text(cert, 300), clean_text(leaf.get("not_after"), 40)])
    out["tls"] = ([_wl(L, "h_host"), _wl(L, "h_ip"), _wl(L, "h_protocols"), _wl(L, "h_suites"), _wl(L, "h_cert"),
                   _wl(L, "h_expires")], rows[:50])
    rows = []
    for t in inv.get("technologies") or []:
        if isinstance(t, dict):
            rows.append([clean_text(t.get("name"), 80), clean_text(t.get("version"), 40),
                         ("، " if not L.en else ", ").join(_inv(L, c) for c in t.get("categories") or [])[:120], ""])
    for lib in inv.get("libraries") or []:
        if isinstance(lib, dict):
            rows.append([clean_text(lib.get("name"), 80), clean_text(lib.get("version"), 40), "JavaScript",
                         _yn(L, lib.get("vulnerable")) if "vulnerable" in lib else ""])
    for s in inv.get("server_software") or []:
        if isinstance(s, dict):
            rows.append([clean_text(s.get("name") or s.get("product"), 80), clean_text(s.get("version"), 40),
                         _inv(L, s.get("source") or s.get("where") or "server"), ""])
    out["technologies"] = ([_wl(L, "h_name"), _wl(L, "h_version"), _wl(L, "h_kind"), _wl(L, "h_vulnerable")], rows[:200])
    rows = []
    tp = inv.get("third_parties") if isinstance(inv.get("third_parties"), dict) else {}
    for host, kinds in tp.items():
        rows.append([clean_text(host, 200), ("، " if not L.en else ", ").join(_inv(L, k) for k in kinds or [])[:120]
                     if isinstance(kinds, list) else clean_text(kinds, 120)])
    out["third_parties"] = ([_wl(L, "h_host"), _wl(L, "h_kind")], rows[:200])
    return out


def remediation_snippets(findings: list[Finding], web: dict | None, lang: str) -> list[dict]:
    """Copy-paste fixes (webscan/remediation.py) for the web findings, detected platforms first."""
    rule_ids = []
    for f in sort_findings(findings):
        if f.source == "web" and f.rule_id not in rule_ids:
            rule_ids.append(f.rule_id)
    if not rule_ids:
        return []
    try:
        from .webscan import remediation
    except ImportError:                                          # pragma: no cover
        return []
    inv = (web or {}).get("inventory") if isinstance((web or {}).get("inventory"), dict) else {}
    detected = [p for p in inv.get("platforms") or [] if isinstance(p, str)]
    host = ""
    try:
        host = urllib.parse.urlsplit(str((web or {}).get("final_url") or (web or {}).get("target") or "")).hostname or ""
    except ValueError:
        host = ""
    try:
        return remediation.for_rules(rule_ids, "en" if lang == "en" else "ar", host=host or None, detected=detected)
    except Exception:  # noqa: BLE001 - a report never fails on the snippet library
        return []


def _diff_parts(web: dict) -> dict | None:
    d = web.get("diff") if isinstance(web.get("diff"), dict) else None
    if not d:
        return None
    f = d.get("findings") if isinstance(d.get("findings"), dict) else {}
    return {"comparable": bool(d.get("comparable")), "notes": [n for n in d.get("notes") or [] if isinstance(n, dict)],
            "new": [r for r in f.get("new") or [] if isinstance(r, dict)],
            "resolved": [r for r in f.get("resolved") or [] if isinstance(r, dict)],
            "unchanged": [r for r in f.get("unchanged") or [] if isinstance(r, dict)],
            "posture": [p for p in d.get("posture") or [] if isinstance(p, dict)],
            "grades": d.get("grades") if isinstance(d.get("grades"), dict) else {},
            "previous": d.get("previous") if isinstance(d.get("previous"), dict) else {}}


def _row_title(L: "_Lang", r: dict) -> str:
    return clean_text((r.get("title_en") if L.en else r.get("title_ar")) or r.get("title_en") or r.get("rule"), 200)


def _grade_change_text(L: "_Lang", key: str, ch) -> str:
    if not isinstance(ch, dict):
        return ""
    before, after = ch.get("before"), ch.get("after")
    if isinstance(before, dict):
        before = before.get("grade")
    if isinstance(after, dict):
        after = after.get("grade")
    name = _wl(L, 'g_' + key) if key in ('kashif', 'observatory', 'ssllabs') else clean_text(key, 30)
    before, after = clean_text(before, 10) or '—', clean_text(after, 10) or '—'
    # Arabic reads right to left: "من B إلى A" as in webscan/diff.py, not an arrow that points back at the old grade
    return f"{name}: {before} → {after}" if L.en else f"{name}: من {before} إلى {after}"


# ------------------------------------------------------------------------------------------- web: HTML


_TAB_CSS = "".join(f".tabs>input:nth-of-type({i}):checked~div.panel:nth-of-type({i}){{display:block}}" for i in range(1, 25))
_WEB_CSS = """
.web h2{margin-top:2rem}.grades{display:flex;gap:.75rem;flex-wrap:wrap}
.grade{background:#fff;border:1px solid #ddd;border-radius:.5rem;padding:.75rem 1rem;min-width:12rem;flex:1}
.grade .letter{font-size:2.2rem;font-weight:800}.grade small{color:#555;display:block}
.grade ul{margin:.3rem 0 0;padding-inline-start:1.1rem;font-size:.85em}
.cov{display:flex;gap:.5rem;flex-wrap:wrap;margin:.5rem 0}.cov span{background:#fff;border:1px solid #ddd;border-radius:1rem;padding:.2rem .7rem}
.cov .s-fail{border-color:#c2410c}.cov .s-not_tested,.cov .s-inconclusive{border-color:#a16207}
.tabs{margin:.5rem 0}.tabs>input{position:absolute;opacity:0;pointer-events:none}
.tabs>label{display:inline-block;padding:.35rem .8rem;border:1px solid #ddd;border-bottom:none;border-radius:.4rem .4rem 0 0;
background:#f1f1f1;cursor:pointer;margin-inline-end:.2rem}.tabs>input:checked+label{background:#fff;font-weight:700}
.tabs>input:focus-visible+label{outline:2px solid #0e7490}
.tabs>div.panel{display:none;border:1px solid #ddd;background:#fff;padding:.6rem;overflow-x:auto}
.snip{background:#fff;border:1px solid #ddd;border-radius:.5rem;padding:.6rem 1rem;margin:.6rem 0}
.snip pre{direction:ltr;text-align:left;background:#f6f8fa;padding:.5rem;overflow:auto;font-size:.82em;white-space:pre}
.caveat{color:#92400e}.conf{font-size:.75em;color:#555;display:block;margin-top:.2rem}
.posture li.regression{color:#991b1b}.posture li.improvement{color:#166534}
"""


def _html_table(head: list[str], rows: list[list[str]], L: "_Lang") -> str:
    e = html.escape
    if not rows:
        return f"<p>{e(_wl(L, 'inv_empty'))}</p>"
    th = "".join(f"<th>{e(h)}</th>" for h in head)
    body = "".join("<tr>" + "".join(f"<td><bdi dir='auto'>{e(c)}</bdi></td>" for c in r) + "</tr>" for r in rows)
    return f"<div class='tw'><table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table></div>"


def _html_tabs(name: str, tabs: list[tuple[str, str]]) -> str:
    """CSS-only tabs (radio buttons): no script, so the report works under any CSP and offline."""
    e = html.escape
    inputs = []
    panels = []
    for i, (label, body) in enumerate(tabs):
        tid = f"{name}-{i}"
        inputs.append(f"<input type='radio' name='{e(name)}' id='{e(tid)}'{' checked' if i == 0 else ''}>"
                      f"<label for='{e(tid)}'><bdi dir='auto'>{e(label)}</bdi></label>")
        panels.append(f"<div class='panel'>{body}</div>")
    return f"<div class='tabs'>{''.join(inputs)}{''.join(panels)}</div>"


def _web_html(findings: list[Finding], web: dict, L: "_Lang", part: str = "top") -> str:
    e = html.escape
    out = ["<section class='web'>"]
    if part == "bottom":
        return _web_html_bottom(findings, web, L)
    # summary line
    facts = [(_wl(L, "w_profile"), clean_text(web.get("profile"), 20)), (_wl(L, "w_requests"), clean_text(web.get("requests"), 10)),
             (_wl(L, "w_final"), clean_text(web.get("final_url"), 300)), (_wl(L, "w_data"), clean_text(web.get("data_date"), 20))]
    out.append("<p>" + " · ".join(f"{e(k)}: <bdi dir='ltr'>{e(v)}</bdi>" for k, v in facts if v) + "</p>")
    # grades
    out.append(f"<h2>{e(_wl(L, 'grades'))}</h2><div class='grades'>")
    provisional = False
    for g in _grade_rows(web, L):
        provisional = provisional or g["provisional"]
        score = "" if g["score"] is None else f"{g['score']:g}" + (f"/{g['max']:g}" if g["max"] else "")
        caps = "".join(f"<li>{_bidi_html(L, c)}</li>" for c in g["caps"][:8])
        out.append(f"<div class='grade g-{e(g['key'])}'><b>{e(g['name'])}</b>"
                   f"<div class='letter' dir='ltr'>{e(g['grade'] or '—')}</div>"
                   + (f"<small dir='ltr'>{e(score)}</small>" if score else f"<small>{e(_wl(L, 'g_none'))}</small>" if not g['grade'] else "")
                   + (f"<small>{_bidi_html(L, g['label'])}</small>" if g["label"] else "")
                   + "".join(f"<small>{_bidi_html(L, n)}</small>" for n in g["notes"][:4])
                   + (f"<small>{e(_wl(L, 'g_caps'))}:</small><ul>{caps}</ul>" if caps else "") + "</div>")
    out.append("</div>")
    if provisional:
        out.append(f"<p><small>{e(_wl(L, 'g_provisional'))}</small></p>")
    # coverage
    counts = _coverage_counts(web)
    out.append(f"<h2>{e(_wl(L, 'coverage'))}</h2><div class='cov'>"
               + "".join(f"<span class='s-{s}'>{e(_wl(L, 's_' + s))}: <b>{counts[s]}</b></span>" for s in _STATE_ORDER)
               + f"</div><p><small>{e(_wl(L, 'cov_never_pass'))}</small></p>")
    problems = _coverage_problems(web, L)
    if problems:
        rows = [[c, _wl(L, "s_" + s) if ("s_" + s) in _WEB_LABELS else s, r] for c, s, r in problems]
        out.append(f"<details><summary>{e(_wl(L, 'cov_details'))} ({len(problems)})</summary>"
                   + _html_table([_wl(L, "cov_check"), _wl(L, "cov_state"), _wl(L, "cov_reason")], rows, L) + "</details>")
    # diff
    dp = _diff_parts(web)
    if dp:
        out.append(f"<h2>{e(_wl(L, 'diff'))}</h2>")
        for n in dp["notes"]:
            out.append(f"<p>{_bidi_html(L, clean_text(_pair(L, n), 400))}</p>")
        if dp["comparable"]:
            changes = [_grade_change_text(L, k, v) for k, v in dp["grades"].items()]
            changes = [c for c in changes if c]
            if changes:
                out.append(f"<p><b>{e(_wl(L, 'd_grade'))}:</b> " + " · ".join(f"<bdi>{_bidi_html(L, c)}</bdi>" for c in changes) + "</p>")
            if dp["posture"]:
                out.append(f"<h3>{e(_wl(L, 'd_posture'))}</h3><ul class='posture'>"
                           + "".join(f"<li class='{e(str(p.get('direction')))}'>{e(_wl(L, 'd_' + p['direction']) if ('d_' + str(p.get('direction'))) in _WEB_LABELS else '')}: "
                                     f"<bdi>{_bidi_html(L, clean_text(_pair(L, p), 400))}</bdi></li>" for p in dp["posture"][:200]) + "</ul>")
            for key in ("new", "resolved"):
                items = dp[key]
                out.append(f"<h3>{e(_wl(L, 'd_' + key))} ({len(items)})</h3>")
                if items:
                    out.append("<ul>" + "".join(f"<li><span class='b {e(str(r.get('severity')))}'>{e(L.sev(r['severity']) if r.get('severity') in SEVERITY_AR else '?')}</span> "
                                                f"<code>{e(clean_text(r.get('rule'), 40))}</code> <bdi>{e(_row_title(L, r))}</bdi></li>"
                                                for r in items[:200]) + "</ul>")
            out.append(f"<p><small>{e(_wl(L, 'd_unchanged'))}: {len(dp['unchanged'])}</small></p>")
    out.append("</section>")
    return "".join(out)


def _web_html_bottom(findings: list[Finding], web: dict, L: "_Lang") -> str:
    e = html.escape
    out = ["<section class='web'>"]
    # inventory tabs
    tables = inventory_tables(web, L)
    out.append(f"<h2>{e(_wl(L, 'inventory'))}</h2>")
    out.append(_html_tabs("inv", [(_wl(L, "t_" + k), _html_table(*tables[k], L)) for k in INVENTORY_TABS]))
    # remediation snippets with platform tabs
    snippets = remediation_snippets(findings, web, L.lang)
    if snippets:
        out.append(f"<h2>{e(_wl(L, 'remediation'))}</h2>")
        for i, sn in enumerate(snippets):
            blocks = [b for b in list(sn.get("detected") or []) + list(sn.get("other") or []) if isinstance(b, dict)]
            tabs = []
            for b in blocks:
                body = (f"<pre><code>{e(str(b.get('code') or ''))}</code></pre>" if b.get("code") else "") \
                    + (f"<p>{e(str(b.get('note') or ''))}</p>" if b.get("note") else "")
                tabs.append((str(b.get("name") or b.get("platform") or ""), body))
            out.append(f"<div class='snip'><h3><code>{e(str(sn.get('id')))}</code> {e(str(sn.get('title') or ''))}</h3>"
                       f"<p>{e(str(sn.get('summary') or ''))}</p>"
                       + (f"<p class='caveat'><b>{e(str(sn.get('caveat_label') or ''))}:</b> {e(str(sn.get('caveat') or ''))}</p>" if sn.get("caveat") else "")
                       + (_html_tabs(f"rem{i}", tabs) if tabs else "") + "</div>")
    out.append("</section>")
    return "".join(out)


# --------------------------------------------------------------------------------------- web: Markdown

def _md_table(head: list[str], rows: list[list[str]], L: "_Lang") -> list[str]:
    if not rows:
        return [f"_{_wl(L, 'inv_empty')}_", ""]
    out = ["| " + " | ".join(_md_cell(h, 80) for h in head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(_md_cell(c, 1000) or " " for c in r) + " |" for r in rows]
    return out + [""]


def _web_markdown(findings: list[Finding], web: dict, L: "_Lang", part: str = "top") -> list[str]:
    if part == "bottom":
        return _web_markdown_bottom(findings, web, L)
    md = [f"## {_wl(L, 'web_summary')}", ""]
    for k, v in ((_wl(L, "w_profile"), web.get("profile")), (_wl(L, "w_requests"), web.get("requests")),
                 (_wl(L, "w_final"), web.get("final_url")), (_wl(L, "w_data"), web.get("data_date"))):
        if v not in (None, ""):
            md.append(f"- {k}: `{_md_code(v, 300)}`")
    md += ["", f"### {_wl(L, 'grades')}", ""]
    rows = []
    for g in _grade_rows(web, L):
        score = "" if g["score"] is None else f"{g['score']:g}" + (f"/{g['max']:g}" if g["max"] else "")
        rows.append([g["name"], g["grade"] or "—", score, ("; " if L.en else "؛ ").join((g["notes"] + g["caps"])[:6]) or g["label"]])
    md += _md_table(["", "", "", ""], rows, L)
    counts = _coverage_counts(web)
    md += [f"### {_wl(L, 'coverage')}", "",
           " · ".join(f"{_wl(L, 's_' + s)}: **{counts[s]}**" for s in _STATE_ORDER), "", f"_{_wl(L, 'cov_never_pass')}_", ""]
    problems = _coverage_problems(web, L, limit=200)
    if problems:
        md += _md_table([_wl(L, "cov_check"), _wl(L, "cov_state"), _wl(L, "cov_reason")],
                        [[c, _wl(L, "s_" + s) if ("s_" + s) in _WEB_LABELS else s, r] for c, s, r in problems], L)
    dp = _diff_parts(web)
    if dp:
        md += [f"### {_wl(L, 'diff')}", ""]
        md += [f"- {_md_cell(_pair(L, n), 400)}" for n in dp["notes"]]
        if dp["comparable"]:
            changes = [c for c in (_grade_change_text(L, k, v) for k, v in dp["grades"].items()) if c]
            if changes:
                md.append(f"- {_wl(L, 'd_grade')}: " + " · ".join(_md_cell(c, 100) for c in changes))
            for p in dp["posture"][:200]:
                direction = str(p.get("direction"))
                label = _wl(L, "d_" + direction) if ("d_" + direction) in _WEB_LABELS else direction
                md.append(f"- **{label}**: {_md_cell(_pair(L, p), 400)}")
            for key in ("new", "resolved"):
                md += ["", f"#### {_wl(L, 'd_' + key)} ({len(dp[key])})", ""]
                md += [f"- `{_md_code(r.get('rule'), 40)}` {_md_cell(_row_title(L, r), 200)} ({_md_cell(r.get('severity'), 10)})"
                       for r in dp[key][:200]]
            md += ["", f"{_wl(L, 'd_unchanged')}: {len(dp['unchanged'])}"]
        md.append("")
    return md


def _web_markdown_bottom(findings: list[Finding], web: dict, L: "_Lang") -> list[str]:
    tables = inventory_tables(web, L)
    md = [f"## {_wl(L, 'inventory')}", ""]
    for k in INVENTORY_TABS:
        md += [f"### {_wl(L, 't_' + k)}", ""] + _md_table(*tables[k], L)
    snippets = remediation_snippets(findings, web, L.lang)
    if snippets:
        md += [f"## {_wl(L, 'remediation')}", ""]
        for sn in snippets:
            md += [f"### {sn.get('id')} · {sn.get('title')}", "", str(sn.get("summary") or ""), ""]
            if sn.get("caveat"):
                md += [f"**{sn.get('caveat_label')}:** {sn.get('caveat')}", ""]
            for b in list(sn.get("detected") or []) + list(sn.get("other") or []):
                if not isinstance(b, dict):
                    continue
                md += [f"**{b.get('name')}**", ""]
                code = str(b.get("code") or "")
                if code:
                    fence = "````" if "```" in code else "```"
                    md += [fence + str(b.get("lang") or ""), code, fence, ""]
                if b.get("note"):
                    md += [str(b["note"]), ""]
    return md


def _web_console(web: dict, L: "_Lang") -> list[str]:
    lines = []                               # the grades and coverage are already in the scan notes
    dp = _diff_parts(web)
    if dp and dp["comparable"]:
        lines.append(f"  ⇄ {_wl(L, 'diff')}: {_wl(L, 'd_new')} {len(dp['new'])} · {_wl(L, 'd_resolved')} "
                     f"{len(dp['resolved'])} · {_wl(L, 'd_regression')} "
                     f"{sum(1 for p in dp['posture'] if p.get('direction') == 'regression')}")
        for p in dp["posture"][:5]:
            if p.get("direction") == "regression":
                lines.append(f"     ↓ {clean_text(_pair(L, p), 200)}")
    return lines


def _sarif_web_properties(web: dict) -> dict:
    """``run.properties`` additions for a web scan: the three grades and the coverage counts (spec §4.5)."""
    g = web.get("grades") if isinstance(web.get("grades"), dict) else {}
    grades = {}
    for key in ("kashif", "observatory", "ssllabs"):
        d = g.get(key) if isinstance(g.get(key), dict) else {}
        if d:
            grades[key] = {k: d.get(k) for k in ("grade", "score", "max_score", "provisional", "algorithm") if k in d}
    not_run = [{"check": c.get("check"), "state": c.get("state"), "reason": c.get("reason", "")}
               for c in web.get("coverage") or [] if isinstance(c, dict) and c.get("state") in ("not_tested", "inconclusive")]
    summary = web.get("coverage_summary") if isinstance(web.get("coverage_summary"), dict) else {}
    return {"webProfile": web.get("profile", ""), "grades": grades,
            "coverage": {"counts": _coverage_counts(web), "summary": summary.get("en", ""), "notTested": not_run[:500]}}


def web_view(findings: list[Finding], web: dict, lang: str = "ar") -> dict:
    """What the local UI shows of a web scan (GET /api/scans/<id>/web): the same data as the HTML report, already
    in the UI language and cleaned of control characters (the UI escapes every value again before display).

    ``facts`` (profile, requests, final URL, data date) · ``grades`` [{key, name, grade, score, max, label, caps,
    notes, provisional}] · ``coverage`` {counts, states (labels), problems [[check, state, reason]]} · ``diff`` (None, or
    {comparable, notes, new, resolved, unchanged (count), posture [{direction, label, text}], grades [text]}) ·
    ``inventory`` [{id, label, head, rows}] · ``remediation`` (the snippet library's render(), detected platforms
    first)."""
    L = _Lang("en" if lang == "en" else "ar")
    web = web if _web_ok(web) else {}
    dp = _diff_parts(web) if web else None
    diff = None
    if dp:
        diff = {"comparable": dp["comparable"], "notes": [clean_text(_pair(L, n), 400) for n in dp["notes"]],
                "new": [{"rule": clean_text(r.get("rule"), 40), "severity": r.get("severity") if r.get("severity") in SEVERITIES else "info",
                         "title": _row_title(L, r)} for r in dp["new"][:200]],
                "resolved": [{"rule": clean_text(r.get("rule"), 40), "severity": r.get("severity") if r.get("severity") in SEVERITIES else "info",
                              "title": _row_title(L, r)} for r in dp["resolved"][:200]],
                "unchanged": len(dp["unchanged"]),
                "posture": [{"direction": str(p.get("direction") or ""),
                             "label": _wl(L, "d_" + str(p.get("direction"))) if ("d_" + str(p.get("direction"))) in _WEB_LABELS else "",
                             "text": clean_text(_pair(L, p), 400)} for p in dp["posture"][:200]],
                "grades": [c for c in (_grade_change_text(L, k, v) for k, v in dp["grades"].items()) if c]}
    tables = inventory_tables(web, L) if web else {}
    return {"facts": {"profile": clean_text(web.get("profile"), 20), "requests": web.get("requests"),
                      "final_url": clean_text(web.get("final_url"), 500), "data_date": clean_text(web.get("data_date"), 20),
                      "sensitivity": clean_text(web.get("sensitivity"), 20)},
            "grades": _grade_rows(web, L) if web else [],
            "coverage": {"counts": _coverage_counts(web), "states": {s: _wl(L, "s_" + s) for s in _STATE_ORDER},
                         "problems": [[c, _wl(L, "s_" + s) if ("s_" + s) in _WEB_LABELS else s, r]
                                      for c, s, r in _coverage_problems(web, L)] if web else []},
            "diff": diff,
            "inventory": [{"id": k, "label": _wl(L, "t_" + k), "head": tables[k][0], "rows": tables[k][1]}
                          for k in INVENTORY_TABS if k in tables],
            "remediation": remediation_snippets(findings, web, L.lang) if web else []}
