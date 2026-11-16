"""Console / Markdown / JSON / HTML reports, ordered from highest to lowest severity."""

from __future__ import annotations

import html
import json
import pathlib
import re
import shutil
import textwrap
import urllib.parse
from datetime import datetime, timezone

from . import __version__
from .i18n import to_en
from .i18n.bidi import iso, isolate, wrap_runs
from .i18n.plural import FILES_SCANNED, FINDINGS, PAGES_SCANNED, REQUESTS, ar_count
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
    """The terminal report. ``web``: the ``web`` object of a web scan (:func:`web_section`): the header counts pages
    and requests, and the summary adds the inconclusive-scan warning, what each grade was limited by, the checks that
    did not run grouped by reason and the comparison with the previous scan. Text from a scanned site never carries
    control characters or ANSI escape sequences to the terminal; web lines are wrapped to the terminal width."""
    L = _Lang(lang)
    web = web if _web_ok(web) else None
    findings = sort_findings(findings)
    counts = summary_counts(findings)
    c = (lambda s, t: f"{COLORS[s]}{t}{RESET}") if color else (lambda s, t: t)
    if web:
        return _console_web(findings, target, files, notes, L, web, counts, c)
    lines = [f"Kashif — {target}  ({_scanned(L, files, len(findings))})", ""]
    lines.append(L("summary"))
    for s in SEVERITIES:
        if L.en:
            lines.append(f"  {c(s, s.upper().ljust(9))} {counts[s]}")
        else:
            lines.append(f"  {c(s, SEVERITY_AR[s].rjust(9))}  {s.upper():<8} {counts[s]}")
    for n in notes:
        lines.append(f"  ℹ {_note(L, n, web)}")
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
            lines.append(f"  {BADGE[f.severity]} {f.rule_id}{cwe} {clean_text(_web_title(L, f), 300)}{conf}")
            lines.append(f"     📄 {clean_text(loc, 300)}")
            if f.snippet:
                lines.append(f"     ▸ {clean_text(L.text(f.snippet), 140)}")
            lines.append(f"     💡 {clean_text(_web_advice(L, f), 2000)}")
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
    md = [f"# {L('md_title')} — `{_md_code(target, 500) if web else target}`", ""]
    if web:                                        # a web scan counts pages and requests, not files
        banner = _inconclusive(web, findings, L)
        if banner:
            md += [f"> ⚠ **{_md_cell(banner['text'], 600)}**", ""]
        md += [f"- {L('date')}: {meta['generated_at']}", f"- {_md_cell(_web_scanned(L, files, web.get('requests')), 200)}",
               f"- {L('total')}: {len(findings)}", ""]
    else:
        md += [f"- {L('date')}: {meta['generated_at']}", f"- {L('files')}: {files}", f"- {L('total')}: {len(findings)}",
               ""]
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
                name = _md_cell(_title_en(f) if L.en else f.title_ar, 300)
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
            md.append(f"#### {_md_cell(_web_title(L, f), 300)}")
            md.append(f"- {L('rule')}: `{f.rule_id}`{cwe} · {L('source')}: web"
                      + (f" · {_wl(L, 'confidence')}: {_wl(L, 'c_' + _conf(f))}" if _conf(f) else ""))
            md.append(f"- {L('location')}: `{_md_code(loc, 300)}`")
            if f.snippet:
                md.append(f"- {L('snippet')}: `{_md_code(L.text(f.snippet), 160)}`")
            md.append(f"- {L('fix')}: {_md_cell(_web_advice(L, f), 2000)}")
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


def _sarif_scope(files: int, web: dict | None) -> dict:
    """What was scanned: files for a code scan; pages and requests for a web scan (a web scan has no files)."""
    if _web_ok(web):
        req = web.get("requests")
        return {"pagesScanned": files, "requests": req if isinstance(req, int) and not isinstance(req, bool) else 0}
    return {"filesScanned": files}


def _sarif_web_rule_text(f: Finding, title_en: str, advice_en: str) -> dict:
    """shortDescription / fullDescription / help of a web rule from the rule registry (webscan/rules.py): the rule's
    plain name, its generic remediation, its CWE and the WSTG / ASVS references of Kashif's analyst mapping."""
    try:
        from .webscan.rules import RULES as WEB_RULES
    except ImportError:                                          # pragma: no cover
        WEB_RULES = {}
    meta = WEB_RULES.get(f.rule_id)
    if meta is None:
        return {"help": {"text": advice_en, "markdown": _help_markdown(title_en, advice_en, f.cwe)}}
    name = meta.name_en or title_en
    generic = meta.advice_en if "{" not in meta.advice_en else advice_en     # a template needs this finding's values
    refs = [("WSTG", meta.wstg), ("ASVS 4.0", meta.asvs4), ("ASVS 5.0", meta.asvs5)]
    text = f"{name}. Remediation: {generic}" + (f" Weakness: {meta.cwe}." if meta.cwe else "")
    md = [f"**{name}**", "", f"**Remediation:** {generic}"]
    if meta.cwe:
        md += ["", f"Weakness: {_cwe_link(meta.cwe)}"]
    for label, ids in refs:
        if ids:
            text += f" {label}: {', '.join(ids)}."
            md += ["", f"{label}: {', '.join(ids)}"]
    return {"shortDescription": {"text": name}, "fullDescription": {"text": f"{name}. {generic}"},
            "help": {"text": text, "markdown": "\n".join(md).strip() + "\n"}}


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
            title_en = _title_en(f)
            advice_en = _advice_en(f)
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
            if f.source == "web":
                # a web rule's help is the registry's explanation; no helpUri: the README has no anchor per web rule
                # and a scanned page is not documentation (spec §0.2: no new links to the project's repository)
                rule.pop("helpUri")
                rule.update(_sarif_web_rule_text(f, title_en, advice_en))
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
            "message": {"text": f"{_title_en(f)}: {to_en(f.snippet or '')}".strip(": ") or f.rule_id},
            "locations": [{"physicalLocation": phys}],
            "partialFingerprints": {"vulnscan/v1": f.fingerprint()},
            "properties": ({"severity": f.severity, "advice": _advice_en(f)} if en_only else
                           {"severity": f.severity, "title_ar": f.title_ar, "advice": _advice_en(f),
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
            "properties": ({"target": target, **_sarif_scope(files, web), "notes": _notes_en(notes, web)} if en_only else
                           {"target": target, **_sarif_scope(files, web), "notes": notes,
                            "notes_en": _notes_en(notes, web)}),
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
    "g_algorithm": ("الخوارزمية", "Algorithm"), "g_grade": ("الدرجة", "Grade"), "g_score": ("النقاط", "Score"),
    "g_details": ("التفاصيل", "Details"),
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
    # 1.1.0 report layout
    "w_target": ("الهدف", "Target"), "w_scanned_at": ("تاريخ الفحص", "Scanned at"),
    "w_findings": ("النتائج", "Findings"),
    "b_title": ("الفحص غير حاسم", "Scan inconclusive"),
    "b_text": ("تعذّر إجراء {n} من أصل {total}", "{n} of {total} checks could not run"),
    "b_clean": ("هذه ليست نتيجة نظيفة.", "This is not a clean result."),
    "b_grade": ("لم تُحسب درجة كاشِف", "no Kashif grade was computed"),
    "tiles_muted": ("تشمل هذه الأعداد الفحوص التي أُجريت فقط؛ ولا يُعدّ ما لم يُجرَ منها ناجحًا.",
                    "These counts cover only the checks that ran; a check that could not run is not counted as passed."),
    "gw_a": ("جيدة", "good"), "gw_b": ("مقبولة", "fair"), "gw_c": ("ضعيفة", "weak"), "gw_d": ("ضعيفة جدًا", "poor"),
    "gw_f": ("راسبة", "failing"), "gw_n": ("بلا درجة", "not graded"),
    "g_limited": ("حُدّت الدرجة عند {cap} بسبب", "grade limited to {cap} by"),
    "g_base_bonus": ("النقاط {score} (الأساس {base} ومكافأة {bonus})", "base {base} + bonus {bonus} = {score}"),
    "g_score_only": ("النقاط {score}", "score {score}"),
    "g_families": ("مجموعات درجة كاشِف", "Kashif grade families"), "g_family": ("المجموعة", "Family"),
    "g_weight": ("الوزن", "Weight"), "g_fscore": ("النقاط", "Score"), "g_state": ("الحالة", "State"),
    "g_deductions": ("الخصومات", "Deductions"),
    "fs_tested": ("مُختبَرة", "tested"), "fs_not_applicable": ("غير منطبقة", "not applicable"),
    "fs_untested": ("لم تُختبر", "not tested"),
    "g_obs_tests": ("اختبارات Observatory", "Observatory tests"), "g_test": ("الاختبار", "Test"),
    "g_result": ("النتيجة", "Result"), "g_modifier": ("التعديل", "Modifier"), "g_pass": ("ناجح", "Pass"),
    "g_not_computed": ("لم يُحسب", "not computed"),
    "cov_checks": ("الفحوص", "Checks"), "and_more": ("و{n} غيرها", "and {n} more"),
    "v_good": ("جيدة", "good"), "v_weak": ("ضعيفة", "weak"), "v_missing": ("مفقودة", "missing"),
    "v_ignored": ("مُهمَلة", "ignored"), "v_unset": ("غير مضبوطة", "not set"), "h_seen": ("رُصدت في", "Seen in"),
    "ev": ("الدليل", "Evidence"), "ev_request": ("الطلب", "Request"), "ev_chain": ("سلسلة التوجيه", "Redirect chain"),
    "ev_status": ("حالة الاستجابة", "Status"), "ev_headers": ("ترويسات الاستجابة", "Response headers"),
    "ev_match": ("القيمة المطابقة", "Matched value"), "ev_curl": ("لإعادة الطلب", "Reproduce"),
    "ev_observed": ("وقت الرصد", "Observed at"), "ev_instances": ("عدد المواضع", "Instances"),
    "ev_systemic": ("نمطي على مستوى الموقع", "site-wide (systemic)"), "ev_examples": ("أمثلة", "Examples"),
    "ev_tags": ("مراجع الاختبار", "Testing references"), "ev_notes": ("ملاحظات", "Notes"), "ev_tls": ("TLS", "TLS"),
    "ev_pages": ("+{n} صفحات", "+{n} pages"),
    "rem_link": ("إصلاح جاهز للنسخ ↓", "Copy-paste fix ↓"), "rem_fixes": ("يعالج", "Fixes"),
    "c_new": ("جديد", "NEW"), "c_more": ("… و{n} غيرها", "… and {n} more"),
    "c_copy": ("إصلاحات جاهزة للنسخ: -f html", "copy-paste fixes: -f html"),
    "nt_title": ("فحوص لم تُجرَ", "Not tested"),
    "nt_choice": ("لم تُجرَ بحسب الإعدادات المختارة", "Not run with the chosen settings"),
    "nt_settings": ("نمط الفحص {profile}، الحساسية {sensitivity}", "profile {profile}, sensitivity {sensitivity}"),
    "nt_family": ("في مجموعة {family}", "{family}"),
    "d_grades_same": ("الدرجات لم تتغير", "grades unchanged"),
    "d_baseline": ("لا يوجد فحص سابق لهذا الهدف؛ وسيكون هذا الفحص أساس المقارنة في الفحوص القادمة.",
                   "No previous scan of this target; this one becomes the baseline for the next comparisons."),
    "d_not_retested": ("لم يُعَد فحصها", "Not re-checked"),
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
    # Strict-Transport-Security, Content-Security-Policy and X-Frame-Options rows (webscan/headers.py verdict tokens)
    "ok": "سليمة", "short-max-age": "مدة max-age أقل من سنة", "disabled": "معطَّلة (max-age=0)",
    "enforced": "مفروضة", "meta": "في وسم meta فقط", "report-only": "للتقرير فقط (report-only)",
    "frame-ancestors": "عبر frame-ancestors",
}


def _inv(L: "_Lang", token) -> str:
    """An inventory token in the report language (Arabic name when one is known, else the token as recorded)."""
    text = clean_text(token, 80)
    return text if L.en else _INV_AR.get(text, text)


def _bidi_html(L: "_Lang", text) -> str:
    """Escaped engine text for an Arabic page with every Latin run isolated left-to-right, by the one shared rule of
    ``vulnscan/i18n/bidi.py`` (the UI's ``bidiHtml()`` runs the same pattern): without it ``SameSite=Lax`` inside an
    Arabic sentence displays as ``Lax=SameSite``, ``base-uri 'none'`` as ``'none' base-uri`` and "A+" as "+A".
    Every piece is HTML-escaped; English pages (and text without Arabic) are only escaped."""
    text = "" if text is None else str(text)
    if L.en:
        return html.escape(text)
    # a short run stays on one line in a table cell (td bdi[dir='ltr']); a long one (a URL, a CSP or cookie value)
    # is marked "lr" and may wrap, or one nowrap URL would widen the whole findings table past the page
    return wrap_runs(text, lambda run: f"<bdi dir='ltr'{'' if _short_run(html.unescape(run)) else _LONG_RUN}>{run}</bdi>",
                     html.escape)


_LONG_RUN = " class='lr'"


def _short_run(run: str) -> bool:
    """A run short enough to keep on one line in a table cell: one token up to 32 characters, or a few words up to
    20 ("base-uri 'none'", "SSL Labs A+"); "X-Content-Type-Options: nosniff" may wrap at its space."""
    return len(run) <= (20 if " " in run else 32)


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


def web_section(result, *, sensitivity: str | None = None, compare_previous: bool | None = None) -> dict:
    """The ``web`` object of the JSON report (and of a saved UI scan) from a ``webscan.types.WebScanResult``.

    Keys: ``schema``, ``profile``, ``sensitivity``, ``target``, ``final_url``, ``requests``, ``bytes_received``,
    ``data_date``, ``grades`` (kashif / observatory / ssllabs, spec §3.4), ``coverage`` (one record per check:
    ``check``, ``rules``, ``state``, ``reason``, ``reasons`` [{code, en, ar}], ``hosts``), ``coverage_counts``,
    ``coverage_summary`` {en, ar}, ``inventory`` (§3.9), ``notes`` [{en, ar}], ``diff`` (§3.7, or None) and
    ``snapshot`` (what ``--compare FILE`` reads back). ``compare_previous``: whether a comparison with the previous
    scan was asked for (kept as ``compare_previous`` so the UI can say that a first scan becomes the baseline)."""
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
            "diff": getattr(result, "diff", None), "snapshot": getattr(result, "snapshot", None) or {},
            **({"compare_previous": bool(compare_previous)} if compare_previous is not None else {})}


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
    out["technologies"] = _technology_table(inv, L)
    rows = []
    tp = inv.get("third_parties") if isinstance(inv.get("third_parties"), dict) else {}
    for host, kinds in tp.items():
        rows.append([clean_text(host, 200), ("، " if not L.en else ", ").join(_inv(L, k) for k in kinds or [])[:120]
                     if isinstance(kinds, list) else clean_text(kinds, 120)])
    out["third_parties"] = ([_wl(L, "h_host"), _wl(L, "h_kind")], rows[:200])
    return out


def _technology_table(inv: dict, L: "_Lang") -> tuple[list[str], list[list[str]]]:
    """Technologies, JavaScript libraries and server banners as one table, one row per (name, version): one kind in
    the report language, where each was seen, and the known-vulnerabilities verdict of the library scan."""
    rows: dict[tuple[str, str], dict] = {}

    def row(name, version) -> dict | None:
        name, version = clean_text(name, 80), clean_text(version, 40)
        if not name:
            return None
        return rows.setdefault((name.lower(), version), {"name": name, "version": version, "kind": "", "seen": [],
                                                         "vulnerable": None})

    def seen(r: dict, where) -> None:
        where = clean_text(where, 120)
        if where and where not in r["seen"]:
            r["seen"].append(where)

    for t in inv.get("technologies") or []:
        if not isinstance(t, dict):
            continue
        r = row(t.get("name"), t.get("version"))
        if r is None:
            continue
        cats = [c for c in t.get("categories") or [] if isinstance(c, str)]
        if cats and not r["kind"]:
            r["kind"] = _inv(L, cats[0])
        for ev in t.get("evidence") or []:
            if isinstance(ev, dict) and ev.get("source"):
                src = _inv(L, ev["source"])
                seen(r, f"{src}: {ev['name']}" if ev.get("name") else src)
    for lib in inv.get("libraries") or []:
        if not isinstance(lib, dict):
            continue
        r = row(lib.get("name") or lib.get("component"), lib.get("version"))
        if r is None:
            continue
        if not r["kind"]:
            r["kind"] = _inv(L, "javascript-library")
        if lib.get("url"):
            try:
                path = urllib.parse.urlsplit(str(lib["url"])).path
            except ValueError:
                path = ""
            seen(r, path or lib["url"])
        if "vulnerable" in lib and r["vulnerable"] is not True:
            r["vulnerable"] = lib.get("vulnerable")
    for sw in inv.get("server_software") or []:
        if not isinstance(sw, dict):
            continue
        r = row(sw.get("name") or sw.get("product"), sw.get("version"))
        if r is None:
            continue
        seen(r, sw.get("where") or sw.get("source") or "")
    sep = ", " if L.en else "، "
    out = [[r["name"], r["version"], r["kind"], sep.join(r["seen"][:3]),
            _yn(L, r["vulnerable"]) if r["vulnerable"] is not None else ""] for r in rows.values()]
    return ([_wl(L, "h_name"), _wl(L, "h_version"), _wl(L, "h_kind"), _wl(L, "h_seen"), _wl(L, "h_vulnerable")],
            out[:200])


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
            "not_retested": [r for r in f.get("not_retested") or [] if isinstance(r, dict)],
            "new_fingerprints": [str(x) for x in d.get("new_fingerprints") or [] if isinstance(x, str)],
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


def _grade_changes(L: "_Lang", grades) -> list[str]:
    """The grade changes of a diff, only the grades that changed ("A → A" is not a change)."""
    out = []
    for k, v in (grades or {}).items() if isinstance(grades, dict) else []:
        if not isinstance(v, dict):
            continue
        before, after = v.get("before"), v.get("after")
        before = before.get("grade") if isinstance(before, dict) else before
        after = after.get("grade") if isinstance(after, dict) else after
        if v.get("changed") is False or (v.get("changed") is None and before == after):
            continue
        # the engine's own line when it has one: it also carries the scores ("Kashif: F* (59.69 → 65.94)")
        text = clean_text(_pair(L, v["text"]), 200) if isinstance(v.get("text"), dict) else _grade_change_text(L, k, v)
        if text:
            out.append(text)
    return out


# ------------------------------------------------------------------------------------------- web: shared


# Arabic count phrases of the web sections (five CLDR forms, see i18n/plural.py)
_CHECKS_AR = ("فحص واحد", "فحصان", "{n} فحوص", "{n} فحصًا", "{n} فحص")
_CHECKS_GEN_AR = ("فحص واحد", "فحصين", "{n} فحوص", "{n} فحصًا", "{n} فحص")       # object of «إجراء»
_D_COUNT_AR = {
    "new": ("نتيجة جديدة واحدة", "نتيجتان جديدتان", "{n} نتائج جديدة", "{n} نتيجةً جديدةً", "{n} نتيجة جديدة"),
    "resolved": ("نتيجة واحدة حُلّت", "نتيجتان حُلّتا", "{n} نتائج حُلّت", "{n} نتيجةً حُلّت", "{n} نتيجة حُلّت"),
    "unchanged": ("نتيجة واحدة لم تتغير", "نتيجتان لم تتغيرا", "{n} نتائج لم تتغير", "{n} نتيجةً لم تتغير",
                  "{n} نتيجة لم تتغير"),
    "not_retested": ("نتيجة واحدة لم يُعَد فحصها", "نتيجتان لم يُعَد فحصهما", "{n} نتائج لم يُعَد فحصها",
                     "{n} نتيجةً لم يُعَد فحصها", "{n} نتيجة لم يُعَد فحصها"),
}
_D_COUNT_EN = {"new": "{n} new", "resolved": "{n} resolved", "unchanged": "{n} unchanged",
               "not_retested": "{n} not re-checked"}
# reasons that are the user's own settings (profile, sensitivity, crawl, robots, third-party lookups), not limitations
_CHOICE_REASONS = frozenset({"profile", "deep_off", "crawl_off", "sensitivity", "third_party_off", "robots"})
_SEE_SNIPPET = re.compile(r"\s*[(（]\s*(?:see the snippet|انظر المقتطف)\s*[)）]", re.I)
_AR_MONTHS = ("يناير", "فبراير", "مارس", "أبريل", "مايو", "يونيو", "يوليو", "أغسطس", "سبتمبر", "أكتوبر", "نوفمبر",
              "ديسمبر")
_EN_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _web_title(L: "_Lang", f: Finding) -> str:
    """A web finding's title: the engine's own English (``title``, or ``extra.title_en``) in English, Arabic else."""
    en = f.extra.get("title_en") if isinstance(f.extra.get("title_en"), str) and f.extra.get("title_en") else f.title
    if L.en:
        return en or to_en(f.title_ar)
    if L.lang == "ar":
        return f.title_ar or en
    return f"{f.title_ar} — {en}"


def _web_advice(L: "_Lang", f: Finding) -> str:
    """A web finding's advice: the engine's own English (``extra.advice_en``) in English, else the Arabic advice."""
    if L.en:
        en = f.extra.get("advice_en")
        return en if isinstance(en, str) and en else to_en(f.advice or "")
    return f.advice or ""


def _title_en(f: Finding) -> str:
    en = f.extra.get("title_en") if f.source == "web" else None
    return en if isinstance(en, str) and en else (f.title or to_en(f.title_ar) or f.rule_id)


def _advice_en(f: Finding) -> str:
    en = f.extra.get("advice_en") if f.source == "web" else None
    return en if isinstance(en, str) and en else to_en(f.advice or "")


def _web_scanned(L: "_Lang", pages, requests, n: int | None = None) -> str:
    """"1 page scanned · 5 requests[, 3 findings]" with nouns that agree with their numbers."""
    try:
        pages = int(pages or 0)
    except (TypeError, ValueError):
        pages = 0
    try:
        requests = int(requests or 0)
    except (TypeError, ValueError):
        requests = 0
    if L.en:
        out = f"{pages} page{'' if pages == 1 else 's'} scanned · {requests} request{'' if requests == 1 else 's'}"
        return out + (f", {n} finding{'' if n == 1 else 's'}" if n is not None else "")
    out = f"{ar_count(pages, PAGES_SCANNED)} · {ar_count(requests, REQUESTS)}"
    return out + (f"، {ar_count(n, FINDINGS)}" if n is not None else "")


def _cnt_checks(L: "_Lang", n: int, genitive: bool = False) -> str:
    if L.en:
        return f"{n} check{'' if n == 1 else 's'}"
    return ar_count(n, _CHECKS_GEN_AR if genitive else _CHECKS_AR)


def _rule_name(L: "_Lang", rid: str) -> str:
    """The registry's plain title of a web rule (coverage, links), or the id itself."""
    try:
        from .webscan.rules import RULES as WEB_RULES
    except ImportError:                                          # pragma: no cover
        return rid
    meta = WEB_RULES.get(rid)
    return (meta.name_en if L.en else meta.name_ar) if meta is not None else rid


def _local_date(L: "_Lang", stamp: str) -> str:
    """An ISO timestamp as "14 Nov 2026, 01:55 UTC" / "14 نوفمبر 2026، 01:55 UTC" (the input when unreadable)."""
    try:
        dt = datetime.fromisoformat(str(stamp).replace("Z", "+00:00")).astimezone(timezone.utc)
    except (TypeError, ValueError):
        return clean_text(stamp, 40)
    if L.en:
        return f"{dt.day} {_EN_MONTHS[dt.month - 1]} {dt.year}, {dt:%H:%M} UTC"
    return f"{dt.day} {_AR_MONTHS[dt.month - 1]} {dt.year}، {dt:%H:%M} UTC"


def _reason_code(r: dict) -> str:
    return str(r.get("code") or "") if isinstance(r, dict) else ""


def _is_limitation(c: dict) -> bool:
    """A check that could not run because of this run's conditions (WAF, rate limit, budget, HTTP only …), not
    because of the chosen profile or sensitivity."""
    if c.get("state") == "inconclusive":
        return True
    if c.get("state") != "not_tested":
        return False
    try:
        from .webscan.coverage import REASONS
    except ImportError:                                          # pragma: no cover
        REASONS = {}
    codes = [_reason_code(r) for r in c.get("reasons") or [] if isinstance(r, dict)] or ["not_run"]
    return any(not (code in _CHOICE_REASONS or (code in REASONS and REASONS[code][2])) for code in codes)


def _inconclusive(web: dict, findings: list[Finding], L: "_Lang") -> dict | None:
    """The inconclusive-scan warning: {n, total, reasons, text} when the Kashif grade is "?", WEB990 was raised or
    more than a quarter of the checks did not run (inconclusive + not tested); None for a conclusive scan."""
    counts = _coverage_counts(web)
    total = sum(counts.values())
    g = web.get("grades") if isinstance(web.get("grades"), dict) else {}
    kashif = g.get("kashif") if isinstance(g.get("kashif"), dict) else {}
    no_grade = str(kashif.get("grade") or "").startswith("?")
    waf = any(f.rule_id == "WEB990" for f in findings)
    missing = counts["inconclusive"] + counts["not_tested"]
    if not (no_grade or waf or (total and missing / total > 0.25)):
        return None
    limited = [c for c in web.get("coverage") or [] if isinstance(c, dict) and _is_limitation(c)]
    n = len(limited) or missing
    reasons: dict[str, int] = {}
    for c in limited:
        for r in c.get("reasons") or []:
            if isinstance(r, dict) and _reason_code(r) not in _CHOICE_REASONS:
                text = clean_text(_pair(L, r), 160)
                if text:
                    reasons[text] = reasons.get(text, 0) + 1
    generic = {clean_text(_pair(L, {"en": "the check did not run", "ar": "لم يُجرَ هذا الفحص"}), 160)}
    ranked = [t for t, _n in sorted(reasons.items(), key=lambda kv: -kv[1])]
    top = ([t for t in ranked if t not in generic] or ranked)[:2]
    if L.en:
        head = f"{_wl(L, 'b_title')}: {_wl(L, 'b_text').format(n=n, total=total)}"
    else:
        head = f"{_wl(L, 'b_title')}: تعذّر إجراء {_cnt_checks(L, n, genitive=True)} من أصل {total}"
    why = ("; " if L.en else "؛ ").join(top)
    if no_grade and not why:
        why = _wl(L, "b_grade")
    text = head + (f" — {why}" if why else "") + ". " + _wl(L, "b_clean")
    return {"n": n, "total": total, "reasons": top, "text": text, "no_grade": no_grade}


def _coverage_groups(web: dict, L: "_Lang", states=("not_tested", "inconclusive", "fail")) -> list[dict]:
    """The checks that did not pass, grouped by (state, reason): [{state, state_label, reason, codes, choice,
    checks [{id, title}]}], inconclusive and not tested first, the largest groups first within a state."""
    groups: dict[tuple[str, str], dict] = {}
    for c in web.get("coverage") or []:
        if not isinstance(c, dict) or c.get("state") not in states:
            continue
        state = str(c.get("state"))
        reasons = [r for r in c.get("reasons") or [] if isinstance(r, dict)]
        text = ("; " if L.en else "؛ ").join(t for t in (clean_text(_pair(L, r), 200) for r in reasons) if t)
        codes = [_reason_code(r) for r in reasons]
        g = groups.setdefault((state, text), {"state": state, "state_label": _wl(L, "s_" + state), "reason": text,
                                              "codes": codes, "choice": bool(codes) and all(
                                                  x in _CHOICE_REASONS for x in codes), "checks": []})
        cid = clean_text(c.get("check"), 60)
        g["checks"].append({"id": cid, "title": clean_text(_rule_name(L, cid), 200)})
    order = {"inconclusive": 0, "not_tested": 1, "fail": 2}
    return sorted(groups.values(), key=lambda g: (order.get(g["state"], 3), g["choice"], -len(g["checks"])))


def _families_of(L: "_Lang", web: dict, checks: list[str]) -> str:
    """The grade families ("TLS", "Transport & HSTS") of some checks, in the report language."""
    try:
        from .webscan.rules import RULES as WEB_RULES
    except ImportError:                                          # pragma: no cover
        return ""
    fams = (((web.get("grades") or {}).get("kashif") or {}).get("families") or {}) if isinstance(web.get("grades"),
                                                                                                   dict) else {}
    names: list[str] = []
    for cid in checks:
        meta = WEB_RULES.get(cid)
        fam = meta.grade_family if meta is not None else ""
        name = _pair(L, (fams.get(fam) or {}).get("name")) if isinstance(fams.get(fam), dict) else ""
        if name and name not in names:
            names.append(name)
    return (", " if L.en else "، ").join(names[:3]) if len(names) <= 3 else ""


def _grade_class(grade) -> str:
    g = str(grade or "").strip().upper()
    if not g or g.startswith("?"):
        return "n"
    first = g[0]
    return {"A": "a", "B": "b", "C": "c", "D": "d", "E": "d", "F": "f", "T": "f", "M": "f"}.get(first, "n")


def _grade_detail(web: dict, L: "_Lang", key: str) -> dict:
    """Score text, binding cap and the cap texts of one algorithm: {score_text, binding: {cap, rules, texts},
    caps [{cap, rule, text}], notes [text]}."""
    g = web.get("grades") if isinstance(web.get("grades"), dict) else {}
    d = g.get(key) if isinstance(g.get(key), dict) else {}
    out: dict = {"score_text": "", "binding": None, "caps": [], "notes": [clean_text(_pair(L, n), 300) for n in
                                                                           d.get("notes") or [] if isinstance(n, dict)]}
    num = lambda v: v if isinstance(v, (int, float)) and not isinstance(v, bool) else None   # noqa: E731
    score = num(d.get("score"))
    if key == "kashif" and score is not None:
        base = num(d.get("base"))
        bonus = num((d.get("bonus") or {}).get("total")) if isinstance(d.get("bonus"), dict) else None
        if base is not None and bonus:
            out["score_text"] = _wl(L, "g_base_bonus").format(base=round(base), bonus=round(bonus), score=round(score))
        else:
            out["score_text"] = _wl(L, "g_score_only").format(score=round(score))
    elif score is not None:
        mx = num(d.get("max_score"))
        out["score_text"] = f"{score:g}" + (f"/{mx:g}" if mx else "")
    caps = [c for c in d.get("caps") or [] if isinstance(c, dict)]
    out["caps"] = [{"cap": clean_text(c.get("cap"), 4), "rule": clean_text(c.get("rule"), 60),
                    "text": clean_text(_pair(L, c), 300)} for c in caps]
    letter = str(d.get("letter") or d.get("grade") or "").rstrip("*")
    if key == "kashif" and score is not None and letter and caps:
        try:
            from .webscan.grade import LETTERS, letter_for
            by_score = letter_for(float(score))
            binding = [c for c in out["caps"] if c["cap"] == letter]
            if binding and letter in LETTERS and by_score in LETTERS and LETTERS.index(by_score) < LETTERS.index(letter):
                out["binding"] = {"cap": letter, "rules": [c["rule"] for c in binding if c["rule"]],
                                  "all_rules": [c["rule"] for c in binding], "texts": [c["text"] for c in binding]}
        except ImportError:                                      # pragma: no cover
            pass
    return out


# ------------------------------------------------------------------------------------------- web: console


def _term_width() -> int:
    try:
        cols = shutil.get_terminal_size((100, 24)).columns
    except (OSError, ValueError):
        cols = 100
    return max(60, min(int(cols or 100), 160))


def _con(L: "_Lang", text: str) -> str:
    """A console line in the report language: Latin runs of Arabic text isolated (grades, URLs, headers, ids)."""
    return text if L.en else isolate(text)


def _wrapped(L: "_Lang", text, first: str, width: int, indent: int = 8, limit: int = 2000) -> list[str]:
    """Untrusted text wrapped to the terminal width: ``first`` before the first line, a hanging indent of ``indent``
    spaces before the others. Each Arabic line is isolated after wrapping (an isolate never spans two lines)."""
    text = clean_text(text, limit)
    if not text:
        return []
    parts = textwrap.wrap(text, width=max(30, width - indent), break_long_words=False, break_on_hyphens=False) or [text]
    return [(first if i == 0 else " " * indent) + _con(L, part) for i, part in enumerate(parts)]


def _new_keys(dp: dict | None) -> set[str]:
    if not dp or not dp.get("comparable"):
        return set()
    keys = set(dp.get("new_fingerprints") or [])
    for r in dp.get("new") or []:
        keys.update(str(r.get(k)) for k in ("fingerprint", "key") if r.get(k))
    return keys


def _is_new(f: Finding, keys: set[str]) -> bool:
    if not keys:
        return False
    try:
        fp = f.fingerprint()
    except Exception:  # noqa: BLE001 - a malformed finding is simply not marked
        fp = ""
    return fp in keys or str(f.extra.get("fp_key") or "") in keys


def _d_count(L: "_Lang", key: str, n: int) -> str:
    return _D_COUNT_EN[key].format(n=n) if L.en else ar_count(n, _D_COUNT_AR[key])


def _sev_word(L: "_Lang", sev) -> str:
    return (str(sev).upper() if L.en else SEVERITY_AR[sev]) if sev in SEVERITY_AR else "?"


def _more(L: "_Lang", n: int) -> str:
    return _wl(L, "c_more").format(n=n)


def _diff_console(dp: dict, L: "_Lang", width: int) -> list[str]:
    head = f"  ⇄ {_wl(L, 'diff')}"
    prev = dp.get("previous") or {}
    when = _local_date(L, prev["scanned_at"]) if prev.get("scanned_at") else ""
    extra = [x for x in (when, clean_text(prev.get("profile"), 20)) if x]
    if extra:
        head += f" ({(', ' if L.en else '، ').join(extra)})"
    lines = [_con(L, head)]
    for n in dp.get("notes") or []:
        lines += _wrapped(L, _pair(L, n), "     ℹ ", width, 7, 400)
    if not dp.get("comparable"):
        return lines
    parts = [_d_count(L, k, len(dp.get(k) or [])) for k in ("new", "resolved", "unchanged", "not_retested")]
    changes = _grade_changes(L, dp.get("grades"))
    parts += changes or [_wl(L, "d_grades_same")]
    lines += _wrapped(L, " · ".join(parts), "     ", width, 7, 1000)
    for sign, key in (("+", "new"), ("−", "resolved")):
        rows = dp.get(key) or []
        for r in rows[:10]:
            rule, title = clean_text(r.get("rule"), 60), _row_title(L, r)
            # Arabic: the id after the title and a "·" between them: "WEB204 base-uri" or "base-uri 'none' (WEB204)"
            # would read as one left-to-right run (the shared rule stops a run at "·", not at "(")
            text = (f"{_sev_word(L, r.get('severity'))} {rule} {title}" if L.en else
                    f"{_sev_word(L, r.get('severity'))}: {title} · {rule}")
            lines += _wrapped(L, text, f"     {sign} ", width, 7, 300)
        if len(rows) > 10:
            lines.append("       " + _con(L, _more(L, len(rows) - 10)))
    for sign, direction in (("↓", "regression"), ("↑", "improvement")):
        items = [p for p in dp.get("posture") or [] if p.get("direction") == direction]
        for p in items[:5]:
            lines += _wrapped(L, _pair(L, p), f"     {sign} ", width, 7, 300)
        if len(items) > 5:
            lines.append("       " + _con(L, _more(L, len(items) - 5)))
    return lines


def _grades_console(web: dict, L: "_Lang", width: int) -> list[str]:
    """One "★" line per algorithm that has something to explain: the binding cap, why it is provisional or
    ungraded, Observatory's "partial" or WAF qualifier."""
    lines = []
    for g in _grade_rows(web, L):
        det = _grade_detail(web, L, g["key"])
        why = []
        if det["binding"]:
            why.append(f"{_wl(L, 'g_limited').format(cap=det['binding']['cap'])}: "
                       + ("; " if L.en else "؛ ").join(det["binding"]["texts"]))
        why += det["notes"][:3]
        if not why:
            continue
        name = {"kashif": "Kashif" if L.en else "كاشِف", "observatory": "Observatory",
                "ssllabs": "SSL Labs-compatible" if L.en else "درجة SSL Labs المتوافقة"}[g["key"]]
        grade = g["grade"]
        if g["key"] == "observatory" and g["score"] is not None and g["grade"]:
            grade = f"{g['score']:g} ({g['grade']})"
        lines += _wrapped(L, f"{name}{' ' + grade if grade else ''}: " + ("; " if L.en else "؛ ").join(why), "  ★ ",
                          width, 4, 900)
    return lines


def _not_tested_console(web: dict, L: "_Lang", width: int) -> list[str]:
    groups = _coverage_groups(web, L, states=("not_tested", "inconclusive"))
    if not groups:
        return []
    lines = [_con(L, f"  {_wl(L, 'nt_title')}:")]
    choice = [g for g in groups if g["choice"]]
    for g in groups:
        if g["choice"]:
            continue
        ids = [c["id"] for c in g["checks"]]
        fam = _families_of(L, web, ids)
        shown = (", " if L.en else "، ").join(ids[:2]) + ("…" if len(ids) > 2 else "")
        state = "" if g["state"] == "not_tested" else f" [{g['state_label']}]"
        if L.en:
            what = f"{len(ids)} {fam + ' ' if fam else ''}check{'' if len(ids) == 1 else 's'}{state} ({shown})"
        else:   # the ids before the family name: "TLS (WEB030" would be one left-to-right run
            what = f"{_cnt_checks(L, len(ids))} ({shown})" + (f" {_wl(L, 'nt_family').format(family=fam)}" if fam
                                                               else "") + state
        lines += _wrapped(L, f"{what}: {g['reason'] or g['state_label']}", "    ⊘ ", width, 6, 400)
    if choice:
        settings = _wl(L, "nt_settings").format(profile=clean_text(web.get("profile"), 20) or "?",
                                                sensitivity=clean_text(web.get("sensitivity"), 20) or "default")
        parts = [f"{_cnt_checks(L, len(g['checks']))} — {g['reason']}" for g in choice]
        lines += _wrapped(L, f"{_wl(L, 'nt_choice')}: " + " · ".join(parts) + f" ({settings})", "    ◌ ", width, 6,
                          600)
    return lines


def _console_web(findings: list[Finding], target: str, files: int, notes: list[str], L: "_Lang", web: dict,
                 counts: dict, c) -> str:
    width = _term_width()
    head = _web_scanned(L, files, web.get("requests"), len(findings))
    lines = [f"Kashif — {clean_text(target, 500)}  ({_con(L, head)})", ""]
    banner = _inconclusive(web, findings, L)
    if banner:
        lines += _wrapped(L, banner["text"], "⚠ ", width, 2, 600) + [""]
    lines.append(L("summary"))
    for s in SEVERITIES:
        if L.en:
            lines.append(f"  {c(s, s.upper().ljust(9))} {counts[s]}")
        else:
            lines.append(f"  {c(s, SEVERITY_AR[s].rjust(9))}  {s.upper():<8} {counts[s]}")
    shown = set()
    for n in notes:
        text = _note(L, n, web)
        if _is_id_list_note(web, n):
            continue                                  # the "Not tested" block below says it by reason
        shown.add(text)
        lines += _wrapped(L, text, "  ℹ ", width, 4, 2000)
    inv = web.get("inventory") if isinstance(web.get("inventory"), dict) else {}
    hidden = inv.get("hidden_by_sensitivity") if isinstance(inv.get("hidden_by_sensitivity"), dict) else {}
    hidden_text = clean_text(_pair(L, hidden), 600) if hidden.get("en") or hidden.get("ar") else ""
    if hidden_text and hidden_text not in shown:
        lines += _wrapped(L, hidden_text, "  ◌ ", width, 4, 600)
    lines += _grades_console(web, L, width)
    lines += _not_tested_console(web, L, width)
    dp = _diff_parts(web)
    if dp:
        lines += _diff_console(dp, L, width)
    lines.append("")
    if not findings:
        lines.append(L("none"))
        return "\n".join(lines)
    new = _new_keys(dp)
    snippet_titles = _snippet_titles(findings, web, L)
    current = None
    for f in findings:
        if f.severity != current:
            current = f.severity
            lines.append(c(current, f"━━ {L.sev_pair(current)} ({counts[current]}) ━━"))
        lines += _console_finding(f, L, width, new, snippet_titles, web)
    return "\n".join(lines)


def _is_id_list_note(web: dict, note: str) -> bool:
    """A scan note that is only a truncated list of check ids ("Not performed: WEB030, WEB070, …")."""
    for n in web.get("notes") or []:
        if isinstance(n, dict) and n.get("ar") == note:
            en = str(n.get("en") or "")
            return en.startswith(("Not performed: ", "Checks that could not run: "))
    return False


def _snippet_titles(findings: list[Finding], web: dict | None, L: "_Lang") -> dict[str, str]:
    """{snippet id: title} of the copy-paste fixes of these findings."""
    out = {}
    for sn in remediation_snippets(findings, web, L.lang):
        if isinstance(sn, dict) and sn.get("id"):
            out[str(sn["id"])] = clean_text(sn.get("title"), 200)
    return out


def _remediation_ids(f: Finding) -> list[str]:
    ids = f.extra.get("remediation")
    if isinstance(ids, str):
        ids = [ids]
    out = [str(x) for x in ids or [] if isinstance(x, str)]
    if not out:
        try:
            from .webscan.rules import RULES as WEB_RULES
            meta = WEB_RULES.get(f.rule_id)
            out = list(meta.fix) if meta is not None else []
        except ImportError:                                      # pragma: no cover
            out = []
    return out


def _url_line(L: "_Lang", f: Finding) -> str:
    """The page a web finding was seen on, with "+N pages" and the site-wide mark."""
    url = f.extra.get("url")
    if not url:
        ex = f.extra.get("examples")
        url = ex[0] if isinstance(ex, list) and ex else ""
    if not url:
        return ""
    bits = []
    pages = f.extra.get("page_count") or f.extra.get("instances")
    if isinstance(pages, int) and not isinstance(pages, bool) and pages > 1:
        bits.append(_more_pages(L, pages - 1))
    if f.extra.get("systemic") is True:
        bits.append(_wl(L, "ev_systemic"))
    return clean_text(url, 500) + (f" ({(', ' if L.en else '، ').join(bits)})" if bits else "")


def _more_pages(L: "_Lang", n: int) -> str:
    if L.en:
        return f"+{n} page{'' if n == 1 else 's'}"
    return "+" + ar_count(n, ("صفحة واحدة", "صفحتان", "{n} صفحات", "{n} صفحةً", "{n} صفحة"))


def _console_finding(f: Finding, L: "_Lang", width: int, new: set[str], snippet_titles: dict[str, str],
                     web: dict | None) -> list[str]:
    if f.source != "web":                          # a code finding in a web report: unchanged rendering
        loc = f"{f.file}:{f.line}" if f.line else f.file
        return [f"  {BADGE[f.severity]} {f.rule_id}{f' [{f.cwe}]' if f.cwe else ''} {L.title(f)}", f"     📄 {loc}",
                f"     💡 {L.text(f.advice)}"]
    conf = f" ({_wl(L, 'c_' + _conf(f))})" if _conf(f) else ""
    tag = f"{_wl(L, 'c_new')} " if _is_new(f, new) else ""
    cwe = f" [{f.cwe}]" if f.cwe else ""
    head = f"{f.rule_id}{cwe}"
    out = [f"  {BADGE[f.severity]} {tag}{head if L.en else iso(head)} "
           + _con(L, f"{clean_text(_web_title(L, f), 300)}{conf}")]
    url = _url_line(L, f)
    if url:
        out.append("     🔗 " + _con(L, url))
    else:
        out.append(f"     📄 {clean_text(f.file, 300)}")
    if f.rule_id in ("WEB991", "WEB990") and web:      # the reasons, not the truncated id list of the snippet
        state = "inconclusive" if f.rule_id == "WEB990" else "not_tested"
        groups = [g for g in _coverage_groups(web, L, states=(state,)) if not g["choice"]]
        for g in groups[:4]:
            out += _wrapped(L, f"{_cnt_checks(L, len(g['checks']))}: {g['reason'] or g['state_label']}", "     ▸ ",
                            width, 8, 300)
    elif f.snippet:
        out += _wrapped(L, L.text(f.snippet), "     ▸ ", width, 8, 300)
    notes = [n for n in f.extra.get("notes") or [] if isinstance(n, (dict, str))]
    if f.rule_id not in ("WEB991", "WEB990"):
        snippet = clean_text(L.text(f.snippet), 300)
        for n in [n for n in notes if clean_text(_pair(L, n), 300) != snippet][:2]:
            out += _wrapped(L, _pair(L, n), "     · ", width, 8, 200)
    advice = _web_advice(L, f)
    see = bool(_SEE_SNIPPET.search(advice))
    out += _wrapped(L, _SEE_SNIPPET.sub("", advice), "     💡 ", width, 8, 2000)
    if see:
        titles = [snippet_titles[i] for i in _remediation_ids(f) if i in snippet_titles]
        out.append("     🧩 " + _con(L, f"{clean_text(titles[0], 120) + ' — ' if titles else ''}{_wl(L, 'c_copy')}"))
    ev = f.extra.get("evidence") if isinstance(f.extra.get("evidence"), dict) else {}
    if ev.get("curl"):                              # one line: a wrapped command would not paste back
        out.append(f"     ↻ {clean_text(ev['curl'], 1000)}")
    return out


# ------------------------------------------------------------------------------------------- web: HTML


def render_html(findings: list[Finding], target: str, files: int, notes: list[str], lang: str = "both",
                web: dict | None = None) -> str:
    """The HTML report (one self-contained file, no script). ``web`` (:func:`web_section`) adds, under the title, the
    inconclusive-scan banner, the scan facts and the grades; then the coverage and the diff; the confidence column
    and the evidence of each finding; after the findings the inventory tabs and the copy-paste fixes with platform
    tabs. Arabic text is isolated run by run (``_bidi_html``); the page adapts to phones, dark mode and print."""
    L = _Lang(lang)
    web = web if _web_ok(web) else None
    show_conf = any(_conf(f) for f in findings)
    findings = sort_findings(findings)
    counts = summary_counts(findings)
    generated = _meta(target, files, notes)["generated_at"]
    snippets = remediation_snippets(findings, web, L.lang) if web else []
    snippet_ids = {str(sn.get("id")) for sn in snippets if isinstance(sn, dict)}
    anchored: set[str] = set()
    rows = [_html_row(f, L, show_conf, anchored, snippet_ids) for f in findings]
    e = (lambda s: html.escape(clean_text(s, 2000))) if web else html.escape
    banner = _inconclusive(web, findings, L) if web else None
    summary = "".join(f"<div class='tile {s}'><div class='n'>{counts[s]}</div><div>{e(L.sev(s))}"
                      + ("" if L.en else f"<br><small>{s}</small>") + "</div></div>"
                      for s in SEVERITIES)
    tiles = (f"<div class='tiles muted'>{summary}</div><p class='tcap'><small>{e(_wl(L, 'tiles_muted'))}</small></p>"
             if banner else f"<div class=\"tiles\">{summary}</div>")
    shown = [n for n in notes if not (web and _note_shown_elsewhere(web, n))]
    notes_html = "".join(f"<li>{_bidi_html(L, _note(L, n, web)) if web else e(_note(L, n, web))}</li>" for n in shown)
    empty = f"<tr><td colspan={6 if show_conf else 5}>{e(L('no_results'))}</td></tr>"
    conf_head = f"<th>{e(_wl(L, 'confidence'))}</th>" if show_conf else ""
    if web:
        head = _web_html_head(findings, web, L, target, files, generated, banner, anchored)
        facts = ""
    else:
        head = ""
        facts = (f"<p>{e(L('files'))}: {files} · {e(L('findings'))}: {len(findings)} · "
                 f"<bdi dir=\"ltr\">{e(generated)}</bdi></p>\n")
    web_top = _web_html(findings, web, L, "top", anchored) if web else ""
    web_bottom = _web_html_bottom(findings, web, L, snippets, anchored) if web else ""
    web_css = (_WEB_CSS + _TAB_CSS) if web else ""
    html_lang, html_dir, align = ("en", "ltr", "left") if L.en else ("ar", "rtl", "right")
    return f"""<!doctype html><html lang="{html_lang}" dir="{html_dir}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Kashif — {e(target)}</title>
<style>
{_TOKENS_CSS}
body{{font-family:system-ui,Segoe UI,Tahoma,sans-serif;margin:2rem;background:var(--bg);color:var(--fg)}}
a{{color:var(--link)}}
.tiles{{display:flex;gap:.75rem;flex-wrap:wrap;margin:1rem 0}}
.tile{{padding:.75rem 1.25rem;border-radius:.5rem;color:#fff;min-width:7rem;text-align:center}}
.tile .n{{font-size:2rem;font-weight:700}}
.tile.critical,.b.critical{{background:#7f1d1d}}.tile.high,.b.high{{background:#c2410c}}.tile.medium,.b.medium{{background:#a16207}}
.tile.low,.b.low{{background:#0e7490}}.tile.info,.b.info{{background:#52525b}}
.tiles.muted .tile{{background:#6b7280}}.tcap{{margin:-.5rem 0 1rem;color:var(--muted)}}
table{{border-collapse:collapse;width:100%;background:var(--card)}}
th,td{{border:1px solid var(--line);padding:.5rem;vertical-align:top;text-align:{align}}}
tr.critical td:first-child,tr.high td:first-child{{font-weight:700}}
.b{{padding:.15rem .5rem;border-radius:.25rem;color:#fff;white-space:nowrap}}
code{{direction:ltr;unicode-bidi:isolate;font-size:.85em;overflow-wrap:anywhere}}
bdi,code,.tw td{{overflow-wrap:anywhere;word-break:break-word}}
td bdi[dir='ltr']{{white-space:nowrap}}td bdi.lr{{white-space:normal}}
h1{{overflow-wrap:anywhere}}
.tw{{max-width:100%;overflow-x:auto}}
td{{min-width:5rem}}td.w{{min-width:12rem}}
@media (max-width:1000px){{td{{min-width:0}}td.w{{min-width:8rem}}}}
@media (max-width:640px){{body{{margin:1rem}}h1{{font-size:1.4rem}}.tile{{min-width:5rem;padding:.5rem .8rem}}
td bdi[dir='ltr']{{white-space:normal}}
.fd-h+.tw>table,.fd-h+.tw>table>tbody,.fd-h+.tw>table>tbody>tr,.fd-h+.tw>table>tbody>tr>td{{display:block;width:auto;min-width:0}}
.fd-h+.tw>table>thead{{display:none}}
.fd-h+.tw>table{{background:none}}
.fd-h+.tw>table>tbody>tr{{border:1px solid var(--line);border-radius:.5rem;margin:.75rem 0;background:var(--card);overflow:hidden}}
.fd-h+.tw>table>tbody>tr>td{{border:none;border-bottom:1px solid var(--line)}}
.fd-h+.tw>table>tbody>tr>td:last-child{{border-bottom:none}}
.fd-h+.tw>table>tbody>tr>td[data-label]::before{{content:attr(data-label);display:block;font-size:.75em;font-weight:600;color:var(--muted);margin-bottom:.15rem}}}}
.fix{{margin-top:.5rem}}.fix summary{{cursor:pointer;font-weight:600;color:var(--ok)}}
.diff{{direction:ltr;text-align:left;background:var(--code);padding:.5rem;overflow:auto;font-size:.8em;margin:.3rem 0 0}}
.diff span{{display:block}}.diff .add{{background:var(--add)}}.diff .del{{background:var(--del)}}
.flow{{margin:.4rem 0 0;padding-inline-start:1.2rem;font-size:.8em;color:var(--muted)}}
{web_css}
@media print{{
*{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
body{{margin:0;background:#fff}}
.tabs>label,.tabs>input{{display:none}}
.tabs>div.panel{{display:block!important;border:none;padding:0;overflow:visible}}
.ph{{display:block!important}}
details::details-content{{content-visibility:visible;display:contents}}
details>summary{{list-style:none}}
tr{{break-inside:avoid}}
.tw{{overflow:visible}}
td,td.w{{min-width:0}}th,td{{padding:.3rem}}.ev td.nw,.hdrs td.nw{{white-space:normal}}
.fd-h+.tw>table>tbody>tr>td:nth-child(-n+3){{overflow-wrap:normal;word-break:normal}}
}}
</style></head><body>
<h1>{e(L('md_title'))} — <code dir="ltr">{e(target)}</code></h1>
{head}{facts}<ul>{notes_html}</ul>
{tiles}
{web_top}
<h2 class="fd-h">{e(L('html_by_sev'))}</h2>
<div class="tw"><table><thead><tr><th>{e(L('sev_col'))}</th>{conf_head}<th>{e(L('col_rule'))}</th><th>{e(L('col_vuln'))}</th><th>{e(L('location'))}</th><th>{e(L('fix'))}</th></tr></thead>
<tbody>{''.join(rows) or empty}</tbody></table></div>
{web_bottom}
</body></html>"""


# Colour tokens: light by default, an AA-checked dark scheme (every text colour ≥ 4.5:1 on its background, measured
# with the WCAG formula), and light again for print
_LIGHT = ("--bg:#fafafa;--fg:#222;--card:#fff;--line:#ddd;--muted:#555;--link:#0e5a8a;--code:#f6f8fa;--add:#dcfce7;"
          "--del:#fee2e2;--ok:#166534;--warn:#92400e;--warnbg:#fff7ed;--bad:#991b1b;--accent:#0e7490;--hl:#fef9c3;"
          "--ga:#166534;--gb:#3f6212;--gc:#854d0e;--gd:#9a3412;--gf:#991b1b;--gn:#52525b")
_DARK = ("--bg:#111418;--fg:#e6e6e6;--card:#1b1f24;--line:#3a3f45;--muted:#b4bac1;--link:#7cc4f5;--code:#22272e;"
         "--add:#12361f;--del:#3d1717;--ok:#4ade80;--warn:#fbbf24;--warnbg:#2a1f0e;--bad:#f87171;--accent:#67e8f9;"
         "--hl:#3b3413;--ga:#4ade80;--gb:#a3e635;--gc:#facc15;--gd:#fb923c;--gf:#f87171;--gn:#a1a1aa")
_TOKENS_CSS = (f":root{{{_LIGHT};color-scheme:light dark}}\n"
               f"@media (prefers-color-scheme:dark){{:root{{{_DARK}}}}}\n"
               f"@media print{{:root{{{_LIGHT};color-scheme:light}}}}")


def _html_row(f: Finding, L: "_Lang", show_conf: bool, anchored: set[str], snippet_ids: set[str]) -> str:
    """One row of the findings table. Every text goes through ``_bidi_html`` (escaped; Latin runs of Arabic text
    isolated); a web finding's text can come from the scanned site, so it is also stripped of control characters."""
    web_f = f.source == "web"
    if web_f:
        e = lambda s: html.escape(clean_text(s, 2000))          # noqa: E731
        b = lambda s: _bidi_html(L, clean_text(s, 2000))         # noqa: E731
    else:
        e = html.escape
        b = lambda s: _bidi_html(L, s)                           # noqa: E731
    title = _web_title(L, f) if web_f else L.title(f)
    if L.en:
        title_html = f"<b>{e(title)}</b>"
    elif L.lang == "ar":
        title_html = f"<b>{b(f.title_ar or (_title_en(f) if web_f else f.title))}</b>"
    else:
        title_html = f"<b>{b(f.title_ar)}</b><br><small dir='ltr'>{e(_title_en(f) if web_f else f.title)}</small>"
    labels = {k: html.escape(L(k)) for k in ("sev_col", "col_rule", "col_vuln", "location", "fix")}
    rid = ""
    if web_f and f.rule_id not in anchored:          # the target of the coverage, grade-cap and fix links
        anchored.add(f.rule_id)
        rid = f" id='f-{html.escape(f.rule_id)}'"
    conf_cell = (f"<td data-label='{html.escape(_wl(L, 'confidence'))}'>{e(_wl(L, 'c_' + _conf(f))) if _conf(f) else ''}</td>"
                 if show_conf else "")
    steps = _steps(f)
    flow = ("<ol class='flow'>" + "".join(f"<li><code>{e(str(st.get('file', '')))}:{st.get('line', '')}</code> "
                                          f"<bdi>{b(L.text(st.get('text', '')))}</bdi></li>" for st in steps) + "</ol>"
            if steps else "")
    if web_f:
        loc = _html_web_location(f, L)
        advice = b(_SEE_SNIPPET.sub("", _web_advice(L, f))) + _html_copy_link(f, L, snippet_ids)
        evidence = _html_evidence(f, L)
    else:
        loc = f"<code>{e(f'{f.file}:{f.line}' if f.line else f.file)}</code>"
        advice = b(L.text(f.advice))
        evidence = ""
    snippet = f"<br><small dir='auto'>{b(L.text(f.snippet)[:140])}</small>" if (f.snippet or not web_f) else ""
    return (f"<tr class='{f.severity}'{rid}><td data-label='{labels['sev_col']}'><span class='b {f.severity}'>"
            f"{e(L.sev(f.severity))}</span></td>{conf_cell}"
            f"<td data-label='{labels['col_rule']}'><code>{e(f.rule_id)}</code><br><small>{e(f.cwe)}</small></td>"
            f"<td class='w' data-label='{labels['col_vuln']}'>{title_html}{evidence}</td>"
            f"<td class='w' data-label='{labels['location']}'>{loc}{snippet}{flow}</td>"
            f"<td class='w' data-label='{labels['fix']}'>{advice}{_fix_html(f, L)}</td></tr>")


def _first_url(f: Finding) -> str:
    ex = f.extra.get("examples")
    url = ex[0] if isinstance(ex, list) and ex and isinstance(ex[0], str) else f.extra.get("url") or ""
    return str(url)


def _html_web_location(f: Finding, L: "_Lang") -> str:
    """Host and the path of the first example URL (``/server-status``), with "+N pages" for a grouped finding."""
    e = html.escape
    out = f"<code>{e(clean_text(f.file, 300))}</code>"
    try:
        parts = urllib.parse.urlsplit(_first_url(f))
        path = parts.path + (f"?{parts.query}" if parts.query else "")
    except ValueError:
        path = ""
    if path and path != "/":
        out += f"<br><code dir='ltr'>{e(clean_text(path, 300))}</code>"
    pages = f.extra.get("page_count") or f.extra.get("instances")
    if isinstance(pages, int) and not isinstance(pages, bool) and pages > 1:
        out += f" <small class='nw'>{_bidi_html(L, _more_pages(L, pages - 1))}</small>"
    return out


def _html_copy_link(f: Finding, L: "_Lang", snippet_ids: set[str]) -> str:
    ids = [i for i in _remediation_ids(f) if i in snippet_ids]
    if not ids:
        return ""
    return f"<p class='cp'><a href='#rem-{html.escape(ids[0])}'>{html.escape(_wl(L, 'rem_link'))}</a></p>"


def _kv(L: "_Lang", key: str, value_html: str) -> str:
    return f"<div class='kv'><b>{html.escape(_wl(L, key))}:</b> {value_html}</div>"


def _html_evidence(f: Finding, L: "_Lang") -> str:
    """The evidence of a web finding, collapsed: request line, redirect chain, status, response headers (the matched
    one highlighted), the full matched value, a curl line to reproduce it, when it was observed, how many places
    share it (systemic or not), up to five example URLs, the finding's notes and its WSTG / ASVS references. Every
    value came from the scanned site: escaped and stripped of control characters."""
    e = lambda s, n=2000: html.escape(clean_text(s, n))          # noqa: E731
    ev = f.extra.get("evidence") if isinstance(f.extra.get("evidence"), dict) else {}
    parts: list[str] = []
    req = ev.get("request") if isinstance(ev.get("request"), dict) else {}
    if req.get("url"):
        parts.append(_kv(L, "ev_request", f"<code dir='ltr'>{e(req.get('method') or 'GET', 10)} {e(req['url'])}</code>"))
    chain = [h for h in ev.get("chain") or [] if isinstance(h, dict)]
    if chain:
        hops = "".join(f"<li><code dir='ltr'>{e(h.get('status'), 6)} {e(h.get('url'))}"
                       + (f" → {e(h.get('location'))}" if h.get("location") else "") + "</code></li>" for h in chain[:10])
        parts.append(_kv(L, "ev_chain", f"<ol class='chain' dir='ltr'>{hops}</ol>"))
    if ev.get("status") is not None:
        parts.append(_kv(L, "ev_status", f"<code dir='ltr'>{e(ev.get('status'), 6)}</code>"))
    match = ev.get("match") if isinstance(ev.get("match"), dict) else {}
    mname = str(match.get("name") or "").lower()
    headers = [h for h in ev.get("headers") or [] if isinstance(h, (list, tuple)) and len(h) == 2]
    if headers:
        rows = []
        for name, value in headers[:60]:
            hit = mname and (str(name).lower() == mname or (match.get("where") == "cookie" and
                                                             str(name).lower() == "set-cookie" and
                                                             str(value).lower().startswith(mname + "=")))
            hit_attr = " class='hit'" if hit else ""
            rows.append(f"<tr{hit_attr}><td class='nw'><code>{e(name, 120)}</code></td>"
                        f"<td><code dir='ltr'>{e(value, 1000)}</code></td></tr>")
        parts.append(f"<div class='kv'><b>{html.escape(_wl(L, 'ev_headers'))}:</b></div>"
                     f"<div class='tw'><table><tbody>{''.join(rows)}</tbody></table></div>")
    value = match.get("value")
    if value not in (None, ""):
        label = f"{e(match.get('name'), 200)}: " if match.get("name") else ""
        excerpt = f"\n…\n{e(match.get('excerpt'), 2000)}" if match.get("excerpt") else ""
        parts.append(_kv(L, "ev_match", f"<pre class='mv' dir='ltr'>{label}{e(value, 4000)}{excerpt}</pre>"))
    tls = ev.get("tls") if isinstance(ev.get("tls"), dict) else {}
    if tls:
        bits = [f"{k}: {clean_text(tls.get(k), 300)}" for k in ("ip", "version", "cipher", "subject", "issuer",
                                                                 "not_after", "key", "sigalg") if tls.get(k)]
        parts.append(_kv(L, "ev_tls", f"<pre class='mv' dir='ltr'>{html.escape(chr(10).join(bits))}</pre>"))
    if ev.get("curl"):
        parts.append(_kv(L, "ev_curl", f"<pre dir='ltr'>{e(ev['curl'], 2000)}</pre>"))
    if ev.get("observed_at"):
        stamp = clean_text(ev["observed_at"], 40)
        parts.append(_kv(L, "ev_observed", f"<time datetime='{html.escape(stamp)}'>{_bidi_html(L, _local_date(L, stamp))}</time>"))
    inst = f.extra.get("instances")
    if isinstance(inst, int) and not isinstance(inst, bool):
        badge = f" <span class='sys'>{html.escape(_wl(L, 'ev_systemic'))}</span>" if f.extra.get("systemic") is True else ""
        parts.append(_kv(L, "ev_instances", f"{inst}{badge}"))
    examples = [u for u in f.extra.get("examples") or [] if isinstance(u, str)][:5]
    if examples:
        parts.append(_kv(L, "ev_examples", "<ul class='ex'>" + "".join(f"<li><code dir='ltr'>{e(u, 500)}</code></li>"
                                                                         for u in examples) + "</ul>"))
    notes = [n for n in f.extra.get("notes") or [] if isinstance(n, (dict, str))]
    if notes:
        parts.append(_kv(L, "ev_notes", "<ul>" + "".join(f"<li>{_bidi_html(L, clean_text(_pair(L, n), 600))}</li>"
                                                         for n in notes[:8]) + "</ul>"))
    tags = [f"{label} {clean_text(x, 40)}" for key, label in (("wstg", ""), ("asvs4", "ASVS 4.0"), ("asvs5", "ASVS 5.0"))
            for x in (f.extra.get(key) if isinstance(f.extra.get(key), list) else [])]
    if tags:
        parts.append(_kv(L, "ev_tags", " ".join(f"<code class='tag'>{html.escape(t.strip())}</code>" for t in tags)))
    if not parts:
        return ""
    return f"<details class='ev'><summary>{html.escape(_wl(L, 'ev'))}</summary>{''.join(parts)}</details>"


def _note_shown_elsewhere(web: dict, note: str) -> bool:
    """Scan notes the HTML report shows elsewhere: the coverage line (coverage section), the grades line (grade
    cards), the web data date (facts line) and the truncated check-id lists (coverage table)."""
    for n in web.get("notes") or []:
        if not isinstance(n, dict) or n.get("ar") != note:
            continue
        en = str(n.get("en") or "")
        cov = (web.get("coverage_summary") or {}).get("en") if isinstance(web.get("coverage_summary"), dict) else ""
        return (bool(cov) and en == f"Coverage: {cov}") or en.startswith(("Grades: ", "Coverage: ")) or \
            (bool(web.get("data_date")) and en.startswith("web data as of ")) or _is_id_list_note(web, note)
    return False


def _web_html_head(findings: list[Finding], web: dict, L: "_Lang", target: str, pages: int, generated: str,
                   banner: dict | None, anchored: set[str]) -> str:
    """Under the title: the inconclusive banner, the facts (target, final URL on its own line, pages and requests,
    the scan date) and the grades."""
    e = html.escape
    out = []
    if banner:
        out.append(f"<div class='banner' role='status'><b>⚠ </b>{_bidi_html(L, banner['text'])}</div>")
    facts = [f"{e(_wl(L, 'w_target'))}: <code dir='ltr'>{e(clean_text(target, 2000))}</code>",
             _bidi_html(L, _web_scanned(L, pages, web.get("requests"))),
             f"{e(_wl(L, 'w_findings'))}: {len(findings)}",
             f"<span class='nw'>{e(_wl(L, 'w_scanned_at'))}: <time datetime='{e(generated)}'>"
             f"{_bidi_html(L, _local_date(L, generated))}</time></span>"]
    if web.get("profile"):
        facts.append(f"<span class='nw'>{e(_wl(L, 'w_profile'))}: <bdi dir='ltr'>{e(clean_text(web['profile'], 20))}</bdi></span>")
    if web.get("data_date"):
        facts.append(f"<span class='nw'>{e(_wl(L, 'w_data'))}: <bdi dir='ltr'>{e(clean_text(web['data_date'], 20))}</bdi></span>")
    out.append("<div class='facts'><p>" + " · ".join(facts) + "</p>")
    final = clean_text(web.get("final_url"), 2000)
    if final:
        out.append(f"<p>{e(_wl(L, 'w_final'))}:<br><code dir='ltr' class='url'>{e(final)}</code></p>")
    out.append("</div>")
    out.append(_grades_html(web, L, findings, anchored))
    return "".join(out) + "\n"


def _rule_link(rid: str, rules_in_report: set[str]) -> str:
    rid_e = html.escape(clean_text(rid, 60))
    return f"<a href='#f-{rid_e}'><code>{rid_e}</code></a>" if rid in rules_in_report else f"<code>{rid_e}</code>"


def _grades_html(web: dict, L: "_Lang", findings: list[Finding], anchored: set[str]) -> str:
    """The three grade cards (letter coloured by grade, with a word as well as a colour), the binding cap with its
    rules linked to their findings, then the Kashif family table and the Observatory test table."""
    e = html.escape
    in_report = {f.rule_id for f in findings if f.source == "web"}
    out = [f"<section class='web gsec'><h2>{e(_wl(L, 'grades'))}</h2><div class='grades'>"]
    provisional = False
    for g in _grade_rows(web, L):
        provisional = provisional or g["provisional"]
        det = _grade_detail(web, L, g["key"])
        cls = _grade_class(g["grade"])
        word = _wl(L, "gw_" + cls)
        letter = g["grade"] or "—"
        body = [f"<b>{e(g['name'])}</b>",
                f"<div class='gl'><span class='letter g-{cls}' dir='ltr'>{e(letter if g['grade'] else '?')}</span>"
                f"<span class='gword g-{cls}'>{e(word)}</span></div>"]
        if det["score_text"]:
            body.append(f"<small>{_bidi_html(L, det['score_text'])}</small>")
        if det["binding"]:
            links = " ".join(_rule_link(r, in_report) for r in det["binding"]["rules"])
            # "WEB000: Site served over plain HTTP" → the id is the link, the name follows it
            texts = ("; " if L.en else "؛ ").join(re.sub(r"^[A-Za-z0-9_-]+:\s*", "", t) if r else t for t, r in
                                                  zip(det["binding"]["texts"], det["binding"]["all_rules"]))
            body.append(f"<p class='cap'><b>{_bidi_html(L, _wl(L, 'g_limited').format(cap=det['binding']['cap']))}:</b> "
                        f"{links} — {_bidi_html(L, texts)}</p>")
        if g["label"]:
            body.append(f"<small>{_bidi_html(L, g['label'])}</small>")
        body += [f"<small class='gnote'>{_bidi_html(L, n)}</small>" for n in g["notes"][:4]]
        other = [c for c in det["caps"] if not (det["binding"] and c["cap"] == det["binding"]["cap"])]
        caps = [c["text"] for c in other] if det["caps"] else g["caps"]
        if caps:
            body.append(f"<small>{e(_wl(L, 'g_caps'))}:</small><ul>"
                        + "".join(f"<li>{_bidi_html(L, c)}</li>" for c in caps[:8]) + "</ul>")
        out.append(f"<div class='grade g-{e(g['key'])}'>{''.join(body)}</div>")
    out.append("</div>")
    if provisional:
        out.append(f"<p><small>{e(_wl(L, 'g_provisional'))}</small></p>")
    out.append(_families_html(web, L, in_report))
    out.append(_observatory_html(web, L))
    out.append("</section>")
    return "".join(out)


def _families_html(web: dict, L: "_Lang", in_report: set[str]) -> str:
    e = html.escape
    g = web.get("grades") if isinstance(web.get("grades"), dict) else {}
    fams = ((g.get("kashif") or {}).get("families") or {}) if isinstance(g.get("kashif"), dict) else {}
    if not isinstance(fams, dict) or not fams:
        return ""
    rows = []
    for key, d in fams.items():
        if not isinstance(d, dict):
            continue
        state = str(d.get("state") or "")
        state_label = _wl(L, "fs_" + state) if ("fs_" + state) in _WEB_LABELS else clean_text(state, 30)
        rules = []
        for c in d.get("contributions") or []:
            if isinstance(c, dict):
                for r in c.get("rules") or []:
                    if isinstance(r, str) and r not in rules:
                        rules.append(r)
        pen = d.get("penalty")
        ded = (" ".join(_rule_link(r, in_report) for r in rules[:12])
               + (f" <small dir='ltr'>(−{e(clean_text(pen, 10))})</small>" if pen else "")) if rules else "—"
        score = d.get("score")
        rows.append(f"<tr><td>{_bidi_html(L, clean_text(_pair(L, d.get('name')) or key, 80))}</td>"
                    f"<td>{e(clean_text(d.get('weight'), 6))}</td>"
                    f"<td>{e(clean_text(score, 8)) if state == 'tested' else '—'}</td>"
                    f"<td class='nw'>{e(state_label)}</td><td>{ded}</td></tr>")
    head = "".join(f"<th>{e(_wl(L, k))}</th>" for k in ("g_family", "g_weight", "g_fscore", "g_state", "g_deductions"))
    return (f"<details class='gt'><summary>{e(_wl(L, 'g_families'))}</summary><div class='tw'><table><thead><tr>{head}"
            f"</tr></thead><tbody>{''.join(rows)}</tbody></table></div></details>")


def _observatory_html(web: dict, L: "_Lang") -> str:
    e = html.escape
    g = web.get("grades") if isinstance(web.get("grades"), dict) else {}
    o = g.get("observatory") if isinstance(g.get("observatory"), dict) else {}
    tests = o.get("tests") if isinstance(o.get("tests"), dict) else {}
    missing = [t for t in o.get("missing_tests") or [] if isinstance(t, str)]
    if not tests and not missing:
        return ""
    rows = []
    for name, d in tests.items():
        if not isinstance(d, dict):
            continue
        mod = d.get("modifier")
        mod_s = (f"+{mod}" if isinstance(mod, (int, float)) and mod > 0 else clean_text(mod, 8)) if mod is not None else ""
        ok = d.get("pass")
        mark = "✓" if ok is True else "✗" if ok is False else ""
        rows.append(f"<tr><td class='nw'><code>{e(clean_text(name, 80))}</code></td>"
                    f"<td><code dir='ltr'>{e(clean_text(d.get('slug'), 120))}</code></td>"
                    f"<td dir='ltr'>{e(mod_s)}</td><td>{mark}</td></tr>")
    for name in missing:
        rows.append(f"<tr><td class='nw'><code>{e(clean_text(name, 80))}</code></td>"
                    f"<td>{e(_wl(L, 'g_not_computed'))}</td><td dir='ltr'>0</td><td></td></tr>")
    quirks = [q for q in o.get("quirks") or [] if isinstance(q, dict)]
    notes = "".join(f"<li>{_bidi_html(L, clean_text(_pair(L, q), 400))}</li>" for q in quirks[:6])
    head = "".join(f"<th>{e(_wl(L, k))}</th>" for k in ("g_test", "g_result", "g_modifier", "g_pass"))
    return (f"<details class='gt'><summary>{e(_wl(L, 'g_obs_tests'))}</summary><div class='tw'><table><thead><tr>"
            f"{head}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
            + (f"<ul class='quirks'>{notes}</ul>" if notes else "") + "</details>")


_TAB_CSS = "".join(f".tabs>input:nth-of-type({i}):checked~div.panel:nth-of-type({i}){{display:block}}" for i in range(1, 25))
_WEB_CSS = """
.web h2{margin-top:2rem}.grades{display:flex;gap:.75rem;flex-wrap:wrap}
.grade{background:var(--card);border:1px solid var(--line);border-radius:.5rem;padding:.75rem 1rem;min-width:12rem;flex:1}
.grade .gl{display:flex;align-items:baseline;gap:.6rem;flex-wrap:wrap}
.grade .letter{font-size:2.2rem;font-weight:800}.grade .gword{font-weight:700}.grade small{color:var(--muted);display:block}
.g-a{color:var(--ga)}.g-b{color:var(--gb)}.g-c{color:var(--gc)}.g-d{color:var(--gd)}.g-f{color:var(--gf)}.g-n{color:var(--gn)}
.grade .letter.g-n{font-style:italic}
.grade ul{margin:.3rem 0 0;padding-inline-start:1.1rem;font-size:.85em}.grade .cap{margin:.4rem 0;font-size:.9em}
.gt{margin:.6rem 0}.gt summary,.cov-d summary,.ev summary{cursor:pointer;font-weight:600}
.banner{border:2px solid var(--warn);background:var(--warnbg);color:var(--fg);padding:.6rem .9rem;border-radius:.5rem;margin:.5rem 0 1rem}
.facts p{margin:.3rem 0}.nw{white-space:nowrap}.url{display:inline-block;max-width:100%}
.cov{display:flex;gap:.5rem;flex-wrap:wrap;margin:.5rem 0}.cov span{background:var(--card);border:1px solid var(--line);border-radius:1rem;padding:.2rem .7rem}
.cov .s-fail{border-color:#c2410c}.cov .s-not_tested,.cov .s-inconclusive{border-color:#a16207}
.cov .s-zero{border-style:dashed;color:var(--muted);border-color:var(--line)}
.cov-ids{display:block;color:var(--muted);font-size:.8em}
.tabs{margin:.5rem 0}.tabs>input{position:absolute;opacity:0;pointer-events:none}
.tabs>label{display:inline-block;padding:.35rem .8rem;border:1px solid var(--line);border-bottom:none;border-radius:.4rem .4rem 0 0;
background:var(--code);cursor:pointer;margin-inline-end:.2rem}.tabs>input:checked+label{background:var(--card);font-weight:700}
.tabs>input:focus-visible+label{outline:2px solid var(--accent)}
.tabs>div.panel{display:none;border:1px solid var(--line);background:var(--card);padding:.6rem;overflow-x:auto}
.ph{display:none;margin:.8rem 0 .3rem}
.tw table caption{text-align:start;padding:.3rem 0;font-weight:600}
.v-good{color:var(--ok)}.v-weak{color:var(--warn)}.v-missing{color:var(--bad)}.v-ignored,.v-unset,.v-info{color:var(--muted)}
.snip{background:var(--card);border:1px solid var(--line);border-radius:.5rem;padding:.6rem 1rem;margin:.6rem 0}
.snip h3{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}.snip .fx{font-size:.85em;color:var(--muted)}
.snip pre{direction:ltr;text-align:left;background:var(--code);padding:.5rem;overflow:auto;font-size:.9rem;white-space:pre-wrap;overflow-wrap:anywhere}
.snip pre code,.diff code{font-size:inherit}
.caveat{color:var(--warn)}.conf{font-size:.75em;color:var(--muted);display:block;margin-top:.2rem}
.posture li.regression{color:var(--bad)}.posture li.improvement{color:var(--ok)}
.ev{margin-top:.5rem;font-size:.9em}.ev .kv{margin:.35rem 0}.ev ul,.ev ol{margin:.2rem 0;padding-inline-start:1.2rem}
.ev pre{direction:ltr;text-align:left;background:var(--code);padding:.4rem .5rem;margin:.2rem 0;white-space:pre-wrap;overflow-wrap:anywhere;font-size:.85em}
.ev tr.hit td{background:var(--hl);font-weight:600}.ev td{min-width:0}.ev td.nw,.ev td.nw code,.hdrs td.nw,.hdrs td.nw code{overflow-wrap:normal;word-break:normal}
.sys{display:inline-block;border:1px solid var(--warn);color:var(--warn);border-radius:.8rem;padding:0 .5rem;font-size:.8em}
.tag{margin-inline-end:.3rem}.cp{margin:.4rem 0 0}
@media (max-width:640px){.cov-d table,.cov-d tbody,.cov-d tr,.cov-d td{display:block;min-width:0}.cov-d thead{display:none}
.cov-d tr{border:1px solid var(--line);border-radius:.4rem;margin:.5rem 0}.cov-d td{border:none;padding:.3rem .5rem}
.grade{min-width:0;flex:1 1 100%}
.hdrs td,.gt td,.gt th{min-width:0;padding:.35rem}.hdrs td.nw,.gt td{white-space:normal}.gt table{font-size:.85em}}
.grade small+small{margin-top:.2rem}
"""


def _html_table(head: list[str], rows: list[list[str]], L: "_Lang") -> str:
    e = html.escape
    if not rows:
        return f"<p>{e(_wl(L, 'inv_empty'))}</p>"
    th = "".join(f"<th>{e(h)}</th>" for h in head)
    body = "".join("<tr>" + "".join(f"<td><span dir='auto'>{e(c)}</span></td>" for c in r) + "</tr>" for r in rows)
    return f"<div class='tw'><table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table></div>"


def _html_tabs(name: str, tabs: list[tuple[str, str]]) -> str:
    """CSS-only tabs (radio buttons): no script, so the report works under any CSP and offline. Each panel starts
    with its tab name as a heading that only print shows (print shows every panel, and no tab labels)."""
    e = html.escape
    inputs = []
    panels = []
    for i, (label, body) in enumerate(tabs):
        tid = f"{name}-{i}"
        inputs.append(f"<input type='radio' name='{e(name)}' id='{e(tid)}'{' checked' if i == 0 else ''}>"
                      f"<label for='{e(tid)}'><bdi dir='auto'>{e(label)}</bdi></label>")
        panels.append(f"<div class='panel'><h4 class='ph'><bdi dir='auto'>{e(label)}</bdi></h4>{body}</div>")
    return f"<div class='tabs'>{''.join(inputs)}{''.join(panels)}</div>"


def _web_html(findings: list[Finding], web: dict, L: "_Lang", part: str = "top", anchored: set[str] | None = None) -> str:
    e = html.escape
    if part == "bottom":
        return _web_html_bottom(findings, web, L, None, anchored)
    anchored = anchored if anchored is not None else {f.rule_id for f in findings if f.source == "web"}
    out = ["<section class='web'>"]
    # coverage: zero counts drawn as dashed pills; the checks that did not pass grouped by (state, reason)
    counts = _coverage_counts(web)
    out.append(f"<h2>{e(_wl(L, 'coverage'))}</h2><div class='cov'>"
               + "".join(f"<span class='s-{s}{' s-zero' if not counts[s] else ''}'>{e(_wl(L, 's_' + s))}: "
                         f"<b>{counts[s]}</b></span>" for s in _STATE_ORDER)
               + f"</div><p><small>{e(_wl(L, 'cov_never_pass'))}</small></p>")
    groups = _coverage_groups(web, L)
    if groups:
        rows = []
        for g in groups:
            checks = []
            for c in g["checks"][:60]:
                cid = html.escape(c["id"])
                small = f" <small class='nw'><code>{cid}</code></small>"
                if c["title"] == c["id"]:                   # a check without a registry title: the id once
                    name, small = f"<code>{cid}</code>", ""
                else:
                    name = _bidi_html(L, c["title"])
                if g["state"] == "fail" and c["id"] in anchored:
                    checks.append(f"<a href='#f-{cid}'>{name}</a>{small}")
                else:
                    checks.append(f"{name}{small}")
            more = len(g["checks"]) - 60
            cell = ("، " if not L.en else ", ").join(checks) + (
                f" {_bidi_html(L, _wl(L, 'and_more').format(n=more))}" if more > 0 else "")
            reason = _bidi_html(L, g["reason"]) if g["reason"] else "—"
            rows.append(f"<tr><td class='nw'>{e(g['state_label'])} <b>({len(g['checks'])})</b></td><td>{reason}</td>"
                        f"<td>{cell}</td></tr>")
        head = "".join(f"<th>{e(_wl(L, k))}</th>" for k in ("cov_state", "cov_reason", "cov_checks"))
        total = sum(len(g["checks"]) for g in groups)
        out.append(f"<details class='cov-d'{' open' if len(groups) <= 10 else ''}><summary>{e(_wl(L, 'cov_details'))}"
                   f" ({total})</summary><div class='tw'><table><thead><tr>{head}</tr></thead><tbody>{''.join(rows)}"
                   f"</tbody></table></div></details>")
    # diff
    dp = _diff_parts(web)
    if dp:
        out.append(f"<h2>{e(_wl(L, 'diff'))}</h2>")
        for n in dp["notes"]:
            out.append(f"<p>{_bidi_html(L, clean_text(_pair(L, n), 400))}</p>")
        if dp["comparable"]:
            changes = _grade_changes(L, dp["grades"])
            out.append(f"<p><b>{e(_wl(L, 'd_grade'))}:</b> " + (" · ".join(f"<bdi>{_bidi_html(L, c)}</bdi>" for c in changes)
                                                                  or e(_wl(L, "d_grades_same"))) + "</p>")
            if dp["posture"]:
                out.append(f"<h3>{e(_wl(L, 'd_posture'))}</h3><ul class='posture'>"
                           + "".join(f"<li class='{e(str(p.get('direction')))}'>{e(_wl(L, 'd_' + p['direction']) if ('d_' + str(p.get('direction'))) in _WEB_LABELS else '')}: "
                                     f"<bdi>{_bidi_html(L, clean_text(_pair(L, p), 400))}</bdi></li>" for p in dp["posture"][:200]) + "</ul>")
            for key in ("new", "resolved"):
                items = dp[key]
                out.append(f"<h3>{e(_wl(L, 'd_' + key))} ({len(items)})</h3>")
                if items:
                    out.append("<ul>" + "".join(f"<li><span class='b {e(str(r.get('severity')))}'>{e(L.sev(r['severity']) if r.get('severity') in SEVERITY_AR else '?')}</span> "
                                                + (_rule_link(str(r.get('rule')), anchored) if key == "new" else f"<code>{e(clean_text(r.get('rule'), 40))}</code>")
                                                + f" <bdi>{_bidi_html(L, _row_title(L, r))}</bdi></li>"
                                                for r in items[:200]) + "</ul>")
            out.append(f"<p><small>{e(_wl(L, 'd_unchanged'))}: {len(dp['unchanged'])} · "
                       f"{e(_wl(L, 'd_not_retested'))}: {len(dp['not_retested'])}</small></p>")
    out.append("</section>")
    return "".join(out)


_V_GOOD = frozenset({"ok", "enforced", "nosniff", "deny", "sameorigin", "frame-ancestors", "present", "no-referrer",
                     "same-origin", "strict-origin", "strict-origin-when-cross-origin", "same-site", "require-corp",
                     "credentialless", "same-origin-allow-popups", "noopener-allow-popups"})
_V_WEAK = frozenset({"invalid", "unrecognised", "multi", "frame-ancestors-broad", "short-max-age", "disabled", "meta",
                     "report-only", "unsafe-url", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
                     "unsafe-none", "allow-from", "conflict"})
_V_OPTIONAL = frozenset({"cross-origin-embedder-policy", "cross-origin-resource-policy", "cache-control"})
# named states (not header syntax): shown by name next to the symbol
_V_NAMED_EN = {"ok": "valid", "enforced": "enforced", "present": "present", "frame-ancestors": "via frame-ancestors",
               "short-max-age": "max-age under one year", "disabled": "disabled (max-age=0)", "meta": "meta tag only",
               "report-only": "report-only", "invalid": "invalid", "unrecognised": "unrecognised",
               "ignored-on-http": "ignored over HTTP", "frame-ancestors-broad": "frame-ancestors too broad",
               "multi": "duplicated"}


def _verdict_html(L: "_Lang", header: str, token) -> str:
    """✓ good / ⚠ weak / ✗ missing / ignored, in the report language; the raw verdict token in the title."""
    raw = clean_text(token, 80)
    tok = raw.lower()
    if tok.startswith("report-only:"):
        cat, named = "weak", "report-only"
    elif tok == "missing":
        cat, named = ("unset" if header.lower() in _V_OPTIONAL else "missing"), ""
    elif tok == "ignored-on-http":
        cat, named = "ignored", tok
    elif tok in _V_GOOD:
        cat, named = "good", tok if tok in _V_NAMED_EN else ""
    elif tok in _V_WEAK:
        cat, named = "weak", tok if tok in _V_NAMED_EN else ""
    else:
        cat, named = "info", ""
    sym = {"good": "✓", "weak": "⚠", "missing": "✗", "ignored": "⊘", "unset": "—", "info": "·"}[cat]
    if named:
        text = _V_NAMED_EN[named] if L.en else _INV_AR.get(named, named)
    elif cat == "info":
        text = raw
    else:
        text = _wl(L, "v_" + cat)
    return (f"<td class='nw v-{cat}' title='{html.escape(raw)}'>{sym} "
            f"{_bidi_html(L, text)}</td>")


def _headers_html(web: dict, L: "_Lang") -> str:
    """The security headers inventory: one table per response, its URL once as the caption."""
    e = html.escape
    inv = web.get("inventory") if isinstance(web.get("inventory"), dict) else {}
    out = []
    for entry in (inv.get("security_headers") or [])[:20]:
        if not isinstance(entry, dict):
            continue
        rows = []
        for name, d in (entry.get("headers") or {}).items():
            d = d if isinstance(d, dict) else {"value": d}
            value = clean_text(d.get("value"), 300)
            value_html = f"<code dir='ltr'>{e(value)}</code>" if value else "—"
            rows.append(f"<tr><td class='nw'><code>{e(clean_text(name, 80))}</code></td><td>{value_html}</td>"
                        f"{_verdict_html(L, str(name), d.get('verdict'))}</tr>")
        status = entry.get("status")
        cap = f"<code dir='ltr'>{e(clean_text(entry.get('url'), 500))}</code>" + (
            f" · <span class='nw'>HTTP {e(clean_text(status, 4))}</span>" if status else "")
        head = "".join(f"<th>{e(_wl(L, k))}</th>" for k in ("h_header", "h_value", "h_verdict"))
        out.append(f"<div class='tw'><table class='hdrs'><caption>{cap}</caption><thead><tr>{head}</tr></thead>"
                   f"<tbody>{''.join(rows)}</tbody></table></div>")
    return "".join(out) or f"<p>{e(_wl(L, 'inv_empty'))}</p>"


def _web_html_bottom(findings: list[Finding], web: dict, L: "_Lang", snippets: list[dict] | None = None,
                     anchored: set[str] | None = None) -> str:
    e = html.escape
    out = ["<section class='web'>"]
    # inventory tabs
    tables = inventory_tables(web, L)
    out.append(f"<h2>{e(_wl(L, 'inventory'))}</h2>")
    out.append(_html_tabs("inv", [(_wl(L, "t_" + k), _headers_html(web, L) if k == "headers" else
                                   _html_table(*tables[k], L)) for k in INVENTORY_TABS]))
    # remediation snippets with platform tabs: one card per snippet (id='rem-<id>'), with the findings it fixes
    snippets = remediation_snippets(findings, web, L.lang) if snippets is None else snippets
    anchored = anchored if anchored is not None else {f.rule_id for f in findings if f.source == "web"}
    if snippets:
        out.append(f"<h2>{e(_wl(L, 'remediation'))}</h2>")
        for i, sn in enumerate(snippets):
            sid = str(sn.get("id") or "")
            fixed = [f for f in findings if f.source == "web" and sid in _remediation_ids(f)]
            rules = list(dict.fromkeys(f.rule_id for f in fixed))
            worst = min((SEVERITIES.index(f.severity) for f in fixed), default=None)
            badge = (f"<span class='b {SEVERITIES[worst]}'>{e(L.sev(SEVERITIES[worst]))}</span>"
                     if worst is not None else "")
            links = " ".join(_rule_link(r, anchored) for r in rules[:20])
            blocks = [b for b in list(sn.get("detected") or []) + list(sn.get("other") or []) if isinstance(b, dict)]
            tabs = []
            for b in blocks:
                body = (f"<pre><code>{e(str(b.get('code') or ''))}</code></pre>" if b.get("code") else "") \
                    + (f"<p>{_bidi_html(L, str(b.get('note') or ''))}</p>" if b.get("note") else "")
                tabs.append((str(b.get("name") or b.get("platform") or ""), body))
            out.append(f"<div class='snip' id='rem-{e(sid)}'><h3>{badge}<code>{e(sid)}</code> "
                       f"<span>{_bidi_html(L, str(sn.get('title') or ''))}</span></h3>"
                       + (f"<p class='fx'>{e(_wl(L, 'rem_fixes'))}: {links}</p>" if links else "")
                       + f"<p>{_bidi_html(L, str(sn.get('summary') or ''))}</p>"
                       + (f"<p class='caveat'><b>{e(str(sn.get('caveat_label') or ''))}:</b> {_bidi_html(L, str(sn.get('caveat') or ''))}</p>" if sn.get("caveat") else "")
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
    md += _md_table([_wl(L, "g_algorithm"), _wl(L, "g_grade"), _wl(L, "g_score"), _wl(L, "g_details")], rows, L)
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
            changes = _grade_changes(L, dp["grades"])
            md.append(f"- {_wl(L, 'd_grade')}: " + (" · ".join(_md_cell(c, 100) for c in changes)
                                                     or _wl(L, "d_grades_same")))
            for p in dp["posture"][:200]:
                direction = str(p.get("direction"))
                label = _wl(L, "d_" + direction) if ("d_" + direction) in _WEB_LABELS else direction
                md.append(f"- **{label}**: {_md_cell(_pair(L, p), 400)}")
            for key in ("new", "resolved"):
                md += ["", f"#### {_wl(L, 'd_' + key)} ({len(dp[key])})", ""]
                md += [f"- `{_md_code(r.get('rule'), 40)}` {_md_cell(_row_title(L, r), 200)} ({_md_cell(_sev_word(L, r.get('severity')), 12)})"
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


def web_view(findings: list[Finding], web: dict, lang: str = "ar", *, compare_previous: bool | None = None) -> dict:
    """What the local UI shows of a web scan (GET /api/scans/<id>/web): the same data as the HTML report, already
    in the UI language and cleaned of control characters (the UI escapes every value again before display).

    ``facts`` (profile, requests, final URL, data date) · ``grades`` [{key, name, grade, score, max, label, caps,
    notes, provisional, grade_class, grade_word, score_text, binding}] · ``coverage`` {counts, states (labels),
    problems [[check, state, reason, title]], groups [{state, state_label, reason, choice, checks [{id, title}]}]} ·
    ``inconclusive`` (None, or {n, total, reasons, text}) · ``diff`` (None, or {comparable, notes, new, resolved,
    unchanged (count), not_retested (count), posture [{direction, label, text}], grades [text]}) · ``inventory``
    [{id, label, head, rows}] · ``remediation`` (the snippet library's render(), detected platforms first).

    ``compare_previous`` (default: ``web["compare_previous"]``): a comparison was asked for. When there was no previous
    scan to compare with, ``diff`` is {comparable: false, notes: ["no previous scan; this one becomes the baseline"]}
    instead of None."""
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
                "unchanged": len(dp["unchanged"]), "not_retested": len(dp["not_retested"]),
                "posture": [{"direction": str(p.get("direction") or ""),
                             "label": _wl(L, "d_" + str(p.get("direction"))) if ("d_" + str(p.get("direction"))) in _WEB_LABELS else "",
                             "text": clean_text(_pair(L, p), 400)} for p in dp["posture"][:200]],
                "grades": _grade_changes(L, dp["grades"])}
    elif web and (compare_previous if compare_previous is not None else web.get("compare_previous") is True):
        diff = {"comparable": False, "baseline": True, "notes": [_wl(L, "d_baseline")], "new": [], "resolved": [],
                "unchanged": 0, "not_retested": 0, "posture": [], "grades": []}
    tables = inventory_tables(web, L) if web else {}
    grades = []
    for g in _grade_rows(web, L) if web else []:
        det = _grade_detail(web, L, g["key"])
        cls = _grade_class(g["grade"])
        grades.append({**g, "grade_class": cls, "grade_word": _wl(L, "gw_" + cls), "score_text": det["score_text"],
                       "binding": det["binding"]})
    groups = _coverage_groups(web, L) if web else []
    return {"facts": {"profile": clean_text(web.get("profile"), 20), "requests": web.get("requests"),
                      "final_url": clean_text(web.get("final_url"), 500), "data_date": clean_text(web.get("data_date"), 20),
                      "sensitivity": clean_text(web.get("sensitivity"), 20)},
            "grades": grades,
            "coverage": {"counts": _coverage_counts(web), "states": {s: _wl(L, "s_" + s) for s in _STATE_ORDER},
                         "problems": [[c, _wl(L, "s_" + s) if ("s_" + s) in _WEB_LABELS else s, r,
                                       clean_text(_rule_name(L, c), 200)]
                                      for c, s, r in _coverage_problems(web, L)] if web else [],
                         "groups": [{k: g[k] for k in ("state", "state_label", "reason", "choice", "checks")}
                                    for g in groups]},
            "inconclusive": _inconclusive(web, findings, L) if web else None,
            "diff": diff,
            "inventory": [{"id": k, "label": _wl(L, "t_" + k), "head": tables[k][0], "rows": tables[k][1]}
                          for k in INVENTORY_TABS if k in tables],
            "remediation": remediation_snippets(findings, web, L.lang) if web else []}
