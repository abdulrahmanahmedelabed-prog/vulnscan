"""Exporters: Kashif findings in the formats security teams already run.

INTEGRATION NOTES
=================
(for the step that wires this module into the CLI and the UI; this module edits no other file)

CLI
    * Sub-command ``kashif export REPORT.json -f FORMAT [-o FILE]``: delegate to ``exporters.main(argv)``. Every
      flag of ``main`` (see ``_parser``) can be reused as is. (Wired; the scan's own ``-f`` also accepts every
      format of ``FORMATS``.)
    * Scan flag ``--export FORMAT=FILE`` (repeatable), next to ``--format``: after the scan,
      ``open(FILE, "w", encoding="utf-8", newline="").write(exporters.export(findings, FORMAT, meta))`` with
      ``meta = {"target": target, "files_scanned": files, "lang": lang}``. Keep ``newline=""``: the CSV formats
      carry their own CRLF line ends.
    * ``--risk-score`` on a scan: print ``exporters.project_risk(findings)["score"]`` and its rating in the
      console summary (``exporters.rating_label(rating, lang)``).
UI / server
    * ``GET /api/export?scan=ID&format=FMT&lang=LANG`` -> ``export(saved["findings"], FMT, meta)`` with
      ``Content-Type: format_info(FMT)["mime"]`` and
      ``Content-Disposition: attachment; filename="kashif-<scan>.<format_info(FMT)["ext"]>"``.
    * Reports page: an "Export to ..." menu fed by ``list_formats(lang)`` (id, name, description, ext, mime,
      needs). Formats whose ``needs`` list is not empty (``asff``) need a small form for those ``meta`` keys.
    * Findings table / dashboard: a "Kashif risk score" column and a project gauge from ``risk_score(finding)``
      and ``project_risk(findings)``. Always label it "Kashif risk score": it is not CVSS.
vulnscan.spec
    * ``hiddenimports += ["vulnscan.exporters"]``. No data files, no third-party imports.
README (suggested text)
    * "Works with what you already run: export any scan to DefectDojo (Generic Findings Import), SonarQube
      (Generic Issue Import), JUnit XML for CI dashboards, spreadsheet-safe CSV, Jira CSV import, GitHub
      Issues, AWS Security Hub (ASFF) and OCSF 1.3.0 - offline, no account, no upload."
    * "Kashif risk score: a documented 0-10 priority score per finding and per project (severity, CWE class,
      data-flow proof, reachability, exposure). It is a triage aid, not a CVSS score."

Formats
=======
``defectdojo``        DefectDojo "Generic Findings Import" JSON. Only keys that parser documents are written
                      (an unknown key stops the import): title, severity, description, mitigation, references,
                      file_path, line, cwe, cve, unique_id_from_tool (= fingerprint), vuln_id_from_tool (= rule),
                      static_finding / dynamic_finding, active, verified, false_p, risk_accepted, is_mitigated,
                      date, tags, severity_justification, sast_source_object, sast_sink_object,
                      sast_source_line, sast_source_file_path.
``sonarqube``         SonarQube Generic Issue Import, the format of SonarQube 10.3 and later: ``rules`` (id, name,
                      description, engineId, cleanCodeAttribute, impacts) plus ``issues`` (ruleId,
                      primaryLocation, secondaryLocations). This format has NO ``flows`` key (checked against
                      the importer's source, ExternalIssueReport.java in SonarQube 10.7): the data-flow path is
                      written as ordered ``secondaryLocations``, which is all the importer reads.
``sonarqube-legacy``  The same for SonarQube before 10.3: issues carrying engineId / severity / type.
                      Both SonarQube formats leave out findings triaged as false positive or fixed.
``junit``             JUnit XML: one ``testsuite`` per file, one ``testcase`` per rule in that file, a
                      ``failure`` when a finding reaches ``meta["fail_on"]`` (default ``low``).
``csv``               RFC 4180 CSV, safe to open in a spreadsheet (formula injection neutralised).
``jira-csv``          CSV for Jira's "External System Import": Summary, Issue Type, Priority, Labels, Description.
``github-issues``     JSON list of ``{"title", "body", "labels"}`` - the fields of GitHub's "create an issue" API.
``asff``              AWS Security Finding Format, a JSON list for ``BatchImportFindings``. Needs
                      ``meta["aws_account_id"]`` and ``meta["aws_region"]``. Field names, required fields and
                      enums follow the Security Hub API model (botocore, securityhub 2018-10-26).
``ocsf``              OCSF 1.3.0 "Vulnerability Finding" events (class_uid 2002), checked against the
                      ocsf-schema repository at tag 1.3.0.
``risk``              The Kashif risk score of every finding and of the project, as JSON.
``gitlab-sast``       GitLab SAST report (``artifacts:reports:sast``), schema 15.0.7: ``version``, ``scan``
                      (analyzer, scanner, type "sast", start/end time, status) and ``vulnerabilities`` (id = a
                      UUID derived from the fingerprint, category, name, description, severity, solution,
                      location, identifiers: the Kashif rule first, then CWE / CVE). Checked against the
                      published JSON schemas 15.0.7 and 15.2.x (gitlab-security_report_schemas).
``codeclimate``       Code Climate issues, the format of GitLab Code Quality (``artifacts:reports:codequality``):
                      type, check_name, description, content.body, categories ["Security"], location
                      (path, lines.begin/end), severity (info / minor / major / critical / blocker), fingerprint.
                      Both GitLab formats leave out findings triaged as false positive or fixed. Paths are the
                      report's paths: scan the repository root so that they are relative to it.

Kashif risk score (NOT CVSS)
============================
A 0.0-10.0 number that orders findings for triage. It is inspired by CVSS only in its range and rating
bands; it is not a CVSS score and must not be reported as one. Per finding::

    score = min(10, B x C x E x R x X)        rounded to one decimal, halves up

    B  severity base         critical 9.0 | high 7.5 | medium 5.0 | low 2.5 | info 0.5
    C  CWE class             injection-class and memory-safety weaknesses (code/command execution, SQL,
                             path traversal, SSRF, XXE, deserialisation, upload ...) 1.10 | access control,
                             secrets, cryptography 1.00 | browser-side (XSS, CSRF, redirect) 0.95 |
                             hardening and information exposure 0.85 | unknown or no CWE 1.00
    E  evidence              a source-to-sink data flow was traced, or an analyst confirmed it 1.10 |
                             pattern match 1.00 | audit lead with no traced source 0.60
    R  reachability          proven unreachable 0.50 | starts at an untrusted entry point (or flagged
                             reachable) 1.05 | unknown 1.00
    X  exposure              test, example, fixture, documentation or vendored code 0.50 | observed on a live
                             URL 1.10 | otherwise meta["exposure"]: internet 1.10, internal 1.00 (default),
                             local 0.85

A finding triaged as false positive or fixed scores 0.0. Rating bands: 0 none, 0.1-3.9 low, 4.0-6.9 medium,
7.0-8.9 high, 9.0-10.0 critical. Each score comes with a vector such as ``KRS:1.0/S:H/C:INJ/E:P/R:E/X:N`` that
shows which factor produced it.

Per project, over the findings that are still open (accepted risks and won't-fix are left out), with scores
sorted from highest to lowest s1 >= s2 >= ...::

    project = s1 + (10 - s1) x (1 - exp(-(s2 + s3 + ...) / 40))

so the project is never rated below its worst finding, more findings push it towards 10, and no number of
small findings can outweigh the distance that is left above the worst one.

Limits
======
* SonarQube keeps only the files it indexed: findings on a URL or inside an archive are ignored by its importer.
* ASFF: ``BatchImportFindings`` takes at most 100 findings per call; split the list. Title is cut to 256
  characters and Description to 1024, the API's limits.
* OCSF: a vulnerability object needs a CWE or a CVE. A finding with neither is still exported, without one.
* Jira: the Description uses Jira wiki markup; map the columns in the import wizard.
* This module reads a findings list. It never reads or runs the scanned code and never opens the network.
* Code snippets are exported as the report holds them. If a report contains a hard-coded secret in a snippet,
  so does every export of it: treat export files with the same care as the report.
* Text taken from the report is escaped for its destination (Markdown, Jira wiki markup, XML, CSV formulas).
  Only http(s) URLs are written as links; a CWE is written only in the canonical ``CWE-<number>`` form.
* Server integration: build the download file name from ``format_info(fmt)["ext"]`` and a server-side scan id,
  never from request text, and send ``X-Content-Type-Options: nosniff``.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import quote
from datetime import datetime, timezone

from . import __version__
from .i18n import to_en
from .model import SEVERITIES, SEVERITY_AR, SEVERITY_RANK, Finding, assign_fingerprints, ensure_fingerprints

__all__ = ["export", "list_formats", "format_info", "risk_score", "project_risk", "rating_label", "neutralise_cell",
           "ExportError", "FORMATS", "STR", "main"]

TOOL = "Kashif"
ENGINE_ID = "kashif"
LANGS = ("en", "ar")

STR = {
    "en": {
        "f_defectdojo": "DefectDojo (Generic Findings Import, JSON)",
        "d_defectdojo": "Import in DefectDojo with scan type \"Generic Findings Import\".",
        "f_sonarqube": "SonarQube (Generic Issue Import, 10.3+)",
        "d_sonarqube": "Pass the file to the scanner with sonar.externalIssuesReportPaths.",
        "f_sonarqube-legacy": "SonarQube (Generic Issue Import, before 10.3)",
        "d_sonarqube-legacy": "The older issue format, for SonarQube servers before 10.3.",
        "f_junit": "JUnit XML",
        "d_junit": "One test case per rule and file, so CI dashboards show findings as failed tests.",
        "f_csv": "CSV (spreadsheet-safe)",
        "d_csv": "RFC 4180 CSV; cells that a spreadsheet would run as a formula are neutralised.",
        "f_jira-csv": "Jira CSV import",
        "d_jira-csv": "One issue per finding for Jira's External System Import (CSV).",
        "f_github-issues": "GitHub Issues (JSON: title, body, labels)",
        "d_github-issues": "One issue per finding, with a Markdown body, for the GitHub API or gh.",
        "f_asff": "AWS Security Hub (ASFF)",
        "d_asff": "A findings list for BatchImportFindings. Needs the AWS account ID and Region.",
        "f_ocsf": "OCSF 1.3.0 (Vulnerability Finding)",
        "d_ocsf": "Open Cybersecurity Schema Framework events, class 2002.",
        "f_risk": "Kashif risk score (JSON)",
        "f_gitlab-sast": "GitLab SAST report (gl-sast-report.json)",
        "d_gitlab-sast": "Security tab and merge-request widget: artifacts:reports:sast (schema 15.0).",
        "f_codeclimate": "Code Climate / GitLab Code Quality (JSON)",
        "d_codeclimate": "GitLab Code Quality widget (artifacts:reports:codequality) and Code Climate tools.",
        "d_risk": "The risk score of every finding and of the project. Not a CVSS score.",
        "risk": "Kashif risk score",
        "risk_note": "Kashif risk score (a triage aid, not a CVSS score)",
        "rule": "Rule", "severity": "Severity", "location": "Location", "snippet": "Code", "flow": "Data flow",
        "source": "Untrusted source", "sink": "Sink", "fix": "Remediation", "reference": "Reference",
        "fingerprint": "Fingerprint", "status": "Status", "engine": "Detected by", "occurrences": "Occurrences",
        "line": "line", "found_by": "Found by Kashif static analysis.", "no_findings": "No findings",
        "no_findings_body": "Kashif reported no findings.", "title": "Title", "file": "File", "cwe": "CWE",
        "url": "URL", "project": "Project",
        "r_none": "None", "r_low": "Low", "r_medium": "Medium", "r_high": "High", "r_critical": "Critical",
        "e_format": "unknown export format '{fmt}' (choose from: {choices})",
        "e_findings": "findings must be a list of Finding objects or of their dict form",
        "e_severity": "unknown severity '{value}' (choose from: {choices})",
        "e_exposure": "unknown exposure '{value}' (choose from: internet, internal, local)",
        "e_aws": "the asff format needs meta['aws_account_id'] (12 digits) and meta['aws_region'] "
                 "(--aws-account, --aws-region)",
        "e_aws_cli": "the asff format needs --aws-account (the 12-digit AWS account ID) and --aws-region "
                     "(e.g. eu-west-1)",
        "e_report": "cannot read the report '{path}': {error}",
        "e_report_kind": "cannot read the report '{path}': not a regular file (it may be a device, pipe or directory)",
        "e_report_big": "the report '{path}' is larger than {mb} MB; not read",
        "r_missing": "the file does not exist",
        "r_denied": "permission denied",
        "r_json": "not valid JSON (line {line}, column {col})",
        "r_utf8": "not UTF-8 text",
        "e_shape": "'{path}' is not a Kashif JSON report (expected the output of 'kashif PATH -f json': an object "
                   "with a 'findings' list, or a non-empty list of findings)",
        "e_write": "cannot write '{path}': {error}",
        "h_desc": "Convert a Kashif JSON report to the format of another security tool.",
        "h_report": "Kashif JSON report (kashif PATH --format json), or - for standard input",
        "h_format": "output format (see --list-formats)",
        "h_output": "output file (default: standard output)",
        "h_lang": "language of the exported text: en or ar (default: en)",
        "h_list": "list the available formats and exit",
        "h_min": "leave out findings below this severity",
        "h_fail": "junit: lowest severity reported as a failed test (default: low)",
        "h_project": "project name written to the export (default: the report's target)",
        "h_exposure": "risk score: where the application runs - internet, internal (default) or local",
        "h_account": "asff: AWS account ID (12 digits)",
        "h_region": "asff: AWS Region, for example eu-west-1",
        "h_repo": "github-issues, jira-csv: repository URL, to link every finding to its line",
        "h_ref": "branch or commit used in those links (default: HEAD)",
        "h_bom": "csv, jira-csv: start the file with a byte order mark so Excel reads it as UTF-8",
        "h_score": "print the project's Kashif risk score to standard error",
        "m_score": "Kashif risk score: {score}/10 ({rating}) - {n:open_findings}. Not a CVSS score.",
        "m_written": "written: {path} ({fmt})",
        "e_no_report": "the JSON report to convert is missing: kashif export REPORT.json -f FORMAT "
                       "(make one with: kashif PATH -f json -o REPORT.json)",
        "e_no_format": "the output format is missing: add -f FORMAT (list: kashif export --list-formats) or --score",
    },
    "ar": {
        "f_defectdojo": "DefectDojo (Generic Findings Import، JSON)",
        "d_defectdojo": "استورده في DefectDojo بنوع الفحص \"Generic Findings Import\".",
        "f_sonarqube": "SonarQube (Generic Issue Import، الإصدار 10.3 وما بعده)",
        "d_sonarqube": "مرِّر الملف إلى الماسح بالخاصية sonar.externalIssuesReportPaths.",
        "f_sonarqube-legacy": "SonarQube (Generic Issue Import، قبل الإصدار 10.3)",
        "d_sonarqube-legacy": "الصيغة الأقدم، لخوادم SonarQube قبل الإصدار 10.3.",
        "f_junit": "JUnit XML",
        "d_junit": "حالة اختبار لكل قاعدة وملف، فتُظهر لوحات CI النتائج اختباراتٍ فاشلة.",
        "f_csv": "CSV (آمن لجداول البيانات)",
        "d_csv": "ملف CSV وفق RFC 4180؛ تُعطَّل الخلايا التي قد ينفّذها برنامج الجداول كصيغة.",
        "f_jira-csv": "استيراد CSV إلى Jira",
        "d_jira-csv": "تذكرة لكل نتيجة لأداة External System Import (CSV) في Jira.",
        "f_github-issues": "GitHub Issues (JSON: title و body و labels)",
        "d_github-issues": "تذكرة لكل نتيجة بنص Markdown، لواجهة GitHub البرمجية أو gh.",
        "f_asff": "AWS Security Hub (ASFF)",
        "d_asff": "قائمة نتائج للعملية BatchImportFindings. يلزم رقم حساب AWS والمنطقة.",
        "f_ocsf": "OCSF 1.3.0 (Vulnerability Finding)",
        "d_ocsf": "أحداث Open Cybersecurity Schema Framework من الصنف 2002.",
        "f_risk": "درجة خطر كاشِف (JSON)",
        "f_gitlab-sast": "تقرير GitLab SAST (gl-sast-report.json)",
        "d_gitlab-sast": "تبويب الأمان وأداة طلب الدمج في GitLab: artifacts:reports:sast (المخطط 15.0).",
        "f_codeclimate": "Code Climate / جودة الكود في GitLab (JSON)",
        "d_codeclimate": "أداة جودة الكود في GitLab (artifacts:reports:codequality) وأدوات Code Climate.",
        "d_risk": "درجة الخطر لكل نتيجة وللمشروع. ليست درجة CVSS.",
        "risk": "درجة خطر كاشِف",
        "risk_note": "درجة خطر كاشِف (وسيلة لترتيب الأولويات، وليست درجة CVSS)",
        "rule": "القاعدة", "severity": "الخطورة", "location": "الموضع", "snippet": "الكود", "flow": "مسار التدفق",
        "source": "المصدر غير الموثوق", "sink": "نقطة الخطر", "fix": "الإصلاح", "reference": "المرجع",
        "fingerprint": "البصمة", "status": "الحالة", "engine": "اكتشفه", "occurrences": "عدد المواضع",
        "line": "السطر", "found_by": "اكتشفه التحليل الساكن في كاشِف.", "no_findings": "لا نتائج",
        "no_findings_body": "لم يُبلّغ كاشِف عن أي نتيجة.", "title": "العنوان", "file": "الملف", "cwe": "CWE",
        "url": "الرابط", "project": "المشروع",
        "r_none": "لا خطر", "r_low": "منخفض", "r_medium": "متوسط", "r_high": "عالٍ", "r_critical": "حرج",
        "e_format": "صيغة التصدير '{fmt}' غير معروفة (المتاح: {choices})",
        "e_findings": "يجب أن تكون النتائج قائمة من كائنات Finding أو من صيغتها القاموسية",
        "e_severity": "الخطورة '{value}' غير معروفة (المتاح: {choices})",
        "e_exposure": "قيمة التعرّض '{value}' غير معروفة (المتاح: internet أو internal أو local)",
        "e_aws": "تحتاج الصيغة asff إلى meta['aws_account_id'] (12 رقمًا) و meta['aws_region'] "
                 "(--aws-account و --aws-region)",
        "e_aws_cli": "تحتاج صيغة asff إلى --aws-account (رقم حساب AWS من 12 رقمًا) وإلى --aws-region "
                     "(مثل eu-west-1)",
        "e_report": "تعذّرت قراءة التقرير '{path}': {error}",
        "e_report_kind": "تعذّرت قراءة التقرير '{path}': ليس ملفًا عاديًا (قد يكون جهازًا أو أنبوبًا أو مجلدًا)",
        "e_report_big": "التقرير '{path}' أكبر من {mb} ميغابايت؛ لم يُقرأ",
        "r_missing": "الملف غير موجود",
        "r_denied": "لا صلاحية لقراءته",
        "r_json": "ليس JSON صالحًا (السطر {line}، العمود {col})",
        "r_utf8": "ليس نصًا بترميز UTF-8",
        "e_shape": "'{path}' ليس تقرير JSON من كاشِف (المتوقع مخرجات 'kashif PATH -f json': كائن فيه قائمة "
                   "'findings'، أو قائمة نتائج غير فارغة)",
        "e_write": "تعذّرت الكتابة إلى '{path}': {error}",
        "h_desc": "تحويل تقرير JSON من كاشِف إلى صيغة أداة أمنية أخرى.",
        "h_report": "تقرير JSON من كاشِف (kashif PATH --format json)، أو - للقراءة من الدخل القياسي",
        "h_format": "صيغة الإخراج (انظر --list-formats)",
        "h_output": "ملف الإخراج (الافتراضي: الخرج القياسي)",
        "h_lang": "لغة النص المُصدَّر: en أو ar (الافتراضي: en)",
        "h_list": "عرض الصيغ المتاحة ثم الخروج",
        "h_min": "استبعاد النتائج الأقل من هذه الخطورة",
        "h_fail": "junit: أدنى خطورة تُسجَّل اختبارًا فاشلًا (الافتراضي: low)",
        "h_project": "اسم المشروع في الملف المُصدَّر (الافتراضي: هدف التقرير)",
        "h_exposure": "درجة الخطر: أين يعمل التطبيق - internet أو internal (الافتراضي) أو local",
        "h_account": "asff: رقم حساب AWS (12 رقمًا)",
        "h_region": "asff: منطقة AWS، مثل eu-west-1",
        "h_repo": "github-issues و jira-csv: رابط المستودع، لربط كل نتيجة بسطرها",
        "h_ref": "الفرع أو الإيداع المستخدم في تلك الروابط (الافتراضي: HEAD)",
        "h_bom": "csv و jira-csv: بدء الملف بعلامة ترتيب البايتات ليقرأه Excel بترميز UTF-8",
        "h_score": "طباعة درجة خطر كاشِف للمشروع على خرج الأخطاء",
        "m_score": "درجة خطر كاشِف: {score}/10 ({rating}) - {n:open_findings}. ليست درجة CVSS.",
        "m_written": "كُتب الملف: {path} ({fmt})",
        "e_no_report": "تقرير JSON المراد تحويله غير محدَّد: kashif export REPORT.json -f FORMAT "
                       "(أنشئه بالأمر: kashif PATH -f json -o REPORT.json)",
        "e_no_format": "صيغة الإخراج غير محدَّدة: أضف ‎-f FORMAT (القائمة: kashif export --list-formats) أو ‎--score",
    },
}


def _t(lang: str, key: str, **kw) -> str:
    from .i18n.cliargs import fmt                  # "{n:open_findings}": the noun agrees with the number
    text = STR["ar" if lang == "ar" else "en"].get(key) or STR["en"][key]
    return fmt(text, "ar" if lang == "ar" else "en", **kw) if kw else text


class ExportError(ValueError):
    """A request this module cannot fulfil (unknown format, missing ``meta`` value, malformed findings)."""


# ------------------------------------------------------------------------------------------------ normalisation

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ud800-\udfff\ufffe\uffff]")   # not allowed in XML 1.0
_CLOSED = frozenset({"false_positive", "fixed"})                  # no longer a risk
_PARKED = frozenset({"accepted_risk", "wont_fix"})                # still present, deliberately not worked on
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,19}\b", re.I)
_MAX_LINE = 2 ** 31 - 1                                           # the importers store a line as a 32-bit int


def _s(value) -> str:
    """Any value as text without the control characters that XML, CSV readers and JSON consumers choke on."""
    if value is None:
        return ""
    return _CTRL.sub("", value if isinstance(value, str) else str(value))


def _int(value) -> int:
    if isinstance(value, bool):
        return 0
    try:
        n = int(value)
    except (TypeError, ValueError, OverflowError):            # OverflowError: int(float("inf")) from a hostile report
        return 0
    return n if 0 < n <= _MAX_LINE else 0


def _one_line(text: str) -> str:
    """Collapse every run of whitespace (line breaks included) to one space: titles, rule ids, fingerprints."""
    return " ".join(text.split())


def _safe_url(value) -> str:
    """``value`` when it is an absolute http(s) URL, percent-encoded so that it cannot close a Markdown or Jira
    link early; anything else (``javascript:``, ``data:``, a relative path) becomes the empty string."""
    url = _s(value).strip()
    if not re.match(r"(?i)https?://[^\s/]", url) or len(url) > 2000:
        return ""
    return quote(url, safe=":/?#@!$&'*+,;=%~-._")


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:max(0, limit - 1)].rstrip() + "…"


def _cwe_id(cwe: str):
    m = re.search(r"(\d{1,6})", cwe or "")
    return int(m.group(1)) if m else None


def _cwe_url(cwe: str) -> str:
    n = _cwe_id(cwe)
    return f"https://cwe.mitre.org/data/definitions/{n}.html" if n else ""


class _F:
    """One finding, normalised from a ``Finding`` or from its ``to_dict()`` form. Read-only view."""

    __slots__ = ("rule_id", "severity", "title_en", "title_ar", "file", "line", "snippet", "snippet_en", "advice",
                 "advice_en", "cwe", "source", "extra", "fingerprint", "steps", "status")

    def __init__(self, d: dict):
        extra = d.get("extra") if isinstance(d.get("extra"), dict) else {}
        sev = _s(d.get("severity")).lower()
        self.rule_id = _one_line(_s(d.get("rule_id"))) or "unknown"
        self.severity = sev if sev in SEVERITY_RANK else "info"
        title_ar = _one_line(_s(d.get("title_ar")))
        self.title_en = _one_line(_s(d.get("title"))) or _one_line(_s(to_en(title_ar))) or self.rule_id
        self.title_ar = title_ar or self.title_en
        self.file = _s(d.get("file")).replace("\\", "/")
        self.line = _int(d.get("line"))
        self.snippet = _s(d.get("snippet"))
        self.snippet_en = _s(d.get("snippet_en")) or _s(to_en(self.snippet))
        self.advice = _s(d.get("advice"))
        self.advice_en = _s(d.get("advice_en")) or _s(to_en(self.advice))
        cwe_n = _cwe_id(_s(d.get("cwe")))                 # only the canonical "CWE-<number>" form is written:
        self.cwe = f"CWE-{cwe_n}" if cwe_n else ""          # the raw value would end up inside links and labels
        self.source = _one_line(_s(d.get("source"))) or "vulnscan"
        self.extra = extra
        self.fingerprint = _one_line(_s(d.get("fingerprint")))[:200]
        self.steps = []
        path = extra.get("path")
        for st in path if isinstance(path, list) else []:
            if isinstance(st, dict):
                text = _s(st.get("text"))
                self.steps.append({"file": _s(st.get("file")).replace("\\", "/") or self.file,
                                   "line": _int(st.get("line")), "text": text,
                                   "text_en": _s(st.get("text_en")) or _s(to_en(text))})
        triage = extra.get("triage")
        self.status = _one_line(_s(triage.get("status"))).lower() if isinstance(triage, dict) else ""

    # language-dependent text
    def title(self, lang: str) -> str:
        return self.title_ar if lang == "ar" else self.title_en

    def fix(self, lang: str) -> str:
        return self.advice if lang == "ar" else self.advice_en

    def code(self, lang: str) -> str:
        return self.snippet if lang == "ar" else self.snippet_en

    def step_text(self, st: dict, lang: str) -> str:
        return st["text"] if lang == "ar" else st["text_en"]

    def taint_source(self, lang: str) -> str:
        key = "taint_source" if lang == "ar" else "taint_source_en"
        return _s(self.extra.get(key) or self.extra.get("taint_source"))

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}" if self.line else self.file

    @property
    def is_web(self) -> bool:
        return self.source == "web" or "://" in self.file

    @property
    def cve(self) -> str:
        m = _CVE.search(self.rule_id) or _CVE.search(self.title_en)
        return m.group(0).upper() if m else ""


def _normalise(findings) -> "list[_F]":
    """Findings as ``_F`` views, highest severity first. ``Finding`` objects get their fingerprints the way the
    JSON report does; dicts without a ``fingerprint`` get one computed from the same identity."""
    if isinstance(findings, dict) and isinstance(findings.get("findings"), list):
        findings = findings["findings"]                     # a whole JSON report is accepted too
    if not isinstance(findings, (list, tuple)):
        raise ExportError(_t("en", "e_findings"))
    objs = [f for f in findings if isinstance(f, Finding)]
    dicts = []
    try:
        if objs:
            ensure_fingerprints(objs)
        for f in findings:
            if isinstance(f, Finding):
                dicts.append(f.to_dict())
            elif isinstance(f, dict):
                dicts.append(f)
            else:
                raise ExportError(_t("en", "e_findings"))
    except (KeyError, TypeError, AttributeError) as e:      # a Finding with an unknown severity, a non-dict extra ...
        raise ExportError(_t("en", "e_findings")) from e
    out = [_F(d) for d in dicts]
    missing = [x for x in out if not x.fingerprint]
    if missing:
        shadows = [Finding(x.rule_id, x.severity, x.title_en, x.title_ar, x.file, x.line, x.snippet, x.advice,
                           x.cwe, x.source, {k: v for k, v in x.extra.items() if k == "archive_member"})
                   for x in missing]
        assign_fingerprints(shadows)
        for x, shadow in zip(missing, shadows):
            x.fingerprint = shadow.fingerprint()
    return sorted(out, key=lambda x: (SEVERITY_RANK[x.severity], x.file, x.line, x.rule_id, x.fingerprint))


def _severity_arg(value, lang: str, default: str) -> str:
    if value in (None, ""):
        return default
    sev = str(value).lower()
    if sev not in SEVERITY_RANK:
        raise ExportError(_t(lang, "e_severity", value=value, choices=", ".join(SEVERITIES)))
    return sev


def _timestamp(meta: dict) -> datetime:
    """The scan time from ``meta["generated_at"]`` (ISO 8601), else now. Always timezone-aware UTC."""
    raw = meta.get("generated_at")
    if isinstance(raw, datetime):
        dt = raw
    else:
        try:
            dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00")) if raw else datetime.now(timezone.utc)
        except ValueError:
            dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        dt = dt.astimezone(timezone.utc).replace(microsecond=0)
        dt.timestamp()
        if dt.year < 1970:                                  # strftime("%Y") is not zero-padded before year 1000
            raise ValueError(dt.year)
    except (ValueError, OverflowError, OSError):            # year 1 with a +14:00 offset, year 9999 with -12:00 ...
        dt = datetime.now(timezone.utc).replace(microsecond=0)
    return dt


def _project(meta: dict) -> str:
    name = _s(meta.get("project") or meta.get("target") or "")
    name = name.rstrip("/\\")
    return re.split(r"[/\\]", name)[-1] if name and "://" not in name else (name or "project")


def _link(f: _F, meta: dict) -> str:
    """Permalink to the finding's line when ``meta["repo_url"]`` is given (GitHub / GitLab style). The file path
    and the ref are percent-encoded; ``..`` segments are refused; only http(s) URLs are ever returned."""
    repo = _safe_url(_s(meta.get("repo_url")).rstrip("/"))
    if f.is_web:
        return _safe_url(f.extra.get("url")) or _safe_url(f.file)
    if not repo or "!" in f.file or not f.file or ".." in f.file.split("/"):
        return ""
    ref = quote(_s(meta.get("ref")) or "HEAD", safe="/-._~")
    return f"{repo}/blob/{ref}/{quote(f.file.lstrip('/'), safe='/-._~')}" + (f"#L{f.line}" if f.line else "")


# ---------------------------------------------------------------------------------------------- risk score

_BASE = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
_SEV_CODE = {"critical": "C", "high": "H", "medium": "M", "low": "L", "info": "I"}
# CWE classes. A CWE in none of them weighs 1.00 ("UNK").
_CWE_CLASSES = (
    ("INJ", 1.10, {20, 22, 23, 36, 73, 74, 77, 78, 88, 89, 90, 91, 94, 95, 96, 98, 99, 113, 119, 120, 121, 122, 125,
                   134, 190, 416, 434, 470, 502, 564, 610, 611, 643, 652, 776, 787, 829, 913, 915, 917, 918, 943,
                   1321, 1333, 1336}),
    ("AUTH", 1.00, {250, 259, 269, 284, 285, 287, 290, 294, 295, 297, 306, 307, 310, 311, 312, 319, 320,
                    321, 322, 323, 324, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 345, 347, 384, 425, 521,
                    522, 523, 639, 640, 732, 759, 760, 780, 798, 862, 863, 916, 1390}),
    ("WEB", 0.95, {79, 80, 83, 87, 116, 346, 352, 451, 601, 942, 1021, 1022, 1275}),
    ("HARD", 0.85, {16, 200, 201, 209, 215, 315, 489, 497, 525, 532, 538, 540, 548, 614, 615, 693, 756, 778, 1004, 1104,
                    1188}),
)
_EXPOSURE = {"internet": (1.10, "I"), "internal": (1.00, "N"), "local": (0.85, "L")}
# Path segments that mark code which is not shipped to production.
_NON_PROD = re.compile(
    r"(?i)(^|/)(tests?|testing|__tests__|spec|specs|e2e|fixtures?|testdata|test[-_]data|mocks?|examples?|samples?|"
    r"demos?|docs?|documentation|vendor|third[-_]party|node_modules|benchmarks?)(/|$)"
    r"|(^|/)(test_[^/]+|[^/]+_test\.[a-z0-9]+|[^/]+\.(test|spec)\.[a-z0-9]+|conftest\.py)$")


def _cwe_class(cwe: str):
    n = _cwe_id(cwe)
    if n is None:
        return "UNK", 1.00
    for code, weight, ids in _CWE_CLASSES:
        if n in ids:
            return code, weight
    return "UNK", 1.00


def _round1(value: float) -> float:
    """One decimal, halves rounded up (8.25 -> 8.3), whatever the binary representation of the product."""
    return math.floor(value * 10.0 + 0.5 + 1e-9) / 10.0


def _rating(score: float) -> str:
    if score <= 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def rating_label(rating: str, lang: str = "en") -> str:
    """Display name of a rating (``none``, ``low``, ``medium``, ``high``, ``critical``) in ``lang``."""
    return _t(lang, "r_" + rating) if rating in ("none", "low", "medium", "high", "critical") else rating


def _exposure_arg(meta: dict, lang: str = "en") -> str:
    value = str((meta or {}).get("exposure") or "internal").lower()
    if value not in _EXPOSURE:
        raise ExportError(_t(lang, "e_exposure", value=value))
    return value


def _risk(f: _F, exposure: str) -> dict:
    extra = f.extra
    base = _BASE[f.severity]
    cls, c = _cwe_class(f.cwe)
    traced = bool(extra.get("taint_source") or extra.get("analysis") == "dataflow" or extra.get("interprocedural")
                  or len(f.steps) >= 2)
    if extra.get("audit"):
        e, e_code = 0.60, "A"                   # a lead: the engine found no untrusted source
    elif traced or f.status == "confirmed":
        e, e_code = 1.10, "P"                   # proven
    else:
        e, e_code = 1.00, "M"                   # pattern match
    reach = extra.get("reachable", extra.get("reachability"))
    if reach is False or (isinstance(reach, str) and reach.lower() in ("unreachable", "no", "false", "dead")):
        r, r_code = 0.50, "U"
    elif reach is True or (isinstance(reach, str) and reach.lower() in ("reachable", "yes", "true")) \
            or (extra.get("taint_source") and not extra.get("audit")):
        r, r_code = 1.05, "E"                   # starts at an entry point / untrusted input
    else:
        r, r_code = 1.00, "X"                   # unknown
    path = extra.get("archive_member") or f.file
    if not f.is_web and _NON_PROD.search(str(path).replace("\\", "/")):
        x, x_code = 0.50, "T"                   # test / example / vendored code
    elif f.is_web:
        x, x_code = 1.10, "W"                   # observed on a live URL
    else:
        x, x_code = _EXPOSURE[exposure]
    closed = f.status in _CLOSED
    score = 0.0 if closed else _round1(min(10.0, base * c * e * r * x))
    return {"score": score, "rating": _rating(score),
            "vector": f"KRS:1.0/S:{_SEV_CODE[f.severity]}/C:{cls}/E:{e_code}/R:{r_code}/X:{x_code}",
            "factors": {"severity_base": base, "cwe_class": c, "evidence": e, "reachability": r, "exposure": x},
            "counted": not closed and f.status not in _PARKED}


def risk_score(finding, meta: "dict | None" = None) -> dict:
    """Kashif risk score of one finding (a ``Finding`` or its dict form). NOT a CVSS score.

    Returns ``{"score": 0.0-10.0, "rating": none|low|medium|high|critical, "vector": "KRS:1.0/S:H/C:INJ/E:P/R:E/X:N",
    "factors": {...the five multipliers...}, "counted": bool}``; ``counted`` is False for findings the project
    score leaves out (false positive, fixed, accepted risk, won't fix). ``meta["exposure"]`` may be
    ``internet``, ``internal`` (default) or ``local``. The formula is in the module docstring."""
    return _risk(_normalise([finding])[0], _exposure_arg(meta or {}))


def _project_score(scores: "list[float]") -> float:
    ranked = sorted((s for s in scores if s > 0), reverse=True)
    if not ranked:
        return 0.0
    top = ranked[0]
    return _round1(min(10.0, top + (10.0 - top) * (1.0 - math.exp(-sum(ranked[1:]) / 40.0))))


def project_risk(findings, meta: "dict | None" = None) -> dict:
    """Kashif risk score of a project. NOT a CVSS score.

    Returns ``{"score", "rating", "open_findings", "by_rating": {rating: count}, "top": [up to 10 findings],
    "findings": [{"fingerprint", "rule_id", "file", "line", "severity", "score", "rating", "vector", "counted"}]}``
    with findings ordered from the highest score. The formula is in the module docstring."""
    exposure = _exposure_arg(meta or {})
    return _project_risk(_normalise(findings), exposure)


def _project_risk(items: "list[_F]", exposure: str) -> dict:
    rows = []
    for f in items:
        r = _risk(f, exposure)
        rows.append({"fingerprint": f.fingerprint, "rule_id": f.rule_id, "file": f.file, "line": f.line,
                     "severity": f.severity, "cwe": f.cwe, "score": r["score"], "rating": r["rating"],
                     "vector": r["vector"], "counted": r["counted"]})
    rows.sort(key=lambda row: (-row["score"], row["file"], row["line"], row["rule_id"]))
    counted = [row for row in rows if row["counted"]]
    score = _project_score([row["score"] for row in counted])
    by_rating = {name: 0 for name in ("critical", "high", "medium", "low", "none")}
    for row in counted:
        by_rating[row["rating"]] += 1
    return {"score": score, "rating": _rating(score), "open_findings": len(counted), "by_rating": by_rating,
            "top": counted[:10], "findings": rows}


# ------------------------------------------------------------------------------------------------ text blocks

def _fence(text: str) -> str:
    """A Markdown code fence longer than any run of backticks inside ``text``."""
    longest = max((len(m.group(0)) for m in re.finditer(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def _md_text(text: str) -> str:
    """Prose for a Markdown body: no @mentions, issue references, HTML, links, images (a remote image is a
    tracking beacon for whoever opens the ticket), code spans or broken table cells."""
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = re.sub(r"([\\\[\]`])", r"\\\1", text)
    text = re.sub(r"@(?=\w)", "@\u200b", text)
    text = re.sub(r"#(?=\d)", "#\u200b", text)
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _md_code(text: str) -> str:
    """Inline code span that cannot be closed early by a backtick in ``text``."""
    text = text.replace("\r", " ").replace("\n", " ")
    ticks = "`" * (max((len(m.group(0)) for m in re.finditer(r"`+", text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{ticks}{pad}{text}{pad}{ticks}"


def _markdown_body(f: _F, risk: dict, meta: dict, lang: str, marker: bool = False) -> str:
    L = lambda key: _t(lang, key)                                           # noqa: E731
    out = []
    out.append(f"**{L('severity')}:** {_sev_name(f.severity, lang)} · **{L('rule')}:** {_md_code(f.rule_id)}"
               + (f" · **{L('cwe')}:** [{f.cwe}]({_cwe_url(f.cwe)})" if _cwe_url(f.cwe) else ""))
    link = _link(f, meta)
    loc = f"[{_md_code(f.location)}]({link})" if link else _md_code(f.location)
    out += ["", f"**{L('location')}:** {loc}", ""]
    out.append(f"**{L('risk')}:** {risk['score']}/10 ({rating_label(risk['rating'], lang)}) — "
               f"{_md_code(risk['vector'])}")
    code = f.code(lang)
    if code:
        fence = _fence(code)
        out += ["", f"**{L('snippet')}:**", "", fence, code, fence]
    if f.steps:
        out += ["", f"**{L('flow')}:**", ""]
        src = f.taint_source(lang)
        if src:
            out.append(f"- {L('source')}: {_md_code(src)}")
        for i, st in enumerate(f.steps, 1):
            where = f"{st['file']}:{st['line']}" if st["line"] else st["file"]
            out.append(f"{i}. {_md_code(where)} — {_md_text(f.step_text(st, lang))}")
    fix = f.fix(lang)
    if fix:
        out += ["", f"**{L('fix')}:** {_md_text(fix)}"]
    out += ["", f"{L('found_by')} {L('fingerprint')}: {_md_code(f.fingerprint)}. {L('risk_note')}."]
    if marker:
        out.append(f"<!-- kashif-fingerprint: {re.sub(r'[^0-9a-zA-Z:]', '', f.fingerprint)} -->")
    return "\n".join(out)


def _sev_name(sev: str, lang: str) -> str:
    return SEVERITY_AR[sev] if lang == "ar" else sev.capitalize()


def _plain_body(f: _F, risk: dict, lang: str) -> str:
    """Plain-text description used where the consumer renders no markup (JUnit, ASFF, OCSF)."""
    L = lambda key: _t(lang, key)                                           # noqa: E731
    lines = [f"{L('rule')}: {f.rule_id}" + (f" ({f.cwe})" if f.cwe else ""),
             f"{L('severity')}: {_sev_name(f.severity, lang)}",
             f"{L('location')}: {f.location}",
             f"{L('risk')}: {risk['score']}/10 ({rating_label(risk['rating'], lang)}) {risk['vector']}"]
    if f.code(lang):
        lines.append(f"{L('snippet')}: {f.code(lang)}")
    if f.steps:
        lines.append(f"{L('flow')}:")
        for i, st in enumerate(f.steps, 1):
            where = f"{st['file']}:{st['line']}" if st["line"] else st["file"]
            lines.append(f"  {i}. {where}  {f.step_text(st, lang)}")
    if f.fix(lang):
        lines.append(f"{L('fix')}: {f.fix(lang)}")
    return "\n".join(lines)


# ------------------------------------------------------------------------------------------------ DefectDojo

_DD_SEVERITY = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}


def _defectdojo(items, risks, meta, lang) -> str:
    """DefectDojo Generic Findings Import. Only documented keys: the parser rejects a file with an unknown one."""
    when = _timestamp(meta).strftime("%Y-%m-%d")
    findings = []
    for f, risk in zip(items, risks):
        desc = _markdown_body(f, risk, meta, lang)
        row = {"title": _cut(f.title(lang), 500), "severity": _DD_SEVERITY[f.severity], "description": desc,
               "mitigation": f.fix(lang), "date": when,
               "unique_id_from_tool": f.fingerprint, "vuln_id_from_tool": _cut(f.rule_id, 500),
               "static_finding": not f.is_web, "dynamic_finding": f.is_web,
               "active": f.status not in _CLOSED and f.status not in _PARKED,
               "verified": f.status == "confirmed", "false_p": f.status == "false_positive",
               "risk_accepted": f.status == "accepted_risk", "is_mitigated": f.status == "fixed",
               "severity_justification": f"{_t(lang, 'risk_note')}: {risk['score']}/10 "
                                         f"({rating_label(risk['rating'], lang)}), {risk['vector']}",
               "tags": sorted({ENGINE_ID, re.sub(r"[^a-z0-9_.-]+", "-", f.source.lower()).strip("-") or ENGINE_ID})}
        refs = [u for u in (_cwe_url(f.cwe), _safe_url(f.extra.get("url")), _link(f, meta)) if u]
        if refs:
            row["references"] = "\n".join(dict.fromkeys(refs))
        if f.file:
            row["file_path"] = _cut(f.file, 4000)
        if f.line:
            row["line"] = f.line
        if _cwe_id(f.cwe) is not None:
            row["cwe"] = _cwe_id(f.cwe)
        if f.cve:
            row["cve"] = f.cve
        if f.steps and not f.is_web:
            first, last = f.steps[0], f.steps[-1]
            src = f.taint_source("en")
            if src:
                row["sast_source_object"] = _cut(src, 500)
            row["sast_sink_object"] = _cut(re.sub(r"^[^:]*:\s*", "", last["text_en"]) or last["text_en"], 500)
            if first["line"]:
                row["sast_source_line"] = first["line"]
            row["sast_source_file_path"] = _cut(first["file"], 4000)
        findings.append(row)
    doc = {"findings": findings}
    if meta.get("defectdojo_test_type"):                 # opt-in: creates / selects a Test Type of that name
        doc = {"type": _s(meta["defectdojo_test_type"]), "version": _s(meta.get("tool_version") or __version__),
               "static_tool": True, "dynamic_tool": False, **doc}
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


# ------------------------------------------------------------------------------------------------- SonarQube

_SONAR_IMPACT3 = {"critical": "HIGH", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "LOW"}
_SONAR_IMPACT5 = {"critical": "BLOCKER", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}
_SONAR_LEGACY = {"critical": "BLOCKER", "high": "CRITICAL", "medium": "MAJOR", "low": "MINOR", "info": "INFO"}
_SONAR_EFFORT = {"critical": 120, "high": 60, "medium": 30, "low": 15, "info": 5}


def _sonar_location(file: str, line: int, message: str) -> dict:
    loc = {"message": _cut(message, 1000) or "-", "filePath": file}
    if line:
        loc["textRange"] = {"startLine": line}
    return loc


def _sonar_issue(f: _F, lang: str) -> dict:
    message = f.title(lang)
    src = f.taint_source(lang)
    if src:
        message += f" ({_t(lang, 'source')}: {src})"
    issue = {"ruleId": f.rule_id, "effortMinutes": _SONAR_EFFORT[f.severity],
             "primaryLocation": _sonar_location(f.file or ".", f.line, message)}
    secondary = []
    for i, st in enumerate(f.steps, 1):
        if not st["line"] or not st["file"] or (st["file"] == f.file and st["line"] == f.line):
            continue                                       # the importer needs a line; the primary is not repeated
        secondary.append(_sonar_location(st["file"], st["line"], f"{i}. {f.step_text(st, lang)}"))
    if secondary:
        issue["secondaryLocations"] = secondary
    return issue


def _sonarqube(items, risks, meta, lang) -> str:
    """SonarQube 10.3+ Generic Issue Import: rules (with impacts) and issues. Severity lives on the rule, so a
    rule takes the highest severity among its findings. No ``flows`` key exists in this format."""
    scale = _SONAR_IMPACT5 if str(meta.get("sonar_severity_scale", "3")) == "5" else _SONAR_IMPACT3
    items = [f for f in items if f.status not in _CLOSED]  # a false positive or a fixed finding is not an issue
    rules: dict = {}
    for f in items:                                         # items are sorted: the first hit is the most severe
        if f.rule_id not in rules:
            desc = " ".join(x for x in (f.fix(lang), f.cwe, _cwe_url(f.cwe)) if x)
            rules[f.rule_id] = {"id": f.rule_id, "name": _cut(f.title(lang), 200) or f.rule_id,
                                "description": desc or f.title(lang), "engineId": ENGINE_ID,
                                "cleanCodeAttribute": "TRUSTWORTHY",
                                "impacts": [{"softwareQuality": "SECURITY", "severity": scale[f.severity]}]}
    doc = {"rules": list(rules.values()), "issues": [_sonar_issue(f, lang) for f in items]}
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


def _sonarqube_legacy(items, risks, meta, lang) -> str:
    """Generic Issue Import as read by SonarQube before 10.3 (issues only; each carries engineId, severity, type)."""
    issues = []
    for f in items:
        if f.status in _CLOSED:                             # a false positive or a fixed finding is not an issue
            continue
        issue = _sonar_issue(f, lang)
        issues.append({"engineId": ENGINE_ID, "ruleId": issue.pop("ruleId"), "severity": _SONAR_LEGACY[f.severity],
                       "type": "VULNERABILITY", **issue})
    return json.dumps({"issues": issues}, ensure_ascii=False, indent=2) + "\n"


# ----------------------------------------------------------------------------------------------------- JUnit

def _junit(items, risks, meta, lang) -> str:
    """JUnit XML: a testsuite per file, a testcase per rule in that file. A finding at or above
    ``meta["fail_on"]`` (default ``low``) fails its testcase; one that was triaged away is ``skipped``; lower
    severities pass and are listed in ``system-out``."""
    fail_rank = SEVERITY_RANK[_severity_arg(meta.get("fail_on"), lang, "low")]
    when = _timestamp(meta).strftime("%Y-%m-%dT%H:%M:%S")
    project = _project(meta)
    groups: dict = {}
    for f, risk in zip(items, risks):
        groups.setdefault(f.file or project, {}).setdefault(f.rule_id, []).append((f, risk))
    root = ET.Element("testsuites", {"name": f"{TOOL} — {project}"})
    totals = {"tests": 0, "failures": 0, "skipped": 0}
    if not groups:
        suite = ET.SubElement(root, "testsuite", {"name": TOOL, "tests": "1", "failures": "0", "errors": "0",
                                                  "skipped": "0", "time": "0", "timestamp": when})
        case = ET.SubElement(suite, "testcase", {"classname": TOOL, "name": _t(lang, "no_findings"), "time": "0"})
        ET.SubElement(case, "system-out").text = _t(lang, "no_findings_body")
        totals["tests"] = 1
    for file in sorted(groups):
        suite = ET.SubElement(root, "testsuite", {"name": file, "errors": "0", "time": "0", "timestamp": when})
        counts = {"tests": 0, "failures": 0, "skipped": 0}
        for rule_id, hits in groups[file].items():
            first = hits[0][0]
            live = [(f, r) for f, r in hits if f.status not in _CLOSED and f.status not in _PARKED]
            failing = [(f, r) for f, r in live if SEVERITY_RANK[f.severity] <= fail_rank]
            case = ET.SubElement(suite, "testcase", {"classname": file, "name": f"{rule_id}: {first.title(lang)}",
                                                     "time": "0", "file": file,
                                                     "line": str(min((f.line for f, _ in hits if f.line), default=0))})
            body = "\n\n".join(_plain_body(f, r, lang) for f, r in hits)
            counts["tests"] += 1
            if failing:
                worst = failing[0][0]
                lines = ", ".join(str(f.line) for f, _ in failing if f.line)
                message = f"[{worst.severity.upper()}] {worst.title(lang)}" + (f" ({_t(lang, 'line')} {lines})"
                                                                                if lines else "")
                ET.SubElement(case, "failure", {"type": worst.severity, "message": _cut(message, 500)}).text = body
                counts["failures"] += 1
            elif not live:
                ET.SubElement(case, "skipped", {"message": f"{_t(lang, 'status')}: {first.status}"})
                ET.SubElement(case, "system-out").text = body
                counts["skipped"] += 1
            else:
                ET.SubElement(case, "system-out").text = body
        for key, n in counts.items():
            suite.set(key, str(n))
            totals[key] += n
    root.set("tests", str(totals["tests"]))
    root.set("failures", str(totals["failures"]))
    root.set("errors", "0")
    root.set("skipped", str(totals["skipped"]))
    root.set("time", "0")
    _indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


def _indent(elem, level: int = 0) -> None:
    """Pretty-print in place (ElementTree.indent is 3.9+, but it also re-indents text-only nodes differently)."""
    pad = "\n" + "  " * level
    children = list(elem)
    if children:
        if not (elem.text or "").strip():
            elem.text = pad + "  "
        for child in children:
            _indent(child, level + 1)
            child.tail = pad + "  "
        children[-1].tail = pad
    if level and not (elem.tail or "").strip():
        elem.tail = pad


# ------------------------------------------------------------------------------------------------------- CSV

_FORMULA_START = ("=", "+", "-", "@")
_FULLWIDTH = {"＝": "=", "＋": "+", "－": "-", "＠": "@"}


def neutralise_cell(value) -> str:
    """A spreadsheet-safe CSV cell (CSV / formula injection, CWE-1236).

    A cell that Excel, LibreOffice or Google Sheets would evaluate gets a leading apostrophe, which they show as
    text. That is any cell whose first character - after leading whitespace and invisible characters - is
    ``=``, ``+``, ``-`` or ``@`` (or a full-width form of one), or that begins with a tab, carriage return or
    line feed (which can push a formula into the next cell). Control characters are removed. Numbers passed
    as ``int`` / ``float`` are written unchanged."""
    if isinstance(value, bool) or value is None:
        return "" if value is None else str(value).lower()
    if isinstance(value, (int, float)):
        return str(value)
    text = _s(value)
    if not text:
        return ""
    probe = text.lstrip(" \u00a0\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u202a\u202b\u202c\u202d\u202e")
    first = probe[:1]
    if text[:1] in ("\t", "\r", "\n") or _FULLWIDTH.get(first, first) in _FORMULA_START:
        return "'" + text
    return text


def _csv_text(rows: "list[list]", meta: dict) -> str:
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, dialect="excel", quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    for row in rows:
        writer.writerow([neutralise_cell(cell) for cell in row])
    return ("\ufeff" if meta.get("bom") else "") + buf.getvalue()


def _flow_cell(f: _F, lang: str) -> str:
    parts = []
    for st in f.steps:
        where = f"{st['file']}:{st['line']}" if st["line"] else st["file"]
        parts.append(f"{where} {f.step_text(st, lang)}".strip())
    return " -> ".join(parts)


def _csv(items, risks, meta, lang) -> str:
    """RFC 4180 CSV (CRLF records, quotes doubled), one row per finding, every text cell neutralised."""
    L = lambda key: _t(lang, key)                                           # noqa: E731
    rows = [[L("fingerprint"), L("risk"), L("severity"), L("rule"), L("cwe"), L("title"), L("file"), L("line"),
             L("engine"), L("snippet"), L("fix"), L("flow"), L("source"), L("status"), L("url")]]
    for f, risk in zip(items, risks):
        rows.append([f.fingerprint, risk["score"], _sev_name(f.severity, lang), f.rule_id, f.cwe, f.title(lang),
                     f.file, f.line if f.line else "", f.source, f.code(lang), f.fix(lang), _flow_cell(f, lang),
                     f.taint_source(lang), f.status or "open", _link(f, meta) or _safe_url(f.extra.get("url"))])
    return _csv_text(rows, meta)


# ------------------------------------------------------------------------------------------------------ Jira

_JIRA_PRIORITY = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Lowest"}


def _jira_text(text: str) -> str:
    """Prose for Jira wiki markup: braces, brackets and pipes would start macros, links and tables."""
    return re.sub(r"([{}\[\]|!*_^~+-])", r"\\\1", text.replace("\\", "\\\\")).replace("\r", " ").replace("\n", " ")


def _jira_code(text: str) -> str:
    return "{noformat}\n" + re.sub(r"(?i)\{(\s*noformat[^}]*)\}", r"{ \1 }", text) + "\n{noformat}"


def _jira_label(text: str) -> str:
    return re.sub(r"[^\w.-]+", "-", text, flags=re.UNICODE).strip("-") or ENGINE_ID


def _jira_csv(items, risks, meta, lang) -> str:
    """CSV for Jira's External System Import. Three ``Labels`` columns: Jira reads a repeated column name as
    several values of one field. The last two columns are for optional custom fields."""
    L = lambda key: _t(lang, key)                                           # noqa: E731
    issue_type = _s(meta.get("jira_issue_type")) or "Bug"
    rows = [["Summary", "Issue Type", "Priority", "Labels", "Labels", "Labels", "Description",
             "Kashif Fingerprint", "Kashif Risk Score"]]
    for f, risk in zip(items, risks):
        if f.status in _CLOSED or f.status in _PARKED:
            continue                                        # nothing to do: no ticket
        desc = [f"*{L('severity')}:* {_sev_name(f.severity, lang)}",
                f"*{L('rule')}:* {_jira_text(f.rule_id)}" + (f" ([{f.cwe}|{_cwe_url(f.cwe)}])" if _cwe_url(f.cwe)
                                                           else ""),
                f"*{L('location')}:* {{{{{_jira_text(f.location)}}}}}",
                f"*{L('risk')}:* {risk['score']}/10 ({rating_label(risk['rating'], lang)})"]
        link = _link(f, meta)
        if link:
            desc.append(f"*{L('url')}:* [{link}]")
        if f.code(lang):
            desc += ["", f"*{L('snippet')}:*", _jira_code(f.code(lang))]
        if f.steps:
            desc += ["", f"*{L('flow')}:*"]
            for st in f.steps:
                where = f"{st['file']}:{st['line']}" if st["line"] else st["file"]
                desc.append(f"# {{{{{_jira_text(where)}}}}} {_jira_text(f.step_text(st, lang))}")
        if f.fix(lang):
            desc += ["", f"*{L('fix')}:* {_jira_text(f.fix(lang))}"]
        desc += ["", f"{L('found_by')} {L('fingerprint')}: {_jira_text(f.fingerprint)}. {L('risk_note')}."]
        summary = _cut(f"[{f.severity.upper()}] {f.title(lang)} — {f.location}", 250)
        rows.append([summary, issue_type, _JIRA_PRIORITY[f.severity], "security", ENGINE_ID,
                     _jira_label(f.cwe or f.rule_id), "\n".join(desc), f.fingerprint, risk["score"]])
    return _csv_text(rows, meta)


# ---------------------------------------------------------------------------------------------- GitHub Issues

def _github_issues(items, risks, meta, lang) -> str:
    """JSON list of ``{"title", "body", "labels"}`` - the fields GitHub's "create an issue" API takes. Each body
    ends with ``<!-- kashif-fingerprint: ... -->`` so a script can skip findings that already have an issue."""
    out = []
    for f, risk in zip(items, risks):
        if f.status in _CLOSED or f.status in _PARKED:
            continue
        labels = ["security", ENGINE_ID, f"severity:{f.severity}"] + ([f.cwe] if f.cwe else [])
        title = _cut(f"[{f.severity.upper()}] {f.title(lang)} ({f.location})".replace("\n", " "), 250)
        out.append({"title": title, "body": _markdown_body(f, risk, meta, lang, marker=True), "labels": labels})
    return json.dumps(out, ensure_ascii=False, indent=2) + "\n"


# ------------------------------------------------------------------------------------------------------ ASFF

_ASFF_SEVERITY = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFORMATIONAL"}


def _asff(items, risks, meta, lang) -> str:
    """AWS Security Finding Format: a JSON list for ``aws securityhub batch-import-findings --findings file://F``
    (at most 100 per call). ProductArn is the account's default custom-integration product."""
    account = _s(meta.get("aws_account_id")).strip()
    region = _s(meta.get("aws_region")).strip().lower()
    if not re.fullmatch(r"\d{12}", account) or not re.fullmatch(r"[a-z]{2}(-[a-z]+)+-\d{1,2}", region):
        raise ExportError(_t(lang, "e_aws"))
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    when = _timestamp(meta).strftime("%Y-%m-%dT%H:%M:%SZ")
    project = _project(meta)
    arn = f"arn:{partition}:securityhub:{region}:{account}:product/{account}/default"
    out = []
    for f, risk in zip(items, risks):
        suppressed = f.status in _PARKED or f.status == "false_positive"
        resource = {"Type": "Other", "Id": _cut(f"{project}/{f.file}" if f.file and not f.is_web else
                                                  (f.file or project), 512),
                    "Partition": partition, "Region": region,
                    "Details": {"Other": {k: _cut(v, 1024) for k, v in (("Project", project), ("File", f.file),
                                                                         ("Line", str(f.line or ""))) if v}}}
        item = {
            "SchemaVersion": "2018-10-08",
            "Id": _cut(f"{ENGINE_ID}/{project}/{f.fingerprint}", 512),
            "ProductArn": arn,
            "GeneratorId": _cut(f"{ENGINE_ID}/{f.rule_id}", 512),
            "AwsAccountId": account,
            "Types": [f"Software and Configuration Checks/Vulnerabilities/{f.cwe or 'SAST'}"],
            "CreatedAt": when, "UpdatedAt": when,
            "Severity": {"Label": _ASFF_SEVERITY[f.severity], "Original": f.severity},
            "Title": _cut(f.title(lang), 256),
            "Description": _cut(_plain_body(f, risk, lang), 1024),
            "ProductFields": {"kashif/rule_id": _cut(f.rule_id, 2048), "kashif/fingerprint": f.fingerprint,
                              "kashif/risk_score": str(risk["score"]), "kashif/risk_vector": risk["vector"],
                              "kashif/engine": _cut(f.source, 2048)},
            "Resources": [resource],
            "RecordState": "ACTIVE",
            "Workflow": {"Status": "RESOLVED" if f.status == "fixed" else "SUPPRESSED" if suppressed else "NEW"},
            "VerificationState": {"confirmed": "TRUE_POSITIVE", "false_positive": "FALSE_POSITIVE"}.get(f.status,
                                                                                                        "UNKNOWN"),
        }
        fix = f.fix(lang)
        if fix or _cwe_url(f.cwe):
            rec = {}
            if fix:
                rec["Text"] = _cut(fix, 512)
            if _cwe_url(f.cwe):
                rec["Url"] = _cwe_url(f.cwe)
            item["Remediation"] = {"Recommendation": rec}
        if f.is_web and _safe_url(f.file):
            item["SourceUrl"] = _safe_url(f.file)
        elif f.file and (f.cwe or f.cve):
            path = {"FileName": f.file.rsplit("/", 1)[-1], "FilePath": f.file}
            if f.line:
                path.update(StartLine=f.line, EndLine=f.line)
            code = {"FilePath": path}
            if f.cwe:
                code["Cwes"] = [f.cwe]
            item["Vulnerabilities"] = [{"Id": f.cve or f.cwe, "CodeVulnerabilities": [code]}]
        out.append(item)
    return json.dumps(out, ensure_ascii=False, indent=2) + "\n"


# ------------------------------------------------------------------------------------------------------ OCSF

_OCSF_SEVERITY = {"critical": (5, "Critical"), "high": (4, "High"), "medium": (3, "Medium"), "low": (2, "Low"),
                  "info": (1, "Informational")}


def _ocsf(items, risks, meta, lang) -> str:
    """OCSF 1.3.0 Vulnerability Finding events (category 2 Findings, class 2002), as a JSON list."""
    when = int(_timestamp(meta).timestamp() * 1000)             # timestamp_t: milliseconds since the epoch
    project = _project(meta)
    version = _s(meta.get("tool_version") or __version__)
    out = []
    for f, risk in zip(items, risks):
        sev_id, sev_name = _OCSF_SEVERITY[f.severity]
        if f.status == "fixed":
            activity, status = (3, "Close"), (4, "Resolved")
        elif f.status in _PARKED or f.status == "false_positive":
            activity, status = (1, "Create"), (3, "Suppressed")
        else:
            activity, status = (1, "Create"), (1, "New")
        vuln = {"title": f.title(lang), "desc": _plain_body(f, risk, lang), "severity": sev_name,
                "vendor_name": TOOL}
        if f.cve:
            vuln["cve"] = {"uid": f.cve}
        if f.cwe:
            vuln["cwe"] = {"uid": f.cwe, "src_url": _cwe_url(f.cwe)}
        refs = [u for u in (_cwe_url(f.cwe), _safe_url(f.extra.get("url")), _link(f, meta)) if u]
        if refs:
            vuln["references"] = list(dict.fromkeys(refs))
        if f.file and not f.is_web:
            code = {"file": {"name": f.file.rsplit("/", 1)[-1], "path": f.file, "type_id": 1}}
            if f.line:
                code.update(start_line=f.line, end_line=f.line)
            vuln["affected_code"] = [code]
        if f.fix(lang):
            vuln["remediation"] = {"desc": f.fix(lang)}
        event = {
            "activity_id": activity[0], "activity_name": activity[1],
            "category_uid": 2, "category_name": "Findings",
            "class_uid": 2002, "class_name": "Vulnerability Finding",
            "type_uid": 200200 + activity[0], "type_name": f"Vulnerability Finding: {activity[1]}",
            "severity_id": sev_id, "severity": sev_name,
            "status_id": status[0], "status": status[1],
            "time": when,
            "message": f.title(lang),
            "metadata": {"version": "1.3.0", "product": {"name": TOOL, "vendor_name": TOOL, "version": version},
                         "log_name": project},
            "finding_info": {"uid": f.fingerprint, "title": f.title(lang), "desc": _plain_body(f, risk, lang),
                             "types": [f.rule_id], "created_time": when, "product_uid": ENGINE_ID},
            "vulnerabilities": [vuln],
            "unmapped": {"kashif_risk_score": risk["score"], "kashif_risk_vector": risk["vector"],
                         "kashif_rule_id": f.rule_id, "kashif_engine": f.source, "kashif_location": f.location},
        }
        out.append(event)
    return json.dumps(out, ensure_ascii=False, indent=2) + "\n"


# ------------------------------------------------------------------------------------------------- risk JSON

def _risk_json(items, risks, meta, lang) -> str:
    report = _project_risk(items, _exposure_arg(meta, lang))
    doc = {"name": _t(lang, "risk"), "note": _t(lang, "risk_note"), "project": _project(meta),
           "generated_at": _timestamp(meta).isoformat(), "exposure": _exposure_arg(meta, lang),
           "score": report["score"], "rating": report["rating"],
           "rating_label": rating_label(report["rating"], lang), "open_findings": report["open_findings"],
           "by_rating": report["by_rating"],
           "formula": {"finding": "min(10, severity_base * cwe_class * evidence * reachability * exposure)",
                       "project": "s1 + (10 - s1) * (1 - exp(-(s2 + s3 + ...) / 40)), scores sorted descending",
                       "vector": "KRS:1.0/S:severity/C:cwe class/E:evidence/R:reachability/X:exposure"},
           "findings": report["findings"]}
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


# ------------------------------------------------------------------------------------- GitLab SAST report

GITLAB_SCHEMA_VERSION = "15.0.7"
_GL_SEVERITY = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
_GL_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "gitlab-sast.kashif.invalid")   # fixed: ids stay stable across runs


def _gl_time(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S")                         # the schema's pattern: no zone, no fraction


def _gitlab_sast(items, risks, meta, lang) -> str:
    """GitLab SAST report (``gl-sast-report.json``, schema 15.0.x) for the Security tab and the merge-request
    widget. The vulnerability ``id`` is a UUID derived from the fingerprint, so a re-run keeps every id; the
    primary identifier is the Kashif rule. Findings triaged as false positive or fixed are left out."""
    end = _timestamp(meta)
    start = _timestamp({"generated_at": meta.get("started_at")}) if meta.get("started_at") else end
    if start > end:
        start = end
    version = _s(meta.get("tool_version") or __version__) or "0"
    vulns = []
    for f, risk in zip(items, risks):
        if f.status in _CLOSED:
            continue
        identifiers = [{"type": "kashif_rule_id", "name": f"Kashif {_cut(f.rule_id, 200)}", "value": f.rule_id}]
        if _cwe_id(f.cwe) is not None:
            identifiers.append({"type": "cwe", "name": f.cwe, "value": str(_cwe_id(f.cwe)), "url": _cwe_url(f.cwe)})
        if f.cve:
            identifiers.append({"type": "cve", "name": f.cve, "value": f.cve})
        location: dict = {"file": f.file or "."}
        if f.line:
            location["start_line"] = f.line
            location["end_line"] = f.line
        vuln = {"id": str(uuid.uuid5(_GL_NAMESPACE, f.fingerprint or f"{f.rule_id}:{f.location}")),
                "category": "sast",
                "name": _cut(f.title(lang), 255) or f.rule_id,
                "description": _cut(_markdown_body(f, risk, meta, lang), 1_000_000),
                "severity": _GL_SEVERITY[f.severity],
                "scanner": {"id": ENGINE_ID, "name": TOOL},
                "location": location,
                "identifiers": identifiers}
        fix = f.fix(lang)
        if fix:
            vuln["solution"] = _cut(fix, 7000)
        links = [{"url": u} for u in dict.fromkeys((_cwe_url(f.cwe), _safe_url(f.extra.get("url")))) if u]
        if links:
            vuln["links"] = links
        vulns.append(vuln)
    tool = {"id": ENGINE_ID, "name": TOOL, "version": version, "vendor": {"name": TOOL}}
    doc = {"version": GITLAB_SCHEMA_VERSION, "vulnerabilities": vulns,
           "scan": {"analyzer": dict(tool), "scanner": dict(tool), "type": "sast",
                    "start_time": _gl_time(start), "end_time": _gl_time(end), "status": "success"}}
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


# ------------------------------------------------------------------------------------ Code Climate (GitLab)

_CC_SEVERITY = {"critical": "blocker", "high": "critical", "medium": "major", "low": "minor", "info": "info"}


def _codeclimate(items, risks, meta, lang) -> str:
    """Code Climate issues as a JSON array: the "Code Quality" report of GitLab (``artifacts:reports:codequality``).
    ``fingerprint`` is a hash of the Kashif fingerprint (GitLab compares it between the branch and its target)."""
    out = []
    for f, risk in zip(items, risks):
        if f.status in _CLOSED:
            continue
        line = f.line or 1
        description = f"{f.title(lang)} ({f.rule_id}" + (f", {f.cwe})" if f.cwe else ")")
        out.append({"type": "issue", "check_name": f.rule_id, "description": _cut(description, 1000),
                    "content": {"body": _markdown_body(f, risk, meta, lang)},
                    "categories": ["Security"],
                    "location": {"path": f.file or ".", "lines": {"begin": line, "end": line}},
                    "severity": _CC_SEVERITY[f.severity],
                    "engine_name": ENGINE_ID,
                    "fingerprint": hashlib.sha256((f.fingerprint or f"{f.rule_id}:{f.location}").encode()).hexdigest()[:32]})
    return json.dumps(out, ensure_ascii=False, indent=2) + "\n"


# -------------------------------------------------------------------------------------------------- registry

# id -> (renderer, file extension, MIME type, meta keys the format cannot work without)
FORMATS = {
    "defectdojo": (_defectdojo, "json", "application/json", ()),
    "sonarqube": (_sonarqube, "json", "application/json", ()),
    "sonarqube-legacy": (_sonarqube_legacy, "json", "application/json", ()),
    "junit": (_junit, "xml", "application/xml", ()),
    "csv": (_csv, "csv", "text/csv", ()),
    "jira-csv": (_jira_csv, "csv", "text/csv", ()),
    "github-issues": (_github_issues, "json", "application/json", ()),
    "asff": (_asff, "json", "application/json", ("aws_account_id", "aws_region")),
    "ocsf": (_ocsf, "json", "application/json", ()),
    "risk": (_risk_json, "json", "application/json", ()),
    "gitlab-sast": (_gitlab_sast, "json", "application/json", ()),
    "codeclimate": (_codeclimate, "json", "application/json", ()),
}


def format_info(fmt: str, lang: str = "en") -> dict:
    """``{"id", "name", "description", "ext", "mime", "needs"}`` for one format; ExportError when unknown."""
    if fmt not in FORMATS:
        raise ExportError(_t(lang, "e_format", fmt=fmt, choices=", ".join(FORMATS)))
    _, ext, mime, needs = FORMATS[fmt]
    return {"id": fmt, "name": _t(lang, "f_" + fmt), "description": _t(lang, "d_" + fmt), "ext": ext,
            "mime": mime, "needs": list(needs)}


def list_formats(lang: str = "en") -> "list[dict]":
    """Every export format, in menu order, as ``format_info`` dicts (names and descriptions in ``lang``)."""
    return [format_info(fmt, lang) for fmt in FORMATS]


def export(findings, fmt: str, meta: "dict | None" = None) -> str:
    """Render ``findings`` in the format ``fmt`` and return the text (write it with ``newline=""``).

    ``findings``: a list of ``Finding`` objects or of their ``to_dict()`` form (the ``findings`` list of a Kashif
    JSON report, or the whole report). Nothing is mutated except that ``Finding`` objects without fingerprints
    get them, exactly as the JSON report would assign them.

    ``meta`` (all optional unless noted):
      ``lang``            ``en`` (default) or ``ar``: language of titles, remediation text and labels
      ``project`` / ``target``   project name; ``generated_at``: ISO 8601 scan time (default: now)
      ``min_severity``    leave out findings below this severity
      ``exposure``        risk score input: ``internet``, ``internal`` (default) or ``local``
      ``fail_on``         junit: lowest severity that fails a test (default ``low``)
      ``repo_url``, ``ref``   link findings to their line: ``<repo_url>/blob/<ref>/<file>#L<line>``
      ``bom``             csv, jira-csv: prepend a UTF-8 byte order mark (Excel)
      ``jira_issue_type`` jira-csv: default ``Bug``
      ``defectdojo_test_type``   defectdojo: write a top-level ``type`` (a DefectDojo Test Type name)
      ``sonar_severity_scale``   sonarqube: ``3`` (default; HIGH / MEDIUM / LOW) or ``5`` (adds BLOCKER and INFO,
                          which older servers reject - believed to need SonarQube 10.8 or later; not verified
                          against the importer source, so test one import before relying on it)
      ``aws_account_id``, ``aws_region``   asff: REQUIRED
      ``tool_version``    version written to the export (default: this package's)

    Raises ``ExportError`` for an unknown format, a missing required ``meta`` value or malformed findings."""
    meta = dict(meta or {})
    lang = "ar" if meta.get("lang") == "ar" else "en"
    if fmt not in FORMATS:
        raise ExportError(_t(lang, "e_format", fmt=fmt, choices=", ".join(FORMATS)))
    items = _normalise(findings)
    floor = _severity_arg(meta.get("min_severity"), lang, "info")
    items = [f for f in items if SEVERITY_RANK[f.severity] <= SEVERITY_RANK[floor]]
    exposure = _exposure_arg(meta, lang)
    risks = [_risk(f, exposure) for f in items]
    return FORMATS[fmt][0](items, risks, meta, lang)


# ------------------------------------------------------------------------------------------------------- CLI

def _bi(lang: str, key: str, **kw) -> str:
    """A command-line text in ``lang``; "both" (the default of ``kashif``): the Arabic line, then the English line."""
    from .i18n.cliargs import pick
    return pick(lang, _t("ar", key, **kw), _t("en", key, **kw))


def _parser(lang: str) -> argparse.ArgumentParser:
    from .i18n.cliargs import HelpFormatter
    h = lambda key: _bi(lang, key)                                         # noqa: E731
    p = argparse.ArgumentParser(prog="kashif export", description=h("h_desc"), formatter_class=HelpFormatter)
    p.add_argument("report", nargs="?", help=h("h_report"))
    p.add_argument("-f", "--format", dest="fmt", metavar="FORMAT", help=h("h_format"))
    p.add_argument("-o", "--output", metavar="FILE", help=h("h_output"))
    # "both" (from `kashif export` on a system with no language set): bilingual help and errors, English export
    p.add_argument("--lang", choices=LANGS + ("both",), default=lang, metavar="{en,ar}", help=h("h_lang"))
    p.add_argument("--list-formats", action="store_true", help=h("h_list"))
    p.add_argument("--min-severity", metavar="SEVERITY", help=h("h_min"))
    p.add_argument("--fail-on", metavar="SEVERITY", help=h("h_fail"))
    p.add_argument("--project", help=h("h_project"))
    p.add_argument("--exposure", choices=sorted(_EXPOSURE), help=h("h_exposure"))
    p.add_argument("--aws-account", metavar="ID", help=h("h_account"))
    p.add_argument("--aws-region", metavar="REGION", help=h("h_region"))
    p.add_argument("--repo-url", metavar="URL", help=h("h_repo"))
    p.add_argument("--ref", help=h("h_ref"))
    p.add_argument("--bom", action="store_true", help=h("h_bom"))
    p.add_argument("--score", action="store_true", help=h("h_score"))
    return p


MAX_REPORT_BYTES = 64_000_000          # the same bound as a baseline (baseline.MAX_BASELINE_BYTES)


def _load_report(path: str, lang: str):
    """(findings list, report meta) from a Kashif JSON report file, or from standard input when ``path`` is -.

    At most ``MAX_REPORT_BYTES`` are read, and a named path must be a regular file: ``/dev/zero``, a FIFO or a
    directory is refused with a clear error (exit 2) instead of reading without end or blocking."""
    import os
    import stat
    too_big = ExportError(_bi(lang, "e_report_big", path=path, mb=MAX_REPORT_BYTES // 1_000_000))
    try:
        if path == "-":                                     # bytes, not the console code page (Windows)
            stdin = getattr(sys.stdin, "buffer", None)
            raw = stdin.read(MAX_REPORT_BYTES + 1) if stdin is not None else sys.stdin.read(MAX_REPORT_BYTES + 1)
        else:
            info = os.stat(path)
            if not stat.S_ISREG(info.st_mode):
                raise ExportError(_bi(lang, "e_report_kind", path=path))
            if info.st_size > MAX_REPORT_BYTES:
                raise too_big
            with open(path, "rb") as fh:
                raw = fh.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:                     # stdin, or a file that grew after the stat
            raise too_big
        text = raw.decode("utf-8-sig") if isinstance(raw, bytes) else raw
        data = json.loads(text)
    except ExportError:
        raise
    except (OSError, ValueError, RecursionError) as e:     # RecursionError: JSON nested thousands of levels deep
        raise ExportError(_read_error(lang, path, e)) from e
    # Only a Kashif report goes on: `[]`, `{}` or another tool's JSON would otherwise give an empty export (exit 0)
    if isinstance(data, list) and data and all(_is_finding(d) for d in data):
        return data, {}
    if isinstance(data, dict) and isinstance(data.get("findings"), list) and all(_is_finding(d) for d in data["findings"]):
        return data["findings"], {k: data[k] for k in ("target", "generated_at", "files_scanned") if k in data}
    raise ExportError(_bi(lang, "e_shape", path=path))


def _read_error(lang: str, path: str, e: BaseException) -> str:
    """"cannot read the report" with the reason in the message's own language: the common causes (missing file,
    no permission, broken JSON, not UTF-8) are worded per language instead of Python's English error text."""
    from .i18n.cliargs import pick

    def reason(lg: str) -> str:
        if isinstance(e, FileNotFoundError):
            return _t(lg, "r_missing")
        if isinstance(e, PermissionError):
            return _t(lg, "r_denied")
        if isinstance(e, json.JSONDecodeError):
            return _t(lg, "r_json", line=e.lineno, col=e.colno)
        if isinstance(e, UnicodeDecodeError):
            return _t(lg, "r_utf8")
        return str(e)[:300] or type(e).__name__

    return pick(lang, _t("ar", "e_report", path=path, error=reason("ar")),
                _t("en", "e_report", path=path, error=reason("en")))


def _is_finding(d) -> bool:
    """A finding of a Kashif JSON report (``Finding.to_dict()``): an object with a ``rule_id``."""
    return isinstance(d, dict) and isinstance(d.get("rule_id"), str) and bool(d["rule_id"].strip())


def _utf8_stdout() -> None:
    """Standard output as UTF-8 with the text's own line ends: a Windows console code page cannot print Arabic,
    and text mode would turn the CSV formats' CRLF into CR CR LF."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", newline="")
        except (ValueError, OSError):
            pass


def main(argv: "list[str] | None" = None) -> int:
    """Command line: ``python3 -m vulnscan.exporters report.json -f defectdojo -o out.json``.
    Exit status: 0 done, 2 usage or input error."""
    from .i18n.cliargs import help_lang, localized_argparse
    argv = list(sys.argv[1:] if argv is None else argv)
    hlang = help_lang(argv)                                 # the language also decides the language of --help
    with localized_argparse(hlang):
        parser = _parser(hlang)
        args = parser.parse_args(argv)
    lang = "ar" if args.lang == "ar" else "en"             # "both": an English export, as from a "both" scan
    if args.list_formats:
        _utf8_stdout()
        for info in list_formats(lang):
            print(f"{info['id']:<17} .{info['ext']:<5} {info['name']} — {info['description']}")
        return 0
    if not args.report or not (args.fmt or args.score):
        try:                                                # usage, then the missing part, exit 2
            with localized_argparse(hlang):
                parser.error(_bi(hlang, "e_no_report" if not args.report else "e_no_format"))
        except SystemExit:
            return 2
    try:
        findings, meta = _load_report(args.report, args.lang)
        meta["lang"] = lang
        for key, value in (("min_severity", args.min_severity), ("fail_on", args.fail_on), ("project", args.project),
                           ("exposure", args.exposure), ("aws_account_id", args.aws_account),
                           ("aws_region", args.aws_region), ("repo_url", args.repo_url), ("ref", args.ref)):
            if value:
                meta[key] = value
        if args.bom:
            meta["bom"] = True
        if args.fmt == "asff":                              # checked first, so the message names the options
            try:
                _asff([], [], meta, lang)
            except ExportError:
                raise ExportError(_bi(args.lang, "e_aws_cli")) from None
        if args.score:
            report = project_risk(findings, meta)
            print(_t(lang, "m_score", score=report["score"], rating=rating_label(report["rating"], lang),
                     n=report["open_findings"]), file=sys.stderr)
        if not args.fmt:
            return 0
        text = export(findings, args.fmt, meta)
    except ExportError as e:
        print(f"{parser.prog}: {e}", file=sys.stderr)
        return 2
    if not args.output or args.output == "-":
        _utf8_stdout()
        try:
            sys.stdout.write(text)
            sys.stdout.flush()
        except BrokenPipeError:                             # "... | head": not an error worth a traceback
            pass
        return 0
    try:
        with open(args.output, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
    except OSError as e:
        print(f"{parser.prog}: {_t(lang, 'e_write', path=args.output, error=e)}", file=sys.stderr)
        return 2
    print(_t(lang, "m_written", path=args.output, fmt=args.fmt), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
