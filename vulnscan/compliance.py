"""Compliance mapping and auditor report: findings -> OWASP, ASVS, CWE Top 25, PCI DSS, NIST, ISO 27001, HIPAA, GDPR.

INTEGRATION NOTES
=================
(for the step that wires this module into the CLI and the UI; this module edits no existing file)

CLI (cli.py)
    * New sub-command, delegating to ``compliance.main``::

          kashif compliance <report.json | report.sarif | PATH> [--framework ID ...] [-f html|json|csv|md]
                            [-o FILE] [--lang en|ar] [--fail-on SEVERITY] [--min-severity SEVERITY]
                            [--source-root DIR] [--show-secrets] [--project NAME] [--assessor NAME]
          kashif compliance --list-frameworks
          kashif compliance --check-coverage

    * Optional flags on the normal scan: ``--compliance FRAMEWORK[,FRAMEWORK]`` (print ``render_markdown`` after
      the console report) and ``--audit-report FILE`` (write ``render_html``). Both only need the finding list:
      ``compliance.render_html([f.to_dict() for f in findings], meta, lang)``.
    * Code context: ``--source-root DIR`` (or scanning a directory directly) is the only way to get source lines
      into the report. Do not default it from the ``target`` stored in a report file: that file is untrusted
      input and would decide which directory is read. In ``cli.py`` pass ``source_root=<the path just scanned>``.
    * Exit codes of ``main``: 0 = report written, 1 = ``--fail-on`` threshold reached in a selected framework (or
      ``--check-coverage`` found a gap), 2 = usage or input error.

Web UI (server.py, ui/)
    * ``GET /api/scans/<id>/compliance?framework=...&lang=...`` -> ``json.loads(compliance.render_json(findings, meta))``.
    * ``GET /api/scans/<id>/audit.html?lang=...`` -> ``compliance.render_html(...)`` served as text/html (the page
      has no script and no external asset, so it is safe under a strict CSP; offer it as "Auditor report").
    * Finding detail panel: ``compliance.map_finding(finding_dict)`` gives the control chips
      (``compliance.explain_finding`` adds the basis and the source of each mapping).
    * In server.py pass ``source_root`` only for scans the server ran itself on a local path, never for an uploaded
      report or SARIF file; keep ``mask_secrets=True`` for anything that can be downloaded or shared.
    * A control without findings has status ``"pass"`` in the API and must be labelled "No findings" (as
      ``STR[lang]["st_pass"]`` does), never "Pass" or "Compliant".
    * A "Compliance" tab can render ``compliance.summarize(findings, lang=...)`` as one table per framework.

Other outputs
    * SARIF (report.py): add ``compliance.sarif_tags(finding_dict)`` to ``properties.tags`` of each rule.
    * LSP / PR comments: ``compliance.control_labels(finding_dict)`` returns short labels such as
      ``["OWASP A03", "PCI DSS 6.2.4-injection"]``.

Packaging
    * pyproject.toml ``[tool.setuptools.package-data]``: add ``"data/*.json"`` to the ``vulnscan`` list.
    * vulnscan.spec: ``datas += [(f, "vulnscan/data") for f in glob.glob("vulnscan/data/*.json")]`` and add
      ``"vulnscan.compliance"`` to ``hiddenimports``.
    * New engine CWEs: ``tests/test_compliance.py`` fails when a CWE emitted by the rules, models, queries, web
      checks or the APEX analyzer has no OWASP Top 10 mapping (or documented exclusion) or no weakness category.
      Fix it in ``vulnscan/data/compliance.json`` ("cwe_category", and "cwe_analyst" or "cwe_na" of a framework).

README (suggested text)
    "Compliance evidence, offline: ``kashif compliance report.json -f html -o audit.html`` maps every finding to
    OWASP Top 10:2021, OWASP API Security Top 10 2023, OWASP ASVS 4.0.3, CWE Top 25 (2024), PCI DSS v4.0,
    NIST SSDF, NIST SP 800-53 Rev. 5, ISO/IEC 27001:2022 Annex A, HIPAA 164.312 and GDPR Art. 32, and writes a
    printable auditor report (English or Arabic) with a control matrix per framework and an evidence appendix.
    Every mapping states its basis (published by the framework owner, or a Kashif analyst mapping) and its source.
    It also reads SARIF, so results of other tools can be mapped the same way. Hard-coded secrets are masked in
    the report. The report is evidence to support
    an assessment; it is not a certification."

WHAT THE MODULE DOES
====================
``vulnscan/data/compliance.json`` holds the mapping data. For one framework and one CWE the controls are resolved
in this order, and the first step that yields something wins:

1. ``official``  - the CWE is listed for the control by the framework owner (OWASP Top 10 "List of Mapped CWEs",
                   ASVS CSV, API Top 10 references, CWE Top 25 list);
2. ``analyst``   - a Kashif analyst mapping for that CWE (with a written justification);
3. documented exclusion (``cwe_na``): the framework has no control for this weakness; nothing is mapped;
4. ``inherited`` - the nearest CWE ancestor (ChildOf, CWE view 1000) that has an entry of kind 1 or 2 (not for
                   frameworks with ``"inherit": false``, nor through the CWEs under ``no_inherit``);
5. ``category``  - the weakness category of the finding (injection, transport, secrets ...) mapped to controls.
                   PCI DSS, NIST, ISO 27001, HIPAA and GDPR publish no CWE mapping, so they use only this step;

plus ``generic`` controls that apply to every finding (e.g. SA-11). A finding without a CWE is matched by rule id
prefix (``rules`` in the JSON), e.g. ``OSV:`` -> CWE-1395.

Standard library only. Scanned code is never executed. No network access.

SECURITY NOTES (input reports and SARIF files are untrusted)
    * Every value taken from a finding is HTML-escaped; the report has no script and loads nothing.
    * Source files are read only below ``source_root``, which must be given explicitly (``--source-root`` or
      the ``source_root`` argument; the ``target`` written inside a report is never used as a root). Absolute
      paths, drive and UNC paths, URIs and ``..`` escapes in a finding are refused before the file system is
      touched.
    * Findings in the "secrets" category have string literals and assigned values masked in the report unless
      ``mask_secrets=False`` / ``--show-secrets`` is given, so the report can be handed to a third party.
    * Input files larger than ``MAX_INPUT_BYTES`` are refused; long snippets, advice and flows are truncated.
"""

from __future__ import annotations

import argparse
import csv
import functools
import html
import io
import json
import math
import pathlib
import re
import sys
import urllib.parse
from datetime import datetime, timezone

__all__ = [
    "FRAMEWORKS", "STR", "load_data", "framework_info", "resolve_framework", "cwe_ids", "categories", "map_cwe",
    "map_finding", "explain_finding", "control_labels", "sarif_tags", "risk_score", "summarize", "render_html",
    "render_json", "render_csv", "render_markdown", "load_findings", "emitted_cwes", "coverage_gaps", "main",
]

DATA_FILE = pathlib.Path(__file__).resolve().parent / "data" / "compliance.json"
SEVERITIES = ("critical", "high", "medium", "low", "info")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}
RISK_WEIGHTS = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 0.5, "info": 0.0}
SCHEMA = "kashif-compliance/1"
MAX_INPUT_BYTES = 256 * 1024 * 1024       # largest report / SARIF file load_findings reads
_MAX_SNIPPET, _MAX_ADVICE, _MAX_TITLE, _MAX_STEPS = 2000, 4000, 400, 200

# Framework ids in report order, and the short names accepted by --framework.
FRAMEWORKS = ("owasp-top10-2021", "owasp-api-2023", "owasp-asvs-4.0.3", "cwe-top25-2024", "pci-dss-4.0",
              "nist-ssdf-1.1", "nist-800-53r5", "iso-27001-2022", "hipaa-164.312", "gdpr-art32")
_ALIASES = {
    "owasp": "owasp-top10-2021", "owasp-top10": "owasp-top10-2021", "top10": "owasp-top10-2021",
    "api": "owasp-api-2023", "owasp-api": "owasp-api-2023", "api-top10": "owasp-api-2023",
    "asvs": "owasp-asvs-4.0.3", "owasp-asvs": "owasp-asvs-4.0.3",
    "top25": "cwe-top25-2024", "cwe-top25": "cwe-top25-2024", "cwe": "cwe-top25-2024",
    "pci": "pci-dss-4.0", "pci-dss": "pci-dss-4.0", "pcidss": "pci-dss-4.0",
    "ssdf": "nist-ssdf-1.1", "nist-ssdf": "nist-ssdf-1.1", "800-218": "nist-ssdf-1.1",
    "800-53": "nist-800-53r5", "nist-800-53": "nist-800-53r5", "nist": "nist-800-53r5",
    "iso": "iso-27001-2022", "iso27001": "iso-27001-2022", "iso-27001": "iso-27001-2022", "27001": "iso-27001-2022",
    "hipaa": "hipaa-164.312", "gdpr": "gdpr-art32",
}

STR = {
    "en": {
        "report_title": "Application Security Compliance Evidence Report",
        "report_sub": "Static analysis findings mapped to security frameworks",
        "not_cert": "This report is evidence to support an assessment. It is not a certification, an attestation of "
                    "compliance or an audit opinion.",
        "not_cert_long": "It was produced by automated static analysis of the material listed under Scope. A control "
                         "shown as \"No findings\" means only that the tool reported nothing that maps to it; "
                         "it does not show that the control is implemented or effective. Static analysis can miss "
                         "vulnerabilities and can report issues that are not exploitable. Compliance with any "
                         "framework named here can only be determined by a qualified assessor who examines people, "
                         "process and technology, and for PCI DSS, HIPAA and GDPR only within the applicable scope "
                         "(cardholder data, ePHI, personal data).",
        "target": "Target", "project": "Project", "assessor": "Prepared by", "date": "Report date",
        "scan_date": "Analysis date", "tool": "Tool", "files": "Files analysed", "findings": "Findings",
        "frameworks": "Frameworks", "contents": "Contents",
        "s_scope": "Scope", "s_method": "Methodology", "s_exec": "Executive summary", "s_matrices": "Control matrices",
        "s_appendix": "Appendix A: findings and evidence", "s_sources": "Appendix B: mapping sources",
        "scope_in": "In scope",
        "scope_in_txt": "Source code, configuration and infrastructure-as-code files of the target, analysed without "
                        "executing them: pattern rules, inter-procedural data-flow (taint) analysis and semantic "
                        "queries. Results imported from other tools appear with their own source name.",
        "scope_out": "Out of scope",
        "scope_out_txt": "Running systems and their deployed configuration, network and host controls, penetration "
                         "testing, manual code review, business-logic review, organisational policies and procedures, "
                         "physical security, and any code or component not present in the analysed material.",
        "notes": "Analysis notes",
        "m_1": "Each finding carries a CWE identifier. For every framework the CWE is resolved to controls in this "
               "order; the first step that yields a result is used.",
        "m_basis": "Basis", "m_meaning": "Meaning",
        "b_official": "Official", "b_official_txt": "The framework owner lists this CWE for the control.",
        "b_analyst": "Analyst", "b_analyst_txt": "Mapping assigned by the Kashif maintainers for this CWE, with a "
                                                 "written justification. Not published by the framework owner.",
        "b_inherited": "Inherited", "b_inherited_txt": "Taken from the nearest parent weakness in the CWE hierarchy "
                                                       "that has an official or analyst mapping.",
        "b_category": "Category", "b_category_txt": "Analyst mapping from the weakness category (for example "
                                                    "injection, transport security) to the control. Used for "
                                                    "frameworks that publish no CWE mapping.",
        "b_generic": "Generic", "b_generic_txt": "The control concerns every finding (for example developer security "
                                                 "testing).",
        "m_status": "Control status",
        "m_status_txt": "Fail: at least one mapped finding of severity {sev} or higher. Review: only findings below "
                        "that severity. No findings: nothing mapped to the control; this is absence of "
                        "findings, not proof that the control is met. A control that concerns every finding "
                        "(basis Generic, for example developer security testing) is shown as Review at most: the "
                        "findings are what that activity produces, not evidence that it is missing.",
        "m_risk": "Risk score",
        "m_risk_txt": "W = 10 x critical + 5 x high + 2 x medium + 0.5 x low; score = 100 x (1 - e^(-W/25)), rounded. "
                      "Rating: 0 none, 1-24 low, 25-49 moderate, 50-74 high, 75-100 critical; never below \"high\" "
                      "when a critical finding exists, nor below \"moderate\" when a high finding exists. The score "
                      "ranks reports against each other; it is not a CVSS score or a likelihood.",
        "m_review": "Analyst and category mappings are judgement. Review them before relying on them; the sources "
                    "are listed in Appendix B.",
        "risk": "Risk score", "rating": "Rating",
        "r_none": "None", "r_low": "Low", "r_moderate": "Moderate", "r_high": "High", "r_critical": "Critical",
        "sev": "Severity", "count": "Count",
        "critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info",
        "framework": "Framework", "controls_with": "Controls with findings", "mapped": "Findings mapped",
        "unmapped": "Not mapped", "status": "Status", "top_controls": "Controls with the most findings",
        "st_fail": "Fail", "st_warn": "Review", "st_pass": "No findings",
        "control": "Control", "title": "Title", "total": "Total", "evidence": "Evidence", "basis": "Basis",
        "no_findings": "No findings were reported.",
        "hit_only": "{n} further mapped requirements have no findings and are not listed.",
        "fw_note": "Note", "fw_source": "Source",
        "rule": "Rule", "location": "Location", "code": "Code", "flow": "Data flow", "fix": "Remediation",
        "mapping": "Mapped controls", "fingerprint": "Fingerprint", "taint_source": "Untrusted source",
        "reference": "Reference", "detected_by": "Detected by", "none_mapped": "No control mapped",
        "src_name": "Source", "src_ref": "Reference", "src_retrieved": "Retrieved",
        "unmapped_note": "{n} finding(s) have no CWE that this framework covers and are not counted in the matrix.",
        "footer": "Generated by Kashif {v}. Evidence to support an assessment; not a certification.",
        "more": "+{n} more", "masked": "secret values masked", "truncated": "[truncated]",
        "cli_too_big": "input is larger than {mb} MB",
        "cli_wrote": "wrote {path}", "cli_no_input": "input not found: {path}",
        "cli_bad_fw": "unknown framework: {name} (use --list-frameworks)",
        "cli_bad_json": "cannot read findings from {path}: {err}",
        "cli_gate": "compliance gate: {fw} has findings of severity {sev} or higher",
        "cli_cov_ok": "coverage: all {n} emitted CWEs are mapped",
        "cli_cov_gap": "coverage gap: {cwe} ({why}) emitted by {where}",
    },
    "ar": {
        "report_title": "تقرير أدلة الامتثال لأمن التطبيقات",
        "report_sub": "نتائج التحليل الساكن مربوطة بأطر العمل الأمنية",
        "not_cert": "هذا التقرير دليل يدعم عملية التقييم. ليس شهادة ولا إقرارًا بالامتثال ولا رأي تدقيق.",
        "not_cert_long": "أُنتج بتحليل ساكن آلي للمواد المذكورة في قسم النطاق. الضابط الذي يظهر بحالة «لا نتائج» "
                         "يعني فقط أن الأداة لم تُبلّغ عن شيء يرتبط به، ولا يثبت أن الضابط مطبَّق أو فعّال. التحليل الساكن "
                         "قد يفوّت ثغرات وقد يُبلّغ عن مشكلات غير قابلة للاستغلال. الامتثال لأي إطار مذكور هنا لا يحدده "
                         "إلا مقيّم مؤهل يفحص الأفراد والإجراءات والتقنية، وفي PCI DSS وHIPAA وGDPR ضمن النطاق المنطبق "
                         "فقط (بيانات حاملي البطاقات، المعلومات الصحية الإلكترونية، البيانات الشخصية).",
        "target": "الهدف", "project": "المشروع", "assessor": "أعدّه", "date": "تاريخ التقرير",
        "scan_date": "تاريخ التحليل", "tool": "الأداة", "files": "الملفات المحلَّلة", "findings": "النتائج",
        "frameworks": "أطر العمل", "contents": "المحتويات",
        "s_scope": "النطاق", "s_method": "المنهجية", "s_exec": "الملخص التنفيذي", "s_matrices": "مصفوفات الضوابط",
        "s_appendix": "الملحق أ: النتائج والأدلة", "s_sources": "الملحق ب: مصادر الربط",
        "scope_in": "ضمن النطاق",
        "scope_in_txt": "الشيفرة المصدرية وملفات الإعداد والبنية التحتية كشيفرة للهدف، حُلّلت دون تنفيذها: قواعد "
                        "الأنماط، وتحليل تدفق البيانات بين الدوال (taint)، والاستعلامات الدلالية. النتائج المستوردة من "
                        "أدوات أخرى تظهر باسم مصدرها.",
        "scope_out": "خارج النطاق",
        "scope_out_txt": "الأنظمة العاملة وإعداداتها المنشورة، وضوابط الشبكة والخوادم، واختبار الاختراق، والمراجعة "
                         "اليدوية للشيفرة، ومراجعة منطق الأعمال، والسياسات والإجراءات التنظيمية، والأمن المادي، وأي "
                         "شيفرة أو مكوّن غير موجود في المواد المحلَّلة.",
        "notes": "ملاحظات التحليل",
        "m_1": "تحمل كل نتيجة معرّف CWE. لكل إطار عمل يُربط المعرّف بالضوابط بهذا الترتيب، وتُستخدم أول خطوة تعطي نتيجة.",
        "m_basis": "الأساس", "m_meaning": "المعنى",
        "b_official": "رسمي", "b_official_txt": "مالك الإطار يُدرج هذا المعرّف تحت الضابط.",
        "b_analyst": "محلل", "b_analyst_txt": "ربط وضعه فريق كاشِف لهذا المعرّف مع تبرير مكتوب. غير منشور من مالك الإطار.",
        "b_inherited": "موروث", "b_inherited_txt": "مأخوذ من أقرب نقطة ضعف أم في تسلسل CWE لها ربط رسمي أو ربط محلل.",
        "b_category": "فئة", "b_category_txt": "ربط محلل من فئة نقطة الضعف (مثل الحقن أو أمن النقل) إلى الضابط. "
                                               "يُستخدم للأطر التي لا تنشر ربطًا بمعرّفات CWE.",
        "b_generic": "عام", "b_generic_txt": "الضابط يخص كل نتيجة (مثل اختبار المطوّر الأمني).",
        "m_status": "حالة الضابط",
        "m_status_txt": "راسب: نتيجة واحدة على الأقل مرتبطة بخطورة {sev} أو أعلى. مراجعة: نتائج دون تلك الخطورة فقط. "
                        "لا نتائج: لا شيء مرتبط بالضابط؛ هذا غياب للنتائج وليس إثباتًا لتحقق الضابط. الضابط الذي يخص كل نتيجة "
                        "(الأساس «عام»، مثل اختبار المطوّر الأمني) يظهر بحالة «مراجعة» على الأكثر: النتائج هي ناتج ذلك "
                        "النشاط وليست دليلًا على غيابه.",
        "m_risk": "درجة المخاطر",
        "m_risk_txt": "W = 10 × الحرجة + 5 × العالية + 2 × المتوسطة + 0.5 × المنخفضة؛ الدرجة = 100 × (1 − e^(−W/25)) "
                      "مقرّبة. التصنيف: 0 لا يوجد، 1–24 منخفض، 25–49 متوسط، 50–74 عالٍ، 75–100 حرج؛ ولا يقل عن «عالٍ» "
                      "عند وجود نتيجة حرجة ولا عن «متوسط» عند وجود نتيجة عالية. الدرجة للمقارنة بين التقارير، وليست "
                      "درجة CVSS ولا احتمالًا.",
        "m_review": "ربط المحلل وربط الفئة اجتهاد. راجعهما قبل الاعتماد عليهما؛ المصادر في الملحق ب.",
        "risk": "درجة المخاطر", "rating": "التصنيف",
        "r_none": "لا يوجد", "r_low": "منخفض", "r_moderate": "متوسط", "r_high": "عالٍ", "r_critical": "حرج",
        "sev": "الخطورة", "count": "العدد",
        "critical": "حرج", "high": "عالٍ", "medium": "متوسط", "low": "منخفض", "info": "معلوماتي",
        "framework": "إطار العمل", "controls_with": "ضوابط عليها نتائج", "mapped": "نتائج مرتبطة",
        "unmapped": "غير مرتبطة", "status": "الحالة", "top_controls": "الضوابط الأكثر نتائج",
        "st_fail": "راسب", "st_warn": "مراجعة", "st_pass": "لا نتائج",
        "control": "الضابط", "title": "العنوان", "total": "المجموع", "evidence": "الأدلة", "basis": "الأساس",
        "no_findings": "لم يُبلَّغ عن أي نتيجة.",
        "hit_only": "{n} متطلبًا مرتبطًا آخر بلا نتائج، ولم تُدرج.",
        "fw_note": "ملاحظة", "fw_source": "المصدر",
        "rule": "القاعدة", "location": "الموضع", "code": "الشيفرة", "flow": "مسار تدفق البيانات", "fix": "الإصلاح",
        "mapping": "الضوابط المرتبطة", "fingerprint": "البصمة", "taint_source": "المصدر غير الموثوق",
        "reference": "المرجع", "detected_by": "اكتشفه", "none_mapped": "لا ضابط مرتبط",
        "src_name": "المصدر", "src_ref": "المرجع", "src_retrieved": "تاريخ الجلب",
        "unmapped_note": "{n} نتيجة ليس لها معرّف CWE يغطيه هذا الإطار، ولم تُحتسب في المصفوفة.",
        "footer": "أنتجه كاشِف {v}. دليل يدعم التقييم، وليس شهادة.",
        "more": "+{n} أخرى", "masked": "القيم السرية محجوبة", "truncated": "[مقتطع]",
        "cli_too_big": "المُدخل أكبر من {mb} ميغابايت",
        "cli_wrote": "كُتب {path}", "cli_no_input": "المُدخل غير موجود: {path}",
        "cli_bad_fw": "إطار عمل غير معروف: {name} (استخدم --list-frameworks)",
        "cli_bad_json": "تعذّرت قراءة النتائج من {path}: {err}",
        "cli_gate": "بوابة الامتثال: في {fw} نتائج بخطورة {sev} أو أعلى",
        "cli_cov_ok": "التغطية: كل معرّفات CWE الصادرة ({n}) مرتبطة",
        "cli_cov_gap": "فجوة تغطية: {cwe} ({why}) يصدر من {where}",
    },
}


def _lang(lang: str | None) -> str:
    """Report language: "ar" or "en" (the shared "both" setting means Arabic here)."""
    return "en" if lang == "en" else "ar" if lang in ("ar", "both") else "en"


def _t(lang: str, key: str, **kw) -> str:
    text = STR[_lang(lang)].get(key) or STR["en"][key]
    return text.format(**kw) if kw else text


# ----------------------------------------------------------------------------------------------------------------
# Data
# ----------------------------------------------------------------------------------------------------------------

@functools.lru_cache(maxsize=4)
def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    for key in ("frameworks", "cwe_category", "cwe_parents", "cwe_names", "categories", "sources"):
        if not isinstance(data.get(key), dict):
            raise ValueError(f"compliance data: missing object {key!r}")
    return data


def load_data(path: str | pathlib.Path | None = None) -> dict:
    """The mapping data (``vulnscan/data/compliance.json`` by default), parsed once and cached. Treat it as
    read-only."""
    return _load(str(path or DATA_FILE))


def resolve_framework(name: str) -> str | None:
    """Canonical framework id for an id, an alias ("pci", "asvs", "owasp") or a unique prefix; None if unknown."""
    n = (name or "").strip().lower().replace("_", "-")
    if n in FRAMEWORKS:
        return n
    if n in _ALIASES:
        return _ALIASES[n]
    hits = [f for f in FRAMEWORKS if f.startswith(n)] if n else []
    return hits[0] if len(hits) == 1 else None


def _frameworks(selected) -> list[str]:
    if not selected or selected == "all" or selected == ["all"]:
        return list(FRAMEWORKS)
    if isinstance(selected, str):
        selected = [selected]
    selected = [s for item in selected for s in re.split(r"[,\s]+", str(item)) if s]
    if not selected:
        return list(FRAMEWORKS)
    out = []
    for name in selected:
        if name == "all":
            return list(FRAMEWORKS)
        fid = resolve_framework(name)
        if fid is None:
            raise ValueError(name)
        if fid not in out:
            out.append(fid)
    return out


def framework_info(framework: str, lang: str = "en") -> dict:
    """Title, note and source of one framework: ``{"id", "title", "short", "note", "source": {title, url, ...}}``."""
    data = load_data()
    fid = resolve_framework(framework)
    if fid is None:
        raise ValueError(framework)
    fw = data["frameworks"][fid]
    title = fw.get("title_ar") if _lang(lang) == "ar" and fw.get("title_ar") else fw["title"]
    return {"id": fid, "title": title, "short": fw.get("short", fw["title"]), "note": fw.get("note", ""),
            "source": dict(data["sources"].get(fw.get("source", ""), {}), id=fw.get("source", "")),
            "controls": len(fw["controls"])}


def _control_title(fid: str, control: str, lang: str = "en") -> str:
    c = load_data()["frameworks"][fid]["controls"].get(control) or {}
    if _lang(lang) == "ar" and c.get("title_ar"):
        return c["title_ar"]
    return c.get("title", "")


# ----------------------------------------------------------------------------------------------------------------
# Mapping
# ----------------------------------------------------------------------------------------------------------------

_CWE_RX = re.compile(r"CWE[-_ ]?0*(\d{1,5})(?!\d)", re.I)


def _num(cwe) -> str:
    """"CWE-089", "89" or 89 -> "89"; "" when it is not a CWE."""
    text = str(cwe).strip()
    if text.isdigit():
        return str(int(text))
    m = _CWE_RX.search(text)
    return m.group(1) if m else ""


def _as_dict(finding) -> dict:
    """A finding as the JSON-report dict; accepts a ``vulnscan.model.Finding`` too."""
    if isinstance(finding, dict):
        return finding
    to_dict = getattr(finding, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    raise TypeError(f"finding must be a dict or a Finding, not {type(finding).__name__}")


def _rule_entries(rule_id: str) -> list[dict]:
    return [r for r in load_data().get("rules", []) if rule_id.startswith(r.get("prefix", "\0"))]


def cwe_ids(finding) -> list[str]:
    """CWE numbers of a finding as strings (``["89"]``): from its ``cwe`` field (several are allowed, in any of the
    forms tools write: "CWE-89", "cwe-089", "CWE-89: SQL Injection", 89, ["CWE-89", "CWE-564"]), else from the
    rule-id table."""
    f = _as_dict(finding)
    out: list[str] = []
    raw = f.get("cwe")
    parts = []
    for item in (raw if isinstance(raw, (list, tuple)) else [raw])[:50]:
        if isinstance(item, bool) or item is None:
            continue
        if isinstance(item, int) or (isinstance(item, str) and item.strip().isdigit()):
            item = f"CWE-{int(item)}" if 0 < int(item) < 100000 else ""     # a bare number: 89 or "89"
        parts.append(str(item)[:400])
    for n in _CWE_RX.findall(" ".join(parts)):
        if n not in out:
            out.append(n)
    if not out:
        for entry in _rule_entries(str(f.get("rule_id") or "")):
            for n in _CWE_RX.findall(entry.get("cwe", "")):
                if n not in out:
                    out.append(n)
    return out


def _ancestor_levels(cwe: str):
    """Yield the ancestors of a CWE level by level (parents, then grandparents ...)."""
    parents = load_data()["cwe_parents"]
    seen = {cwe}
    level = [p for p in parents.get(cwe, [])]
    while level:
        level = [p for i, p in enumerate(level) if p not in seen and p not in level[:i]]
        if not level:
            return
        seen.update(level)
        yield level
        level = [pp for p in level for pp in parents.get(p, [])]


def _direct(fw: dict, cwe: str):
    """(controls, basis) from the framework's own CWE tables, or None when the CWE has no entry."""
    if cwe in fw.get("cwe", {}):
        return list(fw["cwe"][cwe]), "official"
    if cwe in fw.get("cwe_analyst", {}):
        return list(fw["cwe_analyst"][cwe].get("controls", [])), "analyst"
    if cwe in fw.get("cwe_na", {}):
        return [], "na"
    return None


@functools.lru_cache(maxsize=8192)
def _map_cwe(fid: str, cwe: str) -> tuple:
    """((control, basis, detail), ...) for one CWE, without category fallback and generic controls."""
    fw = load_data()["frameworks"][fid]
    hit = _direct(fw, cwe)
    if hit is not None:
        ctrls, basis = hit
        detail = fw.get("cwe_analyst", {}).get(cwe, {}).get("note", "") if basis == "analyst" else \
            fw.get("cwe_na", {}).get(cwe, "") if basis == "na" else f"CWE-{cwe}"
        return tuple((c, basis, detail) for c in ctrls) or ((("", "na", detail),) if basis == "na" else ())
    if fw.get("inherit") is False:
        return ()
    blocked = set(load_data().get("no_inherit", []))
    for level in _ancestor_levels(cwe):
        out = []
        for p in level:
            got = None if p in blocked else _direct(fw, p)
            if got and got[1] != "na":
                for c in got[0]:
                    if all(c != o[0] for o in out):
                        out.append((c, "inherited", f"CWE-{p}"))
        if out:
            return tuple(out)
    return ()


@functools.lru_cache(maxsize=8192)
def _cwe_categories(cwe: str) -> tuple:
    data = load_data()
    cats = data["cwe_category"]
    if cwe in cats:
        return tuple(cats[cwe])
    blocked = set(data.get("no_inherit", []))
    for level in _ancestor_levels(cwe):
        out = []
        for p in level:
            for c in ([] if p in blocked else cats.get(p, [])):
                if c not in out:
                    out.append(c)
        if out:
            return tuple(out)
    default = data.get("owasp_default_category", {})
    out = []
    for ctrl, basis, _ in _map_cwe("owasp-top10-2021", cwe):
        if basis != "na" and default.get(ctrl) and default[ctrl] not in out:
            out.append(default[ctrl])
    return tuple(out) or ("other",)


def categories(finding) -> list[str]:
    """Weakness categories of a finding (ids of ``categories`` in the data, e.g. ``["injection"]``; ``["other"]``
    when nothing is known about it)."""
    f = _as_dict(finding)
    out: list[str] = []
    for cwe in cwe_ids(f):
        for c in _cwe_categories(cwe):
            if c not in out:
                out.append(c)
    for entry in _rule_entries(str(f.get("rule_id") or "")):
        for c in entry.get("categories", []):
            if c not in out:
                out.append(c)
    if len(out) > 1 and "other" in out:
        out.remove("other")
    return out or ["other"]


def _explain(f: dict, fid: str) -> list[dict]:
    fw = load_data()["frameworks"][fid]
    rows: list[dict] = []

    def add(control, basis, detail):
        if control and all(r["control"] != control for r in rows):
            rows.append({"control": control, "basis": basis, "detail": detail})

    cwes = cwe_ids(f)
    for cwe in cwes:
        mapped = _map_cwe(fid, cwe)
        for control, basis, detail in mapped:
            if basis != "na":
                add(control, basis, detail if basis != "official" else f"CWE-{cwe}")
        if not mapped:                                  # no CWE-level entry at all: fall back to the category
            for cat in _cwe_categories(cwe):
                for control in fw.get("category", {}).get(cat, []):
                    add(control, "category", cat)
    for entry in _rule_entries(str(f.get("rule_id") or "")):
        for cat in entry.get("categories", []):
            for control in fw.get("category", {}).get(cat, []):
                add(control, "category", cat)
    for control in fw.get("all", []):
        add(control, "generic", "")
    return rows


def map_cwe(cwe: str | int, frameworks=None) -> dict[str, list[str]]:
    """Controls for one CWE (``"CWE-89"``, ``"89"`` or ``89``): ``{framework: [control, ...]}``."""
    num = _num(cwe)
    return map_finding({"cwe": f"CWE-{num}" if num else "", "rule_id": ""}, frameworks)


def map_finding(finding, frameworks=None) -> dict[str, list[str]]:
    """Controls a finding maps to: ``{framework_id: [control_id, ...]}`` for every selected framework (all by
    default). Frameworks with no applicable control have an empty list.

    >>> map_finding({"rule_id": "X", "cwe": "CWE-89"})["owasp-top10-2021"]
    ['A03']
    """
    f = _as_dict(finding)
    return {fid: [r["control"] for r in _explain(f, fid)] for fid in _frameworks(frameworks)}


def explain_finding(finding, frameworks=None, lang: str = "en") -> dict[str, list[dict]]:
    """Like :func:`map_finding`, with the reason for each control:
    ``{framework_id: [{"control", "title", "basis", "detail", "source"}, ...]}``.

    ``basis`` is ``official`` (listed by the framework owner; ``detail`` = the CWE), ``analyst`` (``detail`` = the
    justification), ``inherited`` (``detail`` = the ancestor CWE), ``category`` (``detail`` = the category id) or
    ``generic``. ``source`` is a key of ``load_data()["sources"]``."""
    f = _as_dict(finding)
    data = load_data()
    out = {}
    for fid in _frameworks(frameworks):
        src = data["frameworks"][fid].get("source", "")
        out[fid] = [{**r, "title": _control_title(fid, r["control"], lang),
                     "source": src if r["basis"] in ("official", "generic") else
                     f"{src}+cwe-hierarchy" if r["basis"] == "inherited" else "kashif-analyst"}
                    for r in _explain(f, fid)]
    return out


def control_labels(finding, frameworks=None) -> list[str]:
    """Short labels for chips and comments, e.g. ``["OWASP Top 10 A03", "PCI DSS 6.2.4-injection"]``. Generic
    controls are left out."""
    f = _as_dict(finding)
    data = load_data()
    out = []
    for fid in _frameworks(frameworks):
        short = data["frameworks"][fid].get("short", fid)
        for r in _explain(f, fid):
            if r["basis"] != "generic":
                out.append(f"{short} {r['control']}")
    return out


def sarif_tags(finding, frameworks=("owasp-top10-2021", "cwe-top25-2024", "pci-dss-4.0")) -> list[str]:
    """Tags for SARIF ``properties.tags``: ``["owasp-top10-2021/A03", "pci-dss-4.0/6.2.4-injection", ...]``."""
    f = _as_dict(finding)
    return [f"{fid}/{r['control']}" for fid in _frameworks(list(frameworks)) for r in _explain(f, fid)
            if r["basis"] != "generic"]


# ----------------------------------------------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------------------------------------------

def _sev(f: dict) -> str:
    s = str(f.get("severity") or "").lower()
    return s if s in _RANK else "info"


class _Prepared(list):
    """Marker: a finding list that went through :func:`_prepare` (normalised severity, line, extra, ``_id``)."""


def _int(value) -> int:
    """A non-negative int from anything a report may carry (strings, floats, Infinity, None); 0 when unusable."""
    if isinstance(value, bool):
        return 0
    try:
        n = int(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0
    return n if 0 <= n < 10 ** 9 else 0


def _prepare(findings) -> list[dict]:
    """Findings as dicts, highest severity first, each with a stable report id ``_id`` (F-001 ...)."""
    items = [dict(_as_dict(f)) for f in (findings or [])]
    for f in items:
        f["severity"] = _sev(f)
        f["line"] = _int(f.get("line"))
        if not isinstance(f.get("extra"), dict):
            f["extra"] = {}
    items.sort(key=lambda f: (_RANK[f["severity"]], str(f.get("file") or ""), f["line"], str(f.get("rule_id") or "")))
    width = max(3, len(str(len(items))))
    for i, f in enumerate(items, 1):
        f["_id"] = f"F-{i:0{width}d}"
    return _Prepared(items)


def _counts(items) -> dict[str, int]:
    out = {s: 0 for s in SEVERITIES}
    for f in items:
        out[_sev(f)] += 1
    return out


def risk_score(findings) -> dict:
    """Overall risk of a finding list: ``{"score": 0..100, "rating": none|low|moderate|high|critical, "weighted",
    "counts", "weights"}``. The formula is printed in the report (see ``STR["en"]["m_risk_txt"]``)."""
    counts = _counts(_as_dict(f) for f in (findings or []))
    weighted = sum(RISK_WEIGHTS[s] * n for s, n in counts.items())
    score = int(round(100 * (1 - math.exp(-weighted / 25.0))))
    if weighted > 0:
        score = max(score, 1)
    bands = ["none", "low", "moderate", "high", "critical"]
    band = 0 if score == 0 else 1 if score < 25 else 2 if score < 50 else 3 if score < 75 else 4
    if counts["critical"]:
        band = max(band, 3)
    elif counts["high"]:
        band = max(band, 2)
    return {"score": score, "rating": bands[band], "weighted": weighted, "counts": counts, "weights": dict(RISK_WEIGHTS)}


def _status(counts: dict, fail_on: str) -> str:
    total = sum(counts.values())
    if not total:
        return "pass"
    limit = _RANK.get(fail_on, _RANK["medium"])
    return "fail" if any(counts[s] for s in SEVERITIES if _RANK[s] <= limit) else "warn"


def _control_key(control: str):
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", control)]


def summarize(findings, frameworks=None, lang: str = "en", fail_on: str = "medium") -> dict[str, dict]:
    """Per-framework control table.

    Returns ``{framework_id: {"id", "title", "short", "note", "source", "status", "controls_total",
    "controls_with_findings", "findings_mapped", "findings_unmapped", "rows": [...]}}`` where each row is
    ``{"control", "title", "counts": {severity: n}, "total", "status", "findings": [report ids], "basis": [...]}``.

    ``status`` is ``fail`` (a mapped finding of severity ``fail_on`` or higher), ``warn`` (only lower ones) or
    ``pass`` (no mapped finding: absence of findings, not proof of compliance). A control that only has generic
    mappings (e.g. SA-11 "Developer Testing", PCI DSS 6.3.1) is never ``fail``: findings are what that activity
    produces. Rows follow the framework's
    control order; every control of the framework is present (section-level fallback controls, used by ASVS, only
    when they have findings). ``findings_unmapped`` counts findings that map to
    no control of the framework other than generic ones."""
    items = findings if isinstance(findings, _Prepared) else _prepare(findings)
    data = load_data()
    out = {}
    for fid in _frameworks(frameworks):
        fw = data["frameworks"][fid]
        info = framework_info(fid, lang)
        rows = {c: {"control": c, "title": _control_title(fid, c, lang), "counts": {s: 0 for s in SEVERITIES},
                    "total": 0, "status": "pass", "findings": [], "basis": []} for c in fw["controls"]}
        mapped = unmapped = 0
        for f in items:
            specific = False
            for r in _explain(f, fid):
                row = rows.get(r["control"])
                if row is None:
                    continue
                row["counts"][f["severity"]] += 1
                row["total"] += 1
                row["findings"].append(f["_id"])
                if r["basis"] not in row["basis"]:
                    row["basis"].append(r["basis"])
                specific = specific or r["basis"] != "generic"
            mapped += specific
            unmapped += not specific
        kept = [r for r in rows.values() if r["total"] or not fw["controls"][r["control"]].get("fallback")]
        ordered = sorted(kept, key=lambda r: (fw["controls"][r["control"]].get("rank", 0),
                                                       _control_key(r["control"])))
        for row in ordered:
            row["basis"].sort()
            row["status"] = _status(row["counts"], fail_on)
            if row["basis"] == ["generic"] and row["status"] == "fail":
                row["status"] = "warn"                   # findings are the output of the activity, not its failure
        specific_rows = [r for r in ordered if r["total"] and r["basis"] != ["generic"]]
        worst = "fail" if any(r["status"] == "fail" for r in specific_rows) else \
            "warn" if specific_rows else "pass"
        out[fid] = {**info, "status": worst, "controls_total": len(ordered),
                    "controls_with_findings": sum(1 for r in ordered if r["total"]),
                    "findings_mapped": mapped, "findings_unmapped": unmapped, "rows": ordered}
    return out


# ----------------------------------------------------------------------------------------------------------------
# Rendering helpers
# ----------------------------------------------------------------------------------------------------------------

def _version() -> str:
    try:
        from . import __version__
        return __version__
    except ImportError:                                  # run as a plain script
        return ""


def _to_en(text):
    try:
        from .i18n import to_en
    except ImportError:
        return text
    try:
        return to_en(text)
    except Exception:                                    # a broken catalog must not break a report
        return text


def _f_title(f: dict, lang: str) -> str:
    if lang == "ar":
        return str(f.get("title_ar") or f.get("title") or f.get("rule_id") or "")
    return str(f.get("title") or _to_en(f.get("title_ar") or "") or f.get("rule_id") or "")


def _f_text(f: dict, key: str, lang: str) -> str:
    if lang == "ar":
        return str(f.get(key) or "")
    return str(f.get(f"{key}_en") or _to_en(f.get(key) or "") or "")


def _steps(f: dict, lang: str) -> list[tuple[str, int, str]]:
    out = []
    path = f["extra"].get("path")
    for st in (path if isinstance(path, list) else [])[:_MAX_STEPS]:
        if isinstance(st, dict):
            text = st.get("text", "") if lang == "ar" else (st.get("text_en") or _to_en(st.get("text", "")))
            out.append((str(st.get("file") or "")[:_MAX_TITLE], _int(st.get("line")), str(text or "")[:_MAX_TITLE]))
    return out


def _loc(file, line) -> str:
    return f"{file}:{line}" if line else str(file or "")


_WIN_DEVICES = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def _safe_relative(file) -> str | None:
    """``file`` as a clean relative POSIX path, or None when it is not one.

    A pure string check with no file-system access: absolute paths, Windows drive and UNC paths (``\\\\host\\share``
    would make Windows contact that host), URIs, NTFS streams, device names, archive members (``a.zip!b``) and any
    ``..`` segment are refused."""
    text = str(file or "")
    if not text or len(text) > 4096 or "\0" in text or "!" in text:
        return None
    text = text.replace("\\", "/")
    if text.startswith("/") or ":" in text:
        return None
    parts = [p for p in text.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." or p.split(".")[0].strip().upper() in _WIN_DEVICES for p in parts):
        return None
    return "/".join(parts)


@functools.lru_cache(maxsize=64)
def _file_lines(path: str) -> tuple:
    p = pathlib.Path(path)
    if not p.is_file() or p.stat().st_size > 2_000_000:
        return ()
    return tuple(p.read_text(encoding="utf-8", errors="replace").splitlines())


def _code_context(root, file: str, line: int, radius: int = 2) -> list[tuple[int, str]]:
    """Lines around ``file:line`` read from ``root`` (never outside it); empty when the file is not available."""
    rel = _safe_relative(file)
    if not root or rel is None or line <= 0:
        return []
    try:
        base = pathlib.Path(root).resolve()
        if base.is_file():
            base = base.parent
        path = (base / rel).resolve()
        if base not in path.parents:                     # a symbolic link that leaves the root
            return []
        lines = _file_lines(str(path))
    except (OSError, ValueError):
        return []
    lo, hi = max(1, line - radius), min(len(lines), line + radius)
    return [(n, lines[n - 1][:240]) for n in range(lo, hi + 1)] if lo <= hi else []


_SECRET_CATEGORIES = {"secrets", "crypto-key"}
# The alternatives of each branch are disjoint (an escape, or one character that is neither the quote nor a
# backslash), so an unterminated string cannot cause catastrophic backtracking.
_SECRET_STR = re.compile(r'''"((?:\\.|[^"\\]){6,})"|'((?:\\.|[^'\\]){6,})'|`([^`]{6,})`''')
_SECRET_KV = re.compile(r"""([=:]\s*)([^\s"'`,;#*]{8,})""")
_SECRET_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")


def _mask_secrets(text: str) -> str:
    """Hide what may be a secret in a line of code: the content of string literals, values after ``=`` or ``:``
    and long tokens keep their first two characters, the rest becomes ``******``."""
    def cut(value: str) -> str:
        return value[:2] + "******"
    def literal(m) -> str:
        quote = m.group(0)[0]
        return quote + cut(m.group(1) or m.group(2) or m.group(3)) + quote
    text = _SECRET_STR.sub(literal, text[:_MAX_SNIPPET + 100])
    text = _SECRET_KV.sub(lambda m: m.group(1) + cut(m.group(2)), text)
    return _SECRET_TOKEN.sub(lambda m: cut(m.group(0)), text)


def _clip(text, limit: int, lang: str = "en") -> str:
    text = str(text if text is not None else "")
    return text if len(text) <= limit else text[:limit] + " " + _t(lang, "truncated")


def _meta(meta, items) -> dict:
    m = dict(meta or {})
    m.setdefault("target", "")
    m.setdefault("files_scanned", None)
    m.setdefault("generated_at", "")
    m.setdefault("tool_version", _version())
    m.setdefault("report_generated_at", datetime.now(timezone.utc).isoformat(timespec="seconds"))
    notes = m.get("notes") or []
    m["notes"] = [str(n) for n in notes] if isinstance(notes, list) else [str(notes)]
    return m


def _notes(m: dict, lang: str) -> list[str]:
    if lang == "ar":
        return m["notes"]
    en = m.get("notes_en")
    return [str(n) for n in en] if isinstance(en, list) and len(en) == len(m["notes"]) else [_to_en(n) for n in m["notes"]]


def _sources_used(fids) -> list[tuple[str, dict]]:
    data = load_data()
    keys = [data["frameworks"][f].get("source", "") for f in fids] + ["cwe-hierarchy", "kashif-analyst"]
    seen, out = set(), []
    for k in keys:
        if k and k not in seen and k in data["sources"]:
            seen.add(k)
            out.append((k, data["sources"][k]))
    return out


# ----------------------------------------------------------------------------------------------------------------
# JSON / CSV / Markdown
# ----------------------------------------------------------------------------------------------------------------

def render_json(findings, meta: dict | None = None, lang: str = "en", frameworks=None, fail_on: str = "medium") -> str:
    """Machine-readable compliance report (schema ``kashif-compliance/1``): disclaimer, risk score, the
    :func:`summarize` tables, and every finding with its mapped controls and their basis."""
    lang = _lang(lang)
    items = _prepare(findings)
    fids = _frameworks(frameworks)
    m = _meta(meta, items)
    out = {
        "schema": SCHEMA,
        "disclaimer": _t(lang, "not_cert") + " " + _t(lang, "not_cert_long"),
        "generated_at": m["report_generated_at"],
        "tool": {"name": "Kashif", "version": m["tool_version"]},
        "scope": {"target": m["target"], "files_scanned": m["files_scanned"], "analysis_date": m["generated_at"],
                  "notes": _notes(m, lang)},
        "fail_on": fail_on if fail_on in _RANK else "medium",
        "risk": risk_score(items),
        "summary": _counts(items),
        "frameworks": summarize(items, fids, lang, fail_on),
        "findings": [{
            "id": f["_id"], "rule_id": f.get("rule_id", ""), "severity": f["severity"], "cwe": f.get("cwe", ""),
            "title": _f_title(f, lang), "file": f.get("file", ""), "line": f["line"],
            "fingerprint": f.get("fingerprint", ""), "source": f.get("source", ""), "categories": categories(f),
            "compliance": explain_finding(f, fids, lang),
        } for f in items],
        "sources": dict(_sources_used(fids)),
    }
    return json.dumps(out, ensure_ascii=False, indent=2)


def render_csv(findings, meta: dict | None = None, lang: str = "en", frameworks=None, fail_on: str = "medium") -> str:
    """The control matrices as CSV, one row per control: framework, control, title, status, a count per severity,
    total, and the report ids of the findings."""
    lang = _lang(lang)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["framework", "control", "title", "status", *SEVERITIES, "total", "basis", "findings"])
    for fid, fw in summarize(_prepare(findings), frameworks, lang, fail_on).items():
        for r in fw["rows"]:
            w.writerow([fid, r["control"], r["title"], r["status"], *[r["counts"][s] for s in SEVERITIES],
                        r["total"], " ".join(r["basis"]), " ".join(r["findings"])])
    return buf.getvalue()


def _md(text) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(findings, meta: dict | None = None, lang: str = "en", frameworks=None,
                    fail_on: str = "medium") -> str:
    """Compact Markdown (for pull-request comments and wikis): disclaimer, risk score and, per framework, the
    controls that have findings."""
    lang = _lang(lang)
    items = _prepare(findings)
    risk = risk_score(items)
    lines = [f"# {_t(lang, 'report_title')}", "", f"> {_t(lang, 'not_cert')}", "",
             f"**{_t(lang, 'risk')}:** {risk['score']}/100 ({_t(lang, 'r_' + risk['rating'])}) - "
             + ", ".join(f"{_t(lang, s)}: {risk['counts'][s]}" for s in SEVERITIES), ""]
    for fid, fw in summarize(items, frameworks, lang, fail_on).items():
        lines += [f"## {fw['title']}", ""]
        rows = [r for r in fw["rows"] if r["total"]]
        if not rows:
            lines += [_t(lang, "no_findings"), ""]
            continue
        lines.append(f"| {_t(lang, 'control')} | {_t(lang, 'title')} | " + " | ".join(_t(lang, s) for s in SEVERITIES)
                     + f" | {_t(lang, 'status')} |")
        lines.append("|---|---|" + "---:|" * len(SEVERITIES) + "---|")
        for r in rows:
            lines.append(f"| {_md(r['control'])} | {_md(r['title'])} | " + " | ".join(str(r["counts"][s]) for s in SEVERITIES)
                         + f" | {_t(lang, 'st_' + r['status'])} |")
        lines.append("")
    return "\n".join(lines)


# ----------------------------------------------------------------------------------------------------------------
# HTML
# ----------------------------------------------------------------------------------------------------------------

_CSS = """
:root{--ink:#16202e;--muted:#566174;--line:#d5dbe4;--soft:#f3f5f8;--accent:#0f4c81;
--critical:#8b1a1a;--high:#b9420b;--medium:#8a6100;--low:#1f5fae;--info:#566174;--pass:#1d6b3a}
*{box-sizing:border-box}
html{font-size:15px}
body{margin:0;background:#e9edf2;color:var(--ink);font-family:"Segoe UI","Noto Sans","Noto Sans Arabic",Tahoma,Arial,sans-serif;line-height:1.55}
main{max-width:1040px;margin:0 auto;background:#fff;padding:0 44px 40px}
h1{font-size:2.1rem;line-height:1.2;margin:0 0 .4rem}
h2{font-size:1.45rem;margin:0 0 .9rem;padding-bottom:.35rem;border-bottom:2px solid var(--accent);color:var(--accent)}
h3{font-size:1.1rem;margin:1.5rem 0 .5rem}
p{margin:.5rem 0}
section{padding-top:36px}
.cover{min-height:92vh;display:flex;flex-direction:column;justify-content:center;padding-top:60px}
.cover .brand{font-size:.95rem;letter-spacing:.12em;text-transform:uppercase;color:var(--accent);font-weight:700;margin-bottom:2.2rem}
.cover .sub{font-size:1.15rem;color:var(--muted);margin-bottom:2rem}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:.35rem 1.4rem;margin:1rem 0 1.6rem}
.kv dt{color:var(--muted)}.kv dd{margin:0;font-weight:600;overflow-wrap:anywhere}
.notice{border:1px solid #c9a227;border-inline-start:6px solid #c9a227;background:#fffaf0;padding:.9rem 1.1rem;margin:1.2rem 0}
.notice b{display:block;margin-bottom:.3rem}
table{width:100%;border-collapse:collapse;margin:.6rem 0 1rem;font-size:.92rem}
th,td{border:1px solid var(--line);padding:.4rem .55rem;text-align:start;vertical-align:top}
th{background:var(--soft);font-weight:600}
td.n,th.n{text-align:center;white-space:nowrap;font-variant-numeric:tabular-nums}
td.z{color:#a3acb9}
td.id{white-space:nowrap;font-weight:600}
table.mx td:nth-child(2){min-width:15rem}
.sev{display:inline-block;padding:.05rem .5rem;border-radius:3px;color:#fff;font-size:.8rem;font-weight:700;white-space:nowrap}
.sev.critical{background:var(--critical)}.sev.high{background:var(--high)}.sev.medium{background:var(--medium)}
.sev.low{background:var(--low)}.sev.info{background:var(--info)}
.st{font-weight:700;white-space:nowrap}.st.fail{color:var(--critical)}.st.warn{color:var(--medium)}.st.pass{color:var(--pass)}
.cnt.critical{color:var(--critical);font-weight:700}.cnt.high{color:var(--high);font-weight:700}
.cnt.medium{color:var(--medium);font-weight:700}.cnt.low{color:var(--low);font-weight:700}.cnt.info{color:var(--info);font-weight:700}
.risk{display:flex;gap:1.6rem;align-items:center;flex-wrap:wrap;margin:1rem 0}
.score{border:3px solid var(--ink);border-radius:8px;padding:.6rem 1.2rem;text-align:center;min-width:150px}
.score .num{font-size:2.6rem;font-weight:800;line-height:1}.score .of{color:var(--muted)}
.score.r-critical{border-color:var(--critical);color:var(--critical)}.score.r-high{border-color:var(--high);color:var(--high)}
.score.r-moderate{border-color:var(--medium);color:var(--medium)}.score.r-low{border-color:var(--low);color:var(--low)}
.score.r-none{border-color:var(--pass);color:var(--pass)}
.bars{flex:1;min-width:280px}
.bar{display:grid;grid-template-columns:7.5rem 1fr 3rem;gap:.6rem;align-items:center;margin:.2rem 0}
.bar .track{background:var(--soft);height:.85rem;border:1px solid var(--line)}
.bar .fill{height:100%}
.fill.critical{background:var(--critical)}.fill.high{background:var(--high)}.fill.medium{background:var(--medium)}
.fill.low{background:var(--low)}.fill.info{background:var(--info)}
.refs a{white-space:nowrap}
a{color:var(--accent)}
.small{font-size:.86rem;color:var(--muted)}
.finding{border:1px solid var(--line);border-inline-start:6px solid var(--info);padding:.7rem 1rem;margin:1rem 0}
.finding.critical{border-inline-start-color:var(--critical)}.finding.high{border-inline-start-color:var(--high)}
.finding.medium{border-inline-start-color:var(--medium)}.finding.low{border-inline-start-color:var(--low)}
.finding h4{margin:0 0 .5rem;font-size:1.02rem}
.finding h4 .fid{color:var(--muted);font-weight:600;margin-inline-end:.5rem}
.finding dl{display:grid;grid-template-columns:max-content 1fr;gap:.3rem 1rem;margin:0}
.finding dt{color:var(--muted);font-size:.88rem}.finding dd{margin:0;min-width:0;overflow-wrap:anywhere}
code,pre{font-family:Consolas,"DejaVu Sans Mono","Courier New",monospace;font-size:.86rem;direction:ltr;unicode-bidi:isolate}
code{background:var(--soft);padding:.05rem .3rem;border-radius:3px;overflow-wrap:anywhere}
pre{background:var(--soft);border:1px solid var(--line);padding:.5rem .7rem;margin:.2rem 0;white-space:pre-wrap;overflow-wrap:anywhere;text-align:left}
pre .hit{background:#ffe9a8;display:inline-block;width:100%}
ol.flow{margin:.2rem 0;padding-inline-start:1.3rem}
.chips span{display:inline-block;border:1px solid var(--line);background:var(--soft);border-radius:3px;padding:0 .4rem;margin:.1rem .15rem .1rem 0;font-size:.82rem;white-space:nowrap}
.chips b{color:var(--accent)}
footer{margin-top:2.5rem;padding-top:.8rem;border-top:1px solid var(--line);color:var(--muted);font-size:.85rem}
ol.toc{padding-inline-start:1.3rem}
@page{size:A4;margin:16mm 14mm 18mm}
@media print{
 html{font-size:11.5px}
 body{background:#fff}
 main{max-width:none;padding:0}
 section{padding-top:0}
 .cover{min-height:0;height:250mm;padding-top:0}
 .pb{break-before:page;page-break-before:always}
 h2,h3,h4{break-after:avoid;page-break-after:avoid}
 tr,.finding,.notice,.risk{break-inside:avoid;page-break-inside:avoid}
 thead{display:table-header-group}
 a{color:inherit;text-decoration:none}
 *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
"""


def _e(text) -> str:
    return html.escape(str(text if text is not None else ""), quote=True)


def _bt(text) -> str:
    """Escaped text; identifiers and English titles are isolated left-to-right so they read correctly in RTL."""
    text = str(text if text is not None else "")
    if re.search(r"[\u0600-\u06FF]", text):
        return f"<bdi>{_e(text)}</bdi>"
    return f"<bdi dir='ltr'>{_e(text)}</bdi>"


def _sev_badge(sev: str, lang: str) -> str:
    return f"<span class='sev {sev}'>{_e(_t(lang, sev))}</span>"


def _count_cells(counts: dict) -> str:
    return "".join(f"<td class='n cnt {s}'>{counts[s]}</td>" if counts[s] else "<td class='n z'>0</td>" for s in SEVERITIES)


def _refs(ids: list[str], lang: str, limit: int = 24) -> str:
    shown = " ".join(f"<a href='#{_e(i)}'>{_e(i)}</a>" for i in ids[:limit])
    if len(ids) > limit:
        shown += " " + _e(_t(lang, "more", n=len(ids) - limit))
    return f"<span class='refs'>{shown}</span>"


def _basis_label(basis: str, lang: str) -> str:
    return _t(lang, "b_" + basis) if "b_" + basis in STR["en"] else basis


def _matrix_html(fw: dict, lang: str) -> str:
    data_fw = load_data()["frameworks"][fw["id"]]
    rows = fw["rows"]
    hidden = 0
    if data_fw.get("matrix") == "hit-only":
        hidden = sum(1 for r in rows if not r["total"])
        rows = [r for r in rows if r["total"]]
    head = (f"<thead><tr><th>{_e(_t(lang, 'control'))}</th><th>{_e(_t(lang, 'title'))}</th>"
            + "".join(f"<th class='n'>{_e(_t(lang, s))}</th>" for s in SEVERITIES)
            + f"<th class='n'>{_e(_t(lang, 'status'))}</th><th>{_e(_t(lang, 'basis'))}</th>"
              f"<th>{_e(_t(lang, 'evidence'))}</th></tr></thead>")
    body = []
    for r in rows:
        basis = ", ".join(_basis_label(b, lang) for b in r["basis"])
        levels = data_fw["controls"][r["control"]].get("levels", "")
        title = _bt(r["title"]) + (f" <span class='small'>({_e(levels)})</span>" if levels else "")
        body.append(f"<tr><td class='id'>{_bt(r['control'])}</td><td>{title}</td>{_count_cells(r['counts'])}"
                    f"<td class='n'><span class='st {r['status']}'>{_e(_t(lang, 'st_' + r['status']))}</span></td>"
                    f"<td class='small'>{_e(basis)}</td><td>{_refs(r['findings'], lang) if r['findings'] else ''}</td></tr>")
    parts = [f"<h3 id='fw-{_e(fw['id'])}'>{_bt(fw['title'])}</h3>"]
    if fw.get("note"):
        parts.append(f"<p class='small'><b>{_e(_t(lang, 'fw_note'))}:</b> {_bt(fw['note'])}</p>")
    src = fw.get("source") or {}
    if src.get("title"):
        link = f" <a href='{_e(src['url'])}'>{_e(src['url'])}</a>" if src.get("url") else ""
        parts.append(f"<p class='small'><b>{_e(_t(lang, 'fw_source'))}:</b> {_bt(src['title'])}{link}</p>")
    if body:
        parts.append(f"<table class='mx'>{head}<tbody>{''.join(body)}</tbody></table>")
    else:
        parts.append(f"<p>{_e(_t(lang, 'no_findings'))}</p>")
    if hidden:
        parts.append(f"<p class='small'>{_e(_t(lang, 'hit_only', n=hidden))}</p>")
    if fw["findings_unmapped"]:
        parts.append(f"<p class='small'>{_e(_t(lang, 'unmapped_note', n=fw['findings_unmapped']))}</p>")
    return "".join(parts)


def _finding_html(f: dict, fids: list[str], lang: str, source_root, mask_secrets: bool = True) -> str:
    data = load_data()
    rows = []

    def dd(label, value_html):
        rows.append(f"<dt>{_e(_t(lang, label))}</dt><dd>{value_html}</dd>")

    cwe = ", ".join(f"CWE-{n}" + (f" ({data['cwe_names'][n]})" if data["cwe_names"].get(n) else "") for n in cwe_ids(f))
    dd("rule", f"<code>{_e(_clip(f.get('rule_id', ''), _MAX_TITLE, lang))}</code>" + (f" &middot; <span dir='ltr'>{_e(cwe)}</span>" if cwe else ""))
    dd("location", f"<code>{_e(_clip(_loc(f.get('file', ''), f['line']), _MAX_TITLE, lang))}</code>")
    if f.get("source") and f.get("source") != "vulnscan":
        dd("detected_by", _e(f["source"]))
    mask = mask_secrets and bool(_SECRET_CATEGORIES.intersection(categories(f)))
    hide = _mask_secrets if mask else (lambda t: t)
    note = f"<div class='small'>{_e(_t(lang, 'masked'))}</div>" if mask else ""
    ctx = _code_context(source_root, str(f.get("file") or ""), f["line"])
    if ctx:
        code = "\n".join((f"<span class='hit'>{n:>5} | {_e(hide(t))}</span>" if n == f["line"] else f"{n:>5} | {_e(hide(t))}")
                         for n, t in ctx)
        dd("code", f"<pre>{code}</pre>{note}")
    else:
        snippet = _clip(_f_text(f, "snippet", lang), _MAX_SNIPPET, lang)
        if snippet:
            dd("code", f"<pre>{_e(hide(snippet))}</pre>{note}")
    src = f["extra"].get("taint_source") if lang == "ar" else (f["extra"].get("taint_source_en") or _to_en(f["extra"].get("taint_source") or ""))
    if src:
        dd("taint_source", f"<code>{_e(src)}</code>")
    steps = _steps(f, lang)
    if steps:
        dd("flow", "<ol class='flow'>" + "".join(
            f"<li><code>{_e(_loc(file, line))}</code> {_e(text)}</li>" for file, line, text in steps) + "</ol>")
    advice = _clip(_f_text(f, "advice", lang), _MAX_ADVICE, lang)
    if advice:
        dd("fix", _e(advice))
    url = f["extra"].get("url")
    if isinstance(url, str) and url.startswith(("https://", "http://")):
        dd("reference", f"<a href='{_e(url)}' dir='ltr'>{_e(url)}</a>")
    chips = []
    for fid in fids:
        short = data["frameworks"][fid].get("short", fid)
        for r in _explain(f, fid):
            if r["basis"] != "generic":
                chips.append(f"<span title='{_e(_basis_label(r['basis'], lang))}'><b>{_e(short)}</b> {_e(r['control'])}</span>")
    dd("mapping", f"<span class='chips' dir='ltr'>{''.join(chips)}</span>" if chips else _e(_t(lang, "none_mapped")))
    if f.get("fingerprint"):
        dd("fingerprint", f"<code>{_e(f['fingerprint'])}</code>")
    return (f"<div class='finding {f['severity']}' id='{_e(f['_id'])}'><h4><span class='fid'>{_e(f['_id'])}</span>"
            f"{_sev_badge(f['severity'], lang)} {_bt(_clip(_f_title(f, lang), _MAX_TITLE, lang))}</h4><dl>{''.join(rows)}</dl></div>")


def render_html(findings, meta: dict | None = None, lang: str = "en", frameworks=None, fail_on: str = "medium",
                source_root=None, mask_secrets: bool = True) -> str:
    """A self-contained, printable auditor report (one HTML file: no script, no external asset).

    ``findings``: finding dicts as in the Kashif JSON report (or ``Finding`` objects).
    ``meta``: optional ``{"target", "files_scanned", "generated_at", "notes", "notes_en", "tool_version",
    "project", "assessor", "report_generated_at"}``.
    ``lang``: ``"en"`` or ``"ar"`` (right-to-left). ``frameworks``: ids or aliases, default all.
    ``fail_on``: lowest severity that makes a control "Fail". ``source_root``: directory of the analysed sources;
    when given, the appendix shows the code around each finding (files are read, never executed, and only below
    that directory; pass it only for sources you trust to appear in the report). ``mask_secrets``: hide string
    literals and assigned values in the code of hard-coded secret and key findings (default on).

    Sections: cover, scope, methodology, executive summary with risk score, one control matrix per framework,
    appendix A (every finding with location, code, data-flow path, remediation and mapped controls) and appendix B
    (mapping sources). Print CSS puts each main section on a new page."""
    lang = _lang(lang)
    fail_on = fail_on if fail_on in _RANK else "medium"
    items = _prepare(findings)
    fids = _frameworks(frameworks)
    m = _meta(meta, items)
    summary = summarize(items, fids, lang, fail_on)
    risk = risk_score(items)
    counts = risk["counts"]
    T = functools.partial(_t, lang)
    p = []
    p.append(f"<!DOCTYPE html><html lang='{lang}' dir='{'rtl' if lang == 'ar' else 'ltr'}'><head><meta charset='utf-8'>"
             f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
             f"<meta name='generator' content='Kashif {_e(m['tool_version'])}'>"
             f"<title>{_e(T('report_title'))}{' - ' + _e(m['target']) if m['target'] else ''}</title>"
             f"<style>{_CSS}</style></head><body><main>")

    # cover
    kv = []
    for key, val in (("project", m.get("project")), ("target", m["target"]), ("assessor", m.get("assessor")),
                     ("date", m["report_generated_at"]), ("scan_date", m["generated_at"]),
                     ("tool", f"Kashif {m['tool_version']}".strip()),
                     ("files", m["files_scanned"]), ("findings", len(items))):
        if val not in (None, ""):
            kv.append(f"<dt>{_e(T(key))}</dt><dd><span dir='auto'>{_e(val)}</span></dd>")
    kv.append(f"<dt>{_e(T('frameworks'))}</dt><dd>{_e(', '.join(summary[f]['short'] for f in fids))}</dd>")
    p.append(f"<section class='cover'><div class='brand'>Kashif &middot; كاشِف</div><h1>{_e(T('report_title'))}</h1>"
             f"<div class='sub'>{_e(T('report_sub'))}</div><dl class='kv'>{''.join(kv)}</dl>"
             f"<div class='notice'><b>{_e(T('not_cert'))}</b>{_e(T('not_cert_long'))}</div></section>")

    # contents + scope
    toc = [("scope", "s_scope"), ("method", "s_method"), ("exec", "s_exec"), ("matrices", "s_matrices"),
           ("appendix-a", "s_appendix"), ("appendix-b", "s_sources")]
    p.append(f"<section class='pb'><h2>{_e(T('contents'))}</h2><ol class='toc'>"
             + "".join(f"<li><a href='#{a}'>{_e(T(k))}</a></li>" for a, k in toc) + "</ol>")
    p.append(f"<h2 id='scope' style='margin-top:2rem'>{_e(T('s_scope'))}</h2><dl class='kv'>")
    for key, val in (("target", m["target"]), ("files", m["files_scanned"]), ("scan_date", m["generated_at"]),
                     ("tool", f"Kashif {m['tool_version']}".strip())):
        if val not in (None, ""):
            p.append(f"<dt>{_e(T(key))}</dt><dd><span dir='auto'>{_e(val)}</span></dd>")
    p.append(f"</dl><h3>{_e(T('scope_in'))}</h3><p>{_e(T('scope_in_txt'))}</p>"
             f"<h3>{_e(T('scope_out'))}</h3><p>{_e(T('scope_out_txt'))}</p>")
    notes = [n for n in _notes(m, lang) if n]
    if notes:
        p.append(f"<h3>{_e(T('notes'))}</h3><ul>" + "".join(f"<li>{_e(n)}</li>" for n in notes) + "</ul>")
    p.append("</section>")

    # methodology
    p.append(f"<section class='pb'><h2 id='method'>{_e(T('s_method'))}</h2><p>{_e(T('m_1'))}</p>"
             f"<table><thead><tr><th>{_e(T('m_basis'))}</th><th>{_e(T('m_meaning'))}</th></tr></thead><tbody>"
             + "".join(f"<tr><td class='id'>{_e(T('b_' + b))}</td><td>{_e(T('b_' + b + '_txt'))}</td></tr>"
                       for b in ("official", "analyst", "inherited", "category", "generic"))
             + f"</tbody></table><p>{_e(T('m_review'))}</p>"
               f"<h3>{_e(T('m_status'))}</h3><p>{_e(T('m_status_txt', sev=T(fail_on)))}</p>"
               f"<h3>{_e(T('m_risk'))}</h3><p>{_e(T('m_risk_txt'))}</p>"
               f"<div class='notice'><b>{_e(T('not_cert'))}</b>{_e(T('not_cert_long'))}</div></section>")

    # executive summary
    top = max(counts.values()) or 1
    bars = "".join(f"<div class='bar'><span>{_sev_badge(s, lang)}</span><span class='track'>"
                   f"<span class='fill {s}' style='display:block;width:{100 * counts[s] / top:.1f}%'></span></span>"
                   f"<b>{counts[s]}</b></div>" for s in SEVERITIES)
    p.append(f"<section class='pb'><h2 id='exec'>{_e(T('s_exec'))}</h2><div class='risk'>"
             f"<div class='score r-{risk['rating']}'><div>{_e(T('risk'))}</div><div><span class='num'>{risk['score']}</span>"
             f"<span class='of'>/100</span></div><div><b>{_e(T('r_' + risk['rating']))}</b></div></div>"
             f"<div class='bars'>{bars}</div></div>")
    p.append(f"<table><thead><tr><th>{_e(T('framework'))}</th><th class='n'>{_e(T('controls_with'))}</th>"
             f"<th class='n'>{_e(T('mapped'))}</th><th class='n'>{_e(T('unmapped'))}</th>"
             f"<th class='n'>{_e(T('status'))}</th></tr></thead><tbody>")
    for fid in fids:
        fw = summary[fid]
        p.append(f"<tr><td><a href='#fw-{_e(fid)}'>{_bt(fw['title'])}</a></td>"
                 f"<td class='n'>{fw['controls_with_findings']} / {fw['controls_total']}</td>"
                 f"<td class='n'>{fw['findings_mapped']}</td><td class='n'>{fw['findings_unmapped']}</td>"
                 f"<td class='n'><span class='st {fw['status']}'>{_e(T('st_' + fw['status']))}</span></td></tr>")
    p.append("</tbody></table>")
    ranked = sorted(((r, fw) for fw in summary.values() for r in fw["rows"] if r["total"] and r["basis"] != ["generic"]
                     and not load_data()["frameworks"][fw["id"]]["controls"][r["control"]].get("broad")),
                    key=lambda x: ([-x[0]["counts"][s] for s in SEVERITIES], x[1]["short"], x[0]["control"]))[:10]
    if ranked:
        p.append(f"<h3>{_e(T('top_controls'))}</h3><table><thead><tr><th>{_e(T('framework'))}</th>"
                 f"<th>{_e(T('control'))}</th><th>{_e(T('title'))}</th>"
                 + "".join(f"<th class='n'>{_e(T(s))}</th>" for s in SEVERITIES) + "</tr></thead><tbody>")
        for r, fw in ranked:
            p.append(f"<tr><td>{_e(fw['short'])}</td><td class='id'>{_bt(r['control'])}</td><td>{_bt(r['title'])}</td>"
                     f"{_count_cells(r['counts'])}</tr>")
        p.append("</tbody></table>")
    elif not items:
        p.append(f"<p>{_e(T('no_findings'))}</p>")
    p.append("</section>")

    # matrices
    p.append(f"<section class='pb'><h2 id='matrices'>{_e(T('s_matrices'))}</h2>"
             f"<p class='small'>{_e(T('m_status_txt', sev=T(fail_on)))}</p>")
    for i, fid in enumerate(fids):
        p.append(f"<div{' class=pb' if i else ''}>{_matrix_html(summary[fid], lang)}</div>")
    p.append("</section>")

    # appendix A
    p.append(f"<section class='pb'><h2 id='appendix-a'>{_e(T('s_appendix'))}</h2>")
    if not items:
        p.append(f"<p>{_e(T('no_findings'))}</p>")
    p.extend(_finding_html(f, fids, lang, source_root, mask_secrets) for f in items)
    p.append("</section>")

    # appendix B
    p.append(f"<section class='pb'><h2 id='appendix-b'>{_e(T('s_sources'))}</h2><table><thead><tr>"
             f"<th>{_e(T('src_name'))}</th><th>{_e(T('src_ref'))}</th><th>{_e(T('src_retrieved'))}</th></tr></thead><tbody>")
    for _key, src in _sources_used(fids):
        links = " ".join(f"<a href='{_e(u)}' dir='ltr'>{_e(u)}</a>" for u in (src.get("url"), src.get("also")) if u)
        p.append(f"<tr><td><span dir='ltr'>{_e(src.get('title', ''))}</span></td><td>{links}</td>"
                 f"<td class='small'><span dir='ltr'>{_e(src.get('retrieved', ''))}</span></td></tr>")
    p.append(f"</tbody></table><footer>{_e(T('footer', v=m['tool_version']))}</footer></section></main></body></html>")
    return "".join(p)


# ----------------------------------------------------------------------------------------------------------------
# Input
# ----------------------------------------------------------------------------------------------------------------

def _d(value) -> dict:
    return value if isinstance(value, dict) else {}


def _l(value) -> list:
    return value if isinstance(value, list) else []


def _text(value, limit: int = _MAX_TITLE) -> str:
    """The ``text`` of a SARIF message-like object (or a plain string), bounded."""
    if isinstance(value, dict):
        value = value.get("text")
    return value[:limit] if isinstance(value, str) else ""


def _sarif_severity(result: dict, rule: dict) -> str:
    props = {**_d(rule.get("properties")), **_d(result.get("properties"))}
    try:
        score = float(props.get("security-severity"))
        if score == score:                               # not NaN
            return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "info"
    except (TypeError, ValueError):
        pass
    level = result.get("level") or _d(rule.get("defaultConfiguration")).get("level") or "warning"
    return {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(level if isinstance(level, str) else "", "medium")


def _sarif_uri(uri) -> str:
    """A SARIF artifact URI as a path for display: percent-decoded; ``file://`` URIs keep only their path."""
    if not isinstance(uri, str):
        return ""
    uri = uri[:4096]
    if uri.lower().startswith("file:"):
        uri = urllib.parse.urlsplit(uri).path or uri
    return urllib.parse.unquote(uri)


def _sarif_location(loc) -> tuple[str, int, str]:
    phys = _d(_d(loc).get("physicalLocation"))
    region = _d(phys.get("region"))
    return (_sarif_uri(_d(phys.get("artifactLocation")).get("uri")), _int(region.get("startLine")),
            _text(region.get("snippet"), _MAX_SNIPPET).strip())


def _sarif_skip(res: dict) -> bool:
    """True for results that are not open findings: ``kind`` pass / notApplicable / informational, results absent
    from the current run (``baselineState`` absent) and results with an accepted suppression."""
    if res.get("kind") in ("pass", "notApplicable", "informational") or res.get("baselineState") == "absent":
        return True
    sup = [x for x in _l(res.get("suppressions")) if isinstance(x, dict)]
    return bool(sup) and all(x.get("status", "accepted") == "accepted" for x in sup)


def _sarif_cwes(res: dict, rule: dict) -> list[str]:
    props, rprops = _d(rule.get("properties")), _d(res.get("properties"))
    taxa = [_d(t.get("target")) for t in _l(rule.get("relationships")) if isinstance(t, dict)] + \
           [t for t in _l(res.get("taxa")) if isinstance(t, dict)]
    blob = [*_l(props.get("tags")), props.get("cwe", ""), *_l(rprops.get("tags")), rprops.get("cwe", "")]
    for t in taxa:
        if "cwe" in str(_d(t.get("toolComponent")).get("name", "")).lower():
            ident = str(t.get("id", ""))
            blob.append(ident if "cwe" in ident.lower() else f"CWE-{ident}")
    out: list[str] = []
    for n in _CWE_RX.findall(" ".join(str(x)[:200] for x in blob[:200])):
        if n not in out:
            out.append(n)
    return out


def _from_sarif(doc: dict) -> tuple[list[dict], dict]:
    """Findings from a SARIF 2.1.0 log. Tolerant: members of the wrong type are ignored, never an exception."""
    findings, tools = [], []
    for run in _l(doc.get("runs")):
        if not isinstance(run, dict):
            continue
        driver = _d(_d(run.get("tool")).get("driver"))
        tool = _text(driver.get("name")) or "sarif"
        tools.append(tool)
        rule_list = [r for r in _l(driver.get("rules")) if isinstance(r, dict)]
        rules = {r.get("id"): r for r in rule_list if isinstance(r.get("id"), str)}
        for res in _l(run.get("results")):
            if not isinstance(res, dict) or _sarif_skip(res):
                continue
            ref = _d(res.get("rule"))
            rid = res.get("ruleId") or ref.get("id")
            index = res.get("ruleIndex", ref.get("index"))
            rule = rules.get(rid) if isinstance(rid, str) else None
            if rule is None and isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(rule_list):
                rule = rule_list[index]
            rule = rule or {}
            rid = _text(rid) or _text(rule.get("id"))
            cwes = _sarif_cwes(res, rule)
            locations = _l(res.get("locations"))
            file, line, snippet = _sarif_location(locations[0] if locations else {})
            steps = []
            for flow in _l(res.get("codeFlows"))[:1]:
                for tf in _l(_d(flow).get("threadFlows"))[:1]:
                    for st in _l(_d(tf).get("locations"))[:_MAX_STEPS]:
                        loc = _d(_d(st).get("location"))
                        sf, sl, _ = _sarif_location(loc)
                        text = _text(loc.get("message"))
                        steps.append({"file": sf, "line": sl, "text": text, "text_en": text})
            msg = _text(res.get("message"), _MAX_SNIPPET)
            title = _text(rule.get("shortDescription")) or _text(rule.get("name")) or msg[:120] or rid
            advice = _text(rule.get("help"), 600) or _text(rule.get("fullDescription"), 600)
            fp = res.get("partialFingerprints") or res.get("fingerprints")
            fp = _text(next(iter(fp.values()), "")) if isinstance(fp, dict) else ""
            findings.append({
                "rule_id": rid, "severity": _sarif_severity(res, rule), "title": title, "title_ar": title,
                "file": file, "line": line, "snippet": snippet or msg[:200], "snippet_en": snippet or msg[:200],
                "advice": advice, "advice_en": advice, "cwe": ",".join(f"CWE-{n}" for n in cwes),
                "source": tool, "fingerprint": fp, "extra": {"path": steps} if steps else {},
            })
    return findings, {"target": "", "notes": [f"SARIF: {', '.join(dict.fromkeys(tools))}"] if tools else []}


def load_findings(path: str | pathlib.Path) -> tuple[list[dict], dict]:
    """Read findings for a report: ``(finding_dicts, meta)``.

    ``path`` may be a Kashif JSON report (``{"target", "findings": [...]}``), a JSON list of findings, a SARIF 2.1.0
    file (any tool; results that are suppressed, of kind "pass" or absent from the baseline are left out), or a
    directory / source file / archive to scan now with ``vulnscan.scanner.scan_path`` (static
    analysis only: nothing is executed and no network is used). Raises ``FileNotFoundError`` or ``ValueError``."""
    p = pathlib.Path(path)
    if not p.exists():
        raise FileNotFoundError(str(path))
    if p.is_file() and p.suffix.lower() in (".json", ".sarif"):
        if p.stat().st_size > MAX_INPUT_BYTES:
            raise ValueError(_t("en", "cli_too_big", mb=MAX_INPUT_BYTES // (1024 * 1024)))
        try:
            doc = json.loads(p.read_text(encoding="utf-8-sig"))
        except (ValueError, UnicodeDecodeError) as e:
            raise ValueError(f"not valid JSON: {e}") from e
        except RecursionError as e:
            raise ValueError("JSON is nested too deeply") from e
        if isinstance(doc, dict) and isinstance(doc.get("runs"), list):
            return _from_sarif(doc)
        if isinstance(doc, list):
            doc = {"findings": doc}
        if isinstance(doc, dict) and isinstance(doc.get("findings"), list) \
                and all(isinstance(f, dict) for f in doc["findings"]):
            meta = {k: doc[k] for k in ("target", "files_scanned", "generated_at", "notes", "notes_en") if k in doc}
            return doc["findings"], meta
        raise ValueError("no \"findings\" list and no SARIF \"runs\"")
    from .model import assign_fingerprints
    from .scanner import scan_path
    notes: list[str] = []
    found, files = scan_path(p, notes=notes)
    assign_fingerprints(found)
    meta = {"target": str(p), "files_scanned": files, "notes": notes,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    return [f.to_dict() for f in found], meta


# ----------------------------------------------------------------------------------------------------------------
# Coverage of the engine's own CWEs
# ----------------------------------------------------------------------------------------------------------------

def emitted_cwes(package_dir: str | pathlib.Path | None = None) -> dict[str, list[str]]:
    """Every CWE the engine can emit, with where it is declared: ``{"89": ["rules.py", "models/python.json"]}``.

    Collected from ``vulnscan.rules.RULES`` and from the text of the package's Python sources (web.py,
    apex_export.py, taint.py, semantic.py ...), ``models/*.json`` and ``queries/*.vql``. Needs the source tree, so
    it returns only the rule CWEs in a frozen build."""
    base = pathlib.Path(package_dir) if package_dir else pathlib.Path(__file__).resolve().parent
    out: dict[str, list[str]] = {}

    def add(num: str, where: str):
        lst = out.setdefault(str(int(num)), [])
        if where not in lst:
            lst.append(where)

    try:
        from .rules import RULES
        for rule in RULES:
            for n in _CWE_RX.findall(rule.cwe or ""):
                add(n, "rules.RULES")
    except ImportError:
        pass
    skip = {pathlib.Path(__file__).name}
    files = [f for f in sorted(base.glob("*.py")) if f.name not in skip]
    files += sorted(base.glob("integrations/*.py")) + sorted(base.glob("models/*.json")) + sorted(base.glob("queries/*.vql"))
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for n in re.findall(r"CWE-(\d{1,5})\b", text):
            add(n, f.relative_to(base).as_posix())
    return dict(sorted(out.items(), key=lambda kv: int(kv[0])))


def coverage_gaps(cwes=None) -> list[dict]:
    """CWEs (default: :func:`emitted_cwes`) that the data does not cover: ``[{"cwe", "why", "where"}]``.

    A CWE is covered when it has a weakness category other than "other" AND either an OWASP Top 10:2021 control or
    a documented exclusion (``cwe_na``) for that framework."""
    source = emitted_cwes() if cwes is None else {_num(c): [] for c in cwes if _num(c)}
    gaps = []
    for cwe, where in source.items():
        why = []
        if _cwe_categories(cwe) == ("other",):
            why.append("no weakness category")
        if not _map_cwe("owasp-top10-2021", cwe):
            why.append("no OWASP Top 10 2021 mapping or documented exclusion")
        if why:
            gaps.append({"cwe": f"CWE-{cwe}", "why": "; ".join(why), "where": where})
    return gaps


# ----------------------------------------------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------------------------------------------

_RENDER = {"html": render_html, "json": render_json, "csv": render_csv, "md": render_markdown}


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="kashif compliance",
        description="Map Kashif findings to security frameworks and write an auditor report. "
                    "The report is evidence to support an assessment, not a certification.")
    ap.add_argument("input", nargs="?", help="Kashif JSON report, SARIF file, or a path to scan")
    ap.add_argument("--framework", "-F", action="append", default=[], metavar="ID",
                    help="framework id or alias (repeatable or comma-separated; default: all). See --list-frameworks")
    ap.add_argument("-f", "--format", choices=sorted(_RENDER), default=None, help="output format (default: from -o, else html)")
    ap.add_argument("-o", "--output", metavar="FILE", help="output file (default: standard output)")
    ap.add_argument("--lang", choices=("en", "ar"), default="en", help="report language (default: en)")
    ap.add_argument("--fail-on", choices=SEVERITIES, default=None,
                    help="exit 1 when a selected framework has a mapped finding of this severity or higher; "
                         "also the severity from which a control is shown as Fail (default there: medium)")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="info", help="ignore findings below this severity")
    ap.add_argument("--source-root", metavar="DIR", help="directory of the analysed sources, to show the code around "
                                                         "each finding in the HTML report (default: the scanned PATH "
                                                         "when the input is a directory; never taken from a report file)")
    ap.add_argument("--show-secrets", action="store_true", help="do not mask string literals and values in the code of "
                                                                "hard-coded secret findings (HTML report)")
    ap.add_argument("--project", help="project name for the cover page")
    ap.add_argument("--assessor", help="name of the person or team preparing the report, for the cover page")
    ap.add_argument("--list-frameworks", action="store_true", help="list framework ids and exit")
    ap.add_argument("--check-coverage", action="store_true", help="check that every CWE the engine emits is mapped")
    return ap


def _out(text: str) -> None:
    """Print to standard output; falls back to UTF-8 bytes on consoles whose code page lacks the characters."""
    try:
        sys.stdout.write(text + "\n")
    except UnicodeEncodeError:
        buf = getattr(sys.stdout, "buffer", None)
        if buf is not None:
            buf.write((text + "\n").encode("utf-8"))
        else:
            sys.stdout.write((text + "\n").encode("ascii", "backslashreplace").decode("ascii"))


def main(argv: list[str] | None = None) -> int:
    """Command line entry point; returns the exit code (0 ok, 1 gate failed or coverage gap, 2 usage/input error)."""
    ap = _parser()
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)
    lang = args.lang
    if args.list_frameworks:
        for fid in FRAMEWORKS:
            info = framework_info(fid, lang)
            aliases = ", ".join(sorted(a for a, t in _ALIASES.items() if t == fid))
            _out(f"{fid:<20} {info['title']}  [{aliases}]")
        return 0
    if args.check_coverage:
        gaps = coverage_gaps()
        for g in gaps:
            print(_t(lang, "cli_cov_gap", cwe=g["cwe"], why=g["why"], where=", ".join(g["where"])), file=sys.stderr)
        if not gaps:
            _out(_t(lang, "cli_cov_ok", n=len(emitted_cwes())))
        return 1 if gaps else 0
    if not args.input:
        ap.print_usage(sys.stderr)
        return 2
    try:
        fids = _frameworks(args.framework)
    except ValueError as e:
        print(_t(lang, "cli_bad_fw", name=e), file=sys.stderr)
        return 2
    try:
        findings, meta = load_findings(args.input)
    except FileNotFoundError:
        print(_t(lang, "cli_no_input", path=args.input), file=sys.stderr)
        return 2
    except (ValueError, OSError, RecursionError) as e:
        print(_t(lang, "cli_bad_json", path=args.input, err=e), file=sys.stderr)
        return 2
    if not isinstance(meta, dict):
        meta = {}
    limit = _RANK[args.min_severity]
    findings = [f for f in findings if _RANK[_sev(f)] <= limit]
    if args.project:
        meta["project"] = args.project
    if args.assessor:
        meta["assessor"] = args.assessor
    fmt = args.format
    if fmt is None:
        ext = pathlib.Path(args.output).suffix.lower().lstrip(".") if args.output else ""
        ext = {"htm": "html", "markdown": "md"}.get(ext, ext)
        fmt = ext if ext in _RENDER else "html"
    fail_on = args.fail_on or "medium"
    kwargs = {"meta": meta, "lang": lang, "frameworks": fids, "fail_on": fail_on}
    if fmt == "html":
        # Never meta["target"] of a report file: that text is untrusted and would choose which directory is read.
        root = args.source_root or (args.input if pathlib.Path(args.input).is_dir() else None)
        kwargs["source_root"] = root if root and pathlib.Path(root).is_dir() else None
        kwargs["mask_secrets"] = not args.show_secrets
    text = _RENDER[fmt](findings, **kwargs)
    if args.output:
        try:
            pathlib.Path(args.output).write_text(text, encoding="utf-8")
        except OSError as e:
            print(f"{args.output}: {e}", file=sys.stderr)
            return 2
        print(_t(lang, "cli_wrote", path=args.output), file=sys.stderr)
    else:
        _out(text[:-1] if text.endswith("\n") else text)
    if args.fail_on:
        failed = [fid for fid, fw in summarize(findings, fids, lang, fail_on).items() if fw["status"] == "fail"]
        for fid in failed:
            print(_t(lang, "cli_gate", fw=fid, sev=args.fail_on), file=sys.stderr)
        return 1 if failed else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
