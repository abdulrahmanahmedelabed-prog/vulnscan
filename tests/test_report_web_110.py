"""Kashif 1.1.0 web reports (report.py): bidi isolation of Arabic text, phone layout, the inconclusive-scan banner, the
console summary (diff, grades, not-tested block, wrapping), page/request headers, SARIF help from the rule registry,
the evidence, grade, coverage, inventory and fix sections of the HTML report, and the UI view (web_view).

Offline and fast: every web result is built here from the rule registry (vulnscan/webscan/rules.py)."""

from __future__ import annotations

import json
import re

import pytest

from vulnscan import report
from vulnscan.i18n.bidi import LRI, PDI
from vulnscan.model import Finding
from vulnscan.webscan.rules import RULES

TARGET = "https://shop.example/"
ARABIC = re.compile(r"[؀-ۿ]")


def wf(rule: str, severity: str | None = None, *, params: dict | None = None, snippet: str = "HTTP 200",
       **extra) -> Finding:
    """A web finding as webscan/engine.py builds it (titles and advice from the registry)."""
    meta = RULES[rule]
    params = params or {}
    url = extra.pop("url", TARGET)
    ex = {"confidence": "certain", "url": url, "examples": [url], "instances": 1, "page_count": 1, "systemic": False,
          "remediation": list(meta.fix), "advice_en": meta.advice("en", **params), "wstg": list(meta.wstg),
          "asvs4": list(meta.asvs4), "asvs5": list(meta.asvs5), "fp_key": f"{rule}|shop.example|document|x",
          "notes": [], "evidence": {}}
    ex.update(extra)
    return Finding(rule, severity or meta.severity, meta.title("en", **params), meta.title("ar", **params),
                   "shop.example", 0, snippet, meta.advice("ar", **params), meta.cwe, "web", ex)


def coverage(**states) -> tuple[list[dict], dict]:
    """``states``: {state: [(check, [(code, en, ar)])]} → (coverage records, counts)."""
    recs, counts = [], {s: 0 for s in ("pass", "fail", "not_applicable", "not_tested", "inconclusive")}
    for state, items in states.items():
        for check, reasons in items:
            recs.append({"check": check, "rules": [check], "state": state, "hosts": {},
                         "reasons": [{"code": c, "en": en, "ar": ar} for c, en, ar in reasons]})
            counts[state] += 1
    return recs, counts


def web(**kw) -> dict:
    cov = kw.pop("coverage", [])
    counts = kw.pop("coverage_counts", {"pass": 150, "fail": 3, "not_applicable": 20, "not_tested": 11,
                                        "inconclusive": 0})
    out = {"schema": 1, "profile": "standard", "sensitivity": "default", "target": TARGET, "final_url": TARGET,
           "requests": 5, "data_date": "2026-11-12", "pages": 1, "notes": [],
           "grades": {"kashif": {"grade": "A", "letter": "A", "score": 95, "base": 95, "bonus": {"total": 0},
                                 "caps": [], "notes": [], "label": {"en": "Kashif Web Grade", "ar": "درجة كاشِف"}},
                      "observatory": {"grade": "B+", "score": 80, "max_score": 165},
                      "ssllabs": {"grade": "A+", "score": 97}},
           "coverage": cov, "coverage_counts": counts, "coverage_summary": {}, "inventory": {}, "diff": None}
    out.update(kw)
    return out


def bdi_runs(html: str) -> list[str]:
    return re.findall(r"<bdi dir=['\"]ltr['\"]>(.*?)</bdi>", html)


# ------------------------------------------------------------------------------------------- 1. bidi (blocker)

def test_arabic_html_isolates_each_latin_run_of_titles_advice_and_snippets():
    findings = [wf("WEB-referrer-policy"), wf("WEB204"), wf("WEB062", params={"path": "/server-status"}),
                wf("WEB-permissions-policy"), wf("WEB022", params={"cookie": "sessionid"})]
    for lang in ("ar", "both"):
        html = report.render_html(findings, TARGET, 1, [], lang=lang, web=web())
        runs = bdi_runs(html)
        for needle in ("no-referrer", "base-uri 'none'", "/server-status", "camera=()", "SameSite=Lax"):
            escaped = needle.replace("'", "&#x27;")
            assert escaped in runs, (lang, needle)          # one run holds the whole token, quotes included
        if lang == "both":                                   # the English subtitle reads left to right
            assert "<small dir='ltr'>Missing Referrer-Policy</small>" in html
    en = report.render_html(findings, TARGET, 1, [], lang="en", web=web())
    assert "<bdi dir='ltr'>" not in en.split("<h2 class=\"fd-h\">")[1].split("</table>")[0]


def test_bidi_html_uses_the_shared_rule_and_escapes():
    ar = report._Lang("ar")
    assert report._bidi_html(ar, "أضف base-uri 'none' (أو 'self').") == \
        "أضف <bdi dir='ltr'>base-uri &#x27;none&#x27;</bdi> (أو <bdi dir='ltr'>&#x27;self&#x27;</bdi>)."
    assert "<script" not in report._bidi_html(ar, "نص <script>alert(1)</script>")
    assert report._bidi_html(report._Lang("en"), "a < b") == "a &lt; b"


def test_short_runs_do_not_break_in_table_cells_on_desktop():
    html = report.render_html([wf("WEB022", params={"cookie": "sid"})], TARGET, 1, [], lang="ar", web=web())
    assert "td bdi[dir='ltr']{white-space:nowrap}td bdi.lr{white-space:normal}" in html


def test_long_latin_runs_may_wrap_so_the_findings_table_fits_the_page():
    # a nowrap URL or header line in an Arabic evidence note made the findings table twice the page width (and cut it
    # on paper): only short runs keep to one line
    ar = report._Lang("ar")
    url = "https://exp.example/kashif-404-eb8b29ab5aff7cb6"
    assert report._bidi_html(ar, f"أجاب الطلب ({url}) بصفحة") == f"أجاب الطلب (<bdi dir='ltr' class='lr'>{url}</bdi>) بصفحة"
    assert report._bidi_html(ar, "أرسل X-Content-Type-Options: nosniff دائمًا") == \
        "أرسل <bdi dir='ltr' class='lr'>X-Content-Type-Options: nosniff</bdi> دائمًا"
    assert report._bidi_html(ar, "استخدم Content-Security-Policy هنا") == \
        "استخدم <bdi dir='ltr'>Content-Security-Policy</bdi> هنا"
    html = report.render_html([wf("WEB204")], TARGET, 1, [], lang="ar", web=web())
    css_print = html[html.index("@media print{\n"):]
    assert "td,td.w{min-width:0}" in css_print and ".ev td.nw,.hdrs td.nw{white-space:normal}" in css_print


def test_headers_inventory_fits_a_phone():
    inv = {"security_headers": [{"url": TARGET, "status": 200, "headers": {
        "Cross-Origin-Embedder-Policy": {"value": "", "verdict": "missing"}}}]}
    html = report.render_html([wf("WEB204")], TARGET, 1, [], lang="ar", web=web(inventory=inv))
    assert "<table class='hdrs'><caption>" in html
    assert ".hdrs td,.gt td,.gt th{min-width:0;padding:.35rem}.hdrs td.nw,.gt td{white-space:normal}" in html


# ------------------------------------------------------------------------------------------- 2. phones (blocker)

def test_long_final_url_is_on_its_own_line_and_can_wrap():
    long_url = "https://shop.example/" + "a" * 279
    assert len(long_url) == 300
    html = report.render_html([wf("WEB204")], TARGET, 1, [], lang="ar", web=web(final_url=long_url))
    assert f"<br><code dir='ltr' class='url'>{long_url}</code>" in html
    assert "bdi,code,.tw td{overflow-wrap:anywhere;word-break:break-word}" in html
    assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in html


# ------------------------------------------------------------------------------------------- 3. inconclusive (blocker)

def _blocked_web() -> dict:
    rate = ("rate_limited", "the site rate-limited the scan (HTTP 429)", "قيّد الموقع معدل الطلبات (HTTP 429)")
    cov, counts = coverage(inconclusive=[(f"WEB{100 + i}", [rate]) for i in range(60)],
                           not_tested=[("WEB070", [("deep_off", "deep mode off", "الوضع العميق غير مفعّل")])],
                           **{"pass": [("WEB000", [])] * 123})
    w = web(coverage=cov, coverage_counts=counts)
    w["grades"]["kashif"] = {"grade": "?", "score": None, "caps": [],
                             "notes": [{"en": "no grade: rate limited (WEB990)", "ar": "لا درجة: تقييد للمعدل (WEB990)"}]}
    return w


def test_blocked_scan_gets_a_status_banner_grey_tiles_and_a_neutral_question_mark():
    w = _blocked_web()
    en = report.render_html([wf("WEB990", snippet="429")], TARGET, 1, [], lang="en", web=w)
    m = re.search(r"<div class='banner' role='status'>(.*?)</div>", en)
    assert m and "Scan inconclusive: 60 of 184 checks could not run" in m.group(1)
    assert "HTTP 429" in m.group(1) and "This is not a clean result." in m.group(1)
    assert en.index("role='status'") < en.index("<div class='facts'>")           # right under the title
    assert "<div class='tiles muted'>" in en and "counts cover only the checks that ran" in en
    assert "<span class='letter g-n' dir='ltr'>?</span><span class='gword g-n'>not graded</span>" in en
    assert "no grade: rate limited (WEB990)" in en
    ar = report.render_html([], TARGET, 1, [], lang="ar", web=w)
    assert "الفحص غير حاسم: تعذّر إجراء 60 فحصًا من أصل 184" in ar and "هذه ليست نتيجة نظيفة." in ar
    con = report.render_console([], TARGET, 1, [], color=False, lang="en", web=w)
    assert "⚠ Scan inconclusive: 60 of 184 checks could not run" in con
    md = report.render_markdown([], TARGET, 1, [], lang="en", web=w)
    assert "> ⚠ **Scan inconclusive: 60 of 184 checks could not run" in md


def test_a_conclusive_scan_has_no_banner():
    html = report.render_html([wf("WEB204")], TARGET, 1, [], lang="en", web=web())
    assert "role='status'" not in html and "<div class=\"tiles\">" in html


def test_more_than_a_quarter_not_run_triggers_the_banner():
    http = ("http_only", "the target is served over HTTP only", "الهدف يُقدَّم عبر HTTP فقط")
    cov, counts = coverage(not_tested=[(f"WEB7{i:02d}", [http]) for i in range(50)], **{"pass": [("WEB000", [])] * 100})
    b = report._inconclusive(web(coverage=cov, coverage_counts=counts), [], report._Lang("en"))
    assert b and b["n"] == 50 and b["total"] == 150 and "served over HTTP only" in b["text"]


# ------------------------------------------------------------------------------------------- 4. console diff

def _diff_web() -> tuple[dict, list[Finding]]:
    new = [wf("WEB204", fp_key=f"k{i}") for i in range(12)]
    rows = [{"key": f"k{i}", "fingerprint": f"fp{i}", "rule": "WEB204", "severity": "low",
             "title_en": "CSP base-uri missing", "title_ar": "base-uri مفقود"} for i in range(12)]
    posture = ([{"direction": "regression", "en": f"header removed: X-{i}", "ar": f"حُذفت ترويسة: X-{i}"} for i in range(7)]
               + [{"direction": "improvement", "en": "TLS 1.3 enabled on 1.2.3.4", "ar": "فُعّل TLS 1.3"}])
    d = {"comparable": True, "previous": {"scanned_at": "2026-11-01T10:00:00Z", "profile": "deep"},
         "notes": [{"en": "the previous scan was deep, this one standard: exposure checks are not comparable",
                    "ar": "كان الفحص السابق بنمط الفحص deep وهذا الفحص بنمط standard"}],
         "findings": {"new": rows, "resolved": [dict(rows[0], rule="WEB022", severity="medium")], "unchanged": [{}] * 3,
                      "not_retested": [{}] * 2},
         "grades": {"kashif": {"before": "B", "after": "A", "changed": True},
                    "observatory": {"before": "B+", "after": "B+", "changed": False}},
         "posture": posture, "new_fingerprints": []}
    return web(diff=d), new


def test_console_diff_lists_notes_counts_items_and_marks_new_findings(monkeypatch):
    monkeypatch.setenv("COLUMNS", "120")
    w, new = _diff_web()
    out = report.render_console(new + [wf("WEB022", params={"cookie": "x"}, fp_key="other")], TARGET, 1, [],
                                color=False, lang="en", web=w)
    lines = out.splitlines()
    i = next(n for n, ln in enumerate(lines) if ln.startswith("  ⇄ Compared with the previous scan"))
    assert "(1 Nov 2026, 10:00 UTC, deep)" in lines[i]
    assert "exposure checks are not comparable" in lines[i + 1]                    # the notes first
    assert "12 new · 1 resolved · 3 unchanged · 2 not re-checked · Kashif Web Grade: B → A" in out
    assert sum(1 for ln in lines if ln.startswith("     + LOW WEB204")) == 10 and "       … and 2 more" in lines
    assert "     − MEDIUM WEB022 CSP base-uri missing" in lines
    assert sum(1 for ln in lines if ln.startswith("     ↓ header removed")) == 5 and "       … and 2 more" in out
    assert "     ↑ TLS 1.3 enabled on 1.2.3.4" in lines
    assert sum(1 for ln in lines if "🟨 NEW WEB204" in ln) == 12
    assert not any("NEW WEB022" in ln for ln in lines)


def test_console_diff_in_arabic_agrees_in_number_and_isolates_latin(monkeypatch):
    monkeypatch.setenv("COLUMNS", "160")
    w, new = _diff_web()
    out = report.render_console(new, TARGET, 1, [], color=False, lang="ar", web=w)
    assert "12 نتيجةً جديدةً · نتيجة واحدة حُلّت · 3 نتائج لم تتغير · نتيجتان لم يُعَد فحصهما" in out
    assert f"درجة كاشِف للويب: من {LRI}B{PDI} إلى {LRI}A{PDI}" in out
    assert f"جديد {LRI}WEB204 [CWE-693]{PDI} " in out
    assert f"     + منخفض: {LRI}base-uri{PDI} مفقود · {LRI}WEB204{PDI}" in out


def test_console_diff_in_arabic_keeps_the_rule_id_out_of_a_latin_title_run(monkeypatch):
    # "base-uri 'none' (WEB204)" would be one left-to-right run: the id would show between the Arabic and the title
    monkeypatch.setenv("COLUMNS", "160")
    w, new = _diff_web()
    for r in w["diff"]["findings"]["new"]:
        r["title_ar"] = "سياسة CSP لا تحدد base-uri 'none'"
    out = report.render_console(new, TARGET, 1, [], color=False, lang="ar", web=w)
    assert f"     + منخفض: سياسة {LRI}CSP{PDI} لا تحدد {LRI}base-uri 'none'{PDI} · {LRI}WEB204{PDI}" in out
    assert "(WEB204)" not in out


def test_diff_grade_changes_list_only_the_grades_that_changed():
    w, new = _diff_web()
    w["diff"]["grades"]["ssllabs"] = {"before": "A+", "after": "A+", "change": "same", "changed": False}
    w["diff"]["grades"]["kashif"]["text"] = {"en": "Kashif: B → A (88 → 95)", "ar": "كاشِف: من B إلى A (88 ← 95)"}
    for lang in ("en", "ar"):
        page = report.render_html(new, TARGET, 1, [], lang=lang, web=w)
        md = report.render_markdown(new, TARGET, 1, [], lang=lang, web=w)
        view = report.web_view(new, w, lang)
        for out in (page, md, json.dumps(view, ensure_ascii=False)):
            assert "B+ → B+" not in out and "من B+ إلى B+" not in out and "A+ → A+" not in out
        assert len(view["diff"]["grades"]) == 1
    assert "Kashif: B → A (88 → 95)" in report.render_html(new, TARGET, 1, [], lang="en", web=w)
    w["diff"]["grades"] = {"kashif": {"before": "A", "after": "A", "change": "same", "changed": False}}
    assert "Grade changes:</b> grades unchanged" in report.render_html(new, TARGET, 1, [], lang="en", web=w)
    assert "- Grade changes: grades unchanged" in report.render_markdown(new, TARGET, 1, [], lang="en", web=w)
    assert report.web_view(new, w, "en")["diff"]["grades"] == []


def test_console_diff_that_is_not_comparable_still_says_why():
    d = {"comparable": False, "notes": [{"en": "not compared: the previous scan was of another target (x)",
                                         "ar": "لم تُقارن: الفحص السابق كان لهدف آخر (x)"}]}
    out = report.render_console([], TARGET, 1, [], color=False, lang="en", web=web(diff=d))
    assert "  ⇄ Compared with the previous scan" in out and "     ℹ not compared: the previous scan" in out


# ------------------------------------------------------------------------------------------- 5. console findings

def test_console_web_finding_shows_url_notes_curl_and_wraps(monkeypatch):
    monkeypatch.setenv("COLUMNS", "80")
    f = wf("WEB-content-security-policy", url="https://shop.example/cart", page_count=4, systemic=True,
           notes=[{"en": "No enforced policy on the entry document; " * 4, "ar": "لا سياسة مفروضة على الصفحة؛ " * 4},
                  {"en": "second note", "ar": "ملاحظة ثانية"}, {"en": "third note", "ar": "ثالثة"}],
           evidence={"curl": "curl -sS -D - -o /dev/null -A 'Kashif/1.1.0' https://shop.example/cart"})
    out = report.render_console([f], TARGET, 1, [], color=False, lang="en", web=web())
    lines = out.splitlines()
    assert "     🔗 https://shop.example/cart (+3 pages, site-wide (systemic))" in lines
    assert any(ln.startswith("     · No enforced policy") for ln in lines) and "     · second note" in lines
    assert "third note" not in out                                               # one or two notes only
    assert "     ↻ curl -sS -D - -o /dev/null -A 'Kashif/1.1.0' https://shop.example/cart" in lines
    assert "(see the snippet)" not in out and "     🧩 " in out and "copy-paste fixes: -f html" in out
    body = [ln for ln in lines if ln.startswith(("     ·", "     💡", "        "))]
    assert body and all(len(ln) <= 80 for ln in body)
    assert any(ln.startswith("        ") and not ln.startswith("         ") for ln in lines)   # 8-space hanging indent
    ar = report.render_console([f], TARGET, 1, [], color=False, lang="ar", web=web())
    assert "انظر المقتطف" not in ar and f"{LRI}WEB-content-security-policy" in ar


def test_console_english_title_and_advice_come_from_the_engine():
    f = wf("WEB022", params={"cookie": "sid"})
    f.advice = "نص عربي لا ترجمة له في الفهرس"
    f.extra["advice_en"] = "Set SameSite=Lax explicitly."
    out = report.render_console([f], TARGET, 1, [], color=False, lang="en", web=web())
    assert "Set SameSite=Lax explicitly." in out and not ARABIC.search(out)


def test_code_scan_console_is_unchanged():
    f = Finding("PY001", "high", "Command injection", "حقن أوامر", "a.py", 3, "os.system(x)", "لا تمرر المدخلات", "CWE-78")
    out = report.render_console([f], ".", 1, ["ملاحظة"], color=False, lang="ar")
    assert out.splitlines()[0] == "Kashif — .  (ملف واحد مفحوص، نتيجة واحدة)"
    assert "     📄 a.py:3" in out and "     💡 لا تمرر المدخلات" in out and LRI not in out


# ------------------------------------------------------------------------------------------- 6. console summary

def test_console_summary_groups_not_tested_by_reason_and_explains_grades(monkeypatch):
    monkeypatch.setenv("COLUMNS", "160")
    http = ("http_only", "the target is served over HTTP only", "الهدف يُقدَّم عبر HTTP فقط")
    deep = ("deep_off", "deep mode off", "الوضع العميق غير مفعّل")
    cov, counts = coverage(not_tested=[(c, [http]) for c in ("WEB030", "WEB070", "WEB700", "WEB701")]
                           + [("WEB062", [deep]), ("WEB082", [deep])])
    w = web(coverage=cov, coverage_counts=counts)
    w["grades"]["kashif"] = {"grade": "B+*", "letter": "B+", "score": 92, "base": 92, "provisional": True,
                             "caps": [{"cap": "B+", "rule": "WEB000", "en": "WEB000: Site served over plain HTTP",
                                       "ar": "WEB000: الموقع يُقدَّم عبر HTTP غير مشفّر"}],
                             "notes": [{"en": "provisional: these families could not be tested: TLS",
                                        "ar": "درجة مؤقتة: تعذّر اختبار هذه المجموعات: TLS"}]}
    w["grades"]["observatory"].update(partial=True, notes=[{"en": "partial: not computed: redirection",
                                                            "ar": "جزئية: redirection"}])
    w["inventory"] = {"hidden_by_sensitivity": {"total": 2, "en": "2 tentative findings hidden at the default sensitivity",
                                                "ar": "نتيجتان مبدئيتان مخفيتان بحساسية default"}}
    w["notes"] = [{"en": "Not performed: WEB030, WEB070, WEB700, WEB701", "ar": "لم تُجرَ: WEB030, WEB070"}]
    out = report.render_console([], TARGET, 1, ["لم تُجرَ: WEB030, WEB070"], color=False, lang="en", web=w)
    assert "    ⊘ 4 checks (WEB030, WEB070…): the target is served over HTTP only" in out
    assert "    ◌ Not run with the chosen settings: 2 checks — deep mode off (profile standard, sensitivity default)" in out
    assert "Not performed:" not in out                                           # the truncated id list is gone
    assert "  ◌ 2 tentative findings hidden at the default sensitivity" in out
    assert ("  ★ Kashif B+*: grade limited to B+ by: WEB000: Site served over plain HTTP; provisional: these families "
            "could not be tested: TLS") in out.replace("\n    ", " ")
    assert "  ★ Observatory 80 (B+): partial: not computed: redirection" in out
    ar = report.render_console([], TARGET, 1, [], color=False, lang="ar", web=w)
    assert f"4 فحوص ({LRI}WEB030{PDI}، {LRI}WEB070…{PDI}): الهدف يُقدَّم عبر {LRI}HTTP{PDI} فقط" in ar


# ------------------------------------------------------------------------------------------- 7. headers

@pytest.mark.parametrize("lang,needle", [("en", "(1 page scanned · 5 requests, 2 findings)"),
                                         ("ar", "(صفحة واحدة مفحوصة · 5 طلبات، نتيجتان)")])
def test_web_headers_count_pages_and_requests(lang, needle):
    findings = [wf("WEB204"), wf("WEB215")]
    con = report.render_console(findings, TARGET, 1, [], color=False, lang=lang, web=web())
    assert needle in report.clean_text(con.splitlines()[0], 500)
    md = report.render_markdown(findings, TARGET, 1, [], lang=lang, web=web())
    assert ("- 1 page scanned · 5 requests" if lang == "en" else "- صفحة واحدة مفحوصة · 5 طلبات") in md
    assert "Files scanned" not in md and "الملفات المفحوصة" not in md
    html = report.render_html(findings, TARGET, 1, [], lang=lang, web=web())
    assert "<span class='nw'>" + ("Scanned at" if lang == "en" else "تاريخ الفحص") in html and "<time datetime=" in html
    assert ("Final URL" if lang == "en" else "العنوان النهائي") in html
    assert ">Files scanned<" not in html and "الملفات المفحوصة:" not in html
    props = json.loads(report.render_sarif(findings, TARGET, 1, [], lang=lang, web=web()))["runs"][0]["properties"]
    assert props["pagesScanned"] == 1 and props["requests"] == 5 and "filesScanned" not in props


def test_html_drops_notes_the_facts_and_grade_cards_show():
    notes = [{"en": "Coverage: 3 passed", "ar": "التغطية: 3"}, {"en": "Grades: Kashif A", "ar": "الدرجات: كاشِف A"},
             {"en": "web data as of 2026-11-12", "ar": "بيانات الويب بتاريخ 2026-11-12"},
             {"en": "Scanning through a proxy.", "ar": "يمر الفحص عبر وكيل."}]
    w = web(notes=notes, coverage_summary={"en": "3 passed", "ar": "3"})
    html = report.render_html([], TARGET, 1, [n["ar"] for n in notes], lang="en", web=w)
    assert "<li>Scanning through a proxy.</li>" in html
    assert "<li>Coverage:" not in html and "<li>Grades:" not in html and "<li>web data as of" not in html


# ------------------------------------------------------------------------------------------- 8. SARIF

def test_sarif_web_rules_have_registry_help_and_no_repository_link():
    f = wf("WEB022", params={"cookie": "sid"})
    f.extra["advice_en"] = "Set SameSite=Lax on sid."
    doc = json.loads(report.render_sarif([f], TARGET, 1, [], lang="en", web=web()))
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert "helpUri" not in rule and "github.com" not in json.dumps(rule)
    meta = RULES["WEB022"]
    assert rule["shortDescription"]["text"] == meta.name_en
    assert meta.name_en in rule["help"]["text"] and "WSTG-SESS-02" in rule["help"]["text"]
    assert "**Remediation:**" in rule["help"]["markdown"] and "cwe.mitre.org" in rule["help"]["markdown"]
    res = doc["runs"][0]["results"][0]
    assert res["properties"]["advice"] == "Set SameSite=Lax on sid." and res["message"]["text"].startswith(f.title)
    code = Finding("PY001", "high", "Command injection", "حقن أوامر", "a.py", 3, "x", "y", "CWE-78")
    rule = json.loads(report.render_sarif([code], ".", 1, []))["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["helpUri"] == f"{report.REPO_URL}#PY001"                           # code rules unchanged


# ------------------------------------------------------------------------------------------- 9. evidence

def test_html_evidence_details():
    ev = {"request": {"method": "GET", "url": "https://shop.example/a"},
          "chain": [{"url": "http://shop.example/a", "status": 301, "location": "https://shop.example/a"}],
          "status": 200, "headers": [["Content-Type", "text/html"], ["Content-Security-Policy", "script-src *"]],
          "match": {"where": "header", "name": "Content-Security-Policy", "value": "script-src *"},
          "curl": "curl -sS https://shop.example/a", "observed_at": "2026-11-14T01:55:41Z"}
    f = wf("WEB042", url="https://shop.example/a/b?x=1", evidence=ev, instances=7, systemic=True,
           examples=[f"https://shop.example/p{i}" for i in range(8)], notes=[{"en": "n1", "ar": "ملاحظة"}])
    html = report.render_html([f], TARGET, 1, [], lang="en", web=web())
    d = html[html.index("<details class='ev'>"):]
    d = d[:d.index("</details>")]
    assert "<code dir='ltr'>GET https://shop.example/a</code>" in d and "301 http://shop.example/a → https" in d
    assert "<tr class='hit'><td class='nw'><code>Content-Security-Policy</code>" in d
    assert "<pre class='mv' dir='ltr'>Content-Security-Policy: script-src *</pre>" in d
    assert "<pre dir='ltr'>curl -sS https://shop.example/a</pre>" in d
    assert "14 Nov 2026, 01:55 UTC" in d and "7 <span class='sys'>site-wide (systemic)</span>" in d
    assert d.count("<li><code dir='ltr'>https://shop.example/p") == 5 and "WSTG-CONF-12" in d
    loc = html[html.index("data-label='Location'"):]
    assert "<br><code dir='ltr'>/p0</code>" in loc[:300]                             # the first example's path


# ------------------------------------------------------------------------------------------- 10. grades

def test_grade_cards_score_binding_cap_family_and_observatory_tables():
    w = web()
    w["grades"]["kashif"] = {"grade": "C+", "letter": "C+", "score": 108.4, "base": 100.2, "bonus": {"total": 8.2},
                             "caps": [{"cap": "C+", "rule": "WEB000", "en": "WEB000: Site served over plain HTTP",
                                       "ar": "WEB000: الموقع يُقدَّم عبر HTTP غير مشفّر"}],
                             "families": {"transport": {"name": {"en": "Transport & HSTS", "ar": "النقل وHSTS"},
                                                        "weight": 20, "score": 60, "penalty": 40, "state": "tested",
                                                        "contributions": [{"rules": ["WEB000"], "penalty": 40}]}}}
    w["grades"]["observatory"]["tests"] = {"x-frame-options": {"slug": "x-frame-options-implemented-via-csp",
                                                               "modifier": 5, "pass": True}}
    w["grades"]["observatory"]["missing_tests"] = ["redirection"]
    html = report.render_html([wf("WEB000")], TARGET, 1, [], lang="en", web=w)
    assert html.index("<section class='web gsec'>") < html.index("<div class=\"tiles\">")   # grades under the title
    assert "base 100 + bonus 8 = 108" in html
    assert "<span class='letter g-c' dir='ltr'>C+</span><span class='gword g-c'>weak</span>" in html
    assert "grade limited to C+ by:</b> <a href='#f-WEB000'><code>WEB000</code></a> — Site served over plain HTTP" in html
    assert "id='f-WEB000'" in html
    assert "<td>Transport &amp; HSTS</td><td>20</td><td>60</td>" in html
    assert "x-frame-options-implemented-via-csp" in html and "<td dir='ltr'>+5</td><td>✓</td>" in html
    assert "<code>redirection</code></td><td>not computed</td>" in html
    ar = report.render_html([wf("WEB000")], TARGET, 1, [], lang="ar", web=w)
    assert "النقاط 108 (الأساس 100 ومكافأة 8)" in ar
    assert ".g-a{color:var(--ga)}" in html


# ------------------------------------------------------------------------------------------- 11. coverage

def test_coverage_table_groups_titles_links_and_web_view():
    http = ("http_only", "the target is served over HTTP only", "الهدف يُقدَّم عبر HTTP فقط")
    cov, counts = coverage(fail=[("WEB204", [])], not_tested=[("WEB030", [http]), ("WEB070", [http])])
    w = web(coverage=cov, coverage_counts=counts)
    html = report.render_html([wf("WEB204")], TARGET, 1, [], lang="en", web=w)
    assert "<span class='s-inconclusive s-zero'>inconclusive: <b>0</b></span>" in html
    table = html[html.index("<details class='cov-d' open>"):]
    assert table.index("not tested <b>(2)</b>") < table.index("failed <b>(1)</b>")
    assert f"{RULES['WEB030'].name_en} <small class='nw'><code>WEB030</code></small>" in table
    assert f"<a href='#f-WEB204'>{RULES['WEB204'].name_en}</a>" in table
    view = report.web_view([wf("WEB204")], w, "en")
    assert ["WEB030", "not tested", "the target is served over HTTP only", RULES["WEB030"].name_en] in \
        view["coverage"]["problems"]
    g = view["coverage"]["groups"][0]
    assert g["state"] == "not_tested" and [c["id"] for c in g["checks"]] == ["WEB030", "WEB070"]
    assert view["diff"] is None
    base = report.web_view([], web(compare_previous=True), "ar")["diff"]
    assert base["comparable"] is False and "سيكون هذا الفحص أساس المقارنة" in base["notes"][0]
    assert report.web_view([], web(), "en", compare_previous=True)["diff"]["notes"][0].startswith("No previous scan")


def test_coverage_table_closed_when_there_are_many_groups():
    cov, counts = coverage(not_tested=[(f"WEB{700 + i}", [(f"r{i}", f"reason {i}", f"سبب {i}")]) for i in range(11)])
    html = report.render_html([], TARGET, 1, [], lang="en", web=web(coverage=cov, coverage_counts=counts))
    assert "<details class='cov-d'><summary>" in html


# ------------------------------------------------------------------------------------------- 12. inventory

def test_headers_inventory_grouped_by_url_with_verdict_symbols():
    inv = {"security_headers": [{"url": "https://shop.example/", "status": 200, "headers": {
        "Strict-Transport-Security": {"value": "max-age=300", "verdict": "short-max-age"},
        "X-Frame-Options": {"value": None, "verdict": "missing"},
        "Referrer-Policy": {"value": "no-referrer", "verdict": "no-referrer"},
        "Cross-Origin-Opener-Policy": {"value": "same-origin", "verdict": "ignored-on-http"},
        "Cross-Origin-Embedder-Policy": {"value": None, "verdict": "missing"}}}],
        "technologies": [{"name": "jQuery", "version": "1.12.4", "categories": ["javascript-library"],
                          "evidence": [{"source": "script", "name": ""}]}],
        "libraries": [{"name": "jquery", "version": "1.12.4", "url": "https://shop.example/js/jquery.js",
                       "vulnerable": True}]}
    html = report.render_html([], TARGET, 1, [], lang="ar", web=web(inventory=inv))
    assert html.count("https://shop.example/</code> · <span class='nw'>HTTP 200</span></caption>") == 1
    assert "<td class='nw v-weak' title='short-max-age'>⚠ مدة <bdi dir='ltr'>max-age</bdi> أقل من سنة</td>" in html
    assert "<td class='nw v-missing' title='missing'>✗ مفقودة</td>" in html
    assert "<td class='nw v-good' title='no-referrer'>✓ جيدة</td>" in html
    assert "<td class='nw v-ignored' title='ignored-on-http'>⊘ مُهمَلة عبر <bdi dir='ltr'>HTTP</bdi></td>" in html
    assert "<td class='nw v-unset' title='missing'>— غير مضبوطة</td>" in html
    head, rows = report.inventory_tables(web(inventory=inv), report._Lang("en"))["technologies"]
    assert head[3] == "Seen in" and len(rows) == 1                              # one row per (name, version)
    assert rows[0][2] == "javascript-library" and "/js/jquery.js" in rows[0][3] and rows[0][4] == "yes"
    assert report._INV_AR["enforced"] == "مفروضة" and report._INV_AR["ok"] == "سليمة"


# ------------------------------------------------------------------------------------------- 13. fixes

def test_fix_cards_have_anchors_rule_links_and_the_highest_severity():
    findings = [wf("WEB-content-security-policy", "medium"), wf("WEB204", "low")]
    html = report.render_html(findings, TARGET, 1, [], lang="en", web=web())
    m = re.search(r"<div class='snip' id='rem-S-CSP'><h3><span class='b medium'>Medium</span>", html)
    assert m, "the S-CSP card starts with its highest severity"
    card = html[m.start():html.index("</div>", m.start())]
    assert "Fixes: <a href='#f-WEB-content-security-policy'>" in card and "<a href='#f-WEB204'>" in card
    assert "<p class='cp'><a href='#rem-S-CSP'>Copy-paste fix ↓</a></p>" in html
    assert ".snip pre code,.diff code{font-size:inherit}" in html
    assert ".snip pre{direction:ltr;text-align:left;background:var(--code);padding:.5rem;overflow:auto;" \
           "font-size:.9rem;white-space:pre-wrap;overflow-wrap:anywhere}" in html


# ------------------------------------------------------------------------------------------- 14. CSS

def test_phone_cards_print_and_dark_mode():
    html = report.render_html([wf("WEB204")], TARGET, 1, [], lang="ar", web=web())
    assert "data-label='الخطورة'" in html and "td[data-label]::before{content:attr(data-label)" in html
    assert ".fd-h+.tw>table>thead{display:none}" in html
    css_print = html[html.index("@media print{\n"):]
    for rule in ("print-color-adjust:exact", ".tabs>label,.tabs>input{display:none}",
                 ".tabs>div.panel{display:block!important", "details::details-content{content-visibility:visible",
                 "tr{break-inside:avoid}", ".ph{display:block!important}"):
        assert rule in css_print, rule
    assert "<h4 class='ph'><bdi dir='auto'>" in html                              # printed tab headings
    assert "@media (prefers-color-scheme:dark){:root{--bg:#111418" in html
    assert html.index("prefers-color-scheme:dark") < html.index("@media print{:root{--bg:#fafafa")   # print stays light


# ------------------------------------------------------------------------------------------- 15. brand

def test_arabic_report_strings_use_the_brand_spelling():
    import inspect
    src = inspect.getsource(report)
    assert "كاشف" not in src and "كاشِف" in src
