"""Kashif 1.1.0 web reports and UI, Arabic/English and small-screen review (ux-i18n verification lens).

Found by rendering the CLI reports and the UI web panel in Chromium at 1280 and 360 px, light and dark, in Arabic and
English, against a local site:

* right-to-left display: in "الدرجات: كاشف F* · Observatory 0 (F)" the whole Latin stretch formed one left-to-right
  run, so an Arabic reader saw the Observatory grade "(F)" right after "كاشف"; "A+" and "F*" displayed as "+A" and
  "*F"; "ملف الفحص standard: 45 طلبًا" displayed 45 beside "ملف الفحص";
* the coverage table of the HTML report was not in a scroll box (horizontal page scroll at 360 px); in the UI the
  short cells of the web tables broke letter by letter ("فا/ش/ل", "miss/ing");
* Arabic gaps: inventory verdicts, cookie classes and kinds stayed English ("missing", "session", "script"),
  coverage reasons were joined with ";", grade changes used an arrow that points back at the old grade, "بـ صفحة";
* the grade cards did not say why there was no grade ("?") or which families made it provisional.

Offline: synthetic report data, plus app.js run under Node.js when it is installed.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess

import pytest

from vulnscan import cli, report
from vulnscan.webscan import engine

ROOT = pathlib.Path(__file__).resolve().parents[1]
JS = (ROOT / "vulnscan" / "ui" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "vulnscan" / "ui" / "styles.css").read_text(encoding="utf-8")
NODE = shutil.which("node")
GRADES_AR = "الدرجات: كاشف F* · Observatory 0 (F) · متوافقة مع SSL Labs A+"


def _web() -> dict:
    return {
        "profile": "standard", "requests": 6, "final_url": "http://127.0.0.1:1/", "data_date": "2026-11-12",
        "notes": [{"en": "Grades: Kashif F* · Observatory 0 (F) · SSL Labs-compatible A+", "ar": GRADES_AR}],
        "grades": {
            "kashif": {"grade": "?", "label": {"en": "Kashif Web Grade (A+ to F)", "ar": "درجة كاشف للويب (من A+ إلى F)"},
                       "caps": [{"en": "A+ also requires: HSTS", "ar": "تتطلب الدرجة A+ أيضًا: HSTS"}],
                       "notes": [{"en": "no grade: the site answered with a WAF challenge (WEB990)",
                                  "ar": "لا درجة: أجاب جدار حماية بتحدٍّ بدل الصفحة (WEB990)"}]},
            "observatory": {"grade": "F", "score": 0, "max_score": 165},
            "ssllabs": {"grade": "A+"},
        },
        "coverage_counts": {"pass": 1, "fail": 1, "not_applicable": 0, "not_tested": 1, "inconclusive": 0},
        "coverage": [
            {"check": "WEB-content-security-policy", "state": "fail", "reasons": []},
            {"check": "WEB070", "state": "not_tested",
             "reasons": [{"en": "the target is served over HTTP only", "ar": "الهدف يُقدَّم عبر HTTP فقط"},
                         {"en": "deep mode off", "ar": "الوضع العميق غير مفعّل"}]},
        ],
        "inventory": {
            "security_headers": [{"url": "http://127.0.0.1:1/", "headers": {
                "X-Frame-Options": {"value": None, "verdict": "missing"},
                "Referrer-Policy": {"value": "no-referrer", "verdict": "no-referrer"}}}],
            "cookies": [{"name": "PHPSESSID", "host": "127.0.0.1", "class": "session"}],
            "third_parties": {"code.jquery.com": ["script"], "cdn.example.org": ["style"]},
            "technologies": [{"name": "Apache HTTP Server", "version": "2.4.29", "categories": ["web-server"]}],
            "server_software": [{"product": "PHP", "version": "5.6.40", "where": "X-Powered-By"}],
        },
        "diff": {"comparable": True, "notes": [], "findings": {"new": [], "resolved": [], "unchanged": []},
                 "posture": [], "grades": {"kashif": {"before": "B+", "after": "A+"}}},
    }


# ------------------------------------------------------------------------------------------- bidi isolation

def test_bidi_html_keeps_each_grade_in_its_own_left_to_right_run():
    ar = report._Lang("ar")
    got = report._bidi_html(ar, GRADES_AR)
    runs = re.findall(r"<bdi dir='ltr'>(.*?)</bdi>", got)
    assert runs == ["F*", "Observatory 0", "F", "SSL Labs A+"]         # "F*" and "A+" whole, never "+A"
    assert "(<bdi dir='ltr'>F</bdi>)" in got                           # the brackets follow the Arabic sentence
    assert re.findall(r"<bdi dir='ltr'>(.*?)</bdi>", report._bidi_html(ar, "درجة كاشف للويب (من A+ إلى F): ست")) \
        == ["A+", "F"]
    assert report._bidi_html(ar, "عدد 2024 فقط") == "عدد 2024 فقط"     # a plain number needs no isolate
    assert report._bidi_html(report._Lang("en"), "Kashif A+ <b>") == "Kashif A+ &lt;b&gt;"
    assert "<script" not in report._bidi_html(ar, "نص <script>alert(1)</script> F*")


@pytest.mark.parametrize("lang", ["ar", "both"])
def test_arabic_html_report_isolates_notes_grade_texts_and_tab_names(lang):
    web = _web()
    html = report.render_html([], "http://127.0.0.1:1/", 1, [GRADES_AR], lang=lang, web=web)
    assert "<li>الدرجات: كاشف <bdi dir='ltr'>F*</bdi> · <bdi dir='ltr'>Observatory 0</bdi>" in html
    assert "(من <bdi dir='ltr'>A+</bdi> إلى <bdi dir='ltr'>F</bdi>)" in html           # grade label
    assert "<li>تتطلب الدرجة <bdi dir='ltr'>A+</bdi> أيضًا" in html                   # grade caps
    assert "><bdi dir='auto'>ترويسات الأمان</bdi></label>" in html                     # tab names


def test_english_html_report_has_no_isolates_in_notes():
    web = _web()
    note = web["notes"][0]["en"]
    html = report.render_html([], "http://127.0.0.1:1/", 1, [GRADES_AR], lang="en", web=web)
    assert f"<li>{note}</li>" in html


def test_budget_note_does_not_put_the_request_count_beside_the_profile_label():
    for profile in ("minimal", "standard", "deep"):
        for crawl in (False, True):
            ar, _en = cli.web_budget_note(profile, crawl=crawl)
            # "standard: 45" is one left-to-right run, displayed "ملف الفحص 45 :standard"
            assert not re.search(r"[A-Za-z]: ?\d", ar), ar


def test_waf_note_attaches_the_preposition_to_the_arabic_word():
    for what in (engine.text("waf_what", "ar", provider="Cloudflare"), engine.text("rate_what", "ar", status=429)):
        ar = engine.text("blocked", "ar", what=what)
        assert "بـ " not in ar and "أجاب الموقع ب" + what.split()[0] in ar, ar


# ---------------------------------------------------------------------------------- layout and Arabic text

def test_html_report_tables_scroll_inside_their_box():
    html = report.render_html([], "http://127.0.0.1:1/", 1, [], lang="en", web=_web())
    # every table of the web sections sits in a .tw scroll box: the coverage table pushed a 360 px page to 439 px
    assert html.count("<table>") == html.count("<div class='tw'><table>") + html.count('<div class="tw"><table>')
    assert ".tw{max-width:100%;overflow-x:auto}" in html.replace("{{", "{").replace("}}", "}")


def test_ui_web_tables_keep_short_words_whole():
    assert re.search(r"\.web-table th,\.web-table td\{min-width:[\d.]+em\}", CSS)
    assert ".cov-table td:nth-child(2){white-space:nowrap}" in CSS
    assert "'cov-table')" in JS


@pytest.mark.parametrize("lang", ["ar", "en"])
def test_coverage_reasons_use_the_languages_semicolon(lang):
    L = report._Lang(lang)
    probs = dict((c, r) for c, _s, r in report._coverage_problems(_web(), L))
    assert probs["WEB070"] == ("the target is served over HTTP only; deep mode off" if lang == "en"
                               else "الهدف يُقدَّم عبر HTTP فقط؛ الوضع العميق غير مفعّل")


def test_inventory_tokens_are_arabic_in_arabic_and_unchanged_in_english():
    ar = report.inventory_tables(_web(), report._Lang("ar"))
    en = report.inventory_tables(_web(), report._Lang("en"))
    assert [r[3] for r in ar["headers"][1]] == ["مفقودة", "no-referrer"]          # header syntax stays as sent
    assert [r[3] for r in en["headers"][1]] == ["missing", "no-referrer"]
    assert ar["cookies"][1][0][2] == "جلسة" and en["cookies"][1][0][2] == "session"
    assert [r[1] for r in ar["third_parties"][1]] == ["سكربت", "ملف أنماط"]
    assert [r[1] for r in en["third_parties"][1]] == ["script", "style"]
    assert ar["technologies"][1][0][2] == "خادم ويب" and en["technologies"][1][0][2] == "web-server"
    # the server software row names where the banner was seen (it said "server" for every row)
    assert en["technologies"][1][1][2] == "X-Powered-By"


def test_grade_cards_say_why_there_is_no_grade():
    for lang, needle in (("en", "no grade: the site answered with a WAF challenge"), ("ar", "لا درجة: أجاب جدار حماية")):
        rows = {g["key"]: g for g in report._grade_rows(_web(), report._Lang(lang))}
        assert rows["kashif"]["grade"] == "?" and needle in rows["kashif"]["notes"][0]
        assert needle in report.render_html([], "x", 1, [], lang=lang, web=_web())
        assert needle in report.render_markdown([], "x", 1, [], lang=lang, web=_web())
        assert needle in json.dumps(report.web_view([], _web(), lang), ensure_ascii=False)


def test_grade_change_reads_from_old_to_new_in_both_languages():
    ch = {"before": "B+", "after": "A+"}
    assert report._grade_change_text(report._Lang("en"), "kashif", ch) == "Kashif Web Grade: B+ → A+"
    assert report._grade_change_text(report._Lang("ar"), "kashif", ch) == "درجة كاشِف للويب: من B+ إلى A+"


# ------------------------------------------------------------------------------------------------- the UI

@pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
def test_ui_bidi_keeps_grade_signs_in_the_run():
    prefix = JS[:JS.index("const ARABIC = /")]
    script = prefix + """
;lang = 'ar';
process.stdout.write(JSON.stringify([%s].map((s) => bidi(s))));
""" % ", ".join(json.dumps(s, ensure_ascii=False) for s in (GRADES_AR, "درجة كاشف للويب (من A+ إلى F)", "يدعم C++ فقط"))
    res = subprocess.run([NODE, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert res.returncode == 0, res.stderr
    runs = [re.findall(r'<bdi dir="ltr">(.*?)</bdi>', h) for h in json.loads(res.stdout)]
    assert runs == [["F*", "Observatory 0", "F", "SSL Labs A+"], ["A+", "F"], ["C++"]]


def test_ui_panel_isolates_engine_text_and_tab_names():
    sec = JS[JS.index("/* ------------------------------------------------------- web scan (1.1.0) */"):
             JS.index("/* -------------------------------------------------------------- triage */")]
    for needle in ("bidi(g.label)", "bidi(c)", "bidi(n)", "strList(g.notes)", "bidi(g)}</bdi>",
                   '<bdi dir="auto">${esc(tb.label)}</bdi>'):
        assert needle in sec, needle
