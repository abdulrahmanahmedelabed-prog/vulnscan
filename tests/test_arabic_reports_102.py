"""1.0.2 Arabic review of the engine messages, the reports and the compliance evidence: Arabic sink labels in
data-flow findings (fingerprints unchanged), one term for "code", consistent framework cards, a responsive auditor
report, isolated Latin runs and explicit text direction, and Arabic analyst justifications."""

from __future__ import annotations

import glob
import json
import pathlib
import re
import shutil
import subprocess

import pytest

from vulnscan import compliance as C
from vulnscan import report as R
from vulnscan import taint
from vulnscan.i18n import has_arabic, to_en
from vulnscan.i18n.cat_dynamic import SINK_LABELS_AR, sink_label_ar
from vulnscan.model import Finding, assign_fingerprints
from vulnscan.scanner import scan_path

ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA = ROOT / "tests" / "data"
NODE = shutil.which("node")
TAGS = re.compile(r"<[^>]+>")


def _model_sink_labels() -> set[str]:
    labels = set()
    for path in glob.glob(str(ROOT / "vulnscan" / "models" / "*.json")):
        data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        for key in ("sinks", "attr_sinks", "store_sinks"):
            labels |= {k.get("label", k["rule"]) for k in data.get(key, [])}
    return labels


def _builtin_sink_labels() -> set[str]:
    return {v[6] for v in vars(taint).values()
            if isinstance(v, tuple) and len(v) >= 9 and isinstance(v[0], str) and re.fullmatch(r"DF\d{3}", v[0])}


# ---------------------------------------------------------------- 1. sink labels

def test_every_sink_label_has_an_arabic_form_that_translates_back():
    labels = _model_sink_labels() | _builtin_sink_labels()
    assert len(labels) > 100 and "HTML output (XSS)" in labels and "HTTP response" in labels
    missing = sorted(labels - set(SINK_LABELS_AR))
    assert not missing, f"sink labels without an Arabic form in i18n/cat_dynamic.SINK_LABELS_AR: {missing}"
    assert len(set(SINK_LABELS_AR.values())) == len(SINK_LABELS_AR)          # one English label per Arabic form
    for en, ar in SINK_LABELS_AR.items():
        assert has_arabic(ar) and ar == ar.strip() and "  " not in ar, en
        assert to_en(ar) == en, (en, ar)
        assert to_en(f"نقطة الخطر: {ar}") == f"Sink: {en}"
        assert to_en(f"بيانات غير موثوقة تمرّ عبر run() وتصل إلى {ar}") == f"Tainted data flows through run() into {en}"
        assert not re.search(r"شيفرة|الشيفرة", ar)                          # the product's term is الكود
    assert sink_label_ar("my own sink (user model)") == "my own sink (user model)"


# fingerprints of 1.0.1 (commit 16591ad) for findings whose Arabic text now carries an Arabic sink label
GOLDEN = {
    "realworld/php_include_view_xss": [("DF013", "ctrl.php", 4, "0603fa7ec1ff3f48:0"),
                                       ("DF013", "views/hello.php", 3, "3d845f0889a5365d:0")],
    "regress": [("DF002", "r2_py__setter_builder.py", 27, "41c53abc7cf9db41:1"),
                ("DF013", "sanit_java__XssServlet.java", 10, "4ace8a1c52fcaca6:0"),
                ("DF013", "r2_py__tornado_cmd.py", 9, "5d89c415e2e24fd0:0"),
                ("DF002", "flow_cases__while_flag.py", 10, "d16f852d74dfce1c:0"),
                ("DF004", "r2_py__helper_two_params.py", 34, "7c2b9b14c63903b6:1"),
                ("DF010", "r2_py__ssrf_shadowed_base.py", 8, "3f1134af5520b030:0")],
}


@pytest.mark.parametrize("case", sorted(GOLDEN))
def test_arabic_sink_labels_keep_titles_and_fingerprints(case):
    findings, _ = scan_path(DATA / case, jadx=False, notes=[])
    assign_fingerprints(findings)
    got = {(f.rule_id, f.file, f.line): f for f in findings}
    for rule, file, line, fp in GOLDEN[case]:
        f = got[(rule, file, line)]
        assert f.fingerprint() == fp, (rule, file, line)
    for f in findings:
        d = f.to_dict()
        for st in d["extra"].get("path") or []:
            if st["text"].startswith("نقطة الخطر: "):
                label = st["text_en"].removeprefix("Sink: ")
                assert label in SINK_LABELS_AR and st["text"] == f"نقطة الخطر: {SINK_LABELS_AR[label]}"
                assert not re.search(r"[A-Za-z]{3,} [a-z]{3,}", st["text"]), st["text"]   # no English phrase left
        if "وتصل إلى" in f.title_ar:
            assert f.title.startswith("Tainted data flows through ") and to_en(f.title_ar) == f.title


def test_include_flow_df013_is_arabic_and_english_title_unchanged():
    findings, _ = scan_path(DATA / "realworld" / "php_include_view_xss", jadx=False, notes=[])
    f = next(f for f in findings if f.rule_id == "DF013" and f.file == "ctrl.php")
    assert f.title == "Tainted data flows through include() into HTML output (XSS)"
    assert f.title_ar == "بيانات غير موثوقة تمرّ عبر include() وتصل إلى مخرجات HTML (XSS)"
    assert "HTML output" not in json.dumps(f.to_dict()["extra"]["path"], ensure_ascii=False).split('"text_en"')[0]


# ---------------------------------------------------------------- 2. one term for "code"

OWNED_AR = ["vulnscan/compliance.py", "vulnscan/data/compliance.json", "vulnscan/report.py", "vulnscan/ui/app.js",
            "vulnscan/i18n/cat_dynamic.py"]


@pytest.mark.parametrize("rel", OWNED_AR)
def test_reports_and_compliance_say_alkod_not_alshifra(rel):
    text = (ROOT / rel).read_text(encoding="utf-8")
    assert not re.search(r"شيفرة|شيفرات", text), rel


# ---------------------------------------------------------------- 3. framework cards

def _f(rule="X1", sev="high", cwe="", **kw):
    d = {"rule_id": rule, "severity": sev, "cwe": cwe, "file": "a.py", "line": 1, "title": "t", "title_ar": "ع",
         "extra": {}}
    d.update(kw)
    return d


def test_generic_only_control_is_not_counted_as_control_with_findings():
    # a finding that GDPR maps only through its generic control Art.32(1)(b): status "No findings", 0 mapped, and
    # (since 1.0.2) 0 controls with findings, not "1 of 2"
    gdpr = C.summarize([_f(sev="critical")], ["gdpr"], lang="ar")["gdpr-art32"]
    rows = {r["control"]: r for r in gdpr["rows"]}
    assert rows["Art.32(1)(b)"]["total"] == 1 and rows["Art.32(1)(b)"]["basis"] == ["generic"]
    assert gdpr["status"] == "pass" and gdpr["findings_mapped"] == 0 and gdpr["findings_unmapped"] == 1
    assert gdpr["controls_with_findings"] == 0 and gdpr["controls_total"] == 2


def test_card_counts_agree_with_status_for_every_framework():
    findings = [_f(), _f(rule="INJ001", cwe="CWE-89"), _f(rule="SEC001", cwe="CWE-798", sev="medium"),
                _f(rule="TLS1", cwe="CWE-295", sev="low"), _f(rule="X2", cwe="CWE-1333", sev="info")]
    for subset in ([findings[0]], findings[:2], findings, []):
        for fid, fw in C.summarize(subset).items():
            specific = [r for r in fw["rows"] if r["total"] and r["basis"] != ["generic"]]
            assert fw["controls_with_findings"] == len(specific), fid
            assert (fw["status"] == "pass") == (fw["controls_with_findings"] == 0) == (fw["findings_mapped"] == 0), fid
            assert fw["findings_mapped"] + fw["findings_unmapped"] == len(subset), fid


# ---------------------------------------------------------------- 4/5/6. auditor report layout and direction

def test_direction_skips_identifiers_numbers_and_acronyms():
    rtl = ["A01:2021 تحكم وصول معطوب", "ISO/IEC 27001:2022 الملحق أ", "API1:2023 تفويض معطوب على مستوى الكائن",
           "SQL خام في Exposed", "164.312(b) ضوابط التدقيق", "بيانات غير موثوقة تصل إلى SQL"]
    ltr = ["OWASP Top 10:2021", "PCI DSS v4.0", "Art.32(1)(b)", "CWE-79", "NIST SP 800-53 Rev. 5", "SQL injection",
           "A01:2021 Broken Access Control", ""]
    for text in rtl:
        assert C._direction(text) == "rtl", text
        assert C._bt(text).startswith("<bdi dir='rtl'>"), text
    for text in ltr:
        assert C._direction(text) == "ltr", text
        assert C._bt(text) == f"<bdi dir='ltr'>{C._e(text)}</bdi>", text
    assert C._bt("A01:2021 تحكم وصول معطوب") == "<bdi dir='rtl'><bdi dir='ltr'>A01:2021</bdi> تحكم وصول معطوب</bdi>"
    assert C._bt("ع & <") == "<bdi dir='rtl'>ع &amp; &lt;</bdi>"                          # still escaped
    assert C._bt("<b>x</b>") == "<bdi dir='ltr'>&lt;b&gt;x&lt;/b&gt;</bdi>"


def test_latin_urls_and_ids_in_arabic_prose_are_isolated():
    src = C.load_data()["sources"]["owasp-top10-2021"]["retrieved_ar"]
    out = C._ltr_runs(src)
    assert "<bdi dir='ltr'>github.com/OWASP/Top10</bdi>" in out and "<bdi dir='ltr'>2021/docs/en</bdi>" in out
    assert TAGS.sub("", out) == C._e(src)
    assert C._ltr_runs("عدد 2024 فقط") == "عدد 2024 فقط"                       # numbers need no isolate
    assert C._ltr_runs("plain English") == "plain English"
    assert C._ltr_runs("انظر https://x.example/a-b.") == "انظر <bdi dir='ltr'>https://x.example/a-b</bdi>."


def _audit(lang):
    findings = [_f(rule="INJ001", sev="high", cwe="CWE-89", title="SQL built from input",
                   title_ar="استعلام SQL مبني من مدخلات", snippet="المصدر: request.args",
                   advice="استخدم استعلامات مُعلَّمة (cursor.execute(sql, params)).",
                   extra={"url": "https://example.com/a-very-long-reference-url/with-many-segments-and-hyphens",
                          "path": [{"file": "a.py", "line": 1, "text": "q = request.args"},
                                   {"file": "a.py", "line": 2, "text": "نقطة الخطر: عبارة SQL"}]}),
                _f(rule="LOG1", sev="low", cwe="CWE-117")]
    meta = {"target": "/very/long/path/to/some-project-name/with-many-segments/and-a-really-long-directory-name"}
    return C.render_html(findings, meta, lang=lang)


@pytest.mark.parametrize("lang", ["ar", "en"])
def test_auditor_report_tables_scroll_in_their_own_box(lang):
    out = _audit(lang)
    assert "name='viewport' content='width=device-width, initial-scale=1'" in out
    assert out.count("<table") == out.count("<div class='tw'><table") > 0
    assert out.count("</table>") == out.count("</table></div>")
    assert ".tw{max-width:100%;overflow-x:auto" in out and "@media screen and (max-width:640px)" in out
    assert "<a class='url' href='https://example.com/a-very-long" in out and "dir='ltr'" in out


def test_arabic_auditor_report_isolates_ids_and_urls():
    out = _audit("ar")
    assert "<bdi dir='rtl'><bdi dir='ltr'>A03:2021</bdi> الحقن</bdi>" in out
    assert "<a href='#F-001' dir='ltr'>F-001</a>" in out                              # evidence ids
    assert "<pre class='msg'>" in out and "pre.msg{unicode-bidi:plaintext" in out    # Arabic engine snippet
    assert "<bdi dir='ltr'>q = request.args</bdi>" in out                            # a code step in Arabic text
    assert "<bdi dir='ltr'>cursor.execute(sql, params)</bdi>" in out                  # code inside Arabic advice
    assert "<bdi dir='ltr'>OWASP Top 10</bdi>، <bdi dir='ltr'>OWASP API Top 10</bdi>" in out


def test_report_html_is_responsive_and_rows_are_readable():
    f = Finding("DF002", "critical", "Tainted data reaches a shell command", "بيانات غير موثوقة تصل إلى أمر shell",
                "app.py", 3, "المصدر: request.args", "لا تمرّر مدخلات إلى shell.", "CWE-78", source="taint",
                extra={"path": [{"file": "app.py", "line": 3, "text": "نقطة الخطر: أمر shell"}]})
    for lang in ("ar", "en", "both"):
        page = R.render_html([f], "/a/very/long/target-path", 1, [], lang=lang)
        assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in page
        assert '<div class="tw"><table>' in page and "</table></div>" in page and ".tw{max-width:100%;overflow-x:auto}" in page
        # 1.0.0/1.0.1 painted whole table rows dark red (tr.critical matched the tile colour rule)
        assert not re.search(r"(?<![\w.])\.critical\{", page) and ".tile.critical,.b.critical{background:#7f1d1d}" in page
        assert "@media (max-width:640px)" in page
    page = R.render_html([f], "t", 1, [], lang="ar")
    assert "<small dir='auto'>المصدر: request.args</small>" in page and "<bdi>نقطة الخطر: أمر shell</bdi>" in page


@pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
def test_ui_control_titles_use_explicit_direction():
    js = (ROOT / "vulnscan" / "ui" / "app.js").read_text(encoding="utf-8")
    prefix = js[:js.index("/* Localized engine text")]
    samples = ["A01:2021 تحكم وصول معطوب", "ISO/IEC 27001:2022 الملحق أ", "OWASP Top 10:2021", "Art.32(1)(b)",
               "SQL خام", "A01:2021 Broken Access Control"]
    script = prefix + f";process.stdout.write(JSON.stringify({json.dumps(samples, ensure_ascii=False)}.map(dirOf)));"
    res = subprocess.run([NODE, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert res.returncode == 0, res.stderr
    assert json.loads(res.stdout) == [C._direction(s) for s in samples] == ["rtl", "rtl", "ltr", "ltr", "rtl", "ltr"]
    assert 'class="ctl-title" dir="${dirOf(r.title)}"' in js and 'class="ctl-title" dir="auto"' not in js


# ---------------------------------------------------------------- 7. analyst justifications in Arabic

def test_every_analyst_justification_and_exclusion_has_arabic():
    data = C.load_data()
    n = 0
    for fid, fw in data["frameworks"].items():
        for cwe, entry in fw["cwe_analyst"].items():
            assert has_arabic(entry.get("note_ar", "")) and not has_arabic(entry["note"]), (fid, cwe)
            n += 1
        assert set(fw.get("cwe_na_ar", {})) == set(fw["cwe_na"]), fid
        for cwe, why in fw["cwe_na"].items():
            assert has_arabic(fw["cwe_na_ar"][cwe]) and not has_arabic(why), (fid, cwe)
            n += 1
    assert n >= 58


def test_explain_finding_gives_the_justification_in_the_report_language():
    f = _f(cwe="CWE-1395", rule="OSV:x")
    en = C.explain_finding(f, ["owasp"], lang="en")["owasp-top10-2021"]
    ar = C.explain_finding(f, ["owasp"], lang="ar")["owasp-top10-2021"]
    (r_en,) = [r for r in en if r["basis"] == "analyst"]
    (r_ar,) = [r for r in ar if r["basis"] == "analyst"]
    entry = C.load_data()["frameworks"]["owasp-top10-2021"]["cwe_analyst"]["1395"]
    assert r_en["detail"] == entry["note"] and r_ar["detail"] == entry["note_ar"]
    assert r_en["control"] == r_ar["control"] == "A06" and r_en["source"] == r_ar["source"] == "kashif-analyst"
    doc = json.loads(C.render_json([f], lang="ar", frameworks=["owasp"]))
    assert doc["findings"][0]["compliance"]["owasp-top10-2021"][0]["detail"] == entry["note_ar"]
    # non-analyst details (CWE ids, category ids) are the same in both languages
    sql = _f(cwe="CWE-89")
    assert [r["detail"] for r in C.explain_finding(sql, lang="ar")["pci-dss-4.0"]] == \
        [r["detail"] for r in C.explain_finding(sql, lang="en")["pci-dss-4.0"]]


def test_counted_phrases_agree_with_the_number():
    assert C._t("ar", "hit_only", n=1) == "متطلب واحد آخر مرتبط بلا نتائج، ولم يُدرج."
    assert C._t("ar", "hit_only", n=2).startswith("متطلبان آخران")
    assert C._t("ar", "hit_only", n=3).startswith("3 متطلبات أخرى")
    assert C._t("ar", "hit_only", n=11).startswith("11 متطلبًا آخر")
    assert C._t("ar", "hit_only", n=100).startswith("100 متطلب آخر")
    assert C._t("ar", "unmapped_note", n=2).startswith("نتيجتان ليس لهما")
    assert C._t("en", "unmapped_note", n=1).startswith("1 finding has no CWE")
    assert C._t("en", "hit_only", n=4).startswith("4 further mapped requirements have")
