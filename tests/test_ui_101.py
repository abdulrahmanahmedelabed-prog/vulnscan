"""1.0.1 fixes of the local web UI and the compliance texts it shows.

* Count strings agree with their number in both languages ("1 scan", not "1 scans"; Arabic singular, dual,
  plural 3-10 and accusative singular 11-99) through ``tn()`` and the ``pl`` tables of app.js.
* The compliance framework notes and source citations exist in Arabic and are shown in Arabic in the UI data and
  in the auditor report (``kashif compliance -f html --lang ar``); English output is unchanged.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess

import pytest

from vulnscan import compliance as C

UI = pathlib.Path(__file__).resolve().parents[1] / "vulnscan" / "ui"
JS = (UI / "app.js").read_text(encoding="utf-8")
ARABIC = re.compile(r"[؀-ۿ]")
PLACEHOLDER = re.compile(r"\{(\w+)\}")
AR_FORMS = {"one", "two", "few", "many", "other"}


def _lang_block(lang: str) -> str:
    start = JS.index(f"\n  {lang}: {{")
    return JS[start:JS.index("\n  },", start)]


def _plurals(lang: str) -> dict[str, dict[str, str]]:
    block = _lang_block(lang)
    at = block.find("\n    pl: {")
    if at < 0:
        return {}
    pl = block[at:]
    out = {}
    for key, body in re.findall(r"'([a-z]+\.[A-Za-z]+)': \{(.*?)\},?\n", pl):
        out[key] = dict(re.findall(r"(\w+): '((?:[^'\\]|\\.)*)'", body))
    return out


PL_AR, PL_EN = _plurals("ar"), _plurals("en")


def test_count_strings_have_every_plural_form():
    assert PL_AR and set(PL_AR) == set(PL_EN), sorted(set(PL_AR) ^ set(PL_EN))
    for key in PL_EN:
        assert set(PL_EN[key]) == {"one", "other"}, key
        assert set(PL_AR[key]) == AR_FORMS, key
        for form, text in PL_AR[key].items():
            assert ARABIC.search(text), (key, form)
        for text in PL_EN[key].values():
            assert not ARABIC.search(text), key
        # the counted number ({total} in the "by total" strings, else {n}) may be spelled out in the Arabic
        # singular and dual ("فحص واحد", "فحصان"); every other placeholder must appear in every form
        counted = "total" if "{total}" in PL_EN[key]["other"] else "n"
        others = set(PLACEHOLDER.findall(PL_EN[key]["other"])) - {counted}
        for text in [*PL_AR[key].values(), *PL_EN[key].values()]:
            assert set(PLACEHOLDER.findall(text)) - {counted} == others, (key, text)
        for form in ("few", "many", "other"):
            assert ("{%s}" % counted in PL_AR[key][form]) == ("{%s}" % counted in PL_EN[key]["other"]), (key, form)


def test_every_tn_key_exists_and_old_count_keys_are_gone():
    used = set(re.findall(r"\btn\('([a-z]+\.[A-Za-z]+)'", JS))
    used |= {k for a, b in re.findall(r"\btn\([^,()]*\? '([a-z]+\.[A-Za-z]+)' : '([a-z]+\.[A-Za-z]+)'", JS) for k in (a, b)}
    assert {"proj.nScans", "proj.count", "find.nFiles", "find.nPages", "rules.n"} <= used
    assert used <= set(PL_EN), sorted(used - set(PL_EN))
    for key in PL_EN:                       # a plural key is never read with t(), which would show {n} raw
        assert f"t('{key}'" not in JS.replace(f"tn('{key}'", ""), key
    for gone in ("find.files", "find.pages", "scan.selected", "rules.count"):   # were glued after a number
        assert f"'{gone}'" not in JS, gone


def test_no_flat_english_string_puts_a_plural_noun_after_a_count():
    flat = dict(re.findall(r"'([a-z0-9]+\.[A-Za-z0-9_.]+)': '((?:[^'\\]|\\.)*)'", _lang_block("en")))
    bad = {k: v for k, v in flat.items() if k not in PL_EN and re.search(r"\{(?:n|total|with)\} [a-z]+s\b", v)}
    assert not bad, bad


NODE = shutil.which("node")


@pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
def test_tn_picks_the_form_that_agrees_with_the_count():
    prefix = JS[:JS.index("const sevName")]          # I18N, t(), pluralCat() and tn(): no DOM needed
    probe = prefix + """
;const out = {};
for (const lg of ['en', 'ar']) {
  lang = lg;
  for (const n of [0, 1, 2, 3, 10, 11, 99, 100, 101, 102, 103, 111, 1000]) {
    out[`${lg}|proj.nScans|${n}`] = tn('proj.nScans', n);
    out[`${lg}|cat|${n}`] = pluralCat(n);
  }
  out[`${lg}|showing`] = tn('find.showing', 1, {n: 1, total: 1});
  out[`${lg}|showing5`] = tn('find.showing', 5, {n: 2, total: 5});
  out[`${lg}|spark`] = tn('proj.spark', 2, {vals: '3, 4'});
}
process.stdout.write(JSON.stringify(out));
"""
    res = subprocess.run([NODE, "-"], input=probe, capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert res.returncode == 0, res.stderr
    got = json.loads(res.stdout)
    assert got["en|proj.nScans|1"] == "1 scan" and got["en|proj.nScans|2"] == "2 scans"
    assert got["en|proj.nScans|0"] == "0 scans" and got["en|proj.nScans|101"] == "101 scans"
    assert got["en|showing"] == "Showing 1 of 1 finding" and got["en|showing5"] == "Showing 2 of 5 findings"
    assert got["en|spark"] == "Total findings across 2 scans, oldest to newest: 3, 4"
    ar = {n: got[f"ar|proj.nScans|{n}"] for n in (0, 1, 2, 3, 10, 11, 99, 100, 101, 102, 103, 111, 1000)}
    assert ar[1] == "فحص واحد" and ar[2] == "فحصان"                       # singular, dual
    assert ar[3] == "3 فحوصات" and ar[10] == "10 فحوصات" and ar[103] == "103 فحوصات"   # plural 3-10
    assert ar[11] == "11 فحصًا" and ar[99] == "99 فحصًا" and ar[111] == "111 فحصًا"     # accusative singular
    assert ar[100] == "100 فحص" and ar[101] == "101 فحص" and ar[102] == "102 فحص" and ar[1000] == "1000 فحص"
    assert ar[0] == "0 فحص"
    assert [got[f"ar|cat|{n}"] for n in (1, 2, 3, 11, 100)] == ["one", "two", "few", "many", "other"]
    assert got["ar|showing"] == "عرض 1 من نتيجة واحدة" and got["ar|showing5"] == "عرض 2 من 5 نتائج"
    assert got["ar|spark"] == "إجمالي النتائج عبر فحصين، من الأقدم إلى الأحدث: 3, 4"


# ------------------------------------------------------------------------------------------- compliance text

PROPER = ("OWASP", "ASVS", "PCI DSS", "NIST", "SSDF", "ISO", "HIPAA", "GDPR", "CWE", "MITRE", "ePHI", "HHS")


def test_every_framework_note_and_source_has_an_arabic_version():
    data = C.load_data()
    for fid, fw in data["frameworks"].items():
        ar = fw.get("note_ar", "")
        assert ar and ARABIC.search(ar), fid
        for name in PROPER:                  # proper nouns stay Latin
            if name in fw["note"]:
                assert name in ar, (fid, name)
    for sid, src in data["sources"].items():
        assert src.get("title_ar") and ARABIC.search(src["title_ar"]), sid
        if src.get("retrieved"):
            assert src.get("retrieved_ar") and ARABIC.search(src["retrieved_ar"]), sid
        for name in PROPER:
            if name in src["title"]:
                assert name in src["title_ar"], (sid, name)


def test_framework_info_and_json_use_the_report_language():
    for fid in C.FRAMEWORKS:
        en, ar = C.framework_info(fid, "en"), C.framework_info(fid, "ar")
        raw = C.load_data()["frameworks"][fid]
        assert en["note"] == raw["note"] and ar["note"] == raw["note_ar"]
        assert not ARABIC.search(en["source"]["title"]) and ARABIC.search(ar["source"]["title"])
        assert not any(k.endswith("_ar") for k in (*en["source"], *ar["source"]))   # same JSON shape as 1.0
    finding = {"rule_id": "INJ001", "severity": "high", "cwe": "CWE-89", "file": "a.py", "line": 1,
               "title": "SQL built from input", "title_ar": "استعلام SQL من مدخلات"}
    doc_en = json.loads(C.render_json([finding], {}, "en"))
    doc_ar = json.loads(C.render_json([finding], {}, "ar"))
    assert set(doc_en["sources"]) == set(doc_ar["sources"])
    for sid, src in doc_en["sources"].items():
        assert set(src) == set(doc_ar["sources"][sid]) and not any(k.endswith("_ar") for k in src), sid
        assert not ARABIC.search(src["title"]) and ARABIC.search(doc_ar["sources"][sid]["title"]), sid
    assert doc_ar["frameworks"]["pci-dss-4.0"]["note"].startswith("لا ينشر PCI DSS")


def test_auditor_report_shows_arabic_notes_and_citations():
    finding = {"rule_id": "INJ001", "severity": "high", "cwe": "CWE-89", "file": "a.py", "line": 1,
               "title": "SQL built from input", "title_ar": "استعلام SQL من مدخلات"}
    data = C.load_data()
    ar = C.render_html([finding], {}, "ar")
    en = C.render_html([finding], {}, "en")
    for fid, fw in data["frameworks"].items():
        assert C._e(fw["note_ar"]) in ar and C._e(fw["note"]) not in ar, fid
        assert C._e(fw["note"]) in en and C._e(fw["note_ar"]) not in en, fid
    for sid in ("owasp-top10-2021", "cwe-hierarchy", "kashif-analyst"):
        src = data["sources"][sid]
        assert C._e(src["title_ar"]) in ar and C._e(src["title"]) not in ar, sid
        # a citation that starts with a Latin name ("OWASP Top 10:2021، …") still reads right to left
        assert f"<bdi dir='rtl'>{C._e(src['title_ar'])}</bdi>" in ar, sid
        assert C._e(src["title"]) in en and C._e(src["title_ar"]) not in en, sid
    assert C._e(data["sources"]["cwe-top25-2024"]["retrieved_ar"]) in ar
    assert C._e(data["sources"]["cwe-top25-2024"]["retrieved"]) in en


def test_compliance_cli_html_in_arabic(tmp_path):
    import sys
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"target": "x", "files_scanned": 1, "findings": [
        {"rule_id": "INJ001", "severity": "high", "cwe": "CWE-89", "file": "a.py", "line": 1,
         "title": "SQL built from input", "title_ar": "استعلام SQL من مدخلات"}]}), encoding="utf-8")
    out = tmp_path / "audit.html"
    res = subprocess.run([sys.executable, "-m", "vulnscan", "compliance", str(report), "-f", "html", "--lang", "ar",
                          "--framework", "pci", "-o", str(out)], capture_output=True, text=True, encoding="utf-8",
                         timeout=120)
    assert res.returncode in (0, 1), res.stderr
    html = out.read_text(encoding="utf-8")
    assert "لا ينشر PCI DSS ربطًا مع CWE" in html and "PCI DSS does not publish" not in html
