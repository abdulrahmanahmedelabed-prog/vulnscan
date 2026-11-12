"""1.0.1 Arabic/English review: right-to-left display of Latin runs in the UI, one digit system in the Arabic UI,
Arabic punctuation and terms in the compliance report, and the language of the CLI help and usage errors."""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

from vulnscan import cli
from vulnscan import compliance as C

ROOT = pathlib.Path(__file__).resolve().parents[1]
JS = (ROOT / "vulnscan" / "ui" / "app.js").read_text(encoding="utf-8")
NODE = shutil.which("node")
EASTERN_DIGITS = re.compile(r"[٠-٩]")


def _node(script: str) -> dict:
    prefix = JS[:JS.index("const ARABIC = /")]          # I18N, t(), tn(), esc(), locale() and bidi(): no DOM needed
    res = subprocess.run([NODE, "-"], input=prefix + script, capture_output=True, text=True, encoding="utf-8",
                         timeout=60)
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout)


@pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
def test_bidi_isolates_whole_latin_runs_with_their_numbers():
    samples = {
        "owasp": "OWASP Top 10:2021، قائمة «List of Mapped CWEs» لكل فئة، فلا تذكرهما إلا OWASP.",
        "cfr": "45 CFR 164.312، قاعدة أمن HIPAA - الضمانات التقنية",
        "nist": "NIST SP 800-53 Rev. 5، ضوابط الأمن والخصوصية",
        "flag": "مرّر --sha256 ليُتحقَّق منها",
        "paren": "صفوف الأقسام (مثل V5.3) فهي ربط",
        "call": "الدالة order_query() تبني الاستعلام",
        "number": "عدد 2024 فقط",
    }
    got = _node("""
;const out = {};
lang = 'ar';
for (const [k, v] of Object.entries(%s)) out[k] = bidi(v);
lang = 'en';
out.en = bidi('OWASP Top 10:2021، قائمة');
process.stdout.write(JSON.stringify(out));
""" % json.dumps(samples, ensure_ascii=False))
    iso = {k: re.findall(r'<bdi dir="ltr">(.*?)</bdi>', v) for k, v in got.items()}
    # the year and the "Top 10" stay with their words; before 1.0.1 "OWASP Top" was isolated alone and the bidi
    # algorithm displayed "10:2021 OWASP Top"
    assert iso["owasp"] == ["OWASP Top 10:2021", "List of Mapped CWEs", "OWASP"]
    assert got["owasp"].endswith("</bdi>.")                  # the full stop belongs to the Arabic sentence
    assert iso["cfr"] == ["45 CFR 164.312", "HIPAA"]
    assert iso["nist"] == ["NIST SP 800-53 Rev. 5"]
    assert iso["flag"] == ["--sha256"]
    assert iso["paren"] == ["V5.3"] and "(مثل <bdi" in got["paren"] and "</bdi>)" in got["paren"]
    assert iso["call"] == ["order_query()"]
    assert iso["number"] == [] and got["number"] == samples["number"]
    assert iso["en"] == []                                      # English pages need no isolates


@pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
def test_arabic_ui_dates_use_the_same_digits_as_the_counts():
    got = _node("""
;const d = new Date(Date.UTC(2026, 10, 12, 13, 5));
const out = {};
for (const lg of ['ar', 'en']) {
  lang = lg;
  out[lg] = d.toLocaleString(locale(), {dateStyle: 'medium', timeStyle: 'short'});
  out[lg + 'Count'] = tn('proj.nScans', 12);
  out[lg + 'Fmt'] = fmtDate(d.getTime() / 1000);
}
process.stdout.write(JSON.stringify(out));
""")
    assert "12" in got["arCount"]
    if not re.search(r"[A-Za-z]", got["ar"]):                    # an ICU with Arabic data (full-icu)
        assert not EASTERN_DIGITS.search(got["ar"]), got["ar"]  # was "١٢‏/١١‏/٢٠٢٦" beside "12 فحصًا"
        assert "2026" in got["ar"]
    assert not EASTERN_DIGITS.search(got["en"])
    # an Arabic date is an RTL isolate, so "proj — <date>" in the scan menus keeps its order with Western digits
    assert got["arFmt"] == "\u2067" + got["ar"] + "\u2069"
    assert got["enFmt"] == got["en"]


def _findings():
    return [{"rule_id": "EXE004", "severity": "high", "title": "shell", "file": "a.py", "line": 4,
             "cwe": "CWE-78", "fingerprint": "f1"}]


def test_compliance_markdown_uses_the_arabic_comma_and_the_shared_risk_term():
    ar = C.render_markdown(_findings(), {}, "ar", ["owasp-top10-2021"])
    en = C.render_markdown(_findings(), {}, "en", ["owasp-top10-2021"])
    risk_ar = next(line for line in ar.splitlines() if line.startswith("**"))
    risk_en = next(line for line in en.splitlines() if line.startswith("**"))
    assert risk_ar.startswith("**درجة الخطر:**")               # as in the UI and `kashif --risk-score`
    assert "حرج: 0، عالٍ: 1، " in risk_ar and ", " not in risk_ar
    assert "| A03 |" in ar                                      # the framework table is there too
    assert "Critical: 0, High: 1, " in risk_en                  # English unchanged
    assert C._comma("ar") == "، " and C._comma("both") == "، " and C._comma("en") == ", "


def test_compliance_citations_read_naturally_in_arabic():
    data = json.loads((ROOT / "vulnscan" / "data" / "compliance.json").read_text(encoding="utf-8"))
    text = "\n".join(s.get("title_ar", "") for s in data["sources"].values())
    assert "CWE Top 25 لعام 2024" in text and "قائمة 2024 CWE" not in text
    assert "مُعادة الصياغة" in text and "مُعاد صياغتها" not in text


@pytest.mark.parametrize("lang", ["ar", "en", "both"])
def test_every_main_option_has_help_text(lang):
    parser = cli.build_parser(lang)
    bare = [a.option_strings for a in parser._actions if a.option_strings and not a.help]
    assert bare == [], bare                                     # --no-color had none


def _run(args, extra_env):
    env = {k: v for k, v in os.environ.items()
           if k not in ("VULNSCAN_LANG", "KASHIF_LANG", "LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE")}
    env.update({"LANG": "C.UTF-8", "PYTHONIOENCODING": "utf-8", **extra_env})
    return subprocess.run([sys.executable, "-m", "vulnscan", *args], capture_output=True, text=True,
                          encoding="utf-8", env=env, cwd=str(ROOT), timeout=60)


def test_mcp_usage_errors_follow_kashifs_language_like_its_help():
    both = _run(["mcp", "--bogus"], {})
    assert both.returncode == 2
    assert "خطأ / error" in both.stderr and "--bogus" in both.stderr   # "both", like `kashif mcp --help`
    ar = _run(["mcp", "--bogus"], {"VULNSCAN_LANG": "ar"})
    assert ar.returncode == 2 and "خطأ: معاملات غير معروفة: --bogus" in ar.stderr
    en = _run(["--lang", "en", "mcp", "--bogus"], {})
    assert en.returncode == 2 and "error: unrecognized arguments: --bogus" in en.stderr
    assert not re.search(r"[؀-ۿ]", en.stderr)


@pytest.mark.parametrize("variant, term", [("مهلة المعالجة", "مهلة الإصلاح"), ("اتفاقية مستوى الخدمة", "مهلة الإصلاح"),
                                           ("درجة المخاطر", "درجة الخطر")], ids=["sla", "sla-old", "risk"])
def test_one_arabic_term_per_concept(variant, term):
    # the SLA is "مهلة الإصلاح" in the CLI help, triage, policy and the UI; the risk score is "درجة الخطر"
    for path in [*(ROOT / "vulnscan").glob("*.py"), ROOT / "vulnscan" / "ui" / "app.js"]:
        assert variant not in path.read_text(encoding="utf-8"), (path.name, variant, term)


def test_arabic_count_phrases_follow_cldr_categories():
    from vulnscan.i18n.plural import FILES_SCANNED, ar_category, ar_count
    assert [ar_category(n) for n in (0, 1, 2, 3, 10, 11, 99, 100, 101, 102, 103, 111, 1000)] == \
        ["other", "one", "two", "few", "few", "many", "many", "other", "other", "other", "few", "many", "other"]
    assert [ar_count(n, FILES_SCANNED) for n in (1, 2, 3, 11, 100)] == \
        ["ملف واحد مفحوص", "ملفان مفحوصان", "3 ملفات مفحوصة", "11 ملفًا مفحوصًا", "100 ملف مفحوص"]


@pytest.mark.parametrize("files, n, ar, en", [
    (1, 1, "ملف واحد مفحوص، نتيجة واحدة", "1 file scanned, 1 finding"),
    (2, 2, "ملفان مفحوصان، نتيجتان", "2 files scanned, 2 findings"),
    (3, 0, "3 ملفات مفحوصة، 0 نتيجة", "3 files scanned, 0 findings"),
    (56, 161, "56 ملفًا مفحوصًا، 161 نتيجةً", "56 files scanned, 161 findings"),
    (100, 102, "100 ملف مفحوص، 102 نتيجة", "100 files scanned, 102 findings"),
], ids=["one", "two", "few-zero", "many", "other"])
def test_console_header_counts_agree_with_their_numbers(files, n, ar, en):
    from vulnscan import report
    from vulnscan.model import Finding
    findings = [Finding("EXE004", "high", "t", "ت", "a.py", i + 1, "x", "fix", cwe="CWE-78") for i in range(n)]
    for lang, want in (("ar", ar), ("both", ar), ("en", en)):
        head = report.render_console(findings, "proj", files, [], color=False, lang=lang).splitlines()[0]
        assert head == f"Kashif — proj  ({want})", (lang, head)   # was "1 ملفًا مفحوصًا، 1 نتيجة" / "1 files"
