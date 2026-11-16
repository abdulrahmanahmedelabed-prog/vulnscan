"""The UI's bidi() (vulnscan/ui/app.js) isolates Latin runs in Arabic text by the one shared run rule of
vulnscan/i18n/bidi.py: code-like sequences (= quotes < > ( ) , ;) stay in one left-to-right isolate, date and version
digit runs are isolated, English text is only escaped. Offline; the JavaScript checks run under Node.js when present."""

from __future__ import annotations

import html
import json
import pathlib
import re
import shutil
import subprocess

import pytest

from vulnscan.i18n import bidi as B

JS = (pathlib.Path(__file__).resolve().parents[1] / "vulnscan" / "ui" / "app.js").read_text(encoding="utf-8")
NODE = shutil.which("node")

def _run_node(code: str, **kw):
    """Run ``code`` under Node.js from a temporary file (Windows limits a command line to 32 767 characters)."""
    import os
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(code)
        return subprocess.run([NODE, path], **kw)
    finally:
        os.unlink(path)


# Arabic engine and UI texts with code, header values, URLs, versions and dates (the strings that displayed reversed:
# "Lax=SameSite", "includeSubDomains ;max-age=63072000", "12-11-2026" …)
SAMPLES = [
    "اضبط SameSite=Lax صراحةً.",
    'استخدم method="post" في النموذج.',
    "أرسل Strict-Transport-Security: max-age=63072000; includeSubDomains في كل استجابة.",
    "اضبط base-uri 'none' في السياسة.",
    "أضف frame-ancestors 'self' إلى السياسة.",
    'ضع <meta http-equiv="Content-Security-Policy"> في أول الصفحة.',
    "انتهى الدعم في 2026-11-12.",
    "الإصدار 1.2.3 من المكتبة قديم.",
    "المكتبة jquery@3.4.1 قديمة.",
    "افتح http://example.com/a?b=1&c=2 للتحقق.",
    "درجة كاشف F* · Observatory 0 (F) · SSL Labs A+",
    "يدعم C++ فقط.",
    "اضبط Set-Cookie: id=1; Secure; HttpOnly; SameSite=Strict للجلسة.",
    "الملف /.well-known/security.txt مفقود (404).",
]
WHOLE_RUNS = ["SameSite=Lax", 'method="post"', "Strict-Transport-Security: max-age=63072000; includeSubDomains",
              "base-uri 'none'", "frame-ancestors 'self'", '<meta http-equiv="Content-Security-Policy">', "2026-11-12",
              "1.2.3", "jquery@3.4.1", "http://example.com/a?b=1&c=2", "Observatory 0 (F)", "C++",
              "Set-Cookie: id=1; Secure; HttpOnly; SameSite=Strict", "/.well-known/security.txt"]


def test_app_js_carries_the_shared_rule_verbatim():
    start = JS.index("// BEGIN JS_BIDI")
    end = JS.index("// END JS_BIDI")
    block = JS[JS.index("\n", start) + 1:end]
    assert block == B.JS_BIDI, "regenerate the JS_BIDI block of app.js from vulnscan/i18n/bidi.py"
    assert "const bidi = (text) => (lang === 'ar' ? bidiHtml(text, esc) : esc(text));" in JS
    # the old private word pattern of 1.0.x is gone (one rule for the report and the UI)
    assert "const word = String.raw" not in JS


def test_python_rule_keeps_each_code_sequence_in_one_run():
    for text, run in zip(SAMPLES, WHOLE_RUNS):
        runs = [text[a:b] for a, b in B.ltr_runs(text)]
        assert run in runs, (text, runs)


@pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
def test_ui_bidi_matches_the_shared_rule_under_node():
    prefix = JS[:JS.index("/* Localized engine text")]
    script = prefix + """
;const S = JSON.parse(require('fs').readFileSync(0, 'utf8')); const out = {};
lang = 'ar'; out.ar = S.map((s) => bidi(s)); out.dir = S.map((s) => dirOf(s));
lang = 'en'; out.en = S.map((s) => bidi(s));
process.stdout.write(JSON.stringify(out));
"""
    # app.js expects a DOM: give the slice the few globals it touches at load time
    stub = "const localStorage = {getItem: () => null, setItem: () => {}};\n"
    res = _run_node(stub + script, input=json.dumps(SAMPLES), capture_output=True, text=True,
                         encoding="utf-8", timeout=60)
    assert res.returncode == 0, res.stderr
    out = json.loads(res.stdout)
    for text, got, run in zip(SAMPLES, out["ar"], WHOLE_RUNS):
        runs = [html.unescape(r) for r in re.findall(r'<bdi dir="ltr">(.*?)</bdi>', got)]
        assert runs == [text[a:b] for a, b in B.ltr_runs(text)], (text, runs)
        assert run in runs, (text, runs)
        # nothing is lost or left unescaped: without the isolates the text is the original, escaped
        assert html.unescape(re.sub(r"</?bdi[^>]*>", "", got)) == text
        assert "<meta" not in got and "<bdi" in got
    assert out["en"] == [html.escape(s, quote=True).replace("&#x27;", "&#39;") for s in SAMPLES]
    assert [s for s, d in zip(SAMPLES, out["dir"]) if d != "rtl"] == []


@pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
def test_finding_titles_get_an_explicit_direction_not_auto():
    """Finding titles use dir=dirOf(title) (never the browser's first-letter guess of dir="auto"): an Arabic title that
    starts with an Arabic word and holds mixed-case Latin is right-to-left, an English one left-to-right."""
    cases = {"سياسة CSP تسمح بسكربتات inline ('unsafe-inline')": "rtl", "اضبط SameSite=Lax صراحةً.": "rtl",
             "A01:2021 تحكم وصول معطوب": "rtl", "ISO/IEC 27001:2022 الملحق أ": "rtl", "OWASP Top 10:2021": "ltr",
             "Missing Strict-Transport-Security": "ltr", "WEB052": "ltr", "": "ltr"}
    prefix = JS[:JS.index("/* Localized engine text")]
    script = ("const localStorage = {getItem: () => null, setItem: () => {}};\n" + prefix
              + "\nconst S = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
                "process.stdout.write(JSON.stringify(S.map((s) => dirOf(s))));")
    res = _run_node(script, input=json.dumps(list(cases)), capture_output=True, text=True,
                         encoding="utf-8", timeout=60)
    assert res.returncode == 0, res.stderr
    assert dict(zip(cases, json.loads(res.stdout))) == cases
    rows = JS[JS.index("function renderFindings()"):JS.index("const confOf")]
    assert '<span class="f-title" dir="${dirOf(titleOf(f))}">${bidi(titleOf(f))}</span>' in rows
    assert '<span class="title" dir="${dirOf(titleOf(f))}"' in JS and '<b dir="${dirOf(titleOf(r))}">' in JS
    assert 'f-title" dir="auto"' not in JS
