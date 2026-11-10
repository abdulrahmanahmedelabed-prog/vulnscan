"""English coverage gate.

Every user-facing Arabic string the engine can emit (rule advice and titles, data-flow models, VQL advice, trail
steps, scan notes, CLI help and messages) must have an English translation in vulnscan/i18n. A new rule or
message without English fails here.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

from vulnscan.cli import build_parser, main, resolve_lang
from vulnscan.i18n import has_arabic, to_en, translated
from vulnscan.model import Finding
from vulnscan.report import render_console, render_html, render_markdown, render_sarif
from vulnscan.rules import RULES
from vulnscan.scanner import scan_path

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "tests" / "data"
MODELS = ROOT / "vulnscan" / "models"
ARABIC = re.compile(r"[؀-ۿݐ-ݿﭐ-﷿ﹰ-﻿]+")


def _untranslated(items) -> list[str]:
    return sorted({t for t in items if isinstance(t, str) and not translated(t)})


def _fmt(missing: list[str]) -> str:
    return f"{len(missing)} strings without English:\n" + "\n".join(f"  {m!r}" for m in missing[:60])


# ------------------------------------------------------------------ (a) static catalogues

def _title_missing(title_ar, title) -> bool:
    """An Arabic title has English when the catalog knows it or its record carries an English `title`."""
    return bool(title_ar) and not translated(title_ar) and (not title or has_arabic(title))


def test_rules_translated():
    missing = _untranslated([r.advice for r in RULES])
    missing += sorted({r.title_ar for r in RULES if _title_missing(r.title_ar, r.title)})
    assert not missing, _fmt(missing)


def _model_records(node):
    """Every dict in a model file that carries user-facing text (advice / title_ar)."""
    if isinstance(node, dict):
        if "advice" in node or "title_ar" in node:
            yield node
        for v in node.values():
            yield from _model_records(v)
    elif isinstance(node, list):
        for v in node:
            yield from _model_records(v)


def test_models_translated():
    records = []
    for f in sorted(MODELS.glob("*.json")):
        records += list(_model_records(json.loads(f.read_text(encoding="utf-8"))))
    assert records, "no model strings found"
    missing = _untranslated([r.get("advice") for r in records])
    missing += sorted({r["title_ar"] for r in records if _title_missing(r.get("title_ar"), r.get("title"))})
    assert not missing, _fmt(missing)


def test_builtin_catalogues_translated():
    from vulnscan.scanner import ENTROPY_RULE
    from vulnscan.semantic import CATALOGUE as SEM
    from vulnscan.taint import TAINT_RULES
    from vulnscan.vql import catalogue
    records = [ENTROPY_RULE] + list(SEM) + list(TAINT_RULES) + catalogue()
    missing = _untranslated([r.get("advice", "") for r in records])
    missing += sorted({r["title_ar"] for r in records if _title_missing(r.get("title_ar"), r.get("title"))})
    assert not missing, _fmt(missing)


# ------------------------------------------------------------------ (b) what a real scan emits

def _source_text(root: pathlib.Path, f: Finding) -> str:
    try:
        return (root / f.file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _arabic_outside_code(text: str, source: str) -> bool:
    """Arabic left in English text, ignoring quoted code that is copied verbatim from the scanned file."""
    if not has_arabic(text):
        return False
    for q in re.findall(r"`([^`]*)`|'([^']*)'|\"([^\"]*)\"", text):
        frag = next((x for x in q if x), "")
        if frag and frag in source:
            text = text.replace(frag, "")
    return has_arabic(text)


@pytest.fixture(scope="module")
def scanned():
    notes: list[str] = []
    findings, _ = scan_path(DATA, notes=notes)
    assert findings
    return findings, notes


def test_scan_output_has_english(scanned):
    findings, notes = scanned
    missing: set[str] = set()
    for f in findings:
        d = f.to_dict()
        source = _source_text(DATA, f)
        if _arabic_outside_code(d["advice_en"], source):
            missing.add(f.advice)
        # a snippet is normally the offending source line; only a snippet that is engine prose must be English
        if has_arabic(d["snippet_en"]) and f.snippet.strip() not in source:
            missing.add(f.snippet)
        for st in (d["extra"].get("path") or []):
            if isinstance(st, dict) and _arabic_outside_code(st["text_en"], source):
                missing.add(st.get("text", ""))
    missing |= {n for n in notes if not translated(n)}
    assert not missing, _fmt(sorted(missing))


def test_to_dict_keeps_arabic_and_fingerprint(scanned):
    findings, _ = scanned
    for f in findings[:50]:
        before = f.fingerprint()
        d = f.to_dict()
        assert d["advice"] == f.advice and d["snippet"] == f.snippet
        assert d["fingerprint"] == before == f.fingerprint()
        for st in f.extra.get("path") or []:
            assert "text_en" not in st          # to_dict copies; the finding itself is not mutated


# ------------------------------------------------------------------ (c) the CLI in English

SAMPLE = {
    "app.py": ("import os, pickle, subprocess\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
               "@app.route('/run')\ndef run():\n    cmd = request.args['cmd']\n    return subprocess.check_output(cmd, shell=True)\n\n"
               "@app.route('/load')\ndef load():\n    return pickle.loads(request.data)\n\n"
               "def q(cur):\n    cur.execute(\"SELECT * FROM t WHERE id=\" + request.args['id'])\n"
               "AWS = 'AKIAIOSFODNN7EXAMPLE'\n"),
    "web.js": "const x = location.hash;\ndocument.body.innerHTML = x;\neval(x);\n",
}


@pytest.fixture()
def sample(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    for name, text in SAMPLE.items():
        (src / name).write_text(text, encoding="utf-8")
    return src


@pytest.mark.parametrize("fmt", ["console", "markdown", "html", "sarif"])
def test_cli_english_output_has_no_arabic(sample, tmp_path, fmt):
    out = tmp_path / f"r.{fmt}"
    main([str(sample), "--no-deps", "--no-external", "--lang", "en", "--no-color", "-f", fmt, "-o", str(out)])
    text = out.read_text(encoding="utf-8")
    assert text.strip()
    left = sorted(set(ARABIC.findall(text)))     # the sample has no Arabic code, so any Arabic is untranslated
    assert not left, f"Arabic in --lang en {fmt} output: {left[:40]}"
    if fmt == "html":
        assert '<html lang="en" dir="ltr">' in text


def test_cli_english_help_and_rules(capsys):
    assert not has_arabic(build_parser("en").format_help())
    main(["--lang", "en", "--list-rules"])
    out = capsys.readouterr().out
    assert not ARABIC.findall(out), sorted(set(ARABIC.findall(out)))[:40]


def test_sarif_is_english_first():
    f = Finding("A1", "high", "SQL injection", "حقن SQL", "a.py", 3, "cur.execute(q)", "استخدم استعلامات مُعلَّمة.",
                "CWE-89", extra={"path": [{"file": "a.py", "line": 1, "text": "x"}]})
    doc = json.loads(render_sarif([f], "/p", 1, []))
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["shortDescription"]["text"] == rule["fullDescription"]["text"] == "SQL injection"
    assert "cwe.mitre.org/data/definitions/89.html" in rule["help"]["markdown"]
    assert rule["properties"]["title_ar"] == "حقن SQL"
    res = doc["runs"][0]["results"][0]
    assert res["message"]["text"].startswith("SQL injection")
    assert res["properties"]["advice_ar"] == f.advice


def test_default_output_unchanged_languages(sample):
    """lang "both" (the default) keeps today's bilingual output; "ar" stays Arabic."""
    findings, n = scan_path(sample)
    both = render_markdown(findings, "p", n, [])
    assert "الملخص التنفيذي" in both and "CRITICAL" in both
    assert render_markdown(findings, "p", n, [], lang="both") == both
    assert '<html lang="ar" dir="rtl">' in render_html(findings, "p", n, [], lang="ar")
    assert "الملخص" in render_console(findings, "p", n, [], color=False, lang="ar")
    assert "Summary" in render_console(findings, "p", n, [], color=False, lang="en")


def test_resolve_lang():
    assert resolve_lang("en", {}) == "en"
    assert resolve_lang("auto", {"VULNSCAN_LANG": "en"}) == "en"
    assert resolve_lang("ar", {"VULNSCAN_LANG": "en"}) == "ar"
    assert resolve_lang("auto", {"LANG": "ar_EG.UTF-8"}) == "ar"


# ------------------------------------------------------------------ (d) idempotence

@pytest.mark.parametrize("text", ["Use a parameterized query.", "eval() on dynamic input", "", "a.py:12 → b.py:3",
                                  "Do not deserialize untrusted data; use JSON."])
def test_to_en_idempotent_on_english(text):
    assert to_en(text) == text
    assert to_en(to_en(text)) == to_en(text)


def test_to_en_idempotent_on_catalog():
    from vulnscan.i18n import CATALOG
    for en in list(CATALOG.values())[:500]:
        assert to_en(en) == en


# ------------------------------------------------------------------ web UI server: stored scans carry English

def test_server_scan_stores_english(sample, tmp_path):
    from vulnscan.server import _dict_to_finding, _with_english, run_scan
    from vulnscan.store import Store
    store = Store(tmp_path / "home")
    scan = store.new_scan(str(sample), "path")
    run_scan(store, scan, {"use_osv": False, "use_external": False}, False)
    saved = store.get_scan(scan["id"])
    assert saved["status"] == "done" and len(saved["notes_en"]) == len(saved["notes"])
    assert saved["findings"] and all("advice_en" in d and "snippet_en" in d for d in saved["findings"])
    for d in saved["findings"]:          # reloading ignores the English keys and keeps the fingerprint
        assert _dict_to_finding(d).to_dict()["fingerprint"] == d["fingerprint"]
    missing = store.new_scan(str(tmp_path / "nope"), "path")
    run_scan(store, missing, {}, False)
    err = store.get_scan(missing["id"])
    assert err["status"] == "error" and not has_arabic(err["error_en"])
    legacy = {**saved, "findings": [{k: v for k, v in d.items() if not k.endswith("_en")} for d in saved["findings"]]}
    legacy.pop("notes_en")
    upgraded = _with_english(legacy)
    assert "notes_en" in upgraded and all("advice_en" in d for d in upgraded["findings"])
