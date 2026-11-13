"""Kashif 1.0.2: Arabic and English quality of the command line.

* Every count printed by the command line agrees with its number in Arabic (one, two, few, many and other forms,
  vulnscan/i18n/plural.py) and is singular or plural in English ("{n:findings}" fields, vulnscan/i18n/cliargs.py).
* `kashif compliance` without a report, `kashif export` without a report and `kashif export FILE` without -f print
  the usage and a message naming what is missing (exit 2, as before).
* `kashif ui` greets in both languages under "both".
* history, surface and rules take "both" like the other sub-commands; their --help is translated; lsp --help too.
* VULNSCAN_LANG and KASHIF_LANG are both honoured everywhere, and the help texts name both.
"""

from __future__ import annotations

import pathlib
import re
import string

import pytest

from vulnscan import cli, exporters, history, mcp, policy, ruletest, surface, triage
from vulnscan.i18n import has_arabic, to_en
from vulnscan.i18n.cliargs import NOUNS, count, fmt, lang_from_env
from vulnscan.i18n.plural import ar_count
from vulnscan.integrations import github_pr

ARABIC = re.compile(r"[؀-ۿ]")


@pytest.fixture(autouse=True)
def _neutral_language(monkeypatch):
    for var in ("VULNSCAN_LANG", "KASHIF_LANG", "LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(cli, "_is_arabic_locale", lambda environ=None: False)


def _run(argv, capsys) -> tuple[int, str, str]:
    try:
        code = cli.main(argv)
    except SystemExit as e:
        code = e.code
    out, err = capsys.readouterr()
    return code, out, err


# ------------------------------------------------------------------------------------------- count phrases
@pytest.mark.parametrize("n, ar, en", [
    (0, "0 نتيجة", "0 findings"), (1, "نتيجة واحدة", "1 finding"), (2, "نتيجتان", "2 findings"),
    (3, "3 نتائج", "3 findings"), (10, "10 نتائج", "10 findings"), (11, "11 نتيجةً", "11 findings"),
    (99, "99 نتيجةً", "99 findings"), (100, "100 نتيجة", "100 findings"), (103, "103 نتائج", "103 findings"),
    (111, "111 نتيجةً", "111 findings")])
def test_count_phrase_agrees_with_the_number(n, ar, en):
    assert count(n, "findings", "ar") == ar == ar_count(n, NOUNS["findings"][0])
    assert count(n, "findings", "en") == en
    assert fmt("{n:findings}", "ar", n=n) == ar and fmt("{n:findings}", "en", n=n) == en


def test_count_phrase_dual_after_a_preposition_and_fractions():
    assert fmt("بعد {d:days_obl}", "ar", d=2) == "بعد يومين"
    assert fmt("{d:days}", "ar", d=2) == "يومان"
    assert fmt("بعد {d:days_obl}", "ar", d=1) == "بعد يوم واحد"
    assert fmt("{s:seconds_obl}", "ar", s=2.5) == "2.5 ثانية"         # not a whole number: no dual
    assert fmt("{s:seconds_obl}", "en", s=1.0) == "1 second"
    assert fmt("{fp!r} {n}", "en", fp="x", n=3) == "'x' 3"            # ordinary fields are untouched


def test_every_noun_has_five_arabic_forms_and_english():
    for name, (ar, one, many) in NOUNS.items():
        assert len(ar) == 5 and all(has_arabic(f) for f in ar), name
        assert "{n}" in ar[2] and "{n}" in ar[3] and "{n}" in ar[4] and "{n}" not in ar[0], name
        assert "{n}" in one and "{n}" in many and not has_arabic(one + many), name


# ----------------------------------------------------------------------------------- module messages
def test_triage_counts():
    assert triage._t("ar", "h_list", n=1) == "نتيجة مفروزة واحدة"
    assert triage._t("ar", "h_list", n=2) == "نتيجتان مفروزتان"
    assert triage._t("ar", "h_list", n=11) == "11 نتيجةً مفروزةً"
    assert triage._t("en", "h_list", n=1) == "1 triaged finding"
    assert triage._t("ar", "exp_row", fp="f", rule="r", file="a", date="d", days=2).endswith("(بعد يومين)")
    assert "بعد 5 أيام" in triage._t("ar", "exp_row", fp="f", rule="r", file="a", date="d", days=5)
    assert "بعد 100 يوم" in triage._t("ar", "exp_row", fp="f", rule="r", file="a", date="d", days=100)
    assert triage._t("ar", "merge_done", n=1, c=2) == "دُمج ملفا الفرز: نتيجة واحدة، وحُلّ تعارضان"
    assert triage._t("en", "merge_done", n=1, c=1) == "merged: 1 finding, 1 conflicting edit resolved"
    assert triage._t("en", "expiring", days=1) == "Risk acceptances expiring within 1 day"
    assert triage.TriageError("e_fp_ambiguous", fp="ab", n=2).message("ar") == "'ab' تطابق بصمتين؛ أدخل خانات أكثر"


def test_policy_violation_and_warning_counts():
    v = policy.Violation("severity-threshold", "", {"count": 1, "threshold": "high"})
    assert v.message("ar").startswith("نتيجة واحدة بخطورة عالية") and v.message("en").startswith("1 finding at")
    v = policy.Violation("sla-breach", "", {"count": 3, "severity": "high", "days": 30, "oldest": 2})
    assert "3 نتائج" in v.message("ar") and "(30 يومًا)" in v.message("ar") and "يومان" in v.message("ar")
    assert "3 findings" in v.message("en") and "30 days" in v.message("en") and "2 days" in v.message("en")
    v = policy.Violation("secret", "", {"count": 2})
    assert v.message("ar").startswith("سرّان في الكود") and v.message("en").startswith("2 secrets in the code")
    assert policy._t("ar", "c_valid", path="p", name="n", rules=1, scopes=2, ignores=11) == \
        "p: سياسة صالحة 'n' (شرط بوابة واحد، نطاقان، 11 استثناءً)"
    assert policy._t("en", "c_valid", path="p", name="n", rules=1, scopes=2, ignores=1) == \
        "p: valid policy 'n' (1 gate condition, 2 scopes, 1 ignore)"
    assert policy._t("ar", "w_ignore-expiring", index=1, selector="s", date="d", days=2).endswith("(بعد يومين)")
    assert "(finding(s)" not in policy._t("en", "x_summary", evaluated=1, total=1, ignored=0, disabled=0, triaged=0,
                                          skipped=0)


def test_policy_strings_have_no_bare_plural_markers():
    for key, text in policy.STR["en"].items():
        assert "(s)" not in text, key


def test_mcp_and_surface_and_history_counts():
    assert mcp._t("ar", "n_more", n=2).startswith("لم تُعرض نتيجتان إضافيتان")
    assert mcp._t("en", "n_more", n=1).startswith("1 more finding not shown")
    assert mcp._t("ar", "elided", n=11) == "... حُذفت 11 خطوةً وسيطةً؛ استدعِ get_finding للمسار الكامل ..."
    assert mcp._t("ar", "e_timeout", sec=2) == "لم ينتهِ الفحص خلال ثانيتين فأُوقف."
    assert all("(s)" not in v for v in mcp.STR["en"].values())
    assert surface._t("ar", "r_params", n=1) == "مدخل واحد غير موثوق"
    assert surface._t("ar", "r_params", n=4) == "4 مدخلات غير موثوقة"
    assert surface._t("en", "r_params", n=1) == "1 untrusted parameter"
    assert surface._t("ar", "note_unparsed", n=2, file="x.py").startswith("تعذّر تحليل ملفَّي بايثون")
    assert all("(s)" not in v for v in surface.STR["en"].values())
    assert history._t("ar", "chars", n=40) == "40 حرفًا" and history._t("ar", "chars", n=8) == "8 أحرف"
    assert history._t("en", "n_long", n=1, limit=500) == "not examined (longer than 500 characters): 1 changed line."
    assert history._t("ar", "n_timeout", sec=1).startswith("توقّف الفحص بعد ثانية واحدة")


def test_ruletest_exporters_github_pr_counts():
    assert "(6 ملفات)" in ruletest._t("ar", "verified", name="p", version="1", files=6, sha="x")
    assert "(1 file)" in ruletest._t("en", "verified", name="p", version="1", files=1, sha="x")
    assert ruletest._t("ar", "lint_fail", pack="p", errors=2, warnings=1) == "p: خطآن، تحذير واحد"
    assert ruletest._t("en", "pack_row", name="p", version="1", rules=1, description="d") == "p 1  (1 rule)  d"
    assert exporters._t("ar", "m_score", score=5, rating="r", n=1) == \
        "درجة خطر كاشِف: 5/10 (r) - نتيجة مفتوحة واحدة. ليست درجة CVSS."
    assert exporters._t("en", "m_score", score=5, rating="r", n=1) == \
        "Kashif risk score: 5/10 (r) - 1 open finding. Not a CVSS score."
    assert github_pr._Text("ar")("found", n=2) == "نتيجتان جديدتان في هذا التغيير"
    assert github_pr._Text("en")("found", n=1) == "1 new finding in this change"


def test_every_count_template_formats_in_both_languages():
    """A "{n:noun}" field names a known noun, and both tables of a module render with any count."""
    for table in (triage.STR, policy.STR, mcp.STR, surface.STR, history.STR, ruletest.STR, exporters.STR):
        for lang in ("en", "ar"):
            for key, text in table[lang].items():
                for _, field, spec, _ in string.Formatter().parse(text):
                    if field and re.fullmatch(r"[a-z_]{3,}", spec or ""):    # not a format spec such as 04X
                        assert spec in NOUNS, (lang, key, spec)


# ------------------------------------------------------------------------------- cli.py notes and messages
@pytest.mark.parametrize("n, ar, en", [
    (1, "نتيجة معروفة واحدة", "suppressed 1 known finding "), (2, "نتيجتان معروفتان", "suppressed 2 known findings"),
    (5, "5 نتائج معروفة", "suppressed 5 known findings"), (12, "12 نتيجةً معروفةً", "suppressed 12 known findings"),
    (100, "100 نتيجة معروفة", "suppressed 100 known findings")])
def test_baseline_note_agrees_and_translates(n, ar, en):
    note = f"خط الأساس: كُتمت {ar_count(n, cli._KNOWN_FINDINGS)} من أصل 200؛ تُعرض النتائج الجديدة فقط."
    assert ar in note and en in to_en(note) and not has_arabic(to_en(note))


@pytest.mark.parametrize("n, en", [(1, "1 known vulnerability."), (2, "2 known vulnerabilities."),
                                   (7, "7 known vulnerabilities."), (40, "40 known vulnerabilities."),
                                   (0, "0 known vulnerabilities.")])
def test_osv_note_translates_every_form(n, en):
    note = f"استعلام OSV.dev عن الاعتماديات: {ar_count(n, cli._KNOWN_VULNS)}."
    assert to_en(note) == "OSV.dev dependency check: " + en


def test_notes_of_older_reports_still_translate():
    assert to_en("خط الأساس: كُتمت 1 نتيجة معروفة من أصل 3؛ تُعرض النتائج الجديدة فقط.").startswith(
        "Baseline: suppressed 1 known finding")
    assert to_en("استعلام OSV.dev عن الاعتماديات: 4 ثغرة معروفة.") == "OSV.dev dependency check: 4 known vulnerabilities."


def test_write_baseline_and_list_rules_messages(tmp_path, capsys):
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "app.py").write_text("import os\nos.system(input())\n", encoding="utf-8")
    for lang, want in (("ar", re.compile(r"حُفظ خط الأساس: (بصمة واحدة|بصمتان|\d+ بصمات|\d+ بصمةً|\d+ بصمة) في")),
                       ("en", re.compile(r"Baseline saved: (1 fingerprint|\d+ fingerprints) in"))):
        code, out, _ = _run([str(proj), "--no-deps", "--no-external", "--lang", lang, "--write-baseline",
                             str(tmp_path / f"b-{lang}.json")], capsys)
        assert code == 0 and want.search(out), out
    code, out, _ = _run(["--lang", "ar", "--list-rules"], capsys)
    first = out.splitlines()[0]
    n = int(first.split()[0])
    assert first == ar_count(n, NOUNS["builtin_rules"][0]) + ":"
    code, out, _ = _run(["--lang", "en", "--list-rules"], capsys)
    assert out.splitlines()[0].endswith("built-in rules:") and not ARABIC.search(out)


def test_cat_cli_drops_the_unused_asff_entry():
    from vulnscan.i18n import cat_cli
    assert not any(k.startswith("لصيغة asff استخدم") for k in cat_cli.CATALOG)
    src = pathlib.Path(cli.__file__).read_text(encoding="utf-8")
    assert "لصيغة asff استخدم" not in src


# ---------------------------------------------------------------------- exit 2 with a message, not only usage
@pytest.mark.parametrize("argv, ar, en", [
    (["compliance"], "تقرير الفحص المطلوب ربطه بأطر الامتثال غير محدَّد", "the scan report to map to compliance"),
    (["export"], "تقرير JSON المراد تحويله غير محدَّد", "the JSON report to convert is missing"),
    (["export", "report.json"], "صيغة الإخراج غير محدَّدة", "the output format is missing")])
def test_missing_input_names_what_is_missing(argv, ar, en, capsys):
    code, out, err = _run(argv, capsys)                                     # "both": Arabic line, English line
    assert code == 2 and out == "" and "usage" in err and ar in err and en in err
    code, _, err = _run(argv + ["--lang", "ar"], capsys)
    assert code == 2 and ar in err and en not in err and "الاستخدام" in err
    code, _, err = _run(["--lang", "en"] + argv, capsys)
    assert code == 2 and en in err and not ARABIC.search(err)


def test_compliance_other_commands_are_unchanged(capsys):
    code, out, _ = _run(["compliance", "--list-frameworks", "--lang", "en"], capsys)
    assert code == 0 and "owasp" in out.lower()
    code, _, err = _run(["compliance", "--bogus"], capsys)
    assert code == 2 and err.count("usage") == 1                             # reported once, by the module
    assert exporters.main([]) == 2


# -------------------------------------------------------------------------------- kashif ui startup line
@pytest.mark.parametrize("lang, ar, en", [("both", True, True), ("ar", True, False), ("en", False, True)])
def test_ui_startup_line_follows_the_language(monkeypatch, capsys, tmp_path, lang, ar, en):
    from vulnscan import server

    class FakeServer:
        server_address = ("127.0.0.1", 9)

        def __init__(self, *a, **k):
            pass

        def serve_forever(self):
            raise KeyboardInterrupt

        def server_close(self):
            pass

    monkeypatch.setattr(server, "ThreadingHTTPServer", FakeServer)
    server.serve(9, open_browser=False, home=tmp_path, lang=lang)
    out = capsys.readouterr().out
    assert ("واجهة كاشِف" in out) is ar and ("Kashif UI" in out) is en


# ------------------------------------------------------------------- history, surface, rules, lsp: languages
@pytest.mark.parametrize("cmd", ["history", "secrets-history", "surface", "rules"])
def test_new_sub_commands_take_both(cmd, capsys):
    code, out, _ = _run([cmd, "--help"], capsys)                           # default "both"
    assert code == 0 and "الخيارات / options" in out and "show this help message and exit" in out
    code, out, _ = _run(["--lang", "ar", cmd, "--help"], capsys)
    assert code == 0 and "الخيارات:" in out
    english_help = [ln for ln in out.splitlines()[1:] if ln.strip() and not ARABIC.search(ln)
                    and not ln.strip().startswith(("-", "[", "{", "kashif", "COMMAND", "path", "repo", "KASHIF",
                                                   "VULNSCAN", "2024", "eu-"))]
    assert not [ln for ln in english_help if re.search(r"\b(the|and|of|to|a)\b", ln)], english_help
    code, out, _ = _run(["--lang", "en", cmd, "--help"], capsys)
    assert code == 0 and not ARABIC.search(out)


def test_surface_options_have_help():
    for lang in ("en", "ar", "both"):
        actions = [a for a in surface._parser(lang)._actions if a.dest != "help"]
        assert len(actions) == 12 and all(a.help for a in actions), lang
        assert all(has_arabic(a.help) for a in actions) is (lang != "en")


def test_both_sub_commands_report_in_english(tmp_path, capsys):
    code, _, err = _run(["surface", str(tmp_path / "missing")], capsys)     # "both": English messages
    assert code == 2 and "path not found" in err
    code, _, err = _run(["--lang", "ar", "surface", str(tmp_path / "missing")], capsys)
    assert code == 2 and "المسار غير موجود" in err
    code, out, _ = _run(["rules", "list", "--packs-dir", str(tmp_path)], capsys)
    assert code == 0 and "No rule packs installed" in out


def test_lsp_help_is_translated(capsys):
    code, out, _ = _run(["--lang", "ar", "lsp", "--help"], capsys)
    assert code == 0 and "الاستخدام: kashif lsp" in out and "خادم لغة كاشِف" in out and "transport" not in out
    code, out, _ = _run(["lsp", "--help", "--lang", "en"], capsys)
    assert code == 0 and not ARABIC.search(out) and "Kashif language server" in out
    code, out, _ = _run(["lsp", "--help"], capsys)                          # "both"
    assert code == 0 and "خادم لغة كاشِف" in out and "Kashif language server" in out


# ---------------------------------------------------------------------------- VULNSCAN_LANG and KASHIF_LANG
def test_both_language_variables_are_honoured(monkeypatch):
    assert cli.resolve_lang("auto", {"KASHIF_LANG": "ar"}) == "ar"
    assert cli.resolve_lang("auto", {"VULNSCAN_LANG": "en", "KASHIF_LANG": "ar"}) == "en"
    assert lang_from_env({"VULNSCAN_LANG": "auto", "KASHIF_LANG": "ar_EG.UTF-8"}) == "ar"
    monkeypatch.setenv("VULNSCAN_LANG", "ar")
    assert policy._auto_lang() == "ar"
    monkeypatch.delenv("VULNSCAN_LANG")
    monkeypatch.setenv("KASHIF_LANG", "ar")
    assert policy._auto_lang() == "ar"


@pytest.mark.parametrize("table", [policy._HELP, mcp._HELP, triage._HELP, history.STR, surface._HELP, ruletest._HELP])
def test_help_names_both_language_variables(table):
    key = "h_lang" if table is history.STR else "lang"
    for lang in ("en", "ar"):
        assert "VULNSCAN_LANG" in table[lang][key] and "KASHIF_LANG" in table[lang][key], (lang, key)


def test_main_help_names_both_language_variables():
    for lang in ("en", "ar"):
        text = cli.build_parser(lang).format_help()
        assert "VULNSCAN_LANG" in text and "KASHIF_LANG" in text


def test_mcp_default_language_from_kashif_lang(monkeypatch, capsys):
    monkeypatch.setenv("KASHIF_LANG", "ar")
    assert mcp.main(["--print-config"]) == 0
    assert ARABIC.search(capsys.readouterr().out)


def test_new_help_tables_are_complete():
    for table in (surface._HELP, ruletest._HELP):
        assert set(table["en"]) == set(table["ar"])
        assert all(has_arabic(v) for v in table["ar"].values())
        assert not any(has_arabic(v) for v in table["en"].values())
