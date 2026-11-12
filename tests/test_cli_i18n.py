"""Kashif 1.0.1 command-line language contract.

* `kashif compliance|triage|policy|mcp --help` (and their commands) are Arabic under --lang ar, English under
  --lang en, and both (Arabic line, then English line) under "both", the default when neither --lang,
  VULNSCAN_LANG nor an Arabic locale picks a language, as for `kashif --help` and a scan.
* argparse's own text (usage prefix, headings, -h help, parser errors) follows the same language.
* `kashif --lang en <sub-command>` works like `kashif <sub-command> --lang en`.
* The scan takes --aws-account/--aws-region for -f asff; `kashif export` refuses JSON that is not a report;
  a malformed --baseline is never silently empty.
"""

from __future__ import annotations

import argparse
import json
import pathlib

import pytest

from vulnscan import cli, compliance, exporters, mcp, policy, triage
from vulnscan.cli import main
from vulnscan.i18n import has_arabic
from vulnscan.i18n.cliargs import localized_argparse, pick

AR_HEADINGS = ("الاستخدام:", "الخيارات:", "اعرض هذه المساعدة ثم اخرج")
EN_HEADINGS = ("usage:", "options:", "show this help message and exit")


@pytest.fixture(autouse=True)
def _neutral_language(monkeypatch):
    for var in ("VULNSCAN_LANG", "KASHIF_LANG", "LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(cli, "_is_arabic_locale", lambda environ=None: False)


@pytest.fixture
def project(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text("import os\nos.system(input())\n", encoding="utf-8")
    return proj


def _run(argv, capsys) -> tuple[int, str, str]:
    try:
        code = main(argv)
    except SystemExit as e:
        code = e.code
    out, err = capsys.readouterr()
    return code, out, err


def _help(argv, capsys) -> str:
    code, out, _ = _run(argv + ["--help"], capsys)
    assert code == 0
    return out


# module -> (its English/Arabic help table, kashif arguments that show one help screen)
HELP_SCREENS = [
    (compliance._HELP, ["compliance"]),
    (triage._HELP, ["triage"]),
    (triage._HELP, ["triage", "set"]),
    (triage._HELP, ["triage", "stats"]),
    (triage._HELP, ["triage", "merge"]),
    (policy._HELP, ["policy"]),
    (policy._HELP, ["policy", "check"]),
    (policy._HELP, ["policy", "init"]),
    (mcp._HELP, ["mcp"]),
]


@pytest.mark.parametrize("table, argv", HELP_SCREENS, ids=[" ".join(a) for _, a in HELP_SCREENS])
def test_subcommand_help_in_arabic(table, argv, capsys):
    for args in (argv + ["--lang", "ar"], ["--lang", "ar"] + argv):        # before or after the sub-command
        text = _help(args, capsys)
        assert text.startswith("الاستخدام: kashif "), text[:120]
        for heading in AR_HEADINGS:
            assert heading in text
        for heading in EN_HEADINGS:
            assert heading not in text
        assert not any(en in " ".join(text.split()) for en in table["en"].values() if len(en) > 25)
        shown = [ar for ar in table["ar"].values() if " ".join(ar.split()) in " ".join(text.split())]
        assert shown, text


@pytest.mark.parametrize("table, argv", HELP_SCREENS, ids=[" ".join(a) for _, a in HELP_SCREENS])
def test_subcommand_help_in_english(table, argv, capsys):
    text = _help(["--lang", "en"] + argv, capsys)
    assert text.startswith("usage: kashif ") and not has_arabic(text)


@pytest.mark.parametrize("argv", [["compliance"], ["triage", "stats"], ["policy", "check"], ["mcp"], ["export"]])
def test_subcommand_help_defaults_to_both_languages_like_the_scan(argv, capsys):
    """No --lang, no VULNSCAN_LANG, no Arabic locale: `kashif --help` and a scan are bilingual, and so is this."""
    text = _help(argv, capsys)
    assert text.startswith("usage: kashif ")
    assert "الخيارات / options:" in text and "اعرض هذه المساعدة ثم اخرج\n" in text
    assert "show this help message and exit" in text


def test_main_help_is_bilingual_by_default_and_localized_in_arabic(capsys):
    both = _help([], capsys)
    assert "Folder, file or archive path" in both and "مسار مجلد/ملف/أرشيف" in both
    ar = _help(["--lang", "ar"], capsys)
    assert ar.startswith("الاستخدام: kashif [options] TARGET\n           kashif <sub-command>")
    assert "المعاملات الموضعية:" in ar and "positional arguments" not in ar and "Folder, file" not in ar


def test_forward_lang_keeps_both_for_modules_that_take_it():
    assert cli._forward_lang(["list"], both=True) == ["list", "--lang", "both"]
    assert cli._forward_lang(["list", "--lang", "both"], both=True) == ["list", "--lang", "both"]
    assert cli._forward_lang(["list"]) == ["list"]                          # en|ar modules: English as before
    assert cli._forward_lang([], after_command=True, both=True) == ["--lang", "both"]
    assert cli._forward_lang(["--lang", "ar", "check", "r.json"], after_command=True, both=True) == \
        ["check", "--lang", "ar", "r.json"]


def test_global_lang_before_the_subcommand(tmp_path, capsys):
    code, out, _ = _run(["--lang", "en", "triage", "--root", str(tmp_path), "stats"], capsys)
    assert code == 0 and out.startswith("Triage statistics") and not has_arabic(out)
    code, out, _ = _run(["--lang=ar", "triage", "--root", str(tmp_path), "stats"], capsys)
    assert code == 0 and out.startswith("إحصاءات الفرز")
    # the sub-command's own --lang wins over the one before it
    code, out, _ = _run(["--lang", "ar", "triage", "--root", str(tmp_path), "stats", "--lang", "en"], capsys)
    assert code == 0 and out.startswith("Triage statistics")
    assert cli._hoist_lang(["--lang", "en", "merge-not-a-command"]) == ["--lang", "en", "merge-not-a-command"]
    assert cli._hoist_lang(["--lang", "en", "lsp", "--stdio"]) == ["lsp", "--stdio"]
    assert cli._hoist_lang(["--lang", "en", "triage", "merge", "a", "--", "b"]) == \
        ["triage", "merge", "a", "--lang", "en", "--", "b"]


def test_triage_stats_in_arabic(tmp_path, capsys):
    code, out, _ = _run(["triage", "--root", str(tmp_path), "stats", "--lang", "ar"], capsys)
    assert code == 0
    assert "حرج 0، عالٍ 0، متوسط 0، منخفض 0، معلوماتي 0" in out
    assert "critical" not in out and ", " not in out
    assert "تجاوزات مهلة الإصلاح: 0" in out and "اتفاقية مستوى الخدمة" not in out


def test_parser_errors_are_localized(capsys):
    code, _, err = _run(["--lang", "ar"], capsys)
    assert code == 2 and "خطأ: الهدف مطلوب" in err and "the following arguments" not in err
    code, _, err = _run(["--lang", "en"], capsys)
    assert code == 2 and "error: the following arguments are required: target" in err and not has_arabic(err)
    code, _, err = _run([], capsys)                                         # both: Arabic and English
    assert code == 2 and "الهدف مطلوب" in err and "the following arguments are required: target" in err
    code, _, err = _run(["--lang", "ar", "compliance", "--nope"], capsys)
    assert code == 2 and "معاملات غير معروفة: --nope" in err
    code, _, err = _run(["--lang", "ar", "https://example.invalid/", "--diff-staged", "--authorized"], capsys)
    assert code == 2 and "مستودع git" in err and "need a local path" not in err


def test_localized_argparse_restores_english():
    before = argparse._
    with localized_argparse("ar"):
        assert argparse.ArgumentParser(prog="x").format_help().startswith("الاستخدام: x")
    assert argparse._ is before
    assert argparse.ArgumentParser(prog="x").format_help().startswith("usage: x")
    assert pick("both", "عربي", "English") == "عربي\nEnglish" and pick("en", "عربي", "English") == "English"


# ------------------------------------------------------------------------------------------- asff from a scan

def test_scan_writes_asff_with_the_aws_options(project, capsys):
    code, out, _ = _run([str(project), "--no-deps", "--no-external", "-f", "asff", "--aws-account", "123456789012",
                         "--aws-region", "eu-west-1"], capsys)
    assert code == 0
    doc = json.loads(out)
    assert doc and all(f["AwsAccountId"] == "123456789012" for f in doc)


def test_scan_asff_without_account_is_a_bilingual_usage_error_before_the_scan(project, monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan_path", lambda *a, **k: pytest.fail("the scan started"))
    code, _, err = _run([str(project), "-f", "asff", "--aws-region", "eu-west-1"], capsys)
    assert code == 2
    assert "تحتاج صيغة asff" in err and "the asff format needs a 12-digit AWS account ID" in err
    code, _, err = _run([str(project), "--export", "asff=x.json", "--lang", "en"], capsys)
    assert code == 2 and "--aws-account" in err and not has_arabic(err)


# ------------------------------------------------------------------------------------------- bad inputs

@pytest.mark.parametrize("content", ["[]", "{}", '{"findings": [1, 2]}', '[{"title": "x"}]', '{"runs": []}'])
def test_export_refuses_json_that_is_not_a_report(tmp_path, content, capsys):
    path = tmp_path / "r.json"
    path.write_text(content, encoding="utf-8")
    code, out, err = _run(["export", str(path), "-f", "csv"], capsys)
    assert code == 2 and out == ""
    assert "ليس تقرير JSON من كاشِف" in err and "is not a Kashif JSON report" in err


def test_export_still_takes_reports_and_finding_lists(project, tmp_path, capsys):
    report = tmp_path / "r.json"
    assert _run([str(project), "--no-deps", "--no-external", "-f", "json", "-o", str(report)], capsys)[0] == 0
    assert _run(["export", str(report), "-f", "csv"], capsys)[0] == 0
    findings = json.loads(report.read_text(encoding="utf-8"))["findings"]
    listing = tmp_path / "list.json"
    listing.write_text(json.dumps(findings), encoding="utf-8")
    assert _run(["export", str(listing), "-f", "csv"], capsys)[0] == 0
    clean = tmp_path / "clean.json"
    clean.write_text(json.dumps({"target": "x", "findings": []}), encoding="utf-8")
    assert _run(["export", str(clean), "-f", "junit"], capsys)[0] == 0


def test_export_asff_error_is_bilingual(tmp_path, capsys):
    clean = tmp_path / "clean.json"
    clean.write_text(json.dumps({"findings": []}), encoding="utf-8")
    code, _, err = _run(["export", str(clean), "-f", "asff"], capsys)
    assert code == 2 and "تحتاج صيغة asff" in err and "the asff format needs --aws-account" in err
    assert exporters.main([str(clean), "-f", "asff", "--lang", "en"]) == 2


def test_unreadable_baseline_exits_2_before_the_scan(project, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan_path", lambda *a, **k: pytest.fail("the scan started"))
    bad = tmp_path / "baseline.json"
    bad.write_text("{not json", encoding="utf-8")
    code, _, err = _run([str(project), "--baseline", str(bad)], capsys)
    assert code == 2
    assert "تعذّرت قراءة ملف خط الأساس" in err and "Cannot read the baseline file (not valid JSON)" in err


def test_baseline_of_the_wrong_shape_warns_and_keeps_the_exit_code(project, tmp_path, capsys):
    wrong = tmp_path / "baseline.json"
    wrong.write_text('{"findings": []}', encoding="utf-8")
    code, _, err = _run([str(project), "--no-deps", "--no-external", "--baseline", str(wrong)], capsys)
    assert code == 0
    assert "⚠" in err and "ملف خط الأساس ليس من إنتاج --write-baseline" in err
    assert "was not written by --write-baseline" in err
    code, _, err = _run([str(project), "--no-deps", "--no-external", "--baseline", str(wrong), "--fail-on", "high",
                         "--lang", "en"], capsys)
    assert code == 1 and "was not written by --write-baseline" in err and not has_arabic(err)


def test_missing_or_valid_baseline_gives_no_warning(project, tmp_path, capsys):
    base = tmp_path / "b.json"
    assert _run([str(project), "--no-deps", "--no-external", "--write-baseline", str(base)], capsys)[0] == 0
    raw = base.read_bytes()
    base.write_bytes(b"\xef\xbb\xbf" + raw)                  # saved by a Windows editor: a BOM is still a baseline
    code, out, err = _run([str(project), "--no-deps", "--no-external", "--baseline", str(base), "--fail-on", "low",
                           "--lang", "en"], capsys)
    assert code == 0 and "⚠" not in err and "suppressed" in out
    code, _, err = _run([str(project), "--no-deps", "--no-external", "--baseline", str(tmp_path / "none.json")],
                        capsys)
    assert code == 0 and "⚠" not in err and "✖" not in err


def test_cli_messages_have_english():
    """Every Arabic text added for 1.0.1 to cli.py has its English in vulnscan/i18n (or both tables in a module)."""
    from vulnscan.i18n import translated
    for text in ("الهدف مطلوب: مسار مجلد أو ملف أو أرشيف، أو عنوان http(s)://",
                 "الخياران --diff-base و--diff-staged يحتاجان مسارًا محليًا داخل مستودع git",
                 "لصيغة asff: رقم حساب AWS (12 رقمًا)، مع --aws-region",
                 "لصيغة asff: منطقة AWS لـ Security Hub، مثل eu-west-1",
                 "منفذ الواجهة المحلية (الافتراضي 8765)"):
        assert translated(text), text
    for table in (compliance._HELP, triage._HELP, policy._HELP, mcp._HELP):
        assert set(table["en"]) == set(table["ar"])
        assert all(has_arabic(v) for v in table["ar"].values())
        assert not any(has_arabic(v) for v in table["en"].values())
    assert pathlib.Path(cli.__file__).name == "cli.py"
