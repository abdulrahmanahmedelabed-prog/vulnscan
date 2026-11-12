"""Command-line UX contract for user errors (docs/production.md, "Exit codes"): a scan that cannot run exits 2 with
a one-line message on stderr, never a Python traceback and never 1 (which CI reads as "findings at --fail-on").
Output destinations and --compliance names are checked before the scan starts; a reader that closes the pipe early
("kashif . -f json | head") is not an error."""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

from vulnscan import cli
from vulnscan.cli import main

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _neutral_language(monkeypatch):
    for var in ("VULNSCAN_LANG", "KASHIF_LANG", "LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(cli, "_is_arabic_locale", lambda environ=None: False)


@pytest.fixture
def project(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    return proj


@pytest.fixture
def no_scan(monkeypatch):
    """Fail loudly if the scan starts: the error must be reported before it."""
    def boom(*a, **k):
        raise AssertionError("the scan started before the argument error was reported")
    monkeypatch.setattr(cli, "scan_path", boom)


def _exit_code(argv) -> int:
    try:
        return main(argv)
    except SystemExit as e:
        return e.code


def test_missing_target_exits_2_with_message(tmp_path, capsys):
    missing = tmp_path / "nope"
    assert _exit_code([str(missing), "--lang", "en"]) == 2
    err = capsys.readouterr().err
    assert "Target not found" in err and str(missing) in err
    assert _exit_code([str(missing), "--lang", "ar"]) == 2
    assert "الهدف غير موجود" in capsys.readouterr().err


def test_web_target_without_authorized_exits_2(capsys):
    assert _exit_code(["https://example.invalid/", "--lang", "en"]) == 2
    assert "--authorized" in capsys.readouterr().err


def test_missing_target_exits_2_as_a_process(tmp_path):
    r = subprocess.run([sys.executable, "-m", "vulnscan", str(tmp_path / "nope"), "--lang", "en"], cwd=ROOT,
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 2 and "Target not found" in r.stderr and "Traceback" not in r.stderr


@pytest.mark.parametrize("flag", [["-o", "{d}/x.json", "-f", "json"], ["--audit-report", "{d}/a.html"],
                                  ["--export", "junit={d}/k.xml"], ["--all-formats", "{d}/rep"],
                                  ["--write-baseline", "{d}/b.json"]])
def test_output_into_missing_folder_is_a_usage_error_before_the_scan(project, tmp_path, flag, no_scan, capsys):
    missing = tmp_path / "no" / "such" / "dir"
    args = [a.replace("{d}", str(missing)) for a in flag]
    with pytest.raises(SystemExit) as e:
        main([str(project), "--no-deps", "--no-external", "--lang", "en", *args])
    assert e.value.code == 2
    assert "The folder of the output file does not exist" in capsys.readouterr().err


def test_unwritable_output_exits_2_without_traceback(project, tmp_path, capsys):
    target_is_a_dir = tmp_path / "out"
    target_is_a_dir.mkdir()
    for args in (["-o", str(target_is_a_dir), "-f", "json"], ["--write-baseline", str(target_is_a_dir)]):
        assert main([str(project), "--no-deps", "--no-external", "--lang", "en", *args]) == 2
        err = capsys.readouterr().err
        assert err.startswith("✖ ") and str(target_is_a_dir) in err and "Traceback" not in err


def test_unknown_compliance_framework_is_reported_before_the_scan(project, no_scan, capsys):
    assert main([str(project), "--no-deps", "--no-external", "--lang", "en", "--compliance", "owasp,bogus"]) == 2
    assert "Unknown compliance framework: bogus" in capsys.readouterr().err


def test_known_compliance_frameworks_still_work(project, capsys):
    assert main([str(project), "--no-deps", "--no-external", "--lang", "en", "--compliance", "owasp,pci"]) == 0
    assert "OWASP" in capsys.readouterr().out


def test_closed_pipe_is_not_an_error(project):
    """`kashif . -f json | head -c 1`: the reader is gone before the report is printed."""
    proc = subprocess.Popen([sys.executable, "-m", "vulnscan", str(project), "--no-deps", "--no-external",
                             "-f", "json"], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.stdout.close()                     # the reader left before anything was written
    err = proc.stderr.read().decode("utf-8", "replace")
    assert proc.wait(timeout=120) == 0
    assert "Traceback" not in err and "BrokenPipeError" not in err


def test_export_menu_isolates_latin_first_names_in_arabic():
    """"SonarQube (Generic Issue Import، الإصدار …)" in an RTL page: without an LTR isolate the bidi algorithm moves
    the opening parenthesis after "Generic Issue" and the product name to the middle of the line."""
    js = (ROOT / "vulnscan" / "ui" / "app.js").read_text(encoding="utf-8")
    assert "const ltrName = " in js and "<b>${ltrName(f.name)}</b>" in js


@pytest.mark.parametrize("argv, expected", [
    (["--lang", "ar", "check", "r.json"], ["check", "--lang", "ar", "r.json"]),
    (["--lang=en", "presets"], ["presets", "--lang=en"]),
    (["check", "r.json", "--lang", "ar"], ["check", "--lang", "ar", "r.json"]),
    ([], []),                                     # no command: the module reports it, not "invalid choice: 'ar'"
    (["-h"], ["-h"]),
])
def test_policy_gets_lang_after_its_command(monkeypatch, argv, expected):
    monkeypatch.setenv("VULNSCAN_LANG", "ar")   # the language an Arabic system resolves to
    assert cli._forward_lang(argv, after_command=True) == expected
    assert cli._forward_lang(["init"], after_command=True) == ["init", "--lang", "ar"]


def test_policy_without_command_under_arabic_locale(monkeypatch, capsys):
    monkeypatch.setenv("VULNSCAN_LANG", "ar")
    assert main(["policy"]) == 2
    err = capsys.readouterr().err
    assert "invalid choice" not in err and "required" in err
