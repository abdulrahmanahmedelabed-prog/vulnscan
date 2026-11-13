"""Kashif 1.0.2: fixes from the adversarial review of the Arabic/English user experience.

* `kashif --help` in Arabic names the SARIF file that --all-formats writes, as the English help does.
* `kashif update --help` is bilingual under "both" (the default outside an Arabic locale) like every other
  sub-command, and its messages are English under "both" instead of Arabic only.
* The web UI's scan notes (OSV.dev count, crawled pages) agree with their number in Arabic, like the CLI's notes.
* `kashif export` names a missing or broken report in the message's own language, not Python's English error.
* One term for "code" across the product: الكود (models, dependency notes, rule-pack docs), with the 1.0.1 wording
  still translated for older reports.
* `kashif surface` separates Arabic lists with the Arabic comma.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

from vulnscan import cli, deps, exporters, server, surface, updater
from vulnscan.i18n import to_en
from vulnscan.model import Finding
from vulnscan.store import Store

ROOT = pathlib.Path(__file__).resolve().parents[1]
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


# ------------------------------------------------------------------------------------------- --all-formats

def test_all_formats_help_names_the_same_files_in_both_languages(capsys):
    _, ar, _ = _run(["--lang", "ar", "--help"], capsys)
    _, en, _ = _run(["--lang", "en", "--help"], capsys)
    ar_files = set(re.findall(r"PREFIX\.\w+", ar))
    en_files = set(re.findall(r"PREFIX\.\w+", en))
    assert ar_files == en_files == {"PREFIX.md", "PREFIX.json", "PREFIX.html", "PREFIX.sarif"}
    assert "PREFIX.md وPREFIX.json وPREFIX.html وPREFIX.sarif" in ar      # the conjunction joins the next word


# ----------------------------------------------------------------------------------------------- update

def test_update_help_is_bilingual_under_both(capsys):
    code, out, _ = _run(["update", "--help"], capsys)
    assert code == 0
    for ar in (updater.CLI_TEXT["desc"], updater.CLI_TEXT["yes"]):
        assert ar in out and to_en(ar) in out
    assert "اعرض هذه المساعدة ثم اخرج\n" in out                       # argparse's own line: Arabic, then English
    code, out, _ = _run(["--lang", "en", "update", "--help"], capsys)
    assert code == 0 and not ARABIC.search(out)
    code, out, _ = _run(["--lang", "ar", "update", "--help"], capsys)
    assert code == 0 and updater.CLI_TEXT["desc"] in out and "Check for a newer" not in out


@pytest.mark.parametrize("argv,arabic", [([], False), (["--lang", "en"], False), (["--lang", "ar"], True)])
def test_update_messages_follow_the_language(monkeypatch, capsys, argv, arabic):
    monkeypatch.setattr(updater, "cleanup_stale", lambda: None)
    monkeypatch.setattr(updater, "check", lambda force=False: {"current": "1.0.2", "latest": "1.0.2", "newer": False})
    assert updater.cli_main(argv + ["--check"]) == 0
    out = capsys.readouterr().out
    assert bool(ARABIC.search(out)) is arabic, out
    assert ("أنت تستخدم أحدث إصدار." if arabic else to_en(updater.MESSAGES["up_to_date"])) in out


# ------------------------------------------------------------------------------------------ UI scan notes

def _scan_with_deps(tmp_path, monkeypatch, n):
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "a.py").write_text("x = 1\n", encoding="utf-8")
    dep = [Finding("SCA001", "high", "t", "ع", "requirements.txt", 1, "", "") for _ in range(n)]
    monkeypatch.setattr(server, "audit_dependencies", lambda path: (dep, None))
    store = Store(tmp_path / "home")
    scan = store.new_scan(str(tmp_path / "proj"), "path")
    server.run_scan(store, scan, {"use_osv": True, "use_external": False, "use_jadx": False}, False)
    return store.get_scan(scan["id"])


@pytest.mark.parametrize("n,ar,en", [
    (0, "0 ثغرة معروفة", "0 known vulnerabilities"),
    (1, "ثغرة معروفة واحدة", "1 known vulnerability"),
    (2, "ثغرتان معروفتان", "2 known vulnerabilities"),
    (3, "3 ثغرات معروفة", "3 known vulnerabilities"),
    (11, "11 ثغرةً معروفةً", "11 known vulnerabilities"),
])
def test_ui_osv_note_agrees_with_its_number(tmp_path, monkeypatch, n, ar, en):
    scan = _scan_with_deps(tmp_path, monkeypatch, n)
    assert scan["status"] == "done", scan.get("error")
    note = next(x for x in scan["notes"] if "OSV.dev" in x)
    assert note == f"استعلام OSV.dev عن الاعتماديات: {ar}."                 # the CLI's own note
    note_en = next(x for x in scan["notes_en"] if "OSV.dev" in x)
    assert note_en == f"OSV.dev dependency check: {en}."


def test_notes_of_scans_saved_by_101_still_translate():
    assert to_en("OSV.dev: 5 ثغرة معروفة في الاعتماديات.") == "OSV.dev: 5 known vulnerabilities in dependencies."
    assert to_en("فحص ويب سلبي مع زحف على 7 صفحة من النطاق نفسه (طلب كل 0.5 ثانية).").startswith(
        "Passive web scan")


@pytest.mark.parametrize("n,ar,en", [
    (1, "صفحة واحدة", "1 page"), (2, "صفحتين", "2 pages"), (3, "3 صفحات", "3 pages"),
    (20, "20 صفحةً", "20 pages"), (100, "100 صفحة", "100 pages"),
])
def test_ui_crawl_note_agrees_with_its_number(n, ar, en):
    from vulnscan.i18n.plural import ar_count
    note = f"فحص ويب سلبي مع زحف على {ar_count(n, server._PAGES_OBL)} من النطاق نفسه (طلب كل 0.5 ثانية)."
    assert f"على {ar} من" in note
    assert to_en(note) == f"Passive web scan with a same-origin crawl of {en} (one request every 0.5 s)."
    src = (ROOT / "vulnscan" / "server.py").read_text(encoding="utf-8")
    assert "{files} صفحة" not in src and "{len(dep)} ثغرة" not in src


# ------------------------------------------------------------------------------------------------ export

@pytest.mark.parametrize("lang", ["ar", "en", "both"])
def test_export_read_errors_are_worded_in_the_message_language(tmp_path, capsys, lang):
    bad = tmp_path / "bad.json"
    bad.write_text('{"a":', encoding="utf-8")
    latin1 = tmp_path / "latin1.json"
    latin1.write_bytes(b'{"t": "\xe9"}')
    cases = [(tmp_path / "missing.json", "الملف غير موجود", "the file does not exist"),
             (bad, "ليس JSON صالحًا (السطر 1، العمود 6)", "not valid JSON (line 1, column 6)"),
             (latin1, "ليس نصًا بترميز UTF-8", "not UTF-8 text")]
    for path, ar, en in cases:
        code = exporters.main([str(path), "-f", "csv", "--lang", lang]) if lang != "both" else \
            cli.main(["export", str(path), "-f", "csv"])
        err = capsys.readouterr().err
        assert code == 2
        assert "Errno" not in err and "Expecting" not in err and "codec" not in err, err
        if lang in ("ar", "both"):
            assert ar in err
        if lang in ("en", "both"):
            assert en in err
        if lang == "en":
            assert not ARABIC.search(err)


def test_export_error_strings_exist_in_both_languages():
    for key in ("r_missing", "r_denied", "r_json", "r_utf8"):
        assert exporters._t("en", key, line=1, col=2) and ARABIC.search(exporters._t("ar", key, line=1, col=2))


# ------------------------------------------------------------------------------------------ terminology

def test_one_term_for_code_in_engine_and_model_text():
    files = sorted((ROOT / "vulnscan" / "models").glob("*.json")) + [
        ROOT / "vulnscan" / "deps.py", ROOT / "vulnscan" / "ruletest.py"]
    for f in files:
        assert not re.search(r"شيفرة|شيفرات", f.read_text(encoding="utf-8")), f.name


def test_model_text_with_the_new_term_still_translates():
    seen = 0
    for f in sorted((ROOT / "vulnscan" / "models").glob("*.json")):
        def walk(node):
            nonlocal seen
            if isinstance(node, dict):
                for k, v in node.items():
                    if k == "advice" and isinstance(v, str) and "كود" in v:
                        seen += 1
                        assert not ARABIC.search(to_en(v)), (f.name, v)
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)
        walk(json.loads(f.read_text(encoding="utf-8")))
    assert seen >= 10


@pytest.mark.parametrize("new,old", [
    (deps.NOTE_NOT_IMPORTED, "لم يُعثر على استيراد لهذه الحزمة في الشيفرة المفحوصة؛ خُفِّضت الخطورة درجة واحدة."),
    (deps.NOTE_IMPORTED, "الحزمة مستوردة في الشيفرة المفحوصة."),
    (deps.NOTE_UNKNOWN, "تعذّر تحديد ما إذا كانت الشيفرة تستخدم هذه الحزمة."),
    ("الكود يستدعي دوال مصابة في هذه الحزمة: a.b, c.", "الشيفرة تستدعي دوال مصابة في هذه الحزمة: a.b, c."),
])
def test_dependency_notes_translate_in_new_and_101_wording(new, old):
    assert "الكود" in new
    assert to_en(new) == to_en(old) and not ARABIC.search(to_en(new))


# ------------------------------------------------------------------------------------------------ surface

def test_surface_summary_uses_the_arabic_comma():
    s = surface.build_surface(ROOT / "tests" / "data" / "surface" / "flask", engine=False)
    ar = surface.render_markdown(s, "ar")
    en = surface.render_markdown(s, "en")
    line_ar = next(x for x in ar.splitlines() if x.startswith("- نقاط الدخول"))
    line_en = next(x for x in en.splitlines() if x.startswith("- Entry points"))
    assert "، أوامر سطر الأوامر" in line_ar and ", " not in line_ar
    assert ", CLI commands" in line_en and "،" not in en


# ------------------------------------------------------------------------------ dependency check notes

_WHY = "URLError: Tunnel connection failed: 403 Forbidden"


@pytest.mark.parametrize("n,ar,en", [
    (1, "لفحص اعتمادية واحدة", "check 1 dependency"), (2, "لفحص اعتماديتين", "check 2 dependencies"),
    (3, "لفحص 3 اعتماديات", "check 3 dependencies"), (44, "لفحص 44 اعتماديةً", "check 44 dependencies"),
    (100, "لفحص 100 اعتمادية", "check 100 dependencies"),
])
def test_offline_dependency_note_agrees_with_its_number(n, ar, en):
    from vulnscan.i18n.plural import ar_count
    note = (f"تعذّر الاتصال بـ OSV.dev لفحص {ar_count(n, deps._DEPS_GEN)} ({_WHY}). لم تُفحص ثغرات الاعتماديات؛ "
            "أعد المحاولة عند توفّر الإنترنت، أو استخدم --no-deps لتعطيل هذا الفحص.")
    assert ar in note
    assert f"Could not reach OSV.dev to check {en[6:]} ({_WHY})." in to_en(note)
    assert not ARABIC.search(to_en(note))


def test_partial_and_lacking_dependency_notes_agree_and_translate():
    from vulnscan.i18n.plural import ar_count
    part = (f"تعذّر الاتصال بـ OSV.dev (x): فُحصت {ar_count(2, deps._DEPS_NOM)} من النتائج المخزَّنة مؤقتًا "
            f"({ar_count(1, deps._KNOWN_VULNS_NOM)}) وبقيت {ar_count(11, deps._DEPS_NOM)} بلا فحص.")
    assert "فُحصت اعتماديتان" in part and "(ثغرة معروفة واحدة)" in part and "وبقيت 11 اعتماديةً" in part
    assert to_en(part) == ("Could not reach OSV.dev (x): 2 dependencies checked from cached results "
                           "(1 known vulnerability) and 11 dependencies left unchecked.")
    lack = (f"تعذّر جلب تفاصيل {ar_count(2, deps._VULNS_GEN)} من OSV.dev؛ أُبلغ عنها بخطورة متوسطة ودون الإصدار "
            "المُصحَّح. أعد الفحص لاحقًا للحصول على التفاصيل.")
    assert "تفاصيل ثغرتين" in lack and to_en(lack).startswith("Could not fetch the details of 2 vulnerabilities")
    # the 1.0.1 wording of saved reports still translates
    old = ("تعذّر الاتصال بـ OSV.dev لفحص 44 اعتمادية (x). لم تُفحص ثغرات الاعتماديات؛ أعد المحاولة عند توفّر "
           "الإنترنت، أو استخدم --no-deps لتعطيل هذا الفحص.")
    assert to_en(old).startswith("Could not reach OSV.dev to check 44 dependencies (x).")
    src = (ROOT / "vulnscan" / "deps.py").read_text(encoding="utf-8")
    assert not re.search(r"\{(?!n\})[^{}]+\} (?:اعتمادية|ثغرة)", src)        # no bare "{count} noun" left
