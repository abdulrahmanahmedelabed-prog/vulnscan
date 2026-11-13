"""Rule-authoring kit: write, test, lint, package and share your own detections.

INTEGRATION NOTES (for the step that wires this module into the product)
=======================================================================
CLI (cli.py) - add a ``rules`` sub-command group that forwards to ``ruletest.main``::

    kashif rules new DIR [--name N] [--language python|javascript|java|php|go] [--force]
    kashif rules test [PACK] [--fixtures DIR] [--scope pack|all] [--no-builtin-queries]
                      [--junit FILE] [--json] [-q]
    kashif rules lint PACK [--allow-monolingual] [--json]
    kashif rules pack PACK [-o FILE] [--no-lint] [--sha256-file]
    kashif rules verify FILE [--sha256 HEX]
    kashif rules install FILE [--packs-dir DIR] [--sha256 HEX] [--require-sha256] [--force]
    kashif rules list [--packs-dir DIR]
    kashif rules docs [--lang en|ar]            # prints the rule language reference (Markdown)

  The simplest wiring is ``if argv[:1] == ["rules"]: return ruletest.main(argv[1:])``. Every sub-command takes
  ``--lang en|ar``. Exit codes: 0 = ok, 1 = failing tests / lint errors, 2 = usage, I/O or pack errors.

  Scan command: add ``--pack NAME`` (repeatable) and ``--packs`` (all installed packs) that extend the existing
  ``--models`` / ``--query`` lists::

      models_dirs, query_paths = ruletest.scan_args(names=args.pack or None)
      scan_path(target, models_dirs=(args.models or []) + models_dirs, query_paths=(args.query or []) + query_paths)

  Call ``ruletest.register_pack_translations(pack_dir)`` for each pack used in a scan so that the English
  ``advice_en`` a pack ships is what ``Finding.to_dict()["advice_en"]`` returns (it registers the pair in the
  in-memory i18n catalogue; nothing is written to disk).

UI (server.py / ui/) - suggested hooks:
  * Settings page: a "Rule packs" card listing ``installed_packs()`` (name, version, description, rule count,
    SHA-256) with "Install .kashifpack" (upload -> ``install_pack``) and "Remove" (``remove_pack``).
  * ``GET /api/packs`` -> ``installed_packs()``; ``POST /api/packs/install`` -> ``install_pack``;
    ``POST /api/packs/test`` -> ``run_tests(pack_dir).to_dict()``; ``POST /api/packs/lint`` -> ``lint_pack(...).to_dict()``.
  * Scans started from the UI should add ``scan_args()`` to the ``models_dir`` / ``queries_dir`` settings.
  * A "Rule language" help page rendering ``rules_reference(lang)``.

vulnscan.spec: add ``"vulnscan.ruletest"`` to ``hiddenimports`` (the module is imported lazily by the CLI).

Docs: write ``docs/rules-authoring.md`` from ``rules_reference("en")`` and ``docs/rules-authoring.ar.md`` from
``rules_reference("ar")`` (a test can assert the files are in sync with the function).

README text suggestion:
  "**Write your own rules - and test them.** ``kashif rules new my-pack`` scaffolds a rule pack (a taint model, a
  VQL query, vulnerable and safe fixtures). Annotate fixture lines with ``# kashif: expect MY001`` /
  ``# kashif: expect-none``, run ``kashif rules test my-pack`` and get a per-line diff, an exit code for CI and
  JUnit XML. ``kashif rules lint`` validates the pack, ``kashif rules pack`` bundles it into one ``.kashifpack``
  file with a SHA-256, and ``kashif rules install`` unpacks it safely on a colleague's machine. No account, no
  registry, no network."

Home directory: packs install into ``$KASHIF_HOME/packs``, else ``$VULNSCAN_HOME/packs``, else ``~/.vulnscan/packs``
(the same home the scan store uses today; adjust ``default_packs_dir`` if the home directory is renamed).

Security model (state it in the README; do not promise more):
  * ``install`` / ``verify`` treat the archive as hostile: allow-listed paths only (no ``..``, absolute or drive
    paths, backslashes, hidden names, Windows device names or ``: < > " | ? *``), no symlink, encrypted or
    duplicate entry (case-insensitively), no file/directory collision, size caps enforced on decompressed bytes,
    every hash checked, queries capped at 256 KB, and ``--force`` only replaces a directory that carries this
    module's install record. Output printed by ``main`` has control characters and bidi overrides replaced.
  * A SHA-256 proves integrity, not authorship: there is no signature scheme here. Without ``--sha256``, ``install``
    and ``verify`` check only the archive's own ``MANIFEST.json`` (integrity, not origin) and say so on stderr, with
    the archive's SHA-256 to compare against the publisher's. ``install --require-sha256`` (or the environment
    variable ``KASHIF_REQUIRE_PACK_SHA256=1``) refuses an install without ``--sha256``.
  * An installed pack is data, but it is still *detection logic you chose to trust*: its ``receiver`` and VQL
    ``matches`` regular expressions run against scanned code, so a malicious pack can slow a scan down
    (catastrophic backtracking), hide findings (a sanitizer declared in a user model is trusted for every sink)
    or add noise. Review a third-party pack before using it in a gate. The UI upload endpoint should additionally
    reject request bodies over ``MAX_ARCHIVE_BYTES`` before writing them to disk.
  * The archive is deterministic (fixed timestamps, modes, order, creator byte); byte-for-byte identity across
    machines also needs the same zlib and the same file bytes (mind git's CRLF conversion on Windows). The
    ``digest`` field of ``MANIFEST.json`` is independent of compression.

Design rules of this module: standard library only, never executes scanned or packed code, no network, and it
only reads the engine (``scan_path``, ``vql.Query``); it edits no shared catalogue on disk.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import sys
import tempfile
import time
import zipfile
from dataclasses import asdict, dataclass, field
from xml.etree import ElementTree as ET

from . import __version__
from .model import SEVERITIES

__all__ = [
    "Expectation", "Outcome", "FileResult", "TestReport", "Issue", "LintReport", "PackLayout", "PackError",
    "PackResult", "InstallResult", "parse_annotations", "locate", "run_tests", "lint_pack", "new_pack",
    "build_pack", "verify_pack", "install_pack", "remove_pack", "installed_packs", "scan_args",
    "default_packs_dir", "register_pack_translations", "rules_reference", "main",
]

MANIFEST_NAME = "kashifpack.json"       # the author's pack description, at the pack root
ARCHIVE_MANIFEST = "MANIFEST.json"      # generated inside a .kashifpack: file list + hashes
PACK_EXT = ".kashifpack"
PACK_FORMAT = "kashifpack/1"
INSTALL_RECORD = ".installed.json"

# caps applied when building and when installing an archive (an archive is untrusted input)
MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_ENTRIES = 2000
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BYTES = 50 * 1024 * 1024
MAX_PATH_CHARS = 240
MAX_PATH_DEPTH = 8
MAX_FIXTURE_BYTES = 2 * 1024 * 1024
MAX_QUERY_BYTES = 256 * 1024             # a VQL query is a few lines; the parser is not built for megabytes

LANGUAGES = ("python", "javascript", "java", "kotlin", "csharp", "go", "php", "cpp", "rust", "swift", "ruby", "plsql")
MODEL_KEYS = ("languages", "sources", "entry_points", "sinks", "attr_sinks", "store_sinks", "sanitizers",
              "safe_return_calls", "validators")
SOURCE_KINDS = {"attr": "attrs", "call": "names", "name": "names", "prefix": "prefixes"}
_NAME_RX = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
_META_RX = re.compile(r"^[ \t]*(?://|#)[ \t]*@(\w+)[ \t]+(.*)$", re.M)     # no \s: it would cross lines (quadratic)
_SHA256_RX = re.compile(r"^[0-9a-fA-F]{64}$")
_CONTROL_RX = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")
_VERSION_RX = re.compile(r"^\d+\.\d+(\.\d+)?([-+.][0-9A-Za-z.-]+)?$")
_CWE_RX = re.compile(r"^CWE-\d+$")
_ARABIC_RX = re.compile("[\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF]")
_WIN_RESERVED = {"con", "prn", "aux", "nul", "conin$", "conout$"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}


# ====================================================================================================== strings
STR = {
    "en": {
        "pass": "PASS", "fail": "FAIL", "error": "ERROR", "warning": "warning",
        "missing": "line {line}: expected {rule} - not reported",
        "unexpected": "line {line}: unexpected {rule}{cwe} - {title}",
        "unexpected_none": "line {line}: expect-none, but {rule}{cwe} was reported - {title}",
        "nearby": "reported nearby instead: {where}",
        "todo": "line {line}: known gap {rule} (expect-todo) - still not reported",
        "todo_fixed": "line {line}: {rule} is now reported - change expect-todo to expect",
        "expectations": "{n:expectations}",
        "summary": "{files:fixture_files}, {exp:expectations}: {ok} matched, {missing} missing, {unexpected} unexpected"
                   "{todo}",
        "summary_todo": ", {n:known_gaps}",
        "result_ok": "OK - all expectations met", "result_fail": "FAILED", "result_error": "ERROR - the tests could not run",
        "no_fixtures": "fixtures directory not found: {path}",
        "no_fixture_files": "no fixture files in {path}",
        "no_expectations": "no 'kashif: expect' annotation found in the fixtures - nothing is being asserted",
        "no_rules_dir": "rule pack directory not found: {path}",
        "bad_model": "{file}: not valid JSON ({msg}); the engine would silently skip this file",
        "bad_query": "{file}: {msg}",
        "annot_no_ids": "{file}:{line}: 'kashif: expect' needs at least one rule id or CWE",
        "annot_no_target": "{file}:{line}: annotation is not followed by a line of code",
        "scan_note": "note: {note}",
        "lint_ok": "{pack}: lint passed ({warnings:warnings})",
        "lint_fail": "{pack}: {errors:errors}, {warnings:warnings}",
        "created": "Created rule pack {name} in {path}",
        "next_steps": "Next: edit models/ and queries/, then run:\n  kashif rules test {path}\n"
                      "  kashif rules lint {path}\n  kashif rules pack {path}",
        "packed": "Packed {name} {version}: {path}\n  files: {files}   size: {size} bytes\n  SHA-256: {sha}",
        "verified": "{name} {version}: archive is well-formed ({files:files})\n  SHA-256: {sha}",
        "installed": "Installed {name} {version} into {path}\n  SHA-256: {sha}\n"
                     "Use it in a scan with:  --models {models} --query {queries}",
        "no_packs": "No rule packs installed in {path}",
        "pack_row": "{name} {version}  ({rules:rules})  {description}",
        "e_exists": "{path} already exists (use force / --force to replace it)",
        "e_not_empty": "{path} exists and is not empty (use force / --force)",
        "e_pack_name": "invalid pack name {name!r}: use lowercase letters, digits, '.', '_' and '-' (max 64 characters)",
        "e_language": "no scaffold template for language {language!r}; available: {available}",
        "e_lint_blocks": "the pack has lint errors; fix them or pass lint=False / --no-lint:\n{details}",
        "e_no_archive": "archive not found: {path}",
        "e_archive_size": "archive is larger than the {cap}-byte limit",
        "e_not_zip": "not a .kashifpack archive (not a readable zip file): {msg}",
        "e_entries": "archive has more than {cap} entries",
        "e_unsafe_path": "unsafe path in archive: {name!r} ({why})",
        "e_file_size": "{name}: larger than the {cap}-byte per-file limit",
        "e_total_size": "archive expands to more than {cap} bytes",
        "e_no_manifest": "archive has no MANIFEST.json - it was not created by 'pack'",
        "e_manifest": "MANIFEST.json is invalid: {msg}",
        "e_manifest_mismatch": "{name}: {why}",
        "e_sha": "SHA-256 mismatch: expected {expected}, the archive is {actual}",
        "e_requires": "this pack requires Kashif >= {need}; this is {have}",
        "e_install_lint": "the pack failed validation and was not installed:\n{details}",
        "e_not_installed": "no installed pack named {name!r} in {path}",
        "removed": "Removed {name} from {path}",
        "e_too_big": "{name}: larger than the {cap}-byte per-file limit; not packed",
        # ---- lint messages
        "l_no_manifest": "kashifpack.json is missing (run 'new' to see the expected layout)",
        "l_json": "invalid JSON at line {line}, column {col}: {msg}",
        "l_not_object": "expected a JSON object at the top level, found {got}",
        "l_required": "'{key}' is required",
        "l_type": "expected {want}, found {got}",
        "l_unknown_key": "unknown key '{key}' (ignored by the engine); known keys: {known}",
        "l_name": "must be 1-64 characters of a-z, 0-9, '.', '_', '-', start and end with a letter or digit, and not be a "
                  "reserved Windows device name",
        "l_version": "must look like MAJOR.MINOR.PATCH, e.g. 1.0.0",
        "l_severity": "must be one of {allowed}",
        "l_cwe": "must look like CWE-89",
        "l_regex": "invalid regular expression: {msg}",
        "l_language": "unknown language '{value}'; known: {allowed}",
        "l_kind": "must be one of attr, call, name, prefix",
        "l_arg": "must be a non-negative integer or the string \"self\"",
        "l_bilingual": "needs both an English and an Arabic text: {fields}",
        "l_inconsistent": "rule {rule} is declared with a different {what} elsewhere ({a} vs {b})",
        "l_empty_model": "the file declares no sources, sinks, sanitizers or entry points",
        "l_vql_parse": "the query does not parse: {msg}",
        "l_vql_size": "the query file is larger than the {cap}-byte limit",
        "e_bad_sha": "--sha256 must be 64 hexadecimal characters",
        "w_origin": "origin not verified: without --sha256 only the archive's own MANIFEST.json was checked, which proves "
                    "the files are intact, not who published them.\n  This file's SHA-256 is {sha}\n  Compare it with the "
                    "value the pack's publisher gives you, and pass --sha256 {sha} to check it automatically.",
        "e_sha_required": "--sha256 is required (--require-sha256 / KASHIF_REQUIRE_PACK_SHA256): nothing was installed.\n"
                          "  This file's SHA-256 is {sha}; install it only if it matches the value its publisher gives you:\n"
                          "  kashif rules install FILE --sha256 <the publisher's value>",
        "e_not_a_pack": "{path} exists but is not an installed pack (no install record); it is not replaced",
        "e_write": "the pack could not be written: {msg}",
        "l_vql_run": "the query fails when evaluated: {msg}",
        "l_vql_meta": "metadata line '// @{tag} ...' is required",
        "l_dup_id": "id {id} is already used by {other}",
        "l_builtin_query": "id {id} is the id of a built-in rule; choose your own prefix",
        "l_builtin_model": "rule {id} is a built-in rule: these entries extend it (new sinks reported under the built-in id)",
        "l_nothing": "the pack contains no model (models/*.json) and no query (queries/*.vql)",
        "l_root_files": "{file} is at the pack root: 'pack' only ships models/*.json and queries/*.vql",
        "l_no_fixtures": "no fixtures: add annotated examples under fixtures/ so the rules are tested",
        "l_untested": "rule {id} has no 'kashif: expect {id}' in any fixture",
        "l_unknown_expect": "annotation names {id}, which neither this pack nor the built-in rules define (typo?)",
        "l_empty_list": "must not be empty",
    },
    "ar": {
        "pass": "نجح", "fail": "فشل", "error": "خطأ", "warning": "تحذير",
        "missing": "السطر {line}: المتوقَّع {rule} — لم يُبلَّغ عنه",
        "unexpected": "السطر {line}: نتيجة غير متوقعة {rule}{cwe} — {title}",
        "unexpected_none": "السطر {line}: expect-none لكن أُبلغ عن {rule}{cwe} — {title}",
        "nearby": "أُبلغ عنه في سطر مجاور: {where}",
        "todo": "السطر {line}: فجوة معروفة {rule} (expect-todo) — ما زالت غير مكتشفة",
        "todo_fixed": "السطر {line}: {rule} يُكتشف الآن — حوّل expect-todo إلى expect",
        "expectations": "{n:expectations}",
        "summary": "{files:fixture_files}، {exp:expectations}: مطابق {ok}، مفقود {missing}، غير متوقع {unexpected}{todo}",
        "summary_todo": "، {n:known_gaps}",
        "result_ok": "نجحت كل التوقعات", "result_fail": "فشل", "result_error": "خطأ — تعذّر تشغيل الاختبارات",
        "no_fixtures": "مجلد ملفات الاختبار غير موجود: {path}",
        "no_fixture_files": "لا توجد ملفات اختبار في {path}",
        "no_expectations": "لا يوجد أي تعليق 'kashif: expect' في ملفات الاختبار — لا شيء يُتحقَّق منه",
        "no_rules_dir": "مجلد حزمة القواعد غير موجود: {path}",
        "bad_model": "{file}: ليس JSON صالحًا ({msg})؛ المحرك سيتجاهل هذا الملف بصمت",
        "bad_query": "{file}: {msg}",
        "annot_no_ids": "{file}:{line}: التعليق 'kashif: expect' يحتاج معرّف قاعدة أو CWE واحدًا على الأقل",
        "annot_no_target": "{file}:{line}: التعليق لا يتبعه سطر كود",
        "scan_note": "ملاحظة: {note}",
        "lint_ok": "{pack}: نجح الفحص ({warnings:warnings})",
        "lint_fail": "{pack}: {errors:errors}، {warnings:warnings}",
        "created": "أُنشئت حزمة القواعد {name} في {path}",
        "next_steps": "التالي: عدّل models/ و queries/ ثم شغّل:\n  kashif rules test {path}\n"
                      "  kashif rules lint {path}\n  kashif rules pack {path}",
        "packed": "حُزمت {name} {version}: {path}\n  الملفات: {files}   الحجم: {size} بايت\n  SHA-256: {sha}",
        "verified": "{name} {version}: الأرشيف سليم البنية ({files:files})\n  SHA-256: {sha}",
        "installed": "ثُبّتت {name} {version} في {path}\n  SHA-256: {sha}\n"
                     "استخدمها في الفحص بـ:  --models {models} --query {queries}",
        "no_packs": "لا توجد حزم قواعد مثبّتة في {path}",
        "pack_row": "{name} {version}  ({rules:rules})  {description}",
        "e_exists": "{path} موجود مسبقًا (استخدم force / --force للاستبدال)",
        "e_not_empty": "{path} موجود وغير فارغ (استخدم force / --force)",
        "e_pack_name": "اسم حزمة غير صالح {name!r}: استخدم أحرفًا إنجليزية صغيرة وأرقامًا و '.' و '_' و '-' (64 حرفًا كحد أقصى)",
        "e_language": "لا يوجد قالب للغة {language!r}؛ المتاح: {available}",
        "e_lint_blocks": "في الحزمة أخطاء فحص؛ أصلحها أو استخدم lint=False / --no-lint:\n{details}",
        "e_no_archive": "الأرشيف غير موجود: {path}",
        "e_archive_size": "الأرشيف أكبر من الحد {cap} بايت",
        "e_not_zip": "ليس أرشيف ‎.kashifpack (ملف zip غير مقروء): {msg}",
        "e_entries": "في الأرشيف أكثر من {cap} عنصر",
        "e_unsafe_path": "مسار غير آمن في الأرشيف: {name!r} ({why})",
        "e_file_size": "{name}: أكبر من حد الملف الواحد {cap} بايت",
        "e_total_size": "الأرشيف يتمدد إلى أكثر من {cap} بايت",
        "e_no_manifest": "الأرشيف بلا MANIFEST.json — لم يُنشأ بالأمر pack",
        "e_manifest": "MANIFEST.json غير صالح: {msg}",
        "e_manifest_mismatch": "{name}: {why}",
        "e_sha": "عدم تطابق SHA-256: المتوقع {expected} والأرشيف {actual}",
        "e_requires": "هذه الحزمة تتطلب كاشف >= {need}؛ الإصدار الحالي {have}",
        "e_install_lint": "فشل التحقق من الحزمة ولم تُثبَّت:\n{details}",
        "e_not_installed": "لا توجد حزمة مثبّتة باسم {name!r} في {path}",
        "removed": "حُذفت {name} من {path}",
        "e_too_big": "{name}: أكبر من حد الملف الواحد {cap} بايت؛ لم يُحزم",
        "l_no_manifest": "الملف kashifpack.json مفقود (شغّل 'new' لرؤية البنية المتوقعة)",
        "l_json": "JSON غير صالح في السطر {line}، العمود {col}: {msg}",
        "l_not_object": "المتوقع كائن JSON في المستوى الأعلى، والموجود {got}",
        "l_required": "الحقل '{key}' إلزامي",
        "l_type": "المتوقع {want}، والموجود {got}",
        "l_unknown_key": "مفتاح غير معروف '{key}' (يتجاهله المحرك)؛ المفاتيح المعروفة: {known}",
        "l_name": "يجب أن يتكوّن من 1 إلى 64 من a-z و 0-9 و '.' و '_' و '-'، وأن يبدأ وينتهي بحرف أو رقم، وألا يكون اسم "
                  "جهاز محجوزًا في ويندوز",
        "l_version": "يجب أن يكون بصيغة MAJOR.MINOR.PATCH مثل 1.0.0",
        "l_severity": "يجب أن يكون أحد القيم {allowed}",
        "l_cwe": "يجب أن يكون بصيغة CWE-89",
        "l_regex": "تعبير نمطي غير صالح: {msg}",
        "l_language": "لغة غير معروفة '{value}'؛ المعروف: {allowed}",
        "l_kind": "يجب أن يكون أحد القيم attr أو call أو name أو prefix",
        "l_arg": "يجب أن يكون عددًا صحيحًا غير سالب أو النص \"self\"",
        "l_bilingual": "يلزم نص إنجليزي ونص عربي معًا: {fields}",
        "l_inconsistent": "القاعدة {rule} معرّفة بقيمة {what} مختلفة في موضع آخر ({a} مقابل {b})",
        "l_empty_model": "الملف لا يعرّف مصادر ولا مصارف ولا معقِّمات ولا نقاط دخول",
        "l_vql_parse": "تعذّر تحليل الاستعلام: {msg}",
        "l_vql_size": "ملف الاستعلام أكبر من الحد {cap} بايت",
        "e_bad_sha": "قيمة ‎--sha256 يجب أن تكون 64 خانة ست عشرية",
        "w_origin": "المصدر غير مُتحقَّق منه: بدون ‎--sha256 فُحص ملف MANIFEST.json الذي داخل الأرشيف فقط، وهذا يثبت سلامة "
                    "الملفات لا هوية ناشرها.\n  قيمة SHA-256 لهذا الملف: {sha}\n  قارنها بالقيمة التي يعلنها ناشر الحزمة، "
                    "ومرّر ‎--sha256 {sha} ليُتحقَّق منها تلقائيًا.",
        "e_sha_required": "الخيار ‎--sha256 مطلوب (‎--require-sha256 أو KASHIF_REQUIRE_PACK_SHA256): لم يُثبَّت شيء.\n"
                          "  قيمة SHA-256 لهذا الملف: {sha}؛ لا تثبّته إلا إذا طابقت القيمة التي يعلنها ناشره:\n"
                          "  kashif rules install FILE --sha256 <قيمة الناشر>",
        "e_not_a_pack": "{path} موجود لكنه ليس حزمة مثبّتة (لا سجل تثبيت)؛ لن يُستبدل",
        "e_write": "تعذّرت كتابة الحزمة: {msg}",
        "l_vql_run": "الاستعلام يفشل عند التقييم: {msg}",
        "l_vql_meta": "سطر البيانات الوصفية '// @{tag} ...' إلزامي",
        "l_dup_id": "المعرّف {id} مستخدم مسبقًا في {other}",
        "l_builtin_query": "المعرّف {id} هو معرّف قاعدة مضمّنة؛ اختر بادئة خاصة بك",
        "l_builtin_model": "القاعدة {id} مضمّنة: هذه المدخلات توسّعها (مصارف جديدة تُبلَّغ بالمعرّف المضمّن)",
        "l_nothing": "الحزمة لا تحتوي نموذجًا (models/*.json) ولا استعلامًا (queries/*.vql)",
        "l_root_files": "{file} في جذر الحزمة: الأمر 'pack' يحزم models/*.json و queries/*.vql فقط",
        "l_no_fixtures": "لا توجد ملفات اختبار: أضف أمثلة موسومة تحت fixtures/ لتُختبر القواعد",
        "l_untested": "القاعدة {id} بلا تعليق 'kashif: expect {id}' في أي ملف اختبار",
        "l_unknown_expect": "التعليق يذكر {id} وهو غير معرّف في هذه الحزمة ولا في القواعد المضمّنة (خطأ إملائي؟)",
        "l_empty_list": "يجب ألا يكون فارغًا",
    },
}


def _valid_name(name) -> bool:
    """A pack name is also a directory name on every platform: strict characters, no trailing dot, no Windows
    device name (``con``, ``nul``, ``com1`` ...)."""
    return isinstance(name, str) and bool(_NAME_RX.fullmatch(name)) and name.split(".")[0] not in _WIN_RESERVED


def _t(lang: str, msg: str, /, **kw) -> str:
    from .i18n.cliargs import fmt                  # "{n:expectations}": the noun agrees with the number
    table = STR.get(lang) or STR["en"]
    return fmt(table.get(msg) or STR["en"][msg], "ar" if table is STR["ar"] else "en", **kw)


class PackError(Exception):
    """A pack could not be created, verified or installed. ``str(e)`` is a message in the requested language."""


# ================================================================================================== annotations
@dataclass(frozen=True)
class Expectation:
    """One ``kashif: expect ...`` annotation, resolved to the line of code it speaks about."""
    line: int                 # 1-based line of code the annotation applies to
    kind: str                 # "expect" | "none" | "todo"
    ids: tuple                # rule ids and/or CWE ids; empty for a bare expect-none
    at: int                   # 1-based line the comment itself is on


_ANNOT_RX = re.compile(r"(#|//|--|/\*|<!--)\s*kashif:\s*(expect-none|expect-todo|expect)(?![\w-])[ \t]*:?([^\r\n]*)", re.I)
_ID_STOP_RX = re.compile(r"\s--\s|\*/|-->|[%?]>|\(|\s#\s|\s//\s")


def _norm_id(token: str) -> str:
    """Canonical spelling of an id in an annotation: CWE ids become ``CWE-<n>``; rule ids are kept as written."""
    m = re.fullmatch(r"cwe[-_ ]?(\d+)", token, re.I)
    return f"CWE-{int(m.group(1))}" if m else token


def parse_annotations(text: str) -> tuple[list[Expectation], list[tuple[int, str]]]:
    """Read the ``kashif:`` annotations of one fixture.

    Returns ``(expectations, problems)``; a problem is ``(line, "annot_no_ids" | "annot_no_target")``.

    The comment is found textually, not by parsing the language: a string literal that contains
    ``# kashif: expect ...`` counts as an annotation too.

    * ``<code>  # kashif: expect DF004`` - trailing comment: speaks about its own line.
    * A comment-only line speaks about the next line that is neither blank nor another annotation, so several
      annotations may be stacked above one statement.
    * ``expect A, B`` - every listed rule id or CWE (``CWE-89``) must be reported on the line.
    * ``expect-none`` - nothing at all may be reported on the line; ``expect-none A`` - only A is forbidden.
    * ``expect-todo A`` - a known gap: not reported today; never fails, and is flagged once it starts working.
    * Text after `` -- `` (or in parentheses) is a free comment. Comment markers: ``#  //  --  /*  <!--``.
    """
    lines = text.splitlines()
    raw = []                                    # (line_no, standalone, kind, ids)
    problems: list[tuple[int, str]] = []
    for no, line in enumerate(lines, 1):
        m = _ANNOT_RX.search(line)
        if not m:
            continue
        rest = _ID_STOP_RX.split(m.group(3) + " ", 1)[0]
        ids = tuple(dict.fromkeys(_norm_id(t) for t in re.split(r"[\s,;]+", rest.strip()) if t))
        kind = {"expect": "expect", "expect-none": "none", "expect-todo": "todo"}[m.group(2).lower()]
        if kind != "none" and not ids:
            problems.append((no, "annot_no_ids"))
            continue
        raw.append((no, not line[:m.start()].strip(), kind, ids))
    standalone = {no for no, alone, _k, _i in raw if alone}
    next_code = [0] * (len(lines) + 2)          # next_code[n]: first line >= n that is code (one backward pass)
    for n in range(len(lines), 0, -1):
        next_code[n] = n if lines[n - 1].strip() and n not in standalone else next_code[n + 1]
    out = []
    for no, alone, kind, ids in raw:
        target = no
        if alone:
            target = next_code[no + 1]
            if not target:
                problems.append((no, "annot_no_target"))
                continue
        out.append(Expectation(target, kind, ids, no))
    return out, problems


# ======================================================================================================= layout
@dataclass
class PackLayout:
    """Where the parts of a rule pack are. ``root`` may also be a flat directory of ``*.json`` / ``*.vql`` files."""
    root: pathlib.Path
    manifest_path: pathlib.Path | None
    model_files: list
    query_files: list
    fixtures_dir: pathlib.Path | None
    root_level: list = field(default_factory=list)     # model/query files found at the root instead of models/, queries/

    @property
    def name(self) -> str:
        m = _read_json(self.manifest_path) if self.manifest_path else None
        return str(m.get("name")) if isinstance(m, dict) and m.get("name") else self.root.name


def locate(rules_dir) -> PackLayout:
    """Find the model files, query files and fixtures of a rule pack directory (canonical or flat layout)."""
    root = pathlib.Path(rules_dir)
    manifest = root / MANIFEST_NAME
    models, queries, root_level = [], [], []
    for p in sorted(root.glob("*.json")):
        if p.name not in (MANIFEST_NAME, ARCHIVE_MANIFEST) and p.is_file() and not p.name.startswith("."):
            models.append(p)
            root_level.append(p)
    for p in sorted(root.glob("*.vql")):
        if p.is_file():
            queries.append(p)
            root_level.append(p)
    models += [p for p in sorted((root / "models").glob("*.json")) if p.is_file()]
    queries += [p for p in sorted((root / "queries").glob("*.vql")) if p.is_file()]
    fixtures = next((d for d in (root / "fixtures", root / "tests") if d.is_dir()), None)
    return PackLayout(root, manifest if manifest.is_file() else None, models, queries, fixtures, root_level)


def _loads(text: str):
    """``json.loads`` for untrusted text: hostile nesting raises ``ValueError``, never ``RecursionError``.
    (A UTF-8 byte-order mark is deliberately still an error: the engine's model loader rejects it too.)"""
    try:
        return json.loads(text)
    except RecursionError:
        raise ValueError("JSON is nested too deeply") from None


def _read_json(path):
    try:
        return _loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _model_rule_entries(data) -> list[tuple[str, str, int, dict]]:
    """(section, rule id, index, entry) for every sink-like entry of a parsed model file."""
    out = []
    if isinstance(data, dict):
        for section in ("sinks", "attr_sinks", "store_sinks"):
            entries = data.get(section)
            for i, e in enumerate(entries if isinstance(entries, list) else []):
                if isinstance(e, dict) and isinstance(e.get("rule"), str):
                    out.append((section, e["rule"], i, e))
    return out


def _query_meta(path) -> dict | None:
    """The ``@`` metadata of a query file as written (no defaults), or None when the file is unreadable."""
    try:
        text = pathlib.Path(path).read_text(encoding="utf-8")
    except (OSError, ValueError):
        return None
    return {m.group(1): m.group(2).strip() for m in _META_RX.finditer(text)}


def pack_rule_ids(layout: PackLayout) -> dict[str, str]:
    """Every rule id a pack defines -> the file that defines it (first definition wins)."""
    ids: dict[str, str] = {}
    for p in layout.model_files:
        for _s, rule, _i, _e in _model_rule_entries(_read_json(p)):
            ids.setdefault(rule, p.name)
    for p in layout.query_files:
        meta = _query_meta(p)
        if meta is not None:
            ids.setdefault(meta.get("id") or f"vql/{p.stem}", p.name)
    return ids


_BUILTIN_IDS: dict[str, str] | None = None


def builtin_rule_ids() -> dict[str, str]:
    """Ids of the rules that ship with the tool -> their kind ("model" | "query" | "pattern")."""
    global _BUILTIN_IDS
    if _BUILTIN_IDS is None:
        ids: dict[str, str] = {}
        try:
            from . import rules as _rules
            for r in getattr(_rules, "RULES", []):
                ids.setdefault(r.id, "pattern")
        except Exception:  # noqa: BLE001 - the rule table is optional context for lint, never a reason to fail
            pass
        for p in sorted((pathlib.Path(__file__).parent / "models").glob("*.json")):
            for _s, rule, _i, _e in _model_rule_entries(_read_json(p)):
                ids.setdefault(rule, "model")
        for p in sorted((pathlib.Path(__file__).parent / "queries").glob("*.vql")):
            meta = _query_meta(p)
            if meta is not None:
                ids.setdefault(meta.get("id") or f"vql/{p.stem}", "query")
        _BUILTIN_IDS = ids
    return _BUILTIN_IDS


# ================================================================================================== test runner
@dataclass
class Outcome:
    """The verdict for one expectation or one reported finding of a fixture line."""
    file: str
    line: int
    status: str               # ok | missing | unexpected | todo | todo-fixed
    rule: str
    detail: str = ""          # human-readable, already in the report's language
    title: str = ""
    cwe: str = ""
    nearby: list = field(default_factory=list)     # for "missing": lines close by where the rule was reported

    @property
    def failed(self) -> bool:
        return self.status in ("missing", "unexpected")


@dataclass
class FileResult:
    file: str
    outcomes: list = field(default_factory=list)
    expectations: int = 0
    source: list = field(default_factory=list, repr=False)

    @property
    def passed(self) -> bool:
        return not any(o.failed for o in self.outcomes)


@dataclass
class TestReport:
    """Result of :func:`run_tests`. ``exit_code``: 0 all expectations met, 1 failures, 2 the run itself failed."""
    __test__ = False          # not a pytest test class
    pack: str = ""
    fixtures: str = ""
    files: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    scope_ids: list = field(default_factory=list)
    seconds: float = 0.0
    lang: str = "en"

    def _count(self, *statuses) -> int:
        return sum(1 for f in self.files for o in f.outcomes if o.status in statuses)

    @property
    def expected(self) -> int:
        return sum(f.expectations for f in self.files)

    @property
    def matched(self) -> int:
        return self._count("ok")

    @property
    def missing(self) -> int:
        return self._count("missing")

    @property
    def unexpected(self) -> int:
        return self._count("unexpected")

    @property
    def passed(self) -> bool:
        return not self.errors and all(f.passed for f in self.files)

    @property
    def exit_code(self) -> int:
        return 2 if self.errors else 0 if self.passed else 1

    def to_dict(self) -> dict:
        return {"pack": self.pack, "fixtures": self.fixtures, "passed": self.passed, "exit_code": self.exit_code,
                "expected": self.expected, "matched": self.matched, "missing": self.missing,
                "unexpected": self.unexpected, "known_gaps": self._count("todo"), "errors": list(self.errors),
                "warnings": list(self.warnings), "notes": list(self.notes), "scope_ids": list(self.scope_ids),
                "seconds": round(self.seconds, 3),
                "files": [{"file": f.file, "passed": f.passed, "expectations": f.expectations,
                           "outcomes": [{k: v for k, v in asdict(o).items()} for o in f.outcomes]} for f in self.files]}

    def _file_lines(self, f: FileResult, verbose: bool) -> list[str]:
        out = []
        for o in sorted(f.outcomes, key=lambda o: (o.line, o.status, o.rule)):
            if o.status == "ok" and not verbose:
                continue
            sign = {"missing": "-", "unexpected": "+", "todo": "~", "todo-fixed": "!", "ok": "="}[o.status]
            out.append(f"  {sign} {o.detail}")
            if o.failed and 0 < o.line <= len(f.source):
                out.append(f"      | {f.source[o.line - 1].strip()[:160]}")
            if o.nearby:
                out.append("      " + _t(self.lang, "nearby", where=", ".join(f"{self.lang == 'ar' and 'السطر' or 'line'} {n}"
                                                                           for n in o.nearby)))
        return out

    def to_text(self, verbose: bool = False) -> str:
        """The report as plain text: one PASS/FAIL line per fixture, a ``-``/``+`` diff per failing line, a summary.

        ``-`` marks an expected finding that was not reported, ``+`` a reported finding nobody expected."""
        L, out = self.lang, []
        for e in self.errors:
            out.append(f"{_t(L, 'error')}: {e}")
        for w in self.warnings:
            out.append(f"{_t(L, 'warning')}: {w}")
        for f in self.files:
            head = _t(L, "pass") if f.passed else _t(L, "fail")
            out.append(f"{head} {f.file}  ({_t(L, 'expectations', n=f.expectations)})")
            out.extend(self._file_lines(f, verbose))
        for n in self.notes:
            out.append(_t(L, "scan_note", note=n))
        todo = self._count("todo")
        out.append(_t(L, "summary", files=len(self.files), exp=self.expected, ok=self.matched, missing=self.missing,
                      unexpected=self.unexpected, todo=_t(L, "summary_todo", n=todo) if todo else ""))
        out.append(_t(L, "result_error") if self.errors else _t(L, "result_ok") if self.passed else _t(L, "result_fail"))
        return "\n".join(out) + "\n"

    def to_junit(self) -> str:
        """JUnit XML (one ``<testcase>`` per fixture file) for CI systems: GitLab, Jenkins, Azure DevOps, GitHub."""
        failures = sum(1 for f in self.files if not f.passed)
        suites = ET.Element("testsuites", name="kashif-ruletest", tests=str(len(self.files) + bool(self.errors)),
                            failures=str(failures), errors=str(1 if self.errors else 0), time=f"{self.seconds:.3f}")
        suite = ET.SubElement(suites, "testsuite", name=f"kashif-ruletest:{self.pack or 'builtin'}",
                              tests=str(len(self.files) + bool(self.errors)), failures=str(failures),
                              errors=str(1 if self.errors else 0), time=f"{self.seconds:.3f}")
        if self.errors:
            case = ET.SubElement(suite, "testcase", classname=self.pack or "builtin", name="pack", time="0")
            ET.SubElement(case, "error", message=_xml_safe(self.errors[0])[:300]).text = _xml_safe("\n".join(self.errors))
        for f in self.files:
            case = ET.SubElement(suite, "testcase", classname=self.pack or "builtin", name=f.file, time="0")
            if not f.passed:
                bad = [o for o in f.outcomes if o.failed]
                msg = f"{sum(o.status == 'missing' for o in bad)} missing, {sum(o.status == 'unexpected' for o in bad)} unexpected"
                ET.SubElement(case, "failure", message=msg, type="expectation").text = _xml_safe("\n".join(self._file_lines(f, False)))
        if self.notes or self.warnings:
            ET.SubElement(suite, "system-out").text = _xml_safe("\n".join(list(self.warnings) + list(self.notes)))
        return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(suites, encoding="unicode") + "\n"


def _xml_safe(text: str) -> str:
    return re.sub("[^\\x09\\x0A\\x0D\\x20-\\uD7FF\\uE000-\\uFFFD\\U00010000-\\U0010FFFF]", "?", text)


def _finding_cwes(cwe: str) -> set[str]:
    return {f"CWE-{int(n)}" for n in re.findall(r"(\d+)", cwe or "")}


def _fixture_files(fixtures: pathlib.Path):
    """(path, posix path relative to the fixtures root) exactly as the scanner names files."""
    if fixtures.is_file():
        yield fixtures, fixtures.name
        return
    for dirpath, dirnames, filenames in os.walk(fixtures):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and d != "__pycache__")
        for fn in sorted(filenames):
            p = pathlib.Path(dirpath) / fn
            yield p, p.relative_to(fixtures).as_posix()


def _read_fixture(path: pathlib.Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FIXTURE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def run_tests(rules_dir=None, fixtures_dir=None, *, scope: str = "pack", builtin_queries: bool = True,
              lang: str = "en") -> TestReport:
    """Scan annotated fixtures with a rule pack and compare what was reported with what was expected.

    ``rules_dir``     a rule pack (``models/*.json`` + ``queries/*.vql``) or a flat directory of such files; ``None``
                      tests the built-in rules only (``fixtures_dir`` is then required).
    ``fixtures_dir``  directory (or single file) of annotated examples; default ``<rules_dir>/fixtures``.
    ``scope``         ``"pack"`` (default): a finding on a line without a matching annotation fails the test only
                      when its rule belongs to the pack or is named somewhere in the fixtures, so the built-in
                      rules do not get in the way. ``"all"``: every finding of every rule must be annotated.
    ``builtin_queries``  also run the built-in VQL queries (as a normal scan does).

    A line with a bare ``expect-none`` must be free of *any* finding, whatever the scope. The fixtures are only
    parsed, never executed. Returns a :class:`TestReport` (``.to_text()``, ``.to_junit()``, ``.exit_code``).
    """
    from . import vql
    from .scanner import scan_path

    t0 = time.monotonic()
    rep = TestReport(lang=lang)
    layout = None
    if rules_dir is not None:
        if not pathlib.Path(rules_dir).is_dir():
            rep.errors.append(_t(lang, "no_rules_dir", path=rules_dir))
            return rep
        layout = locate(rules_dir)
        rep.pack = layout.name
    fixtures = pathlib.Path(fixtures_dir) if fixtures_dir is not None else (layout.fixtures_dir if layout else None)
    if fixtures is None or not fixtures.exists():
        rep.errors.append(_t(lang, "no_fixtures", path=str(fixtures_dir if fixtures_dir is not None
                                                           else pathlib.Path(rules_dir or ".") / "fixtures")))
        return rep
    rep.fixtures = str(fixtures)

    # a broken model is skipped silently by the engine and a broken query only leaves a note: both would make
    # every "expect" fail (or, worse, every "expect-none" pass) for the wrong reason, so they stop the run
    scope_ids: set[str] = set()
    if layout is not None:
        for p in layout.model_files:
            try:
                data = _loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError) as e:
                rep.errors.append(_t(lang, "bad_model", file=p.name, msg=str(e)))
                continue
            for issue in _lint_model(data, p.name, lang, metadata=False):
                if issue.level == "error":
                    rep.errors.append(str(issue))
        for p in layout.query_files:
            try:
                text = p.read_text(encoding="utf-8")
                if len(text) > MAX_QUERY_BYTES:
                    raise ValueError(_t(lang, "l_vql_size", cap=MAX_QUERY_BYTES))
                vql.Query(text, p.name)
            except Exception as e:  # noqa: BLE001 - whatever a malformed query makes the parser raise stops the run
                rep.errors.append(_t(lang, "bad_query", file=p.name, msg=str(e) or type(e).__name__))
        scope_ids |= set(pack_rule_ids(layout))

    expectations: dict[str, list[Expectation]] = {}
    sources: dict[str, list[str]] = {}
    for path, rel in _fixture_files(fixtures):
        text = _read_fixture(path)
        if text is None:
            continue
        exps, problems = parse_annotations(text)
        for line, key in problems:
            rep.errors.append(_t(lang, key, file=rel, line=line))
        expectations[rel] = exps
        sources[rel] = text.splitlines()
    if not sources:
        rep.errors.append(_t(lang, "no_fixture_files", path=str(fixtures)))
    if rep.errors:
        rep.seconds = time.monotonic() - t0
        return rep
    for exps in expectations.values():
        for e in exps:
            scope_ids |= {i for i in e.ids if not i.startswith("CWE-")}
    rep.scope_ids = sorted(scope_ids)
    scope_low = {x.lower() for x in scope_ids}
    if not any(expectations.values()):
        rep.warnings.append(_t(lang, "no_expectations"))

    notes: list[str] = []
    findings, _count = scan_path(fixtures, jadx=False, notes=notes,
                                 models_dirs=[str(p) for p in layout.model_files] if layout else None,
                                 query_paths=[str(p) for p in layout.query_files] if layout else None,
                                 queries=builtin_queries)
    rep.notes = [n for n in notes if n]
    by_line: dict[tuple[str, int], list] = {}
    for f in findings:
        by_line.setdefault((f.file, f.line), []).append(f)

    def describe(f):
        return {"rule": f.rule_id, "cwe": f" ({f.cwe})" if f.cwe else "", "title": f.title if lang == "en" else (f.title_ar or f.title)}

    for rel in sorted(sources):
        fr = FileResult(rel, source=sources[rel])
        exps = expectations[rel]
        fr.expectations = sum(len(e.ids) if e.kind != "none" else 1 for e in exps)
        per_line: dict[int, list[Expectation]] = {}
        for e in exps:
            per_line.setdefault(e.line, []).append(e)
        lines = sorted(set(per_line) | {ln for (fl, ln) in by_line if fl == rel})
        for ln in lines:
            found = by_line.get((rel, ln), [])
            claimed: set[int] = set()            # findings accounted for by an expect / expect-todo
            forbidden_all, forbidden = False, set()
            for e in per_line.get(ln, []):
                if e.kind == "none":
                    forbidden_all = forbidden_all or not e.ids
                    forbidden |= set(e.ids)
                    continue
                for want in e.ids:
                    hits = [i for i, f in enumerate(found)
                            if (want in _finding_cwes(f.cwe) if want.startswith("CWE-") else f.rule_id.lower() == want.lower())]
                    claimed.update(hits)
                    if e.kind == "todo":
                        key = "todo_fixed" if hits else "todo"
                        fr.outcomes.append(Outcome(rel, ln, "todo-fixed" if hits else "todo", want, _t(lang, key, line=ln, rule=want)))
                    elif hits:
                        fr.outcomes.append(Outcome(rel, ln, "ok", want, f"line {ln}: {want}"))
                    else:
                        near = sorted({f.line for f in findings if f.file == rel and f.line != ln and abs(f.line - ln) <= 3
                                       and (want in _finding_cwes(f.cwe) if want.startswith("CWE-") else f.rule_id.lower() == want.lower())})
                        fr.outcomes.append(Outcome(rel, ln, "missing", want, _t(lang, "missing", line=ln, rule=want), nearby=near))
            none_ok = bool(forbidden_all or forbidden)
            forbidden_low = {x.lower() for x in forbidden}
            for i, f in enumerate(found):
                hit_none = forbidden_all or f.rule_id.lower() in forbidden_low or bool(_finding_cwes(f.cwe) & forbidden)
                if hit_none:
                    none_ok = False
                    fr.outcomes.append(Outcome(rel, ln, "unexpected", f.rule_id, _t(lang, "unexpected_none", line=ln, **describe(f)),
                                               title=f.title, cwe=f.cwe))
                elif i not in claimed and (scope == "all" or f.rule_id.lower() in scope_low):
                    fr.outcomes.append(Outcome(rel, ln, "unexpected", f.rule_id, _t(lang, "unexpected", line=ln, **describe(f)),
                                               title=f.title, cwe=f.cwe))
            if none_ok:
                fr.outcomes.append(Outcome(rel, ln, "ok", "expect-none", f"line {ln}: expect-none"))
        rep.files.append(fr)
    rep.seconds = time.monotonic() - t0
    return rep


# ========================================================================================================= lint
@dataclass
class Issue:
    level: str                # "error" | "warning"
    code: str                 # stable code, e.g. J004
    file: str                 # path relative to the pack root
    where: str                # JSON path (sinks[0].args) or "" for file-level issues
    message: str

    def __str__(self) -> str:
        loc = f"{self.file}: {self.where}: " if self.where else f"{self.file}: " if self.file else ""
        return f"{loc}{self.message} [{self.code}]"


@dataclass
class LintReport:
    """Result of :func:`lint_pack`. ``ok`` is True when there is no error (warnings do not fail a pack)."""
    pack: str = ""
    issues: list = field(default_factory=list)
    rule_ids: list = field(default_factory=list)
    lang: str = "en"

    @property
    def errors(self) -> list:
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self) -> list:
        return [i for i in self.issues if i.level == "warning"]

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def exit_code(self) -> int:
        return 0 if self.ok else 1

    def to_dict(self) -> dict:
        return {"pack": self.pack, "ok": self.ok, "rule_ids": list(self.rule_ids), "issues": [asdict(i) for i in self.issues]}

    def to_text(self) -> str:
        L = self.lang
        out = [f"{_t(L, 'error') if i.level == 'error' else _t(L, 'warning')}: {i}" for i in self.issues]
        out.append(_t(L, "lint_ok", pack=self.pack, warnings=len(self.warnings)) if self.ok
                   else _t(L, "lint_fail", pack=self.pack, errors=len(self.errors), warnings=len(self.warnings)))
        return "\n".join(out) + "\n"


def _typename(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return f"boolean {json.dumps(v)}"
    if isinstance(v, (int, float)):
        return f"number {v}"
    if isinstance(v, str):
        return "string " + json.dumps(v[:40], ensure_ascii=False)
    return "array" if isinstance(v, list) else "object"


class _Linter:
    def __init__(self, file: str, lang: str):
        self.file, self.lang, self.issues = file, lang, []

    def add(self, level, code, where, msg, /, **kw):
        self.issues.append(Issue(level, code, self.file, where, _t(self.lang, msg, **kw)))

    def err(self, code, where, msg, /, **kw):
        self.add("error", code, where, msg, **kw)

    def warn(self, code, where, msg, /, **kw):
        self.add("warning", code, where, msg, **kw)

    def string(self, obj: dict, key: str, where: str, required=False) -> str | None:
        v = obj.get(key)
        if v is None:
            if required:
                self.err("J005", where, "l_required", key=key)
            return None
        if not isinstance(v, str) or not v.strip():
            self.err("J004", f"{where}.{key}" if where else key, "l_type", want="a non-empty string", got=_typename(v))
            return None
        return v

    def str_list(self, obj: dict, key: str, where: str, required=False) -> list | None:
        path = f"{where}.{key}" if where else key
        v = obj.get(key)
        if v is None:
            if required:
                self.err("J005", where, "l_required", key=key)
            return None
        if not isinstance(v, list):
            self.err("J004", path, "l_type", want="an array of strings", got=_typename(v))
            return None
        ok = True
        for i, item in enumerate(v):
            if not isinstance(item, str) or not item:
                self.err("J004", f"{path}[{i}]", "l_type", want="a non-empty string", got=_typename(item))
                ok = False
        if required and not v:
            self.err("J006", path, "l_empty_list")
            ok = False
        return v if ok else None

    def unknown_keys(self, obj: dict, known, where: str, code="J003"):
        for k in obj:
            if k not in known and not str(k).startswith("_"):
                self.warn(code, where or "(top level)", "l_unknown_key", key=k, known=", ".join(known))

    def bilingual(self, where: str, texts: dict, level: str, code="J007"):
        """`texts`: field name -> text. Needs at least one text with Arabic letters and one without."""
        present = [t for t in texts.values() if isinstance(t, str) and t.strip()]
        has_ar = any(_ARABIC_RX.search(t) for t in present)
        has_en = any(not _ARABIC_RX.search(t) for t in present)
        if not (has_ar and has_en):
            self.add(level, code, where, "l_bilingual", fields=" / ".join(texts))


_SINK_KEYS = {"sinks": ("rule", "names", "severity", "cwe", "title", "title_ar", "advice", "advice_en", "advice_ar", "label",
                        "args", "kwargs", "receiver", "shell"),
              "attr_sinks": ("rule", "attrs", "severity", "cwe", "title", "title_ar", "advice", "advice_en", "advice_ar", "label"),
              "store_sinks": ("rule", "roots", "severity", "cwe", "title", "title_ar", "advice", "advice_en", "advice_ar", "label")}
_SINK_TARGET = {"sinks": "names", "attr_sinks": "attrs", "store_sinks": "roots"}


def _lint_model(data, file: str, lang: str, metadata: bool = True, bilingual_level: str = "error") -> list[Issue]:
    """Hand-written schema validation of one model file. With ``metadata=False`` only what would break or
    silently disable the engine is checked (used by the test runner)."""
    lt = _Linter(file, lang)
    if not isinstance(data, dict):
        lt.err("J002", "", "l_not_object", got=_typename(data))
        return lt.issues
    if metadata:
        lt.unknown_keys(data, MODEL_KEYS, "")
    langs = lt.str_list(data, "languages", "")
    for i, v in enumerate(langs or []):
        if v not in LANGUAGES:
            lt.err("J006", f"languages[{i}]", "l_language", value=v, allowed=", ".join(LANGUAGES))
    for key in ("sanitizers", "safe_return_calls", "validators"):
        lt.str_list(data, key, "")

    def entries(key):
        v = data.get(key)
        if v is None:
            return
        if not isinstance(v, list):
            lt.err("J004", key, "l_type", want="an array of objects", got=_typename(v))
            return
        for i, e in enumerate(v):
            if isinstance(e, dict):
                yield f"{key}[{i}]", e
            else:
                lt.err("J004", f"{key}[{i}]", "l_type", want="an object", got=_typename(e))

    for where, s in entries("sources"):
        kind = s.get("kind")
        if kind is None:
            lt.err("J005", where, "l_required", key="kind")
            continue
        if not isinstance(kind, str) or kind not in SOURCE_KINDS:
            lt.err("J006", f"{where}.kind", "l_kind")
            continue
        lt.str_list(s, SOURCE_KINDS[kind], where, required=True)
        if kind == "attr":
            lt.str_list(s, "roots", where)
        if "label" in s:
            lt.string(s, "label", where)
        if metadata:
            lt.unknown_keys(s, ("kind", "label", SOURCE_KINDS[kind]) + (("roots",) if kind == "attr" else ()), where)
    for where, e in entries("entry_points"):
        for key in ("decorators", "view_bases", "methods", "param_names"):
            lt.str_list(e, key, where)
        if metadata:
            lt.unknown_keys(e, ("decorators", "view_bases", "methods", "param_names", "label"), where)
    for section in ("sinks", "attr_sinks", "store_sinks"):
        for where, k in entries(section):
            lt.string(k, "rule", where, required=True)
            lt.str_list(k, _SINK_TARGET[section], where, required=True)
            sev = k.get("severity")
            if sev is not None and not (isinstance(sev, str) and sev in SEVERITIES):
                lt.err("J006", f"{where}.severity", "l_severity", allowed=", ".join(SEVERITIES))
            for key in ("title", "title_ar", "advice", "advice_en", "advice_ar", "label", "cwe"):
                if key in k:
                    lt.string(k, key, where)
            if section == "sinks":
                args = k.get("args")
                if args is not None:
                    if not isinstance(args, list):
                        lt.err("J004", f"{where}.args", "l_type", want="an array of argument positions", got=_typename(args))
                    else:
                        for i, a in enumerate(args):
                            if not (a == "self" or (isinstance(a, int) and not isinstance(a, bool) and a >= 0)):
                                lt.err("J006", f"{where}.args[{i}]", "l_arg")
                lt.str_list(k, "kwargs", where)
                if "shell" in k and not isinstance(k["shell"], bool):
                    lt.err("J004", f"{where}.shell", "l_type", want="true or false", got=_typename(k["shell"]))
                rx = k.get("receiver")
                if rx is not None:
                    if not isinstance(rx, str):
                        lt.err("J004", f"{where}.receiver", "l_type", want="a regular expression string", got=_typename(rx))
                    else:
                        try:
                            re.compile(rx)
                        except re.error as e:
                            lt.err("J006", f"{where}.receiver", "l_regex", msg=str(e))
            if not metadata:
                continue
            lt.unknown_keys(k, _SINK_KEYS[section], where)
            for key in ("severity", "cwe", "title"):
                if key not in k:
                    lt.err("J007", where, "l_required", key=key)
            cwe = k.get("cwe")
            if isinstance(cwe, str) and cwe and not _CWE_RX.fullmatch(cwe):
                lt.err("J006", f"{where}.cwe", "l_cwe")
            if not any(isinstance(k.get(a), str) and k.get(a).strip() for a in ("advice", "advice_en", "advice_ar")):
                lt.err("J007", where, "l_required", key="advice")
            else:
                lt.bilingual(where, {a: k.get(a) for a in ("advice", "advice_en", "advice_ar")}, bilingual_level)
            if "title" in k:
                lt.bilingual(where, {"title": k.get("title"), "title_ar": k.get("title_ar")}, bilingual_level)
    if metadata and not any(data.get(k) for k in MODEL_KEYS if k != "languages"):
        lt.warn("J009", "", "l_empty_model")
    return lt.issues


def _empty_db() -> dict:
    return {k: [] for k in ("call", "func", "class", "assign", "string", "import", "decorator", "attr", "flow")}


def _lint_query(path: pathlib.Path, rel: str, lang: str, bilingual_level: str) -> tuple[list[Issue], str | None]:
    from . import vql
    lt = _Linter(rel, lang)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, ValueError) as e:
        lt.err("Q001", "", "l_vql_parse", msg=str(e))
        return lt.issues, None
    if len(text) > MAX_QUERY_BYTES:               # refused before the query parser sees it (hostile packs)
        lt.err("Q001", "", "l_vql_size", cap=MAX_QUERY_BYTES)
        return lt.issues, None
    meta = {m.group(1): m.group(2).strip() for m in _META_RX.finditer(text)}
    try:
        q = vql.Query(text, path.name)
    except vql.QueryError as e:
        lt.err("Q001", "", "l_vql_parse", msg=str(e))
        q = None
    except Exception as e:  # noqa: BLE001 - malformed text the parser trips on (deep nesting included)
        lt.err("Q001", "", "l_vql_parse", msg=f"{type(e).__name__}: {e}")
        q = None
    if q is not None:
        try:
            q.findings(_empty_db())
        except vql.QueryError as e:
            lt.err("Q005", "", "l_vql_run", msg=str(e))
        except Exception as e:  # noqa: BLE001 - any evaluation failure of a user query is a lint finding, not a crash
            lt.err("Q005", "", "l_vql_run", msg=f"{type(e).__name__}: {e}")
    for tag in ("id", "name", "severity", "cwe", "advice"):
        if not meta.get(tag) and not (tag == "advice" and (meta.get("advice_en") or meta.get("advice_ar"))):
            lt.err("Q002", "", "l_vql_meta", tag=tag)
    if meta.get("severity") and meta["severity"] not in SEVERITIES:
        lt.err("Q003", "@severity", "l_severity", allowed=", ".join(SEVERITIES))
    if meta.get("cwe") and not _CWE_RX.fullmatch(meta["cwe"]):
        lt.err("Q003", "@cwe", "l_cwe")
    if meta.get("name"):
        lt.bilingual("", {"@name": meta.get("name"), "@name_ar": meta.get("name_ar")}, bilingual_level, "Q004")
    if any(meta.get(a) for a in ("advice", "advice_en", "advice_ar")):
        lt.bilingual("", {"@" + a: meta.get(a) for a in ("advice", "advice_en", "advice_ar")}, bilingual_level, "Q004")
    return lt.issues, meta.get("id") or f"vql/{path.stem}"


_MANIFEST_KEYS = ("name", "version", "description", "description_ar", "author", "license", "homepage", "languages", "kashif")


def _lint_manifest(layout: PackLayout, lang: str, bilingual_level: str) -> list[Issue]:
    lt = _Linter(MANIFEST_NAME, lang)
    if layout.manifest_path is None:
        lt.err("M001", "", "l_no_manifest")
        return lt.issues
    try:
        data = _loads(layout.manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        lt.err("M002", "", "l_json", line=e.lineno, col=e.colno, msg=e.msg)
        return lt.issues
    except (OSError, ValueError) as e:
        lt.err("M002", "", "l_json", line=0, col=0, msg=str(e))
        return lt.issues
    if not isinstance(data, dict):
        lt.err("M002", "", "l_not_object", got=_typename(data))
        return lt.issues
    name = lt.string(data, "name", "", required=True)
    if name and not _valid_name(name):
        lt.err("M003", "name", "l_name")
    version = lt.string(data, "version", "", required=True)
    if version and not _VERSION_RX.fullmatch(version):
        lt.err("M003", "version", "l_version")
    need = lt.string(data, "kashif", "")
    if need and not _VERSION_RX.fullmatch(need):
        lt.err("M003", "kashif", "l_version")
    if lt.string(data, "description", "", required=True):
        lt.bilingual("", {"description": data.get("description"), "description_ar": data.get("description_ar")},
                     bilingual_level, "M004")
    for key in ("author", "license", "homepage", "description_ar"):
        if data.get(key) not in (None, ""):          # an empty optional text is the same as an absent one
            lt.string(data, key, "")
    for i, v in enumerate(lt.str_list(data, "languages", "") or []):
        if v not in LANGUAGES:
            lt.err("M003", f"languages[{i}]", "l_language", value=v, allowed=", ".join(LANGUAGES))
    lt.unknown_keys(data, _MANIFEST_KEYS, "", "M005")
    for i in lt.issues:                               # the shared type/required helpers report model codes
        if i.code.startswith("J"):
            i.code = "M003"
    return lt.issues


def lint_pack(pack_dir, *, lang: str = "en", allow_monolingual: bool = False, check_fixtures: bool = True) -> LintReport:
    """Validate a rule pack and return a :class:`LintReport` with precise, located messages.

    Checks: the manifest (``kashifpack.json``); every model file against the model schema (types, required
    fields, severities, CWE format, regular expressions, argument positions, unknown keys); every query (it must
    parse and evaluate, and carry ``@id @name @severity @cwe @advice``); complete bilingual metadata (English and
    Arabic title/name and advice - an error unless ``allow_monolingual``, then a warning); unique ids (two queries
    with one id, a query id equal to a model rule or to a built-in rule); and, with ``check_fixtures``, that
    fixtures exist, their annotations are well-formed and every rule of the pack is expected at least once.
    """
    root = pathlib.Path(pack_dir)
    rep = LintReport(pack=root.name, lang=lang)
    if not root.is_dir():
        rep.issues.append(Issue("error", "P000", "", "", _t(lang, "no_rules_dir", path=str(pack_dir))))
        return rep
    layout = locate(root)
    rep.pack = layout.name
    bl = "warning" if allow_monolingual else "error"
    rep.issues += _lint_manifest(layout, lang, bl)

    def rel(p: pathlib.Path) -> str:
        return p.relative_to(root).as_posix()

    for p in layout.root_level:
        rep.issues.append(Issue("warning", "P003", rel(p), "", _t(lang, "l_root_files", file=p.name)))
    if not layout.model_files and not layout.query_files:
        rep.issues.append(Issue("error", "P001", "", "", _t(lang, "l_nothing")))

    ids: dict[str, str] = {}                     # id -> defining file
    model_meta: dict[str, tuple] = {}            # rule -> (file/where, severity, cwe)
    builtin = builtin_rule_ids()
    for p in layout.model_files:
        try:
            data = _loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            rep.issues.append(Issue("error", "J001", rel(p), "", _t(lang, "l_json", line=e.lineno, col=e.colno, msg=e.msg)))
            continue
        except (OSError, ValueError) as e:
            rep.issues.append(Issue("error", "J001", rel(p), "", _t(lang, "l_json", line=0, col=0, msg=str(e))))
            continue
        rep.issues += _lint_model(data, rel(p), lang, bilingual_level=bl)
        seen_builtin = set()
        for section, rule, i, e in _model_rule_entries(data):
            where = f"{section}[{i}]"
            ids.setdefault(rule, rel(p))
            if rule in builtin and rule not in seen_builtin:
                seen_builtin.add(rule)
                rep.issues.append(Issue("warning", "I003", rel(p), where, _t(lang, "l_builtin_model", id=rule)))
            prev = model_meta.setdefault(rule, (f"{rel(p)}: {where}", e.get("severity"), e.get("cwe")))
            for idx, what in ((1, "severity"), (2, "cwe")):
                now = e.get(what)
                if prev[idx] is not None and now is not None and prev[idx] != now:
                    rep.issues.append(Issue("warning", "J008", rel(p), where,
                                            _t(lang, "l_inconsistent", rule=rule, what=what, a=now, b=prev[idx])))
    query_ids: dict[str, str] = {}
    for p in layout.query_files:
        issues, qid = _lint_query(p, rel(p), lang, bl)
        rep.issues += issues
        if qid is None:
            continue
        if qid in query_ids:
            rep.issues.append(Issue("error", "I001", rel(p), "@id", _t(lang, "l_dup_id", id=qid, other=query_ids[qid])))
        elif qid in ids:
            rep.issues.append(Issue("error", "I002", rel(p), "@id", _t(lang, "l_dup_id", id=qid, other=ids[qid])))
        elif qid in builtin:
            rep.issues.append(Issue("error", "I003", rel(p), "@id", _t(lang, "l_builtin_query", id=qid)))
        query_ids.setdefault(qid, rel(p))
        ids.setdefault(qid, rel(p))
    rep.rule_ids = sorted(ids)

    if check_fixtures:
        expected: set[str] = set()
        any_file = False
        if layout.fixtures_dir is not None:
            for path, frel in _fixture_files(layout.fixtures_dir):
                text = _read_fixture(path)
                if text is None:
                    continue
                any_file = True
                shown = f"{layout.fixtures_dir.name}/{frel}"
                exps, problems = parse_annotations(text)
                for line, key in problems:
                    rep.issues.append(Issue("error", "F003", shown, "", _t(lang, key, file=frel, line=line)))
                for e in exps:
                    for i in e.ids:
                        expected.add(i)
                        if e.kind != "none" and not i.startswith("CWE-") and i not in ids and i not in builtin \
                                and i.lower() not in {x.lower() for x in ids}:
                            rep.issues.append(Issue("warning", "F004", shown, f"line {e.at}", _t(lang, "l_unknown_expect", id=i)))
        if not any_file:
            rep.issues.append(Issue("warning", "F001", "", "", _t(lang, "l_no_fixtures")))
        else:
            low = {x.lower() for x in expected}
            for rid in sorted(ids):
                if rid.lower() not in low:
                    rep.issues.append(Issue("warning", "F002", ids[rid], "", _t(lang, "l_untested", id=rid)))
    rep.issues.sort(key=lambda i: (i.level != "error", i.file, i.where))
    return rep


# ==================================================================================================== scaffolding
# language -> (extension, source call, sink call, sanitizer call, debug call, vulnerable fixture, safe fixture)
_TEMPLATES = {
    "python": ("py", "examplelib.read_untrusted", "examplelib.run_report", "examplelib.clean_input", "enable_debug",
               "import examplelib\n\n\ndef export_report():\n    query = examplelib.read_untrusted()\n"
               "    # kashif: expect {RULE}\n    examplelib.run_report(query)\n\n\n"
               "def start():\n    examplelib.enable_debug()  # kashif: expect {QUERY}, CWE-489\n",
               "import examplelib\n\n\ndef export_report():\n    query = examplelib.clean_input(examplelib.read_untrusted())\n"
               "    examplelib.run_report(query)  # kashif: expect-none\n\n\n"
               "def fixed_report():\n    examplelib.run_report(\"monthly\")  # kashif: expect-none {RULE}\n"),
    "javascript": ("js", "readUntrusted", "runReport", "cleanInput", "enableDebug",
                   "const examplelib = require('examplelib');\n\nfunction exportReport() {\n"
                   "  const query = examplelib.readUntrusted();\n  // kashif: expect {RULE}\n  examplelib.runReport(query);\n}\n\n"
                   "function start() {\n  examplelib.enableDebug(); // kashif: expect {QUERY}, CWE-489\n}\n",
                   "const examplelib = require('examplelib');\n\nfunction exportReport() {\n"
                   "  const query = examplelib.cleanInput(examplelib.readUntrusted());\n"
                   "  examplelib.runReport(query); // kashif: expect-none\n}\n\n"
                   "function fixedReport() {\n  examplelib.runReport('monthly'); // kashif: expect-none {RULE}\n}\n"),
    "java": ("java", "readUntrusted", "runReport", "cleanInput", "enableDebug",
             "package example;\n\npublic class Vulnerable {\n  public void exportReport(ExampleLib lib) {\n"
             "    String query = lib.readUntrusted();\n    // kashif: expect {RULE}\n    lib.runReport(query);\n  }\n\n"
             "  public void start(ExampleLib lib) {\n    lib.enableDebug(); // kashif: expect {QUERY}, CWE-489\n  }\n}\n",
             "package example;\n\npublic class Safe {\n  public void exportReport(ExampleLib lib) {\n"
             "    String query = lib.cleanInput(lib.readUntrusted());\n    lib.runReport(query); // kashif: expect-none\n  }\n\n"
             "  public void fixedReport(ExampleLib lib) {\n    lib.runReport(\"monthly\"); // kashif: expect-none {RULE}\n  }\n}\n"),
    "php": ("php", "read_untrusted", "run_report", "clean_input", "enable_debug",
            "<?php\nfunction export_report() {\n  $query = read_untrusted();\n  // kashif: expect {RULE}\n  run_report($query);\n}\n\n"
            "function start() {\n  enable_debug(); // kashif: expect {QUERY}, CWE-489\n}\n",
            "<?php\nfunction export_report() {\n  $query = clean_input(read_untrusted());\n"
            "  run_report($query); // kashif: expect-none\n}\n\n"
            "function fixed_report() {\n  run_report('monthly'); // kashif: expect-none {RULE}\n}\n"),
    "go": ("go", "ReadUntrusted", "RunReport", "CleanInput", "EnableDebug",
           "package main\n\nfunc exportReport() {\n\tquery := examplelib.ReadUntrusted()\n\t// kashif: expect {RULE}\n"
           "\texamplelib.RunReport(query)\n}\n\nfunc start() {\n\texamplelib.EnableDebug() // kashif: expect {QUERY}, CWE-489\n}\n",
           "package main\n\nfunc exportReport() {\n\tquery := examplelib.CleanInput(examplelib.ReadUntrusted())\n"
           "\texamplelib.RunReport(query) // kashif: expect-none\n}\n\n"
           "func fixedReport() {\n\texamplelib.RunReport(\"monthly\") // kashif: expect-none {RULE}\n}\n"),
}
SCAFFOLD_LANGUAGES = tuple(_TEMPLATES)


def _scaffold_model(language: str, rule: str, source: str, sink: str, sanitizer: str) -> dict:
    return {
        "_comment": "Taint model: tells the data-flow engine where untrusted data comes from (sources), where it must "
                    "not arrive (sinks) and what makes it safe (sanitizers). Keys starting with '_' are comments: the "
                    "engine ignores unknown keys. Full reference: kashif rules docs",
        "_comment_ar": "نموذج تلوّث: يخبر محرك تدفق البيانات من أين تأتي البيانات غير الموثوقة (sources) وأين يجب ألا تصل "
                       "(sinks) وما الذي يجعلها آمنة (sanitizers). المفاتيح التي تبدأ بـ '_' تعليقات يتجاهلها المحرك.",
        "_comment_languages": "Optional. Restricts this file to the listed languages; omit it to apply the file to every "
                              "language. Values: " + ", ".join(LANGUAGES),
        "languages": [language],
        "sources": [{
            "_comment": "kind 'call': the RETURN VALUE of these functions is untrusted. Other kinds: 'attr' (roots + "
                        "attrs: request.args), 'name' (names: a variable such as $_GET), 'prefix' (prefixes: any dotted "
                        "name starting with ...). 'label' is the text shown as the origin; {name} / {attr} are replaced.",
            "kind": "call",
            "names": [source],
            "label": "{name}()",
        }],
        "sinks": [{
            "_comment": "A finding is reported when tainted data reaches one of the 'args' (0-based positions; \"self\" "
                        "= the receiver object) or 'kwargs' (named arguments) of a call to one of 'names'. Name matching: "
                        "'pkg.fn' matches that dotted name or any name ending in '.pkg.fn'; 'fn' matches any call whose "
                        "last segment is fn; 'builtins.fn' matches only the bare call fn(...). Optional 'receiver' is a "
                        "regular expression the receiver expression must match (obj in obj.fn(...)). Optional 'shell': "
                        "true marks a call that hands its argument to a command shell.",
            "rule": rule,
            "severity": "high",
            "cwe": "CWE-94",
            "title": "Untrusted data reaches the report engine",
            "title_ar": "بيانات غير موثوقة تصل إلى محرك التقارير",
            "advice": "تحقّق من القيمة بقائمة بيضاء أو مرّرها عبر clean_input قبل تشغيل التقرير.",
            "advice_en": "Validate the value against an allow-list or pass it through clean_input before running the report.",
            "label": "report engine",
            "names": [sink],
            "args": [0],
        }],
        "_comment_sanitizers": "Calls whose return value is safe whatever went in. A sanitizer declared in a user model "
                               "is trusted for every sink. Related keys: 'validators' (functions whose successful check in "
                               "an if-condition clears the checked variable) and 'safe_return_calls' (calls an HTTP "
                               "handler may return without a reflected-output finding).",
        "sanitizers": [sanitizer],
    }


def _scaffold_query(name: str, qid: str, debug: str) -> str:
    return f"""// VQL query: a declarative "from ... where ... select" over the program database.
// Lines starting with // or # are comments; the "// @tag value" lines below are the rule's metadata.
// Full reference: kashif rules docs
//
// @id {qid}
// @name Debug mode enabled
// @name_ar تفعيل وضع التنقيح
// @severity medium
// @cwe CWE-489
// @advice عطّل وضع التنقيح في بيئة الإنتاج؛ اجعله خاضعًا لإعداد يُضبط وقت النشر.
// @advice_en Turn debug mode off in production; put it behind a deploy-time setting.
//
// "call" is one of the relations (call, func, class, assign, string, import, decorator, attr, flow).
// c.func is the last segment of the called name, c.name the full dotted name, c.args the argument text.
from call c
where c.func = "{debug}"
select c, "debug mode enabled by " + c.name
"""


def _scaffold_readme(name: str, rule: str, qid: str, language: str, ext: str) -> str:
    return f"""# {name}

A Kashif rule pack. Everything here is data: nothing in a pack is ever executed.

| Path | What it is |
| --- | --- |
| `{MANIFEST_NAME}` | Pack name, version and description (English + Arabic). |
| `models/{name}.json` | Taint model: sources, sinks and sanitizers. Defines rule `{rule}`. |
| `queries/debug-enabled.vql` | VQL query. Defines rule `{qid}`. |
| `fixtures/vulnerable.{ext}` | Code that MUST be reported (`kashif: expect ...`). |
| `fixtures/safe.{ext}` | Code that must NOT be reported (`kashif: expect-none`). |

## Workflow

```
kashif rules test  .     # scan the fixtures, compare with the annotations
kashif rules lint  .     # validate models, queries, ids and metadata
kashif rules pack  .     # -> {name}-0.1.0{PACK_EXT} + SHA-256
kashif rules install {name}-0.1.0{PACK_EXT}
kashif rules docs        # the full rule language reference
```

## Annotations

```
# kashif: expect {rule}            the line below (or this line, as a trailing comment) must report {rule}
# kashif: expect CWE-94            ... or any finding with that CWE
# kashif: expect-none              nothing may be reported on the line
# kashif: expect-none {rule}       {rule} must not be reported (other rules may)
# kashif: expect-todo {rule}       a known gap: documented, does not fail the run
```

A line of a fixture without annotation must not be reported by this pack's own rules.

## بالعربية

حزمة قواعد لكاشف (لغة الأمثلة: {language}). عدّل `models/` و `queries/`، ضع أمثلة مصابة وآمنة في `fixtures/` مع
تعليقات `kashif: expect`، ثم شغّل `test` و `lint` و `pack` كما في الأعلى. لا يُنفَّذ أي شيء من محتوى الحزمة أبدًا.
"""


def new_pack(dest, name: str | None = None, language: str = "python", *, force: bool = False, lang: str = "en") -> pathlib.Path:
    """Create a ready-to-run rule pack in ``dest`` and return its path.

    The pack contains a manifest, a commented taint model (source, sink, sanitizer), a commented VQL query, a
    vulnerable and a safe fixture for ``language`` (one of ``SCAFFOLD_LANGUAGES``) and a README. It passes
    ``lint_pack`` and ``run_tests`` as generated, so an author starts from green. Raises :class:`PackError` when
    ``dest`` is a non-empty directory (unless ``force``), or the name / language is invalid.
    """
    dest = pathlib.Path(dest)
    name = name or re.sub(r"[^a-z0-9._-]+", "-", dest.name.lower()).strip("-._") or "my-pack"
    if not _valid_name(name):
        raise PackError(_t(lang, "e_pack_name", name=name))
    if language not in _TEMPLATES:
        raise PackError(_t(lang, "e_language", language=language, available=", ".join(_TEMPLATES)))
    if dest.exists() and (not dest.is_dir() or any(dest.iterdir())) and not force:
        raise PackError(_t(lang, "e_not_empty", path=str(dest)))
    ext, source, sink, sanitizer, debug, vulnerable, safe = _TEMPLATES[language]
    prefix = (re.sub(r"[^A-Za-z]", "", name).upper() or "PACK")[:4]
    rule, qid = f"{prefix}001", f"{name}/debug-enabled"
    manifest = {"name": name, "version": "0.1.0",
                "description": f"Custom detections for {name}.", "description_ar": f"قواعد كشف مخصّصة لـ {name}.",
                "author": "", "license": "MIT", "languages": [language], "kashif": __version__}
    files = {
        MANIFEST_NAME: json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        f"models/{name}.json": json.dumps(_scaffold_model(language, rule, source, sink, sanitizer), ensure_ascii=False, indent=2) + "\n",
        "queries/debug-enabled.vql": _scaffold_query(name, qid, debug),
        f"fixtures/vulnerable.{ext}": vulnerable.replace("{RULE}", rule).replace("{QUERY}", qid),
        f"fixtures/safe.{ext}": safe.replace("{RULE}", rule).replace("{QUERY}", qid),
        "README.md": _scaffold_readme(name, rule, qid, language, ext),
    }
    for rel, text in files.items():
        p = dest / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")
    return dest


# ============================================================================================== pack and install
@dataclass
class PackResult:
    path: pathlib.Path
    sha256: str               # SHA-256 of the archive file: the value to publish next to the pack
    manifest: dict            # the generated MANIFEST.json
    skipped: list = field(default_factory=list)     # files of the pack directory that were not shipped


@dataclass
class InstallResult:
    path: pathlib.Path
    name: str
    version: str
    sha256: str
    models_dir: pathlib.Path
    queries_dir: pathlib.Path
    warnings: list = field(default_factory=list)


def default_packs_dir() -> pathlib.Path:
    """``$KASHIF_HOME/packs``, else ``$VULNSCAN_HOME/packs``, else ``~/.vulnscan/packs``."""
    home = os.environ.get("KASHIF_HOME") or os.environ.get("VULNSCAN_HOME")
    return (pathlib.Path(home) if home else pathlib.Path.home() / ".vulnscan") / "packs"


def _path_problem(name: str) -> str | None:
    """Why an archive member name is not acceptable, or None. Deliberately strict: an allow-list, not a deny-list."""
    if not name or "\x00" in name or any(ord(c) < 32 for c in name):
        return "control character"
    if "\\" in name:
        return "backslash"
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return "absolute path"
    if len(name) > MAX_PATH_CHARS:
        return "path too long"
    parts = name.split("/")
    if len(parts) > MAX_PATH_DEPTH:
        return "path too deep"
    for part in parts:
        if part in ("", ".", ".."):
            return "path traversal" if part == ".." else "empty path segment"
        if part.startswith(".") or part.endswith((" ", ".")):
            return "hidden or malformed name"
        if part.split(".")[0].strip().lower() in _WIN_RESERVED or any(c in part for c in ':<>"|?*'):
            return "reserved name or character"
        if _CONTROL_RX.search(part):
            return "control character"
    top = parts[0]
    if len(parts) == 1:
        if name in (MANIFEST_NAME, ARCHIVE_MANIFEST) or re.fullmatch(r"(README|LICENSE|NOTICE|CHANGELOG)(\.(md|txt))?", name):
            return None
        return "file not allowed at the pack root"
    if top == "models":
        return None if len(parts) == 2 and name.endswith(".json") else "only models/*.json is allowed"
    if top == "queries":
        return None if len(parts) == 2 and name.endswith(".vql") else "only queries/*.vql is allowed"
    if top == "fixtures":
        return None
    return "directory not allowed in a pack"


def _parents(name: str) -> list[str]:
    parts = name.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]


def _files_digest(files: list[dict]) -> str:
    listing = "".join(f"{f['sha256']}  {f['path']}\n" for f in sorted(files, key=lambda f: f["path"]))
    return hashlib.sha256(listing.encode("utf-8")).hexdigest()


def _sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def build_pack(pack_dir, out=None, *, lint: bool = True, lang: str = "en") -> PackResult:
    """Bundle a rule pack directory into one ``<name>-<version>.kashifpack`` file and return a :class:`PackResult`.

    The archive is a zip holding ``kashifpack.json``, ``README``/``LICENSE``, ``models/*.json``, ``queries/*.vql``,
    ``fixtures/**`` and a generated ``MANIFEST.json`` (format, name, version, every file's size and SHA-256, and a
    digest of the file list). It is deterministic: fixed timestamps, modes and order, so the same files packed
    with the same Python/zlib build give the same bytes and SHA-256 (another zlib may compress differently; the
    ``digest`` in ``MANIFEST.json`` depends only on the files' content and is the same everywhere). ``out`` is a ``*.kashifpack`` file path, or a directory (default: next to the pack directory). With ``lint`` (default)
    a pack that has lint errors is refused. Raises :class:`PackError`.
    """
    root = pathlib.Path(pack_dir)
    if not root.is_dir():
        raise PackError(_t(lang, "no_rules_dir", path=str(pack_dir)))
    if lint:
        rep = lint_pack(root, lang=lang)
        if not rep.ok:
            raise PackError(_t(lang, "e_lint_blocks", details="\n".join(f"  {i}" for i in rep.errors)))
    meta = _read_json(root / MANIFEST_NAME)
    if not isinstance(meta, dict) or not isinstance(meta.get("name"), str) or not _valid_name(meta["name"]) \
            or not isinstance(meta.get("version"), str) or not _VERSION_RX.fullmatch(meta["version"]):
        raise PackError(f"{MANIFEST_NAME}: " + _t(lang, "l_required", key="name / version"))
    payload: list[tuple[str, bytes]] = []
    skipped: list[str] = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        for d in sorted(dirnames):                       # .git, __pycache__, symlinked directories: never walked
            if d.startswith(".") or d == "__pycache__" or os.path.islink(os.path.join(dirpath, d)):
                skipped.append((pathlib.Path(dirpath) / d).relative_to(root).as_posix() + "/")
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and d != "__pycache__"
                             and not os.path.islink(os.path.join(dirpath, d)))
        for fn in sorted(filenames):
            p = pathlib.Path(dirpath) / fn
            rel = p.relative_to(root).as_posix()
            if p.is_symlink() or not p.is_file() or rel == ARCHIVE_MANIFEST or _path_problem(rel):
                skipped.append(rel)
                continue
            if p.stat().st_size > MAX_FILE_BYTES:
                raise PackError(_t(lang, "e_too_big", name=rel, cap=MAX_FILE_BYTES))
            data = p.read_bytes()
            total += len(data)
            payload.append((rel, data))
    if len(payload) + 1 > MAX_ENTRIES:
        raise PackError(_t(lang, "e_entries", cap=MAX_ENTRIES))
    if total > MAX_TOTAL_BYTES:
        raise PackError(_t(lang, "e_total_size", cap=MAX_TOTAL_BYTES))
    payload.sort()
    files = [{"path": rel, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()} for rel, data in payload]
    manifest = {"format": PACK_FORMAT, "name": meta["name"], "version": meta["version"],
                "description": meta.get("description", ""), "description_ar": meta.get("description_ar", ""),
                "kashif": meta.get("kashif", ""), "rules": sorted(pack_rule_ids(locate(root))),
                "files": files, "digest": _files_digest(files)}
    fname = f"{meta['name']}-{meta['version']}{PACK_EXT}"
    target = pathlib.Path(out) if out else root.resolve().parent / fname
    if target.is_dir() or target.suffix != PACK_EXT:          # a directory (created if needed), not a file name
        target = target / fname
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        entries = [(ARCHIVE_MANIFEST, (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"))]
        for rel, data in entries + payload:
            info = zipfile.ZipInfo(rel, date_time=(1980, 1, 1, 0, 0, 0))     # fixed stamp: reproducible archive
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            info.create_system = 3                           # same header bytes on Windows and POSIX
            zf.writestr(info, data)
    blob = buf.getvalue()
    if len(blob) > MAX_ARCHIVE_BYTES:
        raise PackError(_t(lang, "e_archive_size", cap=MAX_ARCHIVE_BYTES))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(blob)
    return PackResult(target, hashlib.sha256(blob).hexdigest(), manifest, skipped)


def _read_archive(archive, sha256: str | None, lang: str) -> tuple[dict, dict[str, bytes], str]:
    """Open an untrusted .kashifpack and return (manifest, {path: bytes}, archive sha256). Nothing touches the disk.

    Every member name is validated against an allow-list before any byte is read; sizes are enforced on the bytes
    actually decompressed (zip headers can lie); symlinks, encrypted and duplicate entries are refused; the
    content must match MANIFEST.json exactly (no extra file, no missing file, every hash)."""
    path = pathlib.Path(archive)
    if not path.is_file():
        raise PackError(_t(lang, "e_no_archive", path=str(archive)))
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise PackError(_t(lang, "e_archive_size", cap=MAX_ARCHIVE_BYTES))
    actual = _sha256_file(path)
    if sha256 and not _SHA256_RX.fullmatch(sha256.strip()):
        raise PackError(_t(lang, "e_bad_sha"))
    if sha256 and actual.lower() != sha256.strip().lower():
        raise PackError(_t(lang, "e_sha", expected=sha256.strip().lower(), actual=actual))
    contents: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ENTRIES:
                raise PackError(_t(lang, "e_entries", cap=MAX_ENTRIES))
            total = 0
            seen: set[str] = set()
            seen_dirs: set[str] = set()
            for info in infos:
                name = info.filename
                if name.endswith("/") and not _path_problem(name.rstrip("/") + "/x") and info.file_size == 0:
                    continue                                  # a plain directory entry inside an allowed tree
                why = _path_problem(name)
                if why is None and (info.external_attr >> 16) & 0o170000 == 0o120000:
                    why = "symbolic link"
                if why is None and info.flag_bits & 0x1:
                    why = "encrypted entry"
                key = name.casefold()                         # case-insensitive file systems (Windows, macOS)
                if why is None and key in seen:
                    why = "duplicate entry"
                if why is None and (key in seen_dirs or any(p in seen for p in _parents(key))):
                    why = "a file and a directory share this name"
                if why is not None:
                    raise PackError(_t(lang, "e_unsafe_path", name=name, why=why))
                seen.add(key)
                seen_dirs.update(_parents(key))
                if info.file_size > MAX_FILE_BYTES:
                    raise PackError(_t(lang, "e_file_size", name=name, cap=MAX_FILE_BYTES))
                with zf.open(info) as fh:
                    data = fh.read(MAX_FILE_BYTES + 1)
                if len(data) > MAX_FILE_BYTES:
                    raise PackError(_t(lang, "e_file_size", name=name, cap=MAX_FILE_BYTES))
                total += len(data)
                if total > MAX_TOTAL_BYTES:
                    raise PackError(_t(lang, "e_total_size", cap=MAX_TOTAL_BYTES))
                contents[name] = data
    except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, RuntimeError, EOFError, OSError, ValueError) as e:
        raise PackError(_t(lang, "e_not_zip", msg=str(e))) from None
    raw = contents.pop(ARCHIVE_MANIFEST, None)
    if raw is None:
        raise PackError(_t(lang, "e_no_manifest"))
    try:
        manifest = _loads(raw.decode("utf-8"))
    except ValueError as e:
        raise PackError(_t(lang, "e_manifest", msg=str(e))) from None
    files = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(manifest, dict) or manifest.get("format") != PACK_FORMAT or not isinstance(files, list) \
            or not isinstance(manifest.get("name"), str) or not _valid_name(manifest["name"]) \
            or not isinstance(manifest.get("version"), str) or not _VERSION_RX.fullmatch(manifest["version"]) \
            or not all(isinstance(f, dict) and isinstance(f.get("path"), str) and isinstance(f.get("sha256"), str) for f in files):
        raise PackError(_t(lang, "e_manifest", msg=f"format must be {PACK_FORMAT} with name, version and files"))
    listed = {f["path"]: f for f in files}
    for name in sorted(set(listed) - set(contents)):
        raise PackError(_t(lang, "e_manifest_mismatch", name=name, why="listed in MANIFEST.json but missing from the archive"))
    for name in sorted(set(contents) - set(listed)):
        raise PackError(_t(lang, "e_manifest_mismatch", name=name, why="present in the archive but not listed in MANIFEST.json"))
    for name, data in contents.items():
        if hashlib.sha256(data).hexdigest() != listed[name]["sha256"].lower():
            raise PackError(_t(lang, "e_manifest_mismatch", name=name, why="content does not match its SHA-256 in MANIFEST.json"))
    if manifest.get("digest") != _files_digest(files):
        raise PackError(_t(lang, "e_manifest", msg="digest does not match the file list"))
    inner = None
    try:
        inner = _loads(contents.get(MANIFEST_NAME, b"").decode("utf-8"))
    except ValueError:
        pass
    if not isinstance(inner, dict) or inner.get("name") != manifest["name"] or inner.get("version") != manifest["version"]:
        raise PackError(_t(lang, "e_manifest_mismatch", name=MANIFEST_NAME, why="name/version differ from MANIFEST.json"))
    return manifest, contents, actual


def verify_pack(archive, sha256: str | None = None, *, lang: str = "en") -> dict:
    """Check a ``.kashifpack`` without installing it. Returns its manifest plus ``archive_sha256``.

    Verifies the optional expected ``sha256`` of the archive, the structural safety of every entry and the
    integrity of the content against ``MANIFEST.json``. Raises :class:`PackError` on any problem. Integrity is not
    authenticity: the SHA-256 only proves the file is the one whose hash you were given through a trusted channel.
    """
    manifest, _contents, actual = _read_archive(archive, sha256, lang)
    return {**manifest, "archive_sha256": actual}


def _version_tuple(v: str) -> tuple:
    return tuple(int(n) for n in re.findall(r"\d+", v.split("-")[0].split("+")[0])[:3])


def install_pack(archive, packs_dir=None, *, sha256: str | None = None, force: bool = False, lang: str = "en") -> InstallResult:
    """Safely unpack a ``.kashifpack`` into ``<packs_dir>/<name>/`` and return an :class:`InstallResult`.

    The archive is fully validated in memory first (see :func:`verify_pack`): zip-slip and absolute paths,
    symlinks, files outside the pack layout, per-file / total size caps and hash mismatches are all refused before
    anything is written. The files are then written into a temporary directory inside ``packs_dir``, linted (a pack
    with lint errors could break scans and is not installed) and moved into place in one step. Nothing in a pack is
    executed. ``force`` replaces an installed pack of the same name. Raises :class:`PackError`.

    Use the result with a scan: ``scan_path(target, models_dirs=[str(r.models_dir)], query_paths=[str(r.queries_dir)])``.
    """
    manifest, contents, actual = _read_archive(archive, sha256, lang)
    need = manifest.get("kashif") or ""
    if isinstance(need, str) and _VERSION_RX.fullmatch(need) and _version_tuple(need) > _version_tuple(__version__):
        raise PackError(_t(lang, "e_requires", need=need, have=__version__))
    packs = pathlib.Path(packs_dir) if packs_dir is not None else default_packs_dir()
    packs.mkdir(parents=True, exist_ok=True)
    final = packs / manifest["name"]
    if final.exists() or final.is_symlink():
        if not force:
            raise PackError(_t(lang, "e_exists", path=str(final)))
        # --force only ever replaces something this module installed: never an unrelated directory that happens
        # to carry the name a (possibly hostile) archive chose for itself
        if final.is_symlink() or not final.is_dir() or not (final / INSTALL_RECORD).is_file():
            raise PackError(_t(lang, "e_not_a_pack", path=str(final)))
    tmp = pathlib.Path(tempfile.mkdtemp(prefix=".installing-", dir=str(packs)))
    try:
        base = tmp.resolve()
        for name, data in contents.items():
            dest = (tmp / name).resolve()
            if base != dest and base not in dest.parents:              # defence in depth behind _path_problem
                raise PackError(_t(lang, "e_unsafe_path", name=name, why="escapes the pack directory"))
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        rep = lint_pack(tmp, lang=lang, allow_monolingual=True)
        if not rep.ok:
            raise PackError(_t(lang, "e_install_lint", details="\n".join(f"  {i}" for i in rep.errors)))
        record = {"name": manifest["name"], "version": manifest["version"], "archive_sha256": actual,
                  "digest": manifest.get("digest", ""), "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  "rules": rep.rule_ids, "description": manifest.get("description", ""),
                  "description_ar": manifest.get("description_ar", "")}
        (tmp / INSTALL_RECORD).write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if final.exists():
            old = packs / f".replaced-{manifest['name']}-{os.getpid()}"
            os.replace(final, old)
            shutil.rmtree(old, ignore_errors=True)
        os.replace(tmp, final)
    except OSError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise PackError(_t(lang, "e_write", msg=str(e))) from None
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return InstallResult(final, manifest["name"], manifest["version"], actual, final / "models", final / "queries",
                         [str(i) for i in rep.warnings])


def remove_pack(name: str, packs_dir=None, *, lang: str = "en") -> pathlib.Path:
    """Delete an installed pack by name. Raises :class:`PackError` when no such pack is installed."""
    packs = pathlib.Path(packs_dir) if packs_dir is not None else default_packs_dir()
    target = packs / name
    if not isinstance(name, str) or not _valid_name(name) or target.is_symlink() or not (target / INSTALL_RECORD).is_file():
        raise PackError(_t(lang, "e_not_installed", name=name, path=str(packs)))
    shutil.rmtree(target)
    return target


def installed_packs(packs_dir=None) -> list[dict]:
    """The packs installed in ``packs_dir``: name, version, descriptions, rules, archive_sha256, path, models_dir, queries_dir."""
    packs = pathlib.Path(packs_dir) if packs_dir is not None else default_packs_dir()
    out = []
    for d in sorted(packs.iterdir()) if packs.is_dir() else []:
        rec = _read_json(d / INSTALL_RECORD) if d.is_dir() and not d.name.startswith(".") else None
        if isinstance(rec, dict):
            out.append({**rec, "path": str(d), "models_dir": str(d / "models"), "queries_dir": str(d / "queries")})
    return out


def scan_args(packs_dir=None, names=None) -> tuple[list[str], list[str]]:
    """``(models_dirs, query_paths)`` for ``scan_path`` covering the installed packs (all, or only ``names``)."""
    models, queries = [], []
    for p in installed_packs(packs_dir):
        if names is not None and p.get("name") not in names:
            continue
        if os.path.isdir(p["models_dir"]):
            models.append(p["models_dir"])
        if os.path.isdir(p["queries_dir"]):
            queries.append(p["queries_dir"])
    return models, queries


def register_pack_translations(pack_dir) -> int:
    """Make the engine's English output use the ``advice_en`` texts a pack ships. Returns the number of pairs added.

    The engine's ``advice`` is Arabic-first and translated through the in-memory i18n catalogue; a pack's Arabic
    advice is unknown to it. This registers ``advice`` -> ``advice_en`` (models) and ``@advice`` -> ``@advice_en``
    (queries) in that catalogue for the current process only."""
    from . import i18n
    added = 0
    layout = locate(pack_dir)
    pairs = []
    for p in layout.model_files:
        for _s, _r, _i, e in _model_rule_entries(_read_json(p)):
            pairs.append((e.get("advice") or e.get("advice_ar"), e.get("advice_en")))
    for p in layout.query_files:
        meta = _query_meta(p) or {}
        pairs.append((meta.get("advice") or meta.get("advice_ar"), meta.get("advice_en")))
    for ar, en in pairs:
        if isinstance(ar, str) and isinstance(en, str) and en.strip() and _ARABIC_RX.search(ar):
            key = re.sub(r"\s+", " ", ar).strip()
            if key not in i18n.CATALOG:
                i18n.CATALOG[key] = en.strip()
                added += 1
    return added


# ==================================================================================================== reference
# (field, type, required, English, Arabic)
_MANIFEST_DOC = [
    ("name", "string", "yes", "Pack identifier: lowercase letters, digits, `.`, `_`, `-` (max 64), starting and ending with a letter or digit. Also the install directory name.",
     "معرّف الحزمة: أحرف إنجليزية صغيرة وأرقام و `.` و `_` و `-` (64 حرفًا كحد أقصى) يبدأ وينتهي بحرف أو رقم، وهو اسم مجلد التثبيت."),
    ("version", "string", "yes", "Version of the pack, `MAJOR.MINOR.PATCH`.", "إصدار الحزمة بصيغة `MAJOR.MINOR.PATCH`."),
    ("description", "string", "yes", "One-line description in English.", "وصف من سطر واحد بالإنجليزية."),
    ("description_ar", "string", "yes", "The same description in Arabic.", "الوصف نفسه بالعربية."),
    ("author", "string", "no", "Author or team.", "المؤلف أو الفريق."),
    ("license", "string", "no", "SPDX licence identifier, e.g. `MIT`.", "معرّف الترخيص بصيغة SPDX مثل `MIT`."),
    ("homepage", "string", "no", "Where the pack lives (informational; never fetched).", "موقع الحزمة (للمعلومة فقط؛ لا يُجلب أبدًا)."),
    ("languages", "array of strings", "no", "Languages the pack targets (informational).", "اللغات التي تستهدفها الحزمة (للمعلومة)."),
    ("kashif", "string", "no", "Minimum Kashif version; `install` refuses the pack on an older version.",
     "أدنى إصدار مطلوب من كاشف؛ يرفض `install` الحزمة على إصدار أقدم."),
]
_MODEL_DOC = [
    ("languages", "array of strings", "no", "Restricts the file to these languages (" + ", ".join(f"`{x}`" for x in LANGUAGES)
     + "). Omitted: the file applies to every language.", "يقصر الملف على هذه اللغات. عند حذفه يُطبَّق الملف على كل اللغات."),
    ("sources", "array of objects", "no", "Where untrusted data enters (see *Sources*).", "من أين تدخل البيانات غير الموثوقة (انظر *المصادر*)."),
    ("entry_points", "array of objects", "no", "What makes a function an externally reachable handler whose parameters are untrusted (see *Entry points*).",
     "ما الذي يجعل الدالة معالِجًا يُستدعى من الخارج فتكون معاملاته غير موثوقة (انظر *نقاط الدخول*)."),
    ("sinks", "array of objects", "no", "Dangerous calls (see *Sinks*).", "الاستدعاءات الخطرة (انظر *المصارف*)."),
    ("attr_sinks", "array of objects", "no", "Dangerous attribute assignments such as `el.innerHTML = x`: sink metadata plus `attrs` (attribute names).",
     "إسنادات خطرة إلى خاصية مثل `el.innerHTML = x`: بيانات المصرف مع `attrs` (أسماء الخصائص)."),
    ("store_sinks", "array of objects", "no", "Trusted stores written by subscript, such as `session[k] = x`: sink metadata plus `roots` (store names). Key and value are both checked.",
     "مخازن موثوقة يُكتب فيها بالفهرسة مثل `session[k] = x`: بيانات المصرف مع `roots` (أسماء المخازن). يُفحص المفتاح والقيمة."),
    ("sanitizers", "array of strings", "no", "Calls whose return value is safe. A sanitizer declared in a user model is trusted for every sink.",
     "استدعاءات قيمتها المُعادة آمنة. المعقِّم المعرَّف في نموذج المستخدم موثوق لكل المصارف."),
    ("validators", "array of strings", "no", "Function names whose check in an `if` condition validates the variables passed to it on the guarded path.",
     "أسماء دوال يُعدّ فحصها في شرط `if` تحققًا من المتغيرات الممرَّرة إليها على المسار المحمي."),
    ("safe_return_calls", "array of strings", "no", "Calls an entry point may `return` without a reflected-output finding (e.g. an auto-escaping template renderer).",
     "استدعاءات يجوز لنقطة الدخول إعادتها دون نتيجة «مخرجات منعكسة» (مثل محرك قوالب يهرّب تلقائيًا)."),
    ("_comment, _anything", "any", "no", "Keys starting with `_` are comments, at any level. The engine ignores unknown keys; `lint` warns about unknown keys that do not start with `_`.",
     "المفاتيح التي تبدأ بـ `_` تعليقات في أي مستوى. المحرك يتجاهل المفاتيح غير المعروفة، و `lint` يحذّر من غير المعروف الذي لا يبدأ بـ `_`."),
]
_SOURCE_DOC = [
    ("kind", "string", "yes", "`attr`, `call`, `name` or `prefix`.", "`attr` أو `call` أو `name` أو `prefix`."),
    ("attrs", "array of strings", "kind=attr", "Attribute names that are untrusted when read from a root: `request.args` -> `args`.",
     "أسماء خصائص غير موثوقة عند قراءتها من جذر: `request.args` -> `args`."),
    ("roots", "array of strings", "no (attr)", "Objects the attributes are read from (`request`, `self.request`). Parameters named in an entry point's `param_names` also count as roots.",
     "الكائنات التي تُقرأ منها الخصائص (`request`). المعاملات المسماة في `param_names` تُعدّ جذورًا أيضًا."),
    ("names", "array of strings", "kind=call / name", "`call`: functions whose return value is untrusted. `name`: variables that are untrusted wherever they appear (`$_GET`, `sys.argv`).",
     "`call`: دوال قيمتها المُعادة غير موثوقة. `name`: متغيرات غير موثوقة أينما ظهرت (`$_GET`)."),
    ("prefixes", "array of strings", "kind=prefix", "Any dotted name starting with one of these prefixes is untrusted.", "أي اسم منقوط يبدأ بإحدى هذه البادئات غير موثوق."),
    ("label", "string", "no", "Text shown as the origin of the data; `{name}` / `{attr}` are replaced.", "النص المعروض كمصدر للبيانات؛ يُستبدل `{name}` / `{attr}`."),
]
_ENTRY_DOC = [
    ("decorators", "array of strings", "no", "Decorator / annotation names that mark a handler (`route`, `GetMapping`).", "أسماء المزخرفات / التعليقات التوضيحية التي تميّز المعالِج (`route`)."),
    ("view_bases", "array of strings", "no", "Base classes whose subclasses are request handlers.", "أصناف أساسية تُعدّ أصنافها الفرعية معالِجات طلبات."),
    ("methods", "array of strings", "no", "Method names that are handlers inside such a class (`get`, `post`).", "أسماء توابع تُعدّ معالِجات داخل هذه الأصناف (`get`، `post`)."),
    ("param_names", "array of strings", "no", "Parameter names that always carry the request (`request`, `req`, `ctx`).", "أسماء معاملات تحمل الطلب دائمًا (`request`، `req`)."),
    ("label", "string", "no", "Text shown as the origin of the data.", "النص المعروض كمصدر للبيانات."),
]
_SINK_DOC = [
    ("rule", "string", "yes", "Rule id reported for the finding. Use your own prefix (`ACME001`). A built-in id (`DF004`) adds sinks to that built-in rule.",
     "معرّف القاعدة المُبلَّغ عنه. استخدم بادئة خاصة بك (`ACME001`). معرّف مضمّن (`DF004`) يضيف مصارف لتلك القاعدة."),
    ("names", "array of strings", "yes", "Called names to match (see *Name matching*).", "الأسماء المستدعاة المطلوب مطابقتها (انظر *مطابقة الأسماء*)."),
    ("severity", "string", "lint", "`critical`, `high`, `medium`, `low` or `info`. Engine default: `high` for `sinks`, `medium` for `attr_sinks` and `store_sinks`.",
     "`critical` أو `high` أو `medium` أو `low` أو `info`. الافتراضي في المحرك: `high` في `sinks` و `medium` في `attr_sinks` و `store_sinks`."),
    ("cwe", "string", "lint", "CWE id, `CWE-89`.", "معرّف CWE مثل `CWE-89`."),
    ("title", "string", "lint", "English title of the finding.", "عنوان النتيجة بالإنجليزية."),
    ("title_ar", "string", "lint", "Arabic title.", "العنوان بالعربية."),
    ("advice", "string", "lint", "Remediation advice. The engine is Arabic-first: put the Arabic text here.", "نصيحة المعالجة. المحرك عربي أولًا: ضع النص العربي هنا."),
    ("advice_en", "string", "lint", "English advice (used for English output once the pack's translations are registered).", "النصيحة بالإنجليزية (تُستخدم في المخرجات الإنجليزية بعد تسجيل ترجمات الحزمة)."),
    ("label", "string", "no", "Short name of the sink shown in the data-flow trail. Default: the rule id.", "اسم قصير للمصرف يظهر في مسار التدفق. الافتراضي: معرّف القاعدة."),
    ("args", "array", "no", "0-based positions of the arguments that must not be tainted; `\"self\"` checks the receiver (`p` in `p.read_text()`). Default `[0]`.",
     "مواضع الوسائط (من 0) التي يجب ألا تكون ملوّثة؛ `\"self\"` يفحص الكائن المستقبِل. الافتراضي `[0]`."),
    ("kwargs", "array of strings", "no", "Named arguments that are also checked (case-insensitive).", "وسائط مسمّاة تُفحص أيضًا (دون حساسية لحالة الأحرف)."),
    ("receiver", "string (regex)", "no", "The sink only matches a method call whose receiver text matches this regular expression (`conn` in `conn.search(x)`).",
     "لا يطابق المصرف إلا استدعاء تابع يطابق نصُّ مستقبِله هذا التعبير النمطي."),
    ("shell", "boolean", "no", "`true` when the call hands its argument to a command shell.", "`true` عندما يمرّر الاستدعاء وسيطه إلى صدفة أوامر."),
]
_VQL_META_DOC = [
    ("@id", "yes", "Rule id, e.g. `acme/debug-enabled`. Must be unique. Default when absent: `vql/<file name>` (lint requires it).", "معرّف القاعدة مثل `acme/debug-enabled`، ويجب أن يكون فريدًا."),
    ("@name", "yes", "English title.", "العنوان بالإنجليزية."),
    ("@name_ar", "yes", "Arabic title.", "العنوان بالعربية."),
    ("@severity", "yes", "`critical`, `high`, `medium`, `low`, `info`.", "`critical` أو `high` أو `medium` أو `low` أو `info`."),
    ("@cwe", "yes", "`CWE-<number>`.", "`CWE-<رقم>`."),
    ("@advice", "yes", "Remediation advice (Arabic-first, like the engine).", "نصيحة المعالجة (بالعربية أولًا كما في المحرك)."),
    ("@advice_en", "yes", "English advice.", "النصيحة بالإنجليزية."),
]
_VQL_RELATIONS = [
    ("call", "id name func receiver file line in_func in_class nargs args arg0 arg1 arg2 arg3 kwargs"),
    ("func", "id name qual file line nparams params decorators class is_entry is_method"),
    ("class", "id name file line bases decorators"),
    ("assign", "id target value file line in_func"),
    ("string", "id value file line in_func"),
    ("import", "id module name alias file line"),
    ("decorator", "id name func file line"),
    ("attr", "id base name file line in_func"),
    ("flow", "id rule severity cwe source label file line callee interprocedural hops sink_file sink_line"),
]
_LINT_CODES = [
    ("M001-M005", "Manifest: missing, invalid JSON, invalid field, missing second language, unknown key.", "ملف البيان: مفقود، JSON غير صالح، حقل غير صالح، لغة ثانية مفقودة، مفتاح غير معروف."),
    ("J001-J009", "Model: invalid JSON, not an object, unknown key, wrong type, missing field, invalid value, incomplete metadata, inconsistent rule, empty file.",
     "النموذج: JSON غير صالح، ليس كائنًا، مفتاح غير معروف، نوع خاطئ، حقل مفقود، قيمة غير صالحة، بيانات وصفية ناقصة، قاعدة غير متسقة، ملف فارغ."),
    ("Q001-Q005", "Query: does not parse, missing metadata, invalid severity/CWE, missing second language, fails when evaluated.",
     "الاستعلام: تعذّر التحليل، بيانات وصفية مفقودة، خطورة/CWE غير صالحة، لغة ثانية مفقودة، يفشل عند التقييم."),
    ("I001-I003", "Ids: duplicate query id, query id equal to a model rule, id of a built-in rule.", "المعرّفات: معرّف استعلام مكرر، معرّف استعلام يساوي قاعدة نموذج، معرّف قاعدة مضمّنة."),
    ("F001-F004", "Fixtures: none, rule never expected, malformed annotation, annotation names an unknown id.", "ملفات الاختبار: لا يوجد، قاعدة بلا توقّع، تعليق مشوّه، تعليق يذكر معرّفًا مجهولًا."),
    ("P001, P003", "Pack: no model and no query; model/query file at the root (not shipped).", "الحزمة: بلا نموذج ولا استعلام؛ ملف نموذج/استعلام في الجذر (لا يُحزم)."),
]


def _table(header: tuple, rows: list) -> str:
    out = ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"]
    out += ["| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |" for r in rows]
    return "\n".join(out)


def rules_reference(lang: str = "en") -> str:
    """The full rule-authoring reference as Markdown (``lang``: ``"en"`` or ``"ar"``).

    Generated from the same tables the linter and the scaffold use, so it cannot drift from the code. The
    integration step writes it to ``docs/rules-authoring.md``; ``kashif rules docs`` prints it."""
    ar = lang == "ar"
    col = 4 if ar else 3

    def fields(rows):
        head = ("الحقل", "النوع", "إلزامي", "الوصف") if ar else ("Field", "Type", "Required", "Description")
        return _table(head, [(f"`{r[0]}`", r[1], r[2], r[col]) for r in rows])

    relations = _table(("العلاقة", "الحقول") if ar else ("Relation", "Fields"), [(f"`{n}`", f"`{f}`") for n, f in _VQL_RELATIONS])
    meta = _table(("الوسم", "إلزامي", "الوصف") if ar else ("Tag", "Required by lint", "Description"),
                  [(f"`{r[0]}`", r[1], r[3 if ar else 2]) for r in _VQL_META_DOC])
    codes = _table(("الرمز", "المعنى") if ar else ("Code", "Meaning"), [(f"`{r[0]}`", r[2 if ar else 1]) for r in _LINT_CODES])
    layout = f"""```
my-pack/
  {MANIFEST_NAME}          # name, version, description (en + ar)
  models/*.json            # taint models: sources, sinks, sanitizers
  queries/*.vql            # VQL queries
  fixtures/                # annotated vulnerable and safe examples (any depth)
  README.md  LICENSE
```"""
    model_example = """```json
{
  "languages": ["python"],
  "sources": [{"kind": "call", "names": ["acme.read_untrusted"], "label": "{name}()"}],
  "sinks": [{
    "rule": "ACME001", "severity": "high", "cwe": "CWE-94",
    "title": "Untrusted data reaches the report engine",
    "title_ar": "بيانات غير موثوقة تصل إلى محرك التقارير",
    "advice": "تحقّق من القيمة بقائمة بيضاء قبل تشغيل التقرير.",
    "advice_en": "Validate the value against an allow-list before running the report.",
    "names": ["acme.run_report"], "args": [0], "kwargs": ["template"]
  }],
  "sanitizers": ["acme.clean_input"]
}
```"""
    vql_example = """```
// @id acme/tls-verify-disabled
// @name TLS verification disabled
// @name_ar تعطيل التحقق من شهادة TLS
// @severity high
// @cwe CWE-295
// @advice فعّل التحقق من الشهادة.
// @advice_en Enable certificate verification.
from call c
where c.name matches "^acme\\\\.http\\\\." and c.kwargs contains "verify=False"
select c, "TLS verification disabled in " + c.name
```"""
    vql_advanced = """```
predicate calls(f, g) { from call c where c.in_func = f and c.func = g }
predicate reaches(f, g) { calls(f, g) or from value h where calls(f, h) and reaches(h, g) }
from func e where e.is_entry and reaches(e.name, "run_report") select e, "handler reaches run_report"

class ReportCall extends call {
  ReportCall() { this.func in ("run_report", "runReport") }
  predicate isDynamic() { not this.arg0 matches "^[\\"']" }
}
from ReportCall c where c.isDynamic() select c, "dynamic report: " + c.arg0

from func f
where count(call c | c.in_func = f.name and c.func = "run_report") > 3
select f, "many reports in " + f.name

from flow fl where fl.rule = "ACME001" and fl.interprocedural select fl, "cross-function flow from " + fl.source
```"""
    annotations = """```python
query = acme.read_untrusted()
# kashif: expect ACME001              <- comment-only line: speaks about the next line of code
acme.run_report(query)
acme.run_report(query)                # kashif: expect ACME001, CWE-94   <- trailing: this line
acme.run_report("monthly")            # kashif: expect-none              <- no finding at all here
acme.run_report(acme.clean_input(q))  # kashif: expect-none ACME001      <- ACME001 forbidden, others ignored
acme.run_report(decode(q))            # kashif: expect-todo ACME001 -- known gap, tracked in ISSUE-12
```"""
    cli = """```
kashif rules new my-pack --language python
kashif rules test my-pack [--scope all] [--junit report.xml] [--json]
kashif rules lint my-pack
kashif rules pack my-pack              # -> my-pack-0.1.0.kashifpack + SHA-256
kashif rules verify my-pack-0.1.0.kashifpack --sha256 <hex>
kashif rules install my-pack-0.1.0.kashifpack --sha256 <hex>
kashif rules list
```"""
    if ar:
        parts = [
            "# كتابة القواعد في كاشف\n\nهذا المرجع الكامل لكتابة قواعد كشف خاصة بك واختبارها ومشاركتها. كل شيء محلي ومجاني ويعمل دون اتصال، "
            "والحزمة بيانات فقط: لا يُنفَّذ شيء من محتواها أبدًا.",
            "## البدء السريع\n\n" + cli,
            "## بنية الحزمة\n\n" + layout + f"\n\n### ملف البيان `{MANIFEST_NAME}`\n\n" + fields(_MANIFEST_DOC),
            "## نماذج التلوّث (`models/*.json`)\n\nالنموذج يخبر محرك تدفق البيانات (بين الدوال والملفات) بثلاثة أشياء: **المصادر** التي تدخل منها "
            "البيانات غير الموثوقة، و**المصارف** التي يجب ألا تصلها، و**المعقِّمات** التي تجعلها آمنة. تُدمج ملفات المستخدم مع النماذج المضمّنة.\n\n"
            + model_example + "\n\n### مفاتيح المستوى الأعلى\n\n" + fields(_MODEL_DOC)
            + "\n\n### المصادر (`sources[]`)\n\n" + fields(_SOURCE_DOC)
            + "\n\n### نقاط الدخول (`entry_points[]`)\n\n" + fields(_ENTRY_DOC)
            + "\n\n### المصارف (`sinks[]`)\n\nالحقول `rule` و `severity` و `cwe` و `title` و `title_ar` و `advice` و `advice_en` و `label` "
            "مشتركة مع `attr_sinks[]` (التي تضيف `attrs`) و `store_sinks[]` (التي تضيف `roots`). «lint» في عمود الإلزام تعني أن المحرك "
            "يقبل غيابه لكن `lint` يطلبه.\n\n" + fields(_SINK_DOC)
            + "\n\n### مطابقة الأسماء\n\n- `pkg.fn`: يطابق الاسم المنقوط نفسه أو أي اسم ينتهي بـ `.pkg.fn`.\n"
            "- `fn`: يطابق أي استدعاء مقطعه الأخير `fn` (`obj.fn(...)`، `a.b.fn(...)`).\n"
            "- `builtins.fn`: يطابق الاستدعاء المجرد `fn(...)` فقط.\n\nتُحلّ الأسماء عبر الاستيرادات والأسماء المستعارة قبل المطابقة.",
            "## استعلامات VQL (`queries/*.vql`)\n\nاستعلام تصريحي `from … where … select` على قاعدة بيانات البرنامج. الأسطر التي تبدأ بـ `//` أو `#` "
            "تعليقات، وأسطر `// @وسم قيمة` هي بيانات القاعدة.\n\n" + vql_example + "\n\n### البيانات الوصفية\n\n" + meta
            + "\n\n### العلاقات\n\n" + relations
            + "\n\n### العوامل\n\n`=` `!=` `<` `>` `<=` `>=`، `matches` (تعبير نمطي، بحث)، `contains` (جزء من نص)، `in (…)`، `and` `or` `not` والأقواس، "
            "و `+` لضم النصوص في `select`. أول عنصر في `select` هو الموضع (متغير)، والباقي نص الرسالة.\n\n"
            "### المحمولات والأصناف والتجميع\n\nمحمولات معرّفة من المستخدم (تكرارية بأسلوب Datalog)، أصناف بمحمول مميِّز وتوابع، ودوال تجميع "
            "`count` `strictcount` `sum` `max` `min` `avg` والمكمِّمان `exists` و `any`.\n\n" + vql_advanced,
            "## ملفات الاختبار والتعليقات\n\nضع أمثلة مصابة وآمنة تحت `fixtures/`. علامات التعليق المقبولة: `#` `//` `--` `/*` `<!--`.\n\n" + annotations
            + "\n\n- `expect A, B`: يجب الإبلاغ عن كل معرّف (قاعدة أو `CWE-89`) على السطر.\n- `expect-none`: لا نتيجة إطلاقًا على السطر؛ "
            "`expect-none A`: يُمنع `A` فقط.\n- `expect-todo A`: فجوة معروفة لا تُفشل التشغيل، ويُنبَّه عند إصلاحها.\n"
            "- تعليق في سطر مستقل يخص أول سطر كود بعده، ويمكن تكديس عدة تعليقات.\n- ما بعد ` -- ` أو بين قوسين تعليق حر.\n"
            "- سطر بلا تعليق يجب ألا تُبلّغ عنه قواعد الحزمة نفسها (النطاق `pack`). مع `--scope all` يجب توسيم كل نتيجة لكل قاعدة.",
            "## مشغّل الاختبارات\n\n`test` يفحص ملفات الاختبار بنماذج واستعلامات الحزمة ويقارن النتائج بالتوقعات. يطبع لكل ملف «نجح/فشل» وفرقًا "
            "لكل سطر: `-` نتيجة متوقعة لم يُبلَّغ عنها (مع الأسطر المجاورة التي ظهرت فيها القاعدة)، و `+` نتيجة غير متوقعة. رموز الخروج: "
            "0 نجاح، 1 فشل توقعات، 2 تعذّر التشغيل (نموذج أو استعلام معطوب، لا ملفات اختبار). `--junit FILE` يكتب JUnit XML و `--json` يطبع JSON.",
            "## الفحص `lint`\n\n" + codes + "\n\nالأخطاء تُفشل الفحص (رمز الخروج 1)؛ التحذيرات لا تُفشله. `--allow-monolingual` يحوّل نقص اللغة الثانية إلى تحذير.",
            f"## الحزم والمشاركة\n\n`pack` ينتج ملفًا واحدًا `<name>-<version>{PACK_EXT}` (أرشيف zip بطوابع زمنية وترتيب ثابتين) يحتوي `MANIFEST.json` "
            "بحجم كل ملف وبصمته SHA-256، ويطبع بصمة SHA-256 للأرشيف لتنشرها مع الملف. `install` يتحقق من البصمة (`--sha256`) ومن كل مسار "
            "(لا مسارات مطلقة ولا `..` ولا روابط رمزية ولا ملفات خارج بنية الحزمة)، ويطبّق حدود الحجم "
            f"({MAX_ARCHIVE_BYTES // (1024 * 1024)} م.ب للأرشيف، {MAX_FILE_BYTES // (1024 * 1024)} م.ب للملف، "
            f"{MAX_TOTAL_BYTES // (1024 * 1024)} م.ب بعد الفك، {MAX_ENTRIES} عنصر)، ثم يفحص الحزمة بـ `lint` قبل نقلها إلى مجلد الحزم. "
            "البصمة تثبت سلامة الملف لا هوية مؤلفه: احصل عليها عبر قناة موثوقة. لا يُنفَّذ شيء من محتوى الحزمة، لكن قواعدها منطق كشف "
            "تقرر أنت الوثوق به: قد تعرّف الحزمة معقِّمات (تُسكت نتائج) وتعابير نمطية (قد تكون بطيئة)، فراجع حزمة الطرف الثالث قبل "
            "الاعتماد عليها في بوابة.",
        ]
    else:
        parts = [
            "# Writing rules for Kashif\n\nThe complete reference for writing, testing and sharing your own detections. Everything is free, "
            "local and offline, and a pack is data only: nothing inside a pack is ever executed.",
            "## Quick start\n\n" + cli,
            "## Pack layout\n\n" + layout + f"\n\n### The manifest `{MANIFEST_NAME}`\n\n" + fields(_MANIFEST_DOC),
            "## Taint models (`models/*.json`)\n\nA model tells the inter-procedural data-flow engine three things: the **sources** untrusted data "
            "comes from, the **sinks** it must not reach and the **sanitizers** that make it safe. User model files are merged with the built-in "
            "models, so a pack can teach the engine an in-house framework in a few lines.\n\n"
            + model_example + "\n\n### Top-level keys\n\n" + fields(_MODEL_DOC)
            + "\n\n### Sources (`sources[]`)\n\n" + fields(_SOURCE_DOC)
            + "\n\n### Entry points (`entry_points[]`)\n\n" + fields(_ENTRY_DOC)
            + "\n\n### Sinks (`sinks[]`)\n\n`rule`, `severity`, `cwe`, `title`, `title_ar`, `advice`, `advice_en` and `label` are shared with "
            "`attr_sinks[]` (which adds `attrs`) and `store_sinks[]` (which adds `roots`). \"lint\" in the Required column means the engine "
            "tolerates its absence but `lint` asks for it.\n\n" + fields(_SINK_DOC)
            + "\n\n### Name matching\n\n- `pkg.fn` matches that dotted name, or any name ending in `.pkg.fn`.\n"
            "- `fn` matches any call whose last segment is `fn` (`obj.fn(...)`, `a.b.fn(...)`).\n"
            "- `builtins.fn` matches only the bare call `fn(...)`.\n\nNames are resolved through imports and aliases before matching.",
            "## VQL queries (`queries/*.vql`)\n\nA declarative `from … where … select` query over the program database. Lines starting with `//` "
            "or `#` are comments; `// @tag value` lines are the rule's metadata.\n\n" + vql_example + "\n\n### Metadata\n\n" + meta
            + "\n\n### Relations\n\n" + relations
            + "\n\nThe `flow` relation holds the taint flows the data-flow engine computed, so a query can refine or re-rank them.\n\n"
            "### Operators\n\n`=` `!=` `<` `>` `<=` `>=`, `matches` (regular expression, search), `contains` (substring), `in (…)`, `and` `or` "
            "`not`, parentheses, and `+` to concatenate strings in `select`. The first `select` item is the location (a variable); the rest is "
            "the message.\n\n### Predicates, classes and aggregates\n\nUser-defined predicates (recursive, Datalog-style, evaluated to a "
            "fixpoint), classes with a characteristic predicate and member predicates, and the aggregates `count` `strictcount` `sum` `max` "
            "`min` `avg` plus the quantifiers `exists` / `any`.\n\n" + vql_advanced,
            "## Fixtures and annotations\n\nPut vulnerable and safe examples under `fixtures/`. Accepted comment markers: `#` `//` `--` `/*` "
            "`<!--`.\n\n" + annotations
            + "\n\n- `expect A, B`: every id (a rule id or `CWE-89`) must be reported on the line.\n- `expect-none`: no finding at all on the "
            "line; `expect-none A`: only `A` is forbidden.\n- `expect-todo A`: a known gap; it never fails the run and is flagged once it "
            "starts being reported.\n- A comment-only line speaks about the next line of code; annotations can be stacked.\n"
            "- Text after ` -- ` or in parentheses is a free comment.\n- A line without annotation must not be reported by the pack's own "
            "rules (scope `pack`). With `--scope all` every finding of every rule must be annotated.",
            "## The test runner\n\n`test` scans the fixtures with the pack's models and queries and compares the findings with the "
            "expectations. It prints PASS/FAIL per fixture and a diff per line: `-` an expected finding that was not reported (with the nearby "
            "lines where the rule did fire, to spot off-by-one annotations), `+` an unexpected finding. Exit codes: 0 all expectations met, 1 "
            "failures, 2 the run could not happen (broken model or query, no fixtures). `--junit FILE` writes JUnit XML; `--json` prints JSON.",
            "## Lint\n\n" + codes + "\n\nErrors fail the lint (exit code 1); warnings do not. `--allow-monolingual` downgrades a missing second "
            "language to a warning.",
            f"## Packing and sharing\n\n`pack` produces one file, `<name>-<version>{PACK_EXT}` (a zip with fixed timestamps and order), holding a `MANIFEST.json` "
            "with every file's size and SHA-256, and prints the SHA-256 of the archive to publish next to it. `install` checks that hash "
            "(`--sha256`), validates every path (no absolute path, no `..`, no symlink, nothing outside the pack layout), enforces size caps "
            f"({MAX_ARCHIVE_BYTES // (1024 * 1024)} MB archive, {MAX_FILE_BYTES // (1024 * 1024)} MB per file, "
            f"{MAX_TOTAL_BYTES // (1024 * 1024)} MB unpacked, {MAX_ENTRIES} entries) and lints the pack before moving it into the packs "
            "directory. A hash proves integrity, not authorship: obtain it through a channel you trust. Nothing in a pack is executed, but "
            "its rules are detection logic you decide to trust: a pack can declare sanitizers (which silence findings) and regular "
            "expressions (which can be slow), so read a third-party pack before relying on it in a gate.",
        ]
    return "\n\n".join(parts) + "\n"


# ========================================================================================================== CLI
def _emit(text: str, stream=None) -> None:
    stream = stream or sys.stdout
    # pack metadata and file names are untrusted: no escape sequence or bidi override reaches the terminal
    text = _CONTROL_RX.sub("?", text)
    try:
        stream.write(text if text.endswith("\n") else text + "\n")
    except UnicodeEncodeError:                 # legacy consoles that cannot print Arabic
        enc = getattr(stream, "encoding", None) or "ascii"
        stream.write((text if text.endswith("\n") else text + "\n").encode(enc, "replace").decode(enc))


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _warn_origin(lang: str, sha: str) -> None:
    """Without --sha256 only the archive's own manifest was checked: say so, with the hash to compare by hand."""
    _emit(f"{_t(lang, 'warning')}: " + _t(lang, "w_origin", sha=sha), sys.stderr)


# --help in English and Arabic ("both": the Arabic line, then the English line; see vulnscan/i18n/cliargs.py)
_HELP = {
    "en": {
        "desc": "Kashif rule-authoring kit: scaffold, test, lint, pack and install rule packs.",
        "lang": "language of the output: en or ar (default: VULNSCAN_LANG or KASHIF_LANG, else en)",
        "new": "create a rule pack from a template",
        "dir": "directory of the new pack",
        "name": "pack name (default: the directory name)",
        "language": "language of the example fixtures",
        "new_force": "write into a non-empty directory",
        "test": "run the annotated fixtures of a pack",
        "pack_dir": "rule pack directory (omit to test the built-in rules with --fixtures)",
        "fixtures": "fixtures directory or file (default: PACK/fixtures)",
        "scope": "pack: only the pack's rules may be 'unexpected' (default); all: every finding must be annotated",
        "no_builtin": "do not run the built-in VQL queries",
        "junit": "also write a JUnit XML report",
        "json": "print the report as JSON",
        "verbose": "also list the expectations that were met",
        "quiet": "print nothing; use the exit code",
        "lint": "validate a rule pack",
        "lint_pack": "rule pack directory",
        "monolingual": "a missing English or Arabic text is a warning, not an error",
        "pack": "bundle a rule pack into one {ext} file",
        "pack_output": "output file or directory",
        "no_lint": "pack even when lint reports errors",
        "sha_file": "also write FILE.sha256 (sha256sum format)",
        "verify": "check a {ext} file without installing it",
        "archive": "the {ext} file",
        "sha256": "expected SHA-256 of the archive",
        "install": "safely unpack a {ext} file into the packs directory",
        "packs_dir": "where packs are installed (default: the Kashif home directory)",
        "require_sha": "refuse to install without --sha256 (default: on when KASHIF_REQUIRE_PACK_SHA256=1)",
        "install_force": "replace an installed pack of the same name",
        "remove": "delete an installed pack",
        "remove_name": "name of the installed pack",
        "list": "list the installed packs",
        "list_json": "print the list as JSON",
        "docs": "print the rule language reference (Markdown)",
        "commands": "commands",
    },
    "ar": {
        "desc": "عُدّة كتابة القواعد في كاشِف: إنشاء حزم القواعد واختبارها وفحصها وحزمها وتثبيتها.",
        "lang": "لغة المخرجات: en أو ar (الافتراضي: VULNSCAN_LANG أو KASHIF_LANG، وإلا en)",
        "new": "أنشئ حزمة قواعد من قالب",
        "dir": "مجلد الحزمة الجديدة",
        "name": "اسم الحزمة (الافتراضي: اسم المجلد)",
        "language": "لغة ملفات الاختبار النموذجية",
        "new_force": "اكتب في مجلد غير فارغ",
        "test": "شغّل ملفات الاختبار الموسومة في حزمة",
        "pack_dir": "مجلد حزمة القواعد (أغفله لاختبار القواعد المدمجة مع --fixtures)",
        "fixtures": "مجلد ملفات الاختبار أو ملف واحد (الافتراضي: PACK/fixtures)",
        "scope": "pack: قواعد الحزمة وحدها يمكن أن تكون «غير متوقعة» (الافتراضي)؛ all: كل نتيجة يجب أن تكون موسومة",
        "no_builtin": "لا تشغّل استعلامات VQL المدمجة",
        "junit": "اكتب أيضًا تقرير JUnit XML",
        "json": "اطبع التقرير بصيغة JSON",
        "verbose": "اعرض أيضًا التوقعات التي تحققت",
        "quiet": "لا تطبع شيئًا؛ استخدم رمز الخروج",
        "lint": "تحقّق من صحة حزمة قواعد",
        "lint_pack": "مجلد حزمة القواعد",
        "monolingual": "غياب النص الإنجليزي أو العربي تحذير لا خطأ",
        "pack": "اجمع حزمة قواعد في ملف {ext} واحد",
        "pack_output": "ملف الإخراج أو مجلده",
        "no_lint": "احزم حتى لو وجد الفحص أخطاء",
        "sha_file": "اكتب أيضًا FILE.sha256 (بصيغة sha256sum)",
        "verify": "افحص ملف {ext} دون تثبيته",
        "archive": "ملف {ext}",
        "sha256": "قيمة SHA-256 المتوقعة للأرشيف",
        "install": "فُكّ ملف {ext} بأمان في مجلد الحزم",
        "packs_dir": "مكان تثبيت الحزم (الافتراضي: مجلد كاشِف في مجلد المستخدم)",
        "require_sha": "ارفض التثبيت دون --sha256 (مفعّل افتراضيًا إذا كان KASHIF_REQUIRE_PACK_SHA256=1)",
        "install_force": "استبدل حزمة مثبّتة بالاسم نفسه",
        "remove": "احذف حزمة مثبّتة",
        "remove_name": "اسم الحزمة المثبّتة",
        "list": "اعرض الحزم المثبّتة",
        "list_json": "اطبع القائمة بصيغة JSON",
        "docs": "اطبع مرجع لغة القواعد (Markdown)",
        "commands": "الأوامر",
    },
}


def _parser(lang: str = "en") -> argparse.ArgumentParser:
    """The ``kashif rules`` parser; ``lang`` (en, ar or both) is the language of its help texts."""
    from .i18n.cliargs import HelpFormatter, pick

    def h(key: str) -> str:
        return pick(lang, _HELP["ar"][key].format(ext=PACK_EXT), _HELP["en"][key].format(ext=PACK_EXT))

    common = argparse.ArgumentParser(add_help=False)
    # SUPPRESS: the option is accepted before and after the sub-command without one default hiding the other
    common.add_argument("--lang", choices=("en", "ar", "both"), default=argparse.SUPPRESS, metavar="{en,ar}",
                        help=h("lang"))
    ap = argparse.ArgumentParser(prog="kashif rules", parents=[common], description=h("desc"),
                                 formatter_class=HelpFormatter)
    title = {"ar": _HELP["ar"]["commands"], "en": _HELP["en"]["commands"]}.get(
        lang, f'{_HELP["ar"]["commands"]} / {_HELP["en"]["commands"]}')      # a heading: one line, as argparse's
    sub = ap.add_subparsers(dest="cmd", metavar="COMMAND", title=title)

    def command(name: str, key: str):
        return sub.add_parser(name, parents=[common], help=h(key), description=h(key), formatter_class=HelpFormatter)

    p = command("new", "new")
    p.add_argument("dir", help=h("dir"))
    p.add_argument("--name", help=h("name"))
    p.add_argument("--language", default="python", choices=SCAFFOLD_LANGUAGES, help=h("language"))
    p.add_argument("--force", action="store_true", help=h("new_force"))
    p = command("test", "test")
    p.add_argument("pack", nargs="?", help=h("pack_dir"))
    p.add_argument("--fixtures", help=h("fixtures"))
    p.add_argument("--scope", choices=("pack", "all"), default="pack", help=h("scope"))
    p.add_argument("--no-builtin-queries", action="store_true", help=h("no_builtin"))
    p.add_argument("--junit", metavar="FILE", help=h("junit"))
    p.add_argument("--json", action="store_true", help=h("json"))
    p.add_argument("-v", "--verbose", action="store_true", help=h("verbose"))
    p.add_argument("-q", "--quiet", action="store_true", help=h("quiet"))
    p = command("lint", "lint")
    p.add_argument("pack", help=h("lint_pack"))
    p.add_argument("--allow-monolingual", action="store_true", help=h("monolingual"))
    p.add_argument("--json", action="store_true", help=h("json"))
    p = command("pack", "pack")
    p.add_argument("pack", help=h("lint_pack"))
    p.add_argument("-o", "--output", help=h("pack_output"))
    p.add_argument("--no-lint", action="store_true", help=h("no_lint"))
    p.add_argument("--sha256-file", action="store_true", help=h("sha_file"))
    p = command("verify", "verify")
    p.add_argument("archive", help=h("archive"))
    p.add_argument("--sha256", help=h("sha256"))
    p = command("install", "install")
    p.add_argument("archive", help=h("archive"))
    p.add_argument("--packs-dir", help=h("packs_dir"))
    p.add_argument("--sha256", help=h("sha256"))
    p.add_argument("--require-sha256", action="store_true", default=_env_flag("KASHIF_REQUIRE_PACK_SHA256"),
                   help=h("require_sha"))
    p.add_argument("--force", action="store_true", help=h("install_force"))
    p = command("remove", "remove")
    p.add_argument("name", help=h("remove_name"))
    p.add_argument("--packs-dir", help=h("packs_dir"))
    p = command("list", "list")
    p.add_argument("--packs-dir", help=h("packs_dir"))
    p.add_argument("--json", action="store_true", help=h("list_json"))
    command("docs", "docs")
    return ap


def main(argv=None) -> int:
    """Command-line entry point. Returns 0 (ok), 1 (failing tests / lint errors) or 2 (usage, I/O or pack error)."""
    from .i18n.cliargs import help_lang, lang_from_env, localized_argparse
    argv = list(sys.argv[1:] if argv is None else argv)
    env = lang_from_env() or "en"                  # VULNSCAN_LANG, then KASHIF_LANG
    hlang = help_lang(argv, default=env)           # --help and usage errors follow --lang (en, ar or both)
    try:
        with localized_argparse(hlang):
            ap = _parser(hlang)
            args = ap.parse_args(argv)
            if not args.cmd:
                ap.print_help()
                return 2
    except SystemExit as e:
        return int(e.code or 0) if isinstance(e.code, int) else 2
    L = "ar" if getattr(args, "lang", env) == "ar" else "en"    # "both": English messages, as from a "both" scan
    try:
        if args.cmd == "new":
            dest = new_pack(args.dir, args.name, args.language, force=args.force, lang=L)
            _emit(_t(L, "created", name=locate(dest).name, path=str(dest)))
            _emit(_t(L, "next_steps", path=str(dest)))
            return 0
        if args.cmd == "test":
            if not args.pack and not args.fixtures:
                _emit(_t(L, "error") + ": " + _t(L, "no_fixtures", path="--fixtures"), sys.stderr)
                return 2
            rep = run_tests(args.pack, args.fixtures, scope=args.scope, builtin_queries=not args.no_builtin_queries, lang=L)
            if args.junit:
                pathlib.Path(args.junit).write_text(rep.to_junit(), encoding="utf-8")
            if args.json:
                _emit(json.dumps(rep.to_dict(), ensure_ascii=False, indent=2))
            elif not args.quiet:
                _emit(rep.to_text(verbose=args.verbose))
            return rep.exit_code
        if args.cmd == "lint":
            rep = lint_pack(args.pack, lang=L, allow_monolingual=args.allow_monolingual)
            _emit(json.dumps(rep.to_dict(), ensure_ascii=False, indent=2) if args.json else rep.to_text())
            return rep.exit_code
        if args.cmd == "pack":
            res = build_pack(args.pack, args.output, lint=not args.no_lint, lang=L)
            if args.sha256_file:
                pathlib.Path(str(res.path) + ".sha256").write_text(f"{res.sha256}  {res.path.name}\n", encoding="utf-8")
            _emit(_t(L, "packed", name=res.manifest["name"], version=res.manifest["version"], path=str(res.path),
                     files=len(res.manifest["files"]), size=res.path.stat().st_size, sha=res.sha256))
            return 0
        if args.cmd == "verify":
            m = verify_pack(args.archive, args.sha256, lang=L)
            _emit(_t(L, "verified", name=m["name"], version=m["version"], files=len(m["files"]), sha=m["archive_sha256"]))
            if not args.sha256:
                _warn_origin(L, m["archive_sha256"])
            return 0
        if args.cmd == "install":
            if not args.sha256 and args.require_sha256:
                m = verify_pack(args.archive, None, lang=L)       # in memory only: nothing is written
                raise PackError(_t(L, "e_sha_required", sha=m["archive_sha256"]))
            res = install_pack(args.archive, args.packs_dir, sha256=args.sha256, force=args.force, lang=L)
            _emit(_t(L, "installed", name=res.name, version=res.version, path=str(res.path), sha=res.sha256,
                     models=str(res.models_dir), queries=str(res.queries_dir)))
            if not args.sha256:
                _warn_origin(L, res.sha256)
            for w in res.warnings:
                _emit(f"{_t(L, 'warning')}: {w}")
            return 0
        if args.cmd == "remove":
            target = remove_pack(args.name, args.packs_dir, lang=L)
            _emit(_t(L, "removed", name=args.name, path=str(target.parent)))
            return 0
        if args.cmd == "list":
            packs = installed_packs(args.packs_dir)
            if args.json:
                _emit(json.dumps(packs, ensure_ascii=False, indent=2))
            elif not packs:
                _emit(_t(L, "no_packs", path=str(args.packs_dir or default_packs_dir())))
            for p in packs if not args.json else []:
                desc = p.get("description_ar") if L == "ar" and p.get("description_ar") else p.get("description", "")
                _emit(_t(L, "pack_row", name=p.get("name", ""), version=p.get("version", ""), rules=len(p.get("rules", [])),
                         description=desc))
            return 0
        if args.cmd == "docs":
            _emit(rules_reference(L))
            return 0
    except PackError as e:
        _emit(f"{_t(L, 'error')}: {e}", sys.stderr)
        return 2
    except OSError as e:
        _emit(f"{_t(L, 'error')}: {e}", sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
