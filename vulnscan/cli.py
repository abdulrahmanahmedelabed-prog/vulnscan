"""Command line interface."""

from __future__ import annotations

import argparse
import locale
import os
import pathlib
import sys
from datetime import datetime, timezone

from . import __version__
from .deps import audit_dependencies
from .external import run_external
from .i18n import localize, to_en
from .i18n.cliargs import RawDescriptionHelpFormatter as _HelpFormatter, lang_from_env, localized_argparse, pick, \
    usage_prefix
from .i18n.plural import ar_count
from .model import SEVERITIES, SEVERITY_RANK, Finding, assign_fingerprints, sort_findings
from .report import render_console, render_html, render_json, render_markdown, render_sarif, summary_counts
from .baseline import apply_baseline, load_baseline, save_baseline
from .exporters import FORMATS as EXPORT_FORMATS
from .rules import RULES
from .scanner import scan_path
from .web import WebUnreachable, scan_site  # noqa: F401 - scan_site: kept for callers of 1.0.x (cli.scan_site)

AUTHORIZATION_NOTICE = (
    "افحص فقط ما تملكه أو ما لديك تصريح كتابي بفحصه. "
    "فحص أنظمة الآخرين دون إذن قد يكون مخالفًا للقانون."
)


LANG_CHOICES = ("auto", "ar", "en", "both")
REPORT_FORMATS = ("console", "markdown", "json", "html", "sarif")      # rendered by report.py
SCAN_FORMATS = REPORT_FORMATS + tuple(EXPORT_FORMATS)                   # + every format of exporters.py

# Sub-commands: name -> one-line description (Arabic; the English is in i18n/cat_cli.py). Shown by `kashif --help`.
SUBCOMMANDS = {
    "ui": "تشغيل الواجهة الرسومية المحلية (لوحة تحكم، فحص، تقارير، إعدادات).",
    "lsp": "خادم لغة (LSP) للمحررات: الثغرات تحت الكود أثناء الكتابة مع إصلاحات سريعة",
    "mcp": "خادم MCP لمساعدات البرمجة بالذكاء الاصطناعي (Claude Code وCursor وVS Code وWindsurf وZed)",
    "update": "تحديث كاشِف إلى أحدث إصدار رسمي بعد التحقق منه (--check للتحقق فقط)",
    "export": "تحويل تقرير JSON إلى صيغة أداة أخرى (DefectDojo وSonarQube وJUnit وCSV وJira وGitLab وASFF وOCSF)",
    "compliance": "ربط النتائج بأطر الامتثال (OWASP وASVS وCWE Top 25 وPCI DSS وNIST وISO 27001) وتقرير للمدقق",
    "history": "الأسرار في تاريخ git: كل سرّ أُودِع يومًا ولو حُذف لاحقًا (الاسم البديل secrets-history)",
    "triage": "فرز النتائج داخل المستودع: إنذار كاذب أو قبول خطر أو لن يُصلَح، مع سجل تدقيق ومهلة إصلاح",
    "policy": "السياسة ككود: بوابة أمان من kashif.yml (check وinit وvalidate وpresets)",
    "surface": "خريطة سطح الهجوم: نقاط الدخول ومدخلاتها والمصادقة الظاهرة والمصارف التي تصل إليها",
    "rules": "اكتب قواعدك واختبرها: حزم القواعد (new وtest وlint وpack وverify وinstall وlist وdocs)",
    "update-data": "تحديث بيانات فاحص المواقع (--web) من آخر إصدار رسمي لكاشِف بعد التحقق منها",
}
# English of sub-command descriptions added after the i18n catalogue (1.1.0); the rest come from to_en().
_SUBCOMMANDS_EN = {
    "update-data": "update the web scanner's data (--web) from the latest official Kashif release, after verifying it",
}

# 1.1.0 passive web scanning options (spec §4.5): help and messages in Arabic and English.
WEB_PROFILES = ("minimal", "standard", "deep")
WEB_SENSITIVITIES = ("strict", "default", "paranoid")
# Requests a profile may send, crawl pages excluded (spec §0.1): the entry chain, standard and deep budgets
WEB_BUDGET = {"minimal": 10, "standard": 45, "deep": 150}
_WEB_HELP = {
    "ar": {
        "deep": "فحص ويب أعمق (يساوي --web-profile deep): ملفات مكشوفة شائعة من قائمة ثابتة مع خطوط أساس لصفحات 404، "
                "وسكربتات الأطراف الثالثة وخرائط المصدر (150 طلبًا على الأكثر، عدا صفحات الزحف)",
        "crawl": "زحف على صفحات الموقع من نفس النطاق وفحصها مع احترام robots.txt (لتطبيقات مثل Moodle وبوابات الجامعات)",
        "delay": "أقل فاصل بالثواني بين طلبين إلى المضيف نفسه، لكل الطلبات (الافتراضي 0.5، والحد الأدنى 0.2)",
        "profile": "ملف الفحص السلبي: minimal طلب الصفحة وتوجيهاتها فقط (10 طلبات على الأكثر)، standard (الافتراضي) "
                   "يضيف نسخة http/https وطلب CORS واحدًا والملفات المعروفة وسكربتات الصفحة (45 طلبًا على الأكثر)، "
                   "deep يضيف الملفات المكشوفة الشائعة (150 طلبًا على الأكثر)",
        "sensitivity": "الحساسية: strict النتائج المؤكَّدة فقط، default (الافتراضي) المؤكَّدة والمرجَّحة، paranoid كل شيء "
                       "مع الفحوص الخاصة بهذا المستوى",
        "ignore_robots": "تجاهل robots.txt عند الزحف (لمالك الموقع فقط)",
        "third_party": "اسمح باستعلامات لدى أطراف ثالثة تكشف اسم الموقع (مثل hstspreload.org)؛ معطّلة افتراضيًا",
        "compare_previous": "قارن بآخر فحص محفوظ لهذا الموقع (في سجل الفحوص المحلي) واحفظ هذا الفحص فيه: "
                            "نتائج جديدة ومحلولة وتغيّر الدرجات وتغييرات الوضع الأمني",
        "compare": "قارن بفحص سابق: معرّف فحص محفوظ في السجل المحلي، أو ملف تقرير JSON من كاشِف",
        "cookie_ignore": "تجاهل كوكي بهذا الاسم في فحوص الكوكيز (يمكن تكراره)",
        "no_proxy": "لا تستخدم الوكيل (HTTP(S)_PROXY) حتى لو كان معرَّفًا في البيئة",
        "web_only": "الخيار {opt} يعمل مع عناوين الويب http(s):// فقط",
        "deep_conflict": "الخيار --deep يعني --web-profile deep؛ لا تجمعه مع --web-profile {profile}",
        "compare_both": "استخدم --compare أو --compare-previous، لا كليهما",
        "compare_missing": "لم يُعثر على الفحص السابق المطلوب للمقارنة (معرّف أو ملف): {what}",
        "compare_bad": "الملف المطلوب للمقارنة ليس تقرير فحص ويب من كاشِف 1.1 (لا لقطة web.snapshot فيه): {what}",
        "no_previous": "لا يوجد فحص سابق محفوظ لهذا الموقع؛ حُفظ هذا الفحص لتُقارن به الفحوص القادمة.",
        "saved": "حُفظ الفحص في السجل المحلي (المعرّف {id}).",
        "budget": "ملف الفحص {profile}: {requests} على الأكثر{crawl}، بلا أي اختبار نشط.",
        "budget_crawl": " إضافةً إلى {pages} من الزحف",
        "ud_desc": "تحديث بيانات فاحص المواقع (مكتبات JavaScript المصابة، وقوائم HSTS والنطاقات العامة، والتقنيات) "
                   "من حزمة آخر إصدار رسمي لكاشِف، بعد التحقق من بصمتها SHA-256. لا يُرسل شيء عن المواقع التي تفحصها.",
        "ud_web": "حدّث بيانات فحص المواقع",
        "ud_check": "تحقّق من وجود بيانات أحدث دون تنزيلها",
        "ud_what": "حدّد ما يُراد تحديثه: --web",
        "ud_path": "المجلد: {path}",
    },
    "en": {
        "deep": "deeper web scan (same as --web-profile deep): a fixed list of commonly exposed files with 404 baselines, "
                "third-party scripts and source maps (at most 150 requests, crawled pages excluded)",
        "crawl": "crawl same-site pages and scan each one, honouring robots.txt (for apps such as Moodle and university "
                 "portals)",
        "delay": "minimum gap in seconds between two requests to one host, for every request (default 0.5, floor 0.2)",
        "profile": "passive scan profile: minimal fetches the page and its redirects only (at most 10 requests), standard "
                   "(default) adds the http/https counterpart, one CORS GET, the well-known files and the page's own "
                   "scripts (at most 45 requests), deep adds commonly exposed files (at most 150 requests)",
        "sensitivity": "sensitivity: strict shows certain findings only, default (the default) certain and firm, paranoid "
                       "everything, including the paranoid-only checks",
        "ignore_robots": "ignore robots.txt when crawling (for the site's owner only)",
        "third_party": "allow third-party lookups that reveal the site's name (such as hstspreload.org); off by default",
        "compare_previous": "compare with the last saved scan of this site (in the local scan history) and save this "
                            "scan there: new and resolved findings, grade changes and posture changes",
        "compare": "compare with an earlier scan: a scan id from the local history, or a Kashif JSON report file",
        "cookie_ignore": "ignore the cookie of this name in the cookie checks (repeatable)",
        "no_proxy": "do not use a proxy (HTTP(S)_PROXY) even when the environment sets one",
        "web_only": "{opt} applies to http(s):// web targets only",
        "deep_conflict": "--deep means --web-profile deep; do not combine it with --web-profile {profile}",
        "compare_both": "use --compare or --compare-previous, not both",
        "compare_missing": "the earlier scan to compare with was not found (id or file): {what}",
        "compare_bad": "the file to compare with is not a Kashif 1.1 web scan report (it has no web.snapshot): {what}",
        "no_previous": "No earlier saved scan of this site; this scan was saved so the next ones can compare with it.",
        "saved": "Scan saved in the local history (id {id}).",
        "budget": "Profile {profile}: at most {requests}{crawl}; no active test.",
        "budget_crawl": " plus up to {pages} crawled",
        "ud_desc": "Update the web scanner's data (vulnerable JavaScript libraries, HSTS preload and public suffix lists, "
                   "technologies) from the package of the latest official Kashif release, after verifying its SHA-256. "
                   "Nothing about the sites you scan is sent.",
        "ud_web": "update the web scanning data",
        "ud_check": "check for newer data without downloading it",
        "ud_what": "say what to update: --web",
        "ud_path": "folder: {path}",
    },
}
_REQUESTS_AR = ("طلب واحد", "طلبان", "{n} طلبات", "{n} طلبًا", "{n} طلب")
_PAGES_AFTER_PREP = ("صفحة واحدة", "صفحتين", "{n} صفحات", "{n} صفحةً", "{n} صفحة")


def _wh(key: str, lang: str, **kw) -> str:
    """A 1.1.0 web text: Arabic, English, or for "both" the Arabic line then the English line."""
    ar, en = _WEB_HELP["ar"][key], _WEB_HELP["en"][key]
    if kw:
        ar, en = ar.format(**kw), en.format(**kw)
    return pick(lang, ar, en)


def web_budget_note(profile: str, crawl: bool = False, max_pages: int = 20) -> tuple[str, str]:
    """(Arabic, English) note stating the profile's real request budget (spec §0.1) instead of 1.0's "one request"."""
    n = WEB_BUDGET.get(profile, WEB_BUDGET["standard"])
    ar = _WEB_HELP["ar"]["budget"].format(
        profile=profile, requests=ar_count(n, _REQUESTS_AR),
        crawl=_WEB_HELP["ar"]["budget_crawl"].format(pages=ar_count(max_pages, _PAGES_AFTER_PREP)) if crawl else "")
    en = _WEB_HELP["en"]["budget"].format(
        profile=profile, requests=f"{n} request{'s' if n != 1 else ''}",
        crawl=_WEB_HELP["en"]["budget_crawl"].format(pages=f"{max_pages} page{'s' if max_pages != 1 else ''}") if crawl else "")
    return ar, en
# Sub-commands that forward their arguments to the module's own main(argv): name -> module of this package.
DELEGATES = {"mcp": "mcp", "export": "exporters", "compliance": "compliance", "history": "history",
             "secrets-history": "history", "triage": "triage", "policy": "policy", "surface": "surface",
             "rules": "ruletest"}
# Delegates whose --lang also takes "both": their --help and usage errors are then Arabic and English, like
# `kashif --help`; their reports and messages are English under "both", as the add-on outputs of a scan are
# (exports, --compliance, the policy explanation). The other delegates take en|ar, so "both" means English there.
BOTH_LANG = frozenset({"mcp", "export", "compliance", "triage", "policy", "history", "secrets-history", "surface",
                       "rules"})


def _is_arabic_locale(environ=None) -> bool:
    env = os.environ if environ is None else environ
    names = [env.get(k, "") for k in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE")]
    try:
        names.append(locale.getlocale()[0] or "")
    except (ValueError, TypeError):
        pass
    return any(n.lower().startswith("ar") for n in names if n)


def resolve_lang(value: str | None = "auto", environ=None) -> str:
    """The output language: "ar", "en" or "both".

    An explicit --lang wins; "auto" uses the VULNSCAN_LANG (or else KASHIF_LANG) environment variable when set,
    else "ar" on an Arabic system locale, else "both" (today's bilingual output: nobody is switched to English-only
    silently)."""
    if value in ("ar", "en", "both"):
        return value
    env = os.environ if environ is None else environ
    from_env = lang_from_env(env)
    if from_env:
        return from_env
    return "ar" if _is_arabic_locale(env) else "both"


def _lang_from_argv(argv: list[str]) -> str:
    """Resolve --lang before the parser exists, so --help itself can be shown in English."""
    value = None
    for i, a in enumerate(argv):
        if a == "--lang" and i + 1 < len(argv):
            value = argv[i + 1]
        elif a.startswith("--lang="):
            value = a.split("=", 1)[1]
    return resolve_lang(value)


def _subcommand_help(lang: str = "both") -> str:
    """The sub-command list printed under `kashif --help` (Arabic, English, or Arabic with English for "both")."""
    def desc(text: str, indent: str = "", en: str | None = None) -> str:
        en = en or to_en(text)
        if lang == "en":
            return en
        return text if lang == "ar" else f"{text}\n{indent}{en}"
    pad = " " * 15
    lines = [desc("الأوامر الفرعية:")]
    lines += [f"  {name:<12} {desc(text, pad, _SUBCOMMANDS_EN.get(name))}" for name, text in SUBCOMMANDS.items()]
    lines += ["", desc("شغّل kashif <أمر فرعي> --help لعرض خياراته.")]
    return "\n".join(lines)


def _forward_lang(argv: list[str], after_command: bool = False, both: bool = False) -> list[str]:
    """Arguments for a sub-command module, whose --lang takes en or ar (and "both" when ``both`` is true): an
    explicit --lang is kept unless the module cannot take it ("both"/"auto" are dropped then), and without one the
    language Kashif resolved (VULNSCAN_LANG or KASHIF_LANG, then the system locale, else "both") is appended when the module takes
    it, so `kashif <sub-command>` speaks the same language as a scan.

    after_command: --lang is moved right after the module's own command word (`kashif policy check --lang ar`); with
    no command word it stays at the end only when ``both`` is true (the module then also takes it there), else it
    is left out (`kashif policy` alone must report the missing command, not "invalid choice: 'ar'")."""
    if "--scan-worker" in argv:
        return list(argv)
    accepted = ("ar", "en", "both") if both else ("ar", "en")
    cut = argv.index("--") if "--" in argv else len(argv)
    head, tail = argv[:cut], argv[cut:]
    out: list[str] = []
    explicit = False
    i = 0
    while i < len(head):
        a = head[i]
        if a == "--lang" and i + 1 < len(head):
            if head[i + 1] in accepted:
                out += [a, head[i + 1]]
                explicit = True
            elif head[i + 1] not in ("both", "auto"):
                out += [a, head[i + 1]]             # let the module report the invalid value
                explicit = True
            i += 2
            continue
        if a.startswith("--lang="):
            if a[7:] in accepted or a[7:] not in ("both", "auto"):
                out.append(a)
                explicit = True
            i += 1
            continue
        out.append(a)
        i += 1
    if not explicit:
        lang = resolve_lang("auto")
        if lang in accepted:
            out += ["--lang", lang]
    if after_command:
        lang_args: list[str] = []
        rest: list[str] = []
        i = 0
        while i < len(out):
            if out[i] == "--lang" and i + 1 < len(out):
                lang_args, i = out[i:i + 2], i + 2
                continue
            if out[i].startswith("--lang="):
                lang_args = [out[i]]
            else:
                rest.append(out[i])
            i += 1
        cmd = next((k for k, a in enumerate(rest) if not a.startswith("-")), None)
        if cmd is None:
            out = rest + (lang_args if both else [])
        else:
            out = rest[:cmd + 1] + lang_args + rest[cmd + 1:]
    return out + tail


_HELP_FLAGS = ("-h", "--help")


def _mcp_args(argv: list[str]) -> list[str]:
    """`kashif mcp`: the server's language stays its own choice (--lang, else VULNSCAN_LANG or KASHIF_LANG, else English: what
    the assistant reads); only --help follows the language Kashif resolved, like every other sub-command."""
    head = argv[:argv.index("--")] if "--" in argv else argv
    if any(a in _HELP_FLAGS for a in head) and not any(a == "--lang" or a.startswith("--lang=") for a in head):
        return list(argv) + ["--lang", resolve_lang("auto")]
    return list(argv)


def _module_lang(args: list[str]) -> str:
    """The language a sub-command module will speak with these (forwarded) arguments; English without --lang."""
    from .i18n.cliargs import help_lang
    return help_lang(args, default="en")


def run_subcommand(name: str, argv: list[str]) -> int:
    """`kashif <name> ...`: forward to the module's own command line (see DELEGATES)."""
    import importlib
    module = importlib.import_module(f".{DELEGATES[name]}", __package__)
    # mcp: the assistant's language, see mcp.py; policy: --lang belongs to its commands (check, init, ...)
    if name == "mcp":
        args = _mcp_args(list(argv))
    else:
        args = _forward_lang(list(argv), after_command=name == "policy", both=name in BOTH_LANG)
    hlang = _module_lang(args)
    if name == "mcp" and not any(a == "--lang" or a.startswith("--lang=") for a in args):
        hlang = resolve_lang("auto")                # usage errors follow Kashif's language, as --help does
    if name == "compliance" and _compliance_input_missing(module, args, hlang):
        return 2
    try:
        with localized_argparse(hlang):             # argparse's own headings and errors, in that language
            code = module.main(args)
        sys.stdout.flush()                          # a closed pipe surfaces here, not at interpreter exit (120)
    except SystemExit as e:                         # argparse inside the module (--help, usage errors)
        code = e.code if isinstance(e.code, int) else (0 if e.code is None else 2)
    except OSError as e:                            # "kashif compliance r.json -f json | head": not an error
        if not _closed_pipe(e):
            raise
        _silence_stdout()
        code = 0
    return int(code or 0)


def _compliance_input_missing(module, args: list[str], hlang: str) -> bool:
    """`kashif compliance` without a report (and without --list-frameworks / --check-coverage): the usage and a
    message naming the missing report, exit 2 (the module itself prints the usage only)."""
    import contextlib
    import io
    if any(a in _HELP_FLAGS for a in args) or not hasattr(module, "_parser"):
        return False
    try:
        with localized_argparse(hlang), contextlib.redirect_stderr(io.StringIO()), \
                contextlib.redirect_stdout(io.StringIO()):
            ns = module._parser(hlang).parse_args(args)     # a usage error is left to the module to report
    except SystemExit:
        return False
    if getattr(ns, "input", None) or getattr(ns, "list_frameworks", False) or getattr(ns, "check_coverage", False):
        return False
    with localized_argparse(hlang):
        try:
            module._parser(hlang).error(_bi("تقرير الفحص المطلوب ربطه بأطر الامتثال غير محدَّد: kashif compliance "
                                            "REPORT.json (تقرير JSON أو SARIF؛ أنشئه بالأمر: kashif PATH -f json "
                                            "-o REPORT.json)", hlang))
        except SystemExit:
            pass
    return True


# Count phrases of the scan notes (stored in Arabic; their English is in i18n/cat_cli.py for every form).
_KNOWN_VULNS = ("ثغرة معروفة واحدة", "ثغرتان معروفتان", "{n} ثغرات معروفة", "{n} ثغرةً معروفةً", "{n} ثغرة معروفة")
_KNOWN_FINDINGS = ("نتيجة معروفة واحدة", "نتيجتان معروفتان", "{n} نتائج معروفة", "{n} نتيجةً معروفةً",
                   "{n} نتيجة معروفة")


def _say(lang: str, ar: str, en: str, **kw) -> str:
    """A console message: English for "en", else Arabic (as ``localize``); a field written ``{n:noun}`` prints the
    number with the noun that agrees with it (vulnscan/i18n/cliargs.py, NOUNS)."""
    from .i18n.cliargs import fmt
    return fmt(en, "en", **kw) if lang == "en" else fmt(ar, "ar", **kw)


def _bi(text: str, lang: str) -> str:
    """A message in ``lang``: Arabic, English, or for "both" the Arabic line then the English line."""
    return pick(lang, text, to_en(text))


def build_parser(lang: str = "both") -> argparse.ArgumentParser:
    def h(text: str) -> str:
        return _bi(text, lang)

    indent = " " * len(usage_prefix(lang))          # the second usage line under the first, after "usage: "
    p = argparse.ArgumentParser(
        prog="kashif",
        usage="kashif [options] TARGET\n" + indent + "kashif <sub-command> [options]   (" + ", ".join(SUBCOMMANDS) + ")",
        description=h("فحص أي برنامج (مجلد مصدر، ملف، أرشيف/APK/JAR، أو عنوان ويب) وإخراج تقرير مرتب من الأعلى خطورة إلى الأقل.")
                    + "\n" + h(AUTHORIZATION_NOTICE),
        epilog=_subcommand_help(lang),
        formatter_class=_HelpFormatter,
    )
    p.add_argument("target", nargs="?", help=h("مسار مجلد/ملف/أرشيف، أو عنوان http(s):// للفحص السلبي، أو «ui» لتشغيل الواجهة الرسومية"))
    p.add_argument("--authorized", action="store_true",
                   help=h("أقرّ بأنني مخوَّل بفحص هذا الهدف (إلزامي لفحص عناوين الويب)"))
    p.add_argument("-f", "--format", choices=SCAN_FORMATS, default="console", metavar="FORMAT",
                   help=h("صيغة التقرير: console أو markdown أو json أو html أو sarif (لـ GitHub Code Scanning وVS Code)، "
                          "أو صيغة تصدير: gitlab-sast وcodeclimate (GitLab) وdefectdojo وsonarqube وjunit وcsv "
                          "وjira-csv وgithub-issues وasff وocsf وrisk (القائمة: kashif export --list-formats)"))
    p.add_argument("--aws-account", metavar="ID",
                   help=h("لصيغة asff: رقم حساب AWS (12 رقمًا)، مع --aws-region"))
    p.add_argument("--aws-region", metavar="REGION",
                   help=h("لصيغة asff: منطقة AWS لـ Security Hub، مثل eu-west-1"))
    p.add_argument("-o", "--output", help=h("اكتب التقرير إلى هذا الملف بدلًا من الشاشة"))
    p.add_argument("--all-formats", metavar="PREFIX", help=h("اكتب PREFIX.md وPREFIX.json وPREFIX.html وPREFIX.sarif معًا"))
    p.add_argument("--export", action="append", default=[], metavar="FORMAT=FILE",
                   help=h("اكتب أيضًا الفحص بصيغة تصدير إلى ملف، مثل gitlab-sast=gl-sast-report.json (يمكن تكراره)"))
    p.add_argument("--risk-score", action="store_true",
                   help=h("اطبع درجة خطر كاشِف للمشروع (من 0 إلى 10؛ وسيلة لترتيب الأولويات وليست درجة CVSS)"))
    p.add_argument("--compliance", metavar="FRAMEWORKS",
                   help=h("اطبع بعد التقرير ملخص الامتثال لهذه الأطر (مفصولة بفواصل، أو all؛ القائمة: "
                          "kashif compliance --list-frameworks)"))
    p.add_argument("--audit-report", metavar="FILE",
                   help=h("اكتب تقرير المدقق (HTML قابل للطباعة) يربط كل نتيجة بضوابط أطر الامتثال"))
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help=h("استثنِ مسارات (يمكن تكراره)"))
    p.add_argument("--ignore-rule", action="append", default=[], metavar="ID", help=h("تجاهل قاعدة بمعرّفها"))
    p.add_argument("--min-severity", choices=SEVERITIES, default="info", help=h("اعرض هذه الخطورة فما فوق فقط"))
    p.add_argument("--fail-on", choices=SEVERITIES, help=h("أعد رمز خروج 1 إذا وُجدت نتيجة بهذه الخطورة أو أعلى (لـ CI)"))
    p.add_argument("--baseline", metavar="FILE", help=h("قارن مع خط أساس: اعرض النتائج الجديدة فقط (النتائج المعروفة تُكتم)"))
    p.add_argument("--write-baseline", metavar="FILE", help=h("احفظ بصمات النتائج الحالية في خط أساس ثم اخرج (لتبنّي الأداة على كود قائم)"))
    p.add_argument("--diff-base", metavar="REF",
                   help=h("افحص كل شيء لكن اعرض فقط النتائج على الأسطر المضافة أو المعدّلة منذ نقطة التفرّع مع REF "
                          "(أو التي يمرّ مسار بياناتها بها)؛ لطلبات الدمج"))
    p.add_argument("--diff-staged", action="store_true",
                   help=h("اعرض فقط النتائج على الأسطر المجهّزة للإيداع (git add) مقارنة بـ HEAD؛ لخطافات pre-commit"))
    p.add_argument("--fix", action="store_true",
                   help=h("طبّق الإصلاحات الآلية الآمنة على الملفات في مكانها ثم اعرض ملخصًا "
                          "(يرفض إذا كانت في شجرة git تغييرات غير مودَعة إلا مع --fix-force)"))
    p.add_argument("--fix-dry-run", action="store_true",
                   help=h("اعرض الإصلاحات الآلية كفروق موحّدة (unified diff) دون تعديل أي ملف"))
    p.add_argument("--fix-force", action="store_true",
                   help=h("طبّق --fix حتى لو كانت في شجرة git تغييرات غير مودَعة"))
    p.add_argument("--triage", nargs="?", const="", default=None, metavar="FILE",
                   help=h("طبّق قرارات الفرز (الافتراضي ‎.kashif/triage.json في المشروع): تُخفى الإنذارات الكاذبة "
                          "والمخاطر المقبولة من التقرير ومن --fail-on، ويُنبَّه على القبول المنتهي والارتداد"))
    p.add_argument("--triage-update", action="store_true",
                   help=h("احفظ في ملف الفرز ما تغيّر: أول ظهور والإصلاح التلقائي والارتداد وانتهاء القبول "
                          "(لـ CI على الفرع الرئيسي فقط، لا لطلبات الدمج)"))
    p.add_argument("--triage-show", default="open,confirmed", metavar="STATUSES",
                   help=h("حالات الفرز التي تبقى في التقرير (الافتراضي open,confirmed؛ all للجميع)"))
    p.add_argument("--sla", metavar="SPEC",
                   help=h("مهلة الإصلاح بالأيام لكل خطورة، مثل critical=7,high=30,medium=90 (مع --triage)"))
    p.add_argument("--fail-on-sla", action="store_true",
                   help=h("أعد رمز خروج 1 إذا تجاوزت نتيجة مفتوحة مهلة إصلاحها (مع --triage)"))
    p.add_argument("--policy", nargs="?", const="", default=None, metavar="FILE",
                   help=h("بوابة الأمان من ملف سياسة (kashif.yml) أو قالب مدمج مثل strict؛ يُطبَّق kashif.yml "
                          "الموجود في المجلد المفحوص تلقائيًا"))
    p.add_argument("--no-policy", action="store_true", help=h("لا تطبّق ملف السياسة الموجود في المجلد المفحوص"))
    p.add_argument("--policy-reports-dir", metavar="DIR",
                   help=h("مجلد التقارير التي يطلبها ملف السياسة (reports)؛ دونه لا تُكتب"))
    p.add_argument("--pack", action="append", default=[], metavar="NAME",
                   help=h("استخدم حزمة قواعد مثبّتة بهذا الاسم (يمكن تكراره؛ انظر kashif rules list)"))
    p.add_argument("--packs", action="store_true", help=h("استخدم كل حزم القواعد المثبّتة"))
    p.add_argument("--no-deps", action="store_true", help=h("لا تستعلم OSV.dev عن ثغرات الاعتماديات (دون إنترنت)"))
    p.add_argument("--no-external", action="store_true", help=h("لا تشغّل bandit/semgrep/gitleaks/npm حتى لو كانت مثبّتة"))
    p.add_argument("--deep", action="store_true", help=_wh("deep", lang))
    p.add_argument("--crawl", action="store_true", help=_wh("crawl", lang))
    p.add_argument("--max-pages", type=int, default=20, metavar="N", help=h("أقصى عدد صفحات عند الزحف (الافتراضي 20)"))
    p.add_argument("--delay", type=float, default=0.5, metavar="SEC", help=_wh("delay", lang))
    p.add_argument("--max-depth", type=int, default=2, metavar="N", help=h("أقصى عمق للزحف (الافتراضي 2)"))
    p.add_argument("--web-profile", choices=WEB_PROFILES, default=None, help=_wh("profile", lang))
    p.add_argument("--web-sensitivity", choices=WEB_SENSITIVITIES, default="default", help=_wh("sensitivity", lang))
    p.add_argument("--ignore-robots", action="store_true", help=_wh("ignore_robots", lang))
    p.add_argument("--third-party-lookups", action="store_true", help=_wh("third_party", lang))
    p.add_argument("--compare-previous", action="store_true", help=_wh("compare_previous", lang))
    p.add_argument("--compare", metavar="ID|FILE", help=_wh("compare", lang))
    p.add_argument("--web-cookie-ignore", action="append", default=[], metavar="NAME", help=_wh("cookie_ignore", lang))
    p.add_argument("--no-proxy", action="store_true", help=_wh("no_proxy", lang))
    p.add_argument("--timeout", type=float, default=20.0, metavar="SEC",
                   help=h("مهلة كل طلب ويب بالثواني (الافتراضي 20؛ يُعاد الطلب الأول مرة بمهلة مضاعفة)"))
    p.add_argument("--models", action="append", default=[], metavar="DIR",
                   help=h("مجلد (أو ملف JSON) نماذج إضافية لمحرّك تدفق البيانات: مصادر ونقاط خطر ومُعقّمات خاصة بمكتباتك"))
    p.add_argument("--query", action="append", default=[], metavar="PATH",
                   help=h("ملف أو مجلد استعلامات VQL إضافية (لغة استعلام تصريحية فوق قاعدة بيانات البرنامج)"))
    p.add_argument("--no-queries", action="store_true", help=h("لا تشغّل استعلامات VQL المدمجة"))
    p.add_argument("--audit", action="store_true",
                   help=h("ملف التدقيق: اعرض أيضًا كل استدعاء خطر (eval/shell/SQL/pickle…) لم يُثبت تحليل التدفق وصول مدخل إليه"))
    p.add_argument("--no-jadx", action="store_true", help=h("لا تفكّ تجميع APK/JAR/AAR/DEX حتى لو كان jadx مثبّتًا"))
    p.add_argument("--jadx-timeout", type=int, default=600, metavar="SEC", help=h("مهلة jadx بالثواني (الافتراضي 600)"))
    p.add_argument("--jadx-include-libs", action="store_true", help=h("افحص أيضًا مكتبات الطرف الثالث داخل الكود المفكوك"))
    p.add_argument("--jobs", type=int, default=None, metavar="N",
                   help=h("عدد العمليات المتوازية لفحص الملفات (الافتراضي: عدد المعالجات؛ 1 يعطّل التوازي)"))
    p.add_argument("--cache", metavar="DIR",
                   help=h("مجلد ذاكرة مؤقتة تزايدية: إعادة فحص مشروع لم يتغير أسرع بكثير وبالنتائج نفسها"))
    p.add_argument("--no-cache", action="store_true", help=h("لا تستخدم الذاكرة المؤقتة للفحص"))
    p.add_argument("--lang", choices=LANG_CHOICES, default="auto",
                   help=h("لغة المخرجات: ar عربية، en إنجليزية، both الاثنتان؛ auto (الافتراضي) يتبع VULNSCAN_LANG أو KASHIF_LANG ثم لغة النظام"))
    p.add_argument("--no-color", action="store_true", help=h("لا تلوّن مخرجات الطرفية"))
    p.add_argument("--list-rules", action="store_true", help=h("اعرض القواعد المدمجة واخرج"))
    # Keep "vulnscan X.Y.Z": the in-app updater of every release (0.9.x included) checks a new binary by this exact text.
    p.add_argument("--version", action="version", version=f"vulnscan {__version__}")
    return p


def update_data_main(argv: list[str]) -> int:
    """`kashif update-data --web [--check]`: install the web data snapshot of the latest release (spec §4.4 step 2).
    Exit: 0 up to date or installed, 1 failure, 10 newer data available (--check)."""
    from . import updater
    lang = _lang_from_argv(argv)
    p = argparse.ArgumentParser(prog="kashif update-data", description=_wh("ud_desc", lang), formatter_class=_HelpFormatter)
    p.add_argument("--web", action="store_true", help=_wh("ud_web", lang))
    p.add_argument("--check", action="store_true", help=_wh("ud_check", lang))
    p.add_argument("--lang", choices=LANG_CHOICES, default="auto", help=argparse.SUPPRESS)
    a = p.parse_args(argv)
    lang = resolve_lang(a.lang)
    out_lang = "en" if lang == "en" else "ar"
    if not a.web:
        p.error(_wh("ud_what", lang))
    try:
        res = updater.update_web_data(check_only=a.check)
    except updater.UpdateError as e:
        msg = getattr(e, "message_en", None) if out_lang == "en" else e.message
        msg = msg or (to_en(e.message) if out_lang == "en" else e.message)
        print(f"✖ {msg}" + (f" ({e.detail})" if e.detail else ""), file=sys.stderr)
        return 1
    print(res.get("message_en") if out_lang == "en" else res.get("message"))
    if res.get("path"):
        print(_wh("ud_path", out_lang, path=res["path"]))
    for n in res.get("notes") or []:
        if isinstance(n, dict) and n.get("en"):
            print(f"ℹ {n['en'] if out_lang == 'en' else n.get('ar') or n['en']}")
    return 10 if res.get("status") == "available" else 0


def ui_main(argv: list[str]) -> int:
    """`vulnscan ui`: start the local web dashboard."""
    lang = _lang_from_argv(argv)

    def h(text: str) -> str:
        return _bi(text, lang)

    with localized_argparse(lang):
        p = argparse.ArgumentParser(prog="kashif ui", formatter_class=_HelpFormatter,
                                    description=h("تشغيل الواجهة الرسومية المحلية (لوحة تحكم، فحص، تقارير، إعدادات)."))
        p.add_argument("--lang", choices=LANG_CHOICES, default="auto", help=argparse.SUPPRESS)
        p.add_argument("--port", type=int, default=8765, help=h("منفذ الواجهة المحلية (الافتراضي 8765)"))
        p.add_argument("--no-browser", action="store_true", help=h("لا تفتح المتصفح تلقائيًا"))
        a = p.parse_args(argv)
    from .server import serve
    serve(a.port, open_browser=not a.no_browser, lang=resolve_lang(a.lang))
    return 0


def _list_rules(lang: str = "both") -> str:
    en = lang == "en"

    def row(rid: str, sev: str, cwe: str, title: str, title_ar: str, advice: str = "", width: int = 8) -> list[str]:
        if not en:
            return [f"{rid:<{width}} {sev:<9} {cwe:<9} {title_ar} — {title}" if title else
                    f"{rid:<{width}} {sev:<9} {cwe:<9} {title_ar}"]
        out = [f"{rid:<{width}} {sev:<9} {cwe:<9} {title or to_en(title_ar)}"]
        if advice:
            out.append(f"{'':<{width}}   {to_en(advice)}")
        return out

    lines = [_say(lang, "{n:builtin_rules}:", "{n:builtin_rules}:", n=len(RULES) + 4), ""]
    for r in sorted(RULES, key=lambda r: (SEVERITY_RANK[r.severity], r.id)):
        lines += row(r.id, r.severity, r.cwe, r.title, r.title_ar, r.advice)
    from .scanner import ENTROPY_RULE as e
    from .semantic import CATALOGUE as SEM
    if en:
        lines += row(e["id"], e["severity"], e["cwe"], f"{e['title']} (Shannon entropy)", e["title_ar"], e.get("advice", ""))
    else:
        lines.append(f"{e['id']:<8} {e['severity']:<9} {e['cwe']:<9} {e['title_ar']} — {e['title']} (إنتروبيا شانون)")
    for r in SEM:
        lines += row(r["id"], r["severity"], r["cwe"], r["title"], r["title_ar"], r.get("advice", ""))
    from .taint import TAINT_RULES
    lines += ["", _say(lang, "{n:dataflow_rules} (12 لغة منها PL/SQL، مدركة للأنواع، عبر الملفات):",
                       "{n:dataflow_rules} (12 languages including PL/SQL; type-aware, cross-file):",
                       n=len(TAINT_RULES)), ""]
    for t in sorted(TAINT_RULES, key=lambda t: (SEVERITY_RANK[t["severity"]], t["id"])):
        lines += row(t["id"], t["severity"], t["cwe"], t["title"], t["title_ar"], t.get("advice", ""))
    from .vql import catalogue
    qs = catalogue()
    lines += ["", _say(lang, "{n:vql_queries} (فوق قاعدة بيانات البرنامج):",
                       "{n:vql_queries} (over the program database):", n=len(qs)), ""]
    for q in sorted(qs, key=lambda q: (SEVERITY_RANK.get(q["severity"], 9), q["id"])):
        lines += row(q["id"], q["severity"], q["cwe"], q["title"] if en else "", q["title_ar"], q.get("advice", ""), width=32)
    return "\n".join(lines)


def run(args: argparse.Namespace) -> tuple[list[Finding], str, int, list[str]] | int:
    lang = getattr(args, "lang_resolved", None) or resolve_lang(getattr(args, "lang", "auto"))
    notes: list[str] = []
    target = args.target
    if target.startswith(("http://", "https://")):
        if not args.authorized:          # exit 2 (the scan could not run), never 1 (= findings, for CI)
            print(f"✖ {localize('فحص عنوان ويب يتطلب --authorized (تأكيد أنك مخوَّل بفحص هذا الهدف).', lang)}",
                  file=sys.stderr)
            raise SystemExit(2)
        return _run_web(args, target, lang)

    path = pathlib.Path(target)
    if not path.exists():
        print(f"✖ {localize(f'الهدف غير موجود: {target}', lang)}", file=sys.stderr)
        raise SystemExit(2)
    models_dirs, query_paths = list(getattr(args, "models", []) or []), list(getattr(args, "query", []) or [])
    if getattr(args, "pack", None) or getattr(args, "packs", False):     # installed rule packs (kashif rules install)
        extra_models, extra_queries = _pack_dirs(args, lang)
        models_dirs += extra_models
        query_paths += extra_queries
    findings, files = scan_path(path, args.exclude, set(args.ignore_rule), jadx=not args.no_jadx,
                                jadx_timeout=args.jadx_timeout, jadx_include_libs=args.jadx_include_libs, notes=notes,
                                models_dirs=models_dirs, query_paths=query_paths, queries=not args.no_queries,
                                audit=args.audit, jobs=args.jobs,
                                cache_dir=None if args.no_cache else args.cache)
    scanners = {"sast", "secrets"}
    if not args.no_deps:
        dep_findings, err = audit_dependencies(path)
        findings.extend(dep_findings)
        notes.append(err or f"استعلام OSV.dev عن الاعتماديات: {ar_count(len(dep_findings), _KNOWN_VULNS)}.")
        if not err:
            scanners.add("deps")
    if not args.no_external:
        ext, ran = run_external(path)
        findings.extend(ext)
        if ran:
            notes.append(f"أدوات خارجية دُمجت نتائجها: {', '.join(ran)}")
            scanners.add("external")
    args.scanners_ran = sorted(scanners)
    return findings, str(path), files, notes


def web_profile(args: argparse.Namespace) -> str:
    """The scan profile of --web-profile / --deep (1.1.0 default: standard)."""
    return getattr(args, "web_profile", None) or ("deep" if getattr(args, "deep", False) else "standard")


def _web_options(args: argparse.Namespace):
    from .web import options_for
    return options_for(timeout=args.timeout, crawl=args.crawl, max_pages=args.max_pages, max_depth=args.max_depth,
                       delay=args.delay, profile=web_profile(args), sensitivity=getattr(args, "web_sensitivity", "default"),
                       respect_robots=not getattr(args, "ignore_robots", False),
                       third_party_lookups=getattr(args, "third_party_lookups", False),
                       cookie_ignore=tuple(getattr(args, "web_cookie_ignore", None) or ()),
                       use_proxy=not getattr(args, "no_proxy", False))


def load_web_snapshot(ref: str, store=None) -> dict | None:
    """The web snapshot (spec §3.7) of --compare REF: a scan id of the local history, a Kashif JSON report
    (``web.snapshot``), a saved scan file (``web_snapshot``) or a bare snapshot. None when REF names nothing;
    raises ValueError when it names a file that holds no web snapshot."""
    import json
    if ref.isalnum() and len(ref) <= 64:
        from .store import Store
        scan = (store or Store()).get_scan(ref)
        if scan is not None:
            snap = scan.get("web_snapshot") or ((scan.get("web") or {}).get("snapshot") if isinstance(scan.get("web"), dict) else None)
            if not isinstance(snap, dict) or not snap:
                raise ValueError(ref)
            return snap
    path = pathlib.Path(ref)
    if not path.is_file():
        return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as e:
        raise ValueError(ref) from e
    if isinstance(doc, dict):
        for snap in ((doc.get("web") or {}).get("snapshot") if isinstance(doc.get("web"), dict) else None,
                     doc.get("web_snapshot"), doc if "checks" in doc and "schema" in doc else None):
            if isinstance(snap, dict) and snap:
                return snap
    raise ValueError(ref)


def _run_web(args: argparse.Namespace, target: str, lang: str):
    """A passive web scan (spec §4.3) with the 1.1.0 options; the ``web`` report object goes to args.web_report."""
    from . import report
    from .web import scan_web
    previous = None
    store = None
    if args.compare:
        try:
            previous = load_web_snapshot(args.compare)
        except ValueError:
            print(f"✖ {_wh('compare_bad', lang, what=args.compare)}", file=sys.stderr)
            return 2
        if previous is None:
            print(f"✖ {_wh('compare_missing', lang, what=args.compare)}", file=sys.stderr)
            return 2
    elif args.compare_previous:
        from .store import Store
        store = Store()
        previous = store.latest_web_snapshot(target)
    opts = _web_options(args)
    scan_id = ""
    if store is not None:
        import uuid
        scan_id = uuid.uuid4().hex[:12]
    try:
        res = scan_web(target, options=opts, previous=previous, scan_id=scan_id)
    except WebUnreachable as e:
        print(f"✖ {localize(str(e), lang)}", file=sys.stderr)
        return 2
    web = report.web_section(res, sensitivity=opts.sensitivity)
    ar, en = web_budget_note(opts.profile, opts.crawl, opts.max_pages)
    web["notes"] = [{"en": en, "ar": ar}] + list(web.get("notes") or [])
    notes = [ar] + list(res.notes)
    if store is not None:
        if previous is None:
            notes.append(_WEB_HELP["ar"]["no_previous"])
            web["notes"].append({"en": _WEB_HELP["en"]["no_previous"], "ar": _WEB_HELP["ar"]["no_previous"]})
        saved = _save_web_scan(store, scan_id, target, res, web, notes)
        if saved:
            print(_wh("saved", "en" if lang == "en" else "ar", id=saved), file=sys.stderr)
    args.web_report = web
    return res.findings, target, 1, notes


def _save_web_scan(store, scan_id: str, target: str, res, web: dict, notes: list[str]) -> str:
    """--compare-previous: keep this scan in the local history (as the UI does), so the next run compares with it."""
    import time
    from .report import summary_counts
    findings = list(res.findings)
    assign_fingerprints(findings)
    now = time.time()
    scan = {"id": scan_id, "target": target, "kind": "url", "status": "done", "started_at": now, "finished_at": now,
            "files_scanned": 1, "notes": notes, "notes_en": [n.get("en", "") for n in web.get("notes") or []][:len(notes)],
            "summary": summary_counts(findings), "findings": [f.to_dict() for f in findings], "error": None,
            "source": "cli", "web": {k: v for k, v in web.items() if k != "snapshot"}, "web_snapshot": res.snapshot}
    try:
        store.save_scan(scan)
    except OSError:
        return ""
    return scan_id


def _pack_dirs(args: argparse.Namespace, lang: str) -> tuple[list[str], list[str]]:
    """Model and query directories of the rule packs named by --pack (or all with --packs); unknown names exit 2."""
    from . import ruletest
    installed = ruletest.installed_packs()
    names = None if args.packs else list(dict.fromkeys(args.pack))
    if names is not None:
        missing = [n for n in names if n not in {p.get("name") for p in installed}]
        if missing:
            print(f"✖ {localize('حزمة القواعد غير مثبّتة: ' + ', '.join(missing), lang)}", file=sys.stderr)
            raise SystemExit(2)
    for pack in installed:
        if names is None or pack.get("name") in names:
            ruletest.register_pack_translations(pack["path"])
    return ruletest.scan_args(names=names)


def _force_utf8_output() -> None:
    """Arabic output crashes on a cp1252 Windows console; force UTF-8 if we can."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def _closed_pipe(e: BaseException) -> bool:
    """The reader of stdout went away ("kashif . -f json | head"). POSIX raises BrokenPipeError; Windows raises
    OSError EINVAL (or EPIPE) from the write, with no file name (a failing report file always carries one)."""
    import errno
    return isinstance(e, BrokenPipeError) or (
        isinstance(e, OSError) and e.errno in (errno.EPIPE, errno.EINVAL) and getattr(e, "filename", None) is None)


def _silence_stdout() -> None:
    """After a broken pipe ("kashif . -f json | head"): send the rest of stdout to /dev/null, so neither the
    remaining output nor the interpreter's final flush raises again."""
    try:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    except (OSError, ValueError):
        pass


class _OutputError(Exception):
    """A report file could not be written (missing folder, permissions): exit 2 with a message, no traceback."""


def _write_file(dest: str, text: str, newline: str | None = None) -> None:
    try:
        with open(dest, "w", encoding="utf-8", newline=newline) as fh:
            fh.write(text)
    except OSError as e:
        raise _OutputError(f"{dest}: {e.strerror or e}") from None


def _check_output_paths(args: argparse.Namespace, parser: argparse.ArgumentParser, m) -> None:
    """Every file the scan will write must go to an existing folder: checked before the (possibly long) scan."""
    dests = [args.output, args.audit_report, args.write_baseline]
    dests += [f"{args.all_formats}.md"] if args.all_formats else []
    dests += [d for _, d in _parse_exports(args.export, parser, m)]
    for dest in filter(None, dests):
        parent = pathlib.Path(dest).parent
        if not parent.is_dir():
            parser.error(m(f"مجلد ملف الإخراج غير موجود: {parent}") + f" ({dest})")


def _aws_meta(args: argparse.Namespace) -> dict:
    """--aws-account / --aws-region as the export metadata of the asff format (as `kashif export` passes them)."""
    meta = {}
    if getattr(args, "aws_account", None):
        meta["aws_account_id"] = args.aws_account
    if getattr(args, "aws_region", None):
        meta["aws_region"] = args.aws_region
    return meta


def _check_asff(args: argparse.Namespace, exports: list[tuple[str, str]], parser: argparse.ArgumentParser, bi) -> None:
    """-f asff / --export asff=FILE need a valid --aws-account and --aws-region: checked before the scan starts."""
    if args.format != "asff" and not any(fmt == "asff" for fmt, _ in exports):
        return
    from .exporters import ExportError, export as do_export
    try:
        do_export([], "asff", _aws_meta(args))          # validates the account and region, writes nothing
    except ExportError:
        parser.error(bi("تحتاج صيغة asff إلى رقم حساب AWS من 12 رقمًا ومنطقة AWS صالحة: "
                        "--aws-account ID --aws-region REGION (مثل --aws-account 123456789012 --aws-region eu-west-1)"))


def _check_baseline(path: str, lang: str) -> bool:
    """--baseline FILE, checked before the scan. A missing file is the first run of a pipeline (every finding is
    new, as before). A file that exists but is not JSON stops the scan with exit 2, like any unreadable input. JSON
    that is not a baseline gets a warning on stderr and counts as empty (the exit code stays as before)."""
    from .baseline import baseline_problem
    problem = baseline_problem(path)
    if problem == "unreadable":
        print(f"✖ {_bi(f'تعذّرت قراءة ملف خط الأساس (ليس JSON صالحًا): {path}', lang)}", file=sys.stderr)
        return False
    if problem == "shape":
        print(f"⚠ {_bi(f'ملف خط الأساس ليس من إنتاج --write-baseline (لا قائمة fingerprints فيه)، فعُدّ فارغًا وكل النتائج تُعرض كجديدة: {path}', lang)}",
              file=sys.stderr)
    return True


def main(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    try:
        code = _main(sys.argv[1:] if argv is None else argv)
        # A report that fits in the stdout buffer meets the closed pipe only here; left to the interpreter's
        # final flush it would end the process with exit code 120.
        sys.stdout.flush()
        return code
    except OSError as e:                     # "kashif . -f json | head": the reader left; not an error
        if not _closed_pipe(e):
            raise
        _silence_stdout()
        return 0
    except _OutputError as e:
        print(f"✖ {e}", file=sys.stderr)
        return 2


# Everything `kashif <word>` routes to before the scan parser: the sub-commands and the built-in ui/lsp/update.
_ROUTED = frozenset(DELEGATES) | {"ui", "lsp", "update", "update-data"}


def _hoist_lang(argv: list[str]) -> list[str]:
    """`kashif --lang en <sub-command> ...` means `kashif <sub-command> ... --lang en`: a --lang written before the
    sub-command word moves into the sub-command's own arguments (before a "--"), unless they name one themselves.
    lsp has no language option, so it is dropped there."""
    i, lang_args = 0, []
    while i < len(argv):
        if argv[i] == "--lang" and i + 1 < len(argv):
            lang_args, i = argv[i:i + 2], i + 2
        elif argv[i].startswith("--lang="):
            lang_args, i = argv[i:i + 1], i + 1
        else:
            break
    if not lang_args or i >= len(argv) or argv[i] not in _ROUTED:
        return argv
    name, rest = argv[i], argv[i + 1:]
    cut = rest.index("--") if "--" in rest else len(rest)
    if name == "lsp" or any(a == "--lang" or a.startswith("--lang=") for a in rest[:cut]):
        return [name] + rest
    return [name] + rest[:cut] + lang_args + rest[cut:]


def _main(argv: list[str]) -> int:
    raw = list(argv)
    argv = _hoist_lang(argv)
    if argv and argv[0] == "ui":
        return ui_main(argv[1:])
    if argv and argv[0] == "lsp":                    # language server for editors (stdio; --stdio accepted)
        from .lsp import main as lsp_main
        hlang = _lang_from_argv(raw)                 # --help follows `kashif --lang X lsp` like every sub-command
        with localized_argparse(hlang):
            return lsp_main(argv[1:], help_lang=hlang)
    if argv and argv[0] == "update":
        from .updater import cli_main as update_main
        with localized_argparse(_lang_from_argv(argv[1:])):
            return update_main(argv[1:])
    if argv and argv[0] == "update-data":
        with localized_argparse(_lang_from_argv(argv[1:])):
            return update_data_main(argv[1:])
    if argv and argv[0] in DELEGATES:               # mcp, export, compliance, history, triage, policy, surface, rules
        return run_subcommand(argv[0], argv[1:])
    lang = _lang_from_argv(argv)
    with localized_argparse(lang):                    # argparse's headings, usage prefix and errors in that language
        return _scan_main(argv, lang)


def _scan_main(argv: list[str], lang: str) -> int:
    parser = build_parser(lang)
    args = parser.parse_args(argv)
    args.lang_resolved = lang = resolve_lang(args.lang)

    def m(text: str) -> str:
        return localize(text, lang)

    def bi(text: str) -> str:                        # usage errors: both languages under "both"
        return _bi(text, lang)

    if args.list_rules:
        print(_list_rules(lang))
        return 0
    if not args.target:
        parser.error(bi("الهدف مطلوب: مسار مجلد أو ملف أو أرشيف، أو عنوان http(s)://"))
    is_web = args.target.startswith(("http://", "https://"))
    if (args.diff_base or args.diff_staged) and is_web:
        parser.error(bi("الخياران --diff-base و--diff-staged يحتاجان مسارًا محليًا داخل مستودع git"))
    if (args.fix or args.fix_dry_run) and is_web:
        from .autofix import MSG as FIX_MSG
        parser.error(bi(FIX_MSG["local_only"]))
    if not is_web:
        for opt, on in (("--compare", args.compare), ("--compare-previous", args.compare_previous)):
            if on:
                parser.error(_wh("web_only", lang, opt=opt))
    if args.deep and args.web_profile not in (None, "deep"):
        parser.error(_wh("deep_conflict", lang, profile=args.web_profile))
    if args.compare and args.compare_previous:
        parser.error(_wh("compare_both", lang))
    exports = _parse_exports(args.export, parser, bi)
    _check_output_paths(args, parser, bi)
    _check_asff(args, exports, parser, bi)
    if args.baseline and not _check_baseline(args.baseline, lang):
        return 2
    if args.compliance and _compliance_frameworks(args.compliance, m) is None:
        return 2                               # a typo in a framework name must not cost a whole scan first
    if args.triage == "" and is_web:
        parser.error(bi("--triage مع عنوان ويب يحتاج مسار ملف الفرز: --triage=FILE"))
    if (args.sla or args.fail_on_sla or args.triage_update) and args.triage is None:
        parser.error(bi("الخيارات --sla و--fail-on-sla و--triage-update تعمل مع --triage"))
    sla_days = _parse_triage_options(args, parser, bi)
    mod_lang = "ar" if lang == "ar" else "en"          # the add-on modules speak en or ar
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result = run(args)
    if isinstance(result, int):          # web target unreachable: message already printed
        return result
    findings, target, files, notes = result
    # Fingerprints are assigned once, on the complete list, so every report and the baseline agree.
    # The baseline is written and applied BEFORE --min-severity: it must record everything that exists
    # today, otherwise lower-severity pre-existing issues would come back as "new" later.
    assign_fingerprints(findings)

    if args.write_baseline:
        try:
            n = save_baseline(findings, args.write_baseline)
        except OSError as e:
            raise _OutputError(f"{args.write_baseline}: {e.strerror or e}") from None
        print(_say(lang, "حُفظ خط الأساس: {n:fingerprints} في {file}. الفحوص القادمة مع --baseline ستعرض الجديد فقط.",
                   "Baseline saved: {n:fingerprints} in {file}. Future scans with --baseline will report new "
                   "findings only.", n=n, file=args.write_baseline))
        return 0

    exit_code = 0
    hidden: list[Finding] = []                 # hidden by a triage decision (kept for SARIF suppressions)
    tri = None
    if args.triage is not None:                # after the fingerprints, before any filtering (vulnscan/triage.py)
        tri, findings, hidden, code = _apply_triage(args, findings, mod_lang, m)
        if code:
            return code
    scope = None
    if args.diff_base or args.diff_staged:     # computed once: the policy needs it before the findings are filtered
        from .diffscope import DiffScopeError, compute
        try:
            scope = compute(args.target, args.diff_base, staged=args.diff_staged and not args.diff_base)
        except DiffScopeError as e:
            print(f"✖ {m(str(e))}", file=sys.stderr)
            return 2
    decision = None
    if not args.no_policy and not (args.fix or args.fix_dry_run) and (args.policy is not None or not is_web):
        decision, code = _evaluate_policy(args, findings + hidden, scope, mod_lang, m, target, files, notes)
        if code:
            return code

    if args.baseline:
        findings, suppressed, size = apply_baseline(findings, args.baseline)
        notes = list(notes) + ([f"خط الأساس: كُتمت {ar_count(suppressed, _KNOWN_FINDINGS)} من أصل {size}؛ "
                                "تُعرض النتائج الجديدة فقط."]
                               if size else ["خط الأساس غير موجود أو فارغ؛ كل النتائج تُعرض كجديدة."])
    if scope is not None:                      # after the baseline (which records everything), before --fail-on
        from .diffscope import filter_findings
        findings, dropped = filter_findings(findings, scope, args.target)
        notes = list(notes) + scope.notes + [f"نتائج خارج التغييرات لم تُعرض: {dropped}."]
    findings = [f for f in findings if SEVERITY_RANK[f.severity] <= SEVERITY_RANK[args.min_severity]]
    findings = sort_findings(findings)

    if not is_web:     # automatic fixes: apply them, or attach to the report
        from . import autofix
        if args.fix or args.fix_dry_run:
            return autofix.run_cli(findings, args.target, dry_run=args.fix_dry_run, force=args.fix_force, lang=lang)
        autofix.attach_fixes(findings, args.target)

    scanners = getattr(args, "scanners_ran", None)
    export_meta = {"target": target, "files_scanned": files, "notes": notes, "lang": mod_lang,
                   "started_at": started_at, "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    if args.fail_on:
        export_meta["fail_on"] = args.fail_on
    export_meta.update(_aws_meta(args))

    def export(fmt: str) -> str:
        from .exporters import ExportError, export as do_export
        try:
            return do_export(findings, fmt, export_meta)
        except ExportError as err:
            print(f"✖ {err}", file=sys.stderr)
            raise SystemExit(2) from None

    web = getattr(args, "web_report", None)          # a web scan's grades, coverage, inventory, diff (report.web_section)
    renderers = {"console": lambda: render_console(findings, target, files, notes,
                                                   color=not args.no_color and args.output is None, lang=lang, web=web),
                 "markdown": lambda: render_markdown(findings, target, files, notes, lang=lang, web=web),
                 "json": lambda: render_json(findings, target, files, notes, scanners=scanners, web=web),
                 "html": lambda: render_html(findings, target, files, notes, lang=lang, web=web),
                 "sarif": lambda: render_sarif(findings, target, files, notes, lang=lang, suppressed=hidden, web=web)}
    machine_stdout = False
    if args.all_formats:
        for ext, fmt in (("md", "markdown"), ("json", "json"), ("html", "html"), ("sarif", "sarif")):
            _write_file(f"{args.all_formats}.{ext}", renderers[fmt]())
        print(render_console(findings, target, files, notes, color=not args.no_color, lang=lang, web=web))
        print("\n" + m(f"كُتبت التقارير: {args.all_formats}.md / .json / .html / .sarif"))
    else:
        text = renderers[args.format]() if args.format in renderers else export(args.format)
        if args.output:
            # newline="": the CSV exports carry their own CRLF line ends
            _write_file(args.output, text, newline="" if args.format in EXPORT_FORMATS else None)
            counts = summary_counts(findings)
            print(m(f"كُتب التقرير إلى {args.output}") + " — " + ", ".join(f"{s}:{counts[s]}" for s in SEVERITIES))
        else:
            machine_stdout = args.format != "console"
            if args.format in renderers:
                print(text)
            else:                                 # the exports end with their own newline
                print(text, end="" if text.endswith("\n") else "\n")
    for fmt, dest in exports:                  # --export FORMAT=FILE
        _write_file(dest, export(fmt), newline="")
        print(m(f"كُتب التقرير إلى {dest}") + f" ({fmt})", file=sys.stderr if machine_stdout else sys.stdout)
    side = sys.stderr if machine_stdout else sys.stdout   # never mix extra text into a JSON/SARIF/... on stdout
    if args.risk_score:
        from .exporters import _t as export_text, project_risk, rating_label
        risk = project_risk(findings, export_meta)
        print(export_text(mod_lang, "m_score", score=risk["score"], rating=rating_label(risk["rating"], mod_lang),
                          n=risk["open_findings"]), file=side)
    if args.compliance or args.audit_report:
        code = _compliance_outputs(args, findings, target, files, notes, mod_lang, m, side)
        if code:
            return code
    if tri is not None and args.fail_on_sla:
        from . import triage
        breaches = triage.stats(tri, sla_days=sla_days)["sla"]["breaches"]
        if breaches:
            print("✖ " + _say(lang, "تجاوز مهلة الإصلاح: {n:open_findings}", "Fix deadline (SLA) exceeded: {n:open_findings}",
                              n=len(breaches)), file=sys.stderr)
            exit_code = 1
    if decision is not None:
        from . import policy
        print(policy.explain(decision, "text", mod_lang), file=sys.stderr, end="")
        exit_code = max(exit_code, decision.exit_code)
    if args.fail_on and any(SEVERITY_RANK[f.severity] <= SEVERITY_RANK[args.fail_on] for f in findings):
        exit_code = 1
    return exit_code


def _parse_exports(specs: list[str], parser: argparse.ArgumentParser, m) -> list[tuple[str, str]]:
    """--export FORMAT=FILE values, validated before the (possibly long) scan starts."""
    out = []
    for spec in specs:
        fmt, sep, dest = spec.partition("=")
        if not sep or not dest or fmt not in SCAN_FORMATS or fmt not in EXPORT_FORMATS:
            parser.error(m("صيغة --export هي FORMAT=FILE بصيغة تصدير معروفة") + f": {spec!r} "
                         f"({', '.join(EXPORT_FORMATS)})")
        out.append((fmt, dest))
    return out


def _parse_triage_options(args, parser: argparse.ArgumentParser, m) -> dict | None:
    """--triage-show and --sla, checked before the scan starts (a typo in a status must not hide every finding)."""
    if args.triage is None:
        return None
    from .triage import STATUSES
    show = [x.strip() for x in args.triage_show.split(",") if x.strip()]
    unknown = [x for x in show if x != "all" and x not in STATUSES]
    if unknown or not show:
        parser.error(m("حالة فرز غير معروفة") + f": {', '.join(unknown) or '-'} ({', '.join(STATUSES)}, all)")
    if not args.sla:
        return None
    days: dict = {}
    for part in args.sla.split(","):
        name, _, value = part.strip().partition("=")
        if name not in SEVERITIES or not value.isdigit():
            parser.error(m("قيمة --sla غير صالحة (مثال: critical=7,high=30,medium=90)") + f": {part!r}")
        days[name] = int(value)
    return days


def _apply_triage(args, findings: list[Finding], mod_lang: str, m):
    """--triage: sync the triage file with this scan (saved only with --triage-update), annotate every finding
    with its decision and keep the statuses of --triage-show. Returns (triage, visible, hidden, exit code)."""
    from . import triage
    path = pathlib.Path(args.triage) if args.triage else triage.default_path(args.target)
    target_path = pathlib.Path(args.target)
    # "fixed (auto)" only after a complete scan: a whole directory, every rule, no diff scoping
    complete = (not args.target.startswith(("http://", "https://")) and target_path.is_dir()
                and not args.ignore_rule and not args.diff_base and not args.diff_staged)
    if args.triage_update and not args.triage and triage.redirected(path):
        print(f"✖ {m('لم يُحدَّث ملف الفرز: المجلد ‎.kashif أو ملف triage.json في المشروع رابط رمزي يشير إلى خارجه')}"
              f": {path}", file=sys.stderr)
        return None, findings, [], 2
    try:
        if args.triage_update:
            box: dict = {}
            tri = triage.update(path, lambda t: box.update(sync=triage.sync(findings, t, complete=complete)))
        else:
            tri = triage.load(path)
            triage.sync(findings, tri, complete=complete)          # in memory only: flags regressions / expiry
        res = triage.apply(findings, tri, show=args.triage_show, lang=mod_lang)
    except triage.TriageError as e:
        print(f"✖ {e.message(mod_lang)}", file=sys.stderr)
        return None, findings, [], 2
    except OSError as e:
        print(f"✖ {path}: {e}", file=sys.stderr)
        return None, findings, [], 2
    lang = getattr(args, "lang_resolved", None) or mod_lang
    if res.expired:
        print("⚠ " + _say(lang, "قبول خطر منتهٍ: أُعيد فتح {n:findings}", "Risk acceptance expired: {n:findings} re-opened",
                          n=len(res.expired)), file=sys.stderr)
    if res.regressions:
        print("⚠ " + _say(lang, "ارتداد: عادت {n:findings} بعد الإصلاح", "Regression: {n:findings} back after being fixed",
                          n=len(res.regressions)), file=sys.stderr)
    return tri, list(res.visible), list(res.hidden), 0


def _evaluate_policy(args, findings: list[Finding], scope, mod_lang: str, m, target: str, files: int, notes: list[str]):
    """The policy gate (vulnscan/policy.py): an explicit --policy FILE|PRESET, else kashif.yml in the scanned
    directory. Returns (decision or None, exit code to stop with or 0). Reports the policy lists are written only
    below --policy-reports-dir."""
    from . import policy
    is_web = args.target.startswith(("http://", "https://"))
    if args.policy:
        source = args.policy
    else:
        source = policy.find_policy(args.target) if not is_web else None
        if not source and args.policy == "":           # a bare --policy asks for the project's file
            print(f"✖ {m('لا يوجد ملف سياسة في المجلد المفحوص')}: {', '.join(policy.POLICY_FILENAMES)}", file=sys.stderr)
            return None, 2
        if not source:
            return None, 0
    try:
        pol = policy.load_policy(source)            # never allow_outside: the file may come from the scanned tree
    except policy.PolicyError as e:
        print(e.format(mod_lang), file=sys.stderr)
        return None, 2
    except OSError as e:
        print(f"✖ {source}: {e}", file=sys.stderr)
        return None, 2
    for w in pol.warnings:
        print(f"⚠ {w.message(mod_lang)}", file=sys.stderr)
    # "new" against the baseline and/or the diff scope, passed as per-finding flags (the report is left untouched)
    known = load_baseline(args.baseline) if args.baseline else None
    in_diff = None
    if scope is not None:
        from .diffscope import filter_findings
        in_diff = {id(f) for f in filter_findings(list(findings), scope, args.target)[0]}
    items = []
    for f in findings:
        d = f.to_dict()
        if known is not None or in_diff is not None:
            d["extra"] = dict(d.get("extra") or {}, new=(known is None or f.fingerprint() not in known)
                              and (in_diff is None or id(f) in in_diff))
        items.append(d)
    base_dir = pathlib.Path("." if is_web else args.target)
    ctx = policy.Context(scanners=set(getattr(args, "scanners_ran", None) or []) or None,
                         base_dir=str(base_dir if base_dir.is_dir() else base_dir.parent))
    try:
        decision = policy.evaluate(items, pol, ctx)
    except (ValueError, TypeError) as e:
        print(f"✖ {e}", file=sys.stderr)
        return None, 2
    if pol.reports:
        if not args.policy_reports_dir:
            print(f"⚠ {m('ملف السياسة يطلب تقارير (reports) لم تُكتب: حدّد مجلدها بالخيار --policy-reports-dir')}",
                  file=sys.stderr)
        else:
            code = _write_policy_reports(pol.reports, args.policy_reports_dir, findings, target, files, notes,
                                         mod_lang, getattr(args, "scanners_ran", None))
            if code:
                return None, code
    return decision, 0


def _write_policy_reports(reports: list[dict], out_dir: str, findings, target, files, notes, lang, scanners) -> int:
    """Write the policy's `reports` below out_dir. The paths come from a file in the scanned repository: they were
    validated as relative and portable by policy.py, and here every one must also resolve inside out_dir and not
    be (or pass through) a symbolic link."""
    root = pathlib.Path(out_dir).resolve()
    visible = sort_findings([f for f in findings if not (isinstance(f.extra.get("triage"), dict)
                                                         and f.extra["triage"].get("status") not in ("open", "confirmed"))])
    render = {"markdown": lambda: render_markdown(visible, target, files, notes, lang=lang),
              "json": lambda: render_json(visible, target, files, notes, scanners=scanners),
              "html": lambda: render_html(visible, target, files, notes, lang=lang),
              "sarif": lambda: render_sarif(visible, target, files, notes, lang=lang)}
    for rep in reports:
        fmt, rel = rep.get("format"), str(rep.get("path") or "")
        if fmt not in render or not rel:
            continue
        dest = root / rel
        parts = [root.joinpath(*pathlib.PurePosixPath(rel).parts[:i]) for i in range(1, len(pathlib.PurePosixPath(rel).parts) + 1)]
        if any(p.is_symlink() for p in parts) or not dest.resolve().is_relative_to(root):
            print(f"✖ {rel}: refused (outside {root} or a symbolic link)", file=sys.stderr)
            return 2
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(render[fmt](), encoding="utf-8")
    return 0


def _compliance_frameworks(spec: str, m) -> list[str] | None:
    """The framework ids of --compliance (comma-separated names or aliases, or all); None, after a message on
    stderr, for an unknown name (the caller exits 2)."""
    from . import compliance
    names = [x for x in spec.replace(" ", ",").split(",") if x]
    if "all" in names or not names:
        return list(compliance.FRAMEWORKS)
    fids: list[str] = []
    for name in names:
        fid = compliance.resolve_framework(name)
        if fid is None:
            print(f"✖ {m('إطار امتثال غير معروف: ' + name)} (kashif compliance --list-frameworks)", file=sys.stderr)
            return None
        if fid not in fids:
            fids.append(fid)
    return fids


def _compliance_outputs(args, findings: list[Finding], target: str, files: int, notes: list[str], lang: str, m,
                        out) -> int:
    """--compliance FRAMEWORKS (Markdown summary after the report) and --audit-report FILE (HTML auditor report)."""
    from . import compliance
    fids = _compliance_frameworks(args.compliance or "all", m)
    if fids is None:
        return 2
    dicts = [f.to_dict() for f in findings]
    meta = {"target": target, "files_scanned": files, "notes": notes,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    if args.compliance:
        print("\n" + compliance.render_markdown(dicts, meta, lang=lang, frameworks=fids), file=out)
    if args.audit_report:
        local = pathlib.Path(args.target)
        root = str(local) if not args.target.startswith(("http://", "https://")) and local.is_dir() else None
        html_text = compliance.render_html(dicts, meta, lang=lang, frameworks=fids, source_root=root, mask_secrets=True)
        _write_file(args.audit_report, html_text)
        print(m(f"كُتب التقرير إلى {args.audit_report}"), file=out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
