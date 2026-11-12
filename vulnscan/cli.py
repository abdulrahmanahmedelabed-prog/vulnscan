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
from .model import SEVERITIES, SEVERITY_RANK, Finding, assign_fingerprints, sort_findings
from .report import render_console, render_html, render_json, render_markdown, render_sarif, summary_counts
from .baseline import apply_baseline, load_baseline, save_baseline
from .exporters import FORMATS as EXPORT_FORMATS
from .rules import RULES
from .scanner import scan_path
from .web import WebUnreachable, scan_site

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
}
# Sub-commands that forward their arguments to the module's own main(argv): name -> module of this package.
DELEGATES = {"mcp": "mcp", "export": "exporters", "compliance": "compliance", "history": "history",
             "secrets-history": "history", "triage": "triage", "policy": "policy", "surface": "surface",
             "rules": "ruletest"}


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

    An explicit --lang wins; "auto" uses the VULNSCAN_LANG environment variable when set, else "ar" on an Arabic
    system locale, else "both" (today's bilingual output: nobody is switched to English-only silently)."""
    if value in ("ar", "en", "both"):
        return value
    env = os.environ if environ is None else environ
    from_env = (env.get("VULNSCAN_LANG") or "").strip().lower()
    if from_env in ("ar", "en", "both"):
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
    def desc(text: str, indent: str = "") -> str:
        if lang == "en":
            return to_en(text)
        return text if lang == "ar" else f"{text}\n{indent}{to_en(text)}"
    pad = " " * 15
    lines = [desc("الأوامر الفرعية:")]
    lines += [f"  {name:<12} {desc(text, pad)}" for name, text in SUBCOMMANDS.items()]
    lines += ["", desc("شغّل kashif <أمر فرعي> --help لعرض خياراته.")]
    return "\n".join(lines)


def _forward_lang(argv: list[str], after_command: bool = False) -> list[str]:
    """Arguments for a sub-command module, whose --lang takes only en or ar: an explicit --lang en|ar is kept,
    "both"/"auto" are dropped, and without one the language Kashif resolved (VULNSCAN_LANG, then the system
    locale) is appended when it is ar or en, so `kashif <sub-command>` speaks the same language as a scan.

    after_command: the module takes --lang only after its own command word (`kashif policy check --lang ar`), so
    --lang is moved right after that word, and left out when there is none (`kashif policy` alone must report the
    missing command, not "invalid choice: 'ar'")."""
    if "--scan-worker" in argv:
        return list(argv)
    cut = argv.index("--") if "--" in argv else len(argv)
    head, tail = argv[:cut], argv[cut:]
    out: list[str] = []
    explicit = False
    i = 0
    while i < len(head):
        a = head[i]
        if a == "--lang" and i + 1 < len(head):
            if head[i + 1] in ("ar", "en"):
                out += [a, head[i + 1]]
                explicit = True
            elif head[i + 1] not in ("both", "auto"):
                out += [a, head[i + 1]]             # let the module report the invalid value
                explicit = True
            i += 2
            continue
        if a.startswith("--lang="):
            if a[7:] not in ("both", "auto"):
                out.append(a)
                explicit = True
            i += 1
            continue
        out.append(a)
        i += 1
    if not explicit:
        lang = resolve_lang("auto")
        if lang in ("ar", "en"):
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
        out = rest if cmd is None else rest[:cmd + 1] + lang_args + rest[cmd + 1:]
    return out + tail


def run_subcommand(name: str, argv: list[str]) -> int:
    """`kashif <name> ...`: forward to the module's own command line (see DELEGATES)."""
    import importlib
    module = importlib.import_module(f".{DELEGATES[name]}", __package__)
    # mcp: the assistant's language, see mcp.py; policy: --lang belongs to its commands (check, init, ...)
    args = list(argv) if name == "mcp" else _forward_lang(list(argv), after_command=name == "policy")
    try:
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


def build_parser(lang: str = "both") -> argparse.ArgumentParser:
    def h(text: str) -> str:
        return localize(text, lang)

    p = argparse.ArgumentParser(
        prog="kashif",
        usage="kashif [options] TARGET\n       kashif <sub-command> [options]   (" + ", ".join(SUBCOMMANDS) + ")",
        description=h("فحص أي برنامج (مجلد مصدر، ملف، أرشيف/APK/JAR، أو عنوان ويب) وإخراج تقرير مرتب من الأعلى خطورة إلى الأقل.")
                    + "\n" + h(AUTHORIZATION_NOTICE),
        epilog=_subcommand_help(lang),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?", help=h("مسار مجلد/ملف/أرشيف، أو عنوان http(s):// للفحص السلبي، أو «ui» لتشغيل الواجهة الرسومية"))
    p.add_argument("--authorized", action="store_true",
                   help=h("أقرّ بأنني مخوَّل بفحص هذا الهدف (إلزامي لفحص عناوين الويب)"))
    p.add_argument("-f", "--format", choices=SCAN_FORMATS, default="console", metavar="FORMAT",
                   help=h("صيغة التقرير: console أو markdown أو json أو html أو sarif (لـ GitHub Code Scanning وVS Code)، "
                          "أو صيغة تصدير: gitlab-sast وcodeclimate (GitLab) وdefectdojo وsonarqube وjunit وcsv "
                          "وjira-csv وgithub-issues وasff وocsf وrisk (القائمة: kashif export --list-formats)"))
    p.add_argument("-o", "--output", help=h("اكتب التقرير إلى هذا الملف بدلًا من الشاشة"))
    p.add_argument("--all-formats", metavar="PREFIX", help=h("اكتب PREFIX.md و PREFIX.json و PREFIX.html معًا"))
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
    p.add_argument("--deep", action="store_true", help=h("فحص ويب أعمق: تحليل HTML وفحص مسارات مكشوفة شائعة (طلبات إضافية محدودة)"))
    p.add_argument("--crawl", action="store_true", help=h("زحف على صفحات الموقع من نفس النطاق وفحصها (لتطبيقات مثل Moodle وبوابات الجامعات)"))
    p.add_argument("--max-pages", type=int, default=20, metavar="N", help=h("أقصى عدد صفحات عند الزحف (الافتراضي 20)"))
    p.add_argument("--delay", type=float, default=0.5, metavar="SEC", help=h("تأخير بين طلبات الزحف بالثواني (الافتراضي 0.5؛ ألطف على الخادم)"))
    p.add_argument("--max-depth", type=int, default=2, metavar="N", help=h("أقصى عمق للزحف (الافتراضي 2)"))
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
                   help=h("لغة المخرجات: ar عربية، en إنجليزية، both الاثنتان؛ auto (الافتراضي) يتبع VULNSCAN_LANG ثم لغة النظام"))
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--list-rules", action="store_true", help=h("اعرض القواعد المدمجة واخرج"))
    # Keep "vulnscan X.Y.Z": the in-app updater of every release (0.9.x included) checks a new binary by this exact text.
    p.add_argument("--version", action="version", version=f"vulnscan {__version__}")
    return p


def ui_main(argv: list[str]) -> int:
    """`vulnscan ui`: start the local web dashboard."""
    lang = _lang_from_argv(argv)

    def h(text: str) -> str:
        return localize(text, lang)

    p = argparse.ArgumentParser(prog="kashif ui", description=h("تشغيل الواجهة الرسومية المحلية (لوحة تحكم، فحص، تقارير، إعدادات)."))
    p.add_argument("--lang", choices=LANG_CHOICES, default="auto", help=argparse.SUPPRESS)
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--no-browser", action="store_true", help=h("لا تفتح المتصفح تلقائيًا"))
    a = p.parse_args(argv)
    from .server import serve
    serve(a.port, open_browser=not a.no_browser, lang=resolve_lang(a.lang))
    return 0


def _list_rules(lang: str = "both") -> str:
    en = lang == "en"

    def m(text: str) -> str:
        return localize(text, lang)

    def row(rid: str, sev: str, cwe: str, title: str, title_ar: str, advice: str = "", width: int = 8) -> list[str]:
        if not en:
            return [f"{rid:<{width}} {sev:<9} {cwe:<9} {title_ar} — {title}" if title else
                    f"{rid:<{width}} {sev:<9} {cwe:<9} {title_ar}"]
        out = [f"{rid:<{width}} {sev:<9} {cwe:<9} {title or to_en(title_ar)}"]
        if advice:
            out.append(f"{'':<{width}}   {to_en(advice)}")
        return out

    lines = [m(f"{len(RULES) + 4} قاعدة مدمجة:"), ""]
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
    lines += ["", m(f"{len(TAINT_RULES)} قاعدة تدفق بيانات وAPEX (12 لغة منها PL/SQL، مدركة للأنواع، عبر الملفات):"), ""]
    for t in sorted(TAINT_RULES, key=lambda t: (SEVERITY_RANK[t["severity"]], t["id"])):
        lines += row(t["id"], t["severity"], t["cwe"], t["title"], t["title_ar"], t.get("advice", ""))
    from .vql import catalogue
    qs = catalogue()
    lines += ["", m(f"{len(qs)} استعلام VQL مدمج (فوق قاعدة بيانات البرنامج):"), ""]
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
        try:
            findings, err, pages = scan_site(target, timeout=args.timeout, deep=args.deep, crawl=args.crawl,
                                             max_pages=args.max_pages, max_depth=args.max_depth, delay=args.delay)
        except WebUnreachable as e:
            print(f"✖ {localize(str(e), lang)}", file=sys.stderr)
            return 2
        if err:
            notes.append(err)
        if args.crawl:
            notes.append("فحص ويب سلبي مع زحف على صفحات النطاق نفسه، بلا اختبار نشط.")
        else:
            notes.append("فحص ويب سلبي أعمق: تحليل الصفحة وفحص مسارات مكشوفة شائعة، بلا اختبار نشط."
                         if args.deep else "فحص ويب سلبي: طلب واحد فقط، بلا أي اختبار نشط.")
        return findings, target, 1, notes

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
        notes.append(err or f"استعلام OSV.dev عن الاعتماديات: {len(dep_findings)} ثغرة معروفة.")
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


def _main(argv: list[str]) -> int:
    if argv and argv[0] == "ui":
        return ui_main(argv[1:])
    if argv and argv[0] == "lsp":                    # language server for editors (stdio; --stdio accepted)
        from .lsp import main as lsp_main
        return lsp_main(argv[1:])
    if argv and argv[0] == "update":
        from .updater import cli_main as update_main
        return update_main(argv[1:])
    if argv and argv[0] in DELEGATES:               # mcp, export, compliance, history, triage, policy, surface, rules
        return run_subcommand(argv[0], argv[1:])
    lang = _lang_from_argv(argv)
    parser = build_parser(lang)
    args = parser.parse_args(argv)
    args.lang_resolved = lang = resolve_lang(args.lang)

    def m(text: str) -> str:
        return localize(text, lang)

    if args.list_rules:
        print(_list_rules(lang))
        return 0
    if not args.target:
        parser.error("the following arguments are required: target")
    is_web = args.target.startswith(("http://", "https://"))
    if (args.diff_base or args.diff_staged) and is_web:
        parser.error("--diff-base/--diff-staged need a local path inside a git repository")
    if (args.fix or args.fix_dry_run) and is_web:
        from .autofix import MSG as FIX_MSG
        parser.error(m(FIX_MSG["local_only"]))
    exports = _parse_exports(args.export, parser, m)
    _check_output_paths(args, parser, m)
    if args.compliance and _compliance_frameworks(args.compliance, m) is None:
        return 2                               # a typo in a framework name must not cost a whole scan first
    if args.triage == "" and is_web:
        parser.error(m("--triage مع عنوان ويب يحتاج مسار ملف الفرز: --triage=FILE"))
    if (args.sla or args.fail_on_sla or args.triage_update) and args.triage is None:
        parser.error(m("الخيارات --sla و--fail-on-sla و--triage-update تعمل مع --triage"))
    sla_days = _parse_triage_options(args, parser, m)
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
        print(m(f"حُفظ خط الأساس: {n} بصمة في {args.write_baseline}. الفحوص القادمة مع --baseline ستعرض الجديد فقط."))
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
        notes = list(notes) + ([f"خط الأساس: كُتمت {suppressed} نتيجة معروفة من أصل {size}؛ تُعرض النتائج الجديدة فقط."]
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

    def export(fmt: str) -> str:
        from .exporters import ExportError, export as do_export
        try:
            return do_export(findings, fmt, export_meta)
        except ExportError as e:
            hint = (" — " + m("لصيغة asff استخدم: kashif export REPORT.json -f asff --aws-account ID --aws-region REGION")
                    if fmt == "asff" else "")
            print(f"✖ {e}{hint}", file=sys.stderr)
            raise SystemExit(2) from None

    renderers = {"console": lambda: render_console(findings, target, files, notes,
                                                   color=not args.no_color and args.output is None, lang=lang),
                 "markdown": lambda: render_markdown(findings, target, files, notes, lang=lang),
                 "json": lambda: render_json(findings, target, files, notes, scanners=scanners),
                 "html": lambda: render_html(findings, target, files, notes, lang=lang),
                 "sarif": lambda: render_sarif(findings, target, files, notes, lang=lang, suppressed=hidden)}
    machine_stdout = False
    if args.all_formats:
        for ext, fmt in (("md", "markdown"), ("json", "json"), ("html", "html"), ("sarif", "sarif")):
            _write_file(f"{args.all_formats}.{ext}", renderers[fmt]())
        print(render_console(findings, target, files, notes, color=not args.no_color, lang=lang))
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
        from .exporters import STR as EXPORT_STR, project_risk, rating_label
        risk = project_risk(findings, export_meta)
        print(EXPORT_STR[mod_lang]["m_score"].format(score=risk["score"], rating=rating_label(risk["rating"], mod_lang),
                                                     n=risk["open_findings"]), file=side)
    if args.compliance or args.audit_report:
        code = _compliance_outputs(args, findings, target, files, notes, mod_lang, m, side)
        if code:
            return code
    if tri is not None and args.fail_on_sla:
        from . import triage
        breaches = triage.stats(tri, sla_days=sla_days)["sla"]["breaches"]
        if breaches:
            print(f"✖ {m(f'تجاوز مهلة الإصلاح: {len(breaches)} نتيجة مفتوحة')}", file=sys.stderr)
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
    if res.expired:
        print(f"⚠ {m(f'قبول خطر منتهٍ: أُعيد فتح {len(res.expired)} نتيجة')}", file=sys.stderr)
    if res.regressions:
        print(f"⚠ {m(f'ارتداد: عادت {len(res.regressions)} نتيجة بعد إصلاحها')}", file=sys.stderr)
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
