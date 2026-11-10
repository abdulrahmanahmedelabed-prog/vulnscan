"""Command line interface."""

from __future__ import annotations

import argparse
import locale
import os
import pathlib
import sys

from . import __version__
from .deps import audit_dependencies
from .external import run_external
from .i18n import localize, to_en
from .model import SEVERITIES, SEVERITY_RANK, Finding, assign_fingerprints, sort_findings
from .report import render_console, render_html, render_json, render_markdown, render_sarif, summary_counts
from .baseline import apply_baseline, save_baseline
from .rules import RULES
from .scanner import scan_path
from .web import WebUnreachable, scan_site

AUTHORIZATION_NOTICE = (
    "افحص فقط ما تملكه أو ما لديك تصريح كتابي بفحصه. "
    "فحص أنظمة الآخرين دون إذن قد يكون مخالفًا للقانون."
)


LANG_CHOICES = ("auto", "ar", "en", "both")


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


def build_parser(lang: str = "both") -> argparse.ArgumentParser:
    def h(text: str) -> str:
        return localize(text, lang)

    p = argparse.ArgumentParser(
        prog="vulnscan",
        description=h("فحص أي برنامج (مجلد مصدر، ملف، أرشيف/APK/JAR، أو عنوان ويب) وإخراج تقرير مرتب من الأعلى خطورة إلى الأقل.")
                    + "\n" + h(AUTHORIZATION_NOTICE),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?", help=h("مسار مجلد/ملف/أرشيف، أو عنوان http(s):// للفحص السلبي، أو «ui» لتشغيل الواجهة الرسومية"))
    p.add_argument("--authorized", action="store_true",
                   help=h("أقرّ بأنني مخوَّل بفحص هذا الهدف (إلزامي لفحص عناوين الويب)"))
    p.add_argument("-f", "--format", choices=("console", "markdown", "json", "html", "sarif"), default="console",
                   help=h("صيغة التقرير؛ sarif للتكامل مع GitHub Code Scanning وVS Code"))
    p.add_argument("-o", "--output", help=h("اكتب التقرير إلى هذا الملف بدلًا من الشاشة"))
    p.add_argument("--all-formats", metavar="PREFIX", help=h("اكتب PREFIX.md و PREFIX.json و PREFIX.html معًا"))
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
    p.add_argument("--lang", choices=LANG_CHOICES, default="auto",
                   help=h("لغة المخرجات: ar عربية، en إنجليزية، both الاثنتان؛ auto (الافتراضي) يتبع VULNSCAN_LANG ثم لغة النظام"))
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--list-rules", action="store_true", help=h("اعرض القواعد المدمجة واخرج"))
    p.add_argument("--version", action="version", version=f"vulnscan {__version__}")
    return p


def ui_main(argv: list[str]) -> int:
    """`vulnscan ui`: start the local web dashboard."""
    lang = _lang_from_argv(argv)

    def h(text: str) -> str:
        return localize(text, lang)

    p = argparse.ArgumentParser(prog="vulnscan ui", description=h("تشغيل الواجهة الرسومية المحلية (لوحة تحكم، فحص، تقارير، إعدادات)."))
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
        if not args.authorized:
            raise SystemExit(localize("فحص عنوان ويب يتطلب --authorized (تأكيد أنك مخوَّل بفحص هذا الهدف).", lang))
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
        raise SystemExit(localize(f"الهدف غير موجود: {target}", lang))
    findings, files = scan_path(path, args.exclude, set(args.ignore_rule), jadx=not args.no_jadx,
                                jadx_timeout=args.jadx_timeout, jadx_include_libs=args.jadx_include_libs, notes=notes,
                                models_dirs=args.models, query_paths=args.query, queries=not args.no_queries,
                                audit=args.audit)
    if not args.no_deps:
        dep_findings, err = audit_dependencies(path)
        findings.extend(dep_findings)
        notes.append(err or f"استعلام OSV.dev عن الاعتماديات: {len(dep_findings)} ثغرة معروفة.")
    if not args.no_external:
        ext, ran = run_external(path)
        findings.extend(ext)
        if ran:
            notes.append(f"أدوات خارجية دُمجت نتائجها: {', '.join(ran)}")
    return findings, str(path), files, notes


def _force_utf8_output() -> None:
    """Arabic output crashes on a cp1252 Windows console; force UTF-8 if we can."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "ui":
        return ui_main(argv[1:])
    if argv and argv[0] == "lsp":                    # language server for editors (stdio; --stdio accepted)
        from .lsp import main as lsp_main
        return lsp_main(argv[1:])
    if argv and argv[0] == "update":
        from .updater import cli_main as update_main
        return update_main(argv[1:])
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
    if (args.diff_base or args.diff_staged) and args.target.startswith(("http://", "https://")):
        parser.error("--diff-base/--diff-staged need a local path inside a git repository")
    result = run(args)
    if isinstance(result, int):          # web target unreachable: message already printed
        return result
    findings, target, files, notes = result
    # Fingerprints are assigned once, on the complete list, so every report and the baseline agree.
    # The baseline is written and applied BEFORE --min-severity: it must record everything that exists
    # today, otherwise lower-severity pre-existing issues would come back as "new" later.
    assign_fingerprints(findings)

    if args.write_baseline:
        n = save_baseline(findings, args.write_baseline)
        print(m(f"حُفظ خط الأساس: {n} بصمة في {args.write_baseline}. الفحوص القادمة مع --baseline ستعرض الجديد فقط."))
        return 0
    if args.baseline:
        findings, suppressed, size = apply_baseline(findings, args.baseline)
        notes = list(notes) + ([f"خط الأساس: كُتمت {suppressed} نتيجة معروفة من أصل {size}؛ تُعرض النتائج الجديدة فقط."]
                               if size else ["خط الأساس غير موجود أو فارغ؛ كل النتائج تُعرض كجديدة."])
    if args.diff_base or args.diff_staged:   # after the baseline (which records everything), before --fail-on
        from .diffscope import DiffScopeError, compute, filter_findings
        try:
            scope = compute(args.target, args.diff_base, staged=args.diff_staged and not args.diff_base)
        except DiffScopeError as e:
            print(f"✖ {m(str(e))}", file=sys.stderr)
            return 2
        findings, dropped = filter_findings(findings, scope, args.target)
        notes = list(notes) + scope.notes + [f"نتائج خارج التغييرات لم تُعرض: {dropped}."]
    findings = [f for f in findings if SEVERITY_RANK[f.severity] <= SEVERITY_RANK[args.min_severity]]
    findings = sort_findings(findings)

    renderers = {"console": lambda: render_console(findings, target, files, notes,
                                                   color=not args.no_color and args.output is None, lang=lang),
                 "markdown": lambda: render_markdown(findings, target, files, notes, lang=lang),
                 "json": lambda: render_json(findings, target, files, notes),
                 "html": lambda: render_html(findings, target, files, notes, lang=lang),
                 "sarif": lambda: render_sarif(findings, target, files, notes, lang=lang)}
    if args.all_formats:
        for ext, fmt in (("md", "markdown"), ("json", "json"), ("html", "html"), ("sarif", "sarif")):
            pathlib.Path(f"{args.all_formats}.{ext}").write_text(renderers[fmt](), encoding="utf-8")
        print(render_console(findings, target, files, notes, color=not args.no_color, lang=lang))
        print("\n" + m(f"كُتبت التقارير: {args.all_formats}.md / .json / .html / .sarif"))
    else:
        text = renderers[args.format]()
        if args.output:
            pathlib.Path(args.output).write_text(text, encoding="utf-8")
            counts = summary_counts(findings)
            print(m(f"كُتب التقرير إلى {args.output}") + " — " + ", ".join(f"{s}:{counts[s]}" for s in SEVERITIES))
        else:
            print(text)

    if args.fail_on and any(SEVERITY_RANK[f.severity] <= SEVERITY_RANK[args.fail_on] for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
