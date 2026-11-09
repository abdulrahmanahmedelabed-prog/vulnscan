"""Command line interface."""

from __future__ import annotations

import argparse
import pathlib
import sys

from . import __version__
from .deps import audit_dependencies
from .external import run_external
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulnscan",
        description="فحص أي برنامج (مجلد مصدر، ملف، أرشيف/APK/JAR، أو عنوان ويب) وإخراج تقرير مرتب من الأعلى خطورة إلى الأقل.\n"
                    + AUTHORIZATION_NOTICE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?", help="مسار مجلد/ملف/أرشيف، أو عنوان http(s):// للفحص السلبي، أو «ui» لتشغيل الواجهة الرسومية")
    p.add_argument("--authorized", action="store_true",
                   help="أقرّ بأنني مخوَّل بفحص هذا الهدف (إلزامي لفحص عناوين الويب)")
    p.add_argument("-f", "--format", choices=("console", "markdown", "json", "html", "sarif"), default="console",
                   help="صيغة التقرير؛ sarif للتكامل مع GitHub Code Scanning وVS Code")
    p.add_argument("-o", "--output", help="اكتب التقرير إلى هذا الملف بدلًا من الشاشة")
    p.add_argument("--all-formats", metavar="PREFIX", help="اكتب PREFIX.md و PREFIX.json و PREFIX.html معًا")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="استثنِ مسارات (يمكن تكراره)")
    p.add_argument("--ignore-rule", action="append", default=[], metavar="ID", help="تجاهل قاعدة بمعرّفها")
    p.add_argument("--min-severity", choices=SEVERITIES, default="info", help="اعرض هذه الخطورة فما فوق فقط")
    p.add_argument("--fail-on", choices=SEVERITIES, help="أعد رمز خروج 1 إذا وُجدت نتيجة بهذه الخطورة أو أعلى (لـ CI)")
    p.add_argument("--baseline", metavar="FILE", help="قارن مع خط أساس: اعرض النتائج الجديدة فقط (النتائج المعروفة تُكتم)")
    p.add_argument("--write-baseline", metavar="FILE", help="احفظ بصمات النتائج الحالية في خط أساس ثم اخرج (لتبنّي الأداة على كود قائم)")
    p.add_argument("--no-deps", action="store_true", help="لا تستعلم OSV.dev عن ثغرات الاعتماديات (دون إنترنت)")
    p.add_argument("--no-external", action="store_true", help="لا تشغّل bandit/semgrep/gitleaks/npm حتى لو كانت مثبّتة")
    p.add_argument("--deep", action="store_true", help="فحص ويب أعمق: تحليل HTML وفحص مسارات مكشوفة شائعة (طلبات إضافية محدودة)")
    p.add_argument("--crawl", action="store_true", help="زحف على صفحات الموقع من نفس النطاق وفحصها (لتطبيقات مثل Moodle وبوابات الجامعات)")
    p.add_argument("--max-pages", type=int, default=20, metavar="N", help="أقصى عدد صفحات عند الزحف (الافتراضي 20)")
    p.add_argument("--delay", type=float, default=0.5, metavar="SEC", help="تأخير بين طلبات الزحف بالثواني (الافتراضي 0.5؛ ألطف على الخادم)")
    p.add_argument("--max-depth", type=int, default=2, metavar="N", help="أقصى عمق للزحف (الافتراضي 2)")
    p.add_argument("--timeout", type=float, default=20.0, metavar="SEC",
                   help="مهلة كل طلب ويب بالثواني (الافتراضي 20؛ يُعاد الطلب الأول مرة بمهلة مضاعفة)")
    p.add_argument("--models", action="append", default=[], metavar="DIR",
                   help="مجلد (أو ملف JSON) نماذج إضافية لمحرّك تدفق البيانات: مصادر ونقاط خطر ومُعقّمات خاصة بمكتباتك")
    p.add_argument("--query", action="append", default=[], metavar="PATH",
                   help="ملف أو مجلد استعلامات VQL إضافية (لغة استعلام تصريحية فوق قاعدة بيانات البرنامج)")
    p.add_argument("--no-queries", action="store_true", help="لا تشغّل استعلامات VQL المدمجة")
    p.add_argument("--audit", action="store_true",
                   help="ملف التدقيق: اعرض أيضًا كل استدعاء خطر (eval/shell/SQL/pickle…) لم يُثبت تحليل التدفق وصول مدخل إليه")
    p.add_argument("--no-jadx", action="store_true", help="لا تفكّ تجميع APK/JAR/AAR/DEX حتى لو كان jadx مثبّتًا")
    p.add_argument("--jadx-timeout", type=int, default=600, metavar="SEC", help="مهلة jadx بالثواني (الافتراضي 600)")
    p.add_argument("--jadx-include-libs", action="store_true", help="افحص أيضًا مكتبات الطرف الثالث داخل الكود المفكوك")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--list-rules", action="store_true", help="اعرض القواعد المدمجة واخرج")
    p.add_argument("--version", action="version", version=f"vulnscan {__version__}")
    return p


def ui_main(argv: list[str]) -> int:
    """`vulnscan ui`: start the local web dashboard."""
    p = argparse.ArgumentParser(prog="vulnscan ui", description="تشغيل الواجهة الرسومية المحلية (لوحة تحكم، فحص، تقارير، إعدادات).")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--no-browser", action="store_true", help="لا تفتح المتصفح تلقائيًا")
    a = p.parse_args(argv)
    from .server import serve
    serve(a.port, open_browser=not a.no_browser)
    return 0


def _list_rules() -> str:
    lines = [f"{len(RULES) + 1} قاعدة مدمجة:", ""]
    for r in sorted(RULES, key=lambda r: (SEVERITY_RANK[r.severity], r.id)):
        lines.append(f"{r.id:<8} {r.severity:<9} {r.cwe:<9} {r.title_ar} — {r.title}")
    from .scanner import ENTROPY_RULE as e
    lines.append(f"{e['id']:<8} {e['severity']:<9} {e['cwe']:<9} {e['title_ar']} — {e['title']} (إنتروبيا شانون)")
    from .taint import TAINT_RULES
    lines += ["", f"{len(TAINT_RULES)} قاعدة تدفق بيانات وAPEX (12 لغة منها PL/SQL، مدركة للأنواع، عبر الملفات):", ""]
    for t in sorted(TAINT_RULES, key=lambda t: (SEVERITY_RANK[t["severity"]], t["id"])):
        lines.append(f"{t['id']:<8} {t['severity']:<9} {t['cwe']:<9} {t['title_ar']} — {t['title']}")
    from .vql import catalogue
    qs = catalogue()
    lines += ["", f"{len(qs)} استعلام VQL مدمج (فوق قاعدة بيانات البرنامج):", ""]
    for q in sorted(qs, key=lambda q: (SEVERITY_RANK.get(q["severity"], 9), q["id"])):
        lines.append(f"{q['id']:<32} {q['severity']:<9} {q['cwe']:<9} {q['title_ar']}")
    return "\n".join(lines)


def run(args: argparse.Namespace) -> tuple[list[Finding], str, int, list[str]] | int:
    notes: list[str] = []
    target = args.target
    if target.startswith(("http://", "https://")):
        if not args.authorized:
            raise SystemExit("فحص عنوان ويب يتطلب --authorized (تأكيد أنك مخوَّل بفحص هذا الهدف).")
        try:
            findings, err, pages = scan_site(target, timeout=args.timeout, deep=args.deep, crawl=args.crawl,
                                             max_pages=args.max_pages, max_depth=args.max_depth, delay=args.delay)
        except WebUnreachable as e:
            print(f"✖ {e}", file=sys.stderr)
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
        raise SystemExit(f"الهدف غير موجود: {target}")
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
    args = build_parser().parse_args(argv)
    if args.list_rules:
        print(_list_rules())
        return 0
    if not args.target:
        build_parser().error("the following arguments are required: target")
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
        print(f"حُفظ خط الأساس: {n} بصمة في {args.write_baseline}. الفحوص القادمة مع --baseline ستعرض الجديد فقط.")
        return 0
    if args.baseline:
        findings, suppressed, size = apply_baseline(findings, args.baseline)
        notes = list(notes) + ([f"خط الأساس: كُتمت {suppressed} نتيجة معروفة من أصل {size}؛ تُعرض النتائج الجديدة فقط."]
                               if size else ["خط الأساس غير موجود أو فارغ؛ كل النتائج تُعرض كجديدة."])
    findings = [f for f in findings if SEVERITY_RANK[f.severity] <= SEVERITY_RANK[args.min_severity]]
    findings = sort_findings(findings)

    renderers = {"console": lambda: render_console(findings, target, files, notes, color=not args.no_color and args.output is None),
                 "markdown": lambda: render_markdown(findings, target, files, notes),
                 "json": lambda: render_json(findings, target, files, notes),
                 "html": lambda: render_html(findings, target, files, notes),
                 "sarif": lambda: render_sarif(findings, target, files, notes)}
    if args.all_formats:
        for ext, fn in (("md", render_markdown), ("json", render_json), ("html", render_html), ("sarif", render_sarif)):
            pathlib.Path(f"{args.all_formats}.{ext}").write_text(fn(findings, target, files, notes), encoding="utf-8")
        print(render_console(findings, target, files, notes, color=not args.no_color))
        print(f"\nكُتبت التقارير: {args.all_formats}.md / .json / .html / .sarif")
    else:
        text = renderers[args.format]()
        if args.output:
            pathlib.Path(args.output).write_text(text, encoding="utf-8")
            counts = summary_counts(findings)
            print(f"كُتب التقرير إلى {args.output} — " + ", ".join(f"{s}:{counts[s]}" for s in SEVERITIES))
        else:
            print(text)

    if args.fail_on and any(SEVERITY_RANK[f.severity] <= SEVERITY_RANK[args.fail_on] for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
