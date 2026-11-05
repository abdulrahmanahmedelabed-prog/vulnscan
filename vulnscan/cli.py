"""Command line interface."""

from __future__ import annotations

import argparse
import pathlib
import sys

from . import __version__
from .deps import audit_dependencies
from .external import run_external
from .model import SEVERITIES, SEVERITY_RANK, Finding, sort_findings
from .report import render_console, render_html, render_json, render_markdown, summary_counts
from .rules import RULES
from .scanner import scan_path
from .web import scan_url

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
    p.add_argument("target", help="مسار مجلد/ملف/أرشيف، أو عنوان http(s):// للفحص السلبي")
    p.add_argument("--authorized", action="store_true",
                   help="أقرّ بأنني مخوَّل بفحص هذا الهدف (إلزامي لفحص عناوين الويب)")
    p.add_argument("-f", "--format", choices=("console", "markdown", "json", "html"), default="console")
    p.add_argument("-o", "--output", help="اكتب التقرير إلى هذا الملف بدلًا من الشاشة")
    p.add_argument("--all-formats", metavar="PREFIX", help="اكتب PREFIX.md و PREFIX.json و PREFIX.html معًا")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="استثنِ مسارات (يمكن تكراره)")
    p.add_argument("--ignore-rule", action="append", default=[], metavar="ID", help="تجاهل قاعدة بمعرّفها")
    p.add_argument("--min-severity", choices=SEVERITIES, default="info", help="اعرض هذه الخطورة فما فوق فقط")
    p.add_argument("--fail-on", choices=SEVERITIES, help="أعد رمز خروج 1 إذا وُجدت نتيجة بهذه الخطورة أو أعلى (لـ CI)")
    p.add_argument("--no-deps", action="store_true", help="لا تستعلم OSV.dev عن ثغرات الاعتماديات (دون إنترنت)")
    p.add_argument("--no-external", action="store_true", help="لا تشغّل bandit/semgrep/gitleaks/npm حتى لو كانت مثبّتة")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--list-rules", action="store_true", help="اعرض القواعد المدمجة واخرج")
    p.add_argument("--version", action="version", version=f"vulnscan {__version__}")
    return p


def _list_rules() -> str:
    lines = [f"{len(RULES)} قاعدة مدمجة:", ""]
    for r in sorted(RULES, key=lambda r: (SEVERITY_RANK[r.severity], r.id)):
        lines.append(f"{r.id:<8} {r.severity:<9} {r.cwe:<9} {r.title_ar} — {r.title}")
    return "\n".join(lines)


def run(args: argparse.Namespace) -> tuple[list[Finding], str, int, list[str]]:
    notes: list[str] = []
    target = args.target
    if target.startswith(("http://", "https://")):
        if not args.authorized:
            raise SystemExit("فحص عنوان ويب يتطلب --authorized (تأكيد أنك مخوَّل بفحص هذا الهدف).")
        findings, err = scan_url(target)
        if err:
            notes.append(err)
        notes.append("فحص ويب سلبي: طلب واحد فقط، بلا أي اختبار نشط.")
        return findings, target, 1, notes

    path = pathlib.Path(target)
    if not path.exists():
        raise SystemExit(f"الهدف غير موجود: {target}")
    findings, files = scan_path(path, args.exclude, set(args.ignore_rule))
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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_rules:
        print(_list_rules())
        return 0
    findings, target, files, notes = run(args)
    findings = [f for f in findings if SEVERITY_RANK[f.severity] <= SEVERITY_RANK[args.min_severity]]
    findings = sort_findings(findings)

    renderers = {"console": lambda: render_console(findings, target, files, notes, color=not args.no_color and args.output is None),
                 "markdown": lambda: render_markdown(findings, target, files, notes),
                 "json": lambda: render_json(findings, target, files, notes),
                 "html": lambda: render_html(findings, target, files, notes)}
    if args.all_formats:
        for ext, fn in (("md", render_markdown), ("json", render_json), ("html", render_html)):
            pathlib.Path(f"{args.all_formats}.{ext}").write_text(fn(findings, target, files, notes), encoding="utf-8")
        print(render_console(findings, target, files, notes, color=not args.no_color))
        print(f"\nكُتبت التقارير: {args.all_formats}.md / .json / .html")
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
