"""English catalog: vulnscan/cli.py (argparse help, console messages, scan notes) and vulnscan/server.py
(scan notes and errors shown in the web UI).

Note: argparse formats help strings with %-interpolation, so English help text must not contain a bare "%".
"""

CATALOG: dict[str, str] = {
    # ------------------------------------------------------------------ argparse: descriptions
    "فحص أي برنامج (مجلد مصدر، ملف، أرشيف/APK/JAR، أو عنوان ويب) وإخراج تقرير مرتب من الأعلى خطورة إلى الأقل.":
        "Scan any software (source folder, file, archive/APK/JAR, or web URL) and produce a report ordered from "
        "highest to lowest severity.",
    "افحص فقط ما تملكه أو ما لديك تصريح كتابي بفحصه. فحص أنظمة الآخرين دون إذن قد يكون مخالفًا للقانون.":
        "Only scan systems you own or have written permission to test. Scanning other people's systems without "
        "permission may be illegal.",
    "تشغيل الواجهة الرسومية المحلية (لوحة تحكم، فحص، تقارير، إعدادات).":
        "Start the local web UI (dashboard, scans, reports, settings).",
    # ------------------------------------------------------------------ argparse: options
    "مسار مجلد/ملف/أرشيف، أو عنوان http(s):// للفحص السلبي، أو «ui» لتشغيل الواجهة الرسومية":
        "Folder, file or archive path; an http(s):// URL for a passive web scan; or \"ui\" to start the web UI",
    "أقرّ بأنني مخوَّل بفحص هذا الهدف (إلزامي لفحص عناوين الويب)":
        "Confirm that you are authorized to scan this target (required for web URLs)",
    "صيغة التقرير؛ sarif للتكامل مع GitHub Code Scanning وVS Code":
        "Report format; use sarif for GitHub Code Scanning and VS Code",
    "اكتب التقرير إلى هذا الملف بدلًا من الشاشة": "Write the report to this file instead of standard output",
    "اكتب PREFIX.md و PREFIX.json و PREFIX.html معًا": "Write PREFIX.md, PREFIX.json, PREFIX.html and PREFIX.sarif at once",
    "استثنِ مسارات (يمكن تكراره)": "Exclude paths matching GLOB (repeatable)",
    "تجاهل قاعدة بمعرّفها": "Ignore a rule by its ID (repeatable)",
    "اعرض هذه الخطورة فما فوق فقط": "Report only findings at or above this severity",
    "أعد رمز خروج 1 إذا وُجدت نتيجة بهذه الخطورة أو أعلى (لـ CI)":
        "Exit with code 1 if any finding is at or above this severity (for CI)",
    "قارن مع خط أساس: اعرض النتائج الجديدة فقط (النتائج المعروفة تُكتم)":
        "Compare with a baseline: report only new findings (known findings are suppressed)",
    "احفظ بصمات النتائج الحالية في خط أساس ثم اخرج (لتبنّي الأداة على كود قائم)":
        "Save the fingerprints of the current findings to a baseline and exit (to adopt the tool on an existing codebase)",
    "لا تستعلم OSV.dev عن ثغرات الاعتماديات (دون إنترنت)":
        "Do not query OSV.dev for vulnerable dependencies (offline mode)",
    "لا تشغّل bandit/semgrep/gitleaks/npm حتى لو كانت مثبّتة":
        "Do not run bandit/semgrep/gitleaks/npm even if they are installed",
    "فحص ويب أعمق: تحليل HTML وفحص مسارات مكشوفة شائعة (طلبات إضافية محدودة)":
        "Deeper web scan: analyze the HTML and probe common exposed paths (a limited number of extra requests)",
    "زحف على صفحات الموقع من نفس النطاق وفحصها (لتطبيقات مثل Moodle وبوابات الجامعات)":
        "Crawl and scan same-origin pages (for applications such as Moodle and university portals)",
    "أقصى عدد صفحات عند الزحف (الافتراضي 20)": "Maximum number of pages to crawl (default 20)",
    "تأخير بين طلبات الزحف بالثواني (الافتراضي 0.5؛ ألطف على الخادم)":
        "Delay between crawl requests in seconds (default 0.5; gentler on the server)",
    "أقصى عمق للزحف (الافتراضي 2)": "Maximum crawl depth (default 2)",
    "مهلة كل طلب ويب بالثواني (الافتراضي 20؛ يُعاد الطلب الأول مرة بمهلة مضاعفة)":
        "Timeout for each web request in seconds (default 20; the first request is retried once with double the timeout)",
    "مجلد (أو ملف JSON) نماذج إضافية لمحرّك تدفق البيانات: مصادر ونقاط خطر ومُعقّمات خاصة بمكتباتك":
        "Folder (or JSON file) of extra data-flow models: sources, sinks and sanitizers for your own libraries",
    "ملف أو مجلد استعلامات VQL إضافية (لغة استعلام تصريحية فوق قاعدة بيانات البرنامج)":
        "File or folder of extra VQL queries (a declarative query language over the program database)",
    "لا تشغّل استعلامات VQL المدمجة": "Do not run the built-in VQL queries",
    "ملف التدقيق: اعرض أيضًا كل استدعاء خطر (eval/shell/SQL/pickle…) لم يُثبت تحليل التدفق وصول مدخل إليه":
        "Audit profile: also report every dangerous call (eval/shell/SQL/pickle…) that data-flow analysis did not "
        "prove is reached by user input",
    "لا تفكّ تجميع APK/JAR/AAR/DEX حتى لو كان jadx مثبّتًا": "Do not decompile APK/JAR/AAR/DEX even if jadx is installed",
    "مهلة jadx بالثواني (الافتراضي 600)": "jadx timeout in seconds (default 600)",
    "افحص أيضًا مكتبات الطرف الثالث داخل الكود المفكوك": "Also scan third-party libraries inside the decompiled code",
    "لغة المخرجات: ar عربية، en إنجليزية، both الاثنتان؛ auto (الافتراضي) يتبع VULNSCAN_LANG ثم لغة النظام":
        "Output language: ar (Arabic), en (English) or both; auto (default) follows VULNSCAN_LANG, then the system locale",
    "اعرض القواعد المدمجة واخرج": "List the built-in rules and exit",
    "لا تفتح المتصفح تلقائيًا": "Do not open the browser automatically",
    # ------------------------------------------------------------------ console messages and scan notes (cli.py)
    "فحص عنوان ويب يتطلب --authorized (تأكيد أنك مخوَّل بفحص هذا الهدف).":
        "Scanning a web URL requires --authorized (confirmation that you are authorized to scan this target).",
    "فحص ويب سلبي مع زحف على صفحات النطاق نفسه، بلا اختبار نشط.":
        "Passive web scan with a same-origin crawl; no active testing.",
    "فحص ويب سلبي أعمق: تحليل الصفحة وفحص مسارات مكشوفة شائعة، بلا اختبار نشط.":
        "Deeper passive web scan: page analysis and common exposed-path probes; no active testing.",
    "فحص ويب سلبي: طلب واحد فقط، بلا أي اختبار نشط.": "Passive web scan: a single request; no active testing.",
    "خط الأساس غير موجود أو فارغ؛ كل النتائج تُعرض كجديدة.":
        "Baseline is missing or empty; all findings are reported as new.",
    # ------------------------------------------------------------------ scan notes and errors (server.py)
    "فحص عنوان ويب يتطلب تأكيد الصلاحية.": "Scanning a web URL requires confirming that you are authorized.",
    "فحص ويب سلبي أعمق: تحليل الصفحة ومسارات مكشوفة شائعة.":
        "Deeper passive web scan: page analysis and common exposed paths.",
    "فحص ويب سلبي: طلب واحد فقط.": "Passive web scan: a single request.",
    "تدفق بيانات": "data flow",
}

PATTERNS: list[tuple[str, str]] = [
    # --list-rules headings
    (r"(?P<n>\d+) قاعدة مدمجة:", r"\g<n> built-in rules:"),
    (r"(?P<n>\d+) قاعدة تدفق بيانات وAPEX \(12 لغة منها PL/SQL، مدركة للأنواع، عبر الملفات\):",
     r"\g<n> data-flow and APEX rules (12 languages including PL/SQL; type-aware, cross-file):"),
    (r"(?P<n>\d+) استعلام VQL مدمج \(فوق قاعدة بيانات البرنامج\):",
     r"\g<n> built-in VQL queries (over the program database):"),
    # errors
    (r"الهدف غير موجود: (?P<target>.+)", r"Target not found: \g<target>"),
    # scan notes (cli.py); a count of exactly 1 gets the English singular
    (r"استعلام OSV\.dev عن الاعتماديات: 1 ثغرة معروفة\.", r"OSV.dev dependency check: 1 known vulnerability."),
    (r"خط الأساس: كُتمت 1 نتيجة معروفة من أصل (?P<size>\d+)؛ تُعرض النتائج الجديدة فقط\.",
     r"Baseline: suppressed 1 known finding out of \g<size>; reporting new findings only."),
    (r"حُفظ خط الأساس: 1 بصمة في (?P<file>.+?)\. الفحوص القادمة مع --baseline ستعرض الجديد فقط\.",
     r"Baseline saved: 1 fingerprint in \g<file>. Future scans with --baseline will report new findings only."),
    (r"فحص ويب سلبي مع زحف على 1 صفحة من النطاق نفسه \(طلب كل (?P<delay>[\d.e+-]+) ثانية\)\.",
     r"Passive web scan with a same-origin crawl of 1 page (one request every \g<delay> s)."),
    (r"OSV\.dev: 1 ثغرة معروفة في الاعتماديات\.", r"OSV.dev: 1 known vulnerability in dependencies."),
    (r"1 ملف مرفوع", r"1 uploaded file"),
    (r"استعلام OSV\.dev عن الاعتماديات: (?P<n>\d+) ثغرة معروفة\.",
     r"OSV.dev dependency check: \g<n> known vulnerabilities."),
    (r"أدوات خارجية دُمجت نتائجها: (?P<tools>[^؀-ۿ]+)", r"Merged results from external tools: \g<tools>"),
    (r"خط الأساس: كُتمت (?P<n>\d+) نتيجة معروفة من أصل (?P<size>\d+)؛ تُعرض النتائج الجديدة فقط\.",
     r"Baseline: suppressed \g<n> known findings out of \g<size>; reporting new findings only."),
    # console messages (cli.py)
    (r"حُفظ خط الأساس: (?P<n>\d+) بصمة في (?P<file>.+?)\. الفحوص القادمة مع --baseline ستعرض الجديد فقط\.",
     r"Baseline saved: \g<n> fingerprints in \g<file>. Future scans with --baseline will report new findings only."),
    (r"كُتبت التقارير: (?P<prefix>.+?)\.md / \.json / \.html / \.sarif",
     r"Reports written: \g<prefix>.md / .json / .html / .sarif"),
    (r"كُتب التقرير إلى (?P<file>.+)", r"Report written to \g<file>"),
    # scan notes (server.py)
    (r"فحص ويب سلبي مع زحف على (?P<n>\d+) صفحة من النطاق نفسه \(طلب كل (?P<delay>[\d.e+-]+) ثانية\)\.",
     r"Passive web scan with a same-origin crawl of \g<n> pages (one request every \g<delay> s)."),
    (r"OSV\.dev: (?P<n>\d+) ثغرة معروفة في الاعتماديات\.", r"OSV.dev: \g<n> known vulnerabilities in dependencies."),
    (r"أدوات خارجية: (?P<tools>[^؀-ۿ]+)", r"External tools: \g<tools>"),
    (r"(?P<n>\d+) ملف مرفوع", r"\g<n> uploaded files"),
    (r"\.py \.js \.ts \(تدفق بيانات\)", r".py .js .ts (data flow)"),
]
