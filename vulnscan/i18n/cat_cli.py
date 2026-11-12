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
    "عدد العمليات المتوازية لفحص الملفات (الافتراضي: عدد المعالجات؛ 1 يعطّل التوازي)":
        "Worker processes for the per-file scan (default: one per CPU; 1 disables parallelism)",
    "مجلد ذاكرة مؤقتة تزايدية: إعادة فحص مشروع لم يتغير أسرع بكثير وبالنتائج نفسها":
        "Incremental cache directory: re-scanning an unchanged project is much faster, with identical results",
    "لا تستخدم الذاكرة المؤقتة للفحص": "Do not use the scan cache",
    "لغة المخرجات: ar عربية، en إنجليزية، both الاثنتان؛ auto (الافتراضي) يتبع VULNSCAN_LANG ثم لغة النظام":
        "Output language: ar (Arabic), en (English) or both; auto (default) follows VULNSCAN_LANG, then the system locale",
    "اعرض القواعد المدمجة واخرج": "List the built-in rules and exit",
    "لا تلوّن مخرجات الطرفية": "Do not color the terminal output",
    "لا تفتح المتصفح تلقائيًا": "Do not open the browser automatically",
    # ------------------------------------------------------------------ 1.0: report formats, add-on flags
    "صيغة التقرير: console أو markdown أو json أو html أو sarif (لـ GitHub Code Scanning وVS Code)، "
    "أو صيغة تصدير: gitlab-sast وcodeclimate (GitLab) وdefectdojo وsonarqube وjunit وcsv "
    "وjira-csv وgithub-issues وasff وocsf وrisk (القائمة: kashif export --list-formats)":
        "Report format: console, markdown, json, html or sarif (GitHub Code Scanning, VS Code), or an export "
        "format: gitlab-sast and codeclimate (GitLab), defectdojo, sonarqube, junit, csv, jira-csv, github-issues, "
        "asff, ocsf, risk (list: kashif export --list-formats)",
    "اكتب أيضًا الفحص بصيغة تصدير إلى ملف، مثل gitlab-sast=gl-sast-report.json (يمكن تكراره)":
        "Also write the scan in an export format to a file, e.g. gitlab-sast=gl-sast-report.json (repeatable)",
    "اطبع درجة خطر كاشِف للمشروع (من 0 إلى 10؛ وسيلة لترتيب الأولويات وليست درجة CVSS)":
        "Print the project's Kashif risk score (0 to 10; a triage aid, not a CVSS score)",
    "اطبع بعد التقرير ملخص الامتثال لهذه الأطر (مفصولة بفواصل، أو all؛ القائمة: kashif compliance --list-frameworks)":
        "After the report, print a compliance summary for these frameworks (comma-separated, or all; list: "
        "kashif compliance --list-frameworks)",
    "اكتب تقرير المدقق (HTML قابل للطباعة) يربط كل نتيجة بضوابط أطر الامتثال":
        "Write the auditor report (printable HTML) that maps every finding to compliance framework controls",
    "طبّق قرارات الفرز (الافتراضي ‎.kashif/triage.json في المشروع): تُخفى الإنذارات الكاذبة والمخاطر المقبولة "
    "من التقرير ومن --fail-on، ويُنبَّه على القبول المنتهي والارتداد":
        "Apply triage decisions (default: .kashif/triage.json in the project): false positives and accepted risks "
        "are left out of the report and of --fail-on; expired acceptances and regressions are flagged",
    "احفظ في ملف الفرز ما تغيّر: أول ظهور والإصلاح التلقائي والارتداد وانتهاء القبول "
    "(لـ CI على الفرع الرئيسي فقط، لا لطلبات الدمج)":
        "Save what changed to the triage file: first seen, fixed automatically, regressions, expired acceptances "
        "(for CI on the main branch only, never on pull requests)",
    "حالات الفرز التي تبقى في التقرير (الافتراضي open,confirmed؛ all للجميع)":
        "Triage statuses kept in the report (default open,confirmed; all keeps everything)",
    "مهلة الإصلاح بالأيام لكل خطورة، مثل critical=7,high=30,medium=90 (مع --triage)":
        "Days allowed to fix each severity, e.g. critical=7,high=30,medium=90 (with --triage)",
    "أعد رمز خروج 1 إذا تجاوزت نتيجة مفتوحة مهلة إصلاحها (مع --triage)":
        "Exit with code 1 when an open finding is past its fix deadline (with --triage)",
    "بوابة الأمان من ملف سياسة (kashif.yml) أو قالب مدمج مثل strict؛ يُطبَّق kashif.yml الموجود في المجلد المفحوص "
    "تلقائيًا":
        "Security gate from a policy file (kashif.yml) or a builtin preset such as strict; a kashif.yml in the "
        "scanned directory is applied automatically",
    "لا تطبّق ملف السياسة الموجود في المجلد المفحوص": "Do not apply the policy file found in the scanned directory",
    "مجلد التقارير التي يطلبها ملف السياسة (reports)؛ دونه لا تُكتب":
        "Directory for the reports the policy file asks for (reports:); without it they are not written",
    "استخدم حزمة قواعد مثبّتة بهذا الاسم (يمكن تكراره؛ انظر kashif rules list)":
        "Use the installed rule pack of this name (repeatable; see kashif rules list)",
    "استخدم كل حزم القواعد المثبّتة": "Use every installed rule pack",
    # ------------------------------------------------------------------ 1.0: sub-commands (kashif --help)
    "الأوامر الفرعية:": "Sub-commands:",
    "شغّل kashif <أمر فرعي> --help لعرض خياراته.": "Run kashif <sub-command> --help for its options.",
    "خادم لغة (LSP) للمحررات: الثغرات تحت الكود أثناء الكتابة مع إصلاحات سريعة":
        "Language server (LSP) for editors: vulnerabilities underlined as you type, with quick fixes",
    "خادم MCP لمساعدات البرمجة بالذكاء الاصطناعي (Claude Code وCursor وVS Code وWindsurf وZed)":
        "MCP server for AI coding assistants (Claude Code, Cursor, VS Code, Windsurf, Zed)",
    "تحديث كاشِف إلى أحدث إصدار رسمي بعد التحقق منه (--check للتحقق فقط)":
        "Update Kashif to the latest official release, verified (--check only checks)",
    "تحويل تقرير JSON إلى صيغة أداة أخرى (DefectDojo وSonarQube وJUnit وCSV وJira وGitLab وASFF وOCSF)":
        "Convert a JSON report to another tool's format (DefectDojo, SonarQube, JUnit, CSV, Jira, GitLab, ASFF, OCSF)",
    "ربط النتائج بأطر الامتثال (OWASP وASVS وCWE Top 25 وPCI DSS وNIST وISO 27001) وتقرير للمدقق":
        "Map findings to compliance frameworks (OWASP, ASVS, CWE Top 25, PCI DSS, NIST, ISO 27001) and write an "
        "auditor report",
    "الأسرار في تاريخ git: كل سرّ أُودِع يومًا ولو حُذف لاحقًا (الاسم البديل secrets-history)":
        "Secrets in git history: every secret ever committed, even if deleted later (alias secrets-history)",
    "فرز النتائج داخل المستودع: إنذار كاذب أو قبول خطر أو لن يُصلَح، مع سجل تدقيق ومهلة إصلاح":
        "Triage stored in the repository: false positive, accepted risk, won't fix, with an audit log and fix SLAs",
    "السياسة ككود: بوابة أمان من kashif.yml (check وinit وvalidate وpresets)":
        "Policy as code: a security gate from kashif.yml (check, init, validate, presets)",
    "خريطة سطح الهجوم: نقاط الدخول ومدخلاتها والمصادقة الظاهرة والمصارف التي تصل إليها":
        "Attack-surface map: entry points, their inputs, the visible authentication and the sinks they reach",
    "اكتب قواعدك واختبرها: حزم القواعد (new وtest وlint وpack وverify وinstall وlist وdocs)":
        "Write and test your own rules: rule packs (new, test, lint, pack, verify, install, list, docs)",
    # ------------------------------------------------------------------ 1.0: console messages
    "--triage مع عنوان ويب يحتاج مسار ملف الفرز: --triage=FILE":
        "--triage with a web URL needs the path of the triage file: --triage=FILE",
    "الخيارات --sla و--fail-on-sla و--triage-update تعمل مع --triage":
        "--sla, --fail-on-sla and --triage-update work together with --triage",
    "حالة فرز غير معروفة": "Unknown triage status",
    "لا يوجد ملف سياسة في المجلد المفحوص": "No policy file in the scanned folder",
    "قيمة --sla غير صالحة (مثال: critical=7,high=30,medium=90)": "Invalid --sla value (example: critical=7,high=30,medium=90)",
    "صيغة --export هي FORMAT=FILE بصيغة تصدير معروفة": "--export takes FORMAT=FILE with a known export format",
    "لصيغة asff استخدم: kashif export REPORT.json -f asff --aws-account ID --aws-region REGION":
        "for asff use: kashif export REPORT.json -f asff --aws-account ID --aws-region REGION",
    "ملف السياسة يطلب تقارير (reports) لم تُكتب: حدّد مجلدها بالخيار --policy-reports-dir":
        "The policy file asks for reports (reports:) that were not written: choose their directory with "
        "--policy-reports-dir",
    "الهدف مطلوب: مسار مجلد أو ملف أو أرشيف، أو عنوان http(s)://":
        "the following arguments are required: target (a folder, file or archive path, or an http(s):// URL)",
    "الخياران --diff-base و--diff-staged يحتاجان مسارًا محليًا داخل مستودع git":
        "--diff-base/--diff-staged need a local path inside a git repository",
    "تحتاج صيغة asff إلى رقم حساب AWS من 12 رقمًا ومنطقة AWS صالحة: --aws-account ID --aws-region REGION "
    "(مثل --aws-account 123456789012 --aws-region eu-west-1)":
        "the asff format needs a 12-digit AWS account ID and a valid AWS region: --aws-account ID --aws-region REGION "
        "(e.g. --aws-account 123456789012 --aws-region eu-west-1)",
    "لصيغة asff: رقم حساب AWS (12 رقمًا)، مع --aws-region": "asff: the AWS account ID (12 digits), with --aws-region",
    "لصيغة asff: منطقة AWS لـ Security Hub، مثل eu-west-1": "asff: the AWS region of Security Hub, e.g. eu-west-1",
    "منفذ الواجهة المحلية (الافتراضي 8765)": "port of the local web UI (default 8765)",
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
    (r"حزمة القواعد غير مثبّتة: (?P<names>.+)", r"Rule pack not installed: \g<names>"),
    (r"إطار امتثال غير معروف: (?P<name>.+)", r"Unknown compliance framework: \g<name>"),
    (r"مجلد ملف الإخراج غير موجود: (?P<dir>.+)", r"The folder of the output file does not exist: \g<dir>"),
    (r"تعذّرت قراءة ملف خط الأساس \(ليس JSON صالحًا\): (?P<path>.+)",
     r"Cannot read the baseline file (not valid JSON): \g<path>"),
    (r"ملف خط الأساس ليس من إنتاج --write-baseline \(لا قائمة fingerprints فيه\)، فعُدّ فارغًا وكل النتائج تُعرض "
     r"كجديدة: (?P<path>.+)",
     r"The baseline file was not written by --write-baseline (it has no fingerprints list); it counts as empty and "
     r"every finding is shown as new: \g<path>"),
    (r"تجاوز مهلة الإصلاح: (?P<n>\d+) نتيجة مفتوحة", r"Fix deadline (SLA) exceeded: \g<n> open findings"),
    (r"لم يُحدَّث ملف الفرز: المجلد ‎\.kashif أو ملف triage\.json في المشروع رابط رمزي يشير إلى خارجه",
     r"The triage file was not updated: .kashif or triage.json in the project is a symbolic link pointing "
     r"outside it"),
    (r"قبول خطر منتهٍ: أُعيد فتح (?P<n>\d+) نتيجة", r"Risk acceptance expired: \g<n> findings re-opened"),
    (r"ارتداد: عادت (?P<n>\d+) نتيجة بعد إصلاحها", r"Regression: \g<n> findings are back after being fixed"),
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
