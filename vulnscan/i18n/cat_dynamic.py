"""English catalog: PATTERNS for text built at run time: data-flow trail steps, source labels, scan notes.

Each regex matches the WHOLE Arabic string (after whitespace normalization). Named groups hold identifiers, paths,
numbers or nested labels; nested labels are translated recursively by vulnscan.i18n.to_en, so e.g.
"المصدر: معامل نقطة الدخول q ← run()" becomes "Source: entry-point parameter q → run()".
"""

# Arabic forms of the data-flow sink labels (vulnscan/models/*.json "label" and the built-in sinks of taint.py).
# The engine writes the label into Arabic text ("نقطة الخطر: <label>", "… وتصل إلى <label>") through
# sink_label_ar(); CATALOG below maps each Arabic form back to its English label, so to_en() restores the exact
# English. Code identifiers (APIs, libraries, protocols) stay in Latin letters. Labels are display text only:
# they are not part of rule ids, English titles or fingerprints. A label missing here (e.g. from a user's own
# model file) is kept as written.
SINK_LABELS_AR: dict[str, str] = {
    # built-in sinks (taint.py)
    "HTTP response": "استجابة HTTP",
    "dynamic method call": "استدعاء دالة ديناميكي",
    "subprocess argument": "وسيط عملية فرعية",
    "template source written to a file": "مصدر قالب يُكتب في ملف",
    "template |safe": "قالب مع المرشّح safe",
    "unescaped view output": "مخرجات عرض غير مُهرَّبة",
    # vulnscan/models/*.json
    "AI system prompt (prompt injection)": "تعليمات النظام للمساعد الذكي (حقن التعليمات)",
    "Android WebView URL": "عنوان يُحمَّل في WebView (أندرويد)",
    "DOM (XSS)": "شجرة DOM (XSS)",
    "DOM / jQuery (XSS)": "شجرة DOM عبر jQuery (XSS)",
    "DQL / SQL": "استعلام DQL أو SQL",
    "DataView.RowFilter expression": "تعبير DataView.RowFilter",
    "HTML (InnerHtml)": "محتوى HTML (InnerHtml)",
    "HTML marked safe (XSS)": "HTML موسوم بأنه آمن (XSS)",
    "HTML output (XSS)": "مخرجات HTML (XSS)",
    "HTML output (htp)": "مخرجات HTML (htp)",
    "HTML response (XSS)": "استجابة HTML (XSS)",
    "HTML response / DOM (XSS)": "استجابة HTML أو DOM (XSS)",
    "HTTP response (XSS)": "استجابة HTTP (XSS)",
    "HTTP response body (XSS)": "متن استجابة HTTP (XSS)",
    "HTTP response body (reflected XSS)": "متن استجابة HTTP (XSS انعكاسي)",
    "HTTP response header": "ترويسة استجابة HTTP",
    "HTTP session attribute": "سمة في جلسة HTTP",
    "HttpClient.BaseAddress": "العنوان الأساسي لـ HttpClient (BaseAddress)",
    "JNDI lookup": "بحث JNDI",
    "JavaScript engine": "محرّك JavaScript",
    "Ktor respondFile": "إرسال ملف في Ktor (respondFile)",
    "Ktor template name": "اسم قالب في Ktor",
    "LDAP filter": "مرشّح LDAP",
    "LDAP filter (DirectorySearcher.Filter)": "مرشّح LDAP (DirectorySearcher.Filter)",
    "LDAP filter (ldap3)": "مرشّح LDAP (ldap3)",
    "Location header": "ترويسة Location",
    "NoSQL query": "استعلام NoSQL",
    "NoSQL query (MongoDB)": "استعلام NoSQL (MongoDB)",
    "NoSQL query (legacy collection update)": "استعلام NoSQL (تحديث مجموعة بالواجهة القديمة)",
    "NoSQL server-side JavaScript": "كود JavaScript تنفّذه قاعدة NoSQL على الخادم",
    "PowerShell script": "سكربت PowerShell",
    "Process launch (shell)": "تشغيل عملية (عبر shell)",
    "ProcessBuilder": "إنشاء عملية (ProcessBuilder)",
    "Realm predicate": "شرط استعلام Realm",
    "SQL": "عبارة SQL",
    "SQL (Android SQLiteDatabase)": "عبارة SQL (Android SQLiteDatabase)",
    "SQL (CommandText)": "عبارة SQL (CommandText)",
    "SQL (ContentResolver selection)": "عبارة SQL (شرط selection في ContentResolver)",
    "SQL (Exposed raw SQL)": "عبارة SQL (SQL خام في Exposed)",
    "SQL (R2DBC DatabaseClient / Spring JdbcClient)": "عبارة SQL (R2DBC DatabaseClient / Spring JdbcClient)",
    "SQL (Spring JDBC / Hibernate / jOOQ)": "عبارة SQL (Spring JDBC / Hibernate / jOOQ)",
    "SQL (asyncpg / databases)": "عبارة SQL (asyncpg / databases)",
    "SQL (gorm clause)": "عبارة SQL (شرط gorm)",
    "SQL (gorm inline condition)": "عبارة SQL (شرط مضمَّن في gorm)",
    "SQL (jOOQ DSLContext plain SQL)": "عبارة SQL (SQL نصي في jOOQ DSLContext)",
    "SQL (kotliquery)": "عبارة SQL (kotliquery)",
    "SQL (pgx)": "عبارة SQL (pgx)",
    "SQL (xorm)": "عبارة SQL (xorm)",
    "SQL execute": "تنفيذ SQL",
    "SQL query": "استعلام SQL",
    "SQL query (query builder raw fragment)": "استعلام SQL (جزء خام في باني الاستعلامات)",
    "SQL query (sqlite / pg-promise)": "استعلام SQL (sqlite / pg-promise)",
    "SQL query (sqlite3 get)": "استعلام SQL (sqlite3 get)",
    "Select AI (natural language to SQL)": "توليد SQL من اللغة الطبيعية (Select AI)",
    "Velocity template evaluation": "تقييم قالب Velocity",
    "XML parser (DOM / SAX / XMLReader)": "محلل XML (DOM / SAX / XMLReader)",
    "XML parser (dom4j DocumentHelper)": "محلل XML (dom4j DocumentHelper)",
    "XML parser (dom4j SAXReader / JDOM SAXBuilder)": "محلل XML (dom4j SAXReader / JDOM SAXBuilder)",
    "XML stream reader (StAX)": "قارئ تدفق XML (StAX)",
    "XML unmarshaller (JAXB)": "محوّل XML إلى كائنات (JAXB)",
    "XPath": "تعبير XPath",
    "XPath query": "استعلام XPath",
    "XSLT stylesheet": "ورقة أنماط XSLT",
    "XSLT transformer / validator": "محوّل XSLT أو مدقّق XML",
    "archive extraction directory": "مجلد استخراج الأرشيف",
    "asyncio loop.subprocess_exec": "عملية فرعية (asyncio loop.subprocess_exec)",
    "asyncio loop.subprocess_shell": "أمر shell (asyncio loop.subprocess_shell)",
    "attributed/HTML text": "نص منسَّق أو HTML",
    "buffer copy length": "طول النسخ إلى مخزن",
    "code / template evaluation": "تقييم كود أو قالب",
    "code execution": "تنفيذ كود",
    "code string (timeit)": "نص كود يُنفَّذ (timeit)",
    "container bean lookup by name": "البحث عن مكوّن في الحاوية باسمه",
    "deserialization": "فك تسلسل",
    "dynamic PL/SQL / job code": "كود PL/SQL ديناميكي أو كود مهمة مجدولة",
    "dynamic SQL": "عبارة SQL ديناميكية",
    "dynamic attribute dispatch": "استدعاء سمة ديناميكي",
    "dynamic class loading": "تحميل أصناف ديناميكي",
    "dynamic import": "استيراد ديناميكي",
    "dynamic module loading": "تحميل وحدات ديناميكي",
    "dynamic require/import": "تحميل وحدة ديناميكي (require/import)",
    "eval/Function/vm": "تقييم كود (eval/Function/vm)",
    "eval/create_function": "تقييم كود (eval/create_function)",
    "eval/exec": "تقييم كود (eval/exec)",
    "exec.Command": "تشغيل أمر (exec.Command)",
    "file inclusion": "تضمين ملف",
    "file path": "مسار ملف",
    "file path (pathlib)": "مسار ملف (pathlib)",
    "filesystem operation": "عملية على نظام الملفات",
    "filesystem operation (source and destination)": "عملية على نظام الملفات (المصدر والوجهة)",
    "format string": "سلسلة تنسيق",
    "innerHTML (DOM XSS)": "الخاصية innerHTML (XSS في DOM)",
    "jQuery DOM insertion (XSS)": "إدراج في DOM عبر jQuery (XSS)",
    "libcurl option (URL / proxy)": "خيار libcurl (العنوان أو الوكيل)",
    "local file path (boto3 S3 transfer)": "مسار ملف محلي (نقل boto3 S3)",
    "location (open redirect)": "الخاصية location (تحويل مفتوح)",
    "log injection": "حقن السجل",
    "log injection (console)": "حقن السجل (console)",
    "os.spawn* program": "برنامج يُشغَّل عبر os.spawn*",
    "os.system": "أمر نظام (os.system)",
    "outbound HTTP (SSRF)": "طلب HTTP صادر (SSRF)",
    "outbound HTTP URL (Fuel)": "عنوان طلب HTTP صادر (Fuel)",
    "outbound HTTP URL (SSRF)": "عنوان طلب HTTP صادر (SSRF)",
    "outbound URL (SSRF)": "عنوان طلب صادر (SSRF)",
    "plugin / code loading": "تحميل إضافات أو كود",
    "process arguments": "وسائط عملية",
    "process arguments (ProcessStartInfo.Arguments)": "وسائط عملية (ProcessStartInfo.Arguments)",
    "redirect": "تحويل",
    "redirect (RedirectLocation)": "تحويل (RedirectLocation)",
    "reflection / assembly load": "انعكاس أو تحميل تجميعات",
    "reflective method lookup": "بحث انعكاسي عن دالة",
    "remote shell command (SSH)": "أمر shell عن بُعد (SSH)",
    "server-side session": "جلسة على الخادم",
    "shell command": "أمر shell",
    "subprocess": "عملية فرعية",
    "template": "قالب",
    "template (SSTI)": "قالب (SSTI)",
    "template / eval": "قالب أو تقييم كود",
    "unbounded buffer copy": "نسخ غير محدود إلى مخزن",
    "uploaded file save path": "مسار حفظ ملف مرفوع",
}


def sink_label_ar(label: str) -> str:
    """The Arabic form of a sink label for Arabic engine text; an unknown label (a user model) is kept as is."""
    return SINK_LABELS_AR.get(label, label)


# Arabic sink label -> English label, so "نقطة الخطر: <Arabic label>" and titles translate back exactly
CATALOG: dict[str, str] = {ar: en for en, ar in SINK_LABELS_AR.items()}

# a code identifier / call target as printed in steps: names, dotted paths, $vars, :BIND items, {placeholders}
_ID = r"[^\s()؀-ۿ]+?"
# a source location "file:line" (paths may contain spaces or Arabic)
_LOC = r".+?:\d+"
# a stored column "TABLE.COLUMN" (either part may be * for "unknown")
_COL = r"[\w$#*]+\.[\w$#*]+"

PATTERNS: list[tuple[str, str]] = [
    # ---- data-flow trail steps (taint.py _step / flow.py)
    (rf"استدعاء (?P<callee>{_ID})\(\)", r"Call to \g<callee>()"),
    (r"نقطة الخطر: (?P<label>.+)", r"Sink: \g<label>"),
    (rf"يمرّ عبر (?P<name>{_ID})\(\) ويُعاد", r"Passes through \g<name>() and is returned"),
    (rf"return من (?P<name>{_ID})\(\)", r"Returned from \g<name>()"),

    # ---- snippets of data-flow findings: "المصدر: <source label> [← callee()]"
    (rf"المصدر: (?P<src>.+) ← (?P<callee>{_ID})\(\)", r"Source: \g<src> → \g<callee>()"),
    (r"المصدر: (?P<src>.+)", r"Source: \g<src>"),

    # ---- source labels (extra.taint_source; also inside snippets and steps)
    (r"معامل نقطة الدخول (?P<param>[^\s؀-ۿ]+)", r"entry-point parameter \g<param>"),
    (rf"قيمة من (?P<name>{_ID})\(\)", r"value returned by \g<name>()"),
    # second-order (stored) sources: a column a user wrote earlier, read back elsewhere
    (rf"بيانات مخزّنة في (?P<col>{_COL}) \(كتبها مستخدم في (?P<loc>{_LOC})\)",
     r"stored data in \g<col> (written by a user at \g<loc>)"),
    (rf"بيانات مخزّنة في العمود (?P<column>[\w$#*]+) يُحدَّد وقت التشغيل \(كتبها مستخدم في (?P<loc>{_LOC})\)",
     r"stored data in column \g<column> of a table chosen at run time (written by a user at \g<loc>)"),
    (rf"بيانات مخزّنة في (?P<col>{_COL}) وقُرئت من جدول يُحدَّد وقت التشغيل \(كتبها مستخدم في (?P<loc>{_LOC})\)",
     r"stored data in \g<col>, read back through a table chosen at run time (written by a user at \g<loc>)"),

    # ---- an assignment step whose right-hand side is a source label: "x = <label>"
    (r"(?P<lhs>[^\s=؀-ۿ][^=؀-ۿ]*?) = (?P<rhs>.*[؀-ۿ].*)", r"\g<lhs> = \g<rhs>"),

    # ---- finding titles synthesized at run time (title_ar; the English title field already exists)
    (rf"بيانات غير موثوقة تمرّ عبر (?P<callee>{_ID})\(\) وتصل إلى (?P<label>.+)",
     r"Tainted data flows through \g<callee>() into \g<label>"),
    (r"(?P<title>.+) — الجدول يُحدَّد وقت التشغيل \(الربط باسم العمود\)",
     r"\g<title> (table chosen at run time; linked by column name)"),
    (r"اعتمادية مصابة بثغرة معروفة: (?P<name>\S+) (?P<ver>\S+)", r"Vulnerable dependency: \g<name> \g<ver>"),
    (r"حزمة npm مصابة: (?P<name>\S+)", r"Vulnerable npm package: \g<name>"),

    # ---- advice synthesized at run time (deps.py OSV, external.py npm audit)
    (r"حدّث (?P<name>\S+) إلى إصدار مُصحَّح \(راجع (?P<url>\S+)\)\.",
     r"Upgrade \g<name> to a patched version (see \g<url>)."),
    (r"حدّث (?P<name>\S+) إلى (?P<fixed>\S+?)\.", r"Upgrade \g<name> to \g<fixed>."),
    (r"حدّث (?P<name>\S+) \(npm audit fix\)\.", r"Upgrade \g<name> (npm audit fix)."),

    # ---- scan notes: scanner.py
    (r"jadx: فُكّ تجميع 1 ملف Java \(مع أخطاء جزئية في بعض الدوال\)\.",
     r"jadx: decompiled 1 Java file (with partial errors in some methods)."),
    (r"jadx: فُكّ تجميع 1 ملف Java\.", r"jadx: decompiled 1 Java file."),
    (r"jadx: فُكّ تجميع (?P<n>\d+) ملف Java \(مع أخطاء جزئية في بعض الدوال\)\.",
     r"jadx: decompiled \g<n> Java files (with partial errors in some methods)."),
    (r"jadx: فُكّ تجميع (?P<n>\d+) ملف Java\.", r"jadx: decompiled \g<n> Java files."),
    (r"jadx تجاوز المهلة \((?P<sec>\d+) ثانية\)؛ جرّب مهلة أكبر\.",
     r"jadx timed out after \g<sec> seconds; try a longer timeout."),
    (r"تعذّر تشغيل jadx: (?P<err>.+)", r"Could not run jadx: \g<err>"),
    (r"jadx لم يُنتج أي ملفات: (?P<err>.+)", r"jadx produced no files: \g<err>"),
    (r"الواجهة الأمامية \((?P<lang>[^)]+)\): تخطّت (?P<n>\d+) من (?P<total>\d+) عبارة في (?P<rel>.+?) "
     r"\(الأسطر (?P<lines>[^)]*)\) — frontend skipped .*",
     r"The \g<lang> frontend skipped \g<n> of \g<total> statements in \g<rel> (lines \g<lines>)"),
    (r"ملفات متداخلة بعمق غير طبيعي \(مولَّدة أو عدائية\) استُثنيت من تحليل التدفق: (?P<files>.+?)"
     r" — too deeply nested for dataflow analysis",
     r"Abnormally deeply nested files (generated or hostile) were excluded from dataflow analysis: \g<files>"),
    (r"تعذّر تحليل تدفق البيانات \((?P<err>[\w.]+)\)؛ عُرضت نتائج القواعد فقط — dataflow analysis failed, pattern results only",
     r"Dataflow analysis failed (\g<err>); showing pattern-rule results only."),

    # ---- scan notes and errors: server.py
    (r"فحص ويب سلبي مع زحف على (?P<n>\d+) صفحة من النطاق نفسه \(طلب كل (?P<delay>[\d.e+-]+) ثانية\)\.",
     r"Passive web scan that crawled \g<n> pages on the same origin (one request every \g<delay> s)."),
    (r"الهدف غير موجود: (?P<target>.+)", r"Target not found: \g<target>"),
    (r"OSV\.dev: (?P<n>\d+) ثغرة معروفة في الاعتماديات\.", r"OSV.dev: \g<n> known vulnerabilities in dependencies."),
    (r"أدوات خارجية: (?P<tools>.+)", r"External tools: \g<tools>"),
    (r"(?P<n>\d+) ملف مرفوع", r"\g<n> uploaded files"),
    (r"vulnscan UI: (?P<url>\S+) \(Ctrl\+C للإيقاف\)", r"vulnscan UI: \g<url>   (press Ctrl+C to stop)"),
]
