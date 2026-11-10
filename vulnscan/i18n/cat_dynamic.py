"""English catalog: PATTERNS for text built at run time: data-flow trail steps, source labels, scan notes.

Each regex matches the WHOLE Arabic string (after whitespace normalization). Named groups hold identifiers, paths,
numbers or nested labels; nested labels are translated recursively by vulnscan.i18n.to_en, so e.g.
"المصدر: معامل نقطة الدخول q ← run()" becomes "Source: entry-point parameter q → run()".
"""

CATALOG: dict[str, str] = {}

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
