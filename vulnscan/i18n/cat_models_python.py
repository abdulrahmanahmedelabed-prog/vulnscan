"""English catalog: Python library models added in the breadth expansion."""

CATALOG: dict[str, str] = {
    # remote / shell command execution (paramiko exec_command, Fabric, Invoke)
    "لا تبنِ أوامر الصدفة (المحلية أو البعيدة عبر SSH) من المدخلات؛ هرّب كل وسيط بـ shlex.quote وتحقق منه بقائمة بيضاء.":
        "Do not build shell commands (local or remote over SSH) from input; quote every argument with shlex.quote "
        "and validate it against an allowlist.",
    # MongoDB server-side JavaScript (bson Code, mongoengine where / exec_js)
    "لا تبنِ كود JavaScript لـ MongoDB ($where / Code / where()) من المدخلات؛ استخدم مشغّلات الاستعلام ومرّر القيم عبر scope.":
        "Do not build MongoDB JavaScript ($where / Code / where()) from input; use query operators and pass "
        "values through the scope.",
    # the wording of Kashif 1.0.1 (الشيفرة), still in older reports
    "لا تبنِ شيفرة JavaScript لـ MongoDB ($where / Code / where()) من المدخلات؛ استخدم مشغّلات الاستعلام ومرّر القيم عبر scope.":
        "Do not build MongoDB JavaScript ($where / Code / where()) from input; use query operators and pass "
        "values through the scope.",
    "بيانات غير موثوقة تصل إلى كود JavaScript تنفّذه MongoDB":
        "Tainted data reaches a MongoDB server-side JavaScript query",
    # the wording of Kashif 1.0.1 (الشيفرة), still in older reports
    "بيانات غير موثوقة تصل إلى شيفرة JavaScript تنفّذها MongoDB":
        "Tainted data reaches a MongoDB server-side JavaScript query",
    # Django mark_safe / SafeString, markupsafe Markup, format_html
    "لا تُعلِّم مدخلات المستخدم كـ HTML آمن (mark_safe / Markup)؛ هرّبها أولًا أو مرّرها وسيطًا إلى format_html.":
        "Do not mark user input as safe HTML (mark_safe / Markup); escape it first or pass it as an argument to "
        "format_html.",
    # stored SSTI: template source text built from data and written to a template file
    "بيانات غير موثوقة تُكتب في نص قالب يُعرض لاحقًا (حقن قوالب مخزّن SSTI)":
        "Tainted data written into a template's source (stored SSTI)",
    "لا تبنِ نص القالب من مدخلات المستخدم؛ خزّن المحتوى بيانات ومرّره متغيرًا إلى قالب ثابت.":
        "Do not build template source from user input; store the content as data and pass it as a variable to a "
        "fixed template.",
    "طبّع المسار وتحقق أنه داخل المجلد المسموح قبل فحص وجوده أو خصائصه: الجواب يكشف ملفات خارج ذلك المجلد.":
        "Canonicalize the path and verify it stays inside the allowed directory before checking whether it exists or "
        "reading its metadata: the answer reveals files outside that directory.",
    "لا تفعّل feature_external_ges / resolve_entities؛ استخدم defusedxml أو محللًا بإعداداته الآمنة الافتراضية لتحليل XML غير موثوق.":
        "Do not turn on feature_external_ges / resolve_entities; parse untrusted XML with defusedxml or a parser left "
        "at its safe defaults.",
}

PATTERNS: list[tuple[str, str]] = []
