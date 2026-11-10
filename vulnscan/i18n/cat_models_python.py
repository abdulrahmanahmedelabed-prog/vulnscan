"""English catalog: Python library models added in the breadth expansion."""

CATALOG: dict[str, str] = {
    # remote / shell command execution (paramiko exec_command, Fabric, Invoke)
    "لا تبنِ أوامر الصدفة (المحلية أو البعيدة عبر SSH) من المدخلات؛ هرّب كل وسيط بـ shlex.quote وتحقق منه بقائمة بيضاء.":
        "Do not build shell commands (local or remote over SSH) from input; quote every argument with shlex.quote "
        "and validate it against an allowlist.",
    # MongoDB server-side JavaScript (bson Code, mongoengine where / exec_js)
    "لا تبنِ شيفرة JavaScript لـ MongoDB ($where / Code / where()) من المدخلات؛ استخدم مشغّلات الاستعلام ومرّر القيم عبر scope.":
        "Do not build MongoDB JavaScript ($where / Code / where()) from input; use query operators and pass "
        "values through the scope.",
    "بيانات غير موثوقة تصل إلى شيفرة JavaScript تنفّذها MongoDB":
        "Tainted data reaches a MongoDB server-side JavaScript query",
    # Django mark_safe / SafeString, markupsafe Markup, format_html
    "لا تُعلِّم مدخلات المستخدم كـ HTML آمن (mark_safe / Markup)؛ هرّبها أولًا أو مرّرها وسيطًا إلى format_html.":
        "Do not mark user input as safe HTML (mark_safe / Markup); escape it first or pass it as an argument to "
        "format_html.",
}

PATTERNS: list[tuple[str, str]] = []
