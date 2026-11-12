"""English catalog: engine precision fixes from the real-world corpus sweep, validators and reflection sinks."""

CATALOG: dict[str, str] = {
    "أزل محارف CR/LF من المدخلات قبل تسجيلها أو استخدم سجلًا مُهيكلًا (JSON).":
        "Strip CR/LF characters from input before logging it, or use structured (JSON) logging.",
    "بيانات غير موثوقة تُحلَّل كـ XML مع تفعيل الكيانات الخارجية (XXE)": "Tainted XML parsed with external entities enabled (XXE)",
    "عطّل DTD والكيانات الخارجية في المحلل (disallow-doctype-decl=true أو external-general-entities=false وACCESS_EXTERNAL_DTD=\"\") قبل تحليل XML غير موثوق.":
        "Disable DTDs and external entities on the parser (disallow-doctype-decl=true, or external-general-entities=false "
        "and ACCESS_EXTERNAL_DTD=\"\") before parsing untrusted XML.",
    "بيانات غير موثوقة تُعرض في قالب دون تهريب (|safe أو autoescape off)":
        "Tainted data rendered unescaped by a template (|safe / autoescape off)",
    "لا تستخدم |safe أو autoescape off مع بيانات المستخدم؛ دع القالب يهرّب القيمة أو عقّمها (bleach) أولًا.":
        "Do not use |safe or autoescape off with user data; let the template escape the value or sanitize it (bleach) "
        "first.",
    "فعّل التهريب التلقائي (autoescape=True / select_autoescape) ولا تعطّله إلا لقوالب نصية غير HTML.":
        "Enable auto-escaping (autoescape=True / select_autoescape); disable it only for non-HTML text templates.",
    "أزل noent: true (الافتراضي آمن) أو استخدم محللًا لا يحلّ الكيانات الخارجية.":
        "Remove noent: true (the default is safe) or use a parser that does not resolve external entities.",
    "لا تقيّم تعابير من المستخدم؛ إن لزم فاستخدم محللًا مقيّدًا بقائمة دوال مسموحة وبدون وصول للكائنات.":
        "Do not evaluate user-supplied expressions; if you must, use a restricted parser with an allow-list of "
        "functions and no object access.",
    "انقل سرّ الجلسة إلى متغير بيئة أو مدير أسرار، وولّده عشوائيًا (32 بايت على الأقل)، وأبطل القيمة المنشورة.":
        "Move the session secret to an environment variable or a secrets manager, generate it randomly (32 bytes or "
        "more), and rotate the published value.",
    "بيانات غير موثوقة تختار الصنف أو الدالة المستدعاة (انعكاس غير آمن)":
        "Tainted data selects the class or function that is invoked (unsafe reflection)",
    "لا تختر صنفًا أو دالة أو وحدة باسم من المدخلات؛ اربط القيم المسموحة بقاموس ثابت (allow-list) من الأسماء إلى الدوال.":
        "Do not choose a class, function or module by a name taken from input; map the allowed values to functions "
        "with a fixed dictionary (allow-list).",
    "لا تجلب كائنًا من الحاوية باسم من المدخلات؛ استخدم قائمة بيضاء من الأسماء المسموحة.":
        "Do not fetch a bean from the container by a name taken from input; use an allow-list of permitted names.",
    "تجاوز تحليل تدفق البيانات ميزانيته الزمنية فاكتمل بدقة أقل (ملخّصات أقل بين الدوال)؛ نتائج القواعد والأسرار "
    "وما اكتمل من نتائج التدفق محفوظة":
        "The data-flow analysis exceeded its time budget and finished with reduced precision (fewer inter-procedural "
        "summaries); rule, secret and completed data-flow findings are kept",
}

PATTERNS: list[tuple[str, str]] = [
    (r"تُركت (?P<n>\d+) ملفات مكتبات مضمَّنة \(vendored\) خارج التحليل — .*",
     r"\g<n> vendored library files (bundles, copied third-party libraries) were skipped"),
]
