"""English catalog: scanner.py, server.py, deps.py, external.py, taint.py, stored.py, queries/*.vql, model.py.

Exact (static) strings only; text built at run time (notes with counts, trail steps, source labels) is in
cat_dynamic.PATTERNS. semantic.py advice is in cat_rules; report.py carries its own bilingual labels.
"""

CATALOG: dict[str, str] = {
    # ---- model.py: SEVERITY_AR
    "حرج": "Critical",
    "عالٍ": "High",
    "متوسط": "Medium",
    "منخفض": "Low",
    "معلوماتي": "Info",

    # ---- scanner.py: entropy detector (SEC011), dumps, project hygiene
    "سلسلة عالية العشوائية (سرّ محتمل)": "High-entropy string (possible secret)",
    "تحقّق: إن كان سرًّا حقيقيًا فأبطله وانقله إلى متغير بيئة أو مدير أسرار.":
        "Verify it: if this is a real secret, revoke it and move it to an environment variable or a secrets manager.",
    "تحقّق: إن كان سرًّا حقيقيًا فأبطله وانقله إلى متغير بيئة أو مدير أسرار. "
    "إن كان قيمة مشروعة (تجزئة، معرّف) فاستثنِ السطر بـ # nosec.":
        "Verify it: if this is a real secret, revoke it and move it to an environment variable or a secrets manager. "
        "If it is a legitimate value (a hash or an identifier), suppress the line with # nosec.",
    "ملف قاعدة بيانات أو نسخة": "Database file or dump",
    "لا تضع نسخ قواعد البيانات في المستودع أو الحزمة؛ قد تحتوي بيانات حساسة.":
        "Do not commit database dumps to the repository or ship them in the package; they may contain sensitive data.",
    "ملف .env غير مُستثنى في .gitignore": ".env file not excluded in .gitignore",
    "أضف .env إلى .gitignore.": "Add .env to .gitignore.",
    "Dockerfile بلا تعليمة USER (يعمل بصلاحيات root)": "Dockerfile has no USER instruction (runs as root)",
    "أضف مستخدمًا غير root وبدّل إليه بتعليمة USER.": "Create a non-root user and switch to it with a USER instruction.",

    # ---- scanner.py: notes
    "jadx غير مثبّت؛ لم يُفكّ تجميع الكود الثنائي (فُحصت الملفات النصية فقط).":
        "jadx is not installed; the bytecode was not decompiled (only text files were scanned).",
    "jadx لم يُنتج أي ملفات.": "jadx produced no files.",
    "تعذّر تشغيل استعلامات VQL — VQL queries failed": "Could not run the VQL queries.",

    # ---- external.py: gitleaks / npm audit
    "سر مكتشف بواسطة gitleaks": "Secret detected by gitleaks",
    "أبطل السر وأزله من التاريخ.": "Revoke the secret and purge it from the repository history.",

    # ---- server.py: notes and errors
    "فحص عنوان ويب يتطلب تأكيد الصلاحية.": "Scanning a web URL requires confirming that you are authorized to test it.",
    "فحص ويب سلبي أعمق: تحليل الصفحة ومسارات مكشوفة شائعة.":
        "Deeper passive web scan: page analysis plus checks for commonly exposed paths.",
    "فحص ويب سلبي: طلب واحد فقط.": "Passive web scan: a single request only.",
    ".py .js .ts (تدفق بيانات)": ".py .js .ts (dataflow)",

    # ---- taint.py: source marks
    "الذكاء الاصطناعي": "AI",
    "بيانات مخزّنة": "stored data",
    "يُحدَّد وقت التشغيل": "chosen at run time",

    # ---- taint.py: built-in sinks
    "بيانات غير موثوقة تصل إلى وسيط لأمر خارجي": "Untrusted data reaches an argument of an external command",
    "تحقّق من الوسيط بقائمة بيضاء، وارفض القيم التي تبدأ بـ -، ولا تمرّر مسارات غير مُطبَّعة.":
        "Validate the argument against an allowlist, reject values that start with -, and never pass non-canonicalized paths.",
    "بيانات غير موثوقة تُعاد في استجابة HTTP (XSS انعكاسي)": "Untrusted data returned in an HTTP response (reflected XSS)",
    "هرّب المخرجات (html.escape / markupsafe) أو استخدم قوالب تُهرِّب تلقائيًا.":
        "Escape the output (html.escape / markupsafe) or use a template engine with auto-escaping.",

    # ---- taint.py: AI output reaching a sink (DF020/DF021)
    "نص يولّده الذكاء الاصطناعي يُنفَّذ كـ SQL أو كود": "AI-generated text executed as SQL / code",
    "لا تنفّذ مخرجات النموذج مباشرة: اسمح فقط بقوالب استعلام ثابتة بمتغيرات ربط، أو تحقّق من الناتج بمحلّل وقائمة بيضاء، "
    "ونفّذ بحساب قراءة فقط محدود الصلاحيات.":
        "Never execute model output directly: allow only fixed query templates with bind variables, or validate the output "
        "with a parser and an allowlist, and run it under a least-privilege, read-only account.",
    "لا تنفّذ كودًا يولّده النموذج؛ اربط أفعاله بإجراءات ثابتة مسموحة.":
        "Never execute model-generated code; map the model's actions to a fixed set of allowed procedures.",
    "نص يولّده الذكاء الاصطناعي يُعرض كـ HTML دون تهريب (XSS عبر النموذج)":
        "AI-generated text rendered as HTML without escaping (XSS via the model)",
    "هرّب مخرجات النموذج بـ apex_escape.html أو اعرضها كنص؛ النموذج قد يُخدع ليولّد سكربتًا.":
        "Escape model output with apex_escape.html or render it as plain text; the model can be tricked into generating script.",

    # ---- taint.py: second-order / stored flows (DF023/DF024)
    "حقن SQL من الدرجة الثانية: بيانات خزّنها مستخدم تُنفَّذ لاحقًا كـ SQL":
        "Second-order SQL injection: stored user data executed as SQL",
    "عامل البيانات المقروءة من الجداول كمدخلات غير موثوقة: استخدم متغيرات الربط وDBMS_ASSERT عند بناء SQL منها.":
        "Treat data read from tables as untrusted input: use bind variables and DBMS_ASSERT when building SQL from it.",
    "حقن من الدرجة الثانية: بيانات خزّنها مستخدم تُنفَّذ لاحقًا ككود":
        "Second-order injection: stored user data executed as code",
    "لا تنفّذ كودًا مبنيًا من بيانات مخزّنة؛ استخدم إجراءات ثابتة.":
        "Never execute code built from stored data; call fixed procedures instead.",
    "حقن أوامر من الدرجة الثانية: بيانات خزّنها مستخدم تصل لاحقًا إلى أمر نظام":
        "Second-order command injection: stored user data reaches an OS command",
    "عامل البيانات المقروءة من قاعدة البيانات كمدخلات غير موثوقة: لا تمرّرها إلى الصدفة.":
        "Treat data read from the database as untrusted input: never pass it to a shell.",
    "حقن أوامر من الدرجة الثانية: بيانات خزّنها مستخدم تصل لاحقًا إلى تنفيذ عملية":
        "Second-order command injection: stored user data reaches process execution",
    "تحقق من البيانات المخزّنة بقائمة بيضاء قبل تمريرها كوسائط.":
        "Validate stored data against an allowlist before passing it as arguments.",
    "XSS مخزّن: بيانات حفظها مستخدم تُكتب في الصفحة دون تهريب":
        "Stored XSS: data a user saved is written to the page unescaped",
    "هرّب القيمة عند العرض (apex_escape.html / htf.escape_sc) لا عند الحفظ فقط.":
        "Escape the value when rendering it (apex_escape.html / htf.escape_sc), not only when saving it.",

    # ---- queries/*.vql: @name_ar and @advice
    "إعداد CORS يسمح بأي أصل (*)": "CORS configured with a wildcard origin",
    "حدّد الأصول المسموحة صراحة، خاصة مع بيانات الاعتماد.":
        "List the allowed origins explicitly, especially when credentials are allowed.",
    "نقطة دخول مُوجَّهة بلا مُزخرِف مصادقة": "Routed entry point without an authentication decorator",
    "تأكد أن المسار عام عن قصد، وإلا أضف مصادقة (login_required، jwt_required، guard…).":
        "Confirm that the route is intentionally public; otherwise add authentication (login_required, jwt_required, a guard, …).",
    "نقطة دخول مُوجَّهة تصل إلى أمر shell عبر سلسلة استدعاءات":
        "Routed entry point can reach a shell command through the call graph",
    "راجع سلسلة الاستدعاءات؛ إن مرّت مدخلات المستخدم فيها فهذا حقن أوامر محتمل.":
        "Review the call chain; if user input flows along it, this is a potential command injection.",
    "كلمة مرور أو سر مُمرَّر كوسيط نصي حرفي": "Password or secret passed as a string literal keyword argument",
    "اقرأ الأسرار من متغيرات البيئة أو مدير أسرار.": "Read secrets from environment variables or a secrets manager.",
    "setTimeout/setInterval بسلسلة نصية (eval ضمني)": "setTimeout/setInterval called with a string (implicit eval)",
    "مرّر دالة بدل سلسلة نصية.": "Pass a function instead of a string.",
    "JWT بلا تحقق من التوقيع أو بخوارزمية none": "JWT decoded without signature verification or with the none algorithm",
    "تحقق دائمًا من التوقيع وحدّد الخوارزميات المسموحة صراحة.":
        "Always verify the signature and specify the allowed algorithms explicitly.",
    "عشوائية غير مشفّرة لقيمة حساسة": "Non-cryptographic randomness used for a sensitive value",
    "استخدم secrets (Python) أو crypto.randomBytes (Node) للرموز وكلمات المرور.":
        "Use secrets (Python) or crypto.randomBytes (Node) to generate tokens and passwords.",
    "استعلام SQL مُركّب بتنسيق نصي أو ضمّ سلاسل": "SQL statement built with string formatting or concatenation",
    "استخدم استعلامات مُعَلَّمة (placeholders) بدل تركيب نص الاستعلام.":
        "Use parameterized queries (placeholders) instead of building the query text.",
    "subprocess مع shell=True وأمر غير ثابت": "subprocess with shell=True and a non-literal command",
    "أزل shell=True ومرّر قائمة وسائط ثابتة البرنامج.":
        "Remove shell=True and pass an argument list whose program is fixed.",
    "تعطيل التحقق من شهادة TLS في طلب HTTP": "TLS certificate verification disabled in an HTTP call",
    "فعّل التحقق من الشهادة؛ وإن كانت ذاتية التوقيع فاستخدم ملف CA خاصًا أو تثبيتًا (pinning).":
        "Enable certificate verification; for a self-signed certificate, use a private CA bundle or certificate pinning.",
    "yaml.load بلا Loader صريح": "yaml.load without an explicit safe Loader",
    "استخدم yaml.safe_load أو مرّر Loader=yaml.SafeLoader.": "Use yaml.safe_load or pass Loader=yaml.SafeLoader.",
}

PATTERNS: list[tuple[str, str]] = []
