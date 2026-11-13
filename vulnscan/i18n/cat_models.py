"""English catalog: vulnscan/models/*.json: sink advice and source labels.

Every model's ``title`` is already English (``title_ar`` is its Arabic counterpart), so only ``advice`` and
the Arabic source ``label`` values need English here. Keys are the advice text exactly as written in the JSON.
"""

CATALOG: dict[str, str] = {
    # --- command execution -------------------------------------------------------------------------------
    "لا تمرّر مدخلات إلى الصدفة؛ استخدم وسائط منفصلة وقائمة بيضاء.":
        "Do not pass input to a shell; pass arguments separately and validate them against an allowlist.",
    "ثبّت البرنامج وتحقق من الوسائط.":
        "Use a fixed program path and validate the arguments.",
    "لا تبنِ الأمر من المدخلات؛ ثبّت FileName ومرّر Arguments بعد تحقق.":
        "Do not build the command from input; use a fixed FileName and pass validated Arguments.",
    "ثبّت البرنامج ولا تمرّر sh -c مع مدخلات؛ تحقق من الوسائط.":
        "Use a fixed program and never pass input to sh -c; validate the arguments.",
    "استخدم ProcessBuilder بقائمة وسائط ثابتة البرنامج وتحقق من المدخلات.":
        "Use ProcessBuilder with an argument list and a fixed program, and validate the input.",
    "ثبّت البرنامج ولا تمرّر الأمر من المدخلات.":
        "Use a fixed program; do not take the command from input.",
    "استخدم execFile/spawn بقائمة وسائط بدلًا من سلسلة أوامر.":
        "Use execFile/spawn with an argument array instead of a command string.",
    "ثبّت البرنامج ولا تمرّر الأمر من المدخلات؛ تجنّب shell: true.":
        "Use a fixed program and do not take the command from input; avoid shell: true.",
    "استخدم escapeshellarg لكل وسيط وescapeshellcmd للأمر، أو تجنّب تنفيذ الأوامر.":
        "Use escapeshellarg for every argument and escapeshellcmd for the command, or avoid running shell commands.",
    "لا تبنِ أوامر النظام من المدخلات؛ استخدم قائمة وسائط بلا shell وتحقق منها.":
        "Do not build OS commands from input; use an argument list without a shell and validate it.",
    "استخدم قائمة وسائط بلا shell=True ولا تبنِ الأمر من المدخلات.":
        "Use an argument list without shell=True and do not build the command from input.",
    "لا تبنِ الأمر من المدخلات؛ ثبّت البرنامج وتحقق من الوسائط.":
        "Do not build the command from input; use a fixed program and validate the arguments.",
    # --- SQL / NoSQL ----------------------------------------------------------------------------------------
    "استخدم استعلامات مُعدّة بدل تركيب النص.":
        "Use prepared statements instead of string concatenation.",
    "استخدم معاملات (SqlParameter / FromSqlInterpolated) بدل تركيب النص.":
        "Use parameters (SqlParameter / FromSqlInterpolated) instead of string concatenation.",
    "استخدم placeholders (?) أو $1 بدل تركيب النص.":
        "Use placeholders (? or $1) instead of string concatenation.",
    "استخدم PreparedStatement مع معاملات (?) بدل تركيب نص الاستعلام.":
        "Use a PreparedStatement with ? parameters instead of concatenating the query text.",
    "استخدم استعلامات مُعَلَّمة/placeholders وتحقق من أنواع المدخلات (حقن SQL/NoSQL).":
        "Use parameterized queries/placeholders and validate input types (SQL/NoSQL injection).",
    "استخدم PDO::prepare مع معاملات مرتبطة بدل تركيب النص.":
        "Use PDO::prepare with bound parameters instead of string concatenation.",
    "استخدم متغيرات الربط (USING :x) بدل دمج النص، وطبّق DBMS_ASSERT على أسماء الجداول والأعمدة.":
        "Use bind variables (USING :x) instead of concatenation, and apply DBMS_ASSERT to table and column names.",
    "استخدم استعلامات مُعَلَّمة (parameters) بدل بناء نص الاستعلام من المدخلات.":
        "Use parameterized queries instead of building the query text from input.",
    "لا تركّب الاستعلام من المدخلات.":
        "Do not build the query from input.",
    # --- file paths -----------------------------------------------------------------------------------------
    "طبّع المسار وتحقق أنه داخل المجلد المسموح.":
        "Canonicalize the path and verify it stays inside the allowed directory.",
    "تحقق من المسار قبل الحذف أو الإنشاء.":
        "Validate the path before deleting or creating files.",
    "طبّع المسار (Path.GetFullPath) وتحقق أنه داخل المجلد المسموح.":
        "Canonicalize the path (Path.GetFullPath) and verify it stays inside the allowed directory.",
    "تحقق من المسار قبل الحذف أو الإنشاء أو الاستخراج.":
        "Validate the path before deleting, creating or extracting files.",
    "استخدم filepath.Clean/Rel وتحقق أن المسار داخل المجلد المسموح.":
        "Use filepath.Clean/Rel and verify the path stays inside the allowed directory.",
    "طبّع المسار (toRealPath/normalize) وتحقق أنه داخل المجلد المسموح.":
        "Canonicalize the path (toRealPath/normalize) and verify it stays inside the allowed directory.",
    "طبّع المسار (path.resolve) وتحقق أنه داخل المجلد المسموح قبل القراءة أو الكتابة.":
        "Canonicalize the path (path.resolve) and verify it stays inside the allowed directory before reading or writing.",
    "طبّع المسار وتحقق أنه داخل المجلد المسموح قبل أي حذف أو نسخ أو إنشاء.":
        "Canonicalize the path and verify it stays inside the allowed directory before any delete, copy or create.",
    "طبّع المسار (realpath) وتحقق أنه داخل المجلد المسموح وارفض ..":
        "Canonicalize the path (realpath), verify it stays inside the allowed directory and reject '..'.",
    "لا تبنِ اسم الملف من المدخلات؛ استخدم قائمة بيضاء.":
        "Do not build the file name from input; use an allowlist.",
    "طبّع المسار وتحقق أنه داخل المجلد المسموح (resolve + is_relative_to).":
        "Normalize the path and verify it stays inside the permitted directory (resolve + is_relative_to).",
    "طبّع المسار وتحقق أنه داخل المجلد المسموح قبل أي عملية حذف أو نسخ أو إنشاء.":
        "Canonicalize the path and verify it stays inside the allowed directory before any delete, copy or create operation.",
    # --- deserialization ------------------------------------------------------------------------------------
    "لا تفكّ بيانات غير موثوقة؛ استخدم صيغًا آمنة.":
        "Do not deserialize untrusted data; use a safe data format.",
    "تجنّب BinaryFormatter؛ استخدم System.Text.Json بأنواع ثابتة وبلا TypeNameHandling.":
        "Avoid BinaryFormatter; use System.Text.Json with fixed types and no TypeNameHandling.",
    "تحقق من البنية قبل الفك واستخدم أنواعًا ثابتة.":
        "Validate the structure before deserializing, and deserialize into fixed types.",
    "لا تفك تسلسل بيانات غير موثوقة؛ استخدم ObjectInputFilter أو JSON بأنواع ثابتة.":
        "Do not deserialize untrusted data; use an ObjectInputFilter or JSON with fixed types.",
    "استخدم JSON.parse أو yaml safeLoad؛ لا تفك تسلسل كائنات من مدخلات.":
        "Use JSON.parse or yaml safeLoad; do not deserialize objects from input.",
    "استخدم json_decode بدل unserialize، أو unserialize مع allowed_classes=false.":
        "Use json_decode instead of unserialize, or call unserialize with allowed_classes=false.",
    "لا تفك تسلسل بيانات غير موثوقة؛ استخدم JSON أو yaml.safe_load.":
        "Do not deserialize untrusted data; use JSON or yaml.safe_load.",
    # --- templates / SSTI -----------------------------------------------------------------------------------
    "لا تبنِ القالب من المدخلات.":
        "Do not build the template from input.",
    "لا تبنِ القالب أو التعبير من المدخلات.":
        "Do not build the template or expression from input.",
    "لا تبنِ القالب من المدخلات ولا تحوّلها إلى template.HTML.":
        "Do not build the template from input or convert input to template.HTML.",
    "لا تبنِ القالب نفسه من المدخلات؛ مرّر البيانات كمتغيرات للقالب.":
        "Do not build the template itself from input; pass the data as template variables.",
    "لا تبنِ القالب من المدخلات؛ مرّر البيانات كمتغيرات.":
        "Do not build the template from input; pass the data as variables.",
    "استخدم قوالب ثابتة ومرّر البيانات كمتغيرات (SSTI).":
        "Use static templates and pass the data as variables (SSTI).",
    # --- redirects ------------------------------------------------------------------------------------------
    "تحقق من الوجهة بقائمة بيضاء.":
        "Validate the destination against an allowlist.",
    "استخدم LocalRedirect أو تحقق من الوجهة.":
        "Use LocalRedirect or validate the destination.",
    "تحقق من وجهة التحويل بقائمة بيضاء.":
        "Validate the redirect target against an allowlist.",
    "تحقق أن وجهة التحويل ضمن قائمة بيضاء أو مسار نسبي فقط (Open Redirect).":
        "Redirect only to allowlisted destinations or relative paths (open redirect).",
    "تحقق من الوجهة قبل الإسناد.":
        "Validate the destination before assigning it.",
    "تحقق من الوجهة بقائمة بيضاء ولا تمرّر مدخلات إلى header().":
        "Validate the destination against an allowlist and do not pass input to header().",
    "تحقق من الوجهة بقائمة بيضاء أو استخدم apex_page.get_url.":
        "Validate the destination against an allowlist or use apex_page.get_url.",
    "تحقق أن وجهة التحويل ضمن قائمة بيضاء (Open Redirect).":
        "Redirect only to allowlisted destinations (open redirect).",
    # --- SSRF -----------------------------------------------------------------------------------------------
    "قيّد الوجهات وارفض العناوين الداخلية.":
        "Restrict outbound destinations and reject internal addresses.",
    "قيّد الوجهات بقائمة بيضاء.":
        "Restrict outbound destinations to an allowlist.",
    "قيّد الوجهات بقائمة بيضاء وارفض العناوين الداخلية.":
        "Restrict outbound destinations to an allowlist and reject internal addresses.",
    "قيّد الوجهات بقائمة بيضاء من النطاقات.":
        "Restrict outbound destinations to an allowlist of domains.",
    "قيّد الوجهات بقائمة بيضاء من النطاقات وارفض العناوين الداخلية.":
        "Restrict outbound destinations to an allowlist of domains and reject internal addresses.",
    "قيّد الوجهات بقائمة بيضاء وبـ Network ACL.":
        "Restrict outbound destinations with an allowlist and a Network ACL.",
    "قيّد الوجهات بقائمة بيضاء من النطاقات، وارفض العناوين الداخلية وعناوين البيانات الوصفية.":
        "Restrict outbound destinations to an allowlist of domains, and reject internal and cloud metadata addresses.",
    # --- code evaluation / dynamic loading ------------------------------------------------------------------
    "لا تنفّذ كودًا مبنيًا من المدخلات.":
        "Do not execute code built from input.",
    # the wording of Kashif 1.0.1 (الشيفرة), still in older reports
    "لا تنفّذ شيفرة مبنية من المدخلات.":
        "Do not execute code built from input.",
    "استخدم قائمة بيضاء ثابتة من الأنواع.":
        "Use a fixed allowlist of types.",
    "لا تحمّل إضافات من مسارات غير موثوقة.":
        "Do not load plugins from untrusted paths.",
    "استخدم قائمة بيضاء ثابتة من الأصناف ولا تنفّذ سكربتات من مدخلات.":
        "Use a fixed allowlist of classes and do not evaluate scripts from input.",
    "لا تنفّذ نصوصًا ديناميكية؛ استخدم JSON.parse أو منطقًا صريحًا.":
        "Do not evaluate dynamic code; use JSON.parse or explicit logic.",
    "حمّل الوحدات من قائمة بيضاء ثابتة.":
        "Load modules only from a fixed allowlist.",
    "لا تنفّذ كودًا من مدخلات؛ استخدم قوائم بيضاء للدوال.":
        "Do not execute code from input; use an allowlist of functions.",
    "استخدم قائمة بيضاء ثابتة من الملفات المسموح تضمينها.":
        "Use a fixed allowlist of files that may be included.",
    "لا تنفّذ كودًا مبنيًا من المدخلات؛ استخدم إجراءات ثابتة بوسائط مربوطة.":
        "Do not execute code built from input; call fixed procedures with bound arguments.",
    "لا تمرّر مدخلات المستخدم إلى eval/exec؛ استخدم منطقًا صريحًا أو ast.literal_eval.":
        "Do not pass user input to eval/exec; use explicit logic or ast.literal_eval.",
    "استورد من قائمة بيضاء ثابتة من الوحدات.":
        "Import only from a fixed allowlist of modules.",
    # --- XSS / output encoding ------------------------------------------------------------------------------
    "هرّب المخرجات أو استخدم قالبًا يُهرّب تلقائيًا.":
        "Encode the output or use an auto-escaping template engine.",
    "هرّب المخرجات (HtmlEncoder) أو استخدم Razor الذي يُهرِّب تلقائيًا.":
        "Encode the output (HtmlEncoder) or use Razor, which escapes automatically.",
    "هرّب المخرجات (html.EscapeString) أو استخدم html/template.":
        "Encode the output (html.EscapeString) or use html/template.",
    "هرّب المخرجات (Encode.forHtml / escapeHtml4) أو استخدم قوالب تُهرِّب تلقائيًا.":
        "Encode the output (Encode.forHtml / escapeHtml4) or use auto-escaping templates.",
    "هرّب المخرجات أو استخدم res.json/textContent أو قالبًا يُهرِّب تلقائيًا.":
        "Encode the output, or use res.json/textContent or an auto-escaping template engine.",
    "استخدم textContent أو عقّم بـ DOMPurify.":
        "Use textContent or sanitize with DOMPurify.",
    "استخدم htmlspecialchars($x, ENT_QUOTES, 'UTF-8') أو قوالب تُهرِّب تلقائيًا (Twig/Blade).":
        "Use htmlspecialchars($x, ENT_QUOTES, 'UTF-8') or auto-escaping templates (Twig/Blade).",
    "هرّب المخرجات بـ apex_escape.html أو htf.escape_sc قبل htp.p.":
        "Escape the output with apex_escape.html or htf.escape_sc before htp.p.",
    "هرّب المخرجات (html.escape / markupsafe) أو استخدم قوالب تُهرِّب تلقائيًا.":
        "Encode the output (html.escape / markupsafe) or use auto-escaping templates.",
    "هرّب المخرجات قبل العرض.":
        "Encode the output before rendering it.",
    # --- LDAP / XPath ---------------------------------------------------------------------------------------
    "هرّب قيم المرشّح.":
        "Escape the filter values.",
    "هرّب المرشّح (ldap.EscapeFilter).":
        "Escape the filter (ldap.EscapeFilter).",
    "هرّب المرشّح أو استخدم LdapQueryBuilder.":
        "Escape the filter or use LdapQueryBuilder.",
    "هرّب قيم المرشّح قبل تركيبه.":
        "Escape the filter values before building the filter.",
    "استخدم ldap_escape للمرشّحات والـDN.":
        "Use ldap_escape for filters and DNs.",
    "هرّب المرشّح بـ apex_escape.ldap_search_filter.":
        "Escape the filter with apex_escape.ldap_search_filter.",
    "هرّب القيم بـ ldap.filter.escape_filter_chars.":
        "Escape the values with ldap.filter.escape_filter_chars.",
    "استخدم متغيرات XPath بدل تركيب الاستعلام.":
        "Use XPath variables instead of building the query by concatenation.",
    "استخدم XPathVariableResolver بدل تركيب الاستعلام.":
        "Use an XPathVariableResolver instead of building the query by concatenation.",
    "لا تركّب استعلام XPath من المدخلات.":
        "Do not build the XPath query from input.",
    "استخدم متغيرات XPath المُعَلَّمة بدل تركيب الاستعلام.":
        "Use parameterized XPath variables instead of building the query by concatenation.",
    # --- logging / memory / format strings ------------------------------------------------------------------
    "أزل أسطر جديدة وأحرف التحكم قبل التسجيل.":
        "Strip newlines and control characters before logging.",
    "أزل أسطر جديدة وأحرف التحكم من المدخلات قبل تسجيلها (حقن سجلات).":
        "Strip newlines and control characters from input before logging it (log injection).",
    "استخدم الدوال المحدودة الطول وتحقق من الأطوال.":
        "Use length-bounded functions and validate buffer sizes.",
    "لا تمرّر المدخلات كسلسلة تنسيق.":
        "Do not pass input as the format string.",
    # --- session / trust boundary ---------------------------------------------------------------------------
    "لا تضع مدخلات المستخدم في الجلسة كقيم موثوقة؛ تحقّق منها بقائمة بيضاء أولًا.":
        "Do not store user input in the session as trusted values; validate it against an allowlist first.",
    "لا تضع مدخلات المستخدم في الجلسة كقيم موثوقة؛ تحقّق منها بقائمة بيضاء أولًا، ولا تجعلها مفتاحًا.":
        "Do not store user input in the session as trusted values; validate it against an allowlist first,"
        " and never use it as a session key.",
    # --- AI (Oracle APEX / Select AI) -----------------------------------------------------------------------
    "ضع مدخلات المستخدم في p_prompt فقط، وأبقِ p_system_prompt ثابتًا؛ افصل البيانات عن التعليمات"
    " ولا تمنح المساعد صلاحيات لا يحتاجها.":
        "Put user input only in p_prompt and keep p_system_prompt constant; separate data from instructions"
        " and do not grant the assistant privileges it does not need.",
    "قيّد ملف تعريف الذكاء (object_list) بجداول آمنة للعرض، واستخدم action => 'showsql' للمراجعة بدل 'runsql'،"
    " ونفّذه بحساب قراءة فقط.":
        "Limit the AI profile (object_list) to tables that are safe to expose, use action => 'showsql' for review"
        " instead of 'runsql', and run it under a read-only account.",
    # --- source labels --------------------------------------------------------------------------------------
    "معامل نقطة الدخول": "entry-point parameter",
}

PATTERNS: list[tuple[str, str]] = [
    # source labels after taint.py substitutes {attr} / {name} with the matched identifier
    (r"معامل نقطة الدخول (?P<name>[\w$#.:]+)", r"entry-point parameter \g<name>"),
    (r"قيمة عنصر الإضافة p_item\.(?P<attr>[\w$#{}]+)", r"plug-in item value p_item.\g<attr>"),
    (r"قيمة الإضافة p_param\.(?P<attr>[\w$#{}]+)", r"plug-in parameter value p_param.\g<attr>"),
    (r"مخرجات الذكاء الاصطناعي من (?P<name>[\w$#.{}]+)\(\)", r"AI output from \g<name>()"),
]
