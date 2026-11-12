"""English catalog: Rust / Swift / C++ / Kotlin library models (breadth round 2)."""

CATALOG: dict[str, str] = {
    # rust.json
    "ضع حدًّا لحجم المدخلات قبل فكّها (bincode: with_limit) وتحقق من القيم بعد الفك؛ لا تستخدم دوال الوصول غير "
    "المتحقَّق منها (unchecked) مع بيانات من خارج النظام.":
        "Put a size limit on the input before decoding it (bincode: with_limit) and validate the values after "
        "decoding; do not use unchecked accessors on data that comes from outside the system.",
    "هرّب قيم المرشّح بـ ldap3::ldap_escape والأسماء المميّزة بـ ldap3::dn_escape قبل البحث.":
        "Escape filter values with ldap3::ldap_escape and distinguished names with ldap3::dn_escape before searching.",
    "بيانات غير موثوقة تصل إلى مفكّك ترميز ثنائي أو YAML دون حدّ للحجم":
        "Untrusted data reaches a binary / YAML decoder without a size limit",
    "بايتات غير موثوقة تصل إلى دالة وصول غير متحقَّق منها (unchecked)":
        "Untrusted bytes reach an unchecked (unvalidated) zero-copy accessor",
    # swift.json
    "لا تركّب صيغة NSPredicate من المدخلات؛ مرّر القيم كوسائط (%@) أو استخدم الاستعلامات المكتوبة بالأنواع.":
        "Do not build an NSPredicate format from input; pass the values as arguments (%@) or use type-safe queries.",
    "بيانات غير موثوقة تصل إلى شرط استعلام Realm (حقن NSPredicate)":
        "Tainted data reaches a Realm query predicate",
    # cpp.json
    "لا تضع عنوانًا من المدخلات في CURLOPT_URL أو CURLOPT_PROXY؛ قيّد المخطط والمضيف بقائمة بيضاء، وعطّل "
    "CURLOPT_FOLLOWLOCATION وقيّد CURLOPT_PROTOCOLS_STR.":
        "Do not put a URL taken from input into CURLOPT_URL or CURLOPT_PROXY; restrict the scheme and host with an "
        "allowlist, disable CURLOPT_FOLLOWLOCATION and restrict CURLOPT_PROTOCOLS_STR.",
    "قيمة غير موثوقة تصل إلى خيار في libcurl (CURLOPT_URL / CURLOPT_PROXY: طلب صادر SSRF)":
        "Tainted value reaches a libcurl option (CURLOPT_URL / CURLOPT_PROXY: SSRF)",
    "طول غير موثوق يصل إلى نسخ إلى مخزن": "Tainted length reaches a bounded buffer copy",
    # kotlin.json
    "لا تركّب نص SQL من المدخلات في rawQuery() أو execSQL()؛ مرّر القيم في selectionArgs / bindArgs مع علامات ?.":
        "Do not build the SQL text of rawQuery() or execSQL() from input; pass the values in selectionArgs / bindArgs "
        "with ? placeholders.",
    "لا تركّب شرط selection أو sortOrder من المدخلات؛ استخدم علامات ? مع selectionArgs وقائمة بيضاء لأعمدة الترتيب.":
        "Do not build the selection or sortOrder from input; use ? placeholders with selectionArgs and an allowlist "
        "of sort columns.",
    "مرّر القيم كمعاملات مسمّاة أو مواضع ? إلى queryOf(statement, params) ولا تركّب نص الاستعلام من المدخلات.":
        "Pass the values as named or ? parameters to queryOf(statement, params); do not build the statement text "
        "from input.",
    "لا تحمّل في WebView عنوانًا من Intent أو من رابط عميق؛ قيّد المخطط والمضيف بقائمة بيضاء وارفض javascript: و "
    "file:، ولا تفعّل JavaScript أو addJavascriptInterface لمحتوى غير موثوق.":
        "Do not load a URL taken from an Intent or a deep link into a WebView; restrict the scheme and host with an "
        "allowlist, reject javascript: and file:, and do not enable JavaScript or addJavascriptInterface for "
        "untrusted content.",
    "اختر اسم القالب من قائمة ثابتة ولا تبنِه من المدخلات؛ مرّر قيم المستخدم في نموذج البيانات فقط.":
        "Pick the template name from a fixed list instead of building it from input; pass user values only in the "
        "data model.",
}

PATTERNS: list[tuple[str, str]] = []
