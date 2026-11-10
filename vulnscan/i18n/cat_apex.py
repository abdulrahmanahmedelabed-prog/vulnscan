"""English catalog: vulnscan/apex_export.py: Oracle APEX checks (APX001-APX021) and component labels.

vulnscan/plsql_frontend.py emits no Arabic text, so it has no entries here.
"""

# Component nouns used in labels ("صفحة 10 › عملية: Save" -> "Page 10 › Process: Save"); Oracle APEX Builder terms.
_COMPONENTS = {
    "صفحة": "Page",
    "التطبيق": "Application",
    "عملية": "Process",
    "عملية تطبيق": "Application Process",
    "منطقة": "Region",
    "عنصر": "Item",
    "عنصر تطبيق": "Application Item",
    "تحقق": "Validation",
    "حساب": "Computation",
    "حساب تطبيق": "Application Computation",
    "تفرّع": "Branch",
    "إجراء ديناميكي": "Dynamic Action",
    "إضافة": "Plug-in",
    "قائمة قيم": "List of Values",
    "مصادقة": "Authentication Scheme",
    "تفويض": "Authorization Scheme",
    "عمود": "Column",
    "زر": "Button",
    "إعداد الذكاء الاصطناعي": "AI Configuration",
    "مصدر RAG": "RAG Source",
    "مصدر ويب": "Web Source Module",
    "مصدر REST": "REST Data Source",
    "ملف إضافة": "Plug-in File",
    "ملف ثابت للتطبيق": "Static Application File",
    "ملف ثابت لمساحة العمل": "Static Workspace File",
    "ملف سمة": "Theme File",
}

CATALOG: dict[str, str] = {
    **_COMPONENTS,

    # ---- rule titles (title_ar; the English title is emitted alongside, listed for completeness)
    "سلسلة استبدال &ITEM. داخل SQL أو PL/SQL (حقن)": "Substitution string &ITEM. inside SQL or PL/SQL (injection)",
    "سلسلة استبدال داخل JavaScript دون مرشّح !JS": "Substitution string inside JavaScript without the !JS filter",
    "استبدال غير مُهرَّب !RAW في HTML": "Unescaped !RAW substitution in HTML",
    "تهريب المخرجات معطّل": "Output escaping disabled",
    "تهريب المخرجات معطّل (XSS محتمل)": "Output escaping disabled (possible XSS)",
    "عنصر يتحكم به المستخدم يُستبدل داخل تعليمات المساعد الذكي": "User-controlled item substituted into an AI prompt",
    "حماية حالة الجلسة (Session State Protection) معطّلة": "Session State Protection is disabled",
    "إعادة الانضمام للجلسات مفعّلة لكل الجلسات (تثبيت الجلسة)": "Rejoin Sessions enabled for all sessions (session fixation)",
    "يمكن تضمين التطبيق في إطار من أي موقع (Clickjacking)": "Application can be embedded in frames from any site (clickjacking)",
    "التطبيق يعمل بروابط تعديل المطوّر في بيئة التشغيل": "Application runs with developer edit links at runtime",
    "خوارزمية checksum ضعيفة للروابط": "Weak checksum hash function for URLs",
    "وضع تهريب HTML أساسي (Basic)": "HTML escaping mode is Basic",
    "واجهة APEX وقت التشغيل يمكنها تعديل التطبيقات": "APEX runtime API can modify applications",
    "كوكي المصادقة غير مقيّد بـ HTTPS (Secure)": "Authentication cookie not restricted to HTTPS (Secure)",
    "مخطط المصادقة الحالي «بلا مصادقة»": "Current authentication scheme is 'No Authentication'",
    "مقارنة كلمة المرور كنص صريح": "Password compared in plain text",
    "صفحة عامة (بلا تسجيل دخول) تعدّل البيانات": "Public page (no sign-in) changes data",
    "صفحة تعدّل البيانات بلا مخطط تفويض": "Page changes data without an authorization scheme",
    "حماية الوصول للصفحة غير مقيّدة (يمكن تمرير أي قيم عبر الرابط)":
        "Page Access Protection is Unrestricted (any values can be passed in the URL)",
    "قيمة العنصر المخفي غير محمية (يمكن التلاعب بها)": "Hidden item value is not protected (can be tampered with)",
    "عملية تطبيق عند الطلب (AJAX) بلا تفويض": "On-demand (AJAX) application process without an authorization scheme",
    "يُسمح بالاستبدال دون النقطة الختامية (&ITEM)": "Substitutions without the trailing dot (&ITEM) are allowed",

    # ---- remediation advice
    "استخدم متغير الربط :ITEM بدل &ITEM.": "Use the bind variable :ITEM instead of &ITEM.",
    "استخدم &ITEM!JS. أو apex.item().getValue().": "Use &ITEM!JS. or apex.item().getValue().",
    "أزل !RAW أو هرّب القيمة.": "Remove !RAW or escape the value.",
    "أزل !RAW (الافتراضي يهرّب HTML) أو هرّب القيمة قبل تخزينها في العنصر.":
        "Remove !RAW (the default escapes HTML), or escape the value before storing it in the item.",
    "أعد تفعيل Escape special characters.": "Re-enable Escape special characters.",
    "أعد تفعيل Escape special characters، أو هرّب القيمة بـ apex_escape.html في الاستعلام.":
        "Re-enable Escape special characters, or escape the value with apex_escape.html in the query.",
    "أعد تفعيل Escape special characters، أو هرّب القيمة بـ apex_escape.html.":
        "Re-enable Escape special characters, or escape the value with apex_escape.html.",
    "لا تضع قيم المستخدم في تعليمات النظام.": "Do not put user-controlled values in the system prompt.",
    "لا تضع قيم المستخدم في تعليمات النظام؛ مرّرها كرسالة مستخدم، وقيّد ما يستطيع المساعد الوصول إليه.":
        "Do not put user-controlled values in the system prompt; pass them as a user message, "
        "and restrict what the assistant can access.",
    "فعّلها من Shared Components › Security Attributes؛ دونها يمكن تغيير أي عنصر عبر الرابط.":
        "Enable it under Shared Components › Security Attributes; without it, any item can be changed through the URL.",
    "اجعل Rejoin Sessions = Disabled أو للصفحات العامة فقط.":
        "Set Rejoin Sessions to Disabled, or to Enabled for Public Sessions only.",
    "اضبط Embed in Frames على Deny أو Allow from same origin.":
        "Set Embed in Frames to Deny or Allow from same origin.",
    "اجعل Status = Available في الإنتاج.": "Set Status to Available in production.",
    "استخدم SH512 في Bookmark Hash Function.": "Set Bookmark Hash Function to SHA-2, 512 bit (SH512).",
    "اجعل HTML Escaping Mode = Extended.": "Set HTML Escaping Mode to Extended.",
    "أزل صلاحية Modify This Application / Modify Other Applications من Runtime API Usage.":
        "Remove the Modify This Application / Modify Other Applications permissions from Runtime API Usage.",
    "فعّل Secure في إعدادات كوكي الجلسة لمخطط المصادقة.":
        "Enable Secure in the session cookie attributes of the authentication scheme.",
    "استخدم مخطط مصادقة حقيقيًا للتطبيق.": "Use a real authentication scheme for the application.",
    "خزّن تجزئة مملّحة (dbms_crypto / apex_util.get_hash مع ملح) وقارن التجزئة، لا النص.":
        "Store a salted hash (dbms_crypto / apex_util.get_hash with a salt) and compare hashes, not plain text.",
    "اجعل الصفحة تتطلب المصادقة أو أزل العمليات التي تكتب البيانات منها.":
        "Require authentication for the page, or remove the processes that write data from it.",
    "أسند Authorization Scheme للصفحة أو للتطبيق؛ المصادقة وحدها تسمح لأي مستخدم مسجّل.":
        "Assign an Authorization Scheme to the page or the application; authentication alone admits any signed-in user.",
    "اضبط Page Access Protection على Arguments Must Have Checksum.":
        "Set Page Access Protection to Arguments Must Have Checksum.",
    "فعّل Value Protected للعنصر المخفي، خصوصًا للمفاتيح والمعرّفات.":
        "Enable Value Protected on the hidden item, especially for keys and IDs.",
    "أسند Authorization Scheme للعملية؛ يمكن لأي جلسة استدعاؤها عبر apex.server.process.":
        "Assign an Authorization Scheme to the process; any session can call it through apex.server.process.",
    "اجعل Substitutions = Exact substitutions only.": "Set Substitutions to Exact substitutions only.",
}

_ITEM = r"(?P<item>[A-Za-z][A-Za-z0-9_$#]*)"
_COMP = "|".join(sorted((k for k in _COMPONENTS if k != "التطبيق"), key=len, reverse=True))
_COMP_RX = rf"(?:{_COMP}|[A-Za-z][\w ]*)"
_PAGE = r"[^›\[\]]+?"
# a component label as apex_export builds it (also the YAML form, whose page may be a page name)
_LABEL = rf"(?:التطبيق|(?:ORDS|JSON) › [^\[\]]*(?:\[\d+\][^\[\]]*)*|صفحة {_PAGE}(?: › {_COMP_RX}(?:: [^\[\]]*)?)?|(?:{_COMP})(?:: [^\[\]]*)?)(?: \(يُحفظ في [\w$#]+\.[\w$#]+\))?"

PATTERNS: list[tuple[str, str]] = [
    # ---- APX001-APX005 (substitution strings), built per item
    (rf"سلسلة استبدال &{_ITEM}\. داخل (?P<kind>SQL|PL/SQL) \(حقن\)",
     r"Substitution string &\g<item>. inside \g<kind> (injection)"),
    (rf"APEX يستبدل &{_ITEM}\. نصيًا قبل التنفيذ فيمكن حقن (?P<kind>SQL|PL/SQL)\. "
     r"استخدم متغير الربط :(?P=item) أو v\('(?P=item)'\) بدلًا منها\.",
     r"APEX replaces &\g<item>. as literal text before execution, which allows \g<kind> injection. "
     r"Use the bind variable :\g<item> or v('\g<item>') instead."),
    (rf"سلسلة استبدال &{_ITEM}\. داخل JavaScript دون مرشّح !JS",
     r"Substitution string &\g<item>. inside JavaScript without the !JS filter"),
    (rf"استخدم &{_ITEM}!JS\. أو اقرأ القيمة بـ apex\.item\('(?P=item)'\)\.getValue\(\) بدل الاستبدال النصي\.",
     r"Use &\g<item>!JS., or read the value with apex.item('\g<item>').getValue() instead of text substitution."),
    (rf"استبدال غير مُهرَّب &{_ITEM}!RAW\. في HTML", r"Unescaped substitution &\g<item>!RAW. in HTML"),
    (rf"عنصر يتحكم به المستخدم &{_ITEM}\. يُستبدل داخل تعليمات المساعد الذكي \(حقن التعليمات\)",
     r"User-controlled item &\g<item>. substituted into an AI prompt (prompt injection)"),

    # ---- snippets: "[<component label>] <code>"
    (rf"\[(?P<label>{_LABEL})\] (?P<rest>.*)", r"[\g<label>] \g<rest>"),
    (rf"\[(?P<label>{_LABEL})\]", r"[\g<label>]"),

    # ---- component labels
    (r"(?P<label>.+) \(يُحفظ في (?P<col>[\w$#]+\.[\w$#]+)\)", r"\g<label> (stored in \g<col>)"),
    (rf"صفحة (?P<pg>{_PAGE}) › (?P<comp>{_COMP_RX}): (?P<name>.+)", r"Page \g<pg> › \g<comp>: \g<name>"),
    (rf"صفحة (?P<pg>{_PAGE}) › (?P<comp>{_COMP_RX})", r"Page \g<pg> › \g<comp>"),
    (rf"(?P<comp>{_COMP}): (?P<name>.+)", r"\g<comp>: \g<name>"),
    (r"صفحة (?P<pg>[^›\[\]():\u0600-\u06FF]+)", r"Page \g<pg>"),

    # ---- virtual path of a static JavaScript file decoded from the export: "<export>!<component>/<file>"
    (rf"(?P<rel>[^!]+)!(?P<comp>{_COMP})/(?P<file>[^/]+)", r"\g<rel>!\g<comp>/\g<file>"),
]
