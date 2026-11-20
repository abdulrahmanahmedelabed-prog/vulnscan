"""English catalog: vulnscan/apex_export.py: Oracle APEX checks (APX001-APX024) and component labels.

APX024 itself is computed in vulnscan/plsql_authz.py; its texts are here with the other APX rules.

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
    "سكربت كائنات الدعم": "Supporting Objects Script",
    "سكربت ترقية كائنات الدعم": "Supporting Objects Upgrade Script",
    "سكربت إزالة كائنات الدعم": "Supporting Objects Deinstallation Script",
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
    "وحدة PL/SQL ملفوفة (wrapped): لا يمكن فحص الكود فيها": "Wrapped PL/SQL unit: its code cannot be scanned",
    "إضافة (Plug-in) معرَّفة لا يستخدمها أي مكوّن في التطبيق": "Plug-in defined but not used by any component of the application",
    "روتين في حزمة PL/SQL لا يتحقق من الصلاحية بينما تتحقق منها الروتينات الشقيقة":
        "PL/SQL package routine does not check authorization while its sibling routines do",

    # ---- APX024 context (plsql_authz.apex_context): why an APEX component calling the routine is not protected
    "صفحة عامة بلا تسجيل دخول": "public page, no sign-in",
    "عملية تطبيق بلا مخطط تفويض": "application process without an authorization scheme",
    "بلا مخطط تفويض يقيّد المستخدمين": "no authorization scheme that restricts users",

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
    "افحص الكود المصدري قبل لفّه (wrap)؛ اللفّ إخفاء لا حماية، ويمكن فكّه.":
        "Scan the source code before it is wrapped; wrapping hides the code, it does not protect it, and it can be unwrapped.",
    "أضف في بداية الروتين التحقق نفسه الذي تستدعيه الروتينات الشقيقة في الحزمة؛ فأي كود في المخطط نفسه يمكنه استدعاؤه مباشرة.":
        "Add at the start of the routine the same check its sibling routines in the package call: any code in the same "
        "schema can call it directly.",
    "احذف الإضافة غير المستخدمة من Shared Components › Plug-ins، أو تأكّد أنها مستخدمة في تطبيق آخر يشترك فيها.":
        "Delete the unused plug-in from Shared Components › Plug-ins, or make sure another application that subscribes "
        "to it uses it.",
}

_ITEM = r"(?P<item>[A-Za-z][A-Za-z0-9_$#]*)"
_COMP = "|".join(sorted((k for k in _COMPONENTS if k != "التطبيق"), key=len, reverse=True))
_COMP_RX = rf"(?:{_COMP}|[A-Za-z][\w ]*)"
_PAGE = r"[^›\[\]]+?"
# a component label as apex_export builds it (also the YAML form, whose page may be a page name)
_LABEL = rf"(?:التطبيق|(?:ORDS|JSON) › [^\[\]]*(?:\[\d+\][^\[\]]*)*|صفحة {_PAGE}(?: › {_COMP_RX}(?:: [^\[\]]*)?)?|(?:{_COMP})(?:: [^\[\]]*)?)(?: \(يُحفظ في [\w$#]+\.[\w$#]+\))?"

_ID = r"[\w$#.]+"
PATTERNS: list[tuple[str, str]] = [
    # ---- APX024 (vulnscan/plsql_authz.py): routine, guard, counts and what the routine accesses
    (rf"(?P<r>{_ID}) لا يتحقق من الصلاحية، بينما تستدعي (?P<k>\d+) من (?P<n>\d+) من الروتينات العامة في الحزمة "
     rf"(?P<g>{_ID}) قبل أول وصول إلى البيانات في نصّها \((?P<m>\d+) منها على كل المسارات\)\. وهو (?P<acc>.+?)\. "
     r"أضف التحقق نفسه \((?P=g)\) في بدايته كما تفعل الروتينات الشقيقة؛ فأي كود في المخطط نفسه \(صفحة APEX أخرى "
     r"مثلًا\) يمكنه استدعاؤه مباشرة\.",
     r"\g<r> does not check authorization, while \g<k> of the \g<n> public routines of the package call \g<g> before "
     r"their first data access in the code (\g<m> of them on every path). It \g<acc>. Add the same check (\g<g>) at "
     r"its start, as the sibling routines do: any code in the same schema (another APEX page, for example) can call it "
     r"directly."),
    # partial coverage, followed by the APEX export context (1.4.0)
    (rf"(?P<r>{_ID}) يتحقق من الصلاحية في بعض المسارات فقط: يمكن الوصول إلى البيانات في السطر (?P<ln>\d+) دون "
     rf"المرور بالتحقق، بينما تستدعي (?P<k>\d+) من (?P<n>\d+) من الروتينات العامة في الحزمة (?P<g>{_ID}) قبل أول "
     rf"وصول إلى البيانات في نصّها \((?P<m>\d+) منها على كل المسارات\)\. "
     rf"وهو (?P<acc>.+?)\. اجعل التحقق \((?P=g)\) قبل كل وصول إلى البيانات، في بدايته أو في شرط يخرج "
     r"من الروتين \(raise أو return\) حين يفشل، لا في فرع واحد أو في معالج استثناء أو بعد الوصول\. (?P<ctx>(?:وفي|ويُستدعى|ولا يُحتسب) .+)",
     r"\g<r> checks authorization on some paths only: the data access at line \g<ln> can be reached without passing "
     r"the check, while \g<k> of the \g<n> public routines of the package call \g<g> before their first data access "
     r"in the code (\g<m> of them on every path). It \g<acc>. "
     r"Put the check (\g<g>) before every data access, at its start or in a condition that leaves the routine (raise "
     r"or return) when it fails, not in one branch, an exception handler or after the access. \g<ctx>"),
    (rf"(?P<r>{_ID}) يتحقق من الصلاحية في بعض المسارات فقط: يمكن الوصول إلى البيانات في السطر (?P<ln>\d+) دون "
     rf"المرور بالتحقق، بينما تستدعي (?P<k>\d+) من (?P<n>\d+) من الروتينات العامة في الحزمة (?P<g>{_ID}) قبل أول "
     rf"وصول إلى البيانات في نصّها \((?P<m>\d+) منها على كل المسارات\)\. "
     rf"وهو (?P<acc>.+?)\. اجعل التحقق \((?P=g)\) قبل كل وصول إلى البيانات، في بدايته أو في شرط يخرج "
     r"من الروتين \(raise أو return\) حين يفشل، لا في فرع واحد أو في معالج استثناء أو بعد الوصول\.",
     r"\g<r> checks authorization on some paths only: the data access at line \g<ln> can be reached without passing "
     r"the check, while \g<k> of the \g<n> public routines of the package call \g<g> before their first data access "
     r"in the code (\g<m> of them on every path). It \g<acc>. "
     r"Put the check (\g<g>) before every data access, at its start or in a condition that leaves the routine (raise "
     r"or return) when it fails, not in one branch, an exception handler or after the access."),
    # the same, followed by what the scanned APEX export says about the routine's callers (1.4.0)
    (rf"(?P<r>{_ID}) لا يتحقق من الصلاحية، بينما تستدعي (?P<k>\d+) من (?P<n>\d+) من الروتينات العامة في الحزمة "
     rf"(?P<g>{_ID}) قبل أول "
     rf"وصول إلى البيانات في نصّها \((?P<m>\d+) منها على كل المسارات\)\. وهو (?P<acc>.+?)\. أضف التحقق نفسه \((?P=g)\) في بدايته كما تفعل الروتينات "
     r"الشقيقة؛ فأي كود في المخطط نفسه \(صفحة APEX أخرى مثلًا\) يمكنه استدعاؤه مباشرة\. (?P<ctx>(?:وفي|ويُستدعى|ولا يُحتسب) .+)",
     r"\g<r> does not check authorization, while \g<k> of the \g<n> public routines of the package call \g<g> before "
     r"their first data access in the code (\g<m> of them on every path). It \g<acc>. Add the same check (\g<g>) at its start, as the sibling routines do: any code in the "
     r"same schema (another APEX page, for example) can call it directly. \g<ctx>"),
    (rf"وفي تطبيق APEX المفحوص لا يُستدعى (?P<r>{_ID}) إلا من مكوّنات محمية بمخطط التفويض (?P<s>.+?) "
     r"\(مواضع الاستدعاء: (?P<n>\d+)، أولها «(?P<label>.+?)» في السطر (?P<line>\d+) من (?P<rel>.+?)\)؛ لكن هذه الحماية "
     r"لا تشمل أي مستدعٍ آخر للحزمة \(صفحة أخرى أو تطبيق آخر أو صلاحية EXECUTE ممنوحة مباشرة\)، فيبقى التحقق داخل "
     r"الروتين لازمًا\.",
     r"In the scanned APEX application, \g<r> is called only from components protected by the authorization scheme "
     r"\g<s> (call sites: \g<n>; the first is «\g<label>» at line \g<line> of \g<rel>); this protection does not cover "
     r"any other caller of the package (another page, another application, or a direct EXECUTE grant), so the check "
     r"inside the routine is still needed."),
    (rf"ويُستدعى (?P<r>{_ID}) في تطبيق APEX المفحوص من مكوّن غير محمي: «(?P<label>.+?)» في السطر (?P<line>\d+) من "
     r"(?P<rel>.+?) \((?P<why>[^()]+)\)؛ المواضع غير المحمية (?P<k>\d+) من (?P<n>\d+)\. فيمكن لأي مستخدم يصل إلى هذا "
     r"المكوّن تشغيل الروتين دون تحقق، ولذلك رُفعت الخطورة إلى «عالية»\. (?P<btn>ويعمل «.+)",
     r"\g<r> is called in the scanned APEX application from an unprotected component: «\g<label>» at line "
     r"\g<line> of \g<rel> (\g<why>); unprotected call sites: \g<k> of \g<n>. Any user who can reach that component "
     r"can run the routine without a check, so the severity was raised to high. \g<btn>"),
    (rf"ويُستدعى (?P<r>{_ID}) في تطبيق APEX المفحوص من مكوّن غير محمي: «(?P<label>.+?)» في السطر (?P<line>\d+) من "
     r"(?P<rel>.+?) \((?P<why>[^()]+)\)؛ المواضع غير المحمية (?P<k>\d+) من (?P<n>\d+)\. فيمكن لأي مستخدم يصل إلى هذا "
     r"المكوّن تشغيل الروتين دون تحقق، ولذلك رُفعت الخطورة إلى «عالية»\.",
     r"\g<r> is called in the scanned APEX application from an unprotected component: «\g<label>» at line "
     r"\g<line> of \g<rel> (\g<why>); unprotected call sites: \g<k> of \g<n>. Any user who can reach that component "
     r"can run the routine without a check, so the severity was raised to high."),
    # a When Button Pressed is not protection (1.5.0)
    (rf"ويعمل «(?P<label>.+?)» عند الضغط على الزر (?P<b>[^ ]+) الذي يحميه المخطط (?P<s>.+?)، لكن إخفاء الزر لا يمنع "
     r"إرسال الصفحة بطلب \(REQUEST\) يحمل اسمه؛ أسند (?P=s) إلى المكوّن نفسه لحمايته\.",
     r"«\g<label>» runs when the button \g<b> is pressed, and \g<b> has the authorization scheme \g<s>; hiding a "
     r"button does not stop a crafted submit with that REQUEST: add \g<s> to the component's own scheme to protect it."),
    # a helper of the package that checks on some of its paths only does not count as a check (1.5.0)
    (rf"ولا يُحتسب استدعاؤه (?P<h>{_ID}) تحققًا: (?P=h) نفسه لا يتحقق من الصلاحية إلا في بعض مساراته\. "
     r"(?P<ctx>(?:وفي|ويُستدعى) .+)",
     r"Its call to \g<h> does not count as a check: \g<h> itself checks authorization on some of its paths only. "
     r"\g<ctx>"),
    (rf"ولا يُحتسب استدعاؤه (?P<h>{_ID}) تحققًا: (?P=h) نفسه لا يتحقق من الصلاحية إلا في بعض مساراته\.",
     r"Its call to \g<h> does not count as a check: \g<h> itself checks authorization on some of its paths only."),
    (rf"يُعيد قيمة (?P<t>[A-Z]+) مقروءة باستعلام(?P<o> \({_ID}(?:, {_ID})*\))?",
     r"returns a \g<t> value read by a query\g<o>"),
    (rf"يُعيد بيانات مقروءة باستعلام(?P<o> \({_ID}(?:, {_ID})*\))?", r"returns data read by a query\g<o>"),
    (rf"يقرأ البيانات باستعلام(?P<o> \({_ID}(?:, {_ID})*\))?", r"reads data with a query\g<o>"),
    (rf"يعدّل البيانات \(DML\)(?P<o> \({_ID}(?:, {_ID})*\))?", r"changes data (DML)\g<o>"),
    (rf"ينفّذ SQL ديناميكيًا(?P<o> \({_ID}(?:, {_ID})*\))?", r"runs dynamic SQL\g<o>"),
    (rf"يكتب بيانات إلى المتصفح \(htp / wpg_docload\)(?P<o> \({_ID}(?:, {_ID})*\))?",
     r"writes data to the browser (htp / wpg_docload)\g<o>"),
    (rf"يستدعي (?P<h>{_ID}) الذي يصل إلى البيانات دون تحقق", r"calls \g<h>, which accesses data without a check"),

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
    (rf"(?P<label>.+) \(بشكل غير مباشر عبر (?P<via>{_ID})\)", r"\g<label> (indirectly via \g<via>)"),
    (r"(?P<label>.+) \(يُحفظ في (?P<col>[\w$#]+\.[\w$#]+)\)", r"\g<label> (stored in \g<col>)"),
    (rf"صفحة (?P<pg>{_PAGE}) › (?P<comp>{_COMP_RX}): (?P<name>.+)", r"Page \g<pg> › \g<comp>: \g<name>"),
    (rf"صفحة (?P<pg>{_PAGE}) › (?P<comp>{_COMP_RX})", r"Page \g<pg> › \g<comp>"),
    (rf"(?P<comp>{_COMP}): (?P<name>.+)", r"\g<comp>: \g<name>"),
    (r"صفحة (?P<pg>[^›\[\]():\u0600-\u06FF]+)", r"Page \g<pg>"),

    # ---- virtual path of a static JavaScript file decoded from the export: "<export>!<component>/<file>"
    (rf"(?P<rel>[^!]+)!(?P<comp>{_COMP})/(?P<file>[^/]+)", r"\g<rel>!\g<comp>/\g<file>"),
]
