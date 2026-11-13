"""English catalog: C# / Go / PHP / Ruby / Rust / Swift / C++ library models added in the breadth expansion."""

CATALOG: dict[str, str] = {
    # go.json
    "لا تمرّر المدخلات إلى sh -c؛ استدعِ البرنامج مباشرة بقائمة معاملات ثابتة وتحقّق من القيم.":
        "Do not pass input to sh -c; call the program directly with a fixed argument list and validate the values.",
    "لا تمرّر نص SQL مركّبًا من المدخلات إلى database/sql أو sqlx أو gorm أو pgx؛ استخدم العناصر النائبة (? أو $1) ومرّر القيم معاملات.":
        "Do not pass SQL text built from input to database/sql, sqlx, gorm or pgx; use placeholders (? or $1) and pass "
        "the values as arguments.",
    "في gorm لا تمرّر نصًا من المدخلات كشرط مضمَّن (First/Find/Delete) ولا كعمود (Order/Group/Pluck)؛ استخدم Where(\"col = ?\", v) وقائمة بيضاء لأسماء الأعمدة.":
        "In gorm, do not pass input text as an inline condition (First/Find/Delete) or as a column (Order/Group/Pluck); "
        "use Where(\"col = ?\", v) and an allowlist of column names.",
    "لا تحلّل مستند استعلام MongoDB من نص يحوي مدخلات المستخدم ولا تستخدم $where أو BsonJavaScript؛ ابنِ المرشّحات ببنّاء المرشّحات ومرّر القيم كمعاملات.":
        "Do not parse a MongoDB query document from text that contains user input and do not use $where or "
        "BsonJavaScript; build filters with the filter builder and pass values as parameters.",
    "طبّع المسار وتحقّق أنه داخل المجلد المسموح (filepath.IsLocal أو strings.HasPrefix بعد filepath.Clean) قبل استخدامه.":
        "Normalize the path and check that it stays inside the allowed directory (filepath.IsLocal, or strings.HasPrefix "
        "after filepath.Clean) before using it.",
    "قيّد الوجهات بقائمة بيضاء من المضيفين والمخططات وارفض العناوين الداخلية قبل إرسال الطلب.":
        "Restrict destinations to an allowlist of hosts and schemes and reject internal addresses before sending the request.",
    "حوّل إلى مسارات محلية فقط أو تحقّق من المضيف بقائمة بيضاء قبل التحويل.":
        "Redirect only to local paths, or check the host against an allowlist before redirecting.",
    "لا تحوّل المدخلات إلى template.HTML/HTMLAttr/CSS/JSStr/Srcset؛ دع html/template يهرّبها تلقائيًا.":
        "Do not convert input to template.HTML/HTMLAttr/CSS/JSStr/Srcset; let html/template escape it automatically.",
    "لا تقيّم كود JavaScript أو تعبيرات (otto/goja/expr/govaluate) مبنية من المدخلات؛ مرّر المدخلات كمتغيرات فقط.":
        "Do not evaluate JavaScript code or expressions (otto/goja/expr/govaluate) built from input; pass input only as "
        "variables.",
    # the wording of Kashif 1.0.1 (الشيفرة), still in older reports
    "لا تقيّم شيفرة JavaScript أو تعبيرات (otto/goja/expr/govaluate) مبنية من المدخلات؛ مرّر المدخلات كمتغيرات فقط.":
        "Do not evaluate JavaScript code or expressions (otto/goja/expr/govaluate) built from input; pass input only as "
        "variables.",
    "هرّب المخرجات (html.EscapeString) أو استخدم html/template بدل كتابة HTML مركّب من المدخلات.":
        "Escape the output (html.EscapeString) or use html/template instead of writing HTML built from input.",
    "لا تركّب تعبير XPath من المدخلات؛ استخدم متغيرات XPath أو قائمة بيضاء من القيم.":
        "Do not build an XPath expression from input; use XPath variables or an allowlist of values.",
    # csharp.json
    "استخدم معاملات (SqlParameter / FromSqlInterpolated / معاملات Dapper) بدل تركيب نص SQL من المدخلات.":
        "Use parameters (SqlParameter / FromSqlInterpolated / Dapper parameters) instead of building SQL text from input.",
    "لا تبنِ سكربت PowerShell من المدخلات؛ استخدم AddCommand وAddParameter بقيم متحقَّق منها.":
        "Do not build a PowerShell script from input; use AddCommand and AddParameter with validated values.",
    "لا تبنِ معاملات العملية من المدخلات؛ ثبّت البرنامج وتحقّق من كل معامل بقائمة بيضاء.":
        "Do not build process arguments from input; fix the program and check every argument against an allowlist.",
    "طبّع المسار (Path.GetFullPath) وتحقّق أنه يبدأ بالمجلد المسموح قبل القراءة أو الكتابة.":
        "Normalize the path (Path.GetFullPath) and check that it starts with the allowed directory before reading or "
        "writing.",
    "لا تفك تسلسل بيانات غير موثوقة بـ NetDataContractSerializer أو XamlReader أو fastJSON؛ استخدم System.Text.Json بأنواع ثابتة.":
        "Do not deserialize untrusted data with NetDataContractSerializer, XamlReader or fastJSON; use System.Text.Json "
        "with fixed types.",
    "لا تترجم أو تنفّذ كود C# أو JavaScript أو قوالب (Razor/Scriban/Handlebars) مبنية من المدخلات؛ مرّر المدخلات كبيانات للنموذج فقط.":
        "Do not compile or run C# or JavaScript code or templates (Razor/Scriban/Handlebars) built from input; pass input "
        "only as model data.",
    # the wording of Kashif 1.0.1 (الشيفرة), still in older reports
    "لا تترجم أو تنفّذ شيفرة C# أو JavaScript أو قوالب (Razor/Scriban/Handlebars) مبنية من المدخلات؛ مرّر المدخلات كبيانات للنموذج فقط.":
        "Do not compile or run C# or JavaScript code or templates (Razor/Scriban/Handlebars) built from input; pass input "
        "only as model data.",
    "استخدم LocalRedirect أو تحقّق بـ Url.IsLocalUrl قبل التحويل.":
        "Use LocalRedirect, or check with Url.IsLocalUrl before redirecting.",
    "قيّد عناوين HttpClient/WebClient بقائمة بيضاء من المضيفين وارفض العناوين الداخلية.":
        "Restrict HttpClient/WebClient addresses to an allowlist of hosts and reject internal addresses.",
    "لا تحمّل أنواعًا أو تجميعات بأسماء من المدخلات؛ استخدم قائمة بيضاء ثابتة.":
        "Do not load types or assemblies by names taken from input; use a fixed allowlist.",
    "لا تُخرج HTML خامًا من المدخلات (MarkupString/AppendHtml/InnerHtml)؛ هرّبه بـ HtmlEncoder أو نظّفه بـ HtmlSanitizer.":
        "Do not output raw HTML from input (MarkupString/AppendHtml/InnerHtml); encode it with HtmlEncoder or clean it "
        "with HtmlSanitizer.",
    "هرّب قيم المرشّح (Encoder.LdapFilterEncode) والأسماء المميّزة (Encoder.LdapDistinguishedNameEncode) قبل البحث.":
        "Encode filter values (Encoder.LdapFilterEncode) and distinguished names (Encoder.LdapDistinguishedNameEncode) "
        "before searching.",
    "بيانات غير موثوقة تصل إلى سكربت PowerShell": "Tainted data reaches a PowerShell script",
    # php.json
    "مرّر القيم عبر setParameter() والعناصر النائبة (:name) بدل دمجها في where/orderBy.":
        "Pass values through setParameter() and placeholders (:name) instead of concatenating them into where/orderBy.",
    "بيانات غير موثوقة تصل إلى تعبير في منشئ استعلامات Doctrine": "Tainted data reaches a Doctrine query builder expression",
    # ruby.json
    "لا تستدعِ html_safe على مدخلات المستخدم؛ هرّبها بـ ERB::Util.h أو نظّفها بـ sanitize.":
        "Do not call html_safe on user input; escape it with ERB::Util.h or clean it with sanitize.",
    "ابنِ المرشّح بـ Net::LDAP::Filter.equals/contains أو هرّب القيمة بـ Net::LDAP::Filter.escape.":
        "Build the filter with Net::LDAP::Filter.equals/contains, or escape the value with Net::LDAP::Filter.escape.",
}

PATTERNS: list[tuple[str, str]] = []
