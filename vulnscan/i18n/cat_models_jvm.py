"""English catalog: Java / Kotlin library models added in the breadth expansion."""

CATALOG: dict[str, str] = {
    # java.json
    "لا تمرّر نص SQL مركّبًا من المدخلات إلى واجهات الاستعلام الخام (JdbcTemplate/Hibernate/jOOQ/R2DBC)؛ استخدم معاملات مربوطة.":
        "Do not pass SQL text built from input to raw-query APIs (JdbcTemplate/Hibernate/jOOQ/R2DBC); use bound parameters.",
    "لا تحلّل استعلام MongoDB من نص يحوي مدخلات المستخدم ولا تستخدم $where؛ ابنِ المرشّحات بـ Filters ومرّر القيم كمعاملات.":
        "Do not parse a MongoDB query from text that contains user input and do not use $where; build filters with "
        "Filters and pass values as parameters.",
    "لا تقيّم تعبيرات OGNL/MVEL/JEXL/EL أو سكربتات Groovy/JavaScript مبنية من المدخلات؛ استخدم قائمة بيضاء من العمليات أو سياق تقييم مقيّدًا.":
        "Do not evaluate OGNL/MVEL/JEXL/EL expressions or Groovy/JavaScript scripts built from input; use an allowlist "
        "of operations or a restricted evaluation context.",
    "لا تمرّر اسم JNDI من المدخلات إلى lookup()؛ استخدم أسماء ثابتة أو قائمة بيضاء (حقن JNDI يؤدي إلى تحميل أصناف بعيدة).":
        "Do not pass a JNDI name from input to lookup(); use fixed names or an allowlist (JNDI injection leads to "
        "remote class loading).",
    "لا تحمّل ورقة أنماط XSLT من مدخلات المستخدم؛ استخدم أوراق أنماط ثابتة وفعّل FEATURE_SECURE_PROCESSING.":
        "Do not load an XSLT stylesheet from user input; use fixed stylesheets and enable FEATURE_SECURE_PROCESSING.",
    "لا تبنِ القالب من المدخلات؛ حمّل القوالب من مجلد موثوق ومرّر المدخلات كبيانات في سياق القالب فقط.":
        "Do not build the template from input; load templates from a trusted directory and pass input only as data "
        "in the template context.",
    "أزل محرفَي CR وLF من القيمة أو ارفضها قبل وضعها في ترويسة الاستجابة.":
        "Strip or reject the CR and LF characters in the value before putting it into a response header.",
    "بيانات غير موثوقة تصل إلى واجهة استعلام SQL خام": "Tainted data reaches a raw SQL query API",
    "بيانات غير موثوقة تصل إلى استعلام MongoDB مُحلَّل من نص": "Tainted data reaches a MongoDB query parsed from text",
    "بيانات غير موثوقة تصل إلى تقييم سكربت أو تعبير": "Tainted data reaches script / expression evaluation",
    "بيانات غير موثوقة تصل إلى بحث JNDI (حقن JNDI)": "Tainted data reaches a JNDI lookup (JNDI injection)",
    "بيانات غير موثوقة تصل إلى ورقة أنماط XSLT (حقن XSLT)": "Tainted data reaches an XSLT stylesheet (XSLT injection)",
    "بيانات غير موثوقة تُكتب في ترويسة استجابة HTTP": "Tainted data written to an HTTP response header",
    # kotlin.json
    "لا تمرّر نص SQL مركّبًا إلى exec() أو execInBatch() في Exposed؛ استخدم DSL أو معاملات مربوطة.":
        "Do not pass concatenated SQL text to exec() or execInBatch() in Exposed; use the DSL or bound parameters.",
    "طبّع المسار وتحقق أنه داخل المجلد المسموح قبل قراءته أو كتابته (File/Path في kotlin.io).":
        "Normalize the path and check that it stays inside the allowed directory before reading or writing it "
        "(kotlin.io File/Path).",
    "بيانات غير موثوقة تصل إلى SQL خام في Exposed": "Tainted data reaches raw SQL in Exposed",
}

PATTERNS: list[tuple[str, str]] = []
