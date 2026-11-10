"""English catalog: JavaScript / TypeScript library models added in the breadth expansion."""

CATALOG: dict[str, str] = {
    "لا تنفّذ نصوصًا من المدخلات حتى داخل vm أو safe-eval: ليست حدودًا أمنية؛ استخدم JSON.parse أو منطقًا صريحًا.":
        "Never execute input as code, even inside vm or safe-eval: they are not security boundaries; use JSON.parse "
        "or explicit logic.",
    "مرّر القيم كمعاملات مرتبطة (whereRaw('x = ?', [v]) أو :name) ولا تدمجها في نص SQL.":
        "Pass values as bound parameters (whereRaw('x = ?', [v]) or :name) instead of concatenating them into the SQL "
        "text.",
    "حوّل القيم إلى نصوص/أرقام صريحة (String(x)) وارفض الكائنات والمفاتيح التي تبدأ بـ $ (حقن NoSQL).":
        "Cast values to explicit strings/numbers (String(x)) and reject objects and keys starting with $ (NoSQL "
        "injection).",
    "استخدم .text() أو عقّم بـ DOMPurify قبل إدراج HTML بـ jQuery.":
        "Use .text(), or sanitize with DOMPurify before inserting HTML with jQuery.",
}

PATTERNS: list[tuple[str, str]] = []
