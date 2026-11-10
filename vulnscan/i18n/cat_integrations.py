"""English catalog: IDE (LSP) and pull-request integration messages."""

CATALOG: dict[str, str] = {
    # ---- language server (vulnscan/lsp.py)
    "اكتم هذه النتيجة": "Suppress this finding",
    "أضِف إلى خط الأساس": "Add to baseline",
    "افتح وصف الضعف في CWE": "Open CWE",
    "الخطورة": "Severity",
    "القاعدة": "Rule",
    "المعالجة": "Remediation",
    "مسار البيانات": "Data-flow trail",
    "أُضيفت النتيجة إلى خط الأساس ولن تظهر بعد الآن.": "The finding was added to the baseline and will no longer be shown.",
    "النتيجة موجودة في خط الأساس مسبقًا.": "The finding is already in the baseline.",
    "تعذّر حفظ خط الأساس؛ تحقّق من أن الملف قابل للكتابة وأنه JSON صالح.":
        "Could not save the baseline; check that the file is writable and is valid JSON.",
    "لم تعد هذه النتيجة موجودة؛ أعد الفحص ثم حاول مجددًا.": "This finding no longer exists; rescan and try again.",
    "افتح هذا الرابط لقراءة وصف الضعف:": "Open this link to read the weakness description:",
    # ---- diff-aware scanning (vulnscan/diffscope.py, --diff-base / --diff-staged)
    "افحص كل شيء لكن اعرض فقط النتائج على الأسطر المضافة أو المعدّلة منذ نقطة التفرّع مع REF "
    "(أو التي يمرّ مسار بياناتها بها)؛ لطلبات الدمج":
        "Scan everything but report only findings on lines added or modified since the merge-base with REF "
        "(or whose data-flow trail crosses one); for pull requests",
    "اعرض فقط النتائج على الأسطر المجهّزة للإيداع (git add) مقارنة بـ HEAD؛ لخطافات pre-commit":
        "Report only findings on lines staged for commit (git add) relative to HEAD; for pre-commit hooks",
    "git غير مثبّت؛ الفحص المقيّد بالتغييرات يحتاج git.": "git is not installed; diff-aware scanning needs git.",
    "الهدف ليس داخل مستودع git؛ لا يمكن تقييد النتائج بالتغييرات.":
        "The target is not inside a git repository; findings cannot be limited to the changes.",
    "تعذّر حساب نقطة التفرّع (نسخة سطحية؟)؛ قورن مع المرجع الأساس مباشرة.":
        "Could not compute the merge-base (shallow clone?); compared with the base ref directly.",
}

PATTERNS: list[tuple[str, str]] = [
    (r"مرجع git غير صالح: (?P<ref>.*)", r"Invalid git ref: \g<ref>"),
    (r"فشل أمر git: (?P<cmd>[\w-]+)", r"git command failed: \g<cmd>"),
    (r"المرجع غير موجود في المستودع: (?P<ref>\S+) \(اجلبه أولًا، مثلًا git fetch origin (?P<ref2>\S+)\)",
     r"Ref not found in the repository: \g<ref> (fetch it first, e.g. git fetch origin \g<ref2>)"),
    (r"تقييد بالتغييرات منذ (?P<ref>\S+): (?P<n>\d+) ملفًا متغيّرًا\.",
     r"Limited to changes since \g<ref>: \g<n> changed file(s)."),
    (r"نتائج خارج التغييرات لم تُعرض: (?P<n>\d+)\.", r"Findings outside the changes not shown: \g<n>."),
]
