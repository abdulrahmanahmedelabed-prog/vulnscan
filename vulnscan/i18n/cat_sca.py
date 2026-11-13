"""English catalog: dependency analysis and reachability (vulnscan/deps.py, vulnscan/sca.py)."""

CATALOG: dict[str, str] = {
    "لم يُعثر على استيراد لهذه الحزمة في الكود المفحوص؛ خُفِّضت الخطورة درجة واحدة.":
        "The scanned code never imports this package, so the severity was lowered one level.",
    # the wording of Kashif 1.0.1 (الشيفرة), still in older reports
    "لم يُعثر على استيراد لهذه الحزمة في الشيفرة المفحوصة؛ خُفِّضت الخطورة درجة واحدة.":
        "The scanned code never imports this package, so the severity was lowered one level.",
    "الحزمة مستوردة في الكود المفحوص.": "The scanned code imports this package.",
    # the wording of Kashif 1.0.1 (الشيفرة), still in older reports
    "الحزمة مستوردة في الشيفرة المفحوصة.": "The scanned code imports this package.",
    "الحزمة مستوردة، لكن لم يُعثر على استدعاء للدوال المصابة المذكورة في التقرير.":
        "The package is imported, but no call to the vulnerable functions named in the advisory was found.",
    "تعذّر تحديد ما إذا كان الكود يستخدم هذه الحزمة.": "Could not determine whether the code uses this package.",
    # the wording of Kashif 1.0.1 (الشيفرة), still in older reports
    "تعذّر تحديد ما إذا كانت الشيفرة تستخدم هذه الحزمة.": "Could not determine whether the code uses this package.",
    "هذه اعتمادية غير مباشرة؛ حدّث الحزمة التي تجلبها أو ثبّت الإصدار المُصحَّح.":
        "This is a transitive dependency: upgrade the package that pulls it in, or pin the patched version.",
}

PATTERNS: list[tuple[str, str]] = [
    (r"الكود يستدعي دوال مصابة في هذه الحزمة: (?P<syms>[^؀-ۿ]+)\.",
     r"The code calls vulnerable functions of this package: \g<syms>."),
    # the wording of Kashif 1.0.1 (الشيفرة), still in older reports
    (r"الشيفرة تستدعي دوال مصابة في هذه الحزمة: (?P<syms>[^؀-ۿ]+)\.",
     r"The code calls vulnerable functions of this package: \g<syms>."),
    # advice = upgrade sentence + notes; each part is translated on its own
    (r"(?P<a>حدّث \S+ إلى .+?\.) (?P<b>\S.*)", r"\g<a> \g<b>"),
    (r"(?P<a>هذه اعتمادية غير مباشرة؛ [^.]+\.) (?P<b>\S.*)", r"\g<a> \g<b>"),
    # scan notes when OSV.dev cannot be reached. Since 1.0.2 each count agrees with its noun ("{n} phrase" below,
    # translated on its own); the patterns after these are the 1.0.1 wording ("N اعتمادية"), still in older reports.
    (r"تعذّر الاتصال بـ OSV\.dev لفحص (?P<n>[^ ()]+(?: [^ ()]+)?) \((?P<why>.+)\)\. لم تُفحص ثغرات الاعتماديات؛ "
     r"أعد المحاولة عند توفّر الإنترنت، أو استخدم --no-deps لتعطيل هذا الفحص\.",
     r"Could not reach OSV.dev to check \g<n> (\g<why>). Dependency vulnerabilities were NOT checked; "
     r"retry when online, or pass --no-deps to turn this check off."),
    (r"تعذّر الاتصال بـ OSV\.dev \((?P<why>.+)\): فُحصت (?P<k>[^ ()]+(?: [^ ()]+)?) من النتائج المخزَّنة مؤقتًا "
     r"\((?P<v>[^()]+)\) وبقيت (?P<u>[^ ()]+(?: [^ ()]+)?) بلا فحص\.",
     r"Could not reach OSV.dev (\g<why>): \g<k> checked from cached results (\g<v>) and \g<u> left unchecked."),
    (r"تعذّر جلب تفاصيل (?P<n>[^ ()]+(?: [^ ()]+)?) من OSV\.dev؛ أُبلغ عنها بخطورة متوسطة ودون الإصدار المُصحَّح\. "
     r"أعد الفحص لاحقًا للحصول على التفاصيل\.",
     r"Could not fetch the details of \g<n> from OSV.dev; they are reported as medium severity without a fixed "
     r"version. Scan again later to get the details."),
    # the count phrases of these notes
    (r"اعتمادية واحدة", r"1 dependency"),
    (r"اعتماديت(?:ان|ين)", r"2 dependencies"),
    (r"(?P<n>\d+) (?:اعتماديات|اعتماديةً|اعتمادية)", r"\g<n> dependencies"),
    (r"ثغرة واحدة", r"1 vulnerability"),
    (r"ثغرتين", r"2 vulnerabilities"),
    (r"(?P<n>\d+) (?:ثغرات|ثغرةً|ثغرة)", r"\g<n> vulnerabilities"),
    (r"ثغرة معروفة واحدة", r"1 known vulnerability"),
    (r"ثغرتان معروفتان", r"2 known vulnerabilities"),
    (r"(?P<n>\d+) (?:ثغرات معروفة|ثغرةً معروفةً|ثغرة معروفة)", r"\g<n> known vulnerabilities"),
    (r"تعذّر الاتصال بـ OSV\.dev لفحص (?P<n>\d+) اعتمادية \((?P<why>.+)\)\. لم تُفحص ثغرات الاعتماديات؛ "
     r"أعد المحاولة عند توفّر الإنترنت، أو استخدم --no-deps لتعطيل هذا الفحص\.",
     r"Could not reach OSV.dev to check \g<n> dependencies (\g<why>). Dependency vulnerabilities were NOT checked; "
     r"retry when online, or pass --no-deps to turn this check off."),
    (r"تعذّر الاتصال بـ OSV\.dev \((?P<why>.+)\): فُحصت (?P<k>\d+) اعتمادية من النتائج المخزَّنة مؤقتًا "
     r"\((?P<v>\d+) ثغرة معروفة\) وبقيت (?P<u>\d+) اعتمادية بلا فحص\.",
     r"Could not reach OSV.dev (\g<why>): \g<k> dependencies were checked from cached results "
     r"(\g<v> known vulnerabilities) and \g<u> dependencies were left unchecked."),
    (r"تعذّر جلب تفاصيل (?P<n>\d+) ثغرة من OSV\.dev؛ أُبلغ عنها بخطورة متوسطة ودون الإصدار المُصحَّح\. "
     r"أعد الفحص لاحقًا للحصول على التفاصيل\.",
     r"Could not fetch the details of \g<n> vulnerabilities from OSV.dev; they are reported as medium severity "
     r"without a fixed version. Scan again later to get the details."),
]
