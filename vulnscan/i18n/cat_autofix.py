"""English catalog: automatic fix suggestions (vulnscan/autofix.py), their CLI flags, report labels and the
editor code action."""

CATALOG: dict[str, str] = {
    # ---- fix descriptions
    "استبدال yaml.load بـ yaml.safe_load الذي لا ينشئ كائنات Python عشوائية.":
        "Replace yaml.load with yaml.safe_load, which cannot construct arbitrary Python objects.",
    "تحويل الأمر الثابت إلى قائمة وسائط وإزالة shell=True حتى لا يمرّ عبر مفسّر الأوامر.":
        "Turn the constant command into an argument list and drop shell=True so it no longer goes through a shell.",
    "استبدال os.system بـ subprocess.run مع قائمة وسائط حتى لا يمرّ الأمر عبر مفسّر الأوامر.":
        "Replace os.system with subprocess.run and an argument list so the command no longer goes through a shell.",
    "إزالة verify=False ليعود التحقق من شهادة TLS إلى وضعه الافتراضي (مفعّل).":
        "Remove verify=False so TLS certificate verification returns to its default (enabled).",
    "ضبط verify على True لإعادة تفعيل التحقق من شهادة TLS.":
        "Set verify to True to re-enable TLS certificate verification.",
    "استبدال MD5/SHA-1 بـ SHA-256. تنبيه: القيم المحسوبة سابقًا بالخوارزمية القديمة لن تطابق الجديدة.":
        "Replace MD5/SHA-1 with SHA-256. Note: digests computed earlier with the old algorithm will no longer match.",
    "استبدال مولّد random القابل للتوقع بمولّد secrets المشفّر.":
        "Replace the predictable random generator with the cryptographic secrets module.",
    "إزالة خيار تعطيل التحقق من توقيع JWT ليُتحقق من التوقيع دائمًا.":
        "Remove the option that disables JWT signature verification so the signature is always verified.",
    "تعطيل وضع التصحيح (debug=False).": "Turn debug mode off (debug=False).",
    "تعطيل الكيانات الخارجية وDTD في محلل XML.": "Disable external entities and DTDs in the XML parser.",
    "استخدام defusedxml بدل محلل XML في المكتبة القياسية. تنبيه: يضيف هذا الاعتمادية defusedxml (pip install defusedxml).":
        "Use defusedxml instead of the standard-library XML parser. Note: this adds the defusedxml dependency "
        "(pip install defusedxml).",
    "تهريب القيمة بـ escape() قبل تعليمها آمنة بـ mark_safe.":
        "Escape the value with escape() before marking it safe with mark_safe.",
    "ضبط علامتي secure وhttponly على الكوكي.": "Set the secure and httponly flags on the cookie.",
    "ضبط httponly=True حتى لا يقرأ JavaScript الكوكي.": "Set httponly=True so JavaScript cannot read the cookie.",
    "ضبط secure وhttpOnly على true في خيارات الكوكي.": "Set secure and httpOnly to true in the cookie options.",
    "ضبط setSecure(true) حتى لا تُرسل الكوكي عبر HTTP غير مشفّر.":
        "Call setSecure(true) so the cookie is never sent over unencrypted HTTP.",
    "تحويل الاستعلام إلى استعلام مُعَلَّم: القيمة تُمرَّر وسيطًا منفصلًا بدل تضمينها في نص SQL.":
        "Turn the statement into a parameterized query: the value is passed as a separate parameter instead of "
        "being embedded in the SQL text.",
    "اقتراح دون تعديل آلي: استبدل Statement بـ PreparedStatement وضع ? مكان كل قيمة ثم اربطها بـ setString/setInt؛ "
    "هذا التحويل يحتاج إعادة هيكلة يدوية.":
        "Advice only, no automatic edit: replace Statement with PreparedStatement, put ? in place of each value and "
        "bind it with setString/setInt; this change needs a manual refactoring.",
    "استبدال exec بـ execFile مع قائمة وسائط حتى لا يمرّ الأمر عبر مفسّر الأوامر؛ المتغيّر يُمرَّر وسيطًا واحدًا.":
        "Replace exec with execFile and an argument list so the command no longer goes through a shell; the "
        "variable is passed as a single argument.",
    "استبدال innerHTML بـ textContent حتى تُعرض القيمة نصًا لا HTML.":
        "Replace innerHTML with textContent so the value is rendered as text, not HTML.",
    "استبدال eval بـ JSON.parse. تنبيه: JSON.parse يقبل JSON الصارم فقط.":
        "Replace eval with JSON.parse. Note: JSON.parse accepts strict JSON only.",
    "ضبط rejectUnauthorized على true لإعادة تفعيل التحقق من شهادة TLS.":
        "Set rejectUnauthorized to true to re-enable TLS certificate verification.",
    "استبدال خوارزمية التجزئة الضعيفة بـ SHA-256. تنبيه: القيم المحسوبة سابقًا لن تطابق الجديدة.":
        "Replace the weak hash algorithm with SHA-256. Note: digests computed earlier will no longer match.",
    "استبدال java.util.Random بـ java.security.SecureRandom.":
        "Replace java.util.Random with java.security.SecureRandom.",
    "إضافة إعدادات الحماية من XXE إلى DocumentBuilderFactory (منع DOCTYPE وتعطيل XInclude وتوسيع الكيانات).":
        "Add XXE hardening to the DocumentBuilderFactory (disallow DOCTYPE, disable XInclude and entity expansion).",
    "إضافة تعليمة USER برقم مستخدم غير root. تنبيه: تأكد أن ملفات التطبيق قابلة للقراءة لهذا المستخدم.":
        "Add a USER instruction with a non-root user id. Note: make sure the application files are readable by "
        "that user.",
    "ضبط allowPrivilegeEscalation على false.": "Set allowPrivilegeEscalation to false.",
    "ضبط runAsNonRoot على true.": "Set runAsNonRoot to true.",
    "إضافة securityContext على مستوى الـ Pod يفرض runAsNonRoot: true. تنبيه: الصورة التي تعمل بصلاحيات root لن تبدأ "
    "حتى يُحدَّد لها مستخدم غير root.":
        "Add a pod-level securityContext that enforces runAsNonRoot: true. Note: an image that runs as root will "
        "not start until it is given a non-root user.",
    "نقل تعبير GitHub غير الموثوق من run: إلى env: واستخدامه كمتغير بيئة في السكربت.":
        "Move the untrusted GitHub expression from run: into env: and use it as an environment variable in the script.",
    # ---- command line
    "طبّق الإصلاحات الآلية الآمنة على الملفات في مكانها ثم اعرض ملخصًا (يرفض إذا كانت في شجرة git تغييرات غير مودَعة "
    "إلا مع --fix-force)":
        "apply the safe automatic fixes in place and print a summary (refuses when the git tree has uncommitted "
        "changes unless --fix-force is given)",
    "اعرض الإصلاحات الآلية كفروق موحّدة (unified diff) دون تعديل أي ملف":
        "print the automatic fixes as unified diffs without modifying any file",
    "طبّق --fix حتى لو كانت في شجرة git تغييرات غير مودَعة":
        "apply --fix even when the git tree has uncommitted changes",
    "رُفض --fix: في شجرة git تغييرات غير مودَعة؛ أودِعها أولًا أو استخدم --fix-force.":
        "--fix refused: the git tree has uncommitted changes; commit them first or use --fix-force.",
    "رُفض --fix: إعدادات git في هذا المستودع تعرّف مرشّح محتوى يشغّل أمرًا، فلم يُشغَّل git للتحقق من "
    "التغييرات غير المودَعة؛ راجع ‎.git/config أو استخدم --fix-force.":
        "--fix refused: this repository's git configuration defines a content filter that runs a command, so git "
        "was not run to check for uncommitted changes; review .git/config or use --fix-force.",
    "أعد الفحص للتحقق من النتائج المتبقية.": "Scan again to check the remaining findings.",
    "--fix و--fix-dry-run يحتاجان مجلدًا أو ملفًا محليًا (لا عنوان ويب ولا أرشيفًا).":
        "--fix and --fix-dry-run need a local directory or file (not a URL or an archive).",
    # ---- reports / editor
    "إصلاح مقترح": "Suggested fix",
    "طبّق إصلاح كاشِف": "Apply Kashif fix",
}

PATTERNS: list[tuple[str, str]] = [
    (r"إصلاح آلي: طُبّق (?P<n>\d+) إصلاحًا في (?P<k>\d+) ملفًا\.", r"Autofix: applied \g<n> fix(es) in \g<k> file(s)."),
    (r"إصلاح آلي \(تجربة دون تعديل\): (?P<n>\d+) إصلاحًا متاحًا في (?P<k>\d+) ملفًا\.",
     r"Autofix (dry run, nothing modified): \g<n> fix(es) available in \g<k> file(s)."),
    (r"نتائج أُصلحت ضمن إصلاح آخر على السطر نفسه: (?P<n>\d+)\.", r"Findings resolved by another fix on the same line: \g<n>."),
    (r"نتائج لها اقتراح يدوي فقط: (?P<n>\d+)\.", r"Findings with manual advice only: \g<n>."),
    (r"نتائج بلا إصلاح آلي: (?P<n>\d+)\.", r"Findings without an automatic fix: \g<n>."),
    (r"تعذّرت الكتابة إلى: (?P<files>.+)", r"Could not write: \g<files>"),
]
