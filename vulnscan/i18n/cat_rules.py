"""English catalog: vulnscan/rules.py (rule and sensitive-file advice) and vulnscan/semantic.py (semantic-check advice)."""

CATALOG: dict[str, str] = {
    # ------------------------------------------------------------------ rules.py: secrets
    "احذف المفتاح من المصدر، وأبطله وأصدر غيره، وخزّن المفاتيح خارج الكود (متغيرات بيئة أو مدير أسرار).":
        "Remove the key from source control, revoke it and issue a new one, and keep keys out of code "
        "(environment variables or a secrets manager).",
    "أبطل المفتاح فورًا من IAM وأصدر مفتاحًا جديدًا، ولا تضع المفاتيح في الكود.":
        "Revoke the key in IAM immediately and issue a new one. Never store access keys in code.",
    "أبطل الرمز من لوحة الخدمة وأصدر غيره، وانقله إلى متغيرات البيئة.":
        "Revoke the token in the service's dashboard, issue a new one, and load it from environment variables.",
    "انقل القيمة إلى متغير بيئة أو مدير أسرار، وأصدر قيمة جديدة إذا كانت حقيقية.":
        "Move the value to an environment variable or a secrets manager, and rotate it if it is a real credential.",
    "لا تضع رموز JWT في المصدر؛ أبطل الرمز إذا كان صالحًا.":
        "Do not store JWTs in source code; revoke the token if it is still valid.",
    "احذف كلمة المرور من السلسلة واقرأها من متغير بيئة.":
        "Remove the password from the connection string and read it from an environment variable.",
    "أبطل الرمز من لوحة المزوّد فورًا وأصدر غيره، وانقله إلى متغيرات البيئة أو مدير أسرار.":
        "Revoke the token in the provider's console immediately, issue a new one, and move it to environment "
        "variables or a secrets manager.",
    "أبطل الرابط (يسمح بالنشر دون مصادقة) وانقله إلى سرّ مُدار.":
        "Revoke the webhook URL (it allows unauthenticated posting) and store it as a managed secret.",
    "احذف ملف مفتاح حساب الخدمة من المستودع، وأبطله من GCP IAM.":
        "Remove the service-account key file from the repository and revoke the key in GCP IAM.",
    "أبطل مفتاح الوصول من Azure وأعد توليده، واستخدم هويات مُدارة.":
        "Revoke and regenerate the access key in Azure, and use managed identities instead.",

    # ------------------------------------------------------------------ rules.py: code execution
    "لا تنفّذ نصوصًا ديناميكية؛ استخدم ast.literal_eval أو منطقًا صريحًا.":
        "Do not execute dynamic strings; use ast.literal_eval or explicit logic.",
    "تجنّب eval؛ استخدم JSON.parse أو منطقًا صريحًا.":
        "Avoid eval; use JSON.parse or explicit logic.",
    "تجنّب تنفيذ الأوامر؛ وإن لزم فاستخدم escapeshellarg وقائمة بيضاء.":
        "Avoid executing commands; if unavoidable, use escapeshellarg and an allowlist.",
    "استخدم قائمة وسائط بدون shell=True وتحقق من المدخلات.":
        "Pass an argument list without shell=True and validate the input.",
    "استخدم execFile/spawn بقائمة وسائط بدلًا من سلسلة أوامر.":
        "Use execFile/spawn with an argument array instead of a command string.",
    "مرّر الوسائط كقائمة وتحقّق منها بقائمة بيضاء.":
        "Pass arguments as a list and validate them against an allowlist.",
    "مرّر الوسائط منفصلة ولا تستدعِ shell.":
        "Pass arguments separately and do not invoke a shell.",
    "مرّر الوسائط كقائمة بدلًا من sh -c.":
        "Pass arguments as a list instead of using sh -c.",
    "نزّل الملف أولًا وتحقق من بصمته/توقيعه ثم شغّله.":
        "Download the file first, verify its checksum or signature, then run it.",

    # ------------------------------------------------------------------ rules.py: injection
    "استخدم الاستعلامات المُعَلَّمة (parameterized queries) بدل تركيب النص.":
        "Use parameterized queries instead of building SQL strings.",
    "استخدم استعلامات مُعَلَّمة أو ORM.":
        "Use parameterized queries or an ORM.",
    "استخدم PDO مع استعلامات مُعَلَّمة.":
        "Use PDO with parameterized queries (prepared statements).",
    "استخدم textContent أو مكتبة تعقيم مثل DOMPurify.":
        "Use textContent, or sanitize with a library such as DOMPurify.",
    "تأكد من تعقيم المحتوى (DOMPurify) قبل عرضه.":
        "Sanitize the content (for example with DOMPurify) before rendering it.",
    "مرّر المخرجات عبر htmlspecialchars.":
        "Encode output with htmlspecialchars.",
    "استخدم قائمة بيضاء من الملفات المسموح تضمينها.":
        "Restrict includes to an allowlist of permitted files.",
    "طبّع المسار وتحقق أنه داخل المجلد المسموح (resolve + is_relative_to).":
        "Normalize the path and verify it stays inside the permitted directory (resolve + is_relative_to).",
    "استخدم قوالب ثابتة ومرّر البيانات كمتغيرات.":
        "Use static templates and pass data as template variables.",

    # ------------------------------------------------------------------ rules.py: deserialization
    "لا تفك تسلسل بيانات غير موثوقة؛ استخدم JSON.":
        "Do not deserialize untrusted data; use JSON.",
    "استخدم yaml.safe_load.":
        "Use yaml.safe_load.",
    "تجنب تسلسل Java للبيانات غير الموثوقة أو استخدم ObjectInputFilter.":
        "Avoid Java deserialization of untrusted data, or restrict it with an ObjectInputFilter.",
    "استخدم json_decode بدلًا من unserialize.":
        "Use json_decode instead of unserialize.",
    "استخدم YAML.safe_load.":
        "Use YAML.safe_load.",

    # ------------------------------------------------------------------ rules.py: crypto / TLS
    "استخدم SHA-256 أو أقوى، ولكلمات المرور bcrypt/argon2.":
        "Use SHA-256 or stronger; for passwords, use bcrypt or Argon2.",
    "فعّل التحقق من الشهادة؛ وثبّت شهادة خاصة (pinning) إذا كانت ذاتية التوقيع.":
        "Enable certificate verification; pin the certificate if it is self-signed.",
    "استخدم TLS 1.2 أو أحدث.":
        "Use TLS 1.2 or later.",
    "استخدم AES-GCM أو ChaCha20-Poly1305.":
        "Use AES-GCM or ChaCha20-Poly1305.",
    "استخدم مولّدًا مشفّرًا: secrets (Python)، crypto.randomBytes (Node)، Random.secure() (Dart)، SecureRandom (Java).":
        "Use a cryptographically secure generator: secrets (Python), crypto.randomBytes (Node), "
        "Random.secure() (Dart), SecureRandom (Java).",
    "ولّد IV/salt عشوائيًا لكل عملية وخزّنه مع النص المشفر.":
        "Generate a random IV/salt for each operation and store it alongside the ciphertext.",

    # ------------------------------------------------------------------ rules.py: network / configuration
    "عطّل الكيانات الخارجية وDTD: لا تفعّل feature_external_ges/resolve_entities، واستخدم defusedxml في Python، "
    "وفي Java فعّل disallow-doctype-decl.":
        "Disable external entities and DTDs: do not enable feature_external_ges/resolve_entities; use defusedxml "
        "in Python, and enable disallow-doctype-decl in Java.",
    "استخدم https://.":
        "Use https://.",
    "اقصر الاستماع على 127.0.0.1 أو ضع الخدمة خلف جدار حماية/عكسي وكيل مع مصادقة.":
        "Bind to 127.0.0.1, or place the service behind a firewall or a reverse proxy that enforces authentication.",
    "حدّد الأصول المسموحة صراحة، خاصة مع allow_credentials.":
        "List allowed origins explicitly, especially when allow_credentials is enabled.",
    "عطّل وضع التصحيح في الإنتاج.":
        "Disable debug mode in production.",
    "حدّد المضيفين المسموحين.":
        "List the allowed hosts explicitly.",
    "استخدم tempfile.NamedTemporaryFile/mkstemp.":
        "Use tempfile.NamedTemporaryFile or tempfile.mkstemp.",
    "استخدم أقل الصلاحيات الممكنة (مثل 750/640).":
        "Apply least-privilege permissions (for example 750/640).",
    "assert يُحذف عند التحسين؛ استخدم شرطًا صريحًا يرفع استثناءً.":
        "assert statements are removed under optimization (-O); use an explicit check that raises an exception.",
    "ارفض المفاتيح الفارغة وافرض المصادقة افتراضيًا.":
        "Reject empty keys and require authentication by default.",
    "تحقق دائمًا من التوقيع وحدّد الخوارزميات المسموحة.":
        "Always verify the signature and specify the allowed algorithms.",

    # ------------------------------------------------------------------ rules.py: Android / iOS
    "عطّل cleartext واستخدم HTTPS فقط (أو استثنِ نطاقات محددة في network_security_config).":
        "Disable cleartext traffic and use HTTPS only (or exempt specific domains in network_security_config).",
    "تأكد أن كل مكوّن مُصدَّر يحتاج إذنًا أو مقصود فعلًا.":
        "Ensure every exported component requires a permission or is intentionally exported.",
    "عطّل allowBackup إذا كان التطبيق يخزن بيانات حساسة.":
        "Disable allowBackup if the app stores sensitive data.",
    "قيّد محتوى WebView بمصادر موثوقة وعطّل الوصول للملفات.":
        "Restrict WebView content to trusted sources and disable file access.",
    "أزل NSAllowsArbitraryLoads أو قصره على نطاقات محددة.":
        "Remove NSAllowsArbitraryLoads or limit the exception to specific domains.",
    "استخدم Keychain/EncryptedSharedPreferences/flutter_secure_storage.":
        "Use Keychain, EncryptedSharedPreferences or flutter_secure_storage.",

    # ------------------------------------------------------------------ rules.py: Docker / CI
    "أضف تعليمة USER لمستخدم غير root.":
        "Add a USER instruction that switches to a non-root user.",
    "استخدم curl مع تحقق من البصمة ثم COPY.":
        "Download with curl, verify the checksum, then use COPY.",
    "ثبّت إصدار الصورة (ويفضَّل digest).":
        "Pin the image version (preferably by digest).",
    "تجنّب privileged ومشاركة docker.sock.":
        "Avoid privileged mode and do not mount docker.sock.",
    "مرّر الأسرار وقت التشغيل أو عبر --secret، لا في الصورة.":
        "Provide secrets at run time or via --secret, never baked into the image.",
    "مرّر القيمة عبر env: ثم استخدم \"$VAR\" في run:، ولا تضمّنها مباشرة.":
        "Pass the value through env: and reference it as \"$VAR\" in run:; never interpolate it directly.",
    "لا تسحب كود الـ PR (ref: head) مع pull_request_target؛ استخدم pull_request.":
        "Do not check out PR code (ref: head) in pull_request_target workflows; use pull_request instead.",
    "اقصر الصلاحيات على ما يلزم (contents: read…).":
        "Grant only the permissions required (contents: read…).",
    "ثبّت الإجراءات الخارجية على SHA كامل.":
        "Pin third-party actions to a full commit SHA.",
    "لا تطبع الأسرار؛ استخدمها عبر env فقط.":
        "Do not print secrets; access them only through env.",
    "مرّر الأسرار عبر متغير بيئة أو ملف بصلاحيات مقيدة.":
        "Pass secrets through an environment variable or a file with restricted permissions.",

    # ------------------------------------------------------------------ rules.py: C memory safety / logging
    "استخدم البدائل المحدودة الطول: fgets/strncpy/snprintf.":
        "Use bounded alternatives: fgets/strncpy/snprintf.",
    "استخدم \"%s\" كسلسلة تنسيق ثابتة.":
        "Use a constant format string such as \"%s\".",
    "لا تسجّل الأسرار؛ قنّع القيم الحساسة.":
        "Do not log secrets; mask sensitive values.",

    # ------------------------------------------------------------------ rules.py: SENSITIVE_FILES
    "لا تضمّن ملفات .env؛ أضفها إلى .gitignore واستخدم .env.example.":
        "Do not commit .env files; add them to .gitignore and provide a .env.example instead.",
    "احذفه من المشروع وأبطل المفتاح.":
        "Remove it from the project and revoke the key.",
    "تأكد أنه لا يحوي مفتاحًا خاصًا؛ خزّن المفاتيح خارج المشروع.":
        "Make sure it does not contain a private key; store keys outside the project.",
    "راجعه واحذف أي رموز وصول.":
        "Review it and remove any access tokens.",
    "عادةً عام، لكن تأكد من قواعد أمان Firebase.":
        "Usually public, but verify your Firebase Security Rules.",
    "تأكد أنه لا يحوي بيانات حقيقية.":
        "Make sure it does not contain real data.",

    # ------------------------------------------------------------------ semantic.py
    "اضبط secure=True (وhttponly=True وsamesite) عند إنشاء الكوكي، وفعّل SESSION_COOKIE_SECURE "
    "حتى لا تُرسل الكوكي عبر HTTP غير مشفّر.":
        "Set secure=True (and httponly=True and samesite) when creating the cookie, and enable "
        "SESSION_COOKIE_SECURE so the cookie is never sent over unencrypted HTTP.",
    "استخدم secrets (token_urlsafe / token_hex / randbelow) أو random.SystemRandom للقيم الأمنية.":
        "Use secrets (token_urlsafe / token_hex / randbelow) or random.SystemRandom for security-sensitive values.",
    "استخدم SHA-256 أو أقوى، ولكلمات المرور PBKDF2/bcrypt/argon2.":
        "Use SHA-256 or stronger; for passwords, use PBKDF2, bcrypt or Argon2.",
    "استخدم AES-GCM (أو ChaCha20-Poly1305) بمفتاح 128/256 بت ومتجه تهيئة عشوائي.":
        "Use AES-GCM (or ChaCha20-Poly1305) with a 128/256-bit key and a random IV.",
    "استخدم java.security.SecureRandom (أو SecureRandom.getInstanceStrong()).":
        "Use java.security.SecureRandom (or SecureRandom.getInstanceStrong()).",
}

# rules.py and semantic.py emit no dynamic (f-string) Arabic text.
PATTERNS: list[tuple[str, str]] = []
