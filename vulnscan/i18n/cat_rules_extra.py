"""English catalog: pattern rules, IaC and VQL queries added in the breadth expansion."""

CATALOG: dict[str, str] = {
    # ------------------------------------------------------------------ secrets
    "أبطل المفتاح أو رمز SAS من Azure وأعد توليده، واستخدم هويات مُدارة أو رموز SAS قصيرة العمر تُولَّد عند الحاجة.":
        "Revoke and regenerate the key or SAS token in Azure, and use managed identities or short-lived SAS tokens "
        "issued on demand.",
    "أبطل الرمز (vault token revoke) وأصدر غيره بعمر قصير، ولا تضعه في الكود.":
        "Revoke the token (vault token revoke), issue a short-lived replacement, and keep it out of code.",
    "احذف المفتاح من المستودع وأصدر غيره؛ التشفير بعبارة مرور لا يمنع الهجوم عليها دون اتصال.":
        "Remove the key from the repository and issue a new one; a passphrase does not stop offline attacks on it.",

    # ------------------------------------------------------------------ Dockerfile / Compose
    "البناء يجري بصلاحيات المستخدم الحالي؛ نفّذ الأوامر المميزة قبل USER ولا تثبّت sudo في الصورة.":
        "Build steps run as the current user; run privileged commands before USER and do not install sudo in the image.",
    "لا تشغّل SSH داخل الحاويات؛ استخدم docker exec/kubectl exec للوصول الإداري.":
        "Do not run SSH inside containers; use docker exec / kubectl exec for administrative access.",
    "لا تعطّل التحقق من الشهادات أو التواقيع؛ أضف شهادة CA الداخلية إلى مخزن الثقة بدلًا من ذلك.":
        "Do not disable certificate or signature verification; add the internal CA certificate to the trust store "
        "instead.",
    "لا تضبط كلمات المرور في طبقات الصورة؛ مرّرها وقت التشغيل أو عبر BuildKit --secret.":
        "Do not set passwords in image layers; pass them at run time or through BuildKit --secret.",
    "أزل network_mode/pid/ipc: host؛ مشاركة مساحات أسماء المضيف تكسر عزل الحاوية.":
        "Remove network_mode/pid/ipc: host; sharing host namespaces breaks container isolation.",
    "أبقِ ملفات seccomp وAppArmor الافتراضية؛ عطّل قدرات محددة فقط عند الحاجة.":
        "Keep the default seccomp and AppArmor profiles; relax only specific capabilities when required.",

    # ------------------------------------------------------------------ Kubernetes
    "اضبط allowPrivilegeEscalation: false في securityContext لكل حاوية.":
        "Set allowPrivilegeEscalation: false in every container's securityContext.",
    "أزل hostNetwork/hostPID/hostIPC؛ فهي تكشف شبكة المضيف وعملياته للحاوية.":
        "Remove hostNetwork/hostPID/hostIPC; they expose the host's network and processes to the container.",
    "تجنّب hostPath؛ استخدم PersistentVolumeClaim أو emptyDir، وإن لزم فاجعله readOnly ومحدودًا.":
        "Avoid hostPath; use a PersistentVolumeClaim or emptyDir, and if it is unavoidable make it readOnly and narrow.",
    "أسقط كل القدرات (drop: [ALL]) وأضف فقط ما يلزم فعلًا؛ SYS_ADMIN وما يماثلها تعادل صلاحيات root.":
        "Drop all capabilities (drop: [ALL]) and add back only what is really needed; SYS_ADMIN and similar are "
        "equivalent to root.",
    "اضبط readOnlyRootFilesystem: true واستخدم emptyDir للمسارات التي تحتاج كتابة.":
        "Set readOnlyRootFilesystem: true and use emptyDir for paths that need to be writable.",
    "اضبط runAsNonRoot: true وrunAsUser برقم غير صفري.":
        "Set runAsNonRoot: true and a non-zero runAsUser.",
    "ثبّت إصدار الصورة (ويفضَّل digest) لتكون عمليات النشر قابلة للتكرار والتدقيق.":
        "Pin the image version (preferably by digest) so deployments are reproducible and auditable.",
    "استخدم RuntimeDefault لملفي seccomp وAppArmor.":
        "Use the RuntimeDefault seccomp and AppArmor profiles.",
    "اذكر الأفعال والموارد اللازمة صراحة بدل *؛ مبدأ أقل الصلاحيات.":
        "List the required verbs and resources explicitly instead of *; follow least privilege.",
    "حدّد resources.limits (cpu وmemory) لكل حاوية لتجنّب استنزاف موارد العقدة.":
        "Set resources.limits (cpu and memory) for every container to avoid exhausting the node's resources.",
    "استخدم valueFrom.secretKeyRef مع Secret مُدار (أو مدير أسرار خارجي) بدل كتابة القيمة.":
        "Use valueFrom.secretKeyRef with a managed Secret (or an external secrets manager) instead of a literal value.",

    # ------------------------------------------------------------------ Terraform
    "اجعل الحاوية خاصة (private) وقدّم الملفات العامة عبر CDN بصلاحيات محددة.":
        "Make the bucket private and serve public files through a CDN with scoped access.",
    "فعّل الإعدادات الأربعة لحظر الوصول العام (true).":
        "Enable all four Block Public Access settings (true).",
    "حدّد الحسابات أو الأدوار المسموحة صراحة، أو أضف شرطًا (Condition) يقيّد المصدر.":
        "Name the allowed accounts or roles explicitly, or add a Condition that restricts the caller.",
    "اذكر الإجراءات اللازمة فقط؛ Action: * يمنح صلاحيات المدير.":
        "List only the actions that are needed; Action: * grants administrator rights.",
    "فعّل التشفير (true) واستخدم مفتاح KMS مُدارًا.":
        "Enable encryption (true) and use a managed KMS key.",
    "اضبط publicly_accessible = false وضع القاعدة في شبكة فرعية خاصة.":
        "Set publicly_accessible = false and place the database in a private subnet.",
    "فعّل enable_logging وenable_log_file_validation في CloudTrail.":
        "Enable enable_logging and enable_log_file_validation on the CloudTrail trail.",
    "اضبط enable_key_rotation = true.":
        "Set enable_key_rotation = true.",
    "أزل allUsers/allAuthenticatedUsers وامنح الوصول لهويات محددة.":
        "Remove allUsers/allAuthenticatedUsers and grant access to specific identities.",
    "اضبط القيمة إلى true لفرض HTTPS.":
        "Set the value to true to enforce HTTPS.",
    "اضبط الحد الأدنى على TLS 1.2 أو أحدث.":
        "Set the minimum to TLS 1.2 or later.",
    "اجعل نقطة نهاية API خاصة أو قيّدها بقائمة عناوين موثوقة.":
        "Make the API endpoint private or restrict it to a list of trusted address ranges.",
    "قيّد public_access_cidrs بعناوين محددة أو عطّل الوصول العام.":
        "Restrict public_access_cidrs to specific ranges or disable public access.",
    'اضبط http_tokens = "required" لفرض IMDSv2 والحد من سرقة بيانات الاعتماد عبر SSRF.':
        'Set http_tokens = "required" to enforce IMDSv2 and limit credential theft through SSRF.',
    "استخدم متغيرات البيئة أو ملفات الاعتماد أو هوية مُدارة بدل كتابة المفاتيح في الإعدادات.":
        "Use environment variables, credential files or a managed identity instead of writing keys in configuration.",
    "عطّل الوصول العام واستخدم رموز SAS قصيرة العمر أو هويات مُدارة.":
        "Disable public access and use short-lived SAS tokens or managed identities.",
    "افرض الاتصالات المشفّرة على قاعدة البيانات.":
        "Enforce encrypted connections to the database.",
    "اسمح فقط بنطاقات العناوين اللازمة.":
        "Allow only the address ranges that are needed.",
    "قيّد المصدر بنطاقات موثوقة أو استخدم bastion/SSM/VPN بدل فتح SSH وRDP للعالم.":
        "Restrict the source to trusted ranges, or use a bastion / SSM / VPN instead of opening SSH and RDP to the "
        "world.",

    # ------------------------------------------------------------------ GitHub Actions
    "ثبّت الإجراءات الخارجية على SHA كامل (40 حرفًا) واذكر الإصدار في تعليق؛ الوسوم والفروع قابلة للنقل.":
        "Pin third-party actions to a full 40-character commit SHA and note the version in a comment; tags and "
        "branches can be moved.",
    "أزل هذا المتغير؛ يعيد تفعيل أوامر set-env/add-path التي تسمح بحقن متغيرات البيئة.":
        "Remove this variable; it re-enables the set-env/add-path commands that allow environment-variable injection.",
    "ثبّت الصورة على digest (@sha256:…).":
        "Pin the image to a digest (@sha256:…).",

    # ------------------------------------------------------------------ JWT / CORS / TLS / crypto
    "استخدم parseSignedClaims/parseClaimsJws مع مفتاح تحقق، ولا تقبل JWT غير موقّع.":
        "Use parseSignedClaims/parseClaimsJws with a verification key, and never accept an unsigned JWT.",
    "لا تقبل الخوارزمية none؛ تحقق من نوع خوارزمية التوقيع في keyFunc.":
        "Never accept the none algorithm; check the signing method's type in keyFunc.",
    "استخدم jwt.Parse مع keyFunc يتحقق من التوقيع والخوارزمية قبل الوثوق بالمطالبات.":
        "Use jwt.Parse with a keyFunc that verifies the signature and algorithm before trusting the claims.",
    "اضبط RequireSignedTokens على true ولا تستبدل SignatureValidator بدالة تتجاوز التحقق من التوقيع.":
        "Set RequireSignedTokens to true and do not replace SignatureValidator with a delegate that skips the signature "
        "check.",
    "مرّر true للتحقق وحدّد algorithm صراحة.":
        "Pass true to verify, and specify the algorithm explicitly.",
    "اقرأ مفتاح التوقيع من مدير أسرار أو متغير بيئة، وأصدر مفتاحًا جديدًا إن كان حقيقيًا.":
        "Read the signing key from a secrets manager or an environment variable, and rotate it if it is real.",
    "لا تجمع بين أي أصل وبيانات الاعتماد؛ حدّد قائمة بيضاء من الأصول الموثوقة.":
        "Never combine any-origin with credentials; allow-list the trusted origins.",
    "قارن الأصل بقائمة بيضاء قبل إعادته في Access-Control-Allow-Origin.":
        "Check the origin against an allow-list before echoing it in Access-Control-Allow-Origin.",
    "فعّل التحقق من الشهادة واسم المضيف؛ استخدم ssl.create_default_context().":
        "Enable certificate and hostname verification; use ssl.create_default_context().",
    "استخدم مدقق أسماء المضيف الافتراضي؛ لا تقبل كل المضيفين.":
        "Use the default hostname verifier; do not accept every host.",
    "لا تتجاوز التحقق من الشهادة؛ ثبّت الشهادة أو أضف CA الداخلية إلى مخزن الثقة.":
        "Do not bypass certificate validation; pin the certificate or add the internal CA to the trust store.",
    "استخدم OpenSSL::SSL::VERIFY_PEER.":
        "Use OpenSSL::SSL::VERIFY_PEER.",
    "فعّل التحقق: CURLOPT_SSL_VERIFYHOST = 2 وverify_peer = true.":
        "Enable verification: CURLOPT_SSL_VERIFYHOST = 2 and verify_peer = true.",
    "حدّد نمطًا مصادقًا صريحًا: AES/GCM/NoPadding مع IV عشوائي.":
        "Specify an explicit authenticated mode: AES/GCM/NoPadding with a random IV.",
    "ولّد IV عشوائيًا لكل عملية تشفير (SecureRandom/crypto/rand) وخزّنه مع النص المشفّر.":
        "Generate a random IV for every encryption (SecureRandom / crypto/rand) and store it with the ciphertext.",
    "ولّد ملحًا عشوائيًا لكل كلمة مرور (16 بايت على الأقل) وخزّنه مع الناتج.":
        "Generate a random salt (at least 16 bytes) for every password and store it with the result.",

    # ------------------------------------------------------------------ VQL queries
    "اضبط secure: true وhttpOnly: true وsameSite للكوكيز.":
        "Set secure: true, httpOnly: true and sameSite on cookies.",
    "حمّل known_hosts واستخدم RejectPolicy؛ قبول أي مفتاح مضيف يسمح بهجوم الوسيط.":
        "Load known_hosts and use RejectPolicy; accepting any host key allows man-in-the-middle attacks.",
    "استخدم ssl.create_default_context().wrap_socket(sock, server_hostname=host)؛ ssl.wrap_socket لا يتحقق من الشهادة "
    "افتراضيًا وأُزيل في Python 3.12.":
        "Use ssl.create_default_context().wrap_socket(sock, server_hostname=host); ssl.wrap_socket does not verify "
        "certificates by default and was removed in Python 3.12.",
    'مرّر filter="data" (Python 3.12+) أو تحقق من مسار كل عنصر قبل الفك؛ قد تحوي الأرشيفات مسارات ../ أو روابط رمزية.':
        'Pass filter="data" (Python 3.12+) or check every member\'s path before extracting; archives can contain ../ '
        "paths or symbolic links.",
}

PATTERNS: list[tuple[str, str]] = []
