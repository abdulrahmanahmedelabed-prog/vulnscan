"""English catalog: vulnscan/web.py: web-scan titles, snippets and advice."""

CATALOG: dict[str, str] = {
    # ---------------------------------------------------------------- EXPECTED_HEADERS (title_ar, advice)
    "ترويسة HSTS مفقودة": "Missing Strict-Transport-Security",
    "أضف Strict-Transport-Security: max-age=31536000; includeSubDomains.":
        "Add Strict-Transport-Security: max-age=31536000; includeSubDomains.",
    "ترويسة CSP مفقودة": "Missing Content-Security-Policy",
    "أضف سياسة CSP تقيّد مصادر السكربتات.":
        "Add a Content-Security-Policy that restricts script sources.",
    "ترويسة X-Content-Type-Options مفقودة": "Missing X-Content-Type-Options",
    "أضف X-Content-Type-Options: nosniff.": "Add X-Content-Type-Options: nosniff.",
    "لا حماية من Clickjacking": "Missing X-Frame-Options / frame-ancestors",
    "أضف X-Frame-Options: DENY أو frame-ancestors في CSP.":
        "Add X-Frame-Options: DENY, or a frame-ancestors directive in the CSP.",
    "ترويسة Referrer-Policy مفقودة": "Missing Referrer-Policy",
    "أضف Referrer-Policy: strict-origin-when-cross-origin.":
        "Add Referrer-Policy: strict-origin-when-cross-origin.",
    "ترويسة Permissions-Policy مفقودة": "Missing Permissions-Policy",
    "قيّد الصلاحيات الحساسة (الكاميرا، الموقع…) بترويسة Permissions-Policy.":
        "Restrict sensitive browser features (camera, geolocation, ...) with a Permissions-Policy header.",

    # ---------------------------------------------------------------- EXPOSED_PATHS (title_ar, advice)
    "مستودع .git مكشوف": "Exposed .git repository",
    "امنع الوصول إلى مجلد .git من خادم الويب؛ المصدر الكامل قد يكون قابلًا للتنزيل.":
        "Block access to the .git directory on the web server; the full source code may be downloadable.",
    "ملف .env مكشوف": "Exposed .env file",
    "أزل .env من جذر الويب فورًا وأبطل أي أسرار فيه.":
        "Remove .env from the web root immediately and revoke any secrets it contains.",
    "بيانات .svn مكشوفة": "Exposed .svn metadata",
    "امنع الوصول إلى .svn من خادم الويب.": "Block access to .svn on the web server.",
    # the same Arabic as the 1.1.0 rule registry (cat_web2): one English for both (this module is read first)
    "ملف .DS_Store مكشوف": "Exposed .DS_Store file",
    "احذف .DS_Store من النشر؛ قد يكشف أسماء الملفات.":
        "Remove .DS_Store from the deployment; it can disclose file names.",
    "صفحة server-status مكشوفة": "Apache server-status exposed",
    "قيّد mod_status على localhost فقط.": "Restrict mod_status to localhost only.",
    "صفحة phpinfo مكشوفة": "phpinfo() exposed",
    "احذف ملفات phpinfo من الإنتاج؛ تكشف إعدادات الخادم.":
        "Remove phpinfo files from production; they disclose server configuration.",
    "لا يوجد security.txt": "No security.txt",
    "أضف /.well-known/security.txt لتسهيل الإبلاغ عن الثغرات (غيابه ليس ثغرة).":
        "Add /.well-known/security.txt to make vulnerability reporting easier (its absence is not a vulnerability).",
    "robots.txt يكشف مسارات حساسة": "robots.txt reveals sensitive paths",
    "لا تضع مسارات إدارية حساسة في robots.txt؛ فهو عام.":
        "Do not list sensitive administrative paths in robots.txt; the file is public.",
    "نسخة احتياطية من .env مكشوفة": "Exposed .env backup",
    "احذف ملفات النسخ الاحتياطي من جذر الويب وأبطل أي أسرار.":
        "Remove backup files from the web root and revoke any secrets they contain.",
    "نسخة احتياطية لقاعدة البيانات مكشوفة": "Exposed database backup",
    "أزل ملفات .sql من جذر الويب؛ قد تحوي بيانات حساسة.":
        "Remove .sql files from the web root; they may contain sensitive data.",
    "ملف .git/config مكشوف": "Exposed .git/config",
    "امنع الوصول إلى مجلد .git من خادم الويب.": "Block access to the .git directory on the web server.",
    "نسخة احتياطية من wp-config مكشوفة": "Exposed wp-config backup",
    "احذف النسخ الاحتياطية وأبطل بيانات قاعدة البيانات.":
        "Remove the backup files and rotate the database credentials.",
    "ملف .htaccess مكشوف": "Exposed .htaccess file",
    "امنع تقديم ملفات .htaccess من خادم الويب.": "Configure the web server to never serve .htaccess files.",
    "نسخة احتياطية من config.php مكشوفة": "Exposed PHP config backup",
    "احذف النسخ الاحتياطية من جذر الويب.": "Remove backup files from the web root.",
    "بيانات اعتماد AWS مكشوفة": "Exposed AWS credentials",
    "أبطل المفاتيح فورًا وأزل الملف من جذر الويب.":
        "Revoke the keys immediately and remove the file from the web root.",
    "نقطة Spring actuator/env مكشوفة": "Spring Boot actuator env exposed",
    "قيّد نقاط actuator الحساسة أو عطّلها في الإنتاج.":
        "Restrict or disable sensitive actuator endpoints in production.",
    "واجهة توثيق API (Swagger) مكشوفة": "API docs (Swagger UI) exposed",
    "قيّد الوصول إلى توثيق API في الإنتاج إن لم يكن عامًا بقصد.":
        "Restrict access to the API documentation in production unless it is intentionally public.",

    # ---------------------------------------------------------------- scan_url
    "الموقع يُقدَّم عبر HTTP غير مشفّر": "Site served over plain HTTP",
    "فعّل HTTPS وأعد توجيه HTTP إليه.": "Enable HTTPS and redirect all HTTP traffic to it.",
    "ترويسة Server تكشف الإصدار": "Server header reveals version",
    "أخفِ رقم الإصدار من ترويسة Server.": "Remove the version number from the Server header.",
    "ترويسة X-Powered-By تكشف التقنية": "X-Powered-By reveals the stack",
    "احذف ترويسة X-Powered-By.": "Remove the X-Powered-By header.",
    "كوكي بدون علامة Secure": "Cookie without Secure flag",
    "أضف Secure لكل الكوكيز.": "Set the Secure attribute on all cookies.",
    "كوكي بدون علامة HttpOnly": "Cookie without HttpOnly flag",
    "أضف HttpOnly للكوكيز التي لا يحتاجها JavaScript.":
        "Set the HttpOnly attribute on cookies that JavaScript does not need to read.",
    "كوكي بدون SameSite": "Cookie without SameSite",
    "أضف SameSite=Lax أو Strict.": "Set SameSite=Lax or SameSite=Strict.",

    # ---------------------------------------------------------------- _csp_weaknesses
    "CSP يسمح بسكربتات inline": "CSP allows 'unsafe-inline' scripts",
    "أزل 'unsafe-inline' واستخدم nonce أو hash.": "Remove 'unsafe-inline' and use a nonce or hash instead.",
    "CSP يسمح بـ unsafe-eval": "CSP allows 'unsafe-eval'",
    "أزل 'unsafe-eval'.": "Remove 'unsafe-eval'.",
    "CSP يسمح بأي مصدر للسكربتات": "CSP script source uses wildcard *",
    "حدّد النطاقات المسموحة بدل *.": "Allowlist specific domains instead of *.",
    "CSP بلا object-src": "CSP missing object-src 'none'",
    "أضف object-src 'none' لمنع الإضافات القديمة.": "Add object-src 'none' to block legacy plugins.",

    # ---------------------------------------------------------------- _analyze_html
    "محتوى مختلط: مورد عبر HTTP في صفحة HTTPS": "Mixed content: insecure resource on HTTPS page",
    "حمّل كل الموارد عبر https://.": "Load all resources over https://.",
    "نموذج يُرسل عبر HTTP": "Form submits over plain HTTP",
    "اجعل action للنموذج https://.": "Make the form's action an https:// URL.",
    "حقل كلمة مرور في صفحة غير HTTPS": "Password field on non-HTTPS page",
    "قدّم صفحات تسجيل الدخول عبر HTTPS فقط.": "Serve login pages over HTTPS only.",
    "سكربت خارجي بلا تحقق سلامة (SRI)": "External script without Subresource Integrity",
    "أضف السمة integrity (SRI) للسكربتات الخارجية.":
        "Add an integrity attribute (Subresource Integrity) to external scripts.",
    "عرض فهرس المجلدات مفعّل": "Directory listing enabled",
    "عطّل autoindex/directory listing على الخادم.": "Disable autoindex / directory listing on the server.",
    "أثر استثناء أو تصحيح في الاستجابة": "Stack trace / debug output in response",
    "عطّل عرض الأخطاء التفصيلية في الإنتاج.": "Disable detailed error output in production.",

    # ---------------------------------------------------------------- _LIBS advice
    "حدّث jQuery إلى 3.5 أو أحدث (إصدارات أقدم بها XSS معروفة: CVE-2020-11022/11023 وأقدم).":
        "Upgrade jQuery to 3.5 or later (older versions have known XSS: CVE-2020-11022/11023 and earlier).",
    "حدّث jQuery UI إلى 1.13.2 أو أحدث (XSS في إصدارات أقدم).":
        "Upgrade jQuery UI to 1.13.2 or later (older versions are vulnerable to XSS).",
    "AngularJS 1.x انتهى دعمه ولا يتلقى تصحيحات أمان؛ انتقل إلى إطار مدعوم.":
        "AngularJS 1.x is end-of-life and receives no security fixes; migrate to a supported framework.",
    "حدّث Bootstrap (XSS في tooltip/popover قبل 3.4.1 و4.3.1: CVE-2019-8331).":
        "Upgrade Bootstrap (XSS in tooltip/popover before 3.4.1 and 4.3.1: CVE-2019-8331).",
    "حدّث Lodash إلى 4.17.21 (تلويث prototype في إصدارات أقدم).":
        "Upgrade Lodash to 4.17.21 (prototype pollution in older versions).",
    "حدّث Moment.js إلى 2.29.4 (ReDoS/path traversal في إصدارات أقدم).":
        "Upgrade Moment.js to 2.29.4 (ReDoS / path traversal in older versions).",
    "حدّث Handlebars إلى 4.7.7 (تلويث prototype وتنفيذ قوالب: CVE-2019-20920).":
        "Upgrade Handlebars to 4.7.7 (prototype pollution and template code execution: CVE-2019-20920).",
    "حدّث DOMPurify إلى 2.4.0 أو أحدث (تجاوزات تعقيم معروفة في إصدارات أقدم).":
        "Upgrade DOMPurify to 2.4.0 or later (older versions have known sanitizer bypasses).",

    # ---------------------------------------------------------------- detect_platform (static advice)
    "امنع الوصول إلى هذا الملف من خادم الويب.": "Block access to this file on the web server.",
    "قيّد الوصول إلى لوحات الإدارة (شبكة داخلية أو مصادقة قوية وحدّ للمحاولات).":
        "Restrict access to admin panels (internal network only, or strong authentication with rate limiting).",

    # ---------------------------------------------------------------- _tls_checks
    "شهادة TLS منتهية": "TLS certificate expired",
    "جدّد شهادة TLS فورًا.": "Renew the TLS certificate immediately.",
    "جدّد الشهادة قبل انتهائها (ويفضَّل التجديد الآلي).":
        "Renew the certificate before it expires (automated renewal is recommended).",
    "شهادة TLS لا تجتاز التحقق": "TLS certificate does not validate",
    "استخدم شهادة موثوقة مطابقة للنطاق (مثل Let's Encrypt).":
        "Use a trusted certificate that matches the domain (for example, Let's Encrypt).",
    "عطّل TLS 1.0/1.1 واقبل TLS 1.2+ فقط.": "Disable TLS 1.0/1.1 and accept only TLS 1.2 and later.",
}

# ---------------------------------------------------------------- explain_failure (vulnscan/web.py)
# Why a site could not be scanned: sentence key → (English, Arabic). vulnscan/web.py composes a message from these
# sentences (FAILURE_COMBOS lists every sequence it can emit) and the patterns below are generated from the same table,
# so the English of an Arabic message saved by the UI or printed by the engine is exactly the English web.py builds.
# Placeholders: {host} {url} {proxy} {port} {err} are left-to-right isolates (U+2066 … U+2069) in the Arabic text;
# {t1} {t2} are durations ("20 ثانيةً" / "20 s", vulnscan.i18n.plural.SECONDS); {n} {status} are numbers.
LRI, PDI, LRM = "\u2066", "\u2069", "\u200e"
FAILURE: dict[str, tuple[str, str]] = {
    "wrap": ("The site was not scanned: {why} (details: {err})", "لم يُفحص الموقع — {why} (التفاصيل: {err})"),
    "timeout": ("The connection to {host} timed out: no answer within {t1}, then {t2} on the retry.",
                "انتهت مهلة الاتصال بـ{host}: لا ردّ خلال {t1}، ثم خلال {t2} في المحاولة الثانية."),
    "timeout_cause": ("The site may be slow or down, or it may block requests from your network or from outside its "
                      "country (firewall or geo-blocking).",
                      "قد يكون الموقع بطيئًا أو متوقفًا، أو يحجب الطلبات القادمة من شبكتك أو من خارج بلده "
                      "(جدار حماية أو حجب جغرافي)."),
    "timeout_try": ("Try opening it in a browser on this machine, or from another network (mobile data).",
                    "جرّب فتحه في متصفح على هذا الجهاز، أو من شبكة أخرى (بيانات الجوال)."),
    "timeout_cli": ("If it is only slow, scan again with a longer timeout: --timeout {n}.",
                    f"وإن كان بطيئًا فحسب فأعد الفحص بمهلة أطول: {LRI}--timeout {{n}}{PDI}."),
    "timeout_ui": ("If it is only slow, increase the timeout in Settings.",
                   "وإن كان بطيئًا فحسب فزِد المهلة من الإعدادات."),
    "deadline": ("{host} kept the response open past the response deadline ({t1}), so the page could not be read.",
                 "أبقى {host} الاستجابة مفتوحة بعد انقضاء مهلة الاستجابة ({t1})، فتعذّرت قراءة الصفحة."),
    "alt_url": ("You can also try {url}.", "ويمكنك أيضًا تجربة {url}."),
    "alt_port": ("Check that the service on port {port} is running.", "تحقّق من أن الخدمة على المنفذ {port} تعمل."),
    "dns": ("Could not resolve the domain name {host}: check the address for typos, your internet connection and "
            "your DNS settings.",
            "تعذّر حلّ اسم النطاق {host}: تحقّق من كتابة العنوان ومن اتصال الإنترنت وإعدادات DNS."),
    "dns_https_proxy": ("Only an HTTPS proxy is set (HTTPS_PROXY), with no HTTP proxy (HTTP_PROXY), so this machine "
                        "resolved the name of this http:// address itself; if your network resolves names only "
                        "through the proxy, set HTTP_PROXY as well, or scan {url}.",
                        f"عُرِّف وكيل HTTPS وحده ({LRI}HTTPS_PROXY{PDI}) بلا وكيل HTTP ({LRI}HTTP_PROXY{PDI})، "
                        f"فحلَّ هذا الجهاز اسم العنوان {LRI}http://{PDI} بنفسه؛ فإن كانت شبكتك لا تحلّ الأسماء إلا "
                        f"عبر الوكيل فعرِّف {LRI}HTTP_PROXY{PDI} أيضًا، أو افحص {{url}}."),
    "refused": ("The server {host} refused the connection: the port is closed or the service is down.",
                "رفض الخادم {host} الاتصال: المنفذ مغلق أو الخدمة متوقفة."),
    "route": ("No network route to {host}: the network or the server is not reachable from this machine right now.",
              "لا يوجد مسار شبكي إلى {host}: الشبكة أو الخادم غير قابلين للوصول من جهازك الآن."),
    "tls": ("Could not establish a secure TLS connection with {host} (invalid certificate or misconfigured TLS). "
            "This is itself a security issue worth reviewing.",
            "فشل إنشاء اتصال TLS آمن مع {host} (شهادة غير صالحة أو إعداد TLS خاطئ). وهذا في حدّ ذاته مشكلة أمنية "
            "تستحق المراجعة."),
    "waf": ("The server {host} dropped the connection during the request: a web application firewall (WAF) may be "
            "blocking it.",
            "قطع الخادم {host} الاتصال أثناء الطلب: قد يكون جدار حماية تطبيقات الويب (WAF) يحجب الطلب."),
    "reset_proxy": ("The connection through the proxy {proxy} was closed during the request to {host}: the proxy or "
                    "the site closed it, and Kashif cannot tell which.",
                    "أُغلق الاتصال عبر الوكيل {proxy} أثناء الطلب إلى {host}: أغلقه الوكيل أو الموقع، ولا يستطيع "
                    "كاشِف معرفة أيهما."),
    "proxy_reset_tls": ("The connection through the proxy {proxy} was closed while the TLS handshake with {host} was "
                        "being set up: the proxy or the site closed it, and Kashif cannot tell which.",
                        "أُغلق الاتصال عبر الوكيل {proxy} أثناء إعداد مصافحة TLS مع {host}: أغلقه الوكيل أو الموقع، "
                        "ولا يستطيع كاشِف معرفة أيهما."),
    "proxy_reset": ("The proxy {proxy} closed the connection before the request to {host} was sent.",
                    "أغلق الوكيل {proxy} الاتصال قبل إرسال الطلب إلى {host}."),
    "proxy_unreachable": ("Could not connect to the proxy {proxy} (from HTTP_PROXY/HTTPS_PROXY).",
                          f"تعذّر الاتصال بالوكيل {{proxy}} (المعرَّف في {LRI}HTTP_PROXY/HTTPS_PROXY{PDI})."),
    "proxy_refused": ("The proxy {proxy} refused to connect to {host} (HTTP {status}), so Kashif did not reach the site.",
                      f"رفض الوكيل {{proxy}} الاتصال بـ{{host}} ({LRI}HTTP {{status}}{PDI})، فلم يصل كاشِف إلى الموقع."),
    "proxy_refused_any": ("The proxy {proxy} refused to connect to {host}, so Kashif did not reach the site.",
                          "رفض الوكيل {proxy} الاتصال بـ{host}، فلم يصل كاشِف إلى الموقع."),
    "via_proxy": ("The request went through the proxy {proxy}.", "مرّ الطلب عبر الوكيل {proxy}."),
    "proxy_fix_cli": ("Check the proxy, or run with --no-proxy.",
                      f"تحقّق من الوكيل، أو شغّل الفحص بالخيار {LRM}--no-proxy."),
    "proxy_fix_ui": ("Check the proxy, or tick \u201cDo not use the system's proxy\u201d in the scan options.",
                     "تحقّق من الوكيل، أو فعّل خيار «لا تستخدم الوكيل (proxy) المعرَّف في النظام» في خيارات الفحص."),
    "unsupported": ("Only http:// and https:// URLs can be scanned (got {url}).",
                    f"لا يمكن فحص إلا عناوين {LRI}http://{PDI} و{LRI}https://{PDI} (العنوان المُعطى: {{url}})."),
    "invalid": ("The address is not a valid URL: {url}.", "العنوان ليس رابطًا صالحًا: {url}."),
    "unreadable": ("{host} answered, but its response could not be read as HTTP.",
                   "أجاب {host}، لكن تعذّرت قراءة استجابته بوصفها HTTP."),
    "other": ("Could not reach {host}.", "تعذّر الوصول إلى {host}."),
}


def _failure_combos() -> tuple[tuple[str, ...], ...]:
    """Every sentence sequence ``web.explain_failure`` can emit as the {why} of "wrap"."""
    out: list[tuple[str, ...]] = []
    for more in ("cli", "ui"):
        fix = f"proxy_fix_{more}"
        for alt in (("alt_url",), ("alt_port",), ()):
            out.append(("timeout", "timeout_cause", "timeout_try", *alt, f"timeout_{more}"))
        out.append(("timeout", "via_proxy", fix, f"timeout_{more}"))
        out += [(k, fix) for k in ("reset_proxy", "proxy_reset_tls", "proxy_reset", "proxy_unreachable",
                                   "proxy_refused", "proxy_refused_any")]
    out += [("deadline",), ("dns",), ("dns", "dns_https_proxy"), ("refused", "alt_url"), ("refused", "alt_port"),
            ("refused",), ("route",), ("tls",), ("waf",), ("unsupported",), ("invalid",), ("unreadable",), ("other",)]
    return tuple(dict.fromkeys(out))


FAILURE_COMBOS = _failure_combos()
_SECS_AR = r"(?:ثانية واحدة|ثانيتين|\d+(?:\.\d+)? (?:ثوانٍ|ثانيةً|ثانية))"
_SLOT = {"host": f"{LRI}(?P<host>[^{PDI}]*){PDI}", "url": f"{LRI}(?P<url>[^{PDI}]*){PDI}",
         "proxy": f"{LRI}(?P<proxy>[^{PDI}]*){PDI}", "port": f"{LRI}(?P<port>[^{PDI}]*){PDI}",
         "t1": f"(?P<t1>{_SECS_AR})", "t2": f"(?P<t2>{_SECS_AR})", "n": r"(?P<n>\d+(?:\.\d+)?)",
         "status": r"(?P<status>\d{3})"}


def failure_pattern(ar: str, en: str) -> tuple[str, str]:
    """(regular expression of the Arabic sentence(s), English replacement) for a FAILURE template."""
    import re
    rx, last = [], 0
    for m in re.finditer(r"\{(\w+)\}", ar):
        rx.append(re.escape(ar[last:m.start()]))
        rx.append(_SLOT[m.group(1)])
        last = m.end()
    rx.append(re.escape(ar[last:]))
    return "".join(rx), re.sub(r"\{(\w+)\}", lambda m: f"\\g<{m.group(1)}>", en)


def _failure_patterns() -> list[tuple[str, str]]:
    out = [(f"لم يُفحص الموقع — (?P<why>.+) \\(التفاصيل: (?:{LRI}(?P<err>.*){PDI})?\\)",
            r"The site was not scanned: \g<why> (details: \g<err>)")]
    for combo in FAILURE_COMBOS:
        out.append(failure_pattern(" ".join(FAILURE[k][1] for k in combo), " ".join(FAILURE[k][0] for k in combo)))
    # durations inside the sentences ({t1}, {t2}): the forms of vulnscan.i18n.plural.SECONDS
    out.append((r"(?P<n>\d+(?:\.\d+)?) (?:ثوانٍ|ثانيةً|ثانية)", r"\g<n> s"))
    return out


CATALOG.update({"ثانية واحدة": "1 s", "ثانيتين": "2 s"})

PATTERNS: list[tuple[str, str]] = _failure_patterns() + [
    # ---------------------------------------------------------------- explain_failure of 1.0.1 / 1.1.0 betas
    # (messages saved in the local scan history before the sentences above)
    (r"لم يُفحص الموقع — (?P<why>.+) \(التفاصيل: (?P<err>.*)\)",
     r"The site was not scanned: \g<why> (details: \g<err>)"),
    (r"انتهت مهلة الاتصال بـ (?P<host>\S+) بعد (?P<secs>\d+) ثانية في محاولتين\. الموقع لم يرد: قد يكون بطيئًا أو متوقفًا، "
     r"أو يحجب الطلبات القادمة من شبكتك أو من خارج بلده \(جدار حماية / حجب جغرافي\)\. "
     r"جرّب: فتح الموقع من المتصفح على الجهاز نفسه، أو من شبكة أخرى \(بيانات الجوال\)، أو (?P<alt>\S+)، "
     r"أو زد المهلة من الإعدادات\.",
     r"The connection to \g<host> timed out after \g<secs> seconds on two attempts. The site did not respond: "
     r"it may be slow or down, or it may block requests from your network or from outside its country "
     r"(firewall / geo-blocking). Try opening the site in a browser on this same machine, from another network "
     r"(mobile data), or at \g<alt>, or increase the timeout in Settings."),
    (r"تعذّر حلّ اسم النطاق (?P<host>\S+): تحقق من كتابة العنوان ومن اتصال الإنترنت أو إعدادات DNS\.",
     r"Could not resolve the domain name \g<host>: check the address for typos, your internet connection "
     r"and your DNS settings."),
    (r"رفض الخادم (?P<host>\S+) الاتصال: المنفذ مغلق أو الخدمة متوقفة\. جرّب (?P<alt>\S+)\.",
     r"The server \g<host> refused the connection: the port is closed or the service is down. Try \g<alt>."),
    (r"لا يوجد مسار شبكي إلى (?P<host>\S+): الشبكة أو الخادم غير قابلين للوصول من جهازك الآن\.",
     r"No network route to \g<host>: the network or the server is not reachable from this machine right now."),
    (r"فشل إنشاء اتصال TLS آمن مع (?P<host>\S+) \(شهادة غير صالحة أو إعداد TLS خاطئ\)\. "
     r"هذا بحد ذاته مشكلة أمنية تستحق المراجعة\.",
     r"Could not establish a secure TLS connection with \g<host> (invalid certificate or misconfigured TLS). "
     r"This is itself a security issue worth reviewing."),
    (r"قطع الخادم (?P<host>\S+) الاتصال أثناء الطلب: قد يكون جدار حماية تطبيقات الويب \(WAF\) يحجب الطلب\.",
     r"The server \g<host> dropped the connection during the request: a web application firewall (WAF) "
     r"may be blocking it."),
    (r"تعذّر الوصول إلى (?P<host>\S+)\.", r"Could not reach \g<host>."),

    # ---------------------------------------------------------------- scan_site crawl note
    (r"تعذّر جلب 1 صفحة أثناء الزحف فلم تُفحص: (?P<pages>.+)",
     r"Could not fetch 1 page during the crawl, so it was not scanned: \g<pages>"),
    (r"تعذّر جلب (?P<n>\d+) صفحة أثناء الزحف فلم تُفحص: (?P<pages>.+)",
     r"Could not fetch \g<n> pages during the crawl, so they were not scanned: \g<pages>"),
    # the page list itself is joined with an Arabic comma; recurse one path at a time
    (r"(?P<first>/[^\s،]*)، (?P<rest>/.*)", r"\g<first>, \g<rest>"),

    # ---------------------------------------------------------------- dynamic titles / advice
    (r"مكتبة (?P<name>.+?) قديمة (?P<ver>[0-9][0-9.]*) \(ثغرات معروفة\)",
     r"Outdated \g<name> \g<ver> (known vulnerabilities)"),
    (r"منصّة مكتشفة: (?P<shown>.+)", r"Detected platform: \g<shown>"),
    (r"تأكد أن (?P<name>.+?) محدّث لآخر إصدار مُصحَّح، وأن إضافاته وقوالبه محدّثة\.",
     r"Make sure \g<name> is updated to the latest patched release, and that its plugins and themes are up to date."),
    (r"إصدار (?P<name>.+?) قديم \((?P<ver>[^)]*)\)", r"Outdated \g<name> (\g<ver>)"),
    (r"حدّث (?P<name>.+?)؛ الإصدارات القديمة بها ثغرات معروفة\.",
     r"Upgrade \g<name>; older versions have known vulnerabilities."),
    (r"(?P<name>.+?): ملف حساس مكشوف (?P<path>\S+)", r"\g<name>: sensitive file exposed \g<path>"),
    (r"(?P<name>.+?): صفحة إدارة أو دخول متاحة (?P<path>\S+)", r"\g<name>: admin/login page reachable \g<path>"),
    (r"شهادة TLS تنتهي خلال 1 يومًا", r"TLS certificate expires in 1 day"),
    (r"شهادة TLS تنتهي خلال (?P<days>\d+) يومًا", r"TLS certificate expires in \g<days> days"),
    (r"الخادم يقبل (?P<proto>TLS [0-9.]+) القديم", r"Server accepts obsolete \g<proto>"),
]
