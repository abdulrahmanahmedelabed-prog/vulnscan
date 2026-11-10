"""English catalog: in-app update (vulnscan/updater.py, UI and CLI update messages)."""

CATALOG: dict[str, str] = {
    # updater.MESSAGES (error and status codes)
    "تعذّر الاتصال بـ GitHub. تحقّق من اتصالك بالإنترنت أو من إعدادات الوكيل (HTTPS_PROXY) ثم أعد المحاولة.":
        "Could not reach GitHub. Check your internet connection or proxy settings (HTTPS_PROXY) and try again.",
    "بلغت حدّ طلبات GitHub المسموح به مؤقتًا. أعد المحاولة بعد قليل.":
        "GitHub's request limit was reached for now. Try again in a little while.",
    "ردّ GitHub غير متوقع. أعد المحاولة لاحقًا.": "GitHub sent an unexpected response. Try again later.",
    "لا يوجد إصدار منشور بعد.": "No release has been published yet.",
    "التحديث من داخل البرنامج متاح للنسخة التنفيذية فقط. استخدم الأمر المعروض للتحديث.":
        "In-app updates are available for the standalone binary only. Use the command shown to update.",
    "لا توجد نسخة تنفيذية جاهزة لهذا النظام أو المعالج. نزّل الإصدار يدويًا من صفحة الإصدارات.":
        "There is no prebuilt binary for this operating system or CPU. Download the release manually from the releases page.",
    "لا يمكن الكتابة في مجلد البرنامج. شغّل التحديث بصلاحيات المسؤول أو نزّل الإصدار يدويًا.":
        "The program's folder is not writable. Run the update with administrator rights or download the release manually.",
    "أنت تستخدم أحدث إصدار.": "You are using the latest version.",
    "الإصدار المنشور ليس أحدث من إصدارك؛ لا يُثبَّت إصدار أقدم أو مماثل.":
        "The published release is not newer than yours; an older or identical version is never installed.",
    "الإصدار المنشور لا يحتوي على ملف هذا النظام.": "The published release has no file for this system.",
    "ملف SHA256SUMS.txt لا يحتوي على بصمة هذا الملف؛ أُلغي التحديث حفاظًا على سلامتك.":
        "SHA256SUMS.txt has no checksum for this file, so the update was cancelled for your safety.",
    "بصمة SHA-256 للملف المنزَّل لا تطابق البصمة المنشورة؛ أُلغي التحديث ولم يتغيّر شيء.":
        "The downloaded file's SHA-256 checksum does not match the published one. The update was cancelled and nothing changed.",
    "الملف المنزَّل أكبر من الحد المسموح؛ أُلغي التحديث.": "The download is larger than allowed, so the update was cancelled.",
    "رُفض التنزيل: العنوان ليس من خوادم GitHub الموثوقة.": "Download refused: the address is not one of GitHub's trusted servers.",
    "الملف المنزَّل ليس برنامجًا تنفيذيًا صالحًا لهذا النظام؛ أُلغي التحديث.":
        "The downloaded file is not a valid executable for this system, so the update was cancelled.",
    "النسخة الجديدة لم تُبلغ عن الإصدار المتوقع عند تجربتها؛ أُلغي التحديث.":
        "The new binary did not report the expected version when tested, so the update was cancelled.",
    "تعذّر استبدال البرنامج؛ أُعيدت النسخة السابقة كما كانت.":
        "The program could not be replaced; the previous version was restored as it was.",
    "انقطع التنزيل أو فشل؛ لم يتغيّر شيء. أعد المحاولة.": "The download failed or was interrupted; nothing changed. Try again.",
    "يوجد تحديث جارٍ بالفعل.": "An update is already in progress.",
    "لا يوجد تحديث مكتمل لإعادة التشغيل.": "There is no completed update to restart into.",
    "اكتمل التحديث بالفعل؛ أعد تشغيل كاشِف لاستخدام الإصدار الجديد.":
        "The update is already installed. Restart Kashif to use the new version.",
    # updater.CLI_TEXT (vulnscan update)
    "التحقق من وجود إصدار أحدث من كاشِف وتثبيته (للنسخة التنفيذية).":
        "Check for a newer version of Kashif and install it (standalone binary).",
    "ثبّت دون سؤال للتأكيد": "Install without asking for confirmation",
    "تحقّق فقط واعرض الحالة (رمز الخروج 10 عند توفّر تحديث)": "Only check and print the status (exit code 10 when an update is available)",
    "الإصدار الحالي:": "Current version:",
    "أحدث إصدار:": "Latest version:",
    "يتوفر إصدار أحدث.": "A newer version is available.",
    "ملاحظات الإصدار:": "Release notes:",
    "للتحديث شغّل:": "To update, run:",
    "أو نزّله من:": "Or download it from:",
    "تنزيل الإصدار الجديد وتثبيته الآن؟ [y/N]": "Download and install the new version now? [y/N]",
    "أُلغي التحديث.": "Update cancelled.",
    "لا توجد طرفية للتأكيد؛ أعد التشغيل مع --yes للتثبيت.": "No terminal to confirm in; run again with --yes to install.",
    "جارٍ التنزيل…": "Downloading…",
    "جارٍ التحقق من بصمة SHA-256 ومن البرنامج الجديد…": "Verifying the SHA-256 checksum and the new binary…",
    "جارٍ استبدال البرنامج…": "Replacing the program…",
    "تم التحديث بنجاح. أعد تشغيل كاشِف لاستخدام الإصدار الجديد:": "Updated successfully. Restart Kashif to use the new version:",
    "النسخة السابقة محفوظة مؤقتًا في:": "The previous version is kept for now at:",
}

PATTERNS: list[tuple[str, str]] = []
