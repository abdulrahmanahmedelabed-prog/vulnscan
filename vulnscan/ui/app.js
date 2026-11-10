/* Kashif (vulnscan) local UI — vanilla JS, no build step, no dependencies. */
'use strict';
const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const I18N = {
  ar: {
    brand: 'كاشِف',
    sev: {critical: 'حرج', high: 'عالٍ', medium: 'متوسط', low: 'منخفض', info: 'معلوماتي'},
    status: {running: 'جارٍ', done: 'مكتمل', error: 'خطأ'},
    theme: {auto: 'المظهر: تلقائي', light: 'المظهر: فاتح', dark: 'المظهر: داكن'},
    src: {vulnscan: 'قواعد الأنماط', taint: 'محرك تدفق البيانات', vql: 'استعلامات VQL', web: 'فحص الويب', apex: 'محلل Apex', osv: 'OSV (الاعتماديات)', npm: 'npm audit'},
    'a11y.skip': 'انتقل إلى المحتوى', 'a11y.nav': 'التنقل الرئيسي', 'a11y.sevFilter': 'تصفية حسب الخطورة',
    err: {'authorization required': 'يجب تأكيد أنك مخوّل بفحص هذا الموقع قبل البدء.', 'target required': 'أدخل مسارًا أو عنوانًا للفحص.', 'bad upload': 'تعذّر قبول الملف المرفوع (الحجم كبير جدًا أو الطلب غير صالح).', 'file required': 'اختر ملفًا واحدًا على الأقل.', forbidden: 'رُفض الطلب: يجب أن يصدر من هذه الواجهة نفسها.', 'not found': 'العنصر غير موجود (ربما حُذف).'},
    'nav.dashboard': 'لوحة التحكم', 'nav.scan': 'فحص جديد', 'nav.findings': 'النتائج', 'nav.reports': 'التقارير', 'nav.rules': 'القواعد', 'nav.settings': 'الإعدادات',
    'dash.title': 'لوحة التحكم', 'dash.sub': 'نظرة عامة على آخر فحص والاتجاه العام.', 'dash.empty': 'لا توجد فحوصات بعد', 'dash.emptyHint': 'ابدأ بفحص مجلد مشروع أو ارفع ملفًا مضغوطًا.',
    'dash.donut': 'توزيع الخطورة (آخر فحص)', 'dash.trend': 'اتجاه النتائج عبر الفحوصات الأخيرة', 'dash.topRules': 'أكثر الثغرات تكرارًا', 'dash.topFiles': 'أكثر الملفات تأثرًا', 'dash.recent': 'الفحوصات الأخيرة',
    'dash.allScans': 'كل الفحوصات', 'dash.latest': 'آخر فحص', 'dash.findingsCap': 'نتيجة', 'dash.oneScan': 'فحص واحد حتى الآن. أجرِ فحوصات أخرى لترى الاتجاه عبر الزمن.', 'dash.total': 'نتيجة إجمالًا',
    'scan.title': 'فحص جديد', 'scan.sub': 'افحص مجلدًا على هذا الجهاز، أو ارفع برنامجًا مضغوطًا أو ملفات، أو افحص عنوان ويب تملكه.',
    'scan.tabPath': 'مسار على الجهاز', 'scan.tabUpload': 'رفع ملفات / أرشيف', 'scan.tabUrl': 'عنوان ويب', 'scan.pathLabel': 'مسار المجلد أو الملف أو الأرشيف', 'scan.start': 'ابدأ الفحص',
    'scan.pathHint': 'يُفحص المجلد بكل محتوياته (تُتجاهل node_modules و .git و build تلقائيًا).', 'scan.drop': 'اسحب وأفلت هنا برنامجًا مضغوطًا (zip / apk / jar / tar.gz / whl) أو أي ملفات',
    'scan.chooseFiles': 'اختر ملفات', 'scan.chooseFolder': 'اختر مجلدًا كاملًا', 'scan.uploadStart': 'ارفع وافحص', 'scan.urlLabel': 'عنوان الموقع (فحص سلبي: طلب واحد فقط)',
    'scan.authorize': 'أقرّ بأنني مالك هذا الموقع أو لديّ تصريح كتابي بفحصه', 'scan.deep': 'فحص أعمق: تحليل الصفحة وفحص مسارات مكشوفة شائعة (طلبات إضافية محدودة)', 'scan.crawl': 'زحف على صفحات الموقع وفحصها (لتطبيقات مثل Moodle وبوابات الجامعات)', 'scan.legal': 'فحص أنظمة الآخرين دون إذن قد يكون مخالفًا للقانون.', 'scan.viewResults': 'عرض النتائج',
    'scan.running': 'جارٍ الفحص…', 'scan.done': 'اكتمل الفحص', 'scan.failed': 'فشل الفحص', 'scan.needAuth': 'يجب تأكيد الصلاحية أولًا', 'scan.selected': 'ملف محدد', 'scan.uploading': 'جارٍ الرفع…', 'scan.uploadFailed': 'تعذّر الرفع',
    'scan.jadxOn': 'jadx مثبّت: سيُفكّ تجميع APK/JAR/AAR/DEX ويُفحص الكود الناتج أيضًا.', 'scan.jadxOff': 'jadx غير مثبّت: تُفحص الملفات النصية داخل APK/JAR فقط. ثبّت jadx (يحتاج Java) لفك تجميع الكود.',
    'scan.uploaded': '{n} ملف مرفوع',
    'find.title': 'النتائج', 'find.sub': 'مرتبة من الأعلى خطورة إلى الأقل. اضغط على أي نتيجة لعرض التفاصيل وطريقة الإصلاح.', 'find.search': 'ابحث في الملف أو القاعدة أو النص…', 'find.allSources': 'كل المصادر',
    'find.none': 'لا نتائج مطابقة للمرشحات الحالية.', 'find.flow': 'مسار التدفق (من المصدر إلى نقطة الخطر)', 'find.files': 'ملفًا مفحوصًا', 'find.pages': 'صفحة مفحوصة', 'find.onPages': 'ظهرت في {n} صفحة',
    'find.advice': 'طريقة الإصلاح', 'find.snippet': 'المقتطف', 'find.ref': 'المرجع', 'find.scan': 'الفحص', 'find.export': 'تصدير',
    'find.dataflow': 'مُثبتة بتدفق البيانات', 'find.pattern': 'مطابقة نمط', 'find.location': 'الموقع', 'find.source': 'المصدر', 'find.sink': 'نقطة الخطر', 'find.step': 'خطوة',
    'find.fingerprint': 'البصمة', 'find.copy': 'نسخ', 'find.copied': 'تم النسخ', 'find.showing': 'عرض {n} من {total} نتيجة', 'find.cwe': 'افتح تعريف {cwe} على موقع MITRE', 'find.input': 'المدخل غير الموثوق', 'find.clear': 'إظهار الكل',
    'rep.title': 'التقارير', 'rep.sub': 'سجل كل الفحوصات، تنزيل التقارير، ومقارنة فحصين لمعرفة ما أُصلح وما استجد.', 'rep.compare': 'مقارنة فحصين', 'rep.compareBtn': 'قارن', 'rep.fixed': 'أُصلحت (اختفت)', 'rep.new': 'جديدة (ظهرت)',
    'rep.target': 'الهدف', 'rep.date': 'التاريخ', 'rep.status': 'الحالة', 'rep.total': 'الإجمالي', 'rep.actions': 'إجراءات', 'rep.delete': 'حذف', 'rep.view': 'عرض', 'rep.nothing': 'لا شيء',
    'rep.base': 'الفحص الأساسي', 'rep.head': 'الفحص الأحدث', 'rep.history': 'سجل الفحوصات', 'rep.download': 'تنزيل تقرير HTML', 'rep.confirmDel': 'حذف هذا الفحص؟', 'rep.noScans': 'لا توجد فحوصات بعد.',
    'rules.title': 'القواعد المدمجة', 'rules.search': 'ابحث في القواعد…', 'rules.count': 'قاعدة', 'rules.id': 'المعرّف', 'rules.sev': 'الخطورة', 'rules.name': 'الثغرة', 'rules.langs': 'الملفات', 'rules.advice': 'الإصلاح',
    'set.title': 'الإعدادات', 'set.sub': 'تُحفظ على هذا الجهاز وتُطبَّق على كل الفحوصات القادمة.', 'set.minSev': 'أدنى خطورة تُعرض', 'set.failOn': 'إفشال CI عند خطورة', 'set.exclude': 'مسارات مستثناة (سطر لكل نمط)',
    'set.ignore': 'قواعد متجاهَلة (معرّف لكل سطر)', 'set.authTargets': 'عناوين ويب مُصرَّح بفحصها (سطر لكل عنوان)', 'set.osv': 'الاستعلام من OSV.dev عن ثغرات الاعتماديات (يحتاج إنترنت)',
    'set.external': 'دمج نتائج الأدوات الخارجية المثبّتة', 'set.audit': 'ملف التدقيق: اعرض أيضًا كل استدعاء خطر لم يُثبت تحليل التدفق وصول مدخل إليه (أشمل، وإنذارات أكثر)', 'set.jadx': 'فك تجميع APK / JAR / AAR / DEX بواسطة jadx وفحص الكود الناتج', 'set.jadxLibs': 'فحص مكتبات الطرف الثالث داخل الكود المفكوك أيضًا (نتائج أكثر وضجيج أكثر)', 'set.jadxTimeout': 'مهلة jadx بالثواني', 'set.jadxOn': 'jadx مثبّت على هذا الجهاز.', 'set.jadxOff': 'jadx غير مثبّت — ثبّته من github.com/skylot/jadx ليُفكّ الكود الثنائي.',
    'set.models': 'مجلد نماذج إضافية لمحرّك تدفق البيانات (JSON: مصادر، نقاط خطر، مُعقّمات)', 'set.queries': 'مجلد استعلامات VQL إضافية (لغة استعلام تصريحية فوق قاعدة بيانات البرنامج)',
    'set.keep': 'عدد الفحوصات المحفوظة', 'set.webTimeout': 'مهلة طلب الويب بالثواني (يُعاد الطلب الأول مرة بمهلة مضاعفة)', 'set.webDelay': 'تأخير بين طلبات الزحف بالثواني (ألطف على الخادم وجدار الحماية)', 'set.save': 'حفظ', 'set.saved': 'تم الحفظ', 'set.home': 'مجلد البيانات', 'set.none': 'لا توجد أدوات مثبّتة',
    'set.secScope': 'النطاق والحدود', 'set.secScopeHint': 'ما يُعرض من النتائج ومتى يفشل التكامل المستمر.', 'set.secAnalysis': 'التحليل والتكاملات', 'set.secAnalysisHint': 'مصادر إضافية للنتائج ودرجة الشمول.',
    'set.secBinary': 'الملفات الثنائية (jadx)', 'set.secWeb': 'فحص الويب', 'set.secWebHint': 'فحص سلبي ولطيف للمواقع المصرّح بها فقط.', 'set.secStorage': 'التخزين',
    'upd.title': 'التحديثات', 'upd.hint': 'يتحقق كاشِف من إصدارات GitHub الرسمية. لا يُرسَل أي شيء عن الكود الذي تفحصه.', 'upd.check': 'التحقق من التحديثات', 'upd.apply': 'حدّث الآن', 'upd.restart': 'أعد التشغيل الآن',
    'upd.current': 'الإصدار الحالي', 'upd.latest': 'أحدث إصدار', 'upd.kind': 'نوع التثبيت', 'upd.notes': 'ملاحظات الإصدار', 'upd.onGithub': 'عرض الإصدار على GitHub',
    'upd.auto': 'التحقق من التحديثات تلقائيًا عند تشغيل الواجهة (مرة كل 6 ساعات على الأكثر)',
    'upd.kindBinary': 'نسخة تنفيذية', 'upd.kindPip': 'حزمة pip', 'upd.kindSource': 'من الكود المصدري',
    'upd.checking': 'جارٍ التحقق من التحديثات…', 'upd.uptodate': 'أنت تستخدم أحدث إصدار', 'upd.uptodateSub': 'كاشِف {v} هو أحدث إصدار منشور.',
    'upd.available': 'الإصدار {v} متاح', 'upd.availableSub': 'لديك الإصدار {cur}.', 'upd.released': 'نُشر {date}.', 'upd.checked': 'آخر تحقق {when}.',
    'upd.disabled': 'التحقق التلقائي متوقف', 'upd.disabledSub': 'اضغط «التحقق من التحديثات» للتحقق الآن.', 'upd.failed': 'تعذّر التحقق من التحديثات',
    'upd.runCmd': 'لتحديث هذا التثبيت شغّل الأمر التالي في الطرفية:', 'upd.manual': 'نزّل الإصدار الجديد من صفحة الإصدارات واستبدل به الملف الحالي.',
    'upd.pill': 'تحديث متاح: {v}', 'upd.pillTitle': 'الإصدار {v} متاح — افتح الإعدادات للتحديث',
    'upd.phase.check': 'جارٍ التحضير…', 'upd.phase.download': 'جارٍ التنزيل…', 'upd.phase.verify': 'جارٍ التحقق من بصمة SHA-256 ومن البرنامج الجديد…', 'upd.phase.swap': 'جارٍ تثبيت الإصدار الجديد…',
    'upd.doneTitle': 'تم تثبيت الإصدار {v}', 'upd.doneSub': 'أعد التشغيل لاستخدامه. احتُفظ بالنسخة السابقة احتياطًا حتى التشغيل القادم.', 'upd.restarting': 'جارٍ إعادة التشغيل…', 'upd.restartSlow': 'لم تعد الواجهة بعد. شغّل كاشِف من جديد إن لزم.',
    'upd.updateFailed': 'لم يكتمل التحديث', 'upd.confirm': 'تنزيل الإصدار {v} وتثبيته الآن؟ ستحتاج إلى إعادة تشغيل الواجهة بعده.',
    'upd.err.offline': 'تعذّر الاتصال بـ GitHub. تحقّق من اتصالك بالإنترنت أو من إعدادات الوكيل ثم أعد المحاولة.', 'upd.err.rate_limited': 'بلغت حدّ طلبات GitHub المسموح به مؤقتًا. أعد المحاولة بعد قليل.',
    'upd.err.bad_response': 'ردّ GitHub غير متوقع. أعد المحاولة لاحقًا.', 'upd.err.no_release': 'لا يوجد إصدار منشور بعد.',
    'upd.err.not_binary': 'التحديث من داخل البرنامج متاح للنسخة التنفيذية فقط.', 'upd.err.unsupported_platform': 'لا توجد نسخة تنفيذية جاهزة لهذا النظام أو المعالج.',
    'upd.err.not_writable': 'لا يمكن الكتابة في مجلد البرنامج. شغّل كاشِف بصلاحيات المسؤول ثم حدّث، أو نزّل الإصدار يدويًا.', 'upd.err.up_to_date': 'أنت تستخدم أحدث إصدار.',
    'upd.err.not_newer': 'الإصدار المنشور ليس أحدث من إصدارك؛ لا يُثبَّت إصدار أقدم أو مماثل.', 'upd.err.asset_missing': 'الإصدار المنشور لا يحتوي على ملف هذا النظام.',
    'upd.err.checksum_missing': 'ملف البصمات لا يحتوي على بصمة هذا الملف؛ أُلغي التحديث حفاظًا على سلامتك.', 'upd.err.checksum_mismatch': 'بصمة الملف المنزَّل لا تطابق البصمة المنشورة؛ أُلغي التحديث ولم يتغيّر شيء.',
    'upd.err.too_large': 'الملف المنزَّل أكبر من الحد المسموح؛ أُلغي التحديث.', 'upd.err.bad_host': 'رُفض التنزيل: العنوان ليس من خوادم GitHub الموثوقة.',
    'upd.err.bad_binary': 'الملف المنزَّل ليس برنامجًا تنفيذيًا صالحًا لهذا النظام؛ أُلغي التحديث.', 'upd.err.version_mismatch': 'النسخة الجديدة لم تُبلغ عن الإصدار المتوقع؛ أُلغي التحديث.',
    'upd.err.swap_failed': 'تعذّر استبدال البرنامج؛ أُعيدت النسخة السابقة كما كانت.', 'upd.err.download_failed': 'انقطع التنزيل أو فشل؛ لم يتغيّر شيء. أعد المحاولة.',
    'upd.err.busy': 'يوجد تحديث جارٍ بالفعل.', 'upd.err.not_ready': 'لا يوجد تحديث مكتمل لإعادة التشغيل.', 'upd.err.restart_pending': 'اكتمل التحديث بالفعل؛ أعد تشغيل كاشِف لاستخدام الإصدار الجديد.', 'upd.err.restart_failed': 'تعذّر بدء الإصدار الجديد تلقائيًا. أغلق كاشِف وشغّله من جديد.', 'upd.err.forbidden': 'رُفض الطلب: يجب أن يصدر من هذه الواجهة نفسها.',
  },
  en: {
    brand: 'Kashif',
    sev: {critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info'},
    status: {running: 'Running', done: 'Completed', error: 'Failed'},
    theme: {auto: 'Theme: system', light: 'Theme: light', dark: 'Theme: dark'},
    src: {vulnscan: 'Pattern rules', taint: 'Data-flow engine', vql: 'VQL queries', web: 'Web checks', apex: 'Apex analyzer', osv: 'OSV (dependencies)', npm: 'npm audit'},
    'a11y.skip': 'Skip to content', 'a11y.nav': 'Main navigation', 'a11y.sevFilter': 'Filter by severity',
    err: {'authorization required': 'Confirm that you are authorized to test this site before scanning it.', 'target required': 'Enter a path or URL to scan.', 'bad upload': 'The upload was rejected (too large or malformed).', 'file required': 'Choose at least one file.', forbidden: 'Request refused: it must come from this UI.', 'not found': 'Not found (it may have been deleted).'},
    'nav.dashboard': 'Dashboard', 'nav.scan': 'New scan', 'nav.findings': 'Findings', 'nav.reports': 'Reports', 'nav.rules': 'Rules', 'nav.settings': 'Settings',
    'dash.title': 'Dashboard', 'dash.sub': 'Overview of the latest scan and how findings trend over time.', 'dash.empty': 'No scans yet', 'dash.emptyHint': 'Scan a project folder or upload an archive to get started.',
    'dash.donut': 'Severity distribution', 'dash.trend': 'Findings over recent scans', 'dash.topRules': 'Most frequent issues', 'dash.topFiles': 'Most affected files', 'dash.recent': 'Recent scans',
    'dash.allScans': 'All scans', 'dash.latest': 'Latest scan', 'dash.findingsCap': 'findings', 'dash.oneScan': 'Only one scan so far. Run more scans to see the trend over time.', 'dash.total': 'findings in total',
    'scan.title': 'New scan', 'scan.sub': 'Scan a folder on this machine, upload an archive or files, or passively check a website you own.',
    'scan.tabPath': 'Local path', 'scan.tabUpload': 'Upload files / archive', 'scan.tabUrl': 'Web URL', 'scan.pathLabel': 'Folder, file or archive path', 'scan.start': 'Start scan',
    'scan.pathHint': 'The whole folder is scanned recursively (node_modules, .git and build are skipped).', 'scan.drop': 'Drop an archive (zip / apk / jar / tar.gz / whl) or any files here',
    'scan.chooseFiles': 'Choose files', 'scan.chooseFolder': 'Choose a folder', 'scan.uploadStart': 'Upload and scan', 'scan.urlLabel': 'Site URL (passive: a single request)',
    'scan.authorize': 'I own this site or have written permission to test it', 'scan.deep': 'Deeper scan: analyze the page and probe common exposed paths (a few extra requests)', 'scan.crawl': 'Crawl same-site pages and scan each one (for apps such as Moodle and university portals)', 'scan.legal': 'Testing systems without permission may be illegal.', 'scan.viewResults': 'View findings',
    'scan.running': 'Scanning…', 'scan.done': 'Scan complete', 'scan.failed': 'Scan failed', 'scan.needAuth': 'Confirm that you are authorized to test this site first', 'scan.selected': 'file(s) selected', 'scan.uploading': 'Uploading…', 'scan.uploadFailed': 'Upload failed',
    'scan.jadxOn': 'jadx is installed: APK/JAR/AAR/DEX files are decompiled and the resulting code is scanned too.', 'scan.jadxOff': 'jadx is not installed: only text files inside APK/JAR are scanned. Install jadx (requires Java) to decompile bytecode.',
    'scan.uploaded': '{n} uploaded files',
    'find.title': 'Findings', 'find.sub': 'Sorted from highest to lowest severity. Select a finding to see its details and remediation.', 'find.search': 'Search file, rule or text…', 'find.allSources': 'All sources',
    'find.none': 'No findings match the current filters.', 'find.flow': 'Data-flow path (source to sink)', 'find.files': 'files scanned', 'find.pages': 'pages scanned', 'find.onPages': 'Seen on {n} pages',
    'find.advice': 'Remediation', 'find.snippet': 'Code', 'find.ref': 'Reference', 'find.scan': 'Scan', 'find.export': 'Export',
    'find.dataflow': 'Proven by data flow', 'find.pattern': 'Pattern match', 'find.location': 'Location', 'find.source': 'Source', 'find.sink': 'Sink', 'find.step': 'Step',
    'find.fingerprint': 'Fingerprint', 'find.copy': 'Copy', 'find.copied': 'Copied', 'find.showing': 'Showing {n} of {total} findings', 'find.cwe': 'Open the {cwe} definition at MITRE', 'find.input': 'Untrusted input', 'find.clear': 'Show all',
    'rep.title': 'Reports', 'rep.sub': 'Scan history, report downloads, and a comparison of two scans to see what was fixed and what is new.', 'rep.compare': 'Compare two scans', 'rep.compareBtn': 'Compare', 'rep.fixed': 'Fixed (no longer present)', 'rep.new': 'New (introduced)',
    'rep.target': 'Target', 'rep.date': 'Date', 'rep.status': 'Status', 'rep.total': 'Total', 'rep.actions': 'Actions', 'rep.delete': 'Delete', 'rep.view': 'View', 'rep.nothing': 'None',
    'rep.base': 'Base scan', 'rep.head': 'Compare with', 'rep.history': 'Scan history', 'rep.download': 'Download HTML report', 'rep.confirmDel': 'Delete this scan?', 'rep.noScans': 'No scans yet.',
    'rules.title': 'Built-in rules', 'rules.search': 'Search rules…', 'rules.count': 'rules', 'rules.id': 'Rule', 'rules.sev': 'Severity', 'rules.name': 'Issue', 'rules.langs': 'Applies to', 'rules.advice': 'Remediation',
    'set.title': 'Settings', 'set.sub': 'Stored on this machine and applied to every new scan.', 'set.minSev': 'Minimum severity shown', 'set.failOn': 'Fail CI at severity', 'set.exclude': 'Excluded paths (one glob per line)',
    'set.ignore': 'Ignored rules (one ID per line)', 'set.authTargets': 'Authorized web targets (one per line)', 'set.osv': 'Query OSV.dev for known vulnerabilities in dependencies (requires internet)',
    'set.external': 'Merge results from installed external scanners', 'set.audit': 'Audit profile: also report risky calls that data-flow analysis did not prove reachable from input (broader, noisier)', 'set.jadx': 'Decompile APK / JAR / AAR / DEX with jadx and scan the output', 'set.jadxLibs': 'Also scan third-party libraries in decompiled code (more findings, more noise)', 'set.jadxTimeout': 'jadx timeout (seconds)', 'set.jadxOn': 'jadx is installed on this machine.', 'set.jadxOff': 'jadx is not installed. Get it from github.com/skylot/jadx to decompile bytecode.',
    'set.models': 'Extra models folder for the data-flow engine (JSON: sources, sinks, sanitizers)', 'set.queries': 'Extra VQL queries folder (declarative queries over the program database)',
    'set.keep': 'Scans to keep', 'set.webTimeout': 'Web request timeout in seconds (the first request is retried once with double the timeout)', 'set.webDelay': 'Delay between crawl requests in seconds (gentler on the server and its firewall)', 'set.save': 'Save changes', 'set.saved': 'Saved', 'set.home': 'Data folder', 'set.none': 'none installed',
    'set.secScope': 'Scope and thresholds', 'set.secScopeHint': 'Which findings are shown and when CI fails.', 'set.secAnalysis': 'Analysis and integrations', 'set.secAnalysisHint': 'Extra result sources and how broad the analysis is.',
    'set.secBinary': 'Binaries (jadx)', 'set.secWeb': 'Web scanning', 'set.secWebHint': 'Passive, rate-limited checks of sites you are authorized to test.', 'set.secStorage': 'Storage',
    'upd.title': 'Updates', 'upd.hint': 'Kashif checks the official GitHub releases. Nothing about the code you scan is sent.', 'upd.check': 'Check for updates', 'upd.apply': 'Update now', 'upd.restart': 'Restart now',
    'upd.current': 'Current version', 'upd.latest': 'Latest version', 'upd.kind': 'Installed as', 'upd.notes': 'Release notes', 'upd.onGithub': 'View the release on GitHub',
    'upd.auto': 'Check for updates automatically when the UI starts (at most every 6 hours)',
    'upd.kindBinary': 'Standalone binary', 'upd.kindPip': 'pip package', 'upd.kindSource': 'Source checkout',
    'upd.checking': 'Checking for updates…', 'upd.uptodate': 'You’re up to date', 'upd.uptodateSub': 'Kashif {v} is the latest release.',
    'upd.available': 'Version {v} is available', 'upd.availableSub': 'You have {cur}.', 'upd.released': 'Released {date}.', 'upd.checked': 'Checked {when}.',
    'upd.disabled': 'Automatic checks are off', 'upd.disabledSub': 'Select “Check for updates” to check now.', 'upd.failed': 'Couldn’t check for updates',
    'upd.runCmd': 'To update this installation, run this command in a terminal:', 'upd.manual': 'Download the new release from the releases page and replace the current file with it.',
    'upd.pill': 'Update available: {v}', 'upd.pillTitle': 'Version {v} is available — open Settings to update',
    'upd.phase.check': 'Preparing…', 'upd.phase.download': 'Downloading…', 'upd.phase.verify': 'Verifying the SHA-256 checksum and the new binary…', 'upd.phase.swap': 'Installing the new version…',
    'upd.doneTitle': 'Version {v} is installed', 'upd.doneSub': 'Restart to start using it. The previous version is kept as a backup until the next start.', 'upd.restarting': 'Restarting…', 'upd.restartSlow': 'The UI has not come back yet. Start Kashif again if needed.',
    'upd.updateFailed': 'The update did not complete', 'upd.confirm': 'Download and install version {v} now? The UI will need a restart afterwards.',
    'upd.err.offline': 'Couldn’t reach GitHub. Check your internet connection or proxy settings and try again.', 'upd.err.rate_limited': 'GitHub’s request limit was reached for now. Try again in a little while.',
    'upd.err.bad_response': 'GitHub sent an unexpected response. Try again later.', 'upd.err.no_release': 'No release has been published yet.',
    'upd.err.not_binary': 'In-app updates are available for the standalone binary only.', 'upd.err.unsupported_platform': 'There is no prebuilt binary for this operating system or CPU.',
    'upd.err.not_writable': 'The program’s folder is not writable. Run Kashif as an administrator and update, or download the release manually.', 'upd.err.up_to_date': 'You are using the latest version.',
    'upd.err.not_newer': 'The published release is not newer than yours; an older or identical version is never installed.', 'upd.err.asset_missing': 'The published release has no file for this system.',
    'upd.err.checksum_missing': 'The checksum file has no entry for this download, so the update was cancelled for your safety.', 'upd.err.checksum_mismatch': 'The download’s checksum does not match the published one. The update was cancelled and nothing changed.',
    'upd.err.too_large': 'The download is larger than allowed, so the update was cancelled.', 'upd.err.bad_host': 'Download refused: the address is not one of GitHub’s trusted servers.',
    'upd.err.bad_binary': 'The downloaded file is not a valid executable for this system, so the update was cancelled.', 'upd.err.version_mismatch': 'The new binary did not report the expected version, so the update was cancelled.',
    'upd.err.swap_failed': 'The program could not be replaced; the previous version was restored as it was.', 'upd.err.download_failed': 'The download failed or was interrupted; nothing changed. Try again.',
    'upd.err.busy': 'An update is already in progress.', 'upd.err.not_ready': 'There is no completed update to restart into.', 'upd.err.restart_pending': 'The update is already installed. Restart Kashif to use the new version.', 'upd.err.restart_failed': 'The new version could not be started automatically. Close Kashif and start it again.', 'upd.err.forbidden': 'Request refused: it must come from this UI.',
  },
};

/* ------------------------------------------------------------- helpers */
const store = {
  get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } },
};
let lang = store.get('vs.lang') === 'en' ? 'en' : 'ar';
const t = (k, vars) => {
  let s = I18N[lang][k] ?? I18N.ar[k] ?? k;
  if (vars) Object.keys(vars).forEach((v) => { s = s.replace(`{${v}}`, vars[v]); });
  return s;
};
const sevName = (s) => I18N[lang].sev[s] || s;
const srcName = (s) => I18N[lang].src[s] || s;  // external tools (semgrep, bandit, ...) keep their own names
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const locale = () => (lang === 'ar' ? 'ar-EG' : 'en-GB');
const fmtDate = (ts) => (ts ? new Date(ts * 1000).toLocaleString(locale(), {dateStyle: 'medium', timeStyle: 'short'}) : '—');
const fmtShort = (ts) => (ts ? new Date(ts * 1000).toLocaleDateString(locale(), {month: 'short', day: 'numeric'}) : '');
const errText = (code) => I18N[lang].err[code] || code;
const api = async (path, opts = {}) => {
  const r = await fetch(path, {headers: {'Content-Type': 'application/json'}, ...opts});
  if (!r.ok) throw new Error(errText((await r.json().catch(() => ({}))).error || r.statusText));
  return r.json();
};
const setHTML = (el, html) => { el.innerHTML = html; }; // nosec — every dynamic value is escaped with esc() before reaching here
const toast = (msg) => { const el = $('#toast'); el.textContent = msg; el.classList.remove('hidden'); clearTimeout(el._t); el._t = setTimeout(() => el.classList.add('hidden'), 3200); };
const total = (s) => SEV.reduce((a, k) => a + (s[k] || 0), 0);
const ic = (name, cls = '') => `<svg class="i ${cls}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
const pill = (s) => `<span class="pill sev-${s}"><span class="dot"></span>${esc(sevName(s))}</span>`;
/* In Arabic text, isolate code identifiers such as order_query() so the bidi algorithm does not mirror their brackets. */
const bidi = (text) => {
  const str = String(text ?? '');
  if (lang !== 'ar' || !/[\u0600-\u06FF]/.test(str)) return esc(str);
  let out = '', last = 0; const tok = String.raw`[A-Za-z_$][\w$:/-]*(?:\.[\w$]+)*(?:\([^)؀-ۿ]*\))?`; const rx = new RegExp(`${tok}(?: +${tok})*`, 'g'); let m;
  while ((m = rx.exec(str))) { out += esc(str.slice(last, m.index)) + `<bdi dir="ltr">${esc(m[0])}</bdi>`; last = m.index + m[0].length; }
  return out + esc(str.slice(last));
};
const ARABIC = /[؀-ۿݐ-ݿﭐ-﷿ﹰ-﻿]/;

/* Localized engine text: the English field (from vulnscan.i18n) in English, the Arabic original in Arabic. */
const loc = (obj, key) => (lang === 'en' ? (obj[key + '_en'] ?? obj[key]) : obj[key]) ?? '';
const titleOf = (o) => (lang === 'en' ? (o.title || o.title_ar) : (o.title_ar || o.title)) || '';
const notesOf = (s) => (lang === 'en' && Array.isArray(s.notes_en) && s.notes_en.length === (s.notes || []).length ? s.notes_en : (s.notes || []));
const errorOf = (s) => (lang === 'en' ? (s.error_en || s.error) : s.error) || '';
const isFlow = (f) => !!((f.extra && Array.isArray(f.extra.path) && f.extra.path.length) || /^DF/.test(f.rule_id || ''));
const cweNum = (c) => { const m = /CWE-(\d+)/i.exec(c || ''); return m ? m[1] : null; };
const cweTag = (c) => {
  const n = cweNum(c);
  if (!n) return c ? `<span class="tag">${esc(c)}</span>` : '';
  return `<a class="tag" href="https://cwe.mitre.org/data/definitions/${n}.html" target="_blank" rel="noopener noreferrer" title="${esc(t('find.cwe', {cwe: 'CWE-' + n}))}">CWE-${n}${ic('external', 'xs')}</a>`;
};
/* A short, human name for a scan target: the upload label, the URL host, or the last path component. */
function scanName(s) {
  if (!s) return '';
  if (s.label) {
    const m = /^(\d+) ملف مرفوع$/.exec(s.label);
    return m ? t('scan.uploaded', {n: m[1]}) : s.label;
  }
  const tg = String(s.target || '');
  if (/^https?:\/\//i.test(tg)) {
    try { const u = new URL(tg); return u.host + (u.pathname !== '/' ? u.pathname : ''); } catch { return tg; }
  }
  const parts = tg.replace(/[\\/]+$/, '').split(/[\\/]/);
  return parts[parts.length - 1] || tg;
}
/* A path with the directory truncated (start ellipsis) and the file name kept whole. */
function fpath(p, line) {
  const s = String(p || '');
  const i = Math.max(s.lastIndexOf('/'), s.lastIndexOf('!'));
  const dir = i >= 0 ? s.slice(0, i + 1) : '';
  const base = s.slice(i + 1) + (line ? `:${line}` : '');
  return `<span class="fpath" title="${esc(s + (line ? ':' + line : ''))}">${dir ? `<span class="dir"><bdi>${esc(dir)}</bdi></span>` : ''}<span class="base">${esc(base)}</span></span>`;
}
const copyBtn = (text) => `<button class="copy" type="button" data-copy="${esc(text)}" aria-label="${esc(t('find.copy'))}" title="${esc(t('find.copy'))}">${ic('copy')}</button>`;

/* ------------------------------------------------------- i18n / theme */
function applyLang() {
  const root = document.documentElement;
  root.lang = lang;
  root.dir = lang === 'ar' ? 'rtl' : 'ltr';
  $$('[data-i18n]').forEach((el) => { el.textContent = t(el.dataset.i18n); });
  $$('[data-i18n-ph]').forEach((el) => { el.placeholder = t(el.dataset.i18nPh); });
  $('#brand-name').textContent = t('brand');
  document.title = `${t('brand')} — vulnscan`;
  const lb = $('#lang-label'); lb.textContent = lang === 'ar' ? 'English' : 'العربية'; lb.lang = lang === 'ar' ? 'en' : 'ar';
  $('#lang-btn').title = lang === 'ar' ? 'English' : 'العربية';
  $('#lang-btn').setAttribute('aria-label', lang === 'ar' ? 'Switch to English' : 'التبديل إلى العربية');
  $('#source-filter').options[0].textContent = t('find.allSources');
  $('#source-filter').setAttribute('aria-label', t('find.allSources'));
  $('nav').setAttribute('aria-label', t('a11y.nav'));
  $('.brand').setAttribute('aria-label', `${t('brand')} — vulnscan`);
  $('#sev-filter').setAttribute('aria-label', t('a11y.sevFilter'));
  $('.btn-group').setAttribute('aria-label', t('find.export'));
  $$('#f-min option, #f-fail option').forEach((o) => { o.textContent = sevName(o.value); });
  applyThemeUI();
}
$('#lang-btn').onclick = () => { lang = lang === 'ar' ? 'en' : 'ar'; store.set('vs.lang', lang); applyLang(); jadxHint(); renderPill(); route(); };
const themeNow = () => document.documentElement.dataset.theme || 'auto';
function applyThemeUI() {
  const th = themeNow();
  $('#theme-icon').setAttribute('href', th === 'dark' ? '#i-moon' : th === 'light' ? '#i-sun' : '#i-auto');
  $('#theme-label').textContent = I18N[lang].theme[th];
  $('#theme-btn').title = I18N[lang].theme[th];
  $('#theme-btn').setAttribute('aria-label', I18N[lang].theme[th]);
}
$('#theme-btn').onclick = () => {
  const cur = themeNow();
  const next = cur === 'dark' ? 'light' : cur === 'light' ? 'auto' : 'dark';
  if (next === 'auto') delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = next;
  store.set('vs.theme', next);
  applyThemeUI();
};
{ const th = store.get('vs.theme'); if (th === 'dark' || th === 'light') document.documentElement.dataset.theme = th; }
$('.skip').addEventListener('click', (e) => { e.preventDefault(); $('#main').focus(); });

/* ------------------------------------------------------------- routing */
const pages = {dashboard: loadDashboard, scan: () => {}, findings: loadFindings, reports: loadReports, rules: loadRules, settings: loadSettings};
let curPage = '';
function route() {
  const h = location.hash.slice(1);
  const slash = h.indexOf('/');
  const name = (slash < 0 ? h : h.slice(0, slash)).split('?')[0] || 'dashboard';
  const arg = slash < 0 ? (h.includes('?') ? h.slice(h.indexOf('?')) : '') : h.slice(slash + 1);
  const page = pages[name] ? name : 'dashboard';
  curPage = page;
  $$('.page').forEach((p) => p.classList.toggle('active', p.id === 'page-' + page));
  $$('nav a').forEach((a) => { const on = a.dataset.nav === page; a.classList.toggle('active', on); if (on) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); });
  Promise.resolve(pages[page](arg)).catch((err) => toast(err.message));
}
window.addEventListener('hashchange', route);

/* ----------------------------------------------------------- dashboard */
let lastTrend = null;
const tilesHTML = (summary, interactive = true) => SEV.map((s) => {
  const n = summary[s] || 0;
  const tag = interactive ? 'button' : 'div';
  return `<${tag} class="tile sev-${s}${n ? '' : ' zero'}" data-sev="${s}"${interactive ? ' type="button"' : ''}><span class="l"><span class="dot"></span>${esc(sevName(s))}</span><span class="n">${n}</span></${tag}>`;
}).join('');
async function loadDashboard() {
  const st = await api('/api/stats');
  const empty = !st.latest;
  $('#dash-empty').classList.toggle('hidden', !empty);
  $('#dash-body').classList.toggle('hidden', empty);
  $('#dash-open').classList.toggle('hidden', empty);
  if (empty) return;
  const L = st.latest; const sum = L.summary;
  $('#dash-open').href = `#findings/${L.id}`;
  setHTML($('#dash-context'), `<span class="ctx" title="${esc(L.target)}">${ic(L.kind === 'url' ? 'globe' : 'folder', 'sm')}<span class="muted">${esc(t('dash.latest'))}:</span> <b class="ellipsis" dir="auto">${esc(scanName(L))}</b></span>`
    + `<span class="ctx">${ic('file', 'sm')}${L.files_scanned} ${esc(t(L.kind === 'url' ? 'find.pages' : 'find.files'))}</span>`
    + `<span class="ctx">${ic('clock', 'sm')}${esc(fmtDate(L.finished_at))}</span>`);
  setHTML($('#tiles'), tilesHTML(sum));
  $$('#tiles .tile').forEach((el) => { el.onclick = () => { location.hash = `findings/${L.id}?sev=${el.dataset.sev}`; }; });
  drawDonut($('#donut'), $('#donut-legend'), sum);
  lastTrend = st.trend; drawTrend($('#trend'), st.trend);
  const maxR = Math.max(1, ...st.top_rules.map((r) => r.count));
  setHTML($('#top-rules'), st.top_rules.map((r) => `<li class="sev-${r.severity}"><span class="main">${pill(r.severity)}<a class="title" href="#findings/${L.id}?q=${encodeURIComponent(r.rule_id)}" title="${esc(titleOf(r))}">${esc(titleOf(r))}</a></span><span class="rid" dir="ltr">${esc(r.rule_id)}</span><span class="bar"><i style="width:${(r.count / maxR) * 100}%"></i></span><span class="cnt">${r.count}</span></li>`).join('') || `<li class="empty-li">${esc(t('rep.nothing'))}</li>`);
  const maxF = Math.max(1, ...st.top_files.map(([, n]) => n));
  setHTML($('#top-files'), st.top_files.map(([f, n]) => `<li><span class="ffile">${ic('file', 'sm')}${fpath(f)}</span><span class="bar"><i style="width:${(n / maxF) * 100}%"></i></span><span class="cnt">${n}</span></li>`).join('') || `<li class="empty-li">${esc(t('rep.nothing'))}</li>`);
  const scans = await api('/api/scans');
  setHTML($('#recent-table'), scanRows(scans.slice(0, 6)));
}
function drawDonut(svg, legend, sum) {
  const tot = total(sum); const r = 46, c = 60, C = 2 * Math.PI * r; let off = 0; const parts = [];
  const live = SEV.filter((s) => sum[s]);
  const gap = live.length > 1 ? 2.5 : 0;
  live.forEach((s) => {
    const len = (sum[s] / tot) * C;
    parts.push(`<circle cx="${c}" cy="${c}" r="${r}" fill="none" class="stroke-${s}" stroke-width="14" stroke-dasharray="${Math.max(0.5, len - gap)} ${C}" stroke-dashoffset="${-off}"><title>${esc(sevName(s))}: ${sum[s]}</title></circle>`);
    off += len;
  });
  const track = `<circle cx="${c}" cy="${c}" r="${r}" fill="none" class="ch-grid" stroke-width="14"/>`;
  setHTML(svg, `${track}<g transform="rotate(-90 ${c} ${c})">${parts.join('')}</g><text x="${c}" y="${c + 3}" text-anchor="middle" font-size="24" class="donut-total">${tot}</text><text x="${c}" y="${c + 19}" text-anchor="middle" font-size="9.5" class="donut-cap">${esc(t('dash.findingsCap'))}</text>`);
  svg.setAttribute('aria-label', SEV.map((s) => `${sevName(s)} ${sum[s] || 0}`).join(', '));
  setHTML(legend, SEV.map((s) => `<div class="sev-${s}"><span class="dot"></span>${esc(sevName(s))}<b>${sum[s] || 0}</b><span class="pct">${tot ? Math.round(((sum[s] || 0) / tot) * 100) : 0}%</span></div>`).join(''));
}
const niceStep = (m) => { const raw = m / 4; if (raw <= 1) return 1; const p = 10 ** Math.floor(Math.log10(raw)); const f = raw / p; return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p; };
function drawTrend(svg, trend) {
  setHTML($('#trend-legend'), SEV.map((s) => `<span class="sev-${s}"><span class="dot"></span>${esc(sevName(s))}</span>`).join(''));
  const note = $('#trend-note');
  if (!trend || !trend.length) { setHTML(svg, ''); note.classList.add('hidden'); return; }
  const W = Math.max(280, Math.round(svg.getBoundingClientRect().width || 600)), H = 200;
  const padL = 34, padR = 8, padT = 16, padB = 26;
  const pw = W - padL - padR, ph = H - padT - padB;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.setAttribute('direction', 'ltr');
  const max = Math.max(1, ...trend.map(total));
  const step = niceStep(max); const top = Math.ceil(max / step) * step;
  let out = '';
  for (let v = 0; v <= top; v += step) {
    const y = padT + ph - (v / top) * ph;
    out += `<line x1="${padL}" x2="${W - padR}" y1="${y}" y2="${y}" class="${v ? 'ch-grid' : 'ch-axis'}"${v ? ' stroke-dasharray="2 3"' : ''}/><text x="${padL - 8}" y="${y + 3.5}" text-anchor="end" class="ch-txt">${v}</text>`;
  }
  const n = trend.length;
  const slots = Math.max(n, 6);              // a lone scan stays a slim bar instead of filling the chart
  const slot = pw / slots;
  const bw = Math.min(32, slot * 0.56);
  const x0 = padL + (pw - slot * n) / 2;    // center the group of bars
  const every = Math.ceil(n / 8);
  trend.forEach((s, i) => {
    const cx = x0 + slot * i + slot / 2; const x = cx - bw / 2;
    let y = padT + ph;
    SEV.slice().reverse().forEach((k) => {
      const v = s[k] || 0; if (!v) return;
      const h = (v / top) * ph; y -= h;
      out += `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${bw.toFixed(1)}" height="${Math.max(1, h - 1).toFixed(1)}" class="fill-${k}" rx="2"><title>${esc(scanName(s))} · ${esc(fmtShort(s.at))} — ${esc(sevName(k))}: ${v}</title></rect>`;
    });
    out += `<text x="${cx.toFixed(1)}" y="${(y - 5).toFixed(1)}" text-anchor="middle" class="ch-total">${total(s)}</text>`;
    if (i % every === 0 || i === n - 1) out += `<text x="${cx.toFixed(1)}" y="${H - 8}" text-anchor="middle" class="ch-txt">${esc(fmtShort(s.at))}</text>`;
  });
  setHTML(svg, out);
  svg.setAttribute('aria-label', t('dash.trend'));
  note.classList.toggle('hidden', n > 1);
  setHTML(note, `${ic('info', 'sm')}<span>${esc(t('dash.oneScan'))}</span>`);
}
let rsz;
window.addEventListener('resize', () => { clearTimeout(rsz); rsz = setTimeout(() => { if (curPage === 'dashboard' && lastTrend) drawTrend($('#trend'), lastTrend); }, 120); });

function scanRows(scans) {
  if (!scans.length) return `<tr><td class="muted" style="text-align:center;padding:32px">${esc(t('rep.noScans'))}</td></tr>`;
  const head = `<thead><tr><th>${esc(t('rep.target'))}</th><th>${esc(t('rep.date'))}</th><th>${esc(t('rep.status'))}</th>${SEV.map((s) => `<th class="num sev-${s}" title="${esc(sevName(s))}"><span class="dot"></span> ${esc(sevName(s))}</th>`).join('')}<th class="num">${esc(t('rep.total'))}</th><th class="num"><span class="sr-only">${esc(t('rep.actions'))}</span></th></tr></thead>`;
  return head + '<tbody>' + scans.map((s) => {
    const err = errorOf(s);
    return `<tr>
    <td><div class="target"><b dir="auto">${esc(scanName(s))}</b><small title="${esc(s.target)}">${esc(s.target)}</small></div></td>
    <td><span class="muted" style="white-space:nowrap">${esc(fmtDate(s.finished_at || s.started_at))}</span></td>
    <td><span class="status ${esc(s.status)}"><span class="dot"></span>${esc(I18N[lang].status[s.status] || s.status)}</span>${err ? `<small class="status-err" title="${esc(err)}">${esc(err)}</small>` : ''}</td>
    ${SEV.map((k) => { const v = (s.summary || {})[k] || 0; return `<td class="num sev-${k}${v ? '' : ' z'}">${v ? `<b>${v}</b>` : '0'}</td>`; }).join('')}<td class="num"><b>${total(s.summary || {})}</b></td>
    <td class="num"><div class="actions">
      <a class="btn sm" href="#findings/${esc(s.id)}">${esc(t('rep.view'))}</a>
      <a class="btn sm icon" href="/api/scans/${esc(s.id)}/report.html?lang=${lang}" download title="${esc(t('rep.download'))}" aria-label="${esc(t('rep.download'))}">${ic('download', 'sm')}</a>
      <button class="btn sm icon danger" type="button" data-del="${esc(s.id)}" title="${esc(t('rep.delete'))}" aria-label="${esc(t('rep.delete'))}">${ic('trash', 'sm')}</button>
    </div></td></tr>`;
  }).join('') + '</tbody>';
}

/* ------------------------------------------------------ global clicks */
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch {
    const ta = document.createElement('textarea'); ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select(); let ok = false; try { ok = document.execCommand('copy'); } catch { ok = false; } ta.remove(); return ok;
  }
}
document.addEventListener('click', async (e) => {
  const cp = e.target.closest('[data-copy]');
  if (cp) {
    e.stopPropagation();
    if (await copyText(cp.dataset.copy)) {
      cp.classList.add('done'); setHTML(cp, ic('check')); cp.title = t('find.copied');
      setTimeout(() => { cp.classList.remove('done'); setHTML(cp, ic('copy')); cp.title = t('find.copy'); }, 1400);
    }
    return;
  }
  const b = e.target.closest('[data-del]'); if (!b) return;
  if (!confirm(t('rep.confirmDel'))) return;
  try { await api(`/api/scans/${b.dataset.del}`, {method: 'DELETE'}); route(); } catch (err) { toast(err.message); }
});

/* ---------------------------------------------------------------- scan */
$$('#scan-tabs .tab').forEach((b) => { b.onclick = () => {
  $$('#scan-tabs .tab').forEach((x) => { x.classList.toggle('active', x === b); x.setAttribute('aria-selected', String(x === b)); });
  $$('.tab-pane').forEach((p) => p.classList.toggle('hidden', p.dataset.pane !== b.dataset.tab));
}; });
async function startScan(body) {
  try { const scan = await api('/api/scan', {method: 'POST', body: JSON.stringify(body)}); watchScan(scan.id); } catch (err) { toast(err.message); }
}
$('#path-btn').onclick = () => { const v = $('#path-input').value.trim(); if (v) startScan({target: v}); else $('#path-input').focus(); };
$('#path-input').onkeydown = (e) => { if (e.key === 'Enter') $('#path-btn').click(); };
$('#url-auth').onchange = (e) => { e.target.removeAttribute('aria-invalid'); e.target.closest('.check').classList.remove('invalid'); };
$('#url-input').onkeydown = (e) => { if (e.key === 'Enter') $('#url-btn').click(); };
$('#url-btn').onclick = () => {
  const v = $('#url-input').value.trim(); if (!v) { $('#url-input').focus(); return; }
  if (!$('#url-auth').checked) {  // refused before any request: mark the consent box itself, not only a transient toast
    const box = $('#url-auth'); box.setAttribute('aria-invalid', 'true'); box.closest('.check').classList.add('invalid');
    toast(t('scan.needAuth')); box.focus(); return;
  }
  startScan({target: v, authorized: true, deep: $('#url-deep').checked, crawl: $('#url-crawl').checked});
};
let pending = [];
const dz = $('#dropzone');
const setFiles = (files) => {
  pending = [...files];
  $('#upload-list').textContent = pending.length ? `${pending.length} ${t('scan.selected')}: ${pending.slice(0, 5).map((f) => f.webkitRelativePath || f.name).join(', ')}${pending.length > 5 ? '…' : ''}` : '';
  $('#upload-btn').classList.toggle('hidden', !pending.length);
};
$('#file-input').onchange = (e) => setFiles(e.target.files);
$('#folder-input').onchange = (e) => setFiles(e.target.files);
['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('over'); }));
['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove('over'); }));
dz.addEventListener('drop', (e) => setFiles(e.dataTransfer.files));
$('#upload-btn').onclick = () => {
  if (!pending.length) return;
  const fd = new FormData(); pending.forEach((f) => fd.append('file', f, f.webkitRelativePath || f.name));
  const xhr = new XMLHttpRequest(); xhr.open('POST', '/api/upload');
  const prog = $('#upload-progress'); prog.classList.remove('hidden');
  xhr.upload.onprogress = (e) => { if (e.lengthComputable) prog.firstElementChild.style.width = (e.loaded / e.total * 100) + '%'; };
  xhr.onload = () => {
    prog.classList.add('hidden'); prog.firstElementChild.style.width = '0';
    if (xhr.status < 300) { watchScan(JSON.parse(xhr.responseText).id); setFiles([]); return; }
    let msg = xhr.responseText; try { msg = errText(JSON.parse(xhr.responseText).error) || msg; } catch { /* plain text */ }
    toast(`${t('scan.uploadFailed')}: ${msg}`);
  };
  xhr.onerror = () => { prog.classList.add('hidden'); toast(t('scan.uploadFailed')); };
  xhr.send(fd);
};
async function watchScan(id) {
  const box = $('#scan-status'); box.classList.remove('hidden');
  $('#scan-status-result').classList.add('hidden'); $('#scan-status-open').classList.add('hidden'); $('#scan-bar').classList.remove('hidden');
  const icon = $('#scan-status-icon'); icon.className = 'status-icon'; setHTML(icon, '<span class="spinner"></span>');
  $('#scan-status-title').textContent = t('scan.running');
  const poll = async () => {
    let s;
    try { s = await api(`/api/scans/${id}`); } catch (err) { toast(err.message); return; }
    $('#scan-status-target').textContent = s.target; $('#scan-status-target').title = s.target;
    if (s.status === 'running') { $('#scan-status-title').textContent = `${t('scan.running')} ${s.files_scanned ? '(' + s.files_scanned + ')' : ''}`; setTimeout(poll, 700); return; }
    $('#scan-bar').classList.add('hidden');
    if (s.status === 'error') {
      icon.className = 'status-icon err'; setHTML(icon, ic('warning'));
      $('#scan-status-title').textContent = `${t('scan.failed')}: ${errorOf(s)}`; return;
    }
    icon.className = 'status-icon ok'; setHTML(icon, ic('check'));
    $('#scan-status-title').textContent = `${t('scan.done')} — ${scanName(s)} · ${s.files_scanned} ${t(s.kind === 'url' ? 'find.pages' : 'find.files')}`;
    setHTML($('#scan-status-tiles'), tilesHTML(s.summary, false));
    $('#scan-status-open').href = `#findings/${s.id}`;
    $('#scan-status-open').classList.remove('hidden');
    $('#scan-status-result').classList.remove('hidden');
  };
  poll();
}

/* ------------------------------------------------------------ findings */
let cur = null; let shown = []; const sevOn = new Set(SEV);
function renderChips() {
  setHTML($('#sev-filter'), SEV.map((s) => `<button class="chip sev-${s}" type="button" data-sev="${s}" aria-pressed="${sevOn.has(s)}"><span class="dot"></span>${esc(sevName(s))}<span class="n">${cur ? (cur.summary[s] || 0) : ''}</span></button>`).join(''));
}
$('#sev-filter').onclick = (e) => {
  const b = e.target.closest('button'); if (!b) return;
  const s = b.dataset.sev; if (sevOn.has(s)) sevOn.delete(s); else sevOn.add(s);
  b.setAttribute('aria-pressed', String(sevOn.has(s))); renderFindings();
};
$('#findings-search').oninput = renderFindings; $('#source-filter').onchange = renderFindings;
$('#findings-scan').onchange = (e) => { location.hash = `findings/${e.target.value}`; };
async function loadFindings(arg) {
  const [id, qs] = (arg || '').split('?'); const q = new URLSearchParams(qs || '');
  const scans = (await api('/api/scans')).filter((s) => s.status === 'done');
  const sel = $('#findings-scan');
  setHTML(sel, scans.map((s) => `<option value="${esc(s.id)}" title="${esc(s.target)}">${esc(scanName(s))} — ${esc(fmtDate(s.finished_at))}</option>`).join(''));
  sel.title = '';
  const chosen = id || (scans[0] && scans[0].id);
  if (!chosen) {
    cur = null; renderChips(); setHTML($('#findings-notes'), ''); setHTML($('#findings-context'), '');
    setHTML($('#findings-list'), `<div class="empty inline"><span class="e-icon">${ic('findings', 'lg')}</span><h2>${esc(t('dash.empty'))}</h2><p class="muted">${esc(t('dash.emptyHint'))}</p><a class="btn primary" href="#scan">${ic('plus')}${esc(t('nav.scan'))}</a></div>`);
    return;
  }
  sel.value = chosen; cur = await api(`/api/scans/${chosen}`); sel.title = cur.target;
  if (q.get('sev')) { sevOn.clear(); sevOn.add(q.get('sev')); } else if (id) { SEV.forEach((s) => sevOn.add(s)); }
  if (q.has('q')) $('#findings-search').value = q.get('q'); else if (id) $('#findings-search').value = '';
  renderChips();
  const sources = [...new Set(cur.findings.map((f) => f.source))];
  setHTML($('#source-filter'), `<option value="">${esc(t('find.allSources'))}</option>` + sources.map((s) => `<option value="${esc(s)}">${esc(srcName(s))}</option>`).join(''));
  ['md', 'json', 'html'].forEach((x) => { $(`#dl-${x}`).href = `/api/scans/${chosen}/report.${x}${x === 'json' ? '' : `?lang=${lang}`}`; });
  setHTML($('#findings-context'), `<span class="ctx" title="${esc(cur.target)}">${ic(cur.kind === 'url' ? 'globe' : 'folder', 'sm')}<b class="ellipsis" dir="auto">${esc(scanName(cur))}</b></span>`
    + `<span class="ctx">${ic('file', 'sm')}${cur.files_scanned} ${esc(t(cur.kind === 'url' ? 'find.pages' : 'find.files'))}</span>`
    + `<span class="ctx">${ic('clock', 'sm')}${esc(fmtDate(cur.finished_at))}</span>`
    + `<span class="ctx">${ic('findings', 'sm')}${total(cur.summary)} ${esc(t('dash.findingsCap'))}</span>`);
  setHTML($('#findings-notes'), notesOf(cur).map((n) => `<div class="note">${ic('info')}<span>${bidi(n)}</span></div>`).join(''));
  renderFindings();
}
function renderFindings() {
  if (!cur) return;
  const q = $('#findings-search').value.trim().toLowerCase(); const src = $('#source-filter').value;
  shown = cur.findings.filter((f) => sevOn.has(f.severity) && (!src || f.source === src)
    && (!q || [f.file, f.rule_id, f.title, f.title_ar, f.snippet, f.snippet_en, f.cwe].join(' ').toLowerCase().includes(q)));
  const head = `<div class="fl-head"><span>${esc(t('find.showing', {n: shown.length, total: cur.findings.length}))}</span>${shown.length < cur.findings.length ? `<button class="btn sm ghost" type="button" id="clear-filters">${ic('x', 'sm')}${esc(t('find.clear'))}</button>` : ''}</div>`;
  if (!shown.length) {
    setHTML($('#findings-list'), head + `<div class="empty inline"><span class="e-icon">${ic('search', 'lg')}</span><p class="muted">${esc(t('find.none'))}</p></div>`);
  } else {
    let html = head, last = null;
    shown.forEach((f, i) => {
      if (f.severity !== last) {
        last = f.severity;
        html += `<div class="sev-head sev-${f.severity}"><span class="dot"></span>${esc(sevName(f.severity))}<span class="count">${shown.filter((x) => x.severity === f.severity).length}</span></div>`;
      }
      const flow = isFlow(f);
      html += `<div class="finding sev-${f.severity}">
        <button class="f-row" type="button" aria-expanded="false" aria-controls="fd-${i}" data-i="${i}">
          ${ic('chevron', 'sm chev')}
          ${pill(f.severity)}
          <span class="f-main"><span class="f-title" dir="auto">${esc(titleOf(f))}</span>
            <span class="f-meta"><code dir="ltr">${esc(f.rule_id)}</code><span class="sep">·</span><span class="loc">${esc(f.file)}${f.line ? ':' + f.line : ''}</span></span></span>
          <span class="f-side">${flow ? `<span class="tag flow">${ic('flow')}${esc(t('find.dataflow'))}</span>` : ''}${f.cwe ? `<span class="tag">${esc(f.cwe)}</span>` : ''}</span>
        </button>
        <div class="f-detail" id="fd-${i}" hidden></div>
      </div>`;
    });
    setHTML($('#findings-list'), html);
  }
  const clr = $('#clear-filters');
  if (clr) clr.onclick = () => { SEV.forEach((s) => sevOn.add(s)); $('#findings-search').value = ''; $('#source-filter').value = ''; renderChips(); renderFindings(); };
}
$('#findings-list').addEventListener('click', (e) => {
  const row = e.target.closest('.f-row'); if (!row) return;
  const box = row.parentElement; const det = box.querySelector('.f-detail');
  const open = row.getAttribute('aria-expanded') !== 'true';
  if (open && !det.dataset.ready) { setHTML(det, detailHTML(shown[+row.dataset.i])); det.dataset.ready = '1'; }
  row.setAttribute('aria-expanded', String(open)); det.hidden = !open; box.classList.toggle('open', open);
});
const stripKind = (s) => String(s || '').replace(/^(Source|Sink|المصدر|نقطة الخطر)\s*:\s*/, '');
function trailHTML(f) {
  const steps = (f.extra.path || []).map((st) => {
    const ar = st.text || ''; const en = st.text_en;
    const text = lang === 'en' ? (en ?? ar) : ar;
    const code = !ARABIC.test(ar) && (en === undefined || en === ar);
    return {file: st.file, line: st.line, text: stripKind(text), code};
  });
  if (steps.length < 2) {  // the engine recorded only the sink: show the tainted input as the source
    const src = stripKind(loc(f, 'snippet')) || (f.extra && loc(f.extra, 'taint_source')) || '';
    steps.unshift({file: '', line: 0, text: src, code: !ARABIC.test(src) && /[.()[\]=]/.test(src)});
  }
  const n = steps.length;
  return `<ol class="trail">${steps.map((st, i) => {
    const kind = i === 0 ? 'src' : i === n - 1 ? 'sink' : 'mid';
    const label = kind === 'src' ? t('find.source') : kind === 'sink' ? t('find.sink') : `${t('find.step')} ${i + 1}`;
    const node = kind === 'src' ? ic('globe') : kind === 'sink' ? ic('warning') : String(i + 1);
    const where = st.file ? `${st.file}${st.line ? ':' + st.line : ''}` : '';
    return `<li class="${kind}"><span class="node" aria-hidden="true">${node}</span><div class="step"><div class="st-head"><span class="st-kind">${esc(label)}</span>${where ? `<span class="st-loc" title="${esc(where)}">${esc(where)}</span>` : ''}</div><div class="st-text${st.code ? ' c' : ''}"${st.code ? ' dir="ltr"' : ''}>${st.code ? esc(st.text) : bidi(st.text)}</div></div></li>`;
  }).join('')}</ol>`;
}
function detailHTML(f) {
  const flow = isFlow(f); const x = f.extra || {};
  const where = `${f.file}${f.line ? ':' + f.line : ''}`;
  const i = Math.max(f.file.lastIndexOf('/'), f.file.lastIndexOf('!'));
  const dir = i >= 0 ? f.file.slice(0, i + 1) : ''; const base = f.file.slice(i + 1);
  const tags = [pill(f.severity), `<span class="tag code" dir="ltr">${esc(f.rule_id)}</span>`, cweTag(f.cwe),
    flow ? `<span class="tag flow">${ic('shield')}${esc(t('find.dataflow'))}</span>` : `<span class="tag">${ic('pattern')}${esc(t('find.pattern'))}</span>`,
    `<span class="tag" title="${esc(f.source)}">${ic('code')}${esc(srcName(f.source))}</span>`,
    x.decompiled ? '<span class="tag">jadx</span>' : '',
    x.page_count > 1 ? `<span class="tag">${esc(t('find.onPages', {n: x.page_count}))}</span>` : ''].join('');
  let body = `<section class="d-sec"><h2>${ic('file')}${esc(t('find.location'))}</h2><div class="locbar">${ic('file')}<span class="p" title="${esc(where)}">${esc(dir)}<b>${esc(base)}</b>${f.line ? ':' + f.line : ''}</span>${copyBtn(where)}</div></section>`;
  if (flow && x.path && x.path.length) {
    body += `<section class="d-sec"><h2>${ic('flow')}${esc(t('find.flow'))}</h2>${trailHTML(f)}</section>`;
  } else if (f.snippet) {
    const snip = loc(f, 'snippet');
    body += `<section class="d-sec"><h2>${ic('code')}${esc(t('find.snippet'))}</h2><div class="code"><div class="code-head"><span class="p">${esc(where)}</span>${copyBtn(snip)}</div><pre><span class="ln">${f.line || ''}</span><code>${esc(snip)}</code></pre></div></section>`;
  }
  const adv = loc(f, 'advice');
  if (adv) body += `<section class="d-sec"><div class="remedy">${ic('bulb')}<div><b>${esc(t('find.advice'))}</b><span>${bidi(adv)}</span></div></div></section>`;
  if (x.url) body += `<section class="d-sec"><h2>${ic('link')}${esc(t('find.ref'))}</h2><a href="${esc(x.url)}" target="_blank" rel="noopener noreferrer" dir="ltr">${esc(x.url)} ${ic('external', 'xs')}</a></section>`;
  if (x.pages && x.pages.length > 1) body += `<section class="d-sec"><details><summary>${esc(t('find.onPages', {n: x.pages.length}))}</summary><ul class="pages-list">${x.pages.slice(0, 50).map((u) => `<li>${esc(u)}</li>`).join('')}</ul></details></section>`;
  if (f.fingerprint) body += `<div class="fp">${ic('hash')}<span>${esc(t('find.fingerprint'))}</span><code>${esc(f.fingerprint)}</code>${copyBtn(f.fingerprint)}</div>`;
  return `<div class="sev-${f.severity}"><div class="d-tags">${tags}</div><div class="d-grid">${body}</div></div>`;
}

/* ------------------------------------------------------------- reports */
async function loadReports() {
  const scans = await api('/api/scans');
  setHTML($('#reports-table'), scanRows(scans));
  const opts = scans.filter((s) => s.status === 'done').map((s) => `<option value="${esc(s.id)}">${esc(scanName(s))} — ${esc(fmtDate(s.finished_at))}</option>`).join('');
  setHTML($('#cmp-a'), opts); setHTML($('#cmp-b'), opts); if ($('#cmp-a').options.length > 1) $('#cmp-a').selectedIndex = 1;
  $('#cmp-btn').disabled = !opts;
}
$('#cmp-btn').onclick = async () => {
  if (!$('#cmp-a').value || !$('#cmp-b').value) return;
  const a = await api(`/api/scans/${$('#cmp-a').value}`), b = await api(`/api/scans/${$('#cmp-b').value}`);
  const key = (f) => `${f.rule_id}|${f.file.replace(/^[^!]*!/, '')}|${f.snippet}`;
  const ka = new Set(a.findings.map(key)), kb = new Set(b.findings.map(key));
  const fixed = a.findings.filter((f) => !kb.has(key(f))), added = b.findings.filter((f) => !ka.has(key(f)));
  setHTML($('#cmp-tiles'), SEV.map((s) => {
    const d = (b.summary[s] || 0) - (a.summary[s] || 0);
    return `<div class="tile sev-${s}${d ? '' : ' zero'}"><span class="l"><span class="dot"></span>${esc(sevName(s))}</span><span class="n ${d > 0 ? 'up' : d < 0 ? 'down' : ''}" dir="ltr">${d > 0 ? '+' : d < 0 ? '−' : ''}${Math.abs(d)}</span></div>`;
  }).join(''));
  const li = (f) => `<li class="sev-${f.severity}"><span class="main">${pill(f.severity)}<span class="rid" dir="ltr">${esc(f.rule_id)}</span>${fpath(f.file, f.line)}</span></li>`;
  $('#cmp-fixed-n').textContent = fixed.length; $('#cmp-new-n').textContent = added.length;
  setHTML($('#cmp-fixed'), fixed.map(li).join('') || `<li class="empty-li">${esc(t('rep.nothing'))}</li>`);
  setHTML($('#cmp-new'), added.map(li).join('') || `<li class="empty-li">${esc(t('rep.nothing'))}</li>`);
  $('#cmp-result').classList.remove('hidden');
};

/* --------------------------------------------------------------- rules */
let rulesCache = null;
async function loadRules() {
  rulesCache = rulesCache || await api('/api/rules');
  $('#rules-count').textContent = `${rulesCache.length} ${t('rules.count')}`;
  renderRules();
}
$('#rules-search').oninput = renderRules;
const langsOf = (r) => (lang === 'en' && Array.isArray(r.langs_en) ? r.langs_en : r.langs) || [];
function renderRules() {
  if (!rulesCache) return;
  const q = $('#rules-search').value.trim().toLowerCase();
  const rows = rulesCache.filter((r) => !q || [r.id, r.title, r.title_ar, r.cwe, r.advice, r.advice_en, ...(r.langs || []), ...(r.langs_en || [])].join(' ').toLowerCase().includes(q));
  setHTML($('#rules-table'), `<thead><tr><th>${esc(t('rules.id'))}</th><th>${esc(t('rules.sev'))}</th><th>${esc(t('rules.name'))}</th><th>${esc(t('rules.advice'))}</th><th>${esc(t('rules.langs'))}</th></tr></thead><tbody>` +
    rows.map((r) => `<tr><td class="rid"><code dir="ltr">${esc(r.id)}</code><div style="margin-top:6px">${cweTag(r.cwe)}</div></td><td>${pill(r.severity)}</td><td class="ttl"><b dir="auto">${esc(titleOf(r))}</b></td><td class="adv">${bidi(loc(r, 'advice')) || '<span class="muted">—</span>'}</td><td><div class="langs">${esc(langsOf(r).slice(0, 8).join(' '))}${langsOf(r).length > 8 ? ' …' : ''}</div></td></tr>`).join('') + '</tbody>');
}

/* ------------------------------------------------------------ settings */
async function loadSettings(arg) {
  const [s, meta] = await Promise.all([api('/api/settings'), api('/api/meta')]);
  const f = $('#settings-form');
  f.min_severity.value = s.min_severity; f.web_timeout.value = s.web_timeout || 20; f.web_delay.value = s.web_delay != null ? s.web_delay : 0.5; f.fail_on.value = s.fail_on; f.keep_scans.value = s.keep_scans;
  f.exclude.value = s.exclude.join('\n'); f.ignore_rules.value = s.ignore_rules.join('\n'); f.authorized_targets.value = s.authorized_targets.join('\n');
  f.use_osv.checked = !!s.use_osv; f.use_external.checked = !!s.use_external;
  f.audit.checked = !!s.audit; f.use_jadx.checked = !!s.use_jadx; f.jadx_include_libs.checked = !!s.jadx_include_libs; f.jadx_timeout.value = s.jadx_timeout;
  f.models_dir.value = s.models_dir || ''; f.queries_dir.value = s.queries_dir || '';
  $('#jadx-state').textContent = meta.jadx ? t('set.jadxOn') : t('set.jadxOff');
  $('#ext-tools').textContent = `(${meta.external_tools.length ? meta.external_tools.join(', ') : t('set.none')})`;
  setHTML($('#settings-home'), `${esc(t('set.home'))}<span class="home-path" dir="ltr" title="${esc(meta.home)}">${esc(meta.home)}</span>`);
  $('#version').textContent = 'v' + meta.version;
  f.check_updates.checked = s.check_updates !== false;
  updAuto = f.check_updates.checked;
  renderUpdate();
  if (!upd.data && !upd.err && !upd.busy && !upd.job) updCheck(false);
  if (arg === 'update') $('#upd-sec').scrollIntoView({block: 'start'});
}
$('#settings-form').onsubmit = async (e) => {
  e.preventDefault(); const f = e.target; const lines = (v) => v.split('\n').map((x) => x.trim()).filter(Boolean);
  try {
    await api('/api/settings', {method: 'POST', body: JSON.stringify({min_severity: f.min_severity.value, web_timeout: Math.min(120, Math.max(5, +f.web_timeout.value || 20)), web_delay: Math.min(10, Math.max(0, +f.web_delay.value || 0)), fail_on: f.fail_on.value, keep_scans: +f.keep_scans.value,
      exclude: lines(f.exclude.value), ignore_rules: lines(f.ignore_rules.value), authorized_targets: lines(f.authorized_targets.value), use_osv: f.use_osv.checked, use_external: f.use_external.checked,
      audit: f.audit.checked, use_jadx: f.use_jadx.checked, jadx_include_libs: f.jadx_include_libs.checked, jadx_timeout: +f.jadx_timeout.value,
      models_dir: f.models_dir.value.trim(), queries_dir: f.queries_dir.value.trim(), check_updates: f.check_updates.checked})});
  } catch (err) { toast(err.message); return; }
  const m = $('#settings-saved'); setHTML(m, `${ic('check', 'sm')}${esc(t('set.saved'))}`); clearTimeout(m._t); m._t = setTimeout(() => { m.textContent = ''; }, 2400);
};


/* ------------------------------------------------------------- updates */
/* GET /api/update checks GitHub (cached 6 h server-side); POST /api/update installs a newer binary in the background. */
const upd = {data: null, err: null, busy: false, job: null, restarting: false};
let updAuto = true;
const RELEASES = 'https://github.com/abdulrahmanahmedelabed-prog/vulnscan/releases/latest';
const updErr = (j) => { const k = 'upd.err.' + (j && j.error); return I18N[lang][k] ? t(k) : ((lang === 'en' ? j && j.message_en : j && j.message) || t('upd.err.offline')); };
const relTime = (ts) => {
  const s = Math.round(ts - Date.now() / 1000); const rtf = new Intl.RelativeTimeFormat(locale(), {numeric: 'auto'});
  const a = Math.abs(s);
  return a < 60 ? rtf.format(0, 'second') : a < 3600 ? rtf.format(Math.round(s / 60), 'minute') : a < 86400 ? rtf.format(Math.round(s / 3600), 'hour') : rtf.format(Math.round(s / 86400), 'day');
};
const fmtMB = (n) => (n / 1048576).toLocaleString(locale(), {maximumFractionDigits: 1});
async function updRequest(path, opts) {
  const r = await fetch(path, {headers: {'Content-Type': 'application/json'}, ...opts});
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(updErr(j)); e.info = j; throw e; }
  return j;
}
async function updCheck(force) {
  upd.busy = true; upd.err = null; renderUpdate();
  try { upd.data = await updRequest('/api/update' + (force ? '?force=1' : '')); } catch (e) { upd.err = e.info && e.info.error ? e.info : {error: 'offline'}; }
  upd.busy = false; renderUpdate();
}
function renderPill() {
  const p = $('#upd-pill'); const d = upd.data;
  const on = !!(d && d.newer && !d.disabled);
  p.classList.toggle('hidden', !on);
  if (!on) return;
  $('.upd-pill-text', p).textContent = t('upd.pill', {v: 'v' + d.latest});
  p.title = t('upd.pillTitle', {v: 'v' + d.latest}); p.setAttribute('aria-label', p.title);
}
function renderUpdate() {
  renderPill();
  const d = upd.data; const job = upd.job;
  const icon = $('#upd-icon'); const title = $('#upd-title'); const sub = $('#upd-sub');
  const show = (sel, on) => $(sel).classList.toggle('hidden', !on);
  const setIcon = (cls, html) => { icon.className = 'upd-icon ' + cls; setHTML(icon, html); };
  $('#upd-current').textContent = 'v' + ((d && d.current) || (meta && meta.version) || '');
  $('#upd-latest').textContent = d && d.latest ? 'v' + d.latest : '—';
  const kind = d && d.install_kind;
  $('#upd-kind').textContent = kind ? t({binary: 'upd.kindBinary', pip: 'upd.kindPip', source: 'upd.kindSource'}[kind] || kind) : '—';
  const working = job && ['check', 'download', 'verify', 'swap'].includes(job.phase);
  $('#upd-check').disabled = upd.busy || working || upd.restarting;
  show('#upd-check', true); show('#upd-apply', false); show('#upd-restart', false); show('#upd-cmd', false); show('#upd-progress-wrap', false);
  // release notes (plain text, never HTML)
  const hasNotes = !!(d && d.newer && d.notes);
  show('#upd-notes', hasNotes);
  if (hasNotes) { $('#upd-notes-body').textContent = d.notes; $('#upd-link').href = /^https:\/\/github\.com\/abdulrahmanahmedelabed-prog\/vulnscan\/releases\//.test(d.url || '') ? d.url : RELEASES; }

  if (upd.restarting) { setIcon('new', '<span class="spinner"></span>'); title.textContent = t('upd.restarting'); sub.textContent = upd.restartSlow ? t('upd.restartSlow') : ''; return; }
  if (job && job.phase !== 'idle') {
    if (working) {
      setIcon('new', '<span class="spinner"></span>'); title.textContent = t('upd.available', {v: d ? 'v' + d.latest : ''}); sub.textContent = t('upd.phase.' + job.phase);
      show('#upd-progress-wrap', true);
      $('#upd-phase').textContent = t('upd.phase.' + job.phase);
      const bar = $('#upd-progress'); const pct = job.phase === 'download' && job.total ? Math.min(100, Math.round(job.bytes * 100 / job.total)) : null;
      bar.classList.toggle('indeterminate', pct === null); $('div', bar).style.width = pct === null ? '' : pct + '%';
      if (pct === null) bar.removeAttribute('aria-valuenow'); else bar.setAttribute('aria-valuenow', pct);
      bar.setAttribute('aria-label', t('upd.phase.' + job.phase));
      $('#upd-bytes').textContent = job.phase === 'download' && job.bytes ? (job.total ? `${fmtMB(job.bytes)} / ${fmtMB(job.total)} MB` : `${fmtMB(job.bytes)} MB`) : '';
      return;
    }
    if (job.phase === 'done') {
      setIcon('ok', ic('check')); title.textContent = t('upd.doneTitle', {v: job.result ? 'v' + job.result.to : ''}); sub.textContent = t('upd.doneSub');
      show('#upd-restart', true); show('#upd-check', false); return;
    }
    if (job.phase === 'error') {
      setIcon('err', ic('warning')); title.textContent = t('upd.updateFailed'); sub.textContent = updErr(job);
      show('#upd-apply', !!(d && d.can_self_update && d.newer && job.error !== 'restart_failed')); return;
    }
  }
  if (upd.busy) { setIcon('', '<span class="spinner"></span>'); title.textContent = t('upd.checking'); sub.textContent = ''; return; }
  if (upd.err) { setIcon('err', ic('warning')); title.textContent = t('upd.failed'); sub.textContent = updErr(upd.err); return; }
  if (!d || d.disabled) { setIcon('', ic('update')); title.textContent = d && d.disabled ? t('upd.disabled') : t('upd.check'); sub.textContent = d && d.disabled ? t('upd.disabledSub') : ''; return; }
  const checked = d.checked_at ? ' ' + t('upd.checked', {when: relTime(d.checked_at)}) : '';
  if (!d.newer) { setIcon('ok', ic('check')); title.textContent = t('upd.uptodate'); sub.textContent = t('upd.uptodateSub', {v: 'v' + d.current}) + checked; return; }
  setIcon('new', ic('update'));
  title.textContent = t('upd.available', {v: 'v' + d.latest});
  const rel = d.published_at ? ' ' + t('upd.released', {date: new Date(d.published_at).toLocaleDateString(locale(), {dateStyle: 'medium'})}) : '';
  sub.textContent = t('upd.availableSub', {cur: 'v' + d.current}) + rel + checked;
  if (d.can_self_update) { show('#upd-apply', true); return; }
  // pip / source / not writable / unsupported: explain and show the exact command (or the download page)
  show('#upd-cmd', true);
  const reason = d.reason && d.reason !== 'not_binary' ? updErr({error: d.reason}) + ' ' : '';
  $('#upd-cmd-label').textContent = reason + (d.command ? t('upd.runCmd') : t('upd.manual'));
  $('.upd-cmd-box').classList.toggle('hidden', !d.command);
  $('#upd-cmd-text').textContent = d.command || '';
  setHTML($('#upd-cmd-copy'), d.command ? copyBtn(d.command) : '');
  if (!d.command) show('#upd-notes', true);
}
async function updPoll() {
  for (;;) {
    try { upd.job = await updRequest('/api/update/status'); } catch (e) { upd.job = {phase: 'error', ...(e.info || {error: 'offline'})}; }
    renderUpdate();
    if (!['check', 'download', 'verify', 'swap'].includes(upd.job.phase)) return;
    await new Promise((res) => setTimeout(res, 400));
  }
}
$('#upd-check').onclick = () => { upd.job = null; updCheck(true); };
$('#upd-apply').onclick = async () => {
  if (!upd.data || !confirm(t('upd.confirm', {v: upd.data.latest}))) return;
  try { upd.job = await updRequest('/api/update', {method: 'POST', body: '{}'}); } catch (e) { upd.job = {phase: 'error', ...(e.info || {error: 'offline'})}; renderUpdate(); return; }
  renderUpdate(); updPoll();
};
$('#upd-restart').onclick = async () => {
  const want = upd.job && upd.job.result ? upd.job.result.to : null;
  try { await updRequest('/api/update/restart', {method: 'POST', body: '{}'}); } catch (e) { upd.job = {phase: 'error', ...(e.info || {})}; renderUpdate(); return; }
  upd.restarting = true; renderUpdate();
  const t0 = Date.now();
  await new Promise((res) => setTimeout(res, 1200));
  for (;;) {
    try { const m = await (await fetch('/api/meta', {cache: 'no-store'})).json(); if (!want || m.version === want) { location.reload(); return; } } catch { /* server still restarting */ }
    try { // the old server is still answering: did starting the new binary fail?
      const j = await (await fetch('/api/update/status', {cache: 'no-store'})).json();
      if (j.restart_error) { upd.restarting = false; upd.job = {...j, phase: 'error', error: 'restart_failed', detail: j.restart_error}; renderUpdate(); return; }
    } catch { /* server still restarting */ }
    if (Date.now() - t0 > 45000 && !upd.restartSlow) { upd.restartSlow = true; renderUpdate(); }
    await new Promise((res) => setTimeout(res, 700));
  }
};
$('#f-upd-auto').onchange = async (e) => {
  updAuto = e.target.checked;
  try { await api('/api/settings', {method: 'POST', body: JSON.stringify({check_updates: updAuto})}); } catch (err) { toast(err.message); }
};

/* ---------------------------------------------------------------- boot */
let meta = null;
const jadxHint = () => { if (meta) $('#jadx-hint').textContent = meta.jadx ? t('scan.jadxOn') : t('scan.jadxOff'); };
api('/api/meta').then((m) => { meta = m; $('#version').textContent = 'v' + m.version; jadxHint(); }).catch(() => {});
applyLang(); route();
/* One quiet check at start (the server honours the "check updates automatically" setting and its 6-hour cache). */
if (curPage !== 'settings') updRequest('/api/update').then((d) => { upd.data = d; renderPill(); }).catch(() => {});
updRequest('/api/update/status').then((j) => { if (j.phase !== 'idle') { upd.job = j; renderUpdate(); if (['check', 'download', 'verify', 'swap'].includes(j.phase)) updPoll(); } }).catch(() => {});
