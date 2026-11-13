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
    'dash.allScans': 'كل الفحوصات', 'dash.latest': 'آخر فحص', 'dash.oneScan': 'فحص واحد حتى الآن. أجرِ فحوصات أخرى لترى الاتجاه عبر الزمن.', 'dash.total': 'نتيجة إجمالًا',
    'scan.title': 'فحص جديد', 'scan.sub': 'افحص مجلدًا على هذا الجهاز، أو ارفع برنامجًا مضغوطًا أو ملفات، أو افحص عنوان ويب تملكه.',
    'scan.tabPath': 'مسار على الجهاز', 'scan.tabUpload': 'رفع ملفات / أرشيف', 'scan.tabUrl': 'عنوان ويب', 'scan.pathLabel': 'مسار المجلد أو الملف أو الأرشيف', 'scan.start': 'ابدأ الفحص',
    'scan.pathHint': 'يُفحص المجلد بكل محتوياته (تُتجاهل node_modules و .git و build تلقائيًا).', 'scan.drop': 'اسحب وأفلت هنا برنامجًا مضغوطًا (zip / apk / jar / tar.gz / whl) أو أي ملفات',
    'scan.chooseFiles': 'اختر ملفات', 'scan.chooseFolder': 'اختر مجلدًا كاملًا', 'scan.uploadStart': 'ارفع وافحص', 'scan.urlLabel': 'عنوان الموقع (فحص سلبي: طلبات GET محدودة، بلا أي اختبار نشط)',
    'scan.authorize': 'أقرّ بأنني مالك هذا الموقع أو لديّ تصريح كتابي بفحصه', 'scan.deep': 'فحص أعمق: تحليل الصفحة وفحص مسارات مكشوفة شائعة (طلبات إضافية محدودة)', 'scan.crawl': 'زحف على صفحات الموقع وفحصها (لتطبيقات مثل Moodle وبوابات الجامعات)', 'scan.legal': 'فحص أنظمة الآخرين دون إذن قد يكون مخالفًا للقانون.', 'scan.viewResults': 'عرض النتائج',
    'scan.running': 'جارٍ الفحص…', 'scan.done': 'اكتمل الفحص', 'scan.failed': 'فشل الفحص', 'scan.needAuth': 'يجب تأكيد الصلاحية أولًا', 'scan.uploading': 'جارٍ الرفع…', 'scan.uploadFailed': 'تعذّر الرفع',
    'scan.jadxOn': 'jadx مثبّت: سيُفكّ تجميع APK/JAR/AAR/DEX ويُفحص الكود الناتج أيضًا.', 'scan.jadxOff': 'jadx غير مثبّت: تُفحص الملفات النصية داخل APK/JAR فقط. ثبّت jadx (يحتاج Java) لفك تجميع الكود.',
    'find.title': 'النتائج', 'find.sub': 'مرتبة من الأعلى خطورة إلى الأقل. اضغط على أي نتيجة لعرض التفاصيل وطريقة الإصلاح.', 'find.search': 'ابحث في الملف أو القاعدة أو النص…', 'find.allSources': 'كل المصادر',
    'find.none': 'لا نتائج مطابقة للمرشحات الحالية.', 'find.flow': 'مسار التدفق (من المصدر إلى نقطة الخطر)',
    'find.advice': 'طريقة الإصلاح', 'find.snippet': 'المقتطف', 'find.ref': 'المرجع', 'find.scan': 'الفحص', 'find.export': 'تصدير',
    'find.dataflow': 'مُثبتة بتدفق البيانات', 'find.pattern': 'مطابقة نمط', 'find.location': 'الموقع', 'find.source': 'المصدر', 'find.sink': 'نقطة الخطر', 'find.step': 'خطوة',
    'find.fingerprint': 'البصمة', 'find.copy': 'نسخ', 'find.copied': 'تم النسخ', 'find.cwe': 'افتح تعريف {cwe} على موقع MITRE', 'find.input': 'المدخل غير الموثوق', 'find.clear': 'إظهار الكل',
    'rep.title': 'التقارير', 'rep.sub': 'سجل كل الفحوصات، تنزيل التقارير، ومقارنة فحصين لمعرفة ما أُصلح وما استجد.', 'rep.compare': 'مقارنة فحصين', 'rep.compareBtn': 'قارن', 'rep.fixed': 'أُصلحت (اختفت)', 'rep.new': 'جديدة (ظهرت)',
    'rep.target': 'الهدف', 'rep.date': 'التاريخ', 'rep.status': 'الحالة', 'rep.total': 'الإجمالي', 'rep.actions': 'إجراءات', 'rep.delete': 'حذف', 'rep.view': 'عرض', 'rep.nothing': 'لا شيء',
    'rep.base': 'الفحص الأساسي', 'rep.head': 'الفحص الأحدث', 'rep.history': 'سجل الفحوصات', 'rep.download': 'تنزيل تقرير HTML', 'rep.confirmDel': 'حذف هذا الفحص؟', 'rep.noScans': 'لا توجد فحوصات بعد.',
    'rules.title': 'القواعد المدمجة', 'rules.search': 'ابحث في القواعد…', 'rules.id': 'المعرّف', 'rules.sev': 'الخطورة', 'rules.name': 'الثغرة', 'rules.langs': 'الملفات', 'rules.advice': 'الإصلاح',
    'set.title': 'الإعدادات', 'set.sub': 'تُحفظ على هذا الجهاز وتُطبَّق على كل الفحوصات القادمة.', 'set.minSev': 'أدنى خطورة تُعرض', 'set.failOn': 'إفشال CI عند خطورة', 'set.exclude': 'مسارات مستثناة (سطر لكل نمط)',
    'set.ignore': 'قواعد متجاهَلة (معرّف لكل سطر)', 'set.authTargets': 'عناوين ويب مُصرَّح بفحصها (سطر لكل عنوان)', 'set.osv': 'الاستعلام من OSV.dev عن ثغرات الاعتماديات (يحتاج إنترنت)',
    'set.external': 'دمج نتائج الأدوات الخارجية المثبّتة', 'set.audit': 'ملف التدقيق: اعرض أيضًا كل استدعاء خطر لم يُثبت تحليل التدفق وصول مدخل إليه (أشمل، وإنذارات أكثر)', 'set.jadx': 'فك تجميع APK / JAR / AAR / DEX بواسطة jadx وفحص الكود الناتج', 'set.jadxLibs': 'فحص مكتبات الطرف الثالث داخل الكود المفكوك أيضًا (نتائج أكثر وضجيج أكثر)', 'set.jadxTimeout': 'مهلة jadx بالثواني', 'set.jadxOn': 'jadx مثبّت على هذا الجهاز.', 'set.jadxOff': 'jadx غير مثبّت — ثبّته من github.com/skylot/jadx ليُفكّ الكود الثنائي.',
    'set.models': 'مجلد نماذج إضافية لمحرّك تدفق البيانات (JSON: مصادر، نقاط خطر، مُعقّمات)', 'set.queries': 'مجلد استعلامات VQL إضافية (لغة استعلام تصريحية فوق قاعدة بيانات البرنامج)',
    'set.keep': 'عدد الفحوصات المحفوظة', 'set.webTimeout': 'مهلة طلب الويب بالثواني (يُعاد الطلب الأول مرة بمهلة مضاعفة)', 'set.webDelay': 'أقل فاصل بالثواني بين طلبين إلى الموقع نفسه، لكل الطلبات (الحد الأدنى 0.2)', 'set.save': 'حفظ', 'set.saved': 'تم الحفظ', 'set.home': 'مجلد البيانات', 'set.none': 'لا توجد أدوات مثبّتة',
    'set.secScope': 'النطاق والحدود', 'set.secScopeHint': 'ما يُعرض من النتائج ومتى يفشل التكامل المستمر.', 'set.secAnalysis': 'التحليل والتكاملات', 'set.secAnalysisHint': 'مصادر إضافية للنتائج ودرجة الشمول.',
    'set.secBinary': 'الملفات الثنائية (jadx)', 'set.secWeb': 'فحص الويب', 'set.secWebHint': 'فحص سلبي ولطيف للمواقع المصرّح بها فقط.', 'set.secStorage': 'التخزين',
    'about.title': 'حول كاشِف', 'about.hint': 'فاحص أمان مفتوح المصدر للكود والتطبيقات.', 'about.name': 'كاشِف', 'about.by': 'من تطوير دائرة البرمجة في الجامعة الإسلامية بغزة.', 'about.contact': 'للتواصل', 'about.license': 'الترخيص',
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
    'nav.projects': 'المشاريع', 'proj.title': 'المشاريع', 'proj.sub': 'كل هدف فحصته، مع آخر نتائجه واتجاهه وما تغيّر بين آخر فحصين.',
    'proj.search': 'ابحث باسم المشروع أو مساره…', 'proj.sort': 'الترتيب', 'proj.sortRecent': 'الأحدث فحصًا', 'proj.sortRisk': 'الأعلى خطورة', 'proj.sortName': 'الاسم',
    'proj.all': 'كل المشاريع', 'proj.switch': 'المشروع', 'proj.rescan': 'أعد الفحص', 'proj.changes': 'التغيّر منذ الفحص السابق', 'proj.trend': 'اتجاه النتائج عبر فحوصات المشروع',
    'proj.scans': 'فحوصات المشروع', 'proj.none': 'لا مشروع يطابق البحث.', 'proj.lastScan': 'آخر فحص',
    'proj.noChange': 'لا تغيّر عن الفحص السابق', 'proj.firstScan': 'فحص واحد حتى الآن',
    'proj.firstScanHint': 'أعد فحص المشروع بعد تعديله لترى هنا ما استجد وما أُصلح.', 'proj.clean': 'لا نتائج', 'proj.history': 'الفحوصات والسجل',
    'proj.neverDone': 'لم يكتمل أي فحص بعد', 'proj.between': 'بين فحص {a} وفحص {b}',
    'proj.newTitle': 'جديدة (ظهرت)', 'proj.fixedTitle': 'أُصلحت (اختفت)', 'proj.notFound': 'المشروع غير موجود (ربما حُذفت فحوصاته).', 'proj.dupHint': 'مشاريع',
    'fix.title': 'إصلاح مقترح', 'fix.copy': 'نسخ الرقعة', 'fix.copied': 'نُسخت الرقعة', 'fix.adviceOnly': 'إرشاد فقط: هذا التغيير يحتاج إلى إعادة هيكلة لا يمكن أتمتتها بأمان.',
    'fix.apply': 'لتطبيق الإصلاحات الآلية على المشروع شغّل:', 'fix.added': 'سطر مضاف:', 'fix.removed': 'سطر محذوف:', 'fix.diffLabel': 'رقعة الإصلاح المقترح للملف {file}', 'fix.badge': 'إصلاح متاح',
    'fix.stats': 'مضاف {a}، محذوف {d}',
    'nav.compliance': 'الامتثال', 'find.compliance': 'الامتثال', 'a11y.export': 'تنزيل النتائج بصيغ أخرى',
    'exp.more': 'صيغ أخرى', 'exp.title': 'صيغ التصدير', 'exp.hint': 'تُطبَّق قرارات الفرز: تُستبعد الإنذارات الكاذبة والنتائج المُصلحة من الصيغ التي تدعم ذلك.',
    'exp.aws': 'رقم حساب AWS (12 رقمًا)', 'exp.region': 'منطقة AWS', 'exp.download': 'تنزيل', 'exp.needAws': 'أدخل رقم حساب AWS من 12 رقمًا ومنطقة مثل us-east-1.', 'exp.loadFail': 'تعذّر تحميل قائمة الصيغ.',
    'comp.title': 'الامتثال', 'comp.sub': 'كيف تتوزع نتائج الفحص على ضوابط الأطر الأمنية والتنظيمية. هذا دليل يدعم التقييم، لا شهادة امتثال.',
    'comp.audit': 'تقرير المدقق', 'comp.auditOne': 'تقرير المدقق لهذا الإطار', 'comp.frameworks': 'الأطر', 'comp.showAll': 'إظهار الضوابط بلا نتائج',
    'comp.risk': 'درجة الخطر', 'comp.r_none': 'لا خطر', 'comp.r_low': 'منخفض', 'comp.r_moderate': 'متوسط', 'comp.r_high': 'عالٍ', 'comp.r_critical': 'حرج',
    'comp.st_fail': 'راسب', 'comp.st_warn': 'مراجعة', 'comp.st_pass': 'لا نتائج',
    'comp.control': 'الضابط', 'comp.ctitle': 'العنوان', 'comp.total': 'النتائج', 'comp.status': 'الحالة',
    'comp.note': 'ملاحظة', 'comp.source': 'المصدر', 'comp.none': 'لا ضوابط عليها نتائج في هذا الإطار.',
    'comp.showFindings': 'عرض نتائج الضابط {c}', 'comp.empty': 'لا يوجد فحص مكتمل بعد.', 'comp.loading': 'جارٍ التحميل…',
    'tri.title': 'الفرز', 'tri.status': 'الحالة', 'tri.justification': 'المبرّر', 'tri.justReq': '(مطلوب لهذه الحالة)', 'tri.expires': 'ينتهي القبول في', 'tri.ticket': 'رابط التذكرة',
    'tri.comment': 'تعليق', 'tri.save': 'احفظ القرار', 'tri.addComment': 'أضف التعليق', 'tri.saved': 'حُفظ قرار الفرز', 'tri.commented': 'أُضيف التعليق', 'tri.history': 'السجل ({n})',
    'tri.by': '{who} · {when}', 'tri.fileProject': 'تُحفظ القرارات مع المشروع في {file}؛ أضفه إلى المستودع ليشاركها الفريق.', 'tri.fileHome': 'تُحفظ القرارات في مجلد بيانات كاشِف: {file}',
    'tri.filter': 'حالة الفرز', 'tri.all': 'كل الحالات', 'tri.showFp': 'إظهار الإنذارات الكاذبة', 'tri.hiddenFp': 'مخفية لأنها إنذارات كاذبة: {n}',
    'tri.expired': 'انتهى قبول الخطر', 'tri.regression': 'تراجع: ظهرت من جديد بعد إصلاحها', 'tri.untracked': 'لم يُسجَّل قرار بعد.', 'tri.needJust': 'هذه الحالة تتطلب مبرّرًا.',
    'tri.loadFail': 'تعذّرت قراءة ملف الفرز: {err}', 'tri.act.status': 'غيّر الحالة', 'tri.act.comment': 'علّق', 'tri.act.severity': 'غيّر الخطورة', 'tri.act.expired': 'انتهى القبول', 'tri.act.regression': 'تراجع', 'tri.act.auto': 'تحديث آلي',
    'tri.ticketBad': 'رابط التذكرة يجب أن يبدأ بـ http:// أو https://', 'tri.fixOnly': 'النتائج التي لها إصلاح مقترح فقط',
    'sf.title': 'سطح الهجوم', 'sf.hint': 'نقاط الدخول إلى المشروع كما يجدها التحليل الساكن: المسارات ومعالجاتها وهل تظهر عليها مصادقة. لا يُرسَل أي طلب ولا يُشغَّل أي كود.',
    'sf.build': 'ابنِ الخريطة', 'sf.rebuild': 'أعد البناء', 'sf.engine': 'تتبّع تدفق البيانات من كل نقطة دخول إلى نقاط الخطر (أبطأ)', 'sf.running': 'جارٍ بناء خريطة سطح الهجوم…',
    'sf.unavailable': 'تُبنى الخريطة لمجلد محلي فُحص من هذا الجهاز فقط (لا للملفات المرفوعة ولا لعناوين الويب).', 'sf.none': 'لم تُبنَ خريطة لآخر فحص بعد.', 'sf.error': 'تعذّر بناء الخريطة: {err}',
    'sf.entries': 'نقاط الدخول', 'sf.unauth': 'بلا مصادقة ظاهرة', 'sf.unauthSink': 'بلا مصادقة وتصل إلى نقطة خطر', 'sf.withFindings': 'عليها نتائج',
    'sf.risk': 'الخطر', 'sf.method': 'الطريقة', 'sf.path': 'المسار', 'sf.handler': 'المعالج', 'sf.auth': 'المصادقة', 'sf.sinks': 'نقاط الخطر', 'sf.findings': 'النتائج',
    'sf.auth_none': 'غير ظاهرة', 'sf.auth_public': 'عامة صراحةً', 'sf.auth_protected': 'محمية', 'sf.showAll': 'عرض الكل ({n})', 'sf.showLess': 'عرض الأخطر فقط', 'sf.openapi': 'OpenAPI',
    'sf.builtAt': 'بُنيت {when}', 'sf.unauthOnly': 'بلا مصادقة فقط', 'sf.empty': 'لم يُعثر على نقاط دخول.', 'sf.search': 'ابحث في المسار أو المعالج…', 'sf.shown': 'عرض {n} من {total}', 'sf.noMatch': 'لا نقاط دخول تطابق المرشحات.',
    'reach.imported': 'مستوردة في كودك', 'reach.not_imported': 'غير مستوردة', 'reach.vulnerable_function_called': 'دالة مصابة مُستدعاة', 'reach.label': 'قابلية الوصول',
    /* 1.1.0 passive web scanning */
    'scan.profile': 'ملف الفحص', 'scan.pMinimal': 'minimal: الصفحة وتوجيهاتها فقط (10 طلبات على الأكثر)',
    'scan.pStandard': 'standard (الافتراضي): الملفات المعروفة وسكربتات الصفحة (45 طلبًا على الأكثر)',
    'scan.pDeep': 'deep: يضيف الملفات المكشوفة الشائعة (150 طلبًا على الأكثر)', 'scan.sens': 'الحساسية', 'scan.sStrict': 'strict: المؤكَّدة فقط',
    'scan.sDefault': 'default: المؤكَّدة والمرجَّحة', 'scan.sParanoid': 'paranoid: كل شيء مع الفحوص الإضافية', 'scan.compare': 'قارن بآخر فحص لهذا الموقع',
    'scan.robots': 'تجاهل robots.txt عند الزحف (لمالك الموقع)', 'scan.thirdParty': 'اسمح باستعلامات لدى أطراف ثالثة تكشف اسم الموقع (مثل hstspreload.org)',
    'scan.noProxy': 'لا تستخدم الوكيل (proxy) المعرَّف في النظام', 'web.grades': 'الدرجات',
    'web.provisional': 'درجة مؤقتة (*): بعض المجموعات لم تُفحص فلم تُحسب', 'web.caps': 'حدود الدرجة', 'web.none': 'لم تُحسب', 'web.coverage': 'تغطية الفحوص',
    'web.covNote': 'الفحص الذي لم يُجرَ أو كان غير حاسم لا يُعدّ ناجحًا ولا يدخل في الدرجة.', 'web.covDetails': 'الفحوص التي لم تنجح أو لم تُجرَ',
    'web.check': 'الفحص', 'web.state': 'الحالة', 'web.reason': 'السبب', 'web.inventory': 'جرد الموقع', 'web.empty': 'لا شيء مسجَّل',
    'web.remediation': 'إصلاحات جاهزة للنسخ', 'web.remHint': 'إعدادات المنصّات المكتشفة في الموقع تظهر أولًا.', 'web.caution': 'تنبيه',
    'web.diff': 'مقارنة بالفحص السابق', 'web.dNew': 'نتائج جديدة', 'web.dResolved': 'نتائج حُلّت', 'web.dUnchanged': 'نتائج لم تتغير',
    'web.dPosture': 'تغييرات في الوضع الأمني', 'web.dGrades': 'تغيّر الدرجات', 'web.dNone': 'لا تغييرات', 'web.confidence': 'الثقة', 'web.c_certain': 'مؤكَّدة',
    'web.c_firm': 'مرجَّحة', 'web.c_tentative': 'محتملة', 'web.page': 'الصفحة', 'web.curl': 'أمر يعيد الطلب نفسه', 'web.mapping': 'ربط المحللين (WSTG وASVS)',
    'web.profile': 'ملف الفحص', 'web.requests': 'الطلبات', 'web.final': 'العنوان النهائي', 'web.data': 'بيانات الويب بتاريخ',
    'web.loadFail': 'تعذّر تحميل تفاصيل فحص الموقع: {err}', 'set.webProfile': 'ملف فحص المواقع الافتراضي', 'set.webSens': 'الحساسية الافتراضية',
    'set.webCompare': 'قارن كل فحص بآخر فحص للموقع نفسه', 'set.webRobots': 'احترم robots.txt عند الزحف',
    'set.web3p': 'اسمح باستعلامات لدى أطراف ثالثة (مثل hstspreload.org)', 'set.webProxy': 'استخدم الوكيل (proxy) المعرَّف في النظام',
    /* Count strings, read with tn(key, count). Arabic nouns take a different form after 1, 2, 3–10, 11–99 and
       100+ (and 0): keys one, two, few, many, other (see pluralCat). The keys marked "by total" agree with {total}. */
    pl: {
      'scan.uploaded': {one: 'ملف واحد مرفوع', two: 'ملفان مرفوعان', few: '{n} ملفات مرفوعة', many: '{n} ملفًا مرفوعًا', other: '{n} ملف مرفوع'},
      'scan.nSelected': {one: 'ملف واحد محدد', two: 'ملفان محددان', few: '{n} ملفات محددة', many: '{n} ملفًا محددًا', other: '{n} ملف محدد'},
      'find.nFiles': {one: 'ملف واحد مفحوص', two: 'ملفان مفحوصان', few: '{n} ملفات مفحوصة', many: '{n} ملفًا مفحوصًا', other: '{n} ملف مفحوص'},
      'find.nPages': {one: 'صفحة واحدة مفحوصة', two: 'صفحتان مفحوصتان', few: '{n} صفحات مفحوصة', many: '{n} صفحةً مفحوصةً', other: '{n} صفحة مفحوصة'},
      'find.nFindings': {one: 'نتيجة واحدة', two: 'نتيجتان', few: '{n} نتائج', many: '{n} نتيجةً', other: '{n} نتيجة'},
      'find.onPages': {one: 'ظهرت في صفحة واحدة', two: 'ظهرت في صفحتين', few: 'ظهرت في {n} صفحات', many: 'ظهرت في {n} صفحةً', other: 'ظهرت في {n} صفحة'},
      'find.showing': {one: 'عرض {n} من نتيجة واحدة', two: 'عرض {n} من نتيجتين', few: 'عرض {n} من {total} نتائج', many: 'عرض {n} من {total} نتيجةً', other: 'عرض {n} من {total} نتيجة'},
      'dash.findingsCap': {one: 'نتيجة', two: 'نتيجتان', few: 'نتائج', many: 'نتيجةً', other: 'نتيجة'},
      'proj.findings': {one: 'نتيجة', two: 'نتيجتان', few: 'نتائج', many: 'نتيجةً', other: 'نتيجة'},
      'proj.count': {one: 'مشروع واحد', two: 'مشروعان', few: '{n} مشاريع', many: '{n} مشروعًا', other: '{n} مشروع'},
      'proj.shown': {one: 'عرض {n} من مشروع واحد', two: 'عرض {n} من مشروعين', few: 'عرض {n} من {total} مشاريع', many: 'عرض {n} من {total} مشروعًا', other: 'عرض {n} من {total} مشروع'},
      'proj.nScans': {one: 'فحص واحد', two: 'فحصان', few: '{n} فحوصات', many: '{n} فحصًا', other: '{n} فحص'},
      'proj.spark': {one: 'إجمالي النتائج عبر فحص واحد، من الأقدم إلى الأحدث: {vals}', two: 'إجمالي النتائج عبر فحصين، من الأقدم إلى الأحدث: {vals}', few: 'إجمالي النتائج عبر {n} فحوصات، من الأقدم إلى الأحدث: {vals}', many: 'إجمالي النتائج عبر {n} فحصًا، من الأقدم إلى الأحدث: {vals}', other: 'إجمالي النتائج عبر {n} فحص، من الأقدم إلى الأحدث: {vals}'},
      'proj.newN': {one: 'نتيجة واحدة جديدة', two: 'نتيجتان جديدتان', few: '{n} نتائج جديدة', many: '{n} نتيجةً جديدةً', other: '{n} نتيجة جديدة'},
      'proj.fixedN': {one: 'أُصلحت نتيجة واحدة', two: 'أُصلحت نتيجتان', few: 'أُصلحت {n} نتائج', many: 'أُصلحت {n} نتيجةً', other: 'أُصلحت {n} نتيجة'},
      'proj.more': {one: 'ونتيجة أخرى', two: 'ونتيجتان أخريان', few: 'و{n} نتائج أخرى', many: 'و{n} نتيجةً أخرى', other: 'و{n} نتيجة أخرى'},
      'comp.controlsWith': {one: '{n} من ضابط واحد عليه نتائج', two: '{n} من ضابطين عليهما نتائج', few: '{n} من {total} ضوابط عليها نتائج', many: '{n} من {total} ضابطًا عليها نتائج', other: '{n} من {total} ضابط عليها نتائج'},
      'comp.fwLabel': {one: '{name}: {status}، {with} من ضابط واحد عليه نتائج', two: '{name}: {status}، {with} من ضابطين عليهما نتائج', few: '{name}: {status}، {with} من {total} ضوابط عليها نتائج', many: '{name}: {status}، {with} من {total} ضابطًا عليها نتائج', other: '{name}: {status}، {with} من {total} ضابط عليها نتائج'},
      'comp.mapped': {one: 'نتيجة واحدة مربوطة', two: 'نتيجتان مربوطتان', few: '{n} نتائج مربوطة', many: '{n} نتيجةً مربوطةً', other: '{n} نتيجة مربوطة'},
      'comp.unmapped': {one: 'نتيجة واحدة غير مربوطة', two: 'نتيجتان غير مربوطتين', few: '{n} نتائج غير مربوطة', many: '{n} نتيجةً غير مربوطة', other: '{n} نتيجة غير مربوطة'},
      'comp.hidden': {one: 'ضابط واحد بلا نتائج مخفي.', two: 'ضابطان بلا نتائج مخفيان.', few: '{n} ضوابط بلا نتائج مخفية.', many: '{n} ضابطًا بلا نتائج مخفية.', other: '{n} ضابط بلا نتائج مخفية.'},
      'rules.n': {one: 'قاعدة واحدة', two: 'قاعدتان', few: '{n} قواعد', many: '{n} قاعدةً', other: '{n} قاعدة'},
    },
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
    'dash.allScans': 'All scans', 'dash.latest': 'Latest scan', 'dash.oneScan': 'Only one scan so far. Run more scans to see the trend over time.', 'dash.total': 'findings in total',
    'scan.title': 'New scan', 'scan.sub': 'Scan a folder on this machine, upload an archive or files, or passively check a website you own.',
    'scan.tabPath': 'Local path', 'scan.tabUpload': 'Upload files / archive', 'scan.tabUrl': 'Web URL', 'scan.pathLabel': 'Folder, file or archive path', 'scan.start': 'Start scan',
    'scan.pathHint': 'The whole folder is scanned recursively (node_modules, .git and build are skipped).', 'scan.drop': 'Drop an archive (zip / apk / jar / tar.gz / whl) or any files here',
    'scan.chooseFiles': 'Choose files', 'scan.chooseFolder': 'Choose a folder', 'scan.uploadStart': 'Upload and scan', 'scan.urlLabel': 'Site URL (passive: a bounded number of GET requests, no active test)',
    'scan.authorize': 'I own this site or have written permission to test it', 'scan.deep': 'Deeper scan: analyze the page and probe common exposed paths (a few extra requests)', 'scan.crawl': 'Crawl same-site pages and scan each one (for apps such as Moodle and university portals)', 'scan.legal': 'Testing systems without permission may be illegal.', 'scan.viewResults': 'View findings',
    'scan.running': 'Scanning…', 'scan.done': 'Scan complete', 'scan.failed': 'Scan failed', 'scan.needAuth': 'Confirm that you are authorized to test this site first', 'scan.uploading': 'Uploading…', 'scan.uploadFailed': 'Upload failed',
    'scan.jadxOn': 'jadx is installed: APK/JAR/AAR/DEX files are decompiled and the resulting code is scanned too.', 'scan.jadxOff': 'jadx is not installed: only text files inside APK/JAR are scanned. Install jadx (requires Java) to decompile bytecode.',
    'find.title': 'Findings', 'find.sub': 'Sorted from highest to lowest severity. Select a finding to see its details and remediation.', 'find.search': 'Search file, rule or text…', 'find.allSources': 'All sources',
    'find.none': 'No findings match the current filters.', 'find.flow': 'Data-flow path (source to sink)',
    'find.advice': 'Remediation', 'find.snippet': 'Code', 'find.ref': 'Reference', 'find.scan': 'Scan', 'find.export': 'Export',
    'find.dataflow': 'Proven by data flow', 'find.pattern': 'Pattern match', 'find.location': 'Location', 'find.source': 'Source', 'find.sink': 'Sink', 'find.step': 'Step',
    'find.fingerprint': 'Fingerprint', 'find.copy': 'Copy', 'find.copied': 'Copied', 'find.cwe': 'Open the {cwe} definition at MITRE', 'find.input': 'Untrusted input', 'find.clear': 'Show all',
    'rep.title': 'Reports', 'rep.sub': 'Scan history, report downloads, and a comparison of two scans to see what was fixed and what is new.', 'rep.compare': 'Compare two scans', 'rep.compareBtn': 'Compare', 'rep.fixed': 'Fixed (no longer present)', 'rep.new': 'New (introduced)',
    'rep.target': 'Target', 'rep.date': 'Date', 'rep.status': 'Status', 'rep.total': 'Total', 'rep.actions': 'Actions', 'rep.delete': 'Delete', 'rep.view': 'View', 'rep.nothing': 'None',
    'rep.base': 'Base scan', 'rep.head': 'Compare with', 'rep.history': 'Scan history', 'rep.download': 'Download HTML report', 'rep.confirmDel': 'Delete this scan?', 'rep.noScans': 'No scans yet.',
    'rules.title': 'Built-in rules', 'rules.search': 'Search rules…', 'rules.id': 'Rule', 'rules.sev': 'Severity', 'rules.name': 'Issue', 'rules.langs': 'Applies to', 'rules.advice': 'Remediation',
    'set.title': 'Settings', 'set.sub': 'Stored on this machine and applied to every new scan.', 'set.minSev': 'Minimum severity shown', 'set.failOn': 'Fail CI at severity', 'set.exclude': 'Excluded paths (one glob per line)',
    'set.ignore': 'Ignored rules (one ID per line)', 'set.authTargets': 'Authorized web targets (one per line)', 'set.osv': 'Query OSV.dev for known vulnerabilities in dependencies (requires internet)',
    'set.external': 'Merge results from installed external scanners', 'set.audit': 'Audit profile: also report risky calls that data-flow analysis did not prove reachable from input (broader, noisier)', 'set.jadx': 'Decompile APK / JAR / AAR / DEX with jadx and scan the output', 'set.jadxLibs': 'Also scan third-party libraries in decompiled code (more findings, more noise)', 'set.jadxTimeout': 'jadx timeout (seconds)', 'set.jadxOn': 'jadx is installed on this machine.', 'set.jadxOff': 'jadx is not installed. Get it from github.com/skylot/jadx to decompile bytecode.',
    'set.models': 'Extra models folder for the data-flow engine (JSON: sources, sinks, sanitizers)', 'set.queries': 'Extra VQL queries folder (declarative queries over the program database)',
    'set.keep': 'Scans to keep', 'set.webTimeout': 'Web request timeout in seconds (the first request is retried once with double the timeout)', 'set.webDelay': 'Minimum gap in seconds between two requests to one site, for every request (floor 0.2)', 'set.save': 'Save changes', 'set.saved': 'Saved', 'set.home': 'Data folder', 'set.none': 'none installed',
    'set.secScope': 'Scope and thresholds', 'set.secScopeHint': 'Which findings are shown and when CI fails.', 'set.secAnalysis': 'Analysis and integrations', 'set.secAnalysisHint': 'Extra result sources and how broad the analysis is.',
    'set.secBinary': 'Binaries (jadx)', 'set.secWeb': 'Web scanning', 'set.secWebHint': 'Passive, rate-limited checks of sites you are authorized to test.', 'set.secStorage': 'Storage',
    'about.title': 'About Kashif', 'about.hint': 'Open-source security scanner for code and applications.', 'about.name': 'Kashif', 'about.by': 'Developed by the Programming Department at the Islamic University of Gaza.', 'about.contact': 'Contact', 'about.license': 'License',
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
    'nav.projects': 'Projects', 'proj.title': 'Projects', 'proj.sub': 'Every target you have scanned, with its latest results, its trend and what changed between the last two scans.',
    'proj.search': 'Search by project name or path…', 'proj.sort': 'Sort by', 'proj.sortRecent': 'Recently scanned', 'proj.sortRisk': 'Highest risk', 'proj.sortName': 'Name',
    'proj.all': 'All projects', 'proj.switch': 'Project', 'proj.rescan': 'Scan again', 'proj.changes': 'Changes since the previous scan', 'proj.trend': 'Findings across this project’s scans',
    'proj.scans': 'Scans of this project', 'proj.none': 'No project matches the search.', 'proj.lastScan': 'Last scan',
    'proj.noChange': 'No change since the previous scan', 'proj.firstScan': 'One scan so far',
    'proj.firstScanHint': 'Scan the project again after changing it to see what is new and what was fixed.', 'proj.clean': 'No findings', 'proj.history': 'Scans and history',
    'proj.neverDone': 'No completed scan yet', 'proj.between': 'Between the scans of {a} and {b}',
    'proj.newTitle': 'New (appeared)', 'proj.fixedTitle': 'Fixed (gone)', 'proj.notFound': 'Project not found (its scans may have been deleted).', 'proj.dupHint': 'projects',
    'fix.title': 'Suggested fix', 'fix.copy': 'Copy patch', 'fix.copied': 'Patch copied', 'fix.adviceOnly': 'Advice only: this change needs a refactoring that cannot be automated safely.',
    'fix.apply': 'To apply the automatic fixes to the project, run:', 'fix.added': 'Added line:', 'fix.removed': 'Removed line:', 'fix.diffLabel': 'Suggested patch for {file}', 'fix.badge': 'Fix available',
    'fix.stats': '{a} added, {d} removed',
    'nav.compliance': 'Compliance', 'find.compliance': 'Compliance', 'a11y.export': 'Download the findings in other formats',
    'exp.more': 'More formats', 'exp.title': 'Export formats', 'exp.hint': 'Triage decisions are applied: false positives and fixed findings are left out of the formats that support it.',
    'exp.aws': 'AWS account ID (12 digits)', 'exp.region': 'AWS region', 'exp.download': 'Download', 'exp.needAws': 'Enter a 12-digit AWS account ID and a region such as us-east-1.', 'exp.loadFail': 'The list of formats could not be loaded.',
    'comp.title': 'Compliance', 'comp.sub': 'How the findings of a scan map to the controls of security and regulatory frameworks. Evidence for an assessment, not a certification.',
    'comp.audit': 'Auditor report', 'comp.auditOne': 'Auditor report for this framework', 'comp.frameworks': 'Frameworks', 'comp.showAll': 'Show controls without findings',
    'comp.risk': 'Risk score', 'comp.r_none': 'None', 'comp.r_low': 'Low', 'comp.r_moderate': 'Moderate', 'comp.r_high': 'High', 'comp.r_critical': 'Critical',
    'comp.st_fail': 'Fail', 'comp.st_warn': 'Review', 'comp.st_pass': 'No findings',
    'comp.control': 'Control', 'comp.ctitle': 'Title', 'comp.total': 'Findings', 'comp.status': 'Status',
    'comp.note': 'Note', 'comp.source': 'Source', 'comp.none': 'No control of this framework has findings.',
    'comp.showFindings': 'Show the findings of {c}', 'comp.empty': 'No completed scan yet.', 'comp.loading': 'Loading…',
    'tri.title': 'Triage', 'tri.status': 'Status', 'tri.justification': 'Justification', 'tri.justReq': '(required for this status)', 'tri.expires': 'Acceptance expires on', 'tri.ticket': 'Ticket URL',
    'tri.comment': 'Comment', 'tri.save': 'Save decision', 'tri.addComment': 'Add comment', 'tri.saved': 'Triage decision saved', 'tri.commented': 'Comment added', 'tri.history': 'History ({n})',
    'tri.by': '{who} · {when}', 'tri.fileProject': 'Decisions are saved with the project in {file}. Commit it so the team shares them.', 'tri.fileHome': 'Decisions are saved in Kashif’s data folder: {file}',
    'tri.filter': 'Triage status', 'tri.all': 'All statuses', 'tri.showFp': 'Show false positives', 'tri.hiddenFp': 'hidden as false positives: {n}',
    'tri.expired': 'Risk acceptance expired', 'tri.regression': 'Regression: reappeared after it was fixed', 'tri.untracked': 'No decision recorded yet.', 'tri.needJust': 'This status needs a justification.',
    'tri.loadFail': 'The triage file could not be read: {err}', 'tri.act.status': 'changed the status', 'tri.act.comment': 'commented', 'tri.act.severity': 'changed the severity', 'tri.act.expired': 'acceptance expired', 'tri.act.regression': 'regression', 'tri.act.auto': 'automatic update',
    'tri.ticketBad': 'The ticket URL must start with http:// or https://', 'tri.fixOnly': 'Only findings with a suggested fix',
    'sf.title': 'Attack surface', 'sf.hint': 'The project’s entry points as static analysis finds them: routes, their handlers and whether authentication is visible. No request is sent and no code is run.',
    'sf.build': 'Build map', 'sf.rebuild': 'Rebuild', 'sf.engine': 'Trace data flow from each entry point to sinks (slower)', 'sf.running': 'Building the attack-surface map…',
    'sf.unavailable': 'The map can only be built for a local folder scanned from this machine (not for uploads or web URLs).', 'sf.none': 'No map has been built for the latest scan yet.', 'sf.error': 'The map could not be built: {err}',
    'sf.entries': 'Entry points', 'sf.unauth': 'No visible authentication', 'sf.unauthSink': 'Unauthenticated and reaching a sink', 'sf.withFindings': 'With findings',
    'sf.risk': 'Risk', 'sf.method': 'Method', 'sf.path': 'Path', 'sf.handler': 'Handler', 'sf.auth': 'Auth', 'sf.sinks': 'Sinks', 'sf.findings': 'Findings',
    'sf.auth_none': 'None visible', 'sf.auth_public': 'Explicitly public', 'sf.auth_protected': 'Protected', 'sf.showAll': 'Show all ({n})', 'sf.showLess': 'Show the riskiest only', 'sf.openapi': 'OpenAPI',
    'sf.builtAt': 'Built {when}', 'sf.unauthOnly': 'Unauthenticated only', 'sf.empty': 'No entry points were found.', 'sf.search': 'Search path or handler…', 'sf.shown': 'Showing {n} of {total}', 'sf.noMatch': 'No entry point matches the filters.',
    'reach.imported': 'Imported by your code', 'reach.not_imported': 'Not imported', 'reach.vulnerable_function_called': 'Vulnerable function called', 'reach.label': 'Reachability',
    /* 1.1.0 passive web scanning */
    'scan.profile': 'Scan profile', 'scan.pMinimal': 'minimal: the page and its redirects only (at most 10 requests)',
    'scan.pStandard': 'standard (default): well-known files and the page\'s own scripts (at most 45 requests)',
    'scan.pDeep': 'deep: adds commonly exposed files (at most 150 requests)', 'scan.sens': 'Sensitivity', 'scan.sStrict': 'strict: certain findings only',
    'scan.sDefault': 'default: certain and firm', 'scan.sParanoid': 'paranoid: everything, with the extra checks',
    'scan.compare': 'Compare with the last scan of this site', 'scan.robots': 'Ignore robots.txt when crawling (for the site\'s owner)',
    'scan.thirdParty': 'Allow third-party lookups that reveal the site\'s name (such as hstspreload.org)', 'scan.noProxy': 'Do not use the system\'s proxy',
    'web.grades': 'Grades', 'web.provisional': 'Provisional grade (*): some families were not tested and do not count', 'web.caps': 'Grade caps',
    'web.none': 'not computed', 'web.coverage': 'Check coverage',
    'web.covNote': 'A check that was not tested or was inconclusive is never shown as passed and never counts in a grade.',
    'web.covDetails': 'Checks that did not pass or did not run', 'web.check': 'Check', 'web.state': 'State', 'web.reason': 'Reason',
    'web.inventory': 'Site inventory', 'web.empty': 'Nothing recorded', 'web.remediation': 'Copy-paste fixes',
    'web.remHint': 'The settings for the platforms detected on the site are shown first.', 'web.caution': 'Caution',
    'web.diff': 'Compared with the previous scan', 'web.dNew': 'New findings', 'web.dResolved': 'Resolved findings', 'web.dUnchanged': 'Unchanged findings',
    'web.dPosture': 'Posture changes', 'web.dGrades': 'Grade changes', 'web.dNone': 'No changes', 'web.confidence': 'Confidence', 'web.c_certain': 'Certain',
    'web.c_firm': 'Firm', 'web.c_tentative': 'Tentative', 'web.page': 'Page', 'web.curl': 'Command that repeats the request',
    'web.mapping': 'Analyst mapping (WSTG and ASVS)', 'web.profile': 'Profile', 'web.requests': 'Requests', 'web.final': 'Final URL',
    'web.data': 'Web data as of', 'web.loadFail': 'Could not load the details of the web scan: {err}', 'set.webProfile': 'Default web scan profile',
    'set.webSens': 'Default sensitivity', 'set.webCompare': 'Compare every scan with the last scan of the same site',
    'set.webRobots': 'Honour robots.txt when crawling', 'set.web3p': 'Allow third-party lookups (such as hstspreload.org)',
    'set.webProxy': 'Use the system\'s proxy',
    pl: {
      'scan.uploaded': {one: '{n} uploaded file', other: '{n} uploaded files'},
      'scan.nSelected': {one: '{n} file selected', other: '{n} files selected'},
      'find.nFiles': {one: '{n} file scanned', other: '{n} files scanned'},
      'find.nPages': {one: '{n} page scanned', other: '{n} pages scanned'},
      'find.nFindings': {one: '{n} finding', other: '{n} findings'},
      'find.onPages': {one: 'Seen on {n} page', other: 'Seen on {n} pages'},
      'find.showing': {one: 'Showing {n} of {total} finding', other: 'Showing {n} of {total} findings'},
      'dash.findingsCap': {one: 'finding', other: 'findings'},
      'proj.findings': {one: 'finding', other: 'findings'},
      'proj.count': {one: '{n} project', other: '{n} projects'},
      'proj.shown': {one: 'Showing {n} of {total} project', other: 'Showing {n} of {total} projects'},
      'proj.nScans': {one: '{n} scan', other: '{n} scans'},
      'proj.spark': {one: 'Total findings across {n} scan, oldest to newest: {vals}', other: 'Total findings across {n} scans, oldest to newest: {vals}'},
      'proj.newN': {one: '{n} new', other: '{n} new'},
      'proj.fixedN': {one: '{n} fixed', other: '{n} fixed'},
      'proj.more': {one: 'and {n} more', other: 'and {n} more'},
      'comp.controlsWith': {one: '{n} of {total} control with findings', other: '{n} of {total} controls with findings'},
      'comp.fwLabel': {one: '{name}: {status}, {with} of {total} control with findings', other: '{name}: {status}, {with} of {total} controls with findings'},
      'comp.mapped': {one: '{n} finding mapped', other: '{n} findings mapped'},
      'comp.unmapped': {one: '{n} not mapped', other: '{n} not mapped'},
      'comp.hidden': {one: '{n} control without findings is hidden.', other: '{n} controls without findings are hidden.'},
      'rules.n': {one: '{n} rule', other: '{n} rules'},
    },
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
/* Plural category of a count. English: one / other. Arabic: one (1), two (2), few (3–10), many (11–99) and other
   (0 and 100, 101, 102…: the singular noun), by the last two digits like CLDR, so 103 is "few" and 111 "many". */
const pluralCat = (count, lg = lang) => {
  const n = Math.abs(Math.trunc(Number(count) || 0));
  if (lg !== 'ar') return n === 1 ? 'one' : 'other';
  if (n === 1 || n === 2) return n === 1 ? 'one' : 'two';
  const r = n % 100;
  return r >= 3 && r <= 10 ? 'few' : r >= 11 ? 'many' : 'other';
};
/* A count string (I18N[lang].pl) in the form that agrees with `count`; {n} is `count` unless vars sets it (the
   "by total" strings agree with {total}: tn('find.showing', total, {n: shown, total})). */
const tn = (k, count, vars) => {
  const forms = I18N[lang].pl[k] || I18N.ar.pl[k];
  if (!forms) return t(k, {n: count, ...vars});
  let s = forms[pluralCat(count)] ?? forms.other;
  const all = {n: count, ...vars};
  Object.keys(all).forEach((v) => { s = s.split(`{${v}}`).join(all[v]); });
  return s;
};
const sevName = (s) => I18N[lang].sev[s] || s;
const srcName = (s) => I18N[lang].src[s] || s;  // external tools (semgrep, bandit, ...) keep their own names
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
/* Arabic month and day names with the Western digits every count, score and report of Kashif uses (ar-EG alone
   switches dates to Eastern Arabic digits, so one line read "١٢‏/١١‏/٢٠٢٦" next to "161 نتيجةً"). */
const locale = () => (lang === 'ar' ? 'ar-EG-u-nu-latn' : 'en-GB');
/* An Arabic date is a right-to-left isolate (U+2067 … U+2069): with Western digits, a date right after a Latin name
   ("proj — 12/11/2026" in a scan menu) would otherwise join the name's left-to-right run and display out of order. */
const dateIso = (s) => (lang === 'ar' && s ? `\u2067${s}\u2069` : s);
const fmtDate = (ts) => (ts ? dateIso(new Date(ts * 1000).toLocaleString(locale(), {dateStyle: 'medium', timeStyle: 'short'})) : '—');
const fmtShort = (ts) => (ts ? dateIso(new Date(ts * 1000).toLocaleDateString(locale(), {month: 'short', day: 'numeric'})) : '');
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
/* In Arabic text, isolate each Latin run so the bidi algorithm neither mirrors its brackets (order_query()) nor
   reorders its words: a run is words of letters, digits and code punctuation joined by spaces, so the numbers of
   "OWASP Top 10:2021", "45 CFR 164.312" or "NIST SP 800-53 Rev. 5" and the dashes of "--sha256" stay in place.
   Trailing punctuation is left to the Arabic sentence, but a grade's "+" or "*" stays in its run ("A+", "F*", which
   otherwise display as "+A", "*F"); a run without a Latin letter (a plain number) needs no isolate. */
const bidi = (text) => {
  const str = String(text ?? '');
  if (lang !== 'ar' || !/[؀-ۿ]/.test(str)) return esc(str);
  const word = String.raw`(?:--?)?[A-Za-z0-9_$./~][\w$:/.~-]*[+*]*(?:\([^()؀-ۿ]*\))*`;
  const rx = new RegExp(String.raw`${word}(?:\.? +${word})*`, 'g');
  let out = '', last = 0, m;
  while ((m = rx.exec(str))) {
    const run = m[0].replace(/[.:,;-]+$/, '');
    if (!/[A-Za-z]/.test(run)) continue;
    out += esc(str.slice(last, m.index)) + `<bdi dir="ltr">${esc(run)}</bdi>`; last = m.index + run.length;
  }
  return out + esc(str.slice(last));
};
const ARABIC = /[؀-ۿݐ-ݿﭐ-﷿ﹰ-﻿]/;
/* Explicit direction of a short text (a control title, a finding title) from its first strong letter after leading
   identifiers, numbers and acronyms, never the browser's first-letter guess of dir="auto": "A01:2021 تحكم وصول معطوب"
   and "ISO/IEC 27001:2022 الملحق أ" are right-to-left, "OWASP Top 10:2021" left-to-right (same rule as the auditor
   report, vulnscan/compliance.py _direction). */
const dirOf = (text) => {
  const str = String(text ?? '');
  for (const tok of str.split(/\s+/)) {
    if (!tok || /^[^؀-ۿ]*\d[^؀-ۿ]*$/.test(tok) || /^[\W_]*[A-Z][A-Z0-9/&._-]+[\W_]*$/.test(tok) || /^[\W\d_]*$/.test(tok)) continue;
    for (const ch of tok) {
      if (ARABIC.test(ch)) return 'rtl';
      if (/[A-Za-zÀ-ɏ]/.test(ch)) return 'ltr';
    }
  }
  return ARABIC.test(str) ? 'rtl' : 'ltr';
};

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
    return m ? tn('scan.uploaded', Number(m[1])) : s.label;
  }
  const tg = String(s.target || '');
  if (/^https?:\/\//i.test(tg)) {
    try { const u = new URL(tg); return u.host + (u.pathname !== '/' ? u.pathname : ''); } catch { return tg; }
  }
  const parts = tg.split(/[\\/]/).filter((x) => x && x !== '.');
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
  $$('nav a').forEach((el) => { const name = t('nav.' + el.dataset.nav); el.setAttribute('aria-label', name); el.title = name; });  // the text is hidden in the narrow icon-only sidebar
  $('.brand').setAttribute('aria-label', `${t('brand')} — vulnscan`);
  $('#sev-filter').setAttribute('aria-label', t('a11y.sevFilter'));
  $('.btn-group').setAttribute('aria-label', t('find.export'));
  $$('#f-min option, #f-fail option').forEach((o) => { o.textContent = sevName(o.value); });
  $('#fix-filter').title = t('tri.fixOnly');
  $('#export-btn').title = t('a11y.export');
  $('#fw-grid').setAttribute('aria-label', t('comp.frameworks'));
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
let webDefaultsSet = false;
async function loadScanPage() {             // the web-scan options start from the settings (once per visit of the app)
  if (webDefaultsSet) return;
  const s = await api('/api/settings');
  webDefaultsSet = true;
  if (['minimal', 'standard', 'deep'].includes(s.web_profile)) $('#url-profile').value = s.web_profile;
  if (['strict', 'default', 'paranoid'].includes(s.web_sensitivity)) $('#url-sens').value = s.web_sensitivity;
  $('#url-compare').checked = s.web_compare_previous !== false; $('#url-3p').checked = !!s.web_third_party_lookups;
  $('#url-noproxy').checked = s.web_use_proxy === false; $('#url-robots').checked = s.web_respect_robots === false;
}
const pages = {dashboard: loadDashboard, projects: loadProjects, scan: loadScanPage, findings: loadFindings, compliance: loadCompliance, reports: loadReports, rules: loadRules, settings: loadSettings};
let curPage = '';
function route() {
  const h = location.hash.slice(1);
  const slash = h.indexOf('/');
  const name = (slash < 0 ? h : h.slice(0, slash)).split('?')[0] || 'dashboard';
  const arg = slash < 0 ? (h.includes('?') ? h.slice(h.indexOf('?')) : '') : h.slice(slash + 1);
  const page = pages[name] ? name : 'dashboard';
  curPage = page;
  setExport(false);
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
let projCache = [];
/* Display name of a project; projects that share a name (two folders called "api") get their parent folder appended. */
function projName(p) {
  const base = scanName({label: p.label, target: p.target}) || p.name || '';
  if (!projCache.some((o) => o.id !== p.id && scanName({label: o.label, target: o.target}) === base)) return base;
  const parts = String(p.target || '').replace(/[\\/]+$/, '').split(/[\\/]/);
  return parts.length > 1 && !p.label ? `${base} (${parts[parts.length - 2] || '/'})` : base;
}
$('#dash-project').onchange = (e) => { store.set('vs.project', e.target.value); loadDashboard(); };
async function loadDashboard(arg) {
  projCache = await api('/api/projects');
  if (arg && projCache.some((p) => p.id === arg)) store.set('vs.project', arg);
  let pid = store.get('vs.project') || '';
  if (!projCache.some((p) => p.id === pid)) pid = '';
  const sel = $('#dash-project');
  setHTML(sel, `<option value="">${esc(t('proj.all'))}</option>` + projCache.map((p) => `<option value="${esc(p.id)}" title="${esc(p.target)}">${esc(projName(p))}</option>`).join(''));
  sel.value = pid; sel.classList.toggle('hidden', projCache.length < 2 && !pid);
  const st = await api('/api/stats' + (pid ? `?project=${pid}` : ''));
  const empty = !st.latest;
  $('#dash-empty').classList.toggle('hidden', !empty);
  $('#dash-body').classList.toggle('hidden', empty);
  $('#dash-open').classList.toggle('hidden', empty);
  if (empty) return;
  const L = st.latest; const sum = L.summary;
  $('#dash-open').href = `#findings/${L.id}`;
  setHTML($('#dash-context'), `<span class="ctx" title="${esc(L.target)}">${ic(L.kind === 'url' ? 'globe' : 'folder', 'sm')}<span class="muted">${esc(t('dash.latest'))}:</span> <b class="ellipsis" dir="auto">${esc(scanName(L))}</b></span>`
    + `<span class="ctx">${ic('file', 'sm')}${esc(tn(L.kind === 'url' ? 'find.nPages' : 'find.nFiles', L.files_scanned))}</span>`
    + `<span class="ctx">${ic('clock', 'sm')}${esc(fmtDate(L.finished_at))}</span>`);
  setHTML($('#tiles'), tilesHTML(sum));
  $$('#tiles .tile').forEach((el) => { el.onclick = () => { location.hash = `findings/${L.id}?sev=${el.dataset.sev}`; }; });
  drawDonut($('#donut'), $('#donut-legend'), sum);
  lastTrend = st.trend; drawTrend($('#trend'), st.trend);
  const maxR = Math.max(1, ...st.top_rules.map((r) => r.count));
  setHTML($('#top-rules'), st.top_rules.map((r) => `<li class="sev-${r.severity}"><span class="main">${pill(r.severity)}<a class="title" href="#findings/${L.id}?q=${encodeURIComponent(r.rule_id)}" title="${esc(titleOf(r))}">${esc(titleOf(r))}</a></span><span class="rid" dir="ltr" title="${esc(r.rule_id)}">${esc(r.rule_id)}</span><span class="bar"><i style="width:${(r.count / maxR) * 100}%"></i></span><span class="cnt">${r.count}</span></li>`).join('') || `<li class="empty-li">${esc(t('rep.nothing'))}</li>`);
  const maxF = Math.max(1, ...st.top_files.map(([, n]) => n));
  setHTML($('#top-files'), st.top_files.map(([f, n]) => `<li><span class="ffile">${ic('file', 'sm')}${fpath(f)}</span><span class="bar"><i style="width:${(n / maxF) * 100}%"></i></span><span class="cnt">${n}</span></li>`).join('') || `<li class="empty-li">${esc(t('rep.nothing'))}</li>`);
  const scans = await api('/api/scans' + (pid ? `?project=${pid}` : ''));
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
  setHTML(svg, `${track}<g transform="rotate(-90 ${c} ${c})">${parts.join('')}</g><text x="${c}" y="${c + 3}" text-anchor="middle" font-size="24" class="donut-total">${tot}</text><text x="${c}" y="${c + 19}" text-anchor="middle" font-size="9.5" class="donut-cap">${esc(tn('dash.findingsCap', tot))}</text>`);
  svg.setAttribute('aria-label', SEV.map((s) => `${sevName(s)} ${sum[s] || 0}`).join(', '));
  setHTML(legend, SEV.map((s) => `<div class="sev-${s}"><span class="dot"></span>${esc(sevName(s))}<b>${sum[s] || 0}</b><span class="pct">${tot ? Math.round(((sum[s] || 0) / tot) * 100) : 0}%</span></div>`).join(''));
}
const niceStep = (m) => { const raw = m / 4; if (raw <= 1) return 1; const p = 10 ** Math.floor(Math.log10(raw)); const f = raw / p; return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p; };
function drawTrend(svg, trend, legend = $('#trend-legend'), note = $('#trend-note'), label = t('dash.trend')) {
  setHTML(legend, SEV.map((s) => `<span class="sev-${s}"><span class="dot"></span>${esc(sevName(s))}</span>`).join(''));
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
  svg.setAttribute('aria-label', `${label}: ${trend.map((s) => total(s)).join(', ')}`);
  note.classList.toggle('hidden', n > 1);
  setHTML(note, `${ic('info', 'sm')}<span>${esc(t('dash.oneScan'))}</span>`);
}
let rsz;
window.addEventListener('resize', () => { clearTimeout(rsz); rsz = setTimeout(() => {
  if (curPage === 'dashboard' && lastTrend) drawTrend($('#trend'), lastTrend);
  if (curPage === 'projects' && projDetail) drawTrend($('#pd-trend'), projDetail.trend, $('#pd-trend-legend'), $('#pd-trend-note'), t('proj.trend'));
}, 120); });

/* ------------------------------------------------------------ projects */
let projDetail = null;
const sevCounts = (sum) => {
  const live = SEV.filter((s) => sum[s]);
  if (!live.length) return `<span class="sevc none">${ic('check', 'sm')}${esc(t('proj.clean'))}</span>`;
  return live.map((s) => `<span class="sevc sev-${s}"><span class="dot"></span><b>${sum[s]}</b> ${esc(sevName(s))}</span>`).join('');
};
/* Total findings per completed scan, oldest to newest (always left to right, like the trend chart). */
function sparkHTML(trend) {
  const vals = trend.map((x) => x.total);
  if (!vals.length) return '';
  const W = 120, H = 36, pad = 4;
  const max = Math.max(1, ...vals), n = vals.length;
  const X = (i) => (n === 1 ? W - pad : pad + (i * (W - 2 * pad)) / (n - 1));
  const Y = (v) => H - pad - (v / max) * (H - 2 * pad);
  const pts = vals.map((v, i) => `${X(i).toFixed(1)},${Y(v).toFixed(1)}`);
  const line = n > 1 ? `<polygon class="sp-area" points="${pad},${H - pad} ${pts.join(' ')} ${W - pad},${H - pad}"/><polyline class="sp-line" points="${pts.join(' ')}"/>` : '';
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" direction="ltr" aria-label="${esc(tn('proj.spark', n, {vals: vals.join(', ')}))}"><line class="sp-base" x1="${pad}" x2="${W - pad}" y1="${H - pad}" y2="${H - pad}"/>${line}<circle class="sp-dot" cx="${X(n - 1).toFixed(1)}" cy="${Y(vals[n - 1]).toFixed(1)}" r="3"/></svg>`;
}
const changeBadges = (p) => {
  if (p.new == null) return `<span class="chg none">${esc(t(p.done_scans ? 'proj.firstScan' : 'proj.neverDone'))}</span>`;
  if (!p.new && !p.fixed) return `<span class="chg none">${ic('check', 'sm')}${esc(t('proj.noChange'))}</span>`;
  return (p.new ? `<span class="chg new">${ic('warning', 'sm')}${esc(tn('proj.newN', p.new))}</span>` : '')
    + (p.fixed ? `<span class="chg fixed">${ic('check', 'sm')}${esc(tn('proj.fixedN', p.fixed))}</span>` : '');
};
const riskKey = (p) => SEV.map((s) => String(p.summary[s] || 0).padStart(7, '0')).join('');
function renderProjects() {
  const q = $('#proj-search').value.trim().toLowerCase(); const sort = $('#proj-sort').value;
  let list = projCache.filter((p) => !q || [p.name, p.target, p.label, projName(p)].join(' ').toLowerCase().includes(q));
  if (sort === 'risk') list = list.slice().sort((a, b) => (riskKey(a) < riskKey(b) ? 1 : riskKey(a) > riskKey(b) ? -1 : 0));
  else if (sort === 'name') list = list.slice().sort((a, b) => projName(a).localeCompare(projName(b), locale()));
  $('#proj-toolbar').classList.toggle('hidden', !projCache.length);
  $('#proj-count').textContent = !projCache.length ? '' : list.length === projCache.length ? tn('proj.count', projCache.length) : tn('proj.shown', projCache.length, {n: list.length, total: projCache.length});
  if (!projCache.length) {
    setHTML($('#proj-grid'), `<div class="empty card wide"><img src="logo.svg" width="56" height="56" alt=""><h2>${esc(t('dash.empty'))}</h2><p class="muted">${esc(t('dash.emptyHint'))}</p><a class="btn primary" href="#scan">${ic('plus')}${esc(t('nav.scan'))}</a></div>`);
    return;
  }
  if (!list.length) { setHTML($('#proj-grid'), `<div class="empty inline wide"><span class="e-icon">${ic('search', 'lg')}</span><p class="muted">${esc(t('proj.none'))}</p></div>`); return; }
  setHTML($('#proj-grid'), list.map((p) => {
    const ls = p.last_scan || {}; const bad = ls.status && ls.status !== 'done';
    return `<article class="card proj" aria-labelledby="pj-${esc(p.id)}">
      <header class="pj-head">
        <span class="pj-icon">${ic(p.kind === 'url' ? 'globe' : p.kind === 'upload' ? 'upload' : 'folder')}</span>
        <div class="pj-name"><h2 id="pj-${esc(p.id)}"><a href="#projects/${esc(p.id)}" dir="auto">${esc(projName(p))}</a></h2><small class="pj-target" dir="ltr" title="${esc(p.target)}"><bdi>${esc(p.kind === 'upload' ? (p.label || '') : p.target)}</bdi></small></div>
        ${bad ? `<span class="status ${esc(ls.status)}"><span class="dot"></span>${esc(I18N[lang].status[ls.status] || ls.status)}</span>` : ''}
      </header>
      <div class="pj-stats">
        <div class="pj-total"><span class="n${p.total ? '' : ' zero'}">${p.done_scans ? p.total : '—'}</span><span class="muted">${esc(tn('proj.findings', p.done_scans ? p.total : 0))}</span></div>
        ${sparkHTML(p.trend)}
      </div>
      <div class="pj-sev">${p.done_scans ? sevCounts(p.summary) : `<span class="sevc none">${esc(t('proj.neverDone'))}</span>`}</div>
      <div class="pj-chg">${changeBadges(p)}</div>
      <footer class="pj-foot">
        <span class="pj-meta muted">${ic('clock', 'sm')}<span>${esc(t('proj.lastScan'))}: ${esc(fmtDate(p.last_scan_at))}</span><span class="sep" aria-hidden="true">·</span><span>${esc(tn('proj.nScans', p.scans))}</span></span>
        <span class="pj-actions">${p.latest ? `<a class="btn sm" href="#findings/${esc(p.latest)}">${esc(t('nav.findings'))}</a>` : ''}<a class="btn sm" href="#projects/${esc(p.id)}">${esc(t('proj.history'))}${ic('chevron', 'sm flip')}</a></span>
      </footer>
    </article>`;
  }).join(''));
}
$('#proj-search').oninput = renderProjects; $('#proj-sort').onchange = renderProjects;
async function loadProjects(arg) {
  const id = (arg || '').split('?')[0];
  $('#proj-list-view').classList.toggle('hidden', !!id);
  $('#proj-detail-view').classList.toggle('hidden', !id);
  projCache = await api('/api/projects');
  if (!id) { projDetail = null; renderProjects(); return; }
  let p;
  try { p = await api(`/api/projects/${encodeURIComponent(id)}`); } catch { toast(t('proj.notFound')); location.hash = 'projects'; return; }
  projDetail = p;
  $('#pd-name').textContent = projName(p);
  $('#pd-target').textContent = p.kind === 'upload' ? (p.label || '') : p.target; $('#pd-target').title = p.target || '';
  $('#pd-open').classList.toggle('hidden', !p.latest); if (p.latest) $('#pd-open').href = `#findings/${p.latest}`;
  $('#pd-rescan').classList.toggle('hidden', p.kind === 'upload');
  $('#pd-rescan').onclick = () => {
    const url = p.kind === 'url';
    $(`#scan-tabs .tab[data-tab="${url ? 'url' : 'path'}"]`).click();
    $(url ? '#url-input' : '#path-input').value = p.target;
    location.hash = 'scan';
    if (!url) $('#path-btn').click();          // a web target still needs the authorization box ticked
  };
  setHTML($('#pd-context'), `<span class="ctx">${ic('clock', 'sm')}<span class="muted">${esc(t('proj.lastScan'))}:</span> ${esc(fmtDate(p.last_scan_at))}</span>`
    + `<span class="ctx">${ic('reports', 'sm')}${esc(tn('proj.nScans', p.scans.length))}</span>`
    + (p.latest ? `<span class="ctx">${ic('file', 'sm')}${esc(tn(p.kind === 'url' ? 'find.nPages' : 'find.nFiles', p.files_scanned))}</span><span class="ctx">${ic('findings', 'sm')}${esc(tn('find.nFindings', p.total))}</span>` : ''));
  setHTML($('#pd-tiles'), tilesHTML(p.summary, !!p.latest));
  if (p.latest) $$('#pd-tiles .tile').forEach((el) => { el.onclick = () => { location.hash = `findings/${p.latest}?sev=${el.dataset.sev}`; }; });
  const done = p.scans.filter((s) => s.status === 'done');
  const li = (f) => `<li class="sev-${esc(f.severity)}"><span class="main">${pill(f.severity)}<span class="title" dir="auto" title="${esc(titleOf(f))}">${esc(titleOf(f))}</span></span>${fpath(f.file, f.line)}</li>`;
  const col = (cls, icon, title, n, items) => `<div class="diff-col ${cls}"><h3>${ic(icon)}<span>${esc(title)}</span> <span class="count">${n}</span></h3><ul class="rank">${items.slice(0, 8).map(li).join('') || `<li class="empty-li">${esc(t('rep.nothing'))}</li>`}${n > 8 ? `<li class="empty-li">${esc(tn('proj.more', n - 8))}</li>` : ''}</ul></div>`;
  setHTML($('#pd-changes'), p.new == null
    ? `<div class="empty inline"><span class="e-icon">${ic('compare', 'lg')}</span><p><b>${esc(t(p.done_scans ? 'proj.firstScan' : 'proj.neverDone'))}</b></p><p class="muted">${esc(t('proj.firstScanHint'))}</p></div>`
    : `<p class="muted pd-between">${esc(t('proj.between', {a: fmtDate(done[1].finished_at), b: fmtDate(done[0].finished_at)}))}</p><div class="pj-chg">${changeBadges(p)}</div>`
      + col('added', 'warning', t('proj.newTitle'), p.new, p.new_findings) + col('fixed', 'check', t('proj.fixedTitle'), p.fixed, p.fixed_findings));
  drawTrend($('#pd-trend'), p.trend, $('#pd-trend-legend'), $('#pd-trend-note'), t('proj.trend'));
  $('#pd-scans-n').textContent = p.scans.length;
  setHTML($('#pd-scans'), scanRows(p.scans));
  loadSurface(p);
}

/* ------------------------------------------------------ attack surface */
/* POST /api/scans/<id>/surface builds the map in the background; GET /api/projects/<id>/surface polls it. */
const sf = {pid: null, scan: null, kind: '', data: null, all: false, unauth: false, q: '', timer: null, blob: null};
const SF_TOP = 25;
/* In Arabic text, keep an English list in brackets, "(redirect, file)", in one left-to-right run. */
const isoParens = (text) => (lang === 'ar' ? esc(text).replace(/\(([^()\u0600-\u06FF]+)\)/g, '(<bdi dir="ltr">$1</bdi>)') : esc(text));
async function loadSurface(p) {
  clearTimeout(sf.timer);
  if (sf.pid !== p.id || sf.scan !== p.latest) { sf.all = false; sf.unauth = false; sf.q = ''; }
  sf.pid = p.id; sf.scan = p.latest; sf.kind = p.kind; sf.data = null;
  $('#sf-card').classList.toggle('hidden', !p.latest);
  if (!p.latest) return;
  let r;
  try { r = await apiRaw(`/api/projects/${encodeURIComponent(p.id)}/surface?lang=${lang}`); } catch (e) { r = {ok: false, status: 0, data: {status: 'error', error: e.message}}; }
  if (sf.pid !== p.id || curPage !== 'projects') return;
  const d = r.data || {};
  if (d.status === 'running') { renderSurfaceState('running'); sf.timer = setTimeout(() => { if (curPage === 'projects' && sf.pid === p.id) loadSurface(p); }, 1000); return; }
  if (d.status === 'done' && d.surface) { sf.data = d; renderSurface(); return; }
  if (d.status === 'error') { renderSurfaceState('error', d.error); return; }
  renderSurfaceState(d.available === false || p.kind !== 'path' ? 'unavailable' : 'none');
}
const sfEngineBox = (on) => `<label class="check inline" for="sf-engine"><input type="checkbox" id="sf-engine"${on ? ' checked' : ''}><span>${esc(t('sf.engine'))}</span></label>`;
function renderSurfaceState(state, err) {
  const acts = $('#sf-actions'); const body = $('#sf-body');
  if (state === 'running') {
    setHTML(acts, '');
    setHTML(body, `<div class="sf-state"><span class="spinner"></span><span>${esc(t('sf.running'))}</span></div><div class="progress indeterminate sf-prog" role="progressbar" aria-label="${esc(t('sf.running'))}"><div></div></div>`);
    return;
  }
  if (state === 'unavailable') { setHTML(acts, ''); setHTML(body, `<div class="sf-state">${ic('info')}<span class="muted">${esc(t('sf.unavailable'))}</span></div>`); return; }
  setHTML(acts, `${sfEngineBox(true)}<button class="btn primary sm" type="button" id="sf-build">${ic('surface', 'sm')}<span>${esc(t('sf.build'))}</span></button>`);
  setHTML(body, state === 'error'
    ? `<div class="sf-state err">${ic('warning')}<span>${esc(t('sf.error', {err: err || ''}))}</span></div>`
    : `<div class="sf-state">${ic('surface')}<span class="muted">${esc(t('sf.none'))}</span></div>`);
}
async function buildSurface() {
  const box = $('#sf-engine'); const engine = box ? box.checked : true;
  let r;
  try { r = await apiRaw(`/api/scans/${encodeURIComponent(sf.scan)}/surface`, {method: 'POST', body: JSON.stringify({engine})}); } catch (e) { r = {ok: false, data: {error: e.message}}; }
  if (!r.ok) {
    if (r.data && r.data.error === 'source not available') { renderSurfaceState('unavailable'); return; }
    toast(apiErr(r.data, String(r.status || ''))); return;
  }
  renderSurfaceState('running');
  sf.timer = setTimeout(() => { if (projDetail && projDetail.id === sf.pid) loadSurface(projDetail); }, 800);
}
const authCell = (e) => {
  const a = e.auth || {}; const st = ['none', 'public', 'protected'].includes(a.status) ? a.status : 'none';
  if (st === 'none' && e.kind !== 'http') return '<span class="muted">—</span>';
  const g = (Array.isArray(a.guards) ? a.guards : []).map((x) => x && x.name).filter(Boolean);
  return `<span class="auth a-${st}">${ic(st === 'protected' ? 'lock' : 'unlock', 'sm')}${esc(t('sf.auth_' + st))}</span>${g.length ? `<small class="guards" dir="ltr" title="${esc(g.join(', '))}">${esc(g.slice(0, 2).join(', '))}${g.length > 2 ? '…' : ''}</small>` : ''}`;
};
function renderSurface() {
  const d = sf.data; const s = d.surface || {}; const sum = s.summary || {}; const all = Array.isArray(s.entries) ? s.entries : [];
  if (sf.blob) URL.revokeObjectURL(sf.blob);
  sf.blob = d.openapi ? URL.createObjectURL(new Blob([d.openapi], {type: 'application/json'})) : null;
  setHTML($('#sf-actions'), `${sfEngineBox(d.engine !== false)}`
    + (sf.blob ? `<a class="btn sm" href="${sf.blob}" download="kashif-${esc(sf.scan)}-openapi.json">${ic('download', 'sm')}<span>${esc(t('sf.openapi'))}</span></a>` : '')
    + `<button class="btn sm" type="button" id="sf-build">${ic('update', 'sm')}<span>${esc(t('sf.rebuild'))}</span></button>`);
  const q = sf.q.trim().toLowerCase();
  const match = all.filter((e) => (!sf.unauth || e.unauthenticated) && (!q || [e.path, e.handler, e.file, e.method, e.framework].join(' ').toLowerCase().includes(q)));
  const list = sf.all || q || sf.unauth ? match : match.slice(0, SF_TOP);
  const stat = (n, label, cls = '') => `<div class="sf-stat ${cls}"><span class="n">${Number(n) || 0}</span><span class="l">${esc(label)}</span></div>`;
  const sid = encodeURIComponent(sf.scan);
  const rows = list.map((e) => {
    const lvl = SEV.includes(e.risk_level) ? e.risk_level : 'info';
    const fps = (Array.isArray(e.findings) ? e.findings : []).map((x) => (x && typeof x === 'object' ? x.fingerprint : x)).filter((x) => typeof x === 'string' && x);
    const reasons = (Array.isArray(e.reasons) ? e.reasons : []).slice(0, 2);
    const method = e.kind === 'http' ? (e.method || (e.methods || []).join(',') || 'ANY') : (e.kind || '');
    return `<tr class="sev-${lvl}">
      <td class="sf-risk"><span class="pill sev-${lvl}" title="${esc(sevName(lvl))}"><span class="dot"></span>${Number(e.risk) || 0}<span class="sr-only"> / 100, ${esc(sevName(lvl))}</span></span></td>
      <td class="sf-path"><span class="ep" dir="ltr"><code class="method">${esc(method)}</code><code class="p">${esc(e.path || '—')}</code></span>${reasons.length ? `<small class="muted" dir="auto">${isoParens(reasons.join(' · '))}</small>` : ''}</td>
      <td class="sf-handler"><code dir="ltr">${esc(e.handler || '—')}</code>${e.file ? fpath(e.file, e.line) : ''}</td>
      <td>${authCell(e)}</td>
      <td><span class="sf-sinks">${(Array.isArray(e.sink_categories) ? e.sink_categories : []).map((c) => `<span class="tag">${esc(c)}</span>`).join('') || '<span class="muted">—</span>'}</span></td>
      <td class="num">${fps.length ? `<a class="link" href="#findings/${sid}?fp=${encodeURIComponent(fps.join(','))}">${fps.length}</a>` : '<span class="muted">0</span>'}</td></tr>`;
  }).join('');
  const head = `<thead><tr><th>${esc(t('sf.risk'))}</th><th>${esc(t('sf.method'))} · ${esc(t('sf.path'))}</th><th>${esc(t('sf.handler'))}</th><th>${esc(t('sf.auth'))}</th><th>${esc(t('sf.sinks'))}</th><th class="num">${esc(t('sf.findings'))}</th></tr></thead>`;
  const more = !q && !sf.unauth && match.length > SF_TOP
    ? `<button class="btn sm ghost" type="button" id="sf-more">${esc(sf.all ? t('sf.showLess') : t('sf.showAll', {n: match.length}))}</button>` : '';
  const notes = (Array.isArray(s.notes) ? s.notes : []).map((n) => `<div class="note">${ic('info')}<span>${bidi(n)}</span></div>`).join('');
  const focusSearch = document.activeElement && document.activeElement.id === 'sf-search';
  setHTML($('#sf-body'), `<div class="sf-stats">${stat(sum.entries, t('sf.entries'))}${stat(sum.unauthenticated, t('sf.unauth'), 'warn')}${stat(sum.unauthenticated_reaching_sink, t('sf.unauthSink'), 'bad')}${stat(sum.with_findings, t('sf.withFindings'))}</div>`
    + (all.length ? `<div class="toolbar sf-tools"><div class="search"><svg class="i" aria-hidden="true"><use href="#i-search"/></svg><input id="sf-search" class="input" type="search" placeholder="${esc(t('sf.search'))}" aria-label="${esc(t('sf.search'))}" value="${esc(sf.q)}"></div>`
      + `<button class="chip toggle" type="button" id="sf-unauth" aria-pressed="${sf.unauth}">${ic('unlock', 'sm')}${esc(t('sf.unauthOnly'))}</button><span class="muted sf-count" role="status">${esc(t('sf.shown', {n: list.length, total: all.length}))}</span></div>`
      + (list.length ? `<div class="table-wrap"><table class="table sf-table">${head}<tbody>${rows}</tbody></table></div>` : `<p class="muted sf-empty">${esc(t('sf.noMatch'))}</p>`)
      : `<p class="muted sf-empty">${esc(t('sf.empty'))}</p>`)
    + `<div class="sf-foot">${more}<span class="muted">${esc(t('sf.builtAt', {when: d.built_at ? fmtDate(d.built_at) : '—'}))}</span></div>${notes ? `<div class="notes sf-notes">${notes}</div>` : ''}`);
  if (focusSearch) { const inp = $('#sf-search'); inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
}
$('#sf-card').addEventListener('click', (e) => {
  if (e.target.closest('#sf-build')) { buildSurface(); return; }
  if (e.target.closest('#sf-more')) { sf.all = !sf.all; renderSurface(); return; }
  const u = e.target.closest('#sf-unauth'); if (u) { sf.unauth = !sf.unauth; renderSurface(); $('#sf-unauth').focus(); }
});
$('#sf-card').addEventListener('input', (e) => { if (e.target.id === 'sf-search') { sf.q = e.target.value; renderSurface(); } });

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
      ${s.status === 'done' ? `<a class="btn sm icon" href="#compliance/${esc(s.id)}" title="${esc(t('nav.compliance'))}" aria-label="${esc(t('nav.compliance'))}">${ic('compliance', 'sm')}</a>` : ''}
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
  startScan({target: v, authorized: true, profile: $('#url-profile').value, sensitivity: $('#url-sens').value,
    crawl: $('#url-crawl').checked, compare_previous: $('#url-compare').checked, ignore_robots: $('#url-robots').checked,
    third_party_lookups: $('#url-3p').checked, use_proxy: !$('#url-noproxy').checked});
};
let pending = [];
const dz = $('#dropzone');
const setFiles = (files) => {
  pending = [...files];
  $('#upload-list').textContent = pending.length ? `${tn('scan.nSelected', pending.length)}: ${pending.slice(0, 5).map((f) => f.webkitRelativePath || f.name).join(', ')}${pending.length > 5 ? '…' : ''}` : '';
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
    $('#scan-status-title').textContent = `${t('scan.done')} — ${scanName(s)} · ${tn(s.kind === 'url' ? 'find.nPages' : 'find.nFiles', s.files_scanned)}`;
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
$('#triage-filter').onchange = renderFindings; $('#show-fp').onchange = renderFindings;
$('#fix-filter').onclick = (e) => { const b = e.currentTarget; b.setAttribute('aria-pressed', String(b.getAttribute('aria-pressed') !== 'true')); renderFindings(); };
let onlyFp = null;   // ?fp=a,b (from the compliance and attack-surface views): show just these findings
$('#findings-scan').onchange = (e) => { location.hash = `findings/${e.target.value}`; };
async function loadFindings(arg) {
  const [id, qs] = (arg || '').split('?'); const q = new URLSearchParams(qs || '');
  const scans = (await api('/api/scans')).filter((s) => s.status === 'done');
  const sel = $('#findings-scan');
  setHTML(sel, scans.map((s) => `<option value="${esc(s.id)}" title="${esc(s.target)}">${esc(scanName(s))} — ${esc(fmtDate(s.finished_at))}</option>`).join(''));
  sel.title = '';
  const chosen = id || (scans[0] && scans[0].id);
  if (!chosen) {
    cur = null; onlyFp = null; renderChips(); setHTML($('#findings-web'), ''); $('#findings-toolbar2').classList.add('hidden'); $('#findings-comp').classList.add('hidden'); setHTML($('#findings-notes'), ''); setHTML($('#findings-context'), '');
    setHTML($('#findings-list'), `<div class="empty inline"><span class="e-icon">${ic('findings', 'lg')}</span><h2>${esc(t('dash.empty'))}</h2><p class="muted">${esc(t('dash.emptyHint'))}</p><a class="btn primary" href="#scan">${ic('plus')}${esc(t('nav.scan'))}</a></div>`);
    return;
  }
  sel.value = chosen; cur = await api(`/api/scans/${chosen}`); sel.title = cur.target;
  await loadTriage(chosen);
  $('#findings-toolbar2').classList.remove('hidden'); $('#findings-comp').classList.remove('hidden');
  $('#findings-comp').href = `#compliance/${encodeURIComponent(chosen)}`;
  if (q.get('sev')) { sevOn.clear(); sevOn.add(q.get('sev')); } else if (id) { SEV.forEach((s) => sevOn.add(s)); }
  if (q.has('q')) $('#findings-search').value = q.get('q'); else if (id) $('#findings-search').value = '';
  onlyFp = q.get('fp') ? new Set(q.get('fp').split(',').filter(Boolean)) : null;
  renderChips(); renderTriageFilter();
  const sources = [...new Set(cur.findings.map((f) => f.source))];
  setHTML($('#source-filter'), `<option value="">${esc(t('find.allSources'))}</option>` + sources.map((s) => `<option value="${esc(s)}">${esc(srcName(s))}</option>`).join(''));
  ['md', 'json', 'html', 'sarif'].forEach((x) => { $(`#dl-${x}`).href = `/api/scans/${chosen}/report.${x}${x === 'json' ? '' : `?lang=${lang}`}`; });
  setHTML($('#findings-context'), `<span class="ctx" title="${esc(cur.target)}">${ic(cur.kind === 'url' ? 'globe' : 'folder', 'sm')}<b class="ellipsis" dir="auto">${esc(scanName(cur))}</b></span>`
    + `<span class="ctx">${ic('file', 'sm')}${esc(tn(cur.kind === 'url' ? 'find.nPages' : 'find.nFiles', cur.files_scanned))}</span>`
    + `<span class="ctx">${ic('clock', 'sm')}${esc(fmtDate(cur.finished_at))}</span>`
    + `<span class="ctx">${ic('findings', 'sm')}${esc(tn('find.nFindings', total(cur.summary)))}</span>`);
  setHTML($('#findings-notes'), notesOf(cur).map((n) => `<div class="note">${ic('info')}<span>${bidi(n)}</span></div>`).join('')
    + (tri.err ? `<div class="note warn">${ic('warning')}<span>${esc(t('tri.loadFail', {err: tri.err}))}</span></div>` : ''));
  loadWebPanel(cur);
  renderFindings();
  if (onlyFp && shown.length) {          // open the finding the link pointed at
    const row = $('#findings-list .f-row'); if (row) { row.click(); row.focus(); row.scrollIntoView({block: 'nearest'}); }
  }
}
function renderFindings() {
  if (!cur) return;
  const q = $('#findings-search').value.trim().toLowerCase(); const src = $('#source-filter').value;
  const tf = $('#triage-filter').value; const showFp = $('#show-fp').checked; const fixOnly = $('#fix-filter').getAttribute('aria-pressed') === 'true';
  let fpHidden = 0;
  shown = onlyFp ? cur.findings.filter((f) => onlyFp.has(f.fingerprint)) : cur.findings.filter((f) => {
    if (!(sevOn.has(f.severity) && (!src || f.source === src) && (!fixOnly || hasFix(f))
      && (!q || [f.file, f.rule_id, f.title, f.title_ar, f.snippet, f.snippet_en, f.cwe].join(' ').toLowerCase().includes(q)))) return false;
    const st = triStatus(f);
    if (tf) return st === tf;
    if (st === 'false_positive' && !showFp) { fpHidden++; return false; }
    return true;
  });
  const head = `<div class="fl-head"><span>${esc(tn('find.showing', cur.findings.length, {n: shown.length, total: cur.findings.length}))}${fpHidden ? ` <span class="fp-hidden">· ${esc(t('tri.hiddenFp', {n: fpHidden}))}</span>` : ''}</span>${shown.length < cur.findings.length ? `<button class="btn sm ghost" type="button" id="clear-filters">${ic('x', 'sm')}${esc(t('find.clear'))}</button>` : ''}</div>`;
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
          <span class="f-side">${sideHTML(f, flow)}</span>
        </button>
        <div class="f-detail" id="fd-${i}" hidden></div>
      </div>`;
    });
    setHTML($('#findings-list'), html);
  }
  const clr = $('#clear-filters');
  if (clr) {
    clr.onclick = () => {
      SEV.forEach((s) => sevOn.add(s)); $('#findings-search').value = ''; $('#source-filter').value = ''; $('#triage-filter').value = '';
      $('#show-fp').checked = true; $('#fix-filter').setAttribute('aria-pressed', 'false');
      if (onlyFp) { onlyFp = null; history.replaceState(null, '', `#findings/${cur.id}`); }
      renderChips(); renderFindings();
    };
  }
}
const confOf = (f) => { const c = f.extra && f.extra.confidence; return ['certain', 'firm', 'tentative'].includes(c) ? c : ''; };
const CONF_KEY = {certain: 'web.c_certain', firm: 'web.c_firm', tentative: 'web.c_tentative'};
const confTag = (f) => (confOf(f) ? `<span class="tag conf-${confOf(f)}" title="${esc(t('web.confidence'))}">${esc(t(CONF_KEY[confOf(f)]))}</span>` : '');
const sideHTML = (f, flow = isFlow(f)) => `${triTag(f)}${reachTag(f)}${confTag(f)}${hasFix(f) ? `<span class="tag fixable" title="${esc(t('fix.badge'))}">${ic('wrench')}<span class="tx">${esc(t('fix.badge'))}</span></span>` : ''}${flow ? `<span class="tag flow">${ic('flow')}${esc(t('find.dataflow'))}</span>` : ''}${f.cwe ? `<span class="tag">${esc(f.cwe)}</span>` : ''}`;
$('#findings-list').addEventListener('click', (e) => {
  const row = e.target.closest('.f-row'); if (!row) return;
  const box = row.parentElement; const det = box.querySelector('.f-detail');
  const open = row.getAttribute('aria-expanded') !== 'true';
  if (open && !det.dataset.ready) { setHTML(det, detailHTML(shown[+row.dataset.i], +row.dataset.i)); det.dataset.ready = '1'; }
  row.setAttribute('aria-expanded', String(open)); det.hidden = !open; box.classList.toggle('open', open);
});
const REACH = {imported: 'warn', not_imported: 'quiet', vulnerable_function_called: 'danger'};
const reachTag = (f) => {
  const x = f.extra || {}; const r = x.reachability;
  if (!REACH[r]) return '';
  const note = loc(x, 'reachability_note');
  return `<span class="tag reach ${REACH[r]}"${note ? ` title="${esc(note)}"` : ''}>${ic(r === 'not_imported' ? 'check' : r === 'imported' ? 'link' : 'warning')}<span class="sr-only">${esc(t('reach.label'))}: </span>${esc(t('reach.' + r))}</span>`;
};
const hasFix = (f) => !!(f.fix && typeof f.fix === 'object' && (f.fix.diff || f.fix.description || f.fix.description_ar));
/* A unified diff as a code block: the +/− sign stays visible in its own column (colour is never the only cue) and
   screen readers hear "Added line" / "Removed line" before the text. */
function diffHTML(diff) {
  let a = 0, d = 0;
  const rows = String(diff).replace(/\n$/, '').split('\n').map((l) => {
    if (/^(---|\+\+\+|diff |index )/.test(l)) return `<span class="dl meta"><span class="sg"> </span><span class="tx">${esc(l)}</span></span>`;
    if (l.startsWith('@@')) return `<span class="dl hunk"><span class="sg"> </span><span class="tx">${esc(l)}</span></span>`;
    if (l[0] === '+') { a++; return `<span class="dl add"><span class="sg" aria-hidden="true">+</span><span class="sr-only">${esc(t('fix.added'))} </span><span class="tx">${esc(l.slice(1))}</span></span>`; }
    if (l[0] === '-') { d++; return `<span class="dl del"><span class="sg" aria-hidden="true">−</span><span class="sr-only">${esc(t('fix.removed'))} </span><span class="tx">${esc(l.slice(1))}</span></span>`; }
    return `<span class="dl"><span class="sg"> </span><span class="tx">${esc(l.replace(/^ /, ''))}</span></span>`;
  });
  return {html: rows.join(''), a, d};
}
// A path as one shell word for the copy-paste command: plain paths as they are, anything else in single quotes
// (where nothing expands: `$(...)`, `;`, backquotes and `"` stay literal; a `'` is written '\'').
const shArg = (p) => /^[\w@%+=:,./\\-]+$/.test(p) ? p : `'${String(p).replace(/'/g, `'\\''`)}'`;

function fixHTML(f, i) {
  const fx = f.fix; const desc = (lang === 'en' ? (fx.description || fx.description_ar) : (fx.description_ar || fx.description)) || '';
  const file = (Array.isArray(fx.edits) && fx.edits[0] && fx.edits[0].file) || f.file;
  let out = `<section class="d-sec fix"><h2>${ic('wrench')}${esc(t('fix.title'))}</h2>`;
  if (desc) out += `<p class="fix-desc">${bidi(desc)}</p>`;
  if (fx.diff) {
    const df = diffHTML(fx.diff);
    out += `<div class="code diff"><div class="code-head"><span class="p" title="${esc(file)}">${esc(file)}</span><span class="diffstat"><span class="sr-only">${esc(t('fix.stats', {a: df.a, d: df.d}))}</span><span class="plus" aria-hidden="true">+${df.a}</span><span class="minus" aria-hidden="true">−${df.d}</span></span><button class="btn sm" type="button" data-patch="${i}">${ic('copy', 'sm')}<span>${esc(t('fix.copy'))}</span></button></div><pre tabindex="0" role="group" aria-label="${esc(t('fix.diffLabel', {file}))}"><code>${df.html}</code></pre></div>`;
    if (cur && cur.kind === 'path') out += `<p class="fix-apply muted">${esc(t('fix.apply'))} <code dir="ltr">kashif ${esc(shArg(cur.target))} --fix</code></p>`;
  } else if (!Array.isArray(fx.edits) || !fx.edits.length) {
    out += `<p class="fix-apply muted">${ic('info', 'sm')}<span>${esc(t('fix.adviceOnly'))}</span></p>`;
  }
  return out + '</section>';
}
$('#findings-list').addEventListener('click', async (e) => {
  const b = e.target.closest('[data-patch]'); if (!b) return;
  const f = shown[+b.dataset.patch]; if (!f || !f.fix) return;
  if (await copyText(f.fix.diff)) {
    const lbl = b.querySelector('span'); lbl.textContent = t('fix.copied'); b.classList.add('done'); toast(t('fix.copied'));
    setTimeout(() => { lbl.textContent = t('fix.copy'); b.classList.remove('done'); }, 1600);
  }
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
function detailHTML(f, idx) {
  const flow = isFlow(f); const x = f.extra || {};
  const where = `${f.file}${f.line ? ':' + f.line : ''}`;
  const i = Math.max(f.file.lastIndexOf('/'), f.file.lastIndexOf('!'));
  const dir = i >= 0 ? f.file.slice(0, i + 1) : ''; const base = f.file.slice(i + 1);
  const tags = [pill(f.severity), `<span class="tag code" dir="ltr">${esc(f.rule_id)}</span>`, cweTag(f.cwe),
    flow ? `<span class="tag flow">${ic('shield')}${esc(t('find.dataflow'))}</span>` : `<span class="tag">${ic('pattern')}${esc(t('find.pattern'))}</span>`,
    `<span class="tag" title="${esc(f.source)}">${ic('code')}${esc(srcName(f.source))}</span>`,
    reachTag(f), confTag(f), x.decompiled ? '<span class="tag">jadx</span>' : '',
    x.page_count > 1 ? `<span class="tag">${esc(tn('find.onPages', x.page_count))}</span>` : ''].join('');
  let body = `<section class="d-sec"><h2>${ic('file')}${esc(t('find.location'))}</h2><div class="locbar">${ic('file')}<span class="p" title="${esc(where)}">${esc(dir)}<b>${esc(base)}</b>${f.line ? ':' + f.line : ''}</span>${copyBtn(where)}</div></section>`;
  if (flow && x.path && x.path.length) {
    body += `<section class="d-sec"><h2>${ic('flow')}${esc(t('find.flow'))}</h2>${trailHTML(f)}</section>`;
  } else if (f.snippet) {
    const snip = loc(f, 'snippet');
    body += `<section class="d-sec"><h2>${ic('code')}${esc(t('find.snippet'))}</h2><div class="code"><div class="code-head"><span class="p">${esc(where)}</span>${copyBtn(snip)}</div><pre tabindex="0"><span class="ln">${f.line || ''}</span><code>${esc(snip)}</code></pre></div></section>`;
  }
  const adv = loc(f, 'advice');
  if (adv) body += `<section class="d-sec"><div class="remedy">${ic('bulb')}<div><b>${esc(t('find.advice'))}</b><span>${bidi(adv)}</span></div></div></section>`;
  if (hasFix(f)) body += fixHTML(f, idx);
  body += triageHTML(f, idx);
  if (f.source === 'web') body += webDetailHTML(f);
  else if (x.url) body += `<section class="d-sec"><h2>${ic('link')}${esc(t('find.ref'))}</h2><a href="${esc(x.url)}" target="_blank" rel="noopener noreferrer" dir="ltr">${esc(x.url)} ${ic('external', 'xs')}</a></section>`;
  if (x.pages && x.pages.length > 1) body += `<section class="d-sec"><details><summary>${esc(tn('find.onPages', x.pages.length))}</summary><ul class="pages-list">${x.pages.slice(0, 50).map((u) => `<li>${esc(u)}</li>`).join('')}</ul></details></section>`;
  if (f.fingerprint) body += `<div class="fp">${ic('hash')}<span>${esc(t('find.fingerprint'))}</span><code>${esc(f.fingerprint)}</code>${copyBtn(f.fingerprint)}</div>`;
  return `<div class="sev-${f.severity}"><div class="d-tags">${tags}</div><div class="d-grid">${body}</div></div>`;
}

/* ------------------------------------------------------- web scan (1.1.0) */
/* GET /api/scans/<id>/web gives grades, coverage, inventory, copy-paste fixes and the diff, already in the UI
   language. Everything in it came from the scanned site: escaped with esc() and shown as text, never as a link. */
const strList = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string') : []);
function webDetailHTML(f) {
  const x = f.extra || {}; const ev = (x.evidence && typeof x.evidence === 'object') ? x.evidence : {};
  let out = '';
  if (typeof x.url === 'string' && x.url) out += `<section class="d-sec"><h2>${ic('globe')}${esc(t('web.page'))}</h2><div class="locbar"><span class="p" dir="ltr">${esc(x.url)}</span>${copyBtn(x.url)}</div></section>`;
  if (typeof ev.curl === 'string' && ev.curl) out += `<section class="d-sec"><h2>${ic('code')}${esc(t('web.curl'))}</h2><div class="code"><div class="code-head"><span class="p">curl</span>${copyBtn(ev.curl)}</div><pre tabindex="0" dir="ltr"><code>${esc(ev.curl)}</code></pre></div></section>`;
  const ids = [...strList(x.wstg).map((v) => 'WSTG ' + v), ...strList(x.asvs4).map((v) => 'ASVS 4 ' + v), ...strList(x.asvs5).map((v) => 'ASVS 5 ' + v)];
  if (ids.length) out += `<section class="d-sec"><h2>${ic('compliance')}${esc(t('web.mapping'))}</h2><div class="d-tags">${ids.map((v) => `<span class="tag code" dir="ltr">${esc(v)}</span>`).join('')}</div></section>`;
  return out;
}
const webTable = (head, rows, cls = '') => (rows.length
  ? `<div class="tw"><table class="web-table${cls ? ' ' + cls : ''}"><thead><tr>${head.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td dir="auto">${esc(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`
  : `<p class="muted">${esc(t('web.empty'))}</p>`);
function webTabs(name, tabs) {
  if (!tabs.length) return '';
  return `<div class="wtabs" data-wtabs="${esc(name)}"><div class="tabs" role="tablist">${tabs.map((tb, i) => `<button class="tab${i ? '' : ' active'}" type="button" role="tab" aria-selected="${i ? 'false' : 'true'}" data-wt="${i}"><bdi dir="auto">${esc(tb.label)}</bdi></button>`).join('')}</div>`
    + tabs.map((tb, i) => `<div class="wpane${i ? ' hidden' : ''}" role="tabpanel" data-wp="${i}">${tb.body}</div>`).join('') + '</div>';
}
function wireTabs(root) {
  $$('.wtabs', root).forEach((box) => {
    $$(':scope > .tabs > .tab', box).forEach((b) => { b.onclick = () => {
      $$(':scope > .tabs > .tab', box).forEach((x) => { x.classList.toggle('active', x === b); x.setAttribute('aria-selected', String(x === b)); });
      $$(':scope > .wpane', box).forEach((p) => p.classList.toggle('hidden', p.dataset.wp !== b.dataset.wt));
    }; });
  });
}
function webPanelHTML(v) {
  const num = (n) => (typeof n === 'number' && Number.isFinite(n) ? String(n) : '');
  const f = v.facts || {};
  let html = `<div class="card web-card"><div class="web-facts">${[['web.profile', f.profile], ['web.requests', num(f.requests)], ['web.final', f.final_url], ['web.data', f.data_date]]
    .filter(([, val]) => val).map(([k, val]) => `<span class="ctx">${esc(t(k))}: <b dir="ltr">${esc(val)}</b></span>`).join('')}</div>`;
  const grades = Array.isArray(v.grades) ? v.grades : [];
  html += `<h2 class="web-h">${ic('shield')}${esc(t('web.grades'))}</h2><div class="grade-cards">${grades.map((g) => {
    const score = num(g.score) ? num(g.score) + (num(g.max) ? '/' + num(g.max) : '') : '';
    const caps = strList(g.caps);
    return `<div class="grade-card g-${esc(g.key)}"><span class="g-name">${esc(g.name)}</span><span class="g-letter" dir="ltr">${esc(g.grade || '—')}</span>`
      + `<span class="muted" dir="ltr">${esc(score || (g.grade ? '' : t('web.none')))}</span>`
      + (g.label ? `<small class="muted">${bidi(g.label)}</small>` : '')
      + strList(g.notes).slice(0, 4).map((n) => `<small class="muted">${bidi(n)}</small>`).join('')
      + (caps.length ? `<details><summary>${esc(t('web.caps'))}</summary><ul>${caps.slice(0, 8).map((c) => `<li>${bidi(c)}</li>`).join('')}</ul></details>` : '') + '</div>';
  }).join('')}</div>`;
  if (grades.some((g) => g.provisional)) html += `<p class="muted small">${esc(t('web.provisional'))}</p>`;
  const cov = v.coverage || {}; const counts = cov.counts || {}; const states = cov.states || {};
  html += `<h2 class="web-h">${ic('check')}${esc(t('web.coverage'))}</h2><div class="cov-chips">${['pass', 'fail', 'not_applicable', 'not_tested', 'inconclusive']
    .map((s) => `<span class="chip cov-${s}">${esc(states[s] || s)} <b>${esc(num(counts[s]) || '0')}</b></span>`).join('')}</div><p class="muted small">${esc(t('web.covNote'))}</p>`;
  const probs = Array.isArray(cov.problems) ? cov.problems : [];
  if (probs.length) html += `<details class="web-details"><summary>${esc(t('web.covDetails'))} (${probs.length})</summary>${webTable([t('web.check'), t('web.state'), t('web.reason')], probs.map((r) => strList(r)), 'cov-table')}</details>`;
  const d = v.diff;
  if (d && typeof d === 'object') {
    html += `<h2 class="web-h">${ic('compare')}${esc(t('web.diff'))}</h2>` + strList(d.notes).map((n) => `<p class="muted">${bidi(n)}</p>`).join('');
    if (d.comparable) {
      const rowsOf = (list) => (Array.isArray(list) ? list : []).map((r) => `<li>${pill(['critical', 'high', 'medium', 'low', 'info'].includes(r.severity) ? r.severity : 'info')} <code dir="ltr">${esc(r.rule)}</code> <span dir="auto">${esc(r.title)}</span></li>`).join('');
      const post = Array.isArray(d.posture) ? d.posture : [];
      if (strList(d.grades).length) html += `<p><b>${esc(t('web.dGrades'))}:</b> ${strList(d.grades).map((g) => `<bdi>${bidi(g)}</bdi>`).join(' · ')}</p>`;
      html += `<div class="diff-grid"><div><h3>${esc(t('web.dNew'))} <span class="count">${esc(String((d.new || []).length))}</span></h3><ul class="diff-list">${rowsOf(d.new)}</ul></div>`
        + `<div><h3>${esc(t('web.dResolved'))} <span class="count">${esc(String((d.resolved || []).length))}</span></h3><ul class="diff-list">${rowsOf(d.resolved)}</ul></div></div>`
        + `<p class="muted small">${esc(t('web.dUnchanged'))}: ${esc(num(d.unchanged) || '0')}</p>`
        + `<h3>${esc(t('web.dPosture'))}</h3>` + (post.length ? `<ul class="posture">${post.map((p) => `<li class="dir-${esc(p.direction)}"><b>${esc(p.label)}</b> <span dir="auto">${bidi(p.text)}</span></li>`).join('')}</ul>` : `<p class="muted">${esc(t('web.dNone'))}</p>`);
    }
  }
  const inv = Array.isArray(v.inventory) ? v.inventory : [];
  html += `<h2 class="web-h">${ic('search')}${esc(t('web.inventory'))}</h2>` + webTabs('inv', inv.map((tb) => ({label: tb.label, body: webTable(strList(tb.head), (Array.isArray(tb.rows) ? tb.rows : []).map((r) => strList(r)))})));
  const rem = Array.isArray(v.remediation) ? v.remediation : [];
  if (rem.length) {
    html += `<h2 class="web-h">${ic('wrench')}${esc(t('web.remediation'))}</h2><p class="muted small">${esc(t('web.remHint'))}</p>`;
    html += rem.map((sn, i) => {
      const blocks = [...(Array.isArray(sn.detected) ? sn.detected : []), ...(Array.isArray(sn.other) ? sn.other : [])];
      return `<div class="snip"><h3><code dir="ltr">${esc(sn.id)}</code> ${esc(sn.title)}</h3><p>${esc(sn.summary)}</p>`
        + (sn.caveat ? `<p class="caveat">${ic('warning', 'sm')}<b>${esc(t('web.caution'))}:</b> ${esc(sn.caveat)}</p>` : '')
        + webTabs('rem' + i, blocks.map((b) => ({label: b.name || b.platform || '', body: (b.code ? `<div class="code"><div class="code-head"><span class="p" dir="ltr">${esc(b.lang || '')}</span>${copyBtn(b.code)}</div><pre tabindex="0" dir="ltr"><code>${esc(b.code)}</code></pre></div>` : '') + (b.note ? `<p class="muted small">${esc(b.note)}</p>` : '')}))) + '</div>';
    }).join('');
  }
  return html + '</div>';
}
async function loadWebPanel(scan) {
  const box = $('#findings-web');
  if (!scan || scan.kind !== 'url' || !scan.web) { setHTML(box, ''); return; }
  try {
    const v = await api(`/api/scans/${encodeURIComponent(scan.id)}/web?lang=${lang}`);
    if (cur !== scan) return;              // another scan was chosen meanwhile
    setHTML(box, webPanelHTML(v)); wireTabs(box);
  } catch (err) { setHTML(box, `<div class="note warn">${ic('warning')}<span>${esc(t('web.loadFail', {err: err.message}))}</span></div>`); }
}

/* -------------------------------------------------------------- triage */
/* GET /api/triage?scan= gives the effective decision of every finding; POST /api/triage/set|comment records one.
   Everything in the triage file comes from the scanned repository: escape it all, look fingerprints up in a Map. */
const TRI_JUST = new Set(['false_positive', 'accepted_risk', 'wont_fix']);
const tri = {scan: null, data: null, ann: new Map(), raw: new Map(), err: null};
const apiRaw = async (path, opts = {}) => {
  const r = await fetch(path, {headers: {'Content-Type': 'application/json'}, cache: 'no-store', ...opts});
  return {ok: r.ok, status: r.status, data: await r.json().catch(() => ({}))};
};
const apiErr = (d, fallback = '') => (lang === 'ar' && d && typeof d.error_ar === 'string' && d.error_ar) || (d && d.error ? errText(String(d.error)) : '') || fallback;
const fmtIso = (s) => { const d = new Date(s); return s && !Number.isNaN(d.getTime()) ? dateIso(d.toLocaleString(locale(), {dateStyle: 'medium', timeStyle: 'short'})) : String(s || ''); };
const isHttp = (u) => typeof u === 'string' && /^https?:\/\/[^\s"'<>]+$/i.test(u);
async function loadTriage(scanId) {
  tri.scan = scanId; tri.data = null; tri.ann = new Map(); tri.raw = new Map(); tri.err = null;
  try {
    const r = await apiRaw(`/api/triage?scan=${encodeURIComponent(scanId)}&lang=${lang}`);
    if (!r.ok) { tri.err = apiErr(r.data, String(r.status)); return; }
    tri.data = r.data;
    Object.entries(r.data.annotations || {}).forEach(([k, v]) => { if (v && typeof v === 'object') tri.ann.set(k, v); });
    Object.entries(r.data.findings || {}).forEach(([k, v]) => { if (v && typeof v === 'object') tri.raw.set(k, v); });
  } catch (e) { tri.err = e.message; }
}
const triStatus = (f) => { const a = tri.ann.get(f.fingerprint); return (a && typeof a.status === 'string' && a.status) || 'open'; };
const triLabel = (st) => {
  const o = tri.data && Array.isArray(tri.data.statuses) && tri.data.statuses.find((x) => x.id === st);
  return o ? ((lang === 'en' ? o.label_en : o.label_ar) || o.label || st) : String(st).replace(/_/g, ' ');
};
const triTag = (f) => {
  const a = tri.ann.get(f.fingerprint); if (!a) return '';
  const st = triStatus(f); const flag = !!(a.expired || a.regression);
  if (st === 'open' && !flag) return '';
  const note = a.expired ? t('tri.expired') : a.regression ? t('tri.regression') : '';
  return `<span class="tag tri st-${esc(st)}${flag ? ' flagged' : ''}"${note ? ` title="${esc(note)}"` : ''}>${ic(flag ? 'warning' : 'flag')}${esc(triLabel(st))}${note ? `<span class="sr-only"> — ${esc(note)}</span>` : ''}</span>`;
};
function renderTriageFilter() {
  const sel = $('#triage-filter'); const v = sel.value;
  const counts = new Map(); (cur ? cur.findings : []).forEach((f) => { const s = triStatus(f); counts.set(s, (counts.get(s) || 0) + 1); });
  const ids = tri.data && Array.isArray(tri.data.statuses) ? tri.data.statuses.map((s) => s.id) : [...counts.keys()];
  setHTML(sel, `<option value="">${esc(t('tri.all'))}</option>` + ids.map((id) => `<option value="${esc(id)}">${esc(triLabel(id))} (${counts.get(id) || 0})</option>`).join(''));
  sel.value = ids.includes(v) ? v : '';
  const fp = counts.get('false_positive') || 0;
  $('#show-fp-n').textContent = fp ? `(${fp})` : '';
  $('#fix-filter-n').textContent = cur ? String(cur.findings.filter(hasFix).length) : '';
}
const TRI_ACTS = new Set(['status', 'comment', 'severity', 'expired', 'regression', 'auto']);
function triageHTML(f, i) {
  if (!f.fingerprint || !tri.data) return '';
  const a = tri.ann.get(f.fingerprint) || {}; const raw = tri.raw.get(f.fingerprint) || {};
  const st = triStatus(f);
  const opts = tri.data.statuses.map((s) => `<option value="${esc(s.id)}"${s.id === st ? ' selected' : ''}>${esc(triLabel(s.id))}</option>`).join('');
  const flags = (a.expired ? `<span class="tag tri flagged">${ic('warning')}${esc(t('tri.expired'))}</span>` : '')
    + (a.regression ? `<span class="tag tri flagged">${ic('warning')}${esc(t('tri.regression'))}</span>` : '');
  const ticket = isHttp(raw.ticket) ? raw.ticket : '';
  const who = raw.author || a.author; const when = raw.updated || a.updated;
  const state = `<div class="tri-cur"><span class="tag tri st-${esc(st)}">${ic('flag')}${esc(triLabel(st))}</span>${flags}`
    + `<span class="muted">${a.tracked || raw.updated ? esc(t('tri.by', {who: who || '—', when: fmtIso(when)})) : esc(t('tri.untracked'))}</span>`
    + (ticket ? `<a class="link" href="${esc(ticket)}" target="_blank" rel="noopener noreferrer" dir="ltr">${ic('link', 'xs')}${esc(ticket.replace(/^https?:\/\//i, '').slice(0, 60))}</a>` : '') + '</div>'
    + (raw.justification ? `<p class="tri-just">${bidi(raw.justification)}</p>` : '');
  const exp = /^\d{4}-\d{2}-\d{2}$/.test(raw.expires || '') ? raw.expires : '';
  const tomorrow = new Date(Date.now() + 86400000).toISOString().slice(0, 10);
  const id = `tri-${i}`;
  const where = tri.data.in_project ? '.kashif/triage.json' : String(tri.data.file || '');
  const fileNote = esc(t(tri.data.in_project ? 'tri.fileProject' : 'tri.fileHome', {file: '\u0001'})).replace('\u0001', `<bdi dir="ltr">${esc(where)}</bdi>`);
  const form = `<form class="tri-form" data-tri="${i}" novalidate>
    <div class="tri-top">
      <div class="field"><label for="${id}-st">${esc(t('tri.status'))}</label><select class="input" id="${id}-st" name="status">${opts}</select></div>
      <div class="field tri-exp"${st === 'accepted_risk' ? '' : ' hidden'}><label for="${id}-ex">${esc(t('tri.expires'))}</label><input class="input" type="date" id="${id}-ex" name="expires" min="${tomorrow}" value="${esc(exp)}"></div>
      <div class="field tri-tk"><label for="${id}-tk">${esc(t('tri.ticket'))}</label><input class="input" type="url" id="${id}-tk" name="ticket" dir="ltr" placeholder="https://" maxlength="2000" value="${esc(ticket)}" aria-describedby="${id}-msg"></div>
    </div>
    <div class="tri-texts">
      <div class="field"><label for="${id}-j">${esc(t('tri.justification'))} <span class="req muted"${TRI_JUST.has(st) ? '' : ' hidden'}>${esc(t('tri.justReq'))}</span></label><textarea class="input" rows="2" id="${id}-j" name="justification" maxlength="2000" dir="auto" aria-describedby="${id}-msg">${esc(raw.justification || '')}</textarea></div>
      <div class="field"><label for="${id}-c">${esc(t('tri.comment'))}</label><textarea class="input" rows="2" id="${id}-c" name="comment" maxlength="2000" dir="auto"></textarea></div>
    </div>
    <div class="tri-actions"><button class="btn primary sm" type="submit">${ic('flag', 'sm')}<span>${esc(t('tri.save'))}</span></button><button class="btn sm" type="button" data-tri-comment>${esc(t('tri.addComment'))}</button><span class="tri-msg" id="${id}-msg" role="status"></span></div>
    <p class="tri-file muted">${ic('file', 'xs')}<span>${fileNote}</span></p>
  </form>`;
  const log = Array.isArray(raw.log) ? raw.log.filter((x) => x && typeof x === 'object').slice(-30).reverse() : [];
  const arrow = lang === 'ar' ? '←' : '→';
  const hist = log.length ? `<details class="tri-log"><summary>${esc(t('tri.history', {n: log.length}))}</summary><ol>${log.map((x) => {
    const act = TRI_ACTS.has(x.action) ? t('tri.act.' + x.action) : String(x.action || '');
    const what = x.action === 'status' ? ` <span class="tri-move">${esc(triLabel(String(x.from || 'open')))} ${arrow} ${esc(triLabel(String(x.to || '')))}</span>` : '';
    const text = typeof x.text === 'string' && x.text ? x.text : (typeof x.justification === 'string' ? x.justification : '');
    return `<li><span class="muted">${esc(fmtIso(x.at))} · <bdi>${esc(x.author || '')}</bdi></span> <b>${esc(act)}</b>${what}${text ? `<q dir="auto">${esc(text)}</q>` : ''}</li>`;
  }).join('')}</ol></details>` : '';
  return `<section class="d-sec tri-sec" data-tri-sec="${i}"><h2>${ic('flag')}${esc(t('tri.title'))}</h2>${state}${form}${hist}</section>`;
}
const triMsg = (form, text, bad) => { const m = $('.tri-msg', form); m.textContent = text; m.classList.toggle('err', !!bad); };
async function triSave(form, action) {
  const i = +form.dataset.tri; const f = shown[i]; if (!f || !cur) return;
  const el = form.elements; const st = el.status.value; const just = el.justification.value.trim();
  const ticket = el.ticket.value.trim(); const comment = el.comment.value.trim();
  [el.justification, el.ticket, el.comment].forEach((x) => x.removeAttribute('aria-invalid'));
  let body;
  if (action === 'comment') {
    if (!comment) { el.comment.setAttribute('aria-invalid', 'true'); el.comment.focus(); return; }
    body = {scan: cur.id, fingerprint: f.fingerprint, text: comment};
  } else {
    if (TRI_JUST.has(st) && !just) { el.justification.setAttribute('aria-invalid', 'true'); triMsg(form, t('tri.needJust'), true); el.justification.focus(); return; }
    if (ticket && !isHttp(ticket)) { el.ticket.setAttribute('aria-invalid', 'true'); triMsg(form, t('tri.ticketBad'), true); el.ticket.focus(); return; }
    body = {scan: cur.id, fingerprint: f.fingerprint, status: st, justification: just, ticket, comment};
    if (st === 'accepted_risk' && el.expires.value) body.expires = el.expires.value;
  }
  const btns = $$('button', form); btns.forEach((b) => { b.disabled = true; });
  let r;
  try { r = await apiRaw(`/api/triage/${action === 'comment' ? 'comment' : 'set'}`, {method: 'POST', body: JSON.stringify(body)}); } catch (err) { r = {ok: false, data: {error: err.message}}; }
  btns.forEach((b) => { b.disabled = false; });
  if (!r.ok) { triMsg(form, apiErr(r.data, String(r.status || '')), true); return; }
  await loadTriage(cur.id);
  const box = form.closest('.finding'); const sec = form.closest('.tri-sec');
  const tmp = document.createElement('div'); setHTML(tmp, triageHTML(f, i));
  const fresh = tmp.firstElementChild; sec.replaceWith(fresh);
  const side = $('.f-side', box); if (side) setHTML(side, sideHTML(f));
  renderTriageFilter();
  triMsg($('.tri-form', fresh), t(action === 'comment' ? 'tri.commented' : 'tri.saved'));
  $('select', fresh).focus();
}
$('#findings-list').addEventListener('submit', (e) => { const form = e.target.closest('.tri-form'); if (!form) return; e.preventDefault(); triSave(form, 'set'); });
$('#findings-list').addEventListener('click', (e) => { const b = e.target.closest('[data-tri-comment]'); if (b) triSave(b.closest('.tri-form'), 'comment'); });
$('#findings-list').addEventListener('change', (e) => {
  const form = e.target.closest('.tri-form'); if (!form || e.target.name !== 'status') return;
  const st = e.target.value;
  $('.tri-exp', form).hidden = st !== 'accepted_risk';
  $('.req', form).hidden = !TRI_JUST.has(st);
  triMsg(form, '');
});

/* -------------------------------------------------------------- export */
/* Every exporter format downloads from GET /api/scans/<id>/export?format=..; the list comes from the server. */
let fmtCache = {lang: null, list: null};
const expBtn = $('#export-btn'); const expMenu = $('#export-menu');
// A name that starts in Latin script and holds Arabic in parentheses ("SonarQube (Generic Issue Import، الإصدار …)")
// is mangled by the bidi algorithm in an RTL page: isolate it as one left-to-right run.
const ltrName = (s) => (lang === 'ar' && /^[A-Za-z]/.test(String(s || '')) ? `<bdi dir="ltr">${esc(s)}</bdi>` : esc(s));
const itemInner = (f) => `<span class="mi-text"><b>${ltrName(f.name)}</b><small>${esc(f.description)}</small></span><span class="mi-ext" dir="ltr">.${esc(f.ext)}</span>`;
async function renderExportMenu() {
  if (!cur) return;
  try {
    if (fmtCache.lang !== lang || !fmtCache.list) fmtCache = {lang, list: await api(`/api/export/formats?lang=${lang}`)};
  } catch { setHTML(expMenu, `<p class="menu-note">${ic('warning', 'sm')}<span>${esc(t('exp.loadFail'))}</span></p>`); return; }
  const base = `/api/scans/${encodeURIComponent(cur.id)}/export?lang=${lang}&format=`;
  setHTML(expMenu, `<p class="menu-title">${esc(t('exp.title'))}</p><ul class="menu-list">${fmtCache.list.map((f) => (Array.isArray(f.needs) && f.needs.length
    ? `<li><details class="menu-aws"><summary class="menu-item">${itemInner(f)}</summary><form class="menu-form" data-fmt="${esc(f.id)}" novalidate>
        <div class="field"><label for="exp-acct">${esc(t('exp.aws'))}</label><input class="input" id="exp-acct" name="aws_account_id" inputmode="numeric" maxlength="12" dir="ltr" autocomplete="off"></div>
        <div class="field"><label for="exp-region">${esc(t('exp.region'))}</label><input class="input" id="exp-region" name="aws_region" dir="ltr" placeholder="us-east-1" maxlength="30" autocomplete="off"></div>
        <button class="btn sm primary" type="submit">${ic('download', 'sm')}<span>${esc(t('exp.download'))}</span></button><p class="menu-err" role="status"></p></form></details></li>`
    : `<li><a class="menu-item" href="${base}${encodeURIComponent(f.id)}" download>${itemInner(f)}</a></li>`)).join('')}</ul><p class="menu-note">${ic('info', 'sm')}<span>${esc(t('exp.hint'))}</span></p>`);
}
function setExport(open) {
  if (!expBtn) return;
  const was = expBtn.getAttribute('aria-expanded') === 'true';
  expBtn.setAttribute('aria-expanded', String(open)); expMenu.classList.toggle('hidden', !open);
  if (open && !was) renderExportMenu().then(() => { const first = $('.menu-item', expMenu); if (first) first.focus(); });
}
expBtn.onclick = () => setExport(expBtn.getAttribute('aria-expanded') !== 'true');
expMenu.addEventListener('keydown', (e) => {
  if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
  const items = $$('.menu-item', expMenu); const k = items.indexOf(document.activeElement); if (k < 0) return;
  e.preventDefault(); items[(k + (e.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length].focus();
});
expMenu.addEventListener('click', (e) => { if (e.target.closest('a.menu-item')) setTimeout(() => setExport(false), 0); });
expMenu.addEventListener('submit', (e) => {
  const form = e.target.closest('.menu-form'); if (!form || !cur) return; e.preventDefault();
  const acct = form.elements.aws_account_id.value.trim(); const region = form.elements.aws_region.value.trim();
  if (!/^\d{12}$/.test(acct) || !/^[a-z]{2}(-[a-z]+)+-\d{1,2}$/.test(region)) { $('.menu-err', form).textContent = t('exp.needAws'); (/^\d{12}$/.test(acct) ? form.elements.aws_region : form.elements.aws_account_id).focus(); return; }
  const a = document.createElement('a');
  a.href = `/api/scans/${encodeURIComponent(cur.id)}/export?lang=${lang}&format=${encodeURIComponent(form.dataset.fmt)}&aws_account_id=${acct}&aws_region=${encodeURIComponent(region)}`;
  a.download = ''; document.body.appendChild(a); a.click(); a.remove(); setExport(false);
});
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && expBtn.getAttribute('aria-expanded') === 'true') { setExport(false); expBtn.focus(); } });
document.addEventListener('click', (e) => { if (expBtn.getAttribute('aria-expanded') === 'true' && !e.target.closest('.menu-wrap')) setExport(false); });

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

/* ---------------------------------------------------------- compliance */
/* GET /api/scans/<id>/compliance?framework=all: per-framework control rows. A control without findings has status
   "pass" and is labelled "No findings" — never "Pass" or "Compliant". */
const comp = {key: '', data: null, scan: null, fw: '', all: false, byId: new Map()};
const stBadge = (st) => { const k = ['fail', 'warn', 'pass'].includes(st) ? st : 'warn'; return `<span class="cst st-${k}">${ic(k === 'fail' ? 'warning' : k === 'warn' ? 'eye' : 'check', 'xs')}${esc(t('comp.st_' + k))}</span>`; };
$('#comp-scan').onchange = (e) => { location.hash = `compliance/${e.target.value}`; };
$('#fw-all').onchange = (e) => { comp.all = e.target.checked; renderFramework(); };
async function loadCompliance(arg) {
  const id = (arg || '').split('?')[0];
  const scans = (await api('/api/scans')).filter((s) => s.status === 'done');
  const sel = $('#comp-scan');
  setHTML(sel, scans.map((s) => `<option value="${esc(s.id)}" title="${esc(s.target)}">${esc(scanName(s))} — ${esc(fmtDate(s.finished_at))}</option>`).join(''));
  const has = (x) => x && scans.some((s) => s.id === x);
  const chosen = has(id) ? id : has(cur && cur.id) ? cur.id : (scans[0] && scans[0].id);
  ['#comp-body', '#comp-audit', '#comp-scan'].forEach((x) => $(x).classList.toggle('hidden', !chosen));
  $('#comp-empty').classList.toggle('hidden', !!chosen);
  if (!chosen) {
    setHTML($('#comp-context'), '');
    setHTML($('#comp-empty'), `<div class="empty card"><span class="e-icon">${ic('compliance', 'lg')}</span><h2>${esc(t('comp.empty'))}</h2><p class="muted">${esc(t('dash.emptyHint'))}</p><a class="btn primary" href="#scan">${ic('plus')}${esc(t('nav.scan'))}</a></div>`);
    return;
  }
  sel.value = chosen; sel.title = (scans.find((s) => s.id === chosen) || {}).target || '';
  comp.scan = scans.find((s) => s.id === chosen);
  const key = `${chosen}|${lang}`;
  if (comp.key !== key) {
    setHTML($('#fw-grid'), `<p class="muted fw-loading"><span class="spinner sm"></span> ${esc(t('comp.loading'))}</p>`);
    comp.data = await api(`/api/scans/${encodeURIComponent(chosen)}/compliance?framework=all&lang=${lang}`);
    comp.key = key;
    comp.byId = new Map((comp.data.findings || []).filter((f) => f && f.id).map((f) => [f.id, f]));
  }
  renderCompliance();
}
function renderCompliance() {
  const d = comp.data; const s = comp.scan; const fws = d.frameworks || {}; const ids = Object.keys(fws);
  if (!ids.includes(comp.fw)) comp.fw = ids[0] || '';
  const risk = d.risk || {}; const rating = ['none', 'low', 'moderate', 'high', 'critical'].includes(risk.rating) ? risk.rating : 'none';
  const sid = encodeURIComponent(s.id);
  setHTML($('#comp-context'), `<span class="ctx" title="${esc(s.target)}">${ic(s.kind === 'url' ? 'globe' : 'folder', 'sm')}<b class="ellipsis" dir="auto">${esc(scanName(s))}</b></span>`
    + `<span class="ctx">${ic('clock', 'sm')}${esc(fmtDate(s.finished_at))}</span>`
    + `<span class="ctx">${ic('findings', 'sm')}${esc(tn('find.nFindings', total(s.summary || {})))}</span>`
    + `<span class="ctx risk r-${rating}">${ic('warning', 'sm')}<span class="muted">${esc(t('comp.risk'))}:</span> <b>${Number(risk.score) || 0}/100</b> <span class="rating">${esc(t('comp.r_' + rating))}</span></span>`
    + `<a class="ctx link" href="#findings/${sid}">${ic('findings', 'sm')}${esc(t('scan.viewResults'))}</a>`);
  $('#comp-disclaimer span').textContent = d.disclaimer || '';
  $('#comp-audit').href = `/api/scans/${sid}/audit.html?framework=all&lang=${lang}`;
  setHTML($('#fw-grid'), ids.map((fid) => {
    const fw = fws[fid]; const on = fid === comp.fw;
    const tot = Number(fw.controls_total) || 0; const w = Number(fw.controls_with_findings) || 0;
    const pct = tot ? Math.round((w / tot) * 100) : 0; const st = ['fail', 'warn', 'pass'].includes(fw.status) ? fw.status : 'warn';
    return `<button type="button" class="fw-card st-${st}" data-fw="${esc(fid)}" aria-pressed="${on}" aria-label="${esc(tn('comp.fwLabel', tot, {name: fw.title, status: t('comp.st_' + st), with: w, total: tot}))}">
      <span class="fw-top"><b>${esc(fw.short || fw.title)}</b>${stBadge(st)}</span>
      <span class="fw-name muted">${esc(fw.title)}</span>
      <span class="fw-bar" aria-hidden="true"><i style="width:${pct}%"></i></span>
      <span class="fw-nums">${esc(tn('comp.controlsWith', tot, {n: w, total: tot}))}</span>
      <span class="fw-nums muted">${esc(tn('comp.mapped', Number(fw.findings_mapped) || 0))}${fw.findings_unmapped ? ' · ' + esc(tn('comp.unmapped', Number(fw.findings_unmapped) || 0)) : ''}</span>
    </button>`;
  }).join(''));
  renderFramework();
}
$('#fw-grid').onclick = (e) => {
  const b = e.target.closest('[data-fw]'); if (!b) return;
  comp.fw = b.dataset.fw;
  $$('#fw-grid [data-fw]').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
  renderFramework();
};
function renderFramework() {
  const fw = comp.data && (comp.data.frameworks || {})[comp.fw];
  $('#fw-detail').classList.toggle('hidden', !fw); if (!fw) return;
  const sid = encodeURIComponent(comp.scan.id);
  $('#fw-title').textContent = fw.title || comp.fw;
  $('#fw-all').checked = comp.all;
  $('#fw-audit').href = `/api/scans/${sid}/audit.html?framework=${encodeURIComponent(comp.fw)}&lang=${lang}`;
  const src = fw.source || {};
  setHTML($('#fw-meta'), (fw.note ? `<p><b>${esc(t('comp.note'))}:</b> ${bidi(fw.note)}</p>` : '')
    + (src.title ? `<p><b>${esc(t('comp.source'))}:</b> ${isHttp(src.url) && /^https:/i.test(src.url) ? `<a href="${esc(src.url)}" target="_blank" rel="noopener noreferrer"><span>${bidi(src.title)}</span>${ic('external', 'xs')}</a>` : bidi(src.title)}</p>` : ''));
  const rows = Array.isArray(fw.rows) ? fw.rows : [];
  const list = comp.all ? rows : rows.filter((r) => r.status !== 'pass');
  const hidden = rows.length - list.length;
  const head = `<thead><tr><th>${esc(t('comp.control'))}</th><th>${esc(t('comp.ctitle'))}</th><th>${esc(t('rules.sev'))}</th><th class="num">${esc(t('comp.total'))}</th><th>${esc(t('comp.status'))}</th></tr></thead>`;
  const body = list.map((r, k) => `<tr class="ctl-row">
      <td class="ctl"><button class="ctl-btn" type="button" data-ctl="${k}" aria-expanded="false" aria-controls="ctl-${k}"${r.total ? '' : ' disabled'} aria-label="${esc(t('comp.showFindings', {c: r.control}))}">${ic('chevron', 'sm chev')}<code dir="ltr">${esc(r.control)}</code></button></td>
      <td class="ctl-title" dir="${dirOf(r.title)}">${bidi(r.title)}</td>
      <td>${r.total ? `<span class="sevcs">${sevCounts(r.counts || {})}</span>` : '<span class="muted">—</span>'}</td>
      <td class="num"><b>${Number(r.total) || 0}</b></td>
      <td>${stBadge(r.status)}</td></tr>
    <tr class="ctl-findings" id="ctl-${k}" hidden><td colspan="5"></td></tr>`).join('');
  setHTML($('#fw-table'), head + `<tbody>${body || `<tr><td colspan="5" class="muted fw-none">${esc(t('comp.none'))}</td></tr>`}</tbody>`
    + (hidden ? `<tfoot><tr><td colspan="5" class="muted fw-hidden">${esc(tn('comp.hidden', hidden))}</td></tr></tfoot>` : ''));
  comp.list = list;
}
$('#fw-table').addEventListener('click', (e) => {
  const b = e.target.closest('[data-ctl]'); if (!b) return;
  const r = comp.list[+b.dataset.ctl]; const tr = document.getElementById(b.getAttribute('aria-controls'));
  const open = b.getAttribute('aria-expanded') !== 'true';
  if (open && !tr.dataset.ready) {
    const fs = (r.findings || []).map((x) => comp.byId.get(x)).filter(Boolean);
    const sid = encodeURIComponent(comp.scan.id);
    setHTML(tr.firstElementChild, `<ul class="rank ctl-list">${fs.slice(0, 50).map((f) => `<li class="sev-${esc(f.severity)}"><span class="main">${pill(f.severity)}<a class="title" dir="${dirOf(f.title)}" href="#findings/${sid}?fp=${encodeURIComponent(f.fingerprint || '')}">${esc(f.title)}</a></span>${fpath(f.file, f.line)}</li>`).join('')}${fs.length > 50 ? `<li class="empty-li">${esc(tn('proj.more', fs.length - 50))}</li>` : ''}</ul>`);
    tr.dataset.ready = '1';
  }
  b.setAttribute('aria-expanded', String(open)); tr.hidden = !open; b.closest('tr').classList.toggle('open', open);
});

/* --------------------------------------------------------------- rules */
let rulesCache = null;
async function loadRules() {
  rulesCache = rulesCache || await api('/api/rules');
  $('#rules-count').textContent = tn('rules.n', rulesCache.length);
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
  f.web_profile.value = ['minimal', 'standard', 'deep'].includes(s.web_profile) ? s.web_profile : 'standard';
  f.web_sensitivity.value = ['strict', 'default', 'paranoid'].includes(s.web_sensitivity) ? s.web_sensitivity : 'default';
  f.web_compare_previous.checked = s.web_compare_previous !== false; f.web_respect_robots.checked = s.web_respect_robots !== false;
  f.web_third_party_lookups.checked = !!s.web_third_party_lookups; f.web_use_proxy.checked = s.web_use_proxy !== false;
  $('#url-profile').value = f.web_profile.value; $('#url-sens').value = f.web_sensitivity.value;
  $('#url-compare').checked = f.web_compare_previous.checked; $('#url-3p').checked = f.web_third_party_lookups.checked;
  $('#url-noproxy').checked = !f.web_use_proxy.checked; $('#url-robots').checked = !f.web_respect_robots.checked;
  webDefaultsSet = true;
  $('#jadx-state').textContent = meta.jadx ? t('set.jadxOn') : t('set.jadxOff');
  $('#ext-tools').textContent = `(${meta.external_tools.length ? meta.external_tools.join(', ') : t('set.none')})`;
  setHTML($('#settings-home'), `${esc(t('set.home'))}<span class="home-path" dir="ltr" title="${esc(meta.home)}">${esc(meta.home)}</span>`);
  $('#version').textContent = 'v' + meta.version;
  $('#about-version').textContent = 'v' + meta.version;
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
      models_dir: f.models_dir.value.trim(), queries_dir: f.queries_dir.value.trim(), check_updates: f.check_updates.checked,
      web_profile: f.web_profile.value, web_sensitivity: f.web_sensitivity.value, web_compare_previous: f.web_compare_previous.checked,
      web_respect_robots: f.web_respect_robots.checked, web_third_party_lookups: f.web_third_party_lookups.checked,
      web_use_proxy: f.web_use_proxy.checked})});
  } catch (err) { toast(err.message); return; }
  webDefaultsSet = false;
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
