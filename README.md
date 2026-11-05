# vulnscan — فاحص ثغرات مستقل لأي برنامج

أداة سطر أوامر بلغة Python (بدون أي اعتماديات خارجية) تفحص **أي برنامج** وتُخرج تقريرًا
مرتبًا **من الأعلى خطورة إلى الأقل**: حرج ← عالٍ ← متوسط ← منخفض ← معلوماتي.

> ⚠️ **الصلاحية أولًا:** افحص فقط ما تملكه أو ما لديك تصريح كتابي بفحصه. فحص أنظمة الآخرين دون إذن
> قد يكون مخالفًا للقانون. فحص عناوين الويب لا يعمل إلا مع العلامة `--authorized`.

## ماذا يفحص؟

| الهدف | مثال | ما يحدث |
|---|---|---|
| مجلد مصدر بأي لغة | `vulnscan ./my-app` | يمر على كل الملفات النصية ويطبّق 65+ قاعدة |
| ملف واحد | `vulnscan server.py` | يفحص الملف وحده |
| أرشيف / حزمة | `vulnscan app.apk` أو `.jar` `.zip` `.whl` `.tar.gz` | يفكّه في مجلد مؤقت ويفحص محتواه |
| عنوان ويب (سلبي) | `vulnscan https://my-site.example --authorized` | طلب GET واحد: ترويسات الأمان، الكوكيز، TLS القديم |

القواعد المدمجة تغطي: Python، JavaScript/TypeScript، Dart/Flutter، Java/Kotlin، Go، PHP، Ruby، C#، C/C++،
Shell، Dockerfile، docker-compose، GitHub Actions، AndroidManifest، iOS plist، وملفات الإعدادات.

فئات الثغرات: أسرار ومفاتيح مضمّنة، تنفيذ أوامر/كود (RCE)، حقن SQL/XSS/قوالب/مسارات، فك تسلسل غير آمن،
تشفير ضعيف وتعطيل TLS، إعدادات خطرة (debug، CORS، 0.0.0.0)، أمان الموبايل، أمان الحاويات و CI،
سلامة الذاكرة في C، تسجيل بيانات حساسة، وملفات لا يجوز شحنها (.env، مفاتيح SSH، قواعد بيانات).

بالإضافة إلى ذلك، وعند توفر الإنترنت:
- **ثغرات الاعتماديات المعروفة (CVE)** عبر [OSV.dev](https://osv.dev) من `requirements.txt`،
  `package-lock.json`، `package.json`، `pubspec.lock`، `go.mod`، `Gemfile.lock`، `composer.lock`.
- **دمج أدوات خارجية** إن كانت مثبّتة (اختياري تمامًا): `bandit`، `semgrep`، `gitleaks`، `npm audit`.

## التثبيت

```bash
pip install git+https://github.com/abdulrahmanahmedelabed-prog/vulnscan
```

أو بدون تثبيت:

```bash
git clone https://github.com/abdulrahmanahmedelabed-prog/vulnscan
cd vulnscan
python -m vulnscan /path/to/project
```

## الاستخدام

```bash
# تقرير ملوّن على الشاشة
vulnscan ./my-project

# تقارير Markdown + JSON + HTML دفعة واحدة
vulnscan ./my-project --all-formats report

# تقرير HTML فقط إلى ملف
vulnscan app.apk -f html -o report.html

# في CI: أفشل البناء إذا وُجد شيء عالٍ أو حرج
vulnscan . --fail-on high --exclude "tests/*"

# دون إنترنت ودون أدوات خارجية
vulnscan . --no-deps --no-external

# فحص سلبي لموقع تملكه
vulnscan https://my-site.example --authorized

# عرض القواعد
vulnscan --list-rules .
```

### الخيارات

| الخيار | الوصف |
|---|---|
| `-f console\|markdown\|json\|html` | صيغة التقرير |
| `-o FILE` | كتابة التقرير إلى ملف |
| `--all-formats PREFIX` | كتابة `PREFIX.md` و `PREFIX.json` و `PREFIX.html` |
| `--min-severity LEVEL` | عرض هذه الخطورة فما فوق |
| `--fail-on LEVEL` | رمز خروج 1 عند وجود نتيجة بهذه الخطورة أو أعلى |
| `--exclude GLOB` | استثناء مسارات (يُكرَّر) |
| `--ignore-rule ID` | تجاهل قاعدة (يُكرَّر) |
| `--no-deps` / `--no-external` | تعطيل OSV / الأدوات الخارجية |
| `--authorized` | إقرار بالصلاحية (إلزامي لعناوين الويب) |

### كتم إنذار مقصود

أضف في نهاية السطر `# nosec` أو `// vulnscan: ignore`. ولكتم ملف كامل ضع `vulnscan: ignore-file`
في أول سطوره.

## شكل التقرير

```
vulnscan — ./my-project  (156 ملفًا مفحوصًا، 37 نتيجة)

الملخص (من الأعلى خطورة إلى الأقل):
        حرج  CRITICAL 0
       عالٍ  HIGH     3
      متوسط  MEDIUM   8
      منخفض  LOW      26
   معلوماتي  INFO     0

━━ عالٍ / HIGH (3) ━━
  🟧 MOB001 [CWE-319] السماح بحركة مرور غير مشفّرة — Cleartext traffic allowed
     📄 app/android/app/src/main/AndroidManifest.xml:6
     ▸ android:usesCleartextTraffic="true"
     💡 عطّل cleartext واستخدم HTTPS فقط …
```

تقرير Markdown يبدأ بملخص تنفيذي وجدول أعداد، ثم «أهم ما يجب إصلاحه أولًا»، ثم كل النتائج مجمّعة حسب الخطورة
مع المعرّف و CWE والموضع والمقتطف وطريقة الإصلاح. تقرير JSON يحمل الحقول نفسها لدمجه في أدوات أخرى.

## التطوير

```bash
pip install -e .[dev]
python -m pytest -q
```

## حدود الأداة

- الفحص الثابت بالقواعد يكشف الأنماط الشائعة ولا يغني عن مراجعة بشرية أو اختبار اختراق.
- قد تظهر إنذارات كاذبة؛ استخدم `--ignore-rule` أو كتم السطر بعد التحقق.
- APK/JAR تُفحص محتوياتها النصية (manifest إن كان نصيًا، الموارد، السكربتات) ولا يُفكّ تجميع الكود الثنائي.
- فحص الويب سلبي بالكامل (طلب واحد) ولا يُجري أي اختبار نشط.

## الرخصة

MIT
