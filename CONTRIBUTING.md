# المساهمة في كاشِف — Contributing

## الإعداد

```bash
git clone https://github.com/abdulrahmanahmedelabed-prog/vulnscan && cd vulnscan
pip install -e .[dev]
```

## قبل فتح طلب دمج

```bash
ruff check vulnscan tests bench          # فحص جودة الكود
python -m pytest -q --cov=vulnscan       # الاختبارات والتغطية (الحد الأدنى في CI)
vulnscan . --no-deps --no-external --exclude "tests/*" --fail-on high   # كاشِف يفحص نفسه
```

## قواعد جديدة أو تحسين الدقة

- كل قاعدة أو نموذج تدفق بيانات جديد يحتاج اختبارًا **يكشف** المثال الضعيف واختبارًا **لا يكشف** المثال الآمن.
- قِس الأثر على OWASP Benchmark ولا تخفض النتيجة:

  ```bash
  git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkPython /tmp/bp
  python bench/score_owasp.py /tmp/bp
  ```

- **ممنوع ضبط الأداة على ملفات المعيار** (أسماء الملفات أو أنماط خاصة به). كل تحسين يجب أن يكون دلالة لغوية عامة
  تصحّ على أي كود حقيقي، وهذا شرط OWASP لاعتبار النتيجة صادقة.

## عقد الثبات (1.x) — Stability contract

كاشِف يتبع الترقيم الدلالي، وما يلي **لا يُكسر** داخل 1.x (التفاصيل في [docs/production.md](docs/production.md)):

- خيارات سطر الأوامر ومعانيها ورموز الخروج (0 / 1 / 2).
- حقول تقارير `json` و`sarif` و`gitlab-sast` و`codeclimate`: تُضاف حقول اختيارية ولا يُحذف حقل ولا يتغير نوعه أو معناه.
- بصمات النتائج (`vulnscan/v1`) وملفات خط الأساس (`vulnscan-baseline/1`): **لا تغيّر طريقة حساب البصمة أبدًا**.
- معرّفات القواعد: لا يُعاد استخدام معرّف ولا يتغير معناه، وإعادة التسمية تكون مع اسم بديل (alias) يبقي المعرّف القديم يعمل.
- تعليقات الكتم (`nosec` و`vulnscan: ignore` و`vulnscan: ignore-file`) وإعدادات LSP (قسم `kashif`) ومدخلات `action.yml`.

المسموح في إصدار فرعي: قواعد ونماذج جديدة، ودقة أعلى (نتائج جديدة أو إنذارات كاذبة أقل)، وتغيير خطورة افتراضية **مع إشعار
في CHANGELOG.md** يذكر القاعدة والخطورة القديمة والجديدة. أي حذف يسبقه إعلان إهمال (deprecation) لإصدار فرعي واحد وثلاثة
أشهر على الأقل، ولا يُنفَّذ إلا في إصدار رئيسي.

In short: within 1.x never break CLI flags, exit codes, machine-readable report schemas, fingerprints, baseline
files, rule IDs (rename only with an alias), suppression comments, LSP settings or action inputs. New rules, better
precision and (with a changelog notice) default-severity changes are fine in a minor release.

## صورة الحاوية — Docker image

```bash
docker build -t kashif:dev .                                    # Dockerfile في جذر المستودع
docker run --rm -v "$PWD:/src:ro" kashif:dev . --no-deps --no-external
```

الصورة تعمل بمستخدم غير جذري (UID 10001) وبنظام ملفات للقراءة فقط؛ لا تضف إليها اعتماديات خارج مكتبة Python القياسية.
صورة الأساس مثبّتة بالـ digest، وكل GitHub Action في `.github/workflows` مثبّت بمعرّف الإيداع الكامل (SHA).

## الإبلاغ عن ثغرة في كاشِف نفسه

راجع [SECURITY.md](SECURITY.md).
