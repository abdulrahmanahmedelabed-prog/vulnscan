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

## الإبلاغ عن ثغرة في كاشِف نفسه

راجع [SECURITY.md](SECURITY.md).
