# سياسة الأمان — Security Policy

## الإصدارات المدعومة

يتبع كاشِف الترقيم الدلالي (Semantic Versioning) بدءًا من 1.0.0، والإصلاحات تصدر كإصدار ترقيعي (patch) لأحدث إصدار فرعي.

| الإصدار | إصلاح الأخطاء | الإصلاحات الأمنية |
|---|---|---|
| أحدث إصدار فرعي من 1.x | نعم | نعم |
| الإصدار الفرعي السابق من 1.x | لا — حدّث إلى الأحدث | الحرجة والعالية فقط، لمدة 6 أشهر بعد صدور الإصدار الفرعي التالي |
| 0.x | لا | لا |

الترقية داخل 1.x آمنة بحكم عقد الثبات (خيارات سطر الأوامر ورموز الخروج وصيغ التقارير والبصمات وخطوط الأساس ومعرّفات
القواعد لا تتغير)؛ التفاصيل في [docs/production.md](docs/production.md). حدّث إلى آخر إصدار من
[صفحة الإصدارات](https://github.com/abdulrahmanahmedelabed-prog/vulnscan/releases/latest).

## الإبلاغ عن ثغرة

**لا تفتح Issue عامًا لثغرة أمنية.** استخدم الإبلاغ الخاص في GitHub:
تبويب **Security** ← **Report a vulnerability**
(https://github.com/abdulrahmanahmedelabed-prog/vulnscan/security/advisories/new).

اذكر الإصدار، وخطوات إعادة الإنتاج، والأثر المتوقع. نردّ خلال 7 أيام، ونهدف إلى إصلاح الثغرات الحرجة
خلال 30 يومًا، وننسب الاكتشاف إليك في ملاحظات الإصدار إن رغبت.

## نطاق ما يُعدّ ثغرة في كاشِف

- تنفيذ كود أو قراءة/كتابة ملفات خارج الهدف أثناء فحص مستودع أو أرشيف خبيث (مثل Zip Slip).
- تعطيل الفحص كليًا بملف مصمَّم (انهيار أو تعليق) — نعامله كثغرة حرمان من الخدمة.
- كشف بيانات المستخدم عبر الواجهة المحلية لأي جهة غير المستخدم نفسه.
- إصلاح تلقائي (`--fix`) يكتب خارج المشروع المفحوص، أو خادم MCP (`kashif mcp`) يقرأ خارج مجلدات المشروع أو يشغّل كودًا.
- ظهور قيمة سرّ كاملة في مخرجات `kashif history` أو أي تقرير (القيم تُخفى دائمًا)، أو تثبيت حزمة قواعد لا تطابق بصمتها.
- أي إرسال لبيانات من البرنامج إلى جهة خارجية غير ما هو موثَّق (استعلام OSV.dev والتحقق من التحديثات).
- إنذار كاذب أو ثغرة لم تُكتشف **ليست** ثغرة أمنية في كاشِف؛ افتح لها Issue عاديًا.

## التحقق من سلامة النسخ

كل إصدار يرفق `SHA256SUMS.txt` وشهادة مصدر بناء (SLSA build provenance) موقّعة من GitHub Actions.
للتحقق من أن الملف بُني من هذا المستودع دون تعديل:

```bash
gh attestation verify kashif-linux-x86_64 --repo abdulrahmanahmedelabed-prog/vulnscan
sha256sum -c SHA256SUMS.txt --ignore-missing
```

صورة الحاوية (`ghcr.io/abdulrahmanahmedelabed-prog/kashif`) تحمل شهادة المصدر نفسها وقائمة مكوّنات (SBOM):

```bash
gh attestation verify oci://ghcr.io/abdulrahmanahmedelabed-prog/kashif:1 --repo abdulrahmanahmedelabed-prog/vulnscan
```

## English summary

**Supported versions.** Kashif follows Semantic Versioning from 1.0.0; fixes ship as a patch release of the latest
minor.

| Version | Bug fixes | Security fixes |
|---|---|---|
| Latest 1.x minor | Yes | Yes |
| Previous 1.x minor | No (upgrade to the latest minor) | Critical and high only, for 6 months after the next minor was released |
| 0.x | No | No |

Upgrading within 1.x is safe under the stability contract in [docs/production.md](docs/production.md).

**Reporting.** Report vulnerabilities privately via GitHub Security Advisories, not public issues. We respond within
7 days and aim to fix critical issues within 30 days.

**In scope** (besides the usual code execution, path traversal and denial of service on malicious input): `--fix`
writing outside the scanned project, the MCP server reading outside the project roots or running code, a full secret
value in `kashif history` or any report output, a rule pack installed despite a checksum mismatch, and any data sent
anywhere other than the documented OSV.dev lookup and update check. False positives and missed findings are not
security issues; open a normal issue.

**Verifying.** Release binaries carry SHA-256 checksums and signed SLSA build provenance (`gh attestation verify`);
the container image carries the same provenance and an SBOM.
