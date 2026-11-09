# سياسة الأمان — Security Policy

## الإصدارات المدعومة

تُصلَح الثغرات في أحدث إصدار فقط. حدّث إلى آخر إصدار من
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
- إنذار كاذب أو ثغرة لم تُكتشف **ليست** ثغرة أمنية في كاشِف؛ افتح لها Issue عاديًا.

## التحقق من سلامة النسخ

كل إصدار يرفق `SHA256SUMS.txt` وشهادة مصدر بناء (SLSA build provenance) موقّعة من GitHub Actions.
للتحقق من أن الملف بُني من هذا المستودع دون تعديل:

```bash
gh attestation verify vulnscan-linux --repo abdulrahmanahmedelabed-prog/vulnscan
sha256sum -c SHA256SUMS.txt --ignore-missing
```

## English summary

Report vulnerabilities privately via GitHub Security Advisories, not public issues. We respond within 7 days.
Release binaries carry SHA-256 checksums and signed SLSA build provenance (`gh attestation verify`).
