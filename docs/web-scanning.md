# Passive web scanning (Kashif 1.1)

[العربية](#الفحص-السلبي-للمواقع)

Kashif checks a web site you own, or are authorized in writing to test, by reading what the site already serves.
Every web scan needs `--authorized` on the command line (or the confirmation box in the UI); without it Kashif exits
with code 2 before sending anything. The rule list, with severities, confidences, CWE, OWASP WSTG and ASVS
mappings, is in [web-checks.md](web-checks.md).

## What Kashif sends

Only `GET` requests, with an honest User-Agent (`Kashif/<version> (+https://abdulrahmanahmedelabed-prog.github.io/vulnscan/scanner.html)`)
and the headers `Accept`, `Accept-Encoding: gzip, deflate`, `Accept-Language: en` (and `Origin` on the one CORS
request). There is one request at a time per host, with at least `--delay` seconds between two of them (default 0.5,
floor 0.2), raised by a `Crawl-delay` in `robots.txt` (capped at 10 s). A `429`, or a `503` with `Retry-After`, is
waited out once (at most 60 s); a second one stops that host and the rest of its checks are reported as
*inconclusive*.

| Profile | Requests (crawl pages excluded) | What is fetched |
|---|---|---|
| `minimal` | at most 10 | the URL and its redirects (the 1.0 behaviour) |
| `standard` (default) | at most 45 | + the http/https counterpart chain (default ports only), one cookieless GET with `Origin: https://kashif-cors-check.invalid`, `/robots.txt`, `/.well-known/security.txt` (`/security.txt` only after a 404), the declared icon or `/favicon.ico`, up to 15 same-site scripts and styles the page references |
| `deep` (`--deep`) | at most 150 | + a fixed list of commonly exposed files (`.git/HEAD`, `.env`, `server-status` …) with soft-404 baselines named `/kashif-404-<16 hex>`, up to 10 third-party scripts and styles, 5 source maps and 10 JPEG images (first 128 KB) |
| `--crawl` | + `--max-pages` (default 20) | same-origin links, breadth first, at most `--max-depth` deep (default 2), `robots.txt` honoured unless `--ignore-robots` |

TLS is assessed with ordinary handshakes and plaintext ClientHello probes (about 14 per address, about 60 with
`deep`). DNS lookups are the ones a browser makes anyway. Kashif never sends payloads, never fuzzes parameters,
never submits forms, never guesses credentials, never uses another method than GET, never spoofs headers or the
User-Agent, never connects to another port than the target's (and 80/443 for the counterpart), refuses to follow a
redirect or a link to a private, loopback or link-local address unless the target itself is one, and never contacts
cloud metadata addresses. Lookups that would reveal the target to a third party (the hstspreload.org API, CT
search, OCSP) are made only with `--third-party-lookups`.

`HTTP(S)_PROXY` and `NO_PROXY` are honoured as in 1.0 (`--no-proxy` turns them off). Through a proxy the checks that
need DNS are reported as *not tested*, and TLS findings drop to *tentative*, because an inspecting proxy replaces the
certificate.

## Options

| Option | Meaning |
|---|---|
| `--web-profile minimal\|standard\|deep` | the request budget above (`--deep` is `--web-profile deep`) |
| `--web-sensitivity strict\|default\|paranoid` | `strict`: certain findings only; `default`: certain and firm; `paranoid`: everything, including the checks marked paranoid-only |
| `--crawl`, `--max-pages N`, `--max-depth N` | crawl same-origin pages |
| `--ignore-robots` | crawl paths that `robots.txt` disallows (for the site's owner) |
| `--delay SEC`, `--timeout SEC` | the gap between two requests to one host; the socket timeout per request |
| `--compare-previous` | compare with the last saved scan of the same site, and save this one in the local history (`~/.vulnscan`, or `VULNSCAN_HOME`) |
| `--compare ID\|FILE` | compare with a saved scan id, or with a JSON report written by `-f json` |
| `--web-cookie-ignore NAME` | leave a cookie out of the cookie checks (repeatable) |
| `--third-party-lookups` | allow lookups that reveal the site's name to a third party |
| `--no-proxy` | do not use the proxy of the environment |

`kashif update-data --web` installs the newer web data snapshot (retire.js, HSTS preload list, Public Suffix List,
technology and end-of-life data …) of the latest official release, after verifying its SHA-256 against the
release's `SHA256SUMS`; `--check` only reports whether one exists (exit code 10). Nothing about the sites you scan is
sent. Every report states the date of the data in use; data older than 90 days adds a note, and older than 180
days the vulnerability checks (WEB054, WEB800, WEB801) are flagged as possibly missing recent CVEs.

## What the reports contain

* **Findings** with a confidence: `certain` (a protocol fact), `firm` (probably real) or `tentative` (may exist).
  A finding seen on many pages is reported once, with the number of instances, up to 5 example URLs and the URL
  templates it occurred on. Every finding keeps its evidence: the request, the redirect chain, the status, the
  headers as received (cookie values redacted), the matched value and a `curl` command that repeats the request
  (every argument shell-quoted).
* **Three grades**: the Kashif Web Grade (A+ to F, six weighted families, capped by serious findings; `*` means
  provisional because a family could not be tested, `?` means a WAF or rate limit answered instead of the site), an
  MDN HTTP Observatory-compatible score (algorithm 6, out of 165), and an SSL Labs-compatible TLS grade (without the
  attack-only tests Kashif does not perform).
* **Coverage**: one state per check: passed, failed, not applicable, not tested or inconclusive, with the reason.
  A check that did not run is never shown as passed and never counts in a grade.
* **Inventory**: security headers with their verdict, CSP policies, cookies (class and attributes, never values),
  TLS per address, technologies and libraries, third-party hosts.
* **Copy-paste fixes** for nginx, Apache httpd, IIS, Caddy, Express, Django, Spring Security, ASP.NET Core and
  Cloudflare; the platforms detected on the site come first.
* **Diff** (with `--compare-previous` or `--compare`): new, resolved and unchanged findings, grade changes and
  posture changes, regressions first. A scan of another target is not compared; a different profile is stated.

| Format | Web content |
|---|---|
| console | findings with their confidence, the notes (profile and request count, coverage, grades, data date), the diff summary |
| `-f markdown`, `-f html` | the sections above; the HTML report uses tabs (no script) for the inventory and the platform snippets |
| `-f json` | the findings (`extra.confidence`, `extra.evidence`, `extra.wstg`/`asvs4`/`asvs5`, `extra.instances` …) and a `web` object: `grades`, `coverage` (one record per check: `check`, `rules`, `state`, `reason`), `coverage_counts`, `inventory`, `notes`, `diff` and `snapshot` (what `--compare FILE` reads) |
| `-f sarif` | rules and results with `properties.precision` (certain → very-high, firm → high, tentative → low), `properties.security-severity` and the tags `external/cwe/cwe-N`, `wstg:…`, `asvs4:…`, `asvs5:…`; the grades and coverage counts in `runs[0].properties` |
| exports | `csv` has a confidence column, ASFF a `Confidence`, the Markdown bodies (DefectDojo, GitLab, GitHub Issues) a confidence line |

`kashif compliance` shows the WSTG, ASVS 4.0.3 and ASVS 5.0.0 ids of a web finding as "Kashif analyst mapping".
A policy file (`kashif.yml`) disables rules and overrides severities by id, as for every other rule:

```yaml
rules:
  disable:
    - id: WEB215
      reason: "CSP reports are collected by the CDN"
  severity:
    - id: WEB-referrer-policy
      severity: low
      reason: "no cross-site navigation leaves this intranet site"
```

## Upgrading from 1.0

* The default profile is `standard` (more than the single request of 1.0); `--web-profile minimal` keeps the 1.0
  traffic.
* Rule ids keep their meaning. Some 1.0 severities were recalibrated (for example a missing HSTS header is now
  medium); see the CHANGELOG.
* The fingerprints of the 1.0 header, CSP and cookie findings are unchanged, so baselines and triage decisions keep
  working for them. Other web findings now fingerprint on their grouping key (rule, host, response kind and a
  normalised value), which no longer changes with nonces, dates or counts; rewrite a web baseline once after the
  upgrade (`--write-baseline`).
* The UI's web-scan form has the profile, sensitivity, crawl and comparison options; each scan of a site is compared
  with its previous one by default (Settings → Web scanning).

---

## الفحص السلبي للمواقع

يفحص كاشِف موقعًا تملكه، أو لديك تصريح كتابي بفحصه، بقراءة ما يقدّمه الموقع أصلًا. كل فحص ويب يتطلب `--authorized` في سطر
الأوامر (أو مربع الإقرار في الواجهة)؛ ودونه يخرج كاشِف برمز 2 قبل إرسال أي طلب. قائمة القواعد بخطورتها وثقتها وربطها بـ
CWE وOWASP WSTG وASVS في [web-checks.md](web-checks.md).

### ما يرسله كاشِف

طلبات `GET` فقط، بمعرّف صادق (`Kashif/<الإصدار>`) والترويسات `Accept` و`Accept-Encoding: gzip, deflate`
و`Accept-Language: en` (و`Origin` في طلب CORS الوحيد). طلب واحد في كل مرة لكل مضيف، وبين طلبين `--delay` ثانية على
الأقل (الافتراضي 0.5 والحد الأدنى 0.2)، وتزيدها قيمة `Crawl-delay` في `robots.txt` (حتى 10 ثوانٍ). وعند `429`، أو
`503` مع `Retry-After`، ينتظر مرة واحدة (60 ثانية على الأكثر)؛ وتكرار ذلك يوقف فحص ذلك المضيف وتُعدّ بقية فحوصه «غير حاسمة».

| ملف الفحص | الطلبات (عدا صفحات الزحف) | ما يُجلب |
|---|---|---|
| `minimal` | 10 طلبات على الأكثر | العنوان وتوجيهاته (سلوك الإصدار 1.0) |
| `standard` (الافتراضي) | 45 طلبًا على الأكثر | مع سلسلة النسخة الأخرى http/https (على المنافذ الافتراضية فقط)، وطلب واحد بلا كوكيز مع `Origin: https://kashif-cors-check.invalid`، و`/robots.txt` و`/.well-known/security.txt` (و`/security.txt` بعد 404 فقط)، والأيقونة، وحتى 15 من سكربتات الصفحة وأنماطها من الموقع نفسه |
| `deep` (أو `--deep`) | 150 طلبًا على الأكثر | مع قائمة ثابتة من الملفات المكشوفة الشائعة وخطوط أساس لصفحات 404 باسم `/kashif-404-<16 hex>`، وحتى 10 سكربتات لأطراف ثالثة و5 خرائط مصدر و10 صور JPEG (أول 128 كيلوبايت) |
| `--crawl` | مع `--max-pages` (الافتراضي 20) | روابط الأصل نفسه، بعمق `--max-depth` على الأكثر (الافتراضي 2)، باحترام `robots.txt` إلا مع `--ignore-robots` |

يُقيَّم TLS بمصافحات عادية ورسائل ClientHello تُقرأ استجاباتها غير المشفّرة فقط (نحو 14 لكل عنوان، ونحو 60 مع `deep`).
ولا يرسل كاشِف حمولات، ولا يجرّب المعاملات، ولا يرسل النماذج، ولا يخمّن كلمات المرور، ولا يستخدم غير GET، ولا يزوّر
الترويسات أو معرّف المتصفح، ولا يتصل بمنفذ غير منفذ الهدف (و80/443 للنسخة الأخرى)، ويرفض اتباع توجيه أو رابط إلى عنوان
خاص أو محلي إلا إن كان الهدف نفسه كذلك، ولا يتصل أبدًا بعناوين البيانات الوصفية للسحابة. والاستعلامات التي تكشف اسم الهدف
لطرف ثالث (واجهة hstspreload.org، والبحث في سجلات الشهادات، وOCSP) لا تُجرى إلا مع `--third-party-lookups`.

ويحترم الفحص `HTTP(S)_PROXY` و`NO_PROXY` كما في 1.0 (ويعطّلهما `--no-proxy`). وعبر الوكيل تُعدّ الفحوص المعتمدة على
DNS «لم تُجرَ»، وتصبح نتائج TLS «محتملة»، لأن الوكيل الفاحص يستبدل الشهادة.

### الخيارات

| الخيار | معناه |
|---|---|
| `--web-profile minimal\|standard\|deep` | حدّ الطلبات أعلاه (`--deep` يساوي `--web-profile deep`) |
| `--web-sensitivity strict\|default\|paranoid` | `strict`: المؤكَّدة فقط؛ `default`: المؤكَّدة والمرجَّحة؛ `paranoid`: كل شيء مع الفحوص الخاصة بهذا المستوى |
| `--crawl` و`--max-pages N` و`--max-depth N` | الزحف على صفحات الأصل نفسه |
| `--ignore-robots` | الزحف على المسارات التي يمنعها `robots.txt` (لمالك الموقع) |
| `--delay SEC` و`--timeout SEC` | الفاصل بين طلبين إلى المضيف نفسه؛ ومهلة كل طلب |
| `--compare-previous` | المقارنة بآخر فحص محفوظ للموقع نفسه، وحفظ هذا الفحص في السجل المحلي (`~/.vulnscan` أو `VULNSCAN_HOME`) |
| `--compare ID\|FILE` | المقارنة بمعرّف فحص محفوظ، أو بتقرير JSON كتبه `-f json` |
| `--web-cookie-ignore NAME` | استبعاد كوكي من فحوص الكوكيز (يمكن تكراره) |
| `--third-party-lookups` | السماح باستعلامات تكشف اسم الموقع لطرف ثالث |
| `--no-proxy` | عدم استخدام الوكيل المعرَّف في البيئة |

يثبّت `kashif update-data --web` بيانات الويب الأحدث (retire.js، وقائمة HSTS preload، وقائمة النطاقات العامة، وبيانات
التقنيات ونهاية الدعم …) من آخر إصدار رسمي بعد التحقق من بصمتها SHA-256 في `SHA256SUMS` للإصدار؛ و`--check` يتحقق فقط
(رمز الخروج 10 إن وُجدت بيانات أحدث). ولا يُرسل شيء عن المواقع التي تفحصها. ويذكر كل تقرير تاريخ البيانات المستخدمة،
وتضيف البيانات الأقدم من 90 يومًا ملاحظة، والأقدم من 180 يومًا تنبيهًا إلى أن فحوص الثغرات المعروفة (WEB054 وWEB800
وWEB801) قد تفوتها ثغرات حديثة.

### محتوى التقارير

* **النتائج** مع درجة ثقتها: مؤكَّدة (حقيقة في البروتوكول) أو مرجَّحة (حقيقية على الأرجح) أو محتملة (قد توجد). والنتيجة
  المتكررة في صفحات كثيرة تظهر مرة واحدة مع عدد مواضعها وحتى 5 أمثلة وقوالب العناوين التي ظهرت فيها. ولكل نتيجة دليلها:
  الطلب وسلسلة التوجيه والحالة والترويسات كما وصلت (مع إخفاء قيم الكوكيز) والقيمة المطابقة وأمر `curl` يعيد الطلب نفسه
  (كل معامل فيه محميّ للصدفة).
* **ثلاث درجات**: درجة كاشِف للويب (من A+ إلى F بست مجموعات موزونة، مع حدود عليا عند النتائج الخطيرة؛ و`*` تعني درجة
  مؤقتة لأن مجموعة لم تُفحص، و`?` تعني أن جدار حماية أو تقييد معدل أجاب بدل الموقع)، ودرجة متوافقة مع MDN HTTP
  Observatory (الخوارزمية 6، من 165)، ودرجة TLS متوافقة مع SSL Labs (دون اختبارات الهجوم التي لا يجريها كاشِف).
* **التغطية**: حالة لكل فحص: ناجح أو فاشل أو غير منطبق أو لم يُجرَ أو غير حاسم، مع السبب. والفحص الذي لم يُجرَ لا يُعرض
  ناجحًا أبدًا ولا يدخل في أي درجة.
* **الجرد**: ترويسات الأمان مع الحكم عليها، وسياسات CSP، والكوكيز (الصنف والخصائص، دون القيم أبدًا)، وTLS لكل عنوان،
  والتقنيات والمكتبات، ومضيفو الأطراف الثالثة.
* **إصلاحات جاهزة للنسخ** لـ nginx وApache httpd وIIS وCaddy وExpress وDjango وSpring Security وASP.NET Core وCloudflare؛
  والمنصّات المكتشفة في الموقع أولًا.
* **المقارنة** (مع `--compare-previous` أو `--compare`): النتائج الجديدة والمحلولة والثابتة، وتغيّر الدرجات وتغييرات الوضع
  الأمني، والتراجعات أولًا. ولا يُقارن فحص بهدف آخر، ويُذكر اختلاف ملف الفحص إن وُجد.

ويحمل تقرير JSON البيانات نفسها تحت المفتاح `web` (`grades` و`coverage` و`inventory` و`notes` و`diff` و`snapshot`)،
وتحمل نتائج SARIF الخاصية `properties.precision` والوسوم `external/cwe/cwe-N` و`wstg:…` و`asvs4:…` و`asvs5:…` مع
الدرجات والتغطية في `runs[0].properties`، وفي تصدير `csv` عمود للثقة. ويعرض `kashif compliance` معرّفات WSTG وASVS
لنتيجة الويب بوصفها «ربط محللي كاشِف». ويعطّل ملف السياسة (`kashif.yml`) القواعد أو يغيّر خطورتها بمعرّفها كأي قاعدة أخرى (`rules.disable` و`rules.severity`،
انظر المثال في القسم الإنجليزي).

### الترقية من 1.0

* ملف الفحص الافتراضي `standard` (أكثر من طلب الإصدار 1.0 الواحد)؛ ويحافظ `--web-profile minimal` على حركة 1.0.
* تبقى معاني معرّفات القواعد كما هي، وأُعيدت معايرة بعض درجات الخطورة (مثل غياب HSTS أصبح متوسطًا)؛ انظر CHANGELOG.
* لا تتغير بصمات نتائج الترويسات وCSP والكوكيز من الإصدار 1.0، فيبقى خط الأساس وقرارات الفرز صالحة لها. أما بقية نتائج
  الويب فبصمتها الآن مفتاح تجميعها (القاعدة والمضيف ونوع الاستجابة وقيمة موحَّدة) فلا تتغير مع قيم nonce أو التواريخ أو
  الأعداد؛ أعد كتابة خط أساس الويب مرة واحدة بعد الترقية (`--write-baseline`).
* في نموذج فحص الويب في الواجهة خيارات ملف الفحص والحساسية والزحف والمقارنة، ويُقارن كل فحص لموقع بالفحص السابق له افتراضيًا
  (الإعدادات ← فحص الويب).
