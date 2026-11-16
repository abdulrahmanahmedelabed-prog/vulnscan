<a id="english"></a>

# Passive web scanning (Kashif 1.1)

**English** | [العربية](#arabic)

Kashif checks a web site you own, or are authorized in writing to test, by reading what the site already serves.
Every web scan needs `--authorized` on the command line (or the confirmation box in the UI); without it Kashif exits
with code 2 before sending anything. The rule list, with severities, confidences, CWE, OWASP WSTG and ASVS
mappings, is in [web-checks.md](web-checks.md). What a site owner sees in their logs is explained on the
[scanner page](https://abdulrahmanahmedelabed-prog.github.io/vulnscan/scanner.html).

## What Kashif sends

Only `GET` requests, with an honest User-Agent (`Kashif/<version> (+https://abdulrahmanahmedelabed-prog.github.io/vulnscan/scanner.html)`)
and the headers `Accept`, `Accept-Encoding: gzip, deflate`, `Accept-Language: en` (and `Origin` on the one CORS
request). There is one request at a time per host, with at least `--delay` seconds between two of them (default 0.5,
floor 0.2), raised by a `Crawl-delay` in `robots.txt` (capped at 10 s). A `429`, or a `503` with `Retry-After`, is
waited out once (at most 60 s); a second one stops that host and the rest of its checks are reported as
*inconclusive*.

| Profile | Requests (crawl pages excluded) | What is fetched |
|---|---|---|
| `minimal` | at most 10 | the URL and its redirects (the 1.0 behaviour); cannot crawl |
| `standard` (default) | at most 45 | + the http/https counterpart chain (default ports only), one cookieless GET with `Origin: https://kashif-cors-check.invalid`, `/robots.txt`, `/.well-known/security.txt` (`/security.txt` only after a 404), the declared icon or `/favicon.ico`, `/sitemap.xml` (with `--crawl`), up to 15 same-site scripts and styles the page references |
| `deep` (`--deep`) | at most 150 | + a fixed list of commonly exposed files (`.git/HEAD`, `.env`, `server-status` …) and the login and administration pages of a detected platform (`/wp-login.php`, `/administrator/` …; fetched once, nothing submitted), with soft-404 baselines named `/kashif-404-<16 hex>`, up to 10 third-party scripts and styles, 5 source maps and 10 JPEG images (first 128 KB) |
| `--crawl` (standard or deep) | + `--max-pages` (default 20, at most 500) | same-origin (same scheme, host and port) links, breadth first, at most `--max-depth` deep (default 2), `robots.txt` honoured unless `--ignore-robots` |

TLS is assessed with ordinary handshakes and plaintext ClientHello probes (about 14 per address, about 60 with
`deep`). DNS lookups are the ones a browser makes anyway. Kashif never sends payloads, never fuzzes parameters,
never submits forms, never guesses credentials, never uses another method than GET, never spoofs headers or the
User-Agent, never connects to another port than the target's (and 80/443 for the counterpart), refuses to follow a
redirect or a link to a private, loopback or link-local address unless the target itself is one, and never contacts
cloud metadata addresses. It makes no lookup that would reveal the target to a third party: the HSTS preload status
comes from the bundled Chromium list, certificate transparency from the certificate's own SCTs, and revocation is
not checked (see [below](#what-a-passive-scan-cannot-find)). `--third-party-lookups` is accepted so that a future
check of that kind can never run without your consent; in 1.1 no check uses it.

### Limits of one scan

* **Time and size:** a scan stops sending requests after 600 s or 50 MB received, whichever comes first. The checks
  that needed the requests not sent are reported as *not tested*, with the reason, never as passed.
* **Crawl:** `--max-pages` is capped at 500 pages (a larger value is lowered with a warning) and `--max-depth`
  defaults to 2. Crawled pages have their own budget on top of the profile's.
* **`minimal` cannot crawl:** `--crawl` with `--web-profile minimal` is rejected before anything is sent (exit
  code 2); use `standard` or `deep`.

### Proxies

`HTTP(S)_PROXY` and `NO_PROXY` are honoured as in 1.0 (`--no-proxy` turns them off). Only `http://` proxies are
supported (HTTPS goes through a `CONNECT` tunnel); any other proxy setting, such as `socks5://` or a bad port, makes
the requests that would use it fail with a proxy error (the scan stops with exit code 2, and `web.error.code` in the
JSON report starts with `proxy`) instead of silently connecting directly. Through a proxy the checks that need DNS are reported as *not tested*, and TLS findings are
*tentative*, because an inspecting proxy replaces the certificate: they appear only with
`--web-sensitivity paranoid`. To assess TLS itself, scan with `--no-proxy`, or add the host to `NO_PROXY`.

## Options

| Option | Meaning |
|---|---|
| `--web-profile minimal\|standard\|deep` | the request budget above (`--deep` is `--web-profile deep`) |
| `--web-sensitivity strict\|default\|paranoid` | `strict`: certain findings only; `default`: certain and firm; `paranoid`: everything, including the 6 checks marked paranoid-only |
| `--crawl`, `--max-pages N`, `--max-depth N` | crawl same-origin pages (same scheme, host and port); at most 500 pages |
| `--ignore-robots` | crawl paths that `robots.txt` disallows (for the site's owner) |
| `--delay SEC`, `--timeout SEC` | the gap between two requests to one host; the socket timeout per request |
| `--compare-previous` | compare with the last saved scan of the same site, and save this one in the local history (`~/.vulnscan`, or `VULNSCAN_HOME`) |
| `--compare ID\|FILE` | compare with a saved scan id, or with a JSON report written by `-f json` (see [Comparing scans](#comparing-scans)) |
| `--fail-on SEVERITY` | exit code 1 when a reported finding is at or above this severity |
| `--fail-on-inconclusive` | exit code 1 when the scan is inconclusive: no Kashif grade (`?`) or a WEB990 finding (a WAF, challenge or rate limit answered instead of the site) |
| `--ignore-rule ID` | leave a web rule out of the report and of `--fail-on` (repeatable); a note lists what was left out, and the grades still count it |
| `--policy FILE` | apply a policy gate (see [Policy files](#policy-files)) |
| `--web-cookie-ignore NAME` | leave a cookie out of the cookie checks (repeatable) |
| `--third-party-lookups` | allow lookups that reveal the site's name to a third party (none in 1.1) |
| `--no-proxy` | do not use the proxy of the environment |

These combinations are rejected before anything is sent (exit code 2): a web option (`--compare`,
`--compare-previous`, `--web-profile`, `--web-sensitivity`, `--third-party-lookups`, `--ignore-robots`,
`--web-cookie-ignore`, `--no-proxy`, `--fail-on-inconclusive`) with a local path instead of a URL; `--deep` with
`--web-profile minimal` or `standard`; `--crawl` with `--web-profile minimal`; `--compare` together with
`--compare-previous`; `--diff-base` or `--diff-staged`, `--fix` or `--fix-dry-run`, and `--triage` without a file
name, with a URL.

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
* **Coverage**: one state per check, with the reason. The JSON `state` tokens are `pass`, `fail`, `not_applicable`,
  `not_tested` and `inconclusive`. A check that did not run is never shown as passed and never counts in a grade.
* **Inventory**: security headers with their verdict, CSP policies, cookies (class and attributes, never values),
  TLS per address, technologies and libraries, third-party hosts.
* **Copy-paste fixes** for 18 platforms: nginx, Apache httpd 2.4, IIS 10, Caddy 2, Express (helmet 7+), Node.js,
  Django, Flask / Werkzeug, Spring Security 6 / Spring Boot, Apache Tomcat, ASP.NET Core 8+, ASP.NET (.NET
  Framework), PHP, Laravel, Symfony, Ruby on Rails, Cloudflare and F5 BIG-IP, plus a platform-neutral form. The
  platforms detected on the site come first.
* **Diff** (with `--compare-previous` or `--compare`): new, resolved and unchanged findings, grade changes and
  posture changes, regressions first. A scan of another target is not compared; a different profile is stated.

| Format | Web content |
|---|---|
| console | findings with their confidence, the notes (profile and request count, coverage, grades, data date), the diff summary |
| `-f markdown`, `-f html` | the sections above; the HTML report uses tabs (no script) for the inventory and the platform snippets |
| `-f json` | the findings (`extra.confidence`, `extra.evidence`, `extra.wstg`/`asvs4`/`asvs5`, `extra.instances` …) and a `web` object: `grades`, `coverage` (one record per check: `check`, `rules`, `state`, `reason`), `coverage_counts`, `inventory`, `notes`, `diff` and `snapshot` (what `--compare FILE` reads) |
| `-f sarif` | rules and results with `properties.precision` (certain → very-high, firm → high, tentative → low), `properties.security-severity` and the tags `external/cwe/cwe-N`, `wstg:…`, `asvs4:…`, `asvs5:…`; the grades and coverage counts in `runs[0].properties`; each result's location is the page URL |
| exports | `csv` has a confidence column, ASFF a `Confidence`, the Markdown bodies (DefectDojo, GitLab, GitHub Issues) a confidence line |

`kashif compliance` shows the WSTG, ASVS 4.0.3 and ASVS 5.0.0 ids of a web finding as "Kashif analyst mapping".

## Comparing scans

`--compare-previous` compares with the last scan of the same site saved in the local history and saves the new
one there. The history lives in `~/.vulnscan` (or `$VULNSCAN_HOME`): one file `scans/<id>.json` per scan, and
`index.json`, a cache of their list. A scan id comes from:

* the line `Scan saved in the local history (id …)` that `--compare-previous` prints on stderr after the report;
* the UI's **Reports** page: a scan's **View** link opens `#findings/<id>`;
* the file names in `$VULNSCAN_HOME/scans/`, or the keys of `$VULNSCAN_HOME/index.json`.

`--compare` takes such an id, or a JSON report written earlier with `-f json` (or `--all-formats`). In CI, where
every run starts on a fresh machine with an empty history, keep the JSON report of the previous run and pass
`--compare previous.json` (see [Using it in CI](#using-it-in-ci)). `kashif history` is unrelated: it searches the git
history of a repository for committed secrets.

## Using it in CI

```bash
kashif https://staging.example.com --authorized --fail-on high -f sarif -o kashif-web.sarif
```

| Exit code | Meaning |
|---|---|
| `0` | the scan ran and nothing failed the gate |
| `1` | the gate failed: a finding at or above `--fail-on`, a failed `--policy` gate, or an inconclusive scan with `--fail-on-inconclusive` |
| `2` | nothing was judged: `--authorized` missing, a rejected option combination, a `--compare` file that is missing or holds no web scan, or a site that could not be reached (DNS, refused connection, timeout, TLS failure, proxy) |

**A WAF is not a pass.** When a WAF challenge or a rate limit answers instead of the site, Kashif stops the optional
requests, reports the affected checks as *inconclusive*, adds the finding WEB990 and shows the Kashif grade as `?`.
WEB990 is `info`, so `--fail-on high` alone would let such a run pass although the site was never really seen: add
`--fail-on-inconclusive` so that it fails, and allow the runner's address on the WAF or scan a staging host.

**A site that cannot be reached** exits with code 2, and `-o` (json, sarif, html, markdown) or `--all-formats` still
writes a report, so a pipeline never reads an old file. The JSON report then has this shape (a completed scan has no
`web.status`):

```json
{
  "target": "https://staging.example.com",
  "generated_at": "2026-11-14T02:24:58+00:00",
  "files_scanned": 0,
  "notes": ["…Arabic explanation…"],
  "notes_en": ["The site was not scanned: …"],
  "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
  "findings": [],
  "web": {
    "schema": 1,
    "status": "unreachable",
    "target": "https://staging.example.com",
    "error": {"code": "refused", "en": "…", "ar": "…", "raw": "[Errno 111] Connection refused"}
  }
}
```

`error.code` is one of `invalid`, `unsupported`, `dns`, `refused`, `timeout`, `deadline`, `unreachable`, `tls`,
`reset`, `network` or a `proxy…` code. In SARIF the same run has `invocations[0].executionSuccessful: false`, a
`toolExecutionNotification` whose descriptor id is `web/<code>`, and the `web` object in
`runs[0].properties.kashif.web`.

**Regressions:** keep the JSON report of the last run and compare with it; `--all-formats PREFIX` writes the SARIF
and the JSON report in one run. A GitHub Actions job:

```yaml
permissions:
  contents: read
  security-events: write          # required to upload SARIF
steps:
  - run: curl -fsSL https://abdulrahmanahmedelabed-prog.github.io/vulnscan/install.sh | sh
  - uses: actions/cache@v4         # the previous run's JSON report
    with:
      path: previous
      key: kashif-web-${{ github.run_id }}
      restore-keys: kashif-web-
  - run: |
      cmp=""; [ -f previous/kashif-web.json ] && cmp="--compare previous/kashif-web.json"
      kashif https://staging.example.com --authorized --fail-on high --fail-on-inconclusive \
        $cmp --all-formats kashif-web
  - if: always()
    run: mkdir -p previous && cp kashif-web.json previous/ 2>/dev/null || true
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: kashif-web.sarif
      category: kashif-web          # keeps the web results apart from the code scan's
```

`category: kashif-web` makes the web analysis a separate one, so uploading it does not replace the alerts of a code
scan of the same repository (and the reverse). Web alerts carry a URL, not a file location: GitHub lists them in
the Security tab, but they have no source view and never appear as annotations on a pull request's changed lines.

## Policy files

For a web scan, a policy applies only when you name it: pass `--policy kashif.yml` (a URL has no project folder in
which a `kashif.yml` could be found automatically). The policy decides the exit code; it does not change the
report. `rules.disable` and `rules.severity` change what the gate counts, but the report still shows those findings
with their own severity; to leave a rule out of the report, use `--ignore-rule ID`. The default gate fails on
`high`, so state the threshold you want in `gate.fail_on`:

```yaml
version: 1
gate:
  fail_on: medium             # the default gate fails on high
rules:
  disable:
    - id: WEB071
      reason: "certificates are renewed automatically 30 days before expiry"
  severity:
    - id: WEB-x-frame-options
      severity: low
      reason: "static documentation with no actions to click-jack"
```

```bash
kashif https://intranet.example --authorized --policy kashif.yml
```

## What a passive scan cannot find

A passive scan reads what an anonymous visitor receives. That bounds what it can say:

* **Anonymous pages only.** Pages behind a login are not visited; Kashif never signs in.
* **No injection, XSS, authentication, access-control or business-logic testing.** Those need requests crafted to
  break the application, which Kashif never sends. Its DOM checks read the page's own JavaScript; they do not run it.
* **Certificate revocation is not checked.** Kashif reads a stapled OCSP response when the server sends one, but it
  does not contact the CA (no CRL or OCSP request).
* **A grade measures configuration hygiene, not the absence of vulnerabilities.** An A+ site can still have an
  injection flaw.

Pair a web scan with a code scan (SAST, `kashif .` on the application's source) and, for what neither can see, an
authorised active test (a penetration test or a DAST tool run with the owner's permission).

## Upgrading from 1.0

* **Default profile `standard`.** A default scan sends up to 45 requests instead of the single fetch of 1.0, and the
  gap between requests applies to every request, so a scan is slower (about 3 s on a local page with the default
  delay, about 27 s with `--deep`). `--web-profile minimal` keeps the 1.0 traffic.
* **Recalibrated severities.** Rule ids keep their meaning, but some 1.0 severities changed, which changes what
  `--fail-on` and severity policies catch:

  | Rule | 1.0 | 1.1 |
  |---|---|---|
  | `WEB-strict-transport-security` (missing HSTS) | high | medium |
  | `WEB020` (cookie without Secure) | medium | high, medium or low, by cookie class and HSTS |
  | `WEB021` (cookie without HttpOnly) | medium for every cookie | medium for session and authentication cookies only |
  | `WEB022` (cookie without SameSite) | low for every cookie | low for session, authentication and CSRF cookies; info (`paranoid`) for others |
  | `WEB050` (mixed content) | medium | medium for active content, low for passive |
  | `WEB053` (no Subresource Integrity) | low | low where a CDN supports SRI, info elsewhere |
  | `WEB054` (vulnerable JavaScript library) | from a hand-made table | the highest severity in the retire.js data |
  | `WEB071` (certificate expires soon) | medium | medium or low; thresholds relative to the certificate's lifetime |
  | `WEB-x-frame-options`, `WEB-content-security-policy` | medium | medium; low on static documents without scripts |
  | `WEB-permissions-policy`, `WEB-x-content-type-options` | CWE-16 | CWE-693 (severity unchanged) |

* **Fewer, grouped findings.** A finding is reported once per host with its instances, the 1.0 false positives are
  gone, and `tentative` findings appear only with `--web-sensitivity paranoid`.
* **Fingerprints.** The six security-header rules, WEB000, WEB010, WEB011, WEB020–WEB022, WEB040–WEB043, WEB052,
  WEB055, WEB056 and WEB060 keep their 1.0 fingerprints, so baselines and triage decisions keep working for them.
  WEB053, WEB054 and the other findings now grouped per host or per library fingerprint on their grouping key, which
  no longer changes with nonces, dates or counts: they appear as new once after the upgrade; rewrite the web
  baseline then (`--write-baseline`).
* **CSV column.** The CSV export has a new last column, `Confidence` (empty for code findings). Readers that address
  columns by name or position are unaffected; readers that check the number of columns must be updated.
* **Proxy failure.** A proxy setting Kashif cannot use (`socks5://`, a bad port) now fails the scan with a
  proxy error (exit code 2) instead of connecting to the site directly. Use `--no-proxy` or `NO_PROXY` to connect
  directly on purpose.
* **Notes.** The note "passive scan: one request" now states the real request budget of the chosen profile. Scans
  saved before the upgrade keep their old text.
* **UI.** The web-scan form has the profile, sensitivity, crawl and comparison options; each scan of a site is
  compared with its previous one by default (Settings → Web scanning).

---

<a id="arabic"></a>

# الفحص السلبي للمواقع (كاشِف 1.1)

[English](#english) | **العربية**

يفحص كاشِف موقعًا تملكه، أو لديك تصريح كتابي بفحصه، بقراءة ما يقدّمه الموقع أصلًا. كل فحص ويب يتطلب `--authorized` في سطر
الأوامر (أو مربع الإقرار في الواجهة)؛ ودونه يخرج كاشِف برمز الخروج 2 قبل إرسال أي طلب. قائمة القواعد بخطورتها وثقتها
وربطها بـ CWE وOWASP WSTG وASVS في [web-checks.md](web-checks.md)، وما يراه مالك الموقع في سجلاته تشرحه
[صفحة الفاحص](https://abdulrahmanahmedelabed-prog.github.io/vulnscan/scanner.html).

## ما يرسله كاشِف

طلبات `GET` فقط، بمعرّف صادق (`Kashif/<الإصدار>`) والترويسات `Accept` و`Accept-Encoding: gzip, deflate`
و`Accept-Language: en` (و`Origin` في طلب CORS الوحيد). طلب واحد في كل مرة لكل مضيف، وبين طلبين `--delay` ثانية على
الأقل (الافتراضي 0.5 والحد الأدنى 0.2)، وتزيدها قيمة `Crawl-delay` في `robots.txt` (حتى 10 ثوانٍ). وعند `429`، أو
`503` مع `Retry-After`، ينتظر مرة واحدة (60 ثانيةً على الأكثر)؛ وتكرار ذلك يوقف فحص ذلك المضيف وتُعدّ بقية فحوصه «غير حاسمة».

| نمط الفحص | الطلبات (عدا صفحات الزحف) | ما يُجلب |
|---|---|---|
| `minimal` | 10 طلبات على الأكثر | العنوان وتوجيهاته (سلوك الإصدار 1.0)؛ ولا زحف فيه |
| `standard` (الافتراضي) | 45 طلبًا على الأكثر | مع سلسلة النسخة الأخرى http/https (على المنافذ الافتراضية فقط)، وطلب واحد بلا كوكيز مع `Origin: https://kashif-cors-check.invalid`، و`/robots.txt` و`/.well-known/security.txt` (و`/security.txt` بعد 404 فقط)، والأيقونة المعلنة أو `/favicon.ico`، و`/sitemap.xml` (مع `--crawl`)، وحتى 15 من سكربتات الصفحة وأنماطها من الموقع نفسه |
| `deep` (أو `--deep`) | 150 طلبًا على الأكثر | مع قائمة ثابتة من الملفات المكشوفة الشائعة (`.git/HEAD` و`.env` و`server-status` …)، وصفحات الدخول والإدارة للمنصّة المكتشفة (`/wp-login.php` و`/administrator/` …؛ تُطلب مرة واحدة دون إرسال أي بيانات)، وخطوط أساس لصفحات 404 باسم `/kashif-404-<16 hex>`، وحتى 10 سكربتات لأطراف ثالثة و5 خرائط مصدر و10 صور JPEG (أول 128 كيلوبايت) |
| `--crawl` (مع standard أو deep) | مع `--max-pages` (الافتراضي 20، والحد الأعلى 500) | روابط الأصل نفسه (المخطط والمضيف والمنفذ أنفسها)، بالعرض أولًا، بعمق `--max-depth` على الأكثر (الافتراضي 2)، باحترام `robots.txt` إلا مع `--ignore-robots` |

يُقيَّم TLS بمصافحات عادية ورسائل ClientHello تُقرأ استجاباتها غير المشفّرة فقط (نحو 14 لكل عنوان، ونحو 60 مع `deep`).
ولا يرسل كاشِف حمولات، ولا يجرّب المعاملات، ولا يرسل النماذج، ولا يخمّن كلمات المرور، ولا يستخدم غير GET، ولا يزوّر
الترويسات أو معرّف المتصفح، ولا يتصل بمنفذ غير منفذ الهدف (و80/443 للنسخة الأخرى)، ويرفض اتباع توجيه أو رابط إلى عنوان
خاص أو محلي إلا إن كان الهدف نفسه كذلك، ولا يتصل أبدًا بعناوين البيانات الوصفية للسحابة. ولا يجري أي استعلام يكشف اسم
الهدف لطرف ثالث: حالة الإدراج المسبق لـ HSTS من قائمة Chromium المضمّنة، وشفافية الشهادات من طوابع SCT المضمّنة في الشهادة نفسها،
ولا يُتحقَّق من إلغاء الشهادة (انظر [ما لا يكشفه الفحص السلبي](#ما-لا-يكشفه-الفحص-السلبي)). ويقبل كاشِف الخيار
`--third-party-lookups` حتى لا يعمل أي فحص من هذا النوع مستقبلًا دون موافقتك، ولا يستعمله أي فحص في الإصدار 1.1.

### حدود الفحص الواحد

* **الوقت والحجم:** يتوقف الفحص عن إرسال الطلبات بعد 600 ثانية أو بعد استقبال 50 ميغابايت، أيهما أسبق. وتُعدّ الفحوص
  التي احتاجت الطلبات التي لم تُرسل «لم تُجرَ» مع السبب، ولا تُعدّ ناجحة أبدًا.
* **الزحف:** الحد الأعلى للخيار `--max-pages` هو 500 صفحة (وتُخفَّض القيمة الأكبر مع تنبيه)، والافتراضي لـ `--max-depth` هو 2.
  ولصفحات الزحف حدّ خاص بها فوق حدّ نمط الفحص.
* **لا زحف في `minimal`:** يُرفض `--crawl` مع `--web-profile minimal` قبل إرسال أي طلب (رمز الخروج 2)؛ استعمل `standard` أو `deep`.

### الوكيل (Proxy)

يحترم الفحص `HTTP(S)_PROXY` و`NO_PROXY` كما في 1.0 (ويعطّلهما `--no-proxy`). ولا يدعم كاشِف إلا الوكيل من نوع `http://`
(ويمر HTTPS عبر نفق `CONNECT`)؛ وأي إعداد آخر، مثل `socks5://` أو منفذ غير صالح، يُفشل الطلبات التي تمر به بخطأ في الوكيل
(فيتوقف الفحص برمز الخروج 2، وقيمة `web.error.code` في تقرير JSON تبدأ بـ `proxy`) بدل الاتصال المباشر خفية. وعبر الوكيل تُعدّ الفحوص المعتمدة على DNS «لم تُجرَ»،
وتصبح نتائج TLS «محتملة» لأن الوكيل الفاحص يستبدل الشهادة، فلا تظهر إلا مع `--web-sensitivity paranoid`. ولتقييم TLS
نفسه افحص مع `--no-proxy`، أو أضف المضيف إلى `NO_PROXY`.

## الخيارات

| الخيار | معناه |
|---|---|
| `--web-profile minimal\|standard\|deep` | حدّ الطلبات أعلاه (`--deep` يساوي `--web-profile deep`) |
| `--web-sensitivity strict\|default\|paranoid` | `strict`: المؤكَّدة فقط؛ `default`: المؤكَّدة والمرجَّحة؛ `paranoid`: كل شيء مع الفحوص الستة الخاصة بهذا المستوى |
| `--crawl` و`--max-pages N` و`--max-depth N` | الزحف على صفحات الأصل نفسه (المخطط والمضيف والمنفذ أنفسها)؛ 500 صفحة على الأكثر |
| `--ignore-robots` | الزحف على المسارات التي يمنعها `robots.txt` (لمالك الموقع) |
| `--delay SEC` و`--timeout SEC` | الفاصل بين طلبين إلى المضيف نفسه؛ ومهلة كل طلب |
| `--compare-previous` | المقارنة بآخر فحص محفوظ للموقع نفسه، وحفظ هذا الفحص في السجل المحلي (`~/.vulnscan` أو `VULNSCAN_HOME`) |
| `--compare ID\|FILE` | المقارنة بمعرّف فحص محفوظ، أو بتقرير JSON كتبه `-f json` (انظر [مقارنة الفحوص](#مقارنة-الفحوص)) |
| `--fail-on SEVERITY` | رمز الخروج 1 إذا ظهرت في التقرير نتيجة بهذه الخطورة أو أعلى |
| `--fail-on-inconclusive` | رمز الخروج 1 إذا كان الفحص غير حاسم: بلا درجة من كاشِف (`?`) أو ظهرت النتيجة WEB990 (أجاب جدار حماية أو تحدٍّ أو تقييد معدل بدل الموقع) |
| `--ignore-rule ID` | استبعاد قاعدة ويب من التقرير ومن `--fail-on` (يمكن تكراره)؛ وتذكر ملاحظةٌ ما استُبعد، وتبقى الدرجات تحسبه |
| `--policy FILE` | تطبيق بوابة سياسة (انظر [ملف السياسة](#ملف-السياسة)) |
| `--web-cookie-ignore NAME` | استبعاد كوكي من فحوص الكوكيز (يمكن تكراره) |
| `--third-party-lookups` | السماح باستعلامات تكشف اسم الموقع لطرف ثالث (لا يوجد منها شيء في 1.1) |
| `--no-proxy` | عدم استخدام الوكيل المعرَّف في البيئة |

وتُرفض هذه التوليفات قبل إرسال أي طلب (رمز الخروج 2): خيار ويب (`--compare` و`--compare-previous` و`--web-profile`
و`--web-sensitivity` و`--third-party-lookups` و`--ignore-robots` و`--web-cookie-ignore` و`--no-proxy`
و`--fail-on-inconclusive`) مع مسار محلي بدل عنوان ويب؛ و`--deep` مع `--web-profile minimal` أو `standard`؛ و`--crawl`
مع `--web-profile minimal`؛ و`--compare` مع `--compare-previous` معًا؛ و`--diff-base` أو `--diff-staged`، و`--fix` أو
`--fix-dry-run`، و`--triage` دون اسم ملف، مع عنوان ويب.

يثبّت `kashif update-data --web` بيانات الويب الأحدث (retire.js، وقائمة HSTS preload، وقائمة النطاقات العامة، وبيانات
التقنيات ونهاية الدعم …) من آخر إصدار رسمي بعد التحقق من بصمتها SHA-256 في `SHA256SUMS` للإصدار؛ و`--check` يتحقق فقط
(رمز الخروج 10 إن وُجدت بيانات أحدث). ولا يُرسل شيء عن المواقع التي تفحصها. ويذكر كل تقرير تاريخ البيانات المستخدمة،
وتضيف البيانات الأقدم من 90 يومًا ملاحظة، والأقدم من 180 يومًا تنبيهًا إلى أن فحوص الثغرات المعروفة (WEB054 وWEB800
وWEB801) قد تفوتها ثغرات حديثة.

## محتوى التقارير

* **النتائج** مع درجة ثقتها: مؤكَّدة (حقيقة في البروتوكول) أو مرجَّحة (حقيقية على الأرجح) أو محتملة (قد توجد). والنتيجة
  المتكررة في صفحات كثيرة تظهر مرة واحدة مع عدد مواضعها وحتى 5 أمثلة وقوالب العناوين التي ظهرت فيها. ولكل نتيجة دليلها:
  الطلب وسلسلة التوجيه والحالة والترويسات كما وصلت (مع إخفاء قيم الكوكيز) والقيمة المطابقة وأمر `curl` يعيد الطلب نفسه
  (كل معامل فيه مُحاط بعلامات اقتباس آمنة لسطر الأوامر).
* **ثلاث درجات**: درجة كاشِف للويب (من A+ إلى F بست مجموعات موزونة، مع حدود عليا عند النتائج الخطيرة؛ و`*` تعني درجة
  مؤقتة لأن مجموعة لم تُفحص، و`?` تعني أن جدار حماية أو تقييد معدل أجاب بدل الموقع)، ودرجة متوافقة مع MDN HTTP
  Observatory (الخوارزمية 6، من 165)، ودرجة TLS متوافقة مع SSL Labs (دون اختبارات الهجوم التي لا يجريها كاشِف).
* **التغطية**: حالة لكل فحص مع السبب: ناجح أو فاشل أو غير منطبق أو لم يُجرَ أو غير حاسم، وقيمها في الحقل `state` في JSON
  هي `pass` و`fail` و`not_applicable` و`not_tested` و`inconclusive`. والفحص الذي لم يُجرَ لا يُعرض ناجحًا أبدًا ولا
  يدخل في أي درجة.
* **الجرد**: ترويسات الأمان مع الحكم عليها، وسياسات CSP، والكوكيز (الصنف والخصائص، دون القيم أبدًا)، وTLS لكل عنوان،
  والتقنيات والمكتبات، ومضيفو الأطراف الثالثة.
* **إصلاحات جاهزة للنسخ** لـ 18 منصةً: nginx وApache httpd 2.4 وIIS 10 وCaddy 2 وExpress ‏(helmet 7+) وNode.js وDjango
  وFlask / Werkzeug وSpring Security 6 / Spring Boot وApache Tomcat وASP.NET Core 8+ وASP.NET ‏(.NET Framework) وPHP
  وLaravel وSymfony وRuby on Rails وCloudflare وF5 BIG-IP، مع صيغة عامة لكل المنصات. والمنصّات المكتشفة في الموقع أولًا.
* **المقارنة** (مع `--compare-previous` أو `--compare`): النتائج الجديدة والمحلولة والثابتة، وتغيّر الدرجات وتغييرات الوضع
  الأمني، والتراجعات أولًا. ولا يُقارن فحص بهدف آخر، ويُذكر اختلاف نمط الفحص إن وُجد.

ويحمل تقرير JSON البيانات نفسها تحت المفتاح `web` (`grades` و`coverage` و`inventory` و`notes` و`diff` و`snapshot`)،
وتحمل نتائج SARIF الخاصية `properties.precision` والوسوم `external/cwe/cwe-N` و`wstg:…` و`asvs4:…` و`asvs5:…` مع
الدرجات والتغطية في `runs[0].properties`، وموضع كل نتيجة فيه هو عنوان الصفحة؛ وفي تصدير `csv` عمود للثقة. ويعرض
`kashif compliance` معرّفات WSTG وASVS لنتيجة الويب بوصفها «ربط محللي كاشِف».

## مقارنة الفحوص

يقارن `--compare-previous` بآخر فحص للموقع نفسه محفوظ في السجل المحلي، ويحفظ الفحص الجديد فيه. والسجل في `~/.vulnscan`
(أو `$VULNSCAN_HOME`): ملف `scans/<id>.json` لكل فحص، والملف `index.json` الذي يخزّن قائمتها مؤقتًا. ويُعرف معرّف الفحص من:

* السطر `حُفظ الفحص في السجل المحلي (المعرّف …)` الذي يطبعه `--compare-previous` على stderr بعد التقرير؛
* صفحة **التقارير** في الواجهة: رابط **عرض** لكل فحص يفتح `#findings/<id>`؛
* أسماء الملفات في `$VULNSCAN_HOME/scans/`، أو مفاتيح `$VULNSCAN_HOME/index.json`.

ويقبل `--compare` هذا المعرّف، أو تقرير JSON كُتب من قبل بـ `-f json` (أو `--all-formats`). وفي CI، حيث يبدأ كل تشغيل على
جهاز جديد بسجل فارغ، احتفظ بتقرير JSON من التشغيل السابق ومرّره بـ `--compare previous.json` (انظر
[الاستخدام في CI](#الاستخدام-في-ci)). ولا علاقة للأمر `kashif history` بذلك: فهو يبحث في سجل git لمستودع عن الأسرار
المرفوعة.

## الاستخدام في CI

```bash
kashif https://staging.example.com --authorized --fail-on high -f sarif -o kashif-web.sarif
```

| رمز الخروج | معناه |
|---|---|
| `0` | اكتمل الفحص ولم يُفشل شيءٌ البوابة |
| `1` | فشلت البوابة: نتيجة بخطورة `--fail-on` أو أعلى، أو فشل بوابة `--policy`، أو فحص غير حاسم مع `--fail-on-inconclusive` |
| `2` | لم يُحكم على شيء: غياب `--authorized`، أو توليفة خيارات مرفوضة، أو ملف `--compare` غير موجود أو بلا فحص ويب، أو تعذّر الوصول إلى الموقع (DNS، أو رفض الاتصال، أو انتهاء المهلة، أو فشل TLS، أو الوكيل) |

**جدار الحماية ليس نجاحًا.** حين يجيب تحدٍّ من جدار حماية (WAF) أو تقييد معدل بدل الموقع، يوقف كاشِف الطلبات الاختيارية،
ويعدّ الفحوص المتأثرة «غير حاسمة»، ويضيف النتيجة WEB990، ويعرض درجة كاشِف `?`. وخطورة WEB990 هي `info`، فلا يُفشل
`--fail-on high` وحده تشغيلًا كهذا مع أن الموقع لم يُرَ فعلًا: أضف `--fail-on-inconclusive` ليفشل، واسمح لعنوان جهاز CI في
جدار الحماية أو افحص نسخة الاختبار (staging).

**الموقع الذي يتعذّر الوصول إليه** يُنهي الفحص برمز الخروج 2، ويكتب `-o` (بصيغة json أو sarif أو html أو markdown) أو
`--all-formats` تقريرًا مع ذلك، فلا تقرأ خطوات CI ملفًا قديمًا. وشكل تقرير JSON حينها هو المثال في القسم الإنجليزي: المفتاح
`web.status` قيمته `"unreachable"` (ولا يوجد هذا المفتاح في فحص مكتمل)، و`web.error` فيه `code` و`en` و`ar` و`raw`،
و`findings` فارغة، و`files_scanned` يساوي 0. وقيمة `error.code` إحدى `invalid` و`unsupported` و`dns` و`refused`
و`timeout` و`deadline` و`unreachable` و`tls` و`reset` و`network` أو رمز يبدأ بـ `proxy`. وفي SARIF يحمل التشغيل نفسه
`invocations[0].executionSuccessful: false` وإشعار `toolExecutionNotification` معرّفه `web/<code>`، والكائن `web` في
`runs[0].properties.kashif.web`.

**التراجعات:** احتفظ بتقرير JSON من آخر تشغيل وقارن به؛ ويكتب `--all-formats PREFIX` تقرير SARIF وتقرير JSON في تشغيل
واحد. ومثال وظيفة GitHub Actions الكامل في القسم الإنجليزي ([Using it in CI](#using-it-in-ci))، وجوهره:

```bash
cmp=""; [ -f previous/kashif-web.json ] && cmp="--compare previous/kashif-web.json"
kashif https://staging.example.com --authorized --fail-on high --fail-on-inconclusive $cmp --all-formats kashif-web
```

ثم ارفع `kashif-web.sarif` بالإجراء `github/codeql-action/upload-sarif` مع `category: kashif-web`، فيصبح تحليل الويب
تحليلًا مستقلًا لا يحلّ محل إنذارات فحص الكود في المستودع نفسه (ولا العكس). وموضع إنذارات الويب عنوان URL لا ملف في
المستودع: يعرضها GitHub في تبويب Security، لكن دون عرض للكود، ولا تظهر أبدًا تعليقاتٍ على الأسطر المتغيرة في طلب الدمج.

## ملف السياسة

في فحص الويب لا تُطبَّق السياسة إلا إذا سمّيتها: مرّر `--policy kashif.yml` (فالعنوان لا مجلد مشروع له يُبحث فيه عن
`kashif.yml` تلقائيًا). والسياسة تحدد رمز الخروج ولا تغيّر التقرير: فـ `rules.disable` و`rules.severity` تغيّران ما تحسبه
البوابة، أما التقرير فيعرض تلك النتائج بخطورتها الأصلية؛ ولاستبعاد قاعدة من التقرير استعمل `--ignore-rule ID`. والبوابة
الافتراضية تفشل عند `high`، فاذكر العتبة التي تريدها في `gate.fail_on`:

```yaml
version: 1
gate:
  fail_on: medium             # البوابة الافتراضية تفشل عند high
rules:
  disable:
    - id: WEB071
      reason: "certificates are renewed automatically 30 days before expiry"
  severity:
    - id: WEB-x-frame-options
      severity: low
      reason: "static documentation with no actions to click-jack"
```

```bash
kashif https://intranet.example --authorized --policy kashif.yml
```

## ما لا يكشفه الفحص السلبي

يقرأ الفحص السلبي ما يتلقاه زائر مجهول، وهذا يحدّ ما يمكنه قوله:

* **الصفحات العامة فقط.** لا تُزار الصفحات التي تتطلب تسجيل الدخول، ولا يسجّل كاشِف الدخول أبدًا.
* **لا اختبار للحقن ولا لـ XSS ولا للمصادقة ولا للتحكم في الوصول ولا لمنطق العمل.** فهذه تحتاج طلبات مصمَّمة لكسر
  التطبيق، ولا يرسلها كاشِف أبدًا. وفحوص DOM تقرأ كود JavaScript في الصفحة ولا تشغّله.
* **لا يُتحقَّق من إلغاء الشهادة.** يقرأ كاشِف استجابة OCSP المرفقة إن أرسلها الخادم، لكنه لا يتصل بجهة الإصدار (فلا طلب
  CRL ولا OCSP).
* **الدرجة تقيس سلامة الإعدادات، لا خلوّ الموقع من الثغرات.** فقد يحمل موقعٌ درجته A+ ثغرة حقن.

لذلك اجمع فحص الويب مع فحص الكود (SAST، أي `kashif .` على كود التطبيق)، ومع اختبار نشط مصرَّح به لما لا يراه أيٌّ منهما
(اختبار اختراق أو أداة DAST تُشغَّل بإذن المالك).

## الترقية من 1.0

* **نمط الفحص الافتراضي `standard`.** يرسل الفحص الافتراضي حتى 45 طلبًا بدل طلب الإصدار 1.0 الواحد، والفاصل بين الطلبات
  يسري على كل طلب، فالفحص أبطأ (نحو 3 ثوانٍ على صفحة محلية بالفاصل الافتراضي، ونحو 27 ثانيةً مع `--deep`). ويحافظ
  `--web-profile minimal` على حركة 1.0.
* **إعادة معايرة الخطورة.** تبقى معاني معرّفات القواعد كما هي، لكن بعض درجات الخطورة تغيّرت، فيتغيّر ما يُفشله `--fail-on`
  وسياسات الخطورة:

  | القاعدة | 1.0 | 1.1 |
  |---|---|---|
  | `WEB-strict-transport-security` (غياب HSTS) | high | medium |
  | `WEB020` (كوكي بلا Secure) | medium | high أو medium أو low بحسب فئة الكوكي وHSTS |
  | `WEB021` (كوكي بلا HttpOnly) | medium لكل الكوكيز | medium لكوكيز الجلسة والمصادقة فقط |
  | `WEB022` (كوكي بلا SameSite) | low لكل الكوكيز | low لكوكيز الجلسة والمصادقة وCSRF، وinfo (في `paranoid`) لغيرها |
  | `WEB050` (المحتوى المختلط) | medium | medium للمحتوى النشط، وlow للسلبي |
  | `WEB053` (بلا SRI) | low | low حيث تدعم شبكة التوزيع SRI، وinfo في غيرها |
  | `WEB054` (مكتبة JavaScript بها ثغرات) | من جدول يدوي | أعلى خطورة في بيانات retire.js |
  | `WEB071` (قرب انتهاء الشهادة) | medium | medium أو low، والعتبات نسبية إلى عمر الشهادة |
  | `WEB-x-frame-options` و`WEB-content-security-policy` | medium | medium، وlow على المستندات الثابتة بلا سكربتات |
  | `WEB-permissions-policy` و`WEB-x-content-type-options` | CWE-16 | CWE-693 (الخطورة كما هي) |

* **نتائج أقل ومجمَّعة.** تظهر النتيجة مرة واحدة لكل مضيف مع مواضعها، وزالت إنذارات 1.0 الكاذبة، ولا تظهر النتائج
  «المحتملة» (`tentative`) إلا مع `--web-sensitivity paranoid`.
* **البصمات.** تحتفظ قواعد ترويسات الأمان الست وWEB000 وWEB010 وWEB011 وWEB020–WEB022 وWEB040–WEB043 وWEB052 وWEB055
  وWEB056 وWEB060 ببصمات الإصدار 1.0، فيبقى خط الأساس وقرارات الفرز صالحة لها. أما WEB053 وWEB054 وبقية النتائج التي صارت
  تُجمع لكل مضيف أو مكتبة فبصمتها الآن مفتاح تجميعها، فلا تتغير مع قيم nonce أو التواريخ أو الأعداد: تظهر جديدةً مرة واحدة بعد
  الترقية، فأعد حينها كتابة خط أساس الويب (`--write-baseline`).
* **عمود CSV.** في تصدير CSV عمود أخير جديد `Confidence` (فارغ لنتائج الكود). ومن يقرأ الأعمدة بأسمائها أو مواضعها لا يتأثر،
  ومن يتحقق من عدد الأعمدة يحتاج إلى التحديث.
* **فشل الوكيل.** إعداد الوكيل الذي لا يستطيع كاشِف استعماله (`socks5://` أو منفذ غير صالح) صار يُفشل الفحص بخطأ
  في الوكيل (رمز الخروج 2) بدل الاتصال المباشر بالموقع. استعمل `--no-proxy` أو `NO_PROXY` للاتصال المباشر عمدًا.
* **الملاحظات.** ملاحظة «فحص سلبي: طلب واحد» صارت تذكر حدّ الطلبات الفعلي لنمط الفحص المختار. وتبقى الفحوص المحفوظة قبل
  الترقية بنصّها القديم.
* **الواجهة.** في نموذج فحص الويب خيارات نمط الفحص والحساسية والزحف والمقارنة، ويُقارن كل فحص لموقع بالفحص السابق له
  افتراضيًا (الإعدادات ← فحص الويب).
