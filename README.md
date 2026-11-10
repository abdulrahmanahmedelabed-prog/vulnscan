<p align="center">
  <img src="docs/logo.svg" alt="Kashif · كاشِف — vulnscan" width="520">
</p>

<p align="center">
  <b>English</b> | <a href="#arabic">العربية</a>
  &nbsp;·&nbsp; <a href="https://abdulrahmanahmedelabed-prog.github.io/vulnscan/">Website</a>
  &nbsp;·&nbsp; <a href="https://github.com/abdulrahmanahmedelabed-prog/vulnscan/releases/latest">Download</a>
</p>

<a id="english"></a>

# Kashif (vulnscan) — open-source SAST with real dataflow analysis

**Kashif** (كاشِف, "the revealer") is a dependency-free static application security testing tool written in
Python. `vulnscan` is the name of the command and the package. It scans source code, archives, Android apps
and (passively) websites, and produces a report ordered from **critical to info**, from the command line or
from a **local web UI** in English and Arabic.

| Dashboard | Finding with its data-flow trace |
|---|---|
| ![Kashif dashboard](docs/screenshots/dashboard-en-light.png) | ![A SQL injection finding with its source-to-sink trace](docs/screenshots/trace-en-light.png) |

> **Authorization first:** scan only what you own or are authorized in writing to test. Scanning other
> people's systems without permission may be illegal. Web targets require the `--authorized` flag.

## What it does

- **Dataflow (taint) analysis in 12 languages** — Python, JavaScript/TypeScript, Java, Kotlin, C#, Go, PHP,
  C/C++, Rust, Swift, Ruby and PL/SQL. Untrusted input is tracked across functions, classes and files, and
  every finding carries the full source → sink path.
- **Precision features** — flow-sensitive analysis with constant folding and dead-branch pruning;
  context-sensitive (k=2) points-to analysis; context-specific sanitizers (`html.escape` protects HTML only,
  not SQL or a shell); second-order (stored) injection through database tables.
- **Rules** — 74 built-in pattern/semantic rules, 46 dataflow + APEX rules and 11 built-in VQL queries
  (VQL is Kashif's declarative query language over the program database).
- **Oracle APEX & ORDS** — APEX application exports, plug-ins and PL/SQL packages.
- **Secrets** — provider-specific patterns plus entropy-based detection.
- **Dependency CVEs** — via [OSV.dev](https://osv.dev) for common lockfiles (optional; the only feature that
  needs the network).
- **Archives & Android** — zip, tar.gz, whl, APK, JAR, AAR, DEX; with [jadx](https://github.com/skylot/jadx)
  installed, bytecode is decompiled and analyzed.
- **Passive web scanning** — security headers, CSP, TLS, cookies, commonly exposed paths, and a crawl with
  rate limiting and an honest User-Agent. No payloads, no form submission.
- **Outputs** — console, Markdown, JSON, HTML and SARIF 2.1.0 (validated against the OASIS schema; works with
  GitHub Code Scanning and the VS Code SARIF viewer), with stable fingerprints.

## Install

### One line (verifies the SHA-256 before installing)

```bash
# macOS and Linux: installs vulnscan (and a kashif alias) into ~/.local/bin
curl -fsSL https://abdulrahmanahmedelabed-prog.github.io/vulnscan/install.sh | sh
```

```powershell
# Windows: installs into %LOCALAPPDATA%\Programs\Kashif and adds it to your PATH
irm https://abdulrahmanahmedelabed-prog.github.io/vulnscan/install.ps1 | iex
```

```bash
# Homebrew (macOS and Linux)
brew tap kashif/vulnscan https://github.com/abdulrahmanahmedelabed-prog/vulnscan
brew install kashif
```

All three download the release binary over HTTPS and check it against the release's `SHA256SUMS.txt`. Because
they download with curl, macOS does not quarantine the file, so Gatekeeper does not block the (not yet notarized)
binary.

### Download a binary (nothing else needed)

Get the file for your platform from the
[latest release](https://github.com/abdulrahmanahmedelabed-prog/vulnscan/releases/latest):

| Platform | File |
|---|---|
| Windows x64 | [`vulnscan-windows.exe`](https://github.com/abdulrahmanahmedelabed-prog/vulnscan/releases/latest/download/vulnscan-windows.exe) — double-click to open the web UI |
| Linux x86-64 (Ubuntu 22.04+, Debian 12, RHEL 9+) | [`vulnscan-linux`](https://github.com/abdulrahmanahmedelabed-prog/vulnscan/releases/latest/download/vulnscan-linux) |
| macOS Apple Silicon | [`vulnscan-macos-arm64`](https://github.com/abdulrahmanahmedelabed-prog/vulnscan/releases/latest/download/vulnscan-macos-arm64) |
| macOS Intel | [`vulnscan-macos-x86_64`](https://github.com/abdulrahmanahmedelabed-prog/vulnscan/releases/latest/download/vulnscan-macos-x86_64) |

```bash
# Linux
chmod +x vulnscan-linux
./vulnscan-linux                    # opens the web UI
./vulnscan-linux ./project --fail-on high

# macOS: the binary is not notarized by Apple. Remove the quarantine flag once
# (or right-click the file > Open on first launch):
chmod +x vulnscan-macos-arm64
xattr -d com.apple.quarantine vulnscan-macos-arm64
./vulnscan-macos-arm64
```

**Verify the download.** Every release ships `SHA256SUMS.txt`, a CycloneDX SBOM (`vulnscan-sbom.cdx.json`)
and signed SLSA build provenance:

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
gh attestation verify vulnscan-linux --repo abdulrahmanahmedelabed-prog/vulnscan
```

### Install with pip (Python 3.10+)

```bash
pip install git+https://github.com/abdulrahmanahmedelabed-prog/vulnscan
```

Kashif has **zero runtime dependencies**. You can also run it from a clone with `python -m vulnscan`.

### Updating

The binaries update themselves. In the web UI open **Settings > Updates** and select **Update now**, then
**Restart now**; a small "Update available" badge appears in the sidebar when a newer release is out. From a
terminal:

```bash
vulnscan update            # check, confirm, download, verify, install
vulnscan update --check    # only check: exit code 10 when an update is available, 0 when up to date
vulnscan update --yes      # no confirmation prompt (scripts)
```

The update is downloaded only from GitHub over HTTPS, checked against the release's `SHA256SUMS.txt`, refused if
it is not newer, and tested (`--version`) before it atomically replaces the running binary; the previous binary is
kept as `<name>.old` until the next start, and any failure rolls back. On macOS, an Intel binary running under
Rosetta is offered the native Apple Silicon build. If the binary's folder is not writable (for example
`/usr/local/bin`), run `sudo vulnscan update`. pip and source installs are never modified: the UI and
`vulnscan update` show the exact command instead (`python -m pip install --upgrade ...` or `git pull`).
The check asks `api.github.com` for the latest release at most every 6 hours and sends nothing about your code;
turn off **Check for updates automatically** in Settings to disable it.

## Quick start

```bash
vulnscan ./my-project                         # colored console report
vulnscan ./my-project --all-formats report    # report.md / .json / .html / .sarif
vulnscan app.apk -f html -o report.html       # archives and APKs
vulnscan . --fail-on high --exclude "tests/*" # CI gate
vulnscan . --no-deps --no-external            # fully offline
vulnscan https://my-site.example --authorized # passive web scan of a site you own
vulnscan ui                                   # web UI on http://127.0.0.1:8765
vulnscan . --lang en                          # English-only output (ar, en, both; or set VULNSCAN_LANG)
```

Every finding, remediation, data-flow step and scan note is available in English and Arabic: the web UI switches
language in one click, `--lang` controls the console and the Markdown/HTML reports, and SARIF is English-first
for GitHub Code Scanning (Arabic kept in the result properties).

The web UI (dashboard, scan, findings, reports, rules, settings) listens on 127.0.0.1 only; data is stored in
`~/.vulnscan` (or `VULNSCAN_HOME`).

## CI and GitHub Code Scanning (SARIF)

```yaml
permissions:
  contents: read
  security-events: write   # required to upload SARIF
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5
    with: { python-version: "3.12" }
  - run: pip install git+https://github.com/abdulrahmanahmedelabed-prog/vulnscan
  - run: vulnscan . --no-deps -f sarif -o vulnscan.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: vulnscan.sarif
```

Findings appear in the Security tab and inline on pull requests, with a numeric severity, CWE and the dataflow
path. Fingerprints are stable across line shifts and reformatting, so alerts are not duplicated.

### Pull-request review comments, GitLab, pre-commit

- **GitHub Action** (`uses: abdulrahmanahmedelabed-prog/vulnscan@v0.9.0`): scans the pull request, uploads SARIF and
  posts one review with inline comments on the changed lines only (rule, severity, remediation, data-flow path),
  plus a summary comment that is updated, not duplicated, on every push.
- **Diff-aware scanning** anywhere: `vulnscan . --diff-base origin/main` reports only what the branch introduces
  (the whole project is still analysed, so cross-file flows stay correct); `--fail-on` then gates on new findings only.
- **GitLab**: `-f gitlab-sast` (Security dashboard and merge-request widget) and `-f codeclimate` (Code Quality);
  a ready `.gitlab-ci.yml`, plus Azure Pipelines and Bitbucket templates, are in `integrations/`.
- **pre-commit**: a `kashif` hook that checks only staged changes.

Full guide: `docs/integrations.md`.

## IDE integration (VS Code, JetBrains, Neovim, Helix, Zed, Sublime, Emacs)

`vulnscan lsp` is a Language Server: vulnerabilities are underlined while you work, with the data-flow path as
related locations, remediation on hover, and quick fixes to suppress a reviewed finding or add it to the baseline.
The VS Code extension (`kashif-vscode.vsix`, attached to every release) runs it for you; other editors connect to
the same server. Setup for each editor: `editors/README.md`.

### Baseline: report only what's new

```bash
vulnscan . --write-baseline .vulnscan-baseline.json          # once; commit the file (fingerprints only)
vulnscan . --baseline .vulnscan-baseline.json --fail-on high # later: new findings only
```

### Audit profile

`--audit` additionally lists every dangerous call (eval, shell, SQL, pickle, …) that dataflow analysis could
not prove is reached by untrusted input — useful for manual security reviews where you want the whole attack
surface, not just proven flows.

## Accuracy: OWASP Benchmark

Measured on the [OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython) v0.1
(1,230 test cases) and the [OWASP Benchmark for Java](https://github.com/OWASP-Benchmark/BenchmarkJava) v1.2
(2,740 test cases). Score = mean over categories of TPR − FPR (Youden's J), the official OWASP method.
**Python: 74.0% · Java: 76.3%.**

| Category | Py TPR % | Py FPR % | Py score | Java TPR % | Java FPR % | Java score |
|---|---:|---:|---:|---:|---:|---:|
| cmdi (command injection) | 100.0 | 42.9 | 57.1 | 100.0 | 24.8 | 75.2 |
| codeinj (code injection) | 100.0 | 45.5 | 54.5 | — | — | — |
| crypto (weak cipher) | — | — | — | 100.0 | 0.0 | 100.0 |
| deserialization (deserialization) | 100.0 | 8.3 | 91.7 | — | — | — |
| hash (weak hashing) | 100.0 | 0.0 | 100.0 | 100.0 | 0.0 | 100.0 |
| ldapi (LDAP injection) | 100.0 | 7.7 | 92.3 | 100.0 | 37.5 | 62.5 |
| pathtraver (path traversal) | 92.3 | 46.6 | 45.7 | 100.0 | 38.5 | 61.5 |
| redirect (open redirect) | 100.0 | 47.6 | 52.4 | — | — | — |
| securecookie (insecure cookie) | 100.0 | 0.0 | 100.0 | 100.0 | 0.0 | 100.0 |
| sqli (SQL injection) | 100.0 | 0.0 | 100.0 | 100.0 | 37.1 | 62.9 |
| trustbound (trust boundary) | 100.0 | 36.8 | 63.2 | 85.5 | 34.9 | 50.7 |
| weakrand (weak randomness) | 100.0 | 0.0 | 100.0 | 100.0 | 0.0 | 100.0 |
| xpathi (XPath injection) | 76.5 | 20.0 | 56.5 | 100.0 | 15.0 | 85.0 |
| xss (cross-site scripting) | 100.0 | 43.1 | 56.9 | 88.2 | 46.4 | 41.8 |
| xxe (XML external entities) | 100.0 | 35.0 | 65.0 | — | — | — |
| **Overall** | | | **74.0** | | | **76.3** |

Each suite is scanned whole, as one application (the Python repository, the Java `src/main` tree), with the
default profile. Reproduce either with one command:

```bash
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkPython && python bench/score_owasp.py BenchmarkPython
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava && python bench/score_owasp.py BenchmarkJava
```

The engine is never tuned to benchmark files: no test-case names, paths or expected results are encoded in
it. The weakest categories (path traversal, XSS, redirects) are where values need deeper tracking; that gap is
reported as measured.

## Languages and targets

| Target | Coverage |
|---|---|
| Dataflow (taint) | Python, JavaScript/TypeScript, Java, Kotlin, C#, Go, PHP, C/C++, Rust, Swift, Ruby, PL/SQL |
| Oracle | APEX application exports, plug-ins, PL/SQL packages, ORDS |
| Android / JVM | APK, JAR, AAR, DEX (decompiled with jadx when installed) |
| Config & CI | Dockerfile, docker-compose, GitHub Actions, AndroidManifest, iOS plist, config files |
| Web (passive) | headers, CSP, TLS, cookies, exposed paths, rate-limited crawl (`--authorized` required) |

## Limitations

- Static analysis finds common patterns and flows; it does not replace human review or penetration testing.
- False positives and misses happen. Suppress a reviewed line with `# nosec` or `// vulnscan: ignore`, or a
  rule with `--ignore-rule`.
- Compared with CodeQL, Semgrep, SonarQube or Snyk Code, Kashif has fewer library models (about 5,100 modelled APIs
  and 149 pattern rules) and far less real-world tuning on large codebases. Its strengths are running fully locally
  with zero dependencies, English and Arabic output, Oracle APEX, archives/APKs and passive web checks in one tool.
- Not modelled yet: validation done by form libraries (WTForms `validate_on_submit()` and similar), reflection
  and dynamic dispatch through strings, and values that flow through files or databases outside the scanned code.
- Without jadx, APK/JAR contents are scanned as text only; decompiled code may differ from the original source.
- The web scan is passive only: no active testing of any kind.

## Security policy

Please report vulnerabilities in Kashif privately via GitHub's
[private vulnerability reporting](https://github.com/abdulrahmanahmedelabed-prog/vulnscan/security/advisories/new);
see [SECURITY.md](SECURITY.md). All GitHub Actions in this repository are pinned by commit SHA, an OpenSSF
Scorecard workflow runs on the repository, and every release ships checksums, an SBOM and signed SLSA
provenance.

## License

[MIT](LICENSE).

---

<a id="arabic"></a>

<p dir="rtl"><a href="#english">English</a> | <b>العربية</b></p>

# كاشِف (vulnscan) — فاحص ثغرات مستقل لأي برنامج

> **كاشِف** هو الاسم العربي للأداة؛ و`vulnscan` هو اسم الأمر والحزمة التقني.

أداة بلغة Python (بدون أي اعتماديات خارجية) تفحص **أي برنامج** وتُخرج تقريرًا
مرتبًا **من الأعلى خطورة إلى الأقل**: حرج ← عالٍ ← متوسط ← منخفض ← معلوماتي.
تعمل من سطر الأوامر، أو من **واجهة رسومية محلية** بلوحة تحكم وتقارير وإعدادات.

| لوحة التحكم | نتيجة مع مسار تدفق البيانات وطريقة الإصلاح |
|---|---|
| ![لوحة تحكم كاشِف](docs/screenshots/dashboard-ar-light.png) | ![نتيجة حقن SQL مع مسارها من المصدر إلى نقطة الخطر](docs/screenshots/trace-ar-light.png) |

| فحص جديد: مجلد أو ملف مضغوط أو موقع | التقارير والمقارنة (الوضع الداكن) |
|---|---|
| ![شاشة الفحص الجديد](docs/screenshots/scan-ar-light.png) | ![التقارير في الوضع الداكن](docs/screenshots/reports-ar-dark.png) |

> ⚠️ **الصلاحية أولًا:** افحص فقط ما تملكه أو ما لديك تصريح كتابي بفحصه. فحص أنظمة الآخرين دون إذن
> قد يكون مخالفًا للقانون. فحص عناوين الويب لا يعمل إلا مع العلامة `--authorized`.

## ماذا يفحص؟

| الهدف | مثال | ما يحدث |
|---|---|---|
| مجلد مصدر بأي لغة | `vulnscan ./my-app` | يمر على كل الملفات النصية ويطبّق 65+ قاعدة |
| ملف واحد | `vulnscan server.py` | يفحص الملف وحده |
| أرشيف / حزمة | `vulnscan app.apk` أو `.jar` `.zip` `.whl` `.tar.gz` | يفكّه في مجلد مؤقت ويفحص محتواه |
| عنوان ويب (سلبي) | `vulnscan https://my-site.example --authorized [--deep] [--crawl]` | ترويسات الأمان، الكوكيز، CSP، TLS، تحليل الصفحة وبصمة المنصّة؛ `--deep` للمسارات المكشوفة و`--crawl` لزحف الصفحات |

القواعد المدمجة تغطي: Python، JavaScript/TypeScript، Dart/Flutter، Java/Kotlin، Go، PHP، Ruby، C#، C/C++،
Shell، Dockerfile، docker-compose، GitHub Actions، AndroidManifest، iOS plist، وملفات الإعدادات.

فئات الثغرات: أسرار ومفاتيح مضمّنة، تنفيذ أوامر/كود (RCE)، حقن SQL/XSS/قوالب/مسارات، فك تسلسل غير آمن،
تشفير ضعيف وتعطيل TLS، إعدادات خطرة (debug، CORS، 0.0.0.0)، أمان الموبايل، أمان الحاويات و CI،
سلامة الذاكرة في C، تسجيل بيانات حساسة، وملفات لا يجوز شحنها (.env، مفاتيح SSH، قواعد بيانات).

### فحص الويب بعمق أكبر

الفحص الافتراضي لعنوان الويب سلبي بالكامل: يقرأ ما يخدمه الموقع فقط ولا يرسل أي بيانات في النماذج
ولا يجرّب أي حمولات. يغطّي:

- **ترويسات الأمان**: HSTS، CSP (مع كشف `unsafe-inline` و`unsafe-eval` و`*`)، X-Frame-Options،
  X-Content-Type-Options، Referrer-Policy، Permissions-Policy.
- **الكوكيز**: علامات Secure و HttpOnly و SameSite.
- **TLS والشهادة**: قبول TLS 1.0/1.1 القديم، وانتهاء الشهادة أو عدم صحتها.
- **تحليل الصفحة** (من نفس الطلب، بلا طلبات إضافية): محتوى مختلط على صفحة HTTPS، نماذج تُرسل عبر HTTP،
  حقل كلمة مرور في صفحة غير آمنة، سكربتات خارجية بلا SRI، إصدار jQuery قديم، عرض فهرس المجلدات،
  وأثر استثناء/تصحيح مسرَّب في الاستجابة.

مع `--deep` (أو خيار «فحص أعمق» في الواجهة) يُجري **عددًا محدودًا** من الطلبات الإضافية لملفات يشيع
تركها مكشوفة بالخطأ: `.git/HEAD`، `.env`، `.svn/entries`، `.DS_Store`، `server-status`، `phpinfo.php`،
و`security.txt`، مع قراءة `robots.txt`. لا يتجاوز ذلك قراءة ما هو متاح أصلًا، ولا يُجري أي اختبار نشط
(لا حقن، ولا تخمين، ولا تجاوز للحماية).

> ⚠️ كل فحص ويب يتطلب `--authorized` (أو تفعيل الإقرار في الواجهة). افحص فقط المواقع التي تملكها أو لديك
> تصريح كتابي بفحصها.

### تحليل تدفق البيانات (Taint) — محرّك مدرك للأنواع على نهج CodeQL

إضافةً إلى قواعد الأنماط، يبني كاشِف **نموذجًا واحدًا للمشروع كله** ويتتبّع البيانات من المصادر غير الموثوقة إلى
نقاط الخطر عبر الدوال والأصناف والملفات. ما يجعله قريبًا من CodeQL:

| القدرة | كيف تعمل في كاشِف |
|---|---|
| **نماذج كبيانات (Models-as-Data)** | المصادر ونقاط الخطر والمُعقّمات ونقاط الدخول والمدقّقات مُعرَّفة في JSON (`vulnscan/models/python.json`). أضف نماذج مكتباتك بـ `--models DIR` أو من الإعدادات دون تعديل الكود. |
| **نماذج مكتبات مدمجة** | Flask/Django/FastAPI/Starlette/Tornado/aiohttp كمصادر ونقاط دخول؛ نقاط خطر لـ `os`/`subprocess`/SQL (`execute`، `raw`، `sqlalchemy.text`)/الملفات/`pickle`/`yaml`/القوالب/`redirect`/**SSRF** (`requests`، `urlopen`، `httpx`)/عمليات نظام الملفات/الاستيراد الديناميكي/XSS الانعكاسي/LDAP/XPath/حقن السجلات. 16 قاعدة `DF001`–`DF016`. |
| **نقاط دخول أطر العمل** | معاملات الدوال المُوجَّهة (`@app.route`، `@router.get`، views بالأصناف، أوامر CLI) مصادر تلقائيًا، كما في RemoteFlowSource. |
| **حلّ استدعاءات مدرك للأنواع** | نوع المتغير من المُنشئ والتعليقات و`self` والحقول وأنواع الإرجاع؛ حلّ الدوال عبر MRO مع التعدد الشكلي؛ تتبّع قيم الدوال (`h = helper`، `functools.partial`) و`*args`/`**kwargs`؛ والاستيرادات المطلقة والنسبية والمستعارة (`import subprocess as sp`). |
| **حساسية الحقول والحاويات** | `self.x` بين الدوال، وسائط المُنشئ إلى الحقول، `append`/التخزين بالفهرس/القوائم الحرفية. |
| **points-to حسّاس للسياق (k=2) وحسّاس للتدفق** | تحليل Andersen بسلسلة استدعاء بعمق اثنين واستنساخ الكائنات، فالمصنع المستدعى من موضعين يعيد كائنين مختلفين حتى عبر غلاف وسيط؛ والمتغيرات المحلية بصيغة SSA (تحديث قوي، ودمج الفروع، وحلقات بنقاط φ) فإعادة الإسناد تلغي التلوّث السابق. |
| **حواجز التحقق (path-sensitivity)** | `if x in ALLOWED:`، `x.isalnum()`، `re.fullmatch(..، x)`، و`if not valid(x): return` تمنع الإبلاغ عن النقطة المحروسة، داخل الدالة وعبر الدوال المساعدة. |
| **مسار التدفق الكامل** | كل نتيجة تحمل خطوات المسار من المصدر إلى نقطة الخطر عبر الإسنادات والاستدعاءات والملفات، وتُعرض في الواجهة والتقارير. |
| **دقة التصنيف** | عنصر ملوّث داخل قائمة وسائط بعد برنامج ثابت وبلا `shell=True` = حقن وسائط (`DF009`، متوسط) لا حقن أوامر (`DF003`)؛ `getoutput`/`os.system` بسلاسل shell = حرج. |
| **كتم مراجَع** | `# nosec` على سطر نقطة الخطر يكتم النتيجة وكل ما يُشتق منها في المستدعين. |

```python
# io_mod.py
def read_name():  return request.args["name"]   # يعيد بيانات غير موثوقة
# exec_mod.py
def run(cmd):     os.system(cmd)                 # وسيط يصل إلى نقطة خطر
# views.py
@app.route("/x")
def handler():    run(read_name())               # ← يُبلَّغ عنه مع مسار: io_mod.py:2 → views.py:3 → exec_mod.py:2
```

مثال على نموذج مستخدم (`my_models.json`):

```json
{"sinks": [{"rule": "DF901", "severity": "high", "cwe": "CWE-999", "label": "mylib.dangerous",
            "names": ["mylib.dangerous"], "title": "custom sink", "title_ar": "نقطة خطر مخصصة",
            "advice": "لا تمرّر مدخلات المستخدم.", "args": [0]}],
 "sanitizers": ["mylib.clean"]}
```

ما يبقى مختلفًا عن CodeQL بصدق: لا نمذجة كاملة للمكتبة المعيارية لكل لغة (النماذج تغطي الأطر الشائعة لا كل واجهة)،
ولا تكامل IDE/مراجعة الطلبات، وواجهات اللغات غير Python تحليلية متسامحة — لكنها الآن **تُبلّغ عن كل عبارة تخطّتها**
(سطرها وسببها في ملاحظات الفحص) فلا يسقط شيء بصمت. القيود الأربع التي كانت قائمة أُغلقت: صار points-to حسّاسًا للسياق
بعمق اثنين وحسّاسًا للتدفق، وصارت VQL تدعم الأصناف والمسندات الذاتية والتجميعات، وصار المحرّك يغطّي 12 لغة.

### تحليل points-to (تحليل المؤشّرات)

فوق استنتاج الأنواع، يُجري المحرّك تحليل **points-to على نهج Andersen، حسّاسًا لموضع الاستدعاء (k = 1) مع استنساخ
الكائنات لكل سياق** (`vulnscan/pointsto.py`): كل استدعاء مُنشئ
وكل قائمة/قاموس حرفي وكل دالة كقيمة **كائن مجرّد** بموضع تخصيصه (allocation site)؛ والمتغيرات وحقول الكائنات
وعناصر الحاويات وقيم الإرجاع **عقد مؤشّرات**؛ والإسنادات وقراءة/كتابة الحقول والاستدعاءات (وسيط ← معامل، إرجاع ← نتيجة،
متلقٍّ ← `self`) والتكرار تولّد قيود احتواء تُحلّ حتى نقطة الثبات. يستفيد منه المحرّك في:

- **حلّ الاستدعاءات على الكائنات الفعلية** لا على النوع الساكن فقط: دوال مُمرَّرة كمعاملات (callbacks)، دوال
  تُعاد من مصانع، كائنات محفوظة في قواميس أو قوائم (`HANDLERS["sh"].run(...)`).
- **التسمية المستعارة في الذاكرة (heap aliasing)**: تلوّث يُخزَّن في حقل كائن يظهر عبر كل أسمائه المستعارة في أي دالة،
  حتى عبر المتغيرات العامة والحاويات (`STORE.append(t)` في دالة، و`os.system(t.cmd)` في أخرى).
- **فصل مواضع التخصيص**: `Task()` ملوّثة في دالة و`Task()` نظيفة في أخرى تبقيان كائنين مختلفين.

- **حساسية السياق**: تُستنسخ عقد الدالة وكائناتها لكل موضع استدعاء (k = 1)، فمصنع يُستدعى من موضعين يُعيد كائنين
  مختلفين، وcallback مُمرَّر كمعامل يُحلّ **لكل موضع استدعاء على حدة**: `run_all(shell, t)` تُبلَّغ و`run_all(logger, t)`
  لا تُبلَّغ، بدل اتحاد كل الدوال التي مرّت يومًا عبر ذلك المعامل.

التحليل غير حسّاس للتدفق، وحساسيته للسياق بعمق استدعاء واحد (k = 1) مع حدّ أقصى للسياقات لكل دالة حفاظًا على
الزمن، بينما تبقى حساسية السياق لتدفق التلوّث نفسه عبر ملخّصات الدوال، فتُبلَّغ النتيجة في موضع الاستدعاء الملوّث.

### 12 لغة بنفس محرّك تدفق البيانات: Python، JavaScript/TypeScript، Java، Kotlin، C#، Go، PHP، C/C++، Rust، Swift، Ruby، PL/SQL

المحرّك يعمل على **شكل** البرنامج لا على لغته، لذا تدعم الأداة JavaScript وTypeScript عبر واجهة أمامية
(`vulnscan/js_frontend.py`) تحلّل الكود بمحلّل متسامح خاص بها (بلا أي اعتمادية) وتُنزّله إلى الشجرة نفسها
التي يفهمها المحرّك، فتحصل تلقائيًا على كل ما سبق: إدراك الأنواع، عبر الملفات، الحقول، حواجز التحقق، ومسار التدفق.

- **ما يُفهم**: ES2020+ (الاستيراد والتصدير و`require`، الأسهم، القوالب النصية، التفكيك، الأصناف، `async/await`،
  التسلسل الاختياري) وTypeScript (التعليقات النوعية تُتجاهل، والمُزخرِفات وخصائص معاملات المُنشئ تُحفظ،
  و`interface/type/enum` تُتخطّى).
- **نماذج Node والمتصفح** في `vulnscan/models/javascript.json`: مصادر Express/Koa/Lambda (`req.query/body/params`،
  `event`، `process.argv`، `location`، `document.cookie`)، ونقاط دخول (`app.get(...)`، NestJS `@Get()`،
  `exports.handler`)، ونقاط خطر `child_process`، `fs`، `res.send`، `innerHTML`، `axios/fetch` (SSRF)، `res.redirect`،
  `require` الديناميكي، قوالب EJS/Pug/Handlebars، واستعلامات `query/raw/$queryRawUnsafe`.
- أسماء الاستيراد تُحلّ (`const cp = require('child_process')` فيُفهم `cp.exec`)، والملفات النسبية
  (`require('./lib/shell')`) تُربط عبر المشروع.
- الملفات المضغوطة (`*.min.js`) وتعريفات الأنواع (`*.d.ts`) والحزم الضخمة تُتخطّى.
- **Java وKotlin وC# وGo وPHP** عبر واجهة أمامية لعائلة C (`vulnscan/cfamily_frontend.py`) بالمنهج نفسه: دوال
  وأصناف وحقول (مع `this` الضمني في Java/Kotlin/C#)، الاستيرادات (`import`/`using`/`use`/حزم Go)، المُزخرِفات
  والسمات (`@GetMapping`، `[HttpGet]`، `#[Route]`)، الاستيفاء النصي (`"$x"`، `$"{x}"`)، معاملات مُنشئ Kotlin
  كحقول مُعنوَنة، أساليب المستقبِل في Go، والمتغيرات الفائقة في PHP. نماذج لكل لغة في `vulnscan/models/`
  (Servlet/Spring/JDBC، Ktor/Spring، ASP.NET/EF، net/http/gin/database/sql، PDO/mysqli/Laravel/Symfony).

```js
// lib/shell.js
const cp = require('child_process');
function run(c) { cp.execSync(c); }        // وسيط يصل إلى أمر shell
module.exports = { run };
// server.js
const { run } = require('./lib/shell');
app.post('/x', (req, res) => { run(req.body.c); });   // ← يُبلَّغ عنه عبر الملفين
```

### Oracle APEX وPL/SQL والمساعد الذكي

يفحص كاشِف كود قاعدة بيانات Oracle وتطبيقات APEX من المصدر، لا من الموقع فقط. ضع ملفات التصدير والحزم في مجلد وافحصه:

```
vulnscan ./my-apex-app        # f100.sql أو application/pages/*.sql، وملفات .pkb/.pks/.sql/.trg
```

| ما يُحلَّل | كيف |
|---|---|
| **PL/SQL** (`.sql` `.pkb` `.pks` `.pls` `.prc` `.fnc` `.trg` …) | الحزم والإجراءات والدوال والمشغّلات والكتل المجهولة، بتحليل تدفق البيانات نفسه عبر الحزم والملفات، مع الوسائط المسمّاة `p_x => v`. |
| **ملف تصدير APEX** (تطبيق كامل أو صفحة أو إضافة) | يُستخرج كل كود من داخل استدعاءات `wwv_flow_imp_page.create_…`: العمليات، ومناطق PL/SQL، و"دالة تُعيد استعلام SQL"، والتحققات والحسابات والشروط، والإجراءات الديناميكية، ورمز الإضافات، وملفات JavaScript المضمّنة بالترميز الست عشري. كل نتيجة تشير إلى سطرها في ملف التصدير وإلى مكوّنها: «صفحة 10 › عملية: Save». |
| **تصدير APEX المقروء (YAML)** | مجلد `readable/` (APEX 23.2+): تُقرأ الخصائص النصية (`pl/sql-code`، `sql-query`، `pl/sql-function-body-returning-sql-query`، كود JavaScript، تعليمات الذكاء الاصطناعي) من سطرها، وتُنسب إلى المكوّن من عناوين `# ====== Region: …`، ويُكشف `escape-special-characters: false`. |
| **معالجات ORDS** | `ORDS.DEFINE_HANDLER` / `DEFINE_SERVICE` حيثما وُجدت: في `.sql`، وداخل سجلات Liquibase/SQLcl بصيغة XML (`runOracleScript` و CDATA)، وفي تعريفات REST بصيغة JSON. معالجات PL/SQL تُحلَّل ككود، ومعالجات الاستعلام كـ SQL، ومتغيرات الربط (`:id` و`:body_text`…) مصادر، و`:forward_location` نقطة تحويل. |
| **دوال داخل SQL الثابت** | الاستعلامات الثابتة في التقارير وقوائم القيم ومعالجات ORDS، وجمل `SELECT/INSERT/UPDATE/DELETE/MERGE` والمؤشرات داخل PL/SQL: متغير الربط آمن لـ SQL، لكن الدالة التي تستقبله تُتتبَّع، فإن بنت به SQL ديناميكيًا يُبلَّغ عنه. |
| **Java داخل قاعدة البيانات** | كتل `create … java source` تُحلَّل بواجهة Java، و«call spec» (`as language java name '…'`) يُربط بالدالة، فيُكشف التدفق من عنصر الصفحة عبر PL/SQL إلى `Runtime.exec` في Java. |

**المصادر**: عناصر الصفحة `:P1_X` و`v('P1_X')` و`nv()` و`apex_util.get_session_state()`، و`apex_application.g_x01…g_f50`، وقيم الإضافات `p_item.value` و`p_param.value`، و`owa_util.get_cgi_env` و`apex_json`.
**نقاط الخطر**: `EXECUTE IMMEDIATE` و`OPEN … FOR` و`DBMS_SQL.PARSE` و`apex_exec` و`apex_collection.create_collection_from_query`، و`htp.p`، و`owa_util.redirect_url`، و`apex_web_service`/`utl_http`، و`utl_file`، و`dbms_ldap`، و`dbms_scheduler`/`dbms_job`.
**المعقّمات**: `USING` (متغيرات الربط) و`DBMS_ASSERT` و`apex_escape` و`htf.escape_sc`.

قواعد خاصة بـ APEX لا تحتاج تدفق بيانات:

| القاعدة | المشكلة |
|---|---|
| `APX001` | سلسلة استبدال `&P1_X.` داخل SQL أو PL/SQL — تُستبدل نصيًا قبل التنفيذ فتسمح بالحقن. |
| `APX002` | `&P1_X.` داخل JavaScript دون المرشّح `!JS`. |
| `APX003` | `&P1_X!RAW.` في HTML. |
| `APX004` | تهريب المخرجات معطّل لعمود أو عنصر (`WITHOUT_MODIFICATION`). |
| `APX005` | عنصر يتحكم به المستخدم يُستبدل داخل تعليمات المساعد الذكي (إعداد AI في APEX 24). |

**فحص إعدادات أمان التطبيق** (على نهج APEX Advisor وAPEX-SERT، من ملف التصدير بصيغتيه SQL وYAML):

| القاعدة | الإعداد |
|---|---|
| `APX006` | حماية حالة الجلسة (Session State Protection) معطّلة |
| `APX007` | Rejoin Sessions لكل الجلسات |
| `APX008` | السماح بالتضمين في إطار من أي موقع |
| `APX009` | روابط تعديل المطوّر في بيئة التشغيل |
| `APX010` | checksum بـ MD5/SHA1 |
| `APX011` | تهريب HTML أساسي |
| `APX012` | Runtime API تعدّل التطبيقات |
| `APX013` | كوكي المصادقة دون Secure |
| `APX014` | مخطط «بلا مصادقة» |
| `APX015` | كلمة مرور تُقارن كنص صريح (المصادقة المخصصة والحزم) |
| `APX016` | صفحة عامة تعدّل البيانات (صفحة الدخول مستثناة) |
| `APX017` | صفحة تعدّل البيانات بلا مخطط تفويض |
| `APX018` | حماية الوصول للصفحة غير مقيّدة |
| `APX019` | عنصر مخفي قيمته غير محمية |
| `APX020` | عملية AJAX عند الطلب بلا تفويض |
| `APX021` | الاستبدال دون النقطة الختامية |

أسماء الخصائص ومعانيها مأخوذة من ملفات تصدير أوراكل الرسمية نفسها، وقد جُرّبت الفحوص عليها.

**ثغرات المساعد الذكي** (`apex_ai` و`dbms_cloud_ai` / Select AI و`dbms_vector_chain`):

| القاعدة | المشكلة |
|---|---|
| `DF019` | بيانات المستخدم تصل إلى `p_system_prompt` — حقن التعليمات. |
| `DF020` حرج | نص يولّده النموذج يُنفَّذ كـ SQL أو كود (`execute immediate` على مخرجات `apex_ai.generate`). |
| `DF021` | مخرجات النموذج تُكتب في الصفحة دون تهريب (XSS عبر النموذج). |
| `DF022` | نص المستخدم يقود توليد SQL عبر Select AI — يُنبّه لتقييد ملف التعريف وصلاحيات التنفيذ. |

**الحقن من الدرجة الثانية وXSS المخزّن** (`DF023` و`DF024`): يتتبّع كاشِف الجداول نفسها. حين يكتب `INSERT` أو `UPDATE`
أو `INSERT … SELECT`، أو نموذج APEX يحفظ عناصره تلقائيًا (Form Region / Automatic Row Processing)، قيمةً من المستخدم في
`جدول.عمود`، تصير كل قراءة لذلك العمود (`SELECT … INTO`، وحقول صفوف حلقات المؤشر، و`FETCH`) مصدرًا ملوّثًا في أي ملف.
يُعاد التحليل حتى الاستقرار فتُتبع النُسخ من جدول إلى آخر. الأعمدة التي لا يكتب فيها المستخدم لا تُبلَّغ عنها، والنتيجة
تذكر أين كُتبت القيمة: «بيانات مخزّنة في NOTES.BODY (كتبها مستخدم في f300.sql:19)».

**تعريفات REST بصيغة JSON**: تُقرأ صيغتان معروفتان: الوحدة المتداخلة (`templates` → `handlers`)، وتصدير جداول ORDS الوصفية
(`USER_ORDS_MODULES` و`_TEMPLATES` و`_HANDLERS`، كما يصدّرها SQL Developer) مع ربط المعالج بنمطه ووحدته عبر المعرّفات.
وفي أي ملف JSON آخر، كل قيمة نصية هي كتلة PL/SQL كاملة (`begin … ; … end;`) تُحلَّل ككود أيًّا كان اسم مفتاحها،
وتُنسب النتيجة إلى مسارها داخل الملف (`JSON › $.steps[0].plsqlBody`).

### الحقن من الدرجة الثانية في كل اللغات

الآلية نفسها (الكتابة في `جدول.عمود` ثم قراءته مصدرًا) تعمل على كل اللغات، لأنها تجري على الشجرة المشتركة بعد الواجهات الأمامية:

| النوع | ما يُفهم |
|---|---|
| **SQL خام بمتغيرات ربط** | `?` و`%s` و`%(name)s` و`$1` و`:name` و`@name`: `cur.execute(sql, params)`، `db.query(sql, [..])`، `db.Exec(sql, a)`، JDBC `prepareStatement` + `setString(1, x)` + `executeQuery`/`ResultSet`، PDO `prepare` + `execute([..])`/`bindParam`، mysqli `bind_param`، ADO.NET `SqlCommand` + `Parameters.AddWithValue`، `db.prepare(sql).run(a)`، و`row.Scan(&x)` في Go. |
| **ORM** | Django وSQLAlchemy وPeewee وSQLModel، وActiveRecord، وMongoose وSequelize وPrisma وTypeORM، وJPA/Hibernate (`@Entity` مع setters/getters ومستودعات Spring Data بالاسم). الكتابة: `create`/`update`/المُنشئ/`obj.f = x`/`setF(x)`؛ القراءة: حقول الكائن المجلوب أو متغير الحلقة. |

ما يعود من قاعدة البيانات يحمل تلوّث الأعمدة فقط، لا تلوّث مفتاح البحث: `Msg.findById(req.params.id).who` ليس ملوّثًا إلا إن كتب
مستخدمٌ في `MSG.WHO`.

**أسماء الجداول الحقيقية**: يُحسب جدول كل صنف ORM كما يحسبه إطاره: `__tablename__` (SQLAlchemy)، و`Meta.db_table` أو
`<app>_<model>` الافتراضي (Django)، و`self.table_name` (Rails)، و`@Table(name=…)`/`@Entity("…")` (JPA/TypeORM)، ومجموعة
Mongoose في الوسيط الثالث، و`tableName` في Sequelize. ثم تُوحَّد كل الأسماء بصيغة قانونية (بلا مخطط، مفرد، وأسماء الأعمدة بلا
شرطات: `created_at` = `createdAt`)، فجدول `notes` في SQL الخام وصنف `Note` في ORM جدول واحد.

**الدوال الوسيطة العامة**: دالة تأخذ الجدول أو الصنف والبيانات كوسائط، مثل `save(table, data)` التي تبني
`INSERT INTO {table}`، أو `create(Model, **fields)`، أو `createRecord(Model, data)`، أو `fetch(table, id)`، تُكتشف تلقائيًا،
وتُنمذج الكتابة والقراءة عند كل استدعاء بالجدول والمفاتيح الفعلية. ومفاتيح قاموس حرفي ثابت لا تُعدّ مدخلات مستخدم،
أما مفاتيح `request.form` فتبقى ملوّثة.

**نصوص SQL غير الحرفية**: يُقيَّم نص الاستعلام قبل تحليله: الثوابت على مستوى المشروع، و`q += …` المتتابعة، و`format`
و`%` و`join` والقوالب النصية، ودوال المشروع التي تبني الاستعلام من وسائطها. واسم الجدول المقروء من الإعدادات يُحلّ من
ملفات المشروع: `.env` و`.ini`/`.cfg` و`.properties` و`.json` و`.yaml` و`.toml`، عبر `os.getenv` و`os.environ` و`process.env`
و`settings.X` و`config["a"]["b"]` و`ENV[...]` و`System.getenv` و`@Value("${…}")` في Spring.
وتُقرأ متغيرات البيئة من ملفات النشر أيضًا: `Dockerfile` و`docker-compose` وKubernetes وHelm وGitHub Actions و`app.json`.
والقيمة المعرّفة في ملفات المشروع إعدادٌ يتحكم به المشغّل فلا تُعامل كمدخل مستخدم، أما المتغير غير المعرّف فيبقى مصدرًا.

**جدول يُحدَّد وقت التشغيل**: حين لا يمكن معرفة الجدول من الملفات أصلًا (اسمه يُقرأ من القاعدة نفسها أو من خدمة خارجية)،
يُربط الحفظ بالقراءة عبر اسم العمود: كتابة المستخدم في العمود `COMMENT` لجدول مجهول تجعل قراءة `COMMENT` مصدرًا محتملًا.
تظهر هذه النتائج بخطورة أقل درجة وبوصف صريح «الجدول يُحدَّد وقت التشغيل (الربط باسم العمود)».

### VQL — لغة استعلام فوق قاعدة بيانات البرنامج

على نهج `from … where … select` في CodeQL، تبني الأداة **قاعدة بيانات علاقية** للبرنامج (الاستدعاءات، الدوال،
الأصناف، الإسنادات، السلاسل، الاستيرادات، المُزخرِفات، السمات، **وتدفقات** محرّك التلوّث) وتشغّل عليها استعلامات
تصريحية. عشرة استعلامات مدمجة في `vulnscan/queries/` (منها: تعطيل التحقق من TLS، `yaml.load` بلا Loader، JWT ضعيف،
CORS بنجمة، نقطة دخول بلا مصادقة، عشوائية غير مشفّرة لسر، SQL مُركّب نصيًا)، وتضيف استعلاماتك بـ `--query DIR`:

```
// @id vql/tls-verify-disabled
// @name TLS certificate verification disabled
// @severity high
// @cwe CWE-295
// @advice فعّل التحقق من الشهادة.
from call c
where c.name matches "^(requests|httpx)\." and c.kwargs contains "verify=False"
select c, "TLS verification disabled in " + c.name
```

- **العلاقات**: `call` (name, func, receiver, args, arg0..arg3, kwargs, in_func, in_class…)، `func` (name, qual,
  decorators, is_entry, is_method…)، `class`، `assign` (target, value)، `string`، `import`، `decorator`، `attr`،
  و`flow` (rule, severity, source, callee, interprocedural, hops, sink_file, sink_line) لنتائج تدفق البيانات.
- **المعاملات**: `=` `!=` `<` `>` `<=` `>=` `matches` (regex) `contains` `in (…)` `and` `or` `not` والأقواس،
  وربط عدة علاقات في `from` بشروط مساواة، و`+` لتركيب الرسالة.
- `vulnscan --list-rules .` يعرض الاستعلامات مع القواعد، وتظهر نتائجها بمصدر `vql`.

- **مسندات يعرّفها المستخدم مع استدعاء ذاتي** (Datalog): `predicate` بعدة فقرات تفصلها `or`، ومتغيرات حرّة
  `value x` تُربط بالضمّ على صفوف المسند، وتقييم تصاعدي حتى نقطة الثبات، فتُكتب الإغلاقات المتعدية مباشرة:

```
predicate calls(f, g)   { from call c where c.in_func = f and c.func = g }
predicate reaches(f, g) { calls(f, g) or from value h where calls(f, h) and reaches(h, g) }
from func e where e.is_entry and reaches(e.name, "system") select e, "يصل إلى أمر shell"
```

  والاستعلام المدمج `vql/entry-reaches-shell` يستخدمها لرصد نقاط الدخول التي تصل إلى أوامر shell عبر مخطط
  الاستدعاءات.

بصدق: VQL تدعم الآن الأصناف (بمسند مميِّز ومسندات أعضاء وجوالب) والمسندات الذاتية والتجميعات (count/strictcount/sum/max/min/avg وexists/any)؛ تبقى مجموعة عملية واسعة من QL دون نظام الوحدات/الاستيراد والأنواع المَعلَمة والمكتبة المعيارية الكاملة.

### فحص تطبيقات الويب وصفحاتها (الزحف وبصمة المنصّات)

لفحص تطبيق ويب متعدد الصفحات مثل بوابة جامعة أو نظام **Moodle** أو تطبيق **Oracle APEX**، أضِف `--crawl`:
تتبع الأداة روابط الصفحات من **النطاق نفسه** زحفًا بالعرض (BFS) وتفحص كل صفحة بالفحوص السلبية.

```bash
vulnscan https://lms.jamiah.example --authorized --crawl --deep
```

- حدود الزحف: `--max-pages` (الافتراضي 20) و`--max-depth` (الافتراضي 2). لا تُتبع روابط الخروج/الحذف
  (logout، delete…) ولا الروابط الخارجة عن النطاق، ولا تُرسَل أي بيانات.
- **بصمة المنصّة**: تتعرّف الأداة تلقائيًا على Moodle وOracle APEX وWordPress وJoomla وDrupal وphpMyAdmin
  وLaravel من الصفحة والترويسات، وتنبّه إذا كان الإصدار قديمًا، وتذكّر بتحديث الإضافات والقوالب. ومع `--deep`
  تفحص مسارات الإدارة والدخول وملفات الإعداد الشائعة لكل منصّة (مثل `/login/index.php` و`/wp-login.php`
  و`/administrator/`).

> ⚠️ الزحف وفحص الويب يتطلبان `--authorized`. افحص فقط الأنظمة التي تملكها أو لديك تصريح كتابي بفحصها —
> فحص بوابة جامعة أو أي نظام لا تملكه دون إذن قد يكون مخالفًا للقانون.

### فك تجميع APK / JAR / AAR / DEX (jadx)

إذا كان [jadx](https://github.com/skylot/jadx) مثبّتًا (يحتاج Java 11+)، تُفكّ تجميع الحزم الثنائية تلقائيًا
إلى كود Java مع فك ترميز `AndroidManifest.xml` والموارد، وتُطبَّق عليها كل القواعد (تنفيذ الأوامر، الأسرار،
التشفير الضعيف، WebView، cleartext…). تظهر هذه النتائج بمسار `app.apk!decompiled/…` وبعلامة `jadx`.

- مكتبات الطرف الثالث الشائعة (androidx، kotlin، okhttp، firebase…) تُستبعد افتراضيًا لتقليل الضجيج؛
  فعّل فحصها بـ `--jadx-include-libs` أو من الإعدادات.
- بدون jadx تُفحص الملفات النصية داخل الحزمة فقط ويظهر تنبيه بذلك في التقرير.
- خيارات: `--no-jadx`، `--jadx-timeout SEC` (الافتراضي 600).

التثبيت: نزّل `jadx-x.y.z.zip` من صفحة الإصدارات وأضف مجلد `bin` إلى PATH، أو:
`brew install jadx` (macOS) · `scoop install jadx` / `choco install jadx` (Windows) · `sudo apt install jadx` (Debian/Ubuntu).

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

## التثبيت بسطر واحد (مع التحقق من SHA-256)

```bash
# macOS ولينكس
curl -fsSL https://abdulrahmanahmedelabed-prog.github.io/vulnscan/install.sh | sh
# Homebrew
brew tap kashif/vulnscan https://github.com/abdulrahmanahmedelabed-prog/vulnscan && brew install kashif
```

```powershell
# ويندوز
irm https://abdulrahmanahmedelabed-prog.github.io/vulnscan/install.ps1 | iex
```

تنزّل الطرق الثلاث النسخة الرسمية وتطابقها مع `SHA256SUMS.txt` قبل التثبيت، ولأنها تنزّل بـ curl فلا يضع macOS علامة
الحجر على الملف فلا يمنعه Gatekeeper.

## داخل محرر الكود وطلبات الدمج

- **محرّرات الكود:** `vulnscan lsp` خادم لغة (LSP) يضع خطًا تحت الثغرات أثناء الكتابة مع مسار تدفق البيانات وطريقة
  الإصلاح وإصلاحات سريعة (كتم نتيجة مُراجَعة أو إضافتها لخط الأساس). إضافة VS Code مرفقة بكل إصدار (`kashif-vscode.vsix`)،
  ويعمل الخادم نفسه مع JetBrains وNeovim وHelix وZed وSublime وEmacs (الإعداد في `editors/README.md`).
- **طلبات الدمج:** إجراء GitHub يعلّق على الأسطر المتغيّرة فقط ويحدّث تعليق ملخّص واحد، و`--diff-base origin/main` لفحص ما
  أضافه الفرع فقط، وتقارير GitLab (`-f gitlab-sast` و`-f codeclimate`)، وخطّاف pre-commit (الدليل في `docs/integrations.md`).

## نسخ جاهزة (بلا تثبيت Python)

نزّل الملف من [صفحة الإصدارات](https://github.com/abdulrahmanahmedelabed-prog/vulnscan/releases/latest):

| النظام | الملف |
|---|---|
| ويندوز x64 | `vulnscan-windows.exe` — انقر مرّتين لفتح الواجهة |
| لينكس x86-64 | `vulnscan-linux` — Ubuntu 22.04 وDebian 12 وRHEL 9 أو أحدث |
| macOS (Apple Silicon) | `vulnscan-macos-arm64` |
| macOS (Intel) | `vulnscan-macos-x86_64` |

على لينكس:

```bash
chmod +x vulnscan-linux
./vulnscan-linux                       # يفتح الواجهة
./vulnscan-linux ./project --fail-on high   # سطر الأوامر
```

على macOS: الملف غير موثَّق (notarized) من Apple، فأزل علامة الحجر مرة واحدة قبل أول تشغيل
(أو انقر على الملف بالزر الأيمن ← Open):

```bash
chmod +x vulnscan-macos-arm64
xattr -d com.apple.quarantine vulnscan-macos-arm64
./vulnscan-macos-arm64
```

كل إصدار يرفق `SHA256SUMS.txt` للتحقق من سلامة الملفات (`sha256sum -c SHA256SUMS.txt --ignore-missing`)،
وقائمة مكوّنات CycloneDX ‏(`vulnscan-sbom.cdx.json`)، ومصدر بناء SLSA موقَّعًا يُتحقَّق منه بـ:

```bash
gh attestation verify vulnscan-linux --repo abdulrahmanahmedelabed-prog/vulnscan
```

النسخة تُبنى آليًا عبر GitHub Actions بواسطة PyInstaller من ملف `vulnscan.spec`، وتتضمن الواجهة كاملة.
لبنائها محليًا: `pip install pyinstaller` ثم `pyinstaller --clean --noconfirm vulnscan.spec` (الناتج في `dist/`).

**صفحة الهبوط**: موقع تعريفي في `site/` يُنشر على GitHub Pages ويتضمن المقارنة مع الأدوات العالمية.

### التحديث

النسخ الجاهزة تحدّث نفسها: من الواجهة افتح **الإعدادات ← التحديثات** واضغط **حدّث الآن** ثم **أعد التشغيل الآن**،
وتظهر شارة «تحديث متاح» في الشريط الجانبي عند صدور إصدار أحدث. ومن سطر الأوامر:

```bash
vulnscan update            # تحقّق، ثم أكّد، ثم نزّل وتحقّق وثبّت
vulnscan update --check    # تحقّق فقط: رمز الخروج 10 عند توفّر تحديث و0 إن كنت على أحدث إصدار
vulnscan update --yes      # دون سؤال للتأكيد (للسكربتات)
```

يُنزَّل التحديث من GitHub فقط عبر HTTPS، ويُطابَق مع `SHA256SUMS.txt` المنشور مع الإصدار، ويُرفض إن لم يكن أحدث،
ويُجرَّب (`--version`) قبل أن يحلّ محلّ البرنامج دفعة واحدة؛ وتبقى النسخة السابقة باسم `<الاسم>.old` حتى التشغيل
القادم، وأي فشل يعيدها كما كانت. على macOS تُعرض النسخة الأصلية لـ Apple Silicon على نسخة Intel العاملة عبر Rosetta.
إن لم يكن مجلد البرنامج قابلًا للكتابة (مثل `/usr/local/bin`) فشغّل `sudo vulnscan update`. أما تثبيت pip أو الكود
المصدري فلا يُعدَّل أبدًا: تعرض الواجهة و`vulnscan update` الأمر المناسب بدلًا من ذلك. يسأل التحقق `api.github.com`
عن أحدث إصدار مرة كل 6 ساعات على الأكثر ولا يرسل شيئًا عن الكود؛ ويمكن إيقافه من خيار
**التحقق من التحديثات تلقائيًا** في الإعدادات.

## التشغيل بنقرة واحدة

بعد تنزيل المشروع وفكّ ضغطه، وتثبيت [Python 3](https://www.python.org/downloads/) (على ويندوز فعّل خيار **Add Python to PATH**):

| النظام | الملف |
|---|---|
| ويندوز | انقر مرّتين على **`run.bat`** |
| macOS | انقر مرّتين على **`run.command`** |
| لينكس | شغّل **`./run.sh`** |

يفتح المتصفح تلقائيًا على الواجهة. اترك النافذة مفتوحة، وللإيقاف اضغط `Ctrl+C`.

## الواجهة الرسومية

```bash
vulnscan ui
```

يفتح المتصفح على `http://127.0.0.1:8765` (الخادم يستمع على هذا الجهاز فقط ولا يُعرَّض للشبكة):

- **لوحة التحكم**: بطاقات العدّ لكل خطورة، مخطط دائري للتوزيع، اتجاه النتائج عبر الفحوصات الأخيرة،
  أكثر الثغرات تكرارًا، أكثر الملفات تأثرًا، وآخر الفحوصات.
- **فحص جديد**: مسار مجلد/ملف/أرشيف على الجهاز، أو **رفع** (سحب وإفلات) أي برنامج مضغوط
  (zip / apk / jar / aar / war / whl / ipa / tar.gz) أو أي عدد من الملفات أو مجلد كامل من المتصفح،
  أو عنوان ويب مع إقرار الصلاحية. تُحذف الملفات المرفوعة بعد الفحص.
- **النتائج**: مرتبة من الأعلى خطورة إلى الأقل، مع فلاتر بالخطورة والمصدر وبحث نصي، وبطاقة لكل نتيجة
  تُفتح لعرض المقتطف وCWE وطريقة الإصلاح، وتنزيل Markdown / JSON / HTML.
- **التقارير**: سجل الفحوصات، تنزيل التقارير، و**مقارنة فحصين** لمعرفة ما أُصلح وما استجد.
- **القواعد**: استعراض كل القواعد المدمجة مع البحث.
- **الإعدادات**: أدنى خطورة، الاستثناءات، القواعد المتجاهَلة، OSV، الأدوات الخارجية، العناوين المصرَّح بها.
- عربي/إنجليزي، فاتح/داكن/تلقائي، ومتجاوب مع شاشات الجوال.

تُحفظ البيانات في `~/.vulnscan` (أو المجلد في `VULNSCAN_HOME`). خيارات: `--port`، `--no-browser`.

## الاستخدام من سطر الأوامر

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

# SARIF لـ GitHub Code Scanning وVS Code
vulnscan . -f sarif -o vulnscan.sarif

# تبنّي الأداة على كود قائم: احفظ الموجود اليوم، ثم اعرض الجديد فقط
vulnscan . --write-baseline .vulnscan-baseline.json
vulnscan . --baseline .vulnscan-baseline.json --fail-on high
```

### التكامل مع GitHub Code Scanning (SARIF)

```yaml
permissions:
  security-events: write   # يلزم لرفع SARIF
# ...
- run: pip install git+https://github.com/abdulrahmanahmedelabed-prog/vulnscan && vulnscan . --no-deps -f sarif -o vulnscan.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: vulnscan.sarif
```

تظهر النتائج في تبويب Security ومباشرة على أسطر طلبات الدمج، مع درجة خطورة رقمية وCWE ومسار تدفق البيانات
(من المصدر إلى نقطة الخطر). كل نتيجة تحمل بصمة ثابتة لا تتغير بتحريك السطر أو إعادة تنسيقه، فلا تتكرر الإنذارات.

### خط الأساس (Baseline)

على كود قائم فيه مئات النتائج القديمة، احفظ بصماتها مرة واحدة بـ `--write-baseline` واحفظ الملف في المستودع
(لا يحوي كودًا، بصمات فقط). بعدها `--baseline` يكتم المعروف ويعرض **الجديد فقط**، و`--fail-on` يُفشل البناء
على الجديد وحده. البصمة = القاعدة + الملف + المقتطف بلا مسافات، فتصمد أمام إزاحة الأسطر وإعادة التنسيق.

### كشف الأسرار

أنماط مزوّدين محددة (AWS وGitHub وSlack وStripe وGoogle وSendGrid وTwilio وMailgun وnpm وPyPI وDigitalOcean
وShopify وSquare وFacebook وTelegram، وروابط Webhook، ومفاتيح حساب خدمة GCP، ومفاتيح Azure Storage)،
إضافة إلى **كشف بالعشوائية (إنتروبيا شانون)** على نهج gitleaks وtrufflehog يلتقط مفاتيح مزوّدين لا نمط لهم،
مع تجاهل التجزئات السداسية وقيم الأمثلة وبيانات base64 للصور وتجزئات integrity.

### الخيارات

| الخيار | الوصف |
|---|---|
| `-f console\|markdown\|json\|html\|sarif` | صيغة التقرير (sarif لـ GitHub Code Scanning وVS Code) |
| `--baseline FILE` / `--write-baseline FILE` | اعرض الجديد فقط مقارنة بخط أساس / احفظ خط الأساس |
| `-o FILE` | كتابة التقرير إلى ملف |
| `--all-formats PREFIX` | كتابة `PREFIX.md` و `PREFIX.json` و `PREFIX.html` و `PREFIX.sarif` |
| `--min-severity LEVEL` | عرض هذه الخطورة فما فوق |
| `--fail-on LEVEL` | رمز خروج 1 عند وجود نتيجة بهذه الخطورة أو أعلى |
| `--exclude GLOB` | استثناء مسارات (يُكرَّر) |
| `--ignore-rule ID` | تجاهل قاعدة (يُكرَّر) |
| `--no-deps` / `--no-external` | تعطيل OSV / الأدوات الخارجية |
| `--no-jadx` / `--jadx-timeout SEC` / `--jadx-include-libs` | التحكم في فك التجميع عبر jadx |
| `--authorized` | إقرار بالصلاحية (إلزامي لعناوين الويب) |
| `--deep` | فحص ويب أعمق (تحليل الصفحة ومسارات مكشوفة شائعة) |
| `--crawl` / `--max-pages` / `--max-depth` | زحف على صفحات الموقع وفحصها (لتطبيقات مثل Moodle وAPEX) |

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

## الدقة: OWASP Benchmark

نقيس كاشِف على مجموعتي OWASP Benchmark الرسميتين بمقياس OWASP نفسه (متوسط معدّل الإيجابيات الصحيحة ناقص معدّل
الإيجابيات الكاذبة لكل فئة): **Python ‏74.0%** (1,230 حالة) و**Java ‏76.3%**
(2,740 حالة). تُفحص كل مجموعة كاملة كتطبيق واحد بالملف الافتراضي، ولا يحوي المحرّك أي اسم أو مسار أو نتيجة من
ملفات الاختبار. الجدول الكامل لكل فئة في القسم الإنجليزي أعلاه وفي صفحة الهبوط، وتعيد إنتاجه بأمر واحد:

```bash
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava && python bench/score_owasp.py BenchmarkJava
```

## مقارنة مع الأدوات العالمية

| | **vulnscan** | Semgrep | SonarQube | Snyk Code | GitHub CodeQL | Bandit | Trivy |
|---|---|---|---|---|---|---|---|
| نوع التحليل | أنماط + تدفق بيانات مدرك للأنواع عبر الملفات مع points-to حسّاس للسياق (k=2) وحسّاس للتدفق (12 لغة) + نماذج كبيانات + VQL بأصناف ومسندات ذاتية وتجميعات | أنماط دلالية + تتبع بيانات (Pro) | تحليل دلالي عميق | تحليل دلالي + تعلّم آلي | تحليل تدفق بيانات بلغة استعلام | AST لـ Python | إعدادات + اعتماديات + حاويات |
| اللغات | 15+ أنماط · تدفق بيانات لـ 12 لغة | 30+ | 30+ | 15+ | 10+ | Python فقط | — (لا كود) |
| كشف الأسرار | ✅ | محدود | ✅ (نسخ مدفوعة) | ✅ | ✅ | ❌ | ✅ |
| ثغرات الاعتماديات (CVE) | ✅ عبر OSV.dev | ✅ (Supply Chain) | محدود | ✅ قوي | ✅ Dependabot | ❌ | ✅ قوي |
| فحص أرشيف / APK / JAR | ✅ + فك تجميع عبر jadx | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (صور وملفات) |
| فحص ويب سلبي (ترويسات/CSP/TLS/شهادة/مسارات مكشوفة) | ✅ | ❌ | ❌ | محدود (SaaS) | ❌ | ❌ | ❌ |
| واجهة رسومية محلية | ✅ بلا خادم خارجي | ❌ (SaaS) | ✅ (تحتاج خادم وقاعدة بيانات) | SaaS | على GitHub | ❌ | ❌ |
| التقرير مرتّب حسب الخطورة | ✅ أساسًا | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| مخرجات SARIF وخط أساس (الجديد فقط) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (SARIF) | ✅ |
| مقارنة فحصين (ما أُصلح/ما استجد) | ✅ | في SaaS | ✅ | ✅ | ✅ | ❌ | ❌ |
| يعمل دون إنترنت | ✅ (عدا OSV) | ✅ محليًا | ✅ | ❌ | ✅ CLI | ✅ | ✅ (بعد تنزيل DB) |
| الاعتماديات | **صفر** (Python فقط) | ثنائي + قواعد | Java + DB | حساب Snyk | CodeQL CLI | pip | ثنائي Go |
| العربية | ✅ عناوين وإصلاحات بالعربية | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| السعر | مجاني (MIT) | مجاني/مدفوع | Community/مدفوع | مجاني محدود/مدفوع | مجاني للمفتوح | مجاني | مجاني |

**أين يتفوق vulnscan؟** خفيف جدًا وبلا اعتماديات، يُغطي عدة لغات وملفات الإعداد والحاويات وCI والموبايل
في أداة واحدة، يقبل الأرشيفات وAPK مباشرة، واجهته وتقاريره بالعربية، ويدمج تلقائيًا نتائج Semgrep وBandit
وgitleaks وnpm audit إن وُجدت فيصبح لوحة واحدة فوقها.

**أين تتفوق الأدوات العالمية؟** CodeQL وSemgrep Pro وSonarQube وSnyk تُجري **تحليل تدفق بيانات** حقيقيًا
(تتبع المدخلات من المصدر إلى الاستخدام الخطر) فتكشف ثغرات لا تظهر بالأنماط وتُقلّل الإنذارات الكاذبة،
ولديها آلاف القواعد وتكاملات IDE وPR. لذلك يُنصح بتشغيل vulnscan كطبقة أولى سريعة، وتثبيت `semgrep`
بجانبه ليدمج نتائجه تلقائيًا عند الحاجة إلى عمق أكبر.

## التطوير

```bash
pip install -e .[dev]
python -m pytest -q
```

البنية: `scanner.py` (المشي على الملفات والأرشيفات) · `rules.py` (القواعد) · `deps.py` (OSV) · `web.py` (الفحص السلبي)
· `external.py` (الأدوات الخارجية) · `report.py` (التقارير) · `server.py` + `ui/` (الواجهة) · `store.py` (الإعدادات والسجل) · `cli.py`.

## حدود الأداة

- الفحص الثابت بالقواعد يكشف الأنماط الشائعة ولا يغني عن مراجعة بشرية أو اختبار اختراق.
- قد تظهر إنذارات كاذبة؛ استخدم `--ignore-rule` أو كتم السطر بعد التحقق.
- غير منمذج بعد: التحقق الذي تجريه مكتبات النماذج (مثل `validate_on_submit()` في WTForms)، والاستدعاء عبر الانعكاس
  (reflection) وأسماء الدوال النصية، والقيم التي تمرّ عبر ملفات أو قواعد بيانات خارج الكود المفحوص.
- بدون jadx تُفحص محتويات APK/JAR النصية فقط؛ ومع jadx يُفحص الكود المفكوك وهو كود مُعاد توليده قد يختلف عن المصدر الأصلي.
- فحص الويب سلبي بالكامل (طلب واحد) ولا يُجري أي اختبار نشط.

## الرخصة

MIT
