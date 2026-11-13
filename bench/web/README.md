# Kashif passive web corpus, scorer and ZAP comparison

This folder measures how accurate Kashif's passive web scanner is (spec §5.2–§5.5). It holds 380 labelled
cases that run offline on `127.0.0.1`. Kashif scans every case through its command line. The results are scored per
rule and gated in CI. The same corpus also runs through OWASP ZAP's passive scanner as a baseline.

| File | What it is |
|---|---|
| `corpus.py` | The cases (single source of truth), the local HTTP/HTTPS servers, the resolver-hook maps and a tiny forward proxy |
| `tls_servers.py` | Test PKI made at run time with the `openssl` CLI, server TLS contexts and the TLS profiles |
| `labels.json` | Generated from `corpus.py` (`python bench/web/corpus.py --write-labels`) and committed, so label changes show as diffs |
| `run_kashif.py` | Runs Kashif's CLI (`-f json`) once per case and records findings, coverage, grades and the traffic the servers saw |
| `score.py` | Per-rule TP/FP/FN/TN, precision, recall, F1, Youden J, confidence calibration, the defect table, the ZAP comparison and the gate |
| `min-score.json` | The gate: the §5.4 targets and per-rule floors that only go up (`--ratchet`) |
| `run_zap.py`, `zap-plan.yaml` | The ZAP 2.17.0 passive baseline (no active scan: a test checks the plan) |
| `results/1.0.2-legacy.json` | The recorded run of the 1.0.1/1.0.2 `web.py` (the two are identical) on the corpus |

## Quick start

```sh
python bench/web/corpus.py --list                         # the cases and their labels
python bench/web/run_kashif.py -o /tmp/web.json            # Kashif 1.1: every case, in parallel (about 2–4 minutes)
python bench/web/score.py /tmp/web.json --min-score bench/web/min-score.json \
       --baseline bench/web/results/1.0.2-legacy.json      # report + gate (exit 1 when below the floor)
python -m pytest tests/web/test_corpus_gate.py             # harness tests; the full gate runs once the 1.1 engine exists
```

Useful options of `run_kashif.py` are `--cases id,id`, `--groups C-CSP,C-HDR`, `--defects` (only the D1–D25 regression
cases), `--keep DIR` (keep every raw report and its stderr) and `--jobs N`. With `--legacy --root DIR` it runs a 1.0.x
copy of Kashif, as described below. To run the slow C-HOSTILE drip case, set `KASHIF_CORPUS_SLOW=1`.

## Case design

`case(id, group, labels, routes, …)` declares one case. In `labels`, `True` means the rule must fire and `False` marks a
trap where the rule must stay silent. Rules that a case does not name are not scored on it. Every rule with a
must-fire label also has a trap somewhere, and every true-positive case names its `twin`; a test enforces both.
Responses are declarative (`R(status, headers, body)`) or small functions of the request. Headers go on the wire
exactly as declared: duplicates, order, raw bytes, obsolete folding and 120 header lines are all possible, and no stray
`Server` or `Date` header is added. Tokens are filled in per response:

| Token | Value |
|---|---|
| `{NONCE}` | A fresh random nonce, the same everywhere in that response |
| `{RAND}` | A fresh 32-hex value, the same everywhere in that response |
| `{HTTPS}`, `{HTTP}`, `{HTTPS:alias}` | The origin of this case (or of its alias host) |
| `{THIRD}` | The case's third-party origin `https://<id>.kashif-third.test:<port>` (a different registrable domain) |
| `{SELF}` | The origin of the current request |
| `{HOST}` | The case's host name |
| `{EXPIRES}`, `{PAST}` | Dates 180 days ahead and 30 days back |

| Group | Cases | Content |
|---|---|---|
| C-RED | 19 | Plain-HTTP content, the first hop not going to HTTPS, a host change, downgrades (Location, meta refresh, script), 302 vs 308, a 12-hop loop, full-page redirects, Basic auth over http, D1 |
| C-HSTS | 19 | Missing HSTS, `max-age=0` (quoted too), short max-age, duplicates, folding, curly quotes, a leading zero, preload, meta, cross-host hops; traps for http-only, IP literal, invalid certificate and same-host redirect |
| C-CSP | 45 | Every CSP rule plus traps for D2 and D7–D11 (nonce + `unsafe-inline`, strict-dynamic, `*.host`, `default-src 'none'`, meta CSP, intersection, JSON API, `script-src-elem`), reporting, Trusted Types |
| C-HDR | 36 | XFO, XCTO, Referrer-Policy, Permissions/Feature-Policy, COOP/COEP/CORP, X-XSS-Protection, HPKP, Content-Type, charset, caching, Clear-Site-Data, the BREACH precondition |
| C-CORS | 12 | Reflection with and without credentials, `null`, `*` + credentials, Vary, `http:` origin, origin lists, `*` with a session |
| C-COOKIE | 33 | Secure/HttpOnly/SameSite by cookie class and HSTS, prefixes, Partitioned, Domain, lifetime, size, BIG-IP, JWT `alg:none`, cookies over http, `__Host-` prefix, D3–D5, D23 (crawled cookies) |
| C-HTML | 45 | Mixed content (active and passive), forms, SRI (missing, crossorigin, sha1, over http, mismatch), tabnabbing, malicious CDNs, miners, URL tokens, password forms (http, downgrade, off-site, autocomplete), CSRF tokens, inline handlers, Flash, D6, D22, D24 (grouping) |
| C-DOM | 11 | DOM XSS, open redirect and postMessage flows; traps for textContent, DOMPurify, a library file and a 2 MB bundle |
| C-DISC | 39 | Banners, debug headers, source maps, internal IPs, ETags, listings, debug pages, DB errors, raw PHP, secrets, serialized objects, ViewState, hashes, cards, HTML comments, error-page banners, EXIF GPS, D16, D18 |
| C-LIB | 15 | retire.js matches (URL, banner, bundle header), EOL frameworks and runtimes, CMS versions, D15 |
| C-TLS | 34 | Expired, not yet valid, self-signed, wrong host, chain problems, SHA-1, RSA-1024, ROCA, 400-day lifetime, must-staple, TLS 1.0, no TLS 1.3, raw-probe stub flights (incl. 1024-bit DHE, a higher version than offered, post-quantum groups), CT, certificate names, Mozilla intermediate conformance, two IPs, D17, D19–D21 |
| C-EXP | 26 | The deep list (with D12–D14 and the never-list check), security.txt, robots.txt, takeover, platform files, D25 (request gaps) |
| C-WAF | 6 | Cloudflare, Akamai and AWS WAF challenges, 429/503 with Retry-After, a WAF that only blocks the deep probes |
| C-GRADE | 12 | A+, A, B, C, F, `*`, `?`, grade monotonicity, and three Observatory fixtures |
| C-HOSTILE | 12 | Markup/ANSI in headers and titles, shell injection in Location, slow drip, 120 headers, gzip bomb, an unrequested `br` body, redirects to metadata/loopback/`file:`/`javascript:`, DNS rebinding, obs-fold (§0.6) |
| C-REVIEW | 16 | CN-only certificates, shared-cache session leaks, session tokens in pages, unpinned package CDNs, unregistered script hosts (WEB517 A/B/C), the resolver sanity guard, proxied scans, WEB318 |

Besides labels, a case can carry `expect`ations, which score.py checks: an exact or maximum `severity`, `confidence`,
`count`/`min_count` (grouping), `grade`, `grade_suffix`, `grade_at_least_case`, `observatory`, coverage `states`,
`max_elapsed`, `stderr_absent`, `json_contains`, `server_never` (paths that must never be requested), `min_gap` and
`entry_gap` (politeness), `max_requests`/`min_requests`, `output_safe` (HTML, Markdown and terminal escaping),
`curl_quoted`, `no_requests_on_ip2`, `max_rss_mb` and `exit`.

### Requirements, skips and platform notes

A case that cannot run on this machine is reported as `skipped` with the reason. It is never counted as passed:

* `tls`: there is no `openssl` CLI, so no https case can run (GitHub's Windows, macOS and Linux runners all have one).
* `tls10`: the local OpenSSL refuses to serve or negotiate TLS 1.0, so `tls10-accepted` cannot run.
* `stub`: these cases need WP10's raw-probe stub `tests/web/tls_stub.py` (recorded server flights for SSLv3, RC4, TLS compression, no renegotiation_info and a timeout).
* `ip2`: `127.0.0.2` cannot be bound. This is the default on macOS, so WEB715 and the loopback-redirect check are skipped there.
* `roca`: there is no ROCA certificate fixture (`tests/data/web/certs/roca-leaf.{pem,key}`, from WP10).
* `fixture:retire-hash`: there is no exact library file whose SHA-1 is in retire.js (`tests/data/web/libs/*.js`, from WP9).
* `slow`: the drip case runs only with `KASHIF_CORPUS_SLOW=1`. The nightly workflow sets it.

## How Kashif reaches the corpus: test-only hooks (contract for WP1 and WP15)

The case hosts are `<id>.<group>.kashif.test`. Their aliases are `<id>-<alias>.<group>.kashif.test`, and each case's
third-party host is `<id>.kashif-third.test`. All of them are RFC 6761 reserved names. `run_kashif.py` sets these
variables for every case and starts Kashif with `python -m vulnscan` from the repository root:

| Variable | Meaning |
|---|---|
| `KASHIF_TEST_RESOLVE=1` | Enables the hooks. Without it, Kashif must ignore the two variables below (spec §5.2: "refused unless") |
| `KASHIF_TEST_RESOLVE_MAP` | Path of a JSON map that `ScanOptions._resolve` must use instead of the OS resolver (format below) |
| `KASHIF_TEST_CAFILE` | The corpus test root CA. The verified handshake trusts it, and certificates chaining to it count as *publicly trusted* (WEB702, WEB709) |

```json
{"version": 1, "case": "rev-unregistered-script",
 "hosts": {"rev-unregistered-script.review.kashif.test": {"status": "ok", "addresses": ["127.0.0.1"], "public": true},
           "cdn.kashif-gone.test": {"status": "nxdomain"},
           "exp-takeover.exp.kashif.test": {"status": "ok", "addresses": ["127.0.0.1"], "public": true,
                                            "canonical": "kashif-corpus-gone.github.io", "aliases": ["exp-takeover.exp.kashif.test"]},
           "hostile-dns-rebinding.hostile.kashif.test": {"status": "ok", "sequence": [["127.0.0.1"], ["10.13.37.1"]], "public": true}},
 "default": {"status": "ok", "addresses": ["127.0.0.1"], "public": true},
 "tls": {"cafile": "/tmp/…/root.pem", "publicly_trusted": true, "ct_required": false}}
```

* `status` is `ok`, `nxdomain`, `nodata` or `tempfail`. `canonical` and `aliases` feed the `gethostbyname_ex`
  emulation used by WEB901, where the canonical name sits at index 0. `sequence` returns successive answers, which
  tests the DNS pinning of §0.1. Names missing from `hosts` use `default`, so no corpus name ever leaves the machine.
* `public: true` marks the address as public for every address-category decision: the SSRF guard, the "loopback
  target → info" guards of WEB000, WEB050 and WEB103, and the private-network severity of WEB321. A redirect from such a
  target to `127.0.0.2` or `169.254.169.254` must therefore be refused.
* `tls.ct_required: false`: certificates from the test CA do not get WEB713, because no corpus certificate can carry
  real SCTs. Without this exception every https case would have a CT finding, and no fixture could reach the A+ grade.
  A case sets `ct_required=True` to declare the CA CT-bound (`tls-ct-missing`, the WEB713 true positive).
* The run also needs the 1.1 CLI options of §4.5: `--web-profile`, `--web-sensitivity`, `--delay`, `--timeout`,
  `--no-proxy`, `--crawl`, `--max-pages`, `--max-depth` and `--web-cookie-ignore`. For the JSON report, score.py reads
  `findings[].extra.confidence` and `extra.instances`, `web.grades.kashif.grade` (or `letter`, with `provisional` for
  the `*`), `web.grades.observatory.score` and `web.coverage`. Coverage is either `{rule_or_check: {"state": …}}` or a
  list of `{"check", "rules": [...], "state", "reason"}`.

Before any other case runs, a preflight case must reach the local server. If it does not, the hook is not active and
the run stops, because without the hook names like `kashif-corpus.dev` could resolve on the internet. The runner also
removes `HTTP(S)_PROXY`/`NO_PROXY` from the environment, except for `rev-proxied`. That case goes through the corpus'
own forward proxy on 127.0.0.1.

What the servers check on every request in 1.1 mode (§0.2, §5.7):

* Only GET is used. Any other method is answered with 405 and recorded as a violation.
* Only the allowed request headers are sent, with the honest `Kashif/` User-Agent.
* The CORS GET carries no cookies, and `standard` never requests a `/kashif-404-*` path.
* The request count stays within the profile budget (minimal 10, standard 45, deep 150, plus crawl pages).
* Requests to one host are at least the configured delay apart.

## Scoring (spec §5.3)

`run_kashif.py` scans each case separately, and each case has its own host, so every finding of a run belongs to its
case. Grouped findings therefore count once per case. For ZAP, which scans all cases in one session, findings are
attributed to cases by URL.

* Each label is scored as TP, FP, FN or TN.
* A label whose rule did not fire, on a case whose coverage marks the check `not_tested` or `inconclusive`, is
  scored *inconclusive*. That is never a TN.
* A crashed run scores its must-fire labels as FN and its traps as `error`.
* For each rule the scorer reports precision, recall, F1 and Youden J (TPR − FPR). Macro F1 over the rules with a
  must-fire label is the headline; micro averages are shown too.
* It also reports precision per confidence bucket (which must be monotone), the noise ratio (raw instances / grouped
  findings), findings per case, and the D1–D25 table (1.0.x baseline vs this run). `--diff PREV.json` lists
  regressions first.
* The gate (`--min-score`) fails on any §5.4 target, any per-rule floor, any unfixed defect, any failed case
  expectation (grades included), any traffic violation and any crashed run. `--ratchet` raises the floors to the
  current values, and only when the gate passes.

### Baseline: Kashif 1.0.1/1.0.2 (`results/1.0.2-legacy.json`)

The 1.0.x scanner has no resolver hook. It runs in *legacy* mode: one case at a time on `127.0.0.1`, with the test CA
trusted through `SSL_CERT_FILE`, and the 18 cases that need host names are skipped. Every D1–D25 case shows its defect
in this run (a test enforces this). The 1.0.1 and 1.0.2 `web.py` files are byte-identical, so one baseline covers both.
To re-record it from a pristine copy of the release:

```sh
git archive v1.0.2 vulnscan | tar -x -C /tmp/kashif-1.0.2
python bench/web/run_kashif.py --legacy --root /tmp/kashif-1.0.2 -o bench/web/results/1.0.2-legacy.json
python bench/web/score.py bench/web/results/1.0.2-legacy.json --baseline bench/web/results/1.0.2-legacy.json
```

### Grade fixtures

The A+, A, B, C, F, `*` and `?` fixtures and the monotonicity pair follow §3.4; phase D confirmed every letter against
the assembled engine (B and C were hand-derived; C now uses distribution banners so WEB800 stays tentative and cannot
cap the grade at F). The Observatory fixtures carry numbers recorded with the official `@mdn/mdn-http-observatory`
1.7.2 analyzer, never by hand: 140, 115 and 0 (`grade-obs-165` is 140 because the corpus host is in no preload list).
To reproduce them (Node 24+, no network once installed):

```sh
npm install --prefix /tmp/obs --ignore-scripts @mdn/mdn-http-observatory@1.7.2
echo '{}' > /tmp/obs/node_modules/@mdn/mdn-http-observatory/conf/hsts-preload.json
python bench/web/observatory_official.py --package /tmp/obs/node_modules/@mdn/mdn-http-observatory \
       --results <run_kashif.py --keep dir>
```

`observatory_official.py` records the fixture responses from the local servers, builds Observatory's `Requests`
object the way its retriever would (Node's header joining included) and calls the package's own `analyzeScan()`.
In phase D the same comparison over every simple corpus case (288 cases) agreed test by test, except where the
recorder cannot know Observatory's view (certificate verification); it found one real difference, repeated
Strict-Transport-Security fields, which transport.py now joins as Node does.

## ZAP comparison (spec §5.5)

```sh
# ZAP 2.17.0 cross-platform zip (sha256 94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0), Java 21
python bench/web/run_zap.py --zap /opt/ZAP_2.17.0 -o bench/web/results/zap-2.17.0.json
python bench/web/score.py /tmp/web.json --zap bench/web/results/zap-2.17.0.json
```

ZAP cannot use the resolver hook, so its corpus is served in *prefix* mode (`http(s)://127.0.0.1:<port>/_case/<id>/`).
The cases that need host names, DNS, TLS-only checks, a proxy, the deep profile or C-HOSTILE are excluded from the ZAP
column and listed in `excluded`. ZAP runs as `zap.sh -cmd -silent -dir <temp home> -autorun <plan>`. The plan has only
`passiveScan-config` (every installed passive rule at its default MEDIUM threshold, retire.js included), `requestor` (the
exact case URLs, plus a same-case redirect target and the crawl pages), `passiveScan-wait` and `report`
(traditional-json). `run_zap.py` refuses to run any plan that has an active-scan, spider, AJAX-spider or fuzz job, and a
test checks both the template and the generated plan. Alerts map to Kashif rules by alert id and alertRef (`ZAP_MAP`,
§5.5). The 10055-4 "wildcard" alert is split by the directives it names. The ZAP 2.17.0 zip has no pscanrulesBeta or
wappalyzer add-ons, so rules from those add-ons (90033, tech detection) only appear if you install them yourself first
(`zap.sh -cmd -addoninstall pscanrulesBeta -addoninstall wappalyzer`). With Docker:
`docker run --rm --network host -v "$PWD:/zap/wrk" ghcr.io/zaproxy/zaproxy:2.17.0 zap.sh -cmd -silent -autorun /zap/wrk/plan.yaml`,
using a plan from `run_zap.py --plan-only plan.yaml` while `corpus.py --serve --mode prefix` serves the corpus.

If ZAP or Java is missing, `run_zap.py` says so, writes `{"status": "skipped", "reason": …}` and exits 0, or 2 with
`--require`. The nightly `web-bench` workflow job downloads the checksum-pinned zip and runs the comparison.

**Claim policy.** The README and the site may say "more accurate than ZAP's passive scanner on the Kashif passive
corpus" only if two things hold. First, Kashif's F1 must be ≥ ZAP's on every mapped rule and its macro F1 strictly
higher; score.py prints `claim allowed: yes/no`. Second, the corpus, the labels and both result files must be published.
Rules that ZAP does not cover are scored, but listed separately and never used for a claim.

## Adding a case

1. Add `case(...)` in the right group of `corpus.py`. Give it a twin (TP ↔ trap) and a `note` explaining the decision.
2. Run `python bench/web/corpus.py --write-labels` and commit `labels.json` with the change.
3. Run `python -m pytest tests/web/test_corpus_gate.py`. It checks structure, twins, rule ids, the plan and the scorer.
4. Run `run_kashif.py --cases <id>` and check the result with `score.py`.
