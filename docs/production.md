# Kashif in production

This page is for teams that run Kashif (the `kashif` command; `vulnscan` still works as an alias) as part of their delivery pipeline: what is guaranteed not to
change under you (the stability contract), how long a version is supported, how to deploy it, and what to check when
upgrading from 0.x.

- [Stability contract](#stability-contract)
- [Support policy](#support-policy)
- [Deployment recipes](#deployment-recipes): [container](#container-image), [CI](#ci), [air-gapped](#air-gapped-use),
  [central dashboard](#central-dashboard), [scaling](#scaling-tips), [performance](#performance)
- [Verifying what you run](#verifying-what-you-run)
- [Upgrading from 0.x](#upgrading-from-0x)

## Stability contract

Kashif follows [Semantic Versioning 2.0.0](https://semver.org/) from 1.0.0 on. The version is `MAJOR.MINOR.PATCH`:

| Release | May contain | Safe to take automatically? |
|---|---|---|
| **PATCH** (1.2.3 to 1.2.4) | Bug fixes, security fixes, false-positive and false-negative fixes | Yes |
| **MINOR** (1.2 to 1.3) | New rules, languages, library models, flags, output fields, formats; deprecations | Yes; expect new findings (see below) |
| **MAJOR** (1.x to 2.0) | Removal or change of anything listed as stable | No; read the upgrade notes |

### Stable in 1.x

Everything in this table keeps working, with the same meaning, in every 1.x release. Additions are allowed
(a new flag, a new optional JSON field, a new rule); removals and changes of meaning are not.

| Surface | What is guaranteed |
|---|---|
| **Command line** | The `kashif` command (and its alias `vulnscan`, the pre-1.0 name) and its subcommands (`ui`, `lsp`, `mcp`, `update`, `export`, `compliance`, `history`, `triage`, `policy`, `surface`, `rules`), every documented flag and its meaning, and the defaults of flags that decide what is reported or whether the job fails (`--fail-on`, `--min-severity`, `--baseline`, `--diff-base`, `--exclude`, `--ignore-rule`). |
| **Exit codes** | `0` the scan completed and nothing reached `--fail-on`; `1` the scan completed and a reported finding has the `--fail-on` severity or higher, the policy gate failed (`kashif.yml` in the scanned folder, or `--policy`), or `--fail-on-sla` found an overdue finding; `2` the scan could not run (bad arguments, unreachable web target, `--diff-base` outside a git repository, a malformed policy or triage file). `kashif update --check` exits `10` when an update is available. A scan returns no other code. The other sub-commands use `0` (done / passed), `1` (their gate failed, e.g. `kashif policy check`, `kashif history` with findings) and `2` (usage or input error). |
| **Machine-readable output** | The schemas of `-f json`, `-f sarif` (SARIF 2.1.0), `-f gitlab-sast` and `-f codeclimate`: existing fields keep their names, types and meaning. New optional fields may appear, so parsers must ignore fields they do not know. |
| **Fingerprints** | A finding's fingerprint (SARIF `partialFingerprints["vulnscan/v1"]`, the `fp` of a baseline entry, the LSP diagnostic `data`) is computed the same way in every 1.x release: the same finding in the same code keeps its identity, so code-scanning alerts, baselines and triage decisions survive upgrades. |
| **Baseline files** | Files written by `--write-baseline` (schema `vulnscan-baseline/1`) are read by every 1.x release. |
| **Rule IDs** | A rule ID never changes its meaning and is never reused. A rule is renamed only together with an alias, so the old ID keeps working in `--ignore-rule`, suppression comments, baselines and policies for the rest of 1.x. A retired rule's ID stays reserved. |
| **Suppression comments** | `# nosec`, `vulnscan: ignore` (any comment syntax, on the flagged line), `# noqa: S###` and `vulnscan: ignore-file` (in the first lines of a file) keep suppressing what they suppress today. |
| **LSP settings** | Section `kashif`: `minSeverity`, `audit`, `exclude`, `baseline`, `language`, through `initializationOptions` or `workspace/didChangeConfiguration`. |
| **GitHub Action** | The inputs (`path`, `fail-on`, `min-severity`, `diff-base`, `baseline`, `language`, `comment-mode`, `upload-sarif`, `audit`, `token`, `python-version`), their defaults, and the outputs (`findings`, `sarif`). |
| **Custom content** | The format of model files passed to `--models` and of VQL queries passed to `--query`: files that load in 1.0 load in every 1.x release. |
| **Environment** | `VULNSCAN_LANG` (output language) and `VULNSCAN_HOME` (where the UI keeps its state). |
| **Container image** | The image name, the `kashif` entrypoint (with `vulnscan` also on the image's PATH), the `/src` working directory, the `/data` state directory and the non-root user ID 10001. |
| **Python** | 1.x runs on Python 3.10 and newer and needs nothing outside the standard library. |

### What may change in a minor release

A scanner that never finds anything new is not improving, so these are deliberately **not** frozen:

- **Findings.** New rules, new library models and better analysis report vulnerabilities that the previous version
  missed, and precision work removes false positives. A pipeline with `--fail-on` can therefore start failing after
  an upgrade without any change to your code. To take upgrades without surprise, gate on a
  [baseline](#adopting-on-an-existing-codebase) or on `--diff-base`, and review the new findings on your own
  schedule.
- **Default severities**, only with a notice in the changelog that names the rule, the old and the new severity.
  Severities are never changed in a patch release.
- **Human-readable output**: the console, Markdown and HTML reports, message wording, remediation text, and the
  English and Arabic translations. Do not parse them; use JSON or SARIF.
- **The web UI** and the JSON API behind it, which is private to the UI.
- **Performance and memory use**, in either direction, within reason; regressions are treated as bugs.
- **Anything marked experimental** in its `--help` text or in the documentation.
- **What the image contains** besides the scanner: the base image and its packages follow security updates.

### Deprecation

Something stable is removed only in a major release, and only after it was marked deprecated in the changelog and,
where it applies, printed a warning on standard error for at least one minor release and three months. Deprecated
behaviour keeps working until then.

## Support policy

| Version | Bug fixes | Security fixes |
|---|---|---|
| Latest 1.x minor | Yes | Yes |
| Previous 1.x minor | No; upgrade to the latest minor | Critical and high severity, for 6 months after the next minor was released |
| 0.x | No | No |

- Fixes are released as a patch release of the latest minor. Because of the contract above, upgrading within 1.x is
  the supported way to get them.
- A vulnerability **in Kashif itself** (for example code execution or a file written outside the target while
  scanning a hostile repository) is handled under [SECURITY.md](../SECURITY.md): private report, answer within
  7 days, a fix for critical issues within 30 days. A missed vulnerability or a false positive in your code is a
  normal bug report.
- Every release carries SHA-256 checksums, an SBOM and signed SLSA build provenance
  ([how to verify](#verifying-what-you-run)).

## Deployment recipes

Pick one way of installing and pin it:

| Way | Pin | Notes |
|---|---|---|
| GitHub Action | A full commit SHA of a release | Pull-request comments and SARIF upload included; see [integrations.md](integrations.md). |
| Container image | `:1.2.3` or the image digest | Nothing to install; includes Python and git. |
| pip | A release tag | Python 3.10+; no dependencies are downloaded. |
| Binary | The release version, checked against `SHA256SUMS.txt` | No Python needed; Windows, Linux, macOS. |

In CI, pass `--no-deps --no-external` unless you want them: `--no-deps` skips the dependency lookup on OSV.dev (the
only network request a source scan makes) and `--no-external` keeps the result independent of whichever other
scanners happen to be installed on the runner.

### Container image

```bash
# scan the current directory
docker run --rm -v "$PWD:/src" ghcr.io/abdulrahmanahmedelabed-prog/kashif:1 .

# the same, locked down: read-only root filesystem, no capabilities, no network, the code mounted read-only
docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --network none \
  -v "$PWD:/src:ro" ghcr.io/abdulrahmanahmedelabed-prog/kashif:1 . --no-deps --no-external --fail-on high

# write a report into the mounted directory: run as yourself so that the file is yours
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" \
  ghcr.io/abdulrahmanahmedelabed-prog/kashif:1 . --no-deps --no-external -f sarif -o kashif.sarif
```

- **Tags.** `:1` follows the latest 1.x release, `:1.2` the latest patch of 1.2, `:1.2.3` and `:v1.2.3` are one
  release, `:latest` is the newest release. For reproducible pipelines pin `:1.2.3` or, better, the digest
  (`kashif@sha256:...`).
- **Platforms.** `linux/amd64` and `linux/arm64`.
- **User.** The image runs as UID/GID 10001, not root. Reading a mounted repository needs no change; to write
  into it (`-o`, `--write-baseline`, `--fix`) either add `--user "$(id -u):$(id -g)"` or write to standard output
  and redirect on the host (`-f sarif > kashif.sarif`).
- **Read-only root filesystem.** Supported. The scanner needs a writable `/tmp` only to unpack archives and APK/JAR
  targets (`--tmpfs /tmp`); the UI keeps its state in `/data` (`VULNSCAN_HOME`), which is a volume.
- **Git.** The image contains git for `--diff-base`, `--diff-staged` and `--fix`. Mount the whole work tree
  including `.git`, and fetch enough history for the merge-base (`fetch-depth: 0` or `GIT_DEPTH: 0`).
- **Not included:** jadx (APK/JAR targets are then scanned as text) and the optional external scanners.

**The web UI in a container.** The UI is a single-user, local tool: it has no login and listens on the loopback
interface only, and it refuses requests whose `Host` header is not `localhost` or `127.0.0.1`. A port published
with `-p` reaches the container's network interface, not its loopback, so `-p 8765:8765` alone does **not** expose
the UI. Share the host's network namespace instead (Linux, and Docker Desktop with host networking enabled):

```bash
docker run --rm --network host --read-only --tmpfs /tmp \
  -v kashif-data:/data -v "$PWD:/src:ro" \
  ghcr.io/abdulrahmanahmedelabed-prog/kashif:1 ui --no-browser --port 8765
# then open http://127.0.0.1:8765/
```

With `--network host` the UI listens on the host's loopback only, exactly as the binary does, and nothing is
reachable from other machines. `kashif-data` keeps the scan history and the settings between runs.

### CI

**GitHub Actions, with the action** (pull-request comments, SARIF, only the findings the change introduced):

```yaml
permissions:
  contents: read
jobs:
  kashif:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: abdulrahmanahmedelabed-prog/vulnscan@<commit SHA of a 1.x release>
        with:
          fail-on: high
```

**Any CI, with the container image** (GitLab CI shown; the job image's entrypoint is overridden so that the runner
can start a shell):

```yaml
kashif:
  image:
    name: ghcr.io/abdulrahmanahmedelabed-prog/kashif:1
    entrypoint: [""]
  variables:
    GIT_DEPTH: 0
  script:
    - kashif . --no-deps --no-external --lang en -f gitlab-sast -o gl-sast-report.json
        --diff-base "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" --fail-on high
  artifacts:
    when: always
    reports:
      sast: gl-sast-report.json
```

**Any CI, with pip** (Jenkins, Azure Pipelines, Bitbucket, a shell script):

```bash
python3 -m venv .kashif && . .kashif/bin/activate
pip install "git+https://github.com/abdulrahmanahmedelabed-prog/vulnscan@v1.0.1"   # pin a release tag
kashif . --no-deps --no-external --lang en -f sarif -o kashif.sarif --fail-on high
```

#### Adopting on an existing codebase

Record what exists today once, commit the file, and fail the build only on what is new:

```bash
kashif . --no-deps --no-external --write-baseline .vulnscan-baseline.json   # once; commit the file
kashif . --no-deps --no-external --baseline .vulnscan-baseline.json --fail-on high
```

The baseline stores fingerprints, rule IDs and file names, never code. It stays valid across 1.x upgrades, and
findings that an upgrade adds are reported as new, which is the review point you want.

### Air-gapped use

A source scan needs no network at all with `--no-deps` (and never sends your code anywhere in any mode). The only
outbound requests Kashif can make are:

| Request | When | Turn off with |
|---|---|---|
| `api.osv.dev` (dependency vulnerabilities; sends package names and versions) | A scan without `--no-deps` | `--no-deps` |
| `api.github.com` (is there a newer release?) | The UI, at most every 6 hours; `kashif update` | Settings > Updates in the UI; do not run `kashif update` |
| The target itself | Only when the target is an `http(s)://` URL with `--authorized` | Scan a path |

To bring Kashif into an isolated network:

```bash
# on a connected machine
docker pull ghcr.io/abdulrahmanahmedelabed-prog/kashif:1.0.1
docker save ghcr.io/abdulrahmanahmedelabed-prog/kashif:1.0.1 -o kashif-1.0.1.tar
sha256sum kashif-1.0.1.tar > kashif-1.0.1.tar.sha256

# on the isolated machine
sha256sum -c kashif-1.0.1.tar.sha256 && docker load -i kashif-1.0.1.tar
docker run --rm --network none -v "$PWD:/src:ro" ghcr.io/abdulrahmanahmedelabed-prog/kashif:1.0.1 . --no-deps --no-external
```

Without Docker, carry the release binary and `SHA256SUMS.txt`, or a wheel built with
`pip wheel --no-deps git+https://github.com/abdulrahmanahmedelabed-prog/vulnscan@v1.0.1` and installed with
`pip install --no-index vulnscan-*.whl`; there are no dependencies to mirror. Upgrade the same way: the in-app
updater needs GitHub and is not used in an isolated network.

### Central dashboard

The UI keeps projects, scan history and trends, which makes it useful as a team dashboard. It was built as a
single-user local tool, so **it has no authentication of its own and must never be exposed directly**: whoever can
reach it can read every result and start a scan of any path its account can read. Put it behind a reverse proxy
that authenticates every request.

1. **Run the UI on the server under its own unprivileged account**, with only the code it should scan mounted
   read-only:

   ```bash
   docker run -d --name kashif --restart unless-stopped --network host \
     --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
     -v kashif-data:/data -v /srv/repos:/src:ro \
     ghcr.io/abdulrahmanahmedelabed-prog/kashif:1 ui --no-browser --port 8765
   ```

   It listens on `127.0.0.1:8765` of the server only. Keep it that way: the proxy on the same host is the only
   door.

2. **Terminate TLS and authenticate in the proxy** (single sign-on through OAuth2 Proxy or your identity
   provider, mutual TLS, or at least HTTP basic authentication over TLS). The UI accepts only requests that name it
   as `127.0.0.1` or `localhost` and whose `Origin` matches, so the proxy must rewrite `Host` and, having done the
   cross-site check itself, drop `Origin` and `Referer`. nginx:

   ```nginx
   server {
       listen 443 ssl;
       server_name kashif.example.com;
       # ssl_certificate ...; ssl_certificate_key ...;

       auth_request /oauth2/auth;                 # or: auth_basic "Kashif"; auth_basic_user_file ...;

       location / {
           # the UI has no CSRF token of its own behind a proxy: refuse cross-site writes here
           set $cross_site 0;
           if ($http_origin !~ "^(|https://kashif\.example\.com)$") { set $cross_site 1; }
           if ($http_sec_fetch_site ~ "^(cross-site|same-site)$")   { set $cross_site 1; }
           if ($cross_site) { return 403; }

           proxy_pass http://127.0.0.1:8765;
           proxy_set_header Host 127.0.0.1:8765;
           proxy_set_header Origin "";
           proxy_set_header Referer "";
           client_max_body_size 512m;             # archive uploads (the UI's own limit)
           proxy_read_timeout 600s;               # long scans
       }
   }
   ```

3. **Know what the dashboard does not give you:** there are no user accounts, roles or per-project permissions;
   everyone the proxy lets in sees everything and can change the settings. Give teams that must not see each
   other's results separate instances (a container and a `/data` volume each). Turn off automatic update checks in
   Settings, upgrade by replacing the image, and back up the `/data` volume.

4. **Feed it from CI** if you prefer pipelines to do the scanning: keep CI reports (`-f json`, `-f sarif`) as build
   artifacts, and use the dashboard for the repositories mounted on the server.

### Scaling tips

- **Scan the whole project, report the change.** `--diff-base` (and the action) still analyses everything, so
  cross-file data flow stays complete, but reports only what the change introduced. Do not scan only the changed
  files: flows that cross files would be lost.
- **Exclude what you do not ship**: vendored code, build output, generated code, minified bundles, fixtures
  (`--exclude "vendor/*" --exclude "dist/*" --exclude "node_modules/*"`). This is the largest single saving in both
  time and noise.
- **Monorepos:** run one job per service directory in parallel (a CI matrix) instead of one scan of the root.
  Data flow is tracked within one scan, so split along boundaries that code does not call across. Keep one baseline
  per job.
- **One scan is one process.** Parallelism comes from running several scans; give each job one CPU and the memory
  the [performance](#performance) table indicates.
- **Keep jobs deterministic:** pin the version, pass `--no-deps --no-external`, and run dependency scanning
  (`--no-external` without `--no-deps`) as a separate scheduled job, because new advisories appear without any code
  change.
- **Nightly full scan, gated pull requests:** a scheduled full scan uploading SARIF keeps the dashboard and the
  Security tab complete, while pull requests are gated by `--diff-base --fail-on high`.
- **Large archives and APKs** are unpacked to the temporary directory; size it for the unpacked content
  (`--tmpfs /tmp:size=2g` in a read-only container). jadx decompilation has its own limit (`--jadx-timeout`).

### Performance

Measured on 12 November 2026 with the 1.0.0 release candidate on a shared Linux container with 4 vCPUs and 15 GB of
RAM, without the dependency lookup or external tools. "Jobs 1" rows ran through the library (`scan_path`, one
process); the command line uses one worker per CPU unless `--jobs` says otherwise. Lines are the lines of the project's source files (approximate).

| Codebase | Languages | Files | Lines of code | Wall time | Peak memory | Setting |
|---|---|---|---|---|---|---|
| Django | Python, HTML templates | 6,973 | ~558,000 | 311–411 s cold (load-dependent; 0.9: 594 s); 3.5 s warm | 3.0–3.5 GB (0.9: 4.5 GB) | `--jobs 3 --cache DIR` |
| SQLAlchemy | Python | 969 | ~1,030,000 | 343 s | 2.8 GB | jobs 1 |
| Next.js | JavaScript, TypeScript | 2,655 | ~1,160,000 | 123 s | 1.3 GB | jobs 1 |
| OWASP Juice Shop | TypeScript, JavaScript | 1,498 | ~113,000 | 47 s | 0.4 GB | jobs 1 |
| OWASP WebGoat | Java | 1,391 | ~99,000 | 23 s | 0.2 GB | jobs 1 |

A warm rescan with `--cache DIR` of a project that has not changed answers from the cache with identical findings.
After editing one file the whole-program analysis still runs, so the rescan is only 10–20% faster than a cold one.

Measure your own repository with `/usr/bin/time -v kashif . --no-deps --no-external -f json -o /dev/null`.

## Verifying what you run

```bash
# binaries: checksum and signed SLSA build provenance
sha256sum -c SHA256SUMS.txt --ignore-missing
gh attestation verify kashif-linux-x86_64 --repo abdulrahmanahmedelabed-prog/vulnscan

# container image: signed SLSA build provenance, and the SBOM attached to the image
gh attestation verify oci://ghcr.io/abdulrahmanahmedelabed-prog/kashif:1.0.1 --repo abdulrahmanahmedelabed-prog/vulnscan
docker buildx imagetools inspect ghcr.io/abdulrahmanahmedelabed-prog/kashif:1.0.1 --format '{{ json .SBOM }}'
```

The provenance states the repository, the workflow and the commit the artifact was built from. A release also
carries a CycloneDX SBOM of the source (`kashif-sbom.cdx.json`).

## Upgrading from 0.x

1.0 is the first release covered by the contract above; 0.x releases changed freely. Going from 0.9 to 1.0:

1. **Pin first, then upgrade.** Note the version you run today (`vulnscan --version`) and pin 1.0.0 explicitly
   (action SHA, image tag or digest, pip tag) instead of following a branch.
2. **Expect a different set of findings.** 1.0 has more rules, more library models and a more precise engine than
   any 0.x release: it reports vulnerabilities that 0.x missed and drops some false positives. Run it once without
   `--fail-on` and compare before you gate on it.
3. **Baselines stay valid.** The fingerprint scheme (`vulnscan/v1`) and the baseline schema (`vulnscan-baseline/1`)
   are the ones 0.9 used, so an existing baseline keeps suppressing what it suppressed. After you have reviewed
   the new findings, either fix them or refresh the file with `--write-baseline`.
4. **Code-scanning alerts keep their identity** for the same reason; alerts for findings that 1.0 no longer
   reports are closed by GitHub as fixed.
5. **Suppressions, `--ignore-rule` lists and rule IDs** carry over unchanged. If the [changelog](../CHANGELOG.md) of 1.0.0
   lists a renamed rule, the old ID keeps working as an alias.
6. **Exit codes are unchanged** (`0`, `1`, `2`), and from 1.0 on they are part of the contract. If a script
   treats every non-zero code as "findings", change it to tell `1` (findings) from `2` (the scan did not run).
7. **Parsers of JSON or SARIF output** keep working; make sure they ignore unknown fields, because minor releases
   add fields.
8. **Python 3.10 or newer** is required for pip and source installs, as in 0.9. The binaries and the image carry
   their own runtime.
9. **The command is now `kashif`.** `vulnscan` keeps working as an alias (pip, the one-line installers, Homebrew,
   the Windows setup and the container image all install both names), so existing scripts need no change. The
   release binaries are published as `kashif-*` and, byte for byte the same, under the old `vulnscan-*` names, so
   a 0.9 binary's in-app update still finds its file.
10. **Test, documentation and example code is reported differently.** Files under test, docs and example paths are
   recognised by their path: rules that only describe fixtures there (sample secrets, plain-HTTP URLs, routes without
   authentication, and similar) are dropped, and the remaining findings there are lowered to `info`, so they no longer
   trip `--fail-on`. Vendored bundles (`compiled/` trees, checked-in static libraries) are skipped with a note. Set
   `VULNSCAN_INCLUDE_TESTS=1` to report those paths in full, as 0.9 did.
11. **A `kashif.yml` in the scanned folder is a policy gate.** It is applied automatically and decides the exit code
   together with `--fail-on`; `--no-policy` turns it off.
12. **PHP `unserialize`.** Flows into `unserialize` are now reported as DF006 (insecure deserialization, CWE-502)
   instead of DF001, so those findings get a new identity; review them once and refresh the baseline.
13. **Read the [changelog](../CHANGELOG.md)** entry of 1.0.0 for anything specific to that release, then roll out to
   one repository, compare, and widen.
