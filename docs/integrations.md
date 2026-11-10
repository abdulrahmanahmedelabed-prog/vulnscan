# Pull-request integration — GitHub

Kashif checks pull requests on GitHub the way CodeQL, Semgrep and Snyk Code PR checks do: the **whole project is
scanned** (so cross-file data flow is complete), but **only the findings the change introduced are reported**, as
inline review comments on the changed lines, one summary comment, SARIF in the Security tab, and a pass/fail
status.

GitHub is the only hosted platform this project integrates with. Outside GitHub, use the command line
(`--diff-base`, `-f sarif`, `--fail-on`) or the pre-commit hook below.

## GitHub Action

```yaml
# .github/workflows/kashif.yml
name: Kashif
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  kashif:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write      # review + summary comment
      security-events: write    # SARIF upload to code scanning
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          fetch-depth: 0          # lets Kashif compute the merge-base with the PR's base
          persist-credentials: false
      - uses: abdulrahmanahmedelabed-prog/vulnscan@<commit SHA>   # pin a full commit SHA
        with:
          fail-on: high
```

### Inputs

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Directory or file to scan, relative to the repository root. |
| `fail-on` | `high` | Fail the job when a **reported** finding has this severity or higher (`critical`, `high`, `medium`, `low`, `info`, `none`). |
| `min-severity` | `info` | Report only this severity or higher. |
| `diff-base` | the PR's base commit | Report only findings on lines changed since the merge-base with this ref. Empty (e.g. on `push`) reports everything. |
| `baseline` | — | Baseline file from `vulnscan --write-baseline`; known findings are not reported. |
| `language` | `en` | Language of the comments and job summary: `en` or `ar`. |
| `comment-mode` | `review` | `review`: inline review comments plus the summary comment; `summary`: the summary comment only; `none`. |
| `upload-sarif` | `true` | Upload SARIF to GitHub code scanning (category `kashif`). |
| `audit` | `false` | Audit profile: also report risky calls not proven reachable by tainted data. |
| `token` | `github.token` | Token for comments. |
| `python-version` | `3.12` | Python used to run the scanner. |

Outputs: `findings` (number reported after all filters) and `sarif` (path of the SARIF file).

### What appears on the pull request

* **One review** (event `COMMENT`) with an inline comment on each new finding whose line is in the PR diff, on the
  right-hand side: severity, rule, title, remediation, a CWE link and the collapsible **data-flow trail**. A data-flow
  finding whose sink is outside the diff is attached to the first step of its trail that *is* in the diff. At most
  50 inline comments per run; the rest are listed in the review body.
* Every comment carries a hidden fingerprint marker, so **re-runs do not duplicate** comments: a new push only adds
  comments for findings that were not commented before. Markers are only trusted on comments written by a bot
  (or by the logins listed in the `KASHIF_COMMENT_AUTHOR` environment variable, comma-separated, if you use a
  personal token).
* **One summary comment**, found by a hidden marker and updated in place, with counts per severity and a table of
  every new finding linked to the exact line at the PR's head commit.
* The same summary in the **job summary** (`$GITHUB_STEP_SUMMARY`).
* SARIF in **code scanning**, with stable `partialFingerprints` and `codeFlows`, so GitHub tracks alerts across
  commits. Paths are rewritten relative to the repository root when `path` is a subdirectory.
* The job **fails** per `fail-on`, gated only on the new findings.

### Pull requests from forks

On `pull_request` events from a fork, GitHub gives the workflow a read-only token. Kashif detects this and does
not try to comment: the summary goes to the job summary and each finding becomes a workflow annotation on the
diff. The SARIF upload is skipped with a warning (the step is `continue-on-error`). Avoid `pull_request_target`
with a checkout of the fork's code.

### Security of the action

* Every third-party action is pinned to a full commit SHA (the same ones the repository's own workflows use).
* Inputs reach shell steps only through environment variables, never as `${{ }}` expressions inside scripts, and
  enumerated inputs (and the `diff-base` ref) are validated before use.
* The scan's console output quotes code from the pull request, so workflow commands are switched off while it is
  printed (`::stop-commands::` with a random token): a line of PR code cannot pose as `::error::`, `::add-mask::`
  or any other workflow command.
* The scanner is installed from the action's own source into a virtual environment in `$RUNNER_TEMP`.
* The REST client (standard library only) sends the token as `Authorization: Bearer`, never on a redirect and never
  to a host other than `GITHUB_API_URL`, and never prints it. It uses `X-GitHub-Api-Version: 2022-11-28` and retries
  secondary rate limits (honouring `Retry-After`) and 5xx responses with exponential backoff.
* GitHub Enterprise Server works unchanged: the action reads `GITHUB_API_URL` and `GITHUB_SERVER_URL`.

## Diff-aware scanning on the command line

```bash
# only what this branch introduced relative to main (merge-base), uncommitted and untracked files included
vulnscan . --diff-base origin/main --fail-on high

# only what is staged for the next commit
vulnscan . --diff-staged --fail-on high

# with a baseline: known findings stay quiet, and only changed lines are reported
vulnscan . --baseline .kashif-baseline.json --diff-base origin/main
```

A finding is reported when its line was added or modified, when a step of its data-flow trail was (changing a
source or deleting a sanitizer creates a new flow even if the sink line is untouched), or, for file-level findings,
when its file changed. Each reported finding is marked `extra.diff` = `line`, `trail` or `file` in the JSON report.
Fingerprints are computed on the full scan and do not change. In a shallow clone where the merge-base is not
available, or the base shares no history with `HEAD`, the diff is taken against the base ref itself (noted in the
report); a base ref that is not in the clone at all stops the scan with exit code 2 and a hint to fetch it. With
`actions/checkout`'s default `fetch-depth: 1` the action fetches the base commit itself; with
`persist-credentials: false` on a private repository it cannot, so use `fetch-depth: 0` as in the example above.
The ref is validated, git is always run without a shell, and the diff is parsed by its hunk line counts, so changed
code that looks like a diff header cannot hide the hunks after it. Renames count only their changed lines; deleted
files report nothing; changed or new binary files and new untracked files count as entirely changed.

## pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/abdulrahmanahmedelabed-prog/vulnscan
    rev: <tag or commit SHA>
    hooks:
      - id: kashif
```

The hook scans the repository offline (`--no-deps --no-external`), reports only findings on staged lines
(`--diff-staged`) and blocks the commit on `high` or `critical`.
