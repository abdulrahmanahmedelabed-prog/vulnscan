"""Post a Kashif scan to a GitHub pull request: one review with inline comments, one summary comment.

Run by the composite action (``action.yml``) after the scan wrote a JSON report::

    python -m vulnscan.integrations.github_pr --report kashif.json --comment-mode review --fail-on high

What it does, in the spirit of CodeQL / Semgrep / Snyk Code PR checks:

* **Inline review.** Each finding whose line (or, for a data-flow finding, a step of its trail) is part of the PR
  diff gets an inline comment on that line, on the RIGHT side: severity, rule, title, remediation, the data-flow
  trail and a CWE link. All go into ONE review (``event: COMMENT``), at most ``--max-inline`` (default 50) comments;
  the rest are listed in the review body. Every comment carries a hidden marker with the finding's stable
  fingerprint, so a re-run on a new push does not post the same comment again.
* **Summary comment.** One issue comment, found again by its hidden marker and updated in place.
* **Job summary.** The same summary is appended to ``$GITHUB_STEP_SUMMARY``. When the token cannot write (a pull
  request from a fork gets a read-only ``GITHUB_TOKEN``), that and workflow annotations are the output.
* **Outcome.** Exit code 1 when a finding is at or above ``--fail-on``.

REST calls use urllib with a Bearer token and ``X-GitHub-Api-Version: 2022-11-28``; ``GITHUB_API_URL`` selects
GitHub Enterprise Server. Secondary rate limits (403/429 with Retry-After) and 5xx are retried with backoff.
The token is never printed, never sent on a redirect, and never sent to a host other than the API host.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from ..model import SEVERITIES, SEVERITY_AR, SEVERITY_RANK

API_VERSION = "2022-11-28"
SUMMARY_MARKER = "<!-- kashif:summary -->"
FP_MARKER = "<!-- kashif:fp={fp} -->"
_FP_RX = re.compile(r"<!-- kashif:fp=([0-9a-f]{16}:\d+) -->")
MAX_BODY = 60000                     # GitHub's limit is 65536 characters per comment/review body
BADGE = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}
_sleep = time.sleep                  # tests replace this

_LABELS = {
    "title": ("كاشِف — نتائج الفحص الأمني", "Kashif — security scan results"),
    "none": ("✔ لا نتائج جديدة في هذا التغيير.", "✔ No new findings in this change."),
    "found": ("{n:new_findings} في هذا التغيير", "{n:new_findings} in this change"),     # count agrees with n
    "base": ("مقارنة مع", "Compared with"),
    "sev": ("الخطورة", "Severity"),
    "count": ("العدد", "Count"),
    "rule": ("القاعدة", "Rule"),
    "finding": ("النتيجة", "Finding"),
    "where": ("الموضع", "Location"),
    "fix": ("المعالجة", "Remediation"),
    "trail": ("مسار البيانات", "Data-flow trail"),
    "more": ("نتائج أخرى لم تُعلَّق على أسطرها", "Other findings (not commented inline)"),
    "truncated": ("… واقتُطع الباقي؛ التقرير الكامل في نتائج الفحص.", "… truncated; the full report is in the scan results."),
    "inline": ("تعليقات على الأسطر", "inline comments"),
    "failed": ("❌ نتائج بخطورة {sev} أو أعلى: الفحص فاشل.", "❌ Findings at {sev} or above: the check fails."),
    "readonly": ("الرمز للقراءة فقط (طلب دمج من نسخة متفرعة): النتائج في ملخص المهمة.",
                 "Read-only token (pull request from a fork): results are in the job summary."),
}


class GitHubError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"GitHub API {status}: {message}")
        self.status = status


def _check_api_url(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    loopback = parts.hostname in ("127.0.0.1", "localhost", "::1")
    if parts.scheme != "https" and not (parts.scheme == "http" and loopback):
        raise ValueError("GITHUB_API_URL must be an https:// URL")
    return url.rstrip("/")


class GitHub:
    """Minimal REST client: JSON in/out, pagination, retries. The token stays in this object."""

    def __init__(self, api_url: str, token: str, retries: int = 4, timeout: float = 30.0):
        self.api = _check_api_url(api_url)
        self._host = urllib.parse.urlsplit(self.api).netloc
        self._token = token
        self.retries = retries
        self.timeout = timeout

    def __repr__(self) -> str:                       # never show the token
        return f"GitHub({self.api!r})"

    def _url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            if urllib.parse.urlsplit(path).netloc != self._host:
                raise GitHubError(0, "refusing to send the token to another host")
            return path
        return self.api + path

    @staticmethod
    def _rate_limited(status: int, headers, body: bytes) -> bool:
        if status == 429:
            return True
        if status != 403:
            return False
        return bool(headers.get("Retry-After")) or headers.get("X-RateLimit-Remaining") == "0" \
            or b"rate limit" in body.lower()

    @staticmethod
    def _delay(headers, attempt: int) -> float:
        ra = headers.get("Retry-After") if headers else None
        if ra and ra.strip().isdigit():
            return min(float(ra), 60.0)
        reset = headers.get("X-RateLimit-Reset") if headers else None
        if headers and headers.get("X-RateLimit-Remaining") == "0" and reset and reset.isdigit():
            return max(1.0, min(float(reset) - time.time(), 60.0))
        return min(2.0 ** attempt, 60.0)

    def request(self, method: str, path: str, body=None):
        """Returns (parsed JSON or None, response headers)."""
        url = self._url(path)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        last = "no response"
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(url, data=data, method=method)
            req.add_unredirected_header("Authorization", f"Bearer {self._token}")
            req.add_header("Accept", "application/vnd.github+json")
            req.add_header("X-GitHub-Api-Version", API_VERSION)
            req.add_header("User-Agent", "kashif-sast")
            if data is not None:
                req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosec B310 - scheme checked above
                    raw = resp.read()
                    headers = resp.headers
                try:
                    return (json.loads(raw) if raw.strip() else None), headers
                except ValueError:           # e.g. an HTML page from a proxy in front of GitHub Enterprise Server
                    raise GitHubError(0, "the API answered with something other than JSON") from None
            except urllib.error.HTTPError as e:
                raw = e.read() or b""
                status, headers = e.code, e.headers
                retry = status >= 500 or self._rate_limited(status, headers, raw)
                try:
                    last = str(json.loads(raw).get("message", ""))[:200]
                except (ValueError, AttributeError):
                    last = raw[:200].decode("utf-8", "replace")
                if retry and attempt < self.retries:
                    _sleep(self._delay(headers, attempt))
                    continue
                raise GitHubError(status, last) from None
            except (urllib.error.URLError, OSError, http.client.HTTPException) as e:   # incl. timeouts, TLS
                last = type(e).__name__
                if attempt < self.retries:
                    _sleep(self._delay(None, attempt))
                    continue
                raise GitHubError(0, last) from None
        raise GitHubError(0, last)

    def paginate(self, path: str, limit: int = 3000):
        """Follow rel="next" by its page number only: the next URL itself is never requested, so a Link header
        cannot redirect the token anywhere."""
        sep = "&" if "?" in path else "?"
        url, seen, page = f"{path}{sep}per_page=100", 0, 1
        while url and seen < limit:
            items, headers = self.request("GET", url)
            if not isinstance(items, list):
                raise GitHubError(0, f"unexpected response for {path}")
            for it in items:
                seen += 1
                yield it
            m = re.search(r'<[^>]*[?&]page=(\d+)[^>]*>;\s*rel="next"', (headers.get("Link") or "") if headers else "")
            nxt = int(m.group(1)) if m else 0
            url = f"{path}{sep}per_page=100&page={nxt}" if nxt > page else None
            page = nxt


# ---------------------------------------------------------------- pure helpers (tested directly)

def commentable_lines(patch: str | None) -> set[int]:
    """RIGHT-side line numbers that appear in a file's PR diff hunk (added or context): where GitHub accepts a
    review comment."""
    lines: set[int] = set()
    new = None
    for ln in (patch or "").splitlines():
        m = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", ln)
        if m:
            new = int(m.group(1))
            continue
        if new is None or ln.startswith("\\"):
            continue
        if ln.startswith("-"):
            continue
        lines.add(new)
        new += 1
    return lines


def _code(text) -> str:
    """Untrusted text (code from the PR) as an inline code span: no markup, no mentions, no forged markers."""
    t = _plain(re.sub(r"\s+", " ", str(text or "")).strip().replace("`", "ˋ")[:200])
    return f"`{t}`" if t else ""


def _plain(text) -> str:
    return str(text or "").replace("<!--", "&lt;!--").replace("-->", "--&gt;")


def _cwe_link(cwe: str) -> str:
    num = (cwe or "").upper().removeprefix("CWE-")
    return f"[{cwe}](https://cwe.mitre.org/data/definitions/{num}.html)" if num.isdigit() else _plain(cwe)


class _Text:
    def __init__(self, lang: str):
        self.en = lang != "ar"

    def __call__(self, key: str, **kw) -> str:
        from ..i18n.cliargs import fmt         # "{n:new_findings}": the noun agrees with the number
        t = _LABELS[key][1 if self.en else 0]
        return fmt(t, "en" if self.en else "ar", **kw) if kw else t

    def sev(self, s: str) -> str:
        return s.upper() if self.en else SEVERITY_AR.get(s, s)

    def title(self, f: dict) -> str:
        return _plain((f.get("title") or f.get("title_ar")) if self.en else (f.get("title_ar") or f.get("title")))

    def advice(self, f: dict) -> str:
        return _plain(f.get("advice_en") or f.get("advice") if self.en else f.get("advice"))

    def step(self, st: dict) -> str:
        return st.get("text_en") or st.get("text", "") if self.en else st.get("text", "")


def comment_body(f: dict, L: _Text, path_of) -> str:
    sev = f.get("severity", "info")
    head = f"**{BADGE.get(sev, '')} {L.sev(sev)} · `{_plain(f.get('rule_id'))}` · {L.title(f)}**"
    if f.get("cwe"):
        head += f" ({_cwe_link(f['cwe'])})"
    out = [head, "", f"**{L('fix')}:** {L.advice(f)}"]
    steps = [st for st in (f.get("extra") or {}).get("path") or [] if isinstance(st, dict)]
    if steps:
        out += ["", f"<details><summary>{L('trail')}</summary>", ""]
        for i, st in enumerate(steps, 1):
            out.append(f"{i}. `{path_of(str(st.get('file') or f.get('file', '')))}:{st.get('line', '')}` — "
                       f"{_code(L.step(st))}")
        out += ["", "</details>"]
    out += ["", FP_MARKER.format(fp=f.get("fingerprint", ""))]
    return "\n".join(out)


def _location(f: dict, path_of, link) -> str:
    p = path_of(f.get("file", ""))
    ln = f.get("line") or 0
    text = f"`{p}:{ln}`" if ln else f"`{p}`"
    url = link(p, ln)
    return f"[{text}]({url})" if url else text


def summary_markdown(findings: list[dict], L: _Text, path_of, link, inline_fps: set[str], base: str = "",
                     fail_on: str | None = None, extra_note: str = "") -> str:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    md = [SUMMARY_MARKER, f"## {L('title')}", ""]
    if extra_note:
        md += [f"> {extra_note}", ""]
    if base:
        md += [f"{L('base')}: `{_plain(base)}`", ""]
    if not findings:
        md.append(L("none"))
        return "\n".join(md) + "\n"
    md += [f"**{L('found', n=len(findings))}**", "", f"| {L('sev')} | {L('count')} |", "|---|---|"]
    md += [f"| {BADGE[s]} {L.sev(s)} | {counts[s]} |" for s in SEVERITIES if counts[s]]
    if fail_on and any(SEVERITY_RANK.get(f.get("severity"), 9) <= SEVERITY_RANK[fail_on] for f in findings):
        md += ["", L("failed", sev=L.sev(fail_on))]
    md += ["", f"| {L('sev')} | {L('rule')} | {L('finding')} | {L('where')} |", "|---|---|---|---|"]
    size = sum(len(x) + 1 for x in md)
    for f in findings:
        mark = " 💬" if f.get("fingerprint") in inline_fps else ""
        row = (f"| {BADGE.get(f.get('severity'), '')} {L.sev(f.get('severity', 'info'))} | `{_plain(f.get('rule_id'))}` | "
               f"{L.title(f).replace('|', '¦')}{mark} | {_location(f, path_of, link)} |")
        if size + len(row) > MAX_BODY - 400:
            md += ["", L("truncated")]
            break
        md.append(row)
        size += len(row) + 1
    if inline_fps:
        md += ["", f"💬 = {L('inline')}"]
    return "\n".join(md) + "\n"


def _annotation(f: dict, L: _Text, path_of) -> str:
    level = "error" if f.get("severity") in ("critical", "high") else "warning"

    def esc(v: str, prop: bool = False) -> str:
        v = str(v).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        return v.replace(":", "%3A").replace(",", "%2C") if prop else v
    props = f"file={esc(path_of(f.get('file', '')), True)}"
    if f.get("line"):
        props += f",line={int(f['line'])}"
    title = f"{f.get('rule_id')} {L.title(f)}"
    props += f",title={esc(title, True)}"
    return f"::{level} {props}::{esc(L.advice(f))}"


# ---------------------------------------------------------------- SARIF paths

def rebase_sarif(sarif_path: str, prefix: str) -> int:
    """Make SARIF artifact URIs relative to the repository root (the scan may have targeted a subdirectory):
    code scanning resolves results against the checkout. Returns how many locations were rewritten."""
    prefix = prefix.strip("/").replace("\\", "/")
    p = pathlib.Path(sarif_path)
    data = json.loads(p.read_text(encoding="utf-8"))
    n = 0

    def fix(loc):
        nonlocal n
        art = (loc or {}).get("artifactLocation") if isinstance(loc, dict) else None
        if isinstance(art, dict) and art.get("uriBaseId") in ("%SRCROOT%", None) and art.get("uri") \
                and "://" not in art["uri"]:
            if prefix and prefix != ".":
                art["uri"] = f"{urllib.parse.quote(prefix, safe='/')}/{art['uri']}"
            art.pop("uriBaseId", None)
            n += 1
    for run in data.get("runs", []):
        run.pop("originalUriBaseIds", None)
        for res in run.get("results", []):
            for loc in res.get("locations", []):
                fix(loc.get("physicalLocation"))
            for cf in res.get("codeFlows", []):
                for tf in cf.get("threadFlows", []):
                    for loc in tf.get("locations", []):
                        fix((loc.get("location") or {}).get("physicalLocation"))
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return n


# ---------------------------------------------------------------- orchestration

def _author_ok(item: dict, allowed: set[str]) -> bool:
    user = item.get("user") or {}
    return user.get("type") == "Bot" or (user.get("login") or "") in allowed


def _write(path: str | None, text: str) -> None:
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text)


def run(args, env) -> int:
    report = json.loads(pathlib.Path(args.report).read_text(encoding="utf-8"))
    findings = [f for f in report.get("findings", []) if isinstance(f, dict)]
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.get("severity"), 9), f.get("file", ""), f.get("line") or 0))
    L = _Text(args.lang)
    repo_root = pathlib.Path(args.repo_root or env.get("GITHUB_WORKSPACE") or os.getcwd()).resolve()
    scan_root = pathlib.Path(args.scan_root).resolve() if pathlib.Path(args.scan_root).is_absolute() \
        else (repo_root / args.scan_root).resolve()
    if scan_root.is_file():
        scan_root = scan_root.parent

    def path_of(rel: str) -> str:
        rel = rel.split("!", 1)[0]
        try:
            return (scan_root / rel).resolve().relative_to(repo_root).as_posix()
        except (ValueError, OSError):
            return rel.replace("\\", "/")

    event = {}
    if env.get("GITHUB_EVENT_PATH"):
        try:
            event = json.loads(pathlib.Path(env["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            event = {}
    pr = event.get("pull_request") or {}
    repo = env.get("GITHUB_REPOSITORY", "")
    head_sha = (pr.get("head") or {}).get("sha") or env.get("GITHUB_SHA", "")
    server = env.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")

    def link(p: str, ln: int) -> str:
        if not (repo and head_sha):
            return ""
        return f"{server}/{repo}/blob/{head_sha}/{urllib.parse.quote(p)}" + (f"#L{ln}" if ln else "")

    failing = bool(args.fail_on) and any(SEVERITY_RANK.get(f.get("severity"), 9) <= SEVERITY_RANK[args.fail_on]
                                         for f in findings)
    outputs = {"findings": len(findings), "inline-comments": 0, "failed": str(failing).lower()}
    head_repo = ((pr.get("head") or {}).get("repo") or {}).get("full_name")
    base_repo = ((pr.get("base") or {}).get("repo") or {}).get("full_name") or repo
    read_only = bool(pr) and env.get("GITHUB_EVENT_NAME") == "pull_request" and bool(head_repo) \
        and head_repo != base_repo
    inline_fps: set[str] = set()
    note = ""
    can_comment = bool(pr.get("number")) and args.comment_mode != "none" and env.get("GITHUB_TOKEN") and repo
    if can_comment and read_only:
        note, can_comment = L("readonly"), False
    if can_comment:
        try:
            gh = GitHub(env.get("GITHUB_API_URL") or "https://api.github.com", env["GITHUB_TOKEN"])
            inline_fps = _post(gh, repo, pr, findings, args, L, path_of, link, env, failing)
        except GitHubError as e:
            if e.status in (401, 403, 404):
                note = L("readonly")
            print(f"kashif: {e}", file=sys.stderr)
        outputs["inline-comments"] = len(inline_fps)
    summary = summary_markdown(findings, L, path_of, link, inline_fps, args.diff_base, args.fail_on, note)
    _write(env.get("GITHUB_STEP_SUMMARY"), summary + "\n")
    if note or not can_comment:            # nobody will see PR comments: annotate the diff instead
        for f in findings[:50]:
            print(_annotation(f, L, path_of))
    _write(env.get("GITHUB_OUTPUT"), "".join(f"{k}={v}\n" for k, v in outputs.items()))
    print(f"kashif: {len(findings)} finding(s), {len(inline_fps)} inline comment(s)")
    return 1 if failing else 0


def _post(gh: GitHub, repo: str, pr: dict, findings: list[dict], args, L: _Text, path_of, link, env,
          failing: bool) -> set[str]:
    num = int(pr["number"])
    allowed = {x for x in (env.get("KASHIF_COMMENT_AUTHOR") or "").split(",") if x}
    inline: set[str] = set()
    if args.comment_mode == "review":
        commentable: dict[str, set[int]] = {}
        for item in gh.paginate(f"/repos/{repo}/pulls/{num}/files"):
            if item.get("status") != "removed":
                commentable[item.get("filename", "")] = commentable_lines(item.get("patch"))
        posted: set[str] = set()
        for c in gh.paginate(f"/repos/{repo}/pulls/{num}/comments"):
            if _author_ok(c, allowed):
                posted.update(_FP_RX.findall(c.get("body") or ""))
        comments, overflow = [], []
        for f in findings:
            fp = f.get("fingerprint", "")
            if fp in posted:
                inline.add(fp)
                continue
            spot = None
            if "!" not in (f.get("file") or ""):
                cands = [(f.get("file", ""), f.get("line") or 0)]
                cands += [(str(st.get("file") or f.get("file", "")), st.get("line") or 0)
                          for st in (f.get("extra") or {}).get("path") or [] if isinstance(st, dict)]
                for rel, ln in cands:
                    p = path_of(rel)
                    try:
                        ln = int(ln)
                    except (TypeError, ValueError):
                        continue
                    if ln and ln in commentable.get(p, ()):
                        spot = (p, ln)
                        break
            if spot and len(comments) < args.max_inline:
                comments.append({"path": spot[0], "line": spot[1], "side": "RIGHT",
                                 "body": comment_body(f, L, path_of)[:MAX_BODY]})
                inline.add(fp)
            elif spot:
                overflow.append(f)
        if comments:
            body = [f"**{L('title')}** — {L('found', n=len(findings))}"]
            if overflow:
                body += ["", f"**{L('more')}:**", ""]
                body += [f"- {BADGE.get(f.get('severity'), '')} `{_plain(f.get('rule_id'))}` {L.title(f)} — "
                         f"{_location(f, path_of, link)}" for f in overflow[:100]]
            review = {"commit_id": pr.get("head", {}).get("sha"), "event": "COMMENT",
                      "body": "\n".join(body)[:MAX_BODY], "comments": comments}
            try:
                gh.request("POST", f"/repos/{repo}/pulls/{num}/reviews", review)
            except GitHubError as e:
                if e.status != 422:          # a line left the diff (new push meanwhile): summary only
                    raise
                inline -= {c_fp for c_fp in _FP_RX.findall("".join(c["body"] for c in comments))}
    summary = summary_markdown(findings, L, path_of, link, inline, args.diff_base, args.fail_on)[:MAX_BODY]
    existing = None
    for c in gh.paginate(f"/repos/{repo}/issues/{num}/comments"):
        if SUMMARY_MARKER in (c.get("body") or "") and _author_ok(c, allowed):
            existing = c
            break
    if existing:
        gh.request("PATCH", f"/repos/{repo}/issues/comments/{int(existing['id'])}", {"body": summary})
    else:
        gh.request("POST", f"/repos/{repo}/issues/{num}/comments", {"body": summary})
    return inline


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m vulnscan.integrations.github_pr",
                                description="Post a Kashif JSON report to a GitHub pull request.")
    p.add_argument("--report", help="JSON report written by vulnscan -f json (or --all-formats)")
    p.add_argument("--comment-mode", choices=("review", "summary", "none"), default="review")
    p.add_argument("--fail-on", choices=SEVERITIES)
    p.add_argument("--lang", choices=("en", "ar"), default="en")
    p.add_argument("--scan-root", default=".", help="the path that was scanned (relative to the repository root)")
    p.add_argument("--repo-root", help="repository root (default: $GITHUB_WORKSPACE, else the current directory)")
    p.add_argument("--diff-base", default="", help="base ref the scan was narrowed to (shown in the summary)")
    p.add_argument("--max-inline", type=int, default=50)
    p.add_argument("--rebase-sarif", metavar="FILE", help="rewrite SARIF URIs relative to the repository root and exit")
    return p


def main(argv: list[str] | None = None, env=None) -> int:
    env = os.environ if env is None else env
    args = build_parser().parse_args(argv)
    if args.rebase_sarif:
        repo_root = pathlib.Path(args.repo_root or env.get("GITHUB_WORKSPACE") or os.getcwd()).resolve()
        root = (repo_root / args.scan_root).resolve()
        if root.is_file():
            root = root.parent
        try:
            prefix = root.relative_to(repo_root).as_posix()
        except ValueError:
            prefix = ""
        print(f"kashif: {rebase_sarif(args.rebase_sarif, prefix)} SARIF location(s) relative to the repository root")
        return 0
    if not args.report:
        build_parser().error("--report is required")
    args.max_inline = max(0, min(args.max_inline, 50))
    return run(args, env)


if __name__ == "__main__":
    sys.exit(main())
