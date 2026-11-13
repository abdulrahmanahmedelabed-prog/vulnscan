"""Pull-request integration: diff-aware scanning (--diff-base / --diff-staged), the GitHub PR reporter against a
local fake GitHub API, SARIF path rebasing, and static checks of action.yml / .pre-commit-hooks.yaml."""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import sys
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from vulnscan.cli import main
from vulnscan.diffscope import DiffScopeError, compute, parse_unified_diff, validate_ref
from vulnscan.integrations import github_pr
from vulnscan.model import SEVERITY_AR
from vulnscan.integrations.github_pr import GitHub, GitHubError, commentable_lines, rebase_sarif

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = pathlib.Path(__file__).parent / "data" / "pr_integration"
GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="git not installed")
SCAN = ["--no-deps", "--no-external", "--no-queries", "--lang", "en", "-f", "json"]


# ---------------------------------------------------------------- git helpers

def _git(repo: pathlib.Path, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    out = subprocess.run([GIT, "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args], cwd=repo,
                         env=env, capture_output=True, text=True, check=True)
    return out.stdout.strip()


def _copy(name: str, dest: pathlib.Path, as_name: str | None = None) -> None:
    shutil.copy(DATA / name, dest / (as_name or name))


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    _copy("helpers.py", r)
    _copy("app_base.py", r, "app.py")
    _git(r, "add", ".")
    _git(r, "commit", "-q", "-m", "base")
    return r


def _scan(target, *extra, capsys=None, out=None) -> tuple[int, list[dict], list[str]]:
    out = out or (pathlib.Path(target).parent / "r.json")
    code = main([str(target), *SCAN, "-o", str(out), *extra])
    data = json.loads(out.read_text(encoding="utf-8"))
    return code, data["findings"], data["notes_en"]


# ---------------------------------------------------------------- diff-aware scanning

@needs_git
def test_diff_base_reports_only_the_new_finding(repo):
    base = _git(repo, "rev-parse", "HEAD")
    _, full, _ = _scan(repo)
    assert {f["file"] for f in full} >= {"app.py", "helpers.py"}       # the base already has findings
    _git(repo, "checkout", "-q", "-b", "feature")
    _copy("added_vuln.py", repo, "added.py")
    _copy("added_safe.py", repo, "added_safe.py")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "change")
    code, found, notes = _scan(repo, "--diff-base", base, "--fail-on", "high")
    assert found and {f["file"] for f in found} == {"added.py"}, found
    assert all(f["extra"]["diff"] == "line" for f in found)
    assert code == 1
    assert any("Limited to changes since" in n for n in notes)
    assert any(n.startswith("Findings outside the changes not shown:") for n in notes)


@needs_git
def test_fail_on_gates_only_new_findings(repo):
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "README.txt").write_text("docs only\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "docs")
    code, found, _ = _scan(repo, "--diff-base", base, "--fail-on", "high")
    assert found == [] and code == 0
    code, _, _ = _scan(repo, "--fail-on", "high")          # without the diff scope the old findings fail
    assert code == 1


@needs_git
def test_trail_touching_change_is_reported(repo):
    """Only the source line changes; the sink line and the helper do not: the flow is still new."""
    base = _git(repo, "rev-parse", "HEAD")
    _copy("app_trail.py", repo, "app.py")
    _git(repo, "commit", "-q", "-am", "make the command user controlled")
    _, found, _ = _scan(repo, "--diff-base", base)
    trail = [f for f in found if f["extra"].get("diff") == "trail"]
    assert trail, found
    assert trail[0]["rule_id"].startswith("DF")
    assert not any(f["file"] == "helpers.py" for f in found)      # the unchanged sink's own rule stays quiet


@needs_git
def test_diff_scope_safe_twin_is_quiet(repo):
    base = _git(repo, "rev-parse", "HEAD")
    _copy("added_safe.py", repo, "added.py")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "safe change")
    code, found, _ = _scan(repo, "--diff-base", base, "--fail-on", "low")
    assert found == [] and code == 0


@needs_git
def test_untracked_and_uncommitted_changes_count(repo):
    _copy("added_vuln.py", repo, "wip.py")                  # untracked, not ignored
    _, found, _ = _scan(repo, "--diff-base", "HEAD")
    assert {f["file"] for f in found} == {"wip.py"}


@needs_git
def test_diff_staged_ignores_untracked(repo):
    _copy("added_vuln.py", repo, "staged.py")
    _copy("added_vuln.py", repo, "untracked.py")
    _git(repo, "add", "staged.py")
    _, found, _ = _scan(repo, "--diff-staged")
    assert {f["file"] for f in found} == {"staged.py"}


@needs_git
def test_diff_staged_before_first_commit(tmp_path):
    r = tmp_path / "fresh"
    r.mkdir()
    _git(r, "init", "-q")
    _copy("added_vuln.py", r, "a.py")
    _git(r, "add", ".")
    _, found, _ = _scan(r, "--diff-staged")
    assert {f["file"] for f in found} == {"a.py"}


@needs_git
def test_diff_base_with_subdirectory_target(repo):
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "svc").mkdir()
    _copy("added_vuln.py", repo / "svc", "x.py")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "svc")
    _, found, _ = _scan(repo / "svc", "--diff-base", base, out=repo.parent / "r.json")
    assert found and {f["file"] for f in found} == {"x.py"}


@needs_git
def test_diff_base_works_with_baseline(repo, tmp_path):
    base = _git(repo, "rev-parse", "HEAD")
    _copy("added_vuln.py", repo, "added.py")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "change")
    bl = tmp_path / "baseline.json"
    assert main([str(repo), "--no-deps", "--no-external", "--no-queries", "--write-baseline", str(bl)]) == 0
    code, found, _ = _scan(repo, "--diff-base", base, "--baseline", str(bl), "--fail-on", "low")
    assert found == [] and code == 0


@needs_git
def test_fingerprints_unchanged_by_diff_scope(repo):
    base = _git(repo, "rev-parse", "HEAD")
    _copy("added_vuln.py", repo, "added.py")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "change")
    _, full, _ = _scan(repo)
    _, scoped, _ = _scan(repo, "--diff-base", base)
    fps = {(f["rule_id"], f["file"], f["line"]): f["fingerprint"] for f in full}
    assert scoped and all(fps[(f["rule_id"], f["file"], f["line"])] == f["fingerprint"] for f in scoped)


@needs_git
@pytest.mark.parametrize("ref", ["--output=/tmp/x", "a..b", "main@{1}", "", "x y", "-", "HEAD:secret.txt"])
def test_invalid_refs_rejected(repo, ref, capsys):
    with pytest.raises(DiffScopeError):
        validate_ref(ref)
    if ref:
        assert main([str(repo), *SCAN, f"--diff-base={ref}"]) == 2
        assert "Invalid git ref" in capsys.readouterr().err


@needs_git
def test_unknown_ref_and_not_a_repo(repo, tmp_path, capsys):
    assert main([str(repo), *SCAN, "--diff-base", "does-not-exist"]) == 2
    assert "Ref not found" in capsys.readouterr().err
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(DiffScopeError):
        compute(plain, "HEAD")


def test_diff_base_rejects_web_targets():
    with pytest.raises(SystemExit):
        main(["https://example.invalid/", "--authorized", "--diff-base", "HEAD"])


def test_parse_unified_diff():
    text = "\n".join([
        "diff --git a/a.py b/a.py", "index 1..2 100644", "--- a/a.py", "+++ b/a.py",
        "@@ -3 +3 @@", "-x", "+y",
        "@@ -10,2 +9,0 @@", "-gone", "-gone2",
        "@@ -20,0 +19,3 @@", "+n1", "+n2", "+n3",
        'diff --git "a/sp\\303\\251c ial.py" "b/sp\\303\\251c ial.py"', "--- \"a/sp\\303\\251c ial.py\"",
        "+++ \"b/sp\\303\\251c ial.py\"", "@@ -0,0 +1,2 @@", "+a", "+b",
        "diff --git a/old.py b/old.py", "deleted file mode 100644", "--- a/old.py", "+++ /dev/null", "@@ -1 +0,0 @@", "-z",
        "diff --git a/img.png b/img.png", "index 1..2 100644", "Binary files a/img.png and b/img.png differ",
    ])
    changed, near, binary = parse_unified_diff(text)
    assert changed["a.py"] == {3, 19, 20, 21}
    assert near["a.py"] == {9, 10}
    assert changed["spéc ial.py"] == {1, 2}
    assert "old.py" not in changed
    assert binary == {"img.png"}


# ---------------------------------------------------------------- fake GitHub API

class FakeGitHub:
    def __init__(self):
        self.requests: list[dict] = []
        self.review_comments: list[dict] = []
        self.issue_comments: list[dict] = []
        self.reviews: list[dict] = []
        self.fail: dict[tuple[str, str], list[int]] = {}
        self.files = [{"filename": "src/app.py", "status": "modified",
                       "patch": "@@ -1,3 +1,5 @@\n ctx\n+added2\n+added3\n ctx4\n-gone\n+added5"},
                      {"filename": "src/gone.py", "status": "removed", "patch": "@@ -1 +0,0 @@\n-x"}]
        self.page_size = 1
        self.comment_page_size = 100
        self.prefix = ""                     # GitHub Enterprise Server serves the API under /api/v3
        self.html: set[tuple[str, str]] = set()
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj=None, headers=None):
                raw = json.dumps(obj).encode() if obj is not None else b""
                self.send_response(code)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _handle(self, method):
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                path, _, query = self.path.partition("?")
                if fake.prefix:
                    if not path.startswith(fake.prefix):
                        return self._send(404, {"message": "Not Found"})
                    path = path[len(fake.prefix):]
                fake.requests.append({"method": method, "path": path, "query": query, "body": body,
                                      "auth": self.headers.get("Authorization"),
                                      "version": self.headers.get("X-GitHub-Api-Version")})
                if (method, path) in fake.html:
                    raw = b"<html>maintenance</html>"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return None
                queue = fake.fail.get((method, path))
                if queue:
                    code = queue.pop(0)
                    hdr = {"Retry-After": "1"} if code in (403, 429) else {}
                    msg = "You have exceeded a secondary rate limit" if code in (403, 429) else "boom"
                    return self._send(code, {"message": msg}, hdr)
                m = re.fullmatch(r"/repos/o/r/(pulls|issues)/7/(files|comments|reviews)", path)
                if method == "GET" and m:
                    items = {"files": fake.files, "comments": fake.review_comments if m.group(1) == "pulls"
                             else fake.issue_comments}[m.group(2)]
                    page = int(dict(p.split("=") for p in query.split("&") if "=" in p).get("page", "1"))
                    n = fake.page_size if m.group(2) == "files" else fake.comment_page_size
                    chunk = items[(page - 1) * n: page * n]
                    hdr = {}
                    if page * n < len(items):
                        hdr["Link"] = (f'<http://127.0.0.1:{fake.port}{fake.prefix}{path}?per_page=100&page={page + 1}>; '
                                       'rel="next"')
                    return self._send(200, chunk, hdr)
                if method == "POST" and path == "/repos/o/r/pulls/7/reviews":
                    fake.reviews.append(body)
                    for c in body.get("comments", []):
                        fake.review_comments.append({**c, "user": {"login": "github-actions[bot]", "type": "Bot"}})
                    return self._send(200, {"id": len(fake.reviews)})
                if method == "POST" and path == "/repos/o/r/issues/7/comments":
                    c = {"id": 100 + len(fake.issue_comments), "body": body["body"],
                         "user": {"login": "github-actions[bot]", "type": "Bot"}}
                    fake.issue_comments.append(c)
                    return self._send(201, c)
                m = re.fullmatch(r"/repos/o/r/issues/comments/(\d+)", path)
                if method == "PATCH" and m:
                    for c in fake.issue_comments:
                        if c["id"] == int(m.group(1)):
                            c["body"] = body["body"]
                            return self._send(200, c)
                return self._send(404, {"message": "Not Found"})

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

            def do_PATCH(self):
                self._handle("PATCH")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def writes(self):
        return [r for r in self.requests if r["method"] != "GET"]


TOKEN = "ghs_" + "FAKEtoken0123456789"


@pytest.fixture
def fake(monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr(github_pr, "_sleep", sleeps.append)
    f = FakeGitHub()
    f.sleeps = sleeps
    yield f
    f.close()


def _finding(fp, line, sev="high", file="app.py", rule="DF002", path=None, **kw):
    return {"rule_id": rule, "severity": sev, "title": "OS command injection", "title_ar": "حقن أوامر",
            "file": file, "line": line, "snippet": "os.system(c)", "advice": "لا تمرّر مدخلات إلى الصدفة.",
            "advice_en": "Do not pass input to a shell.", "cwe": "CWE-78", "source": "taint",
            "fingerprint": f"{fp:016x}:0", "extra": {"path": path or []}, **kw}


def _env(tmp_path, fake, *, fork=False, event_name="pull_request"):
    event = {"pull_request": {"number": 7, "head": {"sha": "abc123", "repo": {"full_name": "fork/r" if fork else "o/r"}},
                              "base": {"sha": "def456", "repo": {"full_name": "o/r"}}}}
    ev = tmp_path / "event.json"
    ev.write_text(json.dumps(event))
    (tmp_path / "ws" / "src").mkdir(parents=True, exist_ok=True)
    return {"GITHUB_TOKEN": TOKEN, "GITHUB_REPOSITORY": "o/r", "GITHUB_EVENT_PATH": str(ev),
            "GITHUB_EVENT_NAME": event_name, "GITHUB_API_URL": fake.url, "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_WORKSPACE": str(tmp_path / "ws"), "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
            "GITHUB_OUTPUT": str(tmp_path / "out.txt")}


def _report(tmp_path, findings):
    p = tmp_path / "kashif.json"
    p.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    return str(p)


def _run(tmp_path, env, findings, *extra):
    return github_pr.main(["--report", _report(tmp_path, findings), "--scan-root", "src", *extra], env=env)


def test_review_payload_paths_lines_sides(tmp_path, fake, capsys):
    env = _env(tmp_path, fake)
    findings = [
        _finding(1, 2),                                             # on an added line
        _finding(2, 4, sev="medium"),                               # context line inside the hunk: commentable
        _finding(3, 40, path=[{"file": "app.py", "line": 3, "text": "c = request.args"},
                              {"file": "app.py", "line": 40, "text": "نقطة الخطر: os.system",
                               "text_en": "Sink: os.system"}]),     # sink outside the diff, trail inside it
        _finding(4, 90, sev="low"),                                 # outside the diff: summary only
        _finding(5, 1, file="gone.py"),                             # removed file: summary only
    ]
    code = _run(tmp_path, env, findings, "--fail-on", "high")
    assert code == 1
    assert len(fake.reviews) == 1
    review = fake.reviews[0]
    assert review["event"] == "COMMENT" and review["commit_id"] == "abc123"
    spots = [(c["path"], c["line"], c["side"]) for c in review["comments"]]
    assert spots == [("src/app.py", 2, "RIGHT"), ("src/app.py", 3, "RIGHT"), ("src/app.py", 4, "RIGHT")]
    first = review["comments"][0]["body"]
    assert "DF002" in first and "HIGH" in first and "Do not pass input to a shell." in first
    assert "[CWE-78](https://cwe.mitre.org/data/definitions/78.html)" in first
    assert "<!-- kashif:fp=0000000000000001:0 -->" in first
    trail_body = review["comments"][1]["body"]
    assert "Data-flow trail" in trail_body and "`src/app.py:40`" in trail_body and "Sink: os.system" in trail_body
    assert all(r["auth"] == f"Bearer {TOKEN}" and r["version"] == "2022-11-28" for r in fake.requests)
    assert len(fake.issue_comments) == 1
    summary = fake.issue_comments[0]["body"]
    assert summary.startswith(github_pr.SUMMARY_MARKER)
    assert "5 new findings" in summary and "src/app.py:90" in summary and "the check fails" in summary
    assert "https://github.com/o/r/blob/abc123/src/app.py#L90" in summary
    assert pathlib.Path(env["GITHUB_STEP_SUMMARY"]).read_text(encoding="utf-8").count(github_pr.SUMMARY_MARKER) == 1
    assert "findings=5" in pathlib.Path(env["GITHUB_OUTPUT"]).read_text(encoding="utf-8")
    out = capsys.readouterr()
    assert TOKEN not in out.out + out.err


def test_files_pagination_is_followed(tmp_path, fake):
    fake.files = [{"filename": "src/a.py", "status": "added", "patch": "@@ -0,0 +1 @@\n+x"},
                  {"filename": "src/app.py", "status": "modified", "patch": "@@ -1 +1 @@\n-a\n+b"}]
    _run(tmp_path, _env(tmp_path, fake), [_finding(1, 1)])
    assert [r["query"] for r in fake.requests if r["path"].endswith("/files")] == ["per_page=100",
                                                                                  "per_page=100&page=2"]
    assert fake.reviews[0]["comments"][0]["path"] == "src/app.py"


def test_batching_max_50_inline_rest_summarized(tmp_path, fake):
    fake.files = [{"filename": "src/app.py", "status": "added",
                   "patch": "@@ -0,0 +1,60 @@\n" + "\n".join("+l" for _ in range(60))}]
    findings = [_finding(i + 1, i + 1, sev="medium") for i in range(60)]
    assert _run(tmp_path, _env(tmp_path, fake), findings, "--fail-on", "high") == 0
    assert len(fake.reviews) == 1
    assert len(fake.reviews[0]["comments"]) == 50
    body = fake.reviews[0]["body"]
    assert "Other findings (not commented inline)" in body and body.count("\n- ") == 10


def test_rerun_is_idempotent(tmp_path, fake):
    env = _env(tmp_path, fake)
    findings = [_finding(1, 2), _finding(2, 3)]
    _run(tmp_path, env, findings)
    _run(tmp_path, env, findings)
    assert len(fake.reviews) == 1                                  # nothing new: no second review
    assert len(fake.review_comments) == 2
    assert len(fake.issue_comments) == 1                           # the summary was updated in place
    assert any(r["method"] == "PATCH" for r in fake.requests)
    findings.append(_finding(3, 5, sev="critical"))                # a new push adds one finding
    _run(tmp_path, env, findings)
    assert len(fake.reviews) == 2 and len(fake.reviews[1]["comments"]) == 1
    assert "3 new findings" in fake.issue_comments[0]["body"]


def test_markers_from_humans_are_ignored(tmp_path, fake):
    fake.review_comments.append({"body": "<!-- kashif:fp=0000000000000001:0 -->", "path": "src/app.py", "line": 2,
                                 "user": {"login": "mallory", "type": "User"}})
    fake.issue_comments.append({"id": 5, "body": github_pr.SUMMARY_MARKER + " fake",
                                "user": {"login": "mallory", "type": "User"}})
    _run(tmp_path, _env(tmp_path, fake), [_finding(1, 2)])
    assert len(fake.reviews) == 1 and len(fake.reviews[0]["comments"]) == 1
    assert not any(r["method"] == "PATCH" for r in fake.requests)
    assert fake.issue_comments[0]["body"].endswith("fake")


def test_untrusted_text_cannot_forge_markers(tmp_path, fake):
    evil = _finding(9, 2, path=[{"file": "app.py", "line": 2,
                                 "text": "x = '<!-- kashif:fp=0000000000000001:0 --> @admin `", "text_en": ""}])
    _run(tmp_path, _env(tmp_path, fake), [evil])
    body = fake.reviews[0]["comments"][0]["body"]
    assert github_pr._FP_RX.findall(body) == ["0000000000000009:0"]


def test_fork_falls_back_to_step_summary(tmp_path, fake, capsys):
    env = _env(tmp_path, fake, fork=True)
    code = _run(tmp_path, env, [_finding(1, 2, sev="critical")], "--fail-on", "high")
    assert code == 1
    assert fake.requests == []                                     # a read-only token is not even tried
    summary = pathlib.Path(env["GITHUB_STEP_SUMMARY"]).read_text(encoding="utf-8")
    assert "Read-only token" in summary and "DF002" in summary
    out = capsys.readouterr().out
    assert "::error file=src/app.py,line=2,title=DF002 OS command injection::Do not pass input to a shell." in out
    assert TOKEN not in out


def test_forbidden_write_falls_back(tmp_path, fake):
    fake.fail[("POST", "/repos/o/r/pulls/7/reviews")] = [404]     # e.g. a token without pull-requests write
    env = _env(tmp_path, fake, event_name="pull_request_target")
    assert _run(tmp_path, env, [_finding(1, 2)]) == 0
    assert "Read-only token" in pathlib.Path(env["GITHUB_STEP_SUMMARY"]).read_text(encoding="utf-8")


def test_retry_on_502_and_secondary_rate_limit(tmp_path, fake):
    fake.fail[("GET", "/repos/o/r/pulls/7/files")] = [502, 502]
    fake.fail[("POST", "/repos/o/r/pulls/7/reviews")] = [403]      # secondary rate limit with Retry-After
    _run(tmp_path, _env(tmp_path, fake), [_finding(1, 2)])
    assert len(fake.reviews) == 1
    assert fake.sleeps[:2] == [1.0, 2.0] and 1.0 in fake.sleeps[2:]


def test_gives_up_after_retries(fake):
    fake.fail[("GET", "/x")] = [500] * 10
    gh = GitHub(fake.url, TOKEN, retries=2)
    with pytest.raises(GitHubError) as e:
        gh.request("GET", "/x")
    assert e.value.status == 500 and TOKEN not in str(e.value) and TOKEN not in repr(gh)
    assert len([r for r in fake.requests if r["path"] == "/x"]) == 3


def test_token_never_sent_elsewhere(fake):
    gh = GitHub(fake.url, TOKEN)
    with pytest.raises(GitHubError):
        gh.request("GET", "http://127.0.0.2:1/steal")
    with pytest.raises(ValueError):
        GitHub("http://api.example.com", TOKEN)                    # plain http only on loopback


def test_summary_mode_and_arabic(tmp_path, fake):
    _run(tmp_path, _env(tmp_path, fake), [_finding(1, 2)], "--comment-mode", "summary", "--lang", "ar")
    assert fake.reviews == []
    body = fake.issue_comments[0]["body"]
    assert "كاشِف" in body and "حقن أوامر" in body and SEVERITY_AR["high"] in body


def test_no_findings_and_mode_none(tmp_path, fake):
    env = _env(tmp_path, fake)
    assert _run(tmp_path, env, [], "--fail-on", "low") == 0
    assert fake.reviews == [] and "No new findings" in fake.issue_comments[0]["body"]
    fake.requests.clear()
    _run(tmp_path, env, [_finding(1, 2)], "--comment-mode", "none")
    assert fake.requests == []


def test_commentable_lines():
    assert commentable_lines("@@ -1,3 +1,4 @@\n a\n+b\n-c\n d\n\\ No newline at end of file\n@@ -9 +10,2 @@\n+x\n+y") \
        == {1, 2, 3, 10, 11}
    assert commentable_lines(None) == set()


def test_rebase_sarif(tmp_path):
    sarif = {"runs": [{"originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///x/"}},
                       "results": [{"locations": [{"physicalLocation": {"artifactLocation": {
                           "uri": "a%20b.py", "uriBaseId": "%SRCROOT%"}}}],
                           "codeFlows": [{"threadFlows": [{"locations": [{"location": {"physicalLocation": {
                               "artifactLocation": {"uri": "c.py", "uriBaseId": "%SRCROOT%"}}}}]}]}]},
                          {"locations": [{"physicalLocation": {"artifactLocation": {"uri": "https://e.x/"}}}]}]}]}
    p = tmp_path / "r.sarif"
    p.write_text(json.dumps(sarif))
    assert rebase_sarif(str(p), "svc/api") == 2
    out = json.loads(p.read_text(encoding="utf-8"))["runs"][0]
    assert "originalUriBaseIds" not in out
    assert out["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] == {"uri": "svc/api/a%20b.py"}
    tf = out["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"][0]["location"]["physicalLocation"]
    assert tf["artifactLocation"]["uri"] == "svc/api/c.py"
    assert out["results"][1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "https://e.x/"


# ---------------------------------------------------------------- end to end: scan -> PR review

@needs_git
def test_end_to_end_scan_to_review(repo, tmp_path, fake):
    base = _git(repo, "rev-parse", "HEAD")
    _copy("added_vuln.py", repo, "added.py")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "change")
    report = tmp_path / "k.json"
    main([str(repo), *SCAN, "-o", str(report), "--diff-base", base])
    found = json.loads(report.read_text(encoding="utf-8"))["findings"]
    lines = sorted({f["line"] for f in found})
    n = len((DATA / "added_vuln.py").read_text(encoding="utf-8").splitlines())
    fake.files = [{"filename": "added.py", "status": "added",
                   "patch": f"@@ -0,0 +1,{n} @@\n" + "\n".join("+x" for _ in range(n))}]
    env = {**_env(tmp_path, fake), "GITHUB_WORKSPACE": str(repo)}
    code = github_pr.main(["--report", str(report), "--scan-root", ".", "--fail-on", "high"], env=env)
    assert code == 1
    assert sorted(c["line"] for c in fake.reviews[0]["comments"]) == sorted(f["line"] for f in found)
    assert lines and all(c["path"] == "added.py" for c in fake.reviews[0]["comments"])


# ---------------------------------------------------------------- packaging files

def _run_blocks(text: str) -> list[str]:
    blocks, cur, indent = [], None, 0
    for line in text.splitlines():
        m = re.match(r"^(\s*)run: \|\s*$", line)
        if m:
            cur, indent = [], len(m.group(1))
            blocks.append(cur)
            continue
        if cur is not None:
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                cur = None
            else:
                cur.append(line)
                continue
        m = re.match(r"^\s*run: (.+)$", line)
        if m:
            blocks.append([m.group(1)])
    return ["\n".join(b) for b in blocks]


def test_action_yml_is_hardened():
    text = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert re.search(r"^name: Kashif SAST$", text, re.M) and "using: composite" in text
    for name in ("path", "fail-on", "min-severity", "diff-base", "language", "comment-mode", "upload-sarif", "audit"):
        assert re.search(rf"^  {re.escape(name)}:$", text, re.M), name
    assert "default: ${{ github.event.pull_request.base.sha }}" in text
    uses = re.findall(r"uses: (\S+)", text)
    assert uses and all(re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", u) for u in uses), uses
    workflows = "".join(p.read_text(encoding="utf-8") for p in (ROOT / ".github" / "workflows").glob("*.yml"))
    assert all(u in workflows for u in uses)                       # the same pinned SHAs as the repo's workflows
    blocks = _run_blocks(text)
    assert len(blocks) >= 5
    assert all("${{" not in b for b in blocks), "inputs must reach run scripts through env"
    assert "github.action_path" in text and "vulnscan.integrations.github_pr" in text


def test_pre_commit_hook():
    text = (ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
    assert "id: kashif" in text and "pass_filenames: false" in text
    for flag in ("--diff-staged", "--fail-on", "high", "--no-deps", "--no-external"):
        assert flag in text


# ---------------------------------------------------------------- adversarial checks

def test_forged_diff_headers_in_changed_code_do_not_hide_later_hunks():
    """An added line "++ b/decoy.py" shows as "+++ b/decoy.py"; a lone CR or U+2028 inside a changed line must not
    split it into a forged header either. Hunk bodies are consumed by their counts."""
    text = "\n".join([
        "diff --git a/app.py b/app.py", "--- a/app.py", "+++ b/app.py",
        "@@ -3 +3,3 @@", "-x3 = 3", '+s = """', "+++ b/decoy.py", '+"""',
        "@@ -9 +11 @@", '-x9 = 9', '+z = "a\rdiff --git a/q b/q @@ -1 +900 @@"',
        "@@ -31 +33 @@", "-x31 = 31", "+os.system(input())",
        "\\ No newline at end of file",
        "diff --git a/b.py b/b.py", "--- a/b.py", "+++ b/b.py", "@@ -1,3 +1,3 @@ ctx", "-a", "+A", " keep", "-c", "+C",
    ])
    changed, _, _ = parse_unified_diff(text)
    assert changed == {"app.py": {3, 4, 5, 11, 33}, "b.py": {1, 2, 3}}


@needs_git
def test_diff_edge_cases_with_real_git(tmp_path):
    r = tmp_path / "edge"
    r.mkdir()
    _git(r, "init", "-q")
    for k, v in (("diff.mnemonicPrefix", "true"), ("diff.interHunkContext", "3"), ("diff.relative", "true")):
        _git(r, "config", k, v)                                    # user config must not change the parse
    files = {"app.py": "".join(f"x{i} = {i}\n" for i in range(1, 40)), "my file.py": "a = 1\n", "ملف.py": "a = 1\n",
             "noeol.py": "a = 1\nb = 2", "ren_old.py": "".join(f"r{i} = {i}\n" for i in range(20)), "gone.py": "g = 1\n"}
    for name, text in files.items():
        (r / name).write_text(text, encoding="utf-8")
    (r / "crlf.py").write_bytes(b"a = 1\r\nb = 2\r\n")
    (r / "img.bin").write_bytes(bytes(range(256)))
    (r / "gone.bin").write_bytes(b"\0\1")
    _git(r, "add", ".")
    _git(r, "commit", "-q", "-m", "base")
    base = _git(r, "rev-parse", "HEAD")
    lines = files["app.py"].splitlines(True)
    lines[2] = 's = """\n++ b/decoy.py\n"""\n'
    lines[30] = "import os; os.system(input())\n"
    (r / "app.py").write_text("".join(lines), encoding="utf-8")
    with open(r / "my file.py", "a", encoding="utf-8") as fh:
        fh.write("b = 2\n")
    with open(r / "ملف.py", "a", encoding="utf-8") as fh:
        fh.write("b = 2\n")
    with open(r / "crlf.py", "ab") as fh:
        fh.write(b"c = 3\r\n")
    (r / "noeol.py").write_text("a = 1\nb = 3", encoding="utf-8")
    (r / "ren_old.py").rename(r / "ren_new.py")
    with open(r / "ren_new.py", "a", encoding="utf-8") as fh:
        fh.write("added = 1\n")
    (r / "gone.py").unlink()
    (r / "gone.bin").unlink()
    (r / "img.bin").write_bytes(bytes(range(255, -1, -1)))
    (r / "new.bin").write_bytes(b"\0\1\2")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "change")
    s = compute(r, base)
    assert s.changed == {"app.py": {3, 4, 5, 33}, "my file.py": {2}, "ملف.py": {2}, "crlf.py": {3},
                         "noeol.py": {2}, "ren_new.py": {21}}
    assert s.whole == {"img.bin", "new.bin"}                       # changed and new binaries; deleted ones are gone
    assert s.near == {}


@needs_git
def test_base_not_an_ancestor_and_shallow_clone(repo, tmp_path, capsys):
    base = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "--orphan", "other")              # unrelated history: no merge-base
    _git(repo, "commit", "-q", "-m", "orphan")
    s = compute(repo, "main")
    assert s.base_commit == base and any("merge-base" in n or "نقطة التفرّع" in n for n in s.notes)
    _git(repo, "checkout", "-q", "main")
    _copy("added_vuln.py", repo, "added.py")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "change")
    shallow = tmp_path / "shallow"
    subprocess.run([GIT, "clone", "-q", "--depth", "1", repo.as_uri(), str(shallow)], check=True, capture_output=True)
    capsys.readouterr()
    code = main([str(shallow), *SCAN, "-o", str(tmp_path / "s.json"), "--diff-base", base])
    assert code == 2 and "Ref not found in the repository" in capsys.readouterr().err   # clear error, no traceback
    subprocess.run([GIT, "-C", str(shallow), "fetch", "-q", "--depth=1", "origin", "--", base], check=True,
                   capture_output=True)
    code, found, notes = _scan(shallow, "--diff-base", base, out=tmp_path / "s.json")
    assert found and {f["file"] for f in found} == {"added.py"}
    assert any("shallow clone" in n for n in notes)


def test_existing_comments_are_paginated(tmp_path, fake):
    fake.comment_page_size = 30
    for i in range(70):                                            # the marker of finding 1 is on page 3
        fake.review_comments.append({"body": f"<!-- kashif:fp={i + 100:016x}:0 -->", "path": "src/app.py",
                                     "line": 2, "user": {"login": "github-actions[bot]", "type": "Bot"}})
    fake.review_comments.append({"body": "<!-- kashif:fp=0000000000000001:0 -->", "path": "src/app.py", "line": 2,
                                 "user": {"login": "github-actions[bot]", "type": "Bot"}})
    _run(tmp_path, _env(tmp_path, fake), [_finding(1, 2)])
    pages = [r["query"] for r in fake.requests if r["path"] == "/repos/o/r/pulls/7/comments"]
    assert pages == ["per_page=100", "per_page=100&page=2", "per_page=100&page=3"]
    assert fake.reviews == []                                      # already commented: nothing new


def test_review_422_falls_back_to_summary(tmp_path, fake):
    fake.fail[("POST", "/repos/o/r/pulls/7/reviews")] = [422]     # a line left the diff after a new push
    env = _env(tmp_path, fake)
    assert _run(tmp_path, env, [_finding(1, 2, sev="critical")], "--fail-on", "high") == 1
    assert fake.reviews == []
    summary = fake.issue_comments[0]["body"]
    assert "1 new finding in" in summary and "💬" not in summary
    assert "inline-comments=0" in pathlib.Path(env["GITHUB_OUTPUT"]).read_text(encoding="utf-8")


def test_secondary_rate_limit_honours_retry_after(fake):
    fake.fail[("GET", "/rl")] = [403, 429]
    gh = GitHub(fake.url, TOKEN)
    with pytest.raises(GitHubError) as e:                          # the fake answers 404 once the queue is empty
        gh.request("GET", "/rl")
    assert e.value.status == 404 and fake.sleeps == [1.0, 1.0]
    fake.sleeps.clear()
    fake.fail[("GET", "/ro")] = [403]                              # a 403 without rate-limit signs is final
    gh2 = GitHub(fake.url, TOKEN)
    gh2._rate_limited = lambda *a: False
    with pytest.raises(GitHubError) as e:
        gh2.request("GET", "/ro")
    assert e.value.status == 403 and fake.sleeps == []


def test_ghes_api_url(tmp_path, fake):
    fake.prefix = "/api/v3"
    env = {**_env(tmp_path, fake), "GITHUB_API_URL": fake.url + "/api/v3/",
           "GITHUB_SERVER_URL": "https://ghes.example.com"}
    fake.files = [{"filename": "src/a.py", "status": "added", "patch": "@@ -0,0 +1 @@\n+x"},
                  {"filename": "src/app.py", "status": "modified", "patch": "@@ -1 +1,2 @@\n-a\n+b\n+c"}]
    _run(tmp_path, env, [_finding(1, 2)])
    assert len(fake.reviews) == 1 and fake.reviews[0]["comments"][0]["line"] == 2
    assert "https://ghes.example.com/o/r/blob/abc123/src/app.py" in fake.issue_comments[0]["body"]
    assert len([r for r in fake.requests if r["path"].endswith("/files")]) == 2      # pagination kept the prefix


def test_non_json_answer_is_handled_without_leaking_the_token(tmp_path, fake, capsys):
    fake.html.add(("GET", "/repos/o/r/pulls/7/files"))
    env = _env(tmp_path, fake)
    assert _run(tmp_path, env, [_finding(1, 2)]) == 0
    out = capsys.readouterr()
    assert "something other than JSON" in out.err and TOKEN not in out.out + out.err
    assert "DF002" in pathlib.Path(env["GITHUB_STEP_SUMMARY"]).read_text(encoding="utf-8")


def test_unreachable_api_is_handled(tmp_path, fake, capsys):
    env = {**_env(tmp_path, fake), "GITHUB_API_URL": "http://127.0.0.1:1"}
    assert _run(tmp_path, env, [_finding(1, 2)]) == 0
    out = capsys.readouterr()
    assert "GitHub API 0" in out.err and TOKEN not in out.out + out.err


def test_action_validates_diff_base_and_stops_workflow_commands():
    text = (ROOT / "action.yml").read_text(encoding="utf-8")
    check = next(b for b in _run_blocks(text) if "invalid input path" in b)
    assert "invalid input diff-base" in check
    # On Windows "bash" may resolve to the WSL launcher rather than Git Bash; the action's run steps execute on
    # Linux/macOS runners, so the shell check runs there.
    if shutil.which("bash") and sys.platform != "win32":
        line = next(ln for ln in check.splitlines() if "diff-base" in ln).strip()
        for value, ok in (("", True), ("origin/main", True), ("0" * 40, True), ("v1^{commit}", True),
                          ("-x", False), ("a..b", False), ("a b", False), ("x@{1}", False), ("$(id)", False)):
            script = f'fail() {{ exit 3; }}\n{line}\nexit 0'
            res = subprocess.run(["bash", "-c", script], env={**os.environ, "DIFF_BASE": value}, check=False)
            assert (res.returncode == 0) == ok, value
    scan = next(b for b in _run_blocks(text) if "-m vulnscan \"${args[@]}\"" in b)
    assert "::stop-commands::" in scan and scan.index("::stop-commands::") < scan.index('-m vulnscan "${args[@]}"')
    assert scan.index('-m vulnscan "${args[@]}"') < scan.index('echo "::$stop::"')
