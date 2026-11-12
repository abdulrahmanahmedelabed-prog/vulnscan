"""Secrets in git history (vulnscan.history).

Every token-shaped string is built at run time: no credential-shaped literal may be committed
(tests/test_no_secret_literals.py)."""

import json
import os
import pathlib
import shutil
import string
import subprocess
import sys
import time

import pytest

from vulnscan import history
from vulnscan.model import Finding

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

_ALNUM = string.ascii_letters + string.digits


def _rand(n: int, seed: int, alphabet: str = _ALNUM) -> str:
    """Deterministic pseudo-random text (no secrets module: the tests must be reproducible)."""
    out, x = [], seed * 2654435761 % 2**32 or 1
    for _ in range(n):
        x = (x * 1103515245 + 12345) % 2**31
        out.append(alphabet[(x >> 8) % len(alphabet)])
    return "".join(out)


def gh_token(seed: int = 1) -> str:
    return "gh" + "p_" + _rand(36, seed)


def aws_key(seed: int = 2) -> str:
    return "AK" + "IA" + _rand(16, seed, string.ascii_uppercase + string.digits)


def pem_header() -> str:
    return "-----BEGIN " + "RSA PRIVATE" + " KEY-----"


ENV = {**os.environ, "GIT_AUTHOR_NAME": "Dev One", "GIT_AUTHOR_EMAIL": "dev1@example.org",
       "GIT_COMMITTER_NAME": "Dev One", "GIT_COMMITTER_EMAIL": "dev1@example.org",
       "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def git(repo, *args, date=None, stdin=None):
    env = dict(ENV)
    if date:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
    p = subprocess.run(["git", "-C", str(repo), *args], env=env, input=stdin, capture_output=True, check=True)
    return p.stdout.decode().strip()


def commit(repo, msg, day):
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", msg, date=f"2024-01-{day:02d}T10:00:00+00:00")
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture()
def repo(tmp_path):
    """c1 adds a GitHub token (config.py) and an AWS key (deploy.sh); c2 removes the GitHub token;
    c3 renames deploy.sh; c4 adds a binary file and a private key; c5 deletes the key file."""
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    tok, aws = gh_token(), aws_key()
    (r / "config.py").write_text(f'import os\nGITHUB = "{tok}"\nDEBUG = False\n')
    (r / "deploy.sh").write_text(f"#!/bin/sh\nexport AWS_ACCESS_KEY_ID={aws}\necho deploying\n")
    c1 = commit(r, "initial", 1)
    (r / "config.py").write_text('import os\nGITHUB = os.environ["GITHUB"]\nDEBUG = False\n')
    c2 = commit(r, "use env", 2)
    (r / "scripts").mkdir()
    git(r, "mv", "deploy.sh", "scripts/release.sh")
    c3 = commit(r, "move script", 3)
    (r / "blob.bin").write_bytes(b"\x00\x01\x02" + tok.encode() + b"\x00" * 50)
    body = [_rand(64, 10 + i, _ALNUM + "+/") for i in range(4)]
    (r / "id_rsa").write_text(pem_header() + "\n" + "\n".join(body) + "\n-----END " + "RSA PRIVATE" + " KEY-----\n")
    c4 = commit(r, "add key", 4)
    (r / "id_rsa").unlink()
    c5 = commit(r, "drop key", 5)
    return {"path": r, "tok": tok, "aws": aws, "commits": [c1, c2, c3, c4, c5], "key_body": body}


def by_rule(result, prefix):
    return [f for f in result.findings if f.rule_id == prefix or f.extra.get("secret_redacted", "").startswith(prefix)]


def test_detects_removed_and_present(repo):
    res = history.scan_history(repo["path"])
    c1, c2, c3, c4, c5 = repo["commits"]
    assert res.commits_scanned == 5 and res.head == c5
    assert all(isinstance(f, Finding) and f.source == "git-history" for f in res.findings)

    gh = [f for f in res.findings if f.extra["secret_redacted"] == history.redact(repo["tok"])]
    assert len(gh) == 1, [f.to_dict() for f in res.findings]
    g = gh[0]
    assert g.file == "config.py" and g.line == 2 and g.rule_id.startswith("SEC")
    assert g.extra["commit"] == c1 and g.extra["date"].startswith("2024-01-01")
    assert g.extra["author"] == "Dev One"
    assert g.extra["still_present"] is False and g.extra["status"] == "removed"
    assert g.extra["removed_in"]["commit"] == c2

    aws = [f for f in res.findings if f.extra["secret_redacted"] == history.redact(repo["aws"])]
    assert len(aws) == 1
    a = aws[0]
    assert a.file == "deploy.sh" and a.extra["commit"] == c1
    assert a.extra["still_present"] is True and a.extra["status"] == "present"      # followed through the rename
    assert a.extra["head_file"] == "scripts/release.sh" and a.extra["head_line"] == 2
    assert a.extra["removed_in"] is None

    key = [f for f in res.findings if f.rule_id == "SEC001"]
    assert len(key) == 1
    assert key[0].file == "id_rsa" and key[0].extra["commit"] == c4
    assert key[0].extra["status"] == "removed" and key[0].extra["removed_in"]["commit"] == c5
    assert len(res.present) == 1 and len(res.removed) == len(res.findings) - 1
    # the token inside the binary file is not reported a second time
    assert all(f.file != "blob.bin" for f in res.findings)


def test_never_prints_the_secret(repo):
    res = history.scan_history(repo["path"])
    secrets = [repo["tok"], repo["aws"]] + repo["key_body"]
    for lang in ("en", "ar"):
        blob = history.render_json(res, lang) + history.render_console(res, lang)
        for s in secrets:
            assert s not in blob
        assert repo["tok"][:4] + "****" + repo["tok"][-4:] in blob
    doc = json.loads(history.render_json(res))
    assert doc["stats"]["secrets"] == len(res.findings) and doc["stats"]["still_present"] == 1
    assert doc["remediation"]["en"][0].startswith("1. Rotate") and doc["remediation"]["ar"]
    for f in doc["findings"]:
        assert f["fingerprint"] and f["extra"]["commit_short"]
    assert "****" in history.redact("x" * 8) and len(history.redact("a" * 40)) == 12
    assert history.redact("short") == "****"


def test_fingerprints_stable_and_secret_free(repo):
    a = history.scan_history(repo["path"])
    b = history.scan_history(repo["path"])
    fa = [f.fingerprint() for f in a.findings]
    assert fa == [f.fingerprint() for f in b.findings] and len(set(fa)) == len(fa)
    da, db = history.result_to_dict(a), history.result_to_dict(b)
    for d in (da, db):
        d["stats"].pop("elapsed")
    assert da == db                                            # deterministic
    for f in a.findings:                                       # identity is built from redacted text only
        assert repo["tok"] not in f.snippet and repo["aws"] not in f.snippet


def test_window_options(repo):
    c1, c2, c3, c4, c5 = repo["commits"]
    res = history.scan_history(repo["path"], max_commits=2)
    assert res.commits_scanned == 2
    assert [f.rule_id for f in res.findings] == ["SEC001"]
    assert any("--max-commits" in n for n in res.notes_text("en"))
    res = history.scan_history(repo["path"], since="2024-01-03T12:00:00+00:00")
    assert res.commits_scanned == 2 and [f.rule_id for f in res.findings] == ["SEC001"]
    res = history.scan_history(repo["path"], until="2024-01-01T12:00:00+00:00")
    assert res.commits_scanned == 1 and len(res.findings) == 2
    assert all(f.extra["status"] != "removed" for f in res.findings)
    res = history.scan_history(repo["path"], excludes=["*.sh", "id_rsa"])
    assert len(res.findings) == 1 and res.findings[0].file == "config.py"


def test_branches(repo):
    r = repo["path"]
    other = gh_token(77)
    git(r, "checkout", "-q", "-b", "feature")
    (r / "feature.env").write_text(f"TOKEN={other}\n")
    commit(r, "feature secret", 6)
    git(r, "checkout", "-q", "main")
    red = history.redact(other)
    everything = history.scan_history(r)
    hit = [f for f in everything.findings if f.extra["secret_redacted"] == red]
    assert len(hit) == 1 and hit[0].extra["status"] == "not-at-head"
    only_main = history.scan_history(r, branches=["main"])
    assert not [f for f in only_main.findings if f.extra["secret_redacted"] == red]
    with pytest.raises(history.HistoryError):
        history.scan_history(r, branches=["--output=/tmp/x"])


def test_unreachable_objects(repo):
    r = repo["path"]
    lost = gh_token(99)
    (r / "staged.txt").write_text(f"token = '{lost}'\n")
    git(r, "add", "staged.txt")
    git(r, "rm", "-q", "--cached", "staged.txt")           # the blob stays in the object store, unreferenced
    (r / "staged.txt").unlink()
    red = history.redact(lost)
    assert not [f for f in history.scan_history(r).findings if f.extra["secret_redacted"] == red]
    res = history.scan_history(r, include_unreachable=True)
    hit = [f for f in res.findings if f.extra["secret_redacted"] == red]
    assert len(hit) == 1 and hit[0].extra["unreachable"] is True and hit[0].extra["commit"] == ""
    assert lost not in history.render_console(res)
    assert not (r / ".git" / "lost-found").exists()        # the repository is not modified


def test_suppression_and_same_secret_twice(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    tok, hidden = gh_token(5), gh_token(6)
    (r / "a.txt").write_text(f"one {tok}\n")
    (r / "b.txt").write_text(f"two {tok}\nx = '{hidden}'  # nosec\n")
    commit(r, "c", 1)
    res = history.scan_history(r)
    assert len(res.findings) == 1                           # one secret, two files, reported once
    f = res.findings[0]
    assert f.extra["occurrences"] == 2 and f.extra["files"] == ["a.txt", "b.txt"] and f.extra["still_present"]
    assert len(history.scan_history(r, honor_suppressions=False).findings) == 2


def test_errors_and_empty_repo(tmp_path):
    with pytest.raises(history.HistoryError) as e:
        history.scan_history(tmp_path)
    assert "not a git repository" in str(e.value)
    assert history.error_text(e.value, "ar") != str(e.value)
    assert history.main([str(tmp_path)]) == 2
    r = tmp_path / "empty"
    r.mkdir()
    git(r, "init", "-q")
    res = history.scan_history(r)
    assert res.findings == [] and res.head is None and res.commits_scanned == 0
    assert history.main([str(r)]) == 0


def test_cli(repo, tmp_path, capsys):
    out = tmp_path / "out.json"
    assert history.main([str(repo["path"]), "-f", "json", "-o", str(out), "--since", "2023-01-01"]) == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["tool"] == "kashif-history" and doc["stats"]["commits"] == 5
    assert repo["tok"] not in out.read_text(encoding="utf-8")
    assert history.main([str(repo["path"]), "--only", "present", "--lang", "ar", "--exit-zero"]) == 0
    text = capsys.readouterr().out
    assert "scripts/release.sh" in text and "config.py" not in text and repo["aws"] not in text
    assert history.STR["ar"]["present"] in text
    p = subprocess.run([sys.executable, "-m", "vulnscan.history", str(repo["path"]), "--max-commits", "1"],
                       capture_output=True, cwd=pathlib.Path(__file__).resolve().parent.parent)
    assert p.returncode in (0, 1) and b"Traceback" not in p.stderr


def test_strings_complete():
    assert set(history.STR["en"]) == set(history.STR["ar"])
    assert len(history.remediation("ar")) == len(history.remediation("en")) == 5


def test_performance_guard(tmp_path):
    """600 commits / ~40k changed lines (one huge line, one binary file) must stay fast and find the needle."""
    r = tmp_path / "big"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    needle = gh_token(123)
    stream = []
    n = 600
    for i in range(1, n + 1):
        lines = [f"def f_{i}_{j}(a, b):  return a * {j} + b  # row {i}" for j in range(60)]
        if i == 300:
            lines.insert(7, f'API = "{needle}"')
        if i == 10:
            lines.append("x" * 300000)                           # minified-style line: skipped, not buffered
        data = ("\n".join(lines) + "\n").encode()
        stream.append(b"commit refs/heads/main\nmark :%d\n" % i)
        stream.append(b"author Dev <dev@example.org> %d +0000\ncommitter Dev <dev@example.org> %d +0000\n"
                      % (1700000000 + i * 60, 1700000000 + i * 60))
        stream.append(b"data 5\nc %03d\n" % (i % 1000))
        if i > 1:
            stream.append(b"from :%d\n" % (i - 1))
        stream.append(b"M 644 inline src/mod_%d.py\ndata %d\n" % (i % 25, len(data)) + data)
        if i == 20:
            blob = b"\x00\x01" * 500
            stream.append(b"M 644 inline asset.dat\ndata %d\n" % len(blob) + blob + b"\n")
    git(r, "fast-import", "--quiet", stdin=b"".join(stream))
    t0 = time.monotonic()
    res = history.scan_history(r)
    took = time.monotonic() - t0
    assert res.commits_scanned == n and res.lines_scanned > 30000
    hits = [f for f in res.findings if f.extra["secret_redacted"] == history.redact(needle)]
    assert len(hits) == 1 and hits[0].extra["subject"] == "c 300" and hits[0].extra["status"] == "removed"
    assert took < 30, f"history scan too slow: {took:.1f}s"
    partial = history.scan_history(r, timeout=0.000001)
    assert partial.commits_scanned < n and any("partial" in t for t in partial.notes_text("en"))


# ------------------------------------------------------------------------------------------- adversarial review
def _new_repo(tmp_path, name="r"):
    r = tmp_path / name
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    return r


def test_redaction_shows_at_most_a_third():
    for n in range(0, 80):
        red = history.redact(_rand(n, n + 1))
        shown = len(red) - 4
        assert shown * 3 <= max(n, 1) or shown == 0, (n, red)
    assert history.redact(_rand(16, 3)).count("*") == 4 and len(history.redact(_rand(16, 3))) == 8


def test_hostile_repo_config_cannot_change_paths_or_run_programs(tmp_path):
    """.git/config is attacker-controlled: diff.noprefix must not corrupt paths (a present secret was reported as
    gone), and neither an external diff nor a partial-clone "remote" command may run."""
    r = _new_repo(tmp_path)
    tok = gh_token(41)
    (r / "a").mkdir()
    (r / "a" / "conf.py").write_text(f'T = "{tok}"\n', encoding="utf-8")
    commit(r, "c1", 1)
    (r / "a" / "other.py").write_text("x = 1\n", encoding="utf-8")
    commit(r, "c2", 2)
    marker = tmp_path / "PWNED"
    for key, value in (("diff.noprefix", "true"), ("diff.mnemonicPrefix", "true"), ("diff.relative", "true"),
                       ("color.ui", "always"), ("diff.external", f"touch {marker}"),
                       ("diff.submodule", "log"), ("core.pager", f"touch {marker}"),
                       ("core.fsmonitor", f"touch {marker}")):
        git(r, "config", key, value)
    res = history.scan_history(r)
    assert [(f.file, f.extra["status"], f.extra["head_file"]) for f in res.findings] == \
        [("a/conf.py", "present", "a/conf.py")]
    # a partial clone whose promisor "remote" is a command: git must not be allowed to contact (= execute) it
    blob = git(r, "rev-parse", "HEAD:a/other.py")
    obj = r / ".git" / "objects" / blob[:2] / blob[2:]
    if obj.exists():
        obj.chmod(0o644)                        # git writes objects read-only; Windows refuses to delete those
        obj.unlink()
        git(r, "config", "extensions.partialClone", "origin")
        git(r, "config", "remote.origin.promisor", "true")
        git(r, "config", "remote.origin.url", f"ext::sh -c touch% {marker}")
        git(r, "config", "protocol.ext.allow", "always")
        try:
            history.scan_history(r)
        except history.HistoryError:
            pass                                            # the object is missing: an honest error is fine
    assert not marker.exists()
    env = history._git_env()
    assert env["GIT_ALLOW_PROTOCOL"] == "" and env["GIT_NO_LAZY_FETCH"] == "1"


def test_inherited_git_dir_does_not_redirect(tmp_path, monkeypatch):
    """Run from a git hook, GIT_DIR points at the hook's repository: the repository named must still be scanned."""
    a, b = _new_repo(tmp_path, "a"), _new_repo(tmp_path, "b")
    ta, tb = gh_token(51), gh_token(52)
    (a / "a.py").write_text(f'T = "{ta}"\n', encoding="utf-8")
    commit(a, "a", 1)
    (b / "b.py").write_text(f'T = "{tb}"\n', encoding="utf-8")
    commit(b, "b", 1)
    monkeypatch.setenv("GIT_DIR", str(a / ".git"))
    monkeypatch.setenv("GIT_INDEX_FILE", str(a / ".git" / "index"))
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", "false")
    assert [f.file for f in history.scan_history(b).findings] == ["b.py"]


def test_secret_in_many_files_still_found_at_head(tmp_path):
    """Only 20 file names are listed, but every path must be checked at HEAD (was: falsely 'removed')."""
    r = _new_repo(tmp_path)
    tok = gh_token(61)
    for i in range(30):
        (r / f"f{i:02d}.py").write_text(f'T = "{tok}"\n', encoding="utf-8")
    commit(r, "c1", 1)
    for i in range(29):
        (r / f"f{i:02d}.py").unlink()
    commit(r, "c2", 2)
    (f,) = history.scan_history(r).findings
    assert f.extra["status"] == "present" and f.extra["head_file"] == "f29.py" and len(f.extra["files"]) == 20
    assert f.extra["occurrences"] == 30


def test_timeout_inside_one_huge_commit(tmp_path):
    r = _new_repo(tmp_path)
    with open(r / "big.py", "w", encoding="utf-8") as fh:
        for i in range(250000):
            fh.write(f"value_{i} = compute({i}, 'row')\n")
    commit(r, "big", 1)
    t0 = time.monotonic()
    res = history.scan_history(r, timeout=0.2)
    assert time.monotonic() - t0 < 5 and res.lines_scanned < 250000
    assert any("partial" in t for t in res.notes_text("en"))


@pytest.mark.skipif(os.name == "nt", reason="file names with control characters cannot be created on Windows")
def test_console_neutralises_terminal_escapes_and_odd_names(tmp_path):
    r = _new_repo(tmp_path)
    t1, t2, t3 = gh_token(71), gh_token(72), gh_token(73)
    (r / "evil\x1b[2Jname.py").write_text(f'T = "{t1}"  # \x1b]0;owned\x07 ‮\n', encoding="utf-8")
    (r / 'q"uote\tتجربة.py').write_text(f'T = "{t2}"\r\n', encoding="utf-8")
    (r / "latin1.py").write_bytes(b"# caf\xe9 \xff\n" + f'T = "{t3}"\n'.encode())
    env = dict(ENV, GIT_AUTHOR_NAME="Ev\x1b[31mil")
    subprocess.run(["git", "-C", str(r), "add", "-A"], env=env, check=True, capture_output=True)
    subprocess.run(["git", "-C", str(r), "commit", "-q", "-m", "s\x1b[5mubject"], env=env, check=True,
                   capture_output=True)
    res = history.scan_history(r)
    assert sorted(f.file for f in res.findings) == sorted(["evil\x1b[2Jname.py", 'q"uote\tتجربة.py', "latin1.py"])
    assert all(f.extra["status"] == "present" for f in res.findings)          # quoted names resolve at HEAD
    for lang in ("en", "ar"):
        text = history.render_console(res, lang)
        assert "\x1b" not in text and "\x07" not in text and "‮" not in text and "\r" not in text
    assert all("\x1b" not in f.snippet for f in res.findings)
    json.loads(history.render_json(res))


def test_private_key_line_and_putty_marker(tmp_path):
    r = _new_repo(tmp_path)
    chunks = [_rand(64, 81, _ALNUM + "+/"), "A" * 64, _rand(64, 82, _ALNUM + "+/")]
    one_line = 'KEY="' + pem_header() + "\\n" + "\\n".join(chunks) + '\\n-----END"'
    (r / "env.sh").write_text(one_line + "\n", encoding="utf-8")
    for name in ("one.ppk", "two.ppk"):                       # two different keys must stay two findings
        (r / name).write_text("PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\n", encoding="utf-8")
    commit(r, "keys", 1)
    res = history.scan_history(r)
    key = [f for f in res.findings if f.file == "env.sh"]
    assert len(key) == 1 and not any(c in key[0].snippet for c in chunks)      # low-entropy chunk masked too
    putty = [f for f in res.findings if f.file.endswith(".ppk")]
    assert sorted(f.file for f in putty) == ["one.ppk", "two.ppk"]
    assert all(f.extra["secret_redacted"] == "" for f in putty)


def test_long_lines_are_reported_and_removals_bounded(tmp_path):
    r = _new_repo(tmp_path)
    tok = gh_token(91)
    (r / "min.py").write_text("x = '" + "a" * 6000 + "'\n" + f'T = "{tok}"\n', encoding="utf-8")
    commit(r, "c1", 1)
    (r / "min.py").write_text("x = 1\n", encoding="utf-8")
    commit(r, "c2", 2)
    res = history.scan_history(r)
    assert any("6000" not in t and "longer than" in t for t in res.notes_text("en"))
    (f,) = res.findings
    assert f.extra["status"] == "removed" and f.extra["removed_in"]["commit"] == git(r, "rev-parse", "HEAD")
    # a removal seen without its addition (window) must not be stored
    w = history._Walker(True, True, [], 10)
    w.removed(history._Hit("SEC003", "critical", "t", "t", "a", "CWE-798", "v" * 40),
              history._Commit("h", "d", "a", "e", "s"), "p.py")
    assert w.removals == {}


def test_cli_output_errors_are_reported_not_raised(repo, tmp_path, capsys):
    target = tmp_path / "missing-dir" / "out.json"
    assert history.main([str(repo["path"]), "-f", "json", "-o", str(target)]) == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err and "missing-dir" in err
    assert history.main(["--definitely-not-an-option"]) == 2
    assert history.main(["--help"]) == 0
