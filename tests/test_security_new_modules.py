"""Regression tests from the adversarial security review of the 1.0 modules (MCP server, autofix --fix)."""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys

import pytest

from vulnscan import autofix, mcp
from vulnscan.cli import main

POSIX_GIT = pytest.mark.skipif(shutil.which("git") is None or os.name == "nt",
                               reason="needs git and a POSIX shell for the planted commands")

# A module named like one the engine imports. If anything imports it, it leaves a marker file and exits.
PLANTED = ("import pathlib\n"
           "pathlib.Path(__file__).with_name('IMPORTED').write_text('project module ran')\n"
           "raise SystemExit(3)\n")


# ------------------------------------------------------------------------------------------- MCP scan worker

def test_mcp_worker_never_imports_modules_of_the_scanned_project(tmp_path, monkeypatch):
    """The MCP client starts the server in the project directory. "python -m" puts the working directory first on
    sys.path, so the scan worker used to import the project's own json.py (code execution while scanning)."""
    project = tmp_path / "proj"
    project.mkdir()
    for name in ("json.py", "hashlib.py", "argparse.py", "tempfile.py"):
        (project / name).write_text(PLANTED, encoding="utf-8")
    (project / "app.py").write_text("import os\nos.system(input())\n", encoding="utf-8")
    monkeypatch.chdir(project)
    srv = mcp.KashifMCPServer(out=io.BytesIO(), roots=[str(project)])
    try:
        res = srv.call_tool("scan_path", {"path": "."})
    finally:
        srv.shutdown()
    assert not (project / "IMPORTED").exists()
    assert res["isError"] is False
    assert srv._worker_ok and srv.isolate                       # the scan really ran in the worker process
    assert res["structuredContent"]["summary"]["total"] >= 1   # and it found the command injection in app.py


def test_mcp_printed_launch_command_does_not_import_from_the_project(monkeypatch):
    monkeypatch.setattr(mcp.shutil, "which", lambda name: None)  # no console script: the "python -m" form
    monkeypatch.delattr(sys, "frozen", raising=False)
    command, args = mcp._launch_command()
    assert args[-2:] == ["-m", "vulnscan.mcp"]
    if sys.version_info >= (3, 11):
        assert args[0] == "-P"


# ------------------------------------------------------------------------------------- autofix: git hardening

def _git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false",
                    *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.py").write_text("import yaml\n\ndata = yaml.load(open('f'))\n", encoding="utf-8")
    _git(root, "init", "-q")
    _git(root, "add", "a.py")
    _git(root, "commit", "-q", "-m", "init")
    return root


@POSIX_GIT
def test_git_dirty_does_not_run_the_repository_fsmonitor(repo, tmp_path):
    marker = tmp_path / "FSMONITOR_RAN"
    _git(repo, "config", "core.fsmonitor", f"touch '{marker}'; false")
    assert autofix.git_dirty(repo, ["a.py"]) == []
    assert not marker.exists()


@POSIX_GIT
def test_fix_refuses_a_repository_whose_content_filter_runs_a_command(repo, tmp_path, capsys):
    marker = tmp_path / "FILTER_RAN"
    _git(repo, "config", "filter.evil.clean", f"touch '{marker}'; cat")
    (repo / ".gitattributes").write_text("*.py filter=evil\n", encoding="utf-8")
    os.utime(repo / "a.py", (1, 1))                            # a stale index entry: git status would clean it
    assert autofix.git_unsafe(repo) == ["filter.evil.clean"]
    assert autofix.git_dirty(repo, ["a.py"])                    # fails closed: never reported as clean
    before = (repo / "a.py").read_text(encoding="utf-8")
    code = main([str(repo), "--no-deps", "--no-external", "--no-color", "--lang", "en", "--fix"])
    err = capsys.readouterr().err
    assert code == 2
    assert "content filter" in err and "filter.evil.clean" in err
    assert (repo / "a.py").read_text(encoding="utf-8") == before
    assert not marker.exists()


@POSIX_GIT
def test_git_lfs_filter_is_not_a_reason_to_refuse(repo):
    _git(repo, "config", "filter.lfs.clean", "git-lfs clean -- %f")
    _git(repo, "config", "filter.lfs.process", "git-lfs filter-process")
    assert autofix.git_unsafe(repo) == []
