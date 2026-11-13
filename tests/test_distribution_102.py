"""1.0.2: the pip distribution is "kashif" (PyPI publishing prep), the upgrade path from the pre-1.0.2 "vulnscan"
distribution, install.ps1 over a running kashif.exe, the bounded `kashif export` reader and the documented counts."""

from __future__ import annotations

import io
import json
import os
import pathlib
import re
import sys
import time

import pytest

from vulnscan import exporters, updater
from vulnscan.i18n import has_arabic

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


# ------------------------------------------------------------------------------------- the distribution name

def test_pyproject_distribution_is_kashif_with_both_commands():
    py = _read("pyproject.toml")
    assert re.search(r'^name = "kashif"$', py, re.M)
    assert not re.search(r'^name = "vulnscan"$', py, re.M)
    assert re.search(r'^kashif = "vulnscan\.cli:main"', py, re.M)
    assert re.search(r'^vulnscan = "vulnscan\.cli:main"', py, re.M)
    assert 'include = ["vulnscan*"]' in py                      # the import package stays vulnscan


def test_container_installs_the_renamed_wheel():
    docker = _read("Dockerfile")
    assert "/dist/kashif-*.whl" in docker and "/dist/vulnscan-*.whl" not in docker


# ----------------------------------------------------------------------------- install_info / upgrade command

class _Meta:
    def __init__(self, urls=(), home=""):
        self.urls, self.home = list(urls), home

    def get_all(self, name):
        return self.urls if name == "Project-URL" else None

    def get(self, name, default=None):
        return self.home if name == "Home-page" else default


class _Dist:
    def __init__(self, direct=None, urls=(), files=(), home=""):
        self.direct, self.metadata, self.files = direct, _Meta(urls, home), list(files)

    def read_text(self, name):
        return json.dumps(self.direct) if (name == "direct_url.json" and self.direct is not None) else None


OURS_URLS = ["Repository, https://github.com/abdulrahmanahmedelabed-prog/vulnscan"]
GIT = {"url": "https://github.com/abdulrahmanahmedelabed-prog/vulnscan", "vcs_info": {"vcs": "git", "commit_id": "0" * 40}}


@pytest.fixture
def dists(monkeypatch, tmp_path):
    from importlib import metadata
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.setattr(updater, "_package_root", lambda: tmp_path)          # no .git: not a source checkout
    table: dict = {}

    def distribution(name):
        if name not in table:
            raise metadata.PackageNotFoundError(name)
        return table[name]
    monkeypatch.setattr(metadata, "distribution", distribution)
    return table


def _never_pypi_vulnscan(cmd: str) -> None:
    """No command may install PyPI's unrelated "vulnscan"."""
    assert not re.search(r"pip install (--upgrade )?vulnscan\b", cmd), cmd


def test_kashif_from_an_index(dists):
    dists["kashif"] = _Dist()
    info = updater.install_info()
    assert info["kind"] == "pip" and info["command"].endswith("-m pip install --upgrade kashif")
    assert "uninstall" not in info["command"]


def test_kashif_from_git_keeps_coming_from_git(dists):
    dists["kashif"] = _Dist(GIT, OURS_URLS)
    cmd = updater.install_info()["command"]
    assert cmd.endswith("pip install --upgrade " + updater._q("git+" + GIT["url"]))
    assert "uninstall" not in cmd


def test_pre_102_git_install_is_removed_first(dists):
    dists["vulnscan"] = _Dist(GIT, OURS_URLS)
    cmd = updater.install_info()["command"]
    assert re.search(r"-m pip uninstall -y vulnscan && .* -m pip install " + re.escape(updater._q("git+" + GIT["url"])) + "$", cmd)
    _never_pypi_vulnscan(cmd)


def test_pre_102_install_without_urls_recognised_by_its_files(dists):
    # 0.x metadata had no project URLs; its RECORD lists this module
    dists["vulnscan"] = _Dist({"url": "file:///src/vulnscan", "dir_info": {}}, files=["vulnscan/__init__.py", "vulnscan/updater.py"])
    cmd = updater.install_info()["command"]
    # a directory install: reinstalled from git, never by the bare (not yet published) name "kashif"
    assert "pip uninstall -y vulnscan &&" in cmd and cmd.endswith("-m pip install " + updater._q("git+" + GIT["url"]))
    _never_pypi_vulnscan(cmd)


def test_both_distributions_installed_removes_both_then_reinstalls(dists):
    # what `pip install --upgrade git+...` (the 1.0.1 command) leaves behind when 1.0.2 is installed over 1.0.1
    dists["kashif"] = _Dist(GIT, OURS_URLS)
    dists["vulnscan"] = _Dist(GIT, OURS_URLS)
    cmd = updater.install_info()["command"]
    assert "-m pip uninstall -y vulnscan kashif && " in cmd
    assert cmd.endswith("-m pip install " + updater._q("git+" + GIT["url"]))


def test_an_unrelated_vulnscan_distribution_is_never_touched(dists):
    dists["vulnscan"] = _Dist(None, ["Homepage, https://example.org/other-vulnscan"], files=["vulnscan/__init__.py"])
    assert updater.install_info() == {"kind": "source", "command": None}      # ours is not a pip install
    dists["kashif"] = _Dist()
    cmd = updater.install_info()["command"]
    assert cmd.endswith("pip install --upgrade kashif") and "uninstall" not in cmd


def test_editable_install_is_a_source_install(dists):
    dists["kashif"] = _Dist({"url": "file:///src", "dir_info": {"editable": True}})
    assert updater.install_info() == {"kind": "source", "command": None}


def test_broken_direct_url_is_tolerated(dists, monkeypatch):
    class Broken(_Dist):
        def read_text(self, name):
            return "[1, 2"
    git = "pip install --upgrade " + updater._q("git+" + GIT["url"])      # unknown origin: the documented git install
    dists["kashif"] = Broken()
    assert updater.install_info()["command"].endswith(git)
    dists["kashif"] = type("Odd", (_Dist,), {"read_text": lambda self, name: "[]"})()
    assert updater.install_info()["command"].endswith(git)


def test_no_distribution_is_a_source_run(dists):
    assert updater.install_info() == {"kind": "source", "command": None}


def test_docs_show_the_upgrade_path_and_never_pip_install_vulnscan():
    prod = _read("docs/production.md")
    assert "## Upgrading a pip install to 1.0.2" in prod and "pip uninstall -y vulnscan kashif" in prod
    assert "pip uninstall -y vulnscan kashif" in _read("README.md")
    for rel in ("README.md", "docs/production.md", "docs/integrations.md", "docs/publishing.md",
                "editors/vscode/README.md", "site/install.sh", "site/install.ps1"):
        text = _read(rel)
        assert not re.search(r"pip3? install (-U |--upgrade )?vulnscan\b", text), rel
    # not published yet: no doc may claim `pip install kashif` works, except the owner's checklist
    for rel in ("README.md", "docs/production.md", "docs/integrations.md", "editors/vscode/README.md"):
        assert not re.search(r"pip3? install (-U |--upgrade )?kashif\b", _read(rel)), rel


# ------------------------------------------------------------------------------------ PyPI release job

def _job(wf: str, name: str) -> str:
    start = wf.index(f"\n  {name}:\n")
    nxt = re.search(r"\n  [a-z][a-z0-9-]*:\n", wf[start + 1:])
    return wf[start: start + 1 + nxt.start()] if nxt else wf[start:]


def test_pypi_jobs_trusted_publishing_and_opt_in():
    wf = _read(".github/workflows/release.yml")
    build, publish = _job(wf, "pypi-build"), _job(wf, "pypi-publish")
    gate = "vars.PYPI_PUBLISH == 'true' && (startsWith(github.ref, 'refs/tags/')"
    assert gate in build and gate in publish
    assert "needs: publish" in build and "needs: pypi-build" in publish
    assert "id-token: write" in publish and "id-token" not in build      # OIDC only where the upload happens
    assert re.search(r"environment:\n\s+name: pypi\n", publish)
    assert re.search(r"uses: pypa/gh-action-pypi-publish@[0-9a-f]{40} # v\d+\.\d+\.\d+", publish)
    assert "password" not in publish and "secrets." not in publish          # no API token
    assert "--sdist --wheel" in build and "kashif-$version.tar.gz" in build and "kashif-$version-py3-none-any.whl" in build
    for line in re.findall(r"uses: (\S+)", build + publish):
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", line), line   # every action pinned by full SHA


def test_publishing_checklist():
    doc = _read("docs/publishing.md")
    for needle in ("pending publisher", "`abdulrahmanahmedelabed-prog`", "`vulnscan`", "`release.yml`", "`pypi`",
                   "PYPI_PUBLISH", "VSCE_TRUSTED_PUBLISHING", "OVSX_PAT", "Trusted Publishing", "Eclipse", "SignPath"):
        assert needle in doc, needle


# ------------------------------------------------------------------------------------------- installers

def test_install_ps1_moves_a_running_exe_out_of_the_way_first():
    ps1 = _read("site/install.ps1")
    move = ps1.index('Move-Item -LiteralPath $Exe -Destination $Old')
    copy = ps1.index('Copy-Item -Force (Join-Path $Tmp $Asset) $Exe')
    assert move < copy
    assert '$Old = "$Exe.old"' in ps1                                   # the updater's name (updater.backup_path)
    assert updater.backup_path(pathlib.Path("kashif.exe")).name == "kashif.exe.old"
    assert "Move-Item -LiteralPath $Old -Destination $Exe" in ps1           # rolled back when the copy fails
    assert 'Copy-Item -Force (Join-Path $Tmp $Asset) (Join-Path $Dir "kashif.exe")' not in ps1


def test_installers_ci_reinstalls_over_a_running_kashif_ui():
    wf = _read(".github/workflows/installers.yml")
    step = wf[wf.index("install.ps1 reinstalls while kashif.exe is running"):]
    step = step[:step.index("\n      - name:")]
    assert '"ui", "--no-browser"' in step and "Start-Process" in step and "-PassThru" in step
    assert step.count("./site/install.ps1") >= 2 and "taskkill /PID $ui.Id /T /F" in step


def test_install_sh_never_suggests_pypi_vulnscan():
    sh = _read("site/install.sh")
    assert "pip install vulnscan" not in sh
    assert 'pip install \\"git+https://github.com/$REPO\\"' in sh


# ------------------------------------------------------------------------------- kashif export: bounded read

def _report(tmp_path) -> pathlib.Path:
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"findings": [{"rule_id": "DF001", "severity": "high", "title": "t", "file": "a.py",
                                           "line": 1}]}), encoding="utf-8")
    return p


def test_export_still_reads_a_normal_report(tmp_path, capsys):
    assert exporters.main([str(_report(tmp_path)), "-f", "csv", "--lang", "en"]) == 0
    assert "DF001" in capsys.readouterr().out


@pytest.mark.skipif(not os.path.exists("/dev/zero"), reason="no /dev/zero")
def test_export_refuses_dev_zero_quickly(capsys):
    start = time.monotonic()
    assert exporters.main(["/dev/zero", "-f", "csv", "--lang", "en"]) == 2
    assert time.monotonic() - start < 10
    err = capsys.readouterr().err
    assert "not a regular file" in err and "/dev/zero" in err


def test_export_refuses_a_directory(tmp_path, capsys):
    assert exporters.main([str(tmp_path), "-f", "csv", "--lang", "en"]) == 2
    assert "not a regular file" in capsys.readouterr().err


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs here")
def test_export_refuses_a_fifo_without_blocking(tmp_path, capsys):
    fifo = tmp_path / "pipe.json"
    os.mkfifo(fifo)
    assert exporters.main([str(fifo), "-f", "csv", "--lang", "en"]) == 2   # would block forever on open()
    assert "not a regular file" in capsys.readouterr().err


def test_export_refuses_a_report_over_the_limit(tmp_path, monkeypatch, capsys):
    report = _report(tmp_path)
    monkeypatch.setattr(exporters, "MAX_REPORT_BYTES", report.stat().st_size - 1)
    assert exporters.main([str(report), "-f", "csv", "--lang", "en"]) == 2
    assert "is larger than" in capsys.readouterr().err
    assert exporters.MAX_REPORT_BYTES < 64_000_000
    monkeypatch.undo()
    assert exporters.MAX_REPORT_BYTES == 64_000_000                         # the baseline's bound


def test_export_bounds_standard_input(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(exporters, "MAX_REPORT_BYTES", 100)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b" " * 1000 + b"[]")))
    assert exporters.main(["-", "-f", "csv", "--lang", "en"]) == 2
    assert "'-' is larger than" in capsys.readouterr().err
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(_report(tmp_path).read_bytes())))
    assert exporters.main(["-", "-f", "csv", "--lang", "en"]) == 0


def test_export_load_errors_in_arabic_and_both(tmp_path, capsys):
    assert exporters.main([str(tmp_path), "-f", "csv", "--lang", "ar"]) == 2
    err = capsys.readouterr().err
    assert "ليس ملفًا عاديًا" in err and "not a regular file" not in err
    assert exporters.main([str(tmp_path), "-f", "csv", "--lang", "both"]) == 2
    err = capsys.readouterr().err
    assert "ليس ملفًا عاديًا" in err and "not a regular file" in err
    for key in ("e_report_kind", "e_report_big"):
        assert has_arabic(exporters.STR["ar"][key]) and not has_arabic(exporters.STR["en"][key])


# ----------------------------------------------------------------------------------------- documented counts

def model_counts() -> dict:
    """How the documented numbers are counted: sources are the source names plus the attributes of root.attr
    sources, sinks the names of every sink entry, sanitizers the sanitizer entries, over vulnscan/models/*.json."""
    out = {"sources": 0, "sinks": 0, "sanitizers": 0}
    for path in sorted((ROOT / "vulnscan" / "models").glob("*.json")):
        d = json.loads(path.read_text(encoding="utf-8"))
        out["sources"] += sum(len(e.get("names", [])) + len(e.get("attrs", [])) for e in d.get("sources", []))
        out["sinks"] += sum(len(e.get("names", [])) for e in d.get("sinks", []))
        out["sanitizers"] += len(d.get("sanitizers", []))
    out["total"] = out["sources"] + out["sinks"] + out["sanitizers"]
    return out


def test_documented_model_counts_match_the_models():
    c = {k: f"{v:,}" for k, v in model_counts().items()}
    readme = _read("README.md")
    assert f"over {c['total']} modelled library APIs\n  ({c['sources']} sources, {c['sinks']} sinks, {c['sanitizers']} sanitizers)" in readme
    assert f"النماذج **{c['total']}** واجهة مكتبة (مصادر {c['sources']}، ونقاط خطر {c['sinks']}، ومعقّمات {c['sanitizers']})" in readme
    assert f'<b class="ltr">{c["total"]}</b><span data-i18n="stat.apis">' in _read("site/index.html")
