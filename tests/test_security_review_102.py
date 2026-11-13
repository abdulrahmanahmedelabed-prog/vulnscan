"""1.0.2 security/packaging review: the update command never names an unclaimed PyPI name, the store-publishing jobs
use OIDC with least privilege and only on release runs, and install.ps1 never leaves a truncated kashif.exe."""

from __future__ import annotations

import json
import pathlib
import re
import sys

import pytest

from vulnscan import updater

ROOT = pathlib.Path(__file__).resolve().parent.parent
GIT_URL = "git+https://github.com/" + updater.REPO
OURS = ["Repository, https://github.com/" + updater.REPO]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


# ------------------------------------------------------------------------- install_info: never a bare "kashif"

class _Meta:
    def __init__(self, urls=()):
        self.urls = list(urls)

    def get_all(self, name):
        return self.urls if name == "Project-URL" else None

    def get(self, name, default=None):
        return default


class _Dist:
    """A distribution whose direct_url.json is ``direct`` (None: installed from an index, no such file)."""

    def __init__(self, direct=None, urls=(), files=()):
        self.direct, self.metadata, self.files = direct, _Meta(urls), list(files)

    def read_text(self, name):
        return json.dumps(self.direct) if (name == "direct_url.json" and self.direct is not None) else None


@pytest.fixture
def dists(monkeypatch, tmp_path):
    from importlib import metadata
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.setattr(updater, "_package_root", lambda: tmp_path)
    table: dict = {}

    def distribution(name):
        if name not in table:
            raise metadata.PackageNotFoundError(name)
        return table[name]
    monkeypatch.setattr(metadata, "distribution", distribution)
    return table


def _bare_kashif(cmd: str) -> bool:
    return bool(re.search(r"pip install (--upgrade )?kashif(\s|$)", cmd))


def test_local_wheel_install_is_told_to_use_git_not_the_unclaimed_pypi_name(dists):
    # `pip install ./kashif-1.0.2-py3-none-any.whl`: pip records the file URL (PEP 610 archive_info)
    dists["kashif"] = _Dist({"url": "file:///tmp/kashif-1.0.2-py3-none-any.whl", "archive_info": {}}, OURS)
    cmd = updater.install_info()["command"]
    assert cmd.endswith("-m pip install --upgrade " + updater._q(GIT_URL)) and not _bare_kashif(cmd)


def test_directory_install_is_told_to_use_git(dists):
    dists["kashif"] = _Dist({"url": "file:///src/vulnscan", "dir_info": {}}, OURS)
    assert updater.install_info()["command"].endswith("pip install --upgrade " + updater._q(GIT_URL))


def test_old_directory_install_plus_new_wheel_is_reinstalled_from_git(dists):
    dists["vulnscan"] = _Dist({"url": "file:///src/old", "dir_info": {}}, OURS)
    dists["kashif"] = _Dist({"url": "file:///tmp/kashif.whl", "archive_info": {}}, OURS)
    cmd = updater.install_info()["command"]
    assert "pip uninstall -y vulnscan kashif && " in cmd and cmd.endswith("-m pip install " + updater._q(GIT_URL))
    assert not _bare_kashif(cmd)


def test_unreadable_direct_url_is_not_taken_for_an_index_install(dists):
    class Unreadable(_Dist):
        def read_text(self, name):
            raise OSError("permission denied")
    dists["kashif"] = Unreadable()
    assert updater.install_info()["command"].endswith("pip install --upgrade " + updater._q(GIT_URL))


def test_index_install_keeps_upgrading_from_the_index(dists):
    dists["kashif"] = _Dist(None, OURS)
    assert updater.install_info()["command"].endswith("-m pip install --upgrade kashif")


def test_malformed_dir_info_does_not_crash(dists):
    dists["kashif"] = _Dist({"url": "file:///src", "dir_info": "editable"})
    assert updater.install_info()["kind"] == "pip"


# --------------------------------------------------------------------------------------- release workflow

yaml = pytest.importorskip("yaml")


@pytest.fixture(scope="module")
def wf() -> dict:
    return yaml.safe_load(_read(".github/workflows/release.yml"))


def _on(wf: dict) -> dict:
    return wf.get("on", wf.get(True))            # PyYAML reads the bare key `on` as True


def test_release_workflow_runs_only_on_tags_and_manual_runs(wf):
    on = _on(wf)
    assert set(on) == {"push", "workflow_dispatch"}
    assert on["push"] == {"tags": ["v*"]}         # no branch pushes, no pull requests
    assert wf["permissions"] == {"contents": "read"}


def test_pypi_publish_job_has_only_the_oidc_permission_and_runs_no_repository_code(wf):
    job = wf["jobs"]["pypi-publish"]
    assert job["permissions"] == {"id-token": "write"}
    assert job["environment"]["name"] == "pypi"
    uses = [s.get("uses", "") for s in job["steps"]]
    assert not any(u.startswith("actions/checkout") for u in uses)          # nothing from the tree runs with the token
    assert not any("run" in s for s in job["steps"])
    assert wf["jobs"]["pypi-build"]["permissions"] == {"contents": "read"}


def test_vscode_marketplace_trusted_publishing_is_opt_in_and_pinned(wf):
    job = wf["jobs"]["publish-vscode-extension"]
    assert job["permissions"].get("id-token") == "write"
    steps = job["steps"]
    oidc = [s for s in steps if "--oidc" in str(s.get("run", ""))]
    assert len(oidc) == 1
    assert oidc[0]["if"] == "vars.VSCE_TRUSTED_PUBLISHING == 'true'"
    assert "env" not in oidc[0] and "secrets." not in json.dumps(oidc[0])     # no token at all
    m = re.search(r"@vscode/vsce@(\d+)\.(\d+)\.(\d+) ", oidc[0]["run"])
    assert m and int(m.group(1)) >= 4                                       # --oidc exists from vsce 4
    node = [s for s in steps if str(s.get("uses", "")).startswith("actions/setup-node@")]
    assert node and re.fullmatch(r"actions/setup-node@[0-9a-f]{40}", node[0]["uses"])
    assert int(node[0]["with"]["node-version"]) >= 22                       # vsce 4 needs Node.js 22
    assert steps.index(node[0]) < steps.index(oidc[0])
    pat = [s for s in steps if "VSCE_PAT" in json.dumps(s.get("env", {}))]
    assert pat and "vars.VSCE_TRUSTED_PUBLISHING != 'true'" in pat[0]["if"]  # never both


def test_every_action_in_the_release_workflow_is_pinned_by_sha(wf):
    for name, job in wf["jobs"].items():
        for step in job.get("steps", []):
            if "uses" in step:
                assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", step["uses"]), (name, step["uses"])


def test_publishing_doc_uses_marketplace_trusted_publishing():
    doc = _read("docs/publishing.md")
    assert "VSCE_TRUSTED_PUBLISHING" in doc and "--oidc" in doc
    assert "anyone can register `kashif`" in doc
    section = doc[doc.index("## 2. Visual Studio Marketplace"):doc.index("## 3. Open VSX")]
    assert "Personal access tokens" not in section                          # no longer the instructions


# --------------------------------------------------------------------------------------------- install.ps1

def test_install_ps1_drops_a_truncated_copy_before_restoring_the_old_exe():
    ps1 = _read("site/install.ps1")
    catch = ps1[ps1.index("Copy-Item -Force (Join-Path $Tmp $Asset) $Exe"):]
    catch = catch[catch.index("catch {"):catch.index("throw")]
    assert catch.index("Remove-Item -Force -LiteralPath $Exe") < catch.index("Move-Item -LiteralPath $Old -Destination $Exe")
