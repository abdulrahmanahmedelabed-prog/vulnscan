"""The release pipeline, the installers and the in-app updater must agree on the asset names.

v0.9.x installs update themselves by downloading the legacy ``vulnscan-*`` asset of the newest release and checking it
against that release's SHA256SUMS.txt, so every release must keep publishing those names as byte-identical copies of
the ``kashif-*`` binaries. These checks read the workflow and installer files as text (no YAML parser: standard
library only) and fail when one place is renamed and another is not.
"""

from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import re

import pytest

from vulnscan import updater

ROOT = pathlib.Path(__file__).resolve().parent.parent
RELEASE = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")


def _matrix_pairs() -> dict[str, str]:
    pairs = dict(re.findall(r"^\s+artifact: (\S+)\n\s+legacy: (\S+)$", RELEASE, re.M))
    assert len(pairs) == 4, pairs
    return pairs


def _block(after: str) -> list[str]:
    """The `out/<name>` lines of the `|` block that follows the line containing `after`."""
    start = RELEASE.index(after)
    names = []
    for line in RELEASE[start:].splitlines()[1:]:
        m = re.fullmatch(r"\s+out/(\S+)", line)
        if not m:
            break
        names.append(m.group(1))
    return names


BINARIES = ["kashif-setup.exe", *sorted(updater.LEGACY_ASSETS), *sorted(updater.LEGACY_ASSETS.values())]


def test_matrix_names_match_the_updater():
    assert _matrix_pairs() == updater.LEGACY_ASSETS


def test_every_binary_is_checksummed_attested_published_and_kept():
    sums_cmd = re.search(r"sha256sum (kashif-setup\.exe.*?) > SHA256SUMS\.txt", RELEASE, re.S).group(1)
    assert sorted(sums_cmd.replace("\\", " ").split()) == sorted(BINARIES)
    assert sorted(_block("subject-path: |")) == sorted(BINARIES)
    published = _block("files: |")
    assert sorted(published) == sorted([*BINARIES, "SHA256SUMS.txt", "kashif-sbom.cdx.json"])
    keep = re.search(r'keep=" (.*?) "', RELEASE).group(1).split()
    assert sorted(keep) == sorted(published)
    assert "output-file: out/kashif-sbom.cdx.json" in RELEASE
    for canon, legacy in updater.LEGACY_ASSETS.items():
        assert f"cmp {canon} {legacy}" in RELEASE          # byte-identical copies, checked before checksumming


def test_built_executable_name_matches_the_spec_and_the_setup_wizard():
    spec = (ROOT / "vulnscan.spec").read_text(encoding="utf-8")
    assert re.search(r'^\s+name="kashif",', spec, re.M)
    built = set(re.findall(r"^\s+built: (\S+)$", RELEASE, re.M))
    assert built == {"dist/kashif", "dist/kashif.exe"}
    assert r"/DSourceExe=$PWD\dist\kashif.exe" in RELEASE
    iss = (ROOT / "packaging" / "windows" / "kashif.iss").read_text(encoding="utf-8")
    assert r'#define SourceExe "..\..\dist\kashif.exe"' in iss
    assert 'DestName: "kashif.exe"' in iss and 'Source: "vulnscan.cmd"' in iss
    assert "kashif.exe" in (ROOT / "packaging" / "windows" / "vulnscan.cmd").read_text(encoding="utf-8")


def test_manual_runs_do_not_publish_by_default():
    assert re.search(r'release_tag:\n(?:\s+#.*\n|\s+\w+:.*\n)*?\s+default: ""', RELEASE)
    gates = re.findall(r"^    if: (.*)$", RELEASE, re.M)
    assert gates and all("inputs.release_tag != ''" in g and "refs/tags/" in g for g in gates)


def test_installers_use_release_asset_names():
    sh = (ROOT / "site" / "install.sh").read_text(encoding="utf-8")
    for canon, legacy in updater.LEGACY_ASSETS.items():
        if canon.endswith(".exe"):
            continue
        assert f'ASSET="{canon}"; LEGACY="{legacy}"' in sh
    ps1 = (ROOT / "site" / "install.ps1").read_text(encoding="utf-8")
    assert '$Asset = "kashif-windows-x86_64.exe"' in ps1 and '$LegacyAsset = "vulnscan-windows.exe"' in ps1


def test_container_entrypoint_and_command_names():
    docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert 'ENTRYPOINT ["kashif"]' in docker and "vulnscan --version" in docker
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'^kashif = "vulnscan\.cli:main"', pyproject, re.M)
    assert re.search(r'^vulnscan = "vulnscan\.cli:main"', pyproject, re.M)


@pytest.fixture(scope="module")
def formula():
    spec = importlib.util.spec_from_file_location("update_formula", ROOT / "packaging" / "update_formula.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _sums(names) -> str:
    return "".join(f"{hashlib.sha256(n.encode()).hexdigest()}  {n}\n" for n in names)


def test_formula_points_at_kashif_assets(formula):
    out = formula.render("v1.0.0", _sums(BINARIES))
    urls = re.findall(r'url "(\S+)"', out)
    assert [u.rsplit("/", 1)[1] for u in urls] == ["kashif-macos-arm64", "kashif-macos-x86_64", "kashif-linux-x86_64"]
    assert all("/releases/download/v1.0.0/" in u for u in urls)
    for name in ("kashif-macos-arm64", "kashif-macos-x86_64", "kashif-linux-x86_64"):
        assert hashlib.sha256(name.encode()).hexdigest() in out
    assert 'bin.install binary => "kashif"' in out and 'bin.install_symlink "kashif" => "vulnscan"' in out


def test_formula_falls_back_to_legacy_assets_of_an_older_release(formula):
    out = formula.render("v0.9.1", _sums(["kashif-setup.exe", *updater.LEGACY_ASSETS.values()]))
    assert [u.rsplit("/", 1)[1] for u in re.findall(r'url "(\S+)"', out)] == \
        ["vulnscan-macos-arm64", "vulnscan-macos-x86_64", "vulnscan-linux"]
    with pytest.raises(SystemExit):
        formula.render("v1.0.0", _sums(["kashif-linux-x86_64"]))


def test_formula_for_a_release_with_only_kashif_assets(formula):
    # the default branch's update_formula.py renders the next release (1.0.1+): kashif-* even with no legacy copy
    out = formula.render("v1.0.1", _sums(["kashif-setup.exe", *sorted(updater.LEGACY_ASSETS)]))
    assert [u.rsplit("/", 1)[1] for u in re.findall(r'url "(\S+)"', out)] == \
        ["kashif-macos-arm64", "kashif-macos-x86_64", "kashif-linux-x86_64"]
    assert 'version "1.0.1"' in out and "/releases/download/v1.0.1/" in out


def test_committed_formula_is_what_the_script_renders(formula):
    """Formula/kashif.rb is generated: re-rendering it from its own version and hashes must give the same file."""
    committed = (ROOT / "Formula" / "kashif.rb").read_text(encoding="utf-8")
    version = re.search(r'^  version "(\d+\.\d+\.\d+)"$', committed, re.M).group(1)
    pairs = re.findall(r'url "\S+/(\S+)"\n\s+sha256 "([0-9a-f]{64})"', committed)
    assert len(pairs) == 3 and all(name.startswith("kashif-") for name, _ in pairs)
    sums = "".join(f"{sha}  {name}\n" for name, sha in pairs)
    assert formula.render(f"v{version}", sums) == committed


def _iss_section(name: str) -> list[str]:
    iss = (ROOT / "packaging" / "windows" / "kashif.iss").read_text(encoding="utf-8")
    body = re.search(rf"^\[{re.escape(name)}\]\n(.*?)(?=^\[)", iss, re.M | re.S).group(1)
    return [line for line in body.splitlines() if line and not line.startswith(";")]


def test_uninstaller_removes_what_the_updater_leaves_next_to_the_binary():
    src = (ROOT / "vulnscan" / "updater.py").read_text(encoding="utf-8")
    prefixes = set(re.findall(r'mkstemp\(prefix="([^"]+)"', src))
    assert prefixes, "updater.py no longer creates its temp download with mkstemp(prefix=...)"
    assert set(re.findall(r'\.glob\("([^"*]+)\*"\)', src)) == prefixes      # cleanup_stale globs the same prefix
    names = set(re.findall(r'^Type: files; Name: "\{app\}\\([^"]+)"$', "\n".join(_iss_section("UninstallDelete")), re.M))
    assert updater.backup_path(pathlib.Path("kashif.exe")).name in names           # kashif.exe.old
    for prefix in prefixes | {".vulnscan-update-", ".kashif-update-"}:
        assert prefix + "*" in names, prefix


def _ps1() -> str:
    return (ROOT / "site" / "install.ps1").read_text(encoding="utf-8")


def test_install_ps1_tolerates_an_unset_user_path():
    ps1 = _ps1()
    # GetEnvironmentVariable("Path", "User") is $null when the user PATH is unset: no method may be called on it
    assert not re.search(r"\$userPath\.\w+\(", ps1)
    assert '"$userPath" -split' in ps1
    # case-insensitive, trailing-backslash-insensitive membership test; empty entries dropped on append
    assert ".TrimEnd('\\').ToLowerInvariant()" in ps1 and "Where-Object { $_.Trim() -ne \"\" }" in ps1
    assert "((@($entries) + $Dir) -join ';')" in ps1


def test_install_ps1_removes_the_stale_pre_rename_binary():
    ps1 = _ps1()
    assert re.search(r'foreach \(\$name in @\("vulnscan\.exe", "vulnscan\.exe\.old"\)\)', ps1)
    assert "Remove-Item -Force -LiteralPath $stale" in ps1 and "Test-Path -LiteralPath $stale" in ps1
    # the legacy-name fallback stays: a release made before the rename has only vulnscan-windows.exe
    assert re.search(r"catch \{[^}]*\$Asset = \$LegacyAsset", ps1, re.S)


def test_installer_workflow_tests_powershell_like_the_shell_installer():
    wf = (ROOT / ".github" / "workflows" / "installers.yml").read_text(encoding="utf-8")
    ps_job = wf[wf.index("\n  install-ps1:"):wf.index("\n  homebrew:")]
    sh_job = wf[wf.index("\n  install-sh:"):wf.index("\n  install-ps1:")]
    legacy = re.findall(r"KASHIF_VERSION: (v0\.9\.\d+)", sh_job)
    assert legacy and set(re.findall(r"KASHIF_VERSION: (v0\.9\.\d+)", ps_job)) == set(legacy)
    assert '[Environment]::SetEnvironmentVariable("Path", $null, "User")' in ps_job
    assert "finally {" in ps_job and '[Environment]::SetEnvironmentVariable("Path", $saved, "User")' in ps_job
    assert "vulnscan.exe was not removed" in ps_job or '"$name was not removed"' in ps_job
    assert "KASHIF_VERSION: v0.0.1" in ps_job
    # only actions already pinned elsewhere in the repository, by full commit SHA
    used = set(re.findall(r"uses: (\S+@[0-9a-f]{40})", wf))
    pinned = set()
    for other in (ROOT / ".github" / "workflows").glob("*.yml"):
        if other.name != "installers.yml":
            pinned |= set(re.findall(r"uses: (\S+@[0-9a-f]{40})", other.read_text(encoding="utf-8")))
    assert used and used <= pinned, used - pinned
    assert not re.search(r"uses: \S+@(?![0-9a-f]{40}\b)", wf)
