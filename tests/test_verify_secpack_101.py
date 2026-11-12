"""1.0.1 verify round (security / packaging): baselines named by the scanned repository are read only when they are
regular files, a hostile baseline cannot crash the scan, and install.sh with a relative KASHIF_INSTALL_DIR leaves a
working ``vulnscan`` alias."""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys

import pytest

from vulnscan import baseline

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_load_baseline_skips_fingerprints_that_are_not_strings(tmp_path):
    # 1.0.0: {"fp": [1]} raised TypeError (unhashable) out of load_baseline, i.e. a traceback from --baseline / the LSP
    path = tmp_path / "base.json"
    path.write_text(json.dumps({"fingerprints": [{"fp": [1]}, {"fp": {"a": 1}}, {"fp": 7}, {"fp": "abc123"}, "x"]}),
                    encoding="utf-8")
    assert baseline.load_baseline(str(path)) == {"abc123"}
    assert baseline.baseline_problem(str(path)) is None


def test_baseline_directory_is_unreadable_not_missing(tmp_path):
    assert baseline.baseline_problem(str(tmp_path)) == "unreadable"
    assert baseline.load_baseline(str(tmp_path)) == set()
    assert baseline.baseline_problem(str(tmp_path / "nope.json")) == "missing"


_PROBE = r"""
import pathlib, sys
from vulnscan.baseline import baseline_problem, load_baseline
from vulnscan.policy import _load_baseline_file
p = sys.argv[1]
print(sorted(load_baseline(p)), baseline_problem(p), _load_baseline_file(pathlib.Path(p)))
from vulnscan.lsp import add_to_baseline
from vulnscan.model import Finding
try:
    add_to_baseline(pathlib.Path(p), Finding("SEC001", "high", "t", "t", "a.py", 1, "x", "a"))
except OSError:
    print("refused")
"""


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a FIFO (POSIX)")
def test_baseline_that_is_a_fifo_is_refused_without_blocking(tmp_path):
    # A repository can commit .kashif-baseline.json (read by the editor extension) or point kashif.yml's gate.baseline
    # at a FIFO or a symlink to /dev/zero: 1.0.0 opened it and blocked forever (or read until memory ran out).
    fifo = tmp_path / ".kashif-baseline.json"
    os.mkfifo(fifo)
    proc = subprocess.run([sys.executable, "-c", _PROBE, str(fifo)], cwd=str(ROOT), capture_output=True,
                          encoding="utf-8", errors="replace", timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == ["[]", "unreadable", "None", "refused"]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a FIFO (POSIX)")
def test_scan_with_a_fifo_baseline_exits_2(tmp_path):
    src = tmp_path / "proj"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    fifo = tmp_path / "base.json"
    os.mkfifo(fifo)
    proc = subprocess.run([sys.executable, "-m", "vulnscan", str(src), "--baseline", str(fifo), "--no-deps",
                           "--lang", "en"], cwd=str(ROOT), capture_output=True, encoding="utf-8", errors="replace",
                          timeout=120)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "Traceback" not in proc.stderr and str(fifo) in proc.stderr


def _install_sh_supported() -> bool:
    if os.name == "nt" or not shutil.which("sh"):
        return False
    if not (shutil.which("sha256sum") or shutil.which("shasum")):
        return False
    system = platform.system()
    return system == "Darwin" or (system == "Linux" and platform.machine().lower() in ("x86_64", "amd64"))


_FAKE_CURL = """#!/bin/sh
# offline stand-in for curl: '-o FILE URL' copies $FAKE_RELEASE/<last part of URL> to FILE
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    --proto) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
f="$FAKE_RELEASE/${url##*/}"
[ -f "$f" ] || exit 22
cp "$f" "$out"
"""


@pytest.mark.skipif(not _install_sh_supported(), reason="install.sh runs on Linux x86_64 and macOS with sh")
def test_install_sh_relative_install_dir_gives_a_working_alias(tmp_path):
    # 1.0.0: KASHIF_INSTALL_DIR=bin made bin/vulnscan -> "bin/kashif", a link relative to bin/ itself (dangling)
    release = tmp_path / "release"
    release.mkdir()
    sums = []
    for name in ("kashif-linux-x86_64", "kashif-macos-arm64", "kashif-macos-x86_64"):
        body = b'#!/bin/sh\necho "kashif 9.9.9"\n'
        (release / name).write_bytes(body)
        sums.append(f"{hashlib.sha256(body).hexdigest()}  {name}\n")
    (release / "SHA256SUMS.txt").write_text("".join(sums), encoding="utf-8", newline="")
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    curl = fakebin / "curl"
    curl.write_text(_FAKE_CURL, encoding="utf-8", newline="")
    curl.chmod(0o755)
    work = tmp_path / "work"
    work.mkdir()
    env = dict(os.environ, PATH=f"{fakebin}{os.pathsep}{os.environ.get('PATH', '')}", FAKE_RELEASE=str(release),
               KASHIF_INSTALL_DIR="bin")
    env.pop("KASHIF_VERSION", None)
    proc = subprocess.run(["sh", str(ROOT / "site" / "install.sh")], cwd=str(work), env=env, capture_output=True,
                          encoding="utf-8", errors="replace", timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    alias = work / "bin" / "vulnscan"
    assert alias.is_symlink() and alias.exists(), os.readlink(alias)
    out = subprocess.run([str(alias), "--version"], capture_output=True, encoding="utf-8", errors="replace",
                         timeout=60)
    assert out.returncode == 0 and out.stdout.strip() == "kashif 9.9.9"
    # the PATH hint names the absolute folder, not "bin"
    assert str((work / "bin").resolve()) in proc.stdout or str(work / "bin") in proc.stdout


def test_lsp_add_to_baseline_does_not_write_through_a_planted_tmp_symlink(tmp_path):
    # 1.0.0 wrote "<baseline>.tmp" by name: a workspace that commits .kashif-baseline.json.tmp as a symlink to, say,
    # ~/.bashrc had that file overwritten with JSON holding repository file names ("$(...)" runs in a shell) as soon
    # as the user picked "Add to baseline" in the editor.
    from vulnscan.lsp import add_to_baseline
    from vulnscan.model import Finding

    victim = tmp_path / "victim.txt"
    victim.write_text("keep me\n", encoding="utf-8")
    ws = tmp_path / "ws"
    ws.mkdir()
    try:
        os.symlink(victim, ws / ".kashif-baseline.json.tmp")
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links cannot be created here")
    finding = Finding("SEC001", "high", "t", "t", "$(touch PWNED).py", 1, "x", "a")
    assert add_to_baseline(ws / ".kashif-baseline.json", finding) is True
    assert victim.read_text(encoding="utf-8") == "keep me\n"
    base = ws / ".kashif-baseline.json"
    assert not base.is_symlink() and finding.fingerprint() in baseline.load_baseline(str(base))
    assert sorted(p.name for p in ws.iterdir()) == [".kashif-baseline.json", ".kashif-baseline.json.tmp"]
