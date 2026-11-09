"""jadx integration, exercised with a stub `jadx` executable on PATH."""
import os
import pathlib
import stat
import zipfile

import sys

import pytest

from vulnscan.scanner import JADX_LIB_EXCLUDES, decompile_with_jadx, jadx_available, scan_path

STUB = """#!/bin/sh
# stub jadx: args ... -d OUT FILE
while [ $# -gt 1 ]; do
  if [ "$1" = "-d" ]; then OUT="$2"; fi
  shift
done
mkdir -p "$OUT/sources/com/example/app" "$OUT/sources/okhttp3" "$OUT/resources"
cat > "$OUT/sources/com/example/app/Main.java" <<'JAVA'
public class Main {
    void run(String cmd) throws Exception { Runtime.getRuntime().exec("sh -c " + cmd); }
    String key = "AKIAIOSFODNN7EXAMPLE";
}
JAVA
printf 'class H { void x() { java.security.MessageDigest.getInstance("MD5"); } }\\n' > "$OUT/sources/okhttp3/H.java"
printf '<manifest><application android:usesCleartextTraffic="true"/></manifest>\\n' > "$OUT/resources/AndroidManifest.xml"
exit 0
"""


@pytest.fixture
def stub_jadx(tmp_path, monkeypatch):
    if sys.platform == "win32":
        pytest.skip("the jadx stub is a POSIX shell script (real jadx on Windows is jadx.bat, found via PATHEXT)")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "jadx"
    exe.write_text(STUB)
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    return exe


@pytest.fixture
def apk(tmp_path):
    path = tmp_path / "demo.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("assets/config.json", '{"password": "supersecret123"}')
        zf.writestr("classes.dex", b"dex\n035\x00binary")
    return path


def test_jadx_detected(stub_jadx):
    assert jadx_available() == str(stub_jadx)
    out, note = decompile_with_jadx(pathlib.Path("/nonexistent.apk"))
    assert out is not None and "2" in note
    assert (out / "sources/com/example/app/Main.java").exists()


def test_apk_scanned_with_decompiled_code(stub_jadx, apk):
    notes = []
    findings, count = scan_path(apk, notes=notes)
    ids = {(f.rule_id, f.file) for f in findings}
    assert ("SEC004", "demo.apk!assets/config.json") in ids            # text inside the archive
    assert ("EXE006", "demo.apk!decompiled/sources/com/example/app/Main.java") in ids
    assert ("SEC002", "demo.apk!decompiled/sources/com/example/app/Main.java") in ids
    assert ("MOB001", "demo.apk!decompiled/resources/AndroidManifest.xml") in ids
    assert not any("okhttp3" in f for _, f in ids)                      # third-party lib excluded
    assert any(f.extra.get("decompiled") for f in findings)
    assert any(n.startswith("jadx:") for n in notes)


def test_jadx_include_libs_and_disable(stub_jadx, apk):
    findings, _ = scan_path(apk, jadx_include_libs=True)
    assert any("okhttp3" in f.file and f.rule_id == "CRY001" for f in findings)
    notes = []
    findings, _ = scan_path(apk, jadx=False, notes=notes)
    assert not any("decompiled" in f.file for f in findings) and notes == []


def test_without_jadx_adds_note(apk, monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent-bin")
    notes = []
    findings, _ = scan_path(apk, notes=notes)
    assert any("jadx غير مثبّت" in n for n in notes)
    assert all("decompiled" not in f.file for f in findings)


def test_lib_excludes_are_globs():
    assert all(p.endswith("/*") for p in JADX_LIB_EXCLUDES)
