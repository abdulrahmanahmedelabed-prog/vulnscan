"""In-app update (vulnscan/updater.py): no real network. A local HTTP fake stands in for the GitHub API and its
download hosts; the API base and the download host allowlist are injected through updater.Net (test-only)."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from vulnscan import updater
from vulnscan.i18n import has_arabic, translated

POSIX = os.name != "nt"


# ------------------------------------------------------------------------------------------- the fake

class Fake:
    """routes: path -> (status, headers, body). Records every request path."""

    def __init__(self):
        self.routes: dict[str, tuple[int, dict, bytes]] = {}
        self.closed = False
        self.hits: list[str] = []
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                fake.hits.append(self.path)
                status, headers, body = fake.routes.get(self.path, (404, {}, b"{}"))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.net = updater.Net(api_url=self.base + "/api/latest", allowed_hosts=frozenset({"127.0.0.1"}), require_https=False,
                              asset_path="/dl/{name}")

    def release(self, tag="v0.9.0", files: dict[str, bytes] | None = None, sums: str | None = None, prerelease=False,
                extra_assets=()):
        files = dict(files or {})
        if sums is None:
            sums = "".join(f"{hashlib.sha256(b).hexdigest()}  {n}\n" for n, b in files.items())
        assets = []
        for name, body in files.items():
            self.routes[f"/dl/{name}"] = (200, {"Content-Type": "application/octet-stream"}, body)
            assets.append({"name": name, "browser_download_url": f"{self.base}/dl/{name}", "size": len(body)})
        self.routes["/dl/SHA256SUMS.txt"] = (200, {}, sums.encode())
        assets.append({"name": "SHA256SUMS.txt", "browser_download_url": f"{self.base}/dl/SHA256SUMS.txt", "size": len(sums)})
        assets += list(extra_assets)
        body = {"tag_name": tag, "prerelease": prerelease, "draft": False, "body": "## What's new\n<b>not html</b>",
                "html_url": "https://github.com/abdulrahmanahmedelabed-prog/vulnscan/releases/tag/" + tag,
                "published_at": "2026-11-01T00:00:00Z", "assets": assets}
        self.routes["/api/latest"] = (200, {"Content-Type": "application/json"}, json.dumps(body).encode())

    def close(self):
        if not self.closed:
            self.closed = True
            self.httpd.shutdown()
            self.httpd.server_close()          # nothing listens any more: connections are refused at once


@pytest.fixture
def fake():
    f = Fake()
    yield f
    f.close()


def script(version: str) -> bytes:
    """A stand-in for the binary: prints its version for --version, like the real one."""
    return f"#!/bin/sh\necho 'vulnscan {version}'\n".encode()


@pytest.fixture
def installed(tmp_path):
    """A fake installed 'binary' (0.8.0) in its own directory."""
    d = tmp_path / "bin"
    d.mkdir()
    exe = d / "vulnscan"
    exe.write_bytes(script("0.8.0"))
    exe.chmod(0o755)
    return exe


@pytest.fixture
def no_header_check(monkeypatch):
    """The fake binaries are shell scripts, not ELF files; the header check has its own tests."""
    monkeypatch.setattr(updater, "check_header", lambda head, asset: True)


def do_apply(fake, exe, **kw):
    return updater.apply(net=fake.net, current=kw.pop("current", "0.8.0"), exe=exe, asset="vulnscan-linux", kind="binary", **kw)


def leftovers(exe: pathlib.Path) -> list[str]:
    return sorted(p.name for p in exe.parent.glob(".vulnscan-update-*"))


# ------------------------------------------------------------------------------------------- versions

@pytest.mark.parametrize("latest,current,expected", [
    ("0.10.0", "0.9.0", True),            # numeric, not string, comparison
    ("0.9.0", "0.10.0", False),
    ("v0.9.0", "0.8.10", True),           # "v" prefix
    ("0.8.10", "v0.9.0", False),
    ("1.0", "0.99.99", True),
    ("0.9.0", "0.9.0", False),            # same version is not an update
    ("v0.9.0", "0.9.0", False),
    ("0.8.0", "0.9.0", False),            # downgrade
    ("0.9.0-rc.1", "0.8.0", False),       # prereleases are never offered
    ("0.9.0rc1", "0.8.0", False),
    ("0.9.0", "0.9.0rc1", True),          # the release is newer than its own prerelease
    ("not-a-version", "0.8.0", False),
    ("", "0.8.0", False),
])
def test_is_newer(latest, current, expected):
    assert updater.is_newer(latest, current) is expected


# ------------------------------------------------------------------------------------------- platform

@pytest.mark.parametrize("system,machine,translated,asset", [
    ("Windows", "AMD64", None, "kashif-windows-x86_64.exe"),
    ("Windows", "ARM64", None, None),
    ("Linux", "x86_64", None, "kashif-linux-x86_64"),
    ("Linux", "aarch64", None, None),
    ("Darwin", "arm64", None, "kashif-macos-arm64"),
    ("Darwin", "x86_64", False, "kashif-macos-x86_64"),
    ("Darwin", "x86_64", True, "kashif-macos-arm64"),     # an Intel build under Rosetta gets the native build
    ("FreeBSD", "amd64", None, None),
])
def test_platform_asset(system, machine, translated, asset):
    assert updater.platform_asset(system, machine, translated) == asset


def test_every_asset_has_a_legacy_name():
    names = {updater.platform_asset(s, m, t) for s, m, t in
             [("Windows", "AMD64", None), ("Linux", "x86_64", None), ("Darwin", "arm64", None), ("Darwin", "x86_64", False)]}
    assert names == set(updater.LEGACY_ASSETS)
    assert set(updater.LEGACY_ASSETS.values()) == {"vulnscan-windows.exe", "vulnscan-linux", "vulnscan-macos-arm64",
                                                   "vulnscan-macos-x86_64"}


def test_resolve_asset_prefers_kashif_then_legacy():
    assert updater.resolve_asset("kashif-linux-x86_64", ["kashif-linux-x86_64", "vulnscan-linux"]) == "kashif-linux-x86_64"
    assert updater.resolve_asset("kashif-linux-x86_64", ["vulnscan-linux", "SHA256SUMS.txt"]) == "vulnscan-linux"
    assert updater.resolve_asset("kashif-linux-x86_64", ["vulnscan-windows.exe", "SHA256SUMS.txt"]) is None
    assert updater.resolve_asset("vulnscan-linux", ["vulnscan-linux"]) == "vulnscan-linux"
    assert updater.resolve_asset("vulnscan-linux", ["kashif-linux-x86_64"]) is None


def test_rosetta_probe_is_used_on_intel_mac(monkeypatch):
    monkeypatch.setattr(updater, "_proc_translated", lambda: True)
    assert updater.platform_asset("Darwin", "x86_64") == "kashif-macos-arm64"
    monkeypatch.setattr(updater, "_proc_translated", lambda: False)
    assert updater.platform_asset("Darwin", "x86_64") == "kashif-macos-x86_64"


# ----------------------------------------------------------------------------------- checksums, headers

def test_parse_sums_exact_name():
    h1, h2 = "a" * 64, "b" * 64
    text = f"{h2}  vulnscan-linux.sig\n{h1} *vulnscan-linux\n{'c' * 64}  vulnscan-linux-old\n"
    assert updater.parse_sums(text, "vulnscan-linux") == h1
    assert updater.parse_sums(text, "vulnscan-windows.exe") is None
    assert updater.parse_sums("garbage\n", "vulnscan-linux") is None


def _pe(machine=0x8664):
    head = bytearray(512)
    head[:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, 0x80)
    head[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", head, 0x84, machine)
    return bytes(head)


def _elf(machine=0x3E, cls=2):
    head = bytearray(64)
    head[:4] = b"\x7fELF"
    head[4], head[5] = cls, 1
    struct.pack_into("<H", head, 18, machine)
    return bytes(head)


def _macho(cpu):
    return b"\xcf\xfa\xed\xfe" + struct.pack("<I", cpu) + bytes(56)


@pytest.mark.parametrize("win,linux,arm,intel", [
    ("vulnscan-windows.exe", "vulnscan-linux", "vulnscan-macos-arm64", "vulnscan-macos-x86_64"),          # legacy
    ("kashif-windows-x86_64.exe", "kashif-linux-x86_64", "kashif-macos-arm64", "kashif-macos-x86_64"),    # current
])
def test_check_header(win, linux, arm, intel):
    assert updater.check_header(_pe(), win)
    assert not updater.check_header(_pe(0x14C), win)          # 32-bit x86
    assert not updater.check_header(_elf(), win)
    assert updater.check_header(_elf(), linux)
    assert not updater.check_header(_pe(), linux)
    assert not updater.check_header(_elf(0xB7), linux)                # aarch64
    assert not updater.check_header(_elf(cls=1), linux)               # 32-bit
    assert not updater.check_header(b"#!/bin/sh\n", linux)
    assert updater.check_header(_macho(0x0100000C), arm)
    assert not updater.check_header(_macho(0x0100000C), intel)
    assert updater.check_header(_macho(0x01000007), intel)
    assert not updater.check_header(_elf(), arm)
    assert updater.check_header(b"\xca\xfe\xba\xbe" + bytes(60), arm)   # universal
    assert not updater.check_header(b"<html>", arm)


def test_check_header_unknown_names_fail_closed():
    for name in ("kashif-linux-aarch64", "other-linux", "kashif-setup.exe", "vulnscan-sbom.cdx.json", "kashif-macos",
                 "kashif-windows-x86_64.exe.sig", ""):
        assert not updater.check_header(_pe(), name), name
        assert not updater.check_header(_elf(), name), name
        assert not updater.check_header(b"\xca\xfe\xba\xbe" + bytes(60), name), name


# ----------------------------------------------------------------------------------------------- check

def test_check_newer_cached_and_forced(fake, tmp_path, installed):
    fake.release("v0.9.0", {"vulnscan-linux": script("0.9.0")})
    kw = dict(home=tmp_path / "home", net=fake.net, current="0.8.0", info={"kind": "binary", "command": None},
              asset="vulnscan-linux", exe=installed)
    st = updater.check(**kw)
    assert st["newer"] and st["latest"] == "0.9.0" and st["current"] == "0.8.0"
    assert st["can_self_update"] and st["reason"] is None and not st["cached"]
    assert "not html" in st["notes"] and st["url"].startswith("https://github.com/")
    assert fake.hits.count("/api/latest") == 1
    again = updater.check(**kw)                                   # within 6 hours: served from the cache
    assert again["cached"] and again["latest"] == "0.9.0" and fake.hits.count("/api/latest") == 1
    updater.check(force=True, **kw)                               # "Check for updates" bypasses the cache
    assert fake.hits.count("/api/latest") == 2


def test_check_cache_expires(fake, tmp_path, monkeypatch):
    fake.release("v0.9.0", {"vulnscan-linux": b"x"})
    kw = dict(home=tmp_path / "home", net=fake.net, current="0.8.0", info={"kind": "pip", "command": "pip"}, asset=None)
    updater.check(**kw)
    real = time.time
    monkeypatch.setattr(updater.time, "time", lambda: real() + updater.CACHE_TTL + 5)
    updater.check(**kw)
    assert fake.hits.count("/api/latest") == 2


def test_check_up_to_date_and_prerelease(fake, tmp_path):
    kw = dict(home=tmp_path / "h", net=fake.net, info={"kind": "binary", "command": None}, asset="vulnscan-linux", force=True)
    fake.release("v0.8.0", {"vulnscan-linux": b"x"})
    assert not updater.check(current="0.8.0", **kw)["newer"]
    fake.release("v0.9.0-rc.1", {"vulnscan-linux": b"x"}, prerelease=True)
    assert not updater.check(current="0.8.0", **kw)["newer"]


def test_check_pip_returns_command(fake, tmp_path):
    fake.release("v0.9.0", {"vulnscan-linux": b"x"})
    st = updater.check(home=tmp_path / "h", net=fake.net, current="0.8.0",
                       info={"kind": "pip", "command": "python -m pip install --upgrade vulnscan"}, asset="vulnscan-linux")
    assert st["newer"] and not st["can_self_update"] and st["reason"] == "not_binary"
    assert st["command"] == "python -m pip install --upgrade vulnscan"
    assert not has_arabic(st["reason_message_en"])


def test_check_not_writable(fake, tmp_path, installed, monkeypatch):
    fake.release("v0.9.0", {"vulnscan-linux": b"x"})
    monkeypatch.setattr(updater, "_dir_writable", lambda d: False)
    st = updater.check(home=tmp_path / "h", net=fake.net, current="0.8.0", info={"kind": "binary", "command": None},
                       asset="vulnscan-linux", exe=installed)
    assert not st["can_self_update"] and st["reason"] == "not_writable"
    if POSIX:
        assert st["command"].startswith("sudo ") and st["command"].endswith(" update")


def test_check_unsupported_platform(fake, tmp_path):
    fake.release("v0.9.0", {"vulnscan-linux": b"x"})
    st = updater.check(home=tmp_path / "h", net=fake.net, current="0.8.0", info={"kind": "binary", "command": None}, asset="")
    assert st["reason"] == "unsupported_platform" and not st["can_self_update"]


def test_rate_limited_and_offline(fake, tmp_path):
    fake.routes["/api/latest"] = (403, {"X-RateLimit-Remaining": "0"}, b'{"message": "API rate limit exceeded"}')
    with pytest.raises(updater.UpdateError) as e:
        updater.check(home=tmp_path / "h", net=fake.net, force=True)
    assert e.value.code == "rate_limited"
    fake.close()
    with pytest.raises(updater.UpdateError) as e:
        updater.check(home=tmp_path / "h", net=fake.net, force=True)
    assert e.value.code == "offline"


def test_bad_json(fake, tmp_path):
    fake.routes["/api/latest"] = (200, {}, b"<html>")
    with pytest.raises(updater.UpdateError) as e:
        updater.fetch_release(fake.net)
    assert e.value.code == "bad_response"


def test_test_api_env_accepts_loopback_only(monkeypatch):
    monkeypatch.setenv(updater.ENV_TEST_API, "http://127.0.0.1:9/api")
    assert updater._api_url(updater.NET) == "http://127.0.0.1:9/api"
    monkeypatch.setenv(updater.ENV_TEST_API, "https://evil.example/api")
    assert updater._api_url(updater.NET) == updater.API_URL
    # the variable never widens where a binary may be downloaded from
    with pytest.raises(updater.UpdateError) as e:
        updater._check_url("http://127.0.0.1:9/dl/vulnscan-linux", updater.NET)
    assert e.value.code == "bad_host"
    for bad in ("http://github.com/x", "https://evil.example/x", "file:///etc/passwd", "https://github.com.evil.example/x"):
        with pytest.raises(updater.UpdateError):
            updater._check_url(bad, updater.NET)
    updater._check_url("https://objects.githubusercontent.com/x", updater.NET)


# ----------------------------------------------------------------------------------------------- apply

pytestmark_posix = pytest.mark.skipif(not POSIX, reason="the fake binary is a POSIX shell script")


@pytestmark_posix
def test_apply_swaps_and_keeps_backup(fake, installed, no_header_check):
    fake.release("v0.9.0", {"vulnscan-linux": script("0.9.0"), "vulnscan-windows.exe": b"MZ"})
    seen = []
    res = do_apply(fake, installed, progress=lambda ph, done, total: seen.append(ph))
    assert res["ok"] and res["from"] == "0.8.0" and res["to"] == "0.9.0" and res["restart_required"]
    assert installed.read_bytes() == script("0.9.0")
    assert os.access(installed, os.X_OK)
    assert updater.backup_path(installed).read_bytes() == script("0.8.0")
    assert updater.reports_version(installed, "0.9.0")
    assert seen[0] == "check" and "download" in seen and "verify" in seen and seen[-1] == "swap"
    assert not leftovers(installed)
    updater.cleanup_stale(installed)                    # next start removes the backup
    assert not updater.backup_path(installed).exists() and installed.exists()


def apply_kashif(fake, exe, **kw):
    return updater.apply(net=fake.net, current="0.8.0", exe=exe, asset="kashif-linux-x86_64", kind="binary", **kw)


@pytestmark_posix
def test_apply_prefers_the_kashif_asset(fake, installed, no_header_check):
    # a current release carries both names; the kashif-* one is downloaded and verified against its own sums line
    fake.release("v0.9.0", {"kashif-linux-x86_64": script("0.9.0"), "vulnscan-linux": script("0.9.0") + b"#legacy\n"})
    assert apply_kashif(fake, installed)["ok"]
    assert installed.read_bytes() == script("0.9.0")
    assert "/dl/kashif-linux-x86_64" in fake.hits and "/dl/vulnscan-linux" not in fake.hits


@pytestmark_posix
def test_apply_falls_back_to_the_legacy_asset(fake, installed, no_header_check):
    # a release made before the rename has only vulnscan-linux, and SHA256SUMS.txt lists only that name
    fake.release("v0.9.0", {"vulnscan-linux": script("0.9.0")})
    assert apply_kashif(fake, installed)["ok"]
    assert installed.read_bytes() == script("0.9.0") and "/dl/vulnscan-linux" in fake.hits
    assert not leftovers(installed)


@pytestmark_posix
def test_apply_legacy_fallback_keeps_the_checksum_check(fake, installed, no_header_check):
    # the fallback name is verified against its own line: a sums file listing only the kashif name is refused
    body = script("0.9.0")
    fake.release("v0.9.0", {"vulnscan-linux": body}, sums=f"{hashlib.sha256(body).hexdigest()}  kashif-linux-x86_64\n")
    with pytest.raises(updater.UpdateError) as e:
        apply_kashif(fake, installed)
    assert e.value.code == "checksum_missing"
    assert installed.read_bytes() == script("0.8.0") and not leftovers(installed)


def test_apply_asset_missing_under_both_names(fake, installed):
    fake.release("v0.9.0", {"vulnscan-windows.exe": b"MZ", "kashif-windows-x86_64.exe": b"MZ"})
    with pytest.raises(updater.UpdateError) as e:
        apply_kashif(fake, installed)
    assert e.value.code == "asset_missing"


def test_check_accepts_legacy_only_release(fake, tmp_path, installed):
    kw = dict(home=tmp_path / "h", net=fake.net, current="0.8.0", info={"kind": "binary", "command": None},
              asset="kashif-linux-x86_64", exe=installed, force=True)
    fake.release("v0.9.0", {"vulnscan-linux": b"x"})
    st = updater.check(**kw)
    assert st["newer"] and st["can_self_update"] and st["reason"] is None
    fake.release("v0.9.0", {"vulnscan-macos-arm64": b"x"})
    st = updater.check(**kw)
    assert not st["can_self_update"] and st["reason"] == "asset_missing"


@pytestmark_posix
def test_checksum_mismatch_refused(fake, installed, no_header_check):
    fake.release("v0.9.0", {"vulnscan-linux": script("0.9.0")}, sums=f"{'0' * 64}  vulnscan-linux\n")
    with pytest.raises(updater.UpdateError) as e:
        do_apply(fake, installed)
    assert e.value.code == "checksum_mismatch"
    assert installed.read_bytes() == script("0.8.0") and not leftovers(installed)
    assert not updater.backup_path(installed).exists()


@pytestmark_posix
def test_missing_checksum_line_refused(fake, installed, no_header_check):
    other = hashlib.sha256(b"x").hexdigest()
    fake.release("v0.9.0", {"vulnscan-linux": script("0.9.0")}, sums=f"{other}  vulnscan-linux.sig\n{other}  vulnscan-macos-arm64\n")
    with pytest.raises(updater.UpdateError) as e:
        do_apply(fake, installed)
    assert e.value.code == "checksum_missing"
    assert installed.read_bytes() == script("0.8.0") and not leftovers(installed)


def test_missing_sums_file_refused(fake, installed, no_header_check):
    fake.release("v0.9.0", {"vulnscan-linux": script("0.9.0")})
    body = json.loads(fake.routes["/api/latest"][2])
    body["assets"] = [a for a in body["assets"] if a["name"] != "SHA256SUMS.txt"]
    fake.routes["/api/latest"] = (200, {}, json.dumps(body).encode())
    with pytest.raises(updater.UpdateError) as e:
        do_apply(fake, installed)
    assert e.value.code == "checksum_missing"


@pytest.mark.parametrize("tag", ["v0.8.0", "v0.7.9", "v0.9.0-rc.1"])
def test_downgrade_or_same_refused(fake, installed, no_header_check, tag):
    fake.release(tag, {"vulnscan-linux": script(tag.lstrip("v"))})
    with pytest.raises(updater.UpdateError) as e:
        do_apply(fake, installed)
    assert e.value.code == "not_newer"
    assert installed.read_bytes() == script("0.8.0")
    assert not any(h.startswith("/dl/") for h in fake.hits)             # nothing was even downloaded


@pytestmark_posix
def test_size_cap(fake, installed, no_header_check, monkeypatch):
    fake.release("v0.9.0", {"vulnscan-linux": script("0.9.0") + b"#" * 5000})
    monkeypatch.setattr(updater, "MAX_BINARY", 1024)
    with pytest.raises(updater.UpdateError) as e:
        do_apply(fake, installed)
    assert e.value.code == "too_large" and not leftovers(installed)
    # a lying size in the API is caught while streaming too
    body = json.loads(fake.routes["/api/latest"][2])
    for a in body["assets"]:
        a["size"] = 10
    fake.routes["/api/latest"] = (200, {}, json.dumps(body).encode())
    with pytest.raises(updater.UpdateError) as e:
        do_apply(fake, installed)
    assert e.value.code == "too_large" and not leftovers(installed)
    assert installed.read_bytes() == script("0.8.0")


@pytestmark_posix
def test_header_check_refuses_non_executable(fake, installed):
    fake.release("v0.9.0", {"vulnscan-linux": script("0.9.0")})        # a shell script is not an ELF binary
    with pytest.raises(updater.UpdateError) as e:
        do_apply(fake, installed)
    assert e.value.code == "bad_binary"
    assert installed.read_bytes() == script("0.8.0") and not leftovers(installed)


@pytestmark_posix
def test_new_binary_must_report_expected_version(fake, installed, no_header_check):
    fake.release("v0.9.0", {"vulnscan-linux": script("0.8.5")})
    with pytest.raises(updater.UpdateError) as e:
        do_apply(fake, installed)
    assert e.value.code == "version_mismatch"
    assert installed.read_bytes() == script("0.8.0") and not leftovers(installed)


@pytestmark_posix
def test_redirect_to_other_host_refused(fake, installed, no_header_check):
    fake.release("v0.9.0", {"vulnscan-linux": script("0.9.0")})
    fake.routes["/dl/vulnscan-linux"] = (302, {"Location": f"http://localhost:{fake.port}/dl/x"}, b"")
    with pytest.raises(updater.UpdateError) as e:
        do_apply(fake, installed)
    assert e.value.code == "bad_host"
    assert installed.read_bytes() == script("0.8.0")
    assert "/dl/x" not in fake.hits                                    # the disallowed hop was never contacted


@pytestmark_posix
def test_rollback_when_installed_file_fails(fake, installed, no_header_check, monkeypatch):
    fake.release("v0.9.0", {"vulnscan-linux": script("0.9.0")})
    real = updater.reports_version
    calls = []

    def flaky(path, version):          # the downloaded file passes; the file once in place does not
        calls.append(pathlib.Path(path))
        return real(path, version) and len(calls) == 1

    monkeypatch.setattr(updater, "reports_version", flaky)
    with pytest.raises(updater.UpdateError) as e:
        do_apply(fake, installed)
    assert e.value.code == "swap_failed" and len(calls) == 2
    assert installed.read_bytes() == script("0.8.0")                   # restored from <exe>.old
    assert not leftovers(installed)


@pytestmark_posix
def test_rollback_when_replace_fails(fake, installed, no_header_check, monkeypatch):
    fake.release("v0.9.0", {"vulnscan-linux": script("0.9.0")})
    real = os.replace

    def broken(src, dst):
        if pathlib.Path(dst) == installed:
            raise OSError("disk full")
        return real(src, dst)

    monkeypatch.setattr(updater.os, "replace", broken)
    with pytest.raises(updater.UpdateError) as e:
        do_apply(fake, installed)
    assert e.value.code == "swap_failed"
    assert installed.read_bytes() == script("0.8.0") and not leftovers(installed)


def test_apply_refuses_non_binary_installs(fake, installed):
    with pytest.raises(updater.UpdateError) as e:
        updater.apply(net=fake.net, exe=installed, kind="pip")
    assert e.value.code == "not_binary"
    assert not fake.hits


def test_cleanup_stale_temp_files(installed):
    stale = installed.parent / ".vulnscan-update-abc"
    stale.write_bytes(b"x")
    old = time.time() - 7200
    os.utime(stale, (old, old))
    fresh = installed.parent / ".vulnscan-update-new"
    fresh.write_bytes(b"x")
    updater.backup_path(installed).write_bytes(b"x")
    updater.cleanup_stale(installed)
    assert not stale.exists() and fresh.exists() and not updater.backup_path(installed).exists()


# -------------------------------------------------------------------------------------------- install kind

class _Dist:
    def __init__(self, direct):
        self.direct = direct

    def read_text(self, name):
        return json.dumps(self.direct) if self.direct is not None else None


def test_install_info(monkeypatch, tmp_path):
    from importlib import metadata
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.setattr(updater, "_package_root", lambda: tmp_path)
    monkeypatch.setattr(metadata, "distribution", lambda name: _Dist(None))
    info = updater.install_info()
    assert info["kind"] == "pip" and info["command"].endswith("-m pip install --upgrade vulnscan")
    assert sys.executable in info["command"] or os.name == "nt"
    monkeypatch.setattr(metadata, "distribution", lambda name: _Dist(
        {"url": "https://github.com/abdulrahmanahmedelabed-prog/vulnscan", "vcs_info": {"vcs": "git"}}))
    assert "git+https://github.com/abdulrahmanahmedelabed-prog/vulnscan" in updater.install_info()["command"]
    monkeypatch.setattr(metadata, "distribution", lambda name: _Dist({"url": "file:///src", "dir_info": {"editable": True}}))
    assert updater.install_info()["kind"] == "source"
    (tmp_path / ".git").mkdir()
    info = updater.install_info()
    assert info["kind"] == "source" and info["command"].startswith("git -C ")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert updater.install_info()["kind"] == "binary"


# ----------------------------------------------------------------------------------------------- i18n / CLI

def test_messages_have_english():
    missing = [m for m in list(updater.MESSAGES.values()) + list(updater.CLI_TEXT.values()) if not translated(m.strip())]
    assert not missing, missing


STATUS = {"current": "0.8.0", "latest": "0.9.0", "newer": True, "notes": "", "url": "https://github.com/x", "install_kind": "binary",
          "asset": "vulnscan-linux", "command": None, "can_self_update": True, "reason": None, "checked_at": 0, "cached": False}


def test_cli_exit_codes(monkeypatch, capsys):
    from vulnscan.cli import main
    monkeypatch.setattr(updater, "check", lambda **kw: dict(STATUS))
    assert main(["update", "--check", "--lang", "en"]) == 10
    out = capsys.readouterr().out
    assert "Latest version: 0.9.0" in out and not has_arabic(out)
    monkeypatch.setattr(updater, "check", lambda **kw: {**STATUS, "newer": False, "latest": "0.8.0"})
    assert main(["update", "--check", "--lang", "en"]) == 0
    assert "latest version" in capsys.readouterr().out

    def offline(**kw):
        raise updater.UpdateError("offline")
    monkeypatch.setattr(updater, "check", offline)
    assert main(["update", "--lang", "en"]) == 1
    err = capsys.readouterr().err
    assert "Could not reach GitHub" in err and not has_arabic(err)


def test_cli_apply(monkeypatch, capsys):
    from vulnscan.cli import main
    monkeypatch.setattr(updater, "check", lambda **kw: dict(STATUS))
    calls = []

    def fake_apply(progress=None, **kw):
        calls.append(1)
        progress("download", 50, 100)
        progress("verify", 0, 0)
        progress("swap", 0, 0)
        return {"ok": True, "from": "0.8.0", "to": "0.9.0", "path": "/x/vulnscan", "backup": "/x/vulnscan.old"}
    monkeypatch.setattr(updater, "apply", fake_apply)
    monkeypatch.setattr(sys, "stdin", None)
    assert main(["update", "--lang", "en"]) == 1 and not calls          # no terminal and no --yes: refuse
    assert "--yes" in capsys.readouterr().err
    assert main(["update", "--yes", "--lang", "en"]) == 0 and calls
    cap = capsys.readouterr()
    assert "Updated successfully" in cap.out and "0.8.0 → 0.9.0" in cap.out and not has_arabic(cap.out + cap.err)
    monkeypatch.setattr(updater, "check", lambda **kw: {**STATUS, "can_self_update": False, "reason": "not_binary",
                                                        "install_kind": "pip", "command": "py -m pip install --upgrade vulnscan"})
    assert main(["update", "--yes", "--lang", "en"]) == 1
    assert "py -m pip install --upgrade vulnscan" in capsys.readouterr().out


# ------------------------------------------------------------------------------------------- server API

@pytest.fixture
def server(tmp_path):
    from vulnscan.server import Handler
    from vulnscan.store import Store
    Handler.store = Store(tmp_path / "home")
    Handler.update_job = updater.Job()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def call(base, path, method="GET", data=None, headers=None):
    h = {"Content-Type": "application/json", "Origin": base, **(headers or {})}
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(base + path, data=body, method=method, headers=h)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_server_check_and_setting(server, monkeypatch):
    forced = []
    monkeypatch.setattr(updater, "check", lambda force=False, home=None: forced.append(force) or dict(STATUS))
    st, body = call(server, "/api/update")
    assert st == 200 and body["newer"] and forced == [False]
    st, body = call(server, "/api/update?force=1")
    assert forced == [False, True]
    call(server, "/api/settings", "POST", {"check_updates": False})
    st, body = call(server, "/api/update")
    assert st == 200 and body["disabled"] and len(forced) == 2          # no network when automatic checks are off
    call(server, "/api/update?force=1")
    assert len(forced) == 3                                             # an explicit check still works

    def offline(**kw):
        raise updater.UpdateError("rate_limited")
    monkeypatch.setattr(updater, "check", offline)
    st, body = call(server, "/api/update?force=1")
    assert st == 502 and body["error"] == "rate_limited" and body["message_en"] and not has_arabic(body["message_en"])


def test_server_update_guards(server, monkeypatch):
    monkeypatch.setattr(updater, "check", lambda **kw: dict(STATUS))
    started = []
    monkeypatch.setattr(updater.Job, "start", lambda self, **kw: started.append(kw) or True)
    monkeypatch.setattr(updater, "install_info", lambda: {"kind": "binary", "command": None})
    assert call(server, "/api/update", "POST", {}, headers={"Origin": "http://evil.example"})[0] == 403
    assert call(server, "/api/update", "POST", {}, headers={"Host": "attacker.example", "Origin": "http://attacker.example"})[0] == 403  # DNS rebinding
    assert call(server, "/api/update", "POST", {}, headers={"Content-Type": "text/plain"})[0] == 403
    assert call(server, "/api/update/restart", "POST", {}, headers={"Origin": "http://evil.example"})[0] == 403
    assert not started
    monkeypatch.setattr(updater, "install_info", lambda: {"kind": "pip", "command": "pip"})
    st, body = call(server, "/api/update", "POST", {})
    assert st == 400 and body["error"] == "not_binary" and not started
    monkeypatch.setattr(updater, "install_info", lambda: {"kind": "binary", "command": None})
    monkeypatch.setattr(updater, "check", lambda **kw: {**STATUS, "newer": False})
    st, body = call(server, "/api/update", "POST", {})
    assert st == 409 and body["error"] == "up_to_date" and not started
    monkeypatch.setattr(updater, "check", lambda **kw: {**STATUS, "can_self_update": False, "reason": "not_writable"})
    st, body = call(server, "/api/update", "POST", {})
    assert st == 409 and body["error"] == "not_writable" and not started


def test_server_apply_progress_and_restart(server, monkeypatch):
    monkeypatch.setattr(updater, "install_info", lambda: {"kind": "binary", "command": None})
    monkeypatch.setattr(updater, "check", lambda **kw: dict(STATUS))
    gate = threading.Event()

    def fake_apply(progress=None, **kw):
        progress("download", 10, 100)
        gate.wait(5)
        progress("verify", 0, 0)
        return {"ok": True, "from": "0.8.0", "to": "0.9.0", "path": "/x", "backup": "/x.old"}
    monkeypatch.setattr(updater, "apply", fake_apply)
    restarted = []
    monkeypatch.setattr(updater, "restart", lambda args=None, exe=None: restarted.append(args))

    st, body = call(server, "/api/update/restart", "POST", {})
    assert st == 409 and body["error"] == "not_ready"
    st, body = call(server, "/api/update", "POST", {})
    assert st == 202
    for _ in range(100):
        snap = call(server, "/api/update/status")[1]
        if snap["phase"] == "download":
            break
        time.sleep(0.02)
    assert snap["phase"] == "download" and snap["bytes"] == 10 and snap["total"] == 100
    assert call(server, "/api/update", "POST", {})[1]["error"] == "busy"            # one update at a time
    gate.set()
    for _ in range(100):
        snap = call(server, "/api/update/status")[1]
        if snap["phase"] == "done":
            break
        time.sleep(0.02)
    assert snap["phase"] == "done" and snap["result"]["to"] == "0.9.0"
    st, _ = call(server, "/api/update/restart", "POST", {})
    assert st == 202
    for _ in range(100):
        if restarted:
            break
        time.sleep(0.02)
    assert restarted and restarted[0][0] == "ui" and "--no-browser" in restarted[0]


def test_server_apply_error_is_reported(server, monkeypatch):
    monkeypatch.setattr(updater, "install_info", lambda: {"kind": "binary", "command": None})
    monkeypatch.setattr(updater, "check", lambda **kw: dict(STATUS))

    def failing(progress=None, **kw):
        raise updater.UpdateError("checksum_mismatch", "abc != def")
    monkeypatch.setattr(updater, "apply", failing)
    assert call(server, "/api/update", "POST", {})[0] == 202
    for _ in range(100):
        snap = call(server, "/api/update/status")[1]
        if snap["phase"] == "error":
            break
        time.sleep(0.02)
    assert snap["error"] == "checksum_mismatch" and "SHA-256" in snap["message_en"]


# ------------------------------------------------------------------------- adversarial review (regressions)

def test_parse_sums_robust_and_fails_closed():
    h1, h2 = "A" * 64, "b" * 64
    # BOM, CRLF, upper-case hex, binary-mode marker, trailing spaces
    assert updater.parse_sums(f"﻿{h1} *vulnscan-linux \r\n", "vulnscan-linux") == h1.lower()
    # near-miss names never match
    for name in ("vulnscan-linux.bak", "./vulnscan-linux", "dir/vulnscan-linux", "VULNSCAN-LINUX", "vulnscan-linux2"):
        assert updater.parse_sums(f"{h1}  {name}\n", "vulnscan-linux") is None, name
    # two different digests for one name: ambiguous, refused; a repeated identical line is fine
    assert updater.parse_sums(f"{h1}  vulnscan-linux\n{h2}  vulnscan-linux\n", "vulnscan-linux") is None
    assert updater.parse_sums(f"{h2}  vulnscan-linux\n{h2}  vulnscan-linux\n", "vulnscan-linux") == h2
    assert updater.parse_sums(f"{'a' * 63}  vulnscan-linux\n", "vulnscan-linux") is None


def test_check_url_rejects_ports_userinfo_and_junk():
    for bad in ("https://github.com:8443/x", "https://user@github.com/x", "https://github.com:x/x",
                "https://evil.example\\@github.com/x", "HTTPS://evil.example/x", "ftp://github.com/x", "//github.com/x"):
        with pytest.raises(updater.UpdateError):
            updater._check_url(bad, updater.NET)
    updater._check_url("https://github.com:443/x", updater.NET)
    updater._check_url("https://GitHub.com/x", updater.NET)               # host names are case-insensitive


def test_asset_url_must_be_the_official_repo_and_tag():
    ok = f"https://github.com/{updater.REPO}/releases/download/v0.9.0/vulnscan-linux"
    updater._check_asset_url(ok, "v0.9.0", "vulnscan-linux", updater.NET)
    for bad in (f"https://github.com/attacker/vulnscan/releases/download/v0.9.0/vulnscan-linux",
                f"https://github.com/{updater.REPO}/releases/download/v0.1.0/vulnscan-linux",     # another (older) tag
                f"https://github.com/{updater.REPO}/releases/download/v0.9.0/vulnscan-linux.bak",
                f"https://github.com/{updater.REPO}/releases/download/v0.9.0/../../../attacker/x/vulnscan-linux",
                f"https://objects.githubusercontent.com/{updater.REPO}/releases/download/v0.9.0/vulnscan-linux#x",
                f"http://github.com/{updater.REPO}/releases/download/v0.9.0/vulnscan-linux"):
        with pytest.raises(updater.UpdateError) as e:
            updater._check_asset_url(bad, "v0.9.0", "vulnscan-linux", updater.NET)
        assert e.value.code == "bad_host", bad


@pytestmark_posix
def test_apply_refuses_assets_outside_the_release_path(fake, installed, no_header_check):
    body = script("0.9.0")
    fake.release("v0.9.0", {"vulnscan-linux": body})
    rel = json.loads(fake.routes["/api/latest"][2])
    for a in rel["assets"]:                       # same allowed host, but another repository's / directory's files
        a["browser_download_url"] = a["browser_download_url"].replace("/dl/", "/other/")
    fake.routes["/api/latest"] = (200, {}, json.dumps(rel).encode())
    fake.routes["/other/vulnscan-linux"] = (200, {}, body)
    with pytest.raises(updater.UpdateError) as e:
        do_apply(fake, installed)
    assert e.value.code == "bad_host"
    assert not any(h.startswith("/other/") for h in fake.hits)            # nothing was downloaded
    assert installed.read_bytes() == script("0.8.0") and not leftovers(installed)


def test_test_api_env_is_never_used_to_install(monkeypatch, installed):
    monkeypatch.setenv(updater.ENV_TEST_API, "http://127.0.0.1:9/api")
    seen = []

    def fake_fetch(net=updater.NET, api=None):
        seen.append(api or net.api_url)
        raise updater.UpdateError("offline")
    monkeypatch.setattr(updater, "fetch_release", fake_fetch)
    with pytest.raises(updater.UpdateError):
        updater.apply(exe=installed, asset="vulnscan-linux", kind="binary")
    assert seen == [updater.API_URL]
    with pytest.raises(updater.UpdateError):
        updater.check(force=True, home=installed.parent, info={"kind": "pip", "command": "x"}, asset="vulnscan-linux")
    assert seen[-1] == "http://127.0.0.1:9/api"                           # the check may use the loopback fake


def test_api_redirect_off_host_refused(fake):
    fake.routes["/api/latest"] = (302, {"Location": f"http://localhost:{fake.port}/evil"}, b"")
    with pytest.raises(updater.UpdateError) as e:
        updater.fetch_release(fake.net)
    assert e.value.code == "bad_host" and "/evil" not in fake.hits


@pytest.mark.parametrize("body", [b"[]", b'{"tag_name": "v1.0.0", "assets": [{"name": "x", "size": "big"}]}',
                                  b'{"tag_name": "v1.0.0", "assets": 5}'])
def test_malformed_release_is_bad_response(fake, body):
    fake.routes["/api/latest"] = (200, {}, body)
    with pytest.raises(updater.UpdateError) as e:
        updater.fetch_release(fake.net)
    assert e.value.code == "bad_response"


class _Resp:
    def __init__(self, chunks, length, exc=None):
        self.chunks, self.headers, self.exc = list(chunks), {"Content-Length": str(length)}, exc

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n):
        if self.chunks:
            return self.chunks.pop(0)
        if self.exc:
            raise self.exc
        return b""


def test_truncated_or_broken_download_is_download_failed(monkeypatch):
    import http.client
    import io
    monkeypatch.setattr(updater, "_open", lambda *a, **k: _Resp([b"x" * 10], 100))
    with pytest.raises(updater.UpdateError) as e:
        updater._download("https://github.com/x", io.BytesIO(), updater.NET, 1000)
    assert e.value.code == "download_failed"
    monkeypatch.setattr(updater, "_open", lambda *a, **k: _Resp([b"x" * 10], 100, http.client.IncompleteRead(b"x")))
    with pytest.raises(updater.UpdateError) as e:
        updater._download("https://github.com/x", io.BytesIO(), updater.NET, 1000)
    assert e.value.code == "download_failed"


def test_disk_full_mid_download(monkeypatch):
    class Full:
        def write(self, b):
            raise OSError(28, "No space left on device")
    monkeypatch.setattr(updater, "_open", lambda *a, **k: _Resp([b"x" * 10], 10))
    with pytest.raises(updater.UpdateError) as e:
        updater._download("https://github.com/x", Full(), updater.NET, 1000)
    assert e.value.code == "download_failed"


@pytestmark_posix
def test_fsync_failure_leaves_old_binary(fake, installed, no_header_check, monkeypatch):
    fake.release("v0.9.0", {"vulnscan-linux": script("0.9.0")})

    def full(fd):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(updater.os, "fsync", full)
    with pytest.raises(updater.UpdateError) as e:
        do_apply(fake, installed)
    assert e.value.code == "download_failed"
    assert installed.read_bytes() == script("0.8.0") and not leftovers(installed)


@pytestmark_posix
@pytest.mark.parametrize("before,after", [(0o755, 0o755), (0o700, 0o700), (0o777, 0o755), (0o775, 0o755)])
def test_new_binary_mode_never_group_or_world_writable(fake, installed, no_header_check, before, after):
    installed.chmod(before)
    fake.release("v0.9.0", {"vulnscan-linux": script("0.9.0")})
    do_apply(fake, installed)
    assert installed.stat().st_mode & 0o777 == after


@pytestmark_posix
def test_reports_version_is_exact(tmp_path):
    exe = tmp_path / "v"
    exe.write_bytes(script("0.9.0.1"))
    exe.chmod(0o755)
    assert not updater.reports_version(exe, "0.9.0")
    assert updater.reports_version(exe, "0.9.0.1")
    exe.write_bytes(script("0.9.0-rc1"))
    assert not updater.reports_version(exe, "0.9.0")


@pytestmark_posix
def test_reports_version_accepts_the_kashif_name(tmp_path):
    exe = tmp_path / "v"
    exe.write_bytes(b"#!/bin/sh\necho 'kashif 1.0.1'\n")
    exe.chmod(0o755)
    assert updater.reports_version(exe, "1.0.1")
    assert not updater.reports_version(exe, "1.0.0")


def test_version_output_is_what_v09_updaters_accept(capsys):
    """v0.9.x self-updaters run the new binary with --version and require exactly this pattern (copied from their
    updater.reports_version); changing the output would make every 0.9.x install refuse the update."""
    import re

    from vulnscan import __version__, cli
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0
    out = capsys.readouterr().out
    assert out.strip() == f"vulnscan {__version__}"
    assert re.search(rf"\bvulnscan\s+v?{re.escape(__version__)}(?![\w.+-])", out)


def test_job_refuses_second_install_and_double_restart():
    job = updater.Job()
    job.state = {"phase": "done", "bytes": 0, "total": 0}
    assert not job.start()
    assert job.claim_restart() and not job.claim_restart()
    assert not job.start()
    job.restart_failed("exec failed")
    assert job.snapshot()["phase"] == "done" and job.snapshot()["restart_error"] == "exec failed"
    assert job.claim_restart() and "restart_error" not in job.snapshot()


def test_server_dns_rebinding_and_cross_site_refused(server, monkeypatch):
    checked = []
    monkeypatch.setattr(updater, "check", lambda **kw: checked.append(kw) or dict(STATUS))
    evil = {"Host": "attacker.example:1234", "Origin": "http://attacker.example:1234"}
    for path in ("/api/update", "/api/update/status", "/api/scans", "/api/settings"):
        assert call(server, path, headers=evil)[0] == 403, path                  # rebinding cannot read the API
    assert call(server, "/api/settings", "POST", {"check_updates": False}, headers=evil)[0] == 403
    assert call(server, "/api/update?force=1", headers={"Sec-Fetch-Site": "cross-site"})[0] == 403  # <img src=...>
    assert call(server, "/api/update?force=1", headers={"Sec-Fetch-Site": "same-site"})[0] == 403   # another local port
    assert call(server, "/api/update", "POST", {}, headers={"Sec-Fetch-Site": "cross-site"})[0] == 403
    assert not checked
    assert call(server, "/api/update", headers={"Sec-Fetch-Site": "same-origin"})[0] == 200
    assert call(server, "/api/update", headers={"Host": "localhost:1"})[0] == 200
    assert call(server, "/api/settings")[0] == 200


def test_server_restart_once_and_restart_failure(server, monkeypatch):
    from vulnscan.server import Handler
    monkeypatch.setattr(updater, "install_info", lambda: {"kind": "binary", "command": None})
    monkeypatch.setattr(updater, "check", lambda **kw: dict(STATUS))
    Handler.update_job.state = {"phase": "done", "bytes": 0, "total": 0, "result": {"to": "0.9.0"}}
    st, body = call(server, "/api/update", "POST", {})
    assert st == 409 and body["error"] == "restart_pending" and not has_arabic(body["message_en"])
    calls = []

    def broken(args=None, exe=None):
        calls.append(args)
        raise OSError("exec format error")
    monkeypatch.setattr(updater, "restart", broken)
    assert call(server, "/api/update/restart", "POST", {})[0] == 202
    assert call(server, "/api/update/restart", "POST", {})[0] == 409            # a double click starts one process
    for _ in range(100):
        snap = call(server, "/api/update/status")[1]
        if snap.get("restart_error"):
            break
        time.sleep(0.02)
    assert len(calls) == 1 and snap["phase"] == "done" and "exec format" in snap["restart_error"]
    assert call(server, "/api/update/restart", "POST", {})[0] == 202            # and the UI may try again
    for _ in range(100):                          # let the timer fire while restart is still patched
        if len(calls) == 2:
            break
        time.sleep(0.02)
    assert len(calls) == 2
