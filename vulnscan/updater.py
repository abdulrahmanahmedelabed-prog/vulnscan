"""In-app update: check GitHub Releases for a newer version and, for the standalone binary, replace it safely.

Security model (the same shape as the self-updaters of gh, rustup and VS Code):

* Only the official repository's releases are consulted, over HTTPS. Downloads are accepted only from GitHub's own
  hosts, and every redirect hop is checked before it is followed.
* The binary is verified against the exact line for its asset name in the release's ``SHA256SUMS.txt``; a missing
  line or a mismatch aborts the update. The file header must match the platform (PE / ELF / Mach-O and CPU), the new
  binary must report the expected version when run with ``--version``, and a downgrade (or the same version) is refused.
* The swap is atomic (temp file in the executable's own directory, then ``os.replace``) and keeps ``<exe>.old`` as a
  backup; any failure rolls back. Stale backups are removed at the next start.
* pip and source installs are never modified: the exact command to run is returned instead.

Nothing here reads hosts or URLs from user input. The API base and the download host allowlist are injectable for
tests only (``Net``); the ``VULNSCAN_UPDATE_API`` environment variable (test-only, documented) may point the *check*
at a loopback fake API; it is never used to install, and never affects which hosts or which repository path a binary
may be downloaded from.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import json
import os
import pathlib
import platform
import re
import shlex
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from . import __version__
from .i18n import localize, to_en

REPO = "abdulrahmanahmedelabed-prog/vulnscan"
API_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_URL = f"https://github.com/{REPO}/releases/latest"
DOWNLOAD_HOSTS = frozenset({"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"})
SUMS_NAME = "SHA256SUMS.txt"
MAX_BINARY = 200 * 1024 * 1024          # no release binary is anywhere near this; a larger body is refused
MAX_SUMS = 64 * 1024
MAX_API = 2 * 1024 * 1024
CACHE_TTL = 6 * 3600
NOTES_MAX = 6000
TIMEOUT = 20
VERSION_TIMEOUT = 90                    # a one-file binary unpacks itself before printing its version
CHUNK = 256 * 1024
ENV_TEST_API = "VULNSCAN_UPDATE_API"   # test-only: a loopback fake for the release API (see module docstring)


@dataclass(frozen=True)
class Net:
    """Where the updater talks to. The defaults are the real GitHub endpoints; tests inject a local fake."""
    api_url: str = API_URL
    allowed_hosts: frozenset = field(default=DOWNLOAD_HOSTS)
    require_https: bool = True
    # Where a release asset must live: the official repository's download path for that exact tag. A release API
    # answer (or the test-only loopback API) can therefore never point at another repository's files.
    asset_path: str = "/" + REPO + "/releases/download/{tag}/{name}"


NET = Net()

# Arabic is the project's first language; English is in vulnscan/i18n/cat_updater.py.
MESSAGES = {
    "offline": "تعذّر الاتصال بـ GitHub. تحقّق من اتصالك بالإنترنت أو من إعدادات الوكيل (HTTPS_PROXY) ثم أعد المحاولة.",
    "rate_limited": "بلغت حدّ طلبات GitHub المسموح به مؤقتًا. أعد المحاولة بعد قليل.",
    "bad_response": "ردّ GitHub غير متوقع. أعد المحاولة لاحقًا.",
    "no_release": "لا يوجد إصدار منشور بعد.",
    "not_binary": "التحديث من داخل البرنامج متاح للنسخة التنفيذية فقط. استخدم الأمر المعروض للتحديث.",
    "unsupported_platform": "لا توجد نسخة تنفيذية جاهزة لهذا النظام أو المعالج. نزّل الإصدار يدويًا من صفحة الإصدارات.",
    "not_writable": "لا يمكن الكتابة في مجلد البرنامج. شغّل التحديث بصلاحيات المسؤول أو نزّل الإصدار يدويًا.",
    "up_to_date": "أنت تستخدم أحدث إصدار.",
    "not_newer": "الإصدار المنشور ليس أحدث من إصدارك؛ لا يُثبَّت إصدار أقدم أو مماثل.",
    "asset_missing": "الإصدار المنشور لا يحتوي على ملف هذا النظام.",
    "checksum_missing": "ملف SHA256SUMS.txt لا يحتوي على بصمة هذا الملف؛ أُلغي التحديث حفاظًا على سلامتك.",
    "checksum_mismatch": "بصمة SHA-256 للملف المنزَّل لا تطابق البصمة المنشورة؛ أُلغي التحديث ولم يتغيّر شيء.",
    "too_large": "الملف المنزَّل أكبر من الحد المسموح؛ أُلغي التحديث.",
    "bad_host": "رُفض التنزيل: العنوان ليس من خوادم GitHub الموثوقة.",
    "bad_binary": "الملف المنزَّل ليس برنامجًا تنفيذيًا صالحًا لهذا النظام؛ أُلغي التحديث.",
    "version_mismatch": "النسخة الجديدة لم تُبلغ عن الإصدار المتوقع عند تجربتها؛ أُلغي التحديث.",
    "swap_failed": "تعذّر استبدال البرنامج؛ أُعيدت النسخة السابقة كما كانت.",
    "download_failed": "انقطع التنزيل أو فشل؛ لم يتغيّر شيء. أعد المحاولة.",
    "busy": "يوجد تحديث جارٍ بالفعل.",
    "not_ready": "لا يوجد تحديث مكتمل لإعادة التشغيل.",
    "restart_pending": "اكتمل التحديث بالفعل؛ أعد تشغيل كاشِف لاستخدام الإصدار الجديد.",
}


class UpdateError(Exception):
    """A user-explainable failure. `code` is stable (the UI maps it); `message` is Arabic, `message_en` English."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(MESSAGES.get(code, code))

    @property
    def message(self) -> str:
        return MESSAGES.get(self.code, self.code)

    def to_dict(self) -> dict:
        return {"error": self.code, "message": self.message, "message_en": to_en(self.message), "detail": self.detail}


# ------------------------------------------------------------------------------------------------ versions

_VER = re.compile(r"^\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-.+]?((?:a|b|rc|alpha|beta|pre|dev)[\w.]*))?(?:\+[\w.]+)?\s*$", re.I)


def parse_version(text: str) -> tuple | None:
    """A sortable key for "v1.2.3", "1.2", "0.9.0-rc.1", "0.9.0rc1". A prerelease sorts before its release."""
    m = _VER.match(str(text or ""))
    if not m:
        return None
    nums = tuple(int(g or 0) for g in m.group(1, 2, 3))
    pre = m.group(4)
    return nums + ((0, pre.lower()) if pre else (1, ""))


def is_prerelease(text: str) -> bool:
    key = parse_version(text)
    return bool(key) and key[3] == 0


def is_newer(latest: str, current: str) -> bool:
    """True when `latest` is a strictly newer stable release than `current` (prereleases are never offered)."""
    a, b = parse_version(latest), parse_version(current)
    if a is None or b is None or is_prerelease(latest):
        return False
    return a > b


def _clean(tag: str) -> str:
    return str(tag or "").strip().lstrip("vV")


# ------------------------------------------------------------------------------------------- environment

def _proc_translated() -> bool:
    """True when this process runs under Rosetta 2 (an Intel binary on Apple Silicon)."""
    try:
        out = subprocess.run(["/usr/sbin/sysctl", "-n", "sysctl.proc_translated"], capture_output=True, text=True,
                             timeout=3, check=False)  # nosec B603 - fixed argv, no shell
        return out.stdout.strip() == "1"
    except (OSError, subprocess.SubprocessError):
        return False


# Release asset names. Since the switch to the Kashif command name the canonical binaries are ``kashif-*``; every release
# also carries byte-identical copies under the legacy ``vulnscan-*`` names, because v0.9.x installs update themselves by
# looking for those. Releases published before the switch have only the legacy names, hence the fallback below.
LEGACY_ASSETS = {
    "kashif-windows-x86_64.exe": "vulnscan-windows.exe",
    "kashif-linux-x86_64": "vulnscan-linux",
    "kashif-macos-arm64": "vulnscan-macos-arm64",
    "kashif-macos-x86_64": "vulnscan-macos-x86_64",
}


def platform_asset(system: str | None = None, machine: str | None = None, translated: bool | None = None) -> str | None:
    """The release asset for this OS/CPU, or None when no prebuilt binary fits."""
    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower()
    if system == "windows":
        return "kashif-windows-x86_64.exe" if machine in ("amd64", "x86_64", "x64") else None
    if system == "linux":
        return "kashif-linux-x86_64" if machine in ("x86_64", "amd64") else None
    if system == "darwin":
        if machine in ("arm64", "aarch64"):
            return "kashif-macos-arm64"
        if machine in ("x86_64", "amd64"):
            if translated is None:
                translated = _proc_translated()
            return "kashif-macos-arm64" if translated else "kashif-macos-x86_64"
    return None


def resolve_asset(asset: str, names) -> str | None:
    """The name under which `asset` is published in a release with these asset `names`: the name itself, else (for a
    release made before the kashif-* names existed) its legacy vulnscan-* name, else None."""
    names = set(names)
    if asset in names:
        return asset
    legacy = LEGACY_ASSETS.get(asset)
    return legacy if legacy in names else None


def _package_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent


def _q(arg: str) -> str:
    if os.name == "nt":
        return f'"{arg}"' if (" " in arg or not arg) else arg
    return shlex.quote(arg)


# The pip distribution is "kashif" from 1.0.2 on (the import package stays `vulnscan`). Up to 1.0.1 it was "vulnscan",
# installed from git: "vulnscan" on PyPI is an unrelated project, so no command may ever name it as something to install.
DIST = "kashif"
LEGACY_DIST = "vulnscan"


def _distribution(name: str):
    try:
        from importlib import metadata
        return metadata.distribution(name)
    except Exception:  # noqa: BLE001 - PackageNotFoundError and broken metadata alike
        return None


def _direct_url(dist) -> dict:
    try:
        direct = json.loads(dist.read_text("direct_url.json") or "{}")
    except (ValueError, OSError, AttributeError):
        return {}
    return direct if isinstance(direct, dict) else {}


def _from_index(dist) -> bool:
    """Whether pip installed ``dist`` from a package index: PEP 610 writes direct_url.json for every other source
    (a VCS URL, a local or remote archive, a directory). Unreadable metadata counts as not from an index."""
    try:
        return dist.read_text("direct_url.json") is None
    except Exception:  # noqa: BLE001 - OSError, a mock or broken metadata
        return False


def _is_this_project(dist) -> bool:
    """Whether a distribution named "vulnscan" is this project (a pre-1.0.2 install), not the unrelated PyPI one."""
    try:
        md = dist.metadata
        urls = list(md.get_all("Project-URL") or []) + [md.get("Home-page") or ""]
        if any(REPO in str(u) for u in urls):
            return True
    except Exception:  # noqa: BLE001 - a mock or broken metadata
        pass
    try:                                       # 0.x had no project URLs: its RECORD lists this very module
        return any(str(f).replace("\\", "/") == "vulnscan/updater.py" for f in (dist.files or ()))
    except Exception:  # noqa: BLE001
        return False


def install_info() -> dict:
    """{kind: binary|pip|source, command: manual update command or None}.

    A pip install from before 1.0.2 is the distribution "vulnscan"; installing "kashif" over it leaves two
    distributions owning the same files (uninstalling either later deletes the other's), so the command for it
    removes the old one first."""
    if getattr(sys, "frozen", False):
        return {"kind": "binary", "command": None}
    root = _package_root()
    if (root / ".git").exists():
        return {"kind": "source", "command": f"git -C {_q(str(root))} pull"}
    dist = _distribution(DIST)
    legacy = _distribution(LEGACY_DIST)
    if legacy is not None and not _is_this_project(legacy):
        legacy = None                                      # someone else's "vulnscan": not ours to remove
    if dist is None and legacy is None:
        return {"kind": "source", "command": None}
    directs = [_direct_url(d) for d in (dist, legacy) if d is not None]
    dir_info = directs[0].get("dir_info")
    if isinstance(dir_info, dict) and dir_info.get("editable"):
        return {"kind": "source", "command": None}
    py = _q(sys.executable or "python3")
    # "kashif" is named as something to install only when the installed "kashif" itself came from a package index
    # (no direct_url.json): before the owner publishes it, that name on PyPI is unclaimed and anyone could upload
    # under it, so a local wheel, an archive, a directory or a pre-1.0.2 "vulnscan" install gets the git URL
    # (the documented install), never the bare name.
    target = DIST if dist is not None and _from_index(dist) else _q(f"git+https://github.com/{REPO}")
    for direct in directs:                                 # an install from git keeps coming from git
        url = direct.get("url", "")
        if direct.get("vcs_info") and isinstance(url, str) and url.startswith("https://"):
            target = _q("git+" + url)
            break
    if legacy is None:
        return {"kind": "pip", "command": f"{py} -m pip install --upgrade {target}"}
    names = f"{LEGACY_DIST} {DIST}" if dist is not None else LEGACY_DIST
    return {"kind": "pip", "command": f"{py} -m pip uninstall -y {names} && {py} -m pip install {target}"}


def _home(home: pathlib.Path | None = None) -> pathlib.Path:
    return home or pathlib.Path(os.environ.get("VULNSCAN_HOME") or pathlib.Path.home() / ".vulnscan")


def _exe() -> pathlib.Path:
    return pathlib.Path(sys.executable).resolve()


def _dir_writable(d: pathlib.Path) -> bool:
    return os.access(d, os.W_OK | os.X_OK)


def _api_url(net: Net) -> str:
    """The release API; VULNSCAN_UPDATE_API (test-only) may replace it with a loopback URL, nothing else."""
    env = os.environ.get(ENV_TEST_API, "").strip()
    if env and net is NET:
        u = urllib.parse.urlparse(env)
        if u.scheme in ("http", "https") and u.hostname in ("127.0.0.1", "localhost", "::1"):
            return env
    return net.api_url


# ---------------------------------------------------------------------------------------------- network

def _ua() -> str:
    return f"Kashif/{__version__} (update check)"


class _CheckedRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse a redirect to any host outside the allowlist before connecting to it."""

    def __init__(self, net: Net):
        self.net = net

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_url(newurl, self.net)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _check_url(url: str, net: Net) -> None:
    try:
        u = urllib.parse.urlparse(url)
        port = u.port
    except ValueError as e:                       # e.g. a non-numeric port
        raise UpdateError("bad_host", url) from e
    if (net.require_https and u.scheme != "https") or u.scheme not in ("http", "https") \
            or (u.hostname or "") not in net.allowed_hosts or u.username is not None or u.password is not None \
            or (net.require_https and port not in (None, 443)):
        raise UpdateError("bad_host", url)


def _check_asset_url(url: str, tag: str, name: str, net: Net) -> None:
    """A release asset URL must be the official repository's download URL for exactly this tag and file name."""
    _check_url(url, net)
    want = net.asset_path.format(tag=urllib.parse.quote(tag, safe=""), name=urllib.parse.quote(name, safe=""))
    u = urllib.parse.urlparse(url)
    if u.path != want or u.params or u.fragment:
        raise UpdateError("bad_host", url)


def _open(url: str, net: Net, accept: str, timeout: float = TIMEOUT, download: bool = False):
    if download:
        _check_url(url, net)
        opener = urllib.request.build_opener(_CheckedRedirect(net))     # ProxyHandler is included: HTTPS_PROXY works
    else:
        # The release API: redirects may not leave the API's own host or drop from HTTPS to HTTP.
        u = urllib.parse.urlparse(url)
        opener = urllib.request.build_opener(_CheckedRedirect(Net(allowed_hosts=frozenset({u.hostname or ""}),
                                                                  require_https=u.scheme == "https")))
    req = urllib.request.Request(url, headers={"User-Agent": _ua(), "Accept": accept})
    resp = opener.open(req, timeout=timeout)  # nosec B310 - scheme and host validated above
    if download:
        try:
            _check_url(resp.geturl(), net)
        except UpdateError:
            resp.close()
            raise
    return resp


def _read_capped(resp, cap: int) -> bytes:
    data = resp.read(cap + 1)
    if len(data) > cap:
        raise UpdateError("too_large")
    return data


def fetch_release(net: Net = NET, api: str | None = None) -> dict:
    """The latest stable release from the API, reduced to the fields we use. `api` defaults to ``net.api_url``."""
    try:
        with _open(api or net.api_url, net, "application/vnd.github+json") as resp:
            raw = _read_capped(resp, MAX_API)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise UpdateError("no_release") from e
        if e.code in (403, 429) and (e.headers.get("X-RateLimit-Remaining") == "0" or e.code == 429
                                     or "rate limit" in e.read(4096).decode("utf-8", "replace").lower()):
            raise UpdateError("rate_limited") from e
        raise UpdateError("bad_response", f"HTTP {e.code}") from e
    except UpdateError:
        raise
    except (urllib.error.URLError, OSError, TimeoutError, http.client.HTTPException) as e:
        raise UpdateError("offline", str(getattr(e, "reason", e))) from e
    try:
        data = json.loads(raw.decode("utf-8"))
        tag = str(data["tag_name"])
        assets = [{"name": str(a.get("name", "")), "url": str(a.get("browser_download_url", "")), "size": int(a.get("size") or 0)}
                  for a in data.get("assets") or [] if isinstance(a, dict)]
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        raise UpdateError("bad_response") from e
    return {"tag": tag, "version": _clean(tag), "prerelease": bool(data.get("prerelease")) or bool(data.get("draft")),
            "notes": str(data.get("body") or "")[:NOTES_MAX], "url": str(data.get("html_url") or RELEASES_URL),
            "published_at": str(data.get("published_at") or ""), "assets": assets}


# ------------------------------------------------------------------------------------------------- check

def _cache_path(home: pathlib.Path | None) -> pathlib.Path:
    return _home(home) / "update-check.json"


def _cached_release(home: pathlib.Path | None, api: str) -> dict | None:
    try:
        data = json.loads(_cache_path(home).read_text(encoding="utf-8"))
        if data.get("api") == api and 0 <= time.time() - float(data["checked_at"]) < CACHE_TTL:
            return data
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return None


def _save_cache(home: pathlib.Path | None, api: str, release: dict, checked_at: float) -> None:
    p = _cache_path(home)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps({"api": api, "checked_at": checked_at, "release": release}, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, p)
    except OSError:
        pass                                         # a read-only home only costs an extra request next time


def check(force: bool = False, home: pathlib.Path | None = None, net: Net = NET, current: str = __version__,
          info: dict | None = None, asset: str | None = None, exe: pathlib.Path | None = None) -> dict:
    """Is a newer release available, and can this install update itself? Cached for 6 hours unless `force`.

    Raises UpdateError (offline, rate_limited, ...) when the release cannot be fetched."""
    api = _api_url(net)
    cached = None if force else _cached_release(home, api)
    if cached:
        release, checked_at = cached["release"], float(cached["checked_at"])
    else:
        release, checked_at = fetch_release(net, api), time.time()
        _save_cache(home, api, release, checked_at)
    info = info or install_info()
    asset = asset if asset is not None else platform_asset()
    latest = release["version"]
    newer = not release.get("prerelease") and is_newer(latest, current)
    out = {"current": current, "latest": latest, "newer": newer, "notes": release.get("notes", ""),
           "url": release.get("url") or RELEASES_URL, "published_at": release.get("published_at", ""),
           "install_kind": info["kind"], "asset": asset, "command": info.get("command"),
           "can_self_update": False, "reason": None, "checked_at": checked_at, "cached": bool(cached)}
    if info["kind"] != "binary":
        out["reason"] = "not_binary"
    elif not asset:
        out["reason"] = "unsupported_platform"
    else:
        exe = exe or _exe()
        if not _dir_writable(exe.parent):
            out["reason"] = "not_writable"
            out["command"] = None if os.name == "nt" else f"sudo {_q(str(exe))} update"
        elif newer and not resolve_asset(asset, (a["name"] for a in release.get("assets", []))):
            out["reason"] = "asset_missing"
        else:
            out["can_self_update"] = True
    if out["reason"]:
        out["reason_message"] = MESSAGES[out["reason"]]
        out["reason_message_en"] = to_en(MESSAGES[out["reason"]])
    return out


# ------------------------------------------------------------------------------------------------- apply

def parse_sums(text: str, name: str) -> str | None:
    """The SHA-256 for exactly `name` from sha256sum output ("<hex>  name" or "<hex> *name"), or None.

    Fails closed: no line, or two lines for the same name with different digests, gives None."""
    found = set()
    for line in text.lstrip("\ufeff").splitlines():
        m = re.fullmatch(r"\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*", line)
        if m and m.group(2) == name:
            found.add(m.group(1).lower())
    return found.pop() if len(found) == 1 else None


def _asset_os(asset: str) -> str | None:
    """The OS an asset name is built for, from the name itself (kashif-* and legacy vulnscan-* alike)."""
    if not asset.startswith(("kashif-", "vulnscan-")):
        return None
    if asset.endswith(".exe") and "-windows" in asset:
        return "windows"
    if asset in ("kashif-linux-x86_64", "vulnscan-linux"):
        return "linux"
    if asset.startswith(("kashif-macos-", "vulnscan-macos-")) and asset.endswith(("-arm64", "-x86_64")):
        return "macos"
    return None


def check_header(head: bytes, asset: str) -> bool:
    """The first bytes of the download must be an executable for the asset's OS and CPU."""
    kind = _asset_os(asset)
    if kind == "windows":                                        # PE, x86-64
        if len(head) < 0x40 or head[:2] != b"MZ":
            return False
        off = struct.unpack_from("<I", head, 0x3C)[0]
        return off + 6 <= len(head) and head[off:off + 4] == b"PE\0\0" and struct.unpack_from("<H", head, off + 4)[0] == 0x8664
    if kind == "linux":                                          # ELF64, little endian, x86-64
        return len(head) >= 20 and head[:4] == b"\x7fELF" and head[4] == 2 and head[5] == 1 \
            and struct.unpack_from("<H", head, 18)[0] == 0x3E
    if kind == "macos":                                          # Mach-O 64 (thin) or universal
        if head[:4] == b"\xca\xfe\xba\xbe":
            return True
        if len(head) < 8 or head[:4] != b"\xcf\xfa\xed\xfe":
            return False
        cpu = struct.unpack_from("<I", head, 4)[0]
        return cpu == (0x0100000C if asset.endswith("arm64") else 0x01000007)
    return False


def _child_env() -> dict:
    """Environment for running another PyInstaller binary: drop the parent's bootloader state."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("_PYI_", "_MEIPASS"))}
    if "LD_LIBRARY_PATH_ORIG" in env:
        env["LD_LIBRARY_PATH"] = env.pop("LD_LIBRARY_PATH_ORIG")
    elif getattr(sys, "frozen", False):
        env.pop("LD_LIBRARY_PATH", None)
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    return env


def reports_version(path: pathlib.Path, version: str) -> bool:
    try:
        out = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=VERSION_TIMEOUT,
                             env=_child_env(), check=False, stdin=subprocess.DEVNULL)  # nosec B603 - our verified binary
    except (OSError, subprocess.SubprocessError):
        return False
    # `--version` prints "vulnscan X.Y.Z", the exact form v0.9.x updaters look for, so it must stay that way while such
    # installs exist. "kashif X.Y.Z" is accepted too, so that a later release may switch without stranding 1.0+ installs.
    return bool(re.search(rf"\b(?:vulnscan|kashif)\s+v?{re.escape(version)}(?![\w.+-])", out.stdout + out.stderr))


def _download(url: str, dest, net: Net, cap: int, progress=None, phase: str = "download") -> str:
    """Stream `url` into the open file `dest`; return its SHA-256. Enforces the size cap and allowed hosts."""
    h = hashlib.sha256()
    try:
        with _open(url, net, "application/octet-stream", download=True) as resp:
            total = int(resp.headers.get("Content-Length") or 0)
            if total > cap:
                raise UpdateError("too_large")
            done = 0
            while True:
                chunk = resp.read(CHUNK)
                if not chunk:
                    break
                done += len(chunk)
                if done > cap:
                    raise UpdateError("too_large")
                h.update(chunk)
                dest.write(chunk)
                if progress:
                    progress(phase, done, total)
            if total and done != total:                       # the connection closed early
                raise UpdateError("download_failed", f"{done}/{total} bytes")
    except UpdateError:
        raise
    except (urllib.error.URLError, OSError, TimeoutError, ValueError, http.client.HTTPException) as e:
        raise UpdateError("download_failed", str(getattr(e, "reason", e))) from e
    return h.hexdigest()


def backup_path(exe: pathlib.Path) -> pathlib.Path:
    return exe.with_name(exe.name + ".old")


def _swap(new: pathlib.Path, exe: pathlib.Path, version: str) -> pathlib.Path:
    """Put `new` in place of `exe`, keeping `<exe>.old`. Rolls back on any failure."""
    old = backup_path(exe)
    try:
        old.unlink(missing_ok=True)
    except OSError:
        pass
    if os.name == "nt":
        # A running .exe cannot be overwritten or deleted, but it can be renamed.
        os.replace(exe, old)
        try:
            os.replace(new, exe)
        except OSError as e:
            os.replace(old, exe)
            raise UpdateError("swap_failed", str(e)) from e
    else:
        try:
            os.link(exe, old)                     # an instant backup that shares the inode
        except OSError:
            import shutil
            shutil.copy2(exe, old)
        try:
            os.replace(new, exe)                  # atomic: exe is always either the old or the new file
        except OSError as e:
            raise UpdateError("swap_failed", str(e)) from e
    if not reports_version(exe, version):        # belt and braces: the file in place must run
        try:
            os.replace(old, exe)
        except OSError:
            pass
        raise UpdateError("swap_failed")
    return old


def apply(home: pathlib.Path | None = None, net: Net = NET, current: str = __version__, exe: pathlib.Path | None = None,
          asset: str | None = None, progress=None, kind: str | None = None) -> dict:
    """Download, verify and install the latest binary. Binary installs only. Raises UpdateError."""
    if (kind or install_info()["kind"]) != "binary":
        raise UpdateError("not_binary")
    asset = asset or platform_asset()
    if not asset:
        raise UpdateError("unsupported_platform")
    exe = (exe or _exe()).resolve()
    if progress:
        progress("check", 0, 0)
    release = fetch_release(net)                   # never the test-only VULNSCAN_UPDATE_API: installs use the real API
    latest = release["version"]
    if release.get("prerelease") or not is_newer(latest, current):
        raise UpdateError("not_newer", f"{current} -> {latest}")
    by_name = {a["name"]: a for a in release["assets"]}
    published = resolve_asset(asset, by_name)      # an older release has only the legacy vulnscan-* name
    if not published:
        raise UpdateError("asset_missing", asset)
    asset = published
    if SUMS_NAME not in by_name:
        raise UpdateError("checksum_missing")
    if by_name[asset]["size"] > MAX_BINARY:
        raise UpdateError("too_large")
    for name in (asset, SUMS_NAME):                # both files must come from this exact release of the official repo
        _check_asset_url(by_name[name]["url"], release["tag"], name, net)
    # The temp file lives next to the executable so the final rename stays on one filesystem (atomic).
    suffix = ".exe" if asset.endswith(".exe") else ""
    try:
        fd, tmp_name = tempfile.mkstemp(prefix=".vulnscan-update-", suffix=suffix, dir=exe.parent)   # O_EXCL, 0600
    except OSError as e:
        raise UpdateError("not_writable", str(exe.parent)) from e
    tmp = pathlib.Path(tmp_name)
    try:
        # Written, checked and chmod-ed through the descriptor mkstemp opened, never by name: nothing else in the
        # directory can swap the file in between. fsync so a crash right after the rename cannot leave an empty binary.
        with os.fdopen(fd, "w+b") as out:
            sums = _fetch_small(by_name[SUMS_NAME]["url"], net)
            expected = parse_sums(sums, asset)
            if not expected:
                raise UpdateError("checksum_missing", asset)
            digest = _download(by_name[asset]["url"], out, net, MAX_BINARY, progress)
            if progress:
                progress("verify", 0, 0)
            if not hmac.compare_digest(digest, expected):
                raise UpdateError("checksum_mismatch", f"{digest} != {expected}")
            out.flush()
            out.seek(0)
            head = out.read(4096)
            if not check_header(head, asset):
                raise UpdateError("bad_binary")
            try:
                os.fsync(out.fileno())
            except OSError as e:                           # e.g. the disk filled up: nothing has changed yet
                raise UpdateError("download_failed", str(e)) from e
            if os.name != "nt":
                os.fchmod(out.fileno(), _exec_mode(exe))
        if not reports_version(tmp, latest):
            raise UpdateError("version_mismatch", latest)
        if progress:
            progress("swap", 0, 0)
        try:
            old = _swap(tmp, exe, latest)
        except OSError as e:                      # e.g. no permission to rename the running binary: nothing changed
            raise UpdateError("swap_failed", str(e)) from e
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return {"ok": True, "from": current, "to": latest, "path": str(exe), "backup": str(old), "restart_required": True}


def _exec_mode(exe: pathlib.Path) -> int:
    """The new binary's mode: the installed one's, made executable by its owner, never group/world writable."""
    try:
        mode = exe.stat().st_mode & 0o777
    except OSError:
        mode = 0o755
    return (mode | 0o700) & ~0o022


def _fetch_small(url: str, net: Net) -> str:
    import io
    buf = io.BytesIO()
    _download(url, buf, net, MAX_SUMS)
    return buf.getvalue().decode("utf-8", "replace")


def cleanup_stale(exe: pathlib.Path | None = None) -> None:
    """Best effort, at start: remove the backup of a previous update and abandoned temp downloads."""
    if exe is None and not getattr(sys, "frozen", False):
        return
    exe = exe or _exe()
    try:
        backup_path(exe).unlink(missing_ok=True)
    except OSError:
        pass
    try:
        for p in exe.parent.glob(".vulnscan-update-*"):
            if time.time() - p.stat().st_mtime > 3600:
                p.unlink(missing_ok=True)
    except OSError:
        pass


def restart(args: list[str] | None = None, exe: pathlib.Path | None = None) -> None:
    """Start the (new) binary with the same arguments in place of this process. Does not return."""
    exe = exe or _exe()
    args = list(sys.argv[1:] if args is None else args)
    env = _child_env()
    env["VULNSCAN_UPDATE_RESTART"] = "1"
    for s in (sys.stdout, sys.stderr):
        try:
            s.flush()
        except (OSError, ValueError):
            pass
    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)
        subprocess.Popen([str(exe), *args], env=env, close_fds=True, creationflags=flags)  # nosec B603 - our own binary
        os._exit(0)
    os.execve(str(exe), [str(exe), *args], env)  # nosec B606 - re-exec of our own verified binary


# --------------------------------------------------------------------------------------- background job

class Job:
    """One update at a time, run in a thread, with progress the UI can poll."""

    def __init__(self):
        self._lock = threading.Lock()
        self.state = {"phase": "idle", "bytes": 0, "total": 0}

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self.state)

    def _set(self, **kw) -> None:
        with self._lock:
            self.state.update(kw)

    def running(self) -> bool:
        return self.snapshot()["phase"] in ("check", "download", "verify", "swap")

    def start(self, **apply_kwargs) -> bool:
        with self._lock:
            if self.state["phase"] in ("check", "download", "verify", "swap", "done", "restarting"):
                return False                     # busy, or already updated (installing again would be pointless)
            self.state = {"phase": "check", "bytes": 0, "total": 0}
        threading.Thread(target=self._run, kwargs=apply_kwargs, daemon=True).start()
        return True

    def claim_restart(self) -> bool:
        """done -> restarting, once: a second restart request (double click) must not start a second process."""
        with self._lock:
            if self.state["phase"] != "done":
                return False
            self.state = {**{k: v for k, v in self.state.items() if k != "restart_error"}, "phase": "restarting"}
            return True

    def restart_failed(self, detail: str) -> None:
        with self._lock:
            self.state = {**self.state, "phase": "done", "restart_error": detail}

    def _run(self, **kw) -> None:
        def progress(phase, done, total):
            self._set(phase=phase, bytes=done, total=total)
        try:
            result = apply(progress=progress, **kw)
            self._set(phase="done", result=result)
        except UpdateError as e:
            self._set(phase="error", **e.to_dict())
        except Exception as e:  # noqa: BLE001 - surfaced to the UI
            self._set(phase="error", error="swap_failed", message=MESSAGES["swap_failed"],
                      message_en=to_en(MESSAGES["swap_failed"]), detail=str(e))


# -------------------------------------------------------------------------------------------------- CLI

CLI_TEXT = {
    "desc": "التحقق من وجود إصدار أحدث من كاشِف وتثبيته (للنسخة التنفيذية).",
    "yes": "ثبّت دون سؤال للتأكيد",
    "check": "تحقّق فقط واعرض الحالة (رمز الخروج 10 عند توفّر تحديث)",
    "current": "الإصدار الحالي:",
    "latest": "أحدث إصدار:",
    "available": "يتوفر إصدار أحدث.",
    "notes": "ملاحظات الإصدار:",
    "run": "للتحديث شغّل:",
    "download": "أو نزّله من:",
    "confirm": "تنزيل الإصدار الجديد وتثبيته الآن؟ [y/N] ",
    "cancelled": "أُلغي التحديث.",
    "need_yes": "لا توجد طرفية للتأكيد؛ أعد التشغيل مع --yes للتثبيت.",
    "downloading": "جارٍ التنزيل…",
    "verifying": "جارٍ التحقق من بصمة SHA-256 ومن البرنامج الجديد…",
    "swapping": "جارٍ استبدال البرنامج…",
    "done": "تم التحديث بنجاح. أعد تشغيل كاشِف لاستخدام الإصدار الجديد:",
    "backup": "النسخة السابقة محفوظة مؤقتًا في:",
}


def cli_main(argv: list[str]) -> int:
    """`vulnscan update [--check] [--yes]`. Exit: 0 up to date or updated, 1 failure, 10 update available (--check)."""
    from .cli import LANG_CHOICES, _bi, _HelpFormatter, _lang_from_argv, resolve_lang
    lang = _lang_from_argv(argv)

    def h(text: str) -> str:                         # --help: Arabic, English, or both under "both"
        return _bi(text, lang)

    p = argparse.ArgumentParser(prog="kashif update", description=h(CLI_TEXT["desc"]), formatter_class=_HelpFormatter)
    p.add_argument("--check", action="store_true", help=h(CLI_TEXT["check"]))
    p.add_argument("-y", "--yes", action="store_true", help=h(CLI_TEXT["yes"]))
    p.add_argument("--lang", choices=LANG_CHOICES, default="auto", help=argparse.SUPPRESS)
    a = p.parse_args(argv)
    lang = resolve_lang(a.lang)
    lang = "en" if lang == "both" else lang          # messages: English under "both", as the other sub-commands

    def m(text: str) -> str:
        return localize(text, lang)
    cleanup_stale()

    def fail(e: UpdateError) -> int:
        print(f"✖ {m(e.message)}" + (f" ({e.detail})" if e.detail else ""), file=sys.stderr)
        return 1

    try:
        st = check(force=True)
    except UpdateError as e:
        return fail(e)
    print(f"{m(CLI_TEXT['current'])} {st['current']}")
    print(f"{m(CLI_TEXT['latest'])} {st['latest']}")
    if not st["newer"]:
        print(m(MESSAGES["up_to_date"]))
        return 0
    print(m(CLI_TEXT["available"]) + f"  {st['url']}")
    if a.check:
        return 10
    if not st["can_self_update"]:
        print(m(MESSAGES[st["reason"]]), file=sys.stderr)
        if st.get("command"):
            print(f"{m(CLI_TEXT['run'])} {st['command']}")
        print(f"{m(CLI_TEXT['download'])} {st['url']}")
        return 1
    if not a.yes:
        if not sys.stdin or not sys.stdin.isatty():
            print(m(CLI_TEXT["need_yes"]), file=sys.stderr)
            return 1
        try:
            answer = input(m(CLI_TEXT["confirm"].strip()) + " ").strip().lower()
        except EOFError:
            answer = ""
        if answer not in ("y", "yes", "ن", "نعم"):
            print(m(CLI_TEXT["cancelled"]))
            return 1
    shown = {"download": "downloading", "verify": "verifying", "swap": "swapping"}
    last = {"phase": None, "pct": -1}
    live = bool(getattr(sys.stderr, "isatty", lambda: False)())   # a percentage line only on a terminal
    sys.stdout.flush()

    def progress(phase, done, total):
        if phase != last["phase"] and phase in shown:
            if last["phase"] == "download":
                print(file=sys.stderr)
            print(m(CLI_TEXT[shown[phase]]), file=sys.stderr, end="" if phase == "download" else "\n")
            last["phase"] = phase
        if phase == "download" and total and live:
            pct = done * 100 // total
            if pct != last["pct"]:
                last["pct"] = pct
                print(f"\r{m(CLI_TEXT['downloading'])} {pct}%  ({done // 1048576}/{total // 1048576} MB)",
                      file=sys.stderr, end="", flush=True)

    try:
        res = apply(progress=progress)
    except UpdateError as e:
        return fail(e)
    print(f"✔ {m(CLI_TEXT['done'])} {res['from']} → {res['to']}")
    print(f"{m(CLI_TEXT['backup'])} {res['backup']}")
    return 0


# ------------------------------------------------------------------------------------- web data (spec §4.4)
#
# `kashif update-data --web` (opt-in): the web scanner's data snapshots (retire.js, HSTS preload, PSL, EOL, server CVEs,
# takeover fingerprints, ...) are refreshed from the latest *Kashif* release, never from the upstreams directly, so a
# user's machine only ever talks to GitHub and only downloads files the release pipeline validated:
#
# * the release asset ``kashif-webdata-<date>.tar.gz`` (built by ``tools/webdata/validate.py --pack``) must be listed
#   in the same release's ``SHA256SUMS.txt`` and match it; both URLs must be this repository's download URLs for
#   that tag (the checks of ``apply`` above);
# * the archive is read in memory, never extracted by tarfile: flat regular files only, plain names, size caps;
#   its ``MANIFEST.json`` must have this Kashif's data schema version, name the asset's date and list exactly the
#   archive's files with matching sha256; every known data file must pass its JSON schema;
# * it is installed atomically into ``<home>/webdata/<date>/`` (a temp directory renamed into place), where
#   ``webscan/data.py`` prefers it while it is newer than the bundled snapshot and verifies every file again;
# * any failure changes nothing: the bundled snapshot (or the previously installed one) stays in use, and scans
#   never need the network for their data (``--offline`` always works).

WEBDATA_ASSET = re.compile(r"^kashif-webdata-(\d{4}-\d{2}-\d{2})\.tar\.gz$")
MAX_WEBDATA = 32 * 1024 * 1024           # the archive (the snapshot is ≈ 1 MB compressed; budget 1.6 MB)
MAX_WEBDATA_FILE = 16 * 1024 * 1024      # one member, as stored
MAX_WEBDATA_TOTAL = 64 * 1024 * 1024     # all members together
MAX_WEBDATA_MEMBERS = 64
WEBDATA_KEEP = 2                         # installed snapshots kept: the newest and the one before it
_WEB_TMP = ".incoming-"                  # in-progress download / unpack inside <home>/webdata (never a dated name)
_WEB_OLD = ".replaced-"                  # a same-date snapshot being replaced
_WEB_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
_WEB_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")

# code -> (Arabic, English); the {date} placeholder is filled in by update_web_data()
WEB_DATA_TEXT = {
    "webdata_missing": ("الإصدار المنشور لا يحتوي على حزمة بيانات الويب؛ تبقى البيانات الحالية مستخدمة.",
                        "The published release has no web data package; the current data stays in use."),
    "webdata_schema": ("حزمة بيانات الويب المنشورة تحتاج إصدارًا أحدث من كاشِف؛ حدّث البرنامج أولًا. "
                       "تبقى البيانات الحالية مستخدمة.",
                       "The published web data package needs a newer version of Kashif; update the program first. "
                       "The current data stays in use."),
    "webdata_invalid": ("حزمة بيانات الويب المنزَّلة غير صالحة؛ لم يتغيّر شيء وتبقى البيانات الحالية مستخدمة.",
                        "The downloaded web data package is invalid; nothing changed and the current data stays in use."),
    "webdata_install_failed": ("تعذّر حفظ بيانات الويب في مجلد كاشِف؛ لم يتغيّر شيء.",
                               "Could not save the web data in Kashif's folder; nothing changed."),
    "webdata_current": ("بيانات الويب محدّثة (بتاريخ {date}).", "Web data is up to date (as of {date})."),
    "webdata_available": ("تتوفر بيانات ويب أحدث بتاريخ {date}.", "Newer web data is available (as of {date})."),
    "webdata_installed": ("ثُبّتت بيانات الويب بتاريخ {date}؛ ستستخدمها الفحوص القادمة.",
                          "Installed web data as of {date}; the next scans use it."),
}


class WebDataError(UpdateError):
    """A web data update failure. Same shape as UpdateError; its English comes from WEB_DATA_TEXT."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        Exception.__init__(self, WEB_DATA_TEXT[code][0])

    @property
    def message(self) -> str:
        return WEB_DATA_TEXT[self.code][0]

    @property
    def message_en(self) -> str:
        return WEB_DATA_TEXT[self.code][1]

    def to_dict(self) -> dict:
        return {"error": self.code, "message": self.message, "message_en": self.message_en, "detail": self.detail}


def _webdata():
    from .webscan import data            # lazy: the web scanner is not needed for a binary update
    return data


def _webdata_known() -> set:
    d = _webdata()
    return set(d.DATA_FILES) | set(d.SIDECARS.values())


def _webdata_verify_dir(directory: pathlib.Path) -> str | None:
    """The date of a complete, verified installed snapshot in `directory`, else None."""
    d = _webdata()
    try:
        man = json.loads((directory / d.MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if d.validate(d.MANIFEST_SCHEMA, man) or man["schema_version"] != d.SCHEMA_VERSION:
        return None
    for name in set(man["files"]) & _webdata_known():
        try:
            raw = (directory / name).read_bytes()
        except OSError:
            return None
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), str(man["files"][name]["sha256"])):
            return None
    return man["generated"]


def _webdata_installed(root: pathlib.Path) -> tuple[str, pathlib.Path] | None:
    """The newest verified snapshot under `root` (the same choice the loader makes), else None."""
    try:
        dirs = sorted((p for p in root.iterdir() if _WEB_DAY.fullmatch(p.name) and p.is_dir() and not p.is_symlink()),
                      key=lambda p: p.name, reverse=True)
    except OSError:
        return None
    for p in dirs:
        day = _webdata_verify_dir(p)
        if day:
            return day, p
    return None


def _webdata_read_archive(fileobj) -> dict[str, bytes]:
    """name -> bytes of a flat tar.gz, read in memory (nothing is extracted to disk by tarfile)."""
    import tarfile
    import zlib
    files: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(fileobj=fileobj, mode="r:gz") as tar:
            for count, m in enumerate(tar, 1):
                if count > MAX_WEBDATA_MEMBERS:
                    raise WebDataError("webdata_invalid", "too many members")
                if not m.isreg():
                    raise WebDataError("webdata_invalid", f"not a regular file: {m.name!r}")
                if not _WEB_NAME.fullmatch(m.name) or m.name in files:
                    raise WebDataError("webdata_invalid", f"unexpected member name: {m.name!r}")
                total += m.size
                if m.size > MAX_WEBDATA_FILE or total > MAX_WEBDATA_TOTAL:
                    raise WebDataError("webdata_invalid", f"too large: {m.name}")
                f = tar.extractfile(m)
                raw = f.read(m.size + 1) if f is not None else b""
                if len(raw) != m.size:
                    raise WebDataError("webdata_invalid", f"truncated: {m.name}")
                files[m.name] = raw
    except (tarfile.TarError, OSError, EOFError, zlib.error) as e:
        raise WebDataError("webdata_invalid", str(e)) from e
    return files


def _webdata_check(files: dict[str, bytes], day: str) -> dict:
    """Verify an archive's content (manifest, schema version, sha256 of every file, JSON schemas). Returns the manifest."""
    import gzip
    import io
    d = _webdata()
    try:
        man = json.loads(files[d.MANIFEST].decode("utf-8"))
    except (KeyError, ValueError) as e:
        raise WebDataError("webdata_invalid", "no readable MANIFEST.json") from e
    errs = d.validate(d.MANIFEST_SCHEMA, man)
    if errs:
        raise WebDataError("webdata_invalid", "; ".join(errs[:3]))
    if man["schema_version"] != d.SCHEMA_VERSION:
        raise WebDataError("webdata_schema", f"schema {man['schema_version']} != {d.SCHEMA_VERSION}")
    if man["generated"] != day:
        raise WebDataError("webdata_invalid", f"manifest date {man['generated']} != asset date {day}")
    listed = set(man["files"])
    if listed != set(files) - {d.MANIFEST}:
        raise WebDataError("webdata_invalid", "the manifest does not list exactly the archive's files")
    for name in sorted(listed):
        entry, raw = man["files"][name], files[name]
        if len(raw) != entry["size"] or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), str(entry["sha256"])):
            raise WebDataError("webdata_invalid", f"{name}: sha256 does not match the manifest")
    known = listed & _webdata_known()
    if not known:
        raise WebDataError("webdata_invalid", "no known data file")
    for name in sorted(known & set(d.SCHEMAS)):
        raw = files[name]
        try:
            if name.endswith(".gz"):
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as g:
                    raw = g.read(MAX_WEBDATA_TOTAL + 1)
                if len(raw) > MAX_WEBDATA_TOTAL:
                    raise ValueError("decompressed size above the cap")
            obj = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError, EOFError) as e:
            raise WebDataError("webdata_invalid", f"{name}: {e}") from e
        errs = d.validate_data(name, obj)
        if errs:
            raise WebDataError("webdata_invalid", f"{name}: {errs[0]}")
    for binary, side in d.SIDECARS.items():
        if (binary in known) != (side in known):
            raise WebDataError("webdata_invalid", f"{binary} and {side} come together")
        if binary in known:
            want = json.loads(files[side].decode("utf-8")).get("sha256", "")
            if not hmac.compare_digest(hashlib.sha256(files[binary]).hexdigest(), str(want)):
                raise WebDataError("webdata_invalid", f"{side}: sha256 does not match {binary}")
    return man


def _webdata_install(root: pathlib.Path, day: str, files: dict[str, bytes]) -> pathlib.Path:
    """Write the snapshot into a temp directory (MANIFEST.json last, fsync-ed), then rename it to <root>/<day>."""
    import secrets
    import shutil
    d = _webdata()
    names = sorted(set(files) & _webdata_known()) + [d.MANIFEST]
    try:
        tmp = pathlib.Path(tempfile.mkdtemp(prefix=_WEB_TMP, dir=root))
    except OSError as e:
        raise WebDataError("webdata_install_failed", str(e)) from e
    final = root / day
    old = None
    try:
        for name in names:
            with open(tmp / name, "wb") as f:
                f.write(files[name])
                f.flush()
                os.fsync(f.fileno())
        if final.exists() or final.is_symlink():
            old = root / f"{_WEB_OLD}{day}-{secrets.token_hex(4)}"
            os.replace(final, old)
        try:
            os.replace(tmp, final)                      # atomic: <day> is either absent, the old or the new snapshot
        except OSError:
            if old is not None:
                os.replace(old, final)
                old = None
            raise
    except OSError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise WebDataError("webdata_install_failed", str(e)) from e
    if old is not None:
        shutil.rmtree(old, ignore_errors=True)
    return final


def _webdata_prune(root: pathlib.Path, keep: int = WEBDATA_KEEP) -> None:
    """Best effort: keep the newest `keep` dated snapshots; drop leftovers of interrupted runs (older than 1 hour)."""
    import shutil
    try:
        entries = list(root.iterdir())
    except OSError:
        return
    dated = sorted((p for p in entries if _WEB_DAY.fullmatch(p.name) and p.is_dir() and not p.is_symlink()),
                   key=lambda p: p.name, reverse=True)
    for p in dated[keep:]:
        shutil.rmtree(p, ignore_errors=True)
    for p in entries:
        if not p.name.startswith((_WEB_TMP, _WEB_OLD)) or p.is_symlink():
            continue
        try:
            if time.time() - p.stat().st_mtime <= 3600:
                continue
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            else:
                p.unlink(missing_ok=True)
        except OSError:
            pass


def _webdata_text(code: str, day: str) -> dict:
    ar, en = WEB_DATA_TEXT[code]
    return {"message": ar.format(date=day), "message_en": en.format(date=day)}


def update_web_data(*, net: Net = NET, root: pathlib.Path | None = None, check_only: bool = False,
                    progress=None) -> dict:
    """Update the web scanner's data snapshots from the latest Kashif release (spec §4.4 step 2).

    `root` is the snapshot root (default: ``webscan.data.user_root()``, i.e. ``$KASHIF_HOME``/``$VULNSCAN_HOME``/
    ``~/.vulnscan`` + ``/webdata``); `check_only` reports without downloading the archive; `progress(phase, done,
    total)` sees check, download, verify and install. Returns ``{"ok", "status": up_to_date|available|installed,
    "latest", "current", "bundled", "installed", "release", "asset", "path", "message", "message_en", "notes"}``
    (``notes``: the staleness notes of the data now in use). Raises UpdateError / WebDataError; nothing changes then.
    """
    d = _webdata()
    root = pathlib.Path(root) if root is not None else d.user_root()
    if progress:
        progress("check", 0, 0)
    release = fetch_release(net)
    if release.get("prerelease"):
        raise UpdateError("no_release")
    by_name = {a["name"]: a for a in release["assets"]}
    offered = sorted(((m.group(1), n) for n in by_name if (m := WEBDATA_ASSET.fullmatch(n))), reverse=True)
    if not offered:
        raise WebDataError("webdata_missing", release["tag"])
    day, asset = offered[0]
    bundled = d._bundled_generated()
    inst = _webdata_installed(root)
    current = max(bundled, inst[0]) if inst else bundled
    out = {"ok": True, "latest": day, "current": current, "bundled": bundled, "installed": inst[0] if inst else None,
           "release": release["version"], "asset": asset, "path": str(inst[1]) if inst else None}
    if day <= current:
        return {**out, "status": "up_to_date", **_webdata_text("webdata_current", current),
                "notes": d.staleness()}
    if check_only:
        return {**out, "status": "available", **_webdata_text("webdata_available", day), "notes": d.staleness()}
    if SUMS_NAME not in by_name:
        raise UpdateError("checksum_missing", asset)
    if by_name[asset]["size"] > MAX_WEBDATA:
        raise UpdateError("too_large", asset)
    for name in (asset, SUMS_NAME):                # both from this exact release of the official repository
        _check_asset_url(by_name[name]["url"], release["tag"], name, net)
    try:
        root.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=_WEB_TMP, suffix=".tar.gz", dir=root)
    except OSError as e:
        raise WebDataError("webdata_install_failed", str(e)) from e
    tmp = pathlib.Path(tmp_name)
    try:
        with os.fdopen(fd, "w+b") as f:
            expected = parse_sums(_fetch_small(by_name[SUMS_NAME]["url"], net), asset)
            if not expected:
                raise UpdateError("checksum_missing", asset)
            digest = _download(by_name[asset]["url"], f, net, MAX_WEBDATA, progress)
            if progress:
                progress("verify", 0, 0)
            if not hmac.compare_digest(digest, expected):
                raise UpdateError("checksum_mismatch", f"{digest} != {expected}")
            f.seek(0)
            files = _webdata_read_archive(f)
        _webdata_check(files, day)
        if progress:
            progress("install", 0, 0)
        path = _webdata_install(root, day, files)
    finally:
        tmp.unlink(missing_ok=True)
    _webdata_prune(root)
    d.clear_cache()
    return {**out, "status": "installed", "current": day, "installed": day, "path": str(path),
            **_webdata_text("webdata_installed", day), "notes": d.staleness()}
