"""Validate the web data snapshots and generate ``vulnscan/data/web/MANIFEST.json`` (spec §4.4; maintainers and CI).

    python tools/webdata/validate.py                     # validate every file, then (re)write MANIFEST.json
    python tools/webdata/validate.py --check             # CI: validate, and fail when MANIFEST.json is not current
    python tools/webdata/validate.py --check --max-age 30 --today 2026-11-13   # release checklist (§4.4 step 1)
    python tools/webdata/validate.py --check --pack out/ # also write out/kashif-webdata-<date>.tar.gz for the release

Checks, per file: it is a known data file (``vulnscan.webscan.data.SCHEMAS`` or a sidecar-described binary), it parses,
it matches its JSON schema and the current ``schema_version``, its regular expressions compile, gzip members carry no
timestamp or file name (so a rebuild is byte-identical), text files use LF line endings (the sha256 must not depend
on the platform's checkout), the PSL sidecar's sha256 matches ``psl.dat.gz``. Across files: every expected file is
present, ``exposed-paths.json`` and the ``tech.json`` deep paths are disjoint, no path from the §0.1 never-list
(heap/thread dumps, profilers) appears anywhere, and the compressed total stays within the §4.4 budget (1.6 MB).

``MANIFEST.json`` is generated, never hand-edited: ``{"schema_version", "generated", "files": {name: {sha256, size,
date, source, license, schema_version, version?}}}`` with sorted keys, so two runs over the same files are
byte-identical. ``generated`` is the newest ``meta.date`` of the files (no clock is read). ``webscan/data.py`` uses it
to decide whether a user snapshot from ``kashif update-data --web`` is newer than the bundled one, and verifies every
file of such a snapshot against its sha256.

``--pack`` writes the release asset ``kashif-webdata-<generated>.tar.gz`` that ``vulnscan.updater.update_web_data()``
installs: a flat, deterministic tar (sorted members, fixed owner, mode and mtime; gzip header without a timestamp)
holding every data file and the manifest. The release workflow adds its line to ``SHA256SUMS.txt``.

Nothing here touches the network.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import sys
import tarfile
import warnings
import zlib
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vulnscan.webscan import data  # noqa: E402  (after the path tweak: the worktree's own package)

DATA_DIR = data.BUNDLED_DIR
MANIFEST = data.MANIFEST
ASSET_PREFIX = "kashif-webdata-"
ASSET_RE = re.compile(r"^kashif-webdata-(\d{4}-\d{2}-\d{2})\.tar\.gz$")
SIZE_BUDGET = 1_600_000            # §4.4: total compressed ≤ 1.6 MB
MAX_FILE = 16 * 1024 * 1024        # no single data file comes near this (decompressed)
# §0.1 "Never": GETs that make the server do expensive or state-changing work. No data file may list them.
NEVER_PATHS = re.compile(r"heapdump|threaddump|/debug/pprof|/actuator/(?:shutdown|restart|refresh|jolokia/exec)|"
                         r"/cache/(?:purge|flush|clear)|/install/(?:step|submit|finish)", re.I)
_FLAGS = {"i": re.I, "m": re.M, "s": re.S, "x": re.X}


def never_listed(path: str) -> bool:
    """On the §0.1 never-list: this module's own list or the scanner's (``webscan.exposure.NEVER_LIST``, which
    ``probe()`` enforces). The release gate must be at least as strict as the scanner, or a refresh could install a
    path that the scanner then silently refuses (and test_exposure only catches it later)."""
    if NEVER_PATHS.search(path):
        return True
    try:
        from vulnscan.webscan.exposure import NEVER_LIST
    except ImportError:            # pragma: no cover - the scanner package is always next to this tool
        return False
    return bool(NEVER_LIST.search(path))


def expected_files() -> tuple[str, ...]:
    """Every file a complete snapshot holds (MANIFEST.json excluded), sorted."""
    return tuple(sorted(set(data.DATA_FILES) | set(data.SIDECARS.values())))


def _gunzip(raw: bytes) -> bytes:
    """Decompressed content, capped. A damaged deflate stream raises ``zlib.error`` (not an OSError): reported as
    ValueError like every other unreadable file."""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as g:
            out = g.read(MAX_FILE + 1)
    except zlib.error as e:
        raise ValueError(f"damaged gzip data ({e})") from e
    if len(out) > MAX_FILE:
        raise ValueError("decompressed size above the cap")
    return out


def _load(path: Path):
    raw = path.read_bytes()
    if path.name.endswith(".gz"):
        raw = _gunzip(raw)
    return json.loads(raw.decode("utf-8"))


# ------------------------------------------------------------------------------------------------ checks

def _gzip_header_errors(name: str, raw: bytes) -> list[str]:
    """RFC 1952 header: no MTIME and no FNAME, or two builds of the same content differ."""
    if len(raw) < 10 or raw[:2] != b"\x1f\x8b":
        return [f"{name}: not a gzip file"]
    errs = []
    if int.from_bytes(raw[4:8], "little"):
        errs.append(f"{name}: gzip header carries a timestamp (use mtime=0: the output must be deterministic)")
    if raw[3] & 0x08:
        errs.append(f"{name}: gzip header carries a file name (use filename='')")
    return errs


PSL_MARKERS = ("===BEGIN ICANN DOMAINS===", "===END ICANN DOMAINS===", "===BEGIN PRIVATE DOMAINS===",
               "===END PRIVATE DOMAINS===")


def _psl_errors(name: str, raw: bytes, sidecar: dict | None) -> list[str]:
    """``psl.dat.gz`` has no JSON schema: it must still be the list (both sections, the sidecar's rule count)."""
    try:
        text = _gunzip(raw).decode("utf-8")
    except UnicodeDecodeError:
        return [f"{name}: not UTF-8 (the Public Suffix List is UTF-8 text)"]
    except (OSError, ValueError, EOFError) as e:
        return [f"{name}: unreadable ({e})"]
    missing = [m for m in PSL_MARKERS if m not in text]
    if missing:
        return [f"{name}: not a Public Suffix List (no {missing[0]})"]
    rules = sum(1 for line in text.splitlines() if line.strip() and not line.strip().startswith("//"))
    want = (sidecar or {}).get("rules")
    if isinstance(want, int) and want != rules:
        return [f"{name}: rule count {rules} differs from the sidecar's {want}"]
    return []


def _regex_errors(name: str, obj) -> list[str]:
    """Every regular expression the scanner will compile from this file must compile."""
    errs: list[str] = []

    def check(pattern, flags: str, where: str) -> None:
        if not isinstance(pattern, str):
            return
        f = 0
        for ch in flags or "":
            f |= _FLAGS.get(ch, 0)
        try:
            # A DeprecationWarning from re on Python 3.10 (e.g. global flags such as "(?i)" not at the start) is an
            # error from 3.11 on: the scanner would then skip the pattern, so the gate fails it on every version.
            with warnings.catch_warnings():
                warnings.simplefilter("error", DeprecationWarning)
                re.compile(pattern, f)
        except (re.error, DeprecationWarning) as e:
            errs.append(f"{name}: {where}: regex does not compile ({e})")

    def walk(node, where: str) -> None:
        if isinstance(node, dict):
            if node.get("type") == "regex" and "pattern" in node:          # SIGNATURE conditions
                check(node["pattern"], node.get("flags", ""), where)
            if "version_pattern" in node:                                  # leak-headers.json
                check(node["version_pattern"], "", where + ".version_pattern")
            for k, v in node.items():
                walk(v, f"{where}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{where}[{i}]")

    re.purge()            # a pattern compiled earlier in this process would not warn again (re's cache)
    try:
        walk(obj, "$")
    except RecursionError:
        return [f"{name}: nested too deeply to check"]
    if name == "tech.json":
        for t in obj.get("technologies", []):
            for i, s in enumerate(t.get("signals", [])):
                check(s.get("pattern"), s.get("flags", ""), f"technologies[{t.get('id')}].signals[{i}]")
    elif name == "malicious-hosts.json":
        for s in obj.get("signatures", []):
            check(s.get("pattern"), s.get("flags", ""), f"signatures[{s.get('id')}]")
    elif name == "secret-rules.json":
        for s in obj.get("extra", []):
            check(s.get("pattern"), "", f"extra[{s.get('id')}]")
        for p in obj.get("publishable", []):
            check(p, "", "publishable")
    return errs


def _deep_paths(objs: dict) -> tuple[list[str], list[str]]:
    exposed = [p.get("path", "") for p in (objs.get("exposed-paths.json") or {}).get("paths", [])]
    platform = [p.get("path", "") for t in (objs.get("tech.json") or {}).get("technologies", [])
                for p in t.get("deep_paths", [])]
    return exposed, platform


def compressed_size(directory: Path, names) -> int:
    """Bytes the snapshot takes compressed: ``.gz`` files as they are, others as gzip -9 would store them."""
    total = 0
    for n in names:
        raw = (directory / n).read_bytes()
        total += len(raw) if n.endswith(".gz") else len(gzip.compress(raw, 9, mtime=0))
    return total


def validate_dir(directory: Path = DATA_DIR, *, max_age: int | None = None, today: date | None = None) -> list[str]:
    """Every problem found in a snapshot directory (empty list = valid)."""
    directory = Path(directory)
    errs: list[str] = []
    want = set(expected_files())
    try:
        present = {p.name for p in directory.iterdir() if p.is_file()}
        stray_dirs = sorted(p.name for p in directory.iterdir() if p.is_dir() and p.name != "__pycache__")
    except OSError as e:
        return [f"{directory}: unreadable ({e})"]
    for d in stray_dirs:
        errs.append(f"{d}/: unexpected directory in the data folder")
    for n in sorted(present - want - {MANIFEST}):
        errs.append(f"{n}: unknown data file (give it a schema in vulnscan/webscan/data.py SCHEMAS)")
    for n in sorted(want - present):
        errs.append(f"{n}: missing")
    objs: dict = {}
    for n in sorted(want & present):
        path = directory / n
        raw = path.read_bytes()
        if n.endswith(".gz"):
            errs += _gzip_header_errors(n, raw)
        else:
            if b"\r" in raw:
                errs.append(f"{n}: CR line endings (use LF: the sha256 must be the same on every platform)")
            if raw.startswith(b"\xef\xbb\xbf"):
                errs.append(f"{n}: starts with a UTF-8 BOM")
        if n not in data.SCHEMAS:          # a binary file described by its sidecar (psl.dat.gz)
            continue
        try:
            obj = _load(path)
        except (OSError, ValueError, EOFError, RecursionError) as e:
            errs.append(f"{n}: unreadable ({e})")
            continue
        bad = [e if e.startswith(n + ":") else f"{n}: {e}" for e in data.validate_data(n, obj)]
        if bad:            # the cross-file checks below assume the schema's shapes
            errs += bad
            continue
        objs[n] = obj
        errs += _regex_errors(n, obj)
        if max_age is not None:
            d = (obj.get("meta") or {}).get("date") if isinstance(obj, dict) else None
            try:
                age = ((today or datetime.now(timezone.utc).date()) - date.fromisoformat(d)).days
            except (TypeError, ValueError):
                age = None
            shown = n
            for binary, side in data.SIDECARS.items():
                shown = binary if side == n else shown
            if age is not None and age > max_age:
                errs.append(f"{shown}: snapshot of {d} is {age} days old (limit {max_age}); "
                            "run python tools/webdata/refresh.py")
            elif age is not None and age < -1:     # one day of slack for time zones
                # A future date becomes the manifest's "generated": installed by update_web_data(), such a snapshot
                # would look newer than every later release and every newer bundled snapshot, for good.
                errs.append(f"{shown}: dated {d}, in the future (a typo in --date?)")
    for binary, side in data.SIDECARS.items():
        meta = objs.get(side)
        if meta and binary in present:
            digest = hashlib.sha256((directory / binary).read_bytes()).hexdigest()
            if meta.get("sha256") != digest:
                errs.append(f"{side}: sha256 does not match {binary}")
        if binary == "psl.dat.gz" and binary in present:
            errs += _psl_errors(binary, (directory / binary).read_bytes(), meta)
    exposed, platform = _deep_paths(objs)
    both = sorted(set(exposed) & set(platform))
    if both:
        errs.append(f"exposed-paths.json / tech.json: paths listed in both files: {both}")
    for p in exposed + platform:
        if never_listed(p):
            errs.append(f"deep path {p!r} is on the §0.1 never-list (expensive or state-changing GET)")
    if not (want - present):
        size = compressed_size(directory, sorted(want))
        if size > SIZE_BUDGET:
            errs.append(f"snapshot is {size} bytes compressed; the §4.4 budget is {SIZE_BUDGET}")
    if not errs:          # what the loader and update_web_data() will read must pass their own schema
        errs += [f"{MANIFEST}: {e}" for e in data.validate(data.MANIFEST_SCHEMA, build_manifest(directory))]
    return errs


# ---------------------------------------------------------------------------------------------- manifest

def build_manifest(directory: Path = DATA_DIR) -> dict:
    """The manifest of a (validated) snapshot directory; deterministic for the same files."""
    directory = Path(directory)
    files: dict[str, dict] = {}
    dates: list[str] = []
    for n in expected_files():
        path = directory / n
        if not path.is_file():
            continue
        raw = path.read_bytes()
        entry: dict = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
        meta_name = data.SIDECARS.get(n, n)
        try:
            meta = (_load(directory / meta_name) or {}).get("meta") or {}
        except (OSError, ValueError, EOFError, AttributeError, RecursionError):
            meta = {}
        if not isinstance(meta, dict):     # a broken file: validate_dir() reports it; the manifest just omits its meta
            meta = {}
        for key in ("date", "source", "license", "schema_version"):
            if meta.get(key) not in (None, ""):
                entry[key] = meta[key]
        if meta.get("upstream_version"):
            entry["version"] = str(meta["upstream_version"])
        if isinstance(entry.get("date"), str):
            dates.append(entry["date"])
        files[n] = entry
    return {"schema_version": data.SCHEMA_VERSION, "generated": max(dates) if dates else "0000-00-00", "files": files}


def render_manifest(manifest: dict) -> bytes:
    return (json.dumps(manifest, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def write_manifest(directory: Path = DATA_DIR) -> Path:
    directory = Path(directory)
    path = directory / MANIFEST
    tmp = directory / (MANIFEST + ".tmp")
    tmp.write_bytes(render_manifest(build_manifest(directory)))
    tmp.replace(path)
    return path


def manifest_current(directory: Path = DATA_DIR) -> bool:
    path = Path(directory) / MANIFEST
    try:
        return path.read_bytes() == render_manifest(build_manifest(directory))
    except OSError:
        return False


# -------------------------------------------------------------------------------------------------- pack

def asset_name(generated: str) -> str:
    return f"{ASSET_PREFIX}{generated}.tar.gz"


def pack(directory: Path, out_dir: Path) -> Path:
    """Write ``kashif-webdata-<generated>.tar.gz`` (flat, deterministic) from a snapshot with a current manifest."""
    directory, out_dir = Path(directory), Path(out_dir)
    manifest = json.loads((directory / MANIFEST).read_text(encoding="utf-8"))
    generated = manifest["generated"]
    mtime = int(datetime.fromisoformat(generated + "T00:00:00+00:00").timestamp())
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for n in sorted([*manifest["files"], MANIFEST]):
            raw = (directory / n).read_bytes()
            info = tarfile.TarInfo(n)
            info.size, info.mtime, info.mode = len(raw), mtime, 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.type = tarfile.REGTYPE
            tar.addfile(info, io.BytesIO(raw))
    gz = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=gz, compresslevel=9, mtime=0) as g:
        g.write(buf.getvalue())
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / asset_name(generated)
    tmp = out_dir / (path.name + ".tmp")
    tmp.write_bytes(gz.getvalue())
    tmp.replace(path)
    return path


def sha256_line(path: Path) -> str:
    """The ``sha256sum`` line for a file, as the release's SHA256SUMS.txt carries it."""
    return f"{hashlib.sha256(Path(path).read_bytes()).hexdigest()}  {Path(path).name}"


# --------------------------------------------------------------------------------------------------- CLI

def safe_streams() -> None:
    """Problems can quote data (Arabic titles, upstream text): on a Windows pipe stdout/stderr use the ANSI code page,
    where printing them would raise UnicodeEncodeError instead of listing the problems."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):     # not a TextIOWrapper (captured by a test, redirected)
            pass


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", default=str(DATA_DIR), help="snapshot directory (default: vulnscan/data/web)")
    ap.add_argument("--check", action="store_true", help="do not write: fail when MANIFEST.json is not current")
    ap.add_argument("--max-age", type=int, metavar="DAYS", help="fail when any snapshot is older than DAYS (release: 30)")
    ap.add_argument("--today", type=date.fromisoformat, help="reference date for --max-age (YYYY-MM-DD; default: today, UTC)")
    ap.add_argument("--pack", metavar="DIR", help="also write the release asset kashif-webdata-<date>.tar.gz into DIR")
    args = ap.parse_args(argv)
    safe_streams()
    directory = Path(args.dir)
    errs = validate_dir(directory, max_age=args.max_age, today=args.today)
    if errs:
        print(f"{len(errs)} problem(s) in {directory}:", file=sys.stderr)
        for e in errs:
            print("  " + e, file=sys.stderr)
        return 1
    if args.check:
        if not manifest_current(directory):
            print(f"{directory / MANIFEST} is not current: run python tools/webdata/validate.py", file=sys.stderr)
            return 1
        print(f"{len(expected_files())} data files valid; {MANIFEST} is current")
    else:
        path = write_manifest(directory)
        print(f"{len(expected_files())} data files valid; wrote {path}")
    if args.pack:
        asset = pack(directory, Path(args.pack))
        print(sha256_line(asset))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
