"""Refresh the bundled retire.js repository (maintainers only; needs the network unless --from is given).

    python tools/webdata/retire.py                          # download RetireJS/retire.js master
    python tools/webdata/retire.py --ref <commit>           # a pinned upstream commit
    python tools/webdata/retire.py --from jsrepository-v4.json

Writes ``vulnscan/data/web/retire-jsrepository.json.gz``: ``{"meta": …, "repository": <jsrepository-v4.json>}``.
The repository is retire.js data (Apache-2.0; NOTICE carries the attribution), copied unmodified except that the
``retire-example`` entry (a fake library used by retire's own tests) is dropped. ``dont check`` is kept: its ``uri``
extractors name scripts that retire.js never scans, and libs.py honours that. The gzip header carries no timestamp,
so the same input always produces the same bytes (stable sha256 in the manifest).
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "vulnscan" / "data" / "web"
OUT_NAME = "retire-jsrepository.json.gz"
RAW = "https://raw.githubusercontent.com/RetireJS/retire.js/{ref}/repository/jsrepository-v4.json"
SOURCE = "RetireJS/retire.js, repository/jsrepository-v4.json"
LICENSE = "Apache-2.0"
DROP = ("retire-example",)
MIN_LIBS = 60


def fetch(ref: str = "master", timeout: float = 60.0) -> bytes:
    sys.path.insert(0, str(ROOT))
    from vulnscan import __version__
    req = urllib.request.Request(RAW.format(ref=ref), headers={"User-Agent": f"Kashif/{__version__} webdata-refresh"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # nosec - fixed maintainer URL
        return resp.read(16 * 1024 * 1024)


def build(repo: dict, day: str, upstream: str = "", notes: str = "") -> dict:
    if not isinstance(repo, dict) or len(repo) < MIN_LIBS:
        raise SystemExit(f"suspiciously small repository: {len(repo) if isinstance(repo, dict) else type(repo).__name__}")
    out = {name: entry for name, entry in repo.items() if name not in DROP}
    for name, entry in out.items():
        entry.setdefault("vulnerabilities", [])
        entry.setdefault("extractors", {})
    meta = {"schema_version": 1, "date": day, "source": SOURCE, "license": LICENSE, "generator": "tools/webdata/retire.py"}
    if upstream:
        meta["upstream_version"] = upstream
    if notes:
        meta["notes"] = notes
    return {"meta": meta, "repository": out}


def gz_bytes(obj: dict) -> bytes:
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=False).encode("utf-8")
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, compresslevel=9, mtime=0) as g:
        g.write(raw)
    return buf.getvalue()


def write(obj: dict, out_dir: Path = OUT_DIR) -> Path:
    sys.path.insert(0, str(ROOT))
    from vulnscan.webscan import data
    errors = data.validate_data(OUT_NAME, obj)
    if errors:
        raise SystemExit("schema errors: " + "; ".join(errors[:5]))
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / OUT_NAME
    path.write_bytes(gz_bytes(obj))
    return path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--from", dest="src", help="a local jsrepository-v4.json")
    ap.add_argument("--ref", default="master", help="upstream branch or commit (default: master)")
    ap.add_argument("--upstream-version", default="", help="upstream commit/version recorded in meta")
    ap.add_argument("--date", help="snapshot date YYYY-MM-DD (default: today, UTC)")
    ap.add_argument("--notes", default="", help="free-text provenance note stored in the header")
    ap.add_argument("--out", default=str(OUT_DIR), help="output directory (default: vulnscan/data/web)")
    args = ap.parse_args(argv)
    blob = Path(args.src).read_bytes() if args.src else fetch(args.ref)
    repo = json.loads(blob.decode("utf-8"))
    day = args.date or datetime.now(timezone.utc).date().isoformat()
    obj = build(repo, day, args.upstream_version or ("" if args.src else args.ref), args.notes)
    path = write(obj, Path(args.out))
    ranges = sum(len(e.get("vulnerabilities", [])) for e in obj["repository"].values())
    print(f"wrote {path} ({len(obj['repository'])} entries, {ranges} vulnerable ranges)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
