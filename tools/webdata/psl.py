"""Refresh the bundled Public Suffix List (maintainers only; needs the network unless --from is given).

    python tools/webdata/psl.py                      # download from publicsuffix.org
    python tools/webdata/psl.py --from list.dat      # use a local copy (offline / mirror)

Writes ``vulnscan/data/web/psl.dat.gz`` (the list byte-for-byte, gzip with a fixed header so the output is
deterministic) and its header ``psl.dat.meta.json`` (date, source, licence, sha256, rule count). The list is MPL-2.0
and is vendored unmodified; NOTICE carries the licence notice. Downloading the whole list leaks nothing about any
scan target.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "vulnscan" / "data" / "web"
SOURCE = "https://publicsuffix.org/list/public_suffix_list.dat"
LICENSE = "MPL-2.0"
MIN_RULES = 5000


def fetch(url: str = SOURCE, timeout: float = 60.0) -> bytes:
    sys.path.insert(0, str(ROOT))
    from vulnscan import __version__
    req = urllib.request.Request(url, headers={"User-Agent": f"Kashif/{__version__} webdata-refresh"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # nosec - fixed maintainer URL
        return resp.read(8 * 1024 * 1024)


def count_rules(raw: bytes) -> int:
    n = 0
    for line in raw.decode("utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("//"):
            n += 1
    return n


def check(raw: bytes) -> int:
    text = raw.decode("utf-8")
    for marker in ("===BEGIN ICANN DOMAINS===", "===END ICANN DOMAINS===", "===BEGIN PRIVATE DOMAINS===",
                   "===END PRIVATE DOMAINS==="):
        if marker not in text:
            raise SystemExit(f"not a Public Suffix List: missing {marker}")
    n = count_rules(raw)
    if n < MIN_RULES:
        raise SystemExit(f"suspiciously small list: {n} rules")
    return n


def gzip_deterministic(raw: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, compresslevel=9, mtime=0) as g:
        g.write(raw)
    return buf.getvalue()


def write(raw: bytes, day: str, notes: str = "", out_dir: Path = OUT_DIR) -> dict:
    rules = check(raw)
    gz = gzip_deterministic(raw)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "psl.dat.gz").write_bytes(gz)
    meta = {"schema_version": 1, "date": day, "source": SOURCE, "license": LICENSE, "generator": "tools/webdata/psl.py"}
    if notes:
        meta["notes"] = notes
    sidecar = {"meta": meta, "file": "psl.dat.gz", "sha256": hashlib.sha256(gz).hexdigest(), "rules": rules}
    (out_dir / "psl.dat.meta.json").write_text(json.dumps(sidecar, indent=2, ensure_ascii=False) + "\n",
                                               encoding="utf-8", newline="\n")
    return sidecar


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--from", dest="src", help="read the list from this local file instead of downloading it")
    ap.add_argument("--date", help="snapshot date YYYY-MM-DD (default: today, UTC)")
    ap.add_argument("--notes", default="", help="free-text provenance note stored in the header")
    ap.add_argument("--out", default=str(OUT_DIR), help="output directory (default: vulnscan/data/web)")
    args = ap.parse_args(argv)
    raw = Path(args.src).read_bytes() if args.src else fetch()
    day = args.date or datetime.now(timezone.utc).date().isoformat()
    info = write(raw, day, args.notes, Path(args.out))
    print(f"psl.dat.gz: {info['rules']} rules, sha256 {info['sha256']}, date {day}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
