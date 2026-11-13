"""Refresh the bundled HSTS preload snapshot (maintainers only; needs the network unless --from is given).

    python tools/webdata/hsts_preload.py                     # download Chromium's list (default branch mirror)
    python tools/webdata/hsts_preload.py --googlesource      # the canonical chromium.googlesource.com copy
    python tools/webdata/hsts_preload.py --from FILE         # a local transport_security_state_static.json

Writes ``vulnscan/data/web/hsts-preload.json.gz``: every ``force-https`` entry of Chromium's
``net/http/transport_security_state_static.json`` as ``name → include_subdomains`` plus the preloaded TLDs (entries without
a dot, also inlined in ``vulnscan/webscan/transport.py`` as ``PRELOADED_TLDS``). The data is Chromium's (BSD-3-Clause;
NOTICE carries the attribution). Pinning-only entries are dropped. The output is deterministic (sorted keys, gzip with
``mtime=0``). Downloading the whole list leaks nothing about any scan target; Kashif never queries hstspreload.org per
target unless the user passes ``--third-party-lookups``.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import io
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "vulnscan" / "data" / "web"
OUT_NAME = "hsts-preload.json.gz"
PATH = "net/http/transport_security_state_static.json"
MIRROR = "https://raw.githubusercontent.com/chromium/chromium/main/" + PATH
GOOGLESOURCE = "https://chromium.googlesource.com/chromium/src/+/main/" + PATH + "?format=TEXT"   # base64 body
SOURCE = "Chromium " + PATH
LICENSE = "BSD-3-Clause"
MIN_ENTRIES = 50_000
MIN_TLDS = 40
MAX_DOWNLOAD = 64 * 1024 * 1024


def fetch(url: str, timeout: float = 120.0) -> bytes:
    sys.path.insert(0, str(ROOT))
    from vulnscan import __version__
    req = urllib.request.Request(url, headers={"User-Agent": f"Kashif/{__version__} webdata-refresh"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # nosec - fixed maintainer URL
        raw = resp.read(MAX_DOWNLOAD + 1)
    if len(raw) > MAX_DOWNLOAD:
        raise SystemExit("download larger than expected")
    if "format=TEXT" in url:
        raw = base64.b64decode(raw)
    return raw


def parse(raw: bytes) -> dict[str, bool]:
    """``name → include_subdomains`` of every force-https entry (the file is JSON with ``//`` comment lines)."""
    text = raw.decode("utf-8")
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("//"))
    doc = json.loads(body)
    out: dict[str, bool] = {}
    for e in doc.get("entries", []):
        if not isinstance(e, dict) or e.get("mode") != "force-https":
            continue
        name = str(e.get("name", "")).strip().lower().rstrip(".")
        if not name or name.startswith(".") or ".." in name or " " in name:
            continue
        out[name] = bool(e.get("include_subdomains")) or out.get(name, False)
    return out


def build(entries: dict[str, bool], day: str, notes: str = "", source_url: str = MIRROR) -> dict:
    tlds = sorted(n for n in entries if "." not in n)
    if len(entries) < MIN_ENTRIES:
        raise SystemExit(f"suspiciously small list: {len(entries)} entries")
    if len(tlds) < MIN_TLDS:
        raise SystemExit(f"suspiciously few preloaded TLDs: {len(tlds)}")
    meta = {"schema_version": 1, "date": day, "source": f"{SOURCE} ({source_url})", "license": LICENSE,
            "generator": "tools/webdata/hsts_preload.py"}
    if notes:
        meta["notes"] = notes
    return {"meta": meta, "tlds": tlds, "entries": dict(sorted(entries.items()))}


def gzip_deterministic(raw: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, compresslevel=9, mtime=0) as g:
        g.write(raw)
    return buf.getvalue()


def write(doc: dict, out_dir: Path = OUT_DIR) -> Path:
    sys.path.insert(0, str(ROOT))
    from vulnscan.webscan import data
    errors = data.validate_data(OUT_NAME, doc)
    if errors:
        raise SystemExit("schema errors: " + "; ".join(errors[:5]))
    payload = json.dumps(doc, ensure_ascii=True, separators=(",", ":"), sort_keys=False).encode("ascii")
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / OUT_NAME
    path.write_bytes(gzip_deterministic(payload))
    return path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--from", dest="src", help="read transport_security_state_static.json from this local file")
    src.add_argument("--googlesource", action="store_true", help="download from chromium.googlesource.com")
    src.add_argument("--url", help="download from this URL instead (a mirror of the same file)")
    ap.add_argument("--date", help="snapshot date YYYY-MM-DD (default: today, UTC)")
    ap.add_argument("--notes", default="", help="free-text provenance note stored in the header (e.g. the commit)")
    ap.add_argument("--out", default=str(OUT_DIR), help="output directory (default: vulnscan/data/web)")
    args = ap.parse_args(argv)
    if args.src:
        raw, url = Path(args.src).read_bytes(), MIRROR
    else:
        url = args.url or (GOOGLESOURCE if args.googlesource else MIRROR)
        raw = fetch(url)
    day = args.date or datetime.now(timezone.utc).date().isoformat()
    doc = build(parse(raw), day, args.notes, url.split("?", 1)[0])
    path = write(doc, Path(args.out))
    print(f"{path.name}: {len(doc['entries'])} entries, {len(doc['tlds'])} TLDs, {path.stat().st_size} bytes, date {day}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
