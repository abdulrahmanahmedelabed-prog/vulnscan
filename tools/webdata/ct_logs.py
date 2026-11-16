"""Refresh the bundled Certificate Transparency log list (maintainers only; needs the network unless --from is given).

    python tools/webdata/ct_logs.py                        # download Chromium's copy of the CT log list
    python tools/webdata/ct_logs.py --from log_list.json   # use a local copy (offline / mirror)

Source: ``components/certificate_transparency/data/log_list.json`` in the Chromium source tree (the same v3 list as
``gstatic.com/ct/log_list/v3/log_list.json``, which Chrome's CT policy enforces). Chromium's source is BSD-3-Clause;
NOTICE carries the Chromium notice. Only facts are kept: log id (base64 SHA-256 of the log key) → operator, state,
description. Keys and URLs are dropped: Kashif never contacts a log. ``meta.date`` is the list's own
``log_list_timestamp`` so the output is byte-identical for the same input. WEB713 (spec §2.8) turns tentative when
this snapshot is older than 120 days.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "vulnscan" / "data" / "web"
OUT_NAME = "ct-logs.json"
SOURCE = ("https://raw.githubusercontent.com/chromium/chromium/main/components/certificate_transparency/data/"
          "log_list.json")
LICENSE = "BSD-3-Clause (Chromium)"
STATES = ("pending", "qualified", "usable", "readonly", "retired", "rejected")
MIN_LOGS = 10


def fetch(url: str = SOURCE, timeout: float = 60.0) -> bytes:
    sys.path.insert(0, str(ROOT))
    from vulnscan import __version__
    req = urllib.request.Request(url, headers={"User-Agent": f"Kashif/{__version__} webdata-refresh"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # nosec - fixed maintainer URL
        return resp.read(16 * 1024 * 1024)


def _state(entry: dict) -> tuple[str, str]:
    st = entry.get("state") or {}
    for name in STATES:
        if name in st:
            return name, str((st.get(name) or {}).get("timestamp", ""))[:10]
    return "pending", ""


def build(raw: dict, notes: str = "") -> dict:
    """Normalise Chromium's log list v3 into ``{"meta", "logs": {log_id: {operator, state, description}}}``."""
    logs: dict[str, dict] = {}
    for op in raw.get("operators") or []:
        name = str(op.get("name") or "").strip()
        for kind in ("logs", "tiled_logs"):
            for entry in op.get(kind) or []:
                log_id = str(entry.get("log_id") or "")
                if len(log_id) != 44 or not name:
                    continue
                state, since = _state(entry)
                item = {"operator": name, "state": state, "description": str(entry.get("description") or "")}
                if since:
                    item["state_since"] = since
                logs[log_id] = item
    if len(logs) < MIN_LOGS:
        raise SystemExit(f"suspiciously small log list: {len(logs)} logs")
    stamp = str(raw.get("log_list_timestamp") or "")[:10]
    if len(stamp) != 10:
        raise SystemExit("log list without log_list_timestamp")
    meta = {"schema_version": 1, "date": stamp, "source": SOURCE, "license": LICENSE,
            "generator": "tools/webdata/ct_logs.py", "upstream_version": str(raw.get("version") or "")}
    if notes:
        meta["notes"] = notes
    return {"meta": meta, "logs": dict(sorted(logs.items()))}


def write(obj: dict, out_dir: Path = OUT_DIR) -> Path:
    sys.path.insert(0, str(ROOT))
    from vulnscan.webscan import data
    errors = data.validate_data(OUT_NAME, obj)
    if errors:
        raise SystemExit("schema errors:\n" + "\n".join(errors[:20]))
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / OUT_NAME
    path.write_text(json.dumps(obj, indent=1, ensure_ascii=False, sort_keys=False) + "\n", encoding="utf-8",
                    newline="\n")
    return path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--from", dest="src", help="local log_list.json (v3 format)")
    ap.add_argument("--url", default=SOURCE, help="download URL (default: Chromium's copy)")
    ap.add_argument("--notes", default="", help="free-text provenance note stored in the header")
    ap.add_argument("--out", default=str(OUT_DIR), help="output directory (default: vulnscan/data/web)")
    args = ap.parse_args(argv)
    raw = Path(args.src).read_bytes() if args.src else fetch(args.url)
    obj = build(json.loads(raw.decode("utf-8")), notes=args.notes)
    path = write(obj, Path(args.out))
    ops = sorted({v["operator"] for v in obj["logs"].values()})
    print(f"{path.name}: {len(obj['logs'])} logs, {len(ops)} operators, list of {obj['meta']['date']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
