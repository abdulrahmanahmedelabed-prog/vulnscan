"""Refresh the bundled CSP allowlist-bypass lists (maintainers only; needs the network unless --from is given).

    python tools/webdata/csp_bypass.py                       # download google/csp-evaluator (default branch)
    python tools/webdata/csp_bypass.py --ref <commit>        # a pinned upstream commit
    python tools/webdata/csp_bypass.py --from DIR            # a local checkout (DIR/allowlist_bypasses/json/*.json)

Writes ``vulnscan/data/web/csp-bypass.json``: the JSONP endpoints, AngularJS hosts and Flash files that CSP Evaluator
knows can bypass a host-allowlist policy (WEB209). The lists are data from google/csp-evaluator (Apache-2.0; NOTICE
carries the attribution); they are copied unmodified apart from de-duplication and protocol-relative normalisation
(``//host/path``). Downloading the lists leaks nothing about any scan target.

The upstream ``needsEval`` list (JSONP hosts whose bypass needs ``'unsafe-eval'``) has no key in the frozen data schema
(WP0); csp.py carries it as ``NEEDS_EVAL`` and this script prints a warning when upstream changes it.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "vulnscan" / "data" / "web"
OUT_NAME = "csp-bypass.json"
REPO = "google/csp-evaluator"
RAW = "https://raw.githubusercontent.com/" + REPO + "/{ref}/allowlist_bypasses/json/{name}.json"
SOURCE = "google/csp-evaluator, allowlist_bypasses/json"
LICENSE = "Apache-2.0"
FILES = ("jsonp", "angular", "flash")
MIN_JSONP, MIN_ANGULAR = 100, 30


def fetch(name: str, ref: str = "main", timeout: float = 60.0) -> bytes:
    sys.path.insert(0, str(ROOT))
    from vulnscan import __version__
    url = RAW.format(ref=ref, name=name)
    req = urllib.request.Request(url, headers={"User-Agent": f"Kashif/{__version__} webdata-refresh"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # nosec - fixed maintainer URL
        return resp.read(4 * 1024 * 1024)


def _norm(url: str) -> str | None:
    """``//host/path`` (lower-case host, path kept); None for anything that is not a protocol-relative URL."""
    u = url.strip()
    if "://" in u:
        u = "//" + u.split("://", 1)[1]
    if not u.startswith("//") or len(u) < 4 or any(c.isspace() for c in u):
        return None
    host, sep, path = u[2:].partition("/")
    if not host or not all(c.isalnum() or c in "-." for c in host):
        return None
    return "//" + host.lower() + (sep + path if sep else "/")


def normalise(raw: dict[str, dict]) -> tuple[dict[str, list[str]], list[str]]:
    """``({"jsonp": [...], "angular": [...], "flash": [...]}, needs_eval)`` from the three upstream JSON objects."""
    out: dict[str, list[str]] = {}
    for name in FILES:
        urls = raw.get(name, {}).get("urls", [])
        seen: dict[str, None] = {}
        for u in urls:
            n = _norm(str(u))
            if n:
                seen.setdefault(n, None)
        out[name] = list(seen)
    needs_eval = sorted({str(h).strip().lower() for h in raw.get("jsonp", {}).get("needsEval", []) if str(h).strip()})
    if len(out["jsonp"]) < MIN_JSONP or len(out["angular"]) < MIN_ANGULAR:
        raise SystemExit(f"suspiciously small lists: jsonp={len(out['jsonp'])} angular={len(out['angular'])}")
    return out, needs_eval


def build(raw: dict[str, dict], day: str, upstream: str = "", notes: str = "") -> dict:
    lists, _needs_eval = normalise(raw)
    meta = {"schema_version": 1, "date": day, "source": SOURCE, "license": LICENSE,
            "generator": "tools/webdata/csp_bypass.py"}
    if upstream:
        meta["upstream_version"] = upstream
    if notes:
        meta["notes"] = notes
    return {"meta": meta, "jsonp": lists["jsonp"], "angular": lists["angular"], "flash": lists["flash"]}


def write(obj: dict, out_dir: Path = OUT_DIR) -> Path:
    sys.path.insert(0, str(ROOT))
    from vulnscan.webscan import data
    errors = data.validate_data(OUT_NAME, obj)
    if errors:
        raise SystemExit("schema errors: " + "; ".join(errors[:5]))
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / OUT_NAME
    path.write_text(json.dumps(obj, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    return path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--from", dest="src", help="local csp-evaluator checkout (reads allowlist_bypasses/json/*.json)")
    ap.add_argument("--ref", default="main", help="upstream branch or commit to download (default: main)")
    ap.add_argument("--upstream-version", default="", help="upstream commit/version recorded in meta")
    ap.add_argument("--date", help="snapshot date YYYY-MM-DD (default: today, UTC)")
    ap.add_argument("--notes", default="", help="free-text provenance note stored in the header")
    ap.add_argument("--out", default=str(OUT_DIR), help="output directory (default: vulnscan/data/web)")
    args = ap.parse_args(argv)
    raw: dict[str, dict] = {}
    for name in FILES:
        if args.src:
            blob = (Path(args.src) / "allowlist_bypasses" / "json" / f"{name}.json").read_bytes()
        else:
            blob = fetch(name, args.ref)
        raw[name] = json.loads(blob.decode("utf-8"))
    day = args.date or datetime.now(timezone.utc).date().isoformat()
    upstream = args.upstream_version or ("" if args.src else args.ref)
    obj = build(raw, day, upstream, args.notes)
    path = write(obj, Path(args.out))
    _lists, needs_eval = normalise(raw)
    sys.path.insert(0, str(ROOT))
    from vulnscan.webscan.csp import NEEDS_EVAL
    if set(needs_eval) != set(NEEDS_EVAL):
        print(f"warning: upstream needsEval changed; update csp.NEEDS_EVAL to {needs_eval}", file=sys.stderr)
    print(f"{path.name}: jsonp={len(obj['jsonp'])} angular={len(obj['angular'])} flash={len(obj['flash'])}, date {day}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
