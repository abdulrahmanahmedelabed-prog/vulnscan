"""Refresh the bundled end-of-life snapshot (maintainers only; needs the network unless --from is given).

    python tools/webdata/eol.py                     # download products/<slug>.md from endoflife-date/endoflife.date
    python tools/webdata/eol.py --from DIR          # a local checkout's products/ directory (or a folder of .md files)

Writes ``vulnscan/data/web/eol.json``: product → release cycles with the end-of-life date (or ``false``), the latest
patch release, release date, LTS flag and end of active support. The data is endoflife.date's (MIT; NOTICE carries the
attribution), read from the YAML front matter of each product page. The snapshot is shipped as is: Kashif never asks
endoflife.date (or anyone) about a scan target.

The ``iis`` product is derived: IIS versions ship with Windows Server (6.0 → 2003, 7.0 → 2008, 7.5 → 2008 R2,
8.0 → 2012, 8.5 → 2012 R2, 10.0 → 2016 and later), so each IIS cycle takes the end-of-life date of its Windows Server
release (10.0 takes the newest, i.e. it is not end of life while any Windows Server with IIS 10.0 is supported).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "vulnscan" / "data" / "web"
OUT_NAME = "eol.json"
RAW = "https://raw.githubusercontent.com/endoflife-date/endoflife.date/{ref}/products/{slug}.md"
SOURCE = "endoflife-date/endoflife.date, products/*.md"
LICENSE = "MIT"

# platforms (WEB081), server software and runtimes (WEB801), front-end frameworks (WEB803)
PRODUCTS = (
    "wordpress", "drupal", "joomla", "moodle", "magento", "typo3", "laravel", "django", "ruby-on-rails", "spring-boot",
    "symfony", "mediawiki", "umbraco", "craft-cms", "nextcloud", "gitlab", "confluence", "jira-software", "phpbb",
    "php", "nginx", "apache-http-server", "tomcat", "openssl", "nodejs", "python", "centos", "ubuntu", "debian", "rhel",
    "windows-server", "eclipse-jetty", "haproxy", "squid",
    "jquery", "jquery-ui", "angularjs", "angular", "bootstrap", "vue", "react", "emberjs", "nextjs",
)
IIS_MAP = (("6.0", ("2003-sp2", "2003")), ("7.0", ("2008-sp2", "2008")), ("7.5", ("2008-r2-sp1", "2008-r2")),
           ("8.0", ("2012",)), ("8.5", ("2012-r2",)), ("10.0", ("2025", "2022", "2019", "2016")))
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def fetch(slug: str, ref: str = "master", timeout: float = 60.0) -> str | None:
    sys.path.insert(0, str(ROOT))
    from vulnscan import __version__
    req = urllib.request.Request(RAW.format(ref=ref, slug=slug),
                                 headers={"User-Agent": f"Kashif/{__version__} webdata-refresh"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:   # nosec - fixed maintainer URL
            return resp.read(2 * 1024 * 1024).decode("utf-8")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def _scalar(raw: str):
    v = raw.split(" #", 1)[0].strip()
    if v.startswith(("'", '"')) and v.endswith(v[0]) and len(v) >= 2:
        return v[1:-1]
    low = v.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("null", "~", ""):
        return None
    return v


def parse_product(md: str) -> dict:
    """``{"name": title, "cycles": [...]}`` from an endoflife.date product page (front matter only)."""
    parts = md.split("\n---", 1)
    front = parts[0] if md.startswith("---") else md
    lines = front.splitlines()
    title = ""
    cycles: list[dict] = []
    in_releases = False
    cur: dict | None = None
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" ") and not line.startswith("-"):
            in_releases = line.startswith("releases:")
            if line.startswith("title:"):
                title = str(_scalar(line.split(":", 1)[1]) or "")
            continue
        if not in_releases:
            continue
        m = re.match(r"^\s*-\s+(\w+):\s*(.*)$", line)
        if m:
            cur = {}
            cycles.append(cur)
            cur[m.group(1)] = _scalar(m.group(2))
            continue
        m = re.match(r"^\s+(\w+):\s*(.*)$", line)
        if m and cur is not None:
            cur[m.group(1)] = _scalar(m.group(2))
    out = []
    for c in cycles:
        cyc = c.get("releaseCycle")
        if cyc in (None, ""):
            continue
        item: dict = {"cycle": str(cyc), "eol": _date_or_bool(c.get("eol"))}
        if c.get("latest") not in (None, ""):
            item["latest"] = str(c["latest"])
        if isinstance(c.get("releaseDate"), str) and _DATE.match(c["releaseDate"]):
            item["release"] = c["releaseDate"]
        if isinstance(c.get("lts"), bool):
            item["lts"] = c["lts"]
        sup = c.get("support", c.get("eoas"))
        if sup is not None:
            item["support"] = _date_or_bool(sup)
        out.append(item)
    return {"name": title, "cycles": out}


def _date_or_bool(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and _DATE.match(v):
        return v
    return False


def derive_iis(windows: dict) -> dict:
    by = {c["cycle"]: c for c in windows.get("cycles", [])}
    cycles = []
    for iis, names in IIS_MAP:
        found = [by[n] for n in names if n in by]
        if not found:
            continue
        eols = [c["eol"] for c in found]
        if any(e is False for e in eols):
            eol = False
        else:
            eol = max(e for e in eols if isinstance(e, str))
        cycles.append({"cycle": iis, "eol": eol})
    return {"name": "Microsoft IIS", "cycles": cycles}


def build(pages: dict[str, str], day: str, upstream: str = "", notes: str = "") -> dict:
    products: dict[str, dict] = {}
    for slug, md in sorted(pages.items()):
        prod = parse_product(md)
        if prod["cycles"]:
            products[slug] = prod
    if "windows-server" in products:
        products["iis"] = derive_iis(products["windows-server"])
    if len(products) < 10:
        raise SystemExit(f"suspiciously few products: {len(products)}")
    meta = {"schema_version": 1, "date": day, "source": SOURCE, "license": LICENSE, "generator": "tools/webdata/eol.py"}
    if upstream:
        meta["upstream_version"] = upstream
    if notes:
        meta["notes"] = notes
    return {"meta": meta, "products": products}


def write(obj: dict, out_dir: Path = OUT_DIR) -> Path:
    sys.path.insert(0, str(ROOT))
    from vulnscan.webscan import data
    errors = data.validate_data(OUT_NAME, obj)
    if errors:
        raise SystemExit("schema errors: " + "; ".join(errors[:5]))
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / OUT_NAME
    path.write_text(json.dumps(obj, indent=None, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8",
                    newline="\n")
    return path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--from", dest="src", help="directory with <slug>.md product pages")
    ap.add_argument("--ref", default="master", help="upstream branch or commit (default: master)")
    ap.add_argument("--upstream-version", default="", help="upstream commit/version recorded in meta")
    ap.add_argument("--date", help="snapshot date YYYY-MM-DD (default: today, UTC)")
    ap.add_argument("--notes", default="", help="free-text provenance note stored in the header")
    ap.add_argument("--out", default=str(OUT_DIR), help="output directory (default: vulnscan/data/web)")
    args = ap.parse_args(argv)
    pages: dict[str, str] = {}
    for slug in PRODUCTS:
        if args.src:
            p = Path(args.src) / f"{slug}.md"
            text = p.read_text(encoding="utf-8") if p.is_file() else None
        else:
            text = fetch(slug, args.ref)
        if text is None:
            print(f"warning: no product page for {slug}", file=sys.stderr)
            continue
        pages[slug] = text
    day = args.date or datetime.now(timezone.utc).date().isoformat()
    obj = build(pages, day, args.upstream_version or ("" if args.src else args.ref), args.notes)
    path = write(obj, Path(args.out))
    print(f"wrote {path} ({len(obj['products'])} products)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
