"""Refresh the bundled favicon hash table (maintainers only; needs the network unless --from is given).

    python tools/webdata/favicons.py                       # download projectdiscovery/nuclei-templates main
    python tools/webdata/favicons.py --from favicon-detect.yaml

Writes ``vulnscan/data/web/favicons.json``: Shodan-style favicon hashes (signed MurmurHash3 x86-32 of
``base64.encodebytes(icon)``, see ``webscan/mmh3.py``) → technology, from nuclei's
``http/technologies/favicon-detect.yaml`` (MIT; NOTICE carries the attribution). Each matcher's ``name`` becomes the
technology id (lower-case, ``[a-z0-9._+-]``); names that tech.json knows under another id are mapped by ``ALIASES``.
YAML is parsed with a few regular expressions: the template is a flat list of ``name`` + ``dsl`` matchers.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "vulnscan" / "data" / "web"
OUT_NAME = "favicons.json"
RAW = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/{ref}/http/technologies/favicon-detect.yaml"
SOURCE = "projectdiscovery/nuclei-templates, http/technologies/favicon-detect.yaml"
LICENSE = "MIT"
MIN_HASHES = 500
# nuclei matcher name → tech.json id
ALIASES = {"apache-tomcat": "tomcat", "atlassian-jira": "jira", "atlassian-confluence": "confluence",
           "spring-boot": "spring-boot", "phpmyadmin": "phpmyadmin", "gitlab": "gitlab", "jenkins": "jenkins",
           "grafana": "grafana", "kibana": "kibana", "wordpress": "wordpress", "joomla": "joomla", "drupal": "drupal",
           "moodle": "moodle", "magento": "magento", "plesk": "plesk", "cpanel-login": "cpanel", "webmin": "webmin",
           "roundcube-webmail": "roundcube", "big-ip": "f5-big-ip", "microsoft-owa": "outlook-web-app",
           "outlook-web-application": "outlook-web-app", "sonarqube": "sonarqube", "nextcloud": "nextcloud",
           "angular-io-angularjs": "angular", "react": "react", "laravel": "laravel", "django": "django"}


def fetch(ref: str = "main", timeout: float = 60.0) -> str:
    sys.path.insert(0, str(ROOT))
    from vulnscan import __version__
    req = urllib.request.Request(RAW.format(ref=ref), headers={"User-Agent": f"Kashif/{__version__} webdata-refresh"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # nosec - fixed maintainer URL
        return resp.read(8 * 1024 * 1024).decode("utf-8")


def slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9._+-]+", "-", name.strip().lower()).strip("-.")
    return s or "unknown"


def parse(yaml_text: str) -> list[dict]:
    """``[{"hash", "tech", "name"}]`` in template order (first name wins for a hash listed twice)."""
    out: list[dict] = []
    seen: set[int] = set()
    for block in re.split(r"\n\s*-\s+type:\s*", yaml_text)[1:]:
        m = re.search(r'\n\s*name:\s*"?([^"\n]+?)"?\s*\n', "\n" + block)
        if not m:
            continue
        name = m.group(1).strip()
        for h in re.findall(r'\\?"(-?\d+)\\?"\s*==\s*mmh3\(base64_py\(body\)\)', block):
            value = int(h)
            if value in seen or not -2**31 <= value < 2**31:
                continue
            seen.add(value)
            tech = ALIASES.get(name.lower(), slug(name))
            out.append({"hash": value, "tech": tech, "name": name})
    return out


def build(yaml_text: str, day: str, upstream: str = "", notes: str = "") -> dict:
    hashes = parse(yaml_text)
    if len(hashes) < MIN_HASHES:
        raise SystemExit(f"suspiciously few favicon hashes: {len(hashes)}")
    meta = {"schema_version": 1, "date": day, "source": SOURCE, "license": LICENSE,
            "generator": "tools/webdata/favicons.py"}
    if upstream:
        meta["upstream_version"] = upstream
    if notes:
        meta["notes"] = notes
    return {"meta": meta, "hashes": hashes}


def write(obj: dict, out_dir: Path = OUT_DIR) -> Path:
    sys.path.insert(0, str(ROOT))
    from vulnscan.webscan import data
    errors = data.validate_data(OUT_NAME, obj)
    if errors:
        raise SystemExit("schema errors: " + "; ".join(errors[:5]))
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / OUT_NAME
    lines = ",\n".join(json.dumps(h, ensure_ascii=False) for h in obj["hashes"])
    path.write_text('{"meta": ' + json.dumps(obj["meta"], ensure_ascii=False) + ',\n"hashes": [\n' + lines + "\n]}\n",
                    encoding="utf-8", newline="\n")
    return path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--from", dest="src", help="a local favicon-detect.yaml")
    ap.add_argument("--ref", default="main", help="upstream branch or commit (default: main)")
    ap.add_argument("--upstream-version", default="", help="upstream commit/version recorded in meta")
    ap.add_argument("--date", help="snapshot date YYYY-MM-DD (default: today, UTC)")
    ap.add_argument("--notes", default="", help="free-text provenance note stored in the header")
    ap.add_argument("--out", default=str(OUT_DIR), help="output directory (default: vulnscan/data/web)")
    args = ap.parse_args(argv)
    text = Path(args.src).read_text(encoding="utf-8") if args.src else fetch(args.ref)
    day = args.date or datetime.now(timezone.utc).date().isoformat()
    obj = build(text, day, args.upstream_version or ("" if args.src else args.ref), args.notes)
    path = write(obj, Path(args.out))
    print(f"wrote {path} ({len(obj['hashes'])} hashes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
