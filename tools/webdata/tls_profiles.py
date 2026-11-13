"""Refresh the bundled Mozilla server-side TLS profiles (maintainers only; needs the network unless --from is given).

    python tools/webdata/tls_profiles.py                     # download guidelines 6.0 from mozilla/ssl-config-generator
    python tools/webdata/tls_profiles.py --from 6.0.json     # use a local copy

Source: ``docs/guidelines/<version>.json`` of mozilla/ssl-config-generator (the data behind ssl-config.mozilla.org;
MPL-2.0; only the factual values are kept, unmodified except one normalisation: a ``null`` ``rsa_key_size`` (the modern
profile allows no RSA certificate) is written as ``0`` because the data schema requires an integer). The "old" profile
was removed upstream in 6.0. ``meta.date`` is given by ``--date`` (the upstream file carries no date) so refreshing
the same file twice is byte-identical.
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
OUT_NAME = "tls-profiles.json"
SOURCE = "https://raw.githubusercontent.com/mozilla/ssl-config-generator/master/docs/guidelines/{version}.json"
LICENSE = "MPL-2.0 (mozilla/ssl-config-generator data)"
KEEP = ("tls_versions", "ciphersuites", "ciphers", "tls_curves", "certificate_types", "certificate_curves",
        "certificate_signatures", "rsa_key_size", "dh_param_size", "ecdh_param_size", "hsts_min_age",
        "maximum_certificate_lifespan", "recommended_certificate_lifespan", "ocsp_staple", "server_preferred_order")


def fetch(version: str = "6.0", timeout: float = 60.0) -> bytes:
    sys.path.insert(0, str(ROOT))
    from vulnscan import __version__
    req = urllib.request.Request(SOURCE.format(version=version),
                                 headers={"User-Agent": f"Kashif/{__version__} webdata-refresh"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # nosec - fixed maintainer URL
        return resp.read(1024 * 1024)


def build(raw: dict, day: str, version: str = "6.0", notes: str = "") -> dict:
    confs = raw.get("configurations") or {}
    profiles: dict[str, dict] = {}
    for name in ("intermediate", "modern"):
        src = confs.get(name)
        if not isinstance(src, dict):
            raise SystemExit(f"profile {name!r} missing upstream")
        prof = {k: src[k] for k in KEEP if k in src}
        if prof.get("rsa_key_size") is None:
            prof["rsa_key_size"] = 0
        ciphers = prof.get("ciphers")
        if isinstance(ciphers, dict):
            prof["ciphers"] = {"iana": list(ciphers.get("iana") or []), "openssl": list(ciphers.get("openssl") or [])}
        profiles[name] = prof
    meta = {"schema_version": 1, "date": day, "source": SOURCE.format(version=version), "license": LICENSE,
            "generator": "tools/webdata/tls_profiles.py", "upstream_version": str(raw.get("version", version))}
    if notes:
        meta["notes"] = notes
    return {"meta": meta, "version": float(raw.get("version") or version), "profiles": profiles}


def write(obj: dict, out_dir: Path = OUT_DIR) -> Path:
    sys.path.insert(0, str(ROOT))
    from vulnscan.webscan import data
    errors = data.validate_data(OUT_NAME, obj)
    if errors:
        raise SystemExit("schema errors:\n" + "\n".join(errors[:20]))
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / OUT_NAME
    path.write_text(json.dumps(obj, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    return path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--from", dest="src", help="local guidelines JSON (e.g. 6.0.json)")
    ap.add_argument("--guidelines", default="6.0", help="guidelines version to download (default: 6.0)")
    ap.add_argument("--date", help="snapshot date YYYY-MM-DD (default: today, UTC)")
    ap.add_argument("--notes", default="", help="free-text provenance note stored in the header")
    ap.add_argument("--out", default=str(OUT_DIR), help="output directory (default: vulnscan/data/web)")
    args = ap.parse_args(argv)
    raw = Path(args.src).read_bytes() if args.src else fetch(args.guidelines)
    day = args.date or datetime.now(timezone.utc).date().isoformat()
    obj = build(json.loads(raw.decode("utf-8")), day, version=args.guidelines, notes=args.notes)
    path = write(obj, Path(args.out))
    print(f"{path.name}: Mozilla guidelines {obj['version']} ({', '.join(obj['profiles'])}), date {day}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
