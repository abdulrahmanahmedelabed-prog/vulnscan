#!/usr/bin/env python3
"""Replace the __VERSION__ placeholder in the landing page with the package version.

Usage:
    python site/stamp_version.py [HTML_FILE] [--version X.Y.Z]

HTML_FILE defaults to site/index.html and is rewritten in place. The version is
read from vulnscan/__init__.py (__version__ = "x.y.z") unless --version is given.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLACEHOLDER = "__VERSION__"


def read_version(init_file: pathlib.Path = ROOT / "vulnscan" / "__init__.py") -> str:
    m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', init_file.read_text(encoding="utf-8"), re.M)
    if not m:
        raise SystemExit(f"stamp_version: __version__ not found in {init_file}")
    return m.group(1)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("html", nargs="?", default=str(ROOT / "site" / "index.html"))
    ap.add_argument("--version", help="version to stamp (default: vulnscan/__init__.py)")
    args = ap.parse_args(argv)

    version = (args.version or read_version()).strip().lstrip("vV")
    if not re.fullmatch(r"[0-9][0-9A-Za-z.+-]*", version):
        raise SystemExit(f"stamp_version: refusing suspicious version {version!r}")
    path = pathlib.Path(args.html)
    text = path.read_text(encoding="utf-8")
    count = text.count(PLACEHOLDER)
    if count == 0:
        print(f"stamp_version: no {PLACEHOLDER} placeholder in {path}", file=sys.stderr)
        return 1
    path.write_text(text.replace(PLACEHOLDER, version), encoding="utf-8")
    print(f"stamp_version: {path}: {count} placeholder(s) -> {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
