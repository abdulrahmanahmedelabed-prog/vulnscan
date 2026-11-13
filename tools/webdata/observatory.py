"""Refresh the bundled MDN HTTP Observatory scoring table (maintainers only; needs the network unless --from is given).

    python tools/webdata/observatory.py                          # download mdn/mdn-http-observatory at tag v1.7.2
    python tools/webdata/observatory.py --from ~/src/mdn-http-observatory --date 2026-11-13

Source: ``src/types.js`` (the ``Expectation`` slugs), ``src/grader/charts.js`` (``GRADE_CHART``, ``SCORE_TABLE``
modifiers, ``MINIMUM_SCORE_FOR_EXTRA_CREDIT``), ``src/constants.js`` (``ALGORITHM_VERSION``) and every
``src/analyzer/tests/*.js`` (the test name and its ``possibleResults``) of mdn/mdn-http-observatory (MPL-2.0). Only the
numbers are kept (test → slug → score modifier, the grade chart): facts, no code. ``grade.py`` (WP13) reproduces the
scorer of ``src/scanner/index.js`` from them. ``meta.date`` comes from ``--date`` so refreshing twice is byte-identical.
The JavaScript is read with regular expressions, never executed.
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
OUT_NAME = "observatory-v6.json"
TAG = "v1.7.2"
RAW = "https://raw.githubusercontent.com/mdn/mdn-http-observatory/{tag}/{path}"
LICENSE = "MPL-2.0 (mdn/mdn-http-observatory; numeric scoring facts only)"
TEST_FILES = ("content-security-policy:csp", "cookies:cookies", "cross-origin-embedder-policy:cross-origin-embedder-policy",
              "cross-origin-opener-policy:cross-origin-opener-policy", "cross-origin-resource-sharing:cors",
              "redirection:redirection", "referrer-policy:referrer-policy",
              "strict-transport-security:strict-transport-security", "subresource-integrity:subresource-integrity",
              "x-content-type-options:x-content-type-options", "x-frame-options:x-frame-options",
              "cross-origin-resource-policy:cross-origin-resource-policy")


def _read(src: str | None, tag: str, rel: str, timeout: float = 60.0) -> str:
    if src:
        return (Path(src) / rel).read_text(encoding="utf-8")
    sys.path.insert(0, str(ROOT))
    from vulnscan import __version__
    req = urllib.request.Request(RAW.format(tag=tag, path=rel), headers={"User-Agent": f"Kashif/{__version__} webdata-refresh"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # nosec - fixed maintainer URL
        return resp.read(2 * 1024 * 1024).decode("utf-8")


def parse(files: dict[str, str]) -> dict:
    """``files``: relative path → JavaScript text. Returns the parsed facts (raises SystemExit on a format change)."""
    types_js = files["src/types.js"]
    block = types_js[types_js.index("export const Expectation"):]
    block = block[:block.index("};")]
    slugs = dict(re.findall(r"(\w+):\s*\"([a-z0-9-]+)\"", block))
    charts = files["src/grader/charts.js"]
    chart_src = charts[charts.index("GRADE_CHART"):]
    chart_src = chart_src[:chart_src.index("]);")]
    chart = {int(k): v for k, v in re.findall(r"\[\s*(\d+)\s*,\s*\"([A-F][+-]?)\"\s*\]", chart_src)}
    table_src = charts[charts.index("export const SCORE_TABLE"):]
    modifiers = {name: int(mod) for name, mod in
                 re.findall(r"Expectation\.(\w+),\s*\{.*?modifier:\s*(-?\d+)", table_src, re.S)}
    m = re.search(r"MINIMUM_SCORE_FOR_EXTRA_CREDIT\s*=\s*(\d+)", charts)
    threshold = int(m.group(1)) if m else None
    m = re.search(r"ALGORITHM_VERSION\s*=\s*(\d+)", files["src/constants.js"])
    algorithm = int(m.group(1)) if m else None
    tests: dict[str, dict[str, int]] = {}
    for item in TEST_FILES:
        test, stem = item.split(":")
        js = files[f"src/analyzer/tests/{stem}.js"]
        name = re.search(r"static name\s*=\s*\"([^\"]+)\"", js)
        res = re.search(r"static possibleResults\s*=\s*\[(.*?)\]", js, re.S)
        if not name or not res or name.group(1) != test:
            raise SystemExit(f"cannot read the test definition in {stem}.js")
        out: dict[str, int] = {}
        for exp in re.findall(r"Expectation\.(\w+)", res.group(1)):
            if exp not in slugs or exp not in modifiers:
                raise SystemExit(f"{test}: expectation {exp} has no slug or no modifier")
            out[slugs[exp]] = modifiers[exp]
        tests[test] = out
    # results a test can produce that are not in its possibleResults (html-not-parseable is set by the SRI test)
    extra = {"subresource-integrity": ("HtmlNotParseable",),
             "content-security-policy": ("CspImplementedButDuplicateDirectives",)}
    for test, names in extra.items():
        for exp in names:
            if exp in slugs and exp in modifiers:
                tests[test].setdefault(slugs[exp], modifiers[exp])
    if algorithm is None or threshold is None or len(chart) != 21 or len(tests) != 12:
        raise SystemExit("unexpected upstream format (algorithm, threshold, chart or tests)")
    return {"algorithm": algorithm, "threshold": threshold, "chart": chart, "tests": tests}


def build(facts: dict, day: str, tag: str = TAG, notes: str = "") -> dict:
    tests = {t: dict(sorted(v.items(), key=lambda kv: (-kv[1], kv[0]))) for t, v in sorted(facts["tests"].items())}
    max_score = 100 + sum(max(0, max(v.values())) for v in tests.values())
    meta = {"schema_version": 1, "date": day, "source": RAW.format(tag=tag, path="src/grader/charts.js"),
            "license": LICENSE, "generator": "tools/webdata/observatory.py", "upstream_version": tag.lstrip("v")}
    if notes:
        meta["notes"] = notes
    return {"meta": meta, "algorithm_version": facts["algorithm"], "max_score": max_score, "base_score": 100,
            "extra_credit_threshold": facts["threshold"], "tests": tests,
            "grade_chart": {str(k): facts["chart"][k] for k in sorted(facts["chart"], reverse=True)}}


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
    ap.add_argument("--from", dest="src", help="local mdn-http-observatory checkout")
    ap.add_argument("--tag", default=TAG, help=f"upstream tag to download (default: {TAG})")
    ap.add_argument("--date", help="snapshot date YYYY-MM-DD (default: today, UTC)")
    ap.add_argument("--notes", default="", help="free-text provenance note stored in the header")
    ap.add_argument("--out", default=str(OUT_DIR), help="output directory (default: vulnscan/data/web)")
    args = ap.parse_args(argv)
    rels = ["src/types.js", "src/grader/charts.js", "src/constants.js"] + \
           [f"src/analyzer/tests/{t.split(':')[1]}.js" for t in TEST_FILES]
    files = {rel: _read(args.src, args.tag, rel) for rel in rels}
    day = args.date or datetime.now(timezone.utc).date().isoformat()
    path = write(build(parse(files), day, args.tag, args.notes), Path(args.out))
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
