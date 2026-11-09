"""Write OWASP Benchmark results into the landing page, so the published numbers are exactly what the scorer measured.

Usage:
    python bench/score_owasp.py BenchmarkPython --json py.json
    python bench/score_owasp.py BenchmarkJava --json java.json
    python bench/update_site.py py.json java.json            # rewrites the BENCH block in site/index.html
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

SITE = pathlib.Path(__file__).resolve().parent.parent / "site" / "index.html"
SUITES = (("python", "OWASP Benchmark for Python v0.1", "BenchmarkPython"),
          ("java", "OWASP Benchmark for Java v1.2", "BenchmarkJava"))


def block(results: list[dict]) -> str:
    out = ["const BENCH = {"]
    for i, ((key, title, repo), res) in enumerate(zip(SUITES, results)):
        cats = res["categories"]
        cases = sum(c["tp"] + c["fn"] + c["fp"] + c["tn"] for c in cats.values())
        out.append(f'  {key}: {{')
        out.append(f'    suite: "{title}", repo: "{repo}", cases: {cases},')
        out.append("    categories: [")
        rows = [f'      {{ id: "{cid}",{" " * (16 - len(cid))}tpr: {c["tpr"]:5.1f}, fpr: {c["fpr"]:4.1f}, score: {c["score"]:5.1f} }}'
                for cid, c in sorted(cats.items())]
        out.append(",\n".join(rows))
        out.append("    ]")
        out.append("  }" + ("," if i + 1 < len(SUITES) else ""))
    out.append("};")
    return "\n".join(out)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    results = [json.loads(pathlib.Path(a).read_text(encoding="utf-8")) for a in argv]
    html = SITE.read_text(encoding="utf-8")
    new, n = re.subn(r"const BENCH = \{.*?\n\};", lambda _m: block(results), html, count=1, flags=re.S)
    if n != 1:
        print("BENCH block not found in site/index.html", file=sys.stderr)
        return 1
    SITE.write_text(new, encoding="utf-8")
    for (key, _, _), res in zip(SUITES, results):
        print(f"{key}: overall {res['overall']}% over {len(res['categories'])} categories")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
