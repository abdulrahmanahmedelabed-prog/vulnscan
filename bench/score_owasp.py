"""Score vulnscan against the OWASP Benchmark (https://owasp.org/www-project-benchmark/).

Usage:
    python bench/score_owasp.py <BenchmarkJava|BenchmarkPython checkout> [--json out.json] [--min-score S]

The Benchmark is a suite of small programs, each labelled with a CWE and whether it is a real vulnerability.
A test case counts as *flagged* when vulnscan reports, in that test's file, a finding whose CWE belongs to the
test's category. Scoring follows the official method: per category, TPR = TP/(TP+FN), FPR = FP/(FP+TN), score =
TPR - FPR (Youden's J); the overall score is the unweighted mean across categories. 0 is random guessing, 100%
is perfect. Commercial SAST tools published by OWASP typically score between 10% and 40% on the Java suite.
"""

from __future__ import annotations

import argparse
import csv
import json
import pathlib
import re
import subprocess
import sys

# Which reported CWEs count as a detection for each Benchmark CWE (tools legitimately use near CWEs).
EQUIV = {
    22: {22, 23, 36, 73},
    78: {78, 77, 88},
    79: {79, 80},
    89: {89, 564},
    90: {90},
    94: {94, 95, 96},
    327: {327, 326, 328},
    328: {328, 327, 916},
    330: {330, 338},
    501: {501},
    502: {502},
    601: {601},
    611: {611, 776},
    614: {614, 1004},
    643: {643},
}


def load_expected(root: pathlib.Path) -> dict[str, tuple[str, bool, int]]:
    csv_path = next(root.glob("expectedresults-*.csv"))
    out = {}
    with open(csv_path, encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#"):
                continue
            out[row[0].strip()] = (row[1].strip(), row[2].strip().lower() == "true", int(row[3]))
    return out


def run_scan(root: pathlib.Path, out: pathlib.Path) -> list[dict]:
    # The whole application is scanned (helpers included), as a user would scan their project; findings are then
    # attributed to test cases by file name.
    code = root if (root / "testcode").is_dir() else root / "src/main"
    subprocess.run([sys.executable, "-m", "vulnscan", str(code), "--exclude", "*.html", "--exclude", "results/*", "--no-deps", "--no-external", "--no-jadx",
                    "-f", "json", "-o", str(out)], check=False, stdout=subprocess.DEVNULL)
    return json.loads(out.read_text(encoding="utf-8"))["findings"]


def score(expected, findings) -> dict:
    cwes_by_test: dict[str, set[int]] = {}
    for f in findings:
        m = re.search(r"(BenchmarkTest\d+)", f.get("file", ""))
        c = re.search(r"(\d+)", f.get("cwe") or "")
        if m and c:
            cwes_by_test.setdefault(m.group(1), set()).add(int(c.group(1)))
    cats: dict[str, dict] = {}
    for test, (cat, real, cwe) in expected.items():
        hit = bool(cwes_by_test.get(test, set()) & EQUIV.get(cwe, {cwe}))
        c = cats.setdefault(cat, {"cwe": cwe, "tp": 0, "fn": 0, "fp": 0, "tn": 0})
        c["tp" if real and hit else "fn" if real else "fp" if hit else "tn"] += 1
    for c in cats.values():
        tpr = c["tp"] / max(1, c["tp"] + c["fn"])
        fpr = c["fp"] / max(1, c["fp"] + c["tn"])
        c.update(tpr=round(tpr * 100, 1), fpr=round(fpr * 100, 1), score=round((tpr - fpr) * 100, 1))
    overall = round(sum(c["score"] for c in cats.values()) / max(1, len(cats)), 1)
    return {"overall": overall, "categories": dict(sorted(cats.items()))}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("benchmark")
    ap.add_argument("--json")
    ap.add_argument("--min-score", type=float)
    a = ap.parse_args()
    root = pathlib.Path(a.benchmark)
    out = pathlib.Path(a.json or "owasp-findings.json")
    res = score(load_expected(root), run_scan(root, out))
    print(f"{'category':<16}{'CWE':>5}{'TP':>6}{'FN':>6}{'FP':>6}{'TN':>6}{'TPR%':>8}{'FPR%':>8}{'score%':>8}")
    for name, c in res["categories"].items():
        print(f"{name:<16}{c['cwe']:>5}{c['tp']:>6}{c['fn']:>6}{c['fp']:>6}{c['tn']:>6}{c['tpr']:>8}{c['fpr']:>8}{c['score']:>8}")
    print(f"\nOverall OWASP Benchmark score (mean TPR-FPR): {res['overall']}%")
    if a.json:
        pathlib.Path(a.json).with_suffix(".score.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    return 1 if a.min_score is not None and res["overall"] < a.min_score else 0


if __name__ == "__main__":
    sys.exit(main())
