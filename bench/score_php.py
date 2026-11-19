"""Score vulnscan against the NIST SARD "PHP Vulnerability Test Suite" (Stivalet & Delaitre, 2015).

Usage:
    python bench/score_php.py <PHP-Vulnerability-test-suite checkout> [--json out.json] [--min-score S]
                              [--jobs N] [--by-input]

Source: https://github.com/stivalet/PHP-Vulnerability-test-suite (commit 6ebd7e0ccbac3b7c3374fe29eaf9167823549744),
the generator's published copy of SARD test suite 103, "PHP Vulnerability Test Suite" (42,212 test cases, test-case
manifests dated 12/11/15). SARD hosts the same files (https://samate.nist.gov/SARD/test-suites/103); the suite's
generator now lives at https://github.com/usnistgov/VTSG.

Labels come from the suite's own manifests (<category>/manifest.xml): a test case is *vulnerable* when its manifest
entry carries a <flaw> element, *safe* otherwise (the script also checks that this agrees with the safe/ and unsafe/
directories). Every test case of every included CWE directory is scored; nothing is sampled.

Included (41,712 cases): Injection/CWE_78 (OS command), CWE_89 (SQL), CWE_90 (LDAP), CWE_91 (XPath: the suite labels
its XPath-query cases CWE-91 "XML Injection"), CWE_95 (eval), CWE_98 (include/require), XSS/CWE_79 and URF/CWE_601
(open redirect). Excluded, 500 cases: IDOR/CWE_862_* (missing authorization: an access-control property, not a data
flow Kashif reports), SDE/CWE_311+327 and SM/CWE_209 (20 cases between them, too few to give a rate).

A test case counts as *flagged* when vulnscan reports, in that test's file, a finding whose CWE belongs to the test's
category (EQUIV below; the injection files also echo the query, and an XSS finding there does not count for SQL).
Scoring follows the OWASP Benchmark method (bench/score_owasp.py): per category TPR = TP/(TP+FN), FPR = FP/(FP+TN),
score = TPR - FPR; the overall score is the unweighted mean across categories.

The suite is generated synthetic code: each case is one source (superglobal, file/command read, session, object
field...), one sanitizer and one sink in a small script, so it measures the taint model's per-function and
per-output-context rules, not whole-application reasoning.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

CATEGORIES = {  # suite directory -> (category name, CWE)
    "Injection/CWE_78": ("cmdi", 78),
    "Injection/CWE_89": ("sqli", 89),
    "Injection/CWE_90": ("ldapi", 90),
    "Injection/CWE_91": ("xpathi", 91),
    "Injection/CWE_95": ("codeinj", 95),
    "Injection/CWE_98": ("fileinc", 98),
    "XSS/CWE_79": ("xss", 79),
    "URF/CWE_601": ("redirect", 601),
}

# Which reported CWEs count as a detection for each suite CWE (tools legitimately use near CWEs).
EQUIV = {
    78: {78, 77, 88},
    79: {79, 80},
    89: {89, 564},
    90: {90},
    91: {91, 643},
    95: {94, 95, 96},
    98: {98, 22, 23, 73, 829},
    601: {601},
}


def load_expected(root: pathlib.Path) -> dict[str, tuple[str, bool, int, str]]:
    """file path relative to root -> (category, vulnerable, cwe, input kind)."""
    out = {}
    for top in sorted({d.split("/")[0] for d in CATEGORIES}):
        tree = ET.parse(root / top / "manifest.xml")
        for tc in tree.getroot().iter("testcase"):
            f = tc.find("file")
            rel = f"{top}/{f.get('path')}"
            sub = "/".join(rel.split("/")[:2])
            if sub not in CATEGORIES:
                continue
            real = f.find("flaw") is not None
            if real != ("/unsafe/" in rel):
                raise SystemExit(f"manifest and directory disagree on {rel}")
            if not (root / rel).is_file():
                raise SystemExit(f"missing test file {rel}")
            cat, cwe = CATEGORIES[sub]
            out[rel] = (cat, real, cwe, pathlib.PurePath(rel).name.split("__")[1])
    return out


def _scan_dir(args) -> list[dict]:
    root, sub, tmp = args
    out = pathlib.Path(tmp) / (sub.replace("/", "_") + ".json")
    subprocess.run([sys.executable, "-m", "vulnscan", str(root / sub), "--no-deps", "--no-external", "--no-jadx",
                    "-f", "json", "-o", str(out)], check=False, stdout=subprocess.DEVNULL)
    findings = json.loads(out.read_text(encoding="utf-8"))["findings"]
    for f in findings:   # paths in the report are relative to the scanned directory
        f["file"] = f"{sub}/{f.get('file', '')}"
    return findings


def run_scan(root: pathlib.Path, jobs: int) -> list[dict]:
    # Each CWE directory is scanned as its own project (the suite has no shared code between test cases).
    with tempfile.TemporaryDirectory() as tmp, concurrent.futures.ProcessPoolExecutor(jobs) as ex:
        return [f for chunk in ex.map(_scan_dir, [(root, s, tmp) for s in CATEGORIES]) for f in chunk]


def _rates(c: dict) -> None:
    tpr = c["tp"] / max(1, c["tp"] + c["fn"])
    fpr = c["fp"] / max(1, c["fp"] + c["tn"])
    c.update(tpr=round(tpr * 100, 1), fpr=round(fpr * 100, 1), score=round((tpr - fpr) * 100, 1))


def score(expected, findings, key=0) -> dict:
    cwes_by_file: dict[str, set[int]] = {}
    for f in findings:
        c = re.search(r"(\d+)", f.get("cwe") or "")
        if c:
            cwes_by_file.setdefault(f.get("file", "").replace("\\", "/"), set()).add(int(c.group(1)))
    cats: dict[str, dict] = {}
    for rel, (cat, real, cwe, inp) in expected.items():
        hit = bool(cwes_by_file.get(rel, set()) & EQUIV.get(cwe, {cwe}))
        name = cat if key == 0 else inp
        c = cats.setdefault(name, {"cwe": cwe if key == 0 else 0, "tp": 0, "fn": 0, "fp": 0, "tn": 0})
        c["tp" if real and hit else "fn" if real else "fp" if hit else "tn"] += 1
    for c in cats.values():
        _rates(c)
    overall = round(sum(c["score"] for c in cats.values()) / max(1, len(cats)), 1)
    return {"overall": overall, "cases": len(expected), "categories": dict(sorted(cats.items()))}


def _table(res: dict, title: str) -> None:
    print(f"{title:<20}{'CWE':>5}{'TP':>6}{'FN':>6}{'FP':>6}{'TN':>6}{'TPR%':>8}{'FPR%':>8}{'score%':>8}")
    for name, c in res["categories"].items():
        print(f"{name:<20}{c['cwe']:>5}{c['tp']:>6}{c['fn']:>6}{c['fp']:>6}{c['tn']:>6}{c['tpr']:>8}{c['fpr']:>8}{c['score']:>8}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("suite")
    ap.add_argument("--json")
    ap.add_argument("--min-score", type=float)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--by-input", action="store_true", help="also break the result down by the test cases' input kind")
    a = ap.parse_args()
    root = pathlib.Path(a.suite)
    expected = load_expected(root)
    findings = run_scan(root, a.jobs)
    res = score(expected, findings)
    _table(res, "category")
    if a.by_input:
        print()
        _table(score(expected, findings, key=1), "input")
    print(f"\nOverall SARD PHP Vulnerability Test Suite score (mean TPR-FPR, {res['cases']} cases): {res['overall']}%")
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps({"findings": findings}), encoding="utf-8")
        pathlib.Path(a.json).with_suffix(".score.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    return 1 if a.min_score is not None and res["overall"] < a.min_score else 0


if __name__ == "__main__":
    sys.exit(main())
