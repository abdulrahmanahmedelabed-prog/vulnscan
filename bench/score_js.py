"""Score vulnscan on JavaScript/TypeScript against the labelled test cases of GitHub's CodeQL security queries.

Usage:
    python bench/score_js.py <codeql checkout> [--json out.json] [--min-score S]

Benchmark: the JavaScript security query tests of https://github.com/github/codeql (MIT licence), directory
``javascript/ql/test/query-tests/Security``, measured at commit 12a0e5138434f47dbf2430178fa0059fb2e611d5
(2026-11-19). Fetch only that directory:

    git clone --filter=blob:none --sparse https://github.com/github/codeql
    git -C codeql sparse-checkout set javascript/ql/test/query-tests/Security
    git -C codeql checkout 12a0e5138434f47dbf2430178fa0059fb2e611d5

The CodeQL team labels these small Express/Koa/Node/browser programs line by line, with inline-expectation
comments: ``// $ Alert`` (or ``Alert[query-id]``) marks a line where the vulnerability is real, ``MISSING: Alert``
a real vulnerability CodeQL itself misses (still a positive here), ``SPURIOUS: Alert`` a line CodeQL wrongly
reports (a negative here). A comment saying the code is ``OK`` / ``GOOD`` / ``safe`` labels a negative; when the
comment stands on its own line it covers the statements below it up to the next blank or comment line.

Tests that switch on a non-default CodeQL threat model (``*.ext.json`` enabling local / environment / response
sources) are left out: both tools' default threat model is remote input.

Test cases are (file, line, query). A query is in scope when its CWE is one vulnerability class vulnscan reports for
JavaScript (``CATEGORIES`` below); out-of-scope queries (ReDoS, prototype pollution, regex quality, missing
middleware, library-input threat models, ...) are not counted. A case is *flagged* when vulnscan reports, in that
file and on that line, a finding whose CWE belongs to the category. CodeQL writes the expectation on the line where
the flagged expression ends, so a finding on an earlier line of the same multi-line expression counts too, and a flow
through a helper function, which vulnscan reports at the call, counts at its sink (the last step of its path).
Scoring is the OWASP Benchmark method: per category TPR = TP/(TP+FN), FPR = FP/(FP+TN), score = TPR - FPR; overall =
unweighted mean over categories. TPR and FPR pooled over all cases are printed too: several categories have only a
few safe cases, so one false alarm moves their FPR (and the mean) a lot.

Findings of a category's CWE on lines of that category's files that carry no label at all are not part of TPR/FPR
(CodeQL's tests assert no alert there, but most such lines are not sinks); they are counted as ``unlabelled`` so
that noise is visible too.

The scanner is never told about this suite: the whole Security directory is scanned once, as a project, with
the default profile, and findings are attributed to test cases afterwards.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

SUBDIR = "javascript/ql/test/query-tests/Security"
EXTS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".html", ".htm"}

# CodeQL query id -> (category, reported CWEs that count as a detection). Near CWEs count, as in score_owasp.py.
CATEGORIES = {
    "js/path-injection": ("pathtraver", {22, 23, 36, 73}),
    "js/zipslip": ("zipslip", {22, 23, 36, 73}),
    "js/command-line-injection": ("cmdi", {78, 77, 88}),
    "js/reflected-xss": ("xss-reflected", {79, 80}),
    "js/stored-xss": ("xss-stored", {79, 80}),
    "js/xss": ("xss-dom", {79, 80}),
    "js/xss-through-exception": ("xss-exception", {79, 80}),
    "js/sql-injection": ("sqli-nosqli", {89, 564, 943, 90}),
    "js/code-injection": ("codeinj", {94, 95, 96, 1336}),     # CWE-1336 (template injection) is a child of CWE-94
    "js/unsafe-deserialization": ("deserialization", {502}),
    "js/server-side-unvalidated-url-redirection": ("redirect-server", {601}),
    "js/client-side-unvalidated-url-redirection": ("redirect-client", {601}),
    "js/xxe": ("xxe", {611, 776}),
    "js/xpath-injection": ("xpathi", {643}),
    "js/request-forgery": ("ssrf", {918}),
    "js/log-injection": ("loginj", {117}),
    "js/clear-text-cookie": ("securecookie", {614, 1004}),
    "js/client-exposed-cookie": ("httponlycookie", {1004, 614}),
    "js/insecure-randomness": ("weakrand", {330, 338}),
    "js/weak-cryptographic-algorithm": ("crypto", {327, 326, 328}),
    "js/insufficient-password-hash": ("hash", {916, 327, 328}),
}

ALERT = re.compile(r"(MISSING:\s*|SPURIOUS:\s*)?\bAlert(?:\[([^\]]+)\])?")
COMMENT = re.compile(r"(//.*$|/\*.*?\*/|<!--.*?-->)")
SAFE = re.compile(r"\b(OK|GOOD|[Ss]afe|SAFE)\b")
UNSAFE = re.compile(r"\bNOT[ -]OK\b|\bBAD\b")


def _queries(root: pathlib.Path) -> dict[pathlib.Path, list[str]]:
    """Directory -> query ids of the .qlref files in it (the query source names the id)."""
    out: dict[pathlib.Path, list[str]] = {}
    for ref in sorted(root.rglob("*.qlref")):
        if any("threatModelConfiguration" in x.read_text(encoding="utf-8") for x in ref.parent.glob("*.ext.json")):
            continue            # the test turns on a non-default CodeQL threat model (local, environment, response)
        m = re.search(r"query:\s*(\S+)", ref.read_text(encoding="utf-8"))
        if not m:
            continue
        name = pathlib.Path(m.group(1)).stem
        qid = QUERY_IDS.get(name)
        if qid:
            out.setdefault(ref.parent, []).append(qid)
    return out


# .ql file stem -> query id (from each query's @id; recorded here so only the test directory need be checked out).
QUERY_IDS = {
    "TaintedPath": "js/path-injection", "ZipSlip": "js/zipslip", "CommandInjection": "js/command-line-injection",
    "ReflectedXss": "js/reflected-xss", "StoredXss": "js/stored-xss", "Xss": "js/xss",
    "ExceptionXss": "js/xss-through-exception", "SqlInjection": "js/sql-injection", "CodeInjection": "js/code-injection",
    "UnsafeDeserialization": "js/unsafe-deserialization",
    "ServerSideUrlRedirect": "js/server-side-unvalidated-url-redirection",
    "ClientSideUrlRedirect": "js/client-side-unvalidated-url-redirection", "Xxe": "js/xxe",
    "XpathInjection": "js/xpath-injection", "RequestForgery": "js/request-forgery", "LogInjection": "js/log-injection",
    "ClearTextCookie": "js/clear-text-cookie", "ClientExposedCookie": "js/client-exposed-cookie",
    "InsecureRandomness": "js/insecure-randomness", "BrokenCryptoAlgorithm": "js/weak-cryptographic-algorithm",
    "InsufficientPasswordHash": "js/insufficient-password-hash",
}


_STRINGS = re.compile(r"(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|//.*$)")


def _first_line(lines: list[str], no: int) -> int:
    """CodeQL puts the expectation on the line where the flagged expression ENDS (`})) // $ Alert` closes a call
    that began lines above); scanners report where it starts. Walk up while brackets are unbalanced."""
    depth = 0
    k = no
    while k >= 1:
        code = _STRINGS.sub("", lines[k - 1])
        depth += sum(code.count(c) for c in "([{") - sum(code.count(c) for c in ")]}")
        if depth >= 0 or no - k >= 40:
            return k
        k -= 1
    return no


def _labels(path: pathlib.Path, qids: list[str]) -> dict[tuple[int, str], tuple[bool, int]]:
    """(line, query id) -> (True for a real vulnerability / False for a labelled safe line, first line)."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    out: dict[tuple[int, str], tuple[bool, int]] = {}
    pending_safe = False
    for no, text in enumerate(lines, 1):
        stripped = text.strip()
        comments = " ".join(COMMENT.findall(text))
        code_only = not stripped or stripped.startswith(("//", "/*", "*", "<!--"))
        pos: set[str] = set()
        neg: set[str] = set()
        if "$" in comments:
            for kind, tag in ALERT.findall(comments.split("$", 1)[1]):
                ids = [tag] if tag else qids
                for q in ids:
                    if q in qids:
                        (neg if kind.startswith("SPURIOUS") else pos).add(q)
        safe_here = bool(SAFE.search(comments)) and not UNSAFE.search(comments)
        if code_only:
            # A comment-only line saying OK opens a labelled block, one saying NOT OK / BAD closes it, and so does a
            # blank line.
            if not stripped or UNSAFE.search(comments):
                pending_safe = False
            elif safe_here:
                pending_safe = True
            continue
        for q in qids:
            if q in pos:
                out[(no, q)] = (True, _first_line(lines, no))
            elif q in neg or safe_here or pending_safe:
                out[(no, q)] = (False, _first_line(lines, no))
    return out


def load_expected(root: pathlib.Path) -> dict[tuple[str, int, str], tuple[bool, int]]:
    base = root / SUBDIR if (root / SUBDIR).is_dir() else root
    dirs = _queries(base)
    expected: dict[tuple[str, int, str], tuple[bool, int]] = {}
    for dirpath, _dirs, files in os.walk(base):
        d = pathlib.Path(dirpath)
        # The queries of the nearest enclosing directory that has .qlref files.
        owner = next((p for p in [d, *d.parents] if p in dirs), None)
        if owner is None:
            continue
        for name in files:
            f = d / name
            if f.suffix in EXTS:
                rel = f.relative_to(base).as_posix()
                for (line, q), real in _labels(f, dirs[owner]).items():
                    expected[(rel, line, q)] = real
    return expected


def run_scan(root: pathlib.Path, out: pathlib.Path) -> tuple[pathlib.Path, list[dict]]:
    base = root / SUBDIR if (root / SUBDIR).is_dir() else root
    subprocess.run([sys.executable, "-m", "vulnscan", str(base), "--no-deps", "--no-external", "-f", "json", "-o", str(out)],
                   check=False, stdout=subprocess.DEVNULL)
    return base, json.loads(out.read_text(encoding="utf-8"))["findings"]


def _reported(base: pathlib.Path, findings) -> dict[tuple[str, int], set[int]]:
    """(file relative to the suite, line) -> CWEs reported there."""
    out: dict[tuple[str, int], set[int]] = {}
    for f in findings:
        c = re.search(r"(\d+)", f.get("cwe") or "")
        if not c or not f.get("line"):
            continue
        p = pathlib.Path(f["file"])
        if p.is_absolute():
            try:
                p = p.resolve().relative_to(base.resolve())
            except ValueError:
                continue
        cwe = int(c.group(1))
        out.setdefault((p.as_posix(), int(f["line"])), set()).add(cwe)
        # A flow through a helper is reported at the call; its last path step is the sink itself.
        path = (f.get("extra") or {}).get("path") or []
        if path and path[-1].get("file") and path[-1].get("line"):
            sp = pathlib.Path(path[-1]["file"])
            if sp.is_absolute():
                try:
                    sp = sp.resolve().relative_to(base.resolve())
                except ValueError:
                    continue
            out.setdefault((sp.as_posix(), int(path[-1]["line"])), set()).add(cwe)
    return out


def _flagged(expected, reported, rel: str, line: int, q: str) -> bool:
    """A finding of the category on the labelled line, or on an earlier line of the same expression that carries no
    label of its own."""
    first = expected[(rel, line, q)][1]
    cwes = CATEGORIES[q][1]
    return any(reported.get((rel, j), set()) & cwes and (j == line or (rel, j, q) not in expected)
               for j in range(first, line + 1))


def _covered(expected) -> set[tuple[str, int, str]]:
    return {(rel, j, q) for (rel, line, q), (_r, first) in expected.items() for j in range(first, line + 1)}


def score(expected, base: pathlib.Path, findings) -> dict:
    reported = _reported(base, findings)
    covered = _covered(expected)
    cats: dict[str, dict] = {}
    for qid, (name, _cwes) in CATEGORIES.items():
        cats[name] = {"query": qid, "tp": 0, "fn": 0, "fp": 0, "tn": 0, "unlabelled": 0}
    files_of: dict[str, set[str]] = {}
    for (rel, line, q), (real, _first) in expected.items():
        name, cwes = CATEGORIES[q]
        files_of.setdefault(q, set()).add(rel)
        hit = _flagged(expected, reported, rel, line, q)
        c = cats[name]
        c["tp" if real and hit else "fn" if real else "fp" if hit else "tn"] += 1
    for q, files in files_of.items():
        name, cwes = CATEGORIES[q]
        for (rel, line), got in reported.items():
            if rel in files and got & cwes and (rel, line, q) not in covered:
                cats[name]["unlabelled"] += 1
    cats = {k: v for k, v in cats.items() if v["tp"] + v["fn"] + v["fp"] + v["tn"]}
    for c in cats.values():
        tpr = c["tp"] / max(1, c["tp"] + c["fn"])
        fpr = c["fp"] / max(1, c["fp"] + c["tn"])
        c.update(tpr=round(tpr * 100, 1), fpr=round(fpr * 100, 1), score=round((tpr - fpr) * 100, 1))
    overall = round(sum(c["score"] for c in cats.values()) / max(1, len(cats)), 1)
    tot = {k: sum(c[k] for c in cats.values()) for k in ("tp", "fn", "fp", "tn", "unlabelled")}
    # pooled over all cases: categories with a handful of safe cases swing the per-category mean (one false alarm
    # among one safe case is an FPR of 100%), so both views are reported
    tot["tpr"] = round(100 * tot["tp"] / max(1, tot["tp"] + tot["fn"]), 1)
    tot["fpr"] = round(100 * tot["fp"] / max(1, tot["fp"] + tot["tn"]), 1)
    return {"overall": overall, "totals": tot, "categories": dict(sorted(cats.items()))}


def cases(expected, base, findings) -> list[dict]:
    """Every labelled case with its outcome (for inspecting misses and false alarms)."""
    reported = _reported(base, findings)
    out = []
    for (rel, line, q), (real, _first) in sorted(expected.items()):
        hit = _flagged(expected, reported, rel, line, q)
        out.append({"file": rel, "line": line, "category": CATEGORIES[q][0], "real": real, "flagged": hit,
                    "outcome": "tp" if real and hit else "fn" if real else "fp" if hit else "tn"})
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("benchmark", help="codeql checkout (or its javascript/ql/test/query-tests/Security directory)")
    ap.add_argument("--json")
    ap.add_argument("--min-score", type=float)
    a = ap.parse_args()
    root = pathlib.Path(a.benchmark)
    out = pathlib.Path(a.json or "js-findings.json")
    expected = load_expected(root)
    base, findings = run_scan(root, out)
    res = score(expected, base, findings)
    print(f"{'category':<18}{'TP':>6}{'FN':>6}{'FP':>6}{'TN':>6}{'TPR%':>8}{'FPR%':>8}{'score%':>8}{'unlab':>7}")
    for name, c in res["categories"].items():
        print(f"{name:<18}{c['tp']:>6}{c['fn']:>6}{c['fp']:>6}{c['tn']:>6}{c['tpr']:>8}{c['fpr']:>8}{c['score']:>8}{c['unlabelled']:>7}")
    t = res["totals"]
    print(f"\n{t['tp'] + t['fn']} vulnerable and {t['fp'] + t['tn']} safe labelled cases in {len(res['categories'])} categories; "
          f"{t['unlabelled']} findings on unlabelled lines")
    print(f"All cases pooled: TPR {t['tpr']}%, FPR {t['fpr']}%")
    print(f"Overall score (mean TPR-FPR over categories): {res['overall']}%")
    if a.json:
        res["cases"] = cases(expected, base, findings)
        pathlib.Path(a.json).with_suffix(".score.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    return 1 if a.min_score is not None and res["overall"] < a.min_score else 0


if __name__ == "__main__":
    sys.exit(main())
