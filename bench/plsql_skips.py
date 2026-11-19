"""How much PL/SQL the frontend skips, over a corpus of real code (Kashif 1.4.0).

Walks a folder the way the scanner routes Oracle code (plain PL/SQL files, APEX application exports, APEX readable
YAML, Liquibase/SQLcl XML, ORDS JSON), runs only the PL/SQL frontend (no data-flow engine, so it is fast), and prints
the statements parsed, the statements skipped, and a histogram of skip reasons grouped by statement kind and
normalized message, each with an example file:line. The corpus itself is never executed, only read.

Usage:
    python bench/plsql_skips.py <corpus-dir> [--top N] [--json out.json] [--per-repo]

The 1.4.0 corpus (`git clone --depth 1` of each into <corpus-dir>; 2482 files, 1.63M lines): OraOpenSource/Logger@600f0c4,
OraOpenSource/OOS-Utils@b621729, utPLSQL/utPLSQL@77fc2b4, mortenbra/alexandria-plsql-utils@ada4875, pljson/pljson@09a54e4,
jkvetina/CORE23@4f1bfcd, oracle-samples/db-sample-schemas@6660bad, oracle-samples/oracle-db-examples@f02e504 and
oracle/apex@90e767b (branch 24.2: sample, starter and utility apps, plug-ins). 1.3.1: 771 of 98,441 statements
skipped (0.78%); 1.4.0: 76 of 99,124 (0.08%), the rest substitution variables and scripts that do not compile.
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from vulnscan import apex_export  # noqa: E402
from vulnscan import plsql_frontend as pf  # noqa: E402

MAX_BYTES = 64 * 1024 * 1024            # scanner.MAX_PLSQL_BYTES
_KIND = re.compile(r"^\{([^}]*)\}\s*")
_LABEL = re.compile(r"^\[[^\]]*\]\s*")


def file_diag(rel: str, text: str) -> dict:
    """The frontend's diagnostics for one file, routed like taint._analyze_plsql."""
    d = {"statements": 0, "skipped": 0, "lines": []}

    def add(sub, delta=0):
        d["statements"] += sub["statements"]
        d["skipped"] += sub["skipped"]
        d["lines"].extend((ln + delta, msg) for ln, msg in sub["lines"])

    def blocks(bs):
        for b in bs:
            if b.kind.startswith("plsql"):
                add(pf.parse_plsql(apex_export.wrapped_plsql(b))[1], b.line - 1)
            elif b.kind == "sql":
                add(pf.sql_call_units(b.code, b.unit)[1], b.line - 1)

    def plain(src, delta=0):
        add(pf.parse_plsql(src)[1], delta)
        ords = apex_export.extract_ords(src, rel)
        for b in ords:
            b.line += delta
        blocks(ords)

    low = rel.lower()
    if low.endswith((".yaml", ".yml")):
        blocks(apex_export.extract_yaml(text, rel)[0])
    elif low.endswith(".xml"):
        for start, script in apex_export.xml_scripts(text):
            plain(script, start - 1)
    elif low.endswith(".json"):
        blocks(apex_export.extract_json_ords(text, rel))
    elif apex_export.is_apex_export(text):
        blocks(apex_export.extract(text, rel)[0] + apex_export.extract_ords(text, rel))
    else:
        plain(text)
    return d


def oracle_files(root: pathlib.Path):
    for p in sorted(root.rglob("*")):
        if ".git" in p.parts or not p.is_file():
            continue
        suf = p.suffix.lower()
        if suf not in pf.PLSQL_EXTS and suf not in (".yaml", ".yml", ".xml", ".json"):
            continue
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
            text = p.read_bytes().decode("utf-8", "replace")
        except OSError:
            continue
        rel = p.relative_to(root).as_posix()
        if suf in pf.PLSQL_EXTS or apex_export.is_oracle_container(text, rel):
            yield rel, text


def normalize(msg: str) -> tuple[str, str]:
    """'[label] {kind} expected ';', found 'X1'' -> ('kind', "expected ';', found 'x#'")."""
    msg = _LABEL.sub("", msg)
    m = _KIND.match(msg)
    kind = m.group(1) if m else ""
    msg = _KIND.sub("", msg)
    msg = re.sub(r"(expected IS/AS in) \S+", r"\1 <name>", msg)
    msg = re.sub(r"\d+", "#", msg.lower())
    return kind, msg


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("corpus")
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--json", help="write totals and the histogram here")
    ap.add_argument("--per-repo", action="store_true", help="totals per top-level folder")
    a = ap.parse_args(argv)
    root = pathlib.Path(a.corpus)
    tot = collections.Counter()
    repos: dict = collections.defaultdict(collections.Counter)
    hist: collections.Counter = collections.Counter()
    example: dict = {}
    for rel, text in oracle_files(root):
        d = file_diag(rel, text)
        repo = rel.split("/", 1)[0]
        for c in (tot, repos[repo]):
            c["files"] += 1
            c["lines"] += text.count("\n") + 1
            c["statements"] += d["statements"]
            c["skipped"] += d["skipped"]
        for ln, msg in d["lines"]:
            key = normalize(msg)
            hist[key] += 1
            example.setdefault(key, f"{rel}:{ln}")

    def pct(c):
        n = c["statements"] + c["skipped"]
        return 100.0 * c["skipped"] / n if n else 0.0
    print(f"files {tot['files']}  lines {tot['lines']}  statements {tot['statements']}  skipped {tot['skipped']}  "
          f"({pct(tot):.3f}% of {tot['statements'] + tot['skipped']})")
    if a.per_repo:
        for r, c in sorted(repos.items()):
            print(f"  {r:45s} files {c['files']:5d} lines {c['lines']:8d} stmts {c['statements']:7d} "
                  f"skipped {c['skipped']:5d} ({pct(c):.3f}%)")
    print(f"\ntop skip reasons ({len(hist)} distinct):")
    for (kind, msg), n in hist.most_common(a.top):
        print(f"{n:6d}  {kind or '-':22s} {msg[:70]:70s} {example[(kind, msg)]}")
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps({
            "totals": dict(tot), "percent": pct(tot), "repos": {r: dict(c) for r, c in repos.items()},
            "reasons": [{"kind": k, "message": m, "count": n, "example": example[(k, m)]} for (k, m), n in hist.most_common()],
        }, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
