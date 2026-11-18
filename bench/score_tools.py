"""Score Bandit and Semgrep JSON on OWASP BenchmarkPython with Kashif's own scorer (same CWE equivalence, same J).

Usage (see docs/comparison.md):
    python bench/score_tools.py <BenchmarkPython> bandit.json semgrep.json <out-dir>
"""
import json, re, sys, pathlib
sys.path.insert(0, "bench")
import score_owasp as so
root = pathlib.Path(sys.argv[1]); exp = so.load_expected(root)
def cwes(v):
    out = []
    for x in (v if isinstance(v, list) else [v]):
        m = re.search(r"(\d+)", str(x or ""))
        if m: out.append("CWE-" + m.group(1))
    return out
b = json.load(open(sys.argv[2]))
bandit = [{"file": r["filename"], "cwe": f"CWE-{r['issue_cwe']['id']}"} for r in b["results"] if r.get("issue_cwe")]
g = json.load(open(sys.argv[3]))
semgrep = [{"file": r["path"], "cwe": c} for r in g["results"] for c in cwes(r["extra"].get("metadata", {}).get("cwe"))]
for name, fs in (("bandit", bandit), ("semgrep", semgrep)):
    res = so.score(exp, fs)
    json.dump(res, open(f"{sys.argv[4]}/{name}.score.json", "w"), indent=1)
    print(name, "overall", res.get("overall"))
    for c, v in sorted(res["categories"].items()):
        print(f"  {c:16s} TPR {v['tpr']:5.1f} FPR {v['fpr']:5.1f} score {v['score']:5.1f}")
