# Kashif, Bandit and Semgrep on the OWASP Benchmark for Python

Measured 2026-11-18 on the same machine, with the same scorer and the same rules for matching a finding to a test case.
Every number below can be reproduced with the commands at the end.

| Tool | Version | Rules | Overall score |
|---|---|---|---:|
| **Kashif** | 1.2.0 | built-in (dataflow + patterns) | **90.2%** |
| Bandit | 1.9.4 | default set | 16.5% |
| Semgrep (Community Edition) | 1.186.0 | `semgrep-rules/python` at commit `a5ad171` (2026-11-10) | 15.7% |

Benchmark: OWASP BenchmarkPython at commit `f129148` (1,230 test cases, 14 categories). Score = mean over categories
of TPR − FPR (Youden's J), the method OWASP uses; 0 is what random guessing gets, 100% is perfect.

## Per category (score %)

| Category | Kashif | Bandit | Semgrep |
|---|---:|---:|---:|
| cmdi | 85.7 | 0.0 | 0.0 |
| codeinj | 100.0 | 0.0 | 0.0 |
| deserialization | 97.2 | 52.8 | 66.7 |
| hash | 100.0 | 100.0 | 76.1 |
| ldapi | 100.0 | 0.0 | 0.0 |
| pathtraver | 57.4 | 0.0 | 1.1 |
| redirect | 100.0 | 0.0 | 2.9 |
| securecookie | 100.0 | 0.0 | 0.0 |
| sqli | 100.0 | 0.0 | 100.0 |
| trustbound | 84.2 | 0.0 | 0.0 |
| weakrand | 100.0 | 77.8 | 0.0 |
| xpathi | 91.9 | 0.0 | 0.0 |
| xss | 81.0 | 0.0 | −27.6 |
| xxe | 65.0 | 0.0 | 0.0 |

A score of 0 hides two different things: a tool that never reports the category (TPR 0, FPR 0), and a tool that
reports every test case in it, real or not (TPR 100, FPR 100). Bandit, for example, flags every command-injection and
SQL test case; it cannot tell the safe ones apart because it does not follow the data.

## How findings are matched (and why it is fair to the other tools)

A test case counts as flagged when a tool reports, in that test's file, a finding whose CWE is in the category's
equivalence class (`bench/score_owasp.py`, `EQUIV`). Bandit and Semgrep use their own CWE labels, so some of their
findings land in a test file with a CWE outside the class. We checked every such case:

- Bandit labels XML imports and `eval` with CWE-20 / CWE-78. Counting those as XXE, XPath and code-injection hits
  would flag every test case in those categories, safe or vulnerable alike, so the score stays 0.
- Semgrep's unmatched labels (mostly CWE-614 on cookie settings and CWE-611 on XML parsing in XPath tests) are
  outside the category being tested.

Counting them would not raise either tool's overall score.

## Limits of this comparison

- The Benchmark is synthetic. It measures how a tool reasons about data flow, not how many real bugs it will find in
  your code.
- Semgrep was run with its free community rules only, offline. Semgrep's commercial rules and engine (cross-file taint)
  were not measured.
- The scorer is Kashif's own (`bench/score_owasp.py`), not OWASP's scorecard tool. The same scorer is applied to all
  three tools.
- Kashif's rules were tuned while measuring against this Benchmark; the other tools' were not. Kashif's changes are
  general dataflow rules with a vulnerable twin in its tests for each, but that history should be kept in mind.

## Reproduce

```bash
git clone https://github.com/OWASP-Benchmark/BenchmarkPython bp
git clone https://github.com/semgrep/semgrep-rules
pip install kashif==1.2.0 bandit==1.9.4 semgrep==1.186.0
python bench/score_owasp.py bp --json kashif.json
bandit -q -r bp/testcode -f json -o bandit.json
semgrep --config semgrep-rules/python --metrics=off --json -o semgrep.json bp/testcode bp/helpers
python bench/score_tools.py bp bandit.json semgrep.json .
```
