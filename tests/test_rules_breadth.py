"""Breadth rules: provider secrets, Dockerfile/Compose, Kubernetes, Terraform, GitHub Actions, JWT/CORS/TLS/crypto
misuse and the VQL queries that go with them.

Each fixture under tests/data/rules_breadth/ marks the line a rule must report with a comment
``expect-next: RULE[, RULE]`` on the line above it. A vulnerable fixture must produce exactly the marked findings
for the breadth rules; its safe twin must produce none.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from vulnscan.i18n import translated
from vulnscan.rules import BLOCK_RULES, RULES, check_blocks
from vulnscan.scanner import scan_file, scan_path
from vulnscan.vql import catalogue

DATA = pathlib.Path(__file__).resolve().parent / "data" / "rules_breadth"

_NEW = re.compile(r"^(SEC0(1[2-9]|[23]\d)|DKR0(0[6-9]|1\d)|K8S\d+|TF\d+|GHA\d+|JWT\d+|CORS\d+|TLS\d+|CRY0(0[7-9]|1\d))$")
NEW_VQL = {"vql/cors-credentials-any-origin", "vql/kdf-hardcoded-salt", "vql/cipher-static-iv", "vql/jwt-hardcoded-secret",
           "vql/ssh-auto-add-host-key", "vql/ssl-wrap-socket-unverified", "vql/tarfile-extractall-no-filter",
           "vql/js-cookie-insecure"}
NEW_RULES = [r for r in RULES if _NEW.match(r.id)]
ALL_NEW_IDS = {r.id for r in NEW_RULES} | {r.id for r in BLOCK_RULES}


def _expected(path: pathlib.Path) -> set:
    out = set()
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, ln in enumerate(lines):
        m = re.search(r"expect-next:\s*([\w/,\s-]+?)\s*$", ln)
        if m:
            for rid in re.split(r"[,\s]+", m.group(1).strip()):
                out.add((rid, i + 2))
    return out


def _breadth_findings(path: pathlib.Path) -> set:
    rel = path.relative_to(DATA).as_posix()
    text = path.read_text(encoding="utf-8")
    found = scan_file(path, rel, RULES, set()) + check_blocks(rel, text)
    return {(f.rule_id, f.line) for f in found if f.rule_id in ALL_NEW_IDS}


VULN = sorted(p for p in DATA.rglob("*") if p.is_file() and p.parent.name != "vql" and p.suffix != ".json"
              and (p.parent.name == "vuln" or p.stem.lower() == "vuln" or p.name == "vuln.yaml"))
SAFE = sorted(p for p in DATA.rglob("*") if p.is_file() and p.parent.name != "vql" and p.suffix != ".json"
              and (p.parent.name == "safe" or p.stem.lower().startswith("safe")))


@pytest.mark.parametrize("path", VULN, ids=lambda p: p.relative_to(DATA).as_posix())
def test_vulnerable_fixture_reports_exactly_the_marked_lines(path):
    expected = _expected(path)
    assert expected, f"{path} has no expect-next markers"
    assert _breadth_findings(path) == expected


@pytest.mark.parametrize("path", SAFE, ids=lambda p: p.relative_to(DATA).as_posix())
def test_safe_twin_reports_nothing(path):
    assert _breadth_findings(path) == set()


def test_policy_json():
    vuln = _breadth_findings(DATA / "tf" / "vuln" / "policy.json")
    assert vuln == {("TF003", 6), ("TF004", 7)}
    assert _breadth_findings(DATA / "tf" / "safe" / "policy.json") == set()


def test_every_breadth_rule_has_a_positive_fixture():
    marked = set()
    for p in VULN:
        marked |= {rid for rid, _ in _expected(p)}
    marked |= {"TF003", "TF004"}
    marked |= set(_SECRET_SAMPLES)
    missing = sorted(ALL_NEW_IDS - marked)
    assert not missing, f"breadth rules without a positive fixture: {missing}"


# ------------------------------------------------------------------ secrets: built at run time, never committed
def _rep(unit: str, n: int) -> str:
    return unit * n


_SECRET_SAMPLES = {
    "SEC012": ["gh" + "s_" + _rep("Ab1", 12), "gh" + "u_" + _rep("Xy9", 12)],
    "SEC013": ["glptt-" + _rep("0a1b", 10), "glrt-" + _rep("Ab1_", 6), "glpat-" + _rep("Ab1", 7) + ".01.abcd"],
    "SEC014": ["xapp-1-A0B1C2D3E4-1234567890123-" + _rep("ab12", 16)],
    "SEC015": ["sk_" + "live_" + _rep("Ab1", 33), "rk_" + "live_" + _rep("Ab12", 6), "whsec_" + _rep("Ab12", 8)],
    "SEC016": [_rep("0123456789abcdef", 2) + "-us21"],
    "SEC017": ["shp" + "ss_" + _rep("a1b2", 8)],
    "SEC018": ["ATATT3xFfGF0" + _rep("Ab1_", 45) + "=1A2B3C4D"],
    "SEC019": ["Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=Root;SharedAccessKey=" + _rep("Ab1+", 10)
               + "Ab1=",
               "https://acct.blob.core.windows.net/c/f?sv=2022-11-02&ss=b&sp=r&sig=" + _rep("Ab1%2B", 8)],
    "SEC020": ["abc8Q~" + _rep("Ab1_", 8) + "xy"],
    "SEC021": ["GOCSPX-" + _rep("Ab1_", 7)],
    "SEC022": ["HRKU-" + _rep("Ab1_", 12), "HEROKU_" + 'API_KEY = "01234567-89ab-cdef-0123-456789abcdef"'],
    "SEC023": ["dckr_" + "pat_" + _rep("Ab1-", 7)],
    "SEC024": ["hf_" + _rep("AbCd", 8) + "Ef"],
    "SEC025": ["sk-" + "proj-" + _rep("Ab1_", 12)],
    "SEC026": ["sk-" + "ant-api03-" + _rep("Ab1_", 22) + "AA"],
    "SEC027": ["dapi" + _rep("0a1b", 8)],
    "SEC028": ["hvs." + _rep("Ab1_", 24)],
    "SEC029": ["lin_api_" + _rep("Ab12", 10), "NRAK-" + _rep("A1B", 9), "pul-" + _rep("0a1b", 10)],
    "SEC030": ["-----BEGIN ENCRYPTED " + "PRIVATE KEY-----", "PuTTY-User-Key-File-3: ssh-ed25519"],
    "SEC031": ['aws_secret_access_key = "' + _rep("Ab1/", 10) + '"'],
}


def test_secret_formats(tmp_path):
    lines, expected = [], set()
    for rid, samples in _SECRET_SAMPLES.items():
        for s in samples:
            lines.append(f"value = {s}" if not s.startswith(("-----", "PuTTY")) else s)
            expected.add((rid, len(lines)))
    f = tmp_path / "tokens.txt"
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    found = {(x.rule_id, x.line) for x in scan_file(f, "tokens.txt", RULES, set()) if x.rule_id in ALL_NEW_IDS}
    assert found == expected


# Near misses that look like a real token format are built at run time, never stored as literals: a literal would
# trip GitHub push protection and other secret scanners on every clone of this repository.
_RUNTIME_NEAR_MISSES = [
    "hf_" + "abcdefghijklmnopqrstuvwxyz" + "abcdefgh",      # Hugging Face shape, but a low-entropy sequence
]


def test_secret_near_misses(tmp_path):
    f = tmp_path / "safe.txt"
    f.write_text((DATA / "secrets" / "safe.txt").read_text(encoding="utf-8") + "\n".join(_RUNTIME_NEAR_MISSES) + "\n",
                 encoding="utf-8")
    assert {x.rule_id for x in scan_file(f, "safe.txt", RULES, set()) if x.rule_id in ALL_NEW_IDS} == set()


# ------------------------------------------------------------------ VQL queries
@pytest.fixture(scope="module")
def vql_findings():
    findings, _ = scan_path(DATA / "vql")
    return {(f.file, f.rule_id, f.line) for f in findings if f.rule_id in NEW_VQL}


@pytest.mark.parametrize("name", ["vuln.py", "vuln.js"])
def test_vql_vulnerable(vql_findings, name):
    expected = {(name, rid, line) for rid, line in _expected(DATA / "vql" / name)}
    assert {x for x in vql_findings if x[0] == name} == expected


@pytest.mark.parametrize("name", ["safe.py", "safe.js"])
def test_vql_safe(vql_findings, name):
    assert {x for x in vql_findings if x[0] == name} == set()


def test_every_new_query_has_a_positive_fixture():
    marked = set()
    for name in ("vuln.py", "vuln.js"):
        marked |= {rid for rid, _ in _expected(DATA / "vql" / name)}
    assert NEW_VQL <= marked
    assert NEW_VQL <= {q["id"] for q in catalogue()}


# ------------------------------------------------------------------ metadata and English
def test_metadata_complete():
    for r in NEW_RULES + BLOCK_RULES:
        assert r.severity in ("critical", "high", "medium", "low", "info"), r.id
        assert r.title and r.title_ar and r.advice and r.cwe.startswith("CWE-"), r.id
        assert translated(r.advice), f"{r.id}: advice has no English"
    ids = [r.id for r in RULES] + [r.id for r in BLOCK_RULES]
    assert len(ids) == len(set(ids))


def test_queries_translated():
    for q in catalogue():
        if q["id"] in NEW_VQL:
            assert translated(q["advice"]), q["id"]


def test_iac_rules_scoped_to_their_files(tmp_path):
    """Terraform rules do not fire on YAML, Kubernetes rules do not fire on Python, Docker rules stay in Dockerfiles."""
    (tmp_path / "notes.py").write_text('hostNetwork = "x"\nacl = "public-read"\n', encoding="utf-8")
    (tmp_path / "values.yaml").write_text('acl = "public-read"\nRUN sudo make\n', encoding="utf-8")
    found = scan_path(tmp_path)[0]
    assert not [f for f in found if f.rule_id in ALL_NEW_IDS]
