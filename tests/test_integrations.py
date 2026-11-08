"""SARIF output, stable fingerprints, baselines, provider-token rules and entropy secret detection.

Fake tokens are assembled by concatenation so the test source never contains a literal that looks like a
real credential (keeps GitHub push protection and other scanners quiet)."""

import json
import pathlib

from vulnscan.baseline import apply_baseline, load_baseline, save_baseline
from vulnscan.cli import main
from vulnscan.model import Finding, assign_fingerprints
from vulnscan.report import render_sarif
from vulnscan.scanner import _entropy_findings, _shannon, scan_path


def _f(rule="X1", file="a.py", line=1, snippet="bad()", sev="high", **extra):
    return Finding(rule, sev, "T", "ع", file, line, snippet, "advice", "CWE-89", extra=dict(extra))


def _ids(findings):
    return {f.rule_id for f in findings}


# ---------------------------------------------------------------- fingerprints

def test_fingerprint_ignores_line_and_whitespace():
    a = _f(line=3, snippet='secret = "x"')
    b = _f(line=40, snippet='secret="x"')
    assert a.fingerprint() == b.fingerprint()


def test_fingerprint_differs_by_rule_file_snippet():
    base = _f()
    assert base.fingerprint() != _f(rule="X2").fingerprint()
    assert base.fingerprint() != _f(file="b.py").fingerprint()
    assert base.fingerprint() != _f(snippet="other()").fingerprint()


def test_duplicate_findings_get_distinct_fingerprints():
    fs = [_f(line=1), _f(line=9)]
    assign_fingerprints(fs)
    assert len({f.fingerprint() for f in fs}) == 2
    fs2 = [_f(line=9), _f(line=1)]          # order of discovery must not matter
    assign_fingerprints(fs2)
    assert {f.fingerprint() for f in fs} == {f.fingerprint() for f in fs2}


def test_to_dict_carries_fingerprint():
    assert _f().to_dict()["fingerprint"].endswith(":0")


# ---------------------------------------------------------------- SARIF

def test_sarif_structure():
    fs = [_f(rule="A1", sev="critical", path=[{"file": "a.py", "line": 1, "what": "source"},
                                           {"file": "a.py", "line": 5, "what": "sink"}]),
          _f(rule="B2", sev="low", file="dir/b.js", line=7)]
    doc = json.loads(render_sarif(fs, "/proj", 2, []))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "vulnscan"
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert set(rules) == {"A1", "B2"}
    assert rules["A1"]["properties"]["security-severity"] == "9.5"
    res = {r["ruleId"]: r for r in run["results"]}
    assert res["A1"]["level"] == "error" and res["B2"]["level"] == "note"
    loc = res["B2"]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "dir/b.js" and loc["region"]["startLine"] == 7
    assert res["A1"]["partialFingerprints"]["vulnscan/v1"]
    assert res["A1"].get("codeFlows")


def test_sarif_file_level_finding_has_valid_region(tmp_path):
    doc = json.loads(render_sarif([_f(line=0)], str(tmp_path), 1, []))
    region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"].get("region")
    assert region is None or region.get("startLine", 1) >= 1     # SARIF requires startLine >= 1


def test_cli_sarif(tmp_path, capsys):
    (tmp_path / "app.py").write_text("import pickle\npickle.loads(d)\n")
    out = tmp_path / "r.sarif"
    main([str(tmp_path), "--no-deps", "--no-external", "-f", "sarif", "-o", str(out)])
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["runs"][0]["results"]


# ---------------------------------------------------------------- baseline

def test_baseline_roundtrip(tmp_path):
    p = tmp_path / "b.json"
    fs = [_f(), _f(rule="X2")]
    assert save_baseline(fs, str(p)) == 2
    assert len(load_baseline(str(p))) == 2
    new, suppressed, size = apply_baseline([_f(line=99), _f(rule="X3")], str(p))
    assert (suppressed, size) == (1, 2)
    assert [f.rule_id for f in new] == ["X3"] and new[0].extra["new"] is True


def test_baseline_missing_file_marks_all_new(tmp_path):
    new, suppressed, size = apply_baseline([_f()], str(tmp_path / "nope.json"))
    assert (len(new), suppressed, size) == (1, 0, 0)


def test_baseline_corrupt_file(tmp_path):
    p = tmp_path / "b.json"
    p.write_text("{not json")
    assert load_baseline(str(p)) == set()


def test_baseline_second_duplicate_is_new(tmp_path):
    """Baseline has one copy of an issue; a second identical copy appearing later must be reported."""
    p = tmp_path / "b.json"
    save_baseline([_f(line=1)], str(p))
    new, suppressed, _ = apply_baseline([_f(line=1), _f(line=20)], str(p))
    assert suppressed == 1 and len(new) == 1


def test_cli_baseline_flow(tmp_path, capsys):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("import pickle\npickle.loads(d)\n")
    base = tmp_path / "base.json"
    assert main([str(src), "--no-deps", "--no-external", "--write-baseline", str(base)]) == 0
    out = tmp_path / "r.json"
    main([str(src), "--no-deps", "--no-external", "--baseline", str(base), "-f", "json", "-o", str(out)])
    assert json.loads(out.read_text(encoding="utf-8"))["findings"] == []
    # reformat the known line and add a new issue: only the new one is reported, and --fail-on sees it
    (src / "app.py").write_text("import pickle, subprocess\n\n\npickle.loads( d )\nsubprocess.call(c, shell=True)\n")
    rc = main([str(src), "--no-deps", "--no-external", "--baseline", str(base), "-f", "json", "-o", str(out),
               "--fail-on", "high"])
    found = json.loads(out.read_text(encoding="utf-8"))["findings"]
    assert found and all("pickle" not in f["snippet"] for f in found)
    assert rc == 1


# ---------------------------------------------------------------- provider token rules

def _scan(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    findings, _ = scan_path(tmp_path, [], set())
    return findings


def test_provider_tokens(tmp_path):
    sg = "SG." + "aB3dE5fG7hJ9kL1mN3pQ5r" + "." + "sT7uV9wX1yZ3aB5cD7eF9gH1jK3lM5nP7qR9sT1uV3w"
    gh_npm = "npm_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    text = f'SENDGRID = "{sg}"\nNPM = "{gh_npm}"\n'
    assert "SEC007" in _ids(_scan(tmp_path, "cfg.py", text))


def test_webhook_rule(tmp_path):
    url = "https://hooks." + "slack.com/services/" + "T01ABCDEF/B01ABCDEF/" + "aBcDeFgHiJkLmNoPqRsTuVwX"
    assert "SEC008" in _ids(_scan(tmp_path, "notify.py", f'HOOK = "{url}"\n'))


def test_gcp_service_account(tmp_path):
    doc = '{\n  "type": "service' + '_account",\n  "project_id": "p"\n}\n'
    assert "SEC009" in _ids(_scan(tmp_path, "key.json", doc))


def test_azure_storage(tmp_path):
    cs = "DefaultEndpoints" + "Protocol=https;AccountName=acct;AccountKey=" + "Zm9vYmFy" * 8 + "=="
    assert "SEC010" in _ids(_scan(tmp_path, "settings.py", f'CONN = "{cs}"\n'))


# ---------------------------------------------------------------- entropy

def test_shannon():
    assert _shannon("") == 0 and _shannon("aaaa") == 0
    assert abs(_shannon("ab") - 1.0) < 1e-9


def test_entropy_flags_secret_assignment():
    tok = "q8Zr" + "T3vLx9" + "Pw2Nk7Ys" + "4Hd6Bm1C"
    fs = _entropy_findings("a.py", 1, f'api_key = "{tok}"')
    assert fs and fs[0].rule_id == "SEC011"


def test_entropy_flags_standalone_long_token():
    tok = "Xk9" + "pQ2vLr7TzN4wYb8HsJ3mCd6Fg1Ke5RaU0" + "oVi2Wq8Ex4Zt"
    assert _entropy_findings("a.py", 1, f'X = "{tok}"')


def test_entropy_skips_benign():
    benign = [
        'commit = "3f786850e387550fdab836ed7e6dc881de23001b"',                 # hex sha, no secret name
        'api_key = "your_api_key_here_please_replace"',                         # placeholder
        'token = os.environ["GITHUB_TOKEN_FOR_DEPLOYMENTS"]',                   # env lookup, no digits
        'import x from "./components/SomethingVeryLongComponentName"',
        '<script integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC">',
        'img = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAD"',
    ]
    for line in benign:
        assert not _entropy_findings("a.py", 1, line), line


def test_entropy_not_duplicated_when_regex_rule_hits(tmp_path):
    fs = _scan(tmp_path, "c.py", "AWS = 'AKIA" + "IOSFODNN7" + "QWERTZ'\n")
    assert "SEC011" not in _ids(fs)


def test_entropy_respects_ignore_rule(tmp_path):
    tok = "Xk9" + "pQ2vLr7TzN4wYb8HsJ3mCd6Fg1Ke5RaU0" + "oVi2Wq8Ex4Zt"
    (tmp_path / "a.py").write_text(f'BLOB = "{tok}"\n')
    assert "SEC011" in _ids(scan_path(tmp_path, [], set())[0])
    assert "SEC011" not in _ids(scan_path(tmp_path, [], {"SEC011"})[0])


def test_list_rules_includes_new_rules(capsys):
    main(["--list-rules"])
    out = capsys.readouterr().out
    for rid in ("SEC007", "SEC008", "SEC009", "SEC010", "SEC011"):
        assert rid in out
