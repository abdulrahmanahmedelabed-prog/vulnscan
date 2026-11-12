"""1.0 integration of the add-on modules into the `kashif` command line (vulnscan/cli.py).

Every sub-command is reachable as `kashif <sub>` and `python3 -m vulnscan <sub>`; the scan's `-f` accepts every
exporter format (gitlab-sast and codeclimate are validated structurally here); the scan flags --export, --triage,
--policy, --compliance, --audit-report and --risk-score work; and every command, flag and format the README and
docs/ show in a code block exists.
"""

from __future__ import annotations

import os
import json
import pathlib
import re
import shlex
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET

import pytest

from vulnscan import cli
from vulnscan.cli import DELEGATES, SCAN_FORMATS, SUBCOMMANDS, build_parser, main
from vulnscan.exporters import FORMATS as EXPORT_FORMATS
from vulnscan.i18n import has_arabic

ROOT = pathlib.Path(__file__).resolve().parent.parent

VULN_PY = '''import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    os.system(cmd)
    return "ok"
'''


@pytest.fixture(autouse=True)
def _neutral_language(monkeypatch):
    """Tests do not depend on the machine's locale: no --lang is forwarded to the sub-commands."""
    for var in ("VULNSCAN_LANG", "KASHIF_LANG", "LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(cli, "_is_arabic_locale", lambda environ=None: False)


@pytest.fixture
def project(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text(VULN_PY, encoding="utf-8")
    return proj


def scan(project, *args):
    return main([str(project), "--no-deps", "--no-external", "--lang", "en", *args])


def critical_fp(project, tmp_path) -> str:
    out = tmp_path / "r.json"
    scan(project, "-f", "json", "-o", str(out))
    doc = json.loads(out.read_text(encoding="utf-8"))
    return next(f["fingerprint"] for f in doc["findings"] if f["severity"] == "critical")


# ------------------------------------------------------------------------------------------- sub-commands

ALL_SUBS = sorted(set(SUBCOMMANDS) | set(DELEGATES))


@pytest.mark.parametrize("sub", ALL_SUBS)
def test_every_subcommand_has_help_with_kashif_usage(sub, capsys):
    try:
        code = main([sub, "--help"])
    except SystemExit as e:                 # ui / lsp / update parse with argparse directly
        code = e.code
    out = capsys.readouterr().out
    assert code in (0, None)
    expected = "history" if sub == "secrets-history" else sub
    assert out.startswith(f"usage: kashif {expected}"), out[:200]
    assert "vulnscan" not in out.splitlines()[0]


@pytest.mark.parametrize("sub", ["mcp", "export", "compliance", "history", "secrets-history", "triage", "policy",
                                 "surface", "rules"])
def test_subcommands_run_as_python_module(sub):
    proc = subprocess.run([sys.executable, "-m", "vulnscan", sub, "--help"], cwd=ROOT, capture_output=True,
                          text=True, encoding="utf-8", timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("usage: kashif "), proc.stdout[:200]


def test_main_help_lists_every_subcommand_in_both_languages():
    for lang in ("en", "ar", "both"):
        text = build_parser(lang).format_help()
        for name in SUBCOMMANDS:
            assert re.search(rf"^  {re.escape(name)}\s", text, re.M), (lang, name)
    en = build_parser("en").format_help()
    assert not has_arabic(en) and "Sub-commands:" in en and "kashif <sub-command> --help" in en
    both = build_parser("both").format_help()
    assert "الأوامر الفرعية" in both and "Sub-commands:" in both


def test_mcp_usage_says_kashif():
    from vulnscan.mcp import build_parser as mcp_parser
    assert mcp_parser().format_usage().startswith("usage: kashif mcp")


def test_forward_lang():
    f = cli._forward_lang
    assert f(["list"]) == ["list"]                                         # neutral locale: nothing added
    assert f(["list", "--lang", "both"]) == ["list"]
    assert f(["list", "--lang=auto"]) == ["list"]
    assert f(["list", "--lang", "ar"]) == ["list", "--lang", "ar"]
    assert f(["mcp", "--scan-worker"]) == ["mcp", "--scan-worker"]


def test_forward_lang_follows_vulnscan_lang(monkeypatch):
    monkeypatch.setenv("VULNSCAN_LANG", "ar")
    assert cli._forward_lang(["list"]) == ["list", "--lang", "ar"]
    assert cli._forward_lang(["merge", "a", "--", "b"]) == ["merge", "a", "--lang", "ar", "--", "b"]
    assert cli._forward_lang(["list", "--lang", "en"]) == ["list", "--lang", "en"]


def test_secrets_history_alias_scans_a_repository(tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
           "-c", "commit.gpgsign=false"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "a.txt").write_text("hello\n")
    subprocess.run(git + ["add", "."], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "init"], check=True)
    assert main(["secrets-history", str(repo), "-f", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["findings"] == []


# ------------------------------------------------------------------------------------------- export formats

def test_scan_format_choices_cover_every_exporter():
    assert set(EXPORT_FORMATS) <= set(SCAN_FORMATS)
    assert {"console", "markdown", "json", "html", "sarif", "gitlab-sast", "codeclimate"} <= set(SCAN_FORMATS)


GL_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info", "Unknown"}
GL_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")


def check_gitlab_sast(doc: dict) -> None:
    """The required structure of the GitLab SAST report schema 15.x (sast-report-format.json)."""
    assert set(doc) >= {"version", "vulnerabilities", "scan"}
    assert re.fullmatch(r"15\.\d+\.\d+", doc["version"])
    sc = doc["scan"]
    assert sc["type"] == "sast" and sc["status"] in ("success", "failure")
    assert GL_TIME.match(sc["start_time"]) and GL_TIME.match(sc["end_time"]) and sc["start_time"] <= sc["end_time"]
    for key in ("analyzer", "scanner"):
        assert all(sc[key][k] for k in ("id", "name", "version")) and sc[key]["vendor"]["name"]
    ids = set()
    for v in doc["vulnerabilities"]:
        assert str(uuid.UUID(v["id"])) == v["id"] and v["id"] not in ids
        ids.add(v["id"])
        assert v["category"] == "sast" and v["severity"] in GL_SEVERITIES
        assert 0 < len(v["name"]) <= 255 and v["description"]
        assert v["scanner"]["id"] == "kashif"
        loc = v["location"]
        assert loc["file"] and isinstance(loc.get("start_line", 1), int) and loc.get("end_line", 1) >= loc.get("start_line", 1)
        assert v["identifiers"] and all(i["type"] and i["name"] and i["value"] for i in v["identifiers"])
        assert v["identifiers"][0]["type"] == "kashif_rule_id"
        for ident in v["identifiers"]:
            if ident["type"] == "cwe":
                assert ident["value"].isdigit() and ident["url"].startswith("https://cwe.mitre.org/")
        assert len(v.get("solution", "")) <= 7000


CC_SEVERITIES = {"info", "minor", "major", "critical", "blocker"}


def check_codeclimate(doc: list) -> None:
    assert isinstance(doc, list)
    fps = set()
    for issue in doc:
        assert issue["type"] == "issue" and issue["check_name"] and issue["description"]
        assert issue["categories"] == ["Security"] and issue["severity"] in CC_SEVERITIES
        lines = issue["location"]["lines"]
        assert issue["location"]["path"] and 1 <= lines["begin"] <= lines["end"]
        assert re.fullmatch(r"[0-9a-f]{32}", issue["fingerprint"]) and issue["fingerprint"] not in fps
        fps.add(issue["fingerprint"])


def test_scan_writes_gitlab_sast(project, tmp_path):
    out = tmp_path / "gl-sast-report.json"
    assert scan(project, "-f", "gitlab-sast", "-o", str(out)) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    check_gitlab_sast(doc)
    crit = [v for v in doc["vulnerabilities"] if v["severity"] == "Critical"]
    assert crit and crit[0]["location"] == {"file": "app.py", "start_line": 10, "end_line": 10}
    assert {"type": "cwe", "name": "CWE-78", "value": "78",
            "url": "https://cwe.mitre.org/data/definitions/78.html"} in crit[0]["identifiers"]
    # stable ids: the same scan twice gives the same vulnerability ids
    again = tmp_path / "again.json"
    assert scan(project, "-f", "gitlab-sast", "-o", str(again)) == 0
    assert [v["id"] for v in json.loads(again.read_text(encoding="utf-8"))["vulnerabilities"]] == [v["id"] for v in doc["vulnerabilities"]]


def test_scan_writes_codeclimate_to_stdout(project, capsys):
    assert scan(project, "-f", "codeclimate") == 0
    doc = json.loads(capsys.readouterr().out)
    check_codeclimate(doc)
    crit = next(i for i in doc if i["severity"] == "blocker")
    assert crit["location"] == {"path": "app.py", "lines": {"begin": 10, "end": 10}} and crit["check_name"]


def test_gitlab_formats_on_the_regression_corpus():
    from vulnscan.exporters import export
    from vulnscan.model import assign_fingerprints
    from vulnscan.scanner import scan_path
    findings, _ = scan_path(ROOT / "tests" / "data" / "regress", [], set())
    assign_fingerprints(findings)
    check_gitlab_sast(json.loads(export(findings, "gitlab-sast", {"lang": "en"})))
    check_codeclimate(json.loads(export(findings, "codeclimate", {"lang": "ar"})))


def test_gitlab_formats_leave_out_false_positives_and_fixed():
    from vulnscan.exporters import export
    base = {"rule_id": "PY001", "severity": "high", "title": "t", "title_ar": "t", "file": "a.py", "line": 3,
            "snippet": "x", "advice": "", "cwe": "CWE-89", "source": "vulnscan"}
    findings = [dict(base, fingerprint="0123456789abcdef:0"),
                dict(base, fingerprint="0123456789abcdef:1", extra={"triage": {"status": "false_positive"}}),
                dict(base, fingerprint="0123456789abcdef:2", extra={"triage": {"status": "fixed"}})]
    assert len(json.loads(export(findings, "gitlab-sast"))["vulnerabilities"]) == 1
    assert len(json.loads(export(findings, "codeclimate"))) == 1


@pytest.mark.parametrize("fmt", sorted(set(EXPORT_FORMATS) - {"asff"}))
def test_scan_accepts_every_export_format(project, tmp_path, fmt):
    out = tmp_path / f"out.{fmt}"
    assert scan(project, "-f", fmt, "-o", str(out)) == 0
    text = out.read_text(encoding="utf-8")
    assert text.strip()
    if fmt == "junit":
        ET.fromstring(text)
    elif not fmt.endswith("csv"):
        json.loads(text)


def test_asff_needs_the_aws_account(project, capsys):
    with pytest.raises(SystemExit) as e:
        scan(project, "-f", "asff")
    assert e.value.code == 2
    err = capsys.readouterr().err                # 1.0.1: the scan takes --aws-account/--aws-region itself
    assert "--aws-account" in err and "--aws-region" in err


def test_existing_formats_unchanged(project, tmp_path, capsys):
    assert scan(project, "-f", "json") == 0
    doc = json.loads(capsys.readouterr().out)
    assert set(doc) >= {"target", "files_scanned", "generated_at", "notes", "notes_en", "summary", "findings"}
    assert doc["scanners"] == ["sast", "secrets"]
    out = tmp_path / "r.sarif"
    assert scan(project, "-f", "sarif", "-o", str(out)) == 0
    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0" and not any("suppressions" in r for r in sarif["runs"][0]["results"])
    capsys.readouterr()
    assert scan(project, "-f", "markdown") == 0 and capsys.readouterr().out.startswith("# ")


def test_export_flag_and_risk_score(project, tmp_path, capsys):
    gl, csv_out = tmp_path / "gl.json", tmp_path / "f.csv"
    assert scan(project, "-f", "json", "-o", str(tmp_path / "r.json"), "--export", f"gitlab-sast={gl}",
                "--export", f"csv={csv_out}", "--risk-score") == 0
    check_gitlab_sast(json.loads(gl.read_text(encoding="utf-8")))
    assert csv_out.read_bytes().count(b"\r\n") >= 2               # the CSV keeps its own CRLF line ends
    assert "Kashif risk score:" in capsys.readouterr().out


def test_export_flag_rejects_bad_specs_before_scanning(project):
    for bad in ("gitlab-sast", "nope=x.json", "json=x.json", "=x"):
        with pytest.raises(SystemExit) as e:
            scan(project, "--export", bad)
        assert e.value.code == 2


def test_machine_output_on_stdout_stays_parseable_with_risk_score(project, capsys):
    assert scan(project, "-f", "gitlab-sast", "--risk-score", "--compliance", "owasp") == 0
    captured = capsys.readouterr()
    check_gitlab_sast(json.loads(captured.out))
    assert "Kashif risk score" in captured.err and "OWASP" in captured.err


# ------------------------------------------------------------------------------------------- compliance

def test_compliance_and_audit_report(project, tmp_path, capsys):
    audit = tmp_path / "audit.html"
    assert scan(project, "--compliance", "owasp,pci", "--audit-report", str(audit), "--no-color") == 0
    out = capsys.readouterr().out
    assert "OWASP Top 10" in out and "PCI DSS" in out
    html = audit.read_text(encoding="utf-8")
    assert "<script" not in html.lower() and "A03" in html


def test_compliance_unknown_framework(project, capsys):
    assert scan(project, "--compliance", "nope") == 2
    assert "Unknown compliance framework: nope" in capsys.readouterr().err


def test_compliance_subcommand_on_a_report(project, tmp_path, capsys):
    report = tmp_path / "r.json"
    scan(project, "-f", "json", "-o", str(report))
    capsys.readouterr()
    assert main(["compliance", str(report), "-f", "json", "--framework", "owasp"]) == 0
    assert json.loads(capsys.readouterr().out)["schema"] == "kashif-compliance/1"


# ------------------------------------------------------------------------------------------- triage

def test_triage_hides_false_positive_and_writes_sarif_suppression(project, tmp_path, capsys):
    fp = critical_fp(project, tmp_path)
    assert main(["triage", "set", fp, "false_positive", "-j", "cmd is validated upstream", "--author", "t",
                 "--root", str(project)]) == 0
    assert (project / ".kashif" / "triage.json").is_file()
    assert scan(project, "--fail-on", "critical") == 1                      # without --triage: still gated
    sarif = tmp_path / "t.sarif"
    capsys.readouterr()
    assert scan(project, "--triage", "--fail-on", "critical", "-f", "sarif", "-o", str(sarif)) == 0
    results = json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"]
    hidden = [r for r in results if r.get("suppressions")]
    assert len(hidden) == 1 and hidden[0]["partialFingerprints"]["vulnscan/v1"] == fp
    assert hidden[0]["suppressions"][0] == {"kind": "external", "status": "accepted",
                                            "justification": "false_positive cmd is validated upstream"}
    assert scan(project, "--triage", "--triage-show", "all", "--fail-on", "critical") == 1


def test_triage_update_records_first_seen_and_options_are_checked(project, tmp_path):
    assert scan(project, "--triage", "--triage-update") == 0
    data = json.loads((project / ".kashif" / "triage.json").read_text(encoding="utf-8"))
    assert data["schema"] == "kashif-triage/1" and all(e.get("first_seen") for e in data["findings"].values())
    for bad in (["--triage", "--triage-show", "opne"], ["--triage", "--sla", "high=soon"], ["--sla", "high=3"],
                ["--triage-update"]):
        with pytest.raises(SystemExit) as e:
            scan(project, *bad)
        assert e.value.code == 2


def test_triage_malformed_file_is_an_error(project, capsys):
    (project / ".kashif").mkdir()
    (project / ".kashif" / "triage.json").write_text("{not json", encoding="utf-8")
    assert scan(project, "--triage") == 2


def test_triage_list_subcommand(project, tmp_path, capsys):
    fp = critical_fp(project, tmp_path)
    assert main(["triage", "set", fp, "confirmed", "--author", "t", "--root", str(project)]) == 0
    capsys.readouterr()
    assert main(["triage", "list", "--root", str(project), "--json"]) == 0
    assert fp in capsys.readouterr().out


# ------------------------------------------------------------------------------------------- policy

def write_policy(project, text: str):
    (project / "kashif.yml").write_text(text, encoding="utf-8")


def test_policy_in_the_project_applies_automatically(project, tmp_path, capsys):
    write_policy(project, "version: 1\nname: demo\ngate:\n  fail_on: high\n")
    assert scan(project, "-o", str(tmp_path / "r.txt")) == 1
    assert "Kashif security gate: FAILED" in capsys.readouterr().err
    assert scan(project, "-o", str(tmp_path / "r.txt"), "--no-policy") == 0
    assert scan(project, "--fix-dry-run") == 0                                      # --fix is not gated
    write_policy(project, "version: 1\nname: lax\ngate:\n  fail_on: never\n")
    assert scan(project, "-o", str(tmp_path / "r.txt")) == 0
    assert "PASSED" in capsys.readouterr().err
    assert scan(project, "-o", str(tmp_path / "r.txt"), "--fail-on", "critical") == 1    # --fail-on still counts


def test_policy_preset_and_malformed_policy(project, tmp_path, capsys):
    assert scan(project, "-o", str(tmp_path / "r.txt"), "--policy", "strict") == 1
    assert scan(project, "-o", str(tmp_path / "r.txt"), "--policy") == 2            # bare --policy, no kashif.yml
    assert "No policy file in the scanned folder" in capsys.readouterr().err
    write_policy(project, "version: 1\ngate:\n  fail_on: hihg\n")
    assert scan(project, "-o", str(tmp_path / "r.txt")) == 2
    assert "kashif.yml" in capsys.readouterr().err


def test_policy_triage_decisions_count(project, tmp_path):
    fp = critical_fp(project, tmp_path)
    main(["triage", "set", fp, "false_positive", "-j", "constant", "--author", "t", "--root", str(project)])
    write_policy(project, "version: 1\nname: demo\ngate:\n  fail_on: high\n")
    assert scan(project, "-o", str(tmp_path / "r.txt")) == 1
    assert scan(project, "-o", str(tmp_path / "r.txt"), "--triage") == 0


def test_policy_reports_only_inside_the_reports_dir(project, tmp_path, capsys):
    write_policy(project, "version: 1\nname: demo\ngate:\n  fail_on: never\nreports:\n"
                          "  - format: sarif\n    path: out/kashif.sarif\n  - format: json\n    path: k.json\n")
    assert scan(project, "-o", str(tmp_path / "r.txt")) == 0
    assert "--policy-reports-dir" in capsys.readouterr().err
    assert not (project / "out").exists() and not (pathlib.Path.cwd() / "out" / "kashif.sarif").exists()
    reports = tmp_path / "reports"
    assert scan(project, "-o", str(tmp_path / "r.txt"), "--policy-reports-dir", str(reports)) == 0
    assert json.loads((reports / "out" / "kashif.sarif").read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert json.loads((reports / "k.json").read_text(encoding="utf-8"))["findings"]


def test_policy_check_subcommand(project, tmp_path, capsys):
    report = tmp_path / "r.json"
    scan(project, "-f", "json", "-o", str(report))
    write_policy(project, "version: 1\nname: demo\ngate:\n  fail_on: critical\n")
    assert main(["policy", "check", str(report), "--policy", str(project / "kashif.yml")]) == 1
    assert main(["policy", "validate", str(project / "kashif.yml")]) == 0


# ------------------------------------------------------------------------------------------- surface, rules

def test_surface_subcommand(project, capsys):
    assert main(["surface", str(project), "-f", "json", "--no-engine"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert any(e["path"] == "/run" for e in doc["entries"])


def test_rules_new_and_test(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["rules", "new", "my-pack", "--language", "python"]) == 0
    assert "kashif rules test" in capsys.readouterr().out
    assert main(["rules", "test", "my-pack"]) == 0


def test_unknown_pack_is_an_error(project, tmp_path, monkeypatch):
    monkeypatch.setenv("KASHIF_HOME", str(tmp_path / "home"))
    with pytest.raises(SystemExit) as e:
        scan(project, "--pack", "does-not-exist")
    assert e.value.code == 2


def test_installed_pack_is_used_by_a_scan(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("KASHIF_HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)
    assert main(["rules", "new", "my-pack", "--language", "python"]) == 0
    assert main(["rules", "pack", "my-pack", "-o", str(tmp_path / "my-pack.kashifpack")]) == 0
    assert main(["rules", "install", str(tmp_path / "my-pack.kashifpack")]) == 0
    capsys.readouterr()
    target = tmp_path / "my-pack" / "fixtures"
    without = main([str(target), "--no-deps", "--no-external", "-f", "json", "--lang", "en"])
    plain = {f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]}
    main([str(target), "--no-deps", "--no-external", "-f", "json", "--lang", "en", "--pack", "my-pack"])
    with_pack = {f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert without in (0, 1) and with_pack - plain, (plain, with_pack)


# ------------------------------------------------------------------------------------------- README / docs

DOCS = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
FENCE = re.compile(r"^```[^\n]*\n(.*?)^```", re.S | re.M)
SPAN = re.compile(r"`([^`\n]+)`")
GROUPS = {"policy", "triage", "rules"}


def _commands(text: str):
    """Every `kashif ...` / `vulnscan ...` command in a fenced block or an inline code span, as a token list."""
    chunks = [line for block in FENCE.findall(text) for line in block.splitlines()]
    chunks += SPAN.findall(FENCE.sub("", text))
    for chunk in chunks:
        chunk = chunk.split(" #", 1)[0].strip().lstrip("-").strip()
        for part in re.split(r"&&|;|\|", chunk):
            try:
                tokens = shlex.split(part)
            except ValueError:
                continue
            for i, tok in enumerate(tokens):
                if tok in ("kashif", "vulnscan") and (i == 0 or tokens[i - 1] in ("sudo", "python3", "python")):
                    yield tokens[i + 1:]
                    break


def _help(argv: list[str], capsys) -> str:
    try:
        main(argv + ["--help"])
    except SystemExit:
        pass
    return capsys.readouterr().out


def test_documented_commands_flags_and_formats_exist(capsys):
    scan_options = {opt for action in build_parser("en")._actions for opt in action.option_strings}
    checked = 0
    problems = []
    help_cache: dict = {}
    for doc in DOCS:
        for tokens in _commands(doc.read_text(encoding="utf-8")):
            if not tokens:
                continue
            checked += 1
            where = f"{doc.relative_to(ROOT)}: kashif {' '.join(tokens)}"
            head = tokens[0]
            if head in SUBCOMMANDS or head in DELEGATES:
                key = [head] + ([tokens[1]] if head in GROUPS and len(tokens) > 1 and not tokens[1].startswith("-")
                                else [])
                text = help_cache.setdefault(tuple(key), _help(key, capsys))
                if not text.startswith("usage: kashif"):
                    problems.append(f"{where}: no help for {' '.join(key)}")
                    continue
                for i, tok in enumerate(tokens[1:], 1):
                    if tok.startswith("--") and tok.split("=", 1)[0] not in text:
                        problems.append(f"{where}: {tok} is not an option of kashif {' '.join(key)}")
                    if tok == "-f" and i + 1 < len(tokens):
                        value = tokens[i + 1]
                        known = value in EXPORT_FORMATS if head == "export" else re.search(rf"[{{,]{re.escape(value)}[,}}]", text)
                        if not known:
                            problems.append(f"{where}: -f {value} is not a format of kashif {' '.join(key)}")
                continue
            if re.fullmatch(r"[a-z][a-z-]+", head) and not head.startswith("-") and not pathlib.Path(head).suffix \
                    and head not in ("ui",) and "/" not in head and head not in {"my-project", "my-app"}:
                problems.append(f"{where}: unknown sub-command {head!r}")
            for i, tok in enumerate(tokens):
                if tok.startswith("-") and tok not in ("-",) and not tok.lstrip("-").isdigit():
                    if tok.split("=", 1)[0] not in scan_options:
                        problems.append(f"{where}: unknown option {tok}")
                if tok in ("-f", "--format") and i + 1 < len(tokens) and tokens[i + 1] not in SCAN_FORMATS:
                    problems.append(f"{where}: unknown format {tokens[i + 1]}")
    # bare `-f X` spans in prose ("`-f gitlab-sast`") name scan formats
    for doc in DOCS:
        for span in SPAN.findall(FENCE.sub("", doc.read_text(encoding="utf-8"))):
            m = re.fullmatch(r"-f ([a-z-]+)", span.strip())
            if m and m.group(1) not in SCAN_FORMATS:
                problems.append(f"{doc.relative_to(ROOT)}: unknown format in `{span}`")
    assert checked > 40, checked
    assert not problems, "\n".join(problems)


def test_readme_documents_every_subcommand():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    for name in list(SUBCOMMANDS) + ["secrets-history"]:
        assert f"kashif {name}" in text or f"`{name}`" in text, name


@pytest.mark.skipif(os.name == "nt", reason="creating symlinks needs privileges on Windows")
@pytest.mark.parametrize("lang", ["en", "ar"])
def test_triage_update_refuses_a_kashif_dir_symlinked_outside(project, tmp_path, capsys, lang):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (project / ".kashif").symlink_to(outside, target_is_directory=True)
    assert main([str(project), "--no-deps", "--no-external", "--lang", lang, "--triage", "--triage-update"]) == 2
    assert not (outside / "triage.json").exists()
    err = capsys.readouterr().err
    assert ("symbolic link" in err) == (lang == "en") and ("رابط رمزي" in err) == (lang == "ar")


@pytest.mark.skipif(os.name == "nt", reason="creating symlinks needs privileges on Windows")
def test_triage_update_refuses_a_symlinked_triage_file(project, tmp_path):
    (project / ".kashif").mkdir()
    victim = tmp_path / "victim.json"
    (project / ".kashif" / "triage.json").symlink_to(victim)
    assert scan(project, "--triage", "--triage-update") == 2
    assert not victim.exists()
