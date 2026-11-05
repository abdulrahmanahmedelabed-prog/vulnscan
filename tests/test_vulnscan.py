import json
import pathlib
import zipfile

import pytest

from vulnscan.cli import main
from vulnscan.deps import _cvss_score, collect_packages
from vulnscan.model import SEVERITIES, SEVERITY_RANK, Finding, sort_findings
from vulnscan.report import render_json, render_markdown
from vulnscan.scanner import scan_path


@pytest.fixture
def project(tmp_path: pathlib.Path) -> pathlib.Path:
    (tmp_path / "app.py").write_text(
        "import pickle, subprocess, hashlib\n"
        "AWS = 'AKIAIOSFODNN7EXAMPLE'\n"
        "password = 'hunter2secret'\n"
        "def load(d):\n"
        "    return pickle.loads(d)\n"
        "def run(cmd):\n"
        "    subprocess.call(cmd, shell=True)\n"
        "h = hashlib.md5(b'x')\n"
        "ok = hashlib.md5(b'x')  # nosec\n"
        "url = 'http://api.example.net/v1'\n"
    )
    (tmp_path / "index.js").write_text("el.innerHTML = userInput;\nconst r = eval(code);\n")
    (tmp_path / "Dockerfile").write_text("FROM python\nRUN pip install x\n")
    (tmp_path / ".env").write_text("TOKEN=abc\n")
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\nnumpy>=1.0\n")
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / "server.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "evil.js").write_text("eval(x)\n")
    (tmp_path / "AndroidManifest.xml").write_text('<application android:usesCleartextTraffic="true"/>\n')
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n"
        "      - run: echo ${{ github.event.pull_request.title }}\n")
    return tmp_path


def ids(findings):
    return {f.rule_id for f in findings}


def test_detects_expected_rules(project):
    findings, count = scan_path(project)
    got = ids(findings)
    for rid in ("SEC001", "SEC002", "SEC004", "DES001", "EXE004", "CRY001", "NET001",
                "INJ004", "EXE002", "DKR003", "DKR000", "FILE001", "FILE003", "MOB001", "CI001", "CI002", "CI004"):
        assert rid in got, rid
    assert count > 0


def test_nosec_and_skip_dirs(project):
    findings, _ = scan_path(project)
    md5 = [f for f in findings if f.rule_id == "CRY001"]
    assert len(md5) == 1 and md5[0].line == 8
    assert not any("node_modules" in f.file for f in findings)


def test_sorted_highest_first(project):
    findings, _ = scan_path(project)
    ordered = sort_findings(findings)
    ranks = [SEVERITY_RANK[f.severity] for f in ordered]
    assert ranks == sorted(ranks)
    assert ordered[0].severity == "critical"


def test_exclude_and_ignore(project):
    findings, _ = scan_path(project, excludes=["keys/*"], ignore_rules={"SEC002"})
    got = ids(findings)
    assert "SEC001" not in got and "SEC002" not in got


def test_archive_target(project, tmp_path):
    archive = tmp_path.parent / f"{tmp_path.name}-bundle.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.write(project / "app.py", "src/app.py")
    findings, _ = scan_path(archive)
    assert "DES001" in ids(findings)
    assert findings[0].file.startswith(archive.name + "!")


def test_collect_packages(project):
    pkgs = collect_packages(project)
    assert ("PyPI", "requests", "2.19.0", "requirements.txt") in pkgs
    assert not any(p[1] == "numpy" for p in pkgs)  # unpinned is skipped


def test_cvss_bucket():
    assert _cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert _cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0


def test_reports(project):
    findings, n = scan_path(project)
    md = render_markdown(findings, "p", n, [])
    assert md.index("CRITICAL") < md.index("HIGH") < md.index("MEDIUM") < md.index("LOW")
    data = json.loads(render_json(findings, "p", n, []))
    assert list(data["summary"]) == list(SEVERITIES)
    assert data["findings"][0]["severity"] == "critical"


def test_cli_fail_on_and_output(project, tmp_path, capsys):
    out = tmp_path / "r.md"
    code = main([str(project), "--no-deps", "--no-external", "-f", "markdown", "-o", str(out), "--fail-on", "high"])
    assert code == 1 and out.exists()
    code = main([str(project), "--no-deps", "--no-external", "--no-color", "--min-severity", "critical"])
    assert code == 0
    assert "CRITICAL" in capsys.readouterr().out


def test_url_requires_authorization():
    with pytest.raises(SystemExit):
        main(["https://example.invalid", "--no-deps"])


def test_clean_project(tmp_path):
    (tmp_path / "ok.py").write_text("import secrets\ntoken = secrets.token_hex(16)\n")
    findings, _ = scan_path(tmp_path)
    assert findings == []
