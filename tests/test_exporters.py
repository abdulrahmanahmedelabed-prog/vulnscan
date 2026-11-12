"""Exporters: structure of every format, XML well-formedness, CSV injection, Arabic text, risk score, CLI."""

import csv
import io
import json
import xml.etree.ElementTree as ET

import pytest

from vulnscan import exporters as ex
from vulnscan.model import Finding

AR_TITLE = "بيانات غير موثوقة تصل إلى استعلام SQL"
AR_ADVICE = "استخدم استعلامات مُعَلَّمة بدل بناء نص الاستعلام."
META = {"target": "/srv/work/shop", "generated_at": "2026-03-04T05:06:07+00:00"}

# Keys the DefectDojo generic parser documents; any other key stops its import.
DD_KEYS = {
    "title", "severity", "description", "mitigation", "impact", "steps_to_reproduce", "severity_justification",
    "references", "param", "payload", "cve", "vulnerability_ids", "cwe", "cwes", "unique_id_from_tool",
    "vuln_id_from_tool", "cvssv3", "cvssv3_score", "cvssv4", "cvssv4_score", "epss_score", "epss_percentile", "active",
    "verified", "false_p", "out_of_scope", "risk_accepted", "under_review", "is_mitigated", "mitigated", "file_path",
    "line", "static_finding", "dynamic_finding", "sast_source_object", "sast_sink_object", "sast_source_line",
    "sast_source_file_path", "component_name", "component_version", "purl", "purl_type", "namespace", "date",
    "thread_id", "scanner_confidence", "nb_occurences", "publish_date", "service", "planned_remediation_date",
    "planned_remediation_version", "effort_for_fixing", "kev_date", "known_exploited", "ransomware_used",
    "fix_available", "fix_version", "tags", "endpoints", "files", "numerical_severity"}


def flow_finding(**kw):
    """A proven SQL injection with a two-step, two-file data-flow path."""
    base = dict(rule_id="DF004", severity="high", title="Tainted data flows into SQL execute", title_ar=AR_TITLE,
                file="app/views.py", line=11, snippet="المصدر: request.args", advice=AR_ADVICE, cwe="CWE-89",
                source="taint",
                extra={"analysis": "dataflow", "taint_source": "request.args", "interprocedural": True,
                       "path": [{"file": "app/views.py", "line": 11, "text": "استدعاء run()"},
                                {"file": "app/db.py", "line": 7, "text": "نقطة الخطر: SQL execute"}]})
    base.update(kw)
    return Finding(**base)


def sample():
    return [
        flow_finding(),
        Finding("EXE004", "critical", "Shell command built from variables", "أمر shell يُبنى من متغيرات", "app/run.py", 3,
                'os.system("ls " + d)', "استخدم قائمة وسائط.", "CWE-78"),
        Finding("CFG001", "low", "Debug mode enabled", "وضع التصحيح مفعّل", "tests/test_app.py", 0, "DEBUG = True",
                "عطّل وضع التصحيح.", "CWE-489"),
        Finding("HDR001", "info", "Missing security header", "ترويسة أمان ناقصة", "https://example.test/login", 0,
                "X-Frame-Options", "أضف الترويسة.", "", "web", {"url": "https://example.test/login"}),
    ]


def dd(findings=None, **meta):
    return json.loads(ex.export(sample() if findings is None else findings, "defectdojo", {**META, **meta}))


# ------------------------------------------------------------------------------------------------- API surface

def test_list_formats_and_unknown_format():
    ids = [f["id"] for f in ex.list_formats()]
    assert ids == list(ex.FORMATS) and {"defectdojo", "sonarqube", "junit", "csv", "jira-csv", "github-issues", "asff",
                                        "ocsf", "risk"} <= set(ids)
    for lang in ("en", "ar"):
        for info in ex.list_formats(lang):
            assert info["name"] and info["description"] and info["ext"] in ("json", "xml", "csv") and info["mime"]
    assert ex.list_formats("ar")[4]["name"] != ex.list_formats("en")[4]["name"]
    assert ex.format_info("asff")["needs"] == ["aws_account_id", "aws_region"]
    with pytest.raises(ex.ExportError):
        ex.export(sample(), "pdf", {})
    with pytest.raises(ex.ExportError):
        ex.export("nope", "csv", {})
    with pytest.raises(ex.ExportError):
        ex.export(sample(), "csv", {"min_severity": "urgent"})


def test_every_string_exists_in_both_languages():
    assert set(ex.STR["en"]) == set(ex.STR["ar"])
    assert all(ex.STR["ar"][k].count("{") == ex.STR["en"][k].count("{") for k in ex.STR["en"])


def test_every_format_renders_objects_dicts_and_empty_lists():
    meta = {**META, "aws_account_id": "123456789012", "aws_region": "eu-west-1"}
    objs = sample()
    dicts = [f.to_dict() for f in sample()]
    for fmt in ex.FORMATS:
        for lang in ("en", "ar"):
            a = ex.export(objs, fmt, {**meta, "lang": lang})
            assert a == ex.export(dicts, fmt, {**meta, "lang": lang}), fmt
            assert a == ex.export({"findings": dicts}, fmt, {**meta, "lang": lang}), fmt
            assert ex.export([], fmt, {**meta, "lang": lang})


def test_dicts_without_fingerprint_get_stable_distinct_ones():
    d = flow_finding().to_dict()
    want = d.pop("fingerprint")
    twin = dict(d)
    rows = dd([d, twin])["findings"]
    ids = [r["unique_id_from_tool"] for r in rows]
    assert ids[0] == want and len(set(ids)) == 2 and ids[1].split(":")[0] == want.split(":")[0]


def test_min_severity_filters():
    assert len(dd(min_severity="high")["findings"]) == 2


# ------------------------------------------------------------------------------------------------- DefectDojo

def test_defectdojo_structure():
    doc = dd()
    assert set(doc) == {"findings"} and len(doc["findings"]) == 4
    for row in doc["findings"]:
        assert set(row) <= DD_KEYS, set(row) - DD_KEYS
        assert row["title"] and row["description"] and row["severity"] in ("Critical", "High", "Medium", "Low", "Info")
        for key in ("active", "verified", "false_p", "static_finding", "dynamic_finding", "risk_accepted", "is_mitigated"):
            assert isinstance(row[key], bool)
        assert row["date"] == "2026-03-04"
    sqli = next(r for r in doc["findings"] if r["vuln_id_from_tool"] == "DF004")
    assert sqli["cwe"] == 89 and sqli["file_path"] == "app/views.py" and sqli["line"] == 11
    assert sqli["unique_id_from_tool"] == flow_finding().to_dict()["fingerprint"]
    assert sqli["static_finding"] is True and sqli["dynamic_finding"] is False
    assert sqli["sast_source_object"] == "request.args" and sqli["sast_sink_object"] == "SQL execute"
    assert sqli["sast_source_line"] == 11 and sqli["sast_source_file_path"] == "app/views.py"
    assert "cwe.mitre.org/data/definitions/89" in sqli["references"]
    assert "Kashif risk score" in sqli["severity_justification"] and "not a CVSS" in sqli["severity_justification"]
    web = next(r for r in doc["findings"] if r["vuln_id_from_tool"] == "HDR001")
    assert web["dynamic_finding"] is True and web["static_finding"] is False and "cwe" not in web and "line" not in web
    assert web["severity"] == "Info"


def test_defectdojo_triage_and_test_type():
    fp = flow_finding(extra={"triage": {"status": "false_positive"}})
    ok = flow_finding(file="b.py", extra={"triage": {"status": "confirmed"}})
    acc = flow_finding(file="c.py", extra={"triage": {"status": "accepted_risk"}})
    rows = {r["file_path"]: r for r in dd([fp, ok, acc])["findings"]}
    assert rows["app/views.py"]["false_p"] and not rows["app/views.py"]["active"]
    assert rows["b.py"]["verified"] and rows["b.py"]["active"]
    assert rows["c.py"]["risk_accepted"] and not rows["c.py"]["active"]
    doc = dd(defectdojo_test_type="Kashif Scan")
    assert doc["type"] == "Kashif Scan" and doc["static_tool"] is True and set(doc) <= {
        "type", "version", "static_tool", "dynamic_tool", "findings", "name", "description"}


def test_defectdojo_arabic_and_english_text():
    ar = next(r for r in dd(lang="ar")["findings"] if r["vuln_id_from_tool"] == "DF004")
    assert ar["title"] == AR_TITLE and ar["mitigation"] == AR_ADVICE and "مسار التدفق" in ar["description"]
    raw = ex.export(sample(), "defectdojo", {**META, "lang": "ar"})
    assert AR_TITLE in raw and "\\u06" not in raw            # real UTF-8, not escapes
    en = next(r for r in dd()["findings"] if r["vuln_id_from_tool"] == "DF004")
    assert en["title"] == "Tainted data flows into SQL execute" and "Data flow" in en["description"]


def test_cve_is_exported_for_dependency_findings():
    f = Finding("CVE-2024-12345", "high", "requests 2.0: CVE-2024-12345", "ثغرة في requests", "requirements.txt", 4,
                "requests==2.0", "حدّث الحزمة.", "", "osv")
    assert dd([f])["findings"][0]["cve"] == "CVE-2024-12345"
    event = json.loads(ex.export([f], "ocsf", META))[0]
    assert event["vulnerabilities"][0]["cve"] == {"uid": "CVE-2024-12345"}


# -------------------------------------------------------------------------------------------------- SonarQube

def test_sonarqube_rules_and_issues():
    doc = json.loads(ex.export(sample() + [flow_finding(file="other.py", severity="medium")], "sonarqube", META))
    assert set(doc) == {"rules", "issues"} and not any("flows" in i for i in doc["issues"])
    ids = [r["id"] for r in doc["rules"]]
    assert len(ids) == len(set(ids)) == 4                   # the importer rejects a duplicate rule id
    for rule in doc["rules"]:
        assert set(rule) == {"id", "name", "description", "engineId", "cleanCodeAttribute", "impacts"}
        assert rule["id"] and rule["name"] and rule["engineId"] == "kashif" and rule["cleanCodeAttribute"] == "TRUSTWORTHY"
        assert rule["impacts"] and all(i["softwareQuality"] == "SECURITY" and i["severity"] in ("HIGH", "MEDIUM", "LOW")
                                       for i in rule["impacts"])
    assert next(r for r in doc["rules"] if r["id"] == "DF004")["impacts"][0]["severity"] == "HIGH"   # the worst one
    assert len(doc["issues"]) == 5
    for issue in doc["issues"]:
        assert set(issue) <= {"ruleId", "effortMinutes", "primaryLocation", "secondaryLocations"}
        assert "severity" not in issue and "type" not in issue           # rejected in the 10.3+ format
        assert issue["ruleId"] in ids
        loc = issue["primaryLocation"]
        assert loc["message"] and loc["filePath"] and ("textRange" not in loc or loc["textRange"]["startLine"] >= 1)
        for sec in issue.get("secondaryLocations", []):
            assert sec["filePath"] and sec["textRange"]["startLine"] >= 1
    sqli = next(i for i in doc["issues"] if i["primaryLocation"]["filePath"] == "app/views.py")
    assert sqli["primaryLocation"]["textRange"] == {"startLine": 11}
    # the data-flow path: the step at the primary location is not repeated, the sink in the other file is kept
    assert [(s["filePath"], s["textRange"]["startLine"]) for s in sqli["secondaryLocations"]] == [("app/db.py", 7)]
    assert sqli["secondaryLocations"][0]["message"].startswith("2. ")
    file_level = next(i for i in doc["issues"] if i["ruleId"] == "CFG001")
    assert "textRange" not in file_level["primaryLocation"]
    five = json.loads(ex.export(sample(), "sonarqube", {**META, "sonar_severity_scale": "5"}))
    assert {r["impacts"][0]["severity"] for r in five["rules"]} == {"BLOCKER", "HIGH", "LOW", "INFO"}


def test_sonarqube_legacy():
    doc = json.loads(ex.export(sample(), "sonarqube-legacy", META))
    assert set(doc) == {"issues"}
    for issue in doc["issues"]:
        assert issue["engineId"] == "kashif" and issue["ruleId"] and issue["type"] == "VULNERABILITY"
        assert issue["severity"] in ("BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO")
        assert issue["primaryLocation"]["message"] and issue["primaryLocation"]["filePath"]


# ------------------------------------------------------------------------------------------------------ JUnit

def test_junit_is_well_formed_and_counts_add_up():
    text = ex.export(sample() + [flow_finding(line=30)], "junit", {**META, "lang": "ar"})
    assert text.startswith('<?xml version="1.0" encoding="UTF-8"?>')
    root = ET.fromstring(text.encode("utf-8"))
    assert root.tag == "testsuites"
    suites = root.findall("testsuite")
    assert sorted(s.get("name") for s in suites) == ["app/run.py", "app/views.py", "https://example.test/login",
                                                     "tests/test_app.py"]
    cases = root.findall("./testsuite/testcase")
    assert len(cases) == 4 == int(root.get("tests"))        # one testcase per rule and file, not per finding
    assert int(root.get("failures")) == len(root.findall(".//failure")) == 3
    for suite in suites:
        assert int(suite.get("tests")) == len(suite.findall("testcase"))
        assert int(suite.get("failures")) == len(suite.findall("testcase/failure"))
    case = next(c for c in cases if c.get("classname") == "app/views.py")
    assert case.get("name") == f"DF004: {AR_TITLE}"
    failure = case.find("failure")
    assert failure.get("type") == "high" and "11, 30" in failure.get("message")
    assert failure.text.count("DF004") == 2 and "نقطة الخطر: SQL execute" in failure.text
    info = next(c for c in cases if c.get("classname").startswith("https://"))
    assert info.find("failure") is None and info.find("system-out").text    # below fail_on: a passing test


def test_junit_fail_on_triage_empty_and_hostile_text():
    root = ET.fromstring(ex.export(sample(), "junit", {**META, "fail_on": "critical"}))
    assert root.get("failures") == "1"
    done = flow_finding(extra={"triage": {"status": "false_positive"}})
    root = ET.fromstring(ex.export([done], "junit", META))
    assert root.get("failures") == "0" and root.get("skipped") == "1" and root.find(".//skipped") is not None
    root = ET.fromstring(ex.export([], "junit", META))
    assert root.get("tests") == "1" and root.get("failures") == "0" and len(root.findall(".//testcase")) == 1
    evil = flow_finding(title='x"><script>&amp; ]]> \x00\x0b\x1f bell\x07', snippet="a < b && c > d ]]> \x08\ud800",
                        file='dir/"q"&<f>.py')
    text = ex.export([evil], "junit", META)
    root = ET.fromstring(text.encode("utf-8"))              # still well-formed
    assert not any(ord(ch) < 32 and ch not in "\n\r\t" for ch in text)
    assert "a < b && c > d ]]>" in root.find(".//failure").text
    assert root.find("testsuite").get("name") == 'dir/"q"&<f>.py'


# -------------------------------------------------------------------------------------------------------- CSV

def parse_csv(text):
    return list(csv.reader(io.StringIO(text, newline="")))


def test_csv_is_rfc4180_and_round_trips():
    f = flow_finding(snippet='say "hi", then\nnext line', title="Comma, quote \" and newline")
    text = ex.export([f, *sample()], "csv", META)
    assert text.endswith("\r\n") and "﻿" not in text
    rows = parse_csv(text)
    assert len(rows) == 6 and len({len(r) for r in rows}) == 1
    head = rows[0]
    row = dict(zip(head, rows[2]))                          # sorted: critical first, then the two high ones
    assert row["Title"] == "Comma, quote \" and newline" and row["Code"] == 'say "hi", then\nnext line'
    assert row["File"] == "app/views.py" and row["line"] == "11" and row["CWE"] == "CWE-89"
    assert float(row["Kashif risk score"]) > 0 and row["Status"] == "open" and ":" in row["Fingerprint"]
    assert "app/db.py:7" in row["Data flow"]
    assert '"say ""hi"", then\nnext line"' in text or '"say ""hi"", then\r\nnext line"' in text
    assert ex.export([f], "csv", {**META, "bom": True}).startswith("﻿")
    ar = parse_csv(ex.export(sample(), "csv", {**META, "lang": "ar"}))
    assert "الخطورة" in ar[0] and any(AR_TITLE in r for r in ar)


@pytest.mark.parametrize("payload", [
    "=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(1,1)", "\t=1+1", "\r=1+1", "\n=1+1", "  =HYPERLINK(\"http://x\")",
    "​=1+1", "﻿=1+1", "＝1+1", "＋1", "=1+1\",=2+2"])
def test_csv_formula_injection_is_neutralised(payload):
    assert ex.neutralise_cell(payload).startswith("'")
    f = flow_finding(title=payload, snippet=payload, advice=payload, file=payload, rule_id=payload,
                     extra={"taint_source": payload, "path": [{"file": payload, "line": 1, "text": payload}],
                            "url": payload})
    for fmt in ("csv", "jira-csv"):
        rows = parse_csv(ex.export([f], fmt, META))
        assert len(rows) == 2
        for cell in rows[1]:
            assert not cell.lstrip("  ​﻿").startswith(("=", "+", "-", "@", "＝", "＋", "－", "＠")), cell
            assert not cell.startswith(("\t", "\r", "\n")), cell


def test_neutralise_cell_leaves_ordinary_text_alone():
    for text in ("os.system(x)", "a = b", "CWE-89", "x@y.z", "بيانات - غير موثوقة", "", "3.5"):
        assert ex.neutralise_cell(text) == text
    assert ex.neutralise_cell(7) == "7" and ex.neutralise_cell(2.5) == "2.5" and ex.neutralise_cell(None) == ""
    assert ex.neutralise_cell("-1") == "'-1" and "\x00" not in ex.neutralise_cell("a\x00b")


# ------------------------------------------------------------------------------------------------------- Jira

def test_jira_csv():
    rows = parse_csv(ex.export(sample(), "jira-csv", {**META, "repo_url": "https://git.example.test/org/shop",
                                                      "ref": "abc123"}))
    head = rows[0]
    assert head[:3] == ["Summary", "Issue Type", "Priority"] and head.count("Labels") == 3 and "Description" in head
    assert len(rows) == 5
    first = dict(zip(head, rows[1]))
    assert first["Summary"].startswith("[CRITICAL] ") and first["Priority"] == "Highest" and first["Issue Type"] == "Bug"
    assert [r[2] for r in rows[1:]] == ["Highest", "High", "Low", "Lowest"]
    labels = [c for h, c in zip(head, rows[2]) if h == "Labels"]
    assert labels == ["security", "kashif", "CWE-89"] and not any(" " in x for x in labels)
    desc = rows[2][head.index("Description")]
    assert "{noformat}" in desc and "https://git.example.test/org/shop/blob/abc123/app/views.py#L11" in desc
    done = flow_finding(extra={"triage": {"status": "fixed"}})
    assert len(parse_csv(ex.export([done], "jira-csv", META))) == 1          # no ticket for a fixed finding
    task = parse_csv(ex.export(sample(), "jira-csv", {**META, "jira_issue_type": "Task", "lang": "ar"}))
    assert task[1][1] == "Task" and "الإصلاح" in task[1][head.index("Description")]
    hostile = flow_finding(snippet="x {noformat} {code} y", advice="see [link|http://evil.test] {panel}")
    desc = parse_csv(ex.export([hostile], "jira-csv", META))[1][head.index("Description")]
    assert desc.count("{noformat}") == 2 and "[link|" not in desc and "{panel}" not in desc


# ----------------------------------------------------------------------------------------------- GitHub Issues

def test_github_issues():
    issues = json.loads(ex.export(sample(), "github-issues", {**META, "repo_url": "https://github.com/o/r/"}))
    assert len(issues) == 4 and all(set(i) == {"title", "body", "labels"} for i in issues)
    sqli = issues[1]
    assert sqli["title"] == "[HIGH] Tainted data flows into SQL execute (app/views.py:11)"
    assert sqli["labels"] == ["security", "kashif", "severity:high", "CWE-89"]
    body = sqli["body"]
    assert "https://github.com/o/r/blob/HEAD/app/views.py#L11" in body and "`app/db.py:7`" in body
    assert f"<!-- kashif-fingerprint: {flow_finding().to_dict()['fingerprint']} -->" in body
    assert "Kashif risk score" in body and "not a CVSS score" in body
    assert all(len(i["title"]) <= 256 for i in issues)


def test_github_issue_body_cannot_be_hijacked():
    f = flow_finding(snippet="```\n</details> @octocat ``` #1 <img src=x>", advice="ping @octocat, see #42 <b>now</b> | x",
                     extra={"path": [{"file": "a`b.py", "line": 2, "text": "step @team <script>"}]})
    body = json.loads(ex.export([f], "github-issues", META))[0]["body"]
    lines = body.split("\n")
    fences = [ln for ln in lines if ln.startswith("````")]
    assert len(fences) == 2 and fences[0] == fences[1]      # a fence longer than the one in the snippet
    outside = "\n".join(lines[:lines.index(fences[0])] + lines[len(lines) - lines[::-1].index(fences[1]):])
    assert "@octocat" not in outside and "@team" not in outside and "#42" not in outside
    assert "<b>" not in outside and "<script>" not in outside and "``a`b.py:2``" in outside


# -------------------------------------------------------------------------------------------------------- ASFF

def test_asff_structure():
    meta = {**META, "aws_account_id": "123456789012", "aws_region": "eu-west-1"}
    items = json.loads(ex.export(sample() + [flow_finding(title="T" * 400, snippet="s" * 3000, file="long.py")],
                                 "asff", meta))
    assert isinstance(items, list) and len(items) == 5
    required = {"SchemaVersion", "Id", "ProductArn", "GeneratorId", "AwsAccountId", "CreatedAt", "UpdatedAt", "Title",
                "Description", "Resources"}
    known = required | {"Types", "Severity", "ProductFields", "RecordState", "Workflow", "VerificationState", "Remediation",
                        "Vulnerabilities", "SourceUrl"}
    for item in items:
        assert required <= set(item) <= known
        assert item["SchemaVersion"] == "2018-10-08" and item["AwsAccountId"] == "123456789012"
        assert item["ProductArn"] == "arn:aws:securityhub:eu-west-1:123456789012:product/123456789012/default"
        assert item["CreatedAt"] == item["UpdatedAt"] == "2026-03-04T05:06:07Z"
        assert 1 <= len(item["Title"]) <= 256 and 1 <= len(item["Description"]) <= 1024 and len(item["Id"]) <= 512
        assert item["Severity"]["Label"] in ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert item["Types"][0].count("/") == 2 and item["Types"][0].startswith("Software and Configuration Checks/")
        assert item["Resources"] and all(r["Type"] == "Other" and r["Id"] for r in item["Resources"])
        assert all(isinstance(v, str) and v for r in item["Resources"] for v in r["Details"]["Other"].values())
        assert len(item["ProductFields"]) <= 50 and all(isinstance(v, str) and len(v) <= 2048
                                                        for v in item["ProductFields"].values())
        assert item["Workflow"]["Status"] == "NEW" and item["RecordState"] == "ACTIVE"
        assert len(item.get("Remediation", {}).get("Recommendation", {}).get("Text", "")) <= 512
    assert len({i["Id"] for i in items}) == 5
    sqli = next(i for i in items if i["GeneratorId"] == "kashif/DF004" and i["Resources"][0]["Id"] == "shop/app/views.py")
    assert sqli["Vulnerabilities"] == [{"Id": "CWE-89", "CodeVulnerabilities": [{
        "FilePath": {"FileName": "views.py", "FilePath": "app/views.py", "StartLine": 11, "EndLine": 11},
        "Cwes": ["CWE-89"]}]}]
    assert sqli["Remediation"]["Recommendation"]["Url"].endswith("/89.html")
    web = next(i for i in items if i["GeneratorId"] == "kashif/HDR001")
    assert web["SourceUrl"] == "https://example.test/login" and web["Severity"]["Label"] == "INFORMATIONAL"
    assert "Vulnerabilities" not in web


def test_asff_needs_account_and_region_and_maps_triage():
    for meta in ({}, {"aws_account_id": "123", "aws_region": "eu-west-1"},
                 {"aws_account_id": "123456789012", "aws_region": "Europe"}):
        with pytest.raises(ex.ExportError):
            ex.export(sample(), "asff", meta)
    meta = {"aws_account_id": "123456789012", "aws_region": "us-gov-west-1"}
    items = json.loads(ex.export([flow_finding(extra={"triage": {"status": "false_positive"}}),
                                  flow_finding(file="b.py", extra={"triage": {"status": "fixed"}}),
                                  flow_finding(file="c.py", extra={"triage": {"status": "confirmed"}})], "asff", meta))
    by = {i["Resources"][0]["Details"]["Other"]["File"]: i for i in items}
    assert by["app/views.py"]["Workflow"]["Status"] == "SUPPRESSED"
    assert by["app/views.py"]["VerificationState"] == "FALSE_POSITIVE"
    assert by["b.py"]["Workflow"]["Status"] == "RESOLVED" and by["c.py"]["VerificationState"] == "TRUE_POSITIVE"
    assert items[0]["ProductArn"].startswith("arn:aws-us-gov:securityhub:us-gov-west-1:")


# -------------------------------------------------------------------------------------------------------- OCSF

def test_ocsf_vulnerability_finding():
    events = json.loads(ex.export(sample(), "ocsf", {**META, "lang": "ar"}))
    assert len(events) == 4
    for e in events:
        assert e["category_uid"] == 2 and e["class_uid"] == 2002 and e["activity_id"] in (1, 2, 3)
        assert e["type_uid"] == e["class_uid"] * 100 + e["activity_id"]
        assert e["severity_id"] in (1, 2, 3, 4, 5) and isinstance(e["time"], int) and e["time"] == 1772600767000
        assert e["metadata"]["version"] == "1.3.0" and e["metadata"]["product"]["vendor_name"]
        assert e["finding_info"]["uid"] and e["finding_info"]["title"]
        assert isinstance(e["vulnerabilities"], list) and len(e["vulnerabilities"]) == 1
        for code in e["vulnerabilities"][0].get("affected_code", []):
            assert code["file"]["name"] and code["file"]["type_id"] == 1
    sqli = next(e for e in events if e["finding_info"]["types"] == ["DF004"])
    vuln = sqli["vulnerabilities"][0]
    assert sqli["severity_id"] == 4 and sqli["severity"] == "High" and sqli["status_id"] == 1
    assert vuln["cwe"]["uid"] == "CWE-89" and "cve" not in vuln
    assert vuln["affected_code"] == [{"file": {"name": "views.py", "path": "app/views.py", "type_id": 1},
                                      "start_line": 11, "end_line": 11}]
    assert vuln["remediation"] == {"desc": AR_ADVICE} and sqli["finding_info"]["title"] == AR_TITLE
    assert sqli["unmapped"]["kashif_risk_score"] > 0
    closed = json.loads(ex.export([flow_finding(extra={"triage": {"status": "fixed"}})], "ocsf", META))[0]
    assert closed["activity_id"] == 3 and closed["type_uid"] == 200203 and closed["status_id"] == 4


# -------------------------------------------------------------------------------------------------- risk score

def score(f, **meta):
    return ex.risk_score(f, meta)["score"]


def test_risk_score_formula():
    r = ex.risk_score(flow_finding())
    # high 7.5 x injection 1.10 x proven flow 1.10 x entry point 1.05 x internal 1.00
    assert r["score"] == 9.5 and r["rating"] == "critical"
    assert r["vector"] == "KRS:1.0/S:H/C:INJ/E:P/R:E/X:N" and r["counted"] is True
    assert r["factors"] == {"severity_base": 7.5, "cwe_class": 1.1, "evidence": 1.1, "reachability": 1.05, "exposure": 1.0}
    pattern = Finding("X1", "high", "t", "t", "a.py", 1, "s", "a", "CWE-89")
    assert score(pattern) == 8.3                            # 8.25, halves round up
    assert score(Finding("X1", "high", "t", "t", "a.py", 1, "s", "a", "")) == 7.5
    assert score(Finding("X1", "high", "t", "t", "a.py", 1, "s", "a", "CWE-79")) == 7.1      # 7.5 x 0.95 = 7.125
    assert score(Finding("X1", "high", "t", "t", "a.py", 1, "s", "a", "CWE-209")) == 6.4     # 7.5 x 0.85 = 6.375


def test_risk_score_orders_findings_sensibly():
    base = score(flow_finding())
    assert score(flow_finding(extra={"audit": True})) < score(flow_finding(extra={})) < base
    assert score(flow_finding(file="tests/test_views.py")) < base
    assert score(flow_finding(file="src/app/views_test.go")) < base
    assert score(flow_finding(file="src/contest/latest.py")) == base         # "test" inside a word is not a test dir
    assert score(flow_finding(extra={"reachable": False, "path": []})) < score(flow_finding(extra={"path": []}))
    assert score(flow_finding(severity="medium"), exposure="local") < score(flow_finding(severity="medium")) \
        < score(flow_finding(severity="medium"), exposure="internet")
    sev = [score(Finding("X", s, "t", "t", "a.py", 1, "s", "a", "CWE-89")) for s in ("critical", "high", "medium", "low", "info")]
    assert sev == sorted(sev, reverse=True) and len(set(sev)) == 5
    assert all(0.0 <= ex.risk_score(f)["score"] <= 10.0 for f in sample())
    assert score(flow_finding(severity="critical"), exposure="internet") == 10.0
    assert score(flow_finding(extra={"triage": {"status": "false_positive"}})) == 0.0
    assert ex.risk_score(flow_finding(extra={"triage": {"status": "accepted_risk"}}))["counted"] is False
    with pytest.raises(ex.ExportError):
        ex.risk_score(flow_finding(), {"exposure": "moon"})


def test_project_risk():
    assert ex.project_risk([])["score"] == 0.0 and ex.project_risk([])["rating"] == "none"
    one = ex.project_risk([flow_finding(severity="medium")])
    assert one["score"] == ex.risk_score(flow_finding(severity="medium"))["score"]      # never below the worst finding
    lows = [Finding("L", "low", "t", "t", f"f{i}.py", 1, "s", "a", "") for i in range(200)]
    many = ex.project_risk(lows)
    assert 2.5 < many["score"] <= 10.0 and many["open_findings"] == 200
    assert ex.project_risk(lows[:5])["score"] < ex.project_risk(lows[:50])["score"]       # more findings, more risk
    report = ex.project_risk(sample())
    assert report["score"] >= max(r["score"] for r in report["findings"]) and report["rating"] == "critical"
    assert [r["score"] for r in report["findings"]] == sorted((r["score"] for r in report["findings"]), reverse=True)
    assert sum(report["by_rating"].values()) == report["open_findings"] == 4
    parked = ex.project_risk([flow_finding(extra={"triage": {"status": "accepted_risk"}})])
    assert parked["score"] == 0.0 and parked["open_findings"] == 0 and parked["findings"][0]["score"] > 0
    doc = json.loads(ex.export(sample(), "risk", {**META, "lang": "ar"}))
    assert doc["score"] == report["score"] and "CVSS" in doc["note"] and doc["project"] == "shop" and doc["formula"]
    assert ex.rating_label("critical", "ar") == "حرج" and ex.rating_label("none") == "None"


# --------------------------------------------------------------------------------------------------------- CLI

def write_report(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"target": "/srv/shop", "files_scanned": 3, "generated_at": META["generated_at"],
                                "findings": [f.to_dict() for f in sample()]}, ensure_ascii=False), encoding="utf-8")
    return path


def test_cli_writes_a_file(tmp_path, capsys):
    report, out = write_report(tmp_path), tmp_path / "out.json"
    assert ex.main([str(report), "-f", "defectdojo", "-o", str(out), "--lang", "ar", "--score"]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert len(doc["findings"]) == 4 and any(r["title"] == AR_TITLE for r in doc["findings"])
    err = capsys.readouterr().err
    assert "درجة خطر كاشِف" in err and "CVSS" in err
    csv_out = tmp_path / "out.csv"
    assert ex.main([str(report), "-f", "csv", "-o", str(csv_out), "--bom", "--min-severity", "high"]) == 0
    raw = csv_out.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf") and raw.count(b"\r\n") == 3 and b"\r\r\n" not in raw


def test_cli_stdout_list_and_errors(tmp_path, capsys):
    report = write_report(tmp_path)
    assert ex.main([str(report), "-f", "junit"]) == 0
    ET.fromstring(capsys.readouterr().out)
    assert ex.main(["--list-formats"]) == 0
    listing = capsys.readouterr().out
    assert all(fmt in listing for fmt in ex.FORMATS)
    assert ex.main([str(report), "-f", "asff"]) == 2 and "aws" in capsys.readouterr().err
    assert ex.main([str(report), "-f", "asff", "--aws-account", "123456789012", "--aws-region", "eu-west-1"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["AwsAccountId"] == "123456789012"
    assert ex.main([str(report), "-f", "nope"]) == 2
    assert ex.main([str(tmp_path / "missing.json"), "-f", "csv"]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text('{"x": 1}', encoding="utf-8")
    assert ex.main([str(bad), "-f", "csv"]) == 2
    assert ex.main([]) == 2
    capsys.readouterr()
    bare = tmp_path / "list.json"
    bare.write_text(json.dumps([f.to_dict() for f in sample()]), encoding="utf-8")
    assert ex.main([str(bare), "-f", "sonarqube"]) == 0 and json.loads(capsys.readouterr().out)["rules"]


def test_export_does_not_mutate_dict_findings():
    dicts = [f.to_dict() for f in sample()]
    before = json.dumps(dicts, sort_keys=True, ensure_ascii=False)
    for fmt in ex.FORMATS:
        ex.export(dicts, fmt, {"aws_account_id": "123456789012", "aws_region": "eu-west-1"})
    assert json.dumps(dicts, sort_keys=True, ensure_ascii=False) == before


# ------------------------------------------------------------------ adversarial review: hostile and malformed input

ASFF_META = {"aws_account_id": "123456789012", "aws_region": "eu-west-1"}
MALFORMED = [
    [{"rule_id": "a", "severity": "high", "line": float("inf")}],
    [{"rule_id": "a", "severity": "high", "line": float("nan")}],
    [{"rule_id": "a", "severity": "high", "line": -5}],
    [{"rule_id": "a", "severity": "high", "line": True}],
    [{"rule_id": "a", "severity": "high", "extra": {"path": 5}}],
    [{"rule_id": "a", "severity": "high", "extra": {"path": "abc"}}],
    [{"rule_id": ["a"], "severity": ["x"], "title": {"a": 1}, "file": 5, "cwe": ["CWE-1"], "title_ar": 5}],
    [{"snippet": 5, "advice": 7, "extra": {"path": [{"text": 5, "file": 3, "line": "x"}, None],
                                             "triage": {"status": [1]}, "taint_source": 4, "url": 9}}],
    [{}],
]


@pytest.mark.parametrize("findings", MALFORMED)
@pytest.mark.parametrize("when", ["0001-01-01T00:00:00+14:00", "9999-12-31T23:59:59-12:00", "not a date", 12, None])
def test_malformed_findings_and_dates_never_crash(findings, when):
    for fmt in ex.FORMATS:
        text = ex.export(findings, fmt, {**ASFF_META, "generated_at": when, "repo_url": "https://example.test/r"})
        assert text
        if fmt == "junit":
            ET.fromstring(text.split("\n", 1)[1])
        elif fmt.endswith("csv"):
            assert parse_csv(text)
        else:
            json.loads(text)


def test_line_numbers_are_bounded_and_never_negative():
    doc = json.loads(ex.export([{"rule_id": "a", "severity": "low", "file": "a.py", "line": 10 ** 30}], "defectdojo"))
    assert "line" not in doc["findings"][0]
    doc = json.loads(ex.export([{"rule_id": "a", "severity": "low", "file": "a.py", "line": "12"}], "defectdojo"))
    assert doc["findings"][0]["line"] == 12


def test_finding_object_with_unknown_severity_is_an_export_error():
    bad = Finding("X1", "catastrophic", "t", "t", "a.py", 1, "s", "a")
    with pytest.raises(ex.ExportError):
        ex.export([bad], "csv")


def test_cwe_is_written_only_in_canonical_form():
    hostile = "cwe-79](javascript:alert(1)) <img src=x>"
    f = flow_finding(cwe=hostile).to_dict()
    for fmt in ex.FORMATS:
        text = ex.export([f], fmt, {**ASFF_META, **META})
        assert "javascript:" not in text and "<img" not in text, fmt
    issue = json.loads(ex.export([f], "github-issues", META))[0]
    assert "CWE-79" in issue["labels"] and all(len(label) <= 50 for label in issue["labels"])
    assert "[CWE-79](https://cwe.mitre.org/data/definitions/79.html)" in issue["body"]
    assert json.loads(ex.export([{"rule_id": "a", "cwe": "none"}], "defectdojo"))["findings"][0].get("cwe") is None


@pytest.mark.parametrize("url", ["javascript:alert(1)", "data:text/html,x", "file:///etc/passwd", "//evil.test/x",
                                 "vbscript:x", " https://", "http://"])
def test_only_http_urls_become_links(url):
    f = {"rule_id": "WEB001", "severity": "medium", "title": "Header missing", "file": url, "source": "web",
         "extra": {"url": url}}
    for fmt in ("defectdojo", "github-issues", "jira-csv", "csv", "ocsf", "asff"):
        text = ex.export([f], fmt, {**ASFF_META, **META})
        doc = parse_csv(text) if fmt.endswith("csv") else json.loads(text)
        if fmt == "defectdojo":
            assert "references" not in doc["findings"][0]
        elif fmt == "ocsf":
            assert "references" not in doc[0]["vulnerabilities"][0]
        elif fmt == "asff":
            assert "SourceUrl" not in doc[0]
        elif fmt == "github-issues":
            assert "](" not in doc[0]["body"]
        elif fmt == "csv":
            assert doc[1][-1] == ""


def test_links_are_percent_encoded_and_cannot_break_out():
    f = flow_finding(file="app/a b)](https:evil.test) [x|y].py").to_dict()
    meta = {**META, "repo_url": "https://git.example.test/o/r", "ref": "feat/x y"}
    body = json.loads(ex.export([f], "github-issues", meta))[0]["body"]
    want = "https://git.example.test/o/r/blob/feat/x%20y/app/a%20b%29%5D%28https%3Aevil.test%29%20%5Bx%7Cy%5D.py#L11"
    assert f"]({want})" in body
    assert "`app/a b)](https:evil.test) [x|y].py:11`" in body and body.count("](https:evil.test)") == 1   # code span only
    row = parse_csv(ex.export([f], "jira-csv", meta))[1]
    assert f"[{want}]" in row[6]
    # a path that climbs out of the repository gets no link; neither does a non-http repo_url
    up = flow_finding(file="../../etc/passwd").to_dict()
    assert "/blob/" not in ex.export([up], "github-issues", meta)
    assert "/blob/" not in ex.export([f], "github-issues", {**META, "repo_url": "javascript:alert(1)//"})
    web = {"rule_id": "WEB001", "severity": "low", "title": "t", "file": "https://shop.test/a?q=(1) x",
           "source": "web"}
    assert json.loads(ex.export([web], "asff", ASFF_META))[0]["SourceUrl"] == "https://shop.test/a?q=%281%29%20x"


def test_markdown_prose_cannot_carry_links_images_or_code_spans():
    advice = "Fix it ![x](https://tracker.test/p.png) [click](https://evil.test) `code` & <b>"
    f = flow_finding(advice=advice).to_dict()
    f["advice_en"] = advice
    for fmt in ("github-issues", "defectdojo"):
        doc = json.loads(ex.export([f], fmt, META))
        body = doc[0]["body"] if fmt == "github-issues" else doc["findings"][0]["description"]
        assert "![x](" not in body and "[click](" not in body and "<b>" not in body
        assert "!\\[x\\](https://tracker.test/p.png) \\[click\\]" in body and "\\`code\\` &amp; &lt;b&gt;" in body


def test_titles_rule_ids_and_fingerprints_are_single_line_and_bounded():
    f = {"rule_id": "R1\nR2", "severity": "high", "title": "one\r\ntwo\tthree", "file": "a.py", "line": 1,
         "fingerprint": "abc\n{color:red}x{color}" + "f" * 5000,
         "extra": {"triage": {"status": "Confirmed"}}}
    issue = json.loads(ex.export([f], "github-issues"))[0]
    assert "\n" not in issue["title"] and "\r" not in issue["title"] and "one two three" in issue["title"]
    dd_row = json.loads(ex.export([f], "defectdojo"))["findings"][0]
    assert len(dd_row["unique_id_from_tool"]) <= 500 and "\n" not in dd_row["unique_id_from_tool"]
    assert dd_row["vuln_id_from_tool"] == "R1 R2" and dd_row["verified"] is True      # status is case-insensitive
    desc = parse_csv(ex.export([f], "jira-csv"))[1][6]
    assert "{color:red}" not in desc and "\\{color:red\\}" in desc


def test_defectdojo_values_fit_the_finding_columns():
    long = "x" * 6000
    f = flow_finding(rule_id=long, file="d/" + long + ".py").to_dict()
    f["extra"]["taint_source_en"] = long
    f["extra"]["path"][-1]["text_en"] = long
    row = json.loads(ex.export([f], "defectdojo"))["findings"][0]
    limits = {"unique_id_from_tool": 500, "vuln_id_from_tool": 500, "file_path": 4000, "sast_source_object": 500,
              "sast_sink_object": 500, "sast_source_file_path": 4000, "cve": 50}
    for key, limit in limits.items():
        assert len(row.get(key, "")) <= limit, key
    assert set(row) <= DD_KEYS


def test_jira_noformat_block_cannot_be_closed_by_the_snippet():
    f = flow_finding(snippet="x {NoFormat} {noformat:nopanel=true} h1. owned {code}").to_dict()
    desc = parse_csv(ex.export([f], "jira-csv", {"lang": "ar"}))[1][6]
    assert desc.count("{noformat}") == 2 and "{NoFormat}" not in desc and "{noformat:" not in desc


def test_sonarqube_leaves_out_false_positives_and_fixed_findings():
    def triaged(status, rule):
        d = flow_finding(rule_id=rule, line=5).to_dict()
        d["extra"]["triage"] = {"status": status}
        return d
    items = [triaged("false_positive", "FP1"), triaged("fixed", "FX1"), triaged("accepted_risk", "AR1"),
             flow_finding().to_dict()]
    doc = json.loads(ex.export(items, "sonarqube"))
    assert {r["id"] for r in doc["rules"]} == {"AR1", "DF004"} == {i["ruleId"] for i in doc["issues"]}
    legacy = json.loads(ex.export(items, "sonarqube-legacy"))
    assert {i["ruleId"] for i in legacy["issues"]} == {"AR1", "DF004"}


def test_ocsf_carries_cve_and_cwe_together():
    f = {"rule_id": "CVE-2024-12345", "severity": "high", "title": "lib", "file": "requirements.txt", "line": 2,
         "cwe": "CWE-502", "source": "osv"}
    vuln = json.loads(ex.export([f], "ocsf"))[0]["vulnerabilities"][0]
    assert vuln["cve"] == {"uid": "CVE-2024-12345"} and vuln["cwe"]["uid"] == "CWE-502"


def test_cli_reads_utf8_stdin_bytes_and_survives_hostile_json(tmp_path, capsys, monkeypatch):
    report = {"target": "t", "findings": [flow_finding().to_dict()]}
    raw = b"\xef\xbb\xbf" + json.dumps(report, ensure_ascii=False).encode("utf-8")

    class Stdin:
        buffer = io.BytesIO(raw)

        def read(self):                                    # the code-page text layer must not be used
            raise AssertionError("text-mode stdin was read")
    monkeypatch.setattr(ex.sys, "stdin", Stdin())
    assert ex.main(["-", "-f", "csv", "--lang", "ar"]) == 0
    assert AR_TITLE in capsys.readouterr().out

    deep = tmp_path / "deep.json"
    deep.write_text("[" * 200000, encoding="utf-8")
    assert ex.main([str(deep), "-f", "csv"]) == 2
    binary = tmp_path / "bin.json"
    binary.write_bytes(b"\xff\xfe\x00\x01")
    assert ex.main([str(binary), "-f", "csv"]) == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err and len(err) < 2000


def test_large_hostile_report_is_linear_time():
    import time
    big = "=cmd|' /C calc'!A0 `` ]] {noformat} " * 3000
    items = [{"rule_id": f"R{i}", "severity": "high", "title": big, "file": "a/" * 500 + f"f{i}_test.py", "line": i,
              "snippet": big, "advice": big, "extra": {"path": [{"file": "x.py", "line": 1, "text": big}] * 5}}
             for i in range(20)]
    start = time.monotonic()
    for fmt in ex.FORMATS:
        ex.export(items, fmt, ASFF_META)
    assert time.monotonic() - start < 90       # a quadratic path takes many minutes; shared CI runners are slow
