"""Kashif 1.1.0 web reports (WP15b, spec §4.5): JSON ``web`` object, SARIF precision/tags/run properties (checked
against the SARIF 2.1.0 schema rules that matter), HTML and Markdown sections (grades, coverage, inventory tabs,
copy-paste fixes with platform tabs, diff), hostile-text escaping, the confidence in the exports, 1.0.1 fingerprint
continuity, compliance coverage of every web CWE and the frozen-build data files.

Everything runs offline against servers on 127.0.0.1 started here.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from vulnscan import compliance, exporters, report
from vulnscan.model import Finding, assign_fingerprints
from vulnscan.web import scan_web

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
ARABIC = re.compile(r"[؀-ۿ]")
HOSTILE = '<script>alert("kashif-xss")</script>\x1b[31mRED\x1b[0m|`x`'


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    """No proxy, no real DNS (test-only resolver hook), no user web data, no user scan history."""
    for k in PROXY_VARS:
        monkeypatch.delenv(k, raising=False)
    rmap = tmp_path / "resolve.json"
    rmap.write_text(json.dumps({"version": 1, "hosts": {},
                                "default": {"status": "ok", "addresses": ["192.0.2.1"], "public": True}}),
                    encoding="utf-8")
    monkeypatch.setenv("KASHIF_TEST_RESOLVE", "1")
    monkeypatch.setenv("KASHIF_TEST_RESOLVE_MAP", str(rmap))
    monkeypatch.delenv("KASHIF_TEST_CAFILE", raising=False)
    monkeypatch.setenv("KASHIF_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VULNSCAN_HOME", str(tmp_path / "home"))
    from vulnscan.webscan import data
    data.clear_cache()
    yield
    data.clear_cache()


# ----------------------------------------------------------------------------------------------- local sites

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>{title}</title></head><body>
<h1>Shop</h1><form action="/login" method="post"><input name="user"><input type="password" name="pw"></form>
<script nonce="{nonce}">console.log(1)</script></body></html>"""


def _handler(headers: dict, title: str = "Shop", cookie: str | None = None):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path != "/":
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "9")
                self.end_headers()
                self.wfile.write(b"not found")
                return
            nonce = secrets.token_urlsafe(16)
            body = PAGE.format(title=title, nonce=nonce).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for k, v in headers.items():
                self.send_header(k, v.replace("{nonce}", nonce))
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(body)
    return H


def _serve(handler):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}/"


@pytest.fixture
def bare_site():
    httpd, url = _serve(_handler({}))
    yield url
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def csp_site():
    headers = {"Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
               "Server": "Apache/2.4.1 (Unix)", "X-Powered-By": "PHP/7.2.1"}
    httpd, url = _serve(_handler(headers, cookie="sessionid=0123456789abcdef0123456789abcdef; Path=/"))
    yield url
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def hostile_site():
    headers = {"Server": "nginx/1.2.3 " + HOSTILE.replace("\x1b", "\\e"), "X-Powered-By": HOSTILE.replace("\x1b", "")}
    httpd, url = _serve(_handler(headers, title=HOSTILE, cookie="sessionid=abc; Path=/"))
    yield url
    httpd.shutdown()
    httpd.server_close()


def _scan(url, **kw):
    kw.setdefault("delay", 0.2)
    kw.setdefault("timeout", 5)
    kw.setdefault("use_proxy", False)
    res = scan_web(url, **kw)
    assign_fingerprints(res.findings)
    return res, report.web_section(res, sensitivity=kw.get("sensitivity", "default"))


# ----------------------------------------------------------------------------------------------- SARIF schema

LEVELS = {"none", "note", "warning", "error"}
PRECISIONS = {"very-high", "high", "medium", "low"}


def _check_property_bag(bag, where):
    assert isinstance(bag, dict), where
    if "tags" in bag:
        tags = bag["tags"]
        assert isinstance(tags, list) and all(isinstance(t, str) for t in tags), where
        assert len(tags) == len(set(tags)), f"{where}: tags must be unique"


def _check_message(msg, where):
    assert isinstance(msg, dict) and (isinstance(msg.get("text"), str) or isinstance(msg.get("id"), str)), where


def validate_sarif_210(doc: dict) -> None:
    """The constraints of the OASIS SARIF 2.1.0 schema (sarif-schema-2.1.0.json) that apply to what Kashif writes:
    required properties, enumerations, value types, uniqueness of tags, property bags, and GitHub's conventions for
    ``security-severity`` (a string holding a number 0.0–10.0) and ``precision`` (very-high|high|medium|low)."""
    assert doc.get("version") == "2.1.0"
    assert isinstance(doc.get("$schema"), str) and doc["$schema"].startswith("https://")
    runs = doc.get("runs")
    assert isinstance(runs, list) and runs
    for run in runs:
        driver = run["tool"]["driver"]
        assert isinstance(driver.get("name"), str) and driver["name"]
        rule_ids = []
        for i, rule in enumerate(driver.get("rules") or []):
            where = f"rule {i}"
            assert isinstance(rule.get("id"), str) and rule["id"], where
            rule_ids.append(rule["id"])
            for key in ("shortDescription", "fullDescription"):
                if key in rule:
                    assert isinstance(rule[key].get("text"), str), where
            if "help" in rule:
                assert isinstance(rule["help"].get("text"), str), where
            if "helpUri" in rule:
                assert re.match(r"^[a-z][a-z0-9+.-]*:", rule["helpUri"]), where
            if "defaultConfiguration" in rule:
                assert rule["defaultConfiguration"].get("level", "warning") in LEVELS, where
            props = rule.get("properties", {})
            _check_property_bag(props, where)
            if "security-severity" in props:
                assert isinstance(props["security-severity"], str) and 0.0 <= float(props["security-severity"]) <= 10.0
            if "precision" in props:
                assert props["precision"] in PRECISIONS, where
            for rel in rule.get("relationships") or []:
                assert isinstance(rel["target"]["id"], str), where
        assert len(rule_ids) == len(set(rule_ids)), "rule ids must be unique"
        for i, res in enumerate(run.get("results") or []):
            where = f"result {i}"
            _check_message(res.get("message"), where)
            assert res.get("level", "warning") in LEVELS, where
            assert res.get("ruleId") in rule_ids, where
            for loc in res.get("locations") or []:
                art = loc["physicalLocation"]["artifactLocation"]
                assert isinstance(art.get("uri"), str) and art["uri"], where
                assert " " not in art["uri"], where
                region = loc["physicalLocation"].get("region")
                if region is not None:
                    assert region.get("startLine", 1) >= 1, where
            for k, v in (res.get("partialFingerprints") or {}).items():
                assert isinstance(k, str) and isinstance(v, str), where
            props = res.get("properties", {})
            _check_property_bag(props, where)
            if "precision" in props:
                assert props["precision"] in PRECISIONS, where
            for sup in res.get("suppressions") or []:
                assert sup["kind"] in ("inSource", "external"), where
        _check_property_bag(run.get("properties", {}), "run")


# ----------------------------------------------------------------------------------------------- reports

@pytest.fixture
def scanned(csp_site):
    res, web = _scan(csp_site)
    return res, web


def test_json_report_has_the_web_object(scanned):
    res, web = scanned
    doc = json.loads(report.render_json(res.findings, res.target, 1, res.notes, web=web))
    w = doc["web"]
    for key in ("profile", "grades", "coverage", "coverage_counts", "inventory", "notes", "snapshot", "diff"):
        assert key in w, key
    assert w["profile"] == "standard" and w["grades"]["kashif"]["grade"]
    states = {c["state"] for c in w["coverage"]}
    assert states <= {"pass", "fail", "not_applicable", "not_tested", "inconclusive"} and "fail" in states
    assert all(isinstance(c["rules"], list) and c["rules"] for c in w["coverage"])
    assert all(f["extra"]["confidence"] in ("certain", "firm", "tentative") for f in doc["findings"])
    # notes_en are the engine's own English (never a half-translated Arabic line)
    assert doc["notes_en"] and not any(ARABIC.search(n) for n in doc["notes_en"])
    # the bench scorer reads the coverage by rule id
    assert any(c["check"] == "WEB-x-frame-options" or "WEB-x-frame-options" in c["rules"] for c in w["coverage"])


def test_sarif_validates_and_carries_precision_tags_and_grades(scanned):
    res, web = scanned
    doc = json.loads(report.render_sarif(res.findings, res.target, 1, res.notes, web=web))
    validate_sarif_210(doc)
    run = doc["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert rules and all(r["properties"].get("precision") in PRECISIONS for r in rules.values())
    csp = rules["WEB040"]["properties"]
    assert "external/cwe/cwe-693" in csp["tags"] or any(t.startswith("external/cwe/cwe-") for t in csp["tags"])
    assert any(t.startswith("wstg:WSTG-") for t in csp["tags"])
    assert any(t.startswith("asvs4:") for t in csp["tags"]) and any(t.startswith("asvs5:") for t in csp["tags"])
    sev = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}
    for r in run["results"]:
        assert r["properties"]["precision"] == report.SARIF_PRECISION[r["properties"]["confidence"]]
        assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("http://127.0.0.1:")
        first = next(x for x in run["results"] if x["ruleId"] == r["ruleId"])
        assert rules[r["ruleId"]]["properties"]["security-severity"] == sev[first["properties"]["severity"]]
    props = run["properties"]
    assert props["grades"]["kashif"]["grade"] == web["grades"]["kashif"]["grade"]
    assert props["grades"]["observatory"]["score"] == web["grades"]["observatory"]["score"]
    assert set(props["coverage"]["counts"]) == {"pass", "fail", "not_applicable", "not_tested", "inconclusive"}
    assert props["webProfile"] == "standard"
    # the English run has no Arabic at all
    en = report.render_sarif(res.findings, res.target, 1, res.notes, lang="en", web=web)
    assert not ARABIC.search(en)
    validate_sarif_210(json.loads(en))


def test_sarif_without_web_is_unchanged_for_source_scans():
    f = Finding("PY001", "high", "Command injection", "حقن أوامر", "a.py", 3, "os.system(x)", "لا تمرر المدخلات", "CWE-78")
    doc = json.loads(report.render_sarif([f], ".", 1, []))
    validate_sarif_210(doc)
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert "precision" not in rule["properties"] and "grades" not in doc["runs"][0]["properties"]


@pytest.mark.parametrize("lang", ["ar", "en", "both"])
def test_html_report_has_every_web_section(scanned, lang):
    res, web = scanned
    html = report.render_html(res.findings, res.target, 1, res.notes, lang=lang, web=web)
    L = report._Lang(lang)
    for key in ("grades", "coverage", "inventory", "remediation"):
        assert report._wl(L, key) in html, key
    for tab in report.INVENTORY_TABS:
        assert f">{report._wl(L, 't_' + tab)}</bdi></label>" in html, tab     # tab names are isolates ("ASP.NET Core 8+")
    assert "<input type='radio' name='inv'" in html and "name='rem0'" in html      # CSS tabs: inventory, platforms
    assert "<script" not in html                                                     # no script at all
    assert f"<th>{report._wl(L, 'confidence')}</th>" in html
    assert ("dir=\"rtl\"" in html) == (lang != "en")
    if lang == "en":
        assert not ARABIC.search(html)


@pytest.mark.parametrize("lang", ["ar", "en"])
def test_markdown_report_has_every_web_section(scanned, lang):
    res, web = scanned
    md = report.render_markdown(res.findings, res.target, 1, res.notes, lang=lang, web=web)
    L = report._Lang(lang)
    for key in ("web_summary", "grades", "coverage", "inventory", "remediation", "confidence"):
        assert report._wl(L, key) in md, key
    for tab in report.INVENTORY_TABS:
        assert f"### {report._wl(L, 't_' + tab)}" in md, tab
    assert "```nginx" in md or "```apache" in md                                    # platform snippets
    if lang == "en":
        assert not ARABIC.search(md)


def test_diff_section_after_a_second_scan(csp_site):
    first, _ = _scan(csp_site)
    second, web = _scan(csp_site, previous=first.snapshot)
    assert web["diff"]["comparable"] is True
    assert web["diff"]["counts"]["unchanged"] >= 1 and web["diff"]["counts"]["new"] == 0
    for lang in ("ar", "en"):
        L = report._Lang(lang)
        html = report.render_html(second.findings, second.target, 1, second.notes, lang=lang, web=web)
        md = report.render_markdown(second.findings, second.target, 1, second.notes, lang=lang, web=web)
        for text in (html, md):
            assert report._wl(L, "diff") in text and report._wl(L, "d_new") in text and report._wl(L, "d_resolved") in text
    console = report.render_console(second.findings, second.target, 1, second.notes, color=False, lang="en", web=web)
    assert "Compared with the previous scan" in console


def test_hostile_text_is_escaped_in_every_report(hostile_site):
    res, web = _scan(hostile_site)
    html = report.render_html(res.findings, res.target, 1, res.notes, lang="en", web=web)
    md = report.render_markdown(res.findings, res.target, 1, res.notes, lang="en", web=web)
    console = report.render_console(res.findings, res.target, 1, res.notes, color=False, lang="en", web=web)
    for text in (html, md):
        assert '<script>alert("kashif-xss")' not in text
    for text in (html, md, console):                # the terminal: no control characters or ANSI sequences
        assert "\x1b" not in text
    assert "&lt;script&gt;" in html
    view = report.web_view(res.findings, web, "en")
    blob = json.dumps(view)
    assert "\\u001b" not in blob


def test_untrusted_inventory_values_cannot_break_markdown_tables():
    web = {"grades": {}, "coverage": [], "coverage_counts": {}, "inventory": {
        "security_headers": [{"url": "https://x/", "headers": {"X-Test": {"value": "a|b\n| c `d` <img src=x>",
                                                                           "verdict": "present"}}}],
        "cookies": [{"name": "c|o\x1b[2Jokie", "host": "x", "class": "unknown"}]}, "notes": []}
    md = "\n".join(report._web_markdown([], web, report._Lang("en"), "bottom"))
    row = next(line for line in md.splitlines() if "X-Test" in line)
    assert row.count(" | ") == 3 and "<img" not in row and "\x1b" not in md
    assert "c\\|o" in md


def test_json_and_sarif_escape_c1_controls_from_the_target():
    # §0.6: json.dumps(ensure_ascii=False) escapes C0 only, so a site's "\x9b" (8-bit CSI) reached the terminal raw on
    # `-f json`/`-f sarif` to stdout; it is written as \u009b now and parses back to the same value
    hostile = "nginx/1.0 \x9b2J\x9d0;title\x07 \x85 \u00e9 \u0639"
    f = Finding("WEB-x-powered-by", "low", hostile, "عنوان " + hostile, "http://x/", 0, hostile, "fix", "CWE-200")
    for text in (report.render_json([f], "http://x/", 1, [hostile]), report.render_sarif([f], "http://x/", 1, [hostile])):
        assert not re.search("[\x80-\x9f]", text)
        assert "\\u009b2J" in text and "\u00e9" in text and "\u0639" in text      # other text stays readable
        doc = json.loads(text)
        notes = doc["notes"] if "notes" in doc else doc["runs"][0]["properties"]["notes"]
        assert notes == [hostile]                                                   # the parsed value is unchanged


def test_reports_without_web_are_byte_identical_to_the_1_0_layout():
    f = Finding("PY001", "high", "Command injection", "حقن أوامر", "a.py", 3, "os.system(x)", "لا تمرر المدخلات", "CWE-78")
    for render in (report.render_markdown, report.render_html):
        assert render([f], ".", 1, ["n"], lang="en") == render([f], ".", 1, ["n"], lang="en", web=None)
    assert "web" not in json.loads(report.render_json([f], ".", 1, []))


# ----------------------------------------------------------------------------------------------- exports

def test_exports_carry_the_confidence(scanned):
    res, _web = scanned
    csv_text = exporters.export(res.findings, "csv", {"target": res.target})
    header = csv_text.splitlines()[0].lstrip("﻿").split(",")
    assert header[-1] == exporters._t("en", "confidence")
    assert any(line.endswith((",certain", ",firm", ",tentative")) for line in csv_text.splitlines()[1:])
    ar = exporters.export(res.findings, "csv", {"target": res.target, "lang": "ar"})
    assert "الثقة" in ar.splitlines()[0]
    asff = json.loads(exporters.export(res.findings, "asff", {"target": res.target, "aws_account_id": "123456789012",
                                                              "aws_region": "eu-west-1"}))
    assert all(item["Confidence"] in (100, 75, 25) for item in asff)
    issues = json.loads(exporters.export(res.findings, "github-issues", {"target": res.target}))
    assert all("**Confidence:**" in i["body"] and "passive web scan" in i["body"] for i in issues)


def test_source_findings_have_no_confidence_in_exports():
    f = Finding("PY001", "high", "Command injection", "حقن أوامر", "a.py", 3, "os.system(x)", "لا تمرر المدخلات", "CWE-78")
    rows = exporters.export([f], "csv", {}).splitlines()
    assert rows[1].endswith(",")
    asff = json.loads(exporters.export([f], "asff", {"aws_account_id": "123456789012", "aws_region": "eu-west-1"}))
    assert "Confidence" not in asff[0]


# ----------------------------------------------------------------------------------------------- fingerprints

def fingerprint_102(rule: str, title: str, file: str, snippet: str) -> str:
    """``Finding.base_fingerprint`` of Kashif 1.0.2 for a web finding (copied from vulnscan/model.py of 1.0.2)."""
    title = re.sub(r"\b\d+ days\b", "N days", title)
    if rule in ("WEB020", "WEB021", "WEB022"):
        snippet = title
    else:
        snippet = title + "|" + re.sub(r"=[^&;\s\"']*", "=", re.sub(r"\bHTTP \d{3}\b", "HTTP", snippet))
    norm = re.sub(r"\s+", "", snippet).lower()
    return hashlib.sha256(f"{rule}\x00{file}\x00{norm}".encode("utf-8", "replace")).hexdigest()[:16]


def test_unchanged_1_0_header_findings_keep_their_fingerprints(bare_site, csp_site):
    """What 1.0.1/1.0.2 reported on these two sites (title, file = host:port, snippet), and the fingerprints 1.0.2
    gave them: the 1.1.0 findings for the same issues must have the same fingerprint, so baselines and triage
    decisions taken on 1.0.x stay valid."""
    res, _ = _scan(bare_site, profile="minimal")
    label = bare_site.split("//")[1].rstrip("/")
    old = {"WEB-content-security-policy": ("Missing Content-Security-Policy", "HTTP 200"),
           "WEB-x-content-type-options": ("Missing X-Content-Type-Options", "HTTP 200"),
           "WEB-x-frame-options": ("Missing X-Frame-Options / frame-ancestors", "HTTP 200"),
           "WEB-referrer-policy": ("Missing Referrer-Policy", "HTTP 200"),
           "WEB-permissions-policy": ("Missing Permissions-Policy", "HTTP 200")}
    got = {f.rule_id: f for f in res.findings}
    assert set(old) <= set(got), sorted(set(old) - set(got))
    for rule, (title, snippet) in old.items():
        assert got[rule].base_fingerprint() == fingerprint_102(rule, title, label, snippet), rule
    res2, _ = _scan(csp_site, profile="minimal")
    label2 = csp_site.split("//")[1].rstrip("/")
    csp = "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
    old2 = {"WEB040": ("CSP allows 'unsafe-inline' scripts", "script-src 'unsafe-inline'"),
            "WEB041": ("CSP allows 'unsafe-eval'", "script-src 'unsafe-eval'"),
            "WEB043": ("CSP missing object-src 'none'", csp),
            "WEB021": ("Cookie without HttpOnly flag: sessionid", "sessionid=…"),
            "WEB022": ("Cookie without SameSite: sessionid", "sessionid=…"),
            "WEB010": ("Server header reveals version: Apache/2.4.1 (Unix)", "Apache/2.4.1 (Unix)"),
            "WEB011": ("X-Powered-By reveals stack: PHP/7.2.1", "PHP/7.2.1")}
    got2 = {f.rule_id: f for f in res2.findings}
    for rule, (title, snippet) in old2.items():
        assert rule in got2, rule
        assert got2[rule].base_fingerprint() == fingerprint_102(rule, title, label2, snippet), rule


def test_new_web_findings_fingerprint_on_fp_key_and_survive_reruns(csp_site):
    a, _ = _scan(csp_site)
    b, _ = _scan(csp_site)              # a fresh nonce on every response
    fa = {f.rule_id: f.fingerprint() for f in a.findings}
    fb = {f.rule_id: f.fingerprint() for f in b.findings}
    assert fa == fb
    f = next(x for x in a.findings if x.rule_id not in report.__dict__.get("_x", ()) and x.extra.get("fp_key")
             and x.rule_id.startswith("WEB2"))
    clone = Finding(f.rule_id, f.severity, f.title, f.title_ar, f.file, 0, "a different snippet 2026-01-01", f.advice,
                    f.cwe, "web", dict(f.extra))
    assert clone.base_fingerprint() == f.base_fingerprint()
    other = Finding(f.rule_id, f.severity, f.title, f.title_ar, f.file, 0, f.snippet, f.advice, f.cwe, "web",
                    {**f.extra, "fp_key": f.extra["fp_key"] + "x"})
    assert other.base_fingerprint() != f.base_fingerprint()


def test_cookie_rules_include_the_1_1_cookie_family():
    from vulnscan.model import _COOKIE_RULES
    assert {"WEB020", "WEB021", "WEB022"} <= _COOKIE_RULES
    assert {f"WEB{n}" for n in range(400, 415)} <= _COOKIE_RULES


# ----------------------------------------------------------------------------------------------- compliance

def _web_cwes() -> set[str]:
    from vulnscan.webscan.rules import RULES
    out = set()
    for meta in RULES.values():
        for cwe in (meta.cwe, *meta.cwe_variants):
            out.update(re.findall(r"CWE-(\d+)", cwe or ""))
    return out


def test_every_web_cwe_is_covered_by_the_compliance_data():
    cwes = _web_cwes()
    assert {"497", "525", "693", "942", "1021", "1275", "1395"} <= cwes
    assert compliance.coverage_gaps([f"CWE-{c}" for c in cwes]) == []
    emitted = compliance.emitted_cwes()
    assert cwes <= set(emitted)
    na = compliance.load_data()["frameworks"]["owasp-top10-2021"].get("cwe_na", {})
    for c in cwes:
        m = compliance.map_cwe(c)
        assert m["owasp-top10-2021"] or c in na, c                     # a control, or a documented exclusion
        assert compliance.categories({"cwe": f"CWE-{c}"}) != ["other"], c
    data = compliance.load_data()
    assert any(r.get("prefix") == "WEB" for r in data["rules"])          # the WEB prefix rule stays


def test_explain_finding_shows_the_analyst_mapping(scanned):
    res, _ = scanned
    f = next(x for x in res.findings if x.extra.get("asvs4"))
    d = f.to_dict()
    ex = compliance.explain_finding(d)
    rows = ex["kashif-analyst"]
    assert rows and all(r["detail"] == "Kashif analyst mapping" and r["source"] == "kashif-analyst" for r in rows)
    assert {r["title"] for r in rows} <= {"OWASP WSTG 4.2", "OWASP ASVS 4.0.3", "OWASP ASVS 5.0.0"}
    controls = {r["control"] for r in ex["owasp-asvs-4.0.3"]}
    assert {f"V{a}" for a in f.extra["asvs4"]} <= controls            # official or, failing that, the analyst row
    synthetic = dict(d, cwe="", extra={**d["extra"], "asvs4": ["14.4.7"]})
    rows4 = [r for r in compliance.explain_finding(synthetic)["owasp-asvs-4.0.3"] if r["control"] == "V14.4.7"]
    assert rows4 and rows4[0]["basis"] == "analyst" and rows4[0]["detail"] == "Kashif analyst mapping"
    ar = compliance.explain_finding(d, lang="ar")["kashif-analyst"]
    assert ar[0]["detail"] == "ربط محللي كاشِف"
    html = compliance.render_html([d], {"target": res.target}, lang="en")
    assert "Kashif analyst mapping" in html and "OWASP WSTG 4.2" in html
    assert f'href="{f.extra["url"]}"' not in html                         # the scanned page is text, not a link
    # findings of a source scan are unchanged
    src = {"rule_id": "PY001", "severity": "high", "cwe": "CWE-78", "file": "a.py", "line": 1, "extra": {}}
    assert "kashif-analyst" not in compliance.explain_finding(src)


# ----------------------------------------------------------------------------------------------- frozen build

def test_frozen_build_and_package_data_include_the_web_data():
    spec = (ROOT / "vulnscan.spec").read_text(encoding="utf-8")
    head = spec[:spec.index("a = Analysis(")]
    import os
    cwd = os.getcwd()
    try:
        os.chdir(ROOT)
        ns: dict = {}
        exec(compile(head, "vulnscan.spec", "exec"), ns)          # noqa: S102 - the repository's own build file
    finally:
        os.chdir(cwd)
    datas = {(src.replace("\\", "/"), dest) for src, dest in ns["datas"]}
    web_files = sorted(p for p in (ROOT / "vulnscan" / "data" / "web").iterdir() if p.is_file())
    assert web_files
    for p in web_files:
        rel = p.relative_to(ROOT).as_posix()
        assert (rel, "vulnscan/data/web") in datas, rel
    assert not any(pathlib.Path(ROOT / src).is_dir() for src, _ in datas), "a directory would be flattened"
    for mod in ("vulnscan.webscan.engine", "vulnscan.webscan.http", "vulnscan.webscan.tls", "vulnscan.i18n.cat_web2"):
        assert mod in ns["ALL_MODULES"] or mod in ns["EXPLICIT"], mod
    toml = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'vulnscan = \[[^\]]*"data/web/\*"', toml)
