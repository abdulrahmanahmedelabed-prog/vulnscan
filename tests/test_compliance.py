"""Compliance mapping (vulnscan/compliance.py + vulnscan/data/compliance.json)."""

import csv
import io
import json
import re

import pytest

from vulnscan import compliance as C
from vulnscan.model import Finding


def _f(rule="INJ001", sev="high", cwe="CWE-89", file="app/db.py", line=12, **kw):
    d = {"rule_id": rule, "severity": sev, "title": "SQL built from input", "title_ar": "استعلام SQL من مدخلات",
         "file": file, "line": line, "snippet": "cur.execute(q + name)", "advice": "استخدم استعلامات مُعلَّمة.",
         "advice_en": "Use parameterized queries.", "cwe": cwe, "source": "vulnscan", "extra": {},
         "fingerprint": "abc123:0"}
    d.update(kw)
    return d


FLOW = {"analysis": "dataflow", "taint_source": "request.args", "taint_source_en": "request.args",
        "path": [{"file": "app/views.py", "line": 7, "text": "name = request.args", "text_en": "name = request.args"},
                 {"file": "app/db.py", "line": 12, "text": "نقطة الخطر: SQL", "text_en": "Sink: SQL"}]}


# ---------------------------------------------------------------- data integrity

def test_data_is_consistent():
    data = C.load_data()
    assert set(data["frameworks"]) == set(C.FRAMEWORKS)
    for fid, fw in data["frameworks"].items():
        assert fw["source"] in data["sources"], fid
        assert data["sources"][fw["source"]]["title"]
        controls = fw["controls"]
        assert controls, fid
        for cwe, ctrls in fw["cwe"].items():
            assert cwe.isdigit() and set(ctrls) <= set(controls), (fid, cwe)
        for cwe, entry in fw["cwe_analyst"].items():
            assert cwe.isdigit() and set(entry["controls"]) <= set(controls) and entry["note"], (fid, cwe)
        for cwe, why in fw["cwe_na"].items():
            assert cwe.isdigit() and why and cwe not in fw["cwe"], (fid, cwe)
        for cat, ctrls in fw["category"].items():
            assert cat in data["categories"] and set(ctrls) <= set(controls), (fid, cat)
        assert set(fw.get("all", [])) <= set(controls)
    for cwe, cats in data["cwe_category"].items():
        assert cwe.isdigit() and cats and set(cats) <= set(data["categories"]), cwe
    for cat in data["categories"].values():
        assert cat["title"] and cat["title_ar"]


def test_every_framework_names_its_source_and_analyst_mappings_are_labelled():
    for fid in C.FRAMEWORKS:
        info = C.framework_info(fid)
        assert info["source"]["title"] and info["title"]
    # frameworks whose owners publish no CWE mapping must say so
    for fid in ("pci-dss-4.0", "nist-800-53r5", "iso-27001-2022", "hipaa-164.312", "nist-ssdf-1.1"):
        assert "analyst" in C.framework_info(fid)["note"].lower()
        rows = C.explain_finding(_f(cwe="CWE-287"), fid)[fid]
        assert rows and all(r["source"] == "kashif-analyst" for r in rows if r["basis"] == "category")


def test_top25_2024_list():
    fw = C.load_data()["frameworks"]["cwe-top25-2024"]
    assert len(fw["controls"]) == 25
    ranks = {c: v["rank"] for c, v in fw["controls"].items()}
    assert sorted(ranks.values()) == list(range(1, 26))
    assert ranks["CWE-79"] == 1 and ranks["CWE-787"] == 2 and ranks["CWE-89"] == 3 and ranks["CWE-306"] == 25


def test_owasp_top10_official_lists():
    ow = C.load_data()["frameworks"]["owasp-top10-2021"]["cwe"]
    assert len(ow) == 196                       # distinct CWEs in the ten "List of Mapped CWEs"
    assert ow["259"] == ["A02", "A07"]          # the only CWE OWASP lists in two categories
    expect = {"22": "A01", "200": "A01", "352": "A01", "601": "A01", "862": "A01", "319": "A02", "327": "A02",
              "338": "A02", "79": "A03", "89": "A03", "78": "A03", "94": "A03", "209": "A04", "256": "A04",
              "434": "A04", "501": "A04", "1021": "A04", "611": "A05", "614": "A05", "942": "A05", "1104": "A06",
              "287": "A07", "295": "A07", "306": "A07", "384": "A07", "798": "A07", "494": "A08", "502": "A08",
              "829": "A08", "117": "A09", "532": "A09", "778": "A09", "918": "A10"}
    for cwe, cat in expect.items():
        assert ow[cwe] == [cat], cwe


# ---------------------------------------------------------------- coverage of the engine

def test_every_emitted_cwe_is_mapped():
    """Fails when a rule, model, query, web check or APEX check emits a CWE the compliance data does not cover.
    Fix: add the CWE to "cwe_category" in vulnscan/data/compliance.json, and to "cwe_analyst" or "cwe_na" of
    owasp-top10-2021 when OWASP does not list it (or one of its parents)."""
    emitted = C.emitted_cwes()
    assert len(emitted) >= 80 and {"89", "79", "78", "22", "798", "1427"} <= set(emitted)
    gaps = C.coverage_gaps()
    assert not gaps, "unmapped CWEs: " + "; ".join(f"{g['cwe']} ({g['why']}) in {', '.join(g['where'])}" for g in gaps)


def test_emitted_cwes_cover_named_origins():
    emitted = C.emitted_cwes()
    origins = {w for where in emitted.values() for w in where}
    assert "rules.RULES" in origins and "web.py" in origins and "apex_export.py" in origins
    assert any(o.startswith("models/") for o in origins) and any(o.startswith("queries/") for o in origins)


def test_every_emitted_cwe_reaches_the_category_frameworks():
    for cwe in C.emitted_cwes():
        m = C.map_cwe(cwe)
        assert C.categories({"cwe": f"CWE-{cwe}"}) != ["other"], cwe
        for fid in ("pci-dss-4.0", "nist-800-53r5", "nist-ssdf-1.1", "gdpr-art32"):
            assert m[fid], (cwe, fid)
        # more than the generic controls: the category must lead somewhere in NIST 800-53
        assert set(m["nist-800-53r5"]) - {"SA-11", "SA-11(1)"}, cwe


def test_coverage_gap_is_reported_for_unknown_cwe():
    gaps = C.coverage_gaps(["CWE-99999"])
    assert gaps and gaps[0]["cwe"] == "CWE-99999" and "category" in gaps[0]["why"]


# ---------------------------------------------------------------- mapping

def test_map_finding_sql_injection():
    m = C.map_finding(_f())
    assert set(m) == set(C.FRAMEWORKS)
    assert m["owasp-top10-2021"] == ["A03"]
    assert m["owasp-asvs-4.0.3"] == ["V5.3.4", "V5.3.5"]
    assert m["cwe-top25-2024"] == ["CWE-89"]
    assert "6.2.4-injection" in m["pci-dss-4.0"]
    assert "SI-10" in m["nist-800-53r5"] and "SA-11" in m["nist-800-53r5"]
    assert "A.8.28" in m["iso-27001-2022"]
    assert "PW.5.1" in m["nist-ssdf-1.1"]
    assert m["hipaa-164.312"] == []              # injection is not tied to a HIPAA technical safeguard
    assert m["gdpr-art32"] == ["Art.32(1)(b)"]


@pytest.mark.parametrize("cwe, fw, control", [
    ("CWE-798", "pci-dss-4.0", "8.6.2"), ("CWE-798", "nist-800-53r5", "IA-5(7)"), ("CWE-798", "iso-27001-2022", "A.5.17"),
    ("CWE-319", "pci-dss-4.0", "4.2.1"), ("CWE-319", "nist-800-53r5", "SC-8"), ("CWE-319", "hipaa-164.312", "164.312(e)(1)"),
    ("CWE-295", "nist-800-53r5", "SC-8"), ("CWE-327", "iso-27001-2022", "A.8.24"), ("CWE-327", "pci-dss-4.0", "6.2.4-crypto"),
    ("CWE-327", "gdpr-art32", "Art.32(1)(a)"), ("CWE-16", "iso-27001-2022", "A.8.9"), ("CWE-16", "nist-800-53r5", "CM-6"),
    ("CWE-306", "pci-dss-4.0", "8.3.1"), ("CWE-306", "hipaa-164.312", "164.312(d)"), ("CWE-862", "hipaa-164.312", "164.312(a)(1)"),
    ("CWE-862", "nist-800-53r5", "AC-3"), ("CWE-778", "hipaa-164.312", "164.312(b)"), ("CWE-778", "pci-dss-4.0", "10.2.1"),
    ("CWE-1395", "owasp-top10-2021", "A06"), ("CWE-1395", "pci-dss-4.0", "6.3.3"), ("CWE-1395", "nist-800-53r5", "SI-2"),
    ("CWE-1104", "nist-800-53r5", "SA-22"), ("CWE-353", "pci-dss-4.0", "6.4.3"), ("CWE-918", "owasp-api-2023", "API7"),
    ("CWE-639", "owasp-api-2023", "API1"), ("CWE-770", "owasp-api-2023", "API4"), ("CWE-79", "pci-dss-4.0", "6.2.4-logic"),
    ("CWE-120", "nist-800-53r5", "SI-16"), ("CWE-256", "pci-dss-4.0", "8.3.2"), ("CWE-489", "owasp-asvs-4.0.3", "V14.3.2"),
    ("CWE-1427", "owasp-top10-2021", "A03"), ("CWE-502", "owasp-top10-2021", "A08"), ("CWE-611", "owasp-asvs-4.0.3", "V5.5.2"),
])
def test_specific_mappings(cwe, fw, control):
    assert control in C.map_cwe(cwe)[fw]


def test_basis_official_inherited_analyst_category_generic():
    ex = C.explain_finding(_f(cwe="CWE-89"))
    assert ex["owasp-top10-2021"] == [{"control": "A03", "basis": "official", "detail": "CWE-89",
                                       "title": "A03:2021 Injection", "source": "owasp-top10-2021"}]
    inh = C.explain_finding(_f(cwe="CWE-36"), "owasp")["owasp-top10-2021"]
    assert [(r["control"], r["basis"], r["detail"]) for r in inh] == [("A01", "inherited", "CWE-22")]
    assert "cwe-hierarchy" in inh[0]["source"]
    an = C.explain_finding(_f(cwe="CWE-1395"), "owasp")["owasp-top10-2021"][0]
    assert an["basis"] == "analyst" and an["source"] == "kashif-analyst" and an["detail"]
    by = {r["control"]: r["basis"] for r in C.explain_finding(_f(cwe="CWE-89"), "nist")["nist-800-53r5"]}
    assert by["SI-10"] == "category" and by["SA-11"] == "generic"
    top = C.explain_finding(_f(cwe="CWE-564"), "top25")["cwe-top25-2024"]      # Hibernate SQLi is a child of CWE-89
    assert [(r["control"], r["basis"]) for r in top] == [("CWE-89", "inherited")]


def test_documented_exclusions_are_not_mapped():
    assert C.map_cwe("CWE-1333")["owasp-top10-2021"] == []        # ReDoS: no Top 10 2021 category
    assert C.map_cwe("CWE-400")["owasp-top10-2021"] == []
    assert C.map_cwe("CWE-120")["owasp-top10-2021"] == []
    assert C.map_cwe("CWE-400")["owasp-api-2023"] == ["API4"]
    assert C.map_cwe("CWE-200")["owasp-api-2023"] == []


def test_cwe_field_forms_and_rule_fallback():
    assert C.cwe_ids({"cwe": "CWE-79, cwe-089"}) == ["79", "89"]
    assert C.cwe_ids({"cwe": "CWE-22: Path Traversal"}) == ["22"]
    assert C.cwe_ids({"cwe": "", "rule_id": "OSV:GHSA-xxxx"}) == ["1395"]
    assert C.map_finding({"rule_id": "npm:lodash", "cwe": ""})["owasp-top10-2021"] == ["A06"]
    assert C.map_finding({"rule_id": "gitleaks:generic", "cwe": ""}, "pci")["pci-dss-4.0"][0] == "8.6.2"
    both = C.map_finding(_f(cwe="CWE-79,CWE-89"))["owasp-asvs-4.0.3"]
    assert "V5.3.3" in both and "V5.3.4" in both
    assert "6.4.1" in C.map_finding({"rule_id": "WEB-Strict-Transport-Security", "cwe": "CWE-319"})["pci-dss-4.0"]
    assert C.map_cwe(89) == C.map_cwe("89") == C.map_cwe("CWE-89")


def test_unknown_finding_gets_only_generic_controls():
    m = C.map_finding({"rule_id": "custom-thing", "cwe": ""})
    assert m["owasp-top10-2021"] == [] and m["owasp-asvs-4.0.3"] == [] and m["hipaa-164.312"] == []
    assert m["nist-800-53r5"] == ["SA-11"]
    assert C.categories({"rule_id": "custom-thing"}) == ["other"]
    assert C.control_labels({"rule_id": "custom-thing", "cwe": ""}) == []


def test_accepts_finding_objects_and_selects_frameworks():
    f = Finding("INJ001", "high", "SQL", "حقن", "a.py", 3, "x", "نصيحة", "CWE-89")
    assert C.map_finding(f, ["owasp", "pci"]).keys() == {"owasp-top10-2021", "pci-dss-4.0"}
    assert C.map_finding(f, "asvs,top25").keys() == {"owasp-asvs-4.0.3", "cwe-top25-2024"}
    assert C.resolve_framework("ISO27001") == "iso-27001-2022" and C.resolve_framework("nope") is None
    with pytest.raises(ValueError):
        C.map_finding(f, ["nope"])
    with pytest.raises(TypeError):
        C.map_finding("not a finding")
    assert "OWASP Top 10 A03" in C.control_labels(f)
    assert "owasp-top10-2021/A03" in C.sarif_tags(f)


# ---------------------------------------------------------------- summary and risk

def test_summarize_counts_and_status():
    fs = [_f(sev="critical"), _f(sev="high", line=20), _f(rule="CRY001", sev="low", cwe="CWE-327", line=5),
          _f(rule="X", sev="info", cwe="", line=1)]
    s = C.summarize(fs, ["owasp"])["owasp-top10-2021"]
    rows = {r["control"]: r for r in s["rows"]}
    assert list(rows) == ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]
    assert rows["A03"]["counts"] == {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0}
    assert rows["A03"]["total"] == 2 and rows["A03"]["status"] == "fail" and rows["A03"]["findings"] == ["F-001", "F-002"]
    assert rows["A02"]["status"] == "warn" and rows["A01"]["status"] == "pass" and rows["A01"]["findings"] == []
    assert s["status"] == "fail" and s["findings_mapped"] == 3 and s["findings_unmapped"] == 1
    assert s["controls_total"] == 10 and s["controls_with_findings"] == 2
    assert C.summarize(fs, ["owasp"], fail_on="low")["owasp-top10-2021"]["rows"][1]["status"] == "fail"
    assert C.summarize(fs, ["owasp"], fail_on="critical")["owasp-top10-2021"]["rows"][2]["status"] == "fail"
    assert C.summarize([], ["owasp"])["owasp-top10-2021"]["status"] == "pass"


def test_summarize_all_frameworks_sorts_controls():
    fs = [_f(), _f(rule="SEC001", cwe="CWE-798", sev="medium"), _f(rule="TLS1", cwe="CWE-295", sev="medium")]
    s = C.summarize(fs, lang="ar")
    assert list(s) == list(C.FRAMEWORKS)
    nist = [r["control"] for r in s["nist-800-53r5"]["rows"]]
    assert nist.index("AU-3(3)") < nist.index("AU-9") < nist.index("AU-12") and nist.index("SC-8") < nist.index("SC-8(1)")
    top = s["cwe-top25-2024"]["rows"]
    assert [r["control"] for r in top[:3]] == ["CWE-79", "CWE-787", "CWE-89"] and len(top) == 25
    assert s["owasp-top10-2021"]["rows"][2]["title"] == "A03:2021 الحقن"
    asvs = s["owasp-asvs-4.0.3"]["rows"]
    assert all(re.fullmatch(r"V\d+\.\d+\.\d+", r["control"]) or r["total"] for r in asvs)   # sections only when hit
    # a generic-only match does not make a framework "fail"
    only_generic = C.summarize([{"rule_id": "x", "severity": "critical", "cwe": ""}], ["nist"])["nist-800-53r5"]
    assert only_generic["status"] == "pass" and only_generic["findings_unmapped"] == 1


def test_risk_score():
    assert C.risk_score([]) == {"score": 0, "rating": "none", "weighted": 0.0,
                                "counts": {s: 0 for s in C.SEVERITIES}, "weights": C.RISK_WEIGHTS}
    assert C.risk_score([_f(sev="info")])["score"] == 0
    low = C.risk_score([_f(sev="low")])
    assert low["score"] >= 1 and low["rating"] == "low"
    assert C.risk_score([_f(sev="high")])["rating"] == "moderate"           # floor for a high finding
    one = C.risk_score([_f(sev="critical")])
    assert one["rating"] == "high" and 25 <= one["score"] < 50              # floor for a critical finding
    many = C.risk_score([_f(sev="critical")] * 30)
    assert many["score"] == 100 and many["rating"] == "critical"
    scores = [C.risk_score([_f(sev="high")] * n)["score"] for n in range(0, 12)]
    assert scores == sorted(scores)
    assert C.risk_score([_f(sev="bogus")])["counts"]["info"] == 1


# ---------------------------------------------------------------- reports

def _report(lang="en", **kw):
    fs = [_f(sev="critical", extra=dict(FLOW)), _f(rule="SEC001", sev="high", cwe="CWE-798", file="cfg.py", line=3,
                                                   title="Hard-coded password", title_ar="كلمة مرور مضمّنة"),
          _f(rule="OSV:GHSA-1", sev="medium", cwe="", file="requirements.txt", line=0, title="Vulnerable dependency x",
             extra={"url": "https://osv.dev/vulnerability/GHSA-1"})]
    meta = {"target": "/srv/app", "files_scanned": 42, "generated_at": "2026-01-02T03:04:05+00:00",
            "notes": ["ملاحظة"], "notes_en": ["A note"], "project": "Payments", "assessor": "AppSec",
            "report_generated_at": "2026-01-03T00:00:00+00:00", "tool_version": "9.9.9"}
    return C.render_html(fs, meta, lang, **kw)


def test_html_report_english():
    out = _report()
    assert out.startswith("<!DOCTYPE html><html lang='en' dir='ltr'>")
    assert C.STR["en"]["not_cert"] in out and out.count(C.STR["en"]["not_cert"]) >= 2
    assert "not a certification" in out.lower()
    for key in ("s_scope", "s_method", "s_exec", "s_matrices", "s_appendix", "s_sources"):
        assert C.STR["en"][key] in out
    for needle in ("Payments", "AppSec", "/srv/app", "Kashif 9.9.9", "A note", "Risk score", "A03:2021 Injection",
                   "PCI DSS v4.0", "8.6.2", "app/db.py:12", "app/views.py:7", "Sink: SQL", "Use parameterized queries.",
                   "request.args", "id='F-001'", "href='#F-001'", "abc123:0", "https://osv.dev/vulnerability/GHSA-1",
                   "CWE-89 (Improper Neutralization of Special Elements used in an SQL Command"):
        assert needle in out, needle
    for fid in C.FRAMEWORKS:
        assert f"id='fw-{fid}'" in out
    assert "@media print" in out and "break-before:page" in out and "@page" in out
    assert out.rstrip().endswith("</html>")


def test_html_report_is_self_contained():
    out = _report()
    assert "<script" not in out.lower() and "<link" not in out.lower() and "<img" not in out.lower()
    assert "@import" not in out and "url(" not in out and " src=" not in out
    assert not re.search(r"\son\w+=", out)                                   # no inline event handlers


def test_html_report_arabic_rtl():
    out = _report("ar", frameworks=["owasp", "pci"])
    assert "<html lang='ar' dir='rtl'>" in out
    text = re.sub(r"<[^>]+>", "", out)                                       # Latin runs are isolated in <bdi>
    assert C.STR["ar"]["not_cert"] in out and "الملخص التنفيذي" in out and "A03:2021 الحقن" in text
    assert "<bdi dir='rtl'><bdi dir='ltr'>A03:2021</bdi> الحقن</bdi>" in out   # Arabic title after an id: RTL
    assert "استعلام SQL من مدخلات" in text and "استخدم استعلامات مُعلَّمة." in out and "نقطة الخطر: SQL" in text
    assert "ملاحظة" in out and "id='fw-pci-dss-4.0'" in out and "id='fw-hipaa-164.312'" not in out
    assert "<bdi dir='ltr'>6.2.4-injection</bdi>" in out                     # identifiers stay left-to-right
    assert "direction:ltr" in out                                            # code blocks


def test_html_escapes_untrusted_text():
    evil = "<script>alert(1)</script>"
    f = _f(title=evil, title_ar=evil, snippet=evil, advice=evil, advice_en=evil, file=f"a/{evil}.py", rule=evil,
           extra={"path": [{"file": evil, "line": 1, "text": evil, "text_en": evil}], "url": "javascript:alert(1)",
                  "taint_source": evil, "taint_source_en": evil}, fingerprint=evil)
    out = C.render_html([f], {"target": evil, "notes": [evil], "project": evil, "assessor": evil}, "en")
    assert "<script" not in out and "javascript:" not in out and "&lt;script&gt;" in out


def test_html_empty_report():
    out = C.render_html([], {"target": "x"}, "en")
    assert C.STR["en"]["no_findings"] in out and ">0</span><span class='of'>/100" in out


def test_html_code_context_reads_only_inside_source_root(tmp_path):
    src = tmp_path / "proj"
    (src / "app").mkdir(parents=True)
    (src / "app" / "db.py").write_text("\n".join(f"line_{i} = {i}" for i in range(1, 31)), encoding="utf-8")
    (tmp_path / "outside.txt").write_text("TOP-SECRET-MARKER\n" * 5, encoding="utf-8")
    out = C.render_html([_f(), _f(file="../outside.txt", line=2, snippet="s")], {"target": str(src)}, "en", source_root=src)
    assert "line_12 = 12" in out and "line_10 = 10" in out and "line_14 = 14" in out and "line_15 = 15" not in out
    assert "class='hit'>   12 | line_12 = 12" in out
    assert "TOP-SECRET-MARKER" not in out
    assert "line_12 = 12" not in C.render_html([_f()], {"target": str(src)}, "en")       # opt-in only


def test_json_report():
    doc = json.loads(C.render_json([_f(extra=dict(FLOW)), _f(rule="SEC001", sev="low", cwe="CWE-798")],
                                   {"target": "t", "files_scanned": 3}, "en", ["owasp", "pci"]))
    assert doc["schema"] == C.SCHEMA and "not a certification" in doc["disclaimer"]
    assert doc["summary"]["high"] == 1 and doc["risk"]["score"] > 0 and doc["scope"]["files_scanned"] == 3
    assert set(doc["frameworks"]) == {"owasp-top10-2021", "pci-dss-4.0"}
    first = doc["findings"][0]
    assert first["id"] == "F-001" and first["categories"] == ["injection"]
    assert first["compliance"]["owasp-top10-2021"][0]["control"] == "A03"
    assert first["compliance"]["owasp-top10-2021"][0]["basis"] == "official"
    assert "pci-dss-4.0" in doc["sources"] and "kashif-analyst" in doc["sources"]
    ar = json.loads(C.render_json([_f()], None, "ar", ["owasp"]))
    assert ar["findings"][0]["title"] == "استعلام SQL من مدخلات"


def test_csv_and_markdown():
    fs = [_f(), _f(rule="SEC001", sev="low", cwe="CWE-798")]
    rows = list(csv.DictReader(io.StringIO(C.render_csv(fs, frameworks=["owasp"]))))
    assert len(rows) == 10
    a03 = next(r for r in rows if r["control"] == "A03")
    assert a03["status"] == "fail" and a03["high"] == "1" and a03["findings"] == "F-001" and a03["basis"] == "official"
    md = C.render_markdown(fs, frameworks=["owasp", "hipaa"])
    assert "| A03 | A03:2021 Injection | 0 | 1 | 0 | 0 | 0 | Fail |" in md and "not a certification" in md.lower()
    assert "| A01 |" not in md and "164.312(d)" in md


def test_strings_have_both_languages():
    assert set(C.STR["en"]) == set(C.STR["ar"])
    for key, text in C.STR["ar"].items():
        assert text.strip(), key
        assert set(re.findall(r"\{(\w+)\}", text)) == set(re.findall(r"\{(\w+)\}", C.STR["en"][key])), key
    assert not any(re.search(r"[؀-ۿ]", v) for v in C.STR["en"].values())


# ---------------------------------------------------------------- input and CLI

def _kashif_json(tmp_path, findings=None):
    p = tmp_path / "report.json"
    p.write_text(json.dumps({"target": "proj", "files_scanned": 5, "generated_at": "2026-01-01T00:00:00+00:00",
                             "notes": [], "summary": {}, "findings": findings if findings is not None else [_f()]},
                            ensure_ascii=False), encoding="utf-8")
    return p


def test_load_findings_kashif_json_and_list(tmp_path):
    fs, meta = C.load_findings(_kashif_json(tmp_path))
    assert fs[0]["rule_id"] == "INJ001" and meta["target"] == "proj" and meta["files_scanned"] == 5
    lst = tmp_path / "list.json"
    lst.write_text(json.dumps([_f()]), encoding="utf-8")
    assert len(C.load_findings(lst)[0]) == 1
    bad = tmp_path / "bad.json"
    bad.write_text("{\"x\": 1}", encoding="utf-8")
    with pytest.raises(ValueError):
        C.load_findings(bad)
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        C.load_findings(bad)
    with pytest.raises(FileNotFoundError):
        C.load_findings(tmp_path / "missing.json")


def test_load_findings_sarif(tmp_path):
    sarif = {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "OtherTool", "rules": [
            {"id": "py/sql-injection", "shortDescription": {"text": "SQL injection"}, "help": {"text": "Use parameters."},
             "properties": {"tags": ["security", "external/cwe/cwe-089"], "security-severity": "9.8"}},
            {"id": "weak-hash", "properties": {"cwe": "CWE-328"}}]}},
        "results": [
            {"ruleId": "py/sql-injection", "message": {"text": "query built from input"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/a.py"},
                                                 "region": {"startLine": 9, "snippet": {"text": "cur.execute(q)"}}}}],
             "codeFlows": [{"threadFlows": [{"locations": [
                 {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/a.py"}, "region": {"startLine": 4}},
                               "message": {"text": "source"}}}]}]}],
             "partialFingerprints": {"primaryLocationLineHash": "deadbeef"}},
            {"ruleId": "weak-hash", "level": "note", "message": {"text": "md5"}}]}]}
    p = tmp_path / "r.sarif"
    p.write_text(json.dumps(sarif), encoding="utf-8")
    fs, meta = C.load_findings(p)
    assert [f["severity"] for f in fs] == ["critical", "low"] and fs[0]["cwe"] == "CWE-89" and fs[1]["cwe"] == "CWE-328"
    assert fs[0]["file"] == "src/a.py" and fs[0]["line"] == 9 and fs[0]["source"] == "OtherTool"
    assert fs[0]["extra"]["path"][0]["line"] == 4 and fs[0]["fingerprint"] == "deadbeef"
    assert C.map_finding(fs[0])["owasp-top10-2021"] == ["A03"] and C.map_finding(fs[1])["owasp-top10-2021"] == ["A02"]
    out = C.render_html(fs, meta, "en", ["owasp"])
    assert "src/a.py:9" in out and "OtherTool" in out


def test_load_findings_scans_a_path(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text("import hashlib\n\ndef digest(p):\n    return hashlib.md5(p.encode()).hexdigest()\n",
                                 encoding="utf-8")
    fs, meta = C.load_findings(proj)
    assert meta["files_scanned"] == 1 and meta["target"] == str(proj)
    assert any("328" in f["cwe"] or "327" in f["cwe"] for f in fs)
    assert all("fingerprint" in f for f in fs)


def test_cli(tmp_path, capsys):
    rep = _kashif_json(tmp_path)
    out = tmp_path / "audit.html"
    assert C.main([str(rep), "--framework", "owasp-top10-2021", "-f", "html", "-o", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "A03:2021 Injection" in text and "id='fw-pci-dss-4.0'" not in text and C.STR["en"]["not_cert"] in text
    assert "wrote" in capsys.readouterr().err

    js = tmp_path / "audit.json"                                             # format from the extension
    assert C.main([str(rep), "-F", "pci,asvs", "-o", str(js), "--lang", "ar"]) == 0
    assert set(json.loads(js.read_text(encoding="utf-8"))["frameworks"]) == {"pci-dss-4.0", "owasp-asvs-4.0.3"}

    assert C.main([str(rep), "-f", "md", "-F", "owasp"]) == 0
    assert "| A03 |" in capsys.readouterr().out

    assert C.main([str(rep), "-f", "csv", "-F", "owasp", "--fail-on", "high"]) == 1           # gate
    assert "owasp-top10-2021" in capsys.readouterr().err
    assert C.main([str(rep), "-f", "csv", "-F", "owasp", "--fail-on", "critical"]) == 0
    assert C.main([str(rep), "-f", "csv", "-F", "owasp", "--fail-on", "high", "--min-severity", "critical"]) == 0
    capsys.readouterr()

    assert C.main([str(rep), "-F", "nope"]) == 2
    assert C.main([str(tmp_path / "missing.json")]) == 2
    assert C.main([]) == 2
    assert C.main(["--bogus"]) == 2
    capsys.readouterr()
    assert C.main(["--list-frameworks"]) == 0
    listed = capsys.readouterr().out
    assert all(fid in listed for fid in C.FRAMEWORKS)
    assert C.main(["--check-coverage"]) == 0


# ---------------------------------------------------------------- adversarial review: hostile input, accuracy

def test_report_target_is_never_used_as_source_root(tmp_path, capsys):
    """A report file is untrusted: its "target" must not choose the directory whose files end up in the HTML."""
    secret_dir = tmp_path / "victim"
    secret_dir.mkdir()
    (secret_dir / "passwd").write_text("ROOT-LINE-MARKER\n" * 5, encoding="utf-8")
    rep = tmp_path / "evil.json"
    rep.write_text(json.dumps({"target": str(secret_dir), "findings": [_f(file="passwd", line=2, snippet="s")]}),
                   encoding="utf-8")
    out = tmp_path / "o.html"
    assert C.main([str(rep), "-o", str(out), "-F", "owasp"]) == 0
    assert "ROOT-LINE-MARKER" not in out.read_text(encoding="utf-8")
    assert C.main([str(rep), "-o", str(out), "-F", "owasp", "--source-root", str(secret_dir)]) == 0   # explicit opt-in
    assert "ROOT-LINE-MARKER" in out.read_text(encoding="utf-8")
    capsys.readouterr()


@pytest.mark.parametrize("file", [
    "/etc/passwd", "\\\\attacker\\share\\x.py", "//attacker/share/x.py", "C:\\Windows\\win.ini", "c:/x.py",
    "file:///etc/passwd", "https://example.org/x", "../x.py", "a/../../x.py", "a\\..\\..\\x.py", "x.py:stream",
    "NUL", "sub/con.txt", "a.zip!b.py", "a\0b", "", ".", "x" * 5000])
def test_unsafe_finding_paths_are_refused_without_touching_the_file_system(file, tmp_path, monkeypatch):
    assert C._safe_relative(file) is None

    def boom(*a, **k):
        raise AssertionError("file system touched")
    monkeypatch.setattr(C, "_file_lines", boom)
    assert C._code_context(tmp_path, file, 1) == []


def test_safe_relative_paths_and_symlink_escape(tmp_path):
    assert C._safe_relative("app\\db.py") == "app/db.py" and C._safe_relative("./a//b.py") == "a/b.py"
    root = tmp_path / "root"
    root.mkdir()
    (root / "ok.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "out.txt").write_text("OUTSIDE\n", encoding="utf-8")
    assert C._code_context(root, "ok.py", 1) == [(1, "x = 1")]
    try:
        (root / "link.py").symlink_to(tmp_path / "out.txt")
    except (OSError, NotImplementedError):                                   # no symlink privilege (Windows)
        return
    assert C._code_context(root, "link.py", 1) == []


def test_secret_findings_are_masked_in_html(tmp_path):
    value = "".join(["Tr0ub", "4dor", "-3x", "Zq9"])                          # built at run time, not a literal
    token = "".join(["QUtJ", "QVhZ", "WlRF", "U1RL", "RVkx", "MjM0"])
    (tmp_path / "cfg.py").write_text(f"a = 1\npassword = \"{value}\"\napi_key: {token}\n", encoding="utf-8")
    f = _f(rule="SEC001", sev="high", cwe="CWE-798", file="cfg.py", line=2, snippet=f"password = \"{value}\"")
    for kwargs in ({}, {"source_root": tmp_path}):
        out = C.render_html([f], {}, "en", ["owasp"], **kwargs)
        assert value not in out and token not in out and "Tr******" in out and C.STR["en"]["masked"] in out
    shown = C.render_html([f], {}, "en", ["owasp"], source_root=tmp_path, mask_secrets=False)
    assert "Tr0ub4dor" in shown and token in shown
    other = C.render_html([_f(snippet=f"q = \"{value}\"")], {}, "en", ["owasp"])          # not a secret finding
    assert value in other and C.STR["en"]["masked"] not in other
    assert C._mask_secrets("-----BEGIN KEY-----") == "-----BEGIN KEY-----"


def test_malformed_findings_do_not_crash_any_renderer():
    weird = [
        {"rule_id": None, "severity": 5, "cwe": ["CWE-89", 79], "file": 7, "line": float("inf"), "extra": "x"},
        {"rule_id": ["a"], "severity": "CRITICAL", "cwe": 89, "line": "12abc", "extra": {"path": 5, "url": 3}},
        {"severity": None, "cwe": {"a": 1}, "line": -5, "title": 3.5, "snippet": ["x"], "advice": {"k": "v"},
         "extra": {"path": [1, "s", {"file": None, "line": "x", "text": None}], "taint_source": 9}, "_id": "<x>"},
        {"_id": "F-999", "line": 10 ** 40, "cwe": "CWE-123456", "fingerprint": ["<zz>"]},
        {},
    ]
    meta = {"target": {"a": 1}, "files_scanned": [1], "notes": "one", "notes_en": 3, "generated_at": 5}
    for render in (C.render_html, C.render_json, C.render_csv, C.render_markdown):
        assert render(weird, meta, "en") and render(weird, meta, "ar")
    html_out = C.render_html(weird, meta, "en")
    assert "<x>" not in html_out and "<zz>" not in html_out and "&lt;zz&gt;" in html_out
    assert C.cwe_ids(weird[1]) == ["89"] and C.cwe_ids(weird[0]) == ["89", "79"]
    assert C.cwe_ids({"cwe": "CWE-123456"}) == [] and C.cwe_ids({"cwe": True}) == []
    doc = json.loads(C.render_json(weird, meta, "en"))
    assert all(f["line"] >= 0 for f in doc["findings"]) and [f["id"] for f in doc["findings"]] == sorted(
        f["id"] for f in doc["findings"])


def test_caller_supplied_ids_cannot_skip_normalisation(tmp_path, capsys):
    """Findings that already carry "_id" (hostile report) once bypassed _prepare and crashed the --fail-on gate."""
    fs = [{"_id": "F-001", "rule_id": "X", "cwe": "CWE-89", "severity": "HIGH"}, {"_id": "F-002", "cwe": "CWE-79"}]
    s = C.summarize(fs, "owasp")["owasp-top10-2021"]
    assert s["status"] == "fail" and next(r for r in s["rows"] if r["control"] == "A03")["counts"]["high"] == 1
    rep = tmp_path / "r.json"
    rep.write_text(json.dumps({"findings": fs}), encoding="utf-8")
    assert C.main([str(rep), "-f", "csv", "-F", "owasp", "--fail-on", "high"]) == 1
    assert "compliance gate" in capsys.readouterr().err


def test_long_text_is_truncated_in_html():
    big = "A" * 50000
    out = C.render_html([_f(snippet=big, advice=big, advice_en=big, title=big, extra={
        "path": [{"file": "f.py", "line": i, "text": "t", "text_en": "t"} for i in range(1, 1000)]})], {}, "en", ["owasp"])
    assert len(out) < 60000 and C.STR["en"]["truncated"] in out and out.count("<li><code>f.py:") == C._MAX_STEPS


def test_malformed_sarif_is_tolerated(tmp_path):
    sarif = {"runs": [
        7, {"tool": "x", "results": "nope"}, {"tool": {"driver": {"name": 5, "rules": [3, {"id": ["x"]}]}}, "results": [
            3, {"ruleId": ["x"], "level": ["error"], "locations": "x", "codeFlows": 5, "message": 9,
                "partialFingerprints": {"a": {"b": 1}}, "properties": {"tags": "CWE-89", "security-severity": "nan"}},
            {"ruleId": "r", "rule": 5, "locations": [{"physicalLocation": {"artifactLocation": {"uri": 5},
                                                                           "region": {"startLine": "abc", "snippet": 5}}}],
             "codeFlows": [{"threadFlows": [{"locations": [5, {"location": 5}]}]}], "fingerprints": [1]},
            {"ruleId": "r2", "locations": [{"physicalLocation": {"region": {"startLine": 1e400}}}]}]}]}
    p = tmp_path / "bad.sarif"
    p.write_text(json.dumps(sarif), encoding="utf-8")
    fs, meta = C.load_findings(p)
    assert len(fs) == 3 and all(f["line"] == 0 for f in fs)
    assert C.render_html(fs, meta, "en", ["owasp"]) and C.render_json(fs, meta, "en")


def test_sarif_skips_closed_results_and_reads_rule_index_taxa_and_file_uris(tmp_path):
    def res(**kw):
        return {"ruleIndex": 0, "message": {"text": "m"}, **kw}
    sarif = {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "T", "rules": [{"id": "R1", "relationships": [
            {"target": {"id": "78", "toolComponent": {"name": "CWE"}}}]}]}},
        "results": [
            res(locations=[{"physicalLocation": {"artifactLocation": {"uri": "file:///srv/app/my%20file.py"},
                                                 "region": {"startLine": 3}}}]),
            res(kind="pass"), res(kind="notApplicable"), res(baselineState="absent"),
            res(suppressions=[{"kind": "inSource"}]), res(suppressions=[{"kind": "external", "status": "accepted"}]),
            res(suppressions=[{"kind": "external", "status": "rejected"}]),
            {"ruleId": "other", "message": {"text": "m"},
             "taxa": [{"id": "CWE-611", "toolComponent": {"name": "cwe"}}]}]}]}
    p = tmp_path / "r.sarif"
    p.write_text(json.dumps(sarif), encoding="utf-8")
    fs, _ = C.load_findings(p)
    assert [(f["rule_id"], f["cwe"]) for f in fs] == [("R1", "CWE-78"), ("R1", "CWE-78"), ("other", "CWE-611")]
    assert fs[0]["file"] == "/srv/app/my file.py" and fs[0]["line"] == 3
    assert C._code_context(tmp_path, fs[0]["file"], 3) == []                 # absolute: never read


def test_load_findings_limits(tmp_path, monkeypatch):
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 200000 + "]" * 200000, encoding="utf-8")
    with pytest.raises(ValueError):
        C.load_findings(deep)
    assert C.main([str(deep)]) == 2
    monkeypatch.setattr(C, "MAX_INPUT_BYTES", 10)
    big = tmp_path / "big.json"
    big.write_text(json.dumps({"findings": [_f()]}), encoding="utf-8")
    with pytest.raises(ValueError):
        C.load_findings(big)
    bom = tmp_path / "bom.json"
    monkeypatch.setattr(C, "MAX_INPUT_BYTES", 10 ** 6)
    bom.write_bytes(b"\xef\xbb\xbf" + json.dumps([_f()]).encode("utf-8"))  # written by Windows tools
    assert len(C.load_findings(bom)[0]) == 1


def test_cwe_hierarchy_is_view_1000_and_pillars_do_not_leak():
    parents = C.load_data()["cwe_parents"]
    # relations that existed in old CWE releases (or other views) and are not ChildOf in view 1000
    for child, stale in (("120", "20"), ("134", "20"), ("117", "20"), ("113", "20"), ("190", "20"), ("798", "287"),
                         ("918", "610"), ("1321", "913")):
        assert stale not in parents[child], (child, stale)
    assert parents["89"] == ["943"] and parents["79"] == ["74"] and parents["1427"] == ["77"]
    for cwe in ("120", "134", "117"):                                        # no longer "CWE-20 #12" by inheritance
        assert "CWE-20" not in C.map_cwe(cwe, "top25")["cwe-top25-2024"], cwe
    # CWE-693 is a pillar; Kashif's analyst mapping for it (configuration) must not reach its descendants
    assert C.map_cwe(693, "owasp")["owasp-top10-2021"] == ["A05"]
    assert C.map_cwe(358, "owasp")["owasp-top10-2021"] == [] and C.categories({"cwe": "CWE-358"}) == ["other"]


def test_api_top10_does_not_inherit_through_cwe_parents():
    api = lambda cwe: C.map_cwe(cwe, "api")["owasp-api-2023"]                # noqa: E731
    assert api(1004) == [] and api(614) == [] and api(732) == []             # cookie flags, file modes: not BOLA
    assert api(639) == ["API1"] and api(862) == ["API1", "API5"] and api(918) == ["API7"]
    assert {r["basis"] for r in C.explain_finding({"cwe": "CWE-862"}, "api")["owasp-api-2023"]} == {"category"}


def test_pci_requirement_wording():
    pci = C.load_data()["frameworks"]["pci-dss-4.0"]
    assert "PAN" in pci["controls"]["3.5.1"]["title"] and "PAN" in pci["controls"]["4.2.1"]["title"]
    assert "interactive login" in pci["controls"]["8.6.2"]["title"]
    assert "7.2.2" not in pci["controls"] and C.map_cwe(250, "pci")["pci-dss-4.0"] == ["7.2.5", "6.3.1"]
    assert "v4.0.1" in pci["note"]


def test_no_control_is_labelled_pass():
    for lang in ("en", "ar"):
        out = C.render_html([_f()], {}, lang, ["pci"])
        assert "Pass (" not in out and ">Pass<" not in out and "ناجح" not in out
        assert f"<span class='st pass'>{C.STR[lang]['st_pass']}</span>" in out


def test_stdout_fallback_on_legacy_console(monkeypatch):
    class Narrow(io.TextIOWrapper):
        pass
    raw = io.BytesIO()
    monkeypatch.setattr("sys.stdout", Narrow(raw, encoding="cp1252", errors="strict"))
    assert C.main(["--list-frameworks", "--lang", "ar"]) == 0
    import sys
    sys.stdout.flush()
    assert "اللائحة".encode("utf-8") in raw.getvalue()


def test_secret_masking_is_linear_on_hostile_lines():
    import time
    start = time.perf_counter()
    for line in ('"' + "a\\" * 1000, "'" + "\\" * 2001, "=" + "a" * 2000 + '"', "'ab" * 700, "= " * 1000, "`" + "a" * 2000):
        C._mask_secrets(line)
    assert time.perf_counter() - start < 2.0
    assert C._mask_secrets("k='abcdefgh'; t=`abcdefghi`; s=\"abc\"") == "k='ab******'; t=`ab******`; s=\"abc\""


def test_generic_controls_never_fail():
    """PCI 6.3.1 / SA-11 / SSDF PW.7.2 list every finding; a finding is the output of that activity, not its failure."""
    s = C.summarize([_f(sev="critical")], ["pci", "800-53", "ssdf"])
    row = lambda fid, c: next(r for r in s[fid]["rows"] if r["control"] == c)   # noqa: E731
    assert row("pci-dss-4.0", "6.3.1")["status"] == "warn" and row("pci-dss-4.0", "6.2.4-injection")["status"] == "fail"
    assert row("nist-800-53r5", "SA-11")["status"] == "warn" and row("nist-ssdf-1.1", "PW.7.2")["status"] == "warn"
    assert row("nist-800-53r5", "SI-10")["status"] == "fail" and s["pci-dss-4.0"]["status"] == "fail"
