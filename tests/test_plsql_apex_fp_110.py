"""Kashif 1.1.0: false positives reported on a real Oracle APEX application (1.0.2), each fixed without losing the
true positives next to it. Fixtures: tests/data/plsql_apex_fp/ (wrapped units, an APEX plug-in package, an
application export with a standard sign-in page, a public page that writes data, a used and an unused plug-in)."""
import json
import pathlib

import pytest

from vulnscan import apex_export, compliance, exporters
from vulnscan.i18n import has_arabic, to_en
from vulnscan.model import Finding, assign_fingerprints, assign_groups, finding_groups
from vulnscan.plsql_frontend import parse_plsql, wrapped_units
from vulnscan.report import render_html, render_json
from vulnscan.scanner import scan_path, skip_reason
from vulnscan.taint import analyze_project

DATA = pathlib.Path(__file__).parent / "data" / "plsql_apex_fp"


@pytest.fixture(scope="module")
def scan():
    notes: list = []
    findings, _ = scan_path(DATA, notes=notes)
    return findings, notes


def _at(findings, file):
    out: dict = {}
    for f in findings:
        if f.file == file:
            out.setdefault(f.line, set()).add(f.rule_id)
    return out


# ------------------------------------------------------------------ 1. wrapped PL/SQL
def test_wrapped_units_are_found_with_their_extent():
    text = (DATA / "hr_wrapped.plb").read_text()
    units = wrapped_units(text)
    assert [(s, k, n) for s, _e, k, n in units] == [(8, "package body", "hr_secure"), (58, "procedure", "HR.PURGE_AUDIT"),
                                                     (92, "function", "hr_hash"), (122, "type body", "t_money")]
    lines = text.split("\n")
    for _s, end, _k, _n in units:
        assert lines[end - 1].strip() == "/"        # ends at the `/` line, not at a wrapped line starting with `/`
    _, diag = parse_plsql(text)
    assert diag["skipped"] == 0 and len(diag["wrapped"]) == 4


def test_wrapped_unit_reported_once_and_never_as_a_secret(scan):
    findings, _ = scan
    wf = [f for f in findings if f.file == "hr_wrapped.plb"]
    assert not [f for f in wf if f.rule_id == "SEC011"]
    apx = sorted((f.line, f.severity) for f in wf if f.rule_id == "APX022")
    assert apx == [(8, "info"), (58, "info"), (92, "info"), (122, "info")]
    assert any(f.rule_id == "DF013" and f.line == 154 for f in wf)      # unwrapped code after them is still analysed


def test_entropy_rule_still_applies_outside_wrapped_units(tmp_path):
    token = "Q7wX2Lp9Rt4Vb8" + "Nm3Kd6Hj1Fs5Gz0Ya"
    (tmp_path / "x.plb").write_text("create or replace function f wrapped\na000000\nb2\n" + "abcd\n" * 15
                                    + "8\n1a 2b\n" + "Zk3Pq8Lm2Vx7Rt5Nb1Hc4Wd9Jf6Gs0YaQe2Tu8Io3Pa7Sd1Fg5Hj9Kl4Zx6Cv\n/\n"
                                    + f"create or replace procedure k is\nbegin\n  api_key := '{token}';\nend k;\n/\n")
    fs, _ = scan_path(tmp_path, notes=[])
    got = sorted((f.rule_id, f.line) for f in fs)
    assert ("APX022", 1) in got and ("SEC011", 25) in got       # the base64 line 21 inside the unit is not
    assert not [x for x in got if x[0] == "SEC011" and x[1] <= 22]


# ------------------------------------------------------------------ 2./3. APEX sources and sanitisers
def test_plugin_attributes_are_not_user_input_but_browser_values_are(scan):
    b = _at(scan[0], "acme_plugins.pkb")
    assert 15 not in b                         # p_region.attribute_01 -> package name (design time) + regexp_like guard
    assert b.get(41) == {"DF004"}              # apex_application.g_x01 concatenated without a guard
    fb = _at(scan[0], "f200.sql")
    assert 90 not in fb                        # the same pattern inside the plug-in of the export


def test_legacy_item_plugin_value_is_user_input():
    src = ("create or replace function render_item(p_item in apex_plugin.t_page_item, p_plugin in apex_plugin.t_plugin,\n"
           "  p_value in varchar2, p_is_readonly in boolean, p_is_printer_friendly in boolean)\n"
           "  return apex_plugin.t_page_item_render_result is\n  l_r apex_plugin.t_page_item_render_result;\nbegin\n"
           "  htp.p('<input value=\"' || p_value || '\" title=\"' || p_item.attribute_01 || '\">');\n"
           "  return l_r;\nend;\n/\n"
           "create or replace procedure save_setting(p_name in varchar2, p_value in varchar2) is\nbegin\n"
           "  htp.p(p_value);\nend;\n/\n")
    fs = analyze_project({"item.sql": src})
    assert sorted((f.rule_id, f.line) for f in fs) == [("DF013", 6)]


def test_regexp_like_guard_with_raise_is_a_sanitiser_only_when_anchored(scan):
    b = _at(scan[0], "acme_plugins.pkb")
    assert 33 not in b                         # anchored allow-list + raise_application_error, values bound with USING
    assert b.get(51) == {"DF004"}              # '[A-Za-z]' only checks that one letter exists


def test_dbms_assert_conversions_and_allow_list_strip(scan):
    b = _at(scan[0], "acme_plugins.pkb")
    assert not set(b) & set(range(58, 64)), b  # DBMS_ASSERT.*, SYS.DBMS_ASSERT.*, to_number, regexp_replace '[^…]'
    assert b.get(64) == {"DF004"}              # DBMS_ASSERT.NOOP checks nothing


def test_bound_values_never_taint_the_statement(scan):
    b = _at(scan[0], "acme_plugins.pkb")
    assert 73 not in b and 76 not in b and 77 not in b and 78 not in b and 80 not in b
    assert b.get(74) == {"DF004"}              # OPEN … FOR with a concatenated value
    assert b.get(79) == {"DF004"}              # DBMS_SQL.PARSE: the statement is its 2nd argument


def test_partial_strip_is_not_a_full_sanitiser():
    src = ("create or replace procedure p is\nbegin\n"
           "  execute immediate 'select 1 from ' || regexp_replace(v('P1_T'), '[^A-Za-z0-9 ]', '');\n"
           "  execute immediate 'select 1 from ' || regexp_replace(v('P1_T'), '[^A-Za-z]', 'x''');\n"
           "  execute immediate 'select 1 from ' || regexp_replace(v('P1_T'), '[^A-Za-z]', '', 1, 1);\n"
           "  htp.p(regexp_replace(v('P1_T'), '[^A-Za-z0-9 .-]'));\n"
           "end;\n/\n")
    b = {f.line: f.rule_id for f in analyze_project({"s.sql": src})}
    assert b == {3: "DF004", 4: "DF004", 5: "DF004"}, b   # a space, a quote put back, only the first match removed


# ------------------------------------------------------------------ 4. output context: HTTP header vs HTML
def test_htp_between_mime_header_and_header_close_writes_a_header(scan):
    fs = [f for f in scan[0] if f.file == "acme_plugins.pkb"]
    b = _at(fs, "acme_plugins.pkb")
    assert 88 not in b and 90 not in b         # letters/digits only, then a constant body
    hdr = next(f for f in fs if f.line == 96)
    assert (hdr.rule_id, hdr.cwe) == ("DF008", "CWE-113")   # header injection (CR/LF), not XSS
    assert b.get(98) == {"DF013"}              # after http_header_close it is HTML again
    assert b.get(103) == {"DF013"} and 104 not in b


def test_header_value_with_cr_and_lf_removed_is_safe_for_the_header_only():
    src = ("create or replace procedure dl is\n  l_f varchar2(200) := v('P1_FILE');\nbegin\n"
           "  owa_util.mime_header('text/csv', false);\n"
           "  htp.p('Content-Disposition: attachment; filename=' || replace(replace(l_f, chr(13)), chr(10), ''));\n"
           "  htp.p('X-Name: ' || replace(l_f, chr(10)));\n"
           "  owa_util.http_header_close;\n"
           "  htp.p(replace(replace(l_f, chr(13)), chr(10)));\n"
           "end;\n/\n")
    got = sorted((f.rule_id, f.line) for f in analyze_project({"dl.sql": src}))
    assert got == [("DF008", 6), ("DF013", 8)], got        # LF alone is not enough; CR/LF-free text is still HTML


def test_request_and_cgi_environment_are_user_input():
    src = ("create or replace procedure r is\nbegin\n"
           "  execute immediate 'begin ' || :REQUEST || '; end;';\n"
           "  execute immediate 'select 1 from ' || v('REQUEST');\n"
           "  htp.p(owa_util.get_cgi_env('QUERY_STRING'));\n"
           "  execute immediate 'select 1 from t where c = :1' using :P1_X;\n"
           "  for r in (select * from t where c = :P1_X) loop null; end loop;\n"
           "end;\n/\n")
    got = sorted((f.rule_id, f.line) for f in analyze_project({"r.sql": src}))
    assert got == [("DF004", 3), ("DF004", 4), ("DF013", 5)], got


# ------------------------------------------------------------------ 5. standard sign-in page / 6. APX009 severity
def test_sign_in_page_is_exempt_and_a_public_page_that_writes_still_fires(scan):
    apx = sorted((f.rule_id, f.line, f.severity) for f in scan[0] if f.file == "f200.sql" and f.rule_id.startswith("APX"))
    assert ("APX016", 180, "high") in apx                       # page 30: public and inserts
    assert not [x for x in apx if x[0] in ("APX016", "APX018") and x[1] > 190]   # page 9999 (alias LOGIN, Arabic name)
    assert ("APX013", 64, "medium") in apx                      # authentication cookie without Secure: still reported
    assert ("APX009", 33, "low") in apx                         # developer toolbar: only a signed-in developer sees it


def test_sign_in_page_detected_by_login_url_or_login_call():
    page = ("begin\nwwv_flow_imp_shared.create_user_interface(p_id=>wwv_flow_imp.id(1), p_login_url=>'f?p=&APP_ID.:101:&APP_SESSION.');\n"
            "wwv_flow_imp_page.create_page(p_id=>101, p_name=>'Anmeldung', p_page_is_public_y_n=>'Y', p_protection_level=>'U');\n"
            "wwv_flow_imp_page.create_page_process(p_id=>1, p_process_point=>'AFTER_SUBMIT', p_process_type=>'NATIVE_PLSQL',"
            " p_process_name=>'Go', p_process_sql_clob=>'null;');\n"
            "wwv_flow_imp_page.create_page(p_id=>102, p_name=>'Entrar', p_page_is_public_y_n=>'Y');\n"
            "wwv_flow_imp_page.create_page_process(p_id=>2, p_process_point=>'AFTER_SUBMIT', p_process_type=>'NATIVE_PLSQL',"
            " p_process_name=>'Entrar', p_process_sql_clob=>'wwv_flow_custom_auth_std.login(p_uname => :P102_U, p_password => :P102_P);');\n"
            "end;\n/\n")
    _, fs, _ = apex_export.extract(page, "f.sql")
    assert not [f for f in fs if f.rule_id in ("APX016", "APX017", "APX018")], [(f.rule_id, f.line) for f in fs]


def test_readable_yaml_login_alias():
    yaml = ("---\n# ====== Page: Inicio de sesion ======\nid: 9999\nidentification: \n  name: Inicio de sesion\n  alias: LOGIN\n"
            "security: \n  authentication: Page Is Public\n  page-access-protection: Unrestricted\n\n"
            "processes: \n- # ====== Process: Login ======\n  id: 1\n  identification: \n    name: Login\n    type: Execute Code\n")
    _, fs, _ = apex_export.extract_yaml(yaml, "readable/application/pages/p09999.yaml")
    assert not [f for f in fs if f.rule_id in ("APX016", "APX018")], [(f.rule_id, f.line) for f in fs]


# ------------------------------------------------------------------ 6. overall score never "critical" without one
def _f(sev, i=0, rule="SEC011"):
    return Finding(rule, sev, "t", "ت", f"a{i}.py", 1, f"x{i}", "", "CWE-798")


def test_compliance_risk_rating_is_capped_by_the_worst_severity():
    many_high = [_f("high", i) for i in range(745)]
    r = compliance.risk_score(many_high)
    assert r["rating"] == "high" and r["score"] <= 74
    assert compliance.risk_score([_f("medium", i) for i in range(500)])["rating"] == "moderate"
    assert compliance.risk_score([_f("low", i) for i in range(500)])["rating"] == "low"
    assert compliance.risk_score(many_high + [_f("critical", 999)])["rating"] == "critical"
    assert compliance.risk_score([_f("info", i) for i in range(50)])["rating"] == "none"


def test_project_risk_is_capped_by_the_worst_severity():
    many_high = [_f("high", i, "DF004") for i in range(745)]
    for f in many_high:
        f.extra["taint_source"] = "x"
    p = exporters.project_risk(many_high, {"exposure": "internet"})
    assert p["rating"] != "critical" and p["score"] <= 8.9
    crit = _f("critical", 999, "DF004")
    crit.extra["taint_source"] = "x"
    assert exporters.project_risk(many_high + [crit], {"exposure": "internet"})["rating"] == "critical"


def test_score_formula_text_says_so_in_both_languages():
    assert "74" in compliance.STR["en"]["m_risk_txt"] and "74" in compliance.STR["ar"]["m_risk_txt"]


# ------------------------------------------------------------------ 6. grouping by root cause
def _copied_plugins(tmp_path):
    body = ("'function render (p_region in apex_plugin.t_region, p_plugin in apex_plugin.t_plugin,',"
            "\n'    p_is_printer_friendly in boolean) return apex_plugin.t_region_render_result is',"
            "\n'    l_r apex_plugin.t_region_render_result;',"
            "\n'begin',"
            "\n'    execute immediate ''begin '' || apex_application.g_x01 || ''.refresh; end;'';',"
            "\n'    return l_r;',"
            "\n'end render;'")
    parts = ["begin\nwwv_flow_imp.create_flow(p_id=>wwv_flow.g_flow_id, p_name=>'X');\n"]
    for k in (1, 2, 3):
        parts.append(f"wwv_flow_imp_shared.create_plugin(\n p_id=>wwv_flow_imp.id({k})\n,p_plugin_type=>'REGION TYPE'\n"
                     f",p_name=>'COM.ACME.P{k}'\n,p_plsql_code=>wwv_flow_string.join(wwv_flow_t_varchar2(\n{body}))\n"
                     ",p_render_function=>'render'\n);\n")
        parts.append(f"wwv_flow_imp_page.create_page_plug(p_id=>wwv_flow_imp.id({k}0), p_plug_name=>'R{k}',"
                     f" p_plug_source_type=>'PLUGIN_COM.ACME.P{k}');\n")
    parts.append("end;\n/\n")
    (tmp_path / "f300.sql").write_text("".join(parts))
    return tmp_path


def test_one_pattern_in_several_plugins_is_one_group_with_its_locations(tmp_path):
    root = _copied_plugins(tmp_path)
    fs, _ = scan_path(root, notes=[])
    df = [f for f in fs if f.rule_id == "DF004"]
    assert len(df) == 3 and len({f.extra.get("group_id") for f in df}) == 1 and df[0].extra["group_size"] == 3
    before = [f.base_fingerprint() for f in df]
    assign_fingerprints(fs)
    fps = {f.fingerprint() for f in df}
    assert len(fps) == 3                                     # each finding keeps its own fingerprint …
    for f in df:
        f.extra.pop("group_id"), f.extra.pop("group_size")
    assign_groups(fs)
    assert [f.base_fingerprint() for f in df] == before       # … which grouping does not touch
    fs, _ = scan_path(root, notes=[])
    doc = json.loads(render_json(fs, str(root), 1, []))
    g = [x for x in doc["groups"] if x["rule_id"] == "DF004"]
    assert len(g) == 1 and g[0]["count"] == 3 and len(g[0]["locations"]) == 3
    assert {x["fingerprint"] for x in g[0]["locations"]} == {f["fingerprint"] for f in doc["findings"] if f["rule_id"] == "DF004"}
    html_ar = render_html(fs, str(root), 1, [], lang="ar")
    html_en = render_html(fs, str(root), 1, [], lang="en")
    assert g[0]["id"] in html_ar and "مواضع" in html_ar and "Repeated patterns" in html_en and "3 places" in html_en


def test_groups_in_json_only_when_something_repeats():
    fs = [_f("high", 1), _f("high", 2)]
    assign_groups(fs)
    assert "groups" not in json.loads(render_json(fs, ".", 2, []))
    assert finding_groups(fs) == []


def test_ui_shows_the_group_and_the_unused_component():
    js = (pathlib.Path(__file__).parent.parent / "vulnscan" / "ui" / "app.js").read_text(encoding="utf-8")
    assert "groupTag(f)" in js and "'find.group'" in js and "unused_component" in js
    assert js.count("'find.unused': ") == 2 and js.count("'find.groupHead': ") == 2    # Arabic and English


# ------------------------------------------------------------------ 7. components defined but not used
def test_unused_plugin_is_reported_and_its_findings_are_lowered_not_dropped(scan):
    fs = [f for f in scan[0] if f.file == "f200.sql"]
    dead = [f for f in fs if f.rule_id == "APX023"]
    assert [(f.line, f.severity) for f in dead] == [(119, "low")] and "LEGACY_GRID" in dead[0].snippet
    inside = next(f for f in fs if f.line == 131)
    assert (inside.rule_id, inside.severity) == ("DF013", "low")
    assert inside.extra["unused_component"] == "إضافة: COM.ACME.LEGACY_GRID"
    assert inside.extra["severity_before_unused"] == "medium"
    assert not [f for f in fs if f.rule_id == "APX023" and "COM.ACME.CHART" in f.snippet]   # used by page 1


def test_plugin_export_alone_is_not_dead_code(tmp_path):
    text = (DATA / "f200.sql").read_text()
    start = text.index("prompt --application/shared_components/plugins/region_type/com_acme_legacy_grid")
    end = text.index("prompt --application/pages/page_00001")
    (tmp_path / "plugin_com_acme_legacy_grid.sql").write_text(text[start:end])
    fs, _ = scan_path(tmp_path, notes=[])
    assert not [f for f in fs if f.rule_id == "APX023"]
    assert [f.severity for f in fs if f.rule_id == "DF013"] == ["medium"]


def test_split_export_usage_is_counted_per_application(tmp_path):
    env = "begin\nwwv_flow_imp.import_begin(p_version_yyyy_mm_dd=>'2024.05.31', p_default_application_id=>{app});\nend;\n/\n"
    plugin = ("begin\nwwv_flow_imp_shared.create_plugin(\n p_id=>wwv_flow_imp.id(1)\n,p_plugin_type=>'REGION TYPE'\n"
              ",p_name=>'COM.ACME.{name}'\n,p_render_function=>'render'\n);\nend;\n/\n")
    (tmp_path / "app1").mkdir()
    (tmp_path / "app1" / "create_application.sql").write_text(env.format(app=1) + "begin\nwwv_flow_imp.create_flow(p_id=>1, p_name=>'A');\nend;\n/\n")
    (tmp_path / "app1" / "plugins.sql").write_text(env.format(app=1) + plugin.format(name="USED") + plugin.format(name="IDLE"))
    (tmp_path / "app1" / "page_00010.sql").write_text(
        env.format(app=1) + "begin\nwwv_flow_imp_page.create_page(p_id=>10, p_name=>'P');\n"
        "wwv_flow_imp_page.create_page_plug(p_id=>wwv_flow_imp.id(2), p_plug_name=>'R', p_plug_source_type=>'PLUGIN_COM.ACME.USED');\nend;\n/\n")
    (tmp_path / "app2.sql").write_text(env.format(app=2) + "begin\nwwv_flow_imp_page.create_page(p_id=>1, p_name=>'Q');\n"
                                       "wwv_flow_imp_page.create_page_plug(p_id=>wwv_flow_imp.id(3), p_plug_name=>'S',"
                                       " p_plug_source_type=>'PLUGIN_COM.ACME.IDLE');\nend;\n/\n")
    fs, _ = scan_path(tmp_path, notes=[])
    dead = [(f.file, f.snippet) for f in fs if f.rule_id == "APX023"]
    assert len(dead) == 1 and dead[0][0] == "app1/plugins.sql" and "COM.ACME.IDLE" in dead[0][1], dead


# ------------------------------------------------------------------ 8. skipped statements carry a reason
def test_each_skipped_statement_has_location_and_reason(tmp_path):
    (tmp_path / "bad.sql").write_text("begin\n  x := := 1;\n  htp.p(:P1_A);\n  y := &&var;\nend;\n/\n")
    notes: list = []
    scan_path(tmp_path, notes=notes)
    det = [n for n in notes if n.startswith("عبارة متخطّاة")]
    assert len(det) == 2, notes
    assert "bad.sql:2" in det[0] and "bad.sql:4" in det[1]
    en = [to_en(n) for n in det]
    assert en[0] == "Skipped statement at bad.sql:2: unsupported or unexpected construct: ':='"
    assert "SQL*Plus substitution variable" in en[1] and not any(has_arabic(x) for x in en)


def test_skip_reasons_are_bilingual():
    for msg in ("expected ';', found 'x'", "unexpected 'foo' in declarations", "expected IS/AS in p", "dangling NOT",
                "missing 'end' for if at line 5", "frontend failure: RecursionError: deep"):
        ar, en = skip_reason(msg)
        assert has_arabic(ar) and not has_arabic(en) and en != msg


def test_apex_block_skip_carries_the_component(tmp_path):
    export = ("begin\nwwv_flow_imp_page.create_page(p_id=>5, p_name=>'Orders');\n"
              "wwv_flow_imp_page.create_page_process(p_id=>1, p_process_type=>'NATIVE_PLSQL', p_process_name=>'Save',"
              " p_process_sql_clob=>'x := := 1;');\nend;\n/\n")
    (tmp_path / "f5.sql").write_text(export)
    notes: list = []
    scan_path(tmp_path, notes=notes)
    det = [to_en(n) for n in notes if n.startswith("عبارة متخطّاة")]
    assert det and det[0].startswith("Skipped statement at f5.sql:3 [Page 5 › Process: Save]:"), det


def test_fixture_counts_by_rule(scan):
    """The measured result on the fixtures (1.0.2: 62 findings, 42 of them SEC011 on wrapped text)."""
    from collections import Counter
    c = Counter(f.rule_id for f in scan[0])
    assert c == Counter({"DF004": 5, "DF013": 4, "DF008": 1, "APX022": 4, "APX016": 1, "APX013": 1, "APX009": 1,
                         "APX023": 1}), c
