"""Kashif 1.4.0: PL/SQL in the Supporting Objects (installation scripts) of an Oracle APEX export, analysed at its
export lines (data flow and APX024), and APX024 context from the authorization schemes of the APEX components that
call the flagged routine."""

from vulnscan import apex_export
from vulnscan.i18n import has_arabic, to_en
from vulnscan.plsql_frontend import tokenize
from vulnscan.scanner import scan_path
from vulnscan.taint import analyze_project

from test_plsql_authz_130 import BIO_PHOTO, GUARD, SIBLINGS, _package

HEAD = """prompt --application/set_environment
set define off verify off feedback off
begin
wwv_flow_imp.import_begin (
 p_version_yyyy_mm_dd=>'2024.05.31'
,p_release=>'24.1.0'
,p_default_workspace_id=>1234
,p_default_application_id=>141
);
end;
/
"""

FLOW = """prompt --application/create_application
begin
wwv_flow_imp.create_flow(
 p_id=>wwv_flow.g_flow_id
,p_name=>'HR'
{app_scheme});
end;
/
prompt --application/shared_components/security/authorizations/hr_admin
begin
wwv_flow_imp_shared.create_security_scheme(
 p_id=>wwv_flow_imp.id(5001)
,p_name=>'HR_ADMIN'
,p_scheme_type=>'NATIVE_IS_IN_GROUP'
,p_attribute_01=>'HR Admins'
);
end;
/
"""


def _join(code: str) -> str:
    """Code -> wwv_flow_string.join(wwv_flow_t_varchar2('line', …)) as APEX 20+ writes it, one element per line."""
    lines = code.rstrip("\n").split("\n")
    return "wwv_flow_string.join(wwv_flow_t_varchar2(\n" + ",\n".join("'" + ln.replace("'", "''") + "'" for ln in lines) + "))"


def _install(code: str, name: str = "hdr_ui", form: str = "join") -> str:
    if form == "join":
        arg = _join(code)
    else:                                         # APEX 5 style: one multi-line literal with '' escapes
        arg = "'" + code.rstrip("\n").replace("'", "''") + "'"
    return (f"prompt --application/deployment/install/install_{name}\nbegin\n"
            f"wwv_flow_imp_shared.create_install_script(\n p_id=>wwv_flow_imp.id(7001)\n,p_install_id=>wwv_flow_imp.id(7000)\n"
            f",p_name=>'{name}'\n,p_sequence=>10\n,p_script_type=>'INSTALL'\n,p_script_clob=>{arg}\n);\nend;\n/\n")


def _page(pid: int, process: str, *, role: str = "", public: bool = False, proc_scheme: str = "",
          point: str = "AFTER_SUBMIT") -> str:
    return (f"prompt --application/pages/page_{pid:05d}\nbegin\nwwv_flow_imp_page.create_page(\n p_id=>{pid}\n"
            f",p_name=>'Page {pid}'\n" + (f",p_required_role=>{role}\n" if role else "")
            + (",p_page_is_public_y_n=>'Y'\n" if public else "") + ");\n"
            f"wwv_flow_imp_page.create_page_process(\n p_id=>wwv_flow_imp.id({pid}01)\n,p_process_sequence=>10\n"
            f",p_process_point=>'{point}'\n,p_process_type=>'NATIVE_PLSQL'\n,p_process_name=>'Proc {pid}'\n"
            f",p_process_sql_clob=>{_join(process)}\n" + (f",p_security_scheme=>{proc_scheme}\n" if proc_scheme else "")
            + ");\nend;\n/\n")


def _lines_of(text: str, needle: str) -> list[int]:
    return [k + 1 for k, ln in enumerate(text.split("\n")) if needle in ln]


PKG = _package(GUARD, SIBLINGS, BIO_PHOTO.format(check=""))
CALL = "begin\n  :P{p}_PHOTO := hdr_ui.bio_photo(:P{p}_EMP_ID);\nend;"


def _apx024(findings) -> list:
    return [f for f in findings if f.rule_id == "APX024"]


# ------------------------------------------------------------------ extraction and line mapping
def test_join_form_is_extracted_at_its_export_lines():
    export = HEAD + _install(PKG)
    _b, _f, _files, info = apex_export.extract_full(export, "f141.sql")
    assert len(info["scripts"]) == 1
    line, script, label = info["scripts"][0]
    assert label == "سكربت كائنات الدعم: hdr_ui"
    lines = export.split("\n")
    for k, code_line in enumerate(script.split("\n")):
        assert lines[line - 1 + k] == "'" + code_line.replace("'", "''") + "'" + ("," if k < len(script.split("\n")) - 1 else "))")
    assert "raise_application_error(-20001, 'Not authorized')" in script      # '' unescaped
    # extract() keeps its 3-tuple and still sees no code block in the script
    blocks, _f2, _f3 = apex_export.extract(export, "f141.sql")
    assert not blocks


def test_legacy_literal_and_unistr_forms_keep_lines():
    code = "create or replace procedure p1 is\nbegin\n  execute immediate 'select 1 from dual';\nend;\n/"
    export = HEAD + _install(code, "p1", form="literal").replace("wwv_flow_imp_shared.create_install_script",
                                                                  "wwv_flow_api.create_install_script")
    _b, _f, _files, info = apex_export.extract_full(export, "f141.sql")
    line, script, _label = info["scripts"][0]
    assert script.split("\n")[2] == "  execute immediate 'select 1 from dual';"
    assert export.split("\n")[line - 1 + 2] == "  execute immediate ''select 1 from dual'';"
    # 'a'||unistr('\000a')|| per line, with one line split over two literals (a blank line keeps the mapping)
    export2 = ("begin\nwwv_flow_api.create_install_script(\n p_id=>1\n,p_name=>'x'\n,p_script_clob=>'create or replace '||\n"
               "'procedure p2 is'||unistr('\\000a')||\n'begin'||unistr('\\000a')||\n'  null;'||unistr('\\000a')||\n'end;'\n);\nend;\n/\n")
    _b, _f, _files, info = apex_export.extract_full(export2, "f.sql")
    line, script, _label = info["scripts"][0]
    lines = export2.split("\n")
    for k, code_line in enumerate(script.split("\n")):
        if code_line.strip():
            assert code_line.split()[0] in lines[line - 1 + k], (k, code_line, lines[line - 1 + k])   # where it starts
    assert script.split("\n")[:3] == ["create or replace procedure p2 is", "", "begin"]


def test_apex4_variable_form():
    export = ("declare\n  s varchar2(32767) := null;\nbegin\ns := null;\n"
              "s:=s||'create or replace procedure p3 is'||unistr('\\000a')||\n"
              "'begin'||unistr('\\000a')||\n'  null;'||unistr('\\000a')||\n'end;';\n\n"
              "wwv_flow_api.create_install_script(\n  p_id => 9 + wwv_flow_api.g_id_offset,\n  p_name=> 'p3',\n"
              "  p_script_clob=> s);\nend;\n/\n")
    _b, _f, _files, info = apex_export.extract_full(export, "f.sql")
    line, script, _label = info["scripts"][0]
    assert script.startswith("create or replace procedure p3 is\nbegin\n")
    assert export.split("\n")[line - 1].startswith("s:=s||'create or replace procedure p3")
    assert export.split("\n")[line + 1].startswith("'  null;'")


def test_script_text_helper_handles_chr_and_lf():
    toks = tokenize("'a'||chr(10)||\n'b'||wwv_flow.lf||\n'c'")[:-1]
    text, first = apex_export._script_text(toks)
    assert (text, first) == ("a\nb\nc", 1)


# ------------------------------------------------------------------ analysis of the supporting-object package
def test_dataflow_inside_supporting_object_package():
    pkg = ("create or replace package body rpt as\n"
           "  procedure run(p_where in varchar2) is\n"
           "  begin\n"
           "    execute immediate 'delete from t where ' || p_where;\n"
           "  end run;\n"
           "  procedure run2 is\n"
           "  begin\n"
           "    execute immediate 'delete from t where id = ' || v('P10_ID');\n"
           "  end run2;\n"
           "end rpt;\n/")
    export = HEAD + _page(10, "begin\n  rpt.run(:P10_FILTER);\nend;") + _install(pkg, "rpt")
    findings = [f for f in analyze_project({"f141.sql": export}) if f.rule_id == "DF004"]
    sink = _lines_of(export, "'    execute immediate ''delete from t where '' || p_where;'")[0]
    sink2 = _lines_of(export, "v(''P10_ID'')")[0]
    call = _lines_of(export, "rpt.run(:P10_FILTER)")[0]
    # page item -> process -> package in the Supporting Objects -> execute immediate (reported at the call, the
    # path ends at the sink's export line)
    f = next(f for f in findings if f.line == call)
    assert [p["line"] for p in f.extra["path"]][-1] == sink
    # source inside the package itself: reported at the sink, labelled with the script
    f2 = next(f for f in findings if f.line == sink2)
    assert f2.extra.get("apex_component") == "سكربت كائنات الدعم: rpt"
    assert f2.snippet.startswith("[سكربت كائنات الدعم: rpt]")
    assert to_en("سكربت كائنات الدعم: rpt") == "Supporting Objects Script: rpt"


def test_apx024_on_supporting_object_package(tmp_path):
    export = HEAD + _install(PKG)
    (tmp_path / "f141.sql").write_text(export)
    findings, _ = scan_path(tmp_path)
    found = _apx024(findings)
    assert len(found) == 1, [(f.rule_id, f.line) for f in findings]
    f = found[0]
    assert f.file == "f141.sql" and f.line == _lines_of(export, "'  function bio_photo(")[0]
    assert f.severity == "medium" and "apex_call_sites" not in f.extra
    assert f.extra["apex_component"] == "سكربت كائنات الدعم: hdr_ui"


# ------------------------------------------------------------------ authorization-scheme context
def _ctx_scan(tmp_path, pages: str, app_scheme: str = ""):
    export = HEAD + FLOW.format(app_scheme=app_scheme) + pages + _install(PKG)
    (tmp_path / "f141.sql").write_text(export)
    findings, _ = scan_path(tmp_path)
    found = _apx024(findings)
    assert len(found) == 1
    return export, found[0]


def test_all_call_sites_protected_keeps_finding_and_says_so(tmp_path):
    pages = (_page(10, CALL.format(p=10), role="wwv_flow_imp.id(5001)")
             + _page(20, CALL.format(p=20), proc_scheme="wwv_flow_imp.id(5001)"))
    export, f = _ctx_scan(tmp_path, pages)
    assert f.severity == "medium"
    assert f.extra["apex_protection"] == "all_protected" and f.extra["apex_schemes"] == ["HR_ADMIN"]
    assert [c["line"] for c in f.extra["apex_call_sites"]] == _lines_of(export, "hdr_ui.bio_photo(")
    assert "HR_ADMIN" in f.advice and "لا تشمل أي مستدعٍ آخر للحزمة" in f.advice
    en = to_en(f.advice)
    assert not has_arabic(en), en
    assert "called only from components protected by the authorization scheme HR_ADMIN" in en
    assert "Page 10 › Process: Proc 10" in en


def test_application_scheme_protects_every_page(tmp_path):
    _export, f = _ctx_scan(tmp_path, _page(10, CALL.format(p=10)), app_scheme=",p_security_scheme=>wwv_flow_imp.id(5001)\n")
    assert f.extra["apex_protection"] == "all_protected" and f.severity == "medium"


def test_one_unprotected_call_site_raises_to_high(tmp_path):
    pages = (_page(10, CALL.format(p=10), role="wwv_flow_imp.id(5001)")
             + _page(20, CALL.format(p=20), role="'MUST_NOT_BE_PUBLIC_USER'"))
    export, f = _ctx_scan(tmp_path, pages)
    assert f.severity == "high" and f.extra["severity_before_apex"] == "medium"
    assert f.extra["apex_protection"] == "unprotected"
    open_ = [c for c in f.extra["apex_call_sites"] if not c["protected"]]
    assert len(open_) == 1 and open_[0]["component"] == "صفحة 20 › عملية: Proc 20"
    assert open_[0]["line"] == _lines_of(export, "hdr_ui.bio_photo(:P20")[0]
    assert "صفحة 20 › عملية: Proc 20" in f.advice and "1 من 2" in f.advice
    en = to_en(f.advice)
    assert not has_arabic(en), en
    assert "from an unprotected component: «Page 20 › Process: Proc 20»" in en
    assert "no authorization scheme that restricts users" in en and "unprotected call sites: 1 of 2" in en


def test_public_page_and_negated_scheme_and_application_process(tmp_path):
    _e, f = _ctx_scan(tmp_path, _page(30, CALL.format(p=30), public=True))
    assert f.severity == "high" and f.extra["apex_call_sites"][0]["reason"] == "صفحة عامة بلا تسجيل دخول"
    assert "public page, no sign-in" in to_en(f.advice)
    _e, f = _ctx_scan(tmp_path, _page(40, CALL.format(p=40), proc_scheme="'!'||wwv_flow_imp.id(5001)"))
    assert f.severity == "high"
    app_proc = ("begin\nwwv_flow_imp_shared.create_flow_process(\n p_id=>wwv_flow_imp.id(8001)\n,p_process_sequence=>1\n"
                ",p_process_point=>'ON_DEMAND'\n,p_process_type=>'NATIVE_PLSQL'\n,p_process_name=>'GET_PHOTO'\n"
                ",p_process_sql_clob=>" + _join("begin\n  htp.p(dbms_lob.getlength(hdr_ui.bio_photo(apex_application.g_x01)));\nend;")
                + "\n);\nend;\n/\n")
    _e, f = _ctx_scan(tmp_path, app_proc)
    assert f.severity == "high" and f.extra["apex_call_sites"][0]["reason"] == "عملية تطبيق بلا مخطط تفويض"
    assert "application process without an authorization scheme" in to_en(f.advice)


def test_package_in_plain_file_called_from_export_gets_context(tmp_path):
    (tmp_path / "hdr_ui.pkb").write_text(PKG)
    (tmp_path / "f141.sql").write_text(HEAD + FLOW.format(app_scheme="") + _page(10, CALL.format(p=10)))
    findings, _ = scan_path(tmp_path)
    f = _apx024(findings)[0]
    assert f.file == "hdr_ui.pkb" and f.severity == "high" and f.extra["apex_protection"] == "unprotected"


def test_comment_mentions_are_not_call_sites(tmp_path):
    _e, f = _ctx_scan(tmp_path, _page(10, "begin\n  -- hdr_ui.bio_photo(1) is called elsewhere\n  null;\nend;"))
    assert "apex_call_sites" not in f.extra and f.severity == "medium"


# ------------------------------------------------------------------ robustness
def test_malformed_scripts_never_crash():
    bad = [
        "begin\nwwv_flow_imp_shared.create_install_script(\n p_id=>1\n,p_script_clob=>wwv_flow_string.join(wwv_flow_t_varchar2(\n'create or replace package body x as',\n",
        "begin\nwwv_flow_imp_shared.create_install_script(p_script_clob=>wwv_flow_string.join(\n",
        "begin\nwwv_flow_imp_shared.create_install_script(p_script_clob=>s);\nend;\n",
        "begin\ns := s || ;\nwwv_flow_api.create_install_script(p_script_clob=>s||unistr('\\zz')||chr(99999999999));\nend;\n",
        "begin\nwwv_flow_imp_shared.create_install_script(p_script_clob=>'create or replace package body p as procedure a is begin",
        "begin\nwwv_flow_imp_shared.create_install_script(p_script_clob=>wwv_flow_string.join(wwv_flow_t_varchar2(((((('x'))))\n",
    ]
    for k, text in enumerate(bad):
        apex_export.extract_full(text, "f.sql")
        analyze_project({f"f{k}.sql": text})


def test_partial_check_with_apex_context_is_translated(tmp_path):
    """Path-sensitive APX024 (partial check) and the APEX call-site context together, in both languages."""
    pkg = _package(GUARD, SIBLINGS, BIO_PHOTO.format(
        check="    if p_emp_id > 100 then\n      check_access('HR_PHOTO');\n    end if;\n"))
    export = (HEAD + FLOW.format(app_scheme="") + _page(20, CALL.format(p=20), public=True) + _install(pkg))
    (tmp_path / "f141.sql").write_text(export)
    findings, _ = scan_path(tmp_path)
    found = _apx024(findings)
    assert len(found) == 1, [(f.rule_id, f.line) for f in findings]
    f = found[0]
    assert f.extra.get("coverage") == "partial" and f.severity == "high"
    assert "في بعض المسارات فقط" in f.advice and "مكوّن غير محمي" in f.advice
    en = to_en(f.advice)
    assert not has_arabic(en), en
    assert "checks authorization on some paths only" in en and "from an unprotected component" in en
