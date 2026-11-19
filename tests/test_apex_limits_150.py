"""Kashif 1.5.0: the documented limits of the 1.4.0 APEX / PL/SQL support, closed.

1. APX024 call sites through synonyms, schema-qualified names, constant dynamic SQL, Invoke API processes and other
   package routines (indirect callers); strings and comments are not calls.
2. Authorization inherited from what APEX enforces: parent regions (recursively), the dynamic action event, the
   page (a button's scheme does not protect a When Button Pressed process: it is named in the message); application processes have only their own scheme and the application's.
3. The readable YAML export (APEX 23.2+): page / component schemes and code, deduplicated against the .sql export
   of the same application.
4. Deinstall and upgrade scripts of the Supporting Objects (and the APEX 24.1+ varchar2 table form).
5. APEX 4.x region / process sources built in a variable (`s := s || '…';`).
6. APX024 reads which way a test of the check's answer goes (= FALSE, != TRUE, NOT (…), NVL(…, FALSE), AND / OR).
7. A package helper is a check only when it reaches the guard on every path to its normal exit.
8. Classification verified on real APEX 4.0-26.2 exports: APEX 4 static regions, item labels (p_prompt) are not AI
   prompts, APEX 5.0 wwv_flow_utilities.join; a compound trigger ending in `END;` no longer hangs the parser.
Every change that reports less has a near-miss twin that is still reported."""

import time

import pytest

from vulnscan import apex_export, plsql_authz
from vulnscan import plsql_frontend as pf
from vulnscan.i18n import has_arabic, to_en
from vulnscan.scanner import scan_path
from vulnscan.taint import analyze_project

from test_apex_supporting_objects_140 import FLOW, HEAD, _install, _join, _lines_of
from test_plsql_authz_130 import BIO_PHOTO, GUARD, SIBLINGS, _package

PKG = _package(GUARD, SIBLINGS, BIO_PHOTO.format(check=""))


def _apx024(findings) -> list:
    return [f for f in findings if f.rule_id == "APX024"]


def _scan(tmp_path, files: dict) -> list:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    findings, _ = scan_path(tmp_path)
    return findings


def _one(tmp_path, files: dict):
    found = _apx024(_scan(tmp_path, files))
    assert len(found) == 1, [(f.file, f.line, f.extra.get("routine")) for f in found]
    return found[0]


def _proc_page(pid: int, code: str, *, role: str = "", extra: str = "") -> str:
    return (f"prompt --application/pages/page_{pid:05d}\nbegin\nwwv_flow_imp_page.create_page(\n p_id=>{pid}\n"
            f",p_name=>'Page {pid}'\n" + (f",p_required_role=>{role}\n" if role else "") + ");\n"
            f"wwv_flow_imp_page.create_page_process(\n p_id=>wwv_flow_imp.id({pid}01)\n,p_process_sequence=>10\n"
            f",p_process_point=>'AFTER_SUBMIT'\n,p_process_type=>'NATIVE_PLSQL'\n,p_process_name=>'Proc {pid}'\n"
            f",p_process_sql_clob=>{_join(code)}\n{extra});\nend;\n/\n")


def _app(pages: str, app_scheme: str = "") -> str:
    return HEAD + FLOW.format(app_scheme=app_scheme) + pages


ADMIN = "wwv_flow_imp.id(5001)"


# =================================================================== 1. call sites
def test_public_synonym_call_site(tmp_path):
    syn = "create or replace public synonym hr_ui for hr.hdr_ui;\n"
    page = _proc_page(10, "begin\n  :P10_X := hr_ui.bio_photo(:P10_ID);\nend;")
    f = _one(tmp_path, {"hdr_ui.pkb": PKG, "synonyms.sql": syn, "f141.sql": _app(page)})
    assert f.severity == "high" and len(f.extra["apex_call_sites"]) == 1
    assert f.extra["apex_call_sites"][0]["line"] == _lines_of(_app(page), "hr_ui.bio_photo(")[0]


def test_private_synonym_in_supporting_objects_and_chained_synonym(tmp_path):
    syn = "create synonym hr_ui2 for hdr_ui;\ncreate or replace synonym hr_ui3 for app.hr_ui2;\n"
    page = _proc_page(10, "begin\n  :P10_X := hr_ui3.bio_photo(:P10_ID);\nend;")
    f = _one(tmp_path, {"f141.sql": _app(page) + _install(PKG + "\n" + syn)})
    assert f.extra["apex_protection"] == "unprotected"


def test_synonym_in_a_comment_or_string_is_not_one(tmp_path):
    syn = "-- create public synonym hr_ui for hdr_ui;\nbegin\n  l := 'create public synonym hr_ui for hdr_ui';\nend;\n/\n"
    page = _proc_page(10, "begin\n  :P10_X := hr_ui.bio_photo(:P10_ID);\nend;")
    f = _one(tmp_path, {"hdr_ui.pkb": PKG, "x.sql": syn, "f141.sql": _app(page)})
    assert "apex_call_sites" not in f.extra and f.severity == "medium"


def test_schema_qualified_and_quoted_call_site(tmp_path):
    page = _proc_page(10, 'begin\n  :P10_X := hr.hdr_ui.bio_photo(:P10_ID);\n  :P10_Y := "HR"."HDR_UI"."BIO_PHOTO"(1);\nend;')
    f = _one(tmp_path, {"hdr_ui.pkb": PKG, "f141.sql": _app(page)})
    assert len(f.extra["apex_call_sites"]) == 2


def test_strings_are_not_calls_but_constant_execute_immediate_is(tmp_path):
    # 1.4 counted any mention outside comments; a string literal is not a call
    mention = _proc_page(10, "begin\n  apex_debug.message('hdr_ui.bio_photo is slow');\nend;")
    f = _one(tmp_path / "a", {"hdr_ui.pkb": PKG, "f141.sql": _app(mention)})
    assert "apex_call_sites" not in f.extra and f.severity == "medium"
    # twin: the whole statement of execute immediate is the literal, so it runs that call
    const = _proc_page(10, "begin\n  execute immediate 'begin :x := hdr_ui.bio_photo(:id); end;' using out :P10_X, :P10_ID;\nend;")
    f = _one(tmp_path / "b", {"hdr_ui.pkb": PKG, "f141.sql": _app(const)})
    assert f.severity == "high" and len(f.extra["apex_call_sites"]) == 1
    # a built string is not known to be that call
    built = _proc_page(10, "begin\n  execute immediate 'begin :x := ' || 'hdr_ui.bio_photo(:id); end;' using out :P10_X, :P10_ID;\nend;")
    f = _one(tmp_path / "c", {"hdr_ui.pkb": PKG, "f141.sql": _app(built)})
    assert "apex_call_sites" not in f.extra


def test_call_sites_helper_lines():
    b = apex_export.Block("plsql", "begin\n  -- hdr_ui.bio_photo(1)\n  x := 'hdr_ui.bio_photo';\n"
                          "  execute immediate 'begin\n  y := hdr_ui.bio_photo(2);\nend;';\n  z := s.hdr_ui.bio_photo(3);\n"
                          "  w := hdr_ui.bio_photo.f;\nend;", 100, "l", "u")
    assert apex_export.call_sites(b, "HDR_UI", "BIO_PHOTO") == [104, 106]


INTERMEDIATE = """create or replace package body rpt_pkg as
  procedure show_photo(p_id in number) is
  begin
    {check}wpg_docload.download_file(hdr_ui.bio_photo(p_id));
  end show_photo;
end rpt_pkg;
/
"""


def test_indirect_call_site_through_another_package(tmp_path):
    page = _proc_page(10, "begin\n  rpt_pkg.show_photo(:P10_ID);\nend;")
    export = _app(page)
    f = _one(tmp_path, {"hdr_ui.pkb": PKG, "rpt_pkg.pkb": INTERMEDIATE.format(check=""), "f141.sql": export})
    c = f.extra["apex_call_sites"]
    assert len(c) == 1 and c[0]["via"] == "RPT_PKG.SHOW_PHOTO" and c[0]["line"] == _lines_of(export, "rpt_pkg.show_photo(")[0]
    assert c[0]["component"] == "صفحة 10 › عملية: Proc 10 (بشكل غير مباشر عبر RPT_PKG.SHOW_PHOTO)"
    assert f.severity == "high"
    en = to_en(f.advice)
    assert not has_arabic(en), en
    assert "«Page 10 › Process: Proc 10 (indirectly via RPT_PKG.SHOW_PHOTO)»" in en


def test_intermediate_that_checks_first_is_not_an_open_way_in(tmp_path):
    check = "if not apex_authorization.is_authorized('PHOTO') then\n      raise_application_error(-20001, 'no');\n    end if;\n    "
    page = _proc_page(10, "begin\n  rpt_pkg.show_photo(:P10_ID);\nend;")
    f = _one(tmp_path, {"hdr_ui.pkb": PKG, "rpt_pkg.pkb": INTERMEDIATE.format(check=check), "f141.sql": _app(page)})
    assert "apex_call_sites" not in f.extra and f.severity == "medium"


def test_indirect_within_the_same_package_and_two_hops(tmp_path):
    two = """create or replace package body ui2 as
  procedure p1(p_id in number) is
  begin
    p2(p_id);
  end p1;
  procedure p2(p_id in number) is
  begin
    rpt_pkg.show_photo(p_id);
  end p2;
end ui2;
/
"""
    page = _proc_page(10, "begin\n  ui2.p1(:P10_ID);\nend;", role=ADMIN)
    f = _one(tmp_path, {"hdr_ui.pkb": PKG, "rpt_pkg.pkb": INTERMEDIATE.format(check=""), "ui2.pkb": two,
                        "f141.sql": _app(page)})
    assert [c["via"] for c in f.extra["apex_call_sites"]] == ["UI2.P1"]
    assert f.extra["apex_protection"] == "all_protected" and f.severity == "medium"


def test_invoke_api_process_is_a_call_site(tmp_path):
    proc = ("prompt --application/pages/page_00010\nbegin\nwwv_flow_imp_page.create_page(\n p_id=>10\n,p_name=>'P'\n);\n"
            "wwv_flow_imp_page.create_page_process(\n p_id=>wwv_flow_imp.id(1001)\n,p_process_sequence=>10\n"
            ",p_process_point=>'AFTER_SUBMIT'\n,p_process_type=>'NATIVE_INVOKE_API'\n,p_process_name=>'Get photo'\n"
            ",p_attribute_01=>'PLSQL_PACKAGE'\n,p_attribute_03=>'HDR_UI'\n,p_attribute_04=>'BIO_PHOTO'\n);\nend;\n/\n")
    export = _app(proc)
    f = _one(tmp_path, {"hdr_ui.pkb": PKG, "f141.sql": export})
    assert f.extra["apex_call_sites"][0]["line"] == _lines_of(export, "p_attribute_04=>'BIO_PHOTO'")[0]
    assert f.severity == "high"


# =================================================================== 2. inherited authorization
def _region(rid: int, name: str, *, parent: int = 0, scheme: str = "", source: str = "", typ: str = "") -> str:
    return (f"wwv_flow_imp_page.create_page_plug(\n p_id=>wwv_flow_imp.id({rid})\n,p_plug_name=>'{name}'\n"
            + (f",p_parent_plug_id=>wwv_flow_imp.id({parent})\n" if parent else "")
            + (f",p_plug_source_type=>'{typ}'\n" if typ else "")
            + (f",p_plug_source=>{_join(source)}\n" if source else "")
            + (f",p_plug_required_role=>{scheme}\n" if scheme else "") + ");\n")


def _page_with(pid: int, body: str, role: str = "") -> str:
    return (f"prompt --application/pages/page_{pid:05d}\nbegin\nwwv_flow_imp_page.create_page(\n p_id=>{pid}\n,p_name=>'P'\n"
            + (f",p_required_role=>{role}\n" if role else "") + ");\n" + body + "end;\n/\n")


PLSQL_REGION = "begin\n  htp.p(dbms_lob.getlength(hdr_ui.bio_photo(:P10_ID)));\nend;"


def test_sub_region_inherits_recursively_in_any_order(tmp_path):
    # the grandchild comes first in the export; its grandparent holds the scheme
    body = (_region(3, "C", parent=2, source=PLSQL_REGION, typ="NATIVE_PLSQL") + _region(2, "B", parent=1)
            + _region(1, "A", scheme=ADMIN))
    f = _one(tmp_path, {"hdr_ui.pkb": PKG, "f141.sql": _app(_page_with(10, body))})
    assert f.extra["apex_protection"] == "all_protected" and f.extra["apex_schemes"] == ["HR_ADMIN"]
    # twin: no region on the chain restricts
    body = _region(3, "C", parent=2, source=PLSQL_REGION, typ="NATIVE_PLSQL") + _region(2, "B", parent=1) + _region(1, "A")
    f = _one(tmp_path / "t", {"hdr_ui.pkb": PKG, "f141.sql": _app(_page_with(10, body))})
    assert f.severity == "high"


def test_non_restricting_own_scheme_does_not_hide_the_region_scheme(tmp_path):
    body = (_region(1, "A", scheme=ADMIN)
            + _region(2, "B", parent=1, source=PLSQL_REGION, typ="NATIVE_PLSQL", scheme="'MUST_NOT_BE_PUBLIC_USER'"))
    f = _one(tmp_path, {"hdr_ui.pkb": PKG, "f141.sql": _app(_page_with(10, body))})
    assert f.extra["apex_protection"] == "all_protected"
    body = _region(1, "A") + _region(2, "B", parent=1, source=PLSQL_REGION, typ="NATIVE_PLSQL",
                                     scheme="'MUST_NOT_BE_PUBLIC_USER'")
    f = _one(tmp_path / "t", {"hdr_ui.pkb": PKG, "f141.sql": _app(_page_with(10, body))})
    assert f.severity == "high"


def _button(bid: int, name: str, *, region: int = 0, scheme: str = "") -> str:
    return (f"wwv_flow_imp_page.create_page_button(\n p_id=>wwv_flow_imp.id({bid})\n,p_button_name=>'{name}'\n"
            + (f",p_button_plug_id=>wwv_flow_imp.id({region})\n" if region else "")
            + (f",p_security_scheme=>{scheme}\n" if scheme else "") + ");\n")


def _process(code: str, extra: str) -> str:
    return ("wwv_flow_imp_page.create_page_process(\n p_id=>wwv_flow_imp.id(9001)\n,p_process_sequence=>10\n"
            ",p_process_point=>'AFTER_SUBMIT'\n,p_process_type=>'NATIVE_PLSQL'\n,p_process_name=>'Save'\n"
            f",p_process_sql_clob=>{_join(code)}\n{extra});\n")


CALL = "begin\n  :P10_X := hdr_ui.bio_photo(:P10_ID);\nend;"


def test_button_scheme_does_not_protect_its_process(tmp_path):
    # When Button Pressed compares the submitted REQUEST with the button's name: a user who can reach the page can
    # post that request although the button was not rendered for them, so the button's scheme protects nothing
    body = _button(77, "SAVE", scheme=ADMIN) + _process(CALL, ",p_process_when_button_id=>wwv_flow_imp.id(77)\n")
    f = _one(tmp_path, {"hdr_ui.pkb": PKG, "f141.sql": _app(_page_with(10, body))})
    assert f.severity == "high" and f.extra["apex_protection"] == "unprotected"
    assert f.extra["apex_button_not_protection"] == {"component": "صفحة 10 › عملية: Save", "button": "SAVE",
                                                     "scheme": "HR_ADMIN"}
    assert "عند الضغط على الزر SAVE الذي يحميه المخطط HR_ADMIN" in f.advice
    en = to_en(f.advice)
    assert not has_arabic(en), en
    assert ("«Page 10 › Process: Save» runs when the button SAVE is pressed, and SAVE has the authorization scheme "
            "HR_ADMIN; hiding a button does not stop a crafted submit with that REQUEST: add HR_ADMIN to the "
            "component's own scheme to protect it.") in en
    # the same through the button's region
    body = (_region(5, "Buttons", scheme=ADMIN) + _button(77, "SAVE", region=5)
            + _process(CALL, ",p_process_when_button_id=>wwv_flow_imp.id(77)\n"))
    f = _one(tmp_path / "r", {"hdr_ui.pkb": PKG, "f141.sql": _app(_page_with(10, body))})
    assert f.severity == "high" and f.extra["apex_button_not_protection"]["scheme"] == "HR_ADMIN"
    # the scheme on the process itself (or its page) protects it
    body = _button(77, "SAVE", scheme=ADMIN) + _process(CALL, f",p_process_when_button_id=>wwv_flow_imp.id(77)\n"
                                                         f",p_security_scheme=>{ADMIN}\n")
    f = _one(tmp_path / "o", {"hdr_ui.pkb": PKG, "f141.sql": _app(_page_with(10, body))})
    assert f.extra["apex_protection"] == "all_protected" and "apex_button_not_protection" not in f.extra


def test_request_condition_is_not_a_button_link(tmp_path):
    # the same button, the process tests REQUEST by name: unprotected too, and not linked to the button
    body = _button(77, "SAVE", scheme=ADMIN) + _process(CALL, ",p_process_when=>'SAVE'\n,p_process_when_type=>'REQUEST_EQUALS_CONDITION'\n")
    f = _one(tmp_path, {"hdr_ui.pkb": PKG, "f141.sql": _app(_page_with(10, body))})
    assert f.severity == "high"
    # and a button without a scheme protects nothing
    body = _button(77, "SAVE") + _process(CALL, ",p_process_when_button_id=>wwv_flow_imp.id(77)\n")
    f = _one(tmp_path / "b", {"hdr_ui.pkb": PKG, "f141.sql": _app(_page_with(10, body))})
    assert f.severity == "high"


def test_page_scheme_covers_its_components_and_dynamic_action_event(tmp_path):
    da = ("wwv_flow_imp_page.create_page_da_event(\n p_id=>wwv_flow_imp.id(61)\n,p_name=>'Load'\n"
          f",p_security_scheme=>{ADMIN}\n);\n"
          "wwv_flow_imp_page.create_page_da_action(\n p_id=>wwv_flow_imp.id(62)\n,p_event_id=>wwv_flow_imp.id(61)\n"
          f",p_action=>'NATIVE_EXECUTE_PLSQL_CODE'\n,p_attribute_01=>{_join(CALL)}\n);\n")
    f = _one(tmp_path, {"hdr_ui.pkb": PKG, "f141.sql": _app(_page_with(10, da))})
    assert f.extra["apex_protection"] == "all_protected"
    f = _one(tmp_path / "p", {"hdr_ui.pkb": PKG, "f141.sql": _app(_page_with(10, da.replace(f",p_security_scheme=>{ADMIN}\n", ""), role=ADMIN))})
    assert f.extra["apex_protection"] == "all_protected"
    f = _one(tmp_path / "n", {"hdr_ui.pkb": PKG, "f141.sql": _app(_page_with(10, da.replace(f",p_security_scheme=>{ADMIN}\n", "")))})
    assert f.severity == "high"


def test_application_process_has_only_its_own_and_the_application_scheme(tmp_path):
    proc = ("begin\nwwv_flow_imp_shared.create_flow_process(\n p_id=>wwv_flow_imp.id(8001)\n,p_process_sequence=>1\n"
            ",p_process_point=>'ON_DEMAND'\n,p_process_type=>'NATIVE_PLSQL'\n,p_process_name=>'GET_PHOTO'\n"
            f",p_process_sql_clob=>{_join(CALL)}\n);\nend;\n/\n")
    # a page with a scheme elsewhere in the export protects nothing of an application process
    f = _one(tmp_path, {"hdr_ui.pkb": PKG, "f141.sql": _app(_page_with(10, "", role=ADMIN) + proc)})
    assert f.severity == "high" and f.extra["apex_call_sites"][0]["reason"] == "عملية تطبيق بلا مخطط تفويض"
    f = _one(tmp_path / "a", {"hdr_ui.pkb": PKG, "f141.sql": _app(proc, app_scheme=f",p_security_scheme=>{ADMIN}\n")})
    assert f.extra["apex_protection"] == "all_protected"


# =================================================================== 3. readable YAML export
APP_YAML = """---
# ====== Application: HR =====================================
id: 141
identification:
  name: HR

authorization:
  authorization-scheme: {scheme}
  run-on-public-pages: false
"""

PAGE_YAML = """---
# ====== Page: Photos ========================================
id: 10
identification:
  name: Photos
  alias: PHOTOS

security:
  authorization-scheme: {page_scheme}
  authentication: Page Requires Authentication
  page-access-protection: Arguments Must Have Checksum

regions:
- # ====== Region: Admin =======================================
  id: 12337047553723501
  identification:
    name: Admin
    type: Static Content

  layout:
    sequence: 10
    parent-region: No Parent

  security:
    authorization-scheme: {region_scheme}

- # ====== Region: Photo =======================================
  id: 12337047553723502
  identification:
    name: Photo
    type: PL/SQL Dynamic Content

  source:
    pl/sql-code: |
      begin
        htp.p(dbms_lob.getlength(hdr_ui.bio_photo(:P10_ID)));
      end;

  layout:
    sequence: 20
    parent-region: Admin # 12337047553723501

buttons:
- # ====== Button: SAVE ========================================
  id: 11995428796685649
  identification:
    button-name: SAVE
    label: Save

  layout:
    sequence: 10
    region: Admin # 12337047553723501

processes:
- # ====== Process: Save Override Info With A Very Long Name That APEX Shortens =
  id: 12340180063723532
  identification:
    name: Save Override Info With A Very Long Name That APEX Shortens In The Header
    type: Execute Code
    execution-chain: None

  source:
    location: Local Database
    language: PL/SQL
    pl/sql-code: |
      begin
        :P10_X := hdr_ui.bio_photo(:P10_ID);
      end;

  execution:
    sequence: 30
    point: Processing

  server-side-condition:
    when-button-pressed: SAVE # 11995428796685649

  security:
    authorization-scheme: {proc_scheme}

"""


def _yaml(page_scheme="", region_scheme="", proc_scheme="") -> str:
    return PAGE_YAML.format(page_scheme=page_scheme, region_scheme=region_scheme, proc_scheme=proc_scheme)


def test_yaml_components_read_with_their_schemes():
    blocks, _f, _files, info = apex_export.extract_yaml_full(_yaml(region_scheme="HR Admin # 5001"),
                                                            "readable/application/pages/p00010.yaml")
    region = next(b for b in blocks if b.comp == "create_page_plug")
    proc = next(b for b in blocks if b.comp == "create_page_process")
    assert region.label == "صفحة 10 › منطقة: Photo" and region.page == "10" and region.scheme == "HR Admin"
    assert proc.label == "صفحة 10 › عملية: Save Override Info With A Very Long Name That APEX Shortens In The Header"
    assert proc.scheme == "" and proc.button == ("SAVE", "HR Admin")   # when-button-pressed: named, not protection
    assert info["pages"]["10"] == {"public": False, "scheme": ""}
    assert apex_export.yaml_scheme("MODEL.LOV.MUST_NOT_BE_PUBLIC_USER") == "MUST_NOT_BE_PUBLIC_USER"
    assert apex_export.yaml_scheme("MODEL.LOV.NOT_W_ARGUMENT # 46995203801871514425") == "!46995203801871514425"
    assert apex_export.yaml_scheme("'{Not Enterprise Edition}' # 29951042215468222") == "!29951042215468222"
    assert apex_export.yaml_scheme("Level 100 Users # 1234") == "Level 100 Users"
    assert apex_export.scheme_name("Level 100 Users", {}) == "Level 100 Users"


def test_yaml_call_sites_and_protection(tmp_path):
    both = _yaml(region_scheme="HR Admin # 5001", proc_scheme="HR Admin # 5001")
    f = _one(tmp_path, {"hdr_ui.pkb": PKG, "readable/application/pages/p00010.yaml": both})
    assert f.extra["apex_protection"] == "all_protected" and f.extra["apex_schemes"] == ["HR Admin"]
    assert len(f.extra["apex_call_sites"]) == 2
    # the process only runs When Button Pressed on a button in the protected region: not protection
    f = _one(tmp_path / "btn", {"hdr_ui.pkb": PKG, "readable/application/pages/p00010.yaml": _yaml(region_scheme="HR Admin # 5001")})
    assert f.severity == "high" and f.extra["apex_button_not_protection"]["button"] == "SAVE"
    assert not has_arabic(to_en(f.advice))
    # twins: a scheme that only requires sign-in, a negated scheme, none
    for scheme in ("MODEL.LOV.MUST_NOT_BE_PUBLIC_USER", "'{Not HR Admin}' # 5001", ""):
        f = _one(tmp_path / str(len(scheme)), {"hdr_ui.pkb": PKG,
                                                 "readable/application/pages/p00010.yaml": _yaml(region_scheme=scheme)})
        assert f.severity == "high", scheme


def test_yaml_page_and_application_schemes(tmp_path):
    f = _one(tmp_path, {"hdr_ui.pkb": PKG, "readable/application/pages/p00010.yaml": _yaml(page_scheme="HR Admin # 5001")})
    assert f.extra["apex_protection"] == "all_protected"
    f = _one(tmp_path / "a", {"hdr_ui.pkb": PKG, "readable/application/f141.yaml": APP_YAML.format(scheme="HR Admin # 5001"),
                              "readable/application/pages/p00010.yaml": _yaml()})
    assert f.extra["apex_protection"] == "all_protected"
    f = _one(tmp_path / "p", {"hdr_ui.pkb": PKG, "readable/application/pages/p00010.yaml":
                              _yaml().replace("Page Requires Authentication", "Page Is Public")})
    assert f.severity == "high" and f.extra["apex_call_sites"][0]["reason"] == "صفحة عامة بلا تسجيل دخول"


SQL_PAGE = ("prompt --application/pages/page_00010\nbegin\nwwv_flow_imp_page.create_page(\n p_id=>10\n,p_name=>'Photos'\n);\n"
            + _region(12337047553723501, "Admin") + _region(12337047553723502, "Photo", parent=12337047553723501,
                                                            source="begin\n  htp.p(dbms_lob.getlength(hdr_ui.bio_photo(:P10_ID)));\nend;",
                                                            typ="NATIVE_DYNAMIC_CONTENT")
            + "end;\n/\n")


def test_both_forms_of_one_application_count_once(tmp_path):
    files = {"hdr_ui.pkb": PKG, "f141.sql": _app(SQL_PAGE), "readable/application/f141.yaml": APP_YAML.format(scheme=""),
             "readable/application/pages/p00010.yaml": _yaml()}
    findings = _scan(tmp_path, files)
    f = _apx024(findings)[0]
    labels = [c["component"] for c in f.extra["apex_call_sites"]]
    assert labels.count("صفحة 10 › منطقة: Photo") == 1, labels
    assert {c["file"] for c in f.extra["apex_call_sites"] if c["component"] == "صفحة 10 › منطقة: Photo"} == {"f141.sql"}
    # the process exists only in the YAML form: kept
    assert any("عملية" in x for x in labels)
    # twin: the YAML of another application (f142) is not a duplicate
    files["readable/application/f141.yaml"] = APP_YAML.format(scheme="").replace("id: 141", "id: 142")
    f = _apx024(_scan(tmp_path / "other", files))[0]
    labels = [c["component"] for c in f.extra["apex_call_sites"]]
    assert labels.count("صفحة 10 › منطقة: Photo") == 2, labels


def test_both_forms_do_not_double_report_findings(tmp_path):
    code = "begin\n  execute immediate 'delete from t where id = ' || :P10_ID;\nend;"
    sql = _app(_proc_page(10, code))
    yaml = ("---\n# ====== Page: Page 10 ====\nid: 10\nidentification: \n  name: Page 10\n\nprocesses: \n"
            "- # ====== Process: Proc 10 ====\n  id: 1\n  identification: \n    name: Proc 10\n    type: Execute Code\n\n"
            "  source: \n    language: PL/SQL\n    pl/sql-code: |\n      begin\n"
            "        execute immediate 'delete from t where id = ' || :P10_ID;\n      end;\n")
    app_yaml = APP_YAML.format(scheme="")
    both = [f for f in _scan(tmp_path, {"f141.sql": sql, "readable/application/f141.yaml": app_yaml,
                                        "readable/application/pages/p00010.yaml": yaml}) if f.rule_id == "DF004"]
    assert [f.file for f in both] == ["f141.sql"]
    # twin: the YAML alone is still analysed and reported
    alone = [f for f in _scan(tmp_path / "y", {"readable/application/pages/p00010.yaml": yaml}) if f.rule_id == "DF004"]
    assert len(alone) == 1


# =================================================================== 4. deinstall / upgrade scripts
def test_deinstall_and_upgrade_scripts_are_analysed(tmp_path):
    rpt = ("create or replace procedure purge_rpt is\nbegin\n  execute immediate 'drop table ' || v('P1_TABLE');\n"
           "end;\n/")
    deinstall = ("begin\nwwv_flow_imp_shared.create_install(\n p_id=>wwv_flow_imp.id(7000)\n"
                 f",p_deinstall_script_clob=>{_join(rpt)}\n);\nend;\n/\n")
    _b, _f, _x, info = apex_export.extract_full(HEAD + deinstall, "f141.sql")
    assert [x[2] for x in info["scripts"]] == ["سكربت إزالة كائنات الدعم"]
    upgrade = _install(PKG).replace("'INSTALL'", "'UPGRADE'")
    _b, _f, _x, info = apex_export.extract_full(HEAD + upgrade, "f141.sql")
    assert [x[2] for x in info["scripts"]] == ["سكربت ترقية كائنات الدعم: hdr_ui"]
    assert to_en("سكربت ترقية كائنات الدعم: hdr_ui") == "Supporting Objects Upgrade Script: hdr_ui"
    findings = _scan(tmp_path, {"f141.sql": HEAD + deinstall + upgrade})
    df = [f for f in findings if f.rule_id == "DF004"]
    assert df and df[0].extra["apex_component"] == "سكربت إزالة كائنات الدعم"
    assert "[Supporting Objects Deinstallation Script]" in to_en(df[0].snippet)
    a = _apx024(findings)
    assert len(a) == 1 and a[0].extra["apex_component"] == "سكربت ترقية كائنات الدعم: hdr_ui"


def test_varchar2_table_script_form_of_apex_24():
    code = "create or replace procedure p4 is\nbegin\n  execute immediate 'delete from t';\nend;\n/"
    lines = code.split("\n")
    export = ("begin\nwwv_flow_imp.g_varchar2_table := wwv_flow_imp.empty_varchar2_table;\n"
              "wwv_flow_imp.g_varchar2_table(1) := '" + lines[0] + "'||wwv_flow.LF||\n'" + lines[1] + "'||wwv_flow.LF||\n'  exec';\n"
              "wwv_flow_imp.g_varchar2_table(2) := 'ute immediate ''delete from t'';'||wwv_flow.LF||\n'end;'||wwv_flow.LF||\n'/';\n"
              "wwv_flow_imp_shared.create_install_script(\n p_id=>wwv_flow_imp.id(1)\n,p_name=>'p4'\n,p_script_type=>'INSTALL'\n"
              ",p_script_clob=>wwv_flow_imp.varchar2_to_clob(wwv_flow_imp.g_varchar2_table)\n);\nend;\n/\n")
    _b, _f, _x, info = apex_export.extract_full(export, "f.sql")
    line, script, _label = info["scripts"][0]
    assert [x for x in script.split("\n") if x] == lines
    rows = export.split("\n")
    for k, text in enumerate(script.split("\n")):
        if text.strip():
            assert text.split()[0][:4] in rows[line - 1 + k]        # where the line starts (pieces split mid-word)


# =================================================================== 5. APEX 4 variable sources
APEX4 = """set define off
begin
wwv_flow_api.set_version(p_version_yyyy_mm_dd=>'2012.01.01');
end;
/
declare
  s varchar2(32767) := null;
begin
s := null;
wwv_flow_api.create_page (
  p_id => 10,
  p_name => 'Report');
end;
/
declare
  s varchar2(32767) := null;
begin
s := null;
s:=s||'begin'||unistr('\\000a')||
'  execute immediate ''delete from t where id = '' || :P10_ID;'||unistr('\\000a')||
'end;';

wwv_flow_api.create_page_plug (
  p_id=> 3523513552840315 + wwv_flow_api.g_id_offset,
  p_flow_id=> wwv_flow.g_flow_id,
  p_page_id=> 10,
  p_plug_name=> 'Run',
  p_plug_source=> s,
  p_plug_source_type=> 'PLSQL_PROCEDURE',
  p_plug_display_point=> 'AFTER_SHOW_ITEMS');
end;
/
declare
  s varchar2(32767) := null;
begin
s := null;
s:=s||'<p>Example: begin execute immediate ''x''; end;</p>';

wwv_flow_api.create_page_plug (
  p_id=> 3523513552840316 + wwv_flow_api.g_id_offset,
  p_page_id=> 10,
  p_plug_name=> 'Help',
  p_plug_source=> s,
  p_plug_source_type=> 'STATIC_TEXT');
end;
/
declare
  p varchar2(32767) := null;
begin
p:=p||'begin'||unistr('\\000a')||
'  hdr_ui.bio_photo(:P10_ID);'||unistr('\\000a')||
'end;';

wwv_flow_api.create_page_process(
  p_id     => 1 + wwv_flow_api.g_id_offset,
  p_flow_id=> wwv_flow.g_flow_id,
  p_flow_step_id => 10,
  p_process_sequence=> 10,
  p_process_point=> 'AFTER_SUBMIT',
  p_process_type=> 'PLSQL',
  p_process_name=> 'Get photo',
  p_process_sql_clob => p);
end;
/
"""


def test_apex4_region_and_process_sources_in_a_variable(tmp_path):
    blocks, _f, _x, _i = apex_export.extract_full(APEX4, "f100.sql")
    run = next(b for b in blocks if b.label == "صفحة 10 › منطقة: Run")
    assert run.kind == "plsql" and run.code.split("\n")[1].strip().startswith("execute immediate")
    rows = APEX4.split("\n")
    assert rows[run.line].startswith("'  execute immediate")      # line 2 of the code is the export's next line
    help_ = next(b for b in blocks if b.label == "صفحة 10 › منطقة: Help")
    assert help_.kind == "html"                                    # APEX 4 static region: text, not code
    proc = next(b for b in blocks if b.comp == "create_page_process")
    assert proc.kind == "plsql" and "hdr_ui.bio_photo" in proc.code
    df = [f for f in analyze_project({"f100.sql": APEX4}) if f.rule_id == "DF004"]
    assert [f.line for f in df] == [_lines_of(APEX4, "execute immediate ''delete")[0]]
    f = _one(tmp_path, {"hdr_ui.pkb": PKG, "f100.sql": APEX4})
    assert f.extra["apex_call_sites"][0]["line"] == _lines_of(APEX4, "hdr_ui.bio_photo(:P10_ID)")[0]


# =================================================================== 6. APX024: which way a test of the answer goes
GUARD_PKG = _package(GUARD, SIBLINGS)
PHOTO = """  function bio_photo(p_emp_id in number, p_flag in varchar2 default null) return blob is
    l_photo blob;
  begin
{check}    select photo into l_photo from hr_photos where emp_id = p_emp_id;
    return l_photo;
  end bio_photo;
"""
RAISE = "      raise_application_error(-20001, 'no');\n"


def _flagged(check: str) -> list:
    text = _package(GUARD, SIBLINGS, PHOTO.format(check=check))
    specs, bodies = plsql_authz.collect(text, "x.pkb")
    return [f for f in plsql_authz.findings(specs, bodies, {"x.pkb": text.split("\n")}) if f.extra["routine"] == "BIO_PHOTO"]


COVERED = {
    "= false then raise": f"    if can_view(p_emp_id) = false then\n{RAISE}    end if;\n",
    "false = (reversed)": f"    if false = can_view(p_emp_id) then\n{RAISE}    end if;\n",
    "not (…)": f"    if not (can_view(p_emp_id)) then\n{RAISE}    end if;\n",
    "!= true": f"    if can_view(p_emp_id) != true then\n{RAISE}    end if;\n",
    "<> true": f"    if can_view(p_emp_id) <> true then\n{RAISE}    end if;\n",
    "nvl(…, false) = false": f"    if nvl(can_view(p_emp_id), false) = false then\n{RAISE}    end if;\n",
    "= 'N' (varchar2 answer)": f"    if user_access(p_emp_id) = 'N' then\n{RAISE}    end if;\n",
    "case when not": f"    case when not can_view(p_emp_id) then\n{RAISE}    else null;\n    end case;\n",
    "not … or p_flag (fails whenever the check fails)": f"    if not can_view(p_emp_id) or p_flag = 'X' then\n{RAISE}    end if;\n",
    "variable = false": f"    if l_ok = false then\n{RAISE}    end if;\n",
}


@pytest.mark.parametrize("case", sorted(COVERED))
def test_failing_branch_forms_cover_the_access(case):
    check = COVERED[case]
    if "l_ok" in check:
        assert not _flagged_var("    l_ok := can_view(p_emp_id);\n" + check), case
    else:
        assert not _flagged(check), case


def _flagged_var(check: str) -> list:
    text = _package(GUARD, SIBLINGS, PHOTO.format(check=check).replace("    l_photo blob;\n", "    l_photo blob;\n    l_ok boolean;\n"))
    specs, bodies = plsql_authz.collect(text, "x.pkb")
    return [f for f in plsql_authz.findings(specs, bodies, {"x.pkb": text.split("\n")}) if f.extra["routine"] == "BIO_PHOTO"]


def test_true_branch_holding_the_access_is_covered():
    check = ("    if can_view(p_emp_id) = true then\n      select photo into l_photo from hr_photos where emp_id = p_emp_id;\n"
             "      return l_photo;\n    end if;\n    return null;\n")
    text = _package(GUARD, SIBLINGS, PHOTO.format(check="").replace(
        "    select photo into l_photo from hr_photos where emp_id = p_emp_id;\n    return l_photo;\n", check))
    specs, bodies = plsql_authz.collect(text, "x.pkb")
    assert not [f for f in plsql_authz.findings(specs, bodies, {"x.pkb": text.split("\n")}) if f.extra["routine"] == "BIO_PHOTO"]
    # twin: the access in the ELSE branch of the same test
    other = ("    if can_view(p_emp_id) = true then\n      null;\n    else\n      select photo into l_photo from hr_photos where emp_id = p_emp_id;\n"
             "      return l_photo;\n    end if;\n    return null;\n")
    text = _package(GUARD, SIBLINGS, PHOTO.format(check="").replace(
        "    select photo into l_photo from hr_photos where emp_id = p_emp_id;\n    return l_photo;\n", other))
    specs, bodies = plsql_authz.collect(text, "x.pkb")
    assert [f.extra["coverage"] for f in plsql_authz.findings(specs, bodies, {"x.pkb": text.split("\n")})
            if f.extra["routine"] == "BIO_PHOTO"] == ["partial"]


FLAGGED = {
    # near-miss twins of COVERED (still reported); 1.4 also missed the AND form (it read any NOT as the failing
    # branch), while it reported the COVERED forms (= FALSE, != TRUE …) as unchecked
    "= true then raise": f"    if can_view(p_emp_id) = true then\n{RAISE}    end if;\n",
    "not … and p_flag (skipped when p_flag differs)": f"    if not can_view(p_emp_id) and p_flag = 'Y' then\n{RAISE}    end if;\n",
    "nvl(…, true) = false (NULL passes)": f"    if not nvl(can_view(p_emp_id), true) then\n{RAISE}    end if;\n",
    "!= false then raise": f"    if can_view(p_emp_id) != false then\n{RAISE}    end if;\n",
    "compared with a variable": f"    if can_view(p_emp_id) = p_flag then\n{RAISE}    end if;\n",
}


@pytest.mark.parametrize("case", sorted(FLAGGED))
def test_wrong_way_or_partial_tests_are_flagged(case):
    found = _flagged(FLAGGED[case])
    assert [f.extra["coverage"] for f in found] == ["partial"], case


def test_or_in_a_guarding_condition_is_flagged():
    check = ("    if can_view(p_emp_id) or p_flag = 'Y' then\n      select photo into l_photo from hr_photos where emp_id = p_emp_id;\n"
             "      return l_photo;\n    end if;\n    return null;\n")
    text = _package(GUARD, SIBLINGS, PHOTO.format(check="").replace(
        "    select photo into l_photo from hr_photos where emp_id = p_emp_id;\n    return l_photo;\n", check))
    assert "return null" in text
    specs, bodies = plsql_authz.collect(text, "x.pkb")
    assert [f.extra["coverage"] for f in plsql_authz.findings(specs, bodies, {"x.pkb": text.split("\n")})
            if f.extra["routine"] == "BIO_PHOTO"] == ["partial"]


# =================================================================== 7. helpers that check on some paths only
PARTIAL_HELPER = """  procedure check_if(p_strict in boolean) is
  begin
    if p_strict then
      check_access('HR_PHOTO');
    end if;
  end check_if;
"""
FULL_HELPER = """  procedure check_photo(p_strict in boolean) is
  begin
    if p_strict then
      check_access('HR_PHOTO_STRICT');
    else
      check_access('HR_PHOTO');
    end if;
  end check_photo;
"""


def _with_helper(helper: str, call: str) -> list:
    text = _package(GUARD, helper, SIBLINGS, PHOTO.format(check=f"    {call};\n"))
    specs, bodies = plsql_authz.collect(text, "x.pkb")
    return [f for f in plsql_authz.findings(specs, bodies, {"x.pkb": text.split("\n")}) if f.extra["routine"] == "BIO_PHOTO"]


def test_helper_that_checks_on_some_paths_only_covers_nothing():
    found = _with_helper(PARTIAL_HELPER, "check_if(false)")
    assert len(found) == 1 and found[0].extra["coverage"] == "none"
    assert found[0].extra["partial_helpers"] == ["HDR_UI.CHECK_IF"]
    f = found[0]
    assert "ولا يُحتسب استدعاؤه HDR_UI.CHECK_IF تحققًا" in f.advice
    en = to_en(f.advice)
    assert not has_arabic(en), en
    assert "Its call to HDR_UI.CHECK_IF does not count as a check" in en


def test_helper_that_checks_on_every_path_counts():
    assert not _with_helper(FULL_HELPER, "check_photo(false)")


def test_partial_helper_note_with_apex_context_is_translated(tmp_path):
    text = _package(GUARD, PARTIAL_HELPER, SIBLINGS, PHOTO.format(check="    check_if(false);\n"))
    page = _proc_page(10, "begin\n  :P10_X := hdr_ui.bio_photo(:P10_ID);\nend;")
    f = _one(tmp_path, {"hdr_ui.pkb": text, "f141.sql": _app(page)})
    en = to_en(f.advice)
    assert not has_arabic(en), en
    assert "some of its paths only. HDR_UI.BIO_PHOTO is called in the scanned APEX application" in en


def test_boolean_helper_returning_false_on_failure_counts():
    helper = """  function photo_ok(p_emp_id in number) return boolean is
  begin
    if apex_authorization.is_authorized('PHOTO') then
      return true;
    end if;
    return false;
  end photo_ok;
"""
    assert not _with_helper(helper, "if not photo_ok(p_emp_id) then raise_application_error(-20001, 'no'); end if")
    # twin: it returns TRUE on the path that skips the check
    bad = helper.replace("    return false;\n", "    return p_emp_id > 0;\n")
    assert len(_with_helper(bad, "if not photo_ok(p_emp_id) then raise_application_error(-20001, 'no'); end if")) == 1


# =================================================================== 8. classification on real old exports
def test_item_label_is_not_an_ai_prompt():
    item = ("begin\nwwv_flow_imp_page.create_page_item(\n p_id=>wwv_flow_imp.id(1)\n,p_name=>'P1_X'\n"
            ",p_prompt=>'Total for &P1_DEPT.'\n,p_display_as=>'NATIVE_TEXT_FIELD'\n);\nend;\n/\n")
    _b, findings, _x = apex_export.extract(item, "f.sql")
    assert not [f for f in findings if f.rule_id == "APX005"]
    raw = item.replace("&P1_DEPT.", "&P1_DEPT!RAW.")
    assert [f.rule_id for f in apex_export.extract(raw, "f.sql")[1]] == ["APX003"]     # a label is HTML
    # twin: the system prompt of an AI configuration is still one
    ai = ("begin\nwwv_flow_imp_shared.create_ai_config(\n p_id=>wwv_flow_imp.id(2)\n,p_name=>'A'\n"
          ",p_system_prompt=>'You help &P1_DEPT. users'\n);\nend;\n/\n")
    assert [f.rule_id for f in apex_export.extract(ai, "f.sql")[1]] == ["APX005"]


def test_apex5_utilities_join_keeps_lines():
    export = ("begin\nwwv_flow_api.create_flow_process(\n p_id=>wwv_flow_api.id(1)\n,p_process_sequence=>1\n"
              ",p_process_point=>'ON_DEMAND'\n,p_process_type=>'NATIVE_PLSQL'\n,p_process_name=>'X'\n"
              ",p_process_sql_clob=>wwv_flow_utilities.join(wwv_flow_t_varchar2(\n'declare',\n'  v varchar2(100) := apex_application.g_x01;',\n"
              "'begin',\n'  execute immediate ''delete from t where id = '' || v;',\n'end;'))\n);\nend;\n/\n")
    blocks, _f, _x = apex_export.extract(export, "f.sql")
    assert blocks[0].code.split("\n")[0] == "declare"
    _u, d = pf.parse_plsql(apex_export.wrapped_plsql(blocks[0]))
    assert d["skipped"] == 0
    df = [f for f in analyze_project({"f.sql": export}) if f.rule_id == "DF004"]
    assert [f.line for f in df] == [_lines_of(export, "execute immediate")[0]]


def test_process_condition_is_code():
    export = ("begin\nwwv_flow_imp_page.create_page_process(\n p_id=>wwv_flow_imp.id(1)\n,p_flow_step_id=>1\n"
              ",p_process_type=>'NATIVE_PLSQL'\n,p_process_name=>'X'\n,p_process_sql_clob=>'null;'\n"
              ",p_process_when=>'&P1_FLAG. = ''Y'''\n,p_process_when_type=>'PLSQL_EXPRESSION'\n);\nend;\n/\n")
    _b, findings, _x = apex_export.extract(export, "f.sql")
    assert [f.rule_id for f in findings] == ["APX001"]


def test_compound_trigger_ending_in_bare_end_parses_quickly():
    trg = ("CREATE OR REPLACE TRIGGER apps__\nFOR UPDATE OR INSERT ON apps\nCOMPOUND TRIGGER\n"
           "  n SIMPLE_INTEGER := 0;\n  BEFORE EACH ROW IS\n  BEGIN\n    n := n + 1;\n  END BEFORE EACH ROW;\n"
           "  AFTER STATEMENT IS\n  BEGIN\n    log_rows(n);\n  END AFTER STATEMENT;\nEND;\n/\n")
    t = time.time()
    _u, d = pf.parse_plsql(trg)
    assert time.time() - t < 5 and d["skipped"] == 0 and d["statements"] >= 2


def test_apex4_variable_restarts_in_each_declare_block():
    two = APEX4 + APEX4[APEX4.index("declare\n  p varchar2"):].replace("Get photo", "Second").replace(
        "hdr_ui.bio_photo(:P10_ID)", "null")
    blocks, _f, _x, _i = apex_export.extract_full(two, "f100.sql")
    second = next(b for b in blocks if b.label.endswith("Second"))
    assert "bio_photo" not in second.code and second.code.split("\n")[1].strip() == "null;"


def test_apex4_row_processing_settings_are_not_code():
    export = APEX4.replace("'  hdr_ui.bio_photo(:P10_ID);'||unistr('\\000a')||\n'end;'", "'F|#OWNER#:T:P10_ID:ID'") \
        .replace("p:=p||'begin'||unistr('\\000a')||\n", "p:=p||")
    assert "p:=p||'F|#OWNER#" in export
    blocks, _f, _x, _i = apex_export.extract_full(export, "f100.sql")
    assert not [b for b in blocks if b.comp == "create_page_process"]


def test_yaml_plugin_code_is_declarations():
    yaml = ("---\n- # ====== Plugin: X ====\n  id: 1\n  identification: \n    name: X\n\n  source: \n    pl/sql-code: |\n"
            "      procedure render(p_region in apex_plugin.t_region) is\n        l_x varchar2(10);\n      begin\n"
            "        htp.p(l_x);\n      end;\n")
    blocks, _f, _x, _i = apex_export.extract_yaml_full(yaml, "readable/application/shared_components/plugins.yaml")
    assert [b.kind for b in blocks] == ["plsql_decls"]
    _u, d = pf.parse_plsql(apex_export.wrapped_plsql(blocks[0]))
    assert d["skipped"] == 0
