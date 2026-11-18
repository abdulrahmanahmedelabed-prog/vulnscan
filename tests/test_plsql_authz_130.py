"""Kashif 1.3.0: APX024, a PL/SQL package routine that does not check authorization while its sibling routines do
(CWE-862), from a user report on an Oracle APEX application: every public routine of HDR_UI called the package's
access check except bio_photo, which returned an employee's face photo (BLOB). Plus regression tests for the other
items of the same report (a sanitised Content-Disposition header, the sign-in page, kinds of skipped statements)."""

from vulnscan import apex_export, plsql_authz
from vulnscan.i18n import has_arabic, to_en
from vulnscan.scanner import scan_path, stmt_kind

GUARD = """  procedure check_access(p_function in varchar2) is
  begin
    if not apex_authorization.is_authorized(p_function) then
      raise_application_error(-20001, 'Not authorized');
    end if;
  end check_access;
"""

SIBLINGS = """  function employee_name(p_emp_id in number) return varchar2 is
    l_name varchar2(200);
  begin
    check_access('HR_VIEW');
    select first_name || ' ' || last_name into l_name from hr_employees where emp_id = p_emp_id;
    return l_name;
  end employee_name;

  procedure update_phone(p_emp_id in number, p_phone in varchar2) is
  begin
    hdr_ui.check_access('HR_EDIT');
    update hr_employees set phone = p_phone where emp_id = p_emp_id;
  end update_phone;

  function salary(p_emp_id in number) return number is
    l_sal number;
  begin
    check_access('HR_PAY');
    select salary into l_sal from hr_salaries where emp_id = p_emp_id;
    return l_sal;
  end;

  procedure delete_note(p_note_id in number) is
  begin
    check_access('HR_EDIT');
    delete from hr_notes where note_id = p_note_id;
  end delete_note;
"""

BIO_PHOTO = """  function bio_photo(p_emp_id in number) return blob is
    l_photo blob;
  begin
{check}    select photo into l_photo from hr_photos where emp_id = p_emp_id;
    return l_photo;
  end bio_photo;
"""


def _package(*parts: str, name: str = "hdr_ui") -> str:
    return f"create or replace package body {name} as\n\n" + "\n".join(parts) + f"\nend {name};\n/\n"


def _scan(tmp_path, files: dict) -> list:
    for rel, text in files.items():
        (tmp_path / rel).write_text(text)
    findings, _ = scan_path(tmp_path)
    return findings


def _apx024(findings) -> list:
    return [f for f in findings if f.rule_id == "APX024"]


# ------------------------------------------------------------------ the rule
def test_unchecked_blob_routine_among_checked_siblings_is_flagged(tmp_path):
    text = _package(GUARD, SIBLINGS, BIO_PHOTO.format(check=""))
    found = _apx024(_scan(tmp_path, {"hdr_ui.pkb": text}))
    assert len(found) == 1, [(f.line, f.snippet) for f in found]
    f = found[0]
    assert (f.file, f.severity, f.cwe) == ("hdr_ui.pkb", "medium", "CWE-862")
    assert f.snippet.startswith("function bio_photo") and text.split("\n")[f.line - 1].strip() == f.snippet
    assert f.extra["confidence"] == "tentative"
    assert (f.extra["routine"], f.extra["guard"], f.extra["guarded_siblings"], f.extra["siblings"]) == \
        ("BIO_PHOTO", "HDR_UI.CHECK_ACCESS", 4, 5)
    assert "HDR_UI.BIO_PHOTO" in f.advice and "HDR_UI.CHECK_ACCESS" in f.advice and "4 من 5" in f.advice
    en = to_en(f.advice)
    assert not has_arabic(en) and not has_arabic(to_en(f.title_ar)), en
    assert "4 of the 5 public routines" in en and "returns a BLOB value read by a query (hr_photos)" in en
    assert "Add the same check (HDR_UI.CHECK_ACCESS)" in en


def test_same_package_with_the_check_added_is_not_flagged(tmp_path):
    text = _package(GUARD, SIBLINGS, BIO_PHOTO.format(check="    check_access('HR_PHOTO');\n"))
    assert not _apx024(_scan(tmp_path, {"hdr_ui.pkb": text}))


def test_a_different_authorization_call_counts_as_a_check(tmp_path):
    check = "    if not apex_authorization.is_authorized('PHOTO') then\n      raise_application_error(-20002, 'no');\n    end if;\n"
    text = _package(GUARD, SIBLINGS, BIO_PHOTO.format(check=check))
    assert not _apx024(_scan(tmp_path, {"hdr_ui.pkb": text}))


def test_package_without_a_guard_has_no_findings(tmp_path):
    no_guard = SIBLINGS.replace("    check_access('HR_VIEW');\n", "").replace("    hdr_ui.check_access('HR_EDIT');\n", "") \
        .replace("    check_access('HR_PAY');\n", "").replace("    check_access('HR_EDIT');\n", "")
    assert "check_access" not in no_guard
    text = _package(no_guard, BIO_PHOTO.format(check=""))
    assert not _apx024(_scan(tmp_path, {"hdr_ui.pkb": text}))


def test_guard_used_by_too_few_siblings_is_not_a_guard(tmp_path):
    # 2 of 5 data routines check: below 3 routines and 60%, so the package has no consistent check to compare with
    few = SIBLINGS.replace("    check_access('HR_PAY');\n", "").replace("    check_access('HR_EDIT');\n", "")
    text = _package(GUARD, few, BIO_PHOTO.format(check=""))
    assert not _apx024(_scan(tmp_path, {"hdr_ui.pkb": text}))


def test_guard_reached_through_an_internal_helper_is_not_flagged(tmp_path):
    helper = """  procedure assert_photo_access(p_emp_id in number) is
  begin
    check_access('HR_PHOTO');
  end assert_photo_access;
"""
    via = """  function bio_photo(p_emp_id in number) return blob is
    l_photo blob;
  begin
    assert_photo_access(p_emp_id);
    select photo into l_photo from hr_photos where emp_id = p_emp_id;
    return l_photo;
  end bio_photo;
"""
    # the siblings themselves reach apex_authorization.is_authorized through check_access (a helper of the package)
    text = _package(GUARD, helper, SIBLINGS, via)
    assert not _apx024(_scan(tmp_path, {"hdr_ui.pkb": text}))
    specs, bodies = plsql_authz.collect(text, "hdr_ui.pkb")
    view = plsql_authz._Pkg(bodies[0], {r.name for r in bodies[0].routines})
    assert {"check_access", "assert_photo_access", "bio_photo", "employee_name"} <= \
        view.reach(lambda c: c == "apex_authorization.is_authorized")


def test_pure_computation_without_a_check_is_not_flagged(tmp_path):
    pure = """  function initials(p_first in varchar2, p_last in varchar2) return varchar2 is
  begin
    return upper(substr(p_first, 1, 1) || substr(p_last, 1, 1));
  end initials;

  function age_band(p_age in number) return varchar2 is
  begin
    case when p_age < 30 then return 'A'; when p_age < 50 then return 'B'; else return 'C'; end case;
  end age_band;
"""
    text = _package(GUARD, SIBLINGS, pure)
    assert not _apx024(_scan(tmp_path, {"hdr_ui.pkb": text}))


def test_spec_decides_what_is_public_and_a_private_routine_is_not_flagged(tmp_path):
    spec = """create or replace package hdr_ui authid definer as
  function employee_name(p_emp_id in number) return varchar2;
  procedure update_phone(p_emp_id in number, p_phone in varchar2);
  function salary(p_emp_id in number) return number;
  procedure delete_note(p_note_id in number);
  procedure check_access(p_function in varchar2);
end hdr_ui;
/
"""
    private = """  function photo_row(p_emp_id in number) return blob is
    l_photo blob;
  begin
    select photo into l_photo from hr_photos where emp_id = p_emp_id;
    return l_photo;
  end photo_row;
"""
    body = _package(GUARD, SIBLINGS, private)
    assert not _apx024(_scan(tmp_path, {"hdr_ui.pks": spec, "hdr_ui.pkb": body}))
    # declared in the spec, the same routine is public and reported (the spec is read from another file)
    (tmp_path / "hdr_ui.pks").write_text(spec.replace("end hdr_ui;", "  function photo_row(p_emp_id in number) return blob;\nend hdr_ui;"))
    found = _apx024(scan_path(tmp_path)[0])
    assert [(f.file, f.extra["routine"], f.extra["spec_seen"]) for f in found] == [("hdr_ui.pkb", "PHOTO_ROW", True)]


def test_without_spec_a_routine_called_inside_the_package_is_a_private_helper(tmp_path):
    helper_user = """  function photo_html(p_emp_id in number) return varchar2 is
  begin
    check_access('HR_PHOTO');
    return '<img src="data:image/jpeg;base64,' || photo_b64(p_emp_id) || '">';
  end photo_html;

  function photo_b64(p_emp_id in number) return clob is
    l_photo blob;
  begin
    select photo into l_photo from hr_photos where emp_id = p_emp_id;
    return apex_web_service.blob2clobbase64(l_photo);
  end photo_b64;
"""
    text = _package(GUARD, SIBLINGS, helper_user)
    assert not _apx024(_scan(tmp_path, {"hdr_ui.pkb": text}))


def test_unchecked_dml_and_download_are_flagged_with_what_they_access(tmp_path):
    more = """  procedure purge_notes(p_emp_id in number) is
  begin
    delete from hr_notes where emp_id = p_emp_id;
  end purge_notes;

  procedure download_cv(p_emp_id in number) is
    l_doc blob;
  begin
    select cv into l_doc from hr_documents where emp_id = p_emp_id;
    owa_util.mime_header('application/pdf', false);
    owa_util.http_header_close;
    wpg_docload.download_file(l_doc);
  end download_cv;
"""
    text = _package(GUARD, SIBLINGS, SIBLINGS.replace("employee_name", "employee_name2").replace("update_phone", "update_phone2")
                    .replace("function salary", "function salary2").replace("end;", "end salary2;")
                    .replace("delete_note", "delete_note2"), more)
    found = {f.extra["routine"]: to_en(f.advice) for f in _apx024(_scan(tmp_path, {"hdr_ui.pkb": text}))}
    assert set(found) == {"PURGE_NOTES", "DOWNLOAD_CV"}, found
    assert "changes data (DML) (hr_notes)" in found["PURGE_NOTES"]
    assert "writes data to the browser (htp / wpg_docload)" in found["DOWNLOAD_CV"]
    assert "8 of the 10 public routines" in found["PURGE_NOTES"]


def test_rule_is_registered_and_translated():
    sev, cwe, title, title_ar, advice = apex_export.CONFIG_RULES["APX024"]
    assert (sev, cwe) == ("medium", "CWE-862")
    assert not has_arabic(to_en(title_ar)) and not has_arabic(to_en(advice))
    from vulnscan.taint import TAINT_RULES
    assert any(r["id"] == "APX024" for r in TAINT_RULES)


def test_guard_names():
    yes = ["apex_authorization.is_authorized", "is_hr_admin", "has_role", "APEX_UTIL.PUBLIC_CHECK_AUTHORIZATION", "hr.sec_pkg.has_privilege",
           "check_access", "can_edit", "is_allowed", "user_has_role", "assert_user_owns_row", "require_admin",
           "authz.check", "verify_permission"]
    no = ["check_dates", "assert_positive", "require_value", "get_access_log", "upper", "htp.p", "log_access_attempt"]
    assert all(plsql_authz._looks_auth(n) for n in yes), [n for n in yes if not plsql_authz._looks_auth(n)]
    assert not any(plsql_authz._looks_auth(n) for n in no), [n for n in no if plsql_authz._looks_auth(n)]


def test_malformed_text_never_fails(tmp_path):
    for text in ("create package body", "create or replace package body p as procedure", "create package p as function",
                 "create or replace package body p as\n procedure a is begin if x then\n"):
        plsql_authz.collect(text, "x.pkb")


# ------------------------------------------------------------------ other items of the same report
DOWNLOAD = """create or replace package body doc_dl as
  procedure download_item is
    l_name varchar2(400) := v('P1_FILE');
    l_blob blob;
  begin
    l_name := regexp_replace(l_name, '[^A-Za-z0-9_-]', '');
    select doc into l_blob from docs where name = l_name;
    owa_util.mime_header('application/pdf', false);
    htp.p('Content-Length: ' || dbms_lob.getlength(l_blob));
    htp.p('Content-Disposition: attachment; filename="' || l_name || '.pdf"');
    owa_util.http_header_close;
    wpg_docload.download_file(l_blob);
  end download_item;

  procedure download_raw is
    l_name varchar2(400) := v('P1_FILE');
    l_blob blob;
  begin
    owa_util.mime_header('application/pdf', false);
    htp.p('Content-Disposition: attachment; filename="' || l_name || '.pdf"');
    owa_util.http_header_close;
    wpg_docload.download_file(l_blob);
  end download_raw;
end doc_dl;
/
"""


def test_sanitised_content_disposition_is_neither_xss_nor_header_injection(tmp_path):
    fs = [(f.rule_id, f.line) for f in _scan(tmp_path, {"doc_dl.pkb": DOWNLOAD}) if f.rule_id.startswith("DF")]
    assert not [x for x in fs if x[1] <= 13], fs            # regexp_replace keeps letters, digits, _ and - only
    assert ("DF008", 20) in fs and not [x for x in fs if x[0] == "DF013"], fs    # unsanitised: header injection


_LOGIN_EXPORT = ("begin\n"
                 "wwv_flow_imp_page.create_page(p_id=>9999, p_name=>'Sign In', p_alias=>'LOGIN', p_page_is_public_y_n=>'Y',"
                 " p_protection_level=>'U');\n"
                 "wwv_flow_imp_page.create_page_process(p_id=>1, p_process_point=>'AFTER_SUBMIT', p_process_type=>'NATIVE_PLSQL',"
                 " p_process_name=>'Login', p_process_sql_clob=>'apex_authentication.login(p_username => :P9999_USERNAME,"
                 " p_password => :P9999_PASSWORD);');\n"
                 "wwv_flow_imp_page.create_page(p_id=>50, p_name=>'Entry', p_page_is_public_y_n=>'Y', p_protection_level=>'U');\n"
                 "wwv_flow_imp_page.create_page_process(p_id=>2, p_process_point=>'AFTER_SUBMIT', p_process_type=>'NATIVE_PLSQL',"
                 " p_process_name=>'Enter', p_process_sql_clob=>'apex_authentication.login(p_username => :P50_U, p_password => :P50_P);');\n"
                 "end;\n/\n")


def test_sign_in_page_raises_neither_apx016_nor_apx018():
    _, fs, _ = apex_export.extract(_LOGIN_EXPORT, "f100.sql")
    assert not [f for f in fs if f.rule_id in ("APX016", "APX018")], [(f.rule_id, f.line) for f in fs]


def test_skipped_statement_notes_name_the_statement_kind(tmp_path):
    (tmp_path / "bad.sql").write_text("begin\n  x := := 1;\n  if x then foo(;\n  end if;\nend;\n/\n"
                                      "create or replace package body p as\n  l_x number := ) ;\n"
                                      "  procedure a is begin null; end;\nend;\n/\n")
    notes: list = []
    scan_path(tmp_path, notes=notes)
    det = [to_en(n) for n in notes if n.startswith("عبارة متخطّاة")]
    assert det == ["Skipped statement (assignment) at bad.sql:2: unsupported or unexpected construct: ':='",
                   "Skipped statement (procedure call) at bad.sql:3: unsupported or unexpected construct: ';'",
                   "Skipped statement (variable declaration) at bad.sql:8: unsupported or unexpected construct: ')'"], det
    assert stmt_kind("SQL UPDATE") == ("جملة SQL ‏UPDATE", "SQL UPDATE statement")
    assert stmt_kind("CREATE PACKAGE BODY")[1] == "CREATE PACKAGE BODY statement"
    assert stmt_kind("<script>") == ("", "")
