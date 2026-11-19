"""Kashif 1.4.0: APX024 follows the paths of a routine. An authorization call counts only when every path to the data
access passes it first: a check in one branch of IF / ELSIF / CASE, in an exception handler, inside a loop or after
the access no longer silences the rule, while a check at the start, before the access, or in a condition whose failing
branch leaves the routine (`if not can_view(…) then raise_application_error(…); end if;`) still does."""

import pytest

from vulnscan import plsql_authz
from vulnscan.i18n import has_arabic, to_en
from vulnscan.scanner import scan_path

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
  end salary;

  procedure delete_note(p_note_id in number) is
  begin
    check_access('HR_EDIT');
    delete from hr_notes where note_id = p_note_id;
  end delete_note;
"""

PHOTO = """  function bio_photo(p_emp_id in number, p_mode in varchar2 default null) return blob is
    l_b blob;
  begin
{body}
  end bio_photo;
"""

READ = """    select photo into l_b from hr_photos where emp_id = p_emp_id;
    return l_b;"""


def _package(*parts: str, name: str = "hdr_ui") -> str:
    return f"create or replace package body {name} as\n\n" + "\n".join(parts) + f"\nend {name};\n/\n"


def _apx024(text: str, rel: str = "hdr_ui.pkb") -> list:
    specs, bodies = plsql_authz.collect(text, rel)
    return plsql_authz.findings(specs, bodies, {rel: text.split("\n")})


def _photo(body: str) -> list:
    return [f for f in _apx024(_package(GUARD, SIBLINGS, PHOTO.format(body=body))) if f.extra["routine"] == "BIO_PHOTO"]


def _line_of(text: str, needle: str) -> int:
    return next(i for i, ln in enumerate(text.split("\n"), 1) if needle in ln)


# ------------------------------------------------------------------ flagged: a path reaches the data without the check
FLAGGED = {
    "guard in one branch of IF": """    if p_mode = 'X' then
      hdr_ui.check_access('HR_PHOTO');
    end if;
""" + READ,
    "guard only in the exception handler": """    begin
      select photo into l_b from hr_photos where emp_id = p_emp_id;
      return l_b;
    exception
      when no_data_found then
        check_access('HR_PHOTO');
        raise;
    end;""",
    "guard whose failure WHEN OTHERS swallows": """    begin
      check_access('HR_PHOTO');
    exception
      when others then
        null;
    end;
""" + READ,
    "guard in the ELSIF branch only": """    if p_mode = 'A' then
      null;
    elsif p_mode = 'B' then
      check_access('HR_PHOTO');
    end if;
""" + READ,
    "guard in IF and ELSE but not ELSIF": """    if p_mode = 'A' then
      check_access('HR_PHOTO');
    elsif p_mode = 'B' then
      l_b := null;
    else
      check_access('HR_PHOTO2');
    end if;
""" + READ,
    "guard in one WHEN of a CASE": """    case p_mode
      when 'A' then check_access('HR_PHOTO');
      when 'B' then null;
      else l_b := null;
    end case;
""" + READ,
    "guard inside a loop that may not run": """    for r in (select role_name from user_roles where emp_id = p_emp_id) loop
      check_access(r.role_name);
    end loop;
""" + READ,
    "guard inside a WHILE loop": """    while p_mode is not null loop
      check_access('HR_PHOTO');
      exit;
    end loop;
""" + READ,
    "unguarded early return of the data": """    select photo into l_b from hr_photos where emp_id = p_emp_id;
    if p_mode = 'FAST' then
      return l_b;
    end if;
    check_access('HR_PHOTO');
    return l_b;""",
    "guard in IF, ELSE returns early on one path only": """    if p_mode = 'X' then
      check_access('HR_PHOTO');
    else
      if p_mode = 'Y' then
        return null;
      end if;
    end if;
""" + READ,
}


@pytest.mark.parametrize("case", sorted(FLAGGED))
def test_check_that_does_not_cover_every_path_is_flagged(case):
    text = _package(GUARD, SIBLINGS, PHOTO.format(body=FLAGGED[case]))
    found = [f for f in _apx024(text) if f.extra["routine"] == "BIO_PHOTO"]
    assert len(found) == 1, case
    f = found[0]
    assert f.extra["coverage"] == "partial" and f.extra["siblings"] == 5
    # siblings counted as in 1.3 (a guard call before the first access in the code: bio_photo itself when its check
    # comes first in the text), of which those whose check covers every path
    assert f.extra["guarded_siblings"] in (4, 5) and f.extra["covering_siblings"] == 4
    assert f.extra["unguarded_line"] == _line_of(text, "return l_b;")
    assert f"line {f.extra['unguarded_line']}" in to_en(f.advice)


def test_partial_message_is_distinct_and_translated():
    f = _photo(FLAGGED["guard in one branch of IF"])[0]
    en = to_en(f.advice)
    assert not has_arabic(en), en
    assert en.startswith("HDR_UI.BIO_PHOTO checks authorization on some paths only: the data access at line ")
    assert ("5 of the 5 public routines of the package call HDR_UI.CHECK_ACCESS before their first data access in the "
            "code (4 of them on every path)") in en
    assert "It returns a BLOB value read by a query (hr_photos)." in en
    assert "not in one branch, an exception handler or after the access" in en
    none = _photo(READ)[0]
    assert none.extra["coverage"] == "none" and none.extra["unguarded_line"] is None
    assert to_en(none.advice).startswith("HDR_UI.BIO_PHOTO does not check authorization, while 4 of the 5 public "
                                         "routines of the package call HDR_UI.CHECK_ACCESS before their first data "
                                         "access in the code (4 of them on every path).")


def test_check_after_the_dml_is_flagged():
    late = """  procedure purge_photo(p_emp_id in number) is
  begin
    delete from hr_photos where emp_id = p_emp_id;
    check_access('HR_EDIT');
  end purge_photo;
"""
    text = _package(GUARD, SIBLINGS, late)
    found = _apx024(text)
    assert [(f.extra["routine"], f.extra["coverage"]) for f in found] == [("PURGE_PHOTO", "partial")]
    assert found[0].extra["unguarded_line"] == _line_of(text, "delete from hr_photos")
    assert "changes data (DML) (hr_photos)" in to_en(found[0].advice)


def test_dml_before_a_loop_that_checks_is_flagged():
    loop = """  procedure purge_photo(p_emp_id in number) is
  begin
    delete from hr_photos where emp_id = p_emp_id;
    for i in 1 .. 3 loop
      check_access('HR_EDIT');
    end loop;
  end purge_photo;
"""
    text = _package(GUARD, SIBLINGS, loop)
    assert [(f.extra["routine"], f.extra["unguarded_line"]) for f in _apx024(text)] == \
        [("PURGE_PHOTO", _line_of(text, "delete from hr_photos"))]


def test_end_to_end_through_the_scanner(tmp_path):
    (tmp_path / "hdr_ui.pkb").write_text(_package(GUARD, SIBLINGS, PHOTO.format(body=FLAGGED["guard in one branch of IF"])))
    found = [f for f in scan_path(tmp_path)[0] if f.rule_id == "APX024"]
    assert [(f.extra["routine"], f.extra["coverage"]) for f in found] == [("BIO_PHOTO", "partial")]


# ------------------------------------------------------------------ not flagged: the check dominates the access
SAFE = {
    "guard first": "    check_access('HR_PHOTO');\n" + READ,
    "guard before the access in straight-line code": """    l_b := null;
    dbms_output.put_line('photo ' || p_emp_id);
    hdr_ui.check_access('HR_PHOTO');
""" + READ,
    "failing branch raises": """    if not hdr_ui.can_view(p_emp_id) then
      raise_application_error(-20002, 'Not allowed');
    end if;
""" + READ,
    "failing branch returns": """    if not hdr_ui.can_view(p_emp_id) then
      return null;
    end if;
""" + READ,
    "failing branch raises an exception": """    if not can_view(p_emp_id) then
      raise no_data_found;
    end if;
""" + READ,
    "access only inside the guarded branch": """    if hdr_ui.can_view(p_emp_id) then
      select photo into l_b from hr_photos where emp_id = p_emp_id;
      return l_b;
    end if;
    return null;""",
    "apex_authorization in the condition": """    if not apex_authorization.is_authorized('HR_PHOTO') then
      raise_application_error(-20002, 'Not allowed');
    elsif p_mode = 'X' then
      l_b := null;
    end if;
""" + READ,
    "guard in every branch": """    if p_mode = 'A' then
      check_access('HR_PHOTO_A');
    elsif p_mode = 'B' then
      check_access('HR_PHOTO_B');
    else
      raise_application_error(-20003, 'Unknown mode');
    end if;
""" + READ,
    "guard in every WHEN of a CASE without ELSE": """    case
      when p_mode = 'A' then check_access('HR_PHOTO_A');
      when p_mode = 'B' then check_access('HR_PHOTO_B');
    end case;
""" + READ,
    "guard before a loop with the access inside": """    check_access('HR_PHOTO');
    for r in (select photo from hr_photos where emp_id = p_emp_id) loop
      l_b := r.photo;
    end loop;
    return l_b;""",
    "guard first in a nested block with a handler": """    begin
      check_access('HR_PHOTO');
      select photo into l_b from hr_photos where emp_id = p_emp_id;
    exception
      when no_data_found then
        l_b := null;
    end;
    return l_b;""",
    "guard in the declarations": "",
    "query of the row's owner before the check": """    select owner_id into l_owner from hr_photos where emp_id = p_emp_id;
    if not can_view(l_owner) then
      raise_application_error(-20002, 'Not allowed');
    end if;
""" + READ,
}


@pytest.mark.parametrize("case", sorted(SAFE))
def test_check_on_every_path_is_not_flagged(case):
    body = SAFE[case]
    text = _package(GUARD, SIBLINGS, PHOTO.format(body=body))
    if case == "guard in the declarations":
        text = text.replace("    l_b blob;\n  begin\n", "    l_ok boolean := can_view(p_emp_id);\n    l_b blob;\n  begin\n"
                            "    if not l_ok then\n      return null;\n    end if;\n" + READ + "\n")
    if "l_owner" in body:
        text = text.replace("    l_b blob;\n", "    l_b blob;\n    l_owner number;\n")
    assert not [f for f in _apx024(text) if f.extra["routine"] == "BIO_PHOTO"], case
    r = next(r for r in plsql_authz.collect(text, "x.pkb")[1][0].routines if r.name == "bio_photo")
    assert r.flow is not None, case                     # decided path by path, not by the lexical fallback


def test_helper_that_calls_the_guard_counts_where_it_is_called():
    helper = """  function photo_ok(p_emp_id in number) return boolean is
  begin
    check_access('HR_PHOTO');
    return true;
  end photo_ok;
"""
    first = PHOTO.format(body="    if not photo_ok(p_emp_id) then\n      return null;\n    end if;\n" + READ)
    assert not _apx024(_package(GUARD, helper, SIBLINGS, first))
    late = PHOTO.format(body="    if p_mode = 'X' then\n      if photo_ok(p_emp_id) then\n        null;\n      end if;\n"
                             "    end if;\n" + READ)
    assert [f.extra["coverage"] for f in _apx024(_package(GUARD, helper, SIBLINGS, late))] == ["partial"]


# ------------------------------------------------------------------ sibling counting
def test_sibling_with_a_conditional_check_is_reported_but_still_elects_the_guard():
    cond = """  procedure update_mail(p_emp_id in number, p_mail in varchar2) is
  begin
    if p_mail is not null then
      check_access('HR_EDIT');
    end if;
    update hr_employees set email = p_mail where emp_id = p_emp_id;
  end update_mail;
"""
    text = _package(GUARD, SIBLINGS, cond, PHOTO.format(body=READ))
    found = {f.extra["routine"]: f for f in _apx024(text)}
    assert set(found) == {"UPDATE_MAIL", "BIO_PHOTO"}
    assert {(f.extra["guarded_siblings"], f.extra["covering_siblings"], f.extra["siblings"]) for f in found.values()} \
        == {(5, 4, 6)}
    assert (found["UPDATE_MAIL"].extra["coverage"], found["BIO_PHOTO"].extra["coverage"]) == ("partial", "none")
    _specs, bodies = plsql_authz.collect(text, "x.pkb")
    view = plsql_authz._Pkg(bodies[0], {r.name for r in bodies[0].routines})
    relevant, checked, _s = plsql_authz._evaluate(view, "check_access")   # the election counts as in 1.3
    assert {r.name for r in checked} == {"employee_name", "update_phone", "salary", "delete_note", "update_mail"}


HR_API = """  procedure update_phone(p_emp_id in number, p_phone in varchar2) is
  begin
    check_access('HR_EDIT');
    update hr_employees set phone = p_phone where emp_id = p_emp_id;
  end update_phone;

  procedure delete_note(p_note_id in number) is
  begin
    check_access('HR_EDIT');
    delete from hr_notes where note_id = p_note_id;
  end delete_note;

  procedure update_email(p_emp_id in number, p_email in varchar2) is
  begin
    check_access('HR_EDIT');
    update hr_employees set email = p_email where emp_id = p_emp_id;
  end update_email;

  procedure update_title(p_emp_id in number, p_title in varchar2, p_self in varchar2) is
  begin
    {title}
    update hr_employees set title = p_title where emp_id = p_emp_id;
  end update_title;

  procedure update_dept(p_emp_id in number, p_dept in number, p_self in varchar2) is
  begin
    {dept}
    update hr_employees set dept_id = p_dept where emp_id = p_emp_id;
  end update_dept;

  procedure delete_employee(p_emp_id in number) is
{decl}  begin
{check}    delete from hr_employees where emp_id = p_emp_id;
  end delete_employee;
"""
COND = "if p_self = 'N' then\n      check_access('HR_EDIT');\n    end if;"
FIRST = "check_access('HR_EDIT');"


def _hr_api(title=FIRST, dept=FIRST, check="", decl="") -> dict:
    text = _package(GUARD, HR_API.format(title=title, dept=dept, check=check, decl=decl), name="hr_api")
    return {f.extra["routine"]: f for f in _apx024(text, "hr_api.pkb")}


def test_branch_guarded_siblings_do_not_hide_an_unchecked_routine():
    # 1.4.0 review (R4): 3 routines check first, 2 only when p_self = 'N', delete_employee never. Counted path by path
    # the guard covered 3 of 6 (< 60%) and nothing was reported; the election counts as in 1.3 again (5 of 6).
    found = _hr_api(title=COND, dept=COND)
    assert {r: f.extra["coverage"] for r, f in found.items()} == \
        {"DELETE_EMPLOYEE": "none", "UPDATE_TITLE": "partial", "UPDATE_DEPT": "partial"}
    f = found["DELETE_EMPLOYEE"]
    assert (f.extra["guarded_siblings"], f.extra["covering_siblings"], f.extra["siblings"]) == (5, 3, 6)
    assert "5 of the 6 public routines of the package call HR_API.CHECK_ACCESS before their first data access in " \
        "the code (3 of them on every path)" in to_en(f.advice)


@pytest.mark.parametrize("check,decl", [
    ("    $if false $then\n    check_access('HR_EDIT');\n    $end\n", ""),
    ("    $if dbms_db_version.ver_le_12 $then\n    check_access('HR_EDIT');\n    $end\n", ""),
    ("    $if false $then\n    null;\n    $else\n    check_access('HR_EDIT');\n    $end\n", ""),
    ("    l_ok := apex_authorization.is_authorized('HR_EDIT');\n", "    l_ok boolean;\n"),
    ("    if not apex_authorization.is_authorized('HR_EDIT') then\n      null;\n    end if;\n", ""),
    ("    if apex_authorization.is_authorized('HR_EDIT') then\n      null;\n    end if;\n", ""),
    ("    goto do_it;\n    check_access('HR_EDIT');\n    <<do_it>>\n", ""),
    ("    for r in (select 1 from dual) loop\n      exit;\n      check_access('HR_EDIT');\n    end loop;\n", ""),
    ("    begin\n      check_access('HR_EDIT');\n    exception\n      when others then null;\n    end;\n", ""),
], ids=["cc-false", "cc-cond", "cc-else-only", "result-unused", "if-not-null", "if-null", "goto", "exit-before", "others-swallows"])
def test_check_that_does_not_guard_the_delete_is_partial(check, decl):
    assert _hr_api(check=check, decl=decl)["DELETE_EMPLOYEE"].extra["coverage"] == "partial"


@pytest.mark.parametrize("check,decl", [
    ("    $if dbms_db_version.ver_le_12 $then\n    check_access('HR_OLD');\n    $else\n    check_access('HR_EDIT');\n"
     "    $end\n", ""),
    ("    l_ok := apex_authorization.is_authorized('HR_EDIT');\n    if not l_ok then\n      raise_application_error("
     "-20001, 'no');\n    end if;\n", "    l_ok boolean;\n"),
    ("    if apex_authorization.is_authorized('HR_EDIT') then\n      delete from hr_employees where emp_id = 0;\n"
     "    else\n      raise_application_error(-20001, 'no');\n    end if;\n", ""),
    ("    goto do_it;\n    null;\n    <<do_it>>\n    check_access('HR_EDIT');\n", ""),
], ids=["cc-both-branches", "variable-tested", "if-else-raise", "goto-forward-to-check"])
def test_check_that_guards_the_delete_is_not_reported(check, decl):
    found = _hr_api(check=check, decl=decl)
    assert "DELETE_EMPLOYEE" not in found, found["DELETE_EMPLOYEE"].extra


def test_siblings_using_the_raise_idiom_are_counted():
    idiom = SIBLINGS
    for perm in ("HR_VIEW", "HR_PAY", "HR_EDIT"):
        idiom = idiom.replace(f"    check_access('{perm}');\n",
                              f"    if not can_view('{perm}') then\n      raise_application_error(-20001, 'no');\n    end if;\n")
    idiom = idiom.replace("    hdr_ui.check_access('HR_EDIT');\n", "    if not can_view('HR_EDIT') then\n      return;\n    end if;\n")
    text = _package(GUARD, idiom, PHOTO.format(body=FLAGGED["guard in one branch of IF"].replace("hdr_ui.check_access",
                                                                                               "can_view")))
    found = _apx024(text)
    assert [(f.extra["routine"], f.extra["guard"], f.extra["guarded_siblings"], f.extra["covering_siblings"],
             f.extra["coverage"]) for f in found] == [("BIO_PHOTO", "HDR_UI.CAN_VIEW", 5, 4, "partial")]


# ------------------------------------------------------------------ robustness: unknown structure -> lexical answer
def test_unparsable_body_falls_back_to_the_lexical_answer():
    broken = FLAGGED["guard in one branch of IF"].replace("      hdr_ui.check_access('HR_PHOTO');\n",
                                                           "      hdr_ui.check_access('HR_PHOTO')\n")   # no ';'
    text = _package(GUARD, SIBLINGS, PHOTO.format(body=broken))
    r = next(r for r in plsql_authz.collect(text, "x.pkb")[1][0].routines if r.name == "bio_photo")
    assert r.flow is None
    assert not _apx024(text)                              # an authorization call is there: as before 1.4.0


def test_check_in_a_nested_subprogram_falls_back_to_the_lexical_answer():
    nested = PHOTO.format(body="    l_b := null;\n    guarded;\n" + READ).replace(
        "    l_b blob;\n", "    l_b blob;\n    procedure guarded is begin check_access('HR_PHOTO'); end guarded;\n")
    assert not _apx024(_package(GUARD, SIBLINGS, nested))


@pytest.mark.parametrize("text", [
    "create or replace package body p as function f return number is begin if x then return 1; end; end p;",
    "create or replace package body p as procedure a is begin case when x then null; end; end p;",
    "create or replace package body p as procedure a is begin loop null; end p;",
    "create or replace package body p as procedure a is begin <<l begin null; end; end p;",
    "create or replace package body p as procedure a is begin exit when; exception when then end; end p;",
])
def test_malformed_bodies_never_fail(text):
    specs, bodies = plsql_authz.collect(text, "x.pkb")
    plsql_authz.findings(specs, bodies, {"x.pkb": text.split("\n")})
    for b in bodies:
        for r in b.routines:
            assert plsql_authz._unguarded(r, [0], [1]) in (None, [], [1])
