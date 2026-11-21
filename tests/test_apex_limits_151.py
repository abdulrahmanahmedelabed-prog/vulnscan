"""Kashif 1.5.1: two APX024 limits of 1.5.0, closed.

1. A helper (or the routine itself) that catches the exception a failed check raises — WHEN OTHERS, and now a
   handler naming it: a package exception the scanned code raises, one bound to an application error code
   (pragma exception_init(e, -20xxx)), or another package's exception (`sec.e_denied`) — and does not re-raise,
   lets the caller go on as if the check passed: it is not a check.
2. A check's answer compared with a string decides which way the check went only for the yes / no values, compared
   as Oracle compares strings (case and all): 'Y', 'YES', 'TRUE', 'T', '1' pass, 'N', 'NO', 'FALSE', 'F', '0'
   fail. Any other value ('GUEST', 'n', 'admin') says nothing, so the code after it is not known to be checked.
Every change that reports less has a near-miss twin that is still reported, and the reverse."""

import pytest

from vulnscan import plsql_authz

SIBLINGS = """  procedure del_a(p_id number) is begin
    check_access(p_id);
    delete from docs where id = p_id;
  end;
  procedure del_b(p_id number) is begin
    check_access(p_id);
    delete from docs where id = p_id;
  end;
  procedure del_c(p_id number) is begin
    check_access(p_id);
    delete from docs where id = p_id;
  end;
"""
CHECK = """  procedure check_access(p_id number) is begin
    if sec.allowed(p_id) = 'N' then raise e_denied; end if;
  end;
"""


def _pkg(decls: str, helper: str, target: str, check: str = CHECK) -> str:
    return (f"create or replace package body p_docs as\n  e_denied exception;\n{decls}{helper}{check}{SIBLINGS}"
            f"  procedure target(p_id number) is begin\n{target}    delete from docs where id = p_id;\n  end;\n"
            "end p_docs;\n/\n")


def _target(text: str) -> list:
    specs, bodies = plsql_authz.collect(text, "p.pkb")
    return [f for f in plsql_authz.findings(specs, bodies, {"p.pkb": text.split("\n")}) if f.extra["routine"] == "TARGET"]


def _helper(handler: str) -> str:
    return f"  procedure ensure_ok(p_id number) is begin\n    check_access(p_id);\n  exception\n{handler}  end;\n"


ENSURE = "    ensure_ok(p_id);\n"


# =================================================================== 1. a handler that catches the check's failure
@pytest.mark.parametrize("handler", [
    "    when e_denied then null;\n",                                        # the package's own exception
    "    when e_denied then logger.log('denied');\n",                       # logging only
    "    when no_data_found or e_denied then null;\n",                       # one of several names
    "    when sec.e_denied then null;\n",                                    # another package's exception
])
def test_helper_swallowing_the_checks_exception_is_no_check(handler):
    found = _target(_pkg("", _helper(handler), ENSURE))
    assert len(found) == 1 and found[0].extra["coverage"] == "none", handler
    assert found[0].extra["partial_helpers"] == ["P_DOCS.ENSURE_OK"]


@pytest.mark.parametrize("handler", [
    "    when e_denied then logger.log('denied'); raise;\n",                 # re-raises
    "    when e_denied then raise_application_error(-20002, 'no');\n",      # raises another error
    "    when no_data_found then null;\n",                                   # an unrelated exception
    "    when dup_val_on_index then null;\n",
])
def test_helper_whose_handler_does_not_swallow_the_failure_counts(handler):
    assert not _target(_pkg("", _helper(handler), ENSURE)), handler


def test_exception_bound_to_an_application_error_code():
    check = ("  procedure check_access(p_id number) is begin\n"
             "    if sec.allowed(p_id) = 'N' then raise_application_error(-20001, 'denied'); end if;\n  end;\n")
    swallow = _helper("    when e_app then null;\n")
    found = _target(_pkg("  e_app exception;\n  pragma exception_init(e_app, -20001);\n", swallow, ENSURE, check))
    assert len(found) == 1
    # twin: an exception bound to an Oracle error (resource busy) is not the check's
    assert not _target(_pkg("  e_busy exception;\n  pragma exception_init(e_busy, -54);\n",
                            _helper("    when e_busy then null;\n"), ENSURE, check))


def test_the_routine_itself_swallowing_the_failure_is_partial():
    target = "    begin\n      check_access(p_id);\n    exception\n      when e_denied then null;\n    end;\n"
    found = _target(_pkg("", "", target))
    assert [f.extra["coverage"] for f in found] == ["partial"]
    assert not _target(_pkg("", "", target.replace("then null;", "then raise;")))


# =================================================================== 2. string answers
FN = """  function can_view_c(p_id number) return varchar2 is begin
    check_access(p_id);
    return 'Y';
  end;
"""


def _str(stmt: str) -> list:
    return _target(_pkg("", FN, f"    {stmt}\n"))


@pytest.mark.parametrize("stmt", [
    "if can_view_c(p_id) != 'TRUE' then raise_application_error(-20001, 'no'); end if;",       # probe d10
    "if can_view_c(p_id) <> 'Y' then raise_application_error(-20001, 'no'); end if;",
    "if can_view_c(p_id) = 'N' then raise_application_error(-20001, 'no'); end if;",
    "if can_view_c(p_id) != 'N' then null; else return; end if;",
    "if can_view_c(p_id) = 'YES' then null; else raise_application_error(-20001, 'no'); end if;",
])
def test_yes_no_strings_decide_the_branch(stmt):
    assert not _str(stmt), stmt


@pytest.mark.parametrize("stmt", [
    "if can_view_c(p_id) != 'n' then null; else return; end if;",            # probe d15: Oracle compares case
    "if can_view_c(p_id) <> 'GUEST' then null; else raise_application_error(-20001, 'no'); end if;",  # d11
    "if can_view_c(p_id) = 'admin' then null; else return; end if;",
    "if can_view_c(p_id) = 'y' then null; else return; end if;",
    "if can_view_c(p_id) != 'Y' then null; else return; end if;",          # the wrong way round
])
def test_other_strings_say_nothing_so_the_access_is_not_known_to_be_checked(stmt):
    assert [f.extra["coverage"] for f in _str(stmt)] == ["partial"], stmt
