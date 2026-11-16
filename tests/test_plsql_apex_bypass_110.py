"""Kashif 1.1.0: adversarial review of the PL/SQL / APEX noise fixes. Each new sanitiser or suppression is attacked
with realistic vulnerable code: a guard that does not hold, a header that is not open, a wrapped header that is not
wrap output, a sign-in page that also writes data, a plug-in used under another reference form. Every such case
must still be reported, and the safe patterns of the user's report must stay quiet."""
import pathlib

from vulnscan.plsql_frontend import wrapped_units
from vulnscan.scanner import scan_path
from vulnscan.taint import analyze_project

DATA = pathlib.Path(__file__).parent / "data" / "plsql_apex_fp"


def _lines(src: str, name: str = "b.sql") -> dict:
    out: dict = {}
    for f in analyze_project({name: src}):
        out.setdefault(f.line, set()).add(f.rule_id)
    return out


def _proc(n: int, guard: str, sink: str = "execute immediate 'begin ' || l_pkg || '.refresh; end;';",
          src: str = "apex_application.g_x01", extra: str = "") -> str:
    return (f"create or replace procedure p{n} is\n  l_pkg varchar2(128) := {src};\nbegin\n{guard}{extra}"
            f"  {sink}\nend p{n};\n/\n")


def _guard(test: str, then: str = "raise_application_error(-20001, 'bad');") -> str:
    return f"  if {test} then\n    {then}\n  end if;\n"


ANCHORED = "'^[A-Za-z][A-Za-z0-9_$#]{0,29}$'"


# ------------------------------------------------------------------ regexp_like guard
def _sink_reported(guard: str, extra: str = "") -> bool:
    src = _proc(1, guard, extra=extra)
    sink_line = src.split("\n").index("  execute immediate 'begin ' || l_pkg || '.refresh; end;';") + 1
    return "DF004" in _lines(src).get(sink_line, set())


def test_the_users_guard_still_clears_the_sink():
    assert not _sink_reported(_guard(f"not regexp_like(l_pkg, {ANCHORED})"))
    assert not _sink_reported(_guard(f"not regexp_like(l_pkg, {ANCHORED}) or l_pkg is null"))
    assert not _sink_reported(_guard("not regexp_like(l_pkg, '^\\w+$')"))
    assert not _sink_reported(_guard("not regexp_like(l_pkg, '^[A-Z]+$', 'i')"))
    assert not _sink_reported(_guard("not regexp_like(l_pkg, '^[A-Za-z0-9_.]+$')"))     # schema.name


def test_guard_that_does_not_stop_the_flow_is_not_a_sanitiser():
    assert _sink_reported(_guard(f"not regexp_like(l_pkg, {ANCHORED})", "apex_debug.message('bad package');"))
    assert _sink_reported(_guard(f"regexp_like(l_pkg, {ANCHORED})"))                    # raises when it is valid
    assert _sink_reported(_guard(f"not regexp_like(l_pkg, {ANCHORED}) and length(l_pkg) > 3"))


def test_guard_on_another_variable_or_overwritten_value_is_not_a_sanitiser():
    src = ("create or replace procedure p is\n  l_pkg varchar2(128) := apex_application.g_x01;\n"
           "  l_other varchar2(128) := apex_application.g_x02;\nbegin\n"
           f"  if not regexp_like(l_other, {ANCHORED}) then\n    raise_application_error(-20001, 'x');\n  end if;\n"
           "  execute immediate 'begin ' || l_pkg || '.refresh; end;';\nend p;\n/\n")
    assert _lines(src).get(8) == {"DF004"}
    # validated, then replaced by another browser value before the sink
    assert _sink_reported(_guard(f"not regexp_like(l_pkg, {ANCHORED})"), extra="  l_pkg := apex_application.g_x02;\n")
    assert _sink_reported(_guard(f"not regexp_like(l_pkg, {ANCHORED})"),
                          extra="  if p_mode = 'B' then\n    l_pkg := v('P1_PKG');\n  end if;\n")
    # a guard inside a branch that may not run, or inside a block whose handler swallows the error
    nested = ("  if p_mode = 'A' then\n" + _guard(f"not regexp_like(l_pkg, {ANCHORED})").replace("  ", "    ", 3)
              + "  end if;\n")
    assert _sink_reported(nested)
    swallowed = ("  begin\n" + _guard(f"not regexp_like(l_pkg, {ANCHORED})")
                 + "  exception when others then null;\n  end;\n")
    assert _sink_reported(swallowed)


def test_pattern_that_does_not_confine_the_value_is_not_a_sanitiser():
    for pat in ("'^.*$'", "'^[A-Za-z]'", "'[A-Za-z]+$'", "'^[A-Za-z '';]+$'", "'^[[:alnum:][:punct:]]+$'",
                "'^[^<>]+$'", "'^[A-Z]+$|x'", "'^[A-Za-z0-9 =-]+$'"):
        assert _sink_reported(_guard(f"not regexp_like(l_pkg, {pat})")), pat


def test_multiline_match_parameter_defeats_the_anchors():
    # with 'm', ^ and $ match at every line: 'valid\n; drop …' passes
    assert _sink_reported(_guard("not regexp_like(l_pkg, '^[A-Za-z0-9_]+$', 'm')"))
    assert _sink_reported(_guard("not regexp_like(l_pkg, '^[A-Za-z0-9_]+$', l_flags)"))


def test_regexp_like_allow_list_is_judged_per_sink():
    # spaces and = are harmless in a header but let an unquoted attribute value grow an event handler
    src = ("create or replace procedure p is\n  l_val varchar2(128) := v('P1_V');\nbegin\n"
           "  if not regexp_like(l_val, '^[A-Za-z0-9 =]+$') then\n    raise_application_error(-20001, 'x');\n  end if;\n"
           "  htp.p('<input value=' || l_val || '>');\n"
           "  htp.p('<b>' || regexp_replace(l_val, '[^A-Za-z0-9 =]') || '</b>');\n"
           "  htp.p('<b>' || regexp_replace(l_val, '[^A-Za-z0-9 .-]') || '</b>');\nend p;\n/\n")
    assert _lines(src) == {7: {"DF013"}, 8: {"DF013"}}


# ------------------------------------------------------------------ DBMS_ASSERT, conversions, binds
def test_non_sanitising_conversions_and_partial_binds():
    src = ("create or replace procedure p is\n  l_n number;\n  l_sql varchar2(4000);\n  l_rc sys_refcursor;\n"
           "  l_cur integer := dbms_sql.open_cursor;\nbegin\n"
           "  execute immediate 'select count(*) from ' || dbms_assert.noop(v('P1_T')) into l_n;\n"                   # 7
           "  execute immediate 'select count(*) from t where c = ' || to_char(v('P1_T')) into l_n;\n"              # 8
           "  execute immediate 'select count(*) from t where c = ' || to_char(to_number(v('P1_T'))) into l_n;\n"   # 9
           "  execute immediate 'select count(*) from t where a = :1 and b = ''' || v('P1_B') || '''' into l_n using v('P1_A');\n"  # 10
           "  l_sql := 'select count(*) from t where b = ''' || v('P1_B') || '''';\n"
           "  execute immediate l_sql into l_n using v('P1_A');\n"                                                 # 12
           "  open l_rc for l_sql using v('P1_A');\n"                                                              # 13
           "  dbms_sql.parse(c => l_cur, statement => l_sql, language_flag => dbms_sql.native);\n"                 # 14
           "  execute immediate 'select count(*) from t where c = ''' || apex_application.g_f01(1) || '''' into l_n;\n"   # 15
           "  execute immediate 'select count(*) from t where c = :1' into l_n using apex_application.g_f01(1);\n"  # 16
           "end p;\n/\n")
    got = _lines(src)
    assert {k for k, v in got.items() if "DF004" in v} == {7, 8, 10, 12, 13, 14, 15}, got


def test_dbms_assert_quoting_is_not_html_escaping():
    src = ("create or replace procedure p is\nbegin\n  htp.p(dbms_assert.enquote_name(v('P1_X')));\n"
           "  htp.p(sys.dbms_assert.enquote_literal(v('P1_X')));\nend p;\n/\n")
    assert _lines(src) == {3: {"DF013"}, 4: {"DF013"}}


# ------------------------------------------------------------------ HTTP header context
def test_html_after_a_closed_or_maybe_open_header_is_still_html():
    crlf_free = "replace(replace(v('P1_X'), chr(13)), chr(10))"
    src = ("create or replace procedure h(p_dl in varchar2) is\nbegin\n"
           "  if p_dl = 'Y' then\n    owa_util.mime_header('application/octet-stream', false);\n"
           "  else\n    owa_util.mime_header('text/html', true);\n  end if;\n"
           f"  htp.p('<p>' || {crlf_free} || '</p>');\n"                                  # 8: HTML on the else path
           "  owa_util.http_header_close;\n"
           "  owa_util.mime_header('text/html', false);\n  owa_util.mime_header('text/html', true);\n"
           f"  htp.p('<p>' || {crlf_free} || '</p>');\n"                                  # 12: closed by the 2nd call
           "  owa_util.mime_header('text/html');\n"
           "  htp.p('<p>' || v('P1_X') || '</p>');\n"                                     # 14: default bclose_header true
           "end h;\n/\n")
    got = _lines(src, "h.sql")
    assert got.get(8) == {"DF013"} and got.get(12) == {"DF013"} and got.get(14) == {"DF013"}, got


def test_header_line_on_some_paths_is_checked_as_a_header_too():
    src = ("create or replace procedure h(p_dl in varchar2) is\nbegin\n"
           "  owa_util.mime_header('text/csv', false);\n"
           "  if p_dl = 'Y' then\n    owa_util.http_header_close;\n  end if;\n"
           "  htp.p('X-Name: ' || apex_escape.html(v('P1_X')));\n"                         # 7: HTML-escaped, CR/LF kept
           "  owa_util.status_line(302, 'Found', false);\n"
           "  htp.p('Location: ' || v('P1_URL'));\n"                                       # 9
           "  owa_util.http_header_close;\nend h;\n/\n")
    got = _lines(src, "h.sql")
    assert got.get(7) == {"DF008"} and got.get(9) == {"DF008"}, got


def test_the_users_header_write_stays_quiet():
    src = ("create or replace procedure dl is\nbegin\n  owa_util.mime_header('text/csv', false);\n"
           "  htp.p('Content-Disposition: attachment; filename=\"' || regexp_replace(v('P1_X'), '[^A-Za-z0-9]', '') || '.csv\"');\n"
           "  owa_util.http_header_close;\n  htp.p('id,name');\nend dl;\n/\n")
    assert _lines(src, "dl.sql") == {}


# ------------------------------------------------------------------ wrapped units
ABCD = "abcd\n" * 15
WRAPPED = ("CREATE OR REPLACE PACKAGE BODY real_w wrapped\na000000\nb2\n" + ABCD
           + "b\n5dc 2ee\nZk3Pq8Lm2Vx7Rt5Nb1Hc4Wd9Jf6Gs0YaQe2Tu8Io3Pa7Sd1Fg5Hj9Kl4Zx6Cv\n/\n")
SINK = "begin\n  execute immediate 'select 1 from ' || v('P1_T');\nend {n};\n/\n"


def test_wrapped_header_in_a_comment_or_string_hides_no_code(tmp_path):
    src = ("/*\ncreate or replace package body hidden wrapped\n*/\n"
           "create or replace procedure c1 is\n" + SINK.format(n="c1")
           + "create or replace procedure c2 is\n  l_s varchar2(400) := q'[\ncreate or replace function f wrapped\n]';\n"
           + SINK.format(n="c2") + WRAPPED + "create or replace procedure after_w is\n" + SINK.format(n="after_w"))
    lines = src.split("\n")
    sinks = [i for i, x in enumerate(lines, 1) if "execute immediate" in x]
    head = lines.index("CREATE OR REPLACE PACKAGE BODY real_w wrapped") + 1
    assert len(sinks) == 3 and [u[0] for u in wrapped_units(src)] == [head]
    (tmp_path / "w.sql").write_text(src)
    fs, _ = scan_path(tmp_path, notes=[])
    got = sorted((f.rule_id, f.line) for f in fs)
    assert got == [("APX022", head)] + [("DF004", n) for n in sinks], got


def test_source_with_the_word_wrapped_is_read_as_code():
    # a header with `wrapped` followed by readable code is not wrap output (it would not compile as one either)
    src = "create or replace procedure fake wrapped\nis\nbegin\n  execute immediate 'select 1 from ' || v('P1_T');\nend;\n/\n"
    assert wrapped_units(src) == []
    nine_i = "create or replace procedure old9 wrapped\n0\n" + ABCD + "3\n7\n9200000\n1\n4\n0\n/\n"
    assert [u[2] for u in wrapped_units(nine_i)] == ["procedure"]          # the 9i layout is still recognised


# ------------------------------------------------------------------ sign-in page and unused plug-ins
def _export(body: str, app: int = 300) -> str:
    head = (DATA / "f200.sql").read_text().split("prompt --application/shared_components/plugins")[0]
    return head.replace("p_default_application_id=>200", f"p_default_application_id=>{app}") + body + (
        "prompt --application/end_environment\nbegin\nwwv_flow_imp.import_end(p_auto_install_sup_obj => false);\n"
        "commit;\nend;\n/\n")


def _page(pid: int, name: str, alias: str, procs: list) -> str:
    out = (f"prompt --application/pages/page_{pid:05d}\nbegin\nwwv_flow_imp_page.create_page(\n p_id=>{pid}\n"
           f",p_name=>'{name}'\n,p_alias=>'{alias}'\n,p_page_is_public_y_n=>'Y'\n,p_protection_level=>'C'\n);\n")
    for i, (pname, code) in enumerate(procs, 1):
        out += (f"wwv_flow_imp_page.create_page_process(\n p_id=>wwv_flow_imp.id({pid}{i:02d})\n,p_process_sequence=>{i}0\n"
                f",p_process_point=>'AFTER_SUBMIT'\n,p_process_type=>'NATIVE_PLSQL'\n,p_process_name=>'{pname}'\n"
                f",p_process_sql_clob=>'{code}'\n,p_process_clob_language=>'PLSQL'\n);\n")
    return out + "end;\n/\n"


def test_a_page_called_login_that_writes_data_is_still_reported(tmp_path):
    body = (_page(40, "Login", "LOGIN", [("Grant bonus", "update emp set sal = sal + :P40_BONUS where empno = :P40_EMPNO;")])
            + _page(41, "Register", "REGISTER", [("Register and sign in",
                    "insert into app_users (username) values (:P41_U); apex_authentication.login(p_username => :P41_U, p_password => :P41_P);")])
            + _page(42, "Sign in", "SIGNIN", [("Login", "apex_authentication.login(p_username => :P42_U, p_password => :P42_P);"),
                                              ("Remember", "apex_authentication.send_login_username_cookie(p_username => :P42_U);")]))
    (tmp_path / "f300.sql").write_text(_export(body))
    fs, _ = scan_path(tmp_path, notes=[])
    apx = sorted((f.rule_id, f.extra.get("apex_component", "")) for f in fs if f.rule_id in ("APX016", "APX017", "APX018"))
    assert [a[0] for a in apx] == ["APX016", "APX016"], apx
    assert "40" in apx[0][1] and "41" in apx[1][1]                     # the plain sign-in page 42 stays quiet


def test_plugin_used_through_any_reference_form_is_not_dead(tmp_path):
    def plugin(pid, name, ptype):
        return (f"begin\nwwv_flow_imp_shared.create_plugin(\n p_id=>wwv_flow_imp.id({pid})\n,p_plugin_type=>'{ptype}'\n"
                f",p_name=>'{name}'\n,p_plsql_code=>wwv_flow_string.join(wwv_flow_t_varchar2(\n'procedure run is',\n'begin',\n"
                f"'    htp.p(''<b>'' || apex_application.g_x05 || ''</b>'');',\n'end run;'))\n,p_api_version=>2\n);\nend;\n/\n")
    body = (plugin(401, "COM.ACME.DA_SHOW", "DYNAMIC ACTION") + plugin(402, "COM.ACME.BADGE", "TEMPLATE COMPONENT")
            + plugin(403, "COM.ACME.ITEM PICKER", "ITEM TYPE") + plugin(404, "COM.ACME.PROC", "PROCESS TYPE")
            + plugin(405, "COM.ACME.DEAD", "REGION TYPE")
            + "begin\nwwv_flow_imp_page.create_page(\n p_id=>1\n,p_name=>'Home'\n);\n"
            "wwv_flow_imp_page.create_page_plug(\n p_id=>wwv_flow_imp.id(501)\n,p_plug_source_type=>'TMPL_COM.ACME.BADGE'\n);\n"
            "wwv_flow_imp_page.create_page_item(\n p_id=>wwv_flow_imp.id(502)\n,p_name=>'P1_PICK'\n"
            ",p_display_as=>'PLUGIN_COM.ACME.ITEM PICKER'\n);\n"
            "wwv_flow_imp_page.create_page_da_action(\n p_id=>wwv_flow_imp.id(503)\n,p_action=>'PLUGIN_COM.ACME.DA_SHOW'\n);\n"
            "wwv_flow_imp_page.create_page_process(\n p_id=>wwv_flow_imp.id(504)\n,p_process_point=>'BEFORE_HEADER'\n"
            ",p_process_type=>'PLUGIN_COM.ACME.PROC'\n,p_process_name=>'Run'\n);\nend;\n/\n")
    (tmp_path / "f300.sql").write_text(_export(body))
    fs, _ = scan_path(tmp_path, notes=[])
    dead = [f.extra.get("unused_component") for f in fs if f.rule_id == "APX023"]
    assert len(dead) == 1 and dead[0].endswith("COM.ACME.DEAD"), dead
    xss = sorted((f.severity, f.extra.get("apex_component", "").split(": ")[-1]) for f in fs if f.rule_id == "DF013")
    assert xss == [("low", "COM.ACME.DEAD"), ("medium", "COM.ACME.BADGE"), ("medium", "COM.ACME.DA_SHOW"),
                   ("medium", "COM.ACME.ITEM PICKER"), ("medium", "COM.ACME.PROC")], xss
