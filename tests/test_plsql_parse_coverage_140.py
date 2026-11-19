"""PL/SQL constructs that real public code uses and the frontend skipped before 1.4.0 (measured with
bench/plsql_skips.py over ~1.6M lines: Logger, OOS-Utils, utPLSQL, Alexandria, pljson, CORE23, the Oracle sample
schemas and examples, and the Oracle APEX 24.2 sample/starter apps). Each statement now parses, and where a construct
carries data, a page item that flows through it into dynamic SQL is still reported (DF004)."""
import pytest

from vulnscan import apex_export
from vulnscan.plsql_frontend import parse_plsql
from vulnscan.scanner import scan_path


def _body(stmts: str, decls: str = "") -> str:
    return (f"create or replace procedure p is\n  l_sql varchar2(4000);\n  l_x varchar2(4000);\n{decls}begin\n"
            f"{stmts}\nend;\n/\n")


def _skips(text: str):
    _, diag = parse_plsql(text)
    return diag["lines"]


def _df004(tmp_path, text: str) -> list:
    (tmp_path / "p.sql").write_text(text)
    findings, _ = scan_path(tmp_path)
    return [f.line for f in findings if f.rule_id == "DF004"]


# ---------------------------------------------------------------- conditional compilation ($if / $then / $end)
CC = _body("""  $if $$no_op $then
    null;
  $elsif dbms_db_version.version < 19 $then
    l_x := 'old';
  $else
    l_x := :P1_X;
  $end
  $if $$debug $then $error 'no debug in ' || $$plsql_unit $end $end
  l_sql := 'select ' || l_x || ' from dual';
  execute immediate l_sql;""")


def test_conditional_compilation_parses():
    assert _skips(CC) == []


def test_conditional_compilation_keeps_every_branch(tmp_path):
    assert _df004(tmp_path, CC)


def test_conditional_compilation_in_declarations(tmp_path):
    src = ("create or replace procedure p is\n  $if dbms_db_version.ver_le_12 $then\n  l_x varchar2(100) := 'a';\n"
           "  $else\n  l_x varchar2(100 char) := :P1_X;\n  $end\n"
           "begin\n  logger.log('x', $$plsql_unit || '.' || $$plsql_line);\n"
           "  execute immediate 'select ' || l_x || ' from dual';\nend;\n/\n")
    assert _skips(src) == []
    assert _df004(tmp_path, src)


def test_inquiry_directive_is_a_constant(tmp_path):
    assert not _df004(tmp_path, _body("  l_sql := 'select ''' || $$plsql_unit || ''' from dual';\n  execute immediate l_sql;"))


# ---------------------------------------------------------------- other statements and expressions
@pytest.mark.parametrize("stmt", [
    "  if l_x is of (t_string) then null; end if;",
    "  if l_x is not of type (only t_string) then null; end if;",
    "  raise dr_def.textile_error;",
    "  raise sys.pkg.e_failed;",
    "  (self as ut_reporter).print_text(l_x);",
    "  l_x := (self as ut_data_value).compare(l_x) + 1;",
    "  l_x := l_a multiset union l_b;",
    "  l_x := l_a multiset union distinct l_b multiset except all l_c;",
    "  l_x := l_a multiset intersect l_b;",
    "  l_x := .567 / k + 1.5e3 * -.2;",
    "  for i in 1..10 loop null; end loop;",
    "  l_x := to_date(:\"P3_END_DATE\", 'YYYYMMDD');",
    "  l_x := systimestamp at time zone 'UTC';",
    "  l_x := from_tz(l_ts, 'UTC') at time zone l_tz;",
    "  l_x := l_ts at local;",
    "  pragma inline(get_suite, 'YES');",
])
def test_statement_parses(stmt):
    assert _skips(_body(stmt)) == []


@pytest.mark.parametrize("expr", [
    "(:P1_X as varchar2(100))",
    "l_a multiset union :P1_X",
    "to_char(:P1_X at time zone 'UTC')",
    "to_char(systimestamp at time zone :P1_X)",
    ':"P1_X"',
])
def test_value_inside_still_reaches_dynamic_sql(tmp_path, expr):
    assert _df004(tmp_path, _body(f"  l_sql := 'select ' || {expr} || ' from dual';\n  execute immediate l_sql;"))


def test_self_as_supertype_call_parses_and_keeps_arguments(tmp_path):
    src = ("create or replace type body r as\n  overriding member procedure m(self in out r, a varchar2) is\n  begin\n"
           "    (self as base_r).m(a);\n    execute immediate 'select ' || a || ' from dual';\n  end;\nend;\n/\n"
           "create or replace procedure p is begin r_obj.m(:P1_X); end;\n/\n")
    assert _skips(src) == []


# ---------------------------------------------------------------- SQL*Plus scripts
def test_exec_assignment_and_exec_block():
    src = ("var task varchar2(30)\nEXEC :task := dbms_sqltune.create_tuning_task(sql_id=>'g6');\n"
           "exec begin execute immediate 'drop user u cascade'; exception when others then null; end;\n"
           "exec dbms_sqltune.execute_tuning_task(:task);\n")
    assert _skips(src) == []


def test_exec_block_dynamic_sql_is_analysed(tmp_path):
    assert _df004(tmp_path, "exec begin execute immediate 'select ' || :P1_X || ' from dual'; end;\n")


def test_sqlplus_period_line_ends_the_buffer():
    assert _skips("comment on column t.c is\n'x';\n.\ncomment on column t.d is 'y';\n") == []


def test_pipelined_function_with_cluster_by_and_using():
    src = ("create or replace function f(c sys_refcursor) return sys.anydataset\n"
           "pipelined parallel_enable (partition c by hash(month))\ncluster c by (month)\nusing rq_impl;\n/\n"
           "begin\n  null;\nend;\n/\n")
    assert _skips(src) == []


def test_skipped_count_is_not_capped():
    src = "begin\n" + "  x := := 1;\n" * 600 + "end;\n/\n"
    _, diag = parse_plsql(src)
    assert diag["skipped"] == 600 and len(diag["lines"]) == 500


# ---------------------------------------------------------------- APEX exports: text that is not PL/SQL
def _apex(component: str) -> str:
    return ("prompt --application/pages/page_00001\nbegin\nwwv_flow_imp_page.create_page(p_id=>1, p_name=>'Home');\n"
            + component + "\nend;\n/\n")


def test_regular_expression_validation_is_not_plsql():
    text = _apex("wwv_flow_imp_page.create_page_validation(\n p_id=>wwv_flow_imp.id(5)\n,p_validation_name=>'email valid'\n"
                 ",p_validation=>'P1_EMAIL'\n,p_validation2=>'[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,4}'\n"
                 ",p_validation_type=>'REGULAR_EXPRESSION'\n);")
    assert apex_export.is_apex_export(text)
    assert not [b for b in apex_export.extract(text, "f1.sql")[0] if b.kind.startswith("plsql")]


def test_static_content_region_showing_code_is_not_plsql():
    text = _apex("wwv_flow_imp_page.create_page_plug(\n p_id=>wwv_flow_imp.id(6)\n,p_plug_name=>'How to'\n"
                 ",p_plug_source=>wwv_flow_string.join(wwv_flow_t_varchar2(\n'<pre><code>',\n'declare',\n"
                 "'  l_x varchar2(20) := apex_application.g_flow_schema_owner;',\n'</code></pre>'))\n);")
    kinds = [b.kind for b in apex_export.extract(text, "f1.sql")[0]]
    assert kinds == ["html"], kinds


def test_plsql_region_with_a_type_is_still_plsql():
    text = _apex("wwv_flow_imp_page.create_page_plug(\n p_id=>wwv_flow_imp.id(7)\n,p_plug_name=>'Greeting'\n"
                 ",p_plug_source=>'htp.p(:P1_NAME);'\n,p_plug_source_type=>'NATIVE_PLSQL'\n);")
    assert [b.kind for b in apex_export.extract(text, "f1.sql")[0]] == ["plsql"]


def test_conditional_compilation_branches_are_alternatives(tmp_path):
    # 1.4.0 review: the branches used to follow each other, so the last assignment won and hid the tainted one
    src = _body("  $if dbms_db_version.ver_le_12 $then\n"
                "    l_sql := 'select count(*) from emp where ename = ''' || v('P1_NAME') || '''';\n"
                "  $else\n    l_sql := 'select count(*) from emp where ename = :1';\n  $end\n"
                "  execute immediate l_sql;")
    assert _skips(src) == []
    assert _df004(tmp_path, src)
    from vulnscan.plsql_frontend import CC_COND, tokenize
    vals = [t.val for t in tokenize("begin $if a $then x := 1; $else x := 2; $end end;", cc_branches=True)]
    assert vals[:4] == ["begin", "if", CC_COND, "then"] and vals[-6:-1] == ["end", "if", ";", "end", ";"]
    # inside an expression the directives are dropped as before
    vals = [t.val for t in tokenize("x := $if a $then 1 $else 2 $end;", cc_branches=True)]
    assert vals == ["x", ":=", "1", "2", ";", ""]
