"""SQL functions whose arguments are not a plain comma list (json_object's `'k' : v` / `key 'k' value v`, trim's
`both … from`, aggregate `order by`, `absent on null`, `returning`, `format json`) parse, and the values inside still
carry their data to a sink. Before 1.3.1 every such statement was skipped (an APEX app had 9 of them)."""
import pytest

from vulnscan.plsql_frontend import parse_plsql
from vulnscan.scanner import scan_path

FORMS = [
    "l_x := json_object('a' : :P1_X);",
    "l_x := json_object('a':l_y, 'b'::P1_X);",
    "l_x := json_object(key 'a' value :P1_X);",
    "l_x := json_object('a' value null absent on null);",
    "l_x := json_object('a' value 1 returning clob);",
    "l_x := json_object('a' : json_array(1, :P1_X absent on null) format json, 'c' value 3 returning clob);",
    "l_x := json_arrayagg(x order by x);",
    "select json_arrayagg(json_object('id' : id) order by id returning clob) into l_x from t;",
    "l_x := trim(both ' ' from :P1_X);",
    "l_x := trim(leading '0' from :P1_X);",
    "l_x := trim(both from :P1_X);",
    "l_x := f(key, both);",
    "l_x := cast(:P1_X as varchar2(10));",
    "l_x := extract(year from sysdate);",
    "l_x := to_number(:P1_X default 0 on conversion error);",
]


@pytest.mark.parametrize("stmt", FORMS)
def test_statement_parses(stmt):
    _, diag = parse_plsql(f"declare l_x varchar2(100); l_y varchar2(100); begin\n {stmt}\nend;\n")
    assert diag["lines"] == [], diag["lines"]


@pytest.mark.parametrize("expr", [
    "json_object('a' : :P1_X)",
    "json_object('a'::P1_X)",
    "json_object(key 'k' value :P1_X absent on null)",
    "json_object('k' value :P1_X returning clob)",
    "trim(both ' ' from :P1_X)",
    "trim(leading '0' from :P1_X)",
])
def test_value_inside_still_reaches_dynamic_sql(tmp_path, expr):
    (tmp_path / "p.sql").write_text(
        "create or replace procedure p is\n  l_sql varchar2(4000);\nbegin\n"
        f"  l_sql := 'select ' || {expr} || ' from dual';\n  execute immediate l_sql;\nend;\n/\n")
    findings, _ = scan_path(tmp_path)
    assert [f.rule_id for f in findings if f.rule_id == "DF004"], [(f.rule_id, f.line) for f in findings]


def test_constant_json_is_not_dynamic_sql(tmp_path):
    (tmp_path / "p.sql").write_text(
        "create or replace procedure p is\n  l_sql varchar2(4000);\nbegin\n"
        "  l_sql := 'select ' || json_object('a' : 'b', key 'c' value 1 absent on null) || ' from dual';\n"
        "  execute immediate l_sql;\nend;\n/\n")
    findings, _ = scan_path(tmp_path)
    assert not [f for f in findings if f.rule_id == "DF004"]
