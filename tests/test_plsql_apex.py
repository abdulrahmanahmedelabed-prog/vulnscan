"""PL/SQL, Oracle APEX exports (pages, plug-ins, AI) and Java stored in the database."""
import pathlib

from vulnscan import apex_export
from vulnscan.plsql_frontend import parse_plsql
from vulnscan.scanner import scan_path
from vulnscan.taint import analyze_project

DATA = pathlib.Path(__file__).parent / "data" / "apex"


def by_line(findings, file=None):
    out = {}
    for f in findings:
        if file is None or f.file == file:
            out.setdefault(f.line, set()).add(f.rule_id)
    return out


def run(**files):
    return analyze_project({k.replace("__", "."): v for k, v in files.items()})


def test_dynamic_sql_concat_vs_bind_and_dbms_assert():
    src = (
        "create or replace procedure p is\n"
        "  l_sql varchar2(400);\n"
        "begin\n"
        "  l_sql := 'select * from t where c = ''' || :P1_X || '''';\n"
        "  execute immediate l_sql;\n"
        "  execute immediate 'select * from t where c = :1' using :P1_X;\n"
        "  execute immediate 'select * from ' || dbms_assert.sql_object_name(:P1_TAB);\n"
        "  open l_cur for 'select * from t order by ' || v('P1_SORT');\n"
        "end;\n"
        "/\n"
    )
    b = by_line(run(p__sql=src))
    assert b.get(5) == {"DF004"}, b         # concatenated item reaches execute immediate
    assert 6 not in b and 7 not in b, b     # USING bind and DBMS_ASSERT are safe
    assert b.get(8) == {"DF004"}, b         # open … for with v('P1_SORT')


def test_htp_xss_and_apex_escape():
    src = ("begin\n"
           "  htp.p('<b>' || :P2_NAME || '</b>');\n"
           "  htp.p(apex_escape.html(:P2_NAME));\n"
           "  sys.htp.prn(apex_application.g_x01);\n"
           "end;\n/\n")
    b = by_line(run(x__sql=src))
    assert b.get(2) == {"DF013"} and b.get(4) == {"DF013"} and 3 not in b, b


def test_flow_across_package_files_named_arguments():
    pkg = ("create or replace package body util as\n"
           "  procedure del(p_where in varchar2) is\n"
           "  begin\n"
           "    execute immediate 'delete from t where ' || p_where;\n"
           "  end;\n"
           "end util;\n/\n")
    caller = "begin\n  util.del(p_where => :P3_FILTER);\nend;\n/\n"
    b = by_line(run(util__pkb=pkg, page__sql=caller), "page.sql")
    assert b.get(2) == {"DF004"}, b


def test_apex_export_components_rules_and_ai():
    findings = analyze_project({"f100.sql": (DATA / "f100.sql").read_text(), "orders.sql": (DATA / "orders.sql").read_text()})
    b = by_line(findings, "f100.sql")
    assert "APX002" in b[20]                 # &P10_NAME. in page JavaScript (the !JS line is not reported)
    assert 21 not in b
    assert "APX001" in b[30]                 # &P10_SEARCH. inside the report SQL
    assert "APX004" in b[38]                 # column escaping disabled
    assert "DF013" in b[45] and 46 not in b  # PL/SQL dynamic region: raw vs apex_escape.html
    assert "DF004" in b[59]                  # process -> orders_pkg.search (other file) -> execute immediate
    assert "DF004" in b[61] and 62 not in b  # concatenation vs USING bind
    assert "DF019" in b[77]                  # page item in the AI system prompt
    assert "DF020" in b[80]                  # AI-generated SQL executed
    assert "DF021" in b[81]                  # AI output written as HTML
    assert "APX005" in b[98] and 99 not in b  # item in the AI config prompt; &APP_USER. is not user input
    assert "DF013" in b[127] and 128 not in b  # plug-in render function: p_param.value raw vs escaped
    labels = {f.extra.get("apex_component") for f in findings if f.file == "f100.sql"}
    assert "صفحة 10 › عملية: Search Orders" in labels
    sev = {f.rule_id: f.severity for f in findings}
    assert sev["DF020"] == "critical"


def test_plugin_static_javascript_file_is_decoded_and_analyzed():
    js = 'document.getElementById("o").innerHTML = location.hash;\n'
    hexed = js.encode().hex().upper()
    export = ("begin\n"
              "wwv_flow_imp.g_varchar2_table := wwv_flow_imp.empty_varchar2_table;\n"
              f"wwv_flow_imp.g_varchar2_table(1) := '{hexed}';\n"
              "wwv_flow_imp_shared.create_plugin_file(\n"
              " p_id=>wwv_flow_imp.id(1)\n"
              ",p_file_name=>'widget.js'\n"
              ",p_file_content=>wwv_flow_imp.varchar2_to_blob(wwv_flow_imp.g_varchar2_table)\n"
              ");\nend;\n/\n")
    assert apex_export.is_apex_export(export)
    fs = analyze_project({"plugin.sql": export})
    assert any(f.file.endswith("widget.js") and f.rule_id == "DF013" for f in fs), [(f.file, f.rule_id) for f in fs]


def test_function_body_returning_sql_region():
    export = ("begin\nwwv_flow_imp_page.create_page(p_id=>5, p_name=>'Search');\n"
              "wwv_flow_imp_page.create_page_plug(\n"
              " p_plug_name=>'Dynamic'\n"
              ",p_query_type=>'FUNC_BODY_RETURNING_SQL'\n"
              ",p_plug_source=>wwv_flow_string.join(wwv_flow_t_varchar2(\n"
              "'begin',\n"
              "'  return ''select * from emp where ename = '''''' || :P5_NAME || '''''''';',\n"
              "'end;'))\n"
              ");\nend;\n/\n")
    b = by_line(analyze_project({"f1.sql": export}))
    assert b.get(8) == {"DF004"}, b


def test_plsql_call_spec_flows_into_java_stored_procedure():
    b = by_line(analyze_project({"javadb.sql": (DATA / "javadb.sql").read_text()}))
    assert b.get(15) == {"DF002"}, b


def test_unparseable_statement_is_reported():
    units, d = parse_plsql("begin\n  x := := 1;\n  htp.p(:P1_A);\nend;\n/\n")
    assert d["skipped"] == 1 and d["lines"][0][0] == 2
    assert by_line(analyze_project({"a.sql": "begin\n  x := := 1;\n  htp.p(:P1_A);\nend;\n/\n"})).get(3) == {"DF013"}


def test_sql_file_is_a_dump_only_by_content(tmp_path):
    (tmp_path / "pkg.sql").write_text("create or replace procedure p is begin null; end;\n/\n")
    (tmp_path / "backup.sql").write_text("-- MySQL dump 10.13\nINSERT INTO users VALUES (1,'a');\n")
    ids = {(f.file, f.rule_id) for f in scan_path(tmp_path, notes=[])[0]}
    assert ("backup.sql", "FILE006") in ids and ("pkg.sql", "FILE006") not in ids


# ------------------------------------------------- readable YAML, ORDS, XML / JSON, functions inside static SQL
def _scan_lines(path):
    notes = []
    fs, _ = scan_path(DATA, notes=notes)
    return by_line([f for f in fs if f.file == path]), fs, notes


def test_readable_yaml_export():
    b, fs, notes = _scan_lines("readable/application/pages/p00020.yaml")
    assert "APX002" in b[11] and 12 not in b      # &P20_NAME. in page JS; the !JS line is safe
    assert "APX001" in b[27]                      # substitution in the report SQL
    assert "DF004" in b[28]                       # :P20_FILTER -> orders_pkg.search (orders.sql) via a function in the SQL
    assert "APX004" in b[37]                      # escape-special-characters: false
    assert "DF004" in b[51]                       # function body returning SQL query
    assert "DF004" in b[67] and 68 not in b       # process: concatenation vs USING
    assert "DF020" in b[90]                       # AI output executed
    assert "APX002" in b[102]
    labels = {f.extra.get("apex_component") for f in fs if f.file.endswith("p00020.yaml")}
    assert "صفحة 20 › عملية: Archive" in labels and "صفحة 20 › إجراء ديناميكي: Ask AI" in labels
    assert not any("p00020" in n for n in notes if "تخطّت" in n)


def test_ords_handlers_in_sql_query_and_plsql():
    b, fs, _ = _scan_lines("ords_module.sql")
    assert "DF004" in b[16]                       # query handler: :id -> hr_util.visible -> execute immediate
    assert "DF004" in b[28]                       # PL/SQL handler: open :result for <concatenated SQL>
    assert "DF008" in b[29]                       # :forward_location := :next_url (open redirect)
    assert any(f.extra.get("apex_component") == "ORDS › hr.v1 POST employees/search" for f in fs)


def test_ords_in_liquibase_xml_and_json():
    b, _, notes = _scan_lines("ords_changelog.xml")
    assert b.get(14) == {"DF004"} and b.get(15) == {"DF013"}, b
    j, _, _ = _scan_lines("ords_module.json")
    assert j.get(9) == {"DF004"}, j               # DELETE handler; the GET query with a bind is safe
    assert not any("ords_changelog" in n for n in notes if "تخطّت" in n)


def test_functions_called_from_static_sql_inside_plsql():
    pkg = ("create or replace package body u as\n"
           "  function f(p in varchar2) return number is\n"
           "    l number;\n"
           "  begin\n"
           "    execute immediate 'select 1 from t where c = ''' || p || '''' into l;\n"
           "    return l;\n"
           "  end;\n"
           "end u;\n/\n")
    proc = ("create or replace procedure p is\n"
            "  cursor c is select u.f(:P9_A) from dual;\n"
            "  l number;\n"
            "begin\n"
            "  select u.f(:P9_B) into l from dual;\n"
            "  update t set x = u.f(:P9_C) where id = 1;\n"
            "  for r in (select u.f(:P9_D) v from dual) loop null; end loop;\n"
            "  select count(*) into l from t where c = :P9_E;\n"
            "end;\n/\n")
    b = by_line(analyze_project({"u.pkb": pkg, "p.sql": proc}), "p.sql")
    assert {2, 5, 6, 7} <= set(b) and all(b[k] == {"DF004"} for k in (2, 5, 6, 7)), b
    assert 8 not in b, b                          # a plain bind in static SQL is safe


def test_only_oracle_bearing_containers_are_analyzed():
    assert not apex_export.is_oracle_container('{"name": "app", "scripts": {"start": "node x"}}', "package.json")
    assert not apex_export.is_oracle_container("services:\n  db:\n    image: postgres\n", "docker-compose.yml")
    assert not apex_export.is_oracle_container("<project><build/></project>", "pom.xml")
    assert apex_export.is_oracle_container((DATA / "ords_changelog.xml").read_text(), "x.xml")
    assert apex_export.is_oracle_container((DATA / "ords_module.json").read_text(), "x.json")
