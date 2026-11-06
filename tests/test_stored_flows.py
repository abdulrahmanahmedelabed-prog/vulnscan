"""Second-order flows through database tables in every language (raw SQL and ORMs), and PL/SQL in any JSON."""
import pathlib

from vulnscan.scanner import scan_path
from vulnscan.taint import analyze_project

DATA = pathlib.Path(__file__).parent / "data" / "stored"
APEX = pathlib.Path(__file__).parent / "data" / "apex"

EXPECTED = {
    ("py_raw.py", 13, "DF023"), ("py_raw.py", 18, "DF024"),                 # sqlite3 / DB-API
    ("py_django.py", 15, "DF023"), ("py_django.py", 16, "DF024"),           # Django ORM
    ("sa_app.py", 23, "DF023"),                                             # SQLAlchemy
    ("js_app.js", 16, "DF024"), ("js_app.js", 19, "DF023"),                 # Mongoose / mysql2
    ("prisma_app.ts", 11, "DF023"),                                         # Prisma
    ("Store.java", 15, "DF024"),                                            # JDBC prepared statement
    ("Profile.kt", 19, "DF023"),                                            # JPA entity + Spring Data repository
    ("Notes.cs", 15, "DF023"),                                              # ADO.NET SqlCommand + parameters
    ("store.php", 7, "DF024"),                                              # PDO prepare / execute
    ("store.go", 11, "DF023"),                                              # database/sql + Scan
    ("notes_controller.rb", 9, "DF023"),                                    # ActiveRecord
}


def test_second_order_across_languages_and_orms():
    fs, _ = scan_path(DATA, notes=[])
    got = {(f.file, f.line, f.rule_id) for f in fs if f.rule_id.startswith("DF")}
    assert got == EXPECTED, (got - EXPECTED, EXPECTED - got)


def test_findings_name_the_column_and_the_write():
    fs, _ = scan_path(DATA, notes=[])
    src = next(f.extra["taint_source"] for f in fs if f.file == "store.go" and f.rule_id == "DF023")
    assert "JOB.CMD" in src and "store.go:5" in src      # canonical (singular) table name


def test_lookup_keys_do_not_taint_fetched_rows():
    # Msg.findById(req.params.id): the row's columns are table data, not the request id
    code = ("const mongoose = require('mongoose');\n"
            "const Msg = mongoose.model('Msg', new mongoose.Schema({ who: String }));\n"
            "app.get('/m', async (req, res) => {\n"
            "  const m = await Msg.findById(req.params.id);\n"
            "  res.send('<b>' + m.who + '</b>');\n"
            "});\n")
    assert not [f for f in analyze_project({"a.js": code}) if f.line == 5]


def test_plsql_block_in_any_json_key():
    fs = analyze_project({"custom_tool.json": (APEX / "custom_tool.json").read_text()})
    assert [(f.rule_id, f.line) for f in fs] == [("DF004", 4)]
    assert "JSON › $.steps[0].plsqlBody" in fs[0].snippet


# ------------------------------------------- real table names across SQL and ORMs; generic data-access helpers
DATA2 = pathlib.Path(__file__).parent / "data" / "stored2"


def _flows2():
    fs, _ = scan_path(DATA2, notes=[])
    return {(f.file, f.line, f.rule_id): f.extra.get("taint_source", "") for f in fs if f.rule_id.startswith("DF")}


def test_orm_and_raw_sql_share_real_table_names():
    got = _flows2()
    # Django default table blog_post <- Post; Meta.db_table custom_tags <- Tag
    assert "POST.BODY" in got[("blog/views.py", 14, "DF023")]
    assert "CUSTOM_TAG.LABEL" in got[("blog/views.py", 16, "DF023")]
    # Mongoose collection 'support_tickets' read through raw SQL
    assert "SUPPORT_TICKET.SUBJECT" in got[("orm_helpers.js", 13, "DF023")]


def test_generic_save_and_fetch_helpers():
    got = _flows2()
    assert "MESSAGE.TEXT" in got[("helpers.py", 21, "DF023")]      # save("messages", {...}) then fetch("messages", 1)
    assert ("helpers.py", 23, "DF023") not in got                 # audit only ever receives a constant
    assert ("helpers.py", 15, "DF004") not in got                 # column names from dict-literal keys are not user data
    assert ("orm_helpers.js", 9, "DF023") in got                  # createRecord(Ticket, {...}) / loadRecord(Ticket, id)


def test_canonical_table_names():
    from vulnscan.stored import canon_col, canon_table
    assert canon_table("notes") == canon_table("Note") == canon_table('"public"."NOTES"') == canon_table("[dbo].[Notes]") == "NOTE"
    assert canon_table("categories") == "CATEGORY" and canon_table("boxes") == "BOX" and canon_table("status") == "STATUS"
    assert canon_col("created_at") == canon_col("createdAt") == "CREATEDAT"


def test_user_controlled_dict_keys_still_count():
    # keys of request data ARE attacker-controlled: column names built from them are injectable
    code = ("import sqlite3\nfrom flask import request\ndb = sqlite3.connect('x')\n"
            "def save(table, data):\n"
            "    cols = ', '.join(data.keys())\n"
            "    db.execute(f'INSERT INTO {table} ({cols}) VALUES (?)', list(data.values()))\n"
            "@app.route('/x', methods=['POST'])\n"
            "def x():\n"
            "    save('t', request.form)\n")
    assert any(f.rule_id == "DF004" and f.line == 9 for f in analyze_project({"a.py": code}))


# ------------------------------------------------ tables from configuration; queries built across functions
DATA3 = pathlib.Path(__file__).parent / "data" / "stored3"


def test_tables_from_configuration_and_sql_built_across_functions():
    fs, _ = scan_path(DATA3, notes=[])
    got = {(f.file, f.line, f.rule_id): f.extra.get("taint_source", "") for f in fs if f.rule_id.startswith("DF")}
    # .env NOTES_TABLE via os.getenv; INSERT built by insert_sql(), SELECT by base_select() with +=
    assert "USER_NOTE.BODY" in got[("app.py", 24, "DF023")]
    # config.yaml db.tickets via cfg['db']['tickets'] and str.format
    assert "HELP_TICKET.SUBJECT" in got[("app.py", 27, "DF023")]
    assert ("app.py", 29, "DF023") not in got                       # user_notes.title is never written by users
    # process.env.LOG_TABLE (.env) in a template literal
    assert "EVENT_LOG.LINE" in got[("logs.js", 6, "DF023")]
    # Spring @Value("${app.audit.table}") from application.properties
    assert "AUDIT_ENTRY.MSG" in got[("src/main/java/Audit.java", 12, "DF023")]


def test_fold_and_config_parsing():
    import ast
    from vulnscan.stored import FoldContext, fold, parse_config
    assert parse_config("app.ini", "[db]\ntable = t1\n")["db.table"] == "t1"
    assert parse_config("c.json", '{"db": {"table": "t2"}}')["db.table"] == "t2"
    assert parse_config(".env.local", "export T=t3\n")["t"] == "t3"
    tree = ast.parse("BASE = 'SELECT a FROM '\n"
                     "def q(t):\n    s = BASE + t\n    s += ' WHERE x = %s'\n    return s\n"
                     "x = q(settings.T)\n"
                     "y = ', '.join(['a', 'b'])\n"
                     "z = 'INSERT INTO %s (c) VALUES (?)' % os.environ['T']\n")
    fc = FoldContext([("", tree)], {"t": "items"})
    vals = {st.targets[0].id: st.value for st in tree.body if isinstance(st, ast.Assign)}
    assert fold(vals["x"], fc) == "SELECT a FROM items WHERE x = %s"
    assert fold(vals["y"], fc) == "a, b"
    assert fold(vals["z"], fc) == "INSERT INTO items (c) VALUES (?)"


# --------------------------------------- deployment manifests; tables chosen at run time; trusted configuration
DATA4 = pathlib.Path(__file__).parent / "data" / "stored4"


def test_tables_from_deployment_manifests_and_run_time_tables():
    fs, _ = scan_path(DATA4, notes=[])
    got = {(f.file, f.line): f for f in fs if f.rule_id.startswith("DF")}
    # Dockerfile ENV, docker-compose environment list, Kubernetes env name/value
    assert "NOTES_V2.BODY" in got[("app.py", 19)].extra["taint_source"]
    assert "TIX_V2.SUBJECT" in got[("app.py", 20)].extra["taint_source"]
    assert "AUDIT_V3.MSG" in got[("app.py", 21)].extra["taint_source"]
    # table from a registry row / a remote service: linked by column, one level lower, and said so
    for line in (23, 24):
        f = got[("app.py", line)]
        assert f.rule_id == "DF023" and f.severity == "medium" and f.extra.get("runtime_table")
        assert "وقت التشغيل" in f.title_ar
    assert ("app.py", 25) not in got                 # archive.title: no user ever writes TITLE
    # env lookups defined in the project's own deployment files are operator configuration, not user input
    assert not any(k[1] in (11, 12, 13) and f.rule_id == "DF004" for k, f in got.items())


def test_undefined_environment_variable_is_still_a_source():
    code = ("import os, sqlite3\ndb = sqlite3.connect('x')\n"
            "def main():\n    db.execute('SELECT * FROM t WHERE c = ' + os.getenv('USER_FILTER'))\n")
    assert any(f.rule_id == "DF004" for f in analyze_project({"cli.py": code}))


def test_manifest_parsers():
    from vulnscan.stored import parse_config
    assert parse_config("Dockerfile", "ENV A=1 B=\"x y\"\nENV C 3\n") == {"a": "1", "b": "x y", "c": "3"}
    assert parse_config("docker-compose.yml", "s:\n  w:\n    environment:\n      - T=v\n")["t"] == "v"
    assert parse_config("k.yaml", "env:\n- name: T\n  value: v\n")["t"] == "v"
    assert parse_config("app.json", '{"env": {"T": {"value": "v"}}}')["t"] == "v"
