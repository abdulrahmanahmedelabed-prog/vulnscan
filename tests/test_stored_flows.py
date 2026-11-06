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
    assert "JOBS.CMD" in src and "store.go:5" in src


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
