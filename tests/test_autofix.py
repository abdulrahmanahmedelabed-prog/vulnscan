"""Deterministic automatic fixes (vulnscan/autofix.py).

Every fixer is proven end to end on a real scan: the vulnerable program is reported and gets a fix; the fixed
program still parses and is no longer reported; a near-miss twin (a shape the fixer must not touch) keeps its
finding and gets NO fix.
"""

from __future__ import annotations

import ast
import io
import json
import shutil
import subprocess
import textwrap

import pytest

from vulnscan import autofix
from vulnscan.autofix import apply_edits, apply_fixes, attach_fixes, compute_fix, fix_text, split_lines
from vulnscan.cli import build_parser, main
from vulnscan.i18n import has_arabic, translated
from vulnscan.model import Finding, assign_fingerprints
from vulnscan.report import render_console, render_html, render_json, render_markdown, render_sarif
from vulnscan.rules import check_blocks
from vulnscan.scanner import scan_path


def _d(src: str) -> str:
    return textwrap.dedent(src).lstrip("\n")


def _scan(root):
    findings, _ = scan_path(root)
    return findings


def _balanced(text: str) -> bool:
    return all(text.count(a) == text.count(b) for a, b in ("()", "[]", "{}"))


def _fix_one(tmp_path, name: str, src: str, rule: str) -> str:
    """Scan `src`, take the fix of the `rule` finding, apply its edits, rescan: the rule is gone and the file parses.
    Returns the fixed text."""
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(src, encoding="utf-8", newline="")
    findings = _scan(tmp_path)
    hits = [f for f in findings if f.rule_id == rule]
    assert hits, f"{rule} not reported; got {sorted({f.rule_id for f in findings})}"
    assert attach_fixes(findings, tmp_path) >= 1
    fix = hits[0].extra.get("fix")
    assert fix and fix["edits"], f"no fix for {rule}"
    _check_contract(fix, src, name)
    new = apply_edits(src, fix["edits"])
    assert new != src
    path.write_text(new, encoding="utf-8", newline="")
    if name.endswith(".py"):
        ast.parse(new)
    elif name.endswith((".js", ".java")):
        assert _balanced(new)
    after = [f for f in _scan(tmp_path) if f.rule_id == rule]
    assert not after, f"{rule} still reported after the fix:\n{new}"
    return new


def _check_contract(fix: dict, src: str, name: str) -> None:
    assert set(fix) == {"description", "description_ar", "diff", "edits"}
    assert fix["description"] and not has_arabic(fix["description"]) and has_arabic(fix["description_ar"])
    n = len(split_lines(src))
    for e in fix["edits"]:
        assert set(e) == {"file", "start_line", "end_line", "replacement"}
        assert e["file"] == name and 1 <= e["start_line"] <= e["end_line"] <= n
        assert e["replacement"]                                 # never empty: full replacement lines
    assert fix["diff"].startswith(f"--- a/{name}\n+++ b/{name}\n@@ ")


def _no_fix(tmp_path, name: str, src: str, rule: str) -> None:
    """The finding is reported but its shape is not one a fixer may rewrite."""
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(src, encoding="utf-8", newline="")
    findings = _scan(tmp_path)
    hits = [f for f in findings if f.rule_id == rule]
    assert hits, f"{rule} not reported; got {sorted({f.rule_id for f in findings})}"
    attach_fixes(findings, tmp_path)
    assert all(not (f.extra.get("fix") or {}).get("edits") for f in hits), hits[0].extra.get("fix")
    assert apply_fixes(hits, tmp_path).files == {} and path.read_text(encoding="utf-8") == src


# ====================================================================== Python

PY_CASES = [
    ("yaml", "DES002", """
        import yaml
        def load(fh):
            return yaml.load(fh)
        """, "yaml.safe_load(fh)"),
    ("yaml_vql", "vql/yaml-load-without-loader", """
        import yaml as y
        def load(fh):
            return y.load(fh)
        """, "y.safe_load(fh)"),
    ("yaml_unsafe_loader", "DES002", """
        import yaml
        def load(fh):
            return yaml.load(fh, Loader=yaml.FullLoader)
        """, "yaml.safe_load(fh)"),
    ("shell", "EXE004", """
        import subprocess
        def listing():
            return subprocess.run("ls -l /tmp", shell=True, check=True)
        """, 'subprocess.run(["ls", "-l", "/tmp"], check=True)'),
    ("shell_multiline", "EXE004", """
        import subprocess
        def listing():
            return subprocess.check_output("git status --short", shell=True,
                                           timeout=5)
        """, 'subprocess.check_output(["git", "status", "--short"],\n'),
    ("os_system", "EXE004", """
        import os
        def listing():
            os.system("ls -l /tmp")
        """, 'subprocess.run(["ls", "-l", "/tmp"])'),
    ("verify", "CRY002", """
        import requests
        def fetch(url):
            return requests.get(url, timeout=5, verify=False)
        """, "requests.get(url, timeout=5)"),
    ("verify_vql", "vql/tls-verify-disabled", """
        import httpx
        def fetch(url):
            return httpx.get(url, verify=False)
        """, "httpx.get(url)"),
    ("verify_session", "CRY002", """
        import requests
        def client():
            s = requests.Session()
            s.verify = False
            return s
        """, "s.verify = True"),
    ("md5", "CRY001", """
        import hashlib
        def digest(password):
            return hashlib.md5(password.encode()).hexdigest()
        """, "hashlib.sha256(password.encode())"),
    ("hash_new", "CRY001", """
        import hashlib
        def digest(password):
            return hashlib.new('sha1', password).hexdigest()
        """, "hashlib.new('sha256', password)"),
    ("random_choice", "RND001", """
        import random
        import string
        def new_token():
            token = "".join(random.choice(string.ascii_letters) for _ in range(32))
            return token
        """, "secrets.choice(string.ascii_letters)"),
    ("random_randint", "RND001", """
        import random
        def new_otp():
            otp = random.randint(100000, 999999)
            return otp
        """, "otp = (secrets.randbelow(900000) + 100000)"),
    ("random_token_hex", "RND001", """
        import random
        def new_session_id():
            session_id = "%032x" % random.getrandbits(128)
            return session_id
        """, "session_id = secrets.token_hex(16)"),
    ("random_vql", "vql/random-for-secret", """
        import random
        def new_token():
            token = random.getrandbits(64)
            return token
        """, "token = secrets.randbits(64)"),
    ("jwt_options", "vql/jwt-weak-verification", """
        import jwt
        def claims(tok, key):
            return jwt.decode(tok, key, algorithms=["HS256"], options={"verify_signature": False})
        """, 'jwt.decode(tok, key, algorithms=["HS256"])'),
    ("jwt_options_keep_others", "CFG007", """
        import jwt
        def claims(tok, key):
            return jwt.decode(tok, key, algorithms=["HS256"], options={"verify_signature": False, "verify_aud": True})
        """, 'options={"verify_aud": True})'),
    ("jwt_verify_kw", "CFG007", """
        import jwt
        def claims(tok, key):
            return jwt.decode(tok, key, verify=False, algorithms=["HS256"])
        """, 'jwt.decode(tok, key, algorithms=["HS256"])'),
    ("debug", "CFG001", """
        from flask import Flask
        app = Flask(__name__)
        if __name__ == "__main__":
            app.run(host="127.0.0.1", debug=True)
        """, 'app.run(host="127.0.0.1", debug=False)'),
    ("xxe_flags", "XXE001", """
        from lxml import etree
        def parser():
            return etree.XMLParser(resolve_entities=True)
        """, "etree.XMLParser(resolve_entities=False)"),
    ("cookie", "COOK001", """
        from flask import make_response
        def view():
            resp = make_response("ok")
            resp.set_cookie("sid", "value")
            return resp
        """, 'resp.set_cookie("sid", "value", secure=True, httponly=True)'),
    ("cookie_secure_false", "COOK001", """
        from flask import make_response
        def view():
            resp = make_response("ok")
            resp.set_cookie(
                "csrftoken",
                "value",
                secure=False,
            )
            return resp
        """, "secure=True,\n"),
    ("cookie_httponly", "COOK002", """
        from flask import make_response
        def view():
            resp = make_response("ok")
            resp.set_cookie("sid", "value", secure=True, httponly=False)
            return resp
        """, "secure=True, httponly=True)"),
    ("sql_fstring", "INJ001", """
        import sqlite3
        def find(con, name):
            cur = con.cursor()
            cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
            return cur.fetchall()
        """, 'cur.execute("SELECT * FROM users WHERE name = ?", (name,))'),
    ("sql_concat", "vql/sql-built-with-format", """
        import sqlite3
        def find(con, uid):
            cur = con.cursor()
            cur.execute("SELECT * FROM users WHERE id = " + uid)
            return cur.fetchall()
        """, 'cur.execute("SELECT * FROM users WHERE id = ?", (uid,))'),
    ("sql_percent", "vql/sql-built-with-format", """
        import sqlite3
        def find(con, uid):
            cur = con.cursor()
            cur.execute("SELECT * FROM users WHERE id = %s AND active = 1" % uid)
            return cur.fetchall()
        """, 'cur.execute("SELECT * FROM users WHERE id = ? AND active = 1", (uid,))'),
    ("sql_format", "vql/sql-built-with-format", """
        import sqlite3
        def find(con, uid):
            cur = con.cursor()
            cur.execute("SELECT * FROM users WHERE id = {}".format(uid))
            return cur.fetchall()
        """, 'cur.execute("SELECT * FROM users WHERE id = ?", (uid,))'),
    ("sql_psycopg", "INJ001", """
        import psycopg2
        def find(con, name):
            cur = con.cursor()
            cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
            return cur.fetchall()
        """, 'cur.execute("SELECT * FROM users WHERE name = %s", (name,))'),
]


@pytest.mark.parametrize("case", PY_CASES, ids=[c[0] for c in PY_CASES])
def test_python_fix_removes_the_finding(tmp_path, case):
    _name, rule, src, expected = case
    new = _fix_one(tmp_path, "app.py", _d(src), rule)
    assert expected in new, new


def test_python_imports_are_added_once_and_only_when_needed(tmp_path):
    new = _fix_one(tmp_path, "app.py", _d('''
        """Module docstring."""
        import random

        def new_token():
            token = random.randrange(10 ** 9)
            return token
        '''), "RND001")
    assert new.splitlines()[1:3] == ["import random", "import secrets"] and new.count("import secrets") == 1
    assert "token = secrets.randbelow(10 ** 9)" in new
    again = _fix_one(tmp_path, "app.py", _d("""
        import os
        import subprocess

        def a():
            os.system("uname -a")
        """), "EXE004")
    assert again.count("import subprocess") == 1 and 'subprocess.run(["uname", "-a"])' in again


def test_tainted_sql_is_fixed_and_data_flow_finding_disappears(tmp_path):
    src = _d("""
        import sqlite3
        from flask import Flask, request

        app = Flask(__name__)

        @app.route("/u")
        def user():
            name = request.args.get("name")
            con = sqlite3.connect("a.db")
            cur = con.cursor()
            cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
            return str(cur.fetchall())
        """)
    new = _fix_one(tmp_path, "app.py", src, "DF004")
    assert 'cur.execute("SELECT * FROM users WHERE name = ?", (name,))' in new
    assert not [f for f in _scan(tmp_path) if f.rule_id in ("INJ001", "vql/sql-built-with-format")]


def test_mark_safe_is_wrapped_in_escape(tmp_path):
    src = _d("""
        from django.http import HttpResponse
        from django.utils.safestring import mark_safe

        def view(request):
            name = request.GET.get("name")
            return HttpResponse(mark_safe(name))
        """)
    new = _fix_one(tmp_path, "views.py", src, "DF013")
    assert "HttpResponse(mark_safe(escape(name)))" in new and "from django.utils.html import escape\n" in new


PY_NO_FIX = [
    ("yaml_custom_loader", "DES002", """
        import yaml
        def load(fh, loader):
            return yaml.load(fh, Loader=loader)
        """),
    ("shell_pipe", "EXE004", """
        import subprocess
        def count():
            return subprocess.run("ls -l | wc -l", shell=True)
        """),
    ("shell_expansion", "EXE004", """
        import subprocess
        def home():
            return subprocess.run("ls $HOME", shell=True)
        """),
    ("shell_builtin", "EXE004", """
        import subprocess
        def go():
            return subprocess.run("cd /tmp", shell=True)
        """),
    ("shell_dynamic", "EXE004", """
        import subprocess
        def run(cmd):
            return subprocess.run(cmd, shell=True)
        """),
    ("os_system_status_used", "EXE004", """
        import os
        def run():
            status = os.system("ls -l /tmp")
            return status
        """),
    ("random_float", "RND001", """
        import random
        def new_token():
            token = str(random.random())
            return token
        """),
    ("jwt_without_algorithms", "CFG007", """
        import jwt
        def claims(tok, key):
            return jwt.decode(tok, key, options={"verify_signature": False})
        """),
    ("cookie_kwargs", "COOK001", """
        from flask import make_response
        def view():
            resp = make_response("ok")
            resp.set_cookie("sid", "value", secure=bool(0) or False, path="/")
            return resp
        """),
    ("sql_table_name", "INJ001", """
        import sqlite3
        def dump(con, table):
            cur = con.cursor()
            cur.execute(f"SELECT * FROM {table} WHERE active = 1")
            return cur.fetchall()
        """),
    ("sql_two_values", "INJ001", """
        import sqlite3
        def find(con, a, b):
            cur = con.cursor()
            cur.execute(f"SELECT * FROM users WHERE a = {a} AND b = {b}")
            return cur.fetchall()
        """),
    ("sql_like_pattern", "INJ001", """
        import sqlite3
        def find(con, q):
            cur = con.cursor()
            cur.execute(f"SELECT * FROM users WHERE name LIKE '%{q}%'")
            return cur.fetchall()
        """),
    ("sql_unknown_driver", "INJ001", """
        def find(cur, uid):
            cur.execute(f"SELECT * FROM users WHERE id = {uid}")
            return cur.fetchall()
        """),
    ("sql_existing_placeholder", "vql/sql-built-with-format", """
        import sqlite3
        def find(con, uid):
            cur = con.cursor()
            cur.execute("SELECT ? FROM users WHERE id = " + uid)
            return cur.fetchall()
        """),
]


@pytest.mark.parametrize("case", PY_NO_FIX, ids=[c[0] for c in PY_NO_FIX])
def test_python_near_miss_keeps_its_finding_and_gets_no_fix(tmp_path, case):
    _name, rule, src = case
    if case[0] == "cookie_kwargs":
        src = src.replace("secure=bool(0) or False", "**opts").replace("def view():", "def view(opts):")
        path = tmp_path / "app.py"
        path.write_text(_d(src), encoding="utf-8", newline="")
        f = Finding("COOK001", "medium", "t", "ت", "app.py", 4, "", "")
        assert compute_fix(f, _d(src)) is None
        return
    _no_fix(tmp_path, "app.py", _d(src), rule)


def test_safe_python_twins_are_not_reported_and_not_touched(tmp_path):
    src = _d("""
        import hashlib
        import secrets
        import sqlite3
        import subprocess

        import requests
        import yaml

        def load(fh):
            return yaml.safe_load(fh)

        def listing():
            return subprocess.run(["ls", "-l", "/tmp"])

        def fetch(url):
            return requests.get(url, timeout=5)

        def digest(data):
            return hashlib.sha256(data).hexdigest()

        def new_token():
            token = secrets.token_hex(16)
            return token

        def find(con, name):
            cur = con.cursor()
            cur.execute("SELECT * FROM users WHERE name = ?", (name,))
            return cur.fetchall()
        """)
    (tmp_path / "app.py").write_text(src, encoding="utf-8", newline="")
    findings = _scan(tmp_path)
    assert not [f for f in findings if f.rule_id in autofix.fixable_rules()], [f.rule_id for f in findings]
    assert attach_fixes(findings, tmp_path) == 0
    assert apply_fixes(findings, tmp_path).files == {}


# ---- XML: no engine rule flags a plain stdlib parse today, so the fixers answer any CWE-611 finding

def _xxe(file: str, line: int) -> Finding:
    return Finding("XXE-EXT", "high", "XML external entity", "كيان XML خارجي", file, line, "", "", "CWE-611")


def test_defusedxml_swaps_a_direct_import(tmp_path):
    src = _d("""
        import xml.etree.ElementTree as ET

        def read(path):
            return ET.parse(path).getroot()
        """)
    fix = compute_fix(_xxe("a.py", 4), src)
    new = apply_edits(src, fix["edits"])
    ast.parse(new)
    assert new.startswith("import defusedxml.ElementTree as ET\n") and "ET.parse(path)" in new
    assert "defusedxml" in fix["description"] and "pip install defusedxml" in fix["description"]   # the dependency
    for imp, call, want in [
        ("from xml.etree import ElementTree as ET", "ET.fromstring(data)", "from defusedxml import ElementTree as ET"),
        ("from xml.etree.ElementTree import fromstring", "fromstring(data)", "from defusedxml.ElementTree import fromstring"),
        ("from xml.dom import minidom", "minidom.parseString(data)", "from defusedxml import minidom"),
        ("import xml.sax as sax", "sax.parseString(data, handler)", "import defusedxml.sax as sax"),
    ]:
        src = f"{imp}\n\ndef read(data, handler=None):\n    return {call}\n"
        fix = compute_fix(_xxe("a.py", 4), src)
        assert fix, imp
        new = apply_edits(src, fix["edits"])
        ast.parse(new)
        assert new.splitlines()[0] == want and call in new


def test_defusedxml_is_not_offered_when_the_module_is_used_for_more_than_parsing():
    # defusedxml.ElementTree has no Element / SubElement: swapping the import would break the file
    src = _d("""
        import xml.etree.ElementTree as ET

        def build(path):
            root = ET.parse(path).getroot()
            ET.SubElement(root, "item")
            return root
        """)
    assert compute_fix(_xxe("a.py", 4), src) is None
    indirect = "import xml.etree.ElementTree\n\ndef read(p):\n    return xml.etree.ElementTree.parse(p)\n"
    assert compute_fix(_xxe("a.py", 4), indirect) is None                   # not a direct alias import
    partial = "from xml.etree.ElementTree import parse, Element\n\ndef read(p):\n    return parse(p)\n"
    assert compute_fix(_xxe("a.py", 4), partial) is None


# ====================================================================== JavaScript

JS_CASES = [
    ("exec_concat", "EXE005", """
        const { exec } = require("child_process");
        function run(dir, cb) {
          exec("ls -l " + dir, cb);
        }
        """, ['const { exec, execFile } = require("child_process");', 'execFile("ls", ["-l", dir], cb);']),
    ("exec_template", "EXE005", """
        import { execSync } from "node:child_process";
        export function run(ref) {
          return execSync(`git rev-parse ${ref}`);
        }
        """, ['import { execSync, execFileSync } from "node:child_process";', 'execFileSync("git", ["rev-parse", ref]);']),
    ("exec_member", "EXE005", """
        const cp = require('child_process');
        function run(dir, cb) {
          cp.exec('du -sh ' + dir, cb);
        }
        """, ['cp.execFile("du", ["-sh", dir], cb);']),
    ("innerhtml", "INJ004", """
        function show(el, name) {
          el.innerHTML = name;
        }
        """, ["el.textContent = name;"]),
    ("eval_json", "EXE002", """
        function parse(text) {
          return eval("(" + text + ")");
        }
        """, ["return JSON.parse(text);"]),
    ("cookie", "vql/js-cookie-insecure", """
        const express = require("express");
        const app = express();
        app.get("/c", (req, res) => {
          res.cookie("sid", "v", { secure: false, httpOnly: false });
          res.end();
        });
        """, ['{ secure: true, httpOnly: true }']),
    ("tls", "CRY002", """
        const https = require("https");
        const agent = new https.Agent({ rejectUnauthorized: false });
        """, ["{ rejectUnauthorized: true }"]),
]


@pytest.mark.parametrize("case", JS_CASES, ids=[c[0] for c in JS_CASES])
def test_javascript_fix_removes_the_finding(tmp_path, case):
    _name, rule, src, expected = case
    new = _fix_one(tmp_path, "app.js", _d(src), rule)
    for want in expected:
        assert want in new, new


JS_NO_FIX = [
    ("exec_pipe", "EXE005", """
        const { exec } = require("child_process");
        function run(dir, cb) {
          exec("ls -l | grep " + dir, cb);
        }
        """),
    ("exec_glued_word", "EXE005", """
        const { exec } = require("child_process");
        function run(dir, cb) {
          exec("ls -l /srv/" + dir, cb);
        }
        """),
    ("exec_not_from_child_process", "EXE005", """
        const { exec } = require("./shell");
        function run(dir, cb) {
          exec("ls -l " + dir, cb);
        }
        """),
    ("innerhtml_markup", "INJ004", """
        function show(el, bodyHtml) {
          el.innerHTML = bodyHtml;
        }
        """),
    ("innerhtml_expression", "INJ004", """
        function show(el, name) {
          el.innerHTML = render(name);
        }
        """),
    ("eval_code", "EXE002", """
        function run(code) {
          return eval(code);
        }
        """),
]


@pytest.mark.parametrize("case", JS_NO_FIX, ids=[c[0] for c in JS_NO_FIX])
def test_javascript_near_miss_keeps_its_finding_and_gets_no_fix(tmp_path, case):
    _name, rule, src = case
    _no_fix(tmp_path, "app.js", _d(src), rule)


# ====================================================================== Java

JAVA = _d("""
    import java.security.MessageDigest;
    import java.util.Random;
    import javax.servlet.http.*;

    public class C extends HttpServlet {
        public byte[] hash(byte[] password) throws Exception {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return md.digest(password);
        }

        public String newToken() {
            Random r = new Random();
            return Long.toHexString(r.nextLong());
        }

        public void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
            Cookie ck = new Cookie("sid", "v");
            ck.setSecure(false);
            resp.addCookie(ck);
        }
    }
    """)


@pytest.mark.parametrize("rule,expected", [
    ("CRY102", 'MessageDigest.getInstance("SHA-256")'),
    ("CRY001", 'MessageDigest.getInstance("SHA-256")'),
    ("RND001", "Random r = new java.security.SecureRandom();"),
    ("COOK001", "ck.setSecure(true);"),
])
def test_java_fix_removes_the_finding(tmp_path, rule, expected):
    assert expected in _fix_one(tmp_path, "C.java", JAVA, rule)


def test_java_xxe_flag_is_flipped(tmp_path):
    src = _d("""
        import javax.xml.parsers.DocumentBuilderFactory;

        public class X {
            DocumentBuilderFactory make() throws Exception {
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
                return dbf;
            }
        }
        """)
    assert 'disallow-doctype-decl", true);' in _fix_one(tmp_path, "X.java", src, "XXE001")


def test_java_seeded_random_and_property_algorithms_are_left_alone(tmp_path):
    src = JAVA.replace("new Random()", "new Random(42L)")
    _no_fix(tmp_path, "C.java", src, "RND001")


def test_java_document_builder_factory_is_hardened_before_use():
    src = _d("""
        import javax.xml.parsers.DocumentBuilder;
        import javax.xml.parsers.DocumentBuilderFactory;

        public class X {
            org.w3c.dom.Document read(java.io.InputStream in) throws Exception {
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                dbf.setNamespaceAware(true);
                DocumentBuilder db = dbf.newDocumentBuilder();
                return db.parse(in);
            }
        }
        """)
    fix = compute_fix(_xxe("X.java", 9), src)
    new = apply_edits(src, fix["edits"])
    lines = new.splitlines()
    at = lines.index("        DocumentBuilder db = dbf.newDocumentBuilder();")
    assert [ln.strip() for ln in lines[at - 3:at]] == [
        'dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
        "dbf.setXIncludeAware(false);", "dbf.setExpandEntityReferences(false);"]
    assert _balanced(new) and len(lines) == len(src.splitlines()) + 3
    assert compute_fix(_xxe("X.java", 9), new) is None                       # already hardened: nothing more to do
    chained = src.replace("DocumentBuilder db = dbf.newDocumentBuilder();\n        return db.parse(in);",
                          "return dbf\n            .newDocumentBuilder().parse(in);")
    assert compute_fix(_xxe("X.java", 9), chained) is None                   # not a statement of its own line


def test_java_sql_injection_gets_advice_only(tmp_path):
    src = _d("""
        import java.sql.*;
        import javax.servlet.http.*;

        public class Q extends HttpServlet {
            public void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
                Connection c = DriverManager.getConnection("jdbc:h2:mem:");
                Statement st = c.createStatement();
                ResultSet rs = st.executeQuery("SELECT * FROM users WHERE name = '" + req.getParameter("name") + "'");
            }
        }
        """)
    (tmp_path / "Q.java").write_text(src, encoding="utf-8", newline="")
    findings = [f for f in _scan(tmp_path) if f.rule_id == "DF004"]
    assert findings and attach_fixes(findings, tmp_path) == 1
    fix = findings[0].extra["fix"]
    assert fix["edits"] == [] and fix["diff"] == "" and "PreparedStatement" in fix["description"]
    rep = apply_fixes(findings, tmp_path)
    assert rep.files == {} and rep.advice == findings and (tmp_path / "Q.java").read_text(encoding="utf-8") == src


# ====================================================================== Dockerfile / Kubernetes / GitHub Actions

def test_dockerfile_gets_a_user_before_cmd(tmp_path):
    src = "FROM python:3.12-slim\nWORKDIR /app\nCOPY . .\nCMD [\"python\", \"app.py\"]\n"
    new = _fix_one(tmp_path, "Dockerfile", src, "DKR000")
    assert new == "FROM python:3.12-slim\nWORKDIR /app\nCOPY . .\nUSER 10001\nCMD [\"python\", \"app.py\"]\n"


def test_dockerfile_in_a_subdirectory_and_without_cmd():
    rel = "services/api/Dockerfile"
    src = "FROM golang:1.22 AS build\nRUN go build -o /app .\nFROM gcr.io/distroless/base\nCOPY --from=build /app /app"
    [finding] = [f for f in check_blocks(rel, src) if f.rule_id == "DKR013"]
    fix = compute_fix(finding, src)
    new = apply_edits(src, fix["edits"])
    assert new == src + "\nUSER 10001\n"
    assert not [f for f in check_blocks(rel, new) if f.rule_id == "DKR013"]
    continued = "FROM alpine:3.20\nRUN apk add --no-cache curl && \\\n    curl --version \\\n"
    [finding] = [f for f in check_blocks(rel, continued) if f.rule_id == "DKR013"]
    assert compute_fix(finding, continued) is None                           # would land inside the RUN


K8S = _d("""
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: web
    spec:
      template:
        spec:
          containers:
            - name: web
              image: nginx:1.27.0
              securityContext:
                allowPrivilegeEscalation: true
                runAsNonRoot: false
    """)


@pytest.mark.parametrize("rule,expected", [("K8S001", "allowPrivilegeEscalation: false"), ("K8S006", "runAsNonRoot: true")])
def test_kubernetes_flag_is_flipped(tmp_path, rule, expected):
    new = _fix_one(tmp_path, "deploy.yaml", K8S, rule)
    assert expected in new and len(new.splitlines()) == len(K8S.splitlines())


def test_kubernetes_pod_security_context_is_added():
    src = K8S[:K8S.index("          securityContext:")]
    [finding] = [f for f in check_blocks("deploy.yaml", src) if f.rule_id == "K8S010"]
    fix = compute_fix(finding, src)
    new = apply_edits(src, fix["edits"])
    assert "    spec:\n      securityContext:\n        runAsNonRoot: true\n      containers:\n" in new
    assert not [f for f in check_blocks("deploy.yaml", new) if f.rule_id == "K8S010"]
    templated = src.replace("nginx:1.27.0", "{{ .Values.image }}")
    assert compute_fix(dataclass_with_line(finding, 2), templated) is None    # Helm template: not plain YAML


def dataclass_with_line(f: Finding, line: int) -> Finding:
    return Finding(f.rule_id, f.severity, f.title, f.title_ar, f.file, line, f.snippet, f.advice, f.cwe, f.source, {})


GHA = _d("""
    name: ci
    on: pull_request
    jobs:
      greet:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
          - name: branch
            run: |
              echo "Branch: ${{ github.head_ref }}"
              git checkout ${{ github.head_ref }}
          - run: echo "${{ github.event.pull_request.head.label }}"
            env:
              LANG: C
    """)


def test_github_actions_expression_moves_to_env(tmp_path):
    path = tmp_path / ".github" / "workflows" / "ci.yml"
    path.parent.mkdir(parents=True)
    path.write_text(GHA, encoding="utf-8", newline="")
    findings = [f for f in _scan(tmp_path) if f.rule_id == "GHA002"]
    assert len(findings) == 3
    rep = apply_fixes(findings, tmp_path)                 # two steps: two fixes; the second line of step 1 is covered
    assert len(rep.fixed) == 2 and len(rep.covered) == 1
    new = path.read_text(encoding="utf-8")
    assert not [f for f in _scan(tmp_path) if f.rule_id == "GHA002"]
    assert ('      - name: branch\n        run: |\n          echo "Branch: ${HEAD_REF}"\n'
            '          git checkout "${HEAD_REF}"\n        env:\n          HEAD_REF: ${{ github.head_ref }}\n') in new
    assert new.count("${{ github.head_ref }}") == 1
    # an existing env: block of the step is extended, not duplicated
    assert 'run: echo "${PR_HEAD_LABEL}"\n        env:\n          PR_HEAD_LABEL: ${{ github.event.pull_request.head.label }}\n          LANG: C\n' in new


def test_github_actions_event_context_leaves_the_script(tmp_path):
    src = _d("""
        name: triage
        on: issues
        jobs:
          t:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.issue.title }}" >> log.txt
        """)
    path = tmp_path / ".github" / "workflows" / "t.yml"
    path.parent.mkdir(parents=True)
    path.write_text(src, encoding="utf-8", newline="")
    [finding] = [f for f in _scan(tmp_path) if f.rule_id == "CI001"]
    attach_fixes([finding], tmp_path)
    new = apply_edits(src, finding.extra["fix"]["edits"])
    assert '      - run: echo "${ISSUE_TITLE}" >> log.txt\n        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n' in new
    path.write_text(new, encoding="utf-8", newline="")
    # the script line no longer interpolates the expression (CI001 is a line pattern: what it still matches is the
    # env: entry of the remediation itself, never a run: line)
    script_lines = {i + 1 for i, ln in enumerate(new.splitlines()) if "run:" in ln}
    assert not [f for f in _scan(tmp_path) if f.rule_id == "CI001" and f.line in script_lines]


@pytest.mark.parametrize("old,new", [
    ('echo "Branch: ${{ github.head_ref }}"', "echo 'Branch: ${{ github.head_ref }}'"),      # no expansion in '...'
    ("runs-on: ubuntu-latest", "runs-on: windows-latest"),                                     # $VAR is not pwsh
    ("- name: branch\n        run: |", "- name: branch\n        shell: python\n        run: |"),
])
def test_github_actions_near_miss_gets_no_fix(tmp_path, old, new):
    one_step = GHA[:GHA.index("      - run: echo")]
    assert old in one_step
    _no_fix(tmp_path, ".github/workflows/ci.yml", one_step.replace(old, new), "GHA002")


# ====================================================================== edits, files, safety

def test_crlf_and_missing_final_newline_are_preserved(tmp_path):
    src = "import yaml\r\ndef load(fh):\r\n    return yaml.load(fh)"
    (tmp_path / "a.py").write_bytes(src.encode())
    findings = [f for f in _scan(tmp_path) if f.rule_id == "DES002"]
    rep = apply_fixes(findings, tmp_path)
    assert (tmp_path / "a.py").read_bytes() == b"import yaml\r\ndef load(fh):\r\n    return yaml.safe_load(fh)"
    assert list(rep.files) == ["a.py"] and len(rep.fixed) == 1


def test_non_ascii_source_keeps_exact_columns(tmp_path):
    src = 'import yaml\ndef load(fh):\n    note = "تحميل الإعدادات"; return yaml.load(fh)  # ملاحظة\n'
    new = _fix_one(tmp_path, "a.py", src, "DES002")
    assert new == src.replace("yaml.load(", "yaml.safe_load(")


def test_several_findings_in_one_file_are_fixed_together_and_lines_are_followed(tmp_path):
    src = _d("""
        import hashlib
        import random
        import subprocess

        import yaml

        def new_token():
            token = random.getrandbits(64)
            return token

        def load(fh):
            return yaml.load(fh)

        def listing():
            return subprocess.run("ls -l /tmp", shell=True)

        def digest(data):
            return hashlib.md5(data).hexdigest()
        """)
    (tmp_path / "a.py").write_text(src, encoding="utf-8", newline="")
    findings = _scan(tmp_path)
    before = {f.rule_id for f in findings}
    assert {"RND001", "DES002", "EXE004", "CRY001"} <= before
    new, status = fix_text(src, "a.py", findings)
    ast.parse(new)
    assert "fixed" in status.values() and "covered" in status.values()      # two rules on one line: fixed once
    for want in ("import secrets\n", "secrets.randbits(64)", "yaml.safe_load(fh)", '["ls", "-l", "/tmp"]', "hashlib.sha256("):
        assert want in new
    rep = apply_fixes(findings, tmp_path)
    assert (tmp_path / "a.py").read_text(encoding="utf-8") == new and len(rep.fixed) >= 4
    assert not {f.rule_id for f in _scan(tmp_path)} & {"RND001", "CRY005", "DES002", "EXE004", "CRY001",
                                                       "vql/yaml-load-without-loader", "vql/random-for-secret"}


def test_nothing_outside_the_scan_root_is_touched(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    outside = tmp_path / "outside.py"
    bad = "import yaml\ndef load(fh):\n    return yaml.load(fh)\n"
    outside.write_text(bad, encoding="utf-8", newline="")
    (root / "inside.py").write_text(bad, encoding="utf-8", newline="")
    escaping = Finding("DES002", "high", "t", "ت", "../outside.py", 3, "", "")
    absolute = Finding("DES002", "high", "t", "ت", str(outside), 3, "", "")
    member = Finding("DES002", "high", "t", "ت", "app.zip!inside.py", 3, "", "")
    try:
        (root / "link.py").symlink_to(outside)
        linked = [Finding("DES002", "high", "t", "ت", "link.py", 3, "", "")]
    except OSError:
        linked = []
    todo = [escaping, absolute, member] + linked
    assert attach_fixes(todo, root) == 0
    rep = apply_fixes(todo, root)
    assert rep.files == {} and len(rep.unfixable) == len(todo)
    assert outside.read_text(encoding="utf-8") == bad
    ok = Finding("DES002", "high", "t", "ت", "inside.py", 3, "", "")
    assert list(apply_fixes([ok], root).files) == ["inside.py"]


def test_findings_of_external_tools_and_unparsable_files_get_no_fix(tmp_path):
    src = "import yaml\ndef load(fh):\n    return yaml.load(fh)\n"
    assert compute_fix(Finding("DES002", "high", "t", "ت", "a.py", 3, "", "", source="bandit"), src) is None
    assert compute_fix(Finding("DES002", "high", "t", "ت", "a.py", 3, "", ""), src + "def broken(:\n") is None
    assert compute_fix(Finding("DES002", "high", "t", "ت", "a.py", 99, "", ""), src) is None
    assert compute_fix(Finding("SEC004", "high", "t", "ت", "a.py", 3, "", ""), src) is None
    (tmp_path / "bin.py").write_bytes(b"import yaml\nyaml.load(x)\n\xff\xfe")
    assert attach_fixes([Finding("DES002", "high", "t", "ت", "bin.py", 2, "", "")], tmp_path) == 0


def test_apply_edits_rejects_overlapping_edits():
    with pytest.raises(ValueError):
        apply_edits("a\nb\n", [{"file": "x", "start_line": 1, "end_line": 2, "replacement": "c\n"},
                               {"file": "x", "start_line": 2, "end_line": 2, "replacement": "d\n"}])


# ====================================================================== Finding.to_dict, reports

@pytest.fixture
def project(tmp_path):
    (tmp_path / "a.py").write_text("import yaml\ndef load(fh):\n    return yaml.load(fh)\n", encoding="utf-8", newline="")
    return tmp_path


def _fixed_findings(project):
    findings = _scan(project)
    assign_fingerprints(findings)
    attach_fixes(findings, project)
    return findings


def test_to_dict_exposes_fix_at_top_level_and_keeps_the_fingerprint(project):
    plain = _scan(project)
    assign_fingerprints(plain)
    findings = _fixed_findings(project)
    for a, b in zip(sorted(plain, key=lambda f: f.key()), sorted(findings, key=lambda f: f.key())):
        da, db = a.to_dict(), b.to_dict()
        assert da["fingerprint"] == db["fingerprint"] and "fix" not in da and "fix" not in db["extra"]
    d = next(f for f in findings if f.rule_id == "DES002").to_dict()
    assert d["fix"]["edits"] == [{"file": "a.py", "start_line": 3, "end_line": 3,
                                  "replacement": "    return yaml.safe_load(fh)\n"}]
    assert "yaml.safe_load" in d["fix"]["description"] and has_arabic(d["fix"]["description_ar"])
    out = json.loads(render_json(findings, str(project), 1, []))
    assert [f["fix"]["diff"] for f in out["findings"] if f["rule_id"] == "DES002"][0].count("\n+    return yaml.safe_load(fh)") == 1


def test_sarif_fixes_follow_the_spec(project):
    findings = _fixed_findings(project)
    sarif = json.loads(render_sarif(findings, str(project), 1, [], lang="en"))
    [res] = [r for r in sarif["runs"][0]["results"] if r["ruleId"] == "DES002"]
    [fix] = res["fixes"]
    assert fix["description"]["text"].startswith("Replace yaml.load") and "properties" not in fix
    [change] = fix["artifactChanges"]
    assert change["artifactLocation"] == {"uri": "a.py", "uriBaseId": "%SRCROOT%"}
    assert change["replacements"] == [{"deletedRegion": {"startLine": 3, "startColumn": 1, "endLine": 3},
                                       "insertedContent": {"text": "    return yaml.safe_load(fh)"}}]
    both = json.loads(render_sarif(findings, str(project), 1, []))
    [res] = [r for r in both["runs"][0]["results"] if r["ruleId"] == "DES002"]
    assert has_arabic(res["fixes"][0]["properties"]["description_ar"])
    # a finding without a fix, or with advice only, carries no SARIF fix
    for f in findings:
        f.extra.pop("fix", None)
    assert all("fixes" not in r for r in json.loads(render_sarif(findings, str(project), 1, []))["runs"][0]["results"])


def test_markdown_html_and_console_show_the_suggested_fix(project):
    findings = _fixed_findings(project)
    md = render_markdown(findings, str(project), 1, [], lang="en")
    assert "- Suggested fix: Replace yaml.load with yaml.safe_load" in md
    assert "  ```diff\n  --- a/a.py\n  +++ b/a.py\n" in md and "\n  +    return yaml.safe_load(fh)\n" in md
    assert "إصلاح مقترح" in render_markdown(findings, str(project), 1, [], lang="ar")
    page = render_html(findings, str(project), 1, [], lang="en")
    assert "<summary>Suggested fix</summary>" in page and "<span class='add'>+    return yaml.safe_load(fh)</span>" in page
    assert not has_arabic(page)
    console = render_console(findings, str(project), 1, [], color=False, lang="en")
    assert "🔧 Suggested fix: Replace yaml.load" in console and not has_arabic(console)
    for f in findings:
        f.extra.pop("fix", None)
    assert "Suggested fix" not in render_markdown(findings, str(project), 1, [], lang="en")
    assert "Suggested fix" not in render_html(findings, str(project), 1, [], lang="en")


# ====================================================================== command line

def _cli(*args):
    return main([*args, "--no-deps", "--no-external", "--lang", "en"])


def test_cli_dry_run_prints_a_patch_and_changes_nothing(project, capsys):
    before = (project / "a.py").read_text(encoding="utf-8")
    assert _cli(str(project), "--fix-dry-run") == 0
    out, err = capsys.readouterr()
    assert out.startswith("--- a/a.py\n+++ b/a.py\n") and "+    return yaml.safe_load(fh)\n" in out
    assert "Autofix (dry run, nothing modified): 1 fix(es) available in 1 file(s)." in err and not has_arabic(err)
    assert (project / "a.py").read_text(encoding="utf-8") == before
    # --fix together with --fix-dry-run stays a dry run
    assert _cli(str(project), "--fix", "--fix-dry-run") == 0
    assert (project / "a.py").read_text(encoding="utf-8") == before


def test_cli_fix_applies_and_reports(project, capsys):
    assert _cli(str(project), "--fix") == 0
    out = capsys.readouterr().out
    assert "Autofix: applied 1 fix(es) in 1 file(s)." in out and "✔ a.py" in out and "Scan again" in out
    assert "yaml.safe_load(fh)" in (project / "a.py").read_text(encoding="utf-8")
    assert _cli(str(project), "--fix") == 0                                  # nothing left: a no-op
    assert "applied 0 fix(es) in 0 file(s)" in capsys.readouterr().out
    assert _cli(str(project), "-f", "json") == 0
    assert not [f for f in json.loads(capsys.readouterr().out)["findings"] if f["rule_id"] == "DES002"]


def test_cli_fix_on_a_single_file_target(project, capsys):
    assert _cli(str(project / "a.py"), "--fix") == 0
    assert "yaml.safe_load(fh)" in (project / "a.py").read_text(encoding="utf-8")


def test_cli_json_report_carries_the_fix(project, capsys):
    assert _cli(str(project), "-f", "json") == 0
    [f] = [f for f in json.loads(capsys.readouterr().out)["findings"] if f["rule_id"] == "DES002"]
    assert f["fix"]["edits"][0]["start_line"] == 3


def test_cli_fix_respects_the_severity_filter(project, capsys):
    assert _cli(str(project), "--fix", "--min-severity", "critical") == 0     # DES002 is high: filtered out
    assert "yaml.load(fh)" in (project / "a.py").read_text(encoding="utf-8")


def test_cli_fix_needs_a_local_target(capsys):
    with pytest.raises(SystemExit):
        main(["https://example.com", "--authorized", "--fix", "--lang", "en", "--timeout", "0.01"])


def _git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false",
                    *args], cwd=cwd, check=True, capture_output=True)


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_cli_fix_refuses_a_dirty_git_tree_unless_forced(project, capsys):
    _git(project, "init", "-q")
    _git(project, "add", "a.py")
    _git(project, "commit", "-q", "-m", "init")
    assert autofix.git_dirty(project, ["a.py"]) == []
    (project / "a.py").write_text((project / "a.py").read_text(encoding="utf-8") + "\n# local edit\n", encoding="utf-8",
                                  newline="")
    assert autofix.git_dirty(project, ["a.py"]) == ["a.py"]
    assert _cli(str(project), "--fix") == 2
    err = capsys.readouterr().err
    assert "--fix refused" in err and "a.py" in err and not has_arabic(err)
    assert "yaml.load(fh)" in (project / "a.py").read_text(encoding="utf-8")
    assert _cli(str(project), "--fix-dry-run") == 0                           # a dry run never needs a clean tree
    capsys.readouterr()
    assert _cli(str(project), "--fix", "--fix-force") == 0
    assert "yaml.safe_load(fh)" in (project / "a.py").read_text(encoding="utf-8")
    # clean tree: applied without force; an untracked file that needs a fix is refused (it could not be restored)
    _git(project, "commit", "-q", "-am", "fixed")
    (project / "b.py").write_text("import yaml\ndef load(fh):\n    return yaml.load(fh)\n", encoding="utf-8", newline="")
    assert _cli(str(project), "--fix") == 2
    _git(project, "add", "b.py")
    _git(project, "commit", "-q", "-m", "b")
    assert _cli(str(project), "--fix") == 0
    assert "yaml.safe_load(fh)" in (project / "b.py").read_text(encoding="utf-8")


def test_not_a_git_repository_is_not_dirty(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git not installed")
    inside = subprocess.run(["git", "-C", str(tmp_path), "rev-parse", "--is-inside-work-tree"], capture_output=True)
    if inside.returncode == 0:
        pytest.skip("temporary directory is inside a git work tree")
    assert autofix.git_dirty(tmp_path, ["a.py"]) is None


# ====================================================================== editor (LSP) code action

def _apply_lsp(text: str, edits: list[dict]) -> str:
    lines = split_lines(text) + [""]

    def offset(pos):
        return sum(len(x) for x in lines[:pos["line"]]) + pos["character"]

    for e in sorted(edits, key=lambda e: (e["range"]["start"]["line"], e["range"]["start"]["character"]), reverse=True):
        text = text[:offset(e["range"]["start"])] + e["newText"] + text[offset(e["range"]["end"]):]
    return text


@pytest.mark.parametrize("src,line,rule,want", [
    ("import yaml\ndef load(fh):\n    return yaml.load(fh)\n", 3, "DES002", "import yaml\ndef load(fh):\n    return yaml.safe_load(fh)\n"),
    ("import yaml\ndef load(fh):\n    return yaml.load(fh)", 3, "DES002", "import yaml\ndef load(fh):\n    return yaml.safe_load(fh)"),
    ("import os\nos.system('ls -l /tmp')\n", 2, "EXE004",
     "import os\nimport subprocess\nsubprocess.run([\"ls\", \"-l\", \"/tmp\"])\n"),
])
def test_lsp_offers_apply_kashif_fix(tmp_path, src, line, rule, want):
    from vulnscan.lsp import MSG, KashifLanguageServer, path_to_uri
    srv = KashifLanguageServer(io.BytesIO(), debounce=0.0)
    try:
        f = Finding(rule, "high", "t", "ت", "a.py", line, "", "")
        diag = {"range": {"start": {"line": line - 1, "character": 0}, "end": {"line": line - 1, "character": 1}}}
        uri = path_to_uri(tmp_path / "a.py")
        action = srv._fix_action(f, diag, uri, src, line - 1, "en")
        assert action["title"].startswith(f"Kashif: Apply Kashif fix ({rule}) — ") and not has_arabic(action["title"])
        assert action["kind"] == "quickfix" and action["isPreferred"] is True and action["diagnostics"] == [diag]
        assert _apply_lsp(src, action["edit"]["changes"][uri]) == want
        assert has_arabic(srv._fix_action(f, diag, uri, src, line - 1, "ar")["title"])
        # the buffer no longer has the vulnerable shape (already fixed, or edited): no action
        assert srv._fix_action(f, diag, uri, want, line - 1, "en") is None
        assert translated(MSG["apply_fix"])
    finally:
        srv.handle({"jsonrpc": "2.0", "id": 99, "method": "shutdown"})
        srv.handle({"jsonrpc": "2.0", "method": "exit"})


def test_lsp_code_action_request_includes_the_fix(tmp_path):
    from vulnscan.lsp import KashifLanguageServer, path_to_uri
    src = "import yaml\ndef load(fh):\n    return yaml.load(fh)\n"
    (tmp_path / "a.py").write_text(src, encoding="utf-8", newline="")
    out = io.BytesIO()
    srv = KashifLanguageServer(out, debounce=0.0)
    try:
        srv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"rootUri": path_to_uri(tmp_path), "capabilities": {},
                               "initializationOptions": {"language": "en"}}})
        srv.handle({"jsonrpc": "2.0", "method": "initialized", "params": {}})
        uri = path_to_uri(tmp_path / "a.py")
        srv.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen",
                    "params": {"textDocument": {"uri": uri, "text": src, "version": 1}}})
        import time
        deadline = time.time() + 30
        while time.time() < deadline and b"publishDiagnostics" not in out.getvalue():
            time.sleep(0.05)
        assert b"publishDiagnostics" in out.getvalue()
        srv.handle({"jsonrpc": "2.0", "id": 7, "method": "textDocument/codeAction",
                    "params": {"textDocument": {"uri": uri}, "range": {"start": {"line": 2, "character": 0},
                                                                       "end": {"line": 2, "character": 0}},
                               "context": {"diagnostics": []}}})
        raw = out.getvalue().decode("utf-8")
        reply = next(json.loads(body) for body in _frames(raw) if json.loads(body).get("id") == 7)
        fixes = [a for a in reply["result"] if "Apply Kashif fix" in a["title"] or "طبّق إصلاح كاشِف" in a["title"]]
        assert fixes and _apply_lsp(src, fixes[0]["edit"]["changes"][uri]) == src.replace("yaml.load", "yaml.safe_load")
        assert reply["result"].index(fixes[0]) == 0                          # offered first
    finally:
        srv.handle({"jsonrpc": "2.0", "id": 99, "method": "shutdown"})
        srv.handle({"jsonrpc": "2.0", "method": "exit"})


def _frames(raw: str):
    pos = 0
    while True:
        head = raw.find("Content-Length:", pos)
        if head < 0:
            return
        sep = raw.find("\r\n\r\n", head)
        size = int(raw[head + 15:raw.find("\r\n", head)])
        body = raw[sep + 4:].encode("utf-8")[:size].decode("utf-8")
        yield body
        pos = sep + 4 + len(body)


# ====================================================================== catalogue

def test_every_description_and_message_has_english():
    for text in list(autofix.D.values()) + list(autofix.MSG.values()):
        assert has_arabic(text) and translated(text), text
    assert not has_arabic(build_parser("en").format_help())
    assert "--fix-dry-run" in build_parser("en").format_help()


def test_fixable_rule_inventory():
    rules = autofix.fixable_rules()
    auto = autofix.fixable_rules(auto_only=True)
    assert len(autofix.FIXERS) == 29 and len({fx.func for fx in autofix.FIXERS}) == 28
    assert len(rules) == 39 and len(auto) == 38 and set(rules) - set(auto) == {"INJ002"}
    for must in ("DES002", "EXE004", "CRY002", "CRY001", "RND001", "CFG007", "CFG001", "XXE001", "DF013", "COOK001",
                 "INJ001", "DF004", "EXE005", "INJ004", "EXE002", "CRY102", "DKR000", "DKR013", "K8S001", "K8S006",
                 "K8S010", "CI001", "GHA002"):
        assert must in rules
    assert {c for fx in autofix.FIXERS for c in fx.cwes} == {"CWE-611"}


# ====================================================================== adversarial review: shapes a fix must not break

def _f(rule: str, line: int, file: str, cwe: str = "") -> Finding:
    return Finding(rule, "high", "t", "t", file, line, "", "", cwe)


def _after(rule: str, line: int, file: str, src: str, cwe: str = "") -> str | None:
    """The fixed text (via the fix's own edits), or None when no automatic fix is offered."""
    fix = compute_fix(_f(rule, line, file, cwe), src)
    if not fix or not fix["edits"]:
        return None
    new = apply_edits(src, fix["edits"])
    if file.endswith(".py"):
        ast.parse(new)
    elif file.endswith((".js", ".java")):
        assert _balanced(new)
    return new


def test_added_import_precedes_module_level_code_that_uses_it():
    # the import used to be appended after the LAST import of the file: below a module-level call (NameError)
    src = "import os\nos.system('ls')\nimport json\n"
    assert _after("EXE004", 2, "a.py", src) == 'import os\nimport subprocess\nsubprocess.run(["ls"])\nimport json\n'
    src = "import random\nTOKEN = random.choice(ALPHABET)\nimport json\n"
    new = _after("RND001", 2, "a.py", src)
    assert new.index("import secrets") < new.index("secrets.choice")
    # no line between the import and its use: no fix rather than a wrong order
    assert _after("EXE004", 1, "a.py", "import os; os.system('ls')\n") is None
    # the new line takes the terminator of its neighbour (mixed line endings stay as they are)
    assert _after("EXE004", 3, "a.py", "import os\nx = 1\r\nos.system('ls')\n") == \
        'import os\nimport subprocess\nx = 1\r\nsubprocess.run(["ls"])\n'


def test_parenthesised_sql_query_is_not_turned_into_a_tuple():
    head = "import sqlite3\nc = sqlite3.connect('x').cursor()\n"
    # execute(("..." + v)) -> execute(("...?", (v,))) would pass ONE tuple as the query
    assert _after("INJ001", 3, "a.py", head + 'c.execute(("SELECT * FROM t WHERE id = " + uid))\n') is None
    assert _after("INJ001", 3, "a.py", head + 'c.execute("SELECT * FROM t WHERE id = " + uid)\n') == \
        head + 'c.execute("SELECT * FROM t WHERE id = ?", (uid,))\n'


def test_removed_argument_on_its_own_line_takes_its_comment_along():
    src = "import yaml\ndata = yaml.load(\n    s,\n    Loader=yaml.Loader,  # trusted file\n)\nprint(data)\n"
    assert _after("DES002", 2, "a.py", src) == "import yaml\ndata = yaml.safe_load(\n    s,\n)\nprint(data)\n"
    src = "import subprocess\nsubprocess.run(\n    'ls -l',  # list\n    shell=True,  # yes\n)\n"
    assert _after("EXE004", 2, "a.py", src) == 'import subprocess\nsubprocess.run(\n    ["ls", "-l"],  # list\n)\n'
    src = "import requests\nrequests.get(\n    u, verify=False  # lab\n)\n"            # shares a line: only the arg goes
    assert _after("CRY002", 2, "a.py", src) == "import requests\nrequests.get(\n    u  # lab\n)\n"
    src = "import yaml\r\nd = yaml.load(\r\n    s,\r\n    Loader=yaml.Loader,\r\n)\r\n"
    assert _after("DES002", 2, "a.py", src) == "import yaml\r\nd = yaml.safe_load(\r\n    s,\r\n)\r\n"


@pytest.mark.parametrize("name, rule, src", [
    ("a.js", "CRY002", "log('rejectUnauthorized: false');\n"),                       # data in a string
    ("a.js", "CRY002", "connect(); // rejectUnauthorized: false\n"),                    # a comment
    ("a.js", "vql/js-cookie-insecure", "res.cookie('pref', 'secure: false', {httpOnly: true});\n"),
    ("a.js", "EXE005", "const { exec } = require('child_process');\n// exec('ls -l ' + dir);\n"),
    ("a.js", "INJ004", "s = 'el.innerHTML = name';\n"),
    ("A.java", "CRY001", 'run(); // MessageDigest.getInstance("MD5")\n'),
    ("A.java", "RND001", "log(\"new Random()\");\n"),
    ("A.java", "COOK001", "c.setSecure(true); // was c.setSecure(false)\n"),
    ("A.java", "XXE001", 'f(); /* f.setFeature("http://xml.org/sax/features/external-general-entities", true); */\n'),
])
def test_token_fixers_leave_strings_and_comments_alone(name, rule, src):
    assert _after(rule, src.count("\n"), name, src) is None


def test_token_fixers_still_fix_code_next_to_strings_and_comments():
    assert _after("CRY002", 1, "a.js", "x({ rejectUnauthorized: false }); // 'q'\n") == \
        "x({ rejectUnauthorized: true }); // 'q'\n"
    src = 'String s = "x"; f.setFeature("http://xml.org/sax/features/external-general-entities", true);\n'
    assert _after("XXE001", 1, "A.java", src) == src.replace("true)", "false)")
    src = "/* const { exec } = require('child_process'); */\nconst { exec } = require('child_process');\nexec('ls ' + d);\n"
    assert _after("EXE005", 3, "a.js", src) == \
        "/* const { exec } = require('child_process'); */\nconst { exec, execFile } = require('child_process');\n" \
        'execFile("ls", [d]);\n'


def test_js_cookie_fix_stays_inside_the_cookie_call():
    src = "res.cookie('a', b, {httpOnly: true}); const cfg = { secure: false };\n"
    assert _after("vql/js-cookie-insecure", 1, "a.js", src) is None
    src = "res.cookie('a', b, {\n  secure: false,\n  httpOnly: false\n});\nconst o = { secure: false };\n"
    assert _after("vql/js-cookie-insecure", 1, "a.js", src) == \
        "res.cookie('a', b, {\n  secure: true,\n  httpOnly: true\n});\nconst o = { secure: false };\n"


def test_js_exec_with_a_shell_option_is_not_rewritten():
    head = "const { exec } = require('child_process');\n"
    assert _after("EXE005", 2, "a.js", head + "exec('ls -l ' + dir, {shell: '/bin/bash'}, cb);\n") is None
    assert _after("EXE005", 2, "a.js", head + "exec('ls -l ' + dir, {cwd: d}, cb);\n") == \
        "const { exec, execFile } = require('child_process');\n" + 'execFile("ls", ["-l", dir], {cwd: d}, cb);\n'


def test_java_random_of_another_package_or_anonymous_subclass_is_left_alone():
    assert _after("RND001", 2, "A.java", "import com.acme.Random;\nRandom r = new Random();\n") is None
    assert _after("RND001", 1, "A.java", "Random r = new Random() { protected int next(int b) { return 4; } };\n") is None
    assert _after("RND001", 2, "A.java", "import java.util.Random;\nRandom r = new Random();\n") == \
        "import java.util.Random;\nRandom r = new java.security.SecureRandom();\n"


def test_yaml_block_scalar_text_is_data_not_a_manifest():
    src = "kind: ConfigMap\ndata:\n  pod.yaml: |\n    spec:\n      containers:\n      - name: a\n"
    assert _after("K8S010", 5, "cm.yaml", src) is None
    src = "kind: ConfigMap\ndata:\n  x: |\n    allowPrivilegeEscalation: true\n"
    assert _after("K8S001", 4, "cm.yaml", src) is None
    src = "spec:\n  securityContext:\n    allowPrivilegeEscalation: true\n"
    assert _after("K8S001", 3, "p.yaml", src) == src.replace("true", "false")


def test_gha_expression_in_a_heredoc_is_not_moved():
    src = ("on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n"
           "          cat <<'EOF'\n          ${{ github.event.issue.title }}\n          EOF\n")
    assert _after("GHA002", 8, ".github/workflows/w.yml", src) is None


def test_dockerfile_for_a_windows_image_gets_no_numeric_user():
    src = "FROM mcr.microsoft.com/windows/nanoserver:ltsc2022\nCMD [\"app.exe\"]\n"
    assert _after("DKR000", 0, "Dockerfile", src) is None
    assert _after("DKR000", 0, "Dockerfile", "FROM alpine\nCMD [\"app\"]\n") == "FROM alpine\nUSER 10001\nCMD [\"app\"]\n"


def test_stale_line_is_unfixable_not_covered():
    text = "import yaml\nd = yaml.load(s)\n"
    new, status = fix_text(text, "a.py", [_f("DES002", 2, "a.py"), _f("DES002", 99, "a.py")])
    assert "safe_load" in new and status == {0: "fixed", 1: "none"}


def test_read_only_and_hard_linked_files_are_not_written(tmp_path):
    import os
    src = "import yaml\nd = yaml.load(s)\n"
    root, outside = tmp_path / "root", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "ro.py").write_text(src, encoding="utf-8", newline="")
    (root / "ro.py").chmod(0o444)                               # root could write it: the mode bits still decide
    (outside / "shared.py").write_text(src, encoding="utf-8", newline="")
    os.link(outside / "shared.py", root / "hard.py")            # a second name of a file outside the scan root
    (root / "ok.py").write_text(src, encoding="utf-8", newline="")
    rep = apply_fixes([_f("DES002", 2, n) for n in ("ro.py", "hard.py", "ok.py")], root)
    assert sorted(rep.errors) == ["hard.py", "ro.py"] and sorted(rep.files) == ["ok.py"]
    assert (outside / "shared.py").read_text(encoding="utf-8") == src
    assert (root / "ro.py").read_text(encoding="utf-8") == src
    assert "safe_load" in (root / "ok.py").read_text(encoding="utf-8")
    (root / "ro.py").chmod(0o644)


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_git_ignored_file_counts_as_dirty(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("gen/\n", encoding="utf-8", newline="")
    _git(tmp_path, "add", ".gitignore")
    _git(tmp_path, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-qm", "init")
    (tmp_path / "gen").mkdir()
    (tmp_path / "gen" / "x.py").write_text("x = 1\n", encoding="utf-8", newline="")
    assert autofix.git_dirty(tmp_path, ["gen/x.py"])           # no committed copy to go back to


def test_sarif_fix_shape_for_a_crlf_multi_line_edit(tmp_path):
    src = "import yaml\r\nd = yaml.load(\r\n    s,\r\n    Loader=yaml.Loader,\r\n)\r\n"
    (tmp_path / "a.py").write_bytes(src.encode())
    f = _f("DES002", 2, "a.py")
    attach_fixes([f], tmp_path)
    run = json.loads(render_sarif([f], str(tmp_path), 1, []))["runs"][0]
    fixes = run["results"][0]["fixes"]
    assert set(fixes[0]) <= {"description", "artifactChanges", "properties"} and fixes[0]["description"]["text"]
    (change,) = fixes[0]["artifactChanges"]
    assert change["artifactLocation"]["uriBaseId"] in run["originalUriBaseIds"]
    for r in change["replacements"]:
        reg = r["deletedRegion"]
        assert reg["startLine"] >= 1 and reg["endLine"] >= reg["startLine"] and reg["startColumn"] == 1
        assert "endColumn" not in reg and not r["insertedContent"]["text"].endswith(("\n", "\r"))
    # applying the SARIF replacements (whole lines, end of line excluded) gives the fix
    lines = src.split("\r\n")
    for r in sorted(change["replacements"], key=lambda r: -r["deletedRegion"]["startLine"]):
        reg = r["deletedRegion"]
        lines[reg["startLine"] - 1:reg["endLine"]] = r["insertedContent"]["text"].split("\r\n")
    assert "\r\n".join(lines) == apply_edits(src, f.extra["fix"]["edits"])
