"""A scan of a large foreign tree (a user scanned C:\\Windows from the UI) ended with status "error" and the message
`'list' object has no attribute 'endswith'`.

Root cause: the JavaScript tokenizer stores a template literal's parts as a list in the token's value. When the
tokenizer desyncs (a regex literal right after `)` is read as a division, so a backtick inside it opens a template
literal and the following code is read inside out) a template token lands where the parser expects a name
(`x.<template>`, an object or destructuring key, an import specifier, a class member). The list became an
identifier in the tree, and the data-flow engine later called str methods on it (stored.model_names:
`canon.endswith(...)`), which aborted the whole project analysis and with it the scan.

Containment: an unexpected error on one file or one manifest is recorded in the scan notes and the scan goes on.
"""

import ast
import pathlib
import tempfile

import pytest

from vulnscan import js_frontend, sca, scanner, server, taint
from vulnscan.i18n import to_en
from vulnscan.scanner import scan_path
from vulnscan.store import Store

# valid JavaScript (node --check accepts it): a regex statement after `if (...)`, then two template literals
DESYNC_JS = "if (window.ok) /`/.test(s);\nvar msg = `\nv = [0].`, tail = ``;\n"

FLASK_APP = ('import os\nfrom flask import Flask, request\napp = Flask(__name__)\n\n@app.route("/run")\ndef run():\n'
             '    os.system(request.args["cmd"])\n    return "ok"\n')
EXPRESS_APP = ("const express = require('express');\nconst cp = require('child_process');\nconst app = express();\n"
               "app.get('/x', (req, res) => { cp.exec(req.query.cmd); res.send('ok'); });\n")


def _project(root: pathlib.Path, files: dict) -> pathlib.Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _flows(findings, file):
    return [f for f in findings if f.file == file and f.source == "taint"]


# ------------------------------------------------------------------------------------------------- root cause
def test_desync_tokenization_puts_template_tokens_in_name_positions():
    toks = [(t.kind, t.val) for t in js_frontend.tokenize(DESYNC_JS)]
    i = toks.index(("punct", "]"))
    assert toks[i + 1] == ("punct", ".") and toks[i + 2][0] == "tpl" and isinstance(toks[i + 2][1], list)


@pytest.mark.parametrize("src", [
    DESYNC_JS,
    "var x = a[0].`t``u`;\n",                       # member name, then a tagged template call
    "var x = 'a'.`t``u`;\n",
    "var y = foo().`t`;\ny.z(1);\n",
    "const { `a`: b } = require('x');\nb(req.query.q);\n",
    "const { `a` } = require('child_process');\na(req.query.q);\n",
    "const { ...`r` } = obj;\n",
    "import { `a` as b } from 'x';\nb(req.query.q);\n",
    "import { a as `b` } from 'x';\n",
    "import * as `ns` from 'x';\n",
    "import a from `x`;\n",
    "class A { `m`() { return 1 } }\n",
    "var o = { `k`: 1, `m`() {} };\n",
])
def test_template_token_never_becomes_a_name(src):
    tree = js_frontend.parse_js(src, "x.js")
    assert taint._malformed(tree) is None
    taint.analyze_project_full({"x.js": src}, None, {})          # used to raise TypeError / AttributeError


def test_ui_scan_of_desync_file_finishes(tmp_path):
    """The reported crash, through the entry point the UI uses (server.run_scan)."""
    root = _project(tmp_path / "Windows", {"SystemApps/Shell Host/js/ui.js": DESYNC_JS, "app.py": FLASK_APP})
    store = Store(tmp_path / "home")
    store.save_settings({"use_osv": False, "use_external": False})
    scan = store.new_scan(str(root), "path")
    server.run_scan(store, scan, store.settings(), False)
    assert scan["status"] == "done", scan.get("error")
    assert scan["files_scanned"] == 2
    assert any(f["file"] == "app.py" and f["rule_id"] == "DF002" for f in scan["findings"])


# ------------------------------------------------------------------------------------------------ containment
def test_malformed_frontend_tree_skips_only_that_file(tmp_path, monkeypatch):
    root = _project(tmp_path, {"bad.js": "var a = 1;\n", "server.js": EXPRESS_APP, "app.py": FLASK_APP})
    real = js_frontend.parse_js

    def parse(text, rel="file.js"):
        tree = real(text, rel)
        if rel.endswith("bad.js"):                       # what a frontend bug produces: a list as an identifier
            tree.body.append(ast.Expr(value=ast.Name(id=[("str", "x")], ctx=ast.Load()), lineno=1, col_offset=0))
        return tree
    monkeypatch.setattr(js_frontend, "parse_js", parse)
    notes: list = []
    findings, files = scan_path(root, notes=notes)
    assert files == 3
    assert _flows(findings, "server.js") and _flows(findings, "app.py")       # the rest of the project is analysed
    note = next(n for n in notes if "bad.js" in n)
    assert "files skipped after an analysis error" in note and "Name.id is a list" in note
    assert "bad.js" in to_en(note) and to_en(note) != note


def test_language_failure_keeps_other_languages(tmp_path, monkeypatch):
    root = _project(tmp_path, {"server.js": EXPRESS_APP, "app.py": FLASK_APP})
    real = taint._stored_build

    def build(models, entries, *a, **k):
        if any(e.rel.endswith(".js") for e in entries):
            raise AttributeError("'list' object has no attribute 'endswith'")
        return real(models, entries, *a, **k)
    monkeypatch.setattr(taint, "_stored_build", build)
    notes: list = []
    findings, _ = scan_path(root, notes=notes)
    assert _flows(findings, "app.py") and not _flows(findings, "server.js")
    note = next(n for n in notes if "javascript dataflow analysis failed" in n)
    assert to_en(note) == ("Dataflow analysis of the javascript files failed (AttributeError); "
                           "showing pattern-rule results for them only.")


def test_whole_dataflow_failure_keeps_pattern_findings(tmp_path, monkeypatch):
    root = _project(tmp_path, {"app.py": FLASK_APP})

    def boom(*a, **k):
        raise KeyError("engine bug")
    monkeypatch.setattr(taint, "analyze_project_full", boom)
    notes: list = []
    findings, _ = scan_path(root, notes=notes)
    assert any(f.rule_id == "EXE004" for f in findings)
    assert any("dataflow analysis failed" in n for n in notes)


@pytest.mark.parametrize("jobs", [1, 2])
def test_per_file_stage_error_skips_only_that_file(tmp_path, monkeypatch, jobs):
    files = {"broken.py": FLASK_APP, "app.py": FLASK_APP}
    files.update({f"pad/f{i}.txt": "x\n" for i in range(4)})
    root = _project(tmp_path, files)
    real = scanner._scan_bytes

    def scan_bytes(path, rel, *a, **k):
        if rel == "broken.py":
            raise AttributeError("'list' object has no attribute 'endswith'")
        return real(path, rel, *a, **k)
    monkeypatch.setattr(scanner, "_scan_bytes", scan_bytes)
    if jobs > 1:                          # the worker-process path: an error there is redone and contained here
        monkeypatch.setattr(scanner, "PARALLEL_MIN_FILES", 2)
        monkeypatch.setenv("KASHIF_MP_START", "fork")
    notes: list = []
    findings, count = scan_path(root, notes=notes, jobs=jobs)
    assert count == len(files)
    assert any(f.file == "app.py" and f.rule_id == "DF002" for f in findings)
    assert not any(f.file == "broken.py" for f in findings)
    note = next(n for n in notes if "broken.py" in n)
    assert "AttributeError" in note and to_en(note).startswith("1 file(s) could not be analysed and were skipped: broken.py")


def test_skipped_files_are_not_cached(tmp_path, monkeypatch):
    root = _project(tmp_path, {"broken.py": FLASK_APP, "app.py": FLASK_APP})
    cache = tmp_path / "cache"
    real = scanner._scan_bytes

    def scan_bytes(path, rel, *a, **k):
        if rel == "broken.py":
            raise ValueError("odd")
        return real(path, rel, *a, **k)
    monkeypatch.setattr(scanner, "_scan_bytes", scan_bytes)
    scan_path(root, notes=[], cache_dir=cache)
    monkeypatch.setattr(scanner, "_scan_bytes", real)
    findings, _ = scan_path(root, notes=[], cache_dir=cache)      # the file is analysed once the error is gone
    assert any(f.file == "broken.py" and f.rule_id == "DF002" for f in findings)


# ----------------------------------------------------------------------------------- manifests with list values
WINDOWS_LIKE = {
    "SystemApps/app/package.json": '{"name": ["a"], "version": ["1"], "main": ["a.js", "b.js"], "bin": ["x"], '
                                   '"license": ["MIT"], "files": [["x"]], "exports": ["./a.js"], "scripts": ["build"], '
                                   '"dependencies": {"lodash": ["4.17.4"]}, "eslintConfig": {"extends": ["a", "b"]}}',
    "SystemApps/app/tsconfig.json": '{"extends": ["./base.json", "./strict.json"], "compilerOptions": {"baseUrl": ["."]}}',
    "SystemApps/app/.eslintrc.json": '{"extends": ["eslint:recommended"], "plugins": [["x"]]}',
    "SystemApps/app/composer.json": '{"name": ["a/b"], "require": {"a/b": ["1.0"]}}',
    "SystemApps/app/package-lock.json": '{"lockfileVersion": 3, "packages": {"": {"name": ["x"]}, '
                                        '"node_modules/lodash": {"version": ["4.17.4"], "dev": ["x"]}}}',
    "SystemApps/arr/package.json": "[1, 2]",
    "SystemApps/arr/tsconfig.json": '["x"]',
    "Microsoft.NET/app.csproj": '<Project><ItemGroup><PackageReference Include="A" Version="1.0"/></ItemGroup></Project>',
    "SystemApps/app/ui.js": DESYNC_JS,
    "app.py": FLASK_APP,
}


def test_manifests_with_list_fields_do_not_break_the_scan(tmp_path):
    root = _project(tmp_path, WINDOWS_LIKE)
    (root / "System32/u16.json").parent.mkdir(parents=True)
    (root / "System32/u16.json").write_bytes('{"a": ["b"]}'.encode("utf-16"))
    sca.collect(root)
    sca.ImportIndex(root)
    findings, count = scan_path(root, notes=[])
    assert count == len(WINDOWS_LIKE) + 1
    assert any(f.file == "app.py" and f.rule_id == "DF002" for f in findings)


def test_a_failing_manifest_parser_is_skipped(tmp_path, monkeypatch):
    root = _project(tmp_path, {"a/package.json": '{"dependencies": {"left-pad": "1.0.0"}}',
                               "b/requirements.txt": "flask==0.12\n"})
    real = sca._parser_for

    def parser_for(name, parent):
        hit = real(name, parent)
        if hit and name == "package.json":
            def bad(*a):
                raise ZeroDivisionError("parser bug")
            return (bad,) + tuple(hit[1:])
        return hit
    monkeypatch.setattr(sca, "_parser_for", parser_for)
    assert [(p.ecosystem, p.name) for p in sca.collect(root)] == [("PyPI", "flask")]
