"""JavaScript / TypeScript taint through the lowering frontend."""
from vulnscan.taint import analyze_project


def run(files):
    return analyze_project(files)


def by_line(findings, file=None):
    return {f.line: f.rule_id for f in findings if file is None or f.file == file}


def test_express_command_injection_template_literal():
    src = (
        "const { exec } = require('child_process');\n"
        "const express = require('express');\n"
        "const app = express();\n"
        "app.get('/run', (req, res) => {\n"
        "  const cmd = `ls ${req.query.dir}`;\n"
        "  exec(cmd);\n"
        "  exec('ls -la');\n"
        "});\n"
    )
    bl = by_line(run({"app.js": src}))
    assert bl.get(6) == "DF002" and 7 not in bl


def test_express_path_traversal_reflection_ssrf_redirect():
    src = (
        "import fs from 'fs';\n"
        "import axios from 'axios';\n"
        "export function handler(req, res) {\n"
        "  fs.readFile(req.params.file, 'utf8', (e, d) => res.send(d));\n"
        "  res.send('Hello ' + req.query.name);\n"
        "  axios.get(req.body.url);\n"
        "  res.redirect(req.query.next);\n"
        "  res.send('static');\n"
        "}\n"
    )
    bl = by_line(run({"routes.js": src}))
    assert bl.get(4) == "DF005" and bl.get(5) == "DF013" and bl.get(6) == "DF010" and bl.get(7) == "DF008"
    assert 8 not in bl


def test_barrier_guard_includes_and_sanitizer():
    src = (
        "const fs = require('fs');\n"
        "const ALLOWED = ['a.txt', 'b.txt'];\n"
        "module.exports = function (req, res) {\n"
        "  const p = req.query.p;\n"
        "  if (ALLOWED.includes(p)) { fs.readFile(p); }\n"
        "  fs.readFile(encodeURIComponent(p));\n"
        "  fs.readFile(p);\n"
        "};\n"
    )
    bl = by_line(run({"a.js": src}))
    assert 5 not in bl and 6 not in bl and bl.get(7) == "DF005"


def test_cross_file_require_and_class_field():
    files = {
        "lib/shell.js": "const cp = require('child_process');\nfunction run(c) { cp.execSync(c); }\nmodule.exports = { run };\n",
        "lib/task.js": ("class Task {\n  constructor(cmd) { this.cmd = cmd; }\n  go() { require('child_process').exec(this.cmd); }\n}\n"
                        "module.exports = Task;\n"),
        "server.js": ("const { run } = require('./lib/shell');\nconst Task = require('./lib/task');\n"
                      "app.post('/x', (req, res) => {\n  run(req.body.c);\n  new Task(req.body.c).go();\n  new Task('ls').go();\n});\n"),
    }
    f = run(files)
    bl = by_line(f, "server.js")
    assert bl.get(4) == "DF002", bl
    assert bl.get(5) == "DF002", bl
    assert 6 not in bl


def test_typescript_nestjs_controller_and_param_property():
    src = (
        "import { Controller, Get, Query } from '@nestjs/common';\n"
        "import { ShellService } from './shell.service';\n"
        "@Controller('x')\n"
        "export class XController {\n"
        "  constructor(private readonly shell: ShellService) {}\n"
        "  @Get()\n"
        "  find(@Query('q') q: string): string {\n"
        "    this.shell.run(q);\n"
        "    return q;\n"
        "  }\n"
        "}\n"
    )
    svc = (
        "import { execSync } from 'child_process';\n"
        "export class ShellService {\n"
        "  run(c: string) { execSync(`ls ${c}`); }\n"
        "}\n"
    )
    f = run({"x.controller.ts": src, "shell.service.ts": svc})
    bl = by_line(f, "x.controller.ts")
    assert bl.get(8) == "DF002", bl   # typed field -> other file's class method -> shell


def test_browser_dom_xss_and_open_redirect():
    src = (
        "const q = new URLSearchParams(location.search).get('q');\n"
        "document.getElementById('out').innerHTML = q;\n"
        "document.getElementById('out').textContent = q;\n"
        "location.href = location.hash.slice(1);\n"
    )
    bl = by_line(run({"page.js": src}))
    assert bl.get(2) == "DF013" and 3 not in bl and bl.get(4) == "DF008"


def test_tolerant_parsing_keeps_going():
    src = (
        "const x = @@@ broken syntax here ;\n"
        "const { exec } = require('child_process');\n"
        "app.get('/a', (req, res) => { exec(req.query.c); });\n"
    )
    assert by_line(run({"a.js": src})).get(3) == "DF002"


def test_mixed_project_python_and_js(tmp_path):
    from vulnscan.scanner import scan_path
    (tmp_path / "app.py").write_text("import os\ndef v(request):\n    os.system(request.args['c'])\n")
    (tmp_path / "app.js").write_text("const cp=require('child_process');\napp.get('/',(req,res)=>{cp.exec(req.query.c)});\n")
    findings, _ = scan_path(tmp_path)
    files = {f.file for f in findings if f.rule_id == "DF002"}
    assert files == {"app.py", "app.js"}
