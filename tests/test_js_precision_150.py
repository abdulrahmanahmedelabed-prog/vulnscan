"""JavaScript / TypeScript precision and recall rules of 1.5.0 (measured on GitHub's CodeQL JavaScript security tests,
bench/score_js.py). Every rule that marks code safe has a vulnerable near-miss twin that stays reported."""
from vulnscan.taint import analyze_project


def hits(src: str, name: str = "app.js") -> dict:
    """line -> set of (rule, CWE) reported in that file."""
    out: dict = {}
    for f in analyze_project({name: src}):
        if f.file == name:
            out.setdefault(f.line, set()).add((f.rule_id, f.cwe))
    return out


def cwes(h: dict, line: int) -> set:
    return {c for _r, c in h.get(line, set())}


EXPRESS = "const express = require('express');\nconst app = express();\n"


# ---------------------------------------------------------------- fs-compatible modules, promisified functions
def test_fs_compatible_modules_are_fs():
    src = ("const fse = require('fs-extra');\nconst gfs = require('graceful-fs');\n"
           "const fsp = require('fs/promises');\n" + EXPRESS +
           "app.post('/f', (req, res) => {\n"
           "  fse.rmSync(req.body.p);\n"            # 7
           "  gfs.readFileSync(req.body.p);\n"      # 8
           "  fsp.readFile(req.body.p);\n"          # 9
           "  fse.rmSync('/tmp/cache');\n"          # 10
           "});\n")
    h = hits(src)
    assert "CWE-22" in cwes(h, 7) and "CWE-22" in cwes(h, 8) and "CWE-22" in cwes(h, 9)
    assert 10 not in h


def test_promisified_functions_keep_their_sink():
    src = ("const cp = require('child_process');\nconst util = require('util');\n"
           "const pify = require('pify');\nconst Promise = require('bluebird');\n" + EXPRESS +
           "app.post('/run', async (req, res) => {\n"
           "  util.promisify(cp.exec)(req.body.cmd);\n"     # 8
           "  const run = util.promisify(cp.exec);\n"
           "  run(req.body.cmd);\n"                         # 10
           "  run('ls -la');\n"                             # 11: constant command
           "  const cpa = Promise.promisifyAll(cp);\n"
           "  cpa.execAsync(req.body.cmd);\n"               # 13
           "  pify(cp).exec(req.body.cmd);\n"               # 14
           "});\n")
    h = hits(src)
    for line in (8, 10, 13, 14):
        assert "CWE-78" in cwes(h, line), line
    assert 11 not in h


def test_async_suffix_needs_an_imported_module():
    # `queue.findAsync(x)` on a value that is no imported module is not `find`
    src = (EXPRESS + "app.post('/q', (req, res) => {\n"
           "  queue.findAsync(req.body.q);\n"               # 4
           "});\n")
    assert 4 not in hits(src)


# ---------------------------------------------------------------- spawn / execFile through a shell
def test_spawn_with_shell_option_is_a_shell_command():
    src = ("const cp = require('child_process');\n" + EXPRESS +
           "app.post('/s', (req, res) => {\n"
           "  const name = req.body.name;\n"
           "  cp.spawn('echo', ['hello', name], { shell: true });\n"      # 6
           "  cp.execFile('echo', [name], { shell: '/bin/sh' });\n"       # 7
           "  cp.spawn('sh', ['-c', name]);\n"                           # 8
           "  cp.spawn('echo', ['hello', name]);\n"                      # 9: argument array, no shell
           "  cp.spawn('echo', ['hello', name], { shell: false });\n"    # 10
           "});\n")
    h = hits(src)
    assert ("DF002", "CWE-78") in h.get(6, set()) and ("DF002", "CWE-78") in h.get(7, set())
    assert ("DF002", "CWE-78") in h.get(8, set())
    assert ("DF002", "CWE-78") not in h.get(9, set()) and ("DF002", "CWE-78") not in h.get(10, set())


# ---------------------------------------------------------------- NoSQL: objects filled field by field
def test_object_filled_by_field_assignment_carries_taint():
    src = ("const mongoose = require('mongoose');\n" + EXPRESS +
           "const User = mongoose.model('User', {name: String});\n"
           "app.post('/find', (req, res) => {\n"
           "  const query = {};\n"
           "  query.name = req.body.name;\n"
           "  User.find(query);\n"                    # 8
           "  const fixed = {};\n"
           "  fixed.name = 'admin';\n"
           "  User.find(fixed);\n"                    # 11
           "});\n")
    h = hits(src)
    assert {"CWE-89", "CWE-943"} & cwes(h, 8)
    assert 11 not in h


def test_mongoose_model_receiver():
    src = ("const mongoose = require('mongoose');\n" + EXPRESS +
           "const Doc = mongoose.model('Doc', {title: String});\n"
           "const Stats = makeStats();\n"
           "app.post('/c', (req, res) => {\n"
           "  Doc.count(req.body.filter);\n"          # 7
           "  Stats.count(req.body.filter);\n"        # 8: not a model
           "});\n")
    h = hits(src)
    assert "CWE-943" in cwes(h, 7)
    assert "CWE-943" not in cwes(h, 8)


# ---------------------------------------------------------------- redirects whose destination is fixed
def test_redirect_with_fixed_destination():
    src = (EXPRESS + "app.get('/r', (req, res) => {\n"
           "  res.redirect('/search?q=' + req.query.q);\n"                         # 4 safe
           "  res.redirect(['index.html?section=', req.query.s].join(''));\n"       # 5 safe
           "  res.redirect('/account/' + req.query.id);\n"                         # 6 safe
           "  res.redirect(`https://app.example/u/${req.query.id}`);\n"            # 7 safe
           "  res.redirect(req.query.next + '?from=login');\n"                     # 8
           "  res.redirect([req.query.page, '?s=', req.query.s].join(''));\n"      # 9
           "  res.redirect('/' + req.query.next);\n"                               # 10: '//evil.example'
           "  res.redirect('//' + req.query.host);\n"                              # 11
           "  res.redirect('https://' + req.query.host + '/x');\n"                 # 12
           "});\n")
    h = hits(src)
    for line in (4, 5, 6, 7):
        assert "CWE-601" not in cwes(h, line), line
    for line in (8, 9, 10, 11, 12):
        assert "CWE-601" in cwes(h, line), line


def test_location_assignment_with_fixed_path():
    src = ("function go() {\n"
           "  location.href = '/foo' + document.location.search.substring(1);\n"   # 2 safe
           "  location.href = document.location.search.substring(1);\n"           # 3
           "}\n")
    h = hits(src)
    assert "CWE-601" not in cwes(h, 2) and "CWE-601" in cwes(h, 3)


# ---------------------------------------------------------------- redirect allow-lists
def test_redirect_allow_lists():
    src = (EXPRESS + "const VALID_REDIRECT = 'https://docs.example/';\nconst SAFE_TARGETS = {'/a': 1};\n"
           "app.get('/r', (req, res) => {\n"
           "  const t = req.query.t;\n"
           "  if (VALID_REDIRECT === t) res.redirect(t);\n"                       # 7 safe
           "  if (other === t) res.redirect(t);\n"                                # 8: compared with a variable
           "  if (SAFE_TARGETS.hasOwnProperty(t)) res.redirect(t);\n"             # 9 safe
           "  else res.redirect(t);\n"                                            # 10
           "  if (t.startsWith('https://app.example/')) res.redirect(t);\n"       # 11 safe
           "  if (t.startsWith('https://app.example')) res.redirect(t);\n"        # 12: app.example.evil.test
           "  if (t.startsWith('/')) res.redirect(t);\n"                          # 13: //evil.test
           "});\n")
    h = hits(src)
    for line in (7, 9, 11):
        assert "CWE-601" not in cwes(h, line), line
    for line in (8, 10, 12, 13):
        assert "CWE-601" in cwes(h, line), line


# ---------------------------------------------------------------- Express sendFile / download
def test_express_sendfile_confinement():
    src = ("const path = require('path');\n" + EXPRESS +
           "app.get('/f', (req, res) => {\n"
           "  res.sendFile(req.query.f, { root: __dirname });\n"                   # 5 safe: root
           "  res.sendFile(__dirname + '/public/' + req.query.f);\n"              # 6 safe: '..' rejected
           "  res.download('/srv/files/' + req.query.f);\n"                       # 7 safe
           "  res.sendFile(req.query.f);\n"                                       # 8: any absolute path
           "  res.sendFile('/' + req.query.f);\n"                                 # 9: any absolute path
           "  res.sendFile(path.join(__dirname, req.query.f));\n"                 # 10: join removes '..'
           "  res.sendfile(__dirname + '/public/' + req.query.f);\n"              # 11: deprecated API
           "});\n")
    h = hits(src)
    for line in (5, 6, 7):
        assert "CWE-22" not in cwes(h, line), line
    for line in (8, 9, 10, 11):
        assert "CWE-22" in cwes(h, line), line


def test_extname_is_a_path_sanitizer():
    src = ("const fs = require('fs');\nconst path = require('path');\n" + EXPRESS +
           "app.get('/f', (req, res) => {\n"
           "  fs.readFileSync(path.extname(req.query.p));\n"          # 6 safe
           "  fs.readFileSync(path.dirname(req.query.p));\n"          # 7
           "});\n")
    h = hits(src)
    assert "CWE-22" not in cwes(h, 6) and "CWE-22" in cwes(h, 7)


# ---------------------------------------------------------------- Content-Type on the path to the response
def test_content_type_must_be_set_on_the_path_to_the_sink():
    src = (EXPRESS + "app.get('/u/:id', (req, res) => {\n"
           "  if (req.query.json) {\n"
           "    res.set('Content-Type', 'application/json');\n"
           "    res.send('{\"q\": \"' + req.query.q + '\"}');\n"     # 6 safe
           "  } else {\n"
           "    res.send('<p>' + req.query.q + '</p>');\n"          # 8: HTML
           "  }\n"
           "});\n"
           "app.get('/v', (req, res) => {\n"
           "  res.type('text/plain');\n"
           "  if (req.query.a) {\n"
           "    res.send('A ' + req.query.q);\n"                    # 14 safe: set before, on every path
           "  }\n"
           "});\n")
    h = hits(src)
    assert "CWE-79" not in cwes(h, 6) and "CWE-79" in cwes(h, 8)
    assert "CWE-79" not in cwes(h, 14)


# ---------------------------------------------------------------- review probes: near misses that stay reported
HEAD = ("const express = require('express'); const app = express(); const path = require('path'); "
        "const cp = require('child_process'); const fs = require('fs'); const db = require('./db');\n")


def _cwes_all(src: str) -> set:
    return {c for cs in hits(src).values() for _r, c in cs}


def test_hasownproperty_on_request_data_is_no_allow_list():
    k03 = HEAD + ("app.post('/a', (req, res) => { const col = req.query.col; "
                  "if (req.body.hasOwnProperty(col)) { db.query('SELECT ' + col + ' FROM t'); } res.end(); });\n")
    k06 = HEAD + ("app.post('/a', (req, res) => { const col = req.query.col; const allowed = req.body.allowed; "
                  "if (allowed.hasOwnProperty(col)) { db.query('SELECT ' + col + ' FROM t'); } res.end(); });\n")
    k07 = HEAD + ("app.post('/a', (req, res) => { const k = req.query.k; "
                  "if (Object.hasOwn(req.query, k)) { cp.exec('run ' + k); } res.end(); });\n")
    k05 = HEAD + ("const COLS = {name: 1, age: 1};\n"
                  "app.post('/a', (req, res) => { const col = req.query.col; "
                  "if (COLS.hasOwnProperty(col)) { db.query('SELECT ' + col + ' FROM t'); } res.end(); });\n")
    assert "CWE-89" in _cwes_all(k03) and "CWE-89" in _cwes_all(k06) and "CWE-78" in _cwes_all(k07)
    assert "CWE-89" not in _cwes_all(k05)                       # a constant table of the module


def test_comparison_with_request_data_is_no_allow_list():
    u01 = HEAD + "app.post('/a', (req, res) => { const t = req.query.u; if (req.body.URL === t) { res.redirect(t); } });\n"
    u02 = HEAD + ("app.post('/a', (req, res) => { const c = req.query.c; "
                  "if (req.body.CMD !== c) { return res.end(); } cp.exec(c); });\n")
    assert "CWE-601" in _cwes_all(u01) and "CWE-78" in _cwes_all(u02)


def test_sendfile_root_or_prefix_that_confines_nothing():
    j11 = HEAD + "app.get('/a', (req, res) => { res.sendFile(req.query.f, {root: req.query.r}); });\n"
    j12 = HEAD + "app.get('/a', (req, res) => { res.sendFile(req.query.f, {root: '/'}); });\n"
    k01 = HEAD + "const BASE = '/';\napp.get('/a', (req, res) => { res.sendFile(BASE + req.query.f); });\n"
    j14 = HEAD + "app.get('/a', (req, res) => { res.sendFile('/static' + req.query.f); });\n"
    for src in (j11, j12, k01, j14):
        assert "CWE-22" in _cwes_all(src), src


def test_later_function_declaration_wins():
    m12 = (HEAD + "function run(x) { cp.exec(x); }\nfunction run2(y) { run(y); }\n"
           "app.get('/a', (req, res) => { run2(req.query.c); });\nfunction run(x) { return 0; }\n")
    assert "CWE-78" not in _cwes_all(m12)
    m12v = (HEAD + "function run(x) { return 0; }\nfunction run2(y) { run(y); }\n"
            "app.get('/a', (req, res) => { run2(req.query.c); });\nfunction run(x) { cp.exec(x); }\n")
    assert "CWE-78" in _cwes_all(m12v)


def test_redirect_prefix_with_whitespace_after_slash():
    # browsers drop tabs and newlines from URLs: "/\t/" + host is "//host"
    j06 = HEAD + "app.get('/a', (req, res) => { res.redirect('/\\t/' + req.query.u); });\n"
    assert "CWE-601" in _cwes_all(j06)


def test_content_type_changed_or_chosen_later_or_not_content_type():
    m14 = HEAD + "app.get('/a', (req, res) => { res.type('json'); res.type(req.query.t); res.send(req.query.x); });\n"
    m15 = HEAD + ("app.get('/a', (req, res) => { res.type('json'); res.set('Content-Type', 'text/html'); "
                  "res.send(req.query.x); });\n")
    m16 = HEAD + "app.get('/a', (req, res) => { res.set('Accept', 'application/json'); res.send(req.query.x); });\n"
    safe = HEAD + "app.get('/a', (req, res) => { res.set('Content-Type', 'application/json'); res.send(req.query.x); });\n"
    for src in (m14, m15, m16):
        assert "CWE-79" in _cwes_all(src), src
    assert "CWE-79" not in _cwes_all(safe)
