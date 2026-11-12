"""Regressions from the real-world corpus sweep (django, flask, fastapi, celery, requests, jinja2, express, koa,
fastify, axios, next, juice-shop, dvna, nodegoat, pygoat, vulpy, dvpwa, WebGoat, DVWA, railsgoat, sinatra, rack,
gin, echo, ...).

Each case under tests/data/realworld/<case>/ is a small program reproducing one triaged problem: the vulnerable
line must stay reported and its safe twin must not be. Crash and hang reproducers must finish quickly.
"""

from __future__ import annotations

import pathlib
import random
import time

import pytest

from vulnscan.scanner import path_kind, is_vendored, scan_path

DATA = pathlib.Path(__file__).resolve().parent / "data" / "realworld"


def _scan(case: str, **kw) -> set:
    findings, _ = scan_path(DATA / case, jadx=False, notes=[], **kw)
    return {(f.rule_id, f.file, f.line) for f in findings}


# case -> (must be reported, must NOT be reported). Entries are (rule, file, line); line None = anywhere in file.
CASES = {
    # --- crashes / hangs
    "ruby_alias_hang": ({("DF002", "app.rb", 13)}, set()),
    "php_crash_ref_function": ({("DF002", "page.inc.php", 9), ("DF013", "page.inc.php", 8)}, set()),
    "go_receiver_files": ({("DF003", "handler.go", 12)}, {("DF003", "bench_test_helpers.go", None),
                                                          ("vql/entry-point-without-auth", "bench_test_helpers.go", None)}),
    # --- request / self sources
    "python_self_attr_source": (set(), {("DF002", "app.py", 10), ("DF001", "app.py", 19)}),
    "python_request_named_param": ({("DF010", "server_vuln.py", 9)}, {("DF010", "client.py", None)}),
    "python_pytest_fixture_request": (set(), {("DF012", "fixture_tutorial.py", None)}),
    "js_r20_request_param_name": (set(), {("DF005", "render.js", None), ("DF010", "render.js", None)}),
    "js_r22_event_message": (set(), {("DF016", "events.js", 4)}),
    "js_r17_env_source": ({("DF008", "app.js", 9)}, {("DF008", "app.js", 4), ("DF008", "app.js", 5)}),
    "js_r7_koa_ctx_body": ({("DF013", "app.js", 11)}, {("DF013", "app.js", 7)}),
    "js_r2_whole_req": ({("DF013", "app.js", 18)}, {("DF013", "app.js", 6), ("DF013", "app.js", 10), ("DF013", "app.js", 14)}),
    "js_m7_destructured_req": ({("DF008", "redirect.ts", 9), ("DF008", "redirect.ts", 15), ("DF008", "redirect.ts", 22)},
                               {("DF008", "redirect.ts", 18)}),
    "python_client_request_union": (set(), {("DF010", "requests/utils.py", None)}),
    # --- entry points
    "python_mock_patch_is_route": (set(), {("DF002", "backend_mock.py", 8),
                                           ("vql/entry-point-without-auth", "backend_mock.py", None)}),
    "js_r1_nonroute_get": (set(), {("DF002", "app.js", None), ("vql/entry-point-without-auth", "app.js", None)}),
    "js_r10_interceptor_return": (set(), {("DF013", "client.js", None), ("vql/entry-point-without-auth", "client.js", None)}),
    "js_r3_route_mw_auth": ({("vql/entry-point-without-auth", "app.js", 7)}, {("vql/entry-point-without-auth", "app.js", 5)}),
    # --- reflected returns / JSON responses
    "python_flask_json_return_xss": ({("DF013", "views.py", 19), ("DF013", "fastapi_app.py", 14)},
                                     {("DF013", "views.py", 9), ("DF013", "views.py", 14), ("DF013", "fastapi_app.py", 9)}),
    "python_celery_task_return_xss": (set(), {("DF013", "tasks.py", None), ("DF006", "tasks.py", 23)}),
    "js_r13_fastify_return_json": ({("DF013", "app.js", 7)}, {("DF013", "app.js", 3), ("DF013", "app.js", 4)}),
    "js_r19_json_responses": ({("DF013", "app.js", 11)}, {("DF013", "app.js", 3), ("DF013", "app.js", 7)}),
    # --- call resolution
    "python_staticmethod_samename": ({("DF004", "views.py", 11)}, set()),
    "python_module_collision": ({("DF004", "bad/app.py", 9)}, {("DF004", "good/app.py", None)}),
    # --- guards, sinks and sanitizers
    "python_guard_on_attr_sanitizes_object": ({("DF006", "app.py", 16)}, set()),
    "python_upload_yaml_imagemath": ({("DF006", "app.py", 14), ("DF001", "app.py", 29)}, {("DF006", "app.py", 22)}),
    "python_orm_exclude_path_sink": (set(), {("DF005", "views.py", None)}),
    "python_pickle_roundtrip": ({("DF006", "check.py", 13), ("DES001", "check.py", 13)},
                                {("DF006", "check.py", 8), ("DES001", "check.py", 8)}),
    "python_stored_row_overtaint": ({("DF025", "auth.py", 28)}, {("DF025", "auth.py", 21)}),
    "python_cli_args_as_remote_source": (set(), {("DF010", "brute.py", 14), ("DF016", "brute.py", 15)}),
    # --- regex / structural rules
    "python_vql_sql_param_fp": ({("vql/sql-built-with-format", "dao.py", 21)},
                                {("vql/sql-built-with-format", "dao.py", 6), ("vql/sql-built-with-format", "dao.py", 11),
                                 ("vql/sql-built-with-format", "dao.py", 16)}),
    "python_regex_rule_import_comment": (set(), {("INJ009", "app.py", None)}),
    "python_html_prose_js_rule": (set(), {("EXE002", "lab.html", None)}),
    "python_rule_misfires": ({("CRY002", "client.py", 6)},
                             {("CFG007", "client.py", 6), ("COOK001", "client.py", 12), ("CRY006", "client.py", 16),
                              ("CFG005", "client.py", 20)}),
    # --- 1.0 self-scan precision: prose about a construct is not the construct
    "python_rules_in_prose": ({("CRY002", "app.py", 26), ("CRY002", "app.py", 30), ("EXE004", "app.py", 34),
                               ("EXE004", "app.py", 35), ("CFG004", "app.py", 48), ("CRY001", "app.py", 49)},
                              {("CRY002", "app.py", 8), ("CRY002", "app.py", 11), ("EXE004", "app.py", 22),
                               ("SEC004", "app.py", 14), ("SEC004", "app.py", 15), ("SEC011", "app.py", 17),
                               ("SEC011", "app.py", 18), ("CRY001", "app.py", 39), ("CFG004", "app.py", 43)}),
    # CI006: `-p` inside a word (`someone-prog/toolkit`) is not a password option; `mysql -pSECRET` is
    "shell_option_in_word": ({("CI006", "install.sh", 4)}, {("CI006", "install.sh", 2), ("CI006", "install.sh", 3)}),
    # `json.load(resp)` after `import json` is the library function, not the project's own `store.load`
    "python_external_module_samename": ({("DF005", "pkg/fetch.py", 14)}, {("DF005", "pkg/fetch.py", 9)}),
    # `pages[name] ? name : 'home'` / `name in pages` / hasOwnProperty: the key can only name an entry of the table
    "js_dispatch_key_guard": ({("DF026", "vuln.js", 9), ("DF026", "vuln.js", 11)},
                              {("DF026", "safe.js", 8), ("DF026", "safe.js", 10), ("DF026", "safe.js", 12),
                               ("DF026", "safe.js", 14)}),
    # ...but membership in a table the client fills (`k in req.query ? k : d`) validates nothing
    "key_guard_client_table": ({("DF013", "app.py", 11), ("DF026", "app.js", 10), ("DF026", "app.js", 12),
                                ("DF026", "app.js", 15)},
                               {("DF013", "app.py", 18), ("DF026", "app.js", 14)}),
    # SEC004: a quoted label table ("password": "Password") is not a credential; password="password" in config is
    "sec004_label_vs_credential": ({("SEC004", "Web.config", 3), ("SEC004", "settings.py", 4)},
                                   {("SEC004", "settings.py", 2), ("SEC004", "settings.py", 8)}),
    # Python `req` parameter: a request only in a module importing a web framework (celery setup.py requirement)
    "python_req_param_non_web": ({("DF005", "views.py", 8)}, {("DF005", "setup.py", None)}),
    # NET001: DTD ids, manifest metadata, reserved test domains, parse-only URLs and hyperlinks are not traffic
    "net001_identifiers": ({("NET001", "package.json", 5), ("NET001", "server.js", 7)},
                           {("NET001", "package.json", 3), ("NET001", "package.json", 4), ("NET001", "mapper.xml", 2),
                            ("NET001", "server.js", 3), ("NET001", "server.js", 4), ("NET001", "server.js", 5)}),
    # django set_language: `nt = translate(next_url)` after `if not url_has_allowed_host_and_scheme(next_url): next_url = "/"`
    # is derived from the validated URL; assigned before the check, or mixed with an unchecked value, it is not
    "python_guard_through_helper": ({("DF008", "views.py", 34), ("DF008", "views.py", 43)},
                                    {("DF008", "views.py", 13), ("DF008", "views.py", 16), ("DF008", "views.py", 26)}),
    # src layout without __init__.py: `import shop.core.helpers` is the project's own src/shop/core/helpers.py
    "python_namespace_pkg_import": ({("DF003", "src/shop/core/views.py", 12)}, set()),
    # --- Django internals: request.session / request.user are server state; a helper the project calls is no view
    "python_django_session_state": ({("DF012", "middleware.py", 15), ("DF012", "views.py", 15)},
                                    {("DF012", "middleware.py", 12), ("DF012", "middleware.py", 14),
                                     ("DF012", "views.py", 6), ("DF013", "views.py", 7), ("DF013", "views.py", 11)}),
    # `getattr(obj, "info")(msg, q)` calls what getattr returned: the outer call's arguments are not getattr's
    "python_call_of_call_result": ({("DF026", "app.py", 19)}, {("DF026", "app.py", 12)}),
    # --- comprehensions carry the taint of what they iterate (vulpy `[dict(zip(row.keys(), row)) for row in rows]`)
    "python_comprehension_taint": ({("DF002", "app.py", 11)}, {("DF002", "app.py", 18), ("DF002", "app.py", 26)}),
    # --- dvpwa: aiohttp `await request.post()` into string-built SQL; the parameterised twin is safe
    "python_aiohttp_post_sqli": ({("DF004", "app.py", 23)}, {("DF004", "app.py", 30)}),
    # --- templates
    # vulpy posts.view.html `{{ post.text | safe }}` over rows a user saved: stored XSS
    "python_stored_xss_template": ({("DF024", "app.py", 11)}, {("DF024", "app.py", 17), ("DF013", "app.py", 17)}),
    # dvpwa: aiohttp_jinja2.setup(autoescape=False) + `@template` handlers returning request data
    "python_aiohttp_autoescape_off": ({("DF013", "app.py", 10), ("INJ010", "app.py", 27)},
                                      {("DF013", "app.py", 16), ("DF013", "app.py", 22)}),
    # pygoat stored-SSTI lab: user text formatted into Jinja template source written to a template file
    "python_stored_ssti_file": ({("DF007", "app.py", 28)}, {("DF007", "app.py", 29)}),
    "python_template_unescaped": ({("DF013", "app.py", 10), ("INJ010", "app.py", 20)},
                                  {("DF013", "app.py", 16), ("INJ010", "app.py", 24)}),
    # --- validators
    "py_form_validators": ({("DF004", "views.py", 17), ("DF002", "api.py", 16), ("DF002", "api.py", 23), ("DF002", "wtf.py", 21)},
                           {("DF004", "views.py", 16), ("DF002", "api.py", 15), ("DF002", "api.py", 22), ("DF002", "wtf.py", 20)}),
    "java_typed_params": ({("DF004", "C.java", 11)},
                          {("DF004", "C.java", 9), ("DF004", "C.java", 10), ("DF004", "C.java", 16)}),
    "js_validators": ({("DF002", "app.js", 4), ("DF002", "app.js", 6)}, {("DF002", "app.js", 3), ("DF002", "app.js", 5)}),
    "kotlin_if_expression": ({("DF013", "OwnerController.kt", 13)}, {("DF013", "OwnerController.kt", 7)}),
    "java_implicit_this": ({("DF004", "S.java", 5)}, {("DF004", "T.java", None)}),
    "js_closure_capture": ({("DF002", "app.js", 5), ("DF002", "app.js", 9), ("DF002", "app.js", 18)}, {("DF002", "app.js", 15)}),
    "js_sequelize_where": ({("DF004", "app.js", 10)}, {("DF004", "app.js", 6)}),
    "go_sqli_stmt": ({("DF004", "main.go", 36)}, {("DF004", "main.go", 41)}),
    "go_bare_name_models": ({("DF010", "main.go", 42), ("DF007", "main.go", 43)},
                            {("DF010", "main.go", 20), ("DF010", "main.go", 25), ("DF007", "main.go", 25),
                             ("DF007", "main.go", 30), ("DF013", "main.go", 35)}),
    "csharp_using_block": ({("DF004", "C.cs", 11)}, set()),
    "csharp_catch_filter": ({("DF004", "C.cs", 24), ("DF002", "C.cs", 15)}, set()),
    "php_typed_params": ({("DF004", "UserRepo.php", 19), ("DF002", "UserRepo.php", 23)}, set()),
    "java_xxe": ({("DF027", "XmlController.java", 15), ("DF027", "XmlController.java", 33)},
                 {("DF027", "XmlController.java", 25)}),
    "js_nosql_where": ({("DF004", "app.js", 7)}, {("DF004", "app.js", 12)}),
    "js_console_log": ({("DF016", "app.js", 6)}, {("DF016", "app.js", 12)}),
    "js_dvna_patterns": ({("XXE002", "xml.js", 6), ("DF001", "calc.js", 6), ("EXE010", "calc.js", 6), ("CFG008", "server.js", 5)},
                         {("XXE002", "xml.js", 11), ("DF001", "calc.js", 10), ("EXE010", "calc.js", 10), ("CFG008", "server.js", 7)}),
    "go_statement_gaps": ({("DF003", "main.go", 25), ("DF013", "main.go", 26), ("DF004", "main.go", 32)}, set()),
    # --- unsafe reflection (CWE-470)
    "reflection": ({("DF026", "a.py", 8), ("DF026", "b.js", 3), ("DF026", "C.java", 5)},
                   {("DF026", "a.py", 11), ("DF026", "b.js", 4), ("DF026", "C.java", 6)}),
    # --- 1.0.1 recall: PHP include / exit, server-side view templates (EJS, Handlebars, Pug, Swig, ERB)
    # DVWA File Inclusion: the level's source file (picked by a switch) sets $file, the front controller includes it
    "php_include_lfi": ({("DF012", "fi/index.php", 13), ("DF012", "lang.php", 3)},
                        {("DF012", "safe/index.php", None), ("DF012", "lang.php", 5)}),
    # a view included by a controller prints the controller's variable; the view's own source is reported once
    "php_include_view_xss": ({("DF013", "ctrl.php", 4), ("DF013", "views/hello.php", 3)},
                             {("DF013", "ctrl_safe.php", None), ("DF013", "ctrl.php", 3), ("DF013", "views/hello.php", 1),
                              ("DF013", "views/hello.php", 2)}),
    # `exit;` / `die(...)` end the script: a failed whitelist check that exits guards what follows
    "php_exit_whitelist": ({("DF012", "unguarded.php", 6), ("DF013", "unguarded.php", 7)},
                           {("DF012", "guarded.php", None), ("DF013", "guarded.php", None)}),
    "js_view_templates": ({("DF013", "routes/app.js", 5), ("DF013", "routes/app.js", 12), ("DF013", "routes/app.js", 15),
                           ("DF013", "routes/app.js", 20), ("DF013", "routes/app.js", 24)},
                          {("DF013", "routes/app.js", 9), ("DF013", "routes/app.js", 18), ("DF013", "routes/app.js", 21)}),
    "js_swig_autoescape_off": ({("DF013", "server.js", 7)}, {("DF013", "server.js", 10)}),
    "js_swig_autoescape_on": (set(), {("DF013", "server.js", None)}),
    "ruby_erb_views": ({("DF013", "app/views/users/show.html.erb", 2), ("DF013", "app/views/users/show.html.erb", 3),
                        ("DF013", "app/views/users/show.html.erb", 4), ("DF013", "app/views/users/show.html.erb", 10),
                        ("DF013", "app/views/layouts/application.html.erb", 2)},
                       {("DF013", "app/views/users/show.html.erb", 1), ("DF013", "app/views/users/show.html.erb", 5),
                        ("DF007", "app/views/users/show.html.erb", None), ("DF013", "app/views/users/show.html.erb", 9),
                        ("DF013", "app/views/users/show.html.erb", 11),
                        ("DF013", "app/views/layouts/application.html.erb", 3)}),
}


def _hit(found: set, rule: str, file: str, line) -> bool:
    return any(r == rule and f == file and (line is None or ln == line) for r, f, ln in found)


@pytest.mark.parametrize("case", sorted(CASES))
def test_realworld_case(case):
    must, must_not = CASES[case]
    t0 = time.monotonic()
    found = _scan(case)
    assert time.monotonic() - t0 < 60, f"{case}: scan too slow"
    missing = sorted(e for e in must if not _hit(found, *e))
    extra = sorted(e for e in must_not if _hit(found, *e))
    assert not missing, f"{case}: not reported {missing}; got {sorted(found)}"
    assert not extra, f"{case}: reported but must not be {extra}"


def test_every_case_directory_is_asserted():
    dirs = {p.name for p in DATA.iterdir() if p.is_dir()}
    assert dirs == set(CASES), sorted(dirs ^ set(CASES))


# ------------------------------------------------------------------ crashes and hangs (generated inputs)
def test_ruby_indented_alias_does_not_hang(tmp_path):
    body = "class A\n" + "".join(f"  def m{i}(x)\n    x\n  end\n  alias_method :n{i}, :m{i}\n  alias o{i} m{i}\n  undef p{i}\n"
                                 for i in range(50)) + "end\n"
    (tmp_path / "a.rb").write_text(body)
    t0 = time.monotonic()
    scan_path(tmp_path, jadx=False, notes=[])
    assert time.monotonic() - t0 < 30


def test_wide_class_hierarchy_scans_in_bounded_time(tmp_path):
    # one base with many subclasses calling each other through self (django Field / sqlalchemy ClauseElement)
    n, m = 200, 10
    lines = ["class Base:"]
    for k in range(m):
        lines += [f"    def m{k}(self, x):", f"        return self.m{(k + 1) % m}(x)", ""]
    for i in range(n):
        lines.append(f"class C{i}(Base if {i} % 2 == 0 else C{max(i - 1, 0)}):")
        for k in range(m):
            lines += [f"    def m{k}(self, x):", f"        return self.m{(k + 3) % m}(x) + self.m{(k + 5) % m}(x)", ""]
    (tmp_path / "app.py").write_text("\n".join(lines))
    t0 = time.monotonic()
    scan_path(tmp_path, jadx=False, notes=[])
    assert time.monotonic() - t0 < 60


def test_dataflow_budget_degrades_with_a_note(tmp_path):
    from vulnscan import taint
    (tmp_path / "app.py").write_text("import os\nfrom flask import request\n\ndef f():\n    os.system(request.args['c'])\n")
    old = taint.DATAFLOW_BUDGET_SECONDS
    taint.DATAFLOW_BUDGET_SECONDS = -1.0        # already over: Windows clocks tick in ~15 ms steps, so 0.0 may not be
    try:
        notes: list = []
        findings, _ = scan_path(tmp_path, jadx=False, notes=notes)
    finally:
        taint.DATAFLOW_BUDGET_SECONDS = old
    assert any("EXE004" == f.rule_id for f in findings)          # rule findings always kept
    assert any("time budget" in __import__("vulnscan.i18n", fromlist=["to_en"]).to_en(n) for n in notes)


def _chain_program(hops: int) -> str:
    out = ["import subprocess", "from flask import Flask", "app = Flask(__name__)", "",
           "@app.route('/x')", "def index():", "    f0()", ""]
    for i in range(hops):
        out += [f"def f{i}():", f"    f{i + 1}()", ""]
    out += [f"def f{hops}():", "    subprocess.run(['ls'])", ""]
    return "\n".join(out)


def test_vql_audit_query_skipped_by_default_and_long_chains_found_with_audit(tmp_path):
    (tmp_path / "app.py").write_text(_chain_program(90))       # longer than the old 64-round cap
    default, _ = scan_path(tmp_path, jadx=False, notes=[])
    assert not any(f.rule_id == "vql/entry-reaches-shell" for f in default)
    audit, _ = scan_path(tmp_path, jadx=False, notes=[], audit=True)
    assert any(f.rule_id == "vql/entry-reaches-shell" for f in audit)


# ------------------------------------------------------------------ test / docs / vendored paths
def test_path_classification():
    assert path_kind("tests/test_a.py") == "test" and path_kind("t/unit/x.py") == "test"
    assert path_kind("src/a.spec.ts") == "test" and path_kind("pkg/a_test.go") == "test"
    assert path_kind("docs_src/a.py") == "docs" and path_kind("examples/app.js") == "example"
    assert path_kind("src/app.py") is None
    assert path_kind("testcode/BenchmarkTest00001.py") is None
    assert is_vendored("packages/next/src/compiled/react-dom/cjs/react-dom.production.js")
    assert is_vendored("app/static/js/materialize.js")
    assert not is_vendored("app/static/js/app.js") and not is_vendored("src/server.js")


def test_test_code_is_demoted_and_fixture_noise_dropped(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text(
        "import os\nfrom flask import request\n\ndef test_x(user):\n    assert user.is_admin\n"
        "    URL = 'http://ci.internal/x'\n    os.system(request.args['c'])\n")
    (tmp_path / "app.py").write_text("import os\nfrom flask import request\n\ndef f():\n    os.system(request.args['c'])\n")
    findings, _ = scan_path(tmp_path, jadx=False, notes=[])
    in_tests = [f for f in findings if f.file.startswith("tests/")]
    assert not any(f.rule_id in ("CFG005", "NET001") for f in in_tests)
    assert in_tests and all(f.severity == "info" and f.extra.get("test") for f in in_tests)
    assert any(f.file == "app.py" and f.rule_id == "DF002" and f.severity != "info" for f in findings)
    everything, _ = scan_path(tmp_path, jadx=False, notes=[], include_tests=True)
    assert any(f.file.startswith("tests/") and f.rule_id == "CFG005" for f in everything)


def test_vendored_library_is_skipped(tmp_path):
    js = tmp_path / "static" / "js"
    js.mkdir(parents=True)
    (js / "materialize.js").write_text("/*! Materialize v1.0.0 | MIT License */\nfunction t(req){ document.body.innerHTML = req.hash; }\n")
    (js / "app.js").write_text("function t(req){ document.body.innerHTML = location.hash; }\n")
    notes: list = []
    findings, _ = scan_path(tmp_path, jadx=False, notes=notes)
    assert not any(f.file.endswith("materialize.js") for f in findings)
    assert any(f.file.endswith("app.js") for f in findings)


def test_private_key_body_is_one_finding_not_one_per_line(tmp_path):
    rnd = random.Random(7)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    body = "\n".join("".join(rnd.choice(alphabet) for _ in range(64)) for _ in range(20))
    (tmp_path / "server.key").write_text("-----BEGIN " + "PRIVATE KEY-----\n" + body + "\n-----END " + "PRIVATE KEY-----\n")
    findings, _ = scan_path(tmp_path, jadx=False, notes=[], include_tests=True)
    assert not any(f.rule_id == "SEC011" for f in findings)
    assert any(f.rule_id == "SEC001" for f in findings)


def test_regex_literal_is_not_a_secret_but_a_key_still_is(tmp_path):
    rnd = random.Random(11)
    key = "".join(rnd.choice("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789") for _ in range(32))
    (tmp_path / "conf.py").write_text(
        "import re\n"
        "_TOKEN_RE = re.compile(r\"[A-Za-z0-9+/=_\\-]{20,}\")\n"
        "_ACCOUNT_KEY = re.compile(r\"(?i)AccountKey=([A-Za-z0-9+/]{20,}={0,2})\")\n"
        f"API_TOKEN = \"{key}\"\n")
    findings, _ = scan_path(tmp_path, jadx=False, notes=[])
    assert {(f.rule_id, f.line) for f in findings if f.rule_id in ("SEC011", "SEC004")} == {("SEC011", 4)}


def test_python_comment_and_string_masking_keeps_real_calls(tmp_path):
    # the call before a comment that repeats it, and a line with prose AND the real call, stay reported
    (tmp_path / "a.py").write_text("import os\nos.system(cmd)  # os.system\nx = 'os.system(' ; os.system(y)\n")
    findings, _ = scan_path(tmp_path, jadx=False, notes=[])
    assert {f.line for f in findings if f.rule_id == "EXE004"} == {2, 3}
