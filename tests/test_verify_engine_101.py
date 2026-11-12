"""1.0.1 verification of the new engine coverage (JS view templates, PHP include, MyBatis `${}`): safe twins that
the first versions reported, next to the vulnerable line that must stay reported."""

from __future__ import annotations

import pathlib

from vulnscan.scanner import scan_path


def _write(root: pathlib.Path, files: dict) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _scan(root: pathlib.Path) -> set:
    findings, _ = scan_path(root, jadx=False, notes=[])
    return {(f.rule_id, f.file, f.line) for f in findings}


_EXPRESS = """const express = require('express');
const app = express();
app.set('view engine', 'ejs');
app.get('/a', (req, res) => { res.render('a', { name: req.query.name }); });
app.get('/b', (req, res) => { res.render('b', { name: req.query.name }); });
app.get('/c', (req, res) => { res.render('c', { name: req.query.name }); });
app.get('/d', (req, res) => { res.render('d', { name: req.query.name }); });
app.get('/e', (req, res) => { res.render('e', { name: req.query.name }); });
app.get('/f', (req, res) => { res.render('f', { name: req.query.name }); });
app.get('/g', (req, res) => { res.render('g', { name: req.query.name }); });
app.get('/h', (req, res) => { res.render('h', { name: req.query.name }); });
app.get('/i', (req, res) => { res.render('i', { name: req.query.name }); });
app.get('/j', (req, res) => { res.render('j', { name: req.query.name }); });
app.listen(3000);
"""


def test_js_view_raw_output_escaped_or_not_printed(tmp_path):
    _write(tmp_path, {
        "app.js": _EXPRESS,
        "views/a.ejs": "<p><%- escapeHtml(name) %></p>\n",                      # escaped by a helper
        "views/b.ejs": "<p><%- DOMPurify.sanitize(name) %></p>\n",               # sanitized
        "views/c.ejs": '<option <%- name ? "selected" : "" %>>x</option>\n',     # only the constants print
        "views/d.ejs": '<p><%- "hello name world" %></p>\n',                     # a string literal
        "views/e.ejs": "<p><%- name.length %></p>\n",                            # a number
        "views/f.hbs": "<p>{{{sanitize name}}}</p>\n",                           # a sanitizing helper
        "views/g.pug": "p!= escape(name)\n",
        "views/h.ejs": "<p><%- unescape(name) %></p>\n",                         # vulnerable: not an escaper
        "views/i.ejs": '<option <%- sel ? name : "" %>>x</option>\n',            # vulnerable: the branch prints it
        "views/j.ejs": "<p><%- name %></p>\n",                                   # vulnerable
    })
    got = {(r, f, ln) for r, f, ln in _scan(tmp_path) if r == "DF013"}
    for line in (11, 12, 13):
        assert ("DF013", "app.js", line) in got
    for line in range(4, 11):
        assert ("DF013", "app.js", line) not in got, line


def test_php_int_cast_is_a_number(tmp_path):
    # `(int) $_GET['id']` is the usual PHP defence; the frontend dropped the cast, so it read as the raw string
    _write(tmp_path, {
        "a.php": "<?php\n$id = (int) $_GET['id'];\ninclude 'views/item.php';\n",
        "views/item.php": "<?php\nmysqli_query($conn, \"SELECT * FROM t WHERE id = \" . $id);\n",
        "b.php": "<?php\n$id = (integer)$_GET['id'];\nmysqli_query($conn, \"SELECT * FROM t WHERE id = \" . $id);\n"
                 "$s = (string) $_GET['s'];\nmysqli_query($conn, \"SELECT * FROM t WHERE s = '\" . $s . \"'\");\n",
        # `(integer)` / `(real)` are casts too: the statement was dropped as unparsable, losing the other operand
        "c.php": "<?php\necho (integer)$_GET['a'] . $_GET['b'];\necho (integer)$_GET['a'];\n",
    })
    found = _scan(tmp_path)
    assert ("DF013", "c.php", 2) in found
    assert ("DF013", "c.php", 3) not in found
    got = {(r, f, ln) for r, f, ln in found if r == "DF004"}
    assert ("DF004", "b.php", 5) in got                       # a (string) cast is still the request's text
    assert ("DF004", "b.php", 3) not in got
    assert ("DF004", "a.php", 3) not in got


_MAPPER = """package org.x;

import org.apache.ibatis.annotations.*;
import java.util.List;

@Mapper
public interface UserMapper {
    List<String> withSchema(@Param("name") String name, @Param("age") int age);

    List<String> inList(@Param("ids") List<String> ids, @Param("n") int n);

    List<String> byName(@Param("name") String name, @Param("age") int age);
}
"""

_MAPPER_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<mapper namespace="org.x.UserMapper">
  <select id="withSchema" resultType="string">
    SELECT * FROM ${schema}.users WHERE name = #{name} AND age = #{age}
  </select>
  <select id="inList" resultType="string">
    SELECT * FROM users WHERE id IN <foreach collection="ids" item="i" separator=",">${i}</foreach> LIMIT #{n}
  </select>
  <select id="byName" resultType="string">
    SELECT * FROM users WHERE name = '${name}' AND age = #{age}
  </select>
</mapper>
"""

_CONTROLLER = """package org.x;

import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController
public class UserController {
    private final UserMapper mapper;

    public UserController(UserMapper mapper) { this.mapper = mapper; }

    @GetMapping("/a")
    public Object a(@RequestParam String name, @RequestParam int age) { return mapper.withSchema(name, age); }

    @GetMapping("/b")
    public Object b(@RequestParam List<String> ids) { return mapper.inList(ids, 3); }

    @GetMapping("/c")
    public Object c(@RequestParam String name) { return mapper.byName(name, 3); }
}
"""


def test_mybatis_config_property_is_not_a_parameter(tmp_path):
    # with several parameters MyBatis binds `${x}` only to a parameter name (or a <foreach> item / <bind>): any
    # other name is a configuration property (`${schema}`, `${prefix}`) substituted when the mapper loads
    _write(tmp_path, {
        "src/main/java/org/x/UserMapper.java": _MAPPER,
        "src/main/java/org/x/UserController.java": _CONTROLLER,
        "src/main/resources/mapper/UserMapper.xml": _MAPPER_XML,
    })
    got = {(r, f, ln) for r, f, ln in _scan(tmp_path) if r == "DF004"}
    ctrl = "src/main/java/org/x/UserController.java"
    assert ("DF004", ctrl, 13) not in got
    assert ("DF004", ctrl, 16) in got                          # the <foreach> item is the ids parameter
    assert ("DF004", ctrl, 19) in got


def test_django_view_routed_through_a_wrapper(tmp_path):
    # path("b/<slug>/", login_required(views.b)): b is a routed view, so slug comes from the URL
    view = ("def {n}(request, slug):\n    with connection.cursor() as c:\n"
            "        c.execute(\"SELECT * FROM t WHERE a = '%s'\" % slug)\n    return HttpResponse(\"ok\")\n\n\n")
    _write(tmp_path, {
        "shop/__init__.py": "",
        "shop/views.py": "from django.http import HttpResponse\nfrom django.db import connection\n\n\n"
                         + "".join(view.format(n=n) for n in "abcd"),
        "shop/urls.py": "from django.urls import path\nfrom django.contrib.auth.decorators import login_required\n"
                        "from django.views.decorators.cache import cache_page\nfrom . import views\n\n"
                        "urlpatterns = [\n    path(\"a/<slug>/\", views.a),\n    path(\"b/<slug>/\", login_required(views.b)),\n"
                        "    path(\"c/<slug>/\", cache_page(60)(views.c)),\n]\n",
    })
    got = {ln for r, f, ln in _scan(tmp_path) if r == "DF004" and f == "shop/views.py"}
    assert {7, 13, 19} <= got
    assert 25 not in got                 # d: not routed, a helper that takes a request


def test_php_include_splicing_has_a_project_budget(monkeypatch):
    # a big top-level header included by every page was copied into each of them: the analysis time grew with
    # pages x header size (300 pages: over 15 minutes). Spliced code is now capped per project.
    import ast

    from vulnscan import cfamily_frontend, php_include

    header = "<?php\n" + "".join(f"$v{i} = isset($_GET['k{i}']) ? $_GET['k{i}'] : 'd';\n" for i in range(40))
    texts = {"inc/header.php": header}
    texts.update({f"page{p}.php": f"<?php\ninclude 'inc/header.php';\necho $v{p};\n" for p in range(30)})
    files = {rel: cfamily_frontend.parse_cfamily(text, rel, "php") for rel, text in texts.items()}
    size = lambda: sum(1 for t in files.values() for _ in ast.walk(t))   # noqa: E731
    before = size()
    header_nodes = sum(1 for st in files["inc/header.php"].body for _ in ast.walk(st))
    cap = 3 * header_nodes + 10
    monkeypatch.setattr(php_include, "MIN_PROJECT_SPLICE", cap, raising=False)
    php_include.inline_includes(files)
    php_include.INLINED.clear()
    grown = size() - before
    assert header_nodes <= grown <= max(cap, before)          # some pages got the header, not all 30


def test_request_param_of_a_project_enum_is_bound_to_its_constants(tmp_path):
    # `ORDER BY ${sort}` with an enum parameter is the usual fix for MyBatis `${}`: Spring binds only the enum's
    # constants, as it binds only numbers to `Long id`
    _write(tmp_path, {
        "src/org/y/Sort.java": "package org.y;\n\npublic enum Sort { NAME, AGE }\n",
        "src/org/y/M.java": "package org.y;\n\nimport org.apache.ibatis.annotations.*;\nimport java.util.List;\n\n"
                            "@Mapper\npublic interface M {\n    @Select(\"SELECT * FROM t ORDER BY ${sort}\")\n"
                            "    List<String> bySort(@Param(\"sort\") Sort sort);\n\n"
                            "    @Select(\"SELECT * FROM t ORDER BY ${col}\")\n    List<String> byCol(@Param(\"col\") String col);\n}\n",
        "src/org/y/C.java": "package org.y;\n\nimport org.springframework.web.bind.annotation.*;\n\n@RestController\n"
                            "public class C {\n    private final M m;\n\n    public C(M m) { this.m = m; }\n\n"
                            "    @GetMapping(\"/a\")\n    public Object a(@RequestParam Sort sort) { return m.bySort(sort); }\n\n"
                            "    @GetMapping(\"/b\")\n    public Object b(@RequestParam String col) { return m.byCol(col); }\n}\n",
    })
    got = {ln for r, f, ln in _scan(tmp_path) if r == "DF004" and f == "src/org/y/C.java"}
    assert 12 not in got
    assert 15 in got
