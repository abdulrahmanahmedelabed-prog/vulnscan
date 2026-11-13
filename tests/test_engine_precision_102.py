"""1.0.2 engine precision / recall items from the 1.0.1 review. Every case is a small project: the vulnerable line
must be reported and its safe twin must not be.

1. Ruby: `URI.parse(x)` only parses a URL; the request is made by Net::HTTP / open-uri / HTTP clients (DF010).
2. Handlebars: `{{{this.x}}}` prints the items of the enclosing `{{#each}}` block only.
3. Swig / Nunjucks: `autoescape: false` counts only for the environment that renders the views.
4. MyBatis: mapper namespaces are the declared package + class (package-less and nested mappers), @SelectProvider.
5. ERB: a view sees the instance variables of the action that renders it.
"""

from __future__ import annotations

import ast
import pathlib

from vulnscan import cfamily_frontend as cf
from vulnscan.scanner import scan_path
from vulnscan.taint import _hbs_path_roots, _hbs_scope_at, _hbs_scopes, _js_noescape_exts, analyze


def _write(root: pathlib.Path, files: dict) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")


def _scan(root: pathlib.Path, rule: str) -> set:
    findings, _ = scan_path(root, jadx=False, notes=[])
    return {(f.file, f.line) for f in findings if f.rule_id == rule}


# ------------------------------------------------------------------------------------------- 1. Ruby URI.parse
_RUBY_SSRF = """class FetchController < ApplicationController
  def parse_only
    u = URI.parse(params[:u])
    @host = u.host
  end
  def referrer(env)
    ref = env['HTTP_REFERER']
    URI.parse(ref.to_s).host || Request.new(env).host
  end
  def net_http
    Net::HTTP.get(URI.parse(params[:u]))
  end
  def parse_then_read
    URI.parse(params[:u]).read
  end
  def kernel_uri_read
    URI(params[:u]).read
  end
  def uri_var_open
    target_uri = URI.parse(params[:u])
    target_uri.open
  end
  def http_client
    HTTP.get(params[:u])
  end
  def response
    uri = URI(params[:u])
    Net::HTTP.get_response(uri)
  end
end
"""


def test_ruby_uri_parse_is_not_an_outbound_request():
    got = {f.line for f in analyze("fetch_controller.rb", _RUBY_SSRF) if f.rule_id == "DF010"}
    assert 3 not in got                      # URI.parse alone: only parses
    assert 8 not in got                      # rack-protection's referrer: URI.parse(ref).host
    for line in (11, 14, 17, 21, 24, 28):    # Net::HTTP, open-uri read/open, HTTP clients
        assert line in got, (line, sorted(got))


# ------------------------------------------------------------------------------------------- 2. Handlebars each
def _hbs(text):
    import re
    scopes = _hbs_scopes(text)
    return {m.group(1): _hbs_path_roots(m.group(1), _hbs_scope_at(scopes, m.start()))
            for m in re.finditer(r"\{\{\{\s*([^}]*?)\s*\}\}\}", text)}


def test_handlebars_paths_resolve_in_the_enclosing_block():
    got = _hbs("{{#each posts}}{{{this.body}}}{{{../site}}}{{#each comments}}{{{this.text}}}{{/each}}"
               "{{else}}{{{this.empty}}}{{/each}}"
               "{{#each users as |u|}}{{{u.name}}}{{{@index}}}{{/each}}"
               "{{#with output}}{{{searchTerm}}}{{/with}}{{{this.top}}}{{{fmt (sanitize a) b}}}{{{@root.x}}}")
    assert got["this.body"] == [("posts", None)]
    assert got["../site"] == [("site", None)]
    assert got["this.text"] == [("posts", None)]        # comments of a post: still the posts' data
    assert got["this.empty"] == [("empty", None)]       # {{else}} of #each runs in the outer context
    assert got["u.name"] == [("users", None)]
    assert got["@index"] == []
    assert got["searchTerm"] == [("output", None)]
    assert got["this.top"] == [("top", None)]
    assert got["fmt (sanitize a) b"] == [("b", None)]   # a sanitizing sub-expression; `fmt` is the helper
    assert got["@root.x"] == [("x", None)]
    # a Mustache-style section iterates its list; it may also be a block helper without arguments: both readings
    assert _hbs("{{#posts}}{{{body}}}{{/posts}}")["body"] == [("posts", None), ("body", None)]


_HBS_APP = """const express = require('express');
const app = express();
app.set('view engine', 'hbs');
app.get('/posts', (req, res) => {
  res.render('posts', { posts: [{ body: req.query.body }], tags: ['a', 'b'] });
});
app.get('/tags', (req, res) => {
  res.render('tags', { posts: [{ body: 'fixed' }], tags: [req.query.tag] });
});
app.listen(3000);
"""


def test_handlebars_this_marks_only_the_enclosing_collection(tmp_path):
    _write(tmp_path, {
        "app.js": _HBS_APP,
        # both views iterate both collections; only `posts` items are printed raw
        "views/posts.hbs": "{{#each posts}}<p>{{{this.body}}}</p>{{/each}}\n{{#each tags}}<i>{{this}}</i>{{/each}}\n",
        "views/tags.hbs": "{{#each posts}}<p>{{{this.body}}}</p>{{/each}}\n{{#each tags}}<i>{{this}}</i>{{/each}}\n",
    })
    got = _scan(tmp_path, "DF013")
    assert ("app.js", 5) in got              # tainted posts, printed raw by {{{this.body}}}
    assert ("app.js", 8) not in got          # tainted tags, only printed escaped ({{this}})


# ------------------------------------------------------------------------------------------- 3. autoescape scope
def test_autoescape_off_counts_for_the_view_engine_only():
    assert _js_noescape_exts(["const swig = require('swig');\napp.engine('.html', require('consolidate').swig);\n"
                              "swig.setDefaults({ autoescape: false });"]) == {".html"}
    assert _js_noescape_exts(["const nunjucks = require('nunjucks');\n"
                              "nunjucks.configure('views', { autoescape: false, express: app });"]) == {"*"}
    assert _js_noescape_exts(["const nunjucks = require('nunjucks');\n"
                              "const env = nunjucks.configure('views', { autoescape: false });\nenv.express(app);"]) == {"*"}
    assert _js_noescape_exts(["const nunjucks = require('nunjucks');\nconst opts = { autoescape: false };\n"
                              "nunjucks.configure('views', opts);\napp.engine('njk', nunjucks.render);"]) == {".njk"}
    # a separate text environment (e-mails), the views keep escaping
    assert _js_noescape_exts(["const nunjucks = require('nunjucks');\n"
                              "const mail = new nunjucks.Environment(new nunjucks.FileSystemLoader('emails'), "
                              "{ autoescape: false });\nnunjucks.configure('views', { autoescape: true, express: app });"]) == set()
    # a Swig instance that is not the one registered as the view engine
    assert _js_noescape_exts(["const swig = require('swig');\nconst txt = new swig.Swig({ autoescape: false });\n"
                              "app.engine('html', swig.renderFile);"]) == set()
    assert _js_noescape_exts(["const swig = require('swig');\nconst s = new swig.Swig({ autoescape: false });\n"
                              "app.engine('html', s.renderFile);"]) == {".html"}
    # commented out
    assert _js_noescape_exts(["const nunjucks = require('nunjucks');\n"
                              "// nunjucks.configure('views', { autoescape: false, express: app });"]) == set()


_NJ_SERVER = """const express = require('express');
const nunjucks = require('nunjucks');
const app = express();
nunjucks.configure('views', { autoescape: true, express: app });
const mail = new nunjucks.Environment(new nunjucks.FileSystemLoader('emails'), { autoescape: false });
app.get('/hello', (req, res) => {
  res.render('hello.njk', { name: req.query.name });
});
app.listen(3000);
"""


def test_text_environment_does_not_unescape_html_views(tmp_path):
    _write(tmp_path, {"server.js": _NJ_SERVER, "views/hello.njk": "<p>Hello {{ name }}</p>\n",
                      "emails/welcome.txt": "Hello {{ name }}\n"})
    assert ("server.js", 7) not in _scan(tmp_path, "DF013")
    _write(tmp_path, {"server.js": _NJ_SERVER.replace("autoescape: true, express", "autoescape: false, express")})
    assert ("server.js", 7) in _scan(tmp_path, "DF013")


# ------------------------------------------------------------------------------------------- 4. MyBatis
_MB_CONTROLLER = """package org.x;

import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController
public class UserController {
    private final Mappers.NestedMapper nested;
    private final ProvMapper prov;
    private final PlainMapper plain;

    public UserController(Mappers.NestedMapper nested, ProvMapper prov, PlainMapper plain) { this.nested = nested; this.prov = prov; this.plain = plain; }

    @GetMapping("/a")
    public Object a(@RequestParam String name) { return nested.byName(name); }

    @GetMapping("/b")
    public Object b(@RequestParam String name) { return prov.concat(name); }

    @GetMapping("/c")
    public Object c(@RequestParam String name) { return prov.bound(name); }

    @GetMapping("/d")
    public Object d(@RequestParam String name) { return prov.builder(name); }

    @GetMapping("/e")
    public Object e(@RequestParam String name, @RequestParam String sort) { return prov.mapped(name, sort); }

    @GetMapping("/f")
    public Object f(@RequestParam String name) { return prov.defaultMethod(name); }

    @GetMapping("/g")
    public Object g(@RequestParam String name) { return plain.byName(name); }

    @GetMapping("/h")
    public Object h(@RequestParam String name) { return nested.safeName(name); }

    @GetMapping("/i")
    public Object i(@RequestParam String name) { return prov.builderSafe(name); }
}
"""

_MB_NESTED = """package org.x;

import org.apache.ibatis.annotations.*;
import java.util.*;

public class Mappers {
    @Mapper
    public interface NestedMapper {
        List<Object> byName(String name);
        List<Object> safeName(String name);
    }
}
"""

_MB_PROVIDER = """package org.x;

import org.apache.ibatis.annotations.*;
import org.apache.ibatis.jdbc.SQL;
import java.util.*;

@Mapper
public interface ProvMapper {
    @SelectProvider(type = UserSql.class, method = "concat")
    List<Object> concat(String name);

    @SelectProvider(type = UserSql.class, method = "bound")
    List<Object> bound(String name);

    @SelectProvider(type = UserSql.class, method = "builder")
    List<Object> builder(String name);

    @SelectProvider(type = UserSql.class, method = "mapped")
    List<Object> mapped(@Param("name") String name, @Param("sort") String sort);

    @SelectProvider(UserSql.class)
    List<Object> defaultMethod(String name);

    @SelectProvider(type = UserSql.class, method = "builderSafe")
    List<Object> builderSafe(String name);

    class UserSql {
        public static String concat(String name) { return "SELECT * FROM users WHERE name = '" + name + "'"; }
        public static String bound(String name) { return "SELECT * FROM users WHERE name = #{name}"; }
        public static String builder(final String name) {
            return new SQL() {{
                SELECT("*");
                FROM("users");
                if (name != null) {
                    WHERE("name like '%" + name + "%'");
                }
            }}.toString();
        }
        public static String builderSafe(final String name) {
            return new SQL() {{ SELECT("*"); FROM("users"); WHERE("name = #{name}"); }}.toString();
        }
        public static String mapped(Map<String, Object> p) { return "SELECT * FROM users ORDER BY " + p.get("sort"); }
        public static String defaultMethod(String name) { return "SELECT * FROM users WHERE id = #{name}"; }
    }
}
"""

_MB_PLAIN = """import java.util.*;

public interface PlainMapper {
    List<Object> byName(String name);
}
"""

_MB_NESTED_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<mapper namespace="org.x.Mappers$NestedMapper">
  <select id="byName" resultType="map">SELECT * FROM users WHERE name = '${name}'</select>
  <select id="safeName" resultType="map">SELECT * FROM users WHERE name = #{name}</select>
</mapper>
"""

_MB_PLAIN_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<mapper namespace="PlainMapper">
  <select id="byName" resultType="map">SELECT * FROM users WHERE name = '${name}'</select>
</mapper>
"""


def test_mybatis_nested_packageless_and_provider_mappers(tmp_path):
    _write(tmp_path, {
        "src/main/java/org/x/UserController.java": _MB_CONTROLLER,
        "src/main/java/org/x/Mappers.java": _MB_NESTED,
        "src/main/java/org/x/ProvMapper.java": _MB_PROVIDER,
        "src/main/java/other/PlainMapper.java": _MB_PLAIN,
        "src/main/resources/mapper/Nested.xml": _MB_NESTED_XML,
        "src/main/resources/mapper/Plain.xml": _MB_PLAIN_XML,
    })
    ctl = "src/main/java/org/x/UserController.java"
    got = {ln for f, ln in _scan(tmp_path, "DF004") if f == ctl}
    assert {15, 18, 24, 27, 33} <= got, sorted(got)    # nested ($), provider concat / SQL builder / Map, package-less
    assert not got & {21, 30, 36, 39}, sorted(got)      # #{} bound in the provider, the builder and the XML


def test_mybatis_namespace_is_the_declared_package():
    src = "package org.real;\npublic interface UserMapper {\n    List<Object> byName(String name);\n}\n"
    stmts = {"byName": (3, "SELECT * FROM u WHERE n = '${name}'")}

    def bound(namespace, rel="src/main/java/org/other/UserMapper.java"):
        mod = cf.parse_cfamily(src, rel, "java")
        return cf.apply_mybatis_xml(mod, cf.module_name(rel), {namespace: ("m.xml", stmts)}, package=cf.jvm_package(src))
    assert bound("org.real.UserMapper") == 1           # the declared package, whatever the directory
    assert bound("org.other.UserMapper") == 0
    assert bound("UserMapper") == 0                    # a package-less namespace is another interface
    nested = "package a.b;\npublic class Outer {\n  public interface In {\n    List<Object> q(String s);\n  }\n}\n"
    for ns in ("a.b.Outer$In", "a.b.Outer.In"):
        mod = cf.parse_cfamily(nested, "Outer.java", "java")
        assert cf.apply_mybatis_xml(mod, "Outer", {ns: ("m.xml", {"q": (2, "x = ${s}")})},
                                    package=cf.jvm_package(nested)) == 1
    assert cf.jvm_package("/* package not.this; */\npackage a.b;\n") == "a.b"
    assert cf.jvm_package("import x.Y;\nclass Z {}\n") == ""


def test_annotation_named_elements_are_keywords_not_assignments():
    mod = cf.parse_cfamily('@Controller\nclass C {\n  @RequestMapping(value = "/x", method = RequestMethod.GET)\n'
                           '  public String x(String name) { return name; }\n}\n', "C.java", "java")
    fn = mod.body[0].body[0]
    assert ast.unparse(fn.decorator_list[0]) == "RequestMapping(value='/x', method=RequestMethod.GET)"
    assert len(fn.body) == 1 and isinstance(fn.body[0], ast.Return)     # nothing leaked into the method body
    sel = cf.parse_cfamily('interface M {\n  @Select(value = "select * from t where a = ${name}")\n'
                           '  List<Object> q(String name);\n}\n', "M.java", "java")
    assert "executeQuery" in ast.unparse(sel)                             # @Select(value = …) is SQL too


# ------------------------------------------------------------------------------------------- 5. ERB action -> view
_USERS_CONTROLLER = """class UsersController < ApplicationController
  before_action :set_user, only: [:show]
  before_action :set_flash, only: [:index]

  def show
    @greeting = params[:g]
  end

  def edit
    @name = params[:n]
    render :preview
  end

  def index
    @query = params[:q]
    load_extra
  end

  def load_extra
    @extra = params[:e]
  end

  def api
    @token = params[:t]
    render json: { ok: true }
  end

  private

  def set_user
    @user = params[:u]
  end

  def set_flash
    @notice = params[:notice]
  end
end
"""


def test_erb_view_sees_the_rendering_actions_variables(tmp_path):
    _write(tmp_path, {
        "app/controllers/users_controller.rb": _USERS_CONTROLLER,
        "app/views/users/show.html.erb": "<p><%== @greeting %></p>\n<p><%== @name %></p>\n<p><%== @query %></p>\n"
                                         "<p><%== @user %></p>\n<p><%== @notice %></p>\n<p><%== @token %></p>\n",
        "app/views/users/preview.html.erb": "<p><%== @name %></p>\n<p><%== @greeting %></p>\n",
        "app/views/users/index.html.erb": "<p><%== @query %></p>\n<p><%== @extra %></p>\n<p><%== @notice %></p>\n"
                                          "<p><%== @greeting %></p>\n",
        "app/views/users/_row.html.erb": "<p><%== @greeting %></p>\n",
        "app/views/users/orphan.html.erb": "<p><%== @greeting %></p>\n",
    })
    got = _scan(tmp_path, "DF013")
    v = "app/views/users/"
    # show: its own action and the filter that runs for it; not edit's / index's / api's variables
    assert {(v + "show.html.erb", 1), (v + "show.html.erb", 4)} <= got
    assert not {(v + "show.html.erb", n) for n in (2, 3, 5, 6)} & got
    # `render :preview` from edit
    assert (v + "preview.html.erb", 1) in got and (v + "preview.html.erb", 2) not in got
    # index: a public helper it calls, and its only: [:index] filter
    assert {(v + "index.html.erb", n) for n in (1, 2, 3)} <= got and (v + "index.html.erb", 4) not in got
    # a partial and a view no action is known to render: any action of the controller may feed them
    assert (v + "_row.html.erb", 1) in got and (v + "orphan.html.erb", 1) in got


def test_ruby_visibility_marks_helpers():
    mod = cf.parse_cfamily("class A < B\n  def a; end\n  private\n  def b; end\n  public\n  def c; end\n"
                           "  private :c\n  private def d\n    1\n  end\n  def e; end\nend\nclass D\n  def f; end\nend\n",
                           "a.rb", "ruby")
    priv = {n.name: getattr(n, "vulnscan_private", False) for n in ast.walk(mod) if isinstance(n, ast.FunctionDef)}
    assert priv == {"a": False, "b": True, "c": True, "d": True, "e": False, "f": False}
