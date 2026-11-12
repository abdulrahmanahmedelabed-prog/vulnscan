"""Regressions from the final independent corpus re-sweep.

Each test is a small program: the vulnerable case must be reported and its safe twin must not be.
"""

from __future__ import annotations

from vulnscan.cfamily_frontend import parse_cfamily_ex, tokenize
from vulnscan.scanner import scan_path


def _scan(root) -> set:
    findings, _ = scan_path(root, jadx=False, notes=[])
    return {(f.rule_id, f.file, f.line) for f in findings}


_MAPPING = '''package demo.ann;
import org.springframework.web.bind.annotation.RequestMapping;
@Retention(RetentionPolicy.RUNTIME)
@Target(value = ElementType.METHOD)
@RequestMapping
public @interface LevelMapping {
    String value();
    String[] tags() default {};
    int order() default 3;
}
'''

_NOT_A_ROUTE = '''package demo.ann;
@Retention(RetentionPolicy.RUNTIME)
public @interface Audited { String value() default ""; }
'''

_CONTROLLER = '''package demo;
import java.util.Map;
import demo.ann.LevelMapping;
import demo.ann.Audited;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.jdbc.core.JdbcTemplate;
public class Cars {
    private final JdbcTemplate jdbc;
    @LevelMapping(value = "LEVEL_1")
    public Object level1(@RequestParam final Map<String, String> queryParams) {
        final String id = queryParams.get("id");
        return jdbc.query("select * from cars where id=" + id, this::row);
    }
    @Audited("x")
    public Object helper(final Map<String, String> values) {
        final String id = values.get("id");
        return jdbc.query("select * from cars where id=" + id, this::row);
    }
}
'''


def test_java_annotation_type_declaration_is_parsed():
    mod, diag = parse_cfamily_ex(_MAPPING, "LevelMapping.java", "java")
    assert diag["skipped"] == 0, diag
    cls = [n for n in mod.body if getattr(n, "name", "") == "LevelMapping"]
    assert cls, "the @interface declaration must become a class"
    names = {getattr(d, "id", None) or getattr(getattr(d, "func", None), "id", None) for d in cls[0].decorator_list}
    assert "RequestMapping" in names


def test_spring_composed_mapping_annotation_marks_an_entry_point(tmp_path):
    (tmp_path / "LevelMapping.java").write_text(_MAPPING)
    (tmp_path / "Audited.java").write_text(_NOT_A_ROUTE)
    (tmp_path / "Cars.java").write_text(_CONTROLLER)
    found = _scan(tmp_path)
    assert ("DF004", "Cars.java", 12) in found          # routed through the meta-annotated @LevelMapping
    assert ("DF004", "Cars.java", 17) not in found      # @Audited is not a request mapping: no request source


def _js_rules(files: dict) -> set:
    from vulnscan.taint import analyze_project
    return {(f.rule_id, f.file, f.line) for f in analyze_project(files)}


_CTOR_DAO = '''const express = require("express");
const app = express();
function AllocationsDAO(db) {
  const allocationsCol = db.collection("allocations");
  this.byThreshold = (userId, threshold, callback) => {
    const criteria = () => {
      if (threshold) { return { $where: `this.stocks > '${threshold}'` }; }
      return { userId: 1 };
    };
    allocationsCol.find(criteria()).toArray(callback);
  };
  this.byUser = (userId, callback) => {
    allocationsCol.find({ userId: parseInt(userId, 10) }).toArray(callback);
  };
}
const dao = new AllocationsDAO(db);
app.get("/vuln", (req, res) => { dao.byThreshold(1, req.query.threshold, () => res.send("ok")); });
app.get("/safe", (req, res) => { dao.byUser(req.query.userId, () => res.send("ok")); });
'''


def test_js_constructor_function_methods_and_closure_return():
    # ES5 constructor function (`this.m = () => …`) + a closure returning a captured variable (NodeGoat A1-2)
    found = _js_rules({"dao.js": _CTOR_DAO})
    assert ("DF004", "dao.js", 17) in found
    assert not any(line == 18 for _, _, line in found if _ != "vql/entry-point-without-auth")


def test_python_closure_returning_captured_request_value():
    src = ("import os\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
           "@app.route('/v')\ndef v():\n    t = request.args.get('t')\n"
           "    def crit():\n        return 'echo ' + t\n    os.system(crit())\n    return 'ok'\n\n"
           "@app.route('/s')\ndef s():\n    t = request.args.get('t')\n"
           "    def fixed():\n        return 'echo fixed'\n    os.system(fixed())\n    return t\n")
    found = {(r, ln) for r, _, ln in _js_rules({"app.py": src})}
    assert ("DF002", 10) in found
    assert ("DF002", 18) not in found


def test_js_mongo_insert_document_is_not_a_query():
    src = ('const express = require("express");\nconst app = express();\n'
           'app.post("/m", (req, res) => {\n  const memosCol = db.collection("memos");\n'
           '  memosCol.insert({ memo: req.body.memo }, () => 1);\n'
           '  memosCol.update({ owner: req.body.owner }, { $set: { seen: true } });\n});\n')
    found = {(r, ln) for r, _, ln in _js_rules({"m.js": src})}
    assert ("DF004", 6) in found
    assert ("DF004", 5) not in found


_JAVA_DECODE = '''package demo;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Base64;
import org.springframework.web.bind.annotation.*;
@RestController
public class Prefs {
    private static final ObjectMapper M = new ObjectMapper();
    private static byte[] decode(String s) { return Base64.getDecoder().decode(s); }
    @GetMapping("/vuln")
    public String vuln(@CookieValue(value = "p", required = false) String p) throws Exception {
        return String.valueOf(M.readValue(decode(p), Object.class));
    }
    @GetMapping("/safe")
    public String safe(@CookieValue(value = "p", required = false) String p) throws Exception {
        return String.valueOf(M.readValue(decode("e30="), Object.class)) + p.length();
    }
}
'''


def test_java_library_call_is_not_resolved_to_a_same_named_project_method():
    # `Base64.getDecoder().decode(s)` inside the class's own `decode` helper was resolved to that helper, so the
    # helper looked recursive and dropped the taint (VulnerableApp InsecureDeserialization)
    found = {(r, ln) for r, _, ln in _js_rules({"Prefs.java": _JAVA_DECODE})}
    assert ("DF006", 11) in found
    assert ("DF006", 15) not in found


_JAXB = '''package demo;
import java.io.*;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.*;
import org.springframework.web.bind.annotation.*;
@RestController
public class Books {
    @PostMapping("/vuln")
    public String vuln(HttpServletRequest request) throws Exception {
        Unmarshaller jaxbUnmarshaller = JAXBContext.newInstance(Book.class).createUnmarshaller();
        return String.valueOf(jaxbUnmarshaller.unmarshal(request.getInputStream()));
    }
    @PostMapping("/safe")
    public String safe(HttpServletRequest request) throws Exception {
        Unmarshaller jaxbUnmarshaller = JAXBContext.newInstance(Book.class).createUnmarshaller();
        return String.valueOf(jaxbUnmarshaller.unmarshal(new File("books.xml"))) + request.getMethod();
    }
}
'''


def test_java_jaxb_unmarshal_of_request_body_is_xxe():
    found = {(r, ln) for r, _, ln in _js_rules({"Books.java": _JAXB})}
    assert ("DF027", 11) in found
    assert ("DF027", 16) not in found


_UPLOAD_BASE = '''package demo;
import java.io.File;
import org.springframework.util.FileCopyUtils;
public class UploadBase {
  protected String execute(byte[] b, String fullName) throws Exception {
    var uploadedFile = new File("/up", fullName);
    FileCopyUtils.copy(b, uploadedFile);
    return "ok";
  }
}
'''

_UPLOAD = '''package demo;
import org.springframework.web.bind.annotation.*;
@RestController
public class Upload extends UploadBase {
  @PostMapping("/vuln")
  public String vuln(@RequestParam("f") String fullName) throws Exception {
    return super.execute(new byte[0], fullName);
  }
  @PostMapping("/safe")
  public String safe(@RequestParam("f") String fullName) throws Exception {
    return super.execute(new byte[0], "avatar.png") + fullName.length();
  }
}
'''


def test_java_super_call_resolves_to_the_inherited_method():
    # WebGoat PathTraversal ProfileUpload: `super.execute(file, fullName, username)` writes new File(dir, fullName)
    found = {(r, f, ln) for r, f, ln in _js_rules({"UploadBase.java": _UPLOAD_BASE, "Upload.java": _UPLOAD})}
    assert ("DF005", "Upload.java", 7) in found
    assert not any(f == "Upload.java" and ln == 11 for r, f, ln in found if r == "DF005")


def test_cleartext_http_rule_ignores_parser_feature_names_and_placeholder_bases():
    from vulnscan.rules import RULES
    rule = next(r for r in RULES if r.id == "NET001")

    def hit(line):
        return bool(rule.pattern.search(line)) and not (rule.skip and rule.skip.search(line))

    assert hit('fetch("http://api.shop.io/orders")')
    assert not hit('dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);')
    assert not hit('spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);')
    assert not hit("const parsed = new URL(route, 'http://n')")


def test_standalone_entropy_skips_identifiers_slugs_and_public_addresses():
    import random
    import string

    from vulnscan.scanner import _entropy_findings

    rng = random.Random(7)
    token = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(44))   # built at run time
    assert _entropy_findings("a.txt", 1, f"blob {token} end")
    assert not _entropy_findings("A.java", 1, "    public static String getBase64UrlSafeWithoutPaddingEncodedString(byte[] t)")
    assert not _entropy_findings("p.txt", 1, "S700_3505|Coin|4|2550-Lucky-Waving-Green-Cat-1_25oz-Gold-Coin-Reverse.jpg|")
    address = "0x" + "".join(rng.choice("0123456789abcdefABCDEF") for _ in range(40))
    assert not _entropy_findings("w.ts", 1, f"const contractAddress = '{address}'")


_RACK_WARN = '''require 'sinatra'
module Prot
  class Base
    def warn(env, message)
      l = env['rack.logger']
      l.warn(message)
    end
    def call(env)
      warn env, "attack prevented by #{self.class}"
      warn env, "bad #{env['QUERY_STRING']}"
    end
  end
end
'''


def test_ruby_bare_call_to_own_method_uses_its_summary_not_the_kernel_model():
    # rack-protection: `warn env, "constant text"` calls Base#warn(env, message), which logs only `message`
    found = {(r, ln) for r, _, ln in _js_rules({"base.rb": _RACK_WARN})}
    assert ("DF016", 10) in found
    assert ("DF016", 9) not in found


_SEQ = '''const express = require("express");
const app = express();
app.get("/b/:id", async (req, res) => {
  const id = req.params.id;
  res.json(await BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, as: "Products" }] }));
});
app.post("/u", async (req, res) => {
  const name = req.body.name;
  res.json(await UserModel.findOne({ where: { name } }));
});
'''


def test_js_route_parameter_alias_is_a_scalar_in_an_orm_filter():
    # juice-shop basket.ts: `const id = req.params.id; BasketModel.findOne({ where: { id } })` binds a string
    found = {(r, ln) for r, _, ln in _js_rules({"r.js": _SEQ})}
    assert ("DF004", 9) in found
    assert ("DF004", 5) not in found


def test_innerhtml_rule_skips_a_choice_between_two_literals():
    from vulnscan.rules import RULES
    rule = next(r for r in RULES if r.id == "INJ004")

    def hit(line):
        return bool(rule.pattern.search(line)) and not (rule.skip and rule.skip.search(line))

    assert hit("el.innerHTML = ok ? data : 'x';")
    assert hit("el.innerHTML = a ? '<b>' : '' + data;")
    assert not hit("themeToggle.innerHTML = newTheme === 'dark' ? 'sun' : 'moon';")


def test_hardcoded_password_rule_skips_php_variable_interpolation():
    from vulnscan.rules import RULES
    rule = next(r for r in RULES if r.id == "SEC004")

    def hit(line):
        return bool(rule.pattern.search(line)) and not (rule.skip and rule.skip.search(line))

    assert hit('$password = "Sup3rS3cret!";')
    assert not hit("""$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = 'x';";""")


_DJ_NEXT = '''from django.http import HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme


def set_language(request):
    next_url = request.POST.get("next")
    if not url_has_allowed_host_and_scheme(url=next_url, allowed_hosts={request.get_host()}):
        next_url = "/"
    return HttpResponseRedirect(next_url)


def unchecked(request):
    next_url = request.POST.get("next")
    if not next_url:
        next_url = "/"
    return HttpResponseRedirect(next_url)
'''


def test_django_redirect_validated_or_replaced_is_not_an_open_redirect():
    found = {(r, ln) for r, _, ln in _js_rules({"views.py": _DJ_NEXT})}
    assert ("DF008", 16) in found
    assert ("DF008", 9) not in found


def test_sql_concat_rule_ignores_upper_case_table_name_constants():
    from vulnscan.rules import RULES
    rule = next(r for r in RULES if r.id == "INJ002")
    assert rule.pattern.search('q = "select * from cars where id=" + id;')
    assert rule.pattern.search('q = "SELECT * FROM " + TABLE + " WHERE id = " + id;')
    assert rule.pattern.search('q = "SELECT * FROM t WHERE a = " + X;')
    assert not rule.pattern.search('cmd.CommandText = "SELECT UserId FROM " + USER_TB_NAME + " WHERE n = $Username";')


_FLASK_TUPLE = '''from flask import Flask, request, jsonify
app = Flask(__name__)


@app.route("/key", methods=["POST"])
def key():
    name = request.form.get("username")
    return jsonify({"key": name}), 200


@app.route("/echo")
def echo():
    return "<p>" + request.args.get("q", "") + "</p>", 200
'''


def test_flask_jsonify_with_status_tuple_is_not_reflected_xss():
    # vulpy good/mod_api.py: `return jsonify({'key': key}), 200`
    found = {(r, ln) for r, _, ln in _js_rules({"api.py": _FLASK_TUPLE})}
    assert ("DF013", 13) in found
    assert ("DF013", 8) not in found


_PY_SUPER = '''import os


class Base:
    def run(self, cmd):
        os.system(cmd)


class Child(Base):
    def run(self, cmd):
        super().run("ls " + cmd)


class Quiet(Base):
    def run(self, cmd):
        super().run("ls")


def view(request):
    Child().run(request.GET["x"])
    Quiet().run(request.GET["x"])
'''


def test_python_super_call_resolves_to_the_base_method():
    found = {(r, ln) for r, _, ln in _js_rules({"v.py": _PY_SUPER})}
    assert ("DF002", 20) in found
    assert ("DF002", 21) not in found


_PT = '''package demo;
import java.io.*;
import java.nio.file.*;
import org.slf4j.*;
import org.springframework.web.bind.annotation.*;
@RestController
public class PT {
    private static final Logger logger = LoggerFactory.getLogger(PT.class);
    @GetMapping("/v")
    public String getImage(String filepath) throws IOException {
        return getImgBase64(filepath);
    }
    @GetMapping("/s")
    public String getFixed(String filepath) throws IOException {
        return getImgBase64("logo.png") + filepath.length();
    }
    private String getImgBase64(String imgFile) throws IOException {
        logger.info("File path: " + imgFile);
        byte[] data = Files.readAllBytes(Paths.get(imgFile));
        return "x";
    }
}
'''


def test_helper_reaching_two_kinds_of_sink_reports_both_at_the_call():
    # java-sec-code PathTraversal: getImgBase64 logs the path, then reads it; only the log finding was reported
    found = {(r, ln) for r, _, ln in _js_rules({"PT.java": _PT})}
    assert {("DF016", 11), ("DF005", 11)} <= found
    assert not any(ln == 15 for r, ln in found if r in ("DF005", "DF016"))


_HTTPCLIENT = '''package demo;
import java.sql.*;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.*;
import org.springframework.web.bind.annotation.*;
@RestController
public class Fetch {
    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) throws Exception {
        CloseableHttpClient client = HttpClients.createDefault();
        client.execute(new HttpGet(url));
        return "ok";
    }
    @GetMapping("/sql")
    public String sql(@RequestParam String name, Connection conn) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.execute("select * from t where n = '" + name + "'");
        return "ok";
    }
}
'''


def test_java_http_client_execute_is_not_a_sql_sink():
    found = {(r, ln) for r, _, ln in _js_rules({"Fetch.java": _HTTPCLIENT})}
    assert ("DF004", 17) in found
    assert ("DF004", 11) not in found


# ------------------------------------------------------------------ 1.0.1 engine precision / MyBatis recall
def _write(root, files: dict) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def _scan_full(root):
    findings, _ = scan_path(root, jadx=False, notes=[])
    return findings


_MB_CONTROLLER = '''package demo.web;

import demo.mapper.UserMapper;
import org.springframework.web.bind.annotation.*;

@RestController
public class Users {
    private UserMapper userMapper;

    @GetMapping("/a")
    public Object a(@RequestParam("name") String name) {
        return userMapper.byNameDollar(name);
    }

    @GetMapping("/b")
    public Object b(@RequestParam("name") String name) {
        return userMapper.byNameHash(name);
    }

    @GetMapping("/c")
    public Object c(@RequestParam("sort") String sort) {
        return userMapper.ordered(sort);
    }

    @GetMapping("/d")
    public Object d(@RequestParam("name") String name) {
        return userMapper.likeXml(name);
    }

    @GetMapping("/e")
    public Object e(@RequestParam("name") String name) {
        return userMapper.byIdXml(name);
    }

    @GetMapping("/f")
    public Object f(@RequestParam("sort") String sort) {
        return userMapper.orderXml(sort);
    }

    @GetMapping("/g")
    public Object g(@RequestParam("sort") String sort) {
        return userMapper.orderXml(Filter.clean(sort));
    }
}
'''

_MB_FILTER = '''package demo.web;

import java.util.regex.Pattern;

public class Filter {
    private static final Pattern SAFE = Pattern.compile("^[a-zA-Z0-9_]+$");

    public static String clean(String s) {
        if (!SAFE.matcher(s).matches()) {
            return null;
        }
        return s;
    }
}
'''

_MB_MAPPER = '''package demo.mapper;

import org.apache.ibatis.annotations.*;
import java.util.List;

@Mapper
public interface UserMapper {
    @Select("select * from users where name = '${name}'")
    List<Object> byNameDollar(@Param("name") String name);

    @Select("select * from users where name = #{name}")
    List<Object> byNameHash(@Param("name") String name);

    @Select({"select * from users", "order by ${order}"})
    List<Object> ordered(@Param("order") String sort);

    List<Object> likeXml(String name);
    List<Object> byIdXml(String name);
    List<Object> orderXml(@Param("order") String sort);
}
'''

_MB_XML = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="demo.mapper.UserMapper">
    <!-- <select id="byIdXml">select * from users where id = ${id}</select> -->
    <sql id="orderBy">order by ${order}</sql>
    <select id="likeXml" resultType="map">
        select * from users where name like '%${_parameter}%'
    </select>
    <select id="byIdXml" resultType="map">
        select * from users where id = #{id}
    </select>
    <select id="orderXml" resultType="map">
        select * from users
        <if test="order != null"><include refid="orderBy"/></if>
    </select>
</mapper>
'''


def test_mybatis_dollar_substitution_is_sql_injection(tmp_path):
    _write(tmp_path, {"src/main/java/demo/web/Users.java": _MB_CONTROLLER,
                      "src/main/java/demo/web/Filter.java": _MB_FILTER,
                      "src/main/java/demo/mapper/UserMapper.java": _MB_MAPPER,
                      "src/main/resources/mapper/UserMapper.xml": _MB_XML})
    findings = _scan_full(tmp_path)
    ctl = "src/main/java/demo/web/Users.java"
    sqli = {f.line: f for f in findings if f.rule_id == "DF004" and f.file == ctl}
    assert {12, 22, 27, 37} <= set(sqli), sorted(sqli)   # ${} in @Select, @Select({..}) with @Param, mapper XML
    assert 17 not in sqli                                # #{name} is a bound parameter
    assert 32 not in sqli                                # #{id} in XML (the ${id} is inside an XML comment)
    assert 42 not in sqli                                # the value was validated by an anchored allow-list regexp
    # the data-flow path ends at the SQL text: the annotation line, or the mapper XML line
    assert sqli[27].extra["path"][-1]["file"] == "src/main/resources/mapper/UserMapper.xml"
    assert sqli[27].extra["path"][-1]["line"] == 7
    assert sqli[37].extra["path"][-1]["line"] == 5        # through <include refid="orderBy"/>
    assert sqli[12].extra["path"][-1]["file"] == "src/main/java/demo/mapper/UserMapper.java"
    assert sqli[12].extra["path"][-1]["line"] == 8


_RB_BASE = '''module Rack
  module Protection
    class Base
      DEFAULT_OPTIONS = {
        reaction: :default_reaction, logging: true,
        html_types: %w[text/html application/xhtml text/xml application/xml]
      }

      def warn(env, message)
        l = env['rack.logger']
        l.warn(message)
      end

      def deny(env)
        warn env, "attack prevented by #{self.class}"
        [403, {}, []]
      end
    end
  end
end
'''

_RB_MIXIN = '''module Logging
  def warn(env, message)
    env['rack.logger'].warn(message)
  end
end

class Parent
  def warn(env, message)
    env['rack.logger'].warn(message)
  end
end

class Mixed
  include Logging

  def call(env)
    warn env, "denied #{self.class}"
    [403, {}, []]
  end
end

class Child < Parent
  def call(env)
    warn env, "denied"
    [403, {}, []]
  end
end

class Plain
  def call(env)
    warn env, "denied"
    [403, {}, []]
  end
end
'''

_RB_TOPLEVEL = '''def warn(env, message)
  puts message.length
end

def call(env)
  warn env, "top"
end
'''


def test_ruby_percent_literals_keep_the_class():
    mod, diag = parse_cfamily_ex(_RB_BASE, "base.rb", "ruby")
    assert diag["skipped"] == 0, diag
    assert [n.name for n in mod.body if n.__class__.__name__ == "ClassDef"] == ["Rack"]
    toks = [t.val for t in tokenize("a = %w[x y]\nb = n % (2)\nc = %q(it's)\nd = %r{^a/b}i\n", "ruby")]
    assert toks[:7] == ["a", "=", "[", "'x'", ",", "'y'", "]"]
    assert toks[7:13] == ["b", "=", "n", "%", "(", "2"]
    assert "'it\\'s'" in toks and '"^a/b"' in toks and "i" not in toks


def test_ruby_own_warn_shadows_kernel_warn(tmp_path):
    _write(tmp_path, {"base.rb": _RB_BASE, "mixin.rb": _RB_MIXIN, "top.rb": _RB_TOPLEVEL})
    found = {(r, f, ln) for r, f, ln in _scan(tmp_path) if r == "DF016"}
    assert ("DF016", "base.rb", 15) not in found          # the class's own warn logs only the message
    assert ("DF016", "mixin.rb", 17) not in found         # warn from an included module
    assert ("DF016", "mixin.rb", 24) not in found         # warn from the base class
    assert ("DF016", "top.rb", 6) not in found            # a top-level def warn replaces Kernel#warn
    assert ("DF016", "mixin.rb", 31) in found             # no project warn: Kernel#warn writes env to the log


_PY_SET_LANGUAGE = '''from django.http import HttpResponse, HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme


def set_language(request):
    next_url = request.POST.get("next", request.GET.get("next"))
    if (
        next_url or request.accepts("text/html")
    ) and not url_has_allowed_host_and_scheme(url=next_url, allowed_hosts={request.get_host()}):
        next_url = request.META.get("HTTP_REFERER")
        if not url_has_allowed_host_and_scheme(url=next_url, allowed_hosts={request.get_host()}):
            next_url = "/"
    return HttpResponseRedirect(next_url) if next_url else HttpResponse(status=204)


def referer_unchecked(request):
    next_url = request.GET.get("next")
    if (next_url or request.accepts("text/html")) and not url_has_allowed_host_and_scheme(url=next_url, allowed_hosts=None):
        next_url = request.META.get("HTTP_REFERER")
    return HttpResponseRedirect(next_url)


def logged_only(request):
    next_url = request.GET.get("next")
    if next_url and not url_has_allowed_host_and_scheme(url=next_url, allowed_hosts=None):
        print("unsafe")
    return HttpResponseRedirect(next_url)


def either_part(request):
    next_url = request.GET.get("next")
    if next_url or not url_has_allowed_host_and_scheme(url=next_url, allowed_hosts=None):
        return HttpResponse(status=400)
    return HttpResponseRedirect(next_url)
'''


def test_python_compound_condition_validation_guard():
    found = {(r, ln) for r, _, ln in _js_rules({"views.py": _PY_SET_LANGUAGE}) if r == "DF008"}
    assert ("DF008", 13) not in found     # empty, or it passed the check; else replaced by a checked referer / "/"
    assert ("DF008", 20) in found         # the referer that replaces it is never checked
    assert ("DF008", 27) in found         # the failed check only logs
    assert ("DF008", 34) not in found     # past `if url or not ok(url): return`, url is empty


_DJ_SHORTCUTS = '''from django.http import HttpResponse


def render(request, template_name, context=None):
    return HttpResponse(context)


def show(request, slug):
    return HttpResponse(slug)


def legacy(request, slug):
    return HttpResponse(slug)
'''

_DJ_URLS = '''from django.urls import path, re_path
from . import shortcuts

urlpatterns = [
    path("show/<slug>/", shortcuts.show),
    re_path(r"^legacy/(?P<slug>\\\\w+)/$", "app.shortcuts.legacy"),
]
'''


def test_django_function_view_needs_routing_evidence(tmp_path):
    _write(tmp_path, {"app/__init__.py": "", "app/shortcuts.py": _DJ_SHORTCUTS, "app/urls.py": _DJ_URLS})
    found = {(r, f, ln) for r, f, ln in _scan(tmp_path) if r == "DF013"}
    assert ("DF013", "app/shortcuts.py", 5) not in found   # a helper taking a request, routed nowhere
    assert ("DF013", "app/shortcuts.py", 9) in found       # routed by path()
    assert ("DF013", "app/shortcuts.py", 13) in found      # routed by a dotted string in re_path()
    # without any URL configuration in the scan (one app's views alone) the signature still decides
    (tmp_path / "app" / "urls.py").unlink()
    found = {(r, f, ln) for r, f, ln in _scan(tmp_path) if r == "DF013"}
    assert ("DF013", "app/shortcuts.py", 5) in found and ("DF013", "app/shortcuts.py", 9) in found


_SEC_CREDENTIALS_JSON = '''{
\t"UserName" : "Dummy",
\t"Password" : "password",
\t"Description" : "a lab file"
}
'''

_SEC_LABELS_PY = '''LABELS = {
    "elapsed": "time",
    "file": "file",
    "secret": "secret",
    "chars": "chars",
    "status": "status",
}
TITLES = {
    "password": "Password",
}
'''


def test_sec004_weak_credential_object_vs_label_table(tmp_path):
    _write(tmp_path, {"secret.json": _SEC_CREDENTIALS_JSON, "labels.py": _SEC_LABELS_PY})
    found = {(r, f, ln) for r, f, ln in _scan(tmp_path) if r == "SEC004"}
    assert ("SEC004", "secret.json", 3) in found       # a credentials object whose password is the word "password"
    assert ("SEC004", "labels.py", 4) not in found     # an entry of a table of entries that repeat their key
    assert ("SEC004", "labels.py", 9) not in found     # the key's display label


_JAVA_VALIDATED_RETURN = '''package x;

import java.sql.Statement;
import java.util.regex.Pattern;
import org.springframework.web.bind.annotation.*;

@RestController
public class E {
    private static final Pattern P = Pattern.compile("^[a-zA-Z0-9_]+$");
    private Statement stmt = null;

    public static String filt(String s) {
        if (!P.matcher(s).matches()) {
            return null;
        }
        return s;
    }

    public static String trimmed(String s) {
        if (s == null) {
            return "";
        }
        return s.trim();
    }

    @GetMapping("/c")
    public String c(@RequestParam("u") String u) {
        stmt.executeQuery("select * from u order by " + filt(u));
        stmt.executeQuery("select * from u order by " + trimmed(u));
        return "";
    }
}
'''


def test_java_helper_returning_a_validated_parameter():
    found = {(r, ln) for r, _, ln in _js_rules({"E.java": _JAVA_VALIDATED_RETURN}) if r == "DF004"}
    assert ("DF004", 28) not in found     # filt() gives back the value only when it matched the allow-list
    assert ("DF004", 29) in found         # a null check validates nothing
