"""1.0.2 adversarial review of the engine precision items (tests/test_engine_precision_102.py): cases where the
first version of each change lost a true positive.

1. Ruby: open-uri `.read` / `.open` on any variable bound to `URI.parse(x)` / `URI(x)`, not only ones named *uri / *url.
2. Handlebars: `{{#each (sort items)}}` iterates `items`; a `{{!-- {{#each x}} --}}` comment opens no block.
3. Swig / Nunjucks: comment stripping keeps strings and regular expressions (`'/api/*'`), `require('swig').setDefaults`,
   and `{express: app}` held in a separate options object.
4. ERB: an action that renders the view from a helper it calls (`render_failure` -> `render :new`).
"""

from __future__ import annotations

import pathlib

from vulnscan.scanner import scan_path
from vulnscan.taint import _hbs_scope_at, _hbs_scopes, _js_noescape_exts, _js_strip_comments


def _write(root: pathlib.Path, files: dict) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")


def _scan(root: pathlib.Path, rule: str) -> set:
    findings, _ = scan_path(root, jadx=False, notes=[])
    return {(f.file, f.line) for f in findings if f.rule_id == rule}


# ------------------------------------------------------------------------------------------- 1. Ruby open-uri
_RUBY_OPEN_URI = """require 'open-uri'
class FetchController < ApplicationController
  def link_read
    link = URI.parse(params[:u])
    link.read
  end
  def kernel_uri_open
    u = URI(params[:u])
    u.open
  end
  def parse_only
    target = URI.parse(params[:u])
    @host = target.host
  end
  def rebound
    f = URI.parse(params[:u])
    f = File.open("/etc/motd")
    f.read
  end
end
"""


def test_open_uri_read_on_any_variable_bound_to_a_uri(tmp_path):
    _write(tmp_path, {"app/controllers/fetch_controller.rb": _RUBY_OPEN_URI})
    got = {ln for f, ln in _scan(tmp_path, "DF010")}
    assert {5, 9} <= got, sorted(got)                 # link.read / u.open fetch the URL
    assert not got & {12, 13, 16, 18}, sorted(got)    # parsing only; a variable also bound to a File


# ------------------------------------------------------------------------------------------- 2. Handlebars
def test_handlebars_subexpression_each_and_comments():
    text = "{{#each (sort items)}}{{{this.html}}}{{/each}}"
    assert _hbs_scope_at(_hbs_scopes(text), text.index("{{{"))[0] == ["items"]
    text = "{{!-- {{#each posts}} --}}{{! {{#with user}} }}<h1>{{{title}}}</h1>"
    assert _hbs_scope_at(_hbs_scopes(text), text.index("{{{"))[0] == []


_HBS_APP = """const express = require('express');
const app = express();
app.set('view engine', 'hbs');
app.get('/a', (req, res) => { res.render('a', { items: req.query.i }); });
app.get('/b', (req, res) => { res.render('b', { title: req.query.t, posts: [] }); });
"""


def test_handlebars_subexpression_and_comment_views(tmp_path):
    _write(tmp_path, {"app.js": _HBS_APP,
                      "views/a.hbs": "{{#each (sort items)}}<p>{{{this.html}}}</p>{{/each}}\n",
                      "views/b.hbs": "{{!-- {{#each posts}} --}}\n<h1>{{{title}}}</h1>\n"})
    assert {("app.js", 4), ("app.js", 5)} <= _scan(tmp_path, "DF013")


# ------------------------------------------------------------------------------------------- 3. autoescape scope
def test_js_comment_stripping_keeps_strings_and_regexes():
    src = ("app.use('/api/*', h);\nconst re = /^\\/x\\/*/;\nconst t = `a/*b`;\nlet d = a / b / c;\n"
           "// gone\nkeep(); /* gone */ keep2();\n")
    out = _js_strip_comments(src)
    assert "'/api/*'" in out and "/^\\/x\\/*/" in out and "`a/*b`" in out and "a / b / c" in out
    assert "gone" not in out and "keep();" in out and "keep2();" in out


def test_autoescape_off_survives_glob_strings_and_inline_require():
    swig = ("const swig = require('swig');\napp.use('/static/*', serve);\n"
            "swig.setDefaults({ autoescape: false });\napp.engine('html', swig.renderFile);\n/* routes */\n")
    assert _js_noescape_exts([swig]) == {".html"}
    nj = ("const nunjucks = require('nunjucks');\nconst re = /^\\/api\\/*/;\n"
          "nunjucks.configure('views', { autoescape: false, express: app });\nconst x = 1; /* end */\n")
    assert _js_noescape_exts([nj]) == {"*"}
    inline = ("require('swig').setDefaults({ autoescape: false });\n"
              "app.engine('html', require(\"swig\").renderFile);\n")
    assert _js_noescape_exts([inline]) == {".html"}
    held = ("const nunjucks = require('nunjucks');\nconst opts = { autoescape: false, express: app };\n"
            "nunjucks.configure('views', opts);\n")
    assert _js_noescape_exts([held]) == {"*"}
    # still: commented out, or a text environment only
    assert _js_noescape_exts(["const swig = require('swig');\napp.use('/a/*', h);\n"
                              "/* swig.setDefaults({ autoescape: false }); */\napp.engine('html', swig.renderFile);"]) \
        == set()


# ------------------------------------------------------------------------------------------- 4. ERB
_POSTS_CONTROLLER = """class PostsController < ApplicationController
  def new
    @a = params[:a]
  end

  def create
    @title = params[:t]
    render_failure
  end

  def other
    @other = params[:o]
  end

  private

  def render_failure
    render :new
  end
end
"""


def test_erb_view_rendered_from_a_helper_of_the_action(tmp_path):
    _write(tmp_path, {"app/controllers/posts_controller.rb": _POSTS_CONTROLLER,
                      "app/views/posts/new.html.erb": "<%== @a %>\n<%== @title %>\n<%== @other %>\n"})
    got = {ln for f, ln in _scan(tmp_path, "DF013") if f == "app/views/posts/new.html.erb"}
    assert {1, 2} <= got and 3 not in got, sorted(got)


_FILTER_CONTROLLER = """class PostsController < ApplicationController
  SHOWN = [:show]
  before_action :set_q, only: SHOWN
  before_action :set_r, only: [:index]

  def show
    @a = params[:a]
  end

  def index
    @i = params[:i]
  end

  private

  def set_q
    @q = params[:q]
  end

  def set_r
    @r = params[:r]
  end
end
"""


def test_erb_filter_with_unknown_only_list_may_run(tmp_path):
    _write(tmp_path, {"app/controllers/posts_controller.rb": _FILTER_CONTROLLER,
                      "app/views/posts/show.html.erb": "<%== @a %>\n<%== @q %>\n<%== @r %>\n<%== @i %>\n"})
    got = {ln for f, ln in _scan(tmp_path, "DF013") if f == "app/views/posts/show.html.erb"}
    assert {1, 2} <= got and not got & {3, 4}, sorted(got)    # `only: SHOWN` is not known: the filter may run
