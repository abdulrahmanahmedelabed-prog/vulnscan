"""ERB views (Rails ``app/views/**/*.html.erb``) lowered to Ruby code for the data-flow engine.

Rails escapes what ``<%= expr %>`` prints, so only output that bypasses escaping is an XSS sink:
``<%== expr %>``, ``<%= raw expr %>`` and ``<%= expr.html_safe %>``. The view becomes one Ruby method of a class
derived from the view's controller (``app/views/users/show.html.erb`` -> ``UsersController``), so the instance
variables the controller's actions set (``@greeting = params[:greeting]``) reach the view as they do at run time,
and request data the view reads itself (``params``, ``cookies``, ``request``) is a source as usual.

Every line stays on its line: text outside tags becomes blank lines, tags on one line are joined with ``;``.
A plain ``<%= expr %>`` that neither calls ``raw`` nor ``html_safe`` is left out (it is escaped); ``<% code %>``
is kept (assignments, loops and conditions the output depends on).
"""

from __future__ import annotations

import posixpath
import re

ERB_EXTS = (".erb",)
VIEW_CLASS = "KashifErbView"
VIEW_METHOD = "kashif_erb_view"
_TAG = re.compile(r"<%(%|#|==|=|-)?(.*?)(-?)%>", re.S)
_RAW_HEAD = re.compile(r"^raw\b\s*(?:\((.*)\)\s*$|(?!\()(.+)$)", re.S)
_BLOCK_OPEN = re.compile(r"\bdo\s*(\|[^|]*\|)?\s*$")
_UNESCAPED = re.compile(r"\bhtml_safe\b|(?<![\w.:@])raw\b")


def _controller(rel: str) -> str:
    """The controller class whose actions render this view: views/admin/users/show -> UsersController."""
    parts = rel.replace("\\", "/").split("/")
    if "views" in parts:
        parts = parts[len(parts) - parts[::-1].index("views"):]
    dirs = [p for p in parts[:-1] if p]
    if not dirs or dirs[0] in ("layouts", "shared", "application"):
        return "ApplicationController"
    name = "".join(w[:1].upper() + w[1:] for w in re.split(r"[_\-]", dirs[-1]) if w)
    return (name or "Application") + "Controller"


def _output(expr: str, raw: bool) -> str | None:
    """The Ruby statement for one output tag, or None when Rails escapes it and nothing in it bypasses that."""
    e = expr.strip()
    if not e:
        return None
    if raw:
        return f"__erb_out__(({e}).html_safe)"
    m = _RAW_HEAD.match(e)
    if m:
        inner = (m.group(1) if m.group(1) is not None else m.group(2)).strip()
        if inner:
            return f"__erb_out__(({inner}).html_safe)"
    if _UNESCAPED.search(e):
        return f"__erb_out__ {e}"
    blk = _BLOCK_OPEN.search(e)
    if blk:                                     # `<%= form_for @user do |f| %>` … `<% end %>`: keep the block
        return f"__erb_out__ do {blk.group(1) or ''}".rstrip()
    return None


def to_ruby(text: str, rel: str = "view.html.erb") -> str:
    """Ruby source with the view's code on the view's lines (see the module docstring)."""
    out = []
    pos = 0
    for m in _TAG.finditer(text):
        out.append("\n" * text.count("\n", pos, m.start()))
        kind, body = m.group(1), m.group(2)
        nl = body.count("\n")
        stmt = None
        if kind in ("%", "#"):
            stmt = None
        elif kind in ("=", "=="):
            stmt = _output(body, kind == "==")
        else:                                   # <% code %> / <%- code %>
            stmt = body.strip() or None
        if stmt is not None:
            # keep the tag's own line breaks inside multi-line code; output tags are folded onto their first line
            stmt = stmt if kind not in ("=", "==") else stmt.replace("\n", " ")
            out.append("; " + stmt + " ;" + ("\n" * (nl - stmt.count("\n"))))
        else:
            out.append("\n" * nl)
        pos = m.end()
    out.append("\n" * text.count("\n", pos))
    code = "".join(out)
    base = _controller(rel)
    return f"class {VIEW_CLASS} < {base}; def {VIEW_METHOD}; " + code + "\nend; end\n"


def is_erb(rel: str) -> bool:
    return rel.lower().endswith(ERB_EXTS) and posixpath.basename(rel.replace("\\", "/"))[:1] != "."
