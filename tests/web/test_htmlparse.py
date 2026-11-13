"""Light DOM (spec §2.6, WP0): <base>, template/noscript/comment exclusion, inline scripts with line offsets, forms,
malformed HTML and the 2 MB performance budget (§4.3)."""

from __future__ import annotations

import time

import pytest

from vulnscan.webscan.htmlparse import line_of, parse, parse_meta_refresh, parse_response, srcset_urls
from vulnscan.webscan.types import HeaderList, Response

URL = "https://shop.example.test/a/b/page.html"


def tags(doc, live_only=True):
    return [e.tag for e in doc.find_all(live_only=live_only)]


def test_elements_attributes_and_order():
    doc = parse('<!DOCTYPE html><html><head><title> Hi  there </title></head><body>'
                '<a HREF="/x" href="/ignored" target=_blank rel="noopener NoReferrer">x</a><input disabled></body></html>',
                URL)
    assert doc.doctype == "html"
    assert doc.title == "Hi there"
    a = doc.find_all("a")[0]
    assert a.attrs["href"] == "/x"                     # first duplicate attribute wins (HTML spec)
    assert a.tokens("rel") == {"noopener", "noreferrer"}
    assert doc.find_all("input")[0].attrs["disabled"] == ""   # valueless attribute
    assert tags(doc) == ["html", "head", "title", "body", "a", "input"]
    assert [e.index for e in doc.elements] == list(range(len(doc.elements)))
    assert doc.elements[doc.find_all("a")[0].parent].tag == "body"


def test_no_doctype_means_quirks():
    assert parse("<html><body>x</body></html>", URL).doctype is None


def test_base_href_resolution():
    doc = parse('<head><base href="https://cdn.example.test/static/"><base href="https://evil.test/"></head>'
                '<body><script src="app.js"></script><img src="//img.test/a.png"><a href="  /x\n y "></a></body>', URL)
    assert doc.base_href == "https://cdn.example.test/static/"     # only the first <base href> counts
    assert doc.resolve(doc.find_all("script")[0].get("src")) == "https://cdn.example.test/static/app.js"
    assert doc.resolve("//img.test/a.png") == "https://img.test/a.png"
    assert doc.resolve(doc.find_all("a")[0].get("href")) == "https://cdn.example.test/x y"
    no_base = parse('<img src="c.png">', URL)
    assert no_base.base_url == URL and no_base.resolve("c.png") == "https://shop.example.test/a/b/c.png"


def test_relative_and_javascript_base_are_handled():
    doc = parse('<base href="../up/"><img src="i.png">', URL)
    assert doc.resolve("i.png") == "https://shop.example.test/a/up/i.png"
    js = parse('<base href="javascript:alert(1)"><img src="i.png">', URL)
    assert js.base_url == URL                            # a non-http(s) base is ignored


def test_template_noscript_and_comments_are_not_live():
    html = ('<body><template><script src="http://t.test/x.js"></script><form action="http://t.test/"></form></template>'
            '<noscript><img src="http://n.test/p.gif"></noscript>'
            '<!-- <script src="http://c.test/y.js"></script> --><img src="https://ok.test/i.png"></body>')
    doc = parse(html, URL)
    live = doc.find_all("script", "img", "form")
    assert [e.tag for e in live] == ["img"] and live[0].get("src") == "https://ok.test/i.png"
    everything = doc.find_all("script", "img", "form", live_only=False)
    assert len(everything) == 4                          # kept for inventory, but marked not live
    assert [c.text.strip() for c in doc.comments] == ['<script src="http://c.test/y.js"></script>']
    assert not any(e.tag == "script" and e.get("src") == "http://c.test/y.js" for e in doc.elements)
    assert len(doc.forms) == 1 and doc.forms[0].live is False


def test_template_contents_excluded_from_visible_text():
    doc = parse("<p>Hello</p><template><p>Secret template</p></template><script>var x='hidden'</script>"
                "<style>.a{}</style><p>World</p>", URL)
    assert doc.visible_text == "Hello World"


def test_inline_scripts_with_line_offsets():
    html = ("<!doctype html>\n<html>\n<head>\n<script nonce='abc' type=\"Module\">\nlet a = 1;\nlet b = '</div>';\n"
            "</script>\n<script src=/x.js></script>\n</head>\n<body><script>\nfoo()</script></body></html>")
    doc = parse(html, URL)
    assert len(doc.inline_scripts) == 2                  # <script src> is not inline
    s = doc.inline_scripts[0]
    assert s.nonce == "abc" and s.type == "module" and s.is_javascript
    assert "let b = '</div>';" in s.text                 # </div> inside a script stays script text
    assert s.line == 4 and html[s.offset:].startswith("\nlet a = 1;")
    assert s.line + s.text.split("\n").index("let b = '</div>';") == 6     # script line N → page line
    second = doc.inline_scripts[1]
    assert second.line == 10 and second.text == "\nfoo()"
    assert parse("<script type='application/ld+json'>{}</script>", URL).inline_scripts[0].is_javascript is False


def test_inline_styles_recorded():
    doc = parse('<style>@import url(http://a.test/x.css);</style><div style="background:url(http://b.test/i.png)"></div>', URL)
    assert doc.inline_styles[0].text.startswith("@import")
    assert doc.find_all("div")[0].get("style") == "background:url(http://b.test/i.png)"


def test_forms_controls_and_form_attribute():
    html = ('<form id="login" action="/session" method="POST"><input name=u><input type=password name=p>'
            '<button formaction="http://x.test/">go</button></form>'
            '<input type=hidden name=csrf form=login>'
            '<form><input type=file name=f></form>')
    doc = parse(html, URL)
    assert len(doc.forms) == 2
    login, upload = doc.forms
    assert login.action == "https://shop.example.test/session" and login.method == "post"
    assert login.effective_method() == "post"
    names = [doc.elements[i].get("name") for i in login.inputs]
    assert names == ["u", "p", None, "csrf"]
    assert upload.action == URL and upload.action_attr is None and upload.effective_method() == "get"
    assert doc.has_password_field and len(doc.password_inputs()) == 1


def test_nested_form_start_tag_is_ignored_like_a_browser():
    doc = parse('<form action="/a"><form action="http://evil.test/"><input name=x></form>', URL)
    assert len(doc.forms) == 1 and doc.forms[0].action == "https://shop.example.test/a"
    assert [doc.elements[i].get("name") for i in doc.forms[0].inputs] == ["x"]


def test_head_detection_for_meta():
    doc = parse('<html><meta http-equiv="Content-Security-Policy" content="default-src \'self\'"><title>x</title>'
                '<p>body starts</p><meta http-equiv="Content-Security-Policy" content="script-src *"></html>', URL)
    head = doc.metas(http_equiv="content-security-policy", head_only=True)
    assert [m.get("content") for m in head] == ["default-src 'self'"]
    assert len(doc.metas(http_equiv="Content-Security-Policy")) == 2
    explicit = parse("<head><noscript><meta http-equiv=refresh content='0;url=/n'></noscript></head><body></body>", URL)
    assert explicit.find_all("meta", live_only=False)[0].in_head


def test_links_and_metas_helpers():
    doc = parse('<link rel="Stylesheet preload" href="/a.css"><link rel=icon href=/f.ico><meta name=generator content="WordPress 6.4">',
                URL)
    assert [e.get("href") for e in doc.links("stylesheet")] == ["/a.css"]
    assert doc.metas(name="generator")[0].get("content") == "WordPress 6.4"


@pytest.mark.parametrize("html", [
    "<div><p>unclosed <b>bold <i>italic",
    "</div></span><p>stray end tags</p></table>",
    "<script>if (a < b && c > d) { document.write('</div><div>') }",            # unterminated script
    "<div attr='unterminated><p>x</p>",
    "<!-- unterminated comment <script>alert(1)</script>",
    "<![CDATA[ x ]]><svg><path d='M0'/><script>s()</script></svg><p>after</p>",
    "<a href=\"x\"\x00 onclick=y>nul</a>",
    "<<<>>><><//></ ><p>ok</p>",
    "<table><tr><td>a<td>b</table><select><option>1<option>2</select>",
    "<textarea><b>not a tag</b></textarea><title><i>t</i></title>",
])
def test_malformed_html_never_raises(html):
    doc = parse(html, URL)
    assert doc.url == URL
    assert isinstance(doc.elements, list)


def test_unclosed_script_keeps_text_and_svg_self_closing():
    doc = parse("<svg><path d='M0'/><circle/></svg><p id=after>x</p>", URL)
    p = doc.elements[doc.ids["after"]]
    assert doc.elements[p.parent].tag != "circle"       # self-closing in SVG does not swallow the rest
    s = parse("<p>x</p><script>var a = '</div>'; // no end", URL)
    assert s.inline_scripts and "var a = '</div>'" in s.inline_scripts[0].text


def test_parse_response_uses_charset():
    body = "<p>مرحبا</p>".encode("windows-1256")
    r = Response("https://a.test/", headers=HeaderList.of(("Content-Type", "text/html; charset=windows-1256")), body=body)
    assert parse_response(r).visible_text == "مرحبا"


def test_srcset_and_meta_refresh_helpers():
    assert srcset_urls("a.png 1x, http://b.test/b.png 2x,c.png") == ["a.png", "http://b.test/b.png", "c.png"]
    assert srcset_urls("data:image/png;base64,AAAA 1x, x.png 2x") == ["data:image/png;base64,AAAA", "x.png"]
    assert srcset_urls("") == []
    assert parse_meta_refresh("0;url=http://x.test/") == (0.0, "http://x.test/")
    assert parse_meta_refresh("5; URL='https://y.test/a b'") == (5.0, "https://y.test/a b")
    assert parse_meta_refresh("3") == (3.0, None)
    assert parse_meta_refresh("nonsense") is None
    assert line_of("a\nb\nc", 4) == 3


def test_two_megabyte_tag_dense_page_is_fast_enough():
    row = ('<div class="item" id="i{n}"><a href="/p/{n}?x=1">Item {n}</a> <span data-v="{n}">text &amp; more</span>'
           '<img src="/i/{n}.png" alt=""></div>\n')
    page = ("<!doctype html><html><head><title>t</title></head><body>"
            + "".join(row.format(n=i) for i in range(16000)) + "</body></html>")[:2_000_000]
    assert len(page) == 2_000_000
    best = 9e9
    for _ in range(2):
        t0 = time.perf_counter()
        doc = parse(page, URL)
        best = min(best, time.perf_counter() - t0)
    assert len(doc.elements) > 50_000
    assert best <= 1.5, f"light DOM over 2 MB took {best:.2f}s (budget 1.5 s, spec §4.3)"
