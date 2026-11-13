"""Accuracy regressions found by scanning benign framework defaults and their broken twins (1.1.0 verification).

Each test pins one real-world output format that the labelled corpus did not cover:

* Express/finalhandler's default development error page joins the stack with ``<br> &nbsp; &nbsp;at …`` on one line
  (WEB056 missed it); production Express only says "Internal Server Error" (trap).
* ASP.NET Core's Developer Exception Page is a debug page (WEB605), like the classic YSOD.
* WordPress bundles libraries under ``/wp-includes/js/``: their ``?ver=`` is the library's version (jQuery 3.7.1,
  jQuery Migrate 3.4.1), not WordPress's; only core assets carry the WordPress version.
* A site whose entry URL answers with an error page that carries HSTS (a 500 or 404) has HSTS: browsers note the header
  whatever the status, so a ``/robots.txt`` served without it must not turn into "Missing Strict-Transport-Security".
"""

from __future__ import annotations

import pytest

from vulnscan.webscan import classify, coverage, disclosure, htmlparse, tech, transport
from vulnscan.webscan.rules import validate_issue
from vulnscan.webscan.types import HeaderList, Page, Response, ScanOptions

URL = "https://app.example.test/"
HSTS = ("Strict-Transport-Security", "max-age=31536000; includeSubDomains")


def _resp(url=URL, status=200, headers=(), body="", ctype="text/html; charset=utf-8", kind=None) -> Response:
    hl = list(headers)
    if ctype:
        hl.append(("Content-Type", ctype))
    r = Response(url=url, status=status, headers=HeaderList.of(*hl), body=body.encode("utf-8"), ip="203.0.113.7")
    if kind:
        r.kind = kind
    return r


def _ctx(make_ctx, entry: Response, sensitivity="default", **fields):
    doc = htmlparse.parse_response(entry) if entry.body and "html" in (entry.headers.first("content-type") or "") else None
    if not entry.kind:
        classify.classify(entry, doc)
    pages = [Page(entry, doc)] if entry.kind == "document" else []
    ctx = make_ctx(target=URL, entry=None, sensitivity=sensitivity, pages=pages, **fields)
    ctx.entry = entry
    ctx.coverage = coverage.Coverage()
    return ctx


def _rules(issues, options=None) -> dict[str, list]:
    out: dict[str, list] = {}
    for i in issues:
        assert not validate_issue(i), (i.rule, validate_issue(i))
        if options is None or options.reports(i.confidence):
            out.setdefault(i.rule, []).append(i)
    return out


# ----------------------------------------------------------------------------------------------- WEB056 / WEB605

# finalhandler: escapeHtml(err.stack).replace(/\n/g, "<br>").replace(/\x20{2}/g, " &nbsp;") inside <pre>
EXPRESS_DEV = ('<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>Error</title>\n</head>\n<body>\n'
               "<pre>TypeError: Cannot read properties of undefined (reading &#39;id&#39;)<br> &nbsp; &nbsp;at "
               "/home/node/app/routes/index.js:14:22<br> &nbsp; &nbsp;at Layer.handle [as handle_request] "
               "(/home/node/app/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next "
               "(/home/node/app/node_modules/express/lib/router/route.js:149:13)</pre>\n</body>\n</html>\n")
EXPRESS_PROD = ('<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>Error</title>\n</head>\n<body>\n'
                "<pre>Internal Server Error</pre>\n</body>\n</html>\n")


def test_express_development_error_page_is_a_stack_trace(make_ctx):
    (i,) = _rules(disclosure.run(_ctx(make_ctx, _resp(status=500, body=EXPRESS_DEV))))["WEB056"]
    assert i.confidence == "firm" and i.evidence.match["name"] == "Node.js"


def test_express_production_error_page_is_clean(make_ctx):
    got = _rules(disclosure.run(_ctx(make_ctx, _resp(status=500, body=EXPRESS_PROD))))
    assert not {"WEB056", "WEB605", "WEB607"} & set(got)


def test_br_joined_frames_in_a_200_tutorial_stay_tentative(make_ctx):
    """The same markup in a 2xx document inside <pre> is documentation (D16): tentative, hidden at default."""
    issues = disclosure.run(_ctx(make_ctx, _resp(status=200, body=EXPRESS_DEV.replace("<title>Error", "<title>Docs"))))
    (i,) = _rules(issues)["WEB056"]
    assert i.confidence == "tentative"
    assert "WEB056" not in _rules(issues, ScanOptions())


ASPNETCORE_DEV = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" /><title>Internal Server Error</title></head><body>'
    '<h1>An unhandled exception occurred while processing the request.</h1><div class="titleerror">InvalidOperationException: '
    'Unable to resolve service for type &#x27;WebApp.IRepo&#x27;.</div><div id="stackpage" class="page"><ul><li>'
    '<h2 class="stackerror">InvalidOperationException</h2></li></ul><div class="rawExceptionBlock"><div '
    'class="rawExceptionDetails"><pre class="rawExceptionStackTrace">System.InvalidOperationException: Unable to resolve '
    "service.\r\n   at Microsoft.Extensions.DependencyInjection.ActivatorUtilities.GetService(IServiceProvider sp, Type type)"
    "\r\n   at lambda_method1(Closure , IServiceProvider , Object[] )</pre></div></div></div></body></html>")


def test_aspnetcore_developer_exception_page_is_debug_mode(make_ctx):
    got = _rules(disclosure.run(_ctx(make_ctx, _resp(status=500, body=ASPNETCORE_DEV))))
    (i,) = got["WEB605"]
    assert i.confidence == "certain" and (i.severity or "high") == "high"
    assert "WEB056" not in got                      # one cause: the debug page already reports the trace


def test_aspnetcore_page_quoted_in_a_blog_post_is_not_debug_mode(make_ctx):
    body = ("<html><body><h1>Turn it off</h1><p>The Developer Exception Page says <code>An unhandled exception occurred "
            'while processing the request.</code> and shows <code>id="stackpage"</code>.</p></body></html>')
    assert "WEB605" not in _rules(disclosure.run(_ctx(make_ctx, _resp(status=200, body=body))))


# ----------------------------------------------------------------------------------------------- WordPress version (WEB080/WEB081)

def _wp(make_ctx, scripts: str, sensitivity="default"):
    html = (f"<!doctype html><html><head>{scripts}"
            '<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css"></head><body></body></html>')
    return _ctx(make_ctx, _resp(body=html), sensitivity=sensitivity)


@pytest.mark.parametrize("sensitivity", ["default", "paranoid"])
def test_wordpress_version_is_not_taken_from_bundled_libraries(make_ctx, sensitivity):
    ctx = _wp(make_ctx, '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>'
                        '<script src="/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1"></script>'
                        '<script src="/wp-includes/js/mediaelement/mediaelement-and-player.min.js?ver=4.2.17"></script>',
              sensitivity)
    got = _rules(tech.run(ctx))
    (wp,) = [i for i in got["WEB080"] if i.params["id"] == "wordpress"]
    assert wp.params["version"] == "" and wp.params["platform"] == "WordPress"
    assert "WEB081" not in got


@pytest.mark.parametrize("asset", [
    '<script src="/wp-includes/js/wp-emoji-release.min.js?ver=6.1.1"></script>',
    '<link rel="stylesheet" id="wp-block-library-css" href="/wp-includes/css/dist/block-library/style.min.css?ver=6.1.1">',
    '<script src="/wp-includes/js/comment-reply.min.js?ver=6.1.1"></script>',
])
def test_wordpress_version_from_core_assets(make_ctx, asset):
    ctx = _wp(make_ctx, '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.6.1"></script>' + asset, "paranoid")
    got = _rules(tech.run(ctx))
    (wp,) = [i for i in got["WEB080"] if i.params["id"] == "wordpress"]
    assert wp.params["version"] == "6.1.1"
    assert all(i.params["version"] == "6.1.1" for i in got.get("WEB081", []))


# ----------------------------------------------------------------------------------------------- HSTS on an error entry

def _transport(ctx):
    out: dict[str, list] = {}
    for i in transport.run(ctx):
        assert validate_issue(i) == [], validate_issue(i)
        out.setdefault(i.rule, []).append(i)
    return out


def _robots(headers=()):
    return _resp(URL + "robots.txt", headers=headers, body="User-agent: *\nAllow: /\n", ctype="text/plain; charset=utf-8",
                 kind="text")


@pytest.mark.parametrize("status", [500, 404])
def test_error_entry_with_hsts_is_not_missing_hsts(make_ctx, status):
    entry = _resp(status=status, headers=[HSTS], body="<html><body><pre>Internal Server Error</pre></body></html>",
                  kind="error_page")
    ctx = _ctx(make_ctx, entry, wellknown={"/robots.txt": _robots()})
    ctx.hsts = transport.hsts_facts(ctx)
    assert ctx.hsts["app.example.test"].present and ctx.hsts["app.example.test"].effective
    got = _transport(ctx)
    assert "WEB-strict-transport-security" not in got
    assert ctx.coverage.state("WEB-strict-transport-security").state == "pass"


def test_error_entry_without_hsts_still_judges_the_2xx(make_ctx):
    entry = _resp(status=500, body="<html><body>oops</body></html>", kind="error_page")
    ctx = _ctx(make_ctx, entry, wellknown={"/robots.txt": _robots()})
    (i,) = _transport(ctx)["WEB-strict-transport-security"]
    assert i.url.endswith("/robots.txt")


def test_2xx_entry_without_hsts_is_still_missing(make_ctx):
    """The exception is only for an error entry: a 2xx entry without HSTS is judged as before."""
    ctx = _ctx(make_ctx, _resp(body="<html><body>ok</body></html>"), wellknown={"/robots.txt": _robots([HSTS])})
    (i,) = _transport(ctx)["WEB-strict-transport-security"]
    assert i.url == URL
