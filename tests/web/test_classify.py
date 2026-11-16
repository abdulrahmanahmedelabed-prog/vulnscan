"""Response classification (spec §3.1), WAF signatures, page roles and the §WEB315 sensitivity test (WP2).

Every kind and role row of §3.1 has a positive and a negative test; every WAF signature has a positive test and the
near-miss traps that must not match. Offline: synthetic responses only (plus the corpus' own WAF responses).
"""

from __future__ import annotations

import base64
import gzip
import pathlib
import re
import sys

import pytest

from vulnscan.webscan import classify as C
from vulnscan.webscan import htmlparse
from vulnscan.webscan.types import CookieFact, HeaderList, Page, Response

BENCH = pathlib.Path(__file__).resolve().parents[2] / "bench" / "web"


def R(status=200, headers=(), body=b"", url="https://example.test/", **kw) -> Response:
    if isinstance(body, str):
        body = body.encode("utf-8")
    return Response(url=url, status=status, headers=HeaderList.of(*headers), body=body, **kw)


HTML = [("Content-Type", "text/html; charset=utf-8")]


def page(body="", title="Page", head=""):
    return f"<!doctype html><html><head><title>{title}</title>{head}</head><body>{body}</body></html>"


def kind(resp):
    return C.kind_of(resp)[0]


# ----------------------------------------------------------------------------------------------- kinds (§3.1 rows)

def test_row1_error():
    assert kind(R(status=None, error="connection refused")) == "error"
    assert kind(R(status=200, error="too many headers")) == "error"
    assert kind(R(200, HTML, page("ok"))) != "error"


@pytest.mark.parametrize("status,expected", [(100, "informational"), (103, "informational"), (204, "no_content"),
                                             (205, "no_content"), (304, "not_modified")])
def test_row2_bodiless_statuses(status, expected):
    assert kind(R(status, HTML)) == expected


def test_row2_negative():
    assert kind(R(200, HTML, page("x"))) == "document"
    assert kind(R(206, [("Content-Type", "application/octet-stream")], b"\0\1")) == "download"


def test_row3_redirect_needs_location():
    assert kind(R(301, [("Location", "/home")])) == "redirect"
    assert kind(R(308, [("Location", "https://example.test/")])) == "redirect"
    # 3xx without Location is not a redirect (browsers render it)
    assert kind(R(300, HTML, page("choose"))) == "document"


def test_row5_rate_limited():
    assert kind(R(429, [("Content-Type", "text/plain")], "slow down")) == "rate_limited"
    assert kind(R(503, [("Retry-After", "1"), ("Content-Type", "text/plain")], "maintenance")) == "rate_limited"
    # negatives: 503 without Retry-After is an error page; Retry-After on a 200 is nothing
    assert kind(R(503, [("Content-Type", "text/plain")], "down")) == "error_page"
    assert kind(R(200, [("Retry-After", "5"), *HTML], page("x"))) == "document"
    assert "rate-limited" in C.kind_of(R(429))[1]


def test_row6_error_page():
    assert kind(R(404, HTML, page("<h1>Not found</h1>"))) == "error_page"
    assert kind(R(500, HTML, page("boom"))) == "error_page"
    assert kind(R(403, HTML, page("forbidden"))) == "error_page"
    assert kind(R(200, HTML, page("<h1>fine</h1>"))) == "document"


@pytest.mark.parametrize("ctype,body,expected", [
    ("text/html; charset=utf-8", page("x"), "document"),
    ("application/xhtml+xml", '<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"></html>', "document"),
    ("application/json", '{"a": 1}', "api_json"),
    ("application/problem+json", '{"title": "x"}', "api_json"),
    ("application/vnd.spring-boot.actuator.v3+json", "{}", "api_json"),
    ("application/xml", '<?xml version="1.0"?><feed/>', "api_xml"),
    ("text/xml", "<rss/>", "api_xml"),
    ("application/atom+xml", "<feed/>", "api_xml"),
    ("application/xml", '<?xml version="1.0"?><!-- c --><html><body/></html>', "document"),
    ("text/javascript", "var a;", "script"),
    ("application/javascript; charset=utf-8", "var a;", "script"),
    ("text/css", "a{}", "style"),
    ("image/png", b"\x89PNG\r\n\x1a\n", "image"),
    ("image/svg+xml", "<svg/>", "image"),
    ("font/woff2", b"wOF2", "font"),
    ("application/font-woff", b"wOFF", "font"),
    ("application/x-font-ttf", b"\0\1\0\0\0", "font"),
    ("audio/mpeg", b"ID3", "media"),
    ("video/mp4", b"\0\0\0\x18ftypmp42", "media"),
    ("application/pdf", b"%PDF-1.7", "download"),
    ("application/octet-stream", b"\0\1\2", "download"),
    ("application/zip", b"PK\x03\x04", "download"),
    ("application/gzip", b"\x1f\x8b\x08", "download"),
    ("text/plain", "hello", "text"),
    ("text/csv", "a,b", "text"),
    ("application/x-unknown-thing", "??", "other"),
])
def test_row7_content_type_essence(ctype, body, expected):
    assert kind(R(200, [("Content-Type", ctype)], body)) == expected


def test_row7_attachment_is_download():
    r = R(200, [("Content-Type", "text/html"), ("Content-Disposition", 'attachment; filename="r.html"')], page("x"))
    assert kind(r) == "download"
    inline = R(200, [("Content-Type", "text/html"), ("Content-Disposition", "inline")], page("x"))
    assert kind(inline) == "document"


@pytest.mark.parametrize("body,expected", [
    (b"<!DOCTYPE html><html><body>x</body></html>", "document"),
    (b"\xef\xbb\xbf  <html lang=en>", "document"),
    (b"<HTML>", "document"),
    (b'{"ok": true}', "api_json"),
    (b"[1, 2]", "api_json"),
    (b'<?xml version="1.0"?><root/>', "api_xml"),
    (b"\x89PNG\r\n\x1a\n....", "image"),
    (b"GIF89a....", "image"),
    (b"\xff\xd8\xff\xe0", "image"),
    (b"%PDF-1.4", "download"),
    (b"PK\x03\x04....", "download"),
    (b"\x1f\x8b\x08\x00", "download"),
])
def test_row8_sniffed_without_content_type(body, expected):
    k, flags = C.kind_of(R(200, [], body))
    assert k == expected and "sniffed" in flags


def test_row8_negatives():
    # unknown bytes without a type stay "other", not a guessed document
    k, flags = C.kind_of(R(200, [], b"hello world"))
    assert k == "other" and "sniffed" not in flags
    # an empty Content-Type value counts as missing
    assert C.kind_of(R(200, [("Content-Type", "")], b"<html>"))[0] == "document"
    # a declared type wins over the magic bytes (no "sniffed" flag)
    k, flags = C.kind_of(R(200, [("Content-Type", "text/plain")], b"<html><body>x"))
    assert k == "text" and "sniffed" not in flags and "magic:text/html" in flags
    # CSS / JS blocks are not JSON
    assert C.sniff(b"{ color: red }") is None and C.sniff(b"{\n  var x = 1;\n}") is None


def test_sniff_table():
    assert C.sniff(b"\x7fELF\x02\x01") == "application/x-executable"
    assert C.sniff(b"MZ" + b"\0" * 58 + (64).to_bytes(4, "little") + b"PE\0\0") == "application/x-msdownload"
    assert C.sniff(b"\0\0\0\x01Bud1\0\0") == "application/x-apple-ds-store"
    assert C.sniff(b"RIFF\0\0\0\0WEBPVP8 ") == "image/webp"
    assert C.sniff(b"Rar!\x1a\x07\x00") == "application/vnd.rar"
    assert C.sniff(b"7z\xbc\xaf\x27\x1c") == "application/x-7z-compressed"
    assert C.sniff(b"BZh91AY") == "application/x-bzip2"
    assert C.sniff(b"x" * 257 + b"ustar\x0000") == "application/x-tar"
    assert C.sniff(b"<?xml version='1.0'?><svg xmlns='http://www.w3.org/2000/svg'/>") == "image/svg+xml"
    assert C.sniff(b"<p>para</p>") == "text/html" and C.sniff(b"<pre>") is None   # "<p" needs a tag end
    assert C.sniff(b"") is None
    assert C.xml_root(b'<?xml version="1.0"?>\n<!DOCTYPE html PUBLIC "x" "y">\n<html/>') == "html"
    assert C.xml_root(b"<x:Envelope xmlns:x='u'/>") == "envelope"


def test_ctype_mismatch_matches_web313_cases():
    assert C.ctype_mismatch(R(200, [("Content-Type", "image/png")], page("x"))) == ("image/png", "text/html")
    assert C.ctype_mismatch(R(200, [("Content-Type", "text/html")], '{"user": 1}')) == ("text/html", "application/json")
    assert C.ctype_mismatch(R(200, [("Content-Type", "text/plain")], b"PK\x03\x04zip")) == ("text/plain", "application/zip")
    assert C.ctype_mismatch(R(200, [("Content-Type", "text/plain")], b"\x7fELF\x02")) is not None
    # traps: consistent types, a JSON-looking but invalid body, an opaque (br) body, no body
    assert C.ctype_mismatch(R(200, [("Content-Type", "application/json")], '{"a": 1}')) is None
    assert C.ctype_mismatch(R(200, [("Content-Type", "text/html")], '{"broken": ')) is None
    assert C.ctype_mismatch(R(200, [("Content-Type", "text/plain")], b"PK\x03\x04", encoding="br")) is None
    assert C.ctype_mismatch(R(200, [("Content-Type", "image/png")], b"")) is None
    k, flags = C.kind_of(R(200, [("Content-Type", "text/html")], '{"user": 1}'))
    assert k == "document" and "ctype-mismatch" in flags


def test_opaque_coding_flag_and_no_sniffing():
    r = R(200, [("Content-Type", "text/html"), ("Content-Encoding", "br")], b"\x8b\x02\x80<html", encoding="br")
    k, flags = C.kind_of(r)
    assert k == "document" and "opaque-coding" in flags and not any(f.startswith("magic:") for f in flags)
    assert "opaque-coding" not in C.kind_of(R(200, HTML, page("x"), encoding="gzip"))[1]
    assert "truncated-body" in C.kind_of(R(200, HTML, page("x"), truncated=True))[1]


# ----------------------------------------------------------------------------------------------- WAF (11 signatures)

CF_PAGE = page('<div id="challenge-platform"></div>', title="Just a moment...")

WAF_POSITIVE = [
    ("cloudflare", R(403, [("cf-mitigated", "challenge"), *HTML], "x")),
    ("cloudflare", R(503, [("Server", "cloudflare"), *HTML], CF_PAGE)),
    ("cloudflare", R(403, [("Server", "cloudflare"), *HTML], page('<script src="/cdn-cgi/x?cf-chl-tk=1"></script>'))),
    ("akamai", R(403, [("Server", "AkamaiGHost"), *HTML],
                 "<H1>Access Denied</H1>Reference&#32;&#35;18&#46;1a2b3c4d&#46;1700000000")),
    ("cloudfront", R(403, [("X-Cache", "Error from cloudfront"), *HTML], page("The request could not be satisfied."))),
    ("aws-waf", R(403, [("x-amzn-waf-action", "captcha"), *HTML], page("<h1>403 Forbidden</h1>"))),
    ("aws-waf", R(405, [*HTML], page('<script>window.awsWafCookieDomainList=[];</script><p>aws-waf-token</p>'))),
    ("imperva", R(200, HTML, page("Request unsuccessful. Incapsula incident ID: 123000450123"))),
    ("imperva", R(403, [("X-Iinfo", "1-2-3 NNNN CT(0 0 0) RT(1 0) q(0 0 0 -1) r(0 0) U5"), *HTML], page("blocked"))),
    ("sucuri", R(403, [("X-Sucuri-ID", "11005"), *HTML], page("Sucuri WebSite Firewall - Access Denied"))),
    ("f5-asm", R(200, HTML, page("The requested URL was rejected. Please consult with your administrator.<br>"
                                 "Your support ID is: 1234567890123456789"))),
    ("azure-front-door", R(403, [("x-azure-ref", "0abc"), *HTML], page("The request is blocked."))),
    ("datadome", R(403, [("X-DataDome", "protected"), *HTML], page("blocked"))),
    ("datadome", R(403, [("x-dd-b", "1"), *HTML], page("blocked"))),
    ("perimeterx", R(403, HTML, page('<div id="px-captcha"></div><p>Press &amp; Hold to confirm you are a human</p>'))),
    ("perimeterx", R(200, HTML, page("<script>window._pxCaptcha = 1;</script>"))),
    ("recaptcha", R(429, HTML, page('<script src="https://www.google.com/recaptcha/api.js"></script>'
                                    '<div class="g-recaptcha"></div>'))),
]


@pytest.mark.parametrize("provider,resp", WAF_POSITIVE, ids=[f"{p}-{i}" for i, (p, _r) in enumerate(WAF_POSITIVE)])
def test_waf_signatures(provider, resp):
    assert C.waf_provider(resp) == provider
    k, flags = C.kind_of(resp)
    assert k == "waf_challenge" and f"waf:{provider}" in flags
    assert C.waf_name(provider) == C.WAF_PROVIDERS[provider]


def test_all_eleven_providers_have_a_positive_case():
    assert len(C.WAF_PROVIDERS) == 11
    assert {p for p, _ in WAF_POSITIVE} == set(C.WAF_PROVIDERS)


WAF_TRAPS = [
    R(200, [("Server", "cloudflare"), ("CF-RAY", "8f00aa11bb22cc33-FRA"), *HTML], page("normal site")),
    R(404, [("Server", "cloudflare"), *HTML], page("Just a moment...", title="Just a moment...")),   # not 403/503
    R(403, [("Server", "cloudflare"), *HTML], page("<h1>Forbidden</h1>")),   # no challenge markup
    R(200, [("Server", "AkamaiGHost"), *HTML], page("Reference #18.1a2b")),   # not 403
    R(403, [("Server", "nginx"), *HTML], page("Reference #18.1a2b")),         # not Akamai
    R(200, [("X-Cache", "Hit from cloudfront"), *HTML], page("ok")),
    R(404, [("X-Cache", "Error from cloudfront"), *HTML], page("missing")),   # a real 404 through CloudFront
    R(200, [("x-amzn-waf-action", "count"), *HTML], page("ok")),              # WAF counted, page served
    R(200, [("X-Iinfo", "1-2-3"), *HTML], page("normal Incapsula-fronted page")),
    R(200, [("X-Sucuri-ID", "11005"), *HTML], page("ok")),
    R(200, HTML, page("Our blog: what does 'The requested URL was rejected' mean?")),
    R(200, [("x-azure-ref", "0abc"), *HTML], page("ok")),
    R(200, [("X-DataDome", "protected"), *HTML], page("ok")),
    R(200, HTML, page("Press & Hold the button to record a voice note")),
    R(200, HTML, page('<form><div class="g-recaptcha"></div></form><script src="https://www.google.com/recaptcha/api.js">'
                      "</script>")),                                          # a contact form with reCAPTCHA
]


@pytest.mark.parametrize("resp", WAF_TRAPS)
def test_waf_traps(resp):
    assert C.waf_provider(resp) is None
    assert C.kind_of(resp)[0] != "waf_challenge"


def test_waf_wins_over_rate_limit_and_error_page():
    r = R(503, [("Server", "cloudflare"), ("Retry-After", "5"), *HTML], CF_PAGE)
    assert kind(r) == "waf_challenge"
    assert kind(R(429, [("Retry-After", "5"), *HTML], page("too many"))) == "rate_limited"


def _corpus():
    if str(BENCH) not in sys.path:
        sys.path.insert(0, str(BENCH))
    try:
        import corpus  # type: ignore
    except Exception as e:   # pragma: no cover - bench/ is not shipped in the sdist
        pytest.skip(f"corpus not importable: {e}")
    return corpus


def _render(text: str) -> str:
    def sub(m):
        tok = m.group(1)
        return {"NONCE": base64.b64encode(b"n" * 18).decode(), "RAND": "0" * 32, "HOST": "waf.kashif.test",
                "SELF": "https://waf.kashif.test"}.get(tok, "https://waf.kashif.test")
    return re.sub(r"\{(HOST|SELF|HTTPS|HTTP|THIRD|NONCE|RAND|EXPIRES|PAST|HTTP_PORT|HTTPS_PORT|CASE)(?::[a-z0-9-]+)?\}",
                  sub, text)


def corpus_response(r, url="https://waf.kashif.test/") -> Response:
    body = _render(r.body).encode("utf-8") if isinstance(r.body, str) else r.body
    return Response(url=url, status=r.status, headers=HeaderList.of(*[tuple(h) for h in r.headers]), body=body)


def test_corpus_waf_cases_classify_as_challenges():
    corpus = _corpus()
    cases = {c.id: c for c in corpus.CASES}
    expected = {"waf-cloudflare": "cloudflare", "waf-akamai": "akamai", "waf-aws": "aws-waf"}
    for cid, provider in expected.items():
        resp = corpus_response(cases[cid].routes["*"])
        assert C.waf_provider(resp) == provider, cid
        assert kind(resp) == "waf_challenge"
    # 503 + Retry-After twice: rate limited, not a WAF
    assert kind(corpus_response(cases["waf-503-twice"].routes["*"])) == "rate_limited"
    # the deep-probe-only WAF case: the entry page is a normal document
    entry = corpus_response(cases["waf-deep-probe-only"].routes["/"])
    assert kind(entry) == "document"


# ----------------------------------------------------------------------------------------------- page roles

def roles_of(html, url="https://example.test/", status=200):
    resp = R(status, HTML, html, url=url)
    return C.page_roles(resp, htmlparse.parse_response(resp))


LOGIN_FORM = ('<form method="post" action="/session"><input name="user" autocomplete="username">'
              '<input type="password" name="pw" autocomplete="current-password"><button>Sign in</button></form>')


def test_role_login():
    assert "login" in roles_of(page(LOGIN_FORM))
    assert "login" in roles_of(page('<input type="password" name="p">'))                    # SPA login, no form
    assert "login" in roles_of(page('<form action="/wp-login.php" method="post"><input name="log"></form>'))
    assert "login" in roles_of(page('<form action="/users/sign-in"><input name="email"></form>'))
    # negatives: no password and an unrelated action; a password inside <template>; a logout form to /session
    assert "login" not in roles_of(page('<form action="/search"><input name="q"></form>'))
    assert "login" not in roles_of(page('<form action="/authors/new"><input name="name"></form>'))
    assert "login" not in roles_of(page('<template><input type="password"></template>'))
    assert "login" not in roles_of(page('<form action="/session" method="post"><input type="hidden" name="_method" '
                                        'value="delete"><button>Log out</button></form>'))


def test_role_signup():
    assert roles_of(page('<form method=post action="/join"><input type="password" autocomplete="new-password">'
                         "</form>")) >= {"signup"}
    two = roles_of(page('<form method=post action="/join"><input type="password" name="a">'
                        '<input type="password" name="b"></form>'))
    assert "signup" in two and "login" not in two
    assert "signup" not in roles_of(page(LOGIN_FORM))
    # change-password form: current + new → both
    both = roles_of(page('<form method=post><input type="password" autocomplete="current-password">'
                         '<input type="password" autocomplete="new-password"></form>'))
    assert both >= {"signup", "login"}


def test_role_authenticated():
    assert "authenticated" in roles_of(page('<nav><a href="/account/logout">Log out</a></nav>'))
    assert "authenticated" in roles_of(page('<div class="user-menu">me</div>'))
    assert "authenticated" in roles_of(page('<p>hi</p>').replace("<body>", '<body class="home logged-in">'))
    assert "authenticated" not in roles_of(page('<a href="/blog/login-tips">Tips</a><p>Sign out is easy.</p>'))


def test_role_admin():
    admin_login = page(LOGIN_FORM, title="Log in | Django site admin")
    assert "admin" in roles_of(admin_login, url="https://example.test/admin/login/")
    assert "admin" in roles_of(page('<div id="adminmenu"></div>', title="Dashboard"), url="https://example.test/wp-admin/")
    # negatives: admin path without markers; admin markers on a non-admin path
    assert "admin" not in roles_of(page("<p>Our administration team</p>", title="Team"),
                                   url="https://example.test/administrative-staff")
    assert "admin" not in roles_of(page("<p>news</p>", title="News"), url="https://example.test/admin/")
    assert "admin" not in roles_of(page(LOGIN_FORM, title="Admin login"), url="https://example.test/login")


def test_role_api_docs():
    assert "api_docs" in roles_of(page('<div id="swagger-ui"></div><script src="./swagger-ui-bundle.js"></script>',
                                       title="Swagger UI"))
    assert "api_docs" in roles_of(page('<redoc spec-url="/openapi.json"></redoc>'))
    assert "api_docs" in roles_of(page('<div id="graphiql">Loading...</div>'))
    assert "api_docs" not in roles_of(page("<p>We publish an OpenAPI spec and use Swagger internally.</p>"))


def test_role_error():
    assert "error" in roles_of(page("<h1>Page not found</h1>", title="Oops"))
    assert "error" in roles_of(page("<p>x</p>", title="404"))
    assert "error" in roles_of(page("<h1>Error</h1>", title="Site"))
    # negatives: a long article title that mentions errors; a real 404 status is error_page, not a 2xx role
    assert "error" not in roles_of(page("<h1>Handling errors in Python: a complete guide to exceptions</h1>",
                                        title="Blog"))
    assert "error" not in roles_of(page("<h1>Page not found</h1>"), status=404)


def test_role_listing():
    nginx = ("<html><head><title>Index of /files/</title></head><body><h1>Index of /files/</h1><hr><pre>"
             '<a href="../">../</a>\n<a href="r.pdf">r.pdf</a></pre></body></html>')
    assert C.listing_server(nginx) == "nginx" and "listing" in roles_of(nginx)
    apache = '<title>Index of /x</title><a href="?C=N;O=D">Name</a><a href="/">Parent Directory</a>'
    assert C.listing_server(apache) == "Apache"
    assert C.listing_server('<pre><A HREF="/">[To Parent Directory]</A></pre>') == "IIS"
    assert C.listing_server("<title>Directory listing for /</title><ul><li><a href=\"a\">a</a></ul>") == "Python"
    # trap: a blog post titled "Index of /blog" without file links (corpus disc-blog-index-of)
    blog = page("<h1>Index of /blog posts</h1><p>An essay about directory listings.</p>", title="Index of /blog")
    assert C.listing_server(blog) is None and "listing" not in roles_of(blog)


def test_role_app_and_static():
    spa = page('<div id="root"></div><noscript>Login to continue</noscript><script src="/static/app.js"></script>')
    r = roles_of(spa)
    assert "app" in r and "login" not in r and "static" not in r
    assert "app" not in roles_of(page("<div id='root'><p>" + "word " * 200 + "</p></div><script src='a.js'></script>"))
    static = page("<h1>About us</h1><p>We sell bread.</p><img src='/b.png'>")
    assert roles_of(static) == {"static"}
    # not static: a form, a script, an inline handler or a javascript: link
    assert "static" not in roles_of(page("<form><input name=q></form>"))
    assert "static" not in roles_of(page("<p>x</p><script>1</script>"))
    assert "static" not in roles_of(page('<button onclick="go()">x</button>'))
    assert "static" not in roles_of(page('<a href="javascript:void(0)">x</a>'))


def test_classify_sets_fields_and_is_idempotent():
    resp = R(200, HTML, page(LOGIN_FORM), url="https://example.test/login")
    resp.flags = frozenset({"obs-fold"})
    C.classify(resp)
    assert resp.kind == "document" and "login" in resp.roles and "obs-fold" in resp.flags
    C.classify(resp)
    assert resp.kind == "document" and "login" in resp.roles
    # roles only for documents
    api = C.classify(R(200, [("Content-Type", "application/json")], '{"password": "x"}'))
    assert api.kind == "api_json" and api.roles == frozenset()
    # an earlier soft404 verdict survives a re-classification
    soft = R(200, HTML, page("x"))
    soft.kind = "soft404"
    assert C.classify(soft).kind == "soft404"


def test_classify_uses_given_dom():
    resp = R(200, HTML, page("<p>no form here</p>"))
    fake = htmlparse.parse(page(LOGIN_FORM), resp.url)
    assert "login" in C.classify(resp, fake).roles


# ----------------------------------------------------------------------------------------------- is_sensitive (§WEB315)

def cookie(resp, name, cls, **kw) -> CookieFact:
    return CookieFact(name=name, value="v" * 20, attrs={}, raw=f"{name}=x", response=resp, host=resp.host,
                      secure_context=True, cls=cls, **kw)


def test_is_sensitive_table():
    base = R(200, HTML, page("<p>hello</p>"))
    assert not C.is_sensitive(base)
    # 1 session/auth cookie set by the response
    assert C.is_sensitive(base, cookies=[cookie(base, "sessionid", "session")])
    assert C.is_sensitive(base, cookies=[cookie(base, "jwt", "auth")])
    assert not C.is_sensitive(base, cookies=[cookie(base, "_ga", "analytics"), cookie(base, "lang", "preference")])
    assert not C.is_sensitive(base, cookies=[cookie(base, "sessionid", "session", deletion=True)])
    assert not C.is_sensitive(base, cookies=[cookie(base, "sessionid", "session", ignored=True)])
    assert not C.is_sensitive(base, cookies=[cookie(base, "visitor", "unknown_secret")])
    # 2 a password field in the document
    login = R(200, HTML, page(LOGIN_FORM))
    assert C.is_sensitive(login, doc=htmlparse.parse_response(login))
    assert not C.is_sensitive(base, doc=htmlparse.parse_response(base))
    # 3 page role
    for role in ("login", "authenticated", "admin"):
        r = R(200, HTML, page("x"))
        r.roles = frozenset({role})
        assert C.is_sensitive(r), role
    r = R(200, HTML, page("x"))
    r.roles = frozenset({"static", "app", "api_docs"})
    assert not C.is_sensitive(r)
    # 4 status 401
    assert C.is_sensitive(R(401, [("WWW-Authenticate", "Basic")]))
    assert not C.is_sensitive(R(403, HTML, page("no")))
    # 5 Vary: Cookie / Authorization (any field, any case)
    assert C.is_sensitive(R(200, [("Vary", "Accept-Encoding, Cookie")], b"x"))
    assert C.is_sensitive(R(200, [("Vary", "Origin"), ("vary", "authorization")], b"x"))
    assert not C.is_sensitive(R(200, [("Vary", "Accept-Encoding, Origin, Cookie-Consent")], b"x"))


def test_mark_sensitive_over_context(make_ctx):
    entry = R(200, HTML, page(LOGIN_FORM), url="https://example.test/login", source="entry")
    page_obj = Page(entry, htmlparse.parse_response(entry))
    asset = R(200, [("Content-Type", "text/css")], b"a{}", url="https://example.test/a.css", source="subresource")
    api = R(200, [("Content-Type", "application/json"), ("Set-Cookie", "sid=1")], b"{}", url="https://example.test/api",
            source="crawl")
    ctx = make_ctx(entry=page_obj, subresources=[asset], pages=[Page(api, None)])
    ctx.cookies = [cookie(api, "sid", "session")]
    assert C.mark_sensitive(ctx) == 2
    assert "sensitive" in entry.flags and "sensitive" in api.flags and "sensitive" not in asset.flags


def test_gzip_body_is_classified_after_decoding():
    # http.py decodes gzip/deflate before classification; the "encoding" field only records the wire coding
    body = page("<p>x</p>").encode()
    assert gzip.decompress(gzip.compress(body)) == body
    assert C.kind_of(R(200, HTML, body, encoding="gzip"))[0] == "document"


def test_strings_are_bilingual():
    for key, (en, ar) in C.STR.items():
        assert en and ar and en != ar, key
        assert re.search(r"[؀-ۿ]", ar), key
        assert set(re.findall(r"\{(\w+)\}", en)) == set(re.findall(r"\{(\w+)\}", ar)), key


# ----------------------------------------------------------------------------------------------- adversarial review

def test_deeply_nested_json_in_html_does_not_crash():
    """"[" * 200000 served as text/html: json.loads raises RecursionError (not ValueError); classification survives."""
    resp = R(200, HTML, b"[" * 200_000)
    k, flags = C.kind_of(resp)
    assert k == "document" and "ctype-mismatch" not in flags
    C.classify(resp)
    C.signature(resp)


JSD = ("<script>(function(){var a=document.createElement('script');a.src='/cdn-cgi/challenge-platform/scripts/jsd/"
       "main.js';document.head.appendChild(a);})();</script>")


def test_cloudflare_injected_bot_script_is_not_a_challenge():
    """Cloudflare's JS detections put /cdn-cgi/challenge-platform/scripts/jsd/main.js in every HTML page, origin
    error pages included: an application 403/503 behind Cloudflare is an error page, not a WAF challenge."""
    for status in (403, 503):
        resp = R(status, [("Server", "cloudflare"), *HTML], page("<h1>Forbidden</h1>" + JSD, title="403"))
        assert C.waf_provider(resp) is None
        assert kind(resp) == "error_page"
    # the challenge itself still matches (orchestrate path, element id, title, cf-mitigated)
    chl = R(403, [("Server", "cloudflare"), *HTML],
            page('<script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1?ray=1"></script>' + JSD))
    assert C.waf_provider(chl) == "cloudflare"


@pytest.mark.parametrize("ctype,body", [
    ("application/javascript", "window._pxCaptcha=function(){};document.getElementById('px-captcha')"),
    ("text/javascript", "/* The requested URL was rejected. Please consult with your administrator. support ID */"),
    ("application/json", '{"faq": "What is an Incapsula incident ID?"}'),
    ("text/plain", "Incapsula incident ID: 1"),
])
def test_waf_body_markers_on_2xx_need_an_html_page(ctype, body):
    """A first-party sensor script, a WAF SDK or a JSON FAQ that contains a marker string is served normally."""
    resp = R(200, [("Content-Type", ctype)], body)
    assert C.waf_provider(resp) is None
    assert kind(resp) != "waf_challenge"


def test_waf_body_markers_on_error_status_any_type():
    # a JSON block response (403) still counts: only 2xx responses need an HTML page
    resp = R(403, [("Content-Type", "application/json")], '{"blockScript": "/x", "msg": "Incapsula incident ID: 9"}')
    assert C.waf_provider(resp) == "imperva"


def test_listing_signature_must_be_title_or_h1():
    article = page("<h1>Hardening Python's http.server</h1><p>By default it shows 'Directory listing for /' to "
                   "everyone.</p><a href='/blog'>Blog</a>", title="Hardening http.server")
    assert C.listing_server(article) is None
    assert "listing" not in roles_of(article)
    tomcat = ('<html><head><title>Directory Listing For [/]</title></head><body><h1>Directory Listing For [/]</h1>'
              '<table><tr><td><a href="/a.txt">a.txt</a></td></tr></table><h3>Apache Tomcat/9.0</h3></body></html>')
    assert C.listing_server(tomcat) == "Tomcat"
    python = ("<!DOCTYPE HTML><html><head><title>Directory listing for /</title></head><body>"
              "<h1>Directory listing for /</h1><ul><li><a href=\"a.txt\">a.txt</a></li></ul></body></html>")
    assert C.listing_server(python) == "Python"


@pytest.mark.parametrize("href", ["/catalog-offers", "/design-outline", "/blog/dialog-off-canvas", "/backlog-outline"])
def test_logout_words_inside_other_words_are_not_logout_links(href):
    roles = roles_of(page(f'<a href="{href}">x</a>'))
    assert "authenticated" not in roles


@pytest.mark.parametrize("href", ["/user/logout", "/sign_out", "/wp-login.php?action=logout", "/LogOff.aspx",
                                  "/auth/sign-out"])
def test_logout_links_still_mark_authenticated(href):
    assert "authenticated" in roles_of(page(f'<a href="{href}">x</a>'))


def test_comment_avatars_do_not_mean_logged_in():
    blog = page('<article><p>Post</p></article><section class="comments"><img class="user-avatar" src="/a.png">'
                "<p>Nice post!</p></section>")
    assert "authenticated" not in roles_of(blog)


def test_admin_words_with_a_suffix_need_admin_structure():
    post = page("<h1>Dashboard design tips</h1><p>Ten ideas for clearer dashboards.</p>", title="Dashboard design tips")
    assert "admin" not in roles_of(post, url="https://example.test/dashboard-design-tips")
    assert "admin" not in roles_of(post, url="https://example.test/blog/admin_tips")
    assert "admin" in roles_of(page(LOGIN_FORM), url="https://example.test/admin-panel/")
    assert "admin" in roles_of(page('<div id="adminmenu"></div>'), url="https://example.test/admin_area/")
    # the exact admin path keeps the title rule of §3.1
    assert "admin" in roles_of(page("<p>x</p>", title="Site administration"), url="https://example.test/admin/")


def test_signup_page_without_dom_is_sensitive():
    """mark_sensitive passes doc=None for pages stored without a DOM; a sign-up page (password field, no login role)
    is still sensitive by §WEB315."""
    r = R(200, HTML, page('<form method=post action="/join"><input type="password" autocomplete="new-password"></form>'))
    C.classify(r)
    assert r.roles == {"signup"}
    assert C.is_sensitive(r)


@pytest.mark.parametrize("body", [
    "<title>" * 40000, "<h1>" * 40000, "<title>Index of /</title>" + "<h1" * 80000, "<" * 300000,
    "<a " * 100000, '<a "' * 80000,
])
def test_hostile_markup_classifies_in_linear_time(body):
    import time
    resp = R(200, HTML, body, url="https://example.test/admin/")
    t = time.perf_counter()
    C.listing_server(resp.text())
    C._first_h1(resp.text())
    C.signature(resp)
    assert time.perf_counter() - t < 2.0          # the quadratic regex version took 3–40 s
