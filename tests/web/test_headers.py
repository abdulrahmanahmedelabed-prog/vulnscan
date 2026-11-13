"""Response-header checks (spec §2.3, WP3): unit vectors, Observatory v6 slugs and the corpus cases that label them.

Everything is offline. The corpus cases are rendered in-process (``corpus.CorpusServer.respond`` without sockets) into
synthetic :class:`Response` objects, classified with classify.py, and fed to ``headers.run``; the labels of every rule
headers.py owns must hold.
"""

from __future__ import annotations

import importlib
import pathlib
import sys
import urllib.parse

import pytest

from vulnscan.webscan import classify, headers, htmlparse, rules
from vulnscan.webscan.coverage import Coverage
from vulnscan.webscan.types import CookieFact, CspFacts, HeaderList, Page, Response

ROOT = pathlib.Path(__file__).resolve().parents[2]
OWN = set(headers.CHECKS)


def _run(ctx):
    issues = headers.run(ctx)
    for i in issues:
        assert rules.validate_issue(i) == [], i
        assert i.rule in OWN
        assert i.evidence.match is not None
    return issues


def _rules(issues, rule=None):
    return [i for i in issues if rule is None or i.rule == rule]


def _doc(make_page, html="<html><head><title>x</title></head><body><p>hi</p></body></html>", url="https://example.test/",
         headers_=None, **kw):
    return make_page(html, url=url, headers=headers_ or [], **kw)


# =============================================================================================== X-Frame-Options

@pytest.mark.parametrize("fields,effect,reason", [
    ([], "absent", ""),
    (["DENY"], "deny", ""),
    (["sameorigin"], "sameorigin", ""),
    (["SAMEORIGIN, SAMEORIGIN"], "sameorigin", "identical"),
    (["SAMEORIGIN", "sameorigin"], "sameorigin", "identical"),
    (["DENY, SAMEORIGIN"], "deny", "conflict"),
    (["DENY", "SAMEORIGIN"], "deny", "conflict"),
    (["ALLOWALL, foo"], "deny", "conflict"),            # HTML spec: a multi-value set with allowall blocks
    (["ALLOW-FROM https://a.example/"], "absent", "allow-from"),
    (["ALLOWALL"], "absent", "invalid"),
    (["whimsy"], "absent", "invalid"),
    (["foo, bar"], "absent", "multi-invalid"),
    ([" Deny "], "deny", ""),
])
def test_xfo_html_spec_algorithm(fields, effect, reason):
    v = headers.xfo_verdict(fields)
    assert (v.effect, v.reason) == (effect, reason)
    assert v.present == bool(fields)


def test_xfo_missing_on_login_page_is_medium(make_page, make_ctx):
    page = make_page('<form method="post" action="/login"><input type="password" name="p"></form>')
    issues = _run(make_ctx(entry=page))
    [i] = _rules(issues, "WEB-x-frame-options")
    assert i.severity == "medium" and i.confidence == "firm"


def test_xfo_missing_on_static_page_is_low(make_page, make_ctx):
    issues = _run(make_ctx(entry=_doc(make_page)))
    [i] = _rules(issues, "WEB-x-frame-options")
    assert i.severity == "low"


def test_xfo_frame_ancestors_in_csp_facts_suppresses_missing(make_page, make_ctx):
    page = _doc(make_page)
    ctx = make_ctx(entry=page)
    ctx.csp[page.response] = CspFacts(frame_ancestors=["'none'"], frame_ancestors_protects=True)
    assert not _rules(_run(ctx), "WEB-x-frame-options")
    # a broad frame-ancestors is WEB206's business (csp.py), not a missing-XFO finding
    ctx.csp[page.response] = CspFacts(frame_ancestors=["*"], frame_ancestors_protects=False)
    assert not _rules(_run(ctx), "WEB-x-frame-options")


def test_xfo_local_csp_fallback_and_report_only_ignored(make_page, make_ctx):
    page = _doc(make_page, headers_=[("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'")])
    assert not _rules(_run(make_ctx(entry=page)), "WEB-x-frame-options")
    # D-fix: frame-ancestors in a report-only policy (or anywhere in text) does not protect
    page = _doc(make_page, headers_=[("Content-Security-Policy-Report-Only", "frame-ancestors 'none'")])
    assert _rules(_run(make_ctx(entry=page)), "WEB-x-frame-options")


def test_xfo_allow_from_gives_web300_instead_of_missing(make_page, make_ctx):
    page = _doc(make_page, headers_=[("X-Frame-Options", "ALLOW-FROM https://partner.example/")])
    issues = _run(make_ctx(entry=page))
    assert not _rules(issues, "WEB-x-frame-options")
    [i] = _rules(issues, "WEB300")
    assert i.severity == "medium" and i.confidence == "certain"
    assert "ALLOW-FROM" in i.notes[0][0]


def test_xfo_web300_low_when_frame_ancestors_protects(make_page, make_ctx):
    page = _doc(make_page, headers_=[("X-Frame-Options", "ALLOWALL"),
                                     ("Content-Security-Policy", "frame-ancestors 'none'")])
    [i] = _rules(_run(make_ctx(entry=page)), "WEB300")
    assert i.severity == "low"


def test_xfo_conflict_and_identical_duplicates(make_page, make_ctx):
    page = _doc(make_page, headers_=[("X-Frame-Options", "DENY"), ("X-Frame-Options", "SAMEORIGIN")])
    issues = _run(make_ctx(entry=page))
    [i] = _rules(issues, "WEB301")
    assert i.severity == "low" and not _rules(issues, "WEB-x-frame-options") and not _rules(issues, "WEB300")
    page = _doc(make_page, headers_=[("X-Frame-Options", "SAMEORIGIN, SAMEORIGIN")])
    assert not _rules(_run(make_ctx(entry=page)), "WEB301")          # honoured by browsers (Observatory FP fixed)
    issues = _run(make_ctx(entry=_doc(make_page, headers_=[("X-Frame-Options", "SAMEORIGIN, SAMEORIGIN")]),
                           sensitivity="paranoid"))
    [i] = _rules(issues, "WEB301")
    assert i.severity == "info"


def test_xfo_meta_is_reported_and_does_not_count(make_page, make_ctx):
    page = make_page('<html><head><meta http-equiv="X-Frame-Options" content="DENY"></head><body></body></html>')
    issues = _run(make_ctx(entry=page))
    assert _rules(issues, "WEB302") and _rules(issues, "WEB-x-frame-options")
    assert _rules(issues, "WEB302")[0].evidence.match["where"] == "body"


def test_xfo_not_judged_on_redirect_404_or_api(make_response, make_ctx, make_page):
    redirect = make_response("https://example.test/", status=301, headers=[("Location", "/home")], kind="redirect")
    err = make_page("<h1>Not found</h1>", status=404, kind="error_page")
    api = make_response("https://example.test/api", body=b'{"a": 1}', content_type="application/json", kind="api_json")
    for entry in (redirect, err, api):
        assert not _rules(_run(make_ctx(entry=entry)), "WEB-x-frame-options")


# =============================================================================================== XCTO

def test_xcto_missing_grouped_per_host_with_kinds(make_page, make_response, make_ctx):
    page = _doc(make_page)
    js = make_response("https://example.test/app.js", body=b"x=1", content_type="text/javascript", kind="script",
                       source="subresource")
    png = make_response("https://example.test/a.png", body=b"\x89PNG\r\n", content_type="image/png", kind="image",
                        source="subresource")
    issues = _run(make_ctx(entry=page, subresources=[js, png]))
    [i] = _rules(issues, "WEB-x-content-type-options")
    assert i.url == page.response.url and i.severity is None
    assert "document, script" in i.notes[0][0] and "2 responses" in i.notes[0][0]
    assert "استجابتين" in i.notes[0][1]


def test_xcto_skips_images_304_and_third_party(make_response, make_ctx):
    png = make_response("https://example.test/a.png", body=b"\x89PNG", content_type="image/png", kind="image")
    nm = make_response("https://example.test/", status=304, kind="not_modified")
    third = make_response("https://cdn.other.test/x.js", body=b"x", content_type="text/javascript", kind="script",
                          source="subresource")
    ok = make_response("https://example.test/", body=b"<p>", content_type="text/html",
                       headers=[("X-Content-Type-Options", "nosniff")], kind="document")
    for entry, subs in ((png, []), (nm, []), (ok, [third])):
        assert not _rules(_run(make_ctx(entry=entry, subresources=subs)), "WEB-x-content-type-options")


@pytest.mark.parametrize("value,fires", [("nosniff", False), ("NoSniff ", False), ("nosniff, nosniff", False),
                                         ("nosnif", True), ("whimsy", True), ("nosniff;", True), ("", True)])
def test_xcto_invalid_value_uses_the_first_value(make_response, make_ctx, value, fires):
    r = make_response(body=b"<p>", content_type="text/html", headers=[("X-Content-Type-Options", value)],
                      kind="document")
    issues = _run(make_ctx(entry=r))
    assert bool(_rules(issues, "WEB303")) is fires
    assert not _rules(issues, "WEB-x-content-type-options")


# =============================================================================================== Referrer-Policy

@pytest.mark.parametrize("fields,meta,policy", [
    (["no-referrer"], None, "no-referrer"),
    (["STRICT-ORIGIN"], None, "strict-origin"),
    (["origin-when-cross-origin, no-referrer, unsafe-url"], None, "unsafe-url"),
    (["no-referrer, whimsy"], None, "no-referrer"),
    (["unsafe-url", "whimsy"], None, "unsafe-url"),
    (["whimsy, whimsy1"], None, None),
    (["unsafe-url"], "no-referrer", "no-referrer"),       # meta processed after the header wins
    (["no-referrer"], "never", "no-referrer"),            # legacy meta keyword
    (["no-referrer"], "always", "unsafe-url"),
    (["no-referrer"], "bogus", "no-referrer"),            # an invalid meta changes nothing
    ([], "no-referrer, same-origin", None),               # meta takes one token, not a list
])
def test_referrer_last_recognised_token(make_page, fields, meta, policy):
    head = f'<meta name="referrer" content="{meta}">' if meta is not None else ""
    page = make_page(f"<html><head>{head}</head><body></body></html>",
                     headers=[("Referrer-Policy", f) for f in fields])
    v = headers.referrer_verdict(page.response, page.doc)
    assert v.policy == policy
    assert v.present == bool(fields or meta is not None)


def test_referrer_rules(make_page, make_ctx):
    issues = _run(make_ctx(entry=_doc(make_page, headers_=[("Referrer-Policy", "unsafe-url")])))
    [i] = _rules(issues, "WEB304")
    assert i.severity == "medium" and i.group_value == "unsafe-url"
    for value in ("origin", "origin-when-cross-origin", "no-referrer-when-downgrade", "whimsy"):
        [i] = _rules(_run(make_ctx(entry=_doc(make_page, headers_=[("Referrer-Policy", value)]))), "WEB304")
        assert i.severity == "low"
    issues = _run(make_ctx(entry=_doc(make_page)))
    [i] = _rules(issues, "WEB-referrer-policy")
    assert i.severity is None and rules.RULES["WEB-referrer-policy"].severity == "info"
    page = make_page('<html><head><meta name="referrer" content="no-referrer"></head></html>')
    issues = _run(make_ctx(entry=page))
    assert not _rules(issues, "WEB-referrer-policy") and not _rules(issues, "WEB304")


# =============================================================================================== Permissions-Policy

@pytest.mark.parametrize("value", ["camera 'none'", "camera=(self", "geolocation='self'", "camera=(), microphone 'none'",
                                   "camera=() "])
def test_pp_structured_field_failure_is_medium(make_page, make_ctx, value):
    issues = _run(make_ctx(entry=_doc(make_page, headers_=[("Permissions-Policy", value)])))
    [i] = _rules(issues, "WEB305")
    assert i.severity == "medium" and i.group_value == "parse-error"


@pytest.mark.parametrize("value,expected", [
    ("camera=(), geolocation=(self), fullscreen=(self \"https://trusted.example\")", []),
    ("camera=none", [("WEB305", "info")]),
    ("camera", [("WEB305", "info")]),                                   # boolean true: disabled
    ('geolocation="https://a.example"', [("WEB305", "low")]),
    ("camra=()", [("WEB305", "low")]),                                  # typo of camera
    ("interest-cohort=(), browsing-topics=()", []),                     # obsolete names are never flagged
    ("totally-unknown-thing=()", []),
    ("geolocation=*", [("WEB306", "low")]),
    ("camera=(* self)", [("WEB306", "low")]),
    ("fullscreen=*", []),                                               # not a powerful feature
    ("camera=(self none)", [("WEB305", "info")]),
])
def test_pp_member_problems(value, expected):
    pp = headers.parse_permissions_policy([value])
    got = [(r, s) for r, s, _n, _g in headers.pp_problems(pp)]
    assert got == expected


def test_pp_missing_feature_policy_and_ignored_obsolete(make_page, make_ctx):
    issues = _run(make_ctx(entry=_doc(make_page)))
    assert _rules(issues, "WEB-permissions-policy")
    issues = _run(make_ctx(entry=_doc(make_page, headers_=[("Feature-Policy", "camera 'none'")])))
    [i] = _rules(issues, "WEB307")
    assert i.severity == "low" and not _rules(issues, "WEB-permissions-policy")
    issues = _run(make_ctx(entry=_doc(make_page, headers_=[("Feature-Policy", "camera 'none'"),
                                                           ("Permissions-Policy", "camera=()")])))
    [i] = _rules(issues, "WEB307")
    assert i.severity == "info"


def test_typo_detection():
    assert headers.typo_of("geolocaton") == "geolocation"
    assert headers.typo_of("camera") is None
    assert headers.typo_of("interest-cohort") is None
    assert headers.typo_of("gpu") is None
    assert headers.typo_of("hdi") is None                # short names: edit distance 1 only


def test_iframe_allow_delegation(make_page, make_ctx):
    html = ('<iframe src="https://meet.other.test/room" allow="camera; microphone *; fullscreen"></iframe>'
            '<iframe src="/same" allow="geolocation"></iframe>')
    issues = _run(make_ctx(entry=make_page(html, headers=[("Permissions-Policy", "payment=()")])))
    got = sorted(i.group_value for i in _rules(issues, "WEB306"))
    assert got == ["iframe:camera:meet.other.test", "iframe:microphone:meet.other.test"]
    # the page's own policy keeps camera and microphone from the frame
    issues = _run(make_ctx(entry=make_page(html, headers=[("Permissions-Policy", "camera=(self), microphone=()")])))
    assert not _rules(issues, "WEB306")
    # ... unless it names the frame's origin
    issues = _run(make_ctx(entry=make_page(html, headers=[
        ("Permissions-Policy", 'camera=(self "https://meet.other.test"), microphone=()')])))
    assert [i.group_value for i in _rules(issues, "WEB306")] == ["iframe:camera:meet.other.test"]


# =============================================================================================== COOP / COEP / CORP

@pytest.mark.parametrize("fields,token,problem", [
    ([], None, "missing"),
    (["same-origin"], "same-origin", ""),
    (['same-origin; report-to="coop"'], "same-origin", ""),
    (["same-origin; report-to"], "same-origin", ""),
    (["same-origin-allow-popups"], "same-origin-allow-popups", ""),
    (["noopener-allow-popups"], "noopener-allow-popups", ""),
    (["unsafe-none"], "unsafe-none", ""),
    (["Same-Origin"], None, "invalid"),
    (['"same-origin"'], None, "invalid"),
    (["same-orign"], None, "invalid"),
    (["same-origin; report-to=coop endpoint"], None, "invalid"),
    (["same-origin", "same-origin"], None, "multi"),
])
def test_coop_tokens(fields, token, problem):
    assert headers.isolation_token(fields, headers.COOP_TOKENS) == (token, problem)


@pytest.mark.parametrize("fields,problem", [(["require-corp"], ""), (["credentialless"], ""), (["unsafe-none"], ""),
                                            (["Require-Corp"], "invalid"), (["require-corp", "credentialless"], "multi")])
def test_coep_tokens(fields, problem):
    assert headers.isolation_token(fields, headers.COEP_TOKENS)[1] == problem


@pytest.mark.parametrize("fields,problem", [(["same-origin"], ""), (["same-site"], ""), (["cross-origin"], ""),
                                            (["Same-Origin"], "invalid"), (["whimsy"], "invalid"),
                                            (["same-origin", "same-origin"], "multi"), ([], "missing")])
def test_corp_values_are_case_sensitive(fields, problem):
    assert headers.corp_value(fields)[1] == problem


def test_isolation_rules(make_page, make_ctx, make_response):
    issues = _run(make_ctx(entry=_doc(make_page)))
    [i] = _rules(issues, "WEB308")
    assert i.severity == "info" and i.group_value == "missing"
    assert not _rules(issues, "WEB309")                               # missing COEP is never reported by default
    login = make_page('<form><input type="password"></form>')
    [i] = _rules(_run(make_ctx(entry=login)), "WEB308")
    assert i.severity == "low"
    for value in ("same-orign", "unsafe-none"):
        [i] = _rules(_run(make_ctx(entry=_doc(make_page, headers_=[("Cross-Origin-Opener-Policy", value)]))), "WEB308")
        assert i.severity == ("low" if value == "same-orign" else "info")
    two = _doc(make_page, headers_=[("Cross-Origin-Embedder-Policy", "require-corp"),
                                    ("Cross-Origin-Embedder-Policy", "credentialless"),
                                    ("Cross-Origin-Opener-Policy", "same-origin")])
    issues = _run(make_ctx(entry=two))
    [i] = _rules(issues, "WEB309")
    assert i.severity == "low" and not _rules(issues, "WEB308")
    issues = _run(make_ctx(entry=_doc(make_page, headers_=[("Cross-Origin-Opener-Policy", "same-origin")]),
                           sensitivity="paranoid"))
    [i] = _rules(issues, "WEB309")
    assert i.severity == "info"
    # G3: ignored over http
    http_page = _doc(make_page, url="http://example.test/", headers_=[("Cross-Origin-Opener-Policy", "same-origin")])
    issues = _run(make_ctx(target="http://example.test/", entry=http_page))
    [i] = _rules(issues, "WEB308")
    assert i.severity == "info" and i.group_value == "http"
    corp = _doc(make_page, headers_=[("Cross-Origin-Resource-Policy", "Same-Origin")])
    [i] = _rules(_run(make_ctx(entry=corp)), "WEB310")
    assert i.severity == "low" and i.confidence == "certain"


def test_corp_missing_on_private_json_is_tentative(make_response, make_ctx):
    api = make_response("https://example.test/api/me", body=b'{"id": 1}', content_type="application/json",
                        kind="api_json", flags=frozenset({"sensitive"}))
    [i] = _rules(_run(make_ctx(entry=api)), "WEB310")
    assert (i.severity, i.confidence) == ("info", "tentative")
    cors = make_response("https://example.test/api/me", body=b'{"id": 1}', content_type="application/json",
                         kind="api_json", flags=frozenset({"sensitive"}),
                         headers=[("Access-Control-Allow-Origin", "https://app.example.test")])
    assert not _rules(_run(make_ctx(entry=cors)), "WEB310")


# =============================================================================================== legacy headers

@pytest.mark.parametrize("value,fires", [("0", False), ("0; mode=block", False), ("1", True), ("1; mode=block", True),
                                         ("1; report=https://r.example/", True)])
def test_xxss(make_page, make_ctx, value, fires):
    issues = _run(make_ctx(entry=_doc(make_page, headers_=[("X-XSS-Protection", value)])))
    got = _rules(issues, "WEB311")
    assert bool(got) is fires
    assert all(i.severity is None for i in got)                       # info (the registry default)


def test_deprecated_headers(make_page, make_ctx):
    issues = _run(make_ctx(entry=_doc(make_page, headers_=[("Public-Key-Pins", 'pin-sha256="x"; max-age=1'),
                                                           ("Expect-CT", "max-age=0"), ("Pragma", "no-cache")])))
    assert sorted(i.group_value for i in _rules(issues, "WEB312")) == ["expect-ct", "pragma", "public-key-pins"]
    issues = _run(make_ctx(entry=_doc(make_page, headers_=[("Pragma", "no-cache"), ("Cache-Control", "no-store")])))
    assert not _rules(issues, "WEB312")


def test_xpcdp(make_page, make_ctx):
    assert _rules(_run(make_ctx(entry=_doc(make_page, headers_=[("X-Permitted-Cross-Domain-Policies", "all")]))),
                  "WEB316")
    assert not _rules(_run(make_ctx(entry=_doc(make_page, headers_=[("X-Permitted-Cross-Domain-Policies", "none")]))),
                      "WEB316")
    assert not _rules(_run(make_ctx(entry=_doc(make_page))), "WEB316")
    [i] = _rules(_run(make_ctx(entry=_doc(make_page), sensitivity="paranoid")), "WEB316")
    assert i.severity == "info"


# =============================================================================================== Content-Type and charset

def test_content_type_rules(make_response, make_ctx):
    no_ct = make_response(body=b"<!doctype html><p>x", kind="document", flags=frozenset({"sniffed"}))
    [i] = _rules(_run(make_ctx(entry=no_ct)), "WEB313")
    assert i.confidence == "certain" and i.group_value == "missing"
    multi = make_response(body=b"<p>x", headers=[("Content-Type", "text/html"), ("Content-Type", "text/plain")],
                          kind="document")
    [i] = _rules(_run(make_ctx(entry=multi)), "WEB313")
    assert i.group_value.startswith("multi")
    same = make_response(body=b"<p>x", headers=[("Content-Type", "text/html"), ("Content-Type", "text/html; charset=utf-8")],
                         kind="document")
    assert not _rules(_run(make_ctx(entry=same)), "WEB313")
    json_html = make_response(body=b'{"id": 7}', content_type="text/html; charset=utf-8")
    classify.classify(json_html)
    [i] = _rules(_run(make_ctx(entry=json_html)), "WEB313")
    assert i.confidence == "firm" and "application/json" in i.notes[0][0]
    empty_204 = make_response(status=204, kind="no_content")
    assert not _rules(_run(make_ctx(entry=empty_204)), "WEB313")


@pytest.mark.parametrize("ctype,body,fires", [
    ("text/html; charset=utf-8", b"<html><head></head></html>", False),
    ("text/html", b'<html><head><meta charset="utf-8"></head></html>', False),
    ("text/html", b"\xef\xbb\xbf<html><head></head></html>", False),                 # BOM decides first
    ("text/html", b"<html><head></head></html>", True),
    ("text/html; charset=utf8", b'<html><head><meta charset="UTF-8"></head></html>', False),
    ('text/html; charset="UTF-8"', b'<meta charset=utf-8>', False),
    ("text/html; charset=latin1", b'<meta charset="windows-1252">', False),          # same WHATWG encoding
    ("text/html; charset=utf-8", b'<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">', True),
    ("text/html; charset=bogus", b"<html></html>", True),
    ("text/html", b" " * 1100 + b'<meta charset="utf-8">', True),                    # beyond the 1024-byte prescan
])
def test_charset_rules(make_response, make_ctx, ctype, body, fires):
    r = make_response(body=body, content_type=ctype, kind="document")
    assert bool(_rules(_run(make_ctx(entry=r)), "WEB314")) is fires


# =============================================================================================== caching

@pytest.mark.parametrize("value,expected", [
    ("no-store", {"no-store": ""}),
    ('private, max-age="60", No-Cache', {"private": "", "max-age": "60", "no-cache": ""}),
    ("public, s-maxage=600", {"public": "", "s-maxage": "600"}),
])
def test_cache_control_parse(value, expected):
    assert headers.parse_cache_control([value]) == expected


def _session_fact(resp, name="sessionid", value="0123456789abcdef"):
    return CookieFact(name=name, value=value, attrs={"path": "/", "secure": "", "httponly": ""},
                      raw=f"{name}={value}; Path=/; Secure; HttpOnly", response=resp, host=resp.host,
                      secure_context=resp.is_https, cls="session", class_source="table")


def test_cache_sensitive_tiers(make_page, make_ctx, make_response):
    login = '<form method="post" action="/login"><input type="password" name="p"></form>'
    page = make_page(login, headers=[("Cache-Control", "public, max-age=600")])
    [i] = _rules(_run(make_ctx(entry=page)), "WEB315")
    assert (i.severity, i.confidence) == ("medium", "firm")
    page = make_page(login, headers=[("Cache-Control", "private, max-age=60")])
    [i] = _rules(_run(make_ctx(entry=page)), "WEB315")
    assert i.severity == "low"
    page = make_page(login, headers=[("Cache-Control", "no-store")])
    assert not _rules(_run(make_ctx(entry=page)), "WEB315")
    # a non-sensitive page is never judged (ZAP 10015's noise)
    assert not _rules(_run(make_ctx(entry=_doc(make_page, headers_=[("Cache-Control", "public, max-age=600")]))), "WEB315")
    # static assets are never judged
    css = make_response("https://example.test/a.css", body=b"a{}", content_type="text/css", kind="style",
                        headers=[("Cache-Control", "public, max-age=31536000, immutable")], flags=frozenset({"sensitive"}))
    assert not _rules(_run(make_ctx(entry=css)), "WEB315")
    # a 302 that sets a session cookie without explicit freshness is not stored by caches
    hop = make_response("https://example.test/login", status=302, headers=[("Location", "/")], kind="redirect")
    ctx = make_ctx(entry=hop)
    ctx.cookies = [_session_fact(hop)]
    assert not _rules(_run(ctx), "WEB315")


def test_cache_hit_with_session_cookie_is_medium(make_page, make_ctx):
    page = _doc(make_page, headers_=[("Age", "120"), ("Cache-Control", "max-age=300"),
                                     ("Set-Cookie", "sessionid=abc; Secure")])
    ctx = make_ctx(entry=page)
    ctx.cookies = [_session_fact(page.response)]
    [i] = _rules(_run(ctx), "WEB315")
    assert (i.severity, i.group_value) == ("medium", "cache-hit")
    assert headers.cache_hit(Response("https://x.test/", headers=HeaderList.of(("CF-Cache-Status", "HIT")))) is not None
    assert headers.cache_hit(Response("https://x.test/", headers=HeaderList.of(("X-Cache", "MISS")))) is None


def test_same_session_value_to_two_cookieless_requests_is_certain_high(make_page, make_response, make_ctx):
    page = _doc(make_page, headers_=[("Cache-Control", "public, max-age=300")])
    cors = make_response("https://example.test/", body=page.response.body, headers=page.response.headers,
                         content_type="text/html", kind="document", source="cors", request_headers=HeaderList.of(("Origin", "https://kashif-cors-check.invalid")))
    ctx = make_ctx(entry=page, cors=cors)
    ctx.cookies = [_session_fact(page.response), _session_fact(cors)]
    issues = _rules(_run(ctx), "WEB315")
    assert [(i.severity, i.confidence) for i in issues] == [("high", "certain")]
    assert "0123456789abcdef" not in repr(issues[0].evidence.to_dict())        # values stay in memory only
    # different values (a fresh session per request) are only the shared-cacheable medium tier
    ctx.cookies = [_session_fact(page.response), _session_fact(cors, value="fedcba9876543210")]
    assert {(i.severity, i.confidence) for i in _rules(_run(ctx), "WEB315")} == {("medium", "firm")}
    # a request that sent the cookie back does not count
    cors.request_headers = HeaderList.of(("Cookie", "sessionid=0123456789abcdef"))
    ctx.cookies = [_session_fact(page.response), _session_fact(cors)]
    assert {i.confidence for i in _rules(_run(ctx), "WEB315")} == {"firm"}


# =============================================================================================== Clear-Site-Data

@pytest.mark.parametrize("url,value,fires", [
    ("https://example.test/", "cookies, storage", True),          # unquoted: whole header ignored
    ("https://example.test/", '"cache"', False),
    ("https://example.test/", '"cookies"', True),                 # ordinary page logs users out of sibling subdomains
    ("https://example.test/", '"*"', True),
    ("https://example.test/logout", '"cookies", "storage"', False),
    ("http://example.test/", '"cache"', True),                    # ignored over http
])
def test_clear_site_data(make_response, make_ctx, url, value, fires):
    r = make_response(url, body=b"<p>", content_type="text/html", headers=[("Clear-Site-Data", value)], kind="document")
    assert bool(_rules(_run(make_ctx(target=url, entry=r)), "WEB317")) is fires


# =============================================================================================== WEB318

def test_security_headers_dropped_on_error_pages(make_page, make_response, make_ctx):
    good = [("Content-Security-Policy", "default-src 'self'"), ("X-Frame-Options", "DENY"),
            ("X-Content-Type-Options", "nosniff"), ("Strict-Transport-Security", "max-age=31536000")]
    page = make_page("<p>home</p>", headers=good)
    bare404 = make_response("https://example.test/robots.txt", status=404, body=b"<h1>Not found</h1>",
                            content_type="text/html", kind="error_page", source="wellknown")
    issues = _run(make_ctx(entry=page, wellknown={"/robots.txt": bare404}))
    [i] = _rules(issues, "WEB318")
    assert i.url.endswith("/robots.txt") and "404" in i.notes[0][0]
    assert i.group_value == ("Content-Security-Policy,X-Frame-Options / frame-ancestors,X-Content-Type-Options,"
                             "Strict-Transport-Security")
    kept404 = make_response("https://example.test/robots.txt", status=404, body=b"<h1>Not found</h1>",
                            content_type="text/html", headers=good, kind="error_page", source="wellknown")
    assert not _rules(_run(make_ctx(entry=page, wellknown={"/robots.txt": kept404})), "WEB318")
    text404 = make_response("https://example.test/favicon.ico", status=404, body=b"nf", content_type="text/plain",
                            kind="error_page", source="wellknown")
    assert not _rules(_run(make_ctx(entry=page, wellknown={"/favicon.ico": text404})), "WEB318")
    # the documents lack the header too: the "missing" rules cover it
    plain = make_page("<p>home</p>")
    assert not _rules(_run(make_ctx(entry=plain, wellknown={"/robots.txt": bare404})), "WEB318")


# =============================================================================================== gates, coverage

def test_waf_entry_makes_document_checks_inconclusive(make_response, make_ctx):
    waf = make_response(status=403, body=b"<title>Just a moment...</title>", content_type="text/html",
                        headers=[("Server", "cloudflare"), ("cf-mitigated", "challenge")], kind="waf_challenge")
    cov = Coverage()
    issues = _run(make_ctx(entry=waf, coverage=cov))
    assert not issues
    st = cov.state("WEB-x-frame-options")
    assert st.state == "inconclusive" and st.reasons[0][0] == "waf"


def test_coverage_states(make_page, make_ctx):
    cov = Coverage()
    _run(make_ctx(entry=_doc(make_page, headers_=[("X-Frame-Options", "DENY")]), coverage=cov))
    assert cov.state("WEB-x-frame-options").state == "pass"
    assert cov.state("WEB-referrer-policy").state == "fail"
    assert cov.state("WEB315").state == "pass"
    cov = Coverage()
    api = Response("https://example.test/api", headers=HeaderList.of(("Content-Type", "application/json")),
                   body=b"{}", kind="api_json")
    _run(make_ctx(entry=api, coverage=cov))
    assert cov.state("WEB-x-frame-options").state == "not_applicable"


def test_paranoid_error_pages_use_tentative_only_where_the_registry_allows(make_page, make_ctx):
    missing = ("WEB-x-frame-options", "WEB-referrer-policy", "WEB-permissions-policy", "WEB308")
    err = make_page("<h1>Server error</h1>", status=500, kind="error_page")
    assert not [i for i in _run(make_ctx(entry=err)) if i.rule in missing]              # G1: never at default
    issues = [i for i in _run(make_ctx(entry=err, sensitivity="paranoid")) if i.rule in missing]
    allowed = {r for r in missing if "tentative" in rules.RULES[r].allowed_confidences}
    assert {i.rule for i in issues} == allowed                                       # integrator request (report)
    assert all(i.confidence == "tentative" for i in issues)


def test_hostile_values_do_not_break_notes(make_page, make_ctx):
    evil = "{value}{0}%s\x1b[31m<script>"
    page = _doc(make_page, headers_=[("X-Frame-Options", evil), ("Referrer-Policy", evil),
                                     ("Permissions-Policy", evil), ("Cross-Origin-Opener-Policy", evil)])
    issues = _run(make_ctx(entry=page))
    assert {"WEB300", "WEB304", "WEB305", "WEB308"} <= {i.rule for i in issues}
    for i in issues:
        for en, ar in i.notes:
            assert "\x1b" not in en and "\x1b" not in ar


def test_i18n_strings_are_bilingual():
    for key, (en, ar) in headers.STR.items():
        assert en and ar and en != ar, key
        assert sorted(set(headers._PLACEHOLDER.findall(en))) == sorted(set(headers._PLACEHOLDER.findall(ar))), key
    catalog, patterns = headers.i18n_catalog()
    assert patterns and catalog
    import re
    en, ar = headers._note("xcto_kinds", responses=headers._count(11, headers._RESPONSES), kinds="document")
    assert "11 استجابةً" in ar
    assert any(re.match(rx, ar) for rx, _ in patterns)


# =============================================================================================== Observatory v6

def _obs(make_page, make_response, hdrs, html=None):
    if html is None:
        r = make_response(headers=hdrs, body=b"{}", content_type="application/json")
        return headers.observatory_slugs(r, None)
    page = make_page(html, headers=hdrs)
    return headers.observatory_slugs(page.response, page.doc)


@pytest.mark.parametrize("hdrs,slug", [
    ([], "x-frame-options-not-implemented"),
    ([("X-Frame-Options", "whimsy")], "x-frame-options-header-invalid"),
    ([("X-Frame-Options", "SAMEORIGIN, SAMEORIGIN")], "x-frame-options-header-invalid"),      # quirk kept
    ([("X-Frame-Options", "DENY"), ("X-Frame-Options", "DENY")], "x-frame-options-header-invalid"),
    ([("X-Frame-Options", "ALLOW-FROM https://mozilla.org")], "x-frame-options-allow-from-origin"),
    ([("X-Frame-Options", "DENY")], "x-frame-options-sameorigin-or-deny"),
    ([("X-Frame-Options", "SAMEORIGIN")], "x-frame-options-sameorigin-or-deny"),
    ([("X-Frame-Options", "DENY"), ("Content-Security-Policy", "frame-ancestors https://mozilla.org")],
     "x-frame-options-implemented-via-csp"),
    ([("Content-Security-Policy", "frame-ancestors *")], "x-frame-options-implemented-via-csp"),   # quirk: +5
    ([("Content-Security-Policy", "frame-ancestors 'none'; script-src a; script-src b")],
     "x-frame-options-not-implemented"),                                                         # CSP invalid
    ([("Content-Security-Policy-Report-Only", "frame-ancestors 'none'")], "x-frame-options-not-implemented"),
])
def test_observatory_xfo(make_page, make_response, hdrs, slug):
    assert _obs(make_page, make_response, hdrs, "<html></html>")["x-frame-options"] == slug


def test_observatory_xfo_ignores_meta_but_meta_csp_frame_ancestors_counts(make_page, make_response):
    html = '<html><head><meta http-equiv="X-Frame-Options" content="DENY"></head></html>'
    assert _obs(make_page, make_response, [], html)["x-frame-options"] == "x-frame-options-not-implemented"
    html = ('<html><head><meta http-equiv="Content-Security-Policy" content="default-src \'self\'; '
            'frame-ancestors \'none\'"></head></html>')
    assert _obs(make_page, make_response, [], html)["x-frame-options"] == "x-frame-options-implemented-via-csp"


@pytest.mark.parametrize("value,slug", [("nosniff", "x-content-type-options-nosniff"),
                                        ("nosniff ", "x-content-type-options-nosniff"),
                                        ("whimsy", "x-content-type-options-header-invalid"),
                                        ("nosniff, nosniff", "x-content-type-options-header-invalid"),
                                        (None, "x-content-type-options-not-implemented")])
def test_observatory_xcto(make_page, make_response, value, slug):
    hdrs = [("X-Content-Type-Options", value)] if value is not None else []
    assert _obs(make_page, make_response, hdrs)["x-content-type-options"] == slug


@pytest.mark.parametrize("hdrs,meta,slug", [
    ([], None, "referrer-policy-not-implemented"),
    (["STRICT-ORIGIN"], None, "referrer-policy-private"),
    (["whimsy"], None, "referrer-policy-header-invalid"),
    (["origin-when-cross-origin, no-referrer, unsafe-url"], None, "referrer-policy-unsafe"),
    (["no-referrer, whimsy"], None, "referrer-policy-private"),
    (["no-referrer-when-downgrade"], None, "referrer-policy-unsafe"),
    ([], "no-referrer, same-origin", "referrer-policy-private"),
    (["unsafe-url"], "no-referrer, same-origin", "referrer-policy-private"),
])
def test_observatory_referrer(make_page, make_response, hdrs, meta, slug):
    head = f'<meta name="referrer" content="{meta}">' if meta else ""
    got = _obs(make_page, make_response, [("Referrer-Policy", h) for h in hdrs], f"<html><head>{head}</head></html>")
    assert got["referrer-policy"] == slug


@pytest.mark.parametrize("hdrs,test,slug", [
    ([], "cross-origin-resource-policy", "corp-not-implemented"),
    ([("Cross-Origin-Resource-Policy", "whimsy")], "cross-origin-resource-policy", "corp-header-invalid"),
    ([("Cross-Origin-Resource-Policy", "same-site")], "cross-origin-resource-policy", "corp-implemented-with-same-site"),
    ([("Cross-Origin-Resource-Policy", "Same-Origin")], "cross-origin-resource-policy",
     "corp-implemented-with-same-origin"),                                    # Observatory lowercases (Fetch does not)
    ([("Cross-Origin-Resource-Policy", "same-origin"), ("Cross-Origin-Resource-Policy", "cross-origin")],
     "cross-origin-resource-policy", "corp-header-invalid"),
    ([], "cross-origin-embedder-policy", "coep-not-implemented"),
    ([("Cross-Origin-Embedder-Policy", "require-corp; report-to")], "cross-origin-embedder-policy",
     "coep-implemented-with-require-corp"),
    ([("Cross-Origin-Embedder-Policy", "Require-Corp")], "cross-origin-embedder-policy", "coep-header-invalid"),
    ([("Cross-Origin-Embedder-Policy", "require-corp"), ("Cross-Origin-Embedder-Policy", "unsafe-none")],
     "cross-origin-embedder-policy", "coep-header-invalid"),
    ([("Cross-Origin-Opener-Policy", 'same-origin-allow-popups; report-to="e"')], "cross-origin-opener-policy",
     "coop-implemented-with-same-origin-allow-popups"),
    ([("Cross-Origin-Opener-Policy", "noopener-allow-popups")], "cross-origin-opener-policy",
     "coop-implemented-with-noopener-allow-popups"),
    ([("Cross-Origin-Opener-Policy", "unsafe-none")], "cross-origin-opener-policy", "coop-implemented-with-unsafe-none"),
    ([("Cross-Origin-Opener-Policy", '"same-origin"')], "cross-origin-opener-policy", "coop-header-invalid"),
    ([("Cross-Origin-Opener-Policy", "same-origin; report-to=coop endpoint")], "cross-origin-opener-policy",
     "coop-header-invalid"),
])
def test_observatory_isolation(make_page, make_response, hdrs, test, slug):
    assert _obs(make_page, make_response, hdrs)[test] == slug


def test_run_writes_observatory_slugs_for_the_auto_response(make_page, make_response, make_ctx):
    http_entry = make_page("<p>x</p>", url="http://example.test/")
    https = make_response("https://example.test/", headers=[("X-Frame-Options", "DENY")], body=b"<p>x</p>",
                          content_type="text/html", kind="document", source="https_probe")
    ctx = make_ctx(target="http://example.test/", entry=http_entry, https_probe=https)
    _run(ctx)
    assert set(headers.OBS_TESTS) <= set(ctx.observatory)
    assert ctx.observatory["x-frame-options"] == "x-frame-options-sameorigin-or-deny"
    ctx = make_ctx(entry=None)
    _run(ctx)
    assert ctx.observatory["x-frame-options"] == "x-frame-options-not-implemented"


# =============================================================================================== corpus cases (offline)

sys.path.insert(0, str(ROOT / "bench" / "web"))
corpus = importlib.import_module("corpus")
CORPUS_CASES = [c for c in corpus.CASES if set(c.labels) & OWN]


class _Sim:
    """Renders one corpus case in-process the way the engine would fetch it (entry chain with a cookie jar, the
    cookieless CORS GET, the well-known files) — no sockets."""

    def __init__(self, case):
        self.case = case
        self.srv = corpus.CorpusServer([case], mode="host", with_tls=False)
        self.srv.http_port, self.srv.https_port = 8080, 8443
        self.hosts = {h.lower(): a for h, a in case.all_hosts().items()}

    def url(self, path: str, scheme: str | None = None, alias: str = "") -> str:
        scheme = scheme or self.case.scheme
        host = self.case.alias_host(alias) if alias else self.case.host
        return f"{scheme}://{host}:{self.srv.port_for(self.case, scheme)}{path}"

    def get(self, url: str, *, jar: dict | None, origin: str | None = None, source: str = "entry") -> Response:
        hops: list[Response] = []
        for _ in range(10):
            p = urllib.parse.urlsplit(url)
            alias = self.hosts.get((p.hostname or "").lower())
            if alias is None:
                break
            req_headers = [("User-Agent", "Kashif-test"), ("Accept", "*/*")]
            if origin:
                req_headers.append(("Origin", origin))
            if jar:
                req_headers.append(("Cookie", "; ".join(f"{k}={v}" for k, v in jar.items())))
            hdrs = {k.lower(): [v] for k, v in req_headers}
            hits, case_hits = self.srv.count(self.case.id, alias, p.path or "/")
            req = corpus.Req(self.case, alias, p.path or "/", p.query, hdrs, p.scheme, hits, case_hits, self.srv,
                             p.netloc)
            r = self.srv.respond(req)
            per: dict = {}
            hl = []
            for name, value in r.headers:
                hl.append((name, corpus._render(value, req, per) if isinstance(value, str) else value.decode("latin-1")))
            body = r.body if isinstance(r.body, bytes) else corpus._render(r.body, req, per).encode("utf-8")
            resp = Response(url=url, status=r.status, headers=HeaderList(tuple(hl)), body=body,
                            request_headers=HeaderList(tuple(req_headers)), source=source)
            if jar is not None:
                for v in resp.headers.get_all("set-cookie"):
                    k, _, rest = v.partition("=")
                    jar[k.strip()] = rest.split(";", 1)[0]
            loc = resp.location
            if resp.status and 300 <= resp.status < 400 and loc:
                hops.append(resp)
                url = loc
                continue
            resp.chain = hops
            return resp
        last = hops.pop() if hops else Response(url=url, status=None, error="unroutable")
        last.chain = hops
        return last

    def context(self, make_ctx):
        c = self.case
        entry = self.get(self.url(c.path), jar={})
        kw: dict = {}
        if c.profile != "minimal":
            kw["cors"] = self.get(entry.url, jar=None, origin=corpus.CORS_PROBE_ORIGIN, source="cors")
            if c.wellknown or any(k.startswith("/robots") for k in c.routes):
                kw["wellknown"] = {path: self.get(self.url(path), jar=None, source="wellknown")
                                   for path in ("/robots.txt", "/.well-known/security.txt", "/favicon.ico")}
        ctx = make_ctx(target=self.url(c.path), entry=None, profile=c.profile, sensitivity=c.sensitivity, **kw)
        ctx.entry = entry
        for r in ctx.all_responses():
            doc = htmlparse.parse_response(r) if r.essence in ("text/html", "") and r.body else None
            classify.classify(r, doc)
            if r is entry and r.kind == "document":
                ctx.pages.append(Page(r, doc, 0))
        ctx.cookies = _cookie_facts(ctx)
        classify.mark_sensitive(ctx)
        return ctx


_SESSION_NAMES = ("sessionid", "phpsessid", "jsessionid", "sid", "connect.sid")


def _cookie_facts(ctx) -> list[CookieFact]:
    out = []
    for r in ctx.all_responses():
        for i, raw in enumerate(r.headers.get_all("set-cookie")):
            first, _, rest = raw.partition(";")
            name, _, value = first.partition("=")
            attrs = {}
            for a in rest.split(";"):
                k, _, v = a.strip().partition("=")
                if k:
                    attrs[k.lower()] = v
            cls = "session" if name.strip().lower() in _SESSION_NAMES or "sess" in name.lower() else "unknown"
            out.append(CookieFact(name=name.strip(), value=value.strip(), attrs=attrs, raw=raw, response=r, host=r.host,
                                  secure_context=r.is_https, cls=cls, index=i))
    return out


@pytest.mark.parametrize("case", CORPUS_CASES, ids=[c.id for c in CORPUS_CASES])
def test_corpus_case_labels(case, make_ctx):
    ctx = _Sim(case).context(make_ctx)
    issues = _run(ctx)
    shown = [i for i in issues if ctx.options.reports(i.confidence)]
    for rule, want in case.labels.items():
        if rule not in OWN:
            continue
        got = [i for i in shown if i.rule == rule]
        assert bool(got) is want, f"{case.id}: {rule} expected {'to fire' if want else 'silent'}, got {got!r}"
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for key in ("severity", "max_severity", "confidence"):
        for rule, val in case.expect.get(key, {}).items():
            if rule not in OWN:
                continue
            got = [i for i in shown if i.rule == rule]
            assert got, f"{case.id}: {rule} did not fire"
            if key == "confidence":
                assert val in {i.confidence for i in got}
                continue
            sevs = [i.severity or rules.RULES[rule].severity for i in got]
            worst = max(sevs, key=sev_rank.__getitem__)
            assert (worst == val) if key == "severity" else sev_rank[worst] <= sev_rank[val], (case.id, rule, sevs)


def test_corpus_covers_the_c_hdr_group():
    ids = {c.id for c in CORPUS_CASES}
    hdr = {c.id for c in corpus.CASES if c.group == "C-HDR"}
    assert hdr <= ids and len(hdr) >= 30


def test_runs_fast_on_a_large_page(make_page, make_ctx):
    import time
    html = "<html><head><title>x</title></head><body>" + "<div><a href='/x'>x</a></div>" * 20000 + "</body></html>"
    page = make_page(html)
    t = time.perf_counter()
    _run(make_ctx(entry=page))
    assert time.perf_counter() - t < 2.0


# =============================================================================================== adversarial review (WP3)

@pytest.mark.parametrize("fields,effect,reason", [
    (["DENY,"], "deny", ""),                         # a stray comma is one layer, not a conflict (Chromium drops it)
    (["SAMEORIGIN, "], "sameorigin", ""),
    (["", "DENY"], "deny", ""),
    ([","], "absent", "invalid"),
    ([""], "absent", "invalid"),
    (["deny;"], "absent", "invalid"),                # not a token list: browsers ignore it
])
def test_xfo_empty_members_are_dropped(fields, effect, reason):
    v = headers.xfo_verdict(fields)
    assert (v.effect, v.reason) == (effect, reason)


def test_xfo_trailing_comma_is_not_a_finding(make_page, make_ctx):
    issues = _run(make_ctx(entry=_doc(make_page, headers_=[("X-Frame-Options", "SAMEORIGIN,")])))
    assert not {"WEB300", "WEB301", "WEB-x-frame-options"} & {i.rule for i in issues}


def test_empty_header_values_are_quoted_in_notes(make_page, make_ctx):
    page = _doc(make_page, headers_=[("X-Frame-Options", ""), ("Cross-Origin-Opener-Policy", ""),
                                     ("Cross-Origin-Resource-Policy", ""), ("X-XSS-Protection", "")])
    issues = _run(make_ctx(entry=page))
    for rule in ("WEB300", "WEB308", "WEB310", "WEB311"):
        [i] = [x for x in issues if x.rule == rule and x.group_value != "missing"]
        assert '""' in i.notes[0][0] and '""' in i.notes[0][1], (rule, i.notes)


def test_repeated_meta_xfo_is_one_finding(make_page, make_ctx):
    html = "<head>" + '<meta http-equiv="X-Frame-Options" content="DENY">' * 500 + "</head><body>x</body>"
    issues = _rules(_run(make_ctx(entry=make_page(html))), "WEB302")
    assert len(issues) == 1


def test_pp_hostile_inner_list_gives_one_finding_per_member():
    junk = " ".join(f"x{i}" for i in range(3000))
    probs = headers.pp_problems(headers.parse_permissions_policy([f'camera=({junk} "not an origin")']))
    assert [(r, s) for r, s, _n, _g in probs] == [("WEB305", "low")]       # the worst element, once
    assert all(len(n[0]) < 400 and len(g) < 200 for _r, _s, n, g in probs)


@pytest.mark.parametrize("value,sev", [
    ("geolocation=(self https://maps.example)", "low"),     # unquoted origin parses as a Token and is dropped
    ("geolocation=https://maps.example", "low"),            # bare unquoted origin: same advice as a bare string
    ("geolocation=(none)", "info"),
    ("geolocation=none", "info"),
])
def test_pp_unquoted_origins_are_low(value, sev):
    probs = headers.pp_problems(headers.parse_permissions_policy([value]))
    assert [(r, s) for r, s, _n, _g in probs] == [("WEB305", sev)]


def test_pp_real_world_policies_are_silent():
    policies = [
        "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), cross-origin-isolated=(), "
        "display-capture=(), document-domain=(), encrypted-media=(), execution-while-not-rendered=(), "
        "execution-while-out-of-viewport=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), "
        "magnetometer=(), microphone=(), midi=(), navigation-override=(), payment=(), picture-in-picture=(), "
        "publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), "
        "xr-spatial-tracking=(), clipboard-read=(), clipboard-write=(), gamepad=(), speaker-selection=(), "
        "conversion-measurement=(), focus-without-user-activation=(), hid=(), idle-detection=(), "
        "interest-cohort=(), serial=(), sync-script=(), trust-token-redemption=(), unload=(), window-placement=(), "
        "vertical-scroll=()",
        "interest-cohort=()",
        'fullscreen=(self "https://player.example"), geolocation=(self), browsing-topics=()',
        "camera=(), microphone=(), notifications=(), push=(), speaker=(), vibrate=(), xr=()",
    ]
    for p in policies:
        assert headers.pp_problems(headers.parse_permissions_policy([p])) == [], p


@pytest.mark.parametrize("name,value", [
    ("session", "eyJ2aXNpdGVkIjp0cnVlfQ=="),                                  # Express cookie-session (base64 JSON)
    ("session.sig", "kWm3w1kFq2bSx0XqmA8Y4VQe3cQ"),                           # …and its signature cookie
    ("session", ".eJyrVkrOzytJzSvRS87PKUpVsgJR-ZmJxanFOalqSqUFqUWJpQVKVgA.ZzJ0aA.sig"),   # Flask (zlib)
    ("auth_token", "eyJhbGciOiJIUzI1NiJ9.eyJndWVzdCI6dHJ1ZX0.c2lnbmF0dXJl"),  # an anonymous JWT
])
def test_identical_self_contained_session_payloads_are_not_certain(make_page, make_response, make_ctx, name, value):
    page = _doc(make_page, headers_=[("Cache-Control", "private, max-age=60")])
    cors = make_response("https://example.test/", body=page.response.body, headers=page.response.headers,
                         content_type="text/html", kind="document", source="cors")
    ctx = make_ctx(entry=page, cors=cors)
    ctx.cookies = [_session_fact(page.response, name, value), _session_fact(cors, name, value)]
    issues = _rules(_run(ctx), "WEB315")
    assert issues and {(i.severity, i.confidence) for i in issues} == {("low", "firm")}


def test_public_with_vary_cookie_only_is_low(make_page, make_ctx):
    page = _doc(make_page, headers_=[("Cache-Control", "public, max-age=600"), ("Vary", "Accept-Encoding, Cookie")])
    [i] = _rules(_run(make_ctx(entry=page)), "WEB315")
    assert (i.severity, i.group_value) == ("low", "shared-vary")
    assert any("Vary" in en for en, _ar in i.notes)
    # a login page stays medium even with Vary: Cookie
    login = make_page('<form method="post"><input type="password" name="p"></form>',
                      headers=[("Cache-Control", "public, max-age=600"), ("Vary", "Cookie")])
    [i] = _rules(_run(make_ctx(entry=login)), "WEB315")
    assert i.severity == "medium"


def test_clear_site_data_on_logout_query_is_silent(make_response, make_ctx):
    r = make_response("https://example.test/wp-login.php?action=logout", content_type="text/html", body=b"bye",
                      headers=[("Clear-Site-Data", '"cookies", "storage"')], kind="document")
    assert not _rules(_run(make_ctx(entry=r)), "WEB317")


@pytest.mark.parametrize("url,sev,group", [
    ("http://127.0.0.1:8000/", "low", "same-orign"),          # a loopback http origin is a secure context
    ("http://localhost/", "low", "same-orign"),
    ("http://app.localhost/", "low", "same-orign"),
    ("http://example.test/", "info", "http"),                  # G3: ignored on plain http
])
def test_g3_treats_loopback_http_as_secure_context(make_page, make_ctx, url, sev, group):
    page = make_page("<p>x</p>", url=url, headers=[("Cross-Origin-Opener-Policy", "same-orign")])
    [i] = [x for x in _run(make_ctx(target=url, entry=page)) if x.rule == "WEB308"]
    assert (i.severity, i.group_value) == (sev, group)


def test_nul_in_charset_label_does_not_crash(make_ctx):
    # http.py decodes header bytes as ISO-8859-1, so a NUL survives into the label; codecs.lookup raises ValueError
    r = Response("https://example.test/", headers=HeaderList.of(("Content-Type", "text/html; charset=utf\x00-8")),
                 body=b"<html><body><p>x</p></body></html>", kind="document")
    issues = _run(make_ctx(entry=r))
    [i] = _rules(issues, "WEB314")
    assert i.group_value == "missing" and len(i.notes) == 2


def test_fuzzed_headers_never_crash(make_ctx):
    import random
    rnd = random.Random(1110)
    names = ["X-Frame-Options", "Referrer-Policy", "Permissions-Policy", "Feature-Policy", "Cross-Origin-Opener-Policy",
             "Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy", "X-Content-Type-Options",
             "X-XSS-Protection", "Clear-Site-Data", "Cache-Control", "Content-Type", "Age", "X-Cache", "Vary",
             "Pragma", "X-Permitted-Cross-Domain-Policies", "Content-Security-Policy"]
    atoms = ["", " ", ",", ";", '"', "'", "(", ")", "=", "*", "self", "deny", "SAMEORIGIN", "allow-from", "camera",
             "nosniff", "public", "s-maxage=", "-1", "9" * 30, "no-store", "\x00", "\x7f", "‮", "é", "\\",
             "https://a.example", "frame-ancestors", "'none'", "unsafe-url", "text/html", "charset=", "utf8",
             '"cookies"', "?1", "{value}", "\t"]
    bodies = [b"", bytes(range(256)) * 4, b"\xef\xbb\xbf<html>",
              b"<meta charset=x><meta name=referrer content=never><iframe src='http://[::1' allow='camera *'></iframe>"
              b"<iframe src='//evil.example/' allow='usb'></iframe><form><input type=password></form>"]
    for _ in range(300):
        hdrs = [(rnd.choice(names), "".join(rnd.choice(atoms) for _ in range(rnd.randint(0, 6))))
                for _ in range(rnd.randint(0, 8))]
        url = rnd.choice(["https://example.test/", "http://example.test/logout", "http://127.0.0.1:1/x"])
        r = Response(url, status=rnd.choice([200, 301, 404, 500, None]), headers=HeaderList.of(*hdrs),
                     body=rnd.choice(bodies), kind=rnd.choice(["", "document", "api_json", "error_page", "script"]))
        ctx = make_ctx(target=url, entry=r, sensitivity=rnd.choice(["default", "paranoid"]))
        ctx.cookies = [_session_fact(r, value="".join(rnd.choice(atoms) for _ in range(4)) + "0123456789")]
        _run(ctx)


def test_security_header_inventory_lists_report_only_isolation(make_page, make_ctx):
    page = _doc(make_page, headers_=[("X-Frame-Options", "ALLOW-FROM https://a.example"),
                                     ("Content-Security-Policy", "frame-ancestors 'self'"),
                                     ("Cross-Origin-Opener-Policy-Report-Only", "same-origin; report-to=\"coop\""),
                                     ("Cross-Origin-Embedder-Policy", "require-corp"),
                                     ("Referrer-Policy", "unsafe-url, no-referrer"),
                                     ("X-Content-Type-Options", "nosniff\x1b[2J")])
    ctx = make_ctx(entry=page)
    _run(ctx)
    [entry] = ctx.inventory["security_headers"]
    rows = entry["headers"]
    assert rows["X-Frame-Options"]["verdict"] == "frame-ancestors"
    assert rows["Cross-Origin-Opener-Policy"]["verdict"] == "missing"
    assert rows["Cross-Origin-Opener-Policy-Report-Only"]["verdict"] == "report-only:same-origin"
    assert rows["Cross-Origin-Embedder-Policy"]["verdict"] == "require-corp"
    assert rows["Referrer-Policy"]["verdict"] == "no-referrer"
    assert rows["X-Content-Type-Options"]["verdict"] == "invalid"
    assert "\x1b" not in rows["X-Content-Type-Options"]["value"]
    # report-only COOP is never a finding (§WEB308)
    assert all(i.group_value != "report-only" for i in _rules(_run(ctx), "WEB308"))


def test_identical_random_iv_payloads_stay_certain(make_page, make_response, make_ctx):
    import base64
    import json
    # Laravel encrypts with a random IV: an identical value on two cookieless requests was replayed by a cache
    value = base64.b64encode(json.dumps({"iv": "aXY=", "value": "dmFs", "mac": "0f" * 32}).encode()).decode()
    page = _doc(make_page, headers_=[("Cache-Control", "private, max-age=60")])
    cors = make_response("https://example.test/", body=page.response.body, headers=page.response.headers,
                         content_type="text/html", kind="document", source="cors")
    ctx = make_ctx(entry=page, cors=cors)
    ctx.cookies = [_session_fact(page.response, "laravel_session", value), _session_fact(cors, "laravel_session", value)]
    assert [(i.severity, i.confidence) for i in _rules(_run(ctx), "WEB315")] == [("high", "certain")]
    assert headers._payload_keys("eyJ" + "A" * 20000) == set()          # bounded, never raises
