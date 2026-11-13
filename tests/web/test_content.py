"""WP7: page content and client-side code (spec §2.6 WEB050–WEB519), SRI, mixed content, malicious hosts, WEB517
variants, the Observatory ``subresource-integrity`` slug, and the C-HTML / C-REVIEW corpus cases (offline: the corpus
routes are rendered into synthetic responses, no server or network)."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from vulnscan.webscan import content, coverage, data, htmlparse
from vulnscan.webscan.rules import RULES, validate_issue
from vulnscan.webscan.types import (
    CookieFact,
    CspFacts,
    DnsRecord,
    HeaderList,
    Page,
    Response,
    ScanContext,
    ScanOptions,
)

ROOT = Path(__file__).resolve().parents[2]
HTML_CT = ("Content-Type", "text/html; charset=utf-8")
SHA384 = "sha384-" + base64.b64encode(hashlib.sha384(b"lib").digest()).decode()


def page(body: str, *, head: str = "", doctype: bool = True, title: str = "t") -> str:
    return (("<!doctype html>" if doctype else "") + f"<html><head><title>{title}</title>{head}</head>"
            f"<body>{body}</body></html>")


def resp(url: str, body: str | bytes = b"", headers=(), status: int = 200, kind: str = "document", **kw) -> Response:
    hl = HeaderList.of(*headers) if headers else HeaderList.of(HTML_CT)
    return Response(url=url, status=status, headers=hl, body=body.encode() if isinstance(body, str) else body,
                    kind=kind, **kw)


def ctx_for(html: str | None = None, url: str = "https://www.example.com/", *, headers=(), pages=(), sensitivity="default",
            profile="standard", **fields) -> ScanContext:
    pgs = []
    entry = None
    if html is not None:
        entry = resp(url, html, headers)
        pgs.append(Page(entry, htmlparse.parse_response(entry)))
    for p in pages:
        pgs.append(p if isinstance(p, Page) else Page(p, htmlparse.parse_response(p)))
    ctx = ScanContext(options=ScanOptions(profile=profile, sensitivity=sensitivity), target=url,
                      entry=fields.pop("entry", entry), pages=pgs, **fields)
    ctx.coverage = coverage.Coverage()
    return ctx


def run(ctx: ScanContext):
    issues = content.run(ctx)
    for i in issues:
        assert validate_issue(i) == [], (i.rule, validate_issue(i))
        assert i.evidence.observed_at
        for en, ar in i.notes:
            assert en and ar
    return issues


def rules(issues, reported_at: ScanOptions | None = None) -> dict[str, list]:
    out: dict[str, list] = {}
    for i in issues:
        if reported_at is None or reported_at.reports(i.confidence):
            out.setdefault(i.rule, []).append(i)
    return out


def sev(issue) -> str:
    return issue.severity or RULES[issue.rule].severity


# ============================================================================================ WEB050 mixed content

def test_mixed_active_and_passive_and_never_links():
    html = page('<script src="http://cdn.third.test/a.js"></script><img src="http://img.third.test/x.png">'
                '<a href="http://partner.test/">p</a>', head='<link rel="canonical" href="http://www.example.com/">'
                '<link rel="alternate" href="http://www.example.com/feed">')
    issues = rules(run(ctx_for(html.replace("<html>", '<html xmlns="http://www.w3.org/1999/xhtml" itemtype="http://schema.org/X">'))))
    (mix,) = issues["WEB050"]
    assert sev(mix) == "medium"
    assert "partner.test" not in json.dumps(mix.notes)          # D6: <a href> is navigation, not mixed content
    assert "www.example.com" not in mix.group_value              # canonical / alternate are never mixed content
    assert mix.evidence.match["value"] == "http://cdn.third.test/a.js"


def test_mixed_passive_only_is_low_and_attribute_set():
    html = page('<picture><source srcset="http://i.test/a.webp 1x, http://i.test/b.webp 2x"><img src="/x.png"></picture>'
                '<video src="https://v.test/a.mp4" poster="http://i.test/p.jpg"></video><table background="http://i.test/bg.gif">'
                '<tr><td style="background:url(http://i.test/td.png)">x</td></tr></table>',
                head='<link rel="icon" href="http://i.test/favicon.ico">')
    (mix,) = rules(run(ctx_for(html)))["WEB050"]
    assert sev(mix) == "low"
    text = json.dumps(mix.notes)
    for u in ("a.webp", "b.webp", "p.jpg", "bg.gif", "td.png", "favicon.ico"):
        assert u in text


@pytest.mark.parametrize("snippet", [
    '<iframe src="http://f.test/"></iframe>', '<object data="http://f.test/x.swf"></object>',
    '<embed src="http://f.test/x.swf">', '<link rel="stylesheet" href="http://f.test/a.css">',
    '<link rel="modulepreload" href="http://f.test/m.js">', '<link rel="manifest" href="http://f.test/m.json">',
    '<svg><use href="http://f.test/s.svg#i"></use></svg>', '<style>@import url(http://f.test/a.css);</style>',
    '<style>@import "http://f.test/b.css";</style>', '<applet code="A.class" archive="http://f.test/a.jar"></applet>',
])
def test_mixed_active_attribute_set(snippet):
    (mix,) = rules(run(ctx_for(page(snippet))))["WEB050"]
    assert sev(mix) == "medium"


def test_mixed_template_comment_loopback_and_http_page_ignored():
    html = page('<template><script src="http://t.test/t.js"></script></template><noscript><img src="http://t.test/n.png">'
                '</noscript><!-- <img src="http://t.test/old.png"> --><img src="http://127.0.0.1:8080/x.png">'
                '<script src="http://localhost/dev.js"></script>')
    assert "WEB050" not in rules(run(ctx_for(html)))
    assert "WEB050" not in rules(run(ctx_for(page('<img src="http://t.test/a.png">'), url="http://www.example.com/")))


def test_mixed_base_href_makes_relative_urls_insecure():
    html = page('<script src="app.js"></script>', head='<base href="http://www.example.com/static/">')
    (mix,) = rules(run(ctx_for(html)))["WEB050"]
    assert mix.evidence.match["value"] == "http://www.example.com/static/app.js"


def test_mixed_upgrade_insecure_requests_header_meta_and_ctx_csp():
    html = page('<script src="http://cdn.third.test/a.js"></script>')
    hdr = (HTML_CT, ("Content-Security-Policy", "default-src https:; upgrade-insecure-requests"))
    (mix,) = rules(run(ctx_for(html, headers=hdr)))["WEB050"]
    assert sev(mix) == "info"
    meta = page('<script src="http://cdn.third.test/a.js"></script>',
                head='<meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">')
    assert sev(rules(run(ctx_for(meta)))["WEB050"][0]) == "info"
    ctx = ctx_for(html)
    ctx.csp[ctx.entry] = CspFacts(upgrade_insecure_requests=True)
    assert sev(rules(run(ctx))["WEB050"][0]) == "info"
    ro = (HTML_CT, ("Content-Security-Policy-Report-Only", "upgrade-insecure-requests"))
    assert sev(rules(run(ctx_for(html, headers=ro)))["WEB050"][0]) == "medium"   # report-only upgrades nothing


def test_mixed_from_subresource_http_hop_and_same_site_stylesheet():
    html = page('<script src="https://cdn.third.test/a.js"></script>', head='<link rel="stylesheet" href="/s.css">')
    hop = resp("https://cdn.third.test/a.js", status=301, headers=(("Location", "http://cdn.third.test/a.js"),),
               kind="redirect", source="subresource")
    final = resp("http://cdn.third.test/a.js", "x", headers=(("Content-Type", "text/javascript"),), kind="script",
                 source="subresource", chain=[hop])
    css = resp("https://www.example.com/s.css", "/* url(http://c.test/comment.png) */ body{background:url(http://i.test/b.png)}"
               "@import url('http://c.test/more.css');", headers=(("Content-Type", "text/css"),), kind="style",
               source="subresource")
    ctx = ctx_for(html, subresources=[final, css])
    (mix,) = rules(run(ctx))["WEB050"]
    text = json.dumps(mix.notes)
    assert sev(mix) == "medium" and "redirects through plain http" in text
    assert "b.png" in text and "more.css" in text and "comment.png" not in text


def test_css_references():
    refs = content.css_references("/* @import url(http://x/c.css); */ @import 'a.css'; p{background:url( \"b.png\" )}")
    assert [(u, a) for u, a, _o in refs] == [("a.css", True), ("b.png", False)]


# ============================================================================================ WEB051 / WEB052 / WEB504

def test_form_action_and_formaction_http():
    html = page('<form method="post" action="http://www.example.com/s"><input name="e"></form>'
                '<form method="post" action="/save"><button formaction="http://www.example.com/save2">S</button></form>'
                '<form method="post" action="http://www.example.com/login"><input type="password" name="p"></form>')
    found = rules(run(ctx_for(html)))["WEB051"]
    assert sorted(sev(i) for i in found) == ["high", "medium", "medium"]
    assert "WEB050" not in rules(run(ctx_for(html)))             # form targets are WEB051's, not mixed content


def test_http_page_forms_wear_web052_and_web504_not_web051_for_relative_actions():
    html = page('<form method="post" action="/login"><input type="password" name="p"></form>'
                '<form method="post" action="https://www.example.com/news"><input name="e"></form>')
    found = rules(run(ctx_for(html, url="http://www.example.com/")))
    assert "WEB051" not in found
    assert len(found["WEB052"]) == 1 and sev(found["WEB052"][0]) == "high"
    assert len(found["WEB504"]) == 1
    explicit = page('<form method="post" action="http://www.example.com/x"><input name="e"></form>')
    assert "WEB051" in rules(run(ctx_for(explicit, url="http://www.example.com/")))


def test_password_in_template_is_not_live():
    html = page('<template><form action="http://www.example.com/x"><input type="password"></form></template>')
    found = rules(run(ctx_for(html, url="http://www.example.com/")))
    assert "WEB052" not in found and "WEB051" not in found


# ============================================================================================ SRI

@pytest.mark.parametrize("value,has_meta,malformed", [
    (SHA384, True, False),
    ("sha256-" + base64.b64encode(b"\x00" * 32).decode(), True, False),
    ("sha512-" + base64.urlsafe_b64encode(b"\xff" * 64).decode().rstrip("="), True, False),   # base64url, no padding
    ("SHA384-" + SHA384[7:], True, False),
    ("sha1-2jmj7l5rSw0yVb/vlWAYkK/YBwk=", False, False),
    ("md5-1B2M2Y8AsgTpgAmY7PhCfg==", False, False),
    ("sha384-abc", True, True),
    ("sha384-" + "!" * 64, True, True),
    ("sha256-" + base64.b64encode(b"\x00" * 32).decode() + "?ct=application/javascript", True, False),
    ("sha1-xxx " + SHA384, True, False),
    ("", False, False),
    ("garbage", False, False),
])
def test_sri_grammar(value, has_meta, malformed):
    meta = content.parse_sri(value)
    assert meta.has_metadata is has_meta
    assert bool([t for t in meta.strongest() if not t.well_formed]) is malformed


def test_sri_strongest_and_match():
    body = b"window.x=1;"
    weak = "sha256-" + base64.b64encode(hashlib.sha256(b"other").digest()).decode()
    strong = content.sri_digest("sha512", body)
    meta = content.parse_sri(f"{weak} {strong}")
    assert [t.algorithm for t in meta.strongest()] == ["sha512"]
    assert meta.matches(body) is True                          # the weaker mismatching digest is ignored
    assert content.parse_sri(weak).matches(body) is False
    assert content.parse_sri("sha1-abc").matches(body) is None


def test_web053_third_party_per_host_and_severities():
    html = page('<script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>'
                '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>'
                '<script async src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>'
                '<script src="https://widgets.vendor.test/w.js"></script>'
                '<script src="https://static.example.com/app.js"></script>'          # same site (PSL), D22
                '<script src="/local.js"></script><script src="data:text/javascript,1"></script>',
                head='<link rel="stylesheet" href="//fonts.vendor2.test/f.css">'
                     '<link rel="preload" as="font" href="https://fonts.vendor3.test/f.woff2">')
    found = {i.group_value: i for i in rules(run(ctx_for(html)))["WEB053"]}
    assert set(found) == {"cdnjs.cloudflare.com", "www.googletagmanager.com", "widgets.vendor.test", "fonts.vendor2.test"}
    assert sev(found["cdnjs.cloudflare.com"]) == "low"
    assert "jquery.min.js" in json.dumps(found["cdnjs.cloudflare.com"].notes)      # every file listed (no break)
    assert sev(found["www.googletagmanager.com"]) == "info"
    assert "cannot be pinned" in found["www.googletagmanager.com"].notes[1][0]
    assert sev(found["widgets.vendor.test"]) == "info"


def test_web053_integrity_policy():
    html = page('<script src="https://cdnjs.cloudflare.com/ajax/libs/x/1.0.0/x.js"></script>')
    on = (HTML_CT, ("Integrity-Policy", "blocked-destinations=(script), endpoints=(e)"))
    (i,) = rules(run(ctx_for(html, headers=on)))["WEB053"]
    assert sev(i) == "info" and any("Integrity-Policy" in n[0] for n in i.notes)
    bad = (HTML_CT, ("Integrity-Policy", "blocked-destinations=script("))
    (i,) = rules(run(ctx_for(html, headers=bad)))["WEB053"]
    assert sev(i) == "low" and any("not a valid structured-field" in n[0] for n in i.notes)
    ro = (HTML_CT, ("Integrity-Policy-Report-Only", "blocked-destinations=(script)"))
    ctx = ctx_for(html, headers=ro)
    (i,) = rules(run(ctx))["WEB053"]
    assert sev(i) == "low"
    assert ctx.inventory["integrity_policy"]["integrity-policy-report-only"]["enforced"] is False


def test_web500_501_502():
    cdn = "https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"
    html = page(f'<script src="{cdn}" integrity="{SHA384}"></script>'                       # WEB500
                f'<script type="module" src="https://m.third.test/m.js" integrity="{SHA384}"></script>'   # cors by default
                f'<script src="https://good.third.test/g.js" integrity="{SHA384}" crossorigin="anonymous"></script>'
                '<script src="https://s1.third.test/s.js" integrity="sha1-2jmj7l5rSw0yVb/vlWAYkK/YBwk=" crossorigin></script>'
                '<script src="https://s2.third.test/s.js" integrity="sha384-short" crossorigin></script>'
                f'<script src="/same-origin.js" integrity="{SHA384}"></script>')
    found = rules(run(ctx_for(html)))
    assert [i.group_value for i in found["WEB500"]] == [cdn]
    assert sorted(i.group_value for i in found["WEB501"]) == ["https://s1.third.test/s.js", "https://s2.third.test/s.js"]
    assert "WEB053" not in found                     # a weak control is never worse than none: no double report
    http_page = page(f'<script src="http://s.third.test/lib.js" integrity="{SHA384}" crossorigin="anonymous"></script>')
    assert "WEB502" in rules(run(ctx_for(http_page, url="http://www.example.com/")))
    https_page = rules(run(ctx_for(http_page)))
    assert "WEB502" not in https_page and "WEB050" in https_page      # WEB050 explains the element on https


def test_web503_deep_verification_decoded_body():
    body = b"window.lib = 1;\n"
    good = content.sri_digest("sha384", body)
    bad = content.sri_digest("sha384", b"else")
    html = page(f'<script src="https://cdn.third.test/a.js" integrity="{good}" crossorigin="anonymous"></script>'
                f'<script src="https://cdn.third.test/b.js" integrity="{bad}" crossorigin="anonymous"></script>'
                f'<script src="https://cdn.third.test/c.js" integrity="{bad}" crossorigin="anonymous"></script>')
    js = (("Content-Type", "text/javascript"),)
    subs = [resp("https://cdn.third.test/a.js", body, js, kind="script", source="subresource", encoding="gzip"),
            resp("https://cdn.third.test/b.js", body, js, kind="script", source="subresource"),
            resp("https://cdn.third.test/c.js", body, js, kind="script", source="subresource", encoding="br")]
    ctx = ctx_for(html, profile="deep", subresources=subs)
    (i,) = rules(run(ctx))["WEB503"]
    assert i.group_value == "https://cdn.third.test/b.js" and i.confidence == "firm"
    assert good in i.notes[0][0] and bad in i.notes[0][0]
    st = ctx.coverage.state("WEB503")
    assert st.state == "fail" and any(code == "unsupported_coding" for code, _e, _a in st.reasons)


def test_web503_not_tested_without_deep():
    html = page(f'<script src="https://cdn.third.test/a.js" integrity="{SHA384}" crossorigin></script>')
    ctx = ctx_for(html)
    run(ctx)
    assert ctx.coverage.state("WEB503").state == "not_tested"


# ============================================================================================ WEB505–WEB509

def test_web505_rel_opener_only():
    html = page('<a href="https://p.third.test/" target="_blank" rel="opener">a</a>'
                '<a href="https://q.third.test/" target="_blank">b</a>'
                '<a href="https://r.third.test/" target="_blank" rel="opener noopener">c</a>'
                '<a href="https://s.third.test/" target="_self" rel="opener">d</a>'
                '<a href="https://static.example.com/" target="_blank" rel="opener">same site</a>')
    found = rules(run(ctx_for(html)))["WEB505"]
    assert [i.group_value for i in found] == ["third.test"]


def test_web506_src_and_inline():
    html = page('<script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>'
                '<script>var s=document.createElement("script");s.src="//bootcdn.net/x.js";</script>'
                '<script src="https://cdnjs.cloudflare.com/polyfill/v3/polyfill.min.js"></script>')
    found = {i.group_value: i for i in rules(run(ctx_for(html)))["WEB506"]}
    assert set(found) == {"polyfill.io", "bootcdn.net"}
    assert found["polyfill.io"].confidence == "certain" and found["bootcdn.net"].confidence == "firm"


def test_web507_signatures_and_no_generic_obfuscation():
    found = rules(run(ctx_for(page('<script>var m=new CoinHive.Anonymous("k");m.start();</script>'))))
    assert [i.group_value for i in found["WEB507"]] == ["coinhive-api"]
    assert "WEB507" not in rules(run(ctx_for(page('<script>eval(atob("YWxlcnQoMSk="));</script>'))))
    assert "WEB507" not in rules(run(ctx_for(page("<p>We were hacked by nobody</p>"))))   # title unchanged
    deface = page("<h1>Hacked by Someone</h1>", title="HaCkEd By Someone")
    assert "WEB507" in rules(run(ctx_for(deface)))


def test_web507_in_fetched_script_file():
    html = page('<script src="/app.js"></script>')
    js = resp("https://www.example.com/app.js", "x();var c=new CoinHive.User('k','u');", (("Content-Type", "text/javascript"),),
              kind="script", source="subresource")
    (i,) = rules(run(ctx_for(html, subresources=[js])))["WEB507"]
    assert i.url == "https://www.example.com/" and i.evidence.request["url"] == "https://www.example.com/app.js"


def test_web508_password_manager_blocking():
    found = rules(run(ctx_for(page('<form method="post"><input type="password" autocomplete="off"></form>'))))
    assert "WEB508" in found
    found = rules(run(ctx_for(page('<form method="post"><input type="password" onpaste="return false"></form>'))))
    assert "WEB508" in found
    ok = page('<form method="post"><input type="password" autocomplete="current-password"></form>')
    assert "WEB508" not in rules(run(ctx_for(ok)))


def test_web509_variants():
    def one(html, roles=frozenset()):
        ctx = ctx_for(html)
        ctx.entry.roles = roles
        return rules(run(ctx)).get("WEB509", [])
    (i,) = one(page('<form method="get" action="/login"><input type="password" name="p"></form>'))
    assert (sev(i), i.confidence) == ("high", "certain")
    (i,) = one(page('<form action="/login"><input type="password" name="p"></form>'))
    assert (sev(i), i.confidence) == ("high", "certain")
    for html in (page('<form><input type="password" name="p"></form>'),
                 page('<form action="/l" onsubmit="go(event)"><input type="password"></form>'),
                 page('<form id="login" action="/l"><input type="password"></form>'
                      '<script>document.getElementById("login").addEventListener("submit", f);</script>')):
        (i,) = one(html)
        assert (sev(i), i.confidence) == ("low", "tentative")
    (i,) = one(page('<form action="/l"><input type="password"></form>'), frozenset({"app"}))
    assert i.confidence == "tentative"
    assert one(page('<form method="post" action="/l"><input type="password"></form>')) == []
    assert one(page('<form action="/l"><input type="password"><button formmethod="post">x</button></form>')) == []
    assert one(page('<form method="get" action="/search"><input name="q"></form>')) == []


# ============================================================================================ WEB510–WEB513

def test_web510_session_ids_in_urls():
    html = page('<a href="/cart;jsessionid=A1B2C3D4E5F6G7H8I9J0">c</a><a href="/p?PHPSESSID=abcdef0123456789">p</a>'
                '<a href="/(S(abcdefghijklmnopqrstuvwx))/home.aspx">a</a><a href="/x?sid=abc">short</a>'
                '<a href="https://other.test/?sid=0123456789abcdef">off-site link</a>')
    found = rules(run(ctx_for(html)))["WEB510"]
    assert sorted(i.group_value for i in found) == ["(s(…))", "jsessionid", "phpsessid"]
    assert all("Referer" in json.dumps(i.notes) for i in found)
    assert all("A1B2C3D4E5F6G7H8I9J0" not in json.dumps(i.evidence.to_dict()) for i in found)   # redacted


def test_web511_and_web512():
    html = page('<a href="/reset?token=8f3a9c2b7d1e4f60a1b2">r</a><a href="/u?email=a.b@example.org">u</a>'
                '<a href="/pay?n=4111111111111111">c</a><a href="/x?token=abc">short</a><a href="/s?q=kashif">q</a>'
                '<a href="/login?next=https://partner.third.test/home">n</a><a href="/login?next=/home">rel</a>'
                '<form method="get" action="/go"><input type="hidden" name="api_key" value="k-1234567890abcdef"></form>')
    opts = ScanOptions(sensitivity="paranoid")
    found = rules(run(ctx_for(html, sensitivity="paranoid")), opts)
    assert sorted(i.group_value for i in found["WEB511"]) == ["api_key", "email", "n", "token"]
    assert [i.group_value for i in found["WEB512"]] == ["next"]
    assert all(sev(i) == "info" for i in found["WEB512"])
    default = rules(run(ctx_for(html)), ScanOptions())
    assert "WEB511" not in default and "WEB512" not in default      # tentative: paranoid only


def test_luhn():
    assert content.luhn_ok("4111111111111111") and not content.luhn_ok("4111111111111112")


def test_web513_upload_inventory():
    ctx = ctx_for(page('<form method="post" action="/up" enctype="multipart/form-data"><input type="file" name="f"></form>'))
    (i,) = rules(run(ctx))["WEB513"]
    assert i.group_value == "https://www.example.com/up"
    assert ctx.inventory["forms"][0]["file"] is True


@pytest.mark.parametrize("doctype,href,fires", [
    (False, "style.css", True), (False, "/style.css", False), (False, "https://x.test/s.css", False),
    (True, "style.css", False), (False, "../css/s.css", True),
])
def test_web514_quirks(doctype, href, fires):
    html = page("x", head=f'<link rel="stylesheet" href="{href}">', doctype=doctype)
    assert ("WEB514" in rules(run(ctx_for(html)))) is fires


def test_quirks_mode_doctypes():
    assert content.quirks_mode(None)
    assert not content.quirks_mode("html")
    assert content.quirks_mode('html public "-//w3c//dtd html 4.01 transitional//en"')
    assert not content.quirks_mode('html public "-//w3c//dtd html 4.01 transitional//en" "http://www.w3.org/tr/html4/loose.dtd"')
    assert content.quirks_mode('html public "-//w3c//dtd html 3.2 final//en"')


# ============================================================================================ paranoid-only WEB515 / WEB516

def test_paranoid_only_rules_are_not_evaluated_below_paranoid():
    html = page('<button onclick="go()">x</button><a href="javascript:void(0)">y</a>'
                '<form method="post" action="/profile"><input name="bio"></form>')
    ctx = ctx_for(html)
    found = rules(run(ctx))
    assert "WEB515" not in found and "WEB516" not in found
    assert ctx.coverage.state("WEB515").state == "not_tested"
    assert ctx.coverage.state("WEB515").reasons[0][0] == "sensitivity"
    ctx = ctx_for(html, sensitivity="paranoid")
    found = rules(run(ctx))
    assert found["WEB515"][0].notes[0][0] == "Inline event handlers: 1; javascript: URLs: 1."
    assert "WEB516" in found


def test_web516_token_or_samesite_session_suppresses():
    html = page('<form method="post" action="/profile"><input name="bio"><input type="hidden" name="csrfmiddlewaretoken" '
                'value="x"></form>')
    assert "WEB516" not in rules(run(ctx_for(html, sensitivity="paranoid")))
    html = page('<form method="post" action="/profile"><input name="bio"></form>')
    ctx = ctx_for(html, sensitivity="paranoid")
    ctx.cookies = [CookieFact("sessionid", "v", {"samesite": "Lax"}, "sessionid=v; SameSite=Lax", ctx.entry,
                              "www.example.com", True, cls="session")]
    assert "WEB516" not in rules(run(ctx))
    search = page('<form method="post" action="/s"><input type="search" name="q"></form>')
    assert "WEB516" not in rules(run(ctx_for(search, sensitivity="paranoid")))


# ============================================================================================ WEB518 / WEB519

def test_web518_cross_site_password_form():
    html = page('<form method="post" action="https://collect.evil.test/p"><input type="password"></form>')
    (i,) = rules(run(ctx_for(html)))["WEB518"]
    assert sev(i) == "medium"                                  # destination referenced nowhere else
    html2 = page('<form method="post" action="https://sso.idp.test/login"><input type="password"></form>'
                 '<script src="https://sso.idp.test/sdk.js" integrity="' + SHA384 + '" crossorigin></script>')
    (i,) = rules(run(ctx_for(html2)))["WEB518"]
    assert sev(i) == "low"
    same = page('<form method="post" action="https://login.example.com/p"><input type="password"></form>')
    assert "WEB518" not in rules(run(ctx_for(same)))
    malicious = page('<form method="post" action="https://x.bootcss.com/p"><input type="password"></form>'
                     '<img src="https://x.bootcss.com/i.png">')
    assert sev(rules(run(ctx_for(malicious)))["WEB518"][0]) == "medium"


@pytest.mark.parametrize("url,pinned", [
    ("https://cdn.jsdelivr.net/npm/lib@3.7.1/dist/x.js", True),
    ("https://cdn.jsdelivr.net/npm/lib@3.7.1-beta.2/dist/x.js", True),
    ("https://cdn.jsdelivr.net/npm/lib/dist/x.js", False),
    ("https://cdn.jsdelivr.net/npm/lib@latest/dist/x.js", False),
    ("https://cdn.jsdelivr.net/npm/lib@3/dist/x.js", False),
    ("https://cdn.jsdelivr.net/npm/lib@3.6/dist/x.js", False),
    ("https://cdn.jsdelivr.net/npm/lib@^3/dist/x.js", False),
    ("https://cdn.jsdelivr.net/npm/lib@~3.6/dist/x.js", False),
    ("https://cdn.jsdelivr.net/npm/@scope/pkg@1.2.3/x.js", True),
    ("https://cdn.jsdelivr.net/npm/@scope/pkg/x.js", False),
    ("https://cdn.jsdelivr.net/gh/user/repo/x.js", False),
    ("https://cdn.jsdelivr.net/gh/user/repo@main/x.js", False),
    ("https://cdn.jsdelivr.net/gh/user/repo@master/x.js", False),
    ("https://cdn.jsdelivr.net/gh/user/repo@dev/x.js", False),
    ("https://cdn.jsdelivr.net/gh/user/repo@1.2.3/x.js", True),
    ("https://cdn.jsdelivr.net/gh/user/repo@v1.2.3/x.js", True),
    ("https://cdn.jsdelivr.net/gh/user/repo@" + "a" * 40 + "/x.js", True),
    ("https://cdn.jsdelivr.net/combine/npm/a@1.0.0,npm/b@2", False),
    ("https://unpkg.com/react@18.3.1/umd/react.production.min.js", True),
    ("https://unpkg.com/react/umd/react.production.min.js", False),
    ("https://unpkg.com/react@18/umd/react.production.min.js", False),
    ("https://esm.sh/react@18.3.1", True),
    ("https://esm.sh/v135/react@18.3.1/es2022/react.mjs", True),
    ("https://esm.sh/react", False),
    ("https://esm.sh/react@18", False),
    ("https://cdn.skypack.dev/react", False),
    ("https://cdn.skypack.dev/react@17.0.2", True),
    ("https://cdn.skypack.dev/-/react@v17.0.1-yH0aYV1FOvoIPeKBbHxg/dist=es2020,mode=imports/optimized/react.js", False),
    ("https://cdn.skypack.dev/-/react@17.0.1-yH0aYV1FOvoIPeKBbHxg/dist=es2020/react.js", True),
    ("https://ga.jspm.io/npm:lodash@4.17.21/lodash.js", True),
    ("https://ga.jspm.io/npm:lodash@4/lodash.js", False),
])
def test_cdn_pin_vectors(url, pinned):
    pins = content.cdn_pin(url)
    assert pins, url
    assert all(p.pinned for p in pins) is pinned


def test_cdn_pin_not_a_package_cdn():
    assert content.cdn_pin("https://cdnjs.cloudflare.com/ajax/libs/x/1/x.js") == []
    assert content.cdn_pin("https://www.example.com/npm/x.js") == []


def test_web519_rule():
    html = page('<script src="https://cdn.jsdelivr.net/npm/kashif-lib@3/dist/lib.min.js"></script>'
                f'<script src="https://unpkg.com/react/umd/r.js" integrity="{SHA384}" crossorigin></script>'
                '<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/u/r@main/s.css">'
                '<img src="https://cdn.jsdelivr.net/npm/icons/x.svg">')
    found = rules(run(ctx_for(html)))["WEB519"]
    assert sorted(i.group_value for i in found) == ["https://cdn.jsdelivr.net/gh/u/r@main/s.css",
                                                    "https://cdn.jsdelivr.net/npm/kashif-lib@3/dist/lib.min.js"]


# ============================================================================================ WEB517

@pytest.fixture
def hooked(monkeypatch):
    monkeypatch.setenv(content.TEST_HOOK_ENV, "1")
    monkeypatch.setattr(content, "PLATFORM", "linux")


def dns(host, status="ok", reg_status="", reg=""):
    from vulnscan.webscan import psl
    return DnsRecord(host, status, ("192.0.2.1",) if status == "ok" else (), registrable=reg or psl.registrable_domain(host) or "",
                     registrable_status=reg_status)


def ctx517(html, records, **kw):
    ctx = ctx_for(html, url="https://www.site.org/", **kw)
    ctx.entry.ip = "192.0.2.10"
    ctx.dns = {r.host: r for r in records}
    return ctx


def test_web517_variant_a_b_and_categories(monkeypatch):
    monkeypatch.setattr(content, "PLATFORM", "linux")
    html = page('<script src="https://cdn.gone-domain.com/app.js"></script><img src="https://img.gone2.com/x.png">'
                '<script src="https://ghost.live.com/a.js"></script><script src="https://ok.live.com/b.js"></script>')
    ctx = ctx517(html, [dns("www.site.org"), dns("cdn.gone-domain.com", "nxdomain", "nxdomain"),
                        dns("img.gone2.com", "nxdomain", "nxdomain"), dns("ghost.live.com", "nxdomain", "ok"),
                        dns("ok.live.com")])
    found = {i.group_value: i for i in run(ctx) if i.rule == "WEB517"}
    assert (sev(found["cdn.gone-domain.com"]), found["cdn.gone-domain.com"].confidence) == ("high", "firm")
    assert sev(found["img.gone2.com"]) == "medium"
    assert (sev(found["ghost.live.com"]), found["ghost.live.com"].confidence) == ("low", "tentative")
    assert "ok.live.com" not in found
    assert found["cdn.gone-domain.com"].evidence.match["where"] == "dns"


def test_web517_macos_variant_a_tentative(monkeypatch):
    monkeypatch.delenv(content.TEST_HOOK_ENV, raising=False)
    monkeypatch.setattr(content, "PLATFORM", "darwin")
    ctx = ctx517(page('<script src="https://cdn.gone-domain.com/app.js"></script>'),
                 [dns("www.site.org"), dns("cdn.gone-domain.com", "nxdomain", "nxdomain")])
    (i,) = [i for i in run(ctx) if i.rule == "WEB517"]
    assert i.confidence == "tentative" and any("macOS" in n[0] for n in i.notes)


def test_web517_guard_proxy_canary_and_no_public_name(monkeypatch):
    monkeypatch.setattr(content, "PLATFORM", "linux")
    html = page('<script src="https://cdn.gone-domain.com/app.js"></script>'
                '<script src="https://cdnjs.cloudflare.com/ajax/libs/x/1.0.0/x.js"></script>')
    canary = ctx517(html, [dns("www.site.org"), dns("cdn.gone-domain.com", "nxdomain", "nxdomain"),
                           dns("cdnjs.cloudflare.com", "nxdomain", "ok")])
    assert not [i for i in run(canary) if i.rule == "WEB517"]
    st = canary.coverage.state("WEB517")
    assert st.state == "not_tested" and st.reasons[0][0] == "resolver"
    proxied = ctx517(html, [DnsRecord("cdn.gone-domain.com", "not_tested", reason="proxied")], proxied=True)
    assert not [i for i in run(proxied) if i.rule == "WEB517"]
    assert proxied.coverage.state("WEB517").reasons[0][0] == "proxied"
    lonely = ctx517(page('<script src="https://cdn.gone-domain.com/app.js"></script>'),
                    [dns("cdn.gone-domain.com", "nxdomain", "nxdomain")])
    lonely.entry.ip = None
    assert not [i for i in run(lonely) if i.rule == "WEB517"]
    assert lonely.coverage.state("WEB517").state == "not_tested"
    minimal = ctx517(html, [], profile="minimal")
    run(minimal)
    assert minimal.coverage.state("WEB517").reasons[0][0] == "profile"


def test_web517_never_fires_for_reserved_and_tempfail(monkeypatch):
    monkeypatch.delenv(content.TEST_HOOK_ENV, raising=False)
    monkeypatch.setattr(content, "PLATFORM", "linux")
    html = page('<script src="https://cdn.gone.test/a.js"></script><script src="https://x.invalid/a.js"></script>'
                '<script src="https://cdn.temp.com/a.js"></script><script src="https://intranet/a.js"></script>')
    ctx = ctx517(html, [dns("www.site.org"), dns("cdn.gone.test", "nxdomain", "nxdomain"),
                        dns("x.invalid", "nxdomain", "nxdomain"), dns("cdn.temp.com", "tempfail"),
                        dns("intranet", "nxdomain", "nxdomain")])
    found = [i for i in run(ctx) if i.rule == "WEB517"]
    assert [(i.group_value, sev(i)) for i in found] == [("intranet", "info")]
    assert any(code == "network" for code, _e, _a in ctx.coverage.state("WEB517").reasons)


def test_dns_candidates_priority_and_exclusions():
    html = page('<img src="https://img.cdn-a.com/x.png"><form action="https://f.forms.com/p"></form>'
                '<script src="https://js.cdn-b.com/a.js"></script><link rel="stylesheet" href="https://css.cdn-c.com/s.css">'
                '<iframe src="https://frame.cdn-d.com/"></iframe><script src="https://www.site.org/own.js"></script>'
                '<script src="https://x.invalid/a.js"></script><script src="https://192.0.2.7/a.js"></script>'
                '<img src="https://js.cdn-b.com/again.png"><template><script src="https://t.dead.com/t.js"></script></template>')
    ctx = ctx_for(html, url="https://www.site.org/")
    assert content.dns_candidates(ctx.pages, ctx.target) == ["js.cdn-b.com", "css.cdn-c.com", "frame.cdn-d.com",
                                                            "f.forms.com", "img.cdn-a.com"]
    assert len(content.dns_candidates(ctx.pages, ctx.target, limit=2)) == 2


def test_web517_not_run_when_nothing_was_resolved(monkeypatch):
    monkeypatch.setattr(content, "PLATFORM", "linux")
    ctx = ctx517(page('<script src="https://cdn.gone-domain.com/app.js"></script>'), [])
    run(ctx)
    st = ctx.coverage.state("WEB517")
    assert st.state == "not_tested" and st.reasons[0][0] == "not_run"
    ok = ctx517(page('<script src="https://cdn.fine.com/app.js"></script>'), [dns("www.site.org"), dns("cdn.fine.com")])
    run(ok)
    assert ok.coverage.state("WEB517").state == "pass"


def test_web517_variant_c_deleted_bucket():
    html = page('<script src="https://kashif-gone.s3.amazonaws.com/app.js"></script>'
                '<img src="https://acct.blob.core.windows.net/c/i.png">')
    s3 = resp("https://kashif-gone.s3.amazonaws.com/app.js", "<Error><Code>NoSuchBucket</Code></Error>",
              (("Content-Type", "application/xml"),), status=404, kind="error_page", source="subresource")
    az = resp("https://acct.blob.core.windows.net/c/i.png", "ContainerNotFound", (("Content-Type", "application/xml"),),
              status=404, kind="error_page", source="subresource")
    other = resp("https://cdn.other.com/app.js", "<Code>NoSuchBucket</Code>", status=404, kind="error_page")
    ctx = ctx_for(html, profile="deep", subresources=[s3, az, other], proxied=True)
    found = {i.group_value: i for i in run(ctx) if i.rule == "WEB517"}
    assert sev(found["kashif-gone.s3.amazonaws.com"]) == "high"
    assert sev(found["acct.blob.core.windows.net"]) == "medium"
    assert "cdn.other.com" not in found


# ============================================================================================ gates and coverage

def test_waf_entry_is_inconclusive_and_soft404_ignored():
    waf = resp("https://www.example.com/", page('<script src="http://x.test/a.js"></script>'), kind="waf_challenge",
               status=403)
    ctx = ctx_for(None, pages=[Page(waf, None)], entry=waf)
    assert run(ctx) == []
    assert ctx.coverage.state("WEB050").state == "inconclusive"
    soft = resp("https://www.example.com/x", page('<script src="http://x.test/a.js"></script>'), kind="soft404")
    ctx = ctx_for(page("ok"), pages=[soft])
    assert "WEB050" not in rules(run(ctx))


def test_opaque_coding_not_tested():
    br = resp("https://www.example.com/", b"\x8b\x00binary", encoding="br")
    ctx = ctx_for(None, pages=[Page(br, None)], entry=br)
    assert run(ctx) == []
    st = ctx.coverage.state("WEB050")
    assert st.state == "not_tested" and st.reasons[0][0] == "unsupported_coding"


def test_unclassified_html_is_judged_and_api_is_not():
    r = resp("https://www.example.com/", page('<script src="http://x.test/a.js"></script>'), kind="")
    assert "WEB050" in rules(run(ctx_for(None, pages=[r], entry=r)))
    j = resp("https://www.example.com/api", '{"html": "<script src=\\"http://x.test/a.js\\"></script>"}',
             (("Content-Type", "application/json"),), kind="api_json")
    assert run(ctx_for(None, pages=[j], entry=j)) == []


def test_coverage_pass_and_fail():
    ctx = ctx_for(page("<p>plain</p>"))
    run(ctx)
    assert ctx.coverage.state("WEB050").state == "pass"
    assert ctx.coverage.state("WEB052").state == "not_applicable"
    ctx = ctx_for(page('<img src="http://x.test/a.png">'))
    run(ctx)
    assert ctx.coverage.state("WEB050").state == "fail"
    assert set(content.CHECKS) == {r for r in RULES if RULES[r].module == "content"}


def test_hostile_values_are_inert():
    html = page('<script src="http://x.test/{items}\x1b[31m.js"></script>'
                '<a href="https://p.third.test/{url}" target="_blank" rel="opener">x</a>')
    for i in run(ctx_for(html)):
        for en, ar in i.notes:
            assert "\x1b" not in en and "\x1b" not in ar
    assert "'$(id)'" not in " ".join(i.evidence.curl for i in run(ctx_for(page("x"), url="https://www.example.com/'$(id)'")))


def test_crawl_pages_group_the_same_form():
    a = resp("https://www.example.com/a", page('<form method="post" action="http://www.example.com/s"><input name="e"></form>'))
    b = resp("https://www.example.com/b", page('<form method="post" action="http://www.example.com/s?x=1"><input name="e"></form>'))
    found = rules(run(ctx_for(page("home"), pages=[a, b])))["WEB051"]
    assert len(found) == 2 and len({(i.host, i.group_value) for i in found}) == 1


# ============================================================================================ Observatory

@pytest.mark.parametrize("body,ctype,url,expected", [
    (None, None, None, "sri-not-implemented-but-no-scripts-loaded"),
    ("{}", "application/json", "https://site.test/", "sri-not-implemented-response-not-html"),
    ("<p>x</p>", "text/html", "https://site.test/", "sri-not-implemented-but-no-scripts-loaded"),
    ("<script>1</script>", "text/html", "https://site.test/", "sri-not-implemented-but-all-scripts-loaded-from-secure-origin"),
    ('<script src="/a.js"></script>', "text/html", "https://site.test/",
     "sri-not-implemented-but-all-scripts-loaded-from-secure-origin"),
    (f'<script src="/a.js" integrity="{SHA384}"></script>', "text/html", "https://site.test/",
     "sri-implemented-and-all-scripts-loaded-securely"),
    ('<script src="https://cdn.other.test/a.js"></script>', "text/html", "https://site.test/",
     "sri-not-implemented-but-external-scripts-loaded-securely"),
    (f'<script src="https://cdn.other.test/a.js" integrity="{SHA384}"></script>', "text/html", "https://site.test/",
     "sri-implemented-and-external-scripts-loaded-securely"),
    (f'<script src="http://cdn.other.test/a.js" integrity="{SHA384}"></script>', "text/html", "https://site.test/",
     "sri-implemented-but-external-scripts-not-loaded-securely"),
    ('<script src="http://cdn.other.test/a.js"></script>', "text/html", "https://site.test/",
     "sri-not-implemented-and-external-scripts-not-loaded-securely"),
    ('<script src="//cdn.other.test/a.js"></script>', "text/html", "https://site.test/",          # quirk: never secure
     "sri-not-implemented-and-external-scripts-not-loaded-securely"),
    ('<script src="https://static.site.test/a.js"></script>', "text/html", "https://www.site.test/",
     "sri-not-implemented-but-all-scripts-loaded-from-secure-origin"),
    # quirk: -5 (index 3) is "worse" than -20 (index 2) in Observatory's order
    (f'<script src="http://a.other.test/a.js" integrity="{SHA384}"></script><script src="https://b.other.test/b.js"></script>',
     "text/html", "https://site.test/", "sri-not-implemented-but-external-scripts-loaded-securely"),
    ('<script src="https://cdn.other.test/a.js"></script>', "Text/HTML", "https://site.test/",   # case-sensitive mime
     "sri-not-implemented-response-not-html"),
    ('<template><script src="http://x.other.test/a.js"></script></template>', "text/html", "https://site.test/",
     "sri-not-implemented-and-external-scripts-not-loaded-securely"),
])
def test_observatory_sri_slug(body, ctype, url, expected):
    r = None if body is None else resp(url, body, (("Content-Type", ctype),))
    host = "site.test" if url is None else re.sub(r"^https?://([^/]+)/.*$", r"\1", url)
    assert content.observatory_sri_slug(r, host) == expected


def test_observatory_private_psl_section_is_ignored_like_tldts():
    r = resp("https://a.github.io/", '<script src="https://b.github.io/x.js"></script>')
    assert content.observatory_sri_slug(r, "a.github.io") == "sri-not-implemented-but-all-scripts-loaded-from-secure-origin"
    ctx = ctx_for(page('<script src="https://b.github.io/x.js"></script>'), url="https://a.github.io/")
    found = rules(run(ctx))
    assert "WEB053" in found                                     # Kashif uses the private section: a third party
    assert ctx.observatory["subresource-integrity"] == "sri-not-implemented-but-all-scripts-loaded-from-secure-origin"


# ============================================================================================ data, i18n, tools

def test_malicious_hosts_data_file():
    obj = data.load_json(content.MALICIOUS_FILE)
    assert data.validate_data(content.MALICIOUS_FILE, obj) == []
    hosts = {h["host"] for h in obj["hosts"]}
    assert {"polyfill.io", "bootcss.com", "bootcdn.net", "staticfile.net", "staticfile.org", "unionadjs.com",
            "xhsbpza.com", "union.macoms.la", "newcrbpc.com"} <= hosts
    for s in obj["signatures"]:
        re.compile(s["pattern"])
        assert "atob" not in s["pattern"] and "eval" not in s["pattern"]


def test_refresh_script_is_deterministic(tmp_path):
    script = ROOT / "tools" / "webdata" / "malicious_hosts.py"
    out = subprocess.run([sys.executable, str(script), "--check"], capture_output=True, text=True, cwd=str(ROOT))
    assert out.returncode == 0, out.stderr
    spec = importlib.util.spec_from_file_location("mh_tool", script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    a = mod.render(mod.build("2026-01-01"))
    assert a == mod.render(mod.build("2026-01-01"))
    java = 'Pattern.compile("(?:https?:)?//(?:[a-z0-9-]+\\\\.)*(polyfill\\\\.io|bootcss\\\\.com|newsite\\\\.example)")'
    assert "newsite.example" in mod.zap_hosts(java)


def test_missing_data_file_is_not_tested():
    class NoData:
        @staticmethod
        def load_json(name):
            raise FileNotFoundError(name)
    ctx = ctx_for(page('<script src="https://polyfill.io/x.js"></script>'), data=NoData())
    assert "WEB506" not in rules(run(ctx))
    assert ctx.coverage.state("WEB506").reasons[0][0] == "data_missing"


_ARABIC = re.compile(r"[\u0600-\u06FF]")


def test_every_note_is_bilingual_and_catalogued():
    for key, (en, ar) in {**content.STR, **content.WHY}.items():
        assert en.strip() and ar.strip(), key
        assert _ARABIC.search(ar) or en == ar, key
        assert set(re.findall(r"\{([a-z_]+)\}", en)) == set(re.findall(r"\{([a-z_]+)\}", ar)), key
    catalog, patterns = content.i18n_catalog()
    for rx, repl in patterns:
        re.compile(rx)
    en, ar = content._note("dns_a", host="a.test", domain="test")
    assert any(re.match(rx, ar) and re.sub(rx, repl, ar) == en for rx, repl in patterns)
    en, ar = content._count(5, content._COUNT_ACTIVE)
    assert ar == "5 عناصر نشطة" and en == "5 active items"
    assert any(re.match(rx, ar) and re.sub(rx, repl, ar) == en for rx, repl in patterns)
    assert content._count(1, content._COUNT_ACTIVE)[1] in catalog
    for n, ar_want in ((9, "9 أحرف"), (20, "20 حرفًا"), (100, "100 حرف")):
        assert content._count(n, content._COUNT_CHARS)[1] == ar_want
    assert content._count(48, content._COUNT_BYTES) == ("48 bytes", "48 بايتًا")
    en, ar = content._note("session_param", name="sid", length=content._count(20, content._COUNT_CHARS), url="u")
    assert en == "Parameter sid carries a value of 20 characters in u." and "20 حرفًا" in ar


# ============================================================================================ corpus cases (offline)

MY_RULES = {r for r in RULES if RULES[r].module == "content"}


def _corpus():
    path = ROOT / "bench" / "web" / "corpus.py"
    if not path.is_file():
        pytest.skip("bench/web/corpus.py not present")
    spec = importlib.util.spec_from_file_location("kashif_bench_corpus", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("kashif_bench_corpus", mod)
    spec.loader.exec_module(mod)
    return mod


CORPUS = None


def _cases():
    global CORPUS
    try:
        CORPUS = CORPUS or _corpus()
    except pytest.skip.Exception:
        return []
    return [c for c in CORPUS.CASES if set(c.labels) & MY_RULES and not callable(c.routes.get(c.path))]


def _render(text: str, case, port: int = 8443) -> str:
    def sub(m):
        tok, arg = m.group(1), m.group(2)
        if tok == "NONCE":
            return "bm9uY2Vub25jZW5vbmNlMTIz"
        if tok == "RAND":
            return "0123456789abcdef0123456789abcdef"
        if tok in ("HTTPS_PORT", "HTTP_PORT"):
            return str(port)
        if tok == "CASE":
            return case.id
        if tok == "HOST":
            return case.alias_host(arg) if arg else case.host
        if tok == "THIRD":
            return f"https://{case.alias_host('third')}"
        if tok in ("EXPIRES", "PAST"):
            return "2027-01-01T00:00:00Z"
        host = case.alias_host(arg) if arg else case.host
        return f"{tok.lower() if tok in ('HTTP', 'HTTPS') else case.scheme}://{host}"
    return CORPUS._TOKEN.sub(sub, text)


def _response(case, url: str, route, source: str) -> Response:
    body = route.body if isinstance(route.body, bytes) else _render(route.body, case).encode()
    headers = HeaderList.of(*[(k, _render(v, case)) for k, v in route.headers])
    ess = (headers.first("content-type") or "").split(";")[0].strip().lower()
    kind = ("document" if ess == "text/html" and 200 <= route.status < 300 else
            "script" if "javascript" in ess else "style" if ess == "text/css" else
            "error_page" if route.status >= 400 else "other")
    return Response(url=url, status=route.status, headers=headers, body=body, kind=kind, source=source,
                    ip="127.0.0.1")


def _corpus_ctx(case) -> ScanContext:
    base = f"{case.scheme}://{case.host}"
    entry = _response(case, base + case.path, case.routes[case.path], "entry")
    pages = [Page(entry, htmlparse.parse_response(entry))]
    subs: list[Response] = []
    for key, route in case.routes.items():
        if callable(route) or key in (case.path, "*"):
            continue
        if ":" in key.split("/", 1)[0]:
            alias, path = key.split(":", 1)
            url = f"https://{case.alias_host(alias)}" + (":8443" if alias != "third" else "") + path
            subs.append(_response(case, url, route, "subresource"))
        elif case.crawl and route.status == 200 and b"<html" in (route.body if isinstance(route.body, bytes)
                                                                   else route.body.encode()):
            r = _response(case, base + key, route, "crawl")
            pages.append(Page(r, htmlparse.parse_response(r), 1))
        else:
            subs.append(_response(case, base + key, route, "subresource"))
    ctx = ScanContext(options=ScanOptions(profile=case.profile, sensitivity=case.sensitivity), target=base + case.path,
                      entry=entry, pages=pages, subresources=subs, proxied=case.use_proxy)
    ctx.coverage = coverage.Coverage()
    hostmap = {h: "ok" for h in case.all_hosts()}
    default = case.dns.get("*", {}).get("status", "ok")
    for name, entry_ in case.dns.items():
        if name != "*":
            hostmap[name] = entry_.get("status", "ok")
    from vulnscan.webscan import psl
    referenced = {content._host(i.url) for _p in pages for i in content._attr_items(_p.doc)} | {case.host}
    for h in referenced:
        if not h:
            continue
        if case.use_proxy:
            ctx.dns[h] = DnsRecord(h, "not_tested", reason="proxied")
            continue
        status = hostmap.get(h, default)
        reg = psl.registrable_domain(h) or ""
        reg_status = hostmap.get(reg, default) if status == "nxdomain" else ""
        ctx.dns[h] = DnsRecord(h, status, ("127.0.0.1",) if status == "ok" else (), registrable=reg,
                               registrable_status=reg_status)
    return ctx


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c.id)
def test_corpus_case(case, monkeypatch):
    monkeypatch.setenv(content.TEST_HOOK_ENV, "1")
    monkeypatch.setattr(content, "PLATFORM", "linux")
    ctx = _corpus_ctx(case)
    issues = run(ctx)
    shown = rules(issues, ctx.options)
    for rule, must in case.labels.items():
        if rule not in MY_RULES:
            continue
        assert (rule in shown) is must, (case.id, rule, must, [(i.rule, i.severity, i.confidence) for i in issues])
    exp = case.expect
    for rule, want in exp.get("severity", {}).items():
        if rule in MY_RULES:
            assert max((sev(i) for i in shown[rule]), key=lambda s: -["critical", "high", "medium", "low", "info"].index(s)) \
                == want, (case.id, rule)
    order = ["info", "low", "medium", "high", "critical"]
    for rule, want in exp.get("max_severity", {}).items():
        if rule in MY_RULES:
            assert all(order.index(sev(i)) <= order.index(want) for i in shown.get(rule, [])), (case.id, rule)
    for rule, want in exp.get("states", {}).items():
        if rule in MY_RULES:
            assert ctx.coverage.state(rule).state == want, (case.id, rule)
    for rule, want in exp.get("count", {}).items():
        if rule in MY_RULES:
            assert len({(i.host, i.group_value) for i in shown.get(rule, [])}) == want, (case.id, rule)


def test_corpus_has_cases_for_wp7():
    ids = {c.id for c in _cases()}
    if not ids:
        pytest.skip("corpus not present")
    for needed in ("html-script-http", "html-sri-mismatch", "rev-jsdelivr-unpinned", "rev-unregistered-script",
                   "rev-s3-nosuchbucket", "rev-all-nxdomain", "rev-proxied"):
        assert needed in ids
