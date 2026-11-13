"""WP5: Set-Cookie parsing, cookie classification and the cookie checks (spec §2.5, §3.3).

Offline: synthetic responses, plus the C-COOKIE corpus cases (and the two WEB414 review cases) rendered in memory from
``bench/web/corpus.py`` without opening any socket.
"""

from __future__ import annotations

import base64
import importlib
import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vulnscan.webscan import cookies, data, htmlparse, rules
from vulnscan.webscan.coverage import Coverage
from vulnscan.webscan.types import (
    CheckModule,
    HeaderList,
    HstsVerdict,
    Page,
    Response,
    ScanContext,
    ScanOptions,
)

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 11, 13, 12, 0, 0, tzinfo=timezone.utc)
RAND = "9f86d081884c7d659a2feaa0c55ad015"          # 32 hex: entropy ≈ 3.8


# ----------------------------------------------------------------------------------------------- helpers

def resp(url="https://www.example.com/", *cookie_values, headers=(), status=200, body=b"", kind="document", **kw):
    hs = list(headers) + [("Set-Cookie", v) for v in cookie_values]
    if isinstance(body, str):
        body = body.encode("utf-8")
    if body and not any(k.lower() == "content-type" for k, _ in hs):
        hs.insert(0, ("Content-Type", "text/html; charset=utf-8"))
    return Response(url=url, status=status, headers=HeaderList.of(*hs), body=body, kind=kind, **kw)


def ctx_for(entry, *, sensitivity="default", hsts=None, pages=None, ignore=(), target=None, **fields):
    opts = ScanOptions(sensitivity=sensitivity, cookie_ignore=tuple(ignore))
    pages = list(pages or [])
    if entry is not None and not any(p.response is entry for p in pages) and entry.kind == "document":
        pages.insert(0, Page(entry, None, 0))
    ctx = ScanContext(options=opts, target=target or (entry.url if entry is not None else "https://www.example.com/"),
                      entry=entry, pages=pages, now=NOW, coverage=Coverage(), **fields)
    for host, verdict in (hsts or {}).items():
        ctx.hsts[host] = verdict
    ctx.cookies = cookies.parse_and_classify(ctx)
    return ctx


def hsts(host, *, sub=True, max_age=63072000, preloaded=False):
    return HstsVerdict(host=host, present=True, valid=True, max_age=max_age, include_subdomains=sub, effective=True,
                       preloaded=preloaded, header_values=(f"max-age={max_age}" + ("; includeSubDomains" if sub else ""),))


def reported(ctx, issues):
    return [i for i in issues if ctx.options.reports(i.confidence)]


def by_rule(issues):
    out: dict[str, list] = {}
    for i in issues:
        out.setdefault(i.rule, []).append(i)
    return out


def scan(*cookie_values, url="https://www.example.com/", **kw):
    ctx = ctx_for(resp(url, *cookie_values, body=kw.pop("body", "<p>x</p>")), **kw)
    issues = cookies.run(ctx)
    for i in issues:
        assert rules.validate_issue(i) == [], (i.rule, rules.validate_issue(i))
    return ctx, issues, by_rule(reported(ctx, issues))


# ----------------------------------------------------------------------------------------------- module shape

def test_module_shape():
    assert isinstance(cookies, CheckModule)
    assert cookies.CHECKS == rules.checks_for_module("cookies")
    ids = set(cookies.CHECKS)
    assert {"WEB020", "WEB021", "WEB022"} <= ids
    assert {f"WEB4{n:02d}" for n in range(15)} <= ids


# ----------------------------------------------------------------------------------------------- RFC 6265bis parsing

@pytest.mark.parametrize("raw,name,value,attrs", [
    ("a=b", "a", "b", {}),
    ("  a = b ; Path=/ ", "a", "b", {"path": "/"}),
    ("novalue", "", "novalue", {}),                       # no "=": empty name, the token is the value
    ("a=", "a", "", {}),
    ("a=b=c", "a", "b=c", {}),
    ('a="quoted"', "a", '"quoted"', {}),
    ("a=b; SECURE; HttpOnly", "a", "b", {"secure": "", "httponly": ""}),
    ("a=b; Secure=yes", "a", "b", {"secure": ""}),        # flag values are ignored
    ("a=b; samesite=lax; SameSite=Strict", "a", "b", {"samesite": "Strict"}),   # last one wins
    ("a=b; Max-Age=10; Max-Age=abc", "a", "b", {"max-age": "10"}),             # invalid ones are ignored
    ("a=b; Domain=; Domain=.Example.COM", "a", "b", {"domain": ".Example.COM"}),
    ("a=b; Domain=example.com; Domain=", "a", "b", {"domain": "example.com"}),  # empty Domain ignored
    ("a=b; Expires=not a date", "a", "b", {}),
    ("a=b; ;; Foo", "a", "b", {"foo": ""}),
    ("a=b; Path=" + "/x" * 600, "a", "b", {}),            # attribute value over 1024 bytes ignored
])
def test_parse_vectors(raw, name, value, attrs):
    p = cookies.parse_set_cookie(raw)
    assert p is not None
    assert (p.name, p.value, p.attrs) == (name, value, attrs)


@pytest.mark.parametrize("raw", ["", " ; ", "=", "a=b\x00c", "a=b\nc", "a=\x7fb"])
def test_parse_ignored_fields(raw):
    assert cookies.parse_set_cookie(raw) is None


def test_parse_htab_allowed_and_no_comma_split():
    p = cookies.parse_set_cookie("a=b\tc; Path=/")
    assert p is not None and p.value == "b\tc"
    p = cookies.parse_set_cookie("a=1, b=2; Secure")        # never split on commas
    assert p.name == "a" and p.value == "1, b=2" and "secure" in p.attrs


@pytest.mark.parametrize("text,expected", [
    ("Wed, 21 Oct 2015 07:28:00 GMT", datetime(2015, 10, 21, 7, 28, tzinfo=timezone.utc)),
    ("Thu, 01-Jan-1970 00:00:01 GMT", datetime(1970, 1, 1, 0, 0, 1, tzinfo=timezone.utc)),
    ("Sunday, 06-Nov-94 08:49:37 GMT", datetime(1994, 11, 6, 8, 49, 37, tzinfo=timezone.utc)),
    ("Sun Nov  6 08:49:37 1994", datetime(1994, 11, 6, 8, 49, 37, tzinfo=timezone.utc)),
    ("06 Nov 30 08:49:37", datetime(2030, 11, 6, 8, 49, 37, tzinfo=timezone.utc)),
    ("Wed, 21 Oct 2015", None),
    ("Wed, 32 Oct 2015 07:28:00 GMT", None),
    ("Wed, 21 Oct 1600 07:28:00 GMT", None),
    ("Wed, 21 Foo 2015 07:28:00 GMT", None),
])
def test_cookie_dates(text, expected):
    assert cookies.parse_cookie_date(text) == expected


def test_facts_cover_every_hop_and_flag_deletions_and_ignores():
    hop = resp("http://example.com/", "sid=" + RAND + "; Path=/", status=301, kind="redirect",
               headers=[("Location", "https://www.example.com/")])
    final = resp("https://www.example.com/", "a=1; Max-Age=0", "b=2; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                 "c=3; Max-Age=60; Expires=Thu, 01 Jan 1970 00:00:00 GMT", "skipme=1", "d=4", chain=[hop])
    ctx = ctx_for(final, ignore=("SKIPME",))
    facts = {f.name: f for f in ctx.cookies}
    assert set(facts) == {"sid", "a", "b", "c", "skipme", "d"}
    assert facts["sid"].response is hop and not facts["sid"].secure_context and facts["sid"].host == "example.com"
    assert facts["a"].deletion and facts["b"].deletion
    assert not facts["c"].deletion                         # Max-Age wins over Expires
    assert facts["skipme"].ignored and not facts["d"].ignored
    assert [f.index for f in ctx.cookies if f.response is final] == [0, 1, 2, 3, 4]


def test_cookie_values_never_reach_evidence():
    ctx, issues, _ = scan("sessionid=" + RAND + "; Path=/")
    blob = json.dumps([i.evidence.to_dict() for i in issues] + [i.notes for i in issues], ensure_ascii=False)
    assert issues and RAND not in blob
    assert "<redacted:32 bytes>" in blob


# ----------------------------------------------------------------------------------------------- classification

@pytest.mark.parametrize("name,value,cls,source", [
    ("PHPSESSID", "x", "session", "table"),
    ("jsessionid", "x", "session", "table"),
    ("ASPSESSIONIDQACTDSTA", "x", "session", "table"),
    ("_myapp_session", "x", "session", "table"),           # Rails _*_session
    ("SSESS" + "a" * 32, "x", "session", "table"),
    ("wordpress_logged_in_abc", "x", "session", "table"),
    ("__Host-sid", "x", "session", "table"),               # prefixes are ignored for the lookup
    ("remember_web_59ba36", "x", "auth", "table"),
    ("XSRF-TOKEN", "x", "csrf", "table"),
    ("_ga", "GA1.2.3.4", "analytics", "table"),
    ("_ga_ABC123", "x", "analytics", "table"),
    ("_hjSession_123", "x", "analytics", "table"),         # analytics cookie with a session-like word
    ("_pk_ses.1.abcd", "*", "analytics", "table"),
    ("BIGipServerpool_web", "x", "lb", "table"),
    ("AWSALB", "x", "lb", "table"),
    ("__cf_bm", "x", "cdn_bot", "table"),
    ("OptanonConsent", "x", "consent", "table"),
    ("lang", "en", "preference", "table"),
    ("my_sess", "x", "session", "heuristic"),
    ("appSession", "x", "session", "heuristic"),           # camelCase word
    ("user_login", "x", "session", "heuristic"),
    ("MYAPPSESSIONID", "x", "session", "heuristic"),       # all-caps word ending in sessionid
    ("api_token", "x", "auth", "heuristic"),
    ("OAuthState", "x", "auth", "heuristic"),
    ("my_csrf_cookie", "x", "csrf", "heuristic"),
    ("x_xsrf_token", "x", "csrf", "heuristic"),           # csrf wins over the token word
    ("sidebar_state", "open", "preference", "table"),
    ("sidebar_open", "x", "unknown", "default"),           # word-bounded: not "sid"
    ("consider_this", "x", "unknown", "default"),
    ("outside_eu", "x", "unknown", "default"),
    ("author_pref", "x", "unknown", "default"),            # not "auth"
    ("data", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "auth", "value"),
    ("flag", "true", "preference", "value"),
    ("ui", "ar", "preference", "value"),
    ("acct_ref", RAND, "unknown_secret", "value"),
    ("cart", "3 items", "unknown", "default"),
    ("blob", "A" * 40, "unknown", "default"),              # long but zero entropy
])
def test_classification(name, value, cls, source):
    assert cookies.classify(name, value) == (cls, source)


def test_table_matches_case_insensitively_and_prefers_exact_then_specific_globs():
    t = cookies.ClassTable([{"name": "a*", "match": "glob", "class": "analytics"},
                            {"name": "ab_*", "match": "glob", "class": "lb"},
                            {"name": "AB_X", "match": "exact", "class": "session"}])
    assert t.lookup("ab_x") == "session" and t.lookup("AB_Y") == "lb" and t.lookup("Az") == "analytics"
    assert t.lookup("b") is None


def test_name_words():
    assert cookies.name_words("ASP.NET_SessionId") == ["asp", "net", "session", "id"]
    assert cookies.name_words("sess1_x-y") == ["sess", "x", "y"]
    assert cookies.name_words("OAuthToken") == ["o", "auth", "token"]


def test_entropy():
    assert cookies.shannon_entropy("") == 0
    assert cookies.shannon_entropy("aaaa") == 0
    assert 3.5 < cookies.shannon_entropy(RAND) <= 4.0


def test_data_file_schema_and_builder_in_sync():
    obj = data.load_json("cookies.json")
    assert data.validate_data("cookies.json", obj) == []
    names = [e["name"].lower() for e in obj["entries"]]
    assert len(names) == len(set(names))
    spec = importlib.util.spec_from_file_location("kashif_webdata_cookies", ROOT / "tools" / "webdata" / "cookies.py")
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    seed = {e["name"].lower(): e["class"] for e in tool.seed_entries()}
    table = {e["name"].lower(): e["class"] for e in obj["entries"] if e.get("source") == "kashif"}
    assert seed == table, "cookies.json is out of date: run python tools/webdata/cookies.py"
    for e in obj["entries"]:
        if e.get("source") == "ocd":
            assert e["class"] in ("analytics", "consent")
            assert not tool.heuristic_hit(e["name"].rstrip("*")), e
            assert cookies.heuristic_class(e["name"].rstrip("*")) is None, e   # same heuristics in both files
    for sample in ("sessionid", "x_sess", "csrf", "auth_key", "ANON", "matomo_sessid", "visitorToken", "rememberMe"):
        assert tool.heuristic_hit(sample) == (cookies.heuristic_class(sample) is not None), sample
        assert tool._words(sample) == cookies.name_words(sample)
    # an Open Cookie Database row named like a session cookie never reaches the table
    csv_text = ("ID,Platform,Category,Cookie / Data Key name,Domain,Description,Retention period,Data Controller,"
                "User Privacy & GDPR Rights Portals,Wildcard match\n"
                "1,Instagram,Marketing,sessionid,,,,,,0\n2,X,Marketing,auth_token,,,,,,0\n3,Acme,Analytics,acme_vid,,,,,,0\n"
                "4,Acme,Analytics,uid,,,,,,0\n5,Acme,Analytics,acme_seg_,,,,,,1\n6,OneTrust,Functional,OTFoo,,,,,,0\n"
                "7,Acme,Functional,acme_cart,,,,,,0\n")
    built, stats = tool.build(csv_text, "2026-11-13")
    ocd = {e["name"]: e["class"] for e in built["entries"] if e["source"] == "ocd"}
    assert ocd == {"acme_vid": "analytics", "acme_seg_*": "analytics", "OTFoo": "consent"}
    assert stats["heuristic"] == 1 and stats["generic"] == 2      # sessionid and uid are generic words
    assert tool.dump(built) == tool.dump(tool.build(csv_text, "2026-11-13")[0])     # deterministic


# ----------------------------------------------------------------------------------------------- WEB020 / 021 / 022

def test_web020_session_without_hsts_is_high():
    _ctx, _i, r = scan("sessionid=" + RAND + "; Path=/; HttpOnly; SameSite=Lax")
    assert [i.severity for i in r["WEB020"]] == ["high"]
    assert r["WEB020"][0].confidence == "certain" and r["WEB020"][0].params == {"cookie": "sessionid"}


def test_web020_session_with_hsts_is_medium_host_only():
    _ctx, _i, r = scan("sessionid=" + RAND + "; Path=/; HttpOnly; SameSite=Lax",
                       hsts={"www.example.com": hsts("www.example.com", sub=False)})
    assert [i.severity for i in r["WEB020"]] == ["medium"]


def test_web020_domain_cookie_needs_include_subdomains_on_the_domain():
    raw = "sessionid=" + RAND + "; Path=/; HttpOnly; SameSite=Lax; Domain=example.com"
    _c, _i, r = scan(raw, hsts={"www.example.com": hsts("www.example.com")})
    assert r["WEB020"][0].severity == "high"               # nothing covers example.com and its other hosts
    _c, _i, r = scan(raw, hsts={"www.example.com": hsts("www.example.com"), "example.com": hsts("example.com")})
    assert r["WEB020"][0].severity == "medium"
    _c, _i, r = scan(raw, hsts={"example.com": hsts("example.com", sub=False)})
    assert r["WEB020"][0].severity == "high"


def test_web020_by_class():
    _c, _i, r = scan("csrftoken=" + RAND + "; Path=/; SameSite=Lax")
    assert r["WEB020"][0].severity == "low"
    _c, _i, r = scan("cart=3; Path=/; SameSite=Lax")
    assert r["WEB020"][0].severity == "low"
    for raw in ("_ga=GA1.2.3.4; Path=/", "OptanonConsent=x; Path=/", "lang=en; Path=/"):
        _c, _i, r = scan(raw)
        assert "WEB020" not in r, raw
        _c, _i, r = scan(raw, sensitivity="paranoid")
        assert [i.severity for i in r["WEB020"]] == ["info"], raw


def test_web020_d3_secure_word_in_name_or_value_is_not_the_flag():
    for raw in ("secure_pref_sid=" + RAND + "; Path=/; HttpOnly", "sessionid=secure; Path=/; HttpOnly",
                "sessionid=" + RAND + "; Path=/secure; HttpOnly"):
        _c, _i, r = scan(raw)
        assert "WEB020" in r, raw
    _c, _i, r = scan("sessionid=" + RAND + "; secure; HttpOnly; SameSite=Lax")
    assert "WEB020" not in r


def test_web020_not_on_http_and_not_for_rejected_prefix():
    _c, _i, r = scan("sessionid=" + RAND + "; Path=/", url="http://www.example.com/")
    assert "WEB020" not in r and "WEB413" in r
    _c, _i, r = scan("__Secure-id=" + RAND + "; Path=/; HttpOnly; SameSite=Lax")
    assert "WEB020" not in r and "WEB401" in r


def test_unknown_secret_default_vs_paranoid():
    raw = "vid=" + RAND + "; Path=/"
    _c, _i, r = scan(raw)
    assert r["WEB020"][0].severity == "low" and "WEB021" not in r and "WEB022" not in r
    ctx, issues, _r = scan(raw, sensitivity="paranoid")
    full = by_rule(issues)
    assert (full["WEB020"][0].severity, full["WEB020"][0].confidence) == ("high", "tentative")
    assert (full["WEB021"][0].severity, full["WEB021"][0].confidence) == ("medium", "tentative")
    assert (full["WEB022"][0].severity, full["WEB022"][0].confidence) == ("low", "tentative")
    assert not ScanOptions(sensitivity="default").reports("tentative")


def test_web021_session_only_and_confidence_by_source():
    _c, _i, r = scan("PHPSESSID=" + RAND + "; Path=/; Secure; SameSite=Lax")
    assert (r["WEB021"][0].severity, r["WEB021"][0].confidence) == ("medium", "certain")
    _c, _i, r = scan("app_sess=" + RAND + "; Path=/; Secure; SameSite=Lax")
    assert r["WEB021"][0].confidence == "firm"
    for raw in ("XSRF-TOKEN=" + RAND + "; Secure; SameSite=Lax", "_ga=GA1.2.3.4; Secure; SameSite=Lax",
                "OptanonConsent=x; Secure; SameSite=Lax", "theme=dark; Secure; SameSite=Lax",
                "AWSALB=abc; Secure; SameSite=Lax", "cart=3; Secure; SameSite=Lax"):
        _c, _i, r = scan(raw)
        assert "WEB021" not in r, raw
    _c, issues, _r = scan("cart=3; Secure; SameSite=Lax", sensitivity="paranoid")
    assert [(i.severity, i.confidence) for i in issues if i.rule == "WEB021"] == [("info", "tentative")]


def test_web022_by_class():
    _c, _i, r = scan("sessionid=" + RAND + "; Secure; HttpOnly")
    assert r["WEB022"][0].severity == "low"
    _c, _i, r = scan("csrftoken=" + RAND + "; Secure")
    assert r["WEB022"][0].severity == "low" and "WEB021" not in r
    _c, _i, r = scan("_gid=GA1.2.3; Secure")
    assert "WEB022" not in r
    _c, _i, r = scan("_gid=GA1.2.3; Secure", sensitivity="paranoid")
    assert r["WEB022"][0].severity == "info"


def test_d4_deletion_cookies_and_ignore_list_are_skipped():
    _c, issues, _r = scan("sid=deleted; Max-Age=0; Path=/", "sessionid=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/",
                          sensitivity="paranoid")
    assert issues == []
    _c, issues, _r = scan("legacy_sess=" + RAND + "; Path=/", ignore=("legacy_sess",), sensitivity="paranoid")
    assert issues == []
    _c, issues, _r = scan("legacy_sess=" + RAND + "; Path=/", ignore=("legacy_*",))
    assert issues == []


# ----------------------------------------------------------------------------------------------- WEB4xx

def test_web400_samesite_none_without_secure_rejected():
    _c, issues, r = scan("embed_pref=" + RAND + "; Path=/; SameSite=None")
    assert set(r) == {"WEB400"}                            # rejected cookie: no Secure/SameSite quality findings
    _c, _i, r = scan("embed_pref=1; Path=/; Secure; SameSite=none")
    assert "WEB400" not in r


@pytest.mark.parametrize("raw,url,bad", [
    ("__Secure-id=1; Path=/", "https://www.example.com/", True),
    ("__secure-id=1; Path=/", "https://www.example.com/", True),           # case-insensitive prefix
    ("__Secure-id=1; Secure; Path=/x", "https://www.example.com/", False),
    ("__Secure-id=1; Secure", "http://www.example.com/", True),
    ("__Host-id=1; Secure; Path=/", "https://www.example.com/", False),
    ("__Host-id=1; Secure; Path=/; Domain=www.example.com", "https://www.example.com/", True),
    ("__Host-id=1; Secure", "https://www.example.com/", True),              # Path=/ is required
    ("__Host-id=1; Secure; Path=/x", "https://www.example.com/", True),
    ("__HOST-id=1; Path=/", "https://www.example.com/", True),
    ("__Http-id=1; Secure; Path=/", "https://www.example.com/", True),      # needs HttpOnly
    ("__Http-id=1; Secure; HttpOnly", "https://www.example.com/", False),
    ("__Host-Http-id=1; Secure; HttpOnly; Path=/", "https://www.example.com/", False),
    ("__Host-Http-id=1; Secure; HttpOnly", "https://www.example.com/", True),
    ("__Hostile=1; Secure", "https://www.example.com/", False),
])
def test_web401_prefix_rules(raw, url, bad):
    _c, _i, r = scan(raw, url=url)
    assert ("WEB401" in r) == bad


def test_web402_invalid_samesite():
    _c, _i, r = scan("sessionid=" + RAND + "; Secure; HttpOnly; SameSite=Lax2")
    assert set(r) == {"WEB402"}
    _c, _i, r = scan("sessionid=" + RAND + "; Secure; HttpOnly; SameSite=")
    assert set(r) == {"WEB402"}
    _c, _i, r = scan("sessionid=" + RAND + "; Secure; HttpOnly; SameSite=STRICT")
    assert r == {}


def test_web403_partitioned():
    _c, _i, r = scan("widget_state=1; Path=/; Partitioned")
    assert set(r) == {"WEB403"}
    _c, _i, r = scan("widget_state=1; Path=/; Partitioned; Secure; SameSite=None")
    assert "WEB403" not in r


def test_web404_domain_variants():
    base = "sessionid=" + RAND + "; Path=/; Secure; HttpOnly; SameSite=Lax"
    _c, _i, r = scan(base + "; Domain=example.com")
    assert [i.severity for i in r["WEB404"]] == ["low"] and "parent" in r["WEB404"][0].group_value
    _c, _i, r = scan(base + "; Domain=www.example.com")
    assert "WEB404" not in r                                # the host itself is not "a parent"
    _c, _i, r = scan("pref=dark; Path=/; Secure; SameSite=Lax; Domain=co.uk", url="https://shop.example.co.uk/")
    assert set(r) == {"WEB404"} and "suffix" in r["WEB404"][0].group_value
    _c, _i, r = scan("pref=dark; Secure; SameSite=Lax; Domain=other.org")
    assert set(r) == {"WEB404"} and "mismatch" in r["WEB404"][0].group_value
    _c, _i, r = scan("pref=dark; Secure; SameSite=Lax; Domain=co.uk", url="https://co.uk/")
    assert "WEB404" not in r                                # a public suffix equal to the host: host-only
    _c, _i, r = scan("pref=dark; Secure; SameSite=Lax; Domain=127.0.0.1", url="https://127.0.0.1:8443/")
    assert "WEB404" not in r
    _c, _i, r = scan("pref=dark; Secure; SameSite=Lax; Domain=0.0.1", url="https://127.0.0.1:8443/")
    assert "WEB404" in r
    _c, _i, r = scan("cart=1; Secure; SameSite=Lax; Domain=example.com")
    assert "WEB404" not in r                                # broad scope only matters for session/auth


def test_web405_lifetimes():
    base = "sessionid=" + RAND + "; Path=/; Secure; HttpOnly; SameSite=Lax"
    _c, _i, r = scan(base + "; Max-Age=7776000")
    assert r["WEB405"][0].severity == "low" and any("90 days" in en for en, _ar in r["WEB405"][0].notes)
    assert any("90 يومًا" in ar for _en, ar in r["WEB405"][0].notes)
    _c, _i, r = scan(base + "; Max-Age=86400")
    assert "WEB405" not in r
    exp = (NOW + timedelta(days=60)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    _c, _i, r = scan(base + "; Expires=" + exp)
    assert r["WEB405"][0].severity == "low"
    _c, _i, r = scan("_ga=GA1.2.3.4; Path=/; Secure; Max-Age=63072000")
    assert r["WEB405"][0].severity == "info"
    _c, _i, r = scan("_ga=GA1.2.3.4; Path=/; Secure; Max-Age=31536000")
    assert "WEB405" not in r


def test_web406_duplicates():
    _c, _i, r = scan("cart=1; Path=/; Secure; SameSite=Lax", "cart=2; Path=/; Secure; SameSite=Strict")
    assert set(r) == {"WEB406"}
    assert any("مرتين" in ar for _en, ar in r["WEB406"][0].notes)
    _c, _i, r = scan("cart=1; Path=/; Secure; SameSite=Lax", "cart=1; Path=/; Secure; SameSite=Lax")
    assert "WEB406" not in r                                # identical repetition
    _c, _i, r = scan("cart=1; Path=/a; Secure; SameSite=Lax", "cart=2; Path=/b; Secure; SameSite=Lax")
    assert "WEB406" not in r                                # different paths are different cookies
    _c, _i, r = scan("cart=; Max-Age=0; Path=/", "cart=2; Path=/; Secure; SameSite=Lax")
    assert "WEB406" not in r                                # delete-then-set


def test_web407_samesite_none_session():
    _c, _i, r = scan("sessionid=" + RAND + "; Path=/; Secure; HttpOnly; SameSite=None")
    assert r["WEB407"][0].severity == "low"
    _c, _i, r = scan("sessionid=" + RAND + "; Path=/; Secure; HttpOnly; SameSite=None; Partitioned")
    assert r["WEB407"][0].severity == "info"
    _c, _i, r = scan("embed=1; Path=/; Secure; SameSite=None")
    assert "WEB407" not in r


def test_web408_size():
    _c, _i, r = scan("blob=" + "A" * 5000 + "; Path=/; Secure; SameSite=Lax")
    assert set(r) == {"WEB408"}
    _c, _i, r = scan("blob=" + "A" * 4000 + "; Path=/; Secure; SameSite=Lax")
    assert "WEB408" not in r


def test_web409_paranoid_only():
    raw = "sessionid=" + RAND + "; Path=/; Secure; HttpOnly; SameSite=Lax"
    ctx, _i, r = scan(raw)
    assert "WEB409" not in r and ctx.coverage.state("WEB409").state == "not_tested"
    _c, _i, r = scan(raw, sensitivity="paranoid")
    assert r["WEB409"][0].severity == "info"
    _c, _i, r = scan("__Host-sid=" + RAND + "; Path=/; Secure; HttpOnly; SameSite=Lax", sensitivity="paranoid")
    assert "WEB409" not in r


def test_web410_and_web413_over_http():
    _c, _i, r = scan("pref=1; Path=/; Secure", url="http://www.example.com/")
    assert set(r) == {"WEB410"}
    _c, _i, r = scan("sessionid=" + RAND + "; Path=/; Secure", url="http://www.example.com/")
    assert set(r) == {"WEB413"}                             # WEB413 suppresses WEB410
    _c, _i, r = scan("csrftoken=" + RAND + "; Path=/; SameSite=Lax", url="http://www.example.com/")
    assert r["WEB413"][0].severity == "low"
    _c, _i, r = scan("_ga=GA1.2.3.4; Path=/", url="http://www.example.com/")
    assert "WEB413" not in r
    _c, _i, r = scan("sessionid=deleted; Max-Age=0", url="http://www.example.com/")
    assert r == {}


def test_web413_on_the_http_redirect_hop():
    hop = resp("http://www.example.com/", "sessionid=" + RAND + "; Path=/; HttpOnly; SameSite=Lax", status=301,
               kind="redirect", headers=[("Location", "https://www.example.com/")])
    final = resp("https://www.example.com/", body="<p>ok</p>", chain=[hop])
    ctx = ctx_for(final, target="http://www.example.com/")
    r = by_rule(reported(ctx, cookies.run(ctx)))
    assert set(r) == {"WEB413"} and r["WEB413"][0].severity == "high"
    assert r["WEB413"][0].url == "http://www.example.com/"


def test_web411_bigip():
    assert str(cookies.decode_bigip("83886090.20480.0000")[0]) == "10.0.0.5"
    assert cookies.decode_bigip("83886090.20480.0000")[1] == 80
    assert cookies.decode_bigip("1677787402.36895.0000") == (cookies.ipaddress.IPv4Address("10.1.1.100"), 8080)
    rd = cookies.decode_bigip("rd5o00000000000000000000ffffc0a80164o80")
    assert str(rd[0]) == "192.168.1.100" and rd[1] == 80
    v6 = cookies.decode_bigip("vi20010db8000000000000000000000030.20480")
    assert str(v6[0]) == "2001:db8::30" and v6[1] == 80
    assert cookies.decode_bigip("!encryptedvalue==") is None
    assert cookies.decode_bigip("99999999999.1.0000") is None
    _c, _i, r = scan("BIGipServerweb_pool=83886090.20480.0000; Path=/; Secure; HttpOnly")
    assert set(r) == {"WEB411"} and any("10.0.0.5:80" in en for en, _ar in r["WEB411"][0].notes)
    public = int.from_bytes(bytes([8, 8, 8, 8]), "little")
    _c, _i, r = scan(f"BIGipServerweb_pool={public}.20480.0000; Path=/; Secure; HttpOnly")
    assert "WEB411" not in r


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def test_web412_sensitive_values():
    none = _b64({"alg": "none", "typ": "JWT"}) + "." + _b64({"sub": "1"}) + "."
    _c, _i, r = scan(f"auth_token={none}; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert set(r) == {"WEB412"} and r["WEB412"][0].severity == "medium" and r["WEB412"][0].confidence == "firm"
    hs = _b64({"alg": "HS256"}) + "." + _b64({"sub": "1", "email": "a@example.com"}) + ".c2ln"
    _c, _i, r = scan(f"auth_token={hs}; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert r["WEB412"][0].severity == "low"
    blob = json.dumps([i.notes for i in _i] + [i.evidence.to_dict() for i in _i])
    assert "a@example.com" not in blob and "email" in blob
    _c, _i, r = scan("prefs=" + _b64({"user": "x", "password": "hunter2"}) + "; Path=/; Secure; SameSite=Lax")
    assert r["WEB412"][0].severity == "medium"
    assert "hunter2" not in json.dumps([i.notes for i in _i])
    _c, _i, r = scan('prefs=%7B%22user_pwd%22%3A%22x%22%7D; Path=/; Secure; SameSite=Lax')
    assert r["WEB412"][0].severity == "medium"
    clean = _b64({"alg": "RS256"}) + "." + _b64({"sub": "1", "exp": 1}) + ".c2ln"
    _c, _i, r = scan(f"auth_token={clean}; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert r == {}
    _c, _i, r = scan("prefs=" + _b64({"pass_through": True}) + "; Path=/; Secure; SameSite=Lax")
    assert r == {}


SESSION_PAGE = '<html><body><script>var sessionToken = "{v}";</script></body></html>'


def test_web414_session_value_in_page():
    raw = "sessionid=" + RAND + "; Path=/; Secure; HttpOnly; SameSite=Lax"
    _c, issues, r = scan(raw, body=SESSION_PAGE.replace("{v}", RAND))
    assert set(r) == {"WEB414"}
    ev = r["WEB414"][0].evidence.to_dict()
    assert ev["match"]["where"] == "body" and RAND not in json.dumps(ev) and ev["match"]["offset"] > 0
    assert any("inline script" in en for en, _ar in r["WEB414"][0].notes)
    _c, _i, r = scan("XSRF-TOKEN=" + RAND + "; Path=/; Secure; SameSite=Lax",
                     body='<form><input type="hidden" name="csrf" value="' + RAND + '"></form>')
    assert "WEB414" not in r                                # csrf class excluded
    _c, _i, r = scan("sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax", body="<p>abc123</p>")
    assert "WEB414" not in r                                # shorter than 16 characters
    _c, _i, r = scan(raw, body="<p>nothing here</p>")
    assert r == {}


def test_web414_later_response_of_the_session_and_contexts():
    entry = resp("https://www.example.com/", "sessionid=" + RAND + "; Path=/; Secure; HttpOnly; SameSite=Lax",
                 body="<p>hi</p>")
    later = resp("https://www.example.com/account", body='<div data-sid="' + RAND + '"></div>',
                 request_headers=HeaderList.of(("Cookie", "sessionid=" + RAND)))
    other = resp("https://www.example.com/x", body="<p>" + RAND + "</p>")          # not served to that session
    ctx = ctx_for(entry, pages=[Page(entry, None, 0), Page(later, None, 1), Page(other, None, 1)])
    r = by_rule(reported(ctx, cookies.run(ctx)))
    assert [i.url for i in r["WEB414"]] == ["https://www.example.com/account"]
    assert any("data-*" in en for en, _ar in r["WEB414"][0].notes)
    text = '<input type="hidden" name="s" value="X"> <meta name="t" content="Y"> <p>Z</p> <a title="W">'
    assert cookies.exposure_context(text, text.index("X")) == "hidden"
    assert cookies.exposure_context(text, text.index("Y")) == "meta"
    assert cookies.exposure_context(text, text.index("Z")) == "content"
    assert cookies.exposure_context(text, text.index("W")) == "attribute"
    assert cookies.exposure_context("<script>x</script> V", 20) == "content"


def test_one_finding_per_rule_cookie_host():
    raw = "sessionid=" + RAND + "; Path=/"
    entry = resp("https://www.example.com/", raw, body="<p>a</p>")
    page2 = resp("https://www.example.com/b", raw, body="<p>b</p>")
    cors = resp("https://www.example.com/", raw, body="<p>a</p>", source="cors")
    ctx = ctx_for(entry, pages=[Page(entry, None, 0), Page(page2, None, 1)], cors=cors)
    issues = cookies.run(ctx)
    r = by_rule(issues)
    assert [len(v) for v in r.values()] == [1] * len(r)
    assert any("3 responses" in en and "3 استجابات" in ar for en, ar in r["WEB020"][0].notes)


def test_third_party_and_waf_responses_are_not_judged():
    entry = resp("https://www.example.com/", body="<p>x</p>")
    third = resp("https://cdn.other.net/lib.js", "tracking=" + RAND, kind="script", source="subresource")
    ctx = ctx_for(entry, subresources=[third])
    assert cookies.run(ctx) == []
    waf = resp("https://www.example.com/", "__cf_bm=abc; Path=/", "sessionid=" + RAND, kind="waf_challenge",
               status=403)
    ctx = ctx_for(waf)
    assert cookies.run(ctx) == []
    assert ctx.coverage.state("WEB020").state == "inconclusive"


def test_coverage_states():
    ctx, _i, _r = scan("sessionid=" + RAND + "; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert ctx.coverage.state("WEB020").state == "pass" and ctx.coverage.state("WEB021").state == "pass"
    assert ctx.coverage.state("WEB413").state == "not_applicable"            # nothing set over http
    ctx, _i, _r = scan("sessionid=" + RAND + "; Path=/")
    assert ctx.coverage.state("WEB020").state == "fail"
    ctx = ctx_for(resp("https://www.example.com/", body="<p>x</p>"))
    assert cookies.run(ctx) == []
    assert ctx.coverage.state("WEB020").state == "not_applicable"


def test_tentative_issue_is_not_counted_as_failed_below_paranoid():
    ctx, issues, r = scan("vid=" + RAND + "; Path=/; Secure; SameSite=Lax; HttpOnly")
    assert r == {} and ctx.coverage.state("WEB020").state == "pass"


def test_hostile_cookie_names_are_cleaned():
    _c, issues, r = scan("\x1b[31mevil{x}=" + RAND + "; Path=/")
    # the raw field contains an ESC control character, so a browser (and Kashif) ignores it
    assert issues == []
    _c, issues, r = scan("evil{cookie}<b>=abc; Path=/")
    issue = r["WEB020"][0]
    assert issue.params["cookie"] == "evil{cookie}<b>"
    assert rules.RULES["WEB020"].title("en", **issue.params) == "Cookie without Secure flag: evil{cookie}<b>"


def test_inventory_has_no_values():
    ctx, _i, _r = scan("sessionid=" + RAND + "; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600")
    inv = ctx.inventory["cookies"]
    assert inv[0]["name"] == "sessionid" and inv[0]["class"] == "session" and inv[0]["value_bytes"] == 32
    assert RAND not in json.dumps(inv)


def test_notes_are_bilingual_and_catalogued():
    cat, pats = cookies.i18n_catalog()
    for en, ar in cookies.STR.values():
        assert en and ar and any("؀" <= ch <= "ۿ" for ch in ar)
    assert cat and pats
    import re as _re
    phrase = cookies._note("echo", where=cookies.WHERE_NAMES["script"], url="https://x.test/")[1]
    assert any(_re.fullmatch(rx, phrase) for rx, _en in pats)


# ----------------------------------------------------------------------------------------------- adversarial review

def test_hostile_numbers_and_nesting_do_not_crash():
    # a 1000-digit Max-Age used to raise OverflowError in float(); deep JSON used to raise RecursionError (3.10/3.11)
    _c, _i, r = scan("sessionid=" + RAND + "; Secure; HttpOnly; SameSite=Lax; Max-Age=" + "9" * 1000)
    assert set(r) == {"WEB405"} and r["WEB405"][0].severity == "low"
    _c, _i, r = scan("sessionid=" + RAND + "; Secure; HttpOnly; SameSite=Lax; Max-Age=-" + "9" * 1000)
    assert r == {}                                           # deletion cookie
    _c, _i, r = scan("prefs=" + "[" * 50000 + "]" * 50000 + "; Secure; SameSite=Lax")
    assert "WEB412" not in r
    deep = base64.urlsafe_b64encode(b"[" * 3000 + b"]" * 3000).decode()
    _c, _i, r = scan("prefs=" + deep + "; Secure; SameSite=Lax")
    assert "WEB412" not in r
    assert cookies.parse_cookie_date("Wed, ١٢ Nov 2026 10:00:00 GMT") is None    # DIGIT is ASCII only


def test_nameless_cookie_keeps_its_value_out_of_evidence():
    secret = "TOPSECRETVALUE0123456789"
    _c, issues, r = scan(secret + "; Path=/x")              # no "=" in the first pair: empty name, value = token
    assert issues and all(i.params["cookie"] == '""' for i in issues)
    blob = json.dumps([i.evidence.to_dict() for i in issues] + [i.notes for i in issues])
    assert secret not in blob and "<redacted:24 bytes>; Path=/x" in blob


@pytest.mark.parametrize("name,cls", [
    ("data-session", "session"), ("partner-auth-token", "auth"), ("recs-session", "session"),
    ("prism_csrf", "csrf"),                                  # imported (Open Cookie Database) globs yield
    ("recs-foo", "analytics"), ("data-abc", "analytics"),    # ... but still classify vendor names
    ("_hjSessionUser_123", "analytics"), ("intercom-session-abc", "analytics"),   # Kashif's own globs win
    ("MATOMO_SESSID", "session"), ("PIWIK_SESSID", "session"),                     # Matomo's login session
])
def test_imported_globs_do_not_hide_session_cookies(name, cls):
    assert cookies.classify(name, "x")[0] == cls


def test_web412_flags_and_camel_case_keys():
    for obj in ({"has_password": True}, {"pass": False}, {"mobile": False, "tablet": False}, {"email": ""},
                {"password_set": "yes"}, {"phone": 1}):
        _c, _i, r = scan("prefs=" + _b64(obj) + "; Path=/; Secure; SameSite=Lax")
        assert "WEB412" not in r, obj
    _c, _i, r = scan("prefs=" + _b64({"userPassword": "hunter2"}) + "; Path=/; Secure; SameSite=Lax")
    assert r["WEB412"][0].severity == "medium" and "hunter2" not in json.dumps([i.notes for i in _i])
    _c, _i, r = scan("prefs=" + _b64({"phone": 4915112345678}) + "; Path=/; Secure; SameSite=Lax")
    assert r["WEB412"][0].severity == "low"
    # a Flask (itsdangerous) session "payload.timestamp.signature" looks like a JWT: its first segment is the data
    flask = _b64({"email": "a@example.com", "_fresh": True}) + ".ZzA1Bg.c2lnbmF0dXJlc2lnbmF0dXJlcw"
    _c, _i, r = scan(f"session={flask}; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert r["WEB412"][0].severity == "low"
    assert "a@example.com" not in json.dumps([i.notes for i in _i] + [i.evidence.to_dict() for i in _i])


def test_structured_values_are_not_random_tokens():
    assert cookies.value_class("%7B%22mobile%22%3Afalse%2C%22tablet%22%3Afalse%7D") is None
    assert cookies.value_class('{"a":"Zq81","b":[1,2,3],"c":"x9Y"}') is None
    assert cookies.value_class(RAND) == "unknown_secret"


def test_web414_excerpt_masks_every_copy_of_the_value():
    second = 'var a = "' + RAND + '", b = "' + RAND + '";'
    cut = 'var a = "' + RAND + '"; ' + "x" * 30 + ' var b = "' + RAND + '";'
    for script in (second, cut):
        _c, _i, r = scan("sessionid=" + RAND + "; Path=/; Secure; HttpOnly; SameSite=Lax",
                         body="<script>" + script + "</script>")
        ev = r["WEB414"][0].evidence.to_dict()
        blob = json.dumps(ev)
        assert RAND not in blob and RAND[:8] not in blob, blob
    text = RAND + "......" + RAND + "......" + RAND          # both neighbours are cut by the 14-character window
    out = cookies._masked_excerpt(text, len(RAND) + 6, RAND, "<r>", width=14)
    assert out == "<r>......<r>......<r>", out


def test_web414_session_cookie_reset_on_every_page_is_one_finding():
    raw = "sessionid=" + RAND + "; Path=/; Secure; HttpOnly; SameSite=Lax"
    pages = []
    for i in range(30):
        r = resp(f"https://www.example.com/p{i}", raw, body=SESSION_PAGE.replace("{v}", RAND),
                 request_headers=HeaderList.of(("Cookie", "sessionid=" + RAND)))
        pages.append(Page(r, None, 1))
    ctx = ctx_for(pages[0].response, pages=pages)
    r = by_rule(reported(ctx, cookies.run(ctx)))
    assert set(r) == {"WEB414"} and len(r["WEB414"]) == 1


# ----------------------------------------------------------------------------------------------- Observatory slug

def obs(*cookie_values, sts=True, url="https://www.example.com/"):
    hs = [("Strict-Transport-Security", "max-age=63072000")] if sts else []
    ctx = ctx_for(resp(url, *cookie_values, headers=hs, body="<p>x</p>"))
    cookies.run(ctx)
    return ctx.observatory["cookies"]


@pytest.mark.parametrize("values,sts,slug", [
    ((), True, "cookies-not-found"),
    (("a=1; Secure; SameSite=Lax",), True, "cookies-secure-with-httponly-sessions-and-samesite"),
    (("a=1; Secure",), True, "cookies-secure-with-httponly-sessions"),
    (("a=1",), True, "cookies-without-secure-flag-but-protected-by-hsts"),
    (("a=1",), False, "cookies-without-secure-flag"),
    (("mysess=1; HttpOnly",), True, "cookies-session-without-secure-flag-but-protected-by-hsts"),
    (("mysess=1; HttpOnly",), False, "cookies-session-without-secure-flag"),
    (("mysess=1; Secure",), True, "cookies-session-without-httponly-flag"),
    (("csrftoken=1; Secure",), True, "cookies-anticsrf-without-samesite-flag"),
    (("a=1; Secure; SameSite=Lax2",), True, "cookies-samesite-flag-invalid"),
    (("a=1; SameSite=None",), True, "cookies-samesite-flag-invalid"),
    (("sid=1; Secure",), True, "cookies-secure-with-httponly-sessions"),     # Observatory: only login|sess
    (("heroku-session-affinity=1",), True, "cookies-not-found"),
    (("x=1; Max-Age=0",), False, "cookies-without-secure-flag"),             # tough-cookie keeps expired cookies
])
def test_observatory_cookie_slug(values, sts, slug):
    assert obs(*values, sts=sts) == slug


def test_observatory_hsts_quirks():
    ctx = ctx_for(resp(headers=[("Strict-Transport-Security", 'max-age="0"')], body="<p>x</p>"))
    assert cookies.observatory_hsts_pass(ctx)                # quoted value: parseInt → NaN → passes
    ctx = ctx_for(resp(headers=[("Strict-Transport-Security", "max-age=63072000, max-age=1")], body="<p>x</p>"))
    assert not cookies.observatory_hsts_pass(ctx)            # comma → invalid
    ctx = ctx_for(resp(headers=[("Strict-Transport-Security", "max-age=600")], body="<p>x</p>"))
    assert not cookies.observatory_hsts_pass(ctx)
    ctx = ctx_for(resp(headers=[("Strict-Transport-Security", "max-age=600")], body="<p>x</p>"))
    ctx.observatory["strict-transport-security"] = "hsts-preloaded"
    assert cookies.observatory_hsts_pass(ctx)


# ----------------------------------------------------------------------------------------------- corpus (C-COOKIE)

def _corpus():
    path = ROOT / "bench" / "web"
    if not (path / "corpus.py").is_file():
        pytest.skip("bench/web/corpus.py not present")
    sys.path.insert(0, str(path))
    try:
        return importlib.import_module("corpus")
    finally:
        sys.path.remove(str(path))


def _hsts_verdict(r: Response) -> HstsVerdict | None:
    if not r.is_https:
        return None
    value = r.headers.first("strict-transport-security")
    if value is None:
        return HstsVerdict(host=r.host)
    parts = [p.strip().lower() for p in value.split(";")]
    age = next((int(p[8:]) for p in parts if p.startswith("max-age=") and p[8:].isdigit()), None)
    return HstsVerdict(host=r.host, present=True, valid=age is not None, max_age=age,
                       include_subdomains="includesubdomains" in parts, effective=bool(age),
                       header_values=(value,), response=r)


class _Renderer:
    """Serves a corpus case in memory: the corpus' own routing and token rendering, no socket."""

    def __init__(self, corpus, case):
        self.corpus = corpus
        self.case = case
        self.server = corpus.CorpusServer(cases=[case], mode="host", with_tls=False)
        self.server.http_port, self.server.https_port = 80, 443

    def get(self, url: str, cookie_header: str | None = None, source: str = "entry") -> Response:
        import urllib.parse as up
        u = up.urlsplit(url)
        req_headers = {"host": [u.netloc]}
        if cookie_header:
            req_headers["cookie"] = [cookie_header]
        c, alias, path = self.server.route(u.netloc, u.path or "/")
        hits = self.server.count(c.id, alias, path)
        req = self.corpus.Req(c, alias, path, u.query, req_headers, u.scheme, hits[0], hits[1], self.server, u.netloc)
        r = self.server.respond(req)
        per: dict = {}
        headers = tuple((n, self.corpus._render(v, req, per) if isinstance(v, str) else v.decode("latin-1"))
                        for n, v in r.headers)
        body = r.body if isinstance(r.body, bytes) else self.corpus._render(r.body, req, per).encode("utf-8")
        rq = HeaderList.of(*([("Cookie", cookie_header)] if cookie_header else []))
        status = r.status
        kind = "redirect" if 300 <= status < 400 else ("document" if 200 <= status < 300 else "error_page")
        return Response(url=url, status=status, headers=HeaderList(headers), body=body, kind=kind,
                        request_headers=rq, source=source)

    def chain(self, url: str, source: str = "entry", jar: dict | None = None) -> Response:
        hops: list[Response] = []
        jar = {} if jar is None else jar
        for _ in range(10):
            cookie = "; ".join(f"{k}={v}" for k, v in jar.items()) or None
            r = self.get(url, cookie, source)
            for raw in r.headers.get_all("set-cookie"):
                p = cookies.parse_set_cookie(raw)
                if p and p.name:
                    jar[p.name] = p.value
            if r.is_redirect:
                hops.append(r)
                url = r.location
                continue
            r.chain = hops
            return r
        raise AssertionError("redirect loop")


def _run_case(corpus, case):
    rd = _Renderer(corpus, case)
    start = rd.server.url(case)
    jar: dict = {}
    entry = rd.chain(start, jar=jar)
    pages = [Page(entry, htmlparse.parse_response(entry), 0)]
    if case.crawl:
        for link in pages[0].doc.find_all("a"):
            href = link.get("href")
            if href and href.startswith("/"):
                r = rd.chain(entry.origin + href, source="crawl", jar=jar)
                pages.append(Page(r, htmlparse.parse_response(r), 1))
    cors = rd.chain(start, source="cors", jar={})                       # anonymous second fetch (§0.1)
    ignore = []
    args = list(case.extra_args)
    while "--web-cookie-ignore" in args:
        i = args.index("--web-cookie-ignore")
        ignore.append(args[i + 1])
        del args[i:i + 2]
    opts = ScanOptions(sensitivity=case.sensitivity, cookie_ignore=tuple(ignore))
    ctx = ScanContext(options=opts, target=start, entry=entry, pages=pages, cors=cors, now=datetime.now(timezone.utc),
                      coverage=Coverage())
    for r in ctx.all_responses():
        v = _hsts_verdict(r)
        if v is not None and r.host not in ctx.hsts:
            ctx.hsts[r.host] = v
    ctx.cookies = cookies.parse_and_classify(ctx)
    issues = cookies.run(ctx)
    return ctx, [i for i in issues if opts.reports(i.confidence)]


def _cookie_cases():
    corpus = _corpus()
    wanted = [c for c in corpus.CASES if c.group == "C-COOKIE" or any(r in rules.checks_for_module("cookies")
                                                                        for r in c.labels) and c.group == "C-REVIEW"]
    return corpus, wanted


def test_corpus_cookie_cases():
    corpus, wanted = _cookie_cases()
    assert len([c for c in wanted if c.group == "C-COOKIE"]) >= 30
    own = set(rules.checks_for_module("cookies"))
    failures = []
    for case in wanted:
        _ctx, issues = _run_case(corpus, case)
        fired = {i.rule: i for i in issues}
        for rule, must in case.labels.items():
            if rule not in own:
                continue
            if must and rule not in fired:
                failures.append(f"{case.id}: {rule} missing")
            if not must and rule in fired:
                failures.append(f"{case.id}: {rule} fired (trap)")
        for rule, sev in case.expect.get("severity", {}).items():
            if rule in own and rule in fired and fired[rule].severity != sev:
                failures.append(f"{case.id}: {rule} severity {fired[rule].severity} != {sev}")
    assert failures == []
