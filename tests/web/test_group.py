"""WP13 grouping (spec §3.5): URL templates, value normalisation, groups and fp_key, systemic, sensitivity,
cross-rule suppression pairs and cross-module adjustments, crawl dedupe helper."""

from __future__ import annotations

import re
from datetime import datetime, timezone

import pytest

from vulnscan.webscan import group
from vulnscan.webscan.rules import RULES
from vulnscan.webscan.types import CookieFact, Evidence, HeaderList, Issue, Page, Response, ScanContext, ScanOptions

NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
SITE = "https://shop.example.test"


def mk(rule, url=SITE + "/", *, severity=None, confidence=None, value="", kind="document", roles=("app",), host="",
       params=None, ips=(), match_name="", match_value="", notes=()):
    ev = Evidence(kind=kind, role=list(roles), match={"where": "header", "name": match_name or rule,
                                                      "value": match_value or value})
    return Issue(rule=rule, url=url, confidence=confidence or RULES[rule].confidence, evidence=ev,
                 params=dict(params or {}), severity=severity, group_value=value, host=host, ips=tuple(ips),
                 notes=list(notes))


def ctx_with(urls=(), kind="document", sensitivity="default", cookies=()):
    resps = [Response(url=u, status=200, headers=HeaderList.of(("Content-Type", "text/html")), kind=kind,
                      body=b"<html></html>") for u in urls]
    entry = resps[0] if resps else None
    ctx = ScanContext(options=ScanOptions(sensitivity=sensitivity), target=SITE + "/", entry=entry,
                      pages=[Page(r, None, i) for i, r in enumerate(resps)], now=NOW)
    ctx.cookies = list(cookies)
    return ctx


# ----------------------------------------------------------------------------------------------- URL templates

@pytest.mark.parametrize("url,template", [
    ("https://Shop.Example.TEST:443/product/12345", "https://shop.example.test/product/{id}"),
    ("https://h.test/blog/2026-11-12/my-first-post-123", "https://h.test/blog/{id}/{id}"),
    ("https://h.test/u/550e8400-e29b-41d4-a716-446655440000/edit", "https://h.test/u/{id}/edit"),
    ("https://h.test/f/0123456789abcdef0123/x", "https://h.test/f/{id}/x"),
    ("https://h.test/t/dGhpc2lzYXRva2VuMTIzNDU2Nzg5MA", "https://h.test/t/{id}"),
    ("https://h.test/search?q=shoes&page=2#top", "https://h.test/search?q={v}&page={v}"),
    ("https://h.test/about-us", "https://h.test/about-us"),
    ("https://h.test/docs/v2/install", "https://h.test/docs/v2/install"),
    ("http://h.test:8080/a?flag", "http://h.test:8080/a?flag"),
    ("https://h.test", "https://h.test/"),
])
def test_url_template(url, template):
    assert group.url_template(url) == template


@pytest.mark.parametrize("raw,norm", [
    ("script-src 'nonce-AbC123xyz+/=' 'strict-dynamic'", "script-src 'nonce-{nonce}' 'strict-dynamic'"),
    ("Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/", "Expires={date}; Path=/"),
    ("built 2026-11-12T10:00:00Z", "built {date}"),
    ("req 550e8400-e29b-41d4-a716-446655440000", "req {uuid}"),
    ("trace 4bf92f3577b34da6a3ce929d0e0e4736", "trace {hex}"),
    ("token eyJhbGciOiJIUzI1NiJ9abcdef0123456789", "token {token}"),
    ("ts=1731412800", "ts={n}"),
    ("jquery@3.6.0", "jquery@3.6.0"),
    ("max-age=600", "max-age=600"),
    ("strict-origin-when-cross-origin", "strict-origin-when-cross-origin"),
    ("  a \r\n  b ", "a b"),
    ("", ""),
])
def test_normalise_value(raw, norm):
    assert group.normalise_value(raw) == norm


# ----------------------------------------------------------------------------------------------- grouping

def test_same_issue_on_many_pages_is_one_group_entry_first():
    urls = [SITE + "/", SITE + "/p/1", SITE + "/p/2", SITE + "/p/3", SITE + "/about", SITE + "/contact", SITE + "/faq"]
    ctx = ctx_with(urls)
    issues = [mk("WEB-content-security-policy", u, value="missing") for u in reversed(urls)]
    [g] = group.group_issues(issues, ctx)
    assert g.instances == 7 and len(g.urls) == 7
    assert g.examples[0] == SITE + "/" and len(g.examples) == 5
    assert g.pages[:2] == [SITE + "/faq", SITE + "/contact"] and SITE + "/p/{id}" in g.pages
    extra = g.extra()
    assert extra["page_count"] == 7 and extra["instances"] == 7 and extra["systemic"] is True
    assert extra["fp_key"] == "WEB-content-security-policy|shop.example.test|document|missing"


def test_group_key_separates_rule_host_kind_value():
    issues = [mk("WEB010", value="Apache/2.4.58"), mk("WEB010", value="nginx/1.25.3"),
              mk("WEB010", value="Apache/2.4.58", kind="error_page"),
              mk("WEB010", "https://cdn.example.test/", value="Apache/2.4.58"), mk("WEB011", value="Apache/2.4.58")]
    assert len(group.group_issues(issues)) == 5


def test_fp_key_stable_across_reruns_with_nonces_dates_and_ids():
    def run(nonce, day, order_id):
        return [mk("WEB212", f"{SITE}/order/{order_id}", value=f"script-src 'nonce-{nonce}'"),
                mk("WEB315", f"{SITE}/account/{order_id}", value=f"Expires: {day}"),
                mk("WEB062", f"{SITE}/.env", value="/.env"),
                mk("WEB054", value="jquery@3.6.0")]
    a = {g.fp_key for g in group.group_issues(run("r4nd0mN0nceAAAA", "Thu, 12 Nov 2026 10:00:00 GMT", 1001))}
    b = {g.fp_key for g in group.group_issues(run("ZZ99otherNonce11", "Fri, 13 Nov 2026 11:30:00 GMT", 2002))}
    assert a == b
    for key in a:
        assert "1001" not in key and "http" not in key and not re.search(r"\b20\d\d\b", key)
    assert any("jquery@3.6.0" in k for k in a)                 # versions are part of the identity


def test_fp_key_long_values_are_capped_with_digest():
    long_value = "default-src 'self' " + " ".join(f"https://cdn{i}.example.test" for i in range(40))
    [g] = group.group_issues([mk("WEB218", value=long_value)])
    assert len(g.fp_key) < 200 and "#" in g.fp_key
    [g2] = group.group_issues([mk("WEB218", value=long_value + " https://extra.example.test")])
    assert g.fp_key != g2.fp_key


def test_empty_group_value_falls_back_to_evidence():
    issues = [mk("WEB062", f"{SITE}/a", value="", match_name="probe", match_value="/a"),
              mk("WEB062", f"{SITE}/b", value="", match_name="probe", match_value="/b")]
    assert len(group.group_issues(issues)) == 2


def test_representative_is_most_severe_then_certain_then_entry():
    issues = [mk("WEB050", SITE + "/x", severity="low", value="v"), mk("WEB050", SITE + "/", severity="medium", value="v"),
              mk("WEB050", SITE + "/y", severity="medium", value="v")]
    [g] = group.group_issues(issues, ctx_with([SITE + "/", SITE + "/x", SITE + "/y"]))
    assert g.severity == "medium" and g.url == SITE + "/"


def test_systemic_needs_80_percent_and_two_responses():
    urls = [f"{SITE}/{i}" for i in range(5)]
    ctx = ctx_with(urls)
    [g] = group.group_issues([mk("WEB053", u, value="x") for u in urls[:4]], ctx)
    assert g.systemic and g.share == pytest.approx(0.8)
    assert any(n[0].startswith("systemic") and "80" in n[1] for n in g.notes)
    [g] = group.group_issues([mk("WEB053", u, value="x") for u in urls[:3]], ctx)
    assert not g.systemic
    [g] = group.group_issues([mk("WEB053", SITE + "/0", value="x")], ctx_with([SITE + "/0"]))
    assert not g.systemic                                       # one response proves nothing about the site


def test_sensitivity_after_grouping():
    tent = mk("WEB511", SITE + "/?token=x", value="token")          # tentative
    mixed = [mk("WEB701", confidence="certain", value="cert"), mk("WEB701", SITE + "/b", confidence="tentative",
                                                                  value="cert")]
    res = group.process([tent] + mixed, ctx_with([SITE + "/"]), sensitivity="default")
    assert [g.rule for g in res.groups] == ["WEB701"] and res.groups[0].instances == 1
    assert [g.rule for g in res.hidden] == ["WEB511"]
    assert {g.rule for g in res.all_groups()} == {"WEB511", "WEB701"}
    assert next(g for g in res.all_groups() if g.rule == "WEB701").instances == 2
    assert {g.rule for g in group.process([tent] + mixed, sensitivity="paranoid").groups} == {"WEB511", "WEB701"}
    strict = group.process([tent, mk("WEB-content-security-policy")], sensitivity="strict")   # firm hidden at strict
    assert strict.groups == [] and len(strict.hidden) == 2
    assert res.raw_count == 3 and res.noise_ratio == 3.0


def test_process_uses_ctx_sensitivity():
    tent = mk("WEB511", SITE + "/?token=x", value="token")
    assert group.process([tent], ctx_with([SITE + "/"], sensitivity="paranoid")).groups


# ----------------------------------------------------------------------------------------------- suppression pairs

HTTP = "http://shop.example.test"
SUPPRESSION = [
    # (suppressor, suppressed, same-cause positive?, reason)
    (mk("WEB000", HTTP + "/"), mk("WEB052", HTTP + "/login", roles=("login",)), True, "by_web000"),
    (mk("WEB000", HTTP + "/"), mk("WEB504", HTTP + "/", value="https://shop.example.test/login"), True, "by_web000"),
    (mk("WEB000", HTTP + "/", severity="info"), mk("WEB052", HTTP + "/login"), False, ""),
    (mk("WEB000", "http://other.example.test/"), mk("WEB052", HTTP + "/login"), False, ""),
    (mk("WEB704", ips=("192.0.2.1",), value="SSLv3"), mk("WEB030", ips=("192.0.2.1",), value="TLSv1.0"), True, "by_web704"),
    (mk("WEB704", ips=("192.0.2.1",), value="SSLv3"), mk("WEB030", ips=("192.0.2.9",), value="TLSv1.0"), False, ""),
    (mk("WEB200", value="report-only"),
     mk("WEB041", value="ro", match_name="Content-Security-Policy-Report-Only"), True, "by_web200"),
    (mk("WEB200", value="report-only"), mk("WEB041", value="x", match_name="Content-Security-Policy"), False, ""),
    (mk("WEB070", value="expired"), mk("WEB-strict-transport-security", value="missing"), True, "by_cert"),
    (mk("WEB072", value="untrusted"), mk("WEB114", value="no-includesubdomains"), True, "by_cert"),
    (mk("WEB070", "https://cdn.example.test/"), mk("WEB-strict-transport-security"), False, ""),
    (mk("WEB206", value="*"), mk("WEB-x-frame-options", value="missing"), True, "by_framing"),
    (mk("WEB300", value="allow-from"), mk("WEB-x-frame-options", value="missing"), True, "by_framing"),
    (mk("WEB301", value="deny,sameorigin"), mk("WEB-x-frame-options", value="missing"), True, "by_framing"),
    (mk("WEB300", SITE + "/other"), mk("WEB-x-frame-options", value="missing"), False, ""),
    (mk("WEB110", value="max-age=0"), mk("WEB-strict-transport-security"), True, "by_hsts_value"),
    (mk("WEB112", value="invalid"), mk("WEB-strict-transport-security"), True, "by_hsts_value"),
    (mk("WEB117", "https://old.example.test/", value="hop"),
     mk("WEB-strict-transport-security", "https://old.example.test/"), True, "by_web117"),
    (mk("WEB050", match_value="http://cdn.example.test/a.js", value="active:x"),
     mk("WEB502", match_value="http://cdn.example.test/a.js#x", value="a"), True, "by_web050"),
    (mk("WEB050", match_value="http://cdn.example.test/b.js", value="active:x"),
     mk("WEB502", match_value="http://cdn.example.test/a.js", value="a"), False, ""),
    (mk("WEB042", params={"variant": "non_script"}, value="non_script"), mk("WEB043", value="object"), True,
     "by_non_script"),
    (mk("WEB042", params={"variant": "non_script"}, value="non_script"), mk("WEB218", value="allowlist"), True,
     "by_non_script"),
    (mk("WEB042", value="script-src *"), mk("WEB043", value="object"), False, ""),
    (mk("WEB042", params={"variant": "non_script"}, value="non_script"), mk("WEB206", value="*"), False, ""),
]


@pytest.mark.parametrize("sup,victim,suppressed,reason", SUPPRESSION,
                         ids=[f"{s.rule}>{v.rule}-{'yes' if x else 'no'}" for s, v, x, _r in SUPPRESSION])
def test_suppression_pairs(sup, victim, suppressed, reason):
    kept, dropped = group.suppress([sup, victim])
    assert sup in kept
    if suppressed:
        assert dropped == [(victim, reason)] and victim not in kept
        assert group.STR[reason][0] and group.STR[reason][1]
    else:
        assert dropped == [] and victim in kept


def test_hidden_suppressor_never_hides_a_shown_finding():
    sup = mk("WEB070", confidence="certain")
    sup.confidence = "tentative"            # pretend: a hidden (tentative) certificate finding
    victim = mk("WEB-strict-transport-security")
    kept, dropped = group.suppress([sup, victim], sensitivity="default")
    assert victim in kept and not dropped


def test_process_reports_suppressed_with_reasons():
    res = group.process([mk("WEB206", value="*"), mk("WEB-x-frame-options", value="missing")])
    assert [g.rule for g in res.groups] == ["WEB206"]
    [row] = res.suppressed_summary()
    assert row["rule"] == "WEB-x-frame-options" and row["reason"] == "by_framing" and row["ar"]


# ----------------------------------------------------------------------------------------------- adjustments

def test_web304_escalates_with_session_ids_in_urls():
    ref = mk("WEB304", severity="low", value="no-referrer-when-downgrade", params={"policy": "no-referrer-when-downgrade"})
    tok = mk("WEB510", SITE + "/cart;jsessionid=x", value="jsessionid")
    [out, _t] = group.adjust([ref, tok])
    assert out.severity == "medium" and out is not ref and ref.severity == "low"
    assert out.notes[-1][0].startswith("raised to medium") and out.notes[-1][1]


@pytest.mark.parametrize("policy", ["origin", "origin-when-cross-origin"])
def test_web304_origin_only_policies_do_not_escalate(policy):
    ref = mk("WEB304", severity="low", value=policy, params={"policy": policy})
    tok = mk("WEB510", SITE + "/cart;jsessionid=x", value="jsessionid")
    assert group.adjust([ref, tok])[0].severity == "low"


def test_web304_needs_token_evidence_on_the_same_site():
    ref = mk("WEB304", severity="low", value="no-referrer-when-downgrade", params={"policy": "no-referrer-when-downgrade"})
    other = mk("WEB511", "https://elsewhere.test/?token=1", value="token")
    assert group.adjust([ref, other])[0].severity == "low"
    assert group.adjust([ref])[0].severity == "low"


def _cookie(name, domain, cls="session"):
    resp = Response(url=SITE + "/", status=200)
    attrs = {"secure": "", "httponly": "", "path": "/"}
    if domain:
        attrs["domain"] = domain
    return CookieFact(name=name, value="v", attrs=attrs, raw=f"{name}=v", response=resp, host="shop.example.test",
                      secure_context=True, cls=cls)


def test_web114_escalates_with_parent_domain_session_cookie():
    isd = mk("WEB114", value="no-includesubdomains")
    ctx = ctx_with([SITE + "/"], cookies=[_cookie("sid", ".example.test")])
    out = group.adjust([isd], ctx)[0]
    assert out.severity == "low" and "sid" in out.notes[-1][0] and "sid" in out.notes[-1][1]
    for cookies in ([_cookie("sid", "")], [_cookie("sid", "shop.example.test")], [_cookie("theme", ".example.test",
                                                                                         "preference")]):
        assert group.adjust([isd], ctx_with([SITE + "/"], cookies=cookies))[0].severity in (None, "info")


# ----------------------------------------------------------------------------------------------- crawl helper

def test_crawl_planner_caps_templates_and_skips_near_duplicates():
    cp = group.CrawlPlanner()
    allowed = [cp.allow(f"{SITE}/product/{i}") for i in range(10)]
    assert allowed == [True] * 3 + [False] * 7
    assert cp.allow(SITE + "/about") and cp.templates()[SITE + "/product/{id}"] == 3
    assert not cp.near_duplicate(0xFFFF0000FFFF0000)
    assert cp.near_duplicate(0xFFFF0000FFFF0007)            # Hamming 3
    assert not cp.near_duplicate(0x0000FFFF0000FFFF)
    assert not cp.near_duplicate(None)


def test_i18n_catalog_of_group_strings():
    catalog, patterns = group.i18n_catalog()
    assert all(any("؀" <= ch <= "ۿ" for ch in ar) for ar in catalog)
    for rx, _repl in patterns:
        re.compile(rx)
    assert len(catalog) + len(patterns) >= len(group.STR)
