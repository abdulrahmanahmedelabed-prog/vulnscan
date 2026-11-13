"""Tests of webscan/cors.py (WP6): the §2.4 table (WEB320–WEB327) with a positive and a trap per rule, the probe-only
rules, the shared-cache guard, private targets, coverage and the Observatory CORS slug. The C-CORS corpus group runs in
tests/web/test_transport.py::test_corpus_groups_pass (one local server for both modules)."""

from __future__ import annotations

import re

import pytest

from vulnscan.webscan import cors
from vulnscan.webscan.coverage import Coverage
from vulnscan.webscan.rules import RULES, validate_issue
from vulnscan.webscan.types import (CORS_PROBE_ORIGIN, CookieFact, DnsRecord, HeaderList, Page, Response, ScanContext,
                                    ScanOptions)

URL = "https://app.example.com/data"
ACAO = "Access-Control-Allow-Origin"
ACAC = "Access-Control-Allow-Credentials"


def R(headers=(), *, probe: bool = False, url: str = URL, status: int = 200, flags=frozenset(), kind="document",
      ip: str | None = None) -> Response:
    req = HeaderList.of(("Origin", CORS_PROBE_ORIGIN)) if probe else HeaderList()
    return Response(url=url, status=status, headers=HeaderList.of(("Content-Type", "text/html"), *headers),
                    body=b"<p>x</p>", request_headers=req, source="cors" if probe else "entry", flags=frozenset(flags),
                    kind=kind, ip=ip)


def reflect(*extra, creds=False):
    hs = [(ACAO, CORS_PROBE_ORIGIN), *extra]
    if creds:
        hs.append((ACAC, "true"))
    return hs


def scan(entry: Response | None = None, probe: Response | None = None, *, sensitivity="default", profile="standard",
         cookies=(), dns=None, pages=None, target=URL) -> tuple[dict, ScanContext]:
    ctx = ScanContext(options=ScanOptions(profile=profile, sensitivity=sensitivity), target=target, entry=entry,
                      cors=probe, coverage=Coverage(), cookies=list(cookies), dns=dict(dns or {}),
                      pages=list(pages or []))
    out: dict[str, list] = {}
    for i in cors.run(ctx):
        assert validate_issue(i) == [], validate_issue(i)
        if ctx.options.reports(i.confidence):
            out.setdefault(i.rule, []).append(i)
    return out, ctx


def sev(i) -> str:
    return i.severity or RULES[i.rule].severity


# ----------------------------------------------------------------------------------------------- reflection rules

def test_web320_reflected_with_credentials():
    got, _ = scan(R(), R(reflect(("Vary", "Origin"), creds=True), probe=True))
    assert [sev(i) for i in got["WEB320"]] == ["high"] and "WEB321" not in got
    assert got["WEB320"][0].evidence.curl.count("Origin: https://kashif-cors-check.invalid") == 1


def test_web321_reflected_without_credentials():
    got, _ = scan(R(), R(reflect(("Vary", "Origin")), probe=True))
    assert [sev(i) for i in got["WEB321"]] == ["low"] and "WEB320" not in got


@pytest.mark.parametrize("acac", ["True", "TRUE", "1", "yes", " false"])
def test_acac_must_be_exactly_true(acac):
    got, _ = scan(R(), R([(ACAO, CORS_PROBE_ORIGIN), (ACAC, acac), ("Vary", "Origin")], probe=True))
    assert "WEB320" not in got and "WEB321" in got


@pytest.mark.parametrize("addr, expect", [("10.1.2.3", "medium"), ("192.168.0.5", "medium"), ("fd00::5", "medium"),
                                          ("127.0.0.1", "low"), ("93.184.216.34", "low")])
def test_web321_private_target_is_medium(addr, expect):
    dns = {"app.example.com": DnsRecord(host="app.example.com", status="ok", addresses=(addr,))}
    got, _ = scan(R(), R(reflect(("Vary", "Origin")), probe=True), dns=dns)
    assert [sev(i) for i in got["WEB321"]] == [expect]
    if expect == "medium":
        assert addr in got["WEB321"][0].notes[-1][0]


def test_reflection_rules_need_the_probe_origin():
    # the unprobed entry happens to send the probe origin value (not a reflection: no Origin was sent)
    got, ctx = scan(R(reflect(creds=True)), None)
    assert not {"WEB320", "WEB321", "WEB324"} & set(got)
    st = ctx.coverage.state("WEB320")
    assert st.state == "not_tested" and st.reasons[0][0] == "not_run"
    _, ctx = scan(R(), None, profile="minimal")
    assert ctx.coverage.state("WEB321").reasons[0][0] == "profile"


@pytest.mark.parametrize("extra, fires", [
    ((("Cache-Control", "public, max-age=300"),), True),
    ((), True),                                                  # heuristically cacheable
    ((("Cache-Control", "no-store"),), False),
    ((("Cache-Control", "private, max-age=60"),), False),
    ((("Set-Cookie", "a=1; Secure"),), False),
    ((("Set-Cookie", "a=1; Secure"), ("Cache-Control", "public")), True),
    ((("Vary", "Accept-Encoding, Origin"),), False),
    ((("Vary", "*"),), False),
])
def test_web324_vary_and_shared_cache_guard(extra, fires):
    got, _ = scan(R(), R(reflect(*extra), probe=True))
    assert ("WEB324" in got) is fires


# ----------------------------------------------------------------------------------------------- value rules

def test_web322_null_origin():
    got, _ = scan(R([(ACAO, "null")]))
    assert [sev(i) for i in got["WEB322"]] == ["medium"]
    got, _ = scan(R([(ACAO, "null"), (ACAC, "true")]))
    assert [sev(i) for i in got["WEB322"]] == ["high"]


def test_web323_star_with_credentials_and_trap():
    got, _ = scan(R([(ACAO, "*"), (ACAC, "true")]))
    assert "WEB323" in got
    got, _ = scan(R([(ACAO, "*")]))
    assert "WEB323" not in got


@pytest.mark.parametrize("fields", [
    [(ACAO, "https://a.example https://b.example")],
    [(ACAO, "https://a.example, https://b.example")],
    [(ACAO, "https://a.example"), (ACAO, "https://a.example")],
])
def test_web325_invalid_value_replaces_other_rules(fields):
    got, _ = scan(R(), R([*fields, (ACAC, "true")], probe=True))
    assert "WEB325" in got and not {"WEB320", "WEB321", "WEB326"} & set(got)


def test_web325_trap_single_origin():
    got, _ = scan(R([(ACAO, "  https://partner.example  ")]))
    assert "WEB325" not in got


def test_web326_http_origin_on_https_and_trap():
    got, _ = scan(R([(ACAO, "http://partner.example")]))
    assert "WEB326" in got
    got, _ = scan(R([(ACAO, "http://partner.example")], url="http://app.example.com/"), target="http://app.example.com/")
    assert "WEB326" not in got
    got, _ = scan(R([(ACAO, "https://partner.example"), (ACAC, "true"), ("Vary", "Origin")]))
    assert not got                                               # the fixed-allowlist trap: nothing at all


def test_web327_session_cookie_fact_sensitive_flag_and_traps():
    e = R([(ACAO, "*"), ("Set-Cookie", "sessionid=abc; Secure; HttpOnly")])
    fact = CookieFact(name="sessionid", value="abc", attrs={"secure": "", "httponly": ""}, raw="sessionid=abc; Secure",
                      response=e, host=e.host, secure_context=True, cls="session")
    got, _ = scan(e, cookies=[fact])
    assert "WEB327" not in got                                    # tentative: paranoid only
    got, _ = scan(e, cookies=[fact], sensitivity="paranoid")
    (i,) = got["WEB327"]
    assert i.confidence == "tentative" and "sessionid" in i.notes[0][0]
    got, _ = scan(R([(ACAO, "*")], flags={"sensitive"}), sensitivity="paranoid")
    assert "WEB327" in got
    pref = CookieFact(name="theme", value="dark", attrs={}, raw="theme=dark", response=e, host=e.host,
                      secure_context=True, cls="preference")
    got, _ = scan(R([(ACAO, "*"), ("Set-Cookie", "theme=dark")]), cookies=[pref], sensitivity="paranoid")
    assert "WEB327" not in got
    got, _ = scan(R([(ACAO, "*")], url="https://app.example.com/lib.js", kind="script"), sensitivity="paranoid",
                  target="https://app.example.com/lib.js")
    assert "WEB327" not in got


def test_web327_name_fallback_without_stage1():
    got, _ = scan(R([(ACAO, "*"), ("Set-Cookie", "PHPSESSID=x; Secure")]), sensitivity="paranoid")
    assert "WEB327" in got


# ----------------------------------------------------------------------------------------------- scope and dedupe

def test_probe_and_entry_give_one_finding_per_rule():
    got, _ = scan(R([(ACAO, "null")]), R([(ACAO, "null")], probe=True))
    assert len(got["WEB322"]) == 1


def test_crawled_pages_are_checked_and_third_parties_are_not():
    page = R([(ACAO, "null")], url="https://app.example.com/other")
    third = R([(ACAO, "null")], url="https://cdn.other.example/x.js")
    got, _ = scan(R(), None, pages=[Page(page, None, 1)])
    assert [i.url for i in got["WEB322"]] == ["https://app.example.com/other"]
    ctx = ScanContext(options=ScanOptions(), target=URL, entry=R(), subresources=[third], coverage=Coverage())
    assert not cors.run(ctx)


def test_waf_entry_is_inconclusive():
    e = R([(ACAO, "null")], kind="waf_challenge", status=403)
    got, ctx = scan(e, R(reflect(creds=True), probe=True, kind="waf_challenge", status=403))
    assert not got
    assert ctx.coverage.state("WEB320").state == "inconclusive"


def test_coverage_pass_and_fail():
    _, ctx = scan(R(), R(reflect(("Vary", "Origin"), creds=True), probe=True))
    assert ctx.coverage.state("WEB320").state == "fail"
    assert ctx.coverage.state("WEB322").state == "pass"
    assert set(cors.CHECKS) == {f"WEB{n}" for n in range(320, 328)}


# ----------------------------------------------------------------------------------------------- Observatory, i18n

@pytest.mark.parametrize("headers, slug", [
    ([], "cross-origin-resource-sharing-not-implemented"),
    ([(ACAO, "*")], "cross-origin-resource-sharing-implemented-with-public-access"),
    ([(ACAO, CORS_PROBE_ORIGIN), (ACAC, "TRUE")], "cross-origin-resource-sharing-implemented-with-universal-access"),
    ([(ACAO, CORS_PROBE_ORIGIN)], "cross-origin-resource-sharing-implemented-with-restricted-access"),
    ([(ACAO, "https://partner.example"), (ACAC, "true")],
     "cross-origin-resource-sharing-implemented-with-restricted-access"),
])
def test_observatory_cors_slug(headers, slug):
    _, ctx = scan(R(), R(headers, probe=True))
    assert ctx.observatory["cross-origin-resource-sharing"] == slug


def test_no_probe_no_slug():
    _, ctx = scan(R(), None)
    assert "cross-origin-resource-sharing" not in ctx.observatory


def test_bilingual_text_and_catalog():
    arabic = re.compile(r"[؀-ۿ]")
    for key, (en, ar) in cors.STR.items():
        assert en and ar and arabic.search(ar), key
        assert set(re.findall(r"\{(\w+)\}", en)) == set(re.findall(r"\{(\w+)\}", ar)), key
    catalog, patterns = cors.i18n_catalog()
    assert catalog[cors.STR["star_creds"][1]] == cors.STR["star_creds"][0]
    got, _ = scan(R([(ACAO, "a, b"), (ACAO, "c")]))
    (i,) = got["WEB325"]
    assert "2 fields" in i.notes[0][0] and "حقلين" in i.notes[0][1]
    en, ar = cors._note("http_origin", value="http://partner.example")
    assert any(re.sub(rx, repl, ar) == en for rx, repl in patterns if re.match(rx, ar))


# ----------------------------------------------------------------------------------------------- adversarial review

@pytest.mark.parametrize("addr, expect", [
    ("198.18.0.7", "low"),            # fake-IP DNS proxies (Clash, Surge) answer 198.18/15 for every public name
    ("192.0.2.10", "low"), ("0.0.0.0", "low"), ("::1", "low"), ("2001:db8::1", "low"),
    ("100.101.102.103", "medium"),    # CGNAT / tailnet: an intranet address
    ("172.31.255.1", "medium"), ("169.254.10.1", "medium"), ("fe80::1", "medium"), ("::ffff:10.0.0.1", "medium"),
])
def test_web321_intranet_ranges_are_explicit(addr, expect):
    dns = {"app.example.com": DnsRecord(host="app.example.com", status="ok", addresses=(addr,))}
    got, _ = scan(R(), R(reflect(("Vary", "Origin")), probe=True), dns=dns)
    assert [sev(i) for i in got["WEB321"]] == [expect]


def test_web321_peer_ip_ignored_through_a_proxy():
    ctx = ScanContext(options=ScanOptions(), target=URL, entry=R(ip="10.0.0.1"),
                      cors=R(reflect(("Vary", "Origin")), probe=True), coverage=Coverage(), proxied=True)
    assert cors.private_target(ctx) == ""


def test_hostile_acao_values_are_capped():
    huge = "https://" + "a" * 500_000 + ".example"
    got, _ = scan(R([(ACAO, huge + ", https://b.example")]), None)
    (i,) = got["WEB325"]
    assert len(i.group_value) <= 80 and all(len(n[0]) < 2000 and len(n[1]) < 2000 for n in i.notes)
    got, _ = scan(R([(ACAO, "http://" + "b" * 500_000)]), None)
    assert len(got["WEB326"][0].group_value) <= 80
    got, _ = scan(R([(ACAO, "null\x1b[2J"), (ACAC, "true")]), None)
    assert got == {} or all("\x1b" not in n[0] for rs in got.values() for i in rs for n in i.notes)
