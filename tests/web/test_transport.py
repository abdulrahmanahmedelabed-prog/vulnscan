"""Tests of webscan/transport.py (WP6): HSTS grammar, preload snapshot and eligibility, redirect-chain rules, WEB000,
WEB116–WEB119, Observatory slugs, stage-1 HSTS facts, coverage, i18n, and the C-RED / C-HSTS corpus groups."""

from __future__ import annotations

import importlib
import re
import shlex
import shutil
import sys
from pathlib import Path

import pytest

from vulnscan.webscan import data, htmlparse, transport
from vulnscan.webscan.coverage import Coverage
from vulnscan.webscan.rules import RULES, validate_issue
from vulnscan.webscan.transport import Preload, parse_sts
from vulnscan.webscan.types import CookieFact, HeaderList, Page, Response, ScanContext, ScanOptions

GOOD = "max-age=63072000; includeSubDomains"
HTML = "text/html; charset=utf-8"


# ----------------------------------------------------------------------------------------------- builders

def R(url: str, status: int | None = 200, headers=(), body: bytes | str = b"<html><body>ok</body></html>",
      kind: str | None = None, **kw) -> Response:
    hl = HeaderList.of(*headers)
    if isinstance(body, str):
        body = body.encode("utf-8")
    if kind is None:
        if status is None:
            kind = "error"
        elif 300 <= status < 400 and hl.has("location"):
            kind = "redirect"
        elif status >= 400:
            kind = "error_page"
        else:
            kind = "document"
    if not hl.has("content-type") and status is not None and kind == "document":
        hl = HeaderList(hl.items + (("Content-Type", HTML),))
    return Response(url=url, status=status, headers=hl, body=body, kind=kind, **kw)


def redirect(url: str, location: str, status: int = 301, headers=(), body: bytes | str = b"") -> Response:
    return R(url, status, [("Location", location), *headers], body=body)


def chain(*hops: Response) -> Response:
    final = hops[-1]
    final.chain = list(hops[:-1])
    return final


def ctx_for(entry: Response | None, target: str | None = None, *, pages=None, profile="standard", sensitivity="default",
            fixed_now=None, **fields) -> ScanContext:
    opts = ScanOptions(profile=profile, sensitivity=sensitivity)
    target = target or (entry.hops()[0].url if entry is not None else "https://example.com/")
    if pages is None:
        pages = []
        if entry is not None and entry.kind == "document" and entry.body:
            pages = [Page(entry, htmlparse.parse_response(entry), 0)]
    ctx = ScanContext(options=opts, target=target, entry=entry, pages=pages, coverage=Coverage(), **fields)
    if fixed_now is not None:
        ctx.now = fixed_now
    return ctx


def issues(ctx: ScanContext) -> dict[str, list]:
    out: dict[str, list] = {}
    for i in transport.run(ctx):
        assert validate_issue(i) == [], validate_issue(i)
        out.setdefault(i.rule, []).append(i)
    return out


def sev(i) -> str:
    return i.severity or RULES[i.rule].severity


def notes_en(i) -> str:
    return " | ".join(n[0] for n in i.notes)


# ----------------------------------------------------------------------------------------------- HSTS grammar

@pytest.mark.parametrize("value, max_age, isd, preload", [
    ("max-age=63072000; includeSubDomains; preload", 63072000, True, True),
    ("MAX-AGE=300;INCLUDESUBDOMAINS", 300, True, False),
    ('max-age="31536000"', 31536000, False, False),          # quoted-string is RFC 6797-valid
    ('max-age="0"', 0, False, False),
    ("max-age=0", 0, False, False),
    ("  max-age = 600 ;\tincludeSubDomains  ", 600, True, False),
    ("max-age=31536000; foo=bar; ;", 31536000, False, False),  # unknown and empty directives are warnings only
])
def test_sts_valid(value, max_age, isd, preload):
    h = parse_sts(value)
    assert h.valid, h.errors
    assert (h.max_age, h.include_subdomains, h.preload) == (max_age, isd, preload)


@pytest.mark.parametrize("value, code", [
    ("max-age=63072000; includeSubDomains, max-age=63072000", "header.parse.comma"),        # folded duplicates
    ("max-age=“63072000”; includeSubDomains", "header.parse.non_ascii"),          # curly quotes
    ("max-age=â\u0080\u009c63072000â\u0080\u009d", "header.parse.non_ascii"),     # same bytes as http.client gives
    ("includeSubDomains", "header.parse.max_age.missing"),
    ("", "header.parse.empty"),
    ("max-age", "header.parse.invalid.max_age.no_value"),
    ("max-age=", "header.parse.invalid.max_age.no_value"),
    ("max-age=063072000", "header.parse.max_age.leading_zero"),
    ("max-age=1e9", "header.parse.max_age.non_digit_characters"),
    ("max-age=-1", "header.parse.max_age.non_digit_characters"),
    ("max-age=３００", "header.parse.max_age.non_digit_characters"),          # fullwidth digits
    (f"max-age={2 ** 64}", "header.parse.max_age.parse_int_error"),
    ("max-age=1; max-age=2", "header.parse.repeated.max_age"),
    ("max-age=1; includeSubDomains; includesubdomains", "header.parse.repeated.include_sub_domains"),
    ("max-age=1; preload; preload", "header.parse.repeated.preload"),
    ("max-age=1; includeSubDomains=yes", "header.parse.invalid.include_sub_domains"),
    ('"max-age=31536000"', "header.parse.quoted_directive"),
    ("max-age=1\x00", "header.parse.non_ascii"),
])
def test_sts_invalid(value, code):
    h = parse_sts(value)
    assert not h.valid
    assert code in h.errors


def test_sts_warnings_and_preload_with_value():
    h = parse_sts("max-age=31536000; preload=1; x-custom; ;")
    assert h.valid and not h.preload
    assert {"header.parse.invalid.preload", "header.parse.unknown_directive", "header.parse.empty_directive"} <= set(
        h.warnings)
    assert h.unknown == ["x-custom"]


def test_preloadable_codes():
    assert parse_sts("max-age=31536000; includeSubDomains; preload").preloadable_codes() == []
    assert parse_sts("max-age=100").preloadable_codes() == [
        "header.preloadable.include_sub_domains.missing", "header.preloadable.preload.missing",
        "header.preloadable.max_age.below_1_year"]
    assert "header.preloadable.max_age.zero" in parse_sts("max-age=0").preloadable_codes()


# ----------------------------------------------------------------------------------------------- preload snapshot

def test_bundled_snapshot_and_inline_tlds():
    doc = data.load_json("hsts-preload.json.gz")
    assert data.validate_data("hsts-preload.json.gz", doc) == []
    assert len(doc["entries"]) > 50_000
    assert set(doc["tlds"]) == transport.PRELOADED_TLDS and len(transport.PRELOADED_TLDS) == 52
    assert doc["meta"]["license"] == "BSD-3-Clause"
    p = Preload.load()
    assert p.available and p.date == doc["meta"]["date"]
    assert p.lookup("kashif-corpus.dev") == (True, True, "dev")
    assert p.lookup("EXAMPLE.APP.") == (True, True, "app")
    assert p.lookup("example.test") == (False, False, "")
    assert p.lookup("127.0.0.1") == (False, False, "")
    name, isd = next(iter(sorted((n, v) for n, v in doc["entries"].items() if "." in n and v)))
    assert p.lookup(name) == (True, True, name) and p.lookup("a.b." + name)[0]


def test_lookup_semantics_exact_and_parent():
    p = Preload({"example.com": True, "noisd.example": False}, tlds=())
    assert p.lookup("example.com") == (True, True, "example.com")
    assert p.lookup("www.example.com") == (True, True, "example.com")
    assert p.lookup("noisd.example") == (True, False, "noisd.example")
    assert p.lookup("www.noisd.example") == (False, False, "")        # parent without include_subdomains
    assert p.lookup("x.page")[0]                                      # inline TLDs always present


def test_missing_data_file_keeps_tlds(monkeypatch):
    class Broken:
        @staticmethod
        def load_json(name):
            raise FileNotFoundError(name)
    p = Preload.load(Broken)
    assert not p.available and p.preloaded("a.dev") and not p.preloaded("example.com")


# ----------------------------------------------------------------------------------------------- WEB000

def test_web000_http_serves_content_non_default_port():
    e = R("http://example.com:8080/", headers=[])
    got = issues(ctx_for(e))
    (i,) = got["WEB000"]
    assert sev(i) == "high" and i.confidence == "certain"
    assert "non-default port" in notes_en(i) and "Variant" not in notes_en(i)


def test_web000_variants_a_and_b():
    e = R("http://example.com/")
    ctx = ctx_for(e)
    ctx.https_probe = R("https://example.com/", None, error="connection refused")
    (i,) = issues(ctx)["WEB000"]
    assert "Variant A" in notes_en(i)
    ctx = ctx_for(R("http://example.com/"))
    ctx.https_probe = R("https://example.com/", headers=[("Strict-Transport-Security", GOOD)])
    (i,) = issues(ctx)["WEB000"]
    assert "Variant B" in notes_en(i)
    ctx = ctx_for(R("http://example.com/"))
    ctx.https_probe = R("https://example.com/", flags=frozenset({"cert-error"}))
    assert "Variant A" in notes_en(issues(ctx)["WEB000"][0])


def test_web000_https_target_http_counterpart_serves():
    e = R("https://example.com/", headers=[("Strict-Transport-Security", GOOD)])
    ctx = ctx_for(e)
    ctx.http_probe = R("http://example.com/")
    (i,) = issues(ctx)["WEB000"]
    assert i.url == "http://example.com/" and "Variant B" in notes_en(i)


def test_web000_preloaded_loopback_and_api():
    assert sev(issues(ctx_for(R("http://kashif.dev/")))["WEB000"][0]) == "info"
    assert sev(issues(ctx_for(R("http://127.0.0.1:8000/")))["WEB000"][0]) == "info"
    assert sev(issues(ctx_for(R("http://localhost/")))["WEB000"][0]) == "info"
    api = R("http://api.example.com/v1/", headers=[("Content-Type", "application/json")], body=b"{}", kind="api_json")
    (i,) = issues(ctx_for(api))["WEB000"]
    assert i.params.get("variant") == "api"
    assert RULES["WEB000"].advice("en", **i.params).startswith("Refuse plain HTTP")


@pytest.mark.parametrize("final", [
    lambda: chain(redirect("http://example.com/", "https://example.com/"), R("https://example.com/")),
    lambda: R("http://example.com/", 403, body=b'{"error":"https required"}', kind="error_page"),
    lambda: R("http://example.com/", 204, body=b"", kind="no_content"),
    lambda: R("http://example.com/", body='<meta http-equiv="refresh" content="0;url=https://example.com/">'),
    lambda: chain(redirect("http://example.com/", "https://example.com/"),
                  redirect("https://example.com/", "http://example.com/x"), R("http://example.com/x")),
])
def test_web000_traps(final):
    assert "WEB000" not in issues(ctx_for(final()))


def test_web000_slow_meta_refresh_still_fires():
    e = R("http://example.com/", body='<meta http-equiv="refresh" content="5;url=https://example.com/">')
    assert "WEB000" in issues(ctx_for(e))


def test_web000_waf_inconclusive():
    e = R("http://example.com/", 403, kind="waf_challenge")
    ctx = ctx_for(e)
    assert "WEB000" not in issues(ctx)
    assert ctx.coverage.state("WEB000").state == "inconclusive"


def test_web000_minimal_profile_not_tested():
    ctx = ctx_for(R("https://example.com/", headers=[("Strict-Transport-Security", GOOD)]), profile="minimal")
    issues(ctx)
    st = ctx.coverage.state("WEB000")
    assert st.state == "not_tested" and st.reasons[0][0] == "profile"


# ----------------------------------------------------------------------------------------------- WEB101 / 102 / 105

def test_web101_first_hop_http():
    f = chain(redirect("http://a.example/", "http://www.a.example/"),
              redirect("http://www.a.example/", "https://www.a.example/"), R("https://www.a.example/"))
    got = issues(ctx_for(f))
    assert "WEB101" in got and "WEB102" not in got and "WEB000" not in got


def test_web101_trap_chain_never_reaches_https():
    f = chain(redirect("http://a.example/", "http://www.a.example/"), R("http://www.a.example/"))
    got = issues(ctx_for(f))
    assert "WEB101" not in got and "WEB000" in got


def test_web102_other_host_and_trap():
    f = chain(redirect("http://a.example/", "https://www.a.example/"), R("https://www.a.example/"))
    (i,) = issues(ctx_for(f))["WEB102"]
    assert sev(i) == "low" and "www.a.example" in notes_en(i)
    f = chain(redirect("http://a.example/", "https://a.example/"), R("https://a.example/"))
    assert "WEB102" not in issues(ctx_for(f))


@pytest.mark.parametrize("status, fires", [(302, True), (303, True), (307, True), (301, False), (308, False)])
def test_web105_temporary_upgrade(status, fires):
    f = chain(redirect("http://a.example/", "https://a.example/", status), R("https://a.example/"))
    assert ("WEB105" in issues(ctx_for(f))) is fires


def test_redirect_rules_skip_preloaded_hosts():
    f = chain(redirect("http://a.dev/", "https://www.a.dev/", 302), R("https://www.a.dev/"))
    ctx = ctx_for(f)
    got = issues(ctx)
    assert not {"WEB101", "WEB102", "WEB105"} & set(got)
    assert ctx.coverage.state("WEB105").state == "not_applicable"


# ----------------------------------------------------------------------------------------------- WEB103

def test_web103_location_downgrade():
    f = chain(redirect("https://a.example/", "http://a.example/plain", 302), R("http://a.example/plain"))
    (i,) = issues(ctx_for(f))["WEB103"]
    assert sev(i) == "high" and i.confidence == "certain" and i.evidence.match["value"] == "http://a.example/plain"


def test_web103_meta_refresh_and_script():
    e = R("https://a.example/", body='<head><meta http-equiv="refresh" content="0; URL=\'http://a.example/\'"></head>'
          '<script>if (!window.k) { window.location.href = "http://a.example/legacy"; }</script>')
    got = issues(ctx_for(e, sensitivity="paranoid"))["WEB103"]
    confs = sorted(i.confidence for i in got)
    assert confs == ["certain", "tentative"]


@pytest.mark.parametrize("body", [
    '<meta http-equiv="refresh" content="0;url=https://a.example/home">',
    '<a href="http://other.example/">plain link</a>',
    '<script>var u = "http://a.example/"; location.href = u;</script>',
    '<template><meta http-equiv="refresh" content="0;url=http://a.example/"></template>',
])
def test_web103_traps(body):
    assert "WEB103" not in issues(ctx_for(R("https://a.example/", body=body), sensitivity="paranoid"))


def test_web103_loopback_ignored():
    f = chain(redirect("https://localhost/", "http://localhost/x"), R("http://localhost/x"))
    assert "WEB103" not in issues(ctx_for(f))
    f = chain(redirect("https://a.example/", "http://127.0.0.1/x"), R("http://127.0.0.1/x"))
    assert "WEB103" not in issues(ctx_for(f))


def test_web103_hostile_location_is_quoted_and_stripped():
    loc = "http://x.example/'$(id)'\x1b[31m"
    f = chain(redirect("https://a.example/", loc), R("http://x.example/"))
    (i,) = issues(ctx_for(f))["WEB103"]
    assert "\x1b" not in notes_en(i) and "\x1b" not in i.notes[0][1]
    shlex.split(i.evidence.curl)          # a well-formed, quoted command line
    assert "$(id)" not in i.evidence.curl.replace("'$(id)'", "")


# ----------------------------------------------------------------------------------------------- WEB104

def _long_chain(n: int, flags=frozenset()) -> Response:
    hops = [redirect(f"https://a.example/r{i}", f"/r{i + 1}", 302) for i in range(n)]
    final = R(f"https://a.example/r{n}") if not flags else hops.pop()
    if flags:
        final.flags = frozenset(flags)
    return chain(*hops, final)


@pytest.mark.parametrize("n, flags, expect", [
    (2, (), None), (3, (), None), (4, (), "info"), (10, {"redirect-limit"}, "low"), (5, {"redirect-loop"}, "low"),
])
def test_web104(n, flags, expect):
    got = issues(ctx_for(_long_chain(n, flags))).get("WEB104")
    if expect is None:
        assert not got
    else:
        assert [sev(i) for i in got] == [expect]


def test_web104_arabic_count_agreement():
    (i,) = issues(ctx_for(_long_chain(4)))["WEB104"]
    assert "4 hops" in i.notes[0][0] and "4 قفزات" in i.notes[0][1]


# ----------------------------------------------------------------------------------------------- WEB106

BIG = ("<html><body><h1>Account</h1><form method=post action=/login><input name=u><input type=password name=p>"
       "</form><table>" + "".join(f'<tr><td><a href="/item/{i}">Item {i}</a></td><td>Description of item {i} in the '
                                  f'catalogue.</td></tr>' for i in range(30)) + "</table></body></html>")


def test_web106_full_page():
    f = chain(redirect("https://a.example/", "/home", body=BIG), R("https://a.example/home"))
    (i,) = issues(ctx_for(f))["WEB106"]
    assert i.confidence == "firm" and "form" in i.group_value


@pytest.mark.parametrize("body, status", [
    ('<html><body>Moved to <a href="/home">/home</a></body></html>', 301),
    ("x" * 2000, 302),                                   # long but no page signals (one signal: text)
    (BIG, 304),
])
def test_web106_traps(body, status):
    hop = R("https://a.example/", status, [("Location", "/home")], body=body)
    f = chain(hop, R("https://a.example/home"))
    assert "WEB106" not in issues(ctx_for(f))


def test_web106_other_site_ignored():
    f = chain(redirect("https://a.example/", "https://cdn.other.example/x"),
              redirect("https://cdn.other.example/x", "https://a.example/home", body=BIG), R("https://a.example/home"))
    assert "WEB106" not in issues(ctx_for(f))


# ----------------------------------------------------------------------------------------------- missing HSTS, WEB110–WEB114

def sts(value: str = GOOD) -> tuple[str, str]:
    return ("Strict-Transport-Security", value)


def test_missing_hsts_and_good():
    (i,) = issues(ctx_for(R("https://a.example/")))["WEB-strict-transport-security"]
    assert sev(i) == "medium" and i.confidence == "firm"
    got = issues(ctx_for(R("https://a.example/", headers=[sts()])))
    assert not {r for r in got if r.startswith("WEB-strict") or r.startswith("WEB11")}


def test_missing_hsts_preloaded_is_info():
    (i,) = issues(ctx_for(R("https://shop.example.dev/")))["WEB-strict-transport-security"]
    assert sev(i) == "info" and "preload" in notes_en(i)


@pytest.mark.parametrize("final", [
    lambda: R("https://127.0.0.1/"),
    lambda: R("https://[::1]:8443/"),
    lambda: R("https://a.example/", flags=frozenset({"cert-error", "cert-verify:18"})),
    lambda: R("http://a.example/", headers=[sts()]),
    lambda: chain(redirect("https://a.example/", "/home"), R("https://a.example/home", headers=[sts()])),
    lambda: chain(redirect("https://a.example/", "https://www.a.example/"), R("https://www.a.example/", headers=[sts()])),
    lambda: R("https://a.example/", 404, kind="error_page"),
])
def test_missing_hsts_traps(final):
    assert "WEB-strict-transport-security" not in issues(ctx_for(final()))


def test_missing_hsts_waf_is_inconclusive():
    ctx = ctx_for(R("https://a.example/", 403, kind="waf_challenge"))
    assert not issues(ctx)
    assert ctx.coverage.state("WEB-strict-transport-security").state == "inconclusive"


def test_ip_literal_not_applicable_coverage():
    ctx = ctx_for(R("https://127.0.0.1/"))
    issues(ctx)
    assert ctx.coverage.state("WEB-strict-transport-security").state == "not_applicable"


@pytest.mark.parametrize("value", ["max-age=0", 'max-age="0"', "max-age=0; includeSubDomains"])
def test_web110_replaces_missing(value):
    got = issues(ctx_for(R("https://a.example/", headers=[sts(value)])))
    assert "WEB110" in got and "WEB-strict-transport-security" not in got and "WEB111" not in got
    assert sev(got["WEB110"][0]) == "medium"


@pytest.mark.parametrize("age, expect, variant", [
    (300, "medium", None), (8640000, "medium", None), (15551999, "medium", None), (15552000, "low", None),
    (17280000, "low", None), (31536000, None, None), (63072000, None, None), (315360001, "info", "too_long"),
])
def test_web111_bands(age, expect, variant):
    got = issues(ctx_for(R("https://a.example/", headers=[sts(f"max-age={age}; includeSubDomains")]))).get("WEB111")
    if expect is None:
        assert not got
    else:
        (i,) = got
        assert sev(i) == expect and i.params.get("variant") == variant
    if variant:
        assert RULES["WEB111"].title("en", **i.params) == "HSTS max-age longer than ten years"


def test_web112_replaces_missing_and_lists_codes():
    got = issues(ctx_for(R("https://a.example/", headers=[sts("max-age=063072000; includeSubDomains")])))
    assert "WEB112" in got and "WEB-strict-transport-security" not in got
    assert "leading_zero" in notes_en(got["WEB112"][0])
    assert not {"WEB110", "WEB111", "WEB114"} & set(got)


def test_web113_identical_and_different():
    got = issues(ctx_for(R("https://a.example/", headers=[sts(), sts()])))
    assert [sev(i) for i in got["WEB113"]] == ["info"]
    got = issues(ctx_for(R("https://a.example/", headers=[sts(), sts("max-age=300")])))
    (i,) = got["WEB113"]
    assert sev(i) == "low" and "WEB111" not in got            # the first field is what browsers use
    assert "2 fields" in notes_en(i) and "حقلين" in i.notes[0][1]


def test_web114_info_low_and_traps():
    e = R("https://www.a.example/", headers=[sts("max-age=63072000")])
    (i,) = issues(ctx_for(e))["WEB114"]
    assert sev(i) == "info"
    e = R("https://www.a.example/", headers=[sts("max-age=63072000"),
                                            ("Set-Cookie", "sid=1; Domain=a.example; Secure; HttpOnly")])
    ctx = ctx_for(e)
    ctx.cookies = [CookieFact(name="sid", value="1", attrs={"domain": "a.example", "secure": "", "httponly": ""},
                              raw="sid=1; Domain=a.example; Secure; HttpOnly", response=e, host="www.a.example",
                              secure_context=True, cls="session")]
    (i,) = issues(ctx)["WEB114"]
    assert sev(i) == "low" and "sid" in notes_en(i)
    assert "WEB114" not in issues(ctx_for(R("https://www.a.example/", headers=[sts()])))
    assert "WEB114" not in issues(ctx_for(R("https://shop.a.dev/", headers=[sts("max-age=63072000")])))


def test_obs_fold_is_a_note_not_a_failure():
    e = R("https://a.example/", headers=[sts("max-age=63072000; includeSubDomains")],
          flags=frozenset({"obs-fold", "obs-fold:strict-transport-security"}))
    got = issues(ctx_for(e))
    assert not {r for r in got if r.startswith("WEB-strict") or r.startswith("WEB11")}
    e = R("https://a.example/", headers=[sts("max-age=300; includeSubDomains")],
          flags=frozenset({"obs-fold:strict-transport-security"}))
    assert "folded" in notes_en(issues(ctx_for(e))["WEB111"][0])


# ----------------------------------------------------------------------------------------------- WEB115

def test_web115_subdomain_with_preload():
    e = R("https://www.a.example/", headers=[sts("max-age=63072000; preload")])
    (i,) = issues(ctx_for(e))["WEB115"]
    assert sev(i) == "low" and i.confidence == "certain"
    for code in ("header.preloadable.include_sub_domains.missing", "domain.is_subdomain"):
        assert code in i.group_value
    assert "not fetched" in notes_en(i)


def _apex_scan(http_chain: Response, https_headers=None) -> dict:
    e = R("https://kashif-apex.example/", headers=list(https_headers or [sts(GOOD + "; preload")]))
    ctx = ctx_for(e)
    ctx.http_probe = http_chain
    return issues(ctx)


def test_web115_apex_eligible_not_in_snapshot_is_info():
    h = chain(redirect("http://kashif-apex.example/", "https://kashif-apex.example/"),
              R("https://kashif-apex.example/", headers=[sts(GOOD + "; preload")]))
    (i,) = _apex_scan(h)["WEB115"]
    assert sev(i) == "info" and i.confidence == "firm" and "Eligible" in notes_en(i)


@pytest.mark.parametrize("hops, code", [
    (lambda: [R("http://kashif-apex.example/")], "redirects.http.no_redirect"),
    (lambda: [redirect("http://kashif-apex.example/", "https://www.kashif-apex.example/"),
              R("https://www.kashif-apex.example/")], "redirects.http.www_first"),
    (lambda: [redirect("http://kashif-apex.example/", "http://kashif-apex.example/home"),
              redirect("http://kashif-apex.example/home", "https://kashif-apex.example/home"),
              R("https://kashif-apex.example/home")], "redirects.http.first_redirect.insecure"),
    (lambda: [redirect("http://kashif-apex.example/", "http://www.kashif-apex.example/"),
              redirect("http://www.kashif-apex.example/", "https://www.kashif-apex.example/"),
              R("https://www.kashif-apex.example/")], "redirects.http.www_first"),
    (lambda: [redirect("http://kashif-apex.example/", "https://kashif-apex.example/"),
              redirect("https://kashif-apex.example/", "/home"), R("https://kashif-apex.example/home")],
     "redirects.http.first_redirect.no_hsts"),
    (lambda: [redirect("http://kashif-apex.example/", "https://kashif-apex.example/"),
              redirect("https://kashif-apex.example/", "http://kashif-apex.example/x", headers=[sts(GOOD + "; preload")]),
              R("http://kashif-apex.example/x")], "redirects.insecure.initial"),
    (lambda: [redirect("http://kashif-apex.example/", "https://kashif-apex.example/"),
              *[redirect(f"https://kashif-apex.example/{i}", f"/{i + 1}", headers=[sts(GOOD + "; preload")])
                for i in range(4)], R("https://kashif-apex.example/4")], "redirects.too_many"),
])
def test_web115_redirect_codes(hops, code):
    got = _apex_scan(chain(*hops()))
    (i,) = got["WEB115"]
    assert sev(i) == "low" and code in i.group_value, i.group_value


def test_web115_traps():
    h = chain(redirect("http://kashif-apex.example/", "https://kashif-apex.example/"),
              R("https://kashif-apex.example/", headers=[sts()]))
    assert "WEB115" not in _apex_scan(h, (sts(),))          # no preload directive: not requesting
    p = Preload.load()
    name = next(n for n, v in sorted(p.entries.items()) if v and n.count(".") == 1 and n.split(".")[1] == "com")
    e = R(f"https://{name}/", headers=[sts(GOOD + "; preload")])
    assert "WEB115" not in issues(ctx_for(e))                # already preloaded: a positive, not a finding


def test_web115_sha1_from_tls_report():
    h = chain(redirect("http://kashif-apex.example/", "https://kashif-apex.example/"),
              R("https://kashif-apex.example/", headers=[sts(GOOD + "; preload")]))
    e = R("https://kashif-apex.example/", headers=[sts(GOOD + "; preload")])
    ctx = ctx_for(e, tls={"192.0.2.1": {"host": "kashif-apex.example", "leaf": {"sigalg": "sha1WithRSAEncryption"}}})
    ctx.http_probe = h
    (i,) = issues(ctx)["WEB115"]
    assert "domain.tls.sha1" in i.group_value


# ----------------------------------------------------------------------------------------------- WEB116 / WEB117

def test_web116_http_header_and_meta():
    got = issues(ctx_for(R("http://a.example/", headers=[sts()])))
    assert [sev(i) for i in got["WEB116"]] == ["info"]
    e = R("https://a.example/", headers=[sts()],
          body='<head><meta http-equiv="Strict-Transport-Security" content="max-age=1"></head>')
    got = issues(ctx_for(e))
    assert [i.group_value for i in got["WEB116"]] == ["meta"]
    assert "WEB116" not in issues(ctx_for(R("https://a.example/", headers=[sts()])))


def test_web117_cross_host_hop_and_traps():
    f = chain(redirect("https://a.example/", "https://www.a.example/"), R("https://www.a.example/", headers=[sts()]))
    got = issues(ctx_for(f))
    assert "WEB117" in got and "WEB-strict-transport-security" not in got
    f = chain(redirect("https://a.example/", "/home"), R("https://a.example/home", headers=[sts()]))
    assert "WEB117" not in issues(ctx_for(f))
    f = chain(redirect("https://a.example/", "https://www.a.example/", headers=[sts()]),
              R("https://www.a.example/", headers=[sts()]))
    assert "WEB117" not in issues(ctx_for(f))
    f = chain(redirect("https://a.dev/", "https://www.a.dev/"), R("https://www.a.dev/", headers=[sts()]))
    assert "WEB117" not in issues(ctx_for(f))               # preloaded: HSTS is enforced anyway


# ----------------------------------------------------------------------------------------------- WEB118 / WEB119

@pytest.mark.parametrize("value, expect", [
    ('Basic realm="admin"', "high"), ('Digest realm="x", nonce="abc", qop="auth"', "medium"),
    ('Bearer realm="api", Basic realm="x"', "high"), ('Bearer realm="api", error="basic"', None),
    ('Negotiate', None),
])
def test_web118(value, expect):
    got = issues(ctx_for(R("http://a.example/admin", 401, [("WWW-Authenticate", value)], kind="error_page")))
    if expect is None:
        assert "WEB118" not in got
    else:
        assert [sev(i) for i in got["WEB118"]] == [expect]


def test_web118_https_trap():
    got = issues(ctx_for(R("https://a.example/admin", 401, [("WWW-Authenticate", "Basic")], kind="error_page")))
    assert "WEB118" not in got


FORM = '<form method=post><input type="hidden" name="csrf_token" value="abc123"><input name=q></form>'


def test_web119_breach_precondition():
    e = R("https://a.example/", headers=[sts(), ("Content-Encoding", "gzip")], body=FORM, encoding="gzip")
    (i,) = issues(ctx_for(e))["WEB119"]
    assert i.confidence == "tentative" and sev(i) == "info"
    (i,) = issues(ctx_for(e, sensitivity="paranoid"))["WEB119"]
    assert sev(i) == "low"


def test_web119_traps_and_opaque():
    assert "WEB119" not in issues(ctx_for(R("https://a.example/", headers=[sts()], body=FORM)))
    e = R("https://a.example/", headers=[sts(), ("Content-Encoding", "gzip")], body="<form><input name=q></form>")
    assert "WEB119" not in issues(ctx_for(e))
    e = R("https://a.example/", headers=[sts(), ("Content-Encoding", "br")], body=b"",
          flags=frozenset({"opaque-coding", "opaque-coding:br"}))
    ctx = ctx_for(e, pages=[Page(e, None, 0)])
    assert "WEB119" not in issues(ctx)
    assert ctx.coverage.state("WEB119").state == "not_tested"


# ----------------------------------------------------------------------------------------------- stage 1 facts

def test_hsts_facts():
    a = R("https://a.example/", headers=[sts()])
    b = R("https://b.example/", headers=[sts("max-age=0")])
    c = R("https://c.example/", headers=[sts("max-age=300, max-age=300")])
    d = R("https://d.example/", headers=[sts("max-age=600")], flags=frozenset({"cert-error"}))
    e = R("https://www.x.dev/")
    ctx = ctx_for(a)
    ctx.pages = [Page(r, None, 0) for r in (a, b, c, d, e)]
    f = transport.hsts_facts(ctx)
    assert f["a.example"].effective and f["a.example"].include_subdomains and f["a.example"].max_age == 63072000
    assert f["a.example"].response is a and f["a.example"].header_values == (GOOD,)
    assert f["b.example"].present and f["b.example"].valid and not f["b.example"].effective
    assert not f["c.example"].valid and "header.parse.comma" in f["c.example"].problems
    assert f["d.example"].cert_error and not f["d.example"].effective
    assert f["www.x.dev"].preloaded and f["www.x.dev"].effective and f["www.x.dev"].include_subdomains
    assert f["dev"].preloaded and f["dev"].include_subdomains          # preloaded parent covers cookie Domain=x.dev
    assert ctx.hsts_for("A.EXAMPLE.") is None                          # hsts_facts is pure: the engine stores it
    assert transport.hsts_facts(ctx_for(R("https://127.0.0.1/", headers=[sts()])))["127.0.0.1"].effective is False


# ----------------------------------------------------------------------------------------------- Observatory

def test_observatory_hsts_quirks():
    p = Preload({}, tlds=())

    def slug(value, verified=True, host="a.example"):
        r = R(f"https://{host}/", headers=[sts(value)] if value is not None else [])
        return transport.observatory_hsts_slug(r, host, p, verified)
    assert slug(None) == "hsts-not-implemented"
    assert slug("max-age=300") == "hsts-implemented-max-age-less-than-six-months"
    assert slug("max-age=15552000") == "hsts-implemented-max-age-at-least-six-months"
    assert slug('max-age="0"') == "hsts-implemented-max-age-at-least-six-months"   # parseInt('"0"') is NaN
    assert slug("max-age=1, max-age=2") == "hsts-header-invalid"
    # two fields: Node's http module (Observatory's client) joins them with ", ", so Observatory 1.7.2 sees a comma
    # (verified with the official analyzer on the hsts-two-headers corpus case in phase D)
    two = R("https://a.example/", headers=[sts(GOOD), sts("max-age=300")])
    assert transport.observatory_hsts_slug(two, "a.example", p) == "hsts-header-invalid"
    assert slug("includeSubDomains") == "hsts-header-invalid"
    assert slug(GOOD, verified=False) == "hsts-invalid-cert"
    assert slug("max-age=300", host="a.dev") == "hsts-preloaded"
    assert transport.observatory_hsts_slug(R("https://a.example/", None, error="x"), "a.example", p) == \
        "hsts-not-implemented-no-https"


def test_observatory_redirection():
    p = Preload({}, tlds=())

    def slug(final):
        return transport.observatory_redirection_slug(final, p)
    assert slug(R("http://a.example/")) == "redirection-missing"
    assert slug(chain(redirect("http://a.example/", "https://a.example/"), R("https://a.example/"))) == \
        "redirection-to-https"
    assert slug(chain(redirect("http://a.example/", "http://www.a.example/"),
                      redirect("http://www.a.example/", "https://www.a.example/"), R("https://www.a.example/"))) == \
        "redirection-not-to-https-on-initial-redirection"
    assert slug(chain(redirect("http://a.example/", "https://b.example/"), R("https://b.example/"))) == \
        "redirection-off-host-from-http"
    assert slug(chain(redirect("http://a.example/", "/x"), R("http://a.example/x"))) == "redirection-not-to-https"
    assert slug(R("http://a.example/", None, error="refused")) == "redirection-not-needed-no-http"
    assert transport.observatory_redirection_slug(R("http://a.dev/"), Preload({}, tlds=())) == \
        "redirection-all-redirects-preloaded"


def test_run_writes_observatory_slugs():
    e = R("https://a.example/", headers=[sts()])
    ctx = ctx_for(e)
    ctx.http_probe = chain(redirect("http://a.example/", "https://a.example/"), R("https://a.example/", headers=[sts()]))
    issues(ctx)
    assert ctx.observatory == {"redirection": "redirection-to-https",
                               "strict-transport-security": "hsts-implemented-max-age-at-least-six-months"}


# ----------------------------------------------------------------------------------------------- coverage, i18n, registry

def test_checks_and_coverage_states():
    assert set(transport.CHECKS) == {r for r, m in RULES.items() if m.module == "transport"}
    ctx = ctx_for(R("https://a.example/"))
    issues(ctx)
    assert ctx.coverage.state("WEB-strict-transport-security").state == "fail"
    assert ctx.coverage.state("WEB103").state == "pass"
    ctx = ctx_for(R("https://a.example/", headers=[sts()]))
    issues(ctx)
    assert ctx.coverage.state("WEB-strict-transport-security").state == "pass"
    assert ctx.coverage.state("WEB119").state == "pass"


def test_bilingual_text_and_catalog():
    arabic = re.compile(r"[؀-ۿ]")
    for table in (transport.STR, transport.CODES):
        for key, (en, ar) in table.items():
            assert en and ar and arabic.search(ar), key
            assert set(re.findall(r"\{(\w+)\}", en)) == set(re.findall(r"\{(\w+)\}", ar)), key
    catalog, patterns = transport.i18n_catalog()
    assert catalog[transport.STR["https_port"][1]] == transport.STR["https_port"][0]
    en, ar = transport._note("downgrade", src="https://a/", dst="http://b/")
    assert any(re.sub(rx, repl, ar) == en for rx, repl in patterns if re.match(rx, ar))


def test_engine_shape_entry_none_and_empty_context():
    ctx = ScanContext(options=ScanOptions(), target="https://a.example/", coverage=Coverage())
    assert transport.run(ctx) == []
    assert transport.hsts_facts(ctx) == {}


# ----------------------------------------------------------------------------------------------- adversarial review

def test_sts_huge_digit_string_is_overflow_not_a_crash():
    # Python 3.10.7+ raises ValueError on int() of > 4300 digits; the header comes from the scanned site (§0.6)
    for v in ("max-age=" + "9" * 100_000, 'max-age="' + "1" * 5000 + '"', "max-age=" + "0" * 5000 + "1"):
        assert not parse_sts(v).valid
    assert "header.parse.max_age.parse_int_error" in parse_sts("max-age=" + "9" * 100_000).errors
    assert parse_sts("max-age=18446744073709551615").valid
    assert parse_sts("max-age=18446744073709551616").errors == ["header.parse.max_age.parse_int_error"]
    got = issues(ctx_for(R("https://a.example/", headers=[("Strict-Transport-Security", "max-age=" + "9" * 100_000)])))
    assert "WEB112" in got and "WEB-strict-transport-security" not in got


def test_web106_hostile_body_is_linear():
    import time
    for body in ("<a " * 200_000, "<a href" * 100_000, "<form " * 100_000):
        hop = R("https://a.example/", 302, [("Location", "/x")], body=body, kind="redirect")
        t = time.perf_counter()
        transport.big_redirect_signals(hop)
        assert time.perf_counter() - t < 5, body[:10]          # the regex version took minutes on 600 KB
    # links inside a comment or a template are not page content
    body = "<html><body><!-- " + '<a href="/a">a</a>' * 5 + " --><template>" + "<form></form><table></table>" + \
           "</template>" + "x" * 2000 + "</body></html>"
    hop = R("https://a.example/", 302, [("Location", "/x")], body=body, kind="redirect")
    assert transport.big_redirect_signals(hop)[0] == ["text"]


def test_web104_cookie_check_round_trip_is_not_a_loop():
    f = chain(redirect("https://a.example/", "https://a.example/cookie-check", 302),
              redirect("https://a.example/cookie-check", "https://a.example/", 302),
              R("https://a.example/", headers=[sts()]))
    assert "WEB104" not in issues(ctx_for(f))
    # the fetcher's verdict (URL + cookie-jar state repeated) still counts, and so does a chain stopped on a repeat
    f = chain(redirect("https://a.example/", "https://a.example/x", 302),
              redirect("https://a.example/x", "https://a.example/", 302, headers=[sts()]))
    f.flags = frozenset({"redirect-loop"})
    assert [sev(i) for i in issues(ctx_for(f))["WEB104"]] == ["low"]
    f = chain(redirect("https://a.example/", "https://a.example/x", 302),
              redirect("https://a.example/x", "https://a.example/", 302),
              redirect("https://a.example/", "https://a.example/x", 302))
    assert [i.group_value for i in issues(ctx_for(f))["WEB104"]] == ["loop"]


def test_web117_not_doubled_with_missing_hsts():
    # a host judged on its own final 2xx is not also reported as a redirecting hop (one cause, one finding)
    e = R("https://a.example/")
    login = chain(redirect("https://a.example/login", "https://sso.other.example/x", 302), R("https://sso.other.example/x"))
    ctx = ctx_for(e)
    ctx.pages.append(Page(login, None, 1))
    got = issues(ctx)
    assert "WEB-strict-transport-security" in got and "WEB117" not in got


def test_web117_ignores_subresource_hosts():
    sub = chain(redirect("https://static.a.example/app.js", "https://cdn.other.example/app.js", 302),
                R("https://cdn.other.example/app.js", headers=[("Content-Type", "text/javascript")], kind="script"))
    got = issues(ctx_for(R("https://a.example/", headers=[sts()]), subresources=[sub]))
    assert "WEB117" not in got


def test_hostile_location_values_are_capped():
    loc = "http://a.example/" + "A" * 200_000
    f = chain(redirect("https://a.example/", loc), R("http://a.example/x"))
    got = issues(ctx_for(f))
    (i,) = got["WEB103"]
    assert len(i.group_value) <= 200 and all(len(n[0]) < 3000 and len(n[1]) < 3000 for n in i.notes)
    for loc in ("http://[::1", "http://\x00evil/", "javascript:alert(1)", "\x1b[31mhttp://x/", "https://a b/"):
        f = chain(redirect("http://a.example/", loc), R("https://a.example/"))
        for rs in issues(ctx_for(f, "http://a.example/")).values():
            for i in rs:
                assert all("\x1b" not in n[0] and "\x00" not in n[1] for n in i.notes)


def test_web103_local_variable_named_location():
    body = '<script>var location = "http://a.example/x"; let  location2 = 1;</script>'
    assert "WEB103" not in issues(ctx_for(R("https://a.example/", body=body), sensitivity="paranoid"))
    body = '<script>window.location = "http://a.example/x";</script>'
    assert "WEB103" in issues(ctx_for(R("https://a.example/", body=body), sensitivity="paranoid"))


def test_web000_https_target_with_bad_certificate_is_variant_a():
    entry = R("https://a.example/", flags=frozenset({"cert-error"}))
    hp = R("http://a.example/", source="http_probe")
    (i,) = issues(ctx_for(entry, http_probe=hp))["WEB000"]
    assert "Variant A" in notes_en(i) and "certificate" in notes_en(i)


def test_web113_arabic_agreement_after_preposition():
    r = R("https://a.example/", headers=[sts("max-age=63072000"), sts("max-age=300")])
    (i,) = issues(ctx_for(r))["WEB113"]
    assert "في حقلين" in i.notes[0][1] and "sent in 2 fields" in i.notes[0][0]


@pytest.mark.parametrize("body", [bytes(range(256)) * 2000, b"\xff\xfe" + "\u0645".encode("utf-16-le") * 5000,
                                  b"<html>" + b"\x00" * 100_000])
def test_binary_and_broken_bodies_do_not_crash(body):
    hop = R("https://a.example/", 302, [("Location", "/x")], body=body + b"x" * 2000, kind="redirect")
    f = chain(hop, R("https://a.example/x", body=body, headers=[("Content-Encoding", "gzip")]))
    issues(ctx_for(f, pages=[Page(f, htmlparse.parse_response(f), 0)]))


# ----------------------------------------------------------------------------------------------- corpus groups (§5.2)

BENCH = Path(__file__).resolve().parents[2] / "bench" / "web"


@pytest.fixture(scope="module")
def corpus_run():
    """Run transport.py and cors.py on every WP16 corpus case that labels a WP6 rule (C-RED, C-HSTS, C-CORS and the
    WP6 labels of C-WAF, C-GRADE, C-HOSTILE), through the real fetcher, classify.py and cookies.py stage 1."""
    if not shutil.which("openssl"):
        pytest.skip("openssl CLI not available for the corpus PKI")
    sys.path.insert(0, str(BENCH))
    try:
        corpus = importlib.import_module("corpus")
    finally:
        sys.path.remove(str(BENCH))
    from vulnscan.webscan import classify, cookies, cors
    from vulnscan.webscan.http import CorpusHooks, Fetcher
    from vulnscan.webscan.types import CORS_PROBE_ORIGIN

    mine = {r for r, m in RULES.items() if m.module in ("transport", "cors")}
    cases = [c for c in corpus.CASES if set(c.labels) & mine]
    srv = corpus.CorpusServer(mode="host").start()
    results = {}
    try:
        if "tls" in srv.unavailable:
            pytest.skip(f"corpus TLS unavailable: {srv.unavailable['tls']}")
        cafile = str(srv.material.root)
        for c in cases:
            if srv.missing(c):
                continue
            url = srv.url(c)
            opts = ScanOptions(profile=c.profile, sensitivity=c.sensitivity, delay=0.2)
            opts._resolve = srv.resolver_map(c, cafile)
            f = Fetcher(opts, hooks=CorpusHooks.from_env({"KASHIF_TEST_RESOLVE": "1"}, opts), proxies={},
                        sleep=lambda s: None)
            entry = f.fetch(url, source="entry")
            ctx = ScanContext(options=opts, target=url, entry=entry, coverage=Coverage())
            if entry.status is not None:
                ctx.cors = f.fetch(entry.url, source="cors", origin=CORS_PROBE_ORIGIN, cookies=False)
                if entry.essence == "text/html":
                    ctx.pages.append(Page(entry, htmlparse.parse_response(entry), 0))
            classify.classify_context(ctx)
            ctx.cookies = cookies.parse_and_classify(ctx)
            ctx.hsts = transport.hsts_facts(ctx)
            classify.mark_sensitive(ctx)
            got = [i for i in transport.run(ctx) + cors.run(ctx) if opts.reports(i.confidence)]
            results[c.id] = (c, got)
    finally:
        srv.stop()
    return mine, results


def test_corpus_groups_pass(corpus_run):
    mine, results = corpus_run
    order = ["info", "low", "medium", "high", "critical"]
    failures = []
    for cid, (c, got) in results.items():
        fired: dict[str, list] = {}
        for i in got:
            fired.setdefault(i.rule, []).append(i)
        for rule, want in c.labels.items():
            if rule not in mine:
                continue
            if (rule in fired) != want:
                failures.append(f"{cid}: {rule} expected {want}")
                continue
            exp = (c.expect.get("severity") or {}).get(rule)
            if want and exp and {sev(i) for i in fired[rule]} != {exp}:
                failures.append(f"{cid}: {rule} severity {[sev(i) for i in fired[rule]]} != {exp}")
            mx = (c.expect.get("max_severity") or {}).get(rule)
            if want and mx and any(order.index(sev(i)) > order.index(mx) for i in fired[rule]):
                failures.append(f"{cid}: {rule} above {mx}")
    assert len(results) >= 45
    assert not failures, failures
