"""WP13 grades (spec §3.4): Kashif Web Grade, exact MDN Observatory v6, SSL Labs-compatible wrapper.

Observatory fixtures: ten response sets (below). Their expected numbers were recorded ONCE by running the official
scorer — ``@mdn/mdn-http-observatory`` 1.7.2 (commit 11b909f, ALGORITHM_VERSION 6), ``src/scanner/index.js``
``analyzeScan`` with its own analyzers, fed the fixture responses the way its retriever records them (Node header
folding, tough-cookie jar, CORS preflight with its default Origin) — through ``tools/webdata/observatory_fixtures.mjs``.
They are never hand-computed. Two layers are checked: Kashif's scorer on the official slugs (exact score, grade,
tests passed, per-test modifier and pass), and the whole chain (Kashif's family modules write the slugs from the same
responses, then the scorer runs).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from vulnscan.webscan import data, grade, group, htmlparse
from vulnscan.webscan.coverage import Coverage
from vulnscan.webscan.rules import CONTROLS, GRADE_FAMILIES, RULES
from vulnscan.webscan.types import (CORS_PROBE_ORIGIN, CookieFact, CspFacts, CspPolicy, Evidence, HeaderList,
                                    HstsVerdict, Issue, Page, Response, ScanContext, ScanOptions)

NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
SCORER = "@mdn/mdn-http-observatory 1.7.2 (commit 11b909f), src/scanner/index.js analyzeScan"
HTML = "text/html; charset=utf-8"
SRI = "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"


# ============================================================================================ Observatory fixtures

def _page(scripts=(), extra_head=""):
    return (f"<!doctype html><html><head><meta charset=\"utf-8\">{extra_head}<title>Kashif fixture</title></head>"
            f"<body><h1>Fixture</h1><p>Observatory fixture page.</p>{''.join(scripts)}</body></html>")


def _fx(id, host, *, https=None, http=None, verified=True, http_verified=True, cors=None, preload=None):
    return {"id": id, "host": host, "https_chain": https, "http_chain": http, "verified": verified,
            "http_verified": http_verified, "cors": cors or {"status": 200, "headers": []}, "preload": preload or {}}


def _ok(url, headers, body="", status=200):
    return {"url": url, "status": status, "headers": [["Content-Type", HTML]] + headers, "body": body}


def _redirect(url, to, status=301):
    return {"url": url, "status": status, "headers": [["Location", to], ["Content-Length", "0"]], "body": ""}


_GOOD = [["Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"],
         ["X-Content-Type-Options", "nosniff"], ["X-Frame-Options", "DENY"], ["Referrer-Policy", "no-referrer"],
         ["Cross-Origin-Resource-Policy", "same-origin"], ["Cross-Origin-Embedder-Policy", "require-corp"],
         ["Cross-Origin-Opener-Policy", "same-origin"]]
_CSP_NONE = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; "
             "base-uri 'none'; form-action 'self'")
_GOOD_PAGE = _page([f'<script src="/app.js" integrity="{SRI}" crossorigin="anonymous"></script>'])
_GOOD_SET = _GOOD + [["Content-Security-Policy", _CSP_NONE],
                     ["Set-Cookie", "__Host-sid=a1b2c3; Secure; HttpOnly; Path=/; SameSite=Lax"]]

FIXTURES = [
    _fx("obs-165", "obs165.kashif.dev", preload={"dev": {"include_subdomains": True}},
        http=[_redirect("http://obs165.kashif.dev/", "https://obs165.kashif.dev/"),
              _ok("https://obs165.kashif.dev/", _GOOD_SET, _GOOD_PAGE)],
        https=[_ok("https://obs165.kashif.dev/", _GOOD_SET, _GOOD_PAGE)]),
    _fx("obs-0", "obs0.kashif.test",
        http=[_ok("http://obs0.kashif.test/", [["Set-Cookie", "sessionid=42; Path=/"]],
                  _page(['<script src="http://cdn.kashif-third.test/lib.js"></script>']))],
        cors={"status": 200, "headers": [], "reflect": True, "credentials": True}),
    _fx("obs-100-flat", "flat.kashif.test",
        http=[_redirect("http://flat.kashif.test/", "https://flat.kashif.test/"), _ok("https://flat.kashif.test/", [])],
        https=[_ok("https://flat.kashif.test/", [
            ["Strict-Transport-Security", "max-age=15552000"], ["X-Content-Type-Options", "nosniff"],
            ["X-Frame-Options", "ALLOW-FROM https://flat.kashif.test/"],
            ["Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; report-uri /a; "
                                        "report-uri /b"]], _page())],
        cors={"status": 200, "headers": [["Access-Control-Allow-Origin", "*"]]}),
    _fx("quirk-hsts-quoted", "quoted.kashif.test",
        http=[_redirect("http://quoted.kashif.test/", "https://quoted.kashif.test/"),
              _ok("https://quoted.kashif.test/", [])],
        https=[_ok("https://quoted.kashif.test/", [
            ["Strict-Transport-Security", 'max-age="0"'], ["X-Frame-Options", "SAMEORIGIN"],
            ["X-Frame-Options", "SAMEORIGIN"], ["X-Content-Type-Options", "nosniff"], ["X-Content-Type-Options", "nosniff"],
            ["Referrer-Policy", "no-referrer, unsafe-url"],
            ["Content-Security-Policy", "script-src 'nonce-r4nd0mN0nce' 'strict-dynamic'; base-uri 'none'"]],
            _page(['<script nonce="r4nd0mN0nce" src="/a.js"></script>']))]),
    _fx("quirk-hsts-comma", "comma.kashif.test",
        http=[_redirect("http://comma.kashif.test/", "https://comma.kashif.test/"), _ok("https://comma.kashif.test/", [])],
        https=[_ok("https://comma.kashif.test/", [
            ["Strict-Transport-Security", "max-age=31536000"], ["Strict-Transport-Security", "max-age=31536000"],
            ["Content-Security-Policy", "default-src 'self'; frame-ancestors *"], ["X-Content-Type-Options", "nosniff"],
            ["Set-Cookie", "PHPSESSID=abc123; Secure; Path=/"],
            ["Cross-Origin-Opener-Policy", "same-origin"], ["Cross-Origin-Opener-Policy", "same-origin"],
            ["Cross-Origin-Embedder-Policy", 'require-corp; report-to="coep"'],
            ["Cross-Origin-Resource-Policy", "same-origin"], ["Cross-Origin-Resource-Policy", "same-origin"]], _page())]),
    _fx("extra-credit-gate", "gate.kashif.test",
        http=[_redirect("http://gate.kashif.test/", "https://gate.kashif.test/"), _ok("https://gate.kashif.test/", [])],
        https=[_ok("https://gate.kashif.test/", [
            ["Strict-Transport-Security", "max-age=31536000"], ["X-Content-Type-Options", "nosniff"],
            ["Content-Security-Policy", "default-src 'self'; default-src 'none'"], ["Referrer-Policy", "same-origin"],
            ["Cross-Origin-Resource-Policy", "same-site"], ["Cross-Origin-Opener-Policy", "same-origin-allow-popups"],
            ["X-Frame-Options", "DENY"]], _page())]),
    _fx("strict-dynamic-invalid", "sd.kashif.test",
        http=[_redirect("http://sd.kashif.test/", "http://sd.kashif.test/home"),
              _redirect("http://sd.kashif.test/home", "https://sd.kashif.test/home"),
              _ok("https://sd.kashif.test/home", [])],
        https=[_ok("https://sd.kashif.test/", [
            ["Strict-Transport-Security", "max-age=7776000"], ["X-Content-Type-Options", "nosniff"],
            ["X-Frame-Options", "SAMEORIGIN"], ["Content-Security-Policy", "script-src 'strict-dynamic'; object-src 'none'"],
            ["Set-Cookie", "csrftoken=t0k3n; Secure; HttpOnly; Path=/"]],
            _page(extra_head='<meta name="referrer" content="unsafe-url">'))]),
    _fx("invalid-cert", "badcert.kashif.test", verified=False, http_verified=False,
        http=[_redirect("http://badcert.kashif.test/", "https://badcert.kashif.test/"),
              _ok("https://badcert.kashif.test/", [])],
        https=[_ok("https://badcert.kashif.test/", [
            ["Strict-Transport-Security", "max-age=31536000"], ["X-Content-Type-Options", "nosniff"],
            ["Content-Security-Policy-Report-Only", "default-src 'self'"], ["Set-Cookie", "theme=dark; Path=/"]], _page())]),
    _fx("meta-csp-cors", "meta.kashif.test",
        http=[_redirect("http://meta.kashif.test/", "https://meta.kashif.test/"), _ok("https://meta.kashif.test/", [])],
        https=[_ok("https://meta.kashif.test/", [
            ["Strict-Transport-Security", "max-age=31536000"], ["X-Content-Type-Options", "nosniff"],
            ["X-Frame-Options", "DENY"], ["Set-Cookie", "sessionid=s3ss; Secure; HttpOnly; Path=/; SameSite=Strict"]],
            _page(['<script src="https://cdn.kashif-third.test/lib.js"></script>'],
                  extra_head="<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
                             "script-src https://cdn.kashif-third.test\">"))],
        cors={"status": 200, "headers": [], "reflect": True, "credentials": True}),
    _fx("off-host", "kashif.test",
        http=[_redirect("http://kashif.test/", "https://www.kashif.test/"), _ok("https://www.kashif.test/", [])],
        https=[_redirect("https://kashif.test/", "https://www.kashif.test/"),
               _ok("https://www.kashif.test/", [
                   ["Strict-Transport-Security", "max-age=31536000"], ["X-Content-Type-Options", "nosniff"],
                   ["X-Frame-Options", "SAMEORIGIN"], ["Referrer-Policy", "strict-origin-when-cross-origin"],
                   ["Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-eval' "
                                               "https://cdn.kashif-third.test; img-src 'self' http:"]],
                   _page([f'<script src="https://cdn.kashif-third.test/lib.js" integrity="{SRI}" '
                          'crossorigin="anonymous"></script>']))]),
]

_T = ("content-security-policy", "cookies", "cross-origin-embedder-policy", "cross-origin-opener-policy",
      "cross-origin-resource-sharing", "redirection", "referrer-policy", "strict-transport-security",
      "subresource-integrity", "x-content-type-options", "x-frame-options", "cross-origin-resource-policy")


def _o(*slugs):
    return dict(zip(_T, slugs))


# id → (score, grade, testsPassed, slugs) exactly as the official scorer returned them (SCORER above)
OFFICIAL = {
    "obs-165": (165, "A+", 12, _o(
        "csp-implemented-with-no-unsafe-default-src-none", "cookies-secure-with-httponly-sessions-and-samesite",
        "coep-implemented-with-require-corp", "coop-implemented-with-same-origin",
        "cross-origin-resource-sharing-not-implemented", "redirection-all-redirects-preloaded", "referrer-policy-private",
        "hsts-preloaded", "sri-implemented-and-all-scripts-loaded-securely", "x-content-type-options-nosniff",
        "x-frame-options-implemented-via-csp", "corp-implemented-with-same-origin")),
    "obs-0": (0, "F", 4, _o(
        "csp-not-implemented", "cookies-session-without-secure-flag", "coep-not-implemented", "coop-not-implemented",
        "cross-origin-resource-sharing-implemented-with-universal-access", "redirection-missing",
        "referrer-policy-not-implemented", "hsts-not-implemented-no-https",
        "sri-not-implemented-and-external-scripts-not-loaded-securely", "x-content-type-options-not-implemented",
        "x-frame-options-not-implemented", "corp-not-implemented")),
    "obs-100-flat": (100, "A+", 12, _o(
        "csp-implemented-but-duplicate-directives", "cookies-not-found", "coep-not-implemented", "coop-not-implemented",
        "cross-origin-resource-sharing-implemented-with-public-access", "redirection-to-https",
        "referrer-policy-not-implemented", "hsts-implemented-max-age-at-least-six-months",
        "sri-not-implemented-but-no-scripts-loaded", "x-content-type-options-nosniff", "x-frame-options-allow-from-origin",
        "corp-not-implemented")),
    "quirk-hsts-quoted": (50, "C", 8, _o(
        "csp-implemented-with-unsafe-inline", "cookies-not-found", "coep-not-implemented", "coop-not-implemented",
        "cross-origin-resource-sharing-not-implemented", "redirection-to-https", "referrer-policy-unsafe",
        "hsts-implemented-max-age-at-least-six-months", "sri-not-implemented-but-all-scripts-loaded-from-secure-origin",
        "x-content-type-options-header-invalid", "x-frame-options-header-invalid", "corp-not-implemented")),
    "quirk-hsts-comma": (40, "D+", 8, _o(
        "csp-implemented-with-no-unsafe", "cookies-session-without-httponly-flag", "coep-implemented-with-require-corp",
        "coop-header-invalid", "cross-origin-resource-sharing-not-implemented", "redirection-to-https",
        "referrer-policy-not-implemented", "hsts-header-invalid", "sri-not-implemented-but-no-scripts-loaded",
        "x-content-type-options-nosniff", "x-frame-options-implemented-via-csp", "corp-header-invalid")),
    "extra-credit-gate": (75, "B", 11, _o(
        "csp-header-invalid", "cookies-not-found", "coep-not-implemented", "coop-implemented-with-same-origin-allow-popups",
        "cross-origin-resource-sharing-not-implemented", "redirection-to-https", "referrer-policy-private",
        "hsts-implemented-max-age-at-least-six-months", "sri-not-implemented-but-no-scripts-loaded",
        "x-content-type-options-nosniff", "x-frame-options-sameorigin-or-deny", "corp-implemented-with-same-site")),
    "strict-dynamic-invalid": (30, "D", 7, _o(
        "csp-header-invalid", "cookies-anticsrf-without-samesite-flag", "coep-not-implemented", "coop-not-implemented",
        "cross-origin-resource-sharing-not-implemented", "redirection-not-to-https-on-initial-redirection",
        "referrer-policy-unsafe", "hsts-implemented-max-age-less-than-six-months",
        "sri-not-implemented-but-no-scripts-loaded", "x-content-type-options-nosniff", "x-frame-options-sameorigin-or-deny",
        "corp-not-implemented")),
    "invalid-cert": (0, "F", 7, _o(
        "csp-not-implemented-but-reporting-enabled", "cookies-without-secure-flag", "coep-not-implemented",
        "coop-not-implemented", "cross-origin-resource-sharing-not-implemented", "redirection-invalid-cert",
        "referrer-policy-not-implemented", "hsts-invalid-cert", "sri-not-implemented-but-no-scripts-loaded",
        "x-content-type-options-nosniff", "x-frame-options-not-implemented", "corp-not-implemented")),
    "meta-csp-cors": (45, "C-", 10, _o(
        "csp-implemented-with-no-unsafe-default-src-none", "cookies-secure-with-httponly-sessions-and-samesite",
        "coep-not-implemented", "coop-not-implemented", "cross-origin-resource-sharing-implemented-with-universal-access",
        "redirection-to-https", "referrer-policy-not-implemented", "hsts-implemented-max-age-at-least-six-months",
        "sri-not-implemented-but-external-scripts-loaded-securely", "x-content-type-options-nosniff",
        "x-frame-options-sameorigin-or-deny", "corp-not-implemented")),
    "off-host": (85, "A-", 10, _o(
        "csp-implemented-with-unsafe-eval", "cookies-not-found", "coep-not-implemented", "coop-not-implemented",
        "cross-origin-resource-sharing-not-implemented", "redirection-off-host-from-http", "referrer-policy-private",
        "hsts-implemented-max-age-at-least-six-months", "sri-implemented-and-external-scripts-loaded-securely",
        "x-content-type-options-nosniff", "x-frame-options-sameorigin-or-deny", "corp-not-implemented")),
}

# fixtures where a family module does not yet reproduce Observatory (reported to the integrator)
# (phase D closed "quirk-hsts-comma": transport now joins repeated Strict-Transport-Security fields as Node does)
E2E_KNOWN_GAPS: dict[str, str] = {}


def test_fixture_set_is_complete():
    assert [f["id"] for f in FIXTURES] == list(OFFICIAL)
    assert len(OFFICIAL) == 10
    scores = {v[0] for v in OFFICIAL.values()}
    assert {165, 100, 0} <= scores              # the C-GRADE anchors of §5.2


@pytest.mark.parametrize("fid", list(OFFICIAL))
def test_observatory_scorer_matches_official(fid):
    score, letter, passed, slugs = OFFICIAL[fid]
    res = grade.observatory_score(slugs)
    assert (res["score"], res["grade"], res["tests_passed"]) == (score, letter, passed)
    assert not res["partial"]
    assert all(t["known"] for t in res["tests"].values())


def _chain(hops, verified=True, source="entry"):
    from vulnscan.webscan import classify
    if not hops:
        return None
    rs = []
    for h in hops:
        flags = frozenset() if verified or not h["url"].startswith("https") else frozenset({"cert-error"})
        rs.append(Response(url=h["url"], status=h["status"], headers=HeaderList.of(*[tuple(x) for x in h["headers"]]),
                           body=h["body"].encode("utf-8"), source=source, flags=flags))
    final = rs[-1]
    final.chain = rs[:-1]
    for r in rs:
        classify.classify(r, htmlparse.parse_response(r) if r.status == 200 else None)
    return final


def _fixture_ctx(f) -> ScanContext:
    from vulnscan.webscan import classify
    https = _chain(f["https_chain"], f["verified"])
    http = _chain(f["http_chain"], f["http_verified"], "http_probe")
    entry = https if https is not None else http
    target = f"https://{f['host']}/" if https is not None else f"http://{f['host']}/"
    hl = [tuple(x) for x in f["cors"]["headers"]]
    if f["cors"].get("reflect"):
        hl.append(("Access-Control-Allow-Origin", CORS_PROBE_ORIGIN))
    if f["cors"].get("credentials"):
        hl.append(("Access-Control-Allow-Credentials", "true"))
    cors = Response(url=entry.url, status=200, headers=HeaderList.of(("Content-Type", "text/html"), *hl),
                    request_headers=HeaderList.of(("Origin", CORS_PROBE_ORIGIN)), source="cors", body=b"<html></html>")
    classify.classify(cors)
    pages = [Page(entry, htmlparse.parse_response(entry), 0)] if entry.kind == "document" else []
    return ScanContext(options=ScanOptions(), target=target, entry=entry,
                       http_probe=http if https is not None else None, cors=cors, pages=pages, now=NOW)


@pytest.mark.parametrize("fid", list(OFFICIAL))
def test_observatory_end_to_end_matches_official(fid):
    """Kashif's family modules write the slugs from the fixture responses; the scorer then matches the official run."""
    from vulnscan.webscan import content, cookies, cors, csp, headers, transport
    if fid in E2E_KNOWN_GAPS:
        pytest.xfail(E2E_KNOWN_GAPS[fid])
    f = next(x for x in FIXTURES if x["id"] == fid)
    ctx = _fixture_ctx(f)
    ctx.csp = csp.parse_all(ctx)
    ctx.hsts = transport.hsts_facts(ctx)
    ctx.cookies = cookies.parse_and_classify(ctx)
    for mod in (transport, csp, headers, cookies, content, cors):
        mod.run(ctx)
    score, letter, passed, slugs = OFFICIAL[fid]
    assert {t: ctx.observatory.get(t) for t in slugs} == slugs
    res = grade.observatory(ctx)
    assert (res["score"], res["grade"], res["tests_passed"]) == (score, letter, passed)


# ============================================================================================ Observatory scorer

def test_observatory_data_file_valid_and_complete():
    table = data.load_json("observatory-v6.json")
    assert data.validate_data("observatory-v6.json", table) == []
    assert table["algorithm_version"] == 6 and table["max_score"] == 165 and table["extra_credit_threshold"] == 90
    assert set(table["tests"]) == set(grade.OBS_TESTS)
    assert sum(len(v) for v in table["tests"].values()) == 77          # every Expectation of SCORE_TABLE
    assert table["grade_chart"]["100"] == "A+" and table["grade_chart"]["0"] == "F" and len(table["grade_chart"]) == 21
    assert table["meta"]["upstream_version"] == "1.7.2"


def test_observatory_refresh_script_is_deterministic(tmp_path):
    """tools/webdata/observatory.py rebuilds the bundled file byte for byte from the parsed facts."""
    import importlib.util
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location("obs_refresh", root / "tools" / "webdata" / "observatory.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    bundled = (root / "vulnscan" / "data" / "web" / "observatory-v6.json").read_text(encoding="utf-8")
    table = json.loads(bundled)
    facts = {"algorithm": 6, "threshold": 90, "chart": {int(k): v for k, v in table["grade_chart"].items()},
             "tests": table["tests"]}
    obj = mod.build(facts, table["meta"]["date"], notes=table["meta"].get("notes", ""))
    path = mod.write(obj, tmp_path)
    assert path.read_text(encoding="utf-8") == bundled


def test_observatory_parser_reads_upstream_shapes():
    import importlib.util
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location("obs_refresh2", root / "tools" / "webdata" / "observatory.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    files = {
        "src/types.js": 'export const Expectation = {\n  A: "csp-a",\n  B:\n    "csp-b",\n};',
        "src/grader/charts.js": "export const GRADE_CHART = new Map([\n" + "".join(
            f'  [{k}, "{v}"],\n' for k, v in [(100, "A+"), (95, "A"), (90, "A"), (85, "A-"), (80, "B+"), (75, "B"),
                                               (70, "B"), (65, "B-"), (60, "C+"), (55, "C"), (50, "C"), (45, "C-"),
                                               (40, "D+"), (35, "D"), (30, "D"), (25, "D-"), (20, "F"), (15, "F"),
                                               (10, "F"), (5, "F"), (0, "F")]) + "]);\n"
        "export const MINIMUM_SCORE_FOR_EXTRA_CREDIT = 90;\nexport const SCORE_TABLE = new Map([\n"
        "  [Expectation.A, { description: `x`, modifier: 5, recommendation: `` }],\n"
        "  [Expectation.B, { description: `y`, modifier: -20, recommendation: `` }],\n]);",
        "src/constants.js": "export const ALGORITHM_VERSION = 6;",
    }
    for item in mod.TEST_FILES:
        test, stem = item.split(":")
        files[f"src/analyzer/tests/{stem}.js"] = (f'static name = "{test}";\n  static possibleResults = [\n'
                                                  "    Expectation.A,\n    Expectation.B,\n  ];")
    facts = mod.parse(files)
    assert facts["algorithm"] == 6 and facts["threshold"] == 90 and facts["chart"][100] == "A+"
    assert facts["tests"]["cookies"] == {"csp-a": 5, "csp-b": -20}


def test_observatory_extra_credit_gate_and_floor():
    base = dict(OFFICIAL["obs-100-flat"][3])
    assert grade.observatory_score({**base, "referrer-policy": "referrer-policy-private"})["score"] == 105
    # uncurved 85 < 90: the +10 CORP bonus is dropped
    s = {**base, "content-security-policy": "csp-implemented-with-unsafe-eval", "redirection": "redirection-off-host-from-http",
         "cross-origin-resource-policy": "corp-implemented-with-same-origin"}
    res = grade.observatory_score(s)
    assert (res["score"], res["grade"], res["extra_credit"]) == (85, "A-", False)
    assert grade.observatory_score({**base, "cookies": "cookies-session-without-secure-flag",
                                    "cross-origin-resource-sharing":
                                        "cross-origin-resource-sharing-implemented-with-universal-access",
                                    "subresource-integrity":
                                        "sri-not-implemented-and-external-scripts-not-loaded-securely"})["score"] == 0


def test_observatory_status_and_partial():
    slugs = OFFICIAL["obs-100-flat"][3]
    assert grade.observatory_score(slugs, status=404)["score"] is None
    assert grade.observatory_score(slugs, status=None)["score"] is None
    for ok in (200, 301, 401, 403):
        assert grade.observatory_score(slugs, status=ok)["score"] == 100
    part = grade.observatory_score({k: v for k, v in slugs.items() if k != "cross-origin-resource-sharing"})
    assert part["partial"] and part["missing_tests"] == ["cross-origin-resource-sharing"] and part["score"] == 100
    assert part["notes"][0]["ar"] and part["notes"][0]["en"]
    none = grade.observatory_score({})
    assert none["score"] is None and none["notes"][0]["en"].startswith("not scored")
    unknown = grade.observatory_score({**slugs, "cookies": "cookies-from-the-future"})
    assert unknown["tests"]["cookies"]["known"] is False and unknown["score"] == 100


def _g(rule, url="https://site.test/", **kw):
    return group.group_issues([mk(rule, url, **kw)])[0]


def test_observatory_quirks_named():
    slugs = dict(OFFICIAL["quirk-hsts-quoted"][3])
    q = {x["id"] for x in grade.observatory_quirks(slugs, [_g("WEB110")])}
    assert "q_hsts_quoted" in q and "q_csp_object" in q and "q_xfo_dup" in q and "obs_cors" in q
    q = {x["id"] for x in grade.observatory_quirks(OFFICIAL["quirk-hsts-comma"][3], [_g("WEB113"), _g("WEB206")])}
    assert {"q_hsts_comma", "q_xfo_fa"} <= q
    q = {x["id"] for x in grade.observatory_quirks(OFFICIAL["extra-credit-gate"][3], [_g("WEB202")])}
    assert "q_csp_dup" in q
    q = {x["id"] for x in grade.observatory_quirks(OFFICIAL["obs-165"][3], [])}
    assert q == {"obs_cors"}


# ============================================================================================ Kashif grade helpers

def mk(rule, url="https://site.test/", *, severity=None, confidence=None, value="", roles=("app",), kind="document",
       host="", params=None, ips=()):
    ev = Evidence(kind=kind, role=list(roles), match={"where": "header", "name": rule, "value": value})
    return Issue(rule=rule, url=url, confidence=confidence or RULES[rule].confidence, evidence=ev,
                 params=dict(params or {}), severity=severity, group_value=value, host=host, ips=tuple(ips))


def ctx_for(entry_url="https://site.test/", *, kind="document", roles=frozenset({"app"}), sensitivity="default",
            hsts=None, csp=None, tls=None, cookies=(), headers=(), body=None):
    entry = Response(url=entry_url, status=200, headers=HeaderList.of(("Content-Type", HTML), *headers), kind=kind,
                     roles=frozenset(roles), body=(body or "<html></html>").encode("utf-8"))
    doc = htmlparse.parse_response(entry) if body is not None else None
    ctx = ScanContext(options=ScanOptions(sensitivity=sensitivity), target=entry_url, entry=entry,
                      pages=[Page(entry, doc, 0)] if kind == "document" else [], now=NOW)
    if hsts is not None:
        ctx.hsts = {entry.host: hsts}
    if csp is not None:
        ctx.csp = {entry: csp}
    if tls is not None:
        ctx.tls = tls
    ctx.cookies = [CookieFact(name=n, value="v", attrs=a, raw=f"{n}=v", response=entry, host=entry.host,
                              secure_context=True, cls=c) for n, a, c in cookies]
    return ctx


def kg(issues, ctx=None, coverage=None, **kw):
    ctx = ctx or ctx_for()
    return grade.kashif_grade(ctx, group.group_issues(issues, ctx), coverage, **kw)


def rank(letter):
    return grade.LETTERS.index(letter.rstrip("*"))


# ============================================================================================ Kashif grade

def test_clean_site_scores_100_and_grade_a_without_aplus_evidence():
    res = kg([])
    assert res["score"] == 100 and res["base"] == 100
    assert res["letter"] == "A"                                     # A+ needs HSTS, CSP and TLS evidence
    assert {m["id"] for m in res["aplus_missing"]} == {"ap_hsts", "ap_csp", "ap_tls"}
    assert res["algorithm"] == grade.ALGORITHM and res["label"]["ar"]


def _aplus_ctx(**over):
    strict = CspPolicy(raw="x", origin="header", directives={
        "script-src": ["'nonce-AbCdEf0123456789'", "'strict-dynamic'"], "object-src": ["'none'"], "base-uri": ["'none'"]})
    tls_ip = {"status": "ok", "versions": {"TLSv1.3": {"state": "yes"}, "TLSv1.2": {"state": "yes"},
                                           "TLSv1.1": {"state": "no"}, "TLSv1.0": {"state": "no"},
                                           "SSLv3": {"state": "no"}},
              "categories": {"aead": {"state": "yes"}, "cbc": {"state": "no"}, "krsa": {"state": "no"},
                             "3des": {"state": "no"}}}
    kw = dict(hsts=HstsVerdict(host="site.test", present=True, valid=True, max_age=63072000, include_subdomains=True,
                               preload=True, effective=True),
              csp=CspFacts(enforced=[strict]), tls={"site.test": {"kind": "kashif-tls-host", "host": "site.test",
                                                                  "ips": {"192.0.2.1": tls_ip}}},
              cookies=[("__Host-sid", {"secure": "", "httponly": "", "path": "/", "samesite": "Lax"}, "session")],
              headers=[("Cross-Origin-Opener-Policy", "same-origin"), ("Cross-Origin-Resource-Policy", "same-origin")])
    kw.update(over)
    return ctx_for(**kw)


def test_aplus_with_full_bonus():
    res = kg([], _aplus_ctx())
    assert res["grade"] == "A+" and res["score"] == 115 and res["bonus"]["total"] == 15
    assert {b["id"] for b in res["bonus"]["items"]} == {"bonus_csp", "bonus_hsts", "bonus_cookies", "bonus_iso"}


@pytest.mark.parametrize("over,missing", [
    ({"tls": {}}, "ap_tls"),
    ({"csp": CspFacts()}, "ap_csp"),
    ({"hsts": HstsVerdict(host="site.test", present=True, valid=True, max_age=15552000, effective=True)}, "ap_hsts"),
])
def test_aplus_requirements(over, missing):
    res = kg([], _aplus_ctx(**over))
    assert res["letter"] == "A" and missing in {m["id"] for m in res["aplus_missing"]}
    assert res["notes"][-1]["ar"].startswith("تتطلب")


def test_aplus_blocked_by_weak_tls_suites_and_web990():
    ctx = _aplus_ctx()
    ctx.tls["site.test"]["ips"]["192.0.2.1"]["categories"]["cbc"] = {"state": "yes"}
    assert grade.tls_modern_only(ctx) is False
    assert kg([], ctx)["letter"] == "A"
    only13 = _aplus_ctx()
    only13.tls["site.test"]["ips"]["192.0.2.1"]["versions"]["TLSv1.2"] = {"state": "no"}
    assert grade.tls_modern_only(only13) is True                 # TLS 1.3 only is stricter than 1.2 + 1.3
    old = _aplus_ctx()
    old.tls["site.test"]["ips"]["192.0.2.1"]["versions"]["TLSv1.0"] = {"state": "yes"}
    assert grade.tls_modern_only(old) is False and grade.tls_modern_only(ctx_for()) is None
    res = kg([mk("WEB990", kind="probe")], _aplus_ctx())
    assert "ap_waf" in {m["id"] for m in res["aplus_missing"]}


def test_bonus_needs_base_90_and_no_medium():
    res = kg([mk("WEB-x-content-type-options")], _aplus_ctx())        # low (policies): base 99, bonus kept
    assert res["bonus"]["total"] == 15
    res = kg([mk("WEB062", severity="medium", value="/.env")], _aplus_ctx())   # medium anywhere: no bonus
    assert res["bonus"]["total"] == 0 and res["score"] == res["base"]
    res = kg([mk("WEB-x-content-type-options")], _aplus_ctx(cookies=[("sid", {"secure": ""}, "session")]))
    assert "bonus_cookies" not in {b["id"] for b in res["bonus"]["items"]}


def test_family_weights_and_each_rule_counted_once():
    one = kg([mk("WEB062", value="/.env", url="https://site.test/.env")])
    many = kg([mk("WEB062", value="/.env", url="https://site.test/.env"),
               mk("WEB062", value="/.git/HEAD", url="https://site.test/.git/HEAD"),
               mk("WEB062", value="/.env", url="https://site.test/a/.env")])
    assert one["families"]["exposure"]["score"] == 60 and many["families"]["exposure"]["score"] == 60
    assert one["base"] == pytest.approx((20 + 20 + 20 + 15 + 15) * 100 / 100 + 10 * 60 / 100)
    assert one["letter"] == "C+"                                     # a high finding caps at C+
    assert sum(w for _en, _ar, w in GRADE_FAMILIES.values()) == 100


def test_penalties_and_confidence_weights():
    assert grade.PENALTY == {"critical": 100, "high": 40, "medium": 20, "low": 5, "info": 0}
    tent = mk("WEB511", url="https://site.test/?token=x")             # low, tentative
    assert kg([tent])["families"]["content"]["penalty"] == 0
    assert kg([tent], ctx_for(sensitivity="paranoid"))["families"]["content"]["penalty"] == 2.5
    high_tent = mk("WEB701", confidence="tentative")
    res = kg([high_tent], ctx_for(sensitivity="paranoid"))
    assert res["families"]["tls"]["penalty"] == 20 and not res["caps"]   # tentative findings never cap


def test_meta_rules_never_count():
    res = kg([mk("WEB991", kind="")])
    assert res["score"] == 100 and not res["caps"]


CAPS = [
    ("WEB609", {"severity": "critical"}, "F"),
    ("WEB062", {"severity": "critical", "value": "/id_rsa"}, "F"),
    ("WEB070", {}, "F"), ("WEB072", {}, "F"), ("WEB700", {}, "F"), ("WEB720", {}, "F"),
    ("WEB701", {"confidence": "certain"}, "F"),
    ("WEB704", {"severity": "critical", "value": "SSLv2"}, "F"),
    ("WEB704", {"severity": "high", "value": "SSLv3"}, "D"),
    ("WEB052", {"roles": ("login",), "url": "http://site.test/login"}, "F"),
    ("WEB509", {"roles": ("login",)}, "F"),
    ("WEB320", {}, "D"),
    ("WEB062", {"value": "/.git/HEAD"}, "C+"),
    ("WEB000", {"url": "http://site.test/"}, "B+"),
    ("WEB030", {}, "B+"),
    ("WEB-content-security-policy", {}, "B+"),
    ("WEB020", {"severity": "medium", "value": "sid"}, "B+"),
    ("WEB705", {"severity": "low"}, "A-"),
    ("WEB111", {"severity": "low"}, "A-"),
    ("WEB022", {"severity": "low", "value": "sid"}, "A"),
    ("WEB114", {}, "A"),
]


@pytest.mark.parametrize("rule,kw,cap", CAPS, ids=[f"{r}-{c}" for r, _k, c in CAPS])
def test_caps_table(rule, kw, cap):
    res = kg([mk(rule, **kw)])
    assert min((c["cap"] for c in res["caps"]), key=rank, default=None) is not None
    assert max((c["cap"] for c in res["caps"]), key=rank) == cap
    assert rank(res["letter"]) >= rank(cap)
    worst = max(res["caps"], key=lambda c: rank(c["cap"]))
    assert worst["en"] and worst["ar"] and any("\u0600" <= ch <= "\u06ff" for ch in worst["ar"])


def test_web000_on_site_with_login_page_caps_d():
    ctx = ctx_for("http://site.test/", roles=frozenset({"login"}))
    res = kg([mk("WEB000", url="http://site.test/", roles=("login",))], ctx)
    assert res["letter"] == "D" and res["caps"][0]["rule"] == "WEB000"
    assert kg([mk("WEB000", url="http://site.test/", severity="info")])["caps"] == []   # preloaded .dev host: info


def test_lowest_cap_wins_and_caps_listed():
    res = kg([mk("WEB030"), mk("WEB070"), mk("WEB114")])
    assert res["letter"] == "F"
    assert [c["cap"] for c in res["caps"]][0] == "F" and {"B+", "A"} <= {c["cap"] for c in res["caps"]}


def test_inconclusive_entry_gives_question_mark():
    ctx = ctx_for(kind="waf_challenge")
    res = kg([mk("WEB990", kind="waf_challenge"), mk("WEB-content-security-policy")], ctx)
    assert res["grade"] == "?" and res["letter"] == "?" and res["score"] is None and res["inconclusive"]
    assert res["notes"][0]["en"].startswith("no grade")


def _coverage(untested_family=None, na_family=None):
    cov = Coverage()
    for fam in grade.FAMILY_ORDER:
        checks = sorted({m.check_id for m in RULES.values() if m.grade_family == fam})
        if fam == untested_family:
            cov.record_many(checks, "not_tested", "proxied")
        elif fam == na_family:
            cov.record_many(checks, "not_applicable")
        else:
            cov.record(checks[0], "pass")
    return cov


def test_provisional_star_when_a_family_is_untested():
    res = kg([], coverage=_coverage(untested_family="tls"))
    assert res["grade"].endswith("*") and res["provisional"]
    assert res["families"]["tls"]["state"] == "untested"
    assert "ap_provisional" in {m["id"] for m in res["aplus_missing"]} or res["letter"] != "A+"
    assert "TLS" in res["notes"][0]["en"] and res["notes"][0]["ar"]
    # TLS (weight 20) is left out of the weight sum
    res2 = kg([mk("WEB062", value="/.env")], coverage=_coverage(untested_family="tls"))
    assert res2["base"] == pytest.approx((20 * 100 + 20 * 100 + 15 * 100 + 15 * 100 + 10 * 60) / 80)


def test_not_applicable_family_is_excluded_without_star():
    res = kg([], coverage=_coverage(na_family="cookies"))
    assert not res["provisional"] and not res["grade"].endswith("*")
    assert res["families"]["cookies"]["state"] == "not_applicable"


def test_family_with_findings_counts_as_tested_even_without_coverage_records():
    res = kg([mk("WEB020", severity="medium", value="sid")], coverage=_coverage(untested_family="cookies"))
    assert res["families"]["cookies"]["state"] == "tested" and not res["provisional"]


def test_nothing_tested_gives_no_letter():
    cov = Coverage()
    res = kg([], coverage=cov)
    assert res["grade"] == "?" and res["notes"][0]["en"].startswith("no grade")


# ---------------------------------------------------------------------------------------- per-control sum cap

def _weak_issues(control, roles):
    missing, weak = CONTROLS[control]
    out = []
    for r in weak:
        m = RULES[r]
        if m.paranoid_only:
            continue
        sev = m.allowed_severities[0]                          # the most severe allowed
        conf = "certain" if "certain" in m.allowed_confidences else m.allowed_confidences[0]
        value = f"weak-{r}"
        if r == "WEB207":
            value = "frame-ancestors" if control == "framing" else "report-uri,sandbox"
        out.append(mk(r, severity=sev, confidence=conf, value=value, roles=roles))
    return out


def _missing_issue(control, roles, ctx=None):
    missing, _weak = CONTROLS[control]
    probe = mk(missing, roles=roles)
    sev = (grade.would_be_severity(control, "site.test", [probe], ctx) if ctx is not None
           else grade.missing_severity(control, [frozenset(roles)]))
    if not RULES[missing].allows(sev):
        sev = RULES[missing].severity
    return mk(missing, severity=sev, roles=roles)


# a document per role, as classify.py would see it (the missing rules' severity depends on the document itself)
_ROLE_BODIES = {
    "app": "<html><body><div id=root></div><script src=/app.js></script></body></html>",
    "static": "<html><body><h1>About</h1><p>Plain text.</p></body></html>",
    "login": "<html><body><form method=post action=/login><input name=u><input type=password name=p></form></body></html>",
}


@pytest.mark.parametrize("control", list(CONTROLS))
@pytest.mark.parametrize("roles", [("app",), ("static",), ("login",)])
def test_sum_cap_weak_never_grades_below_missing(control, roles):
    """§3.4 step 2: for every control, the worst combination of weakness findings grades ≥ the missing header."""
    ctx = ctx_for(roles=frozenset(roles), body=_ROLE_BODIES[roles[0]])
    weak = kg(_weak_issues(control, roles), ctx)
    missing = kg([_missing_issue(control, roles, ctx)], ctx)
    assert weak["score"] >= missing["score"], (weak["families"], missing["families"])
    assert rank(weak["letter"]) <= rank(missing["letter"]), (weak["caps"], missing["caps"])
    # deleting the weak header (weak findings → missing finding) never raises the grade, also when both appear
    both = kg(_weak_issues(control, roles) + [_missing_issue(control, roles, ctx)], ctx)
    assert both["score"] == missing["score"] and rank(both["letter"]) == rank(missing["letter"])


# --- end to end: the real family modules emit the findings, so the ceiling must mirror *their* severity modulation
# (review of WP13: a page with scripts but no form gets a LOW missing-XFO from headers.py, yet WEB300 is medium; a
# preloaded host (.dev) gets an INFO missing-HSTS from transport.py, yet WEB110/111/112 are medium)

_E2E_BODIES = {
    "static": "<!doctype html><html><head><title>x</title></head><body><h1>About</h1><p>Plain words.</p></body></html>",
    "script": "<!doctype html><html><head><title>x</title></head><body><h1>Blog</h1><p>Plain words.</p>"
              "<script src='/a.js'></script></body></html>",
    "form": "<!doctype html><html><head><title>x</title></head><body><h1>Search</h1><form action='/s'><input name=q>"
            "</form></body></html>",
    "login": "<!doctype html><html><head><title>Sign in</title></head><body><form method=post action='/login'>"
             "<input name=u><input type=password name=p></form></body></html>",
    "listing": "<html><head><title>Index of /files</title></head><body><h1>Index of /files</h1><pre>"
               "<a href='a.txt'>a.txt</a></pre></body></html>",
}
_E2E_GOOD = [("Strict-Transport-Security", "max-age=63072000; includeSubDomains"), ("X-Content-Type-Options", "nosniff"),
             ("X-Frame-Options", "DENY"), ("Referrer-Policy", "no-referrer"), ("Permissions-Policy", "camera=()"),
             ("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'"),
             ("Cross-Origin-Opener-Policy", "same-origin")]
_E2E_WEAK = {
    "Strict-Transport-Security": ("max-age=0", "max-age=86400", 'max-age="0"', "max-age=abc", "max-age=20000000",
                                  "max-age=31536000, max-age=31536000"),
    "X-Frame-Options": ("ALLOW-FROM https://a.test/", "ALLOWALL", "DENY, SAMEORIGIN", "junk"),
    "Content-Security-Policy": ("default-src * 'unsafe-inline' 'unsafe-eval'", "frame-ancestors 'none'",
                                "script-src 'strict-dynamic'", "upgrade-insecure-requests"),
    "X-Content-Type-Options": ("nosnif",),
    "Referrer-Policy": ("unsafe-url", "no-referrer-when-downgrade"),
    "Permissions-Policy": ("camera 'none'", "camera=*", "camra=()"),
    "Cross-Origin-Opener-Policy": ("bogus", "same-origin, same-origin"),
}


def _e2e_grade(url, hdrs, body):
    from vulnscan.webscan import classify, content, cookies, csp, headers, transport
    r = Response(url=url, status=200, headers=HeaderList.of(("Content-Type", HTML), *hdrs), body=body.encode("utf-8"),
                 source="entry")
    doc = htmlparse.parse_response(r)
    classify.classify(r, doc)
    ctx = ScanContext(options=ScanOptions(), target=url, entry=r, pages=[Page(r, doc, 0)], now=NOW)
    ctx.csp = csp.parse_all(ctx)
    ctx.hsts = transport.hsts_facts(ctx)
    ctx.cookies = cookies.parse_and_classify(ctx)
    issues = []
    for mod in (transport, csp, headers, cookies, content):
        issues += mod.run(ctx)
    return grade.kashif_grade(ctx, group.process(issues, ctx).all_groups())


# HSTS depends on the host (.dev is a preloaded TLD), the other controls on the document
_E2E_CASES = ([("Strict-Transport-Security", b, u) for u in ("https://site.test/", "https://site.dev/")
               for b in ("static", "login")]
              + [(h, b, "https://site.test/") for h in _E2E_WEAK if h != "Strict-Transport-Security" for b in _E2E_BODIES])


@pytest.mark.parametrize("header,body,url", _E2E_CASES)
def test_sum_cap_end_to_end_weak_header_never_grades_below_no_header(header, body, url):
    rest = [h for h in _E2E_GOOD if h[0] != header]
    missing = _e2e_grade(url, rest, _E2E_BODIES[body])
    for value in _E2E_WEAK[header]:
        weak = _e2e_grade(url, rest + [(header, value)], _E2E_BODIES[body])
        assert weak["score"] >= missing["score"], (value, weak["families"], missing["families"])
        assert rank(weak["letter"]) <= rank(missing["letter"]), (value, weak["caps"], missing["caps"])


def test_frame_ancestors_star_overriding_xfo_costs_points_but_never_the_letter():
    """``frame-ancestors *`` makes browsers ignore X-Frame-Options: DENY, so that CSP really is worse than none for
    framing (WEB206, framing control) — the per-control cap allows the points; the letter still never improves."""
    rest = [h for h in _E2E_GOOD if h[0] != "Content-Security-Policy"]
    missing = _e2e_grade("https://site.test/", rest, _E2E_BODIES["login"])
    weak = _e2e_grade("https://site.test/", rest + [("Content-Security-Policy", "default-src 'self'; frame-ancestors *")],
                      _E2E_BODIES["login"])
    assert rank(weak["letter"]) <= rank(missing["letter"])


def test_would_be_severity_mirrors_the_modules():
    hsts_pre = HstsVerdict(host="site.dev", preloaded=True, effective=True)
    ctx = ctx_for("https://site.dev/", hsts=hsts_pre, body=_E2E_BODIES["script"])
    assert grade.would_be_severity("hsts", "site.dev", [mk("WEB111", "https://site.dev/")], ctx) == "info"
    assert grade.would_be_severity("hsts", "other.test", [mk("WEB111", "https://other.test/")], ctx) == "medium"
    # framing: scripts but no form → low (headers.py); a live form or an interactive role → medium
    assert grade.would_be_severity("framing", "site.dev", [mk("WEB300", "https://site.dev/")], ctx) == "low"
    ctx_form = ctx_for(body=_E2E_BODIES["form"])
    assert grade.would_be_severity("framing", "site.test", [mk("WEB300")], ctx_form) == "medium"
    assert grade.would_be_severity("framing", "site.test", [mk("WEB300", roles=("admin",))], ctx) == "medium"
    # csp: csp.py's static document (no script/form/iframe/object/embed/on*) → low, whatever the page role
    ctx_list = ctx_for(roles=frozenset({"listing"}), body=_E2E_BODIES["listing"])
    assert grade.would_be_severity("csp", "site.test", [mk("WEB040", roles=("listing",))], ctx_list) == "low"
    assert grade.would_be_severity("csp", "site.dev", [mk("WEB040", "https://site.dev/")], ctx) == "medium"
    # a URL that is not a fetched page falls back to the role rule
    assert grade.would_be_severity("csp", "site.test", [mk("WEB040", "https://site.test/x", roles=("static",))],
                                   ctx_list) == "low"
    assert grade.would_be_severity("csp", "site.test", [mk("WEB040", roles=("static",))]) == "low"


def test_frame_ancestors_only_csp_grades_at_least_no_csp():
    """C-GRADE monotonicity fixture: a clickjacking-only CSP is never graded below the same site without CSP."""
    fa_only = [mk("WEB042", params={"variant": "non_script"}, value="non_script"), mk("WEB205", value="missing"),
               mk("WEB215", severity="low", value="none"), mk("WEB204", value="missing")]
    no_csp = [mk("WEB-content-security-policy"), mk("WEB-x-frame-options")]
    a, b = kg(fa_only), kg(no_csp)
    assert a["score"] >= b["score"] and rank(a["letter"]) <= rank(b["letter"])


def test_control_assignment_and_missing_severity():
    assert grade.control_of(_g("WEB207", value="frame-ancestors")) == "framing"
    assert grade.control_of(_g("WEB207", value="report-uri")) == "csp"
    assert grade.control_of(_g("WEB062", value="/.env")) is None
    assert grade.missing_severity("csp", [frozenset({"static"})]) == "low"
    assert grade.missing_severity("csp", [frozenset({"static"}), frozenset({"app"})]) == "medium"
    assert grade.missing_severity("coop", [frozenset({"login"})]) == "low"
    assert grade.missing_severity("referrer", []) == "info"
    assert grade.missing_severity("hsts", []) == "medium"


def test_letter_chart():
    expect = {100: "A+", 99.99: "A", 90: "A", 85: "A-", 80: "B+", 79: "B", 70: "B", 65: "B-", 60: "C+", 50: "C",
              45: "C-", 40: "D+", 30: "D", 25: "D-", 24.9: "F", 0: "F", 140: "A+"}
    for score, letter in expect.items():
        assert grade.letter_for(score) == letter


# ============================================================================================ all three, i18n

def test_grades_bundle_and_summary(monkeypatch):
    ctx = _aplus_ctx()
    ctx.observatory = dict(OFFICIAL["obs-165"][3])
    import vulnscan.webscan.tls as tls_pkg
    monkeypatch.setattr(tls_pkg, "ssllabs_grade", lambda c: {"grade": "A+", "score": 96})
    g = grade.grades(ctx, [])
    assert set(g) == {"kashif", "observatory", "ssllabs"}
    assert g["kashif"]["grade"] == "A+" and g["observatory"]["score"] == 165 and g["ssllabs"]["grade"] == "A+"
    assert "attack-only" in g["ssllabs"]["label"]["en"] and g["ssllabs"]["label"]["ar"]
    assert grade.summary(g) == "Grades: Kashif A+ · Observatory 165 (A+) · SSL Labs-compatible A+"
    assert grade.summary(g, "ar").startswith("الدرجات: كاشف A+")
    json.dumps(g, ensure_ascii=False)


def test_grades_accepts_group_result_and_uses_suppressed_login_evidence():
    ctx = ctx_for("http://site.test/")
    res = group.process([mk("WEB000", url="http://site.test/"),
                         mk("WEB052", url="http://site.test/login", roles=("login",))], ctx)
    assert [i.rule for i, _r in res.suppressed] == ["WEB052"]
    g = grade.grades(ctx, res)
    assert g["kashif"]["letter"] == "D"                          # WEB000 on a site with a login page


def test_ssllabs_without_tls_is_not_graded():
    res = grade.ssllabs(ctx_for())
    assert res["grade"] is None and res["notes"][0]["en"].startswith("not graded")


def test_strings_are_bilingual_with_matching_placeholders():
    import re
    for key, (en, ar) in grade.STR.items():
        assert en and ar, key
        if re.sub(r"\{\w+\}|[\s:]", "", ar):
            assert any("\u0600" <= ch <= "\u06ff" for ch in ar), key
        assert sorted(re.findall(r"\{(\w+)\}", en)) == sorted(re.findall(r"\{(\w+)\}", ar)), key
    catalog, patterns = grade.i18n_catalog()
    assert catalog and patterns
    for rx, _repl in patterns:
        re.compile(rx)
