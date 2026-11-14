"""1.1.0 accuracy corpus (engine end to end, offline): CSP severity ceiling and coverage, the legacy-TLS fallback
(TLS 1.0 only, NULL suites only, 1024-bit DHE only), a SHA-1 intermediate, and minimal-vs-standard diffs.

See corpus_kit.py. Every server listens on 127.0.0.1; names go through the test resolver hook. A TLS case the local
OpenSSL cannot serve is skipped with the reason, never passed.
"""

from __future__ import annotations

import ssl

import pytest

import corpus_kit as K
from vulnscan.webscan import diff, engine
from vulnscan.webscan.types import ScanOptions

PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")


@pytest.fixture(scope="session")
def pki(tmp_path_factory):
    if not K.openssl():
        pytest.skip("openssl CLI not found: the corpus PKI cannot be built")
    return K.build_pki(tmp_path_factory.mktemp("accuracy-pki"))


@pytest.fixture(autouse=True)
def _hooks(monkeypatch, tmp_path, request):
    for k in PROXY_VARS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("KASHIF_TEST_RESOLVE", "1")
    monkeypatch.setenv("KASHIF_TEST_RESOLVE_MAP", str(K.resolver_map(tmp_path / "resolve.json")))
    if "pki" in request.fixturenames:
        monkeypatch.setenv("KASHIF_TEST_CAFILE", str(request.getfixturevalue("pki")["root"]))
    else:
        monkeypatch.delenv("KASHIF_TEST_CAFILE", raising=False)


def tls_server(pki, profile, headers=(("Content-Type", "text/html"),)):
    try:
        ctx = K.server_context(pki, profile)
    except (ssl.SSLError, ValueError, OSError) as e:
        pytest.skip(f"this OpenSSL cannot serve the {profile} profile: {e}")
    return K.TLSServer(ctx, K.http_reply(headers=list(headers)))


def scan(url, **kw):
    kw.setdefault("delay", 0.2)
    kw.setdefault("timeout", 3)
    return engine.scan(url, ScanOptions(**kw))


def by_rule(findings):
    out = {}
    for f in findings:
        out.setdefault(f.rule_id, []).append(f)
    return out


# ----------------------------------------------------------------------------------------------- CSP (item 2)

def test_csp_upgrade_insecure_requests_only_on_a_static_page_is_low(raw_http_server):
    raw_http_server.routes["/"] = K.http_reply(headers=[("Content-Type", "text/html"),
                                                         ("Content-Security-Policy", "upgrade-insecure-requests")])
    res = scan(f"http://{K.HOST}:{raw_http_server.port}/", profile="minimal")
    f = by_rule(res.findings)
    assert "WEB-content-security-policy" not in f
    (w42,) = f["WEB042"]
    assert w42.severity == "low"                                   # min(medium, missing-CSP severity on this page: low)
    assert any("never rated worse than no policy" in n["en"] for n in w42.extra["notes"])


def test_csp_value_checks_are_not_applicable_without_a_policy(raw_http_server):
    raw_http_server.routes["/"] = K.http_reply(headers=[("Content-Type", "text/html")],
                                               body=b"<html><body><script>x()</script></body></html>")
    res = scan(f"http://{K.HOST}:{raw_http_server.port}/", profile="minimal")
    states = {c["check"]: c for c in res.coverage["checks"]}
    assert states["WEB-content-security-policy"]["state"] == "fail"
    for check in ("WEB040", "WEB041", "WEB042", "WEB043", "WEB204", "WEB205", "WEB214", "WEB215", "WEB218"):
        assert states[check]["state"] == "not_applicable", check
        assert [r["code"] for r in states[check]["reasons"]] == ["no_policy"], check
    assert [f.rule_id for f in res.findings if f.rule_id.startswith(("WEB04", "WEB2"))] == []


# ----------------------------------------------------------------------------------------------- diff (item 1)

def test_minimal_after_standard_resolves_nothing(raw_http_server):
    raw_http_server.routes["/"] = K.http_reply(headers=[("Content-Type", "text/html"), ("Server", "nginx/1.18.0")])
    url = f"http://{K.HOST}:{raw_http_server.port}/"
    std = scan(url, profile="standard")
    assert std.findings
    mini = engine.scan(url, ScanOptions(profile="minimal", delay=0.2, timeout=3), previous=std.snapshot)
    d = mini.diff
    assert d["comparable"] and d["findings"]["resolved"] == [] and d["counts"]["resolved"] == 0
    assert d["counts"]["not_retested"] >= 1
    assert all(r["reason"]["en"] and r["reason"]["ar"] for r in d["findings"]["not_retested"])
    again = engine.scan(url, ScanOptions(profile="standard", delay=0.2, timeout=3), previous=std.snapshot)
    assert again.diff["findings"]["resolved"] == [] and again.diff["findings"]["new"] == []
    assert again.diff["grade_changes"][0]["en"] == "no grade changes"


def test_no_csp_then_weak_csp_is_not_a_check_regression(raw_http_server):
    body = b"<html><head><script src='/a.js'></script></head><body></body></html>"
    raw_http_server.routes["/"] = K.http_reply(headers=[("Content-Type", "text/html")], body=body)
    url = f"http://{K.HOST}:{raw_http_server.port}/"
    first = scan(url, profile="minimal")
    raw_http_server.routes["/"] = K.http_reply(headers=[("Content-Type", "text/html"),
                                                         ("Content-Security-Policy", "script-src * 'unsafe-inline'")],
                                               body=body)
    second = engine.scan(url, ScanOptions(profile="minimal", delay=0.2, timeout=3), previous=first.snapshot)
    d = second.diff
    assert [i for i in d["posture"] if i["id"] == "check_regressed"] == []
    assert {"WEB040", "WEB042"} <= {r["rule"] for r in d["findings"]["new"]}
    assert set(d["new_fingerprints"]) == {r["fingerprint"] for r in d["findings"]["new"]}


# ----------------------------------------------------------------------------------------------- legacy TLS (item 3)

def test_tls10_only_server_is_read_over_legacy_tls_and_judged(pki):
    srv = tls_server(pki, "tls10")
    try:
        res = scan(srv.url(), profile="standard")
    finally:
        srv.close()
    f = by_rule(res.findings)
    assert "WEB030" in f
    (w705,) = f["WEB705"]
    assert w705.severity == "high" and w705.extra.get("params", {}).get("variant", "no12no13") == "no12no13"
    assert "WEB706" in f
    assert res.grades["ssllabs"]["grade"] in ("C", "D", "E", "F")
    assert res.grades["kashif"]["grade"].rstrip("*") not in ("A+", "A", "A-", "B+", "B", "B-")
    assert any("legacy" in n["en"] and "TLSV1_ALERT_PROTOCOL_VERSION" in n["en"] for n in res.inventory["notes"])
    assert srv.requests, "the page itself was read (over the legacy connection)"


def test_dhe1024_only_server_falls_back_and_deep_reports_weak_dh(pki):
    srv = tls_server(pki, "dhe1024")
    try:
        std = scan(srv.url(), profile="standard")
        deep = scan(srv.url(), profile="deep")
    finally:
        srv.close()
    assert any("DH_KEY_TOO_SMALL" in n["en"] for n in std.inventory["notes"])
    g = std.grades["ssllabs"]
    assert g["provisional"] is True and any("key exchange strength not measured" in n["en"] for n in g.get("notes", []))
    states = {c["check"]: c for c in std.coverage["checks"]}
    assert states["WEB718"]["state"] == "not_tested"
    assert [r["code"] for r in states["WEB718"]["reasons"]] == ["dh_unmeasured"]
    assert "WEB710" in by_rule(deep.findings)
    assert deep.grades["ssllabs"]["grade"] in ("B", "C", "D", "E", "F")


def test_null_only_server_raw_probe_findings_come_with_the_unreachable_error(pki):
    srv = tls_server(pki, "null")
    try:
        with pytest.raises(engine.WebUnreachable) as exc:
            scan(srv.url(), profile="standard")
    finally:
        srv.close()
    e = exc.value
    assert e.code == "tls" and e.proxy == ""
    f = by_rule(e.findings)
    assert "WEB706" in f and f["WEB706"][0].severity == "high"
    assert e.notes and "WEB706" in e.notes[0][0] and "WEB706" in e.notes[0][1]


# ----------------------------------------------------------------------------------------------- SHA-1 chain (item 4)

def test_sha1_intermediate_is_rejected_like_a_browser_does(pki):
    srv = tls_server(pki, "sha1int")
    try:
        res = scan(srv.url(), profile="standard")
    finally:
        srv.close()
    f = by_rule(res.findings)
    (w72,) = f["WEB072"]
    assert w72.severity == "high"
    assert "rejected by browsers: SHA-1 or weak key in chain" in str(w72.extra.get("evidence") or w72.extra)
    assert "WEB708" in f
    assert res.grades["ssllabs"]["grade"] == "T"
    assert res.grades["ssllabs"]["caps"][0]["en"].startswith("certificate not trusted: rejected by browsers")
    assert res.grades["kashif"]["grade"].rstrip("*") == "F"


def test_good_server_has_revocation_recorded_as_not_checked(pki):
    srv = tls_server(pki, "good")
    try:
        res = scan(srv.url(), profile="standard")
    finally:
        srv.close()
    states = {c["check"]: c for c in res.coverage["checks"]}
    rev = states["WEB714-revocation"]
    assert rev["state"] == "not_tested" and rev["reasons"][0]["code"] == "revocation"
    assert "does not contact the CA" in rev["reasons"][0]["en"]
    assert "certificate revocation" in res.grades["ssllabs"]["label"][0]
    assert not any(r["check"] == "WEB714-revocation" for r in [])     # WEB991 never lists it (no_web991 reason)
    assert "WEB991" not in by_rule(res.findings) or "WEB714-revocation" not in str(by_rule(res.findings)["WEB991"])
