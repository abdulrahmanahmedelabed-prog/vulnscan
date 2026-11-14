"""WP13 scan diff (spec §3.7): snapshot contents (no secrets), comparability, finding categories, grade changes and
posture changes (regressions first)."""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone

import pytest

from vulnscan.webscan import diff, group
from vulnscan.webscan.coverage import Coverage
from vulnscan.webscan.rules import RULES
from vulnscan.webscan.types import (CookieFact, CspFacts, CspPolicy, Evidence, HeaderList, Issue, Page, Response,
                                    ScanContext, ScanOptions)

NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
SITE = "https://shop.example.test/"


def mk(rule, url=SITE, value="", severity=None):
    ev = Evidence(kind="document", role=["app"], match={"where": "header", "name": rule, "value": value})
    return Issue(rule=rule, url=url, confidence=RULES[rule].confidence, evidence=ev, severity=severity,
                 group_value=value, params={"cookie": "sid", "value": value, "path": value, "library": "jquery",
                                            "version": "3.6.0", "platform": "x"})


def make_ctx(*, csp="default-src 'self'; script-src 'self'", cookies=(("__Host-sid", "SECRETVALUE123", {"secure": "",
             "httponly": "", "path": "/", "samesite": "Lax"}, "session"),), headers=(), inventory=None, profile="standard",
             target=SITE, now=NOW):
    hl = [("Content-Type", "text/html"), ("Strict-Transport-Security", "max-age=63072000"),
          ("X-Frame-Options", "DENY")] + list(headers)
    if csp:
        hl.append(("Content-Security-Policy", csp))
    hop = Response(url="http://shop.example.test/", status=301, headers=HeaderList.of(("Location", SITE)))
    entry = Response(url=SITE, status=200, headers=HeaderList.of(*hl), kind="document", body=b"<html></html>",
                     chain=[hop])
    ctx = ScanContext(options=ScanOptions(profile=profile), target=target, entry=entry, pages=[Page(entry, None, 0)],
                      now=now)
    if csp:
        directives = {}
        for part in csp.split(";"):
            bits = part.split()
            if bits:
                directives[bits[0]] = bits[1:]
        ctx.csp = {entry: CspFacts(enforced=[CspPolicy(raw=csp, origin="header", directives=directives)])}
    ctx.cookies = [CookieFact(name=n, value=v, attrs=a, raw=f"{n}={v}", response=entry, host=entry.host,
                              secure_context=True, cls=c) for n, v, a, c in cookies]
    ctx.inventory = inventory if inventory is not None else {
        "third_parties": {"cdn.thirdparty.test": ["script"]},
        "libraries": [{"name": "jQuery", "component": "jquery", "version": "3.6.0"}],
        "technologies": [{"id": "nginx", "name": "nginx", "version": "1.25.3"}],
        "tls": {"shop.example.test": {"ips": {"192.0.2.1": {
            "protocols": {"TLSv1.2": "yes", "TLSv1.3": "no", "TLSv1.0": "no"}, "suites": {"aead": "yes", "cbc": "no"},
            "chain": [{"sha256": "aa" * 32, "issuer": "CN=Old CA", "not_after": "2027-01-01T00:00:00Z",
                       "key": "RSA 2048"}], "scts": {"embedded": 2, "tls": 0}}}}},
        "security_txt": {"present": True, "expires": "2027-06-01T00:00:00Z"},
        "robots": {"disallow": ["/admin"]},
        "deep_probe_hits": [{"path": "/.env", "rule": "WEB062"}],
    }
    return ctx


def snap(ctx, issues=(), grades=None, coverage=None):
    groups = group.group_issues(issues, ctx)
    return diff.snapshot(ctx, groups, grades, coverage, scan_id="s1", version="1.1.0")


def grades_of(k="B", o=70, og="B", s="A"):
    return {"kashif": {"grade": k, "score": 75}, "observatory": {"grade": og, "score": o}, "ssllabs": {"grade": s}}


# ----------------------------------------------------------------------------------------------- snapshot

def test_snapshot_contents_and_no_secret_values():
    cov = Coverage(["WEB-content-security-policy", "WEB062"])
    cov.record("WEB-content-security-policy", "pass")
    s = snap(make_ctx(), [mk("WEB062", SITE + ".env", "/.env")], grades_of(), cov)
    blob = json.dumps(s, ensure_ascii=False)
    assert "SECRETVALUE123" not in blob
    assert s["schema"] == diff.SCHEMA and s["target"] == "https://shop.example.test/" and s["profile"] == "standard"
    inv = s["inventory"]
    assert inv["final_url"] == SITE and inv["chain"] == [["http://shop.example.test/", 301], [SITE, 200]]
    assert inv["headers"]["x-frame-options"] == "DENY"
    assert inv["csp"][0]["directives"]["script-src"] == ["'self'"]
    assert inv["cookies"]["__Host-sid"] == {"class": "session", "secure": True, "httponly": True, "partitioned": False,
                                            "samesite": "lax", "domain": "", "path": "/", "host": "shop.example.test"}
    assert inv["third_party"]["script"] == ["cdn.thirdparty.test"]
    assert inv["libraries"] == {"jQuery": "3.6.0"} and inv["technologies"] == {"nginx": "1.25.3"}
    tls = inv["tls"]["shop.example.test 192.0.2.1"]
    assert tls["protocols"] == ["TLSv1.2"] and tls["suites"] == ["aead"] and tls["scts"] == 2
    assert inv["security_txt"]["expires"].startswith("2027-06-01") and inv["robots_disallow"] == ["/admin"]
    assert inv["deep_hits"] == ["/.env"]
    assert s["checks"]["WEB-content-security-policy"] == "pass" and s["checks"]["WEB062"] == "not_tested"
    [row] = s["findings"]
    assert row["rule"] == "WEB062" and row["key"].startswith("WEB062|shop.example.test|") and row["title_ar"]
    assert s["grades"]["kashif"]["grade"] == "B"


def test_snapshot_nonce_in_csp_and_headers_is_normalised():
    a = snap(make_ctx(csp="script-src 'nonce-AAAAbbbb1111' 'strict-dynamic'"))
    b = snap(make_ctx(csp="script-src 'nonce-ZZZZyyyy9999' 'strict-dynamic'"))
    assert a["inventory"]["csp"] == b["inventory"]["csp"]
    d = diff.diff(a, b)
    assert not [i for i in d["posture"] if i["kind"] == "csp"]


@pytest.mark.parametrize("url,norm", [
    ("HTTPS://Shop.Example.Test:443/", "https://shop.example.test/"),
    ("https://shop.example.test", "https://shop.example.test/"),
    ("https://shop.example.test/app/?x=1#y", "https://shop.example.test/app"),
    ("http://shop.example.test:8080/a/", "http://shop.example.test:8080/a"),
])
def test_normalise_target(url, norm):
    assert diff.normalise_target(url) == norm


# ----------------------------------------------------------------------------------------------- comparability

def test_no_previous_and_other_target():
    cur = snap(make_ctx())
    d = diff.diff(None, cur)
    assert not d["comparable"] and d["notes"][0]["en"].startswith("no previous")
    other = snap(make_ctx(target="https://other.example.test/"))
    d = diff.diff(other, cur)
    assert not d["comparable"] and "other.example.test" in d["notes"][0]["en"] and d["notes"][0]["ar"]
    assert d["findings"] == {"new": [], "resolved": [], "unchanged": [], "not_retested": []}


def test_profile_difference_is_stated_and_deep_hits_not_compared():
    prev = snap(make_ctx(profile="deep"))
    cur = snap(make_ctx(profile="standard", inventory={}))
    d = diff.diff(prev, cur)
    assert d["comparable"] and "deep" in d["notes"][0]["en"] and "standard" in d["notes"][0]["ar"]
    assert not [i for i in d["posture"] if i["kind"] == "deep_probe"]


# ----------------------------------------------------------------------------------------------- findings / grades

def _cov(**states):
    c = Coverage(list(states))
    for check, st in states.items():
        if st in ("not_tested", "inconclusive"):
            c.record(check, st, "profile" if st == "not_tested" else "waf")
        else:
            c.record(check, st, host="shop.example.test")
    return c


def test_new_resolved_unchanged_by_fp_key():
    prev = snap(make_ctx(), [mk("WEB062", SITE + ".env", "/.env"), mk("WEB010", value="nginx/1.25.3")])
    cur = snap(make_ctx(), [mk("WEB010", SITE + "other", value="nginx/1.25.3"), mk("WEB-content-security-policy",
                                                                                  value="missing")],
               coverage=_cov(WEB062="pass", WEB010="fail"))
    d = diff.diff(prev, cur)
    assert [r["rule"] for r in d["findings"]["new"]] == ["WEB-content-security-policy"]
    assert [r["rule"] for r in d["findings"]["resolved"]] == ["WEB062"]
    assert [r["rule"] for r in d["findings"]["unchanged"]] == ["WEB010"]
    assert d["counts"]["new"] == 1 and d["counts"]["resolved"] == 1 and d["counts"]["unchanged"] == 1


def test_unchanged_across_reruns_with_new_nonces():
    prev = snap(make_ctx(), [mk("WEB212", value="script-src 'nonce-aaaa1111bbbb2222'")])
    cur = snap(make_ctx(), [mk("WEB212", value="script-src 'nonce-cccc3333dddd4444'")])
    d = diff.diff(prev, cur)
    assert len(d["findings"]["unchanged"]) == 1 and not d["findings"]["new"]


def test_finding_rows_from_finding_dicts_fall_back_to_fingerprint():
    prev = snap(make_ctx())
    cur = snap(make_ctx())
    prev["findings"] = [diff._finding_row({"rule_id": "WEB010", "severity": "low", "fingerprint": "abc:0", "extra": {}})]
    cur["findings"] = [diff._finding_row({"rule_id": "WEB010", "severity": "low", "fingerprint": "abc:0",
                                          "extra": {"fp_key": "WEB010|h|document|x"}})]
    d = diff.diff(prev, cur)
    assert len(d["findings"]["unchanged"]) == 1


def test_grade_changes_per_algorithm():
    prev = snap(make_ctx(), grades=grades_of("B", 70, "B", "A"))
    cur = snap(make_ctx(), grades=grades_of("A-*", 85, "A-", "A"))
    d = diff.diff(prev, cur)
    assert d["grades"]["kashif"]["change"] == "up" and d["grades"]["observatory"]["change"] == "up"
    assert d["grades"]["ssllabs"]["change"] == "same"
    down = diff.diff(cur, prev)
    assert down["grades"]["kashif"]["change"] == "down"
    assert down["posture"][0]["direction"] == "regression" and down["posture"][0]["kind"] == "grade"


# ----------------------------------------------------------------------------------------------- posture

def _posture(prev_ctx, cur_ctx):
    return diff.diff(snap(prev_ctx), snap(cur_ctx))["posture"]


def _find(items, key):
    return [i for i in items if i["id"] == key]


def test_csp_source_added_is_a_regression_and_named():
    items = _posture(make_ctx(), make_ctx(csp="default-src 'self'; script-src 'self' https://cdn.new.example"))
    [i] = _find(items, "csp_added")
    assert i["direction"] == "regression" and i["en"] == "CSP changed: script-src added https://cdn.new.example"
    assert "script-src" in i["ar"]
    assert _find(items, "third_new")[0]["en"] == "new third-party script host: cdn.new.example"
    removed = _posture(make_ctx(csp="default-src 'self'; script-src 'self' https://old.example"), make_ctx())
    assert _find(removed, "csp_removed")[0]["direction"] == "improvement"
    gone = _posture(make_ctx(), make_ctx(csp=""))
    assert _find(gone, "csp_disabled")[0]["direction"] == "regression"


def test_cookie_changes():
    cur = make_ctx(cookies=(("__Host-sid", "x", {"httponly": "", "path": "/", "samesite": "None"}, "session"),
                            ("__Host-x", "y", {"secure": "", "path": "/"}, "unknown")))
    items = _posture(make_ctx(), cur)
    assert _find(items, "cookie_new")[0]["en"] == "new cookie __Host-x (unknown)"
    assert _find(items, "cookie_lost")[0]["en"] == "cookie __Host-sid lost the Secure attribute"
    assert _find(items, "cookie_samesite")[0]["direction"] == "regression"
    assert _find(_posture(cur, make_ctx()), "cookie_gone")[0]["en"] == "cookie no longer set: __Host-x"


def _inv(**changes):
    base = make_ctx().inventory
    inv = copy.deepcopy(base)
    for k, v in changes.items():
        inv[k] = v
    return inv


def test_library_and_technology_versions():
    cur = make_ctx(inventory=_inv(libraries=[{"name": "jQuery", "version": "3.7.1"}],
                                  technologies=[{"name": "nginx", "version": "1.27.0"}, {"name": "PHP", "version": "8.3"}]))
    items = _posture(make_ctx(), cur)
    [lib] = _find(items, "lib_changed")
    assert lib["en"] == "library jQuery 3.6.0 → 3.7.1" and lib["direction"] == "improvement"
    assert _find(items, "tech_new")[0]["en"] == "new technology detected: PHP 8.3"
    assert _find(items, "tech_changed")[0]["direction"] == "improvement"


def test_tls_changes_protocols_suites_and_certificate():
    inv = _inv()
    ip = inv["tls"]["shop.example.test"]["ips"]["192.0.2.1"]
    ip["protocols"]["TLSv1.3"] = "yes"
    ip["protocols"]["TLSv1.0"] = "yes"
    ip["suites"]["cbc"] = "yes"
    ip["chain"] = [{"sha256": "bb" * 32, "issuer": "CN=New CA", "not_after": "2027-03-01T00:00:00Z", "key": "EC 256"}]
    ip["scts"] = {"embedded": 0, "tls": 0}
    items = _posture(make_ctx(), make_ctx(inventory=inv))
    enabled = {i["en"]: i["direction"] for i in _find(items, "tls_enabled")}
    assert enabled == {"TLS 1.3 enabled on 192.0.2.1": "improvement", "TLS 1.0 enabled on 192.0.2.1": "regression"}
    assert _find(items, "suite_enabled")[0]["direction"] == "regression"
    assert _find(items, "cert_issuer")[0]["en"] == "certificate renewed on 192.0.2.1, new issuer: CN=New CA"
    assert _find(items, "cert_key")[0]["en"].endswith("RSA 2048 → EC 256")
    assert _find(items, "scts_changed")[0]["direction"] == "regression"
    same_issuer = _inv()
    same_issuer["tls"]["shop.example.test"]["ips"]["192.0.2.1"]["chain"][0]["sha256"] = "cc" * 32
    assert _find(_posture(make_ctx(), make_ctx(inventory=same_issuer)), "cert_renewed")


def test_security_txt_expiry_soon_and_robots_and_deep_hits():
    soon = (NOW + timedelta(days=20)).isoformat().replace("+00:00", "Z")
    cur = make_ctx(inventory=_inv(security_txt={"present": True, "expires": soon}, robots={"disallow": ["/admin", "/tmp"]},
                                  deep_probe_hits=[{"path": "/.git/HEAD"}]))
    items = _posture(make_ctx(), cur)
    [exp] = _find(items, "sectxt_soon")
    assert exp["en"] == "security.txt expires in 20 days" and exp["direction"] == "regression"
    assert "20" in exp["ar"] and "يومًا" in exp["ar"]
    assert _find(items, "robots_added")[0]["en"] == "robots.txt now disallows /tmp"
    assert _find(items, "deep_new")[0]["en"] == "newly exposed: /.git/HEAD"
    assert _find(items, "deep_gone")[0]["direction"] == "improvement"
    expired = make_ctx(inventory=_inv(security_txt={"present": True, "expires": "2026-01-01T00:00:00Z"}))
    assert _find(_posture(make_ctx(), expired), "sectxt_expired")
    gone = make_ctx(inventory=_inv(security_txt={"present": False}))
    assert _find(_posture(make_ctx(), gone), "sectxt_removed")[0]["direction"] == "regression"


def test_headers_redirects_and_check_states():
    cur = make_ctx(headers=[("Server", "nginx"), ("Referrer-Policy", "no-referrer")])
    cur.entry.chain = []
    items = _posture(make_ctx(), cur)
    added = {i["en"]: i["direction"] for i in _find(items, "header_added")}
    assert added["header added: Server: nginx"] == "regression"
    assert added["header added: Referrer-Policy: no-referrer"] == "improvement"
    assert _find(items, "chain")
    a, b = Coverage(["WEB062", "WEB010", "WEB030"]), Coverage(["WEB062", "WEB010", "WEB030"])
    a.record("WEB062", "pass"), b.record("WEB062", "fail")
    a.record("WEB010", "fail"), b.record("WEB010", "pass")
    a.record("WEB030", "pass"), b.record("WEB030", "not_tested", "proxied")
    d = diff.diff(snap(make_ctx(), coverage=a), snap(make_ctx(), coverage=b))
    ids = {i["id"]: i["direction"] for i in d["posture"] if i["kind"] == "check"}
    assert ids == {"check_regressed": "regression", "check_fixed": "improvement", "check_coverage": "change"}


def test_regressions_first_and_json_safe():
    cur = make_ctx(csp="default-src 'self'; script-src 'self' https://cdn.new.example",
                   inventory=_inv(libraries=[{"name": "jQuery", "version": "3.7.1"}]))
    d = diff.diff(snap(make_ctx()), snap(cur))
    dirs = [i["direction"] for i in d["posture"]]
    assert dirs == sorted(dirs, key={"regression": 0, "change": 1, "improvement": 2}.__getitem__)
    assert d["counts"]["regressions"] >= 1 and d["counts"]["improvements"] >= 1
    json.loads(json.dumps(d, ensure_ascii=False))


def test_identical_scans_have_no_posture_changes():
    s = snap(make_ctx(), [mk("WEB010", value="nginx")], grades_of())
    d = diff.diff(s, copy.deepcopy(s))
    assert d["posture"] == [] and len(d["findings"]["unchanged"]) == 1


def test_strings_are_bilingual():
    import re
    for key, (en, ar) in diff.STR.items():
        assert en and ar and any("؀" <= ch <= "ۿ" for ch in ar), key
        assert sorted(re.findall(r"\{(\w+)\}", en)) == sorted(re.findall(r"\{(\w+)\}", ar)), key
    catalog, patterns = diff.i18n_catalog()
    for rx, _r in patterns:
        re.compile(rx)


# ----------------------------------------------------------------------------------------------- hostile input (review)

def _paths(o, p=()):
    yield p
    if isinstance(o, dict):
        for k, v in o.items():
            yield from _paths(v, p + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from _paths(v, p + (i,))


def test_malformed_previous_snapshot_never_crashes():
    """A previous snapshot is read from disk (store or --compare file): any field of the wrong type is dropped."""
    base = snap(make_ctx(), [mk("WEB062", SITE + ".env", "/.env")], grades_of())
    junk = [None, 1, "x", [], {}, [1, "a", None], {"a": 1}, 1.5, True]
    for path in _paths(base):
        if not path:
            continue
        for j in junk:
            bad = copy.deepcopy(base)
            o = bad
            for k in path[:-1]:
                o = o[k]
            o[path[-1]] = j
            for a, b in ((bad, base), (base, bad)):
                d = diff.diff(a, b)
                json.dumps(d, ensure_ascii=False)
    for top in (1, "x", [1], 1.5, True, {}, {"target": 5}):
        d = diff.diff(top, base)
        assert d["comparable"] is False


def test_sanitised_snapshot_is_unchanged_for_a_well_formed_one():
    s = snap(make_ctx(), [mk("WEB062", SITE + ".env", "/.env")], grades_of())
    clean = diff.sanitise(json.loads(json.dumps(s)))
    assert clean["inventory"] == json.loads(json.dumps(s["inventory"]))
    assert clean["findings"] == s["findings"] and clean["target"] == s["target"]


def test_security_txt_expiring_within_a_day_is_not_zero_days():
    soon = (NOW + timedelta(hours=5)).isoformat().replace("+00:00", "Z")
    cur = make_ctx(inventory=_inv(security_txt={"present": True, "expires": soon}))
    [exp] = _find(_posture(make_ctx(), cur), "sectxt_soon")
    assert exp["en"] == "security.txt expires in 1 day" and "يوم واحد" in exp["ar"]


# ----------------------------------------------------------------------------------------------- 1.1.0 accuracy round

def test_unmatched_finding_whose_check_did_not_run_is_not_retested_not_resolved():
    prev = snap(make_ctx(), [mk("WEB062", SITE + ".env", "/.env"), mk("WEB010", value="nginx/1.25.3")])
    cur = snap(make_ctx(profile="minimal"), [], coverage=_cov(WEB062="not_tested", WEB010="inconclusive"))
    d = diff.diff(prev, cur)
    assert d["findings"]["resolved"] == [] and d["counts"]["resolved"] == 0
    nr = {r["rule"]: r["reason"] for r in d["findings"]["not_retested"]}
    assert set(nr) == {"WEB062", "WEB010"} and d["counts"]["not_retested"] == 2
    assert nr["WEB062"]["code"] == "profile" and nr["WEB062"]["en"] and nr["WEB062"]["ar"]
    assert nr["WEB010"]["code"] == "waf"
    # a check missing from the current coverage altogether did not run either
    d = diff.diff(prev, snap(make_ctx(), [], coverage=_cov(WEB010="pass")))
    assert [r["rule"] for r in d["findings"]["resolved"]] == ["WEB010"]
    assert [(r["rule"], r["reason"]["code"]) for r in d["findings"]["not_retested"]] == [("WEB062", "not_run")]


def test_failed_check_that_was_partly_skipped_does_not_resolve_other_instances():
    prev = snap(make_ctx(), [mk("WEB052", SITE + "login", SITE + "login"), mk("WEB052", SITE + "a", SITE + "a")])
    c = Coverage(["WEB052"])
    c.record("WEB052", "fail", host="shop.example.test")
    c.record("WEB052", "not_tested", "budget", host="shop.example.test")
    d = diff.diff(prev, snap(make_ctx(), [mk("WEB052", SITE + "a", SITE + "a")], coverage=c))
    assert d["findings"]["resolved"] == []
    assert [r["reason"]["code"] for r in d["findings"]["not_retested"]] == ["partial"]
    c2 = Coverage(["WEB052"])
    c2.record("WEB052", "fail", host="shop.example.test")
    d = diff.diff(prev, snap(make_ctx(), [mk("WEB052", SITE + "a", SITE + "a")], coverage=c2))
    assert len(d["findings"]["resolved"]) == 1 and not d["findings"]["not_retested"]


def test_severity_change_is_one_posture_change_not_new_plus_resolved():
    prev = snap(make_ctx(), [mk("WEB315", value="max-age=600", severity="high")])
    cur = snap(make_ctx(), [mk("WEB315", value="max-age=600", severity="low")], coverage=_cov(WEB315="fail"))
    d = diff.diff(prev, cur)
    assert not d["findings"]["new"] and not d["findings"]["resolved"] and len(d["findings"]["unchanged"]) == 1
    assert d["findings"]["unchanged"][0]["severity_before"] == "high"
    sev = [i for i in d["posture"] if i["kind"] == "severity"]
    assert len(sev) == 1 and sev[0]["direction"] == "change" and sev[0]["en"].startswith("WEB315 high → low")
    assert "عالية" in sev[0]["ar"] and "منخفضة" in sev[0]["ar"] and d["counts"]["severity_changed"] == 1
    # rows of an older snapshot with another key scheme still match on rule + host + group value
    prev["findings"][0]["key"] = "legacy-key"
    prev["findings"][0]["fingerprint"] = "legacy-fp"
    d = diff.diff(prev, cur)
    assert len(d["findings"]["unchanged"]) == 1 and not d["findings"]["new"]


def test_new_fingerprints_are_exposed_for_badges():
    prev = snap(make_ctx(), [mk("WEB010", value="nginx")])
    cur = snap(make_ctx(), [mk("WEB010", value="nginx"), mk("WEB062", SITE + ".env", "/.env")])
    d = diff.diff(prev, cur)
    assert d["new_fingerprints"] == [d["findings"]["new"][0]["fingerprint"]] and d["new_fingerprints"][0]


def test_csp_added_after_none_is_not_a_check_regression():
    """No CSP (the value checks are not_applicable: no_policy), then a weak CSP (WEB042 fails): new findings and a CSP
    posture change, never "check WEB042 now fails"."""
    from vulnscan.webscan import csp
    from vulnscan.webscan.engine import analyze_responses
    from vulnscan.webscan.types import ScanOptions as Opts

    def run_with(csp_value):
        hl = [("Content-Type", "text/html")] + ([("Content-Security-Policy", csp_value)] if csp_value else [])
        entry = Response(url=SITE, status=200, headers=HeaderList.of(*hl), kind="document",
                         body=b"<html><head><script src='/a.js'></script></head><body></body></html>")
        findings, ctx = analyze_responses(SITE, entry, Opts(), modules=("csp",))
        return diff.snapshot(ctx, findings, None, ctx.coverage, scan_id="x", version="1.1.0"), ctx

    before, bctx = run_with("")
    assert bctx.coverage.state("WEB042").state == "not_applicable"
    assert {r[0] for r in bctx.coverage.state("WEB042").reasons} == {"no_policy"}
    after, _ = run_with("upgrade-insecure-requests; script-src *")
    d = diff.diff(before, after)
    assert [i for i in d["posture"] if i["id"] == "check_regressed"] == []
    assert "WEB042" in {r["rule"] for r in d["findings"]["new"]}
    assert [r["rule"] for r in d["findings"]["resolved"]] == ["WEB-content-security-policy"]
    assert csp  # imported for its side effects on the registry


def test_grade_changes_only_changed_with_scores_and_no_change_line():
    def g(k, ks, o, og, s):
        return {"kashif": {"grade": k, "score": ks}, "observatory": {"grade": og, "score": o}, "ssllabs": {"grade": s}}
    prev = snap(make_ctx(), grades=g("F*", 59.69, 0, "F", "A"))
    cur = snap(make_ctx(), grades=g("F*", 65.94, 15, "F", "A"))
    d = diff.diff(prev, cur)
    lines = {x["algorithm"]: x for x in d["grade_changes"]}
    assert set(lines) == {"kashif", "observatory"}
    assert lines["kashif"]["en"] == "Kashif: F* (59.69 → 65.94)"
    assert lines["observatory"]["en"] == "Observatory score rose: 0 → 15 (grade still F)"
    assert lines["kashif"]["ar"].startswith("كاشِف: ") and "⁨F*⁩" in lines["kashif"]["ar"]
    assert lines["observatory"]["ar"].startswith("ارتفعت درجة Observatory")
    assert d["grades"]["ssllabs"]["change"] == "same" and not d["grades"]["ssllabs"]["changed"]
    assert d["grades"]["kashif"]["text"]["en"] == lines["kashif"]["en"]
    letters = diff.diff(snap(make_ctx(), grades=g("C+*", 60, 50, "C", "B")), snap(make_ctx(), grades=g("A*", 92, 50, "C", "B")))
    (line,) = letters["grade_changes"]
    assert line["en"] == "Kashif grade improved: C+* → A* (60 → 92)"
    assert "⁨C+*⁩" in line["ar"] and "⁨A*⁩" in line["ar"] and "كاشِف" in line["ar"]
    same = diff.diff(prev, copy.deepcopy(prev))
    assert same["grade_changes"] == [{"algorithm": "", "direction": "same", "en": "no grade changes",
                                      "ar": "لا تغيّر في الدرجات"}]
    assert not [i for i in same["posture"] if i["kind"] == "grade"]


def test_arabic_values_are_isolated_and_profile_is_called_scan_mode():
    items = _posture(make_ctx(), make_ctx(headers=[("Server", "nginx")]))
    (added,) = _find(items, "header_added")
    assert "⁨Server⁩" in added["ar"] and "⁨nginx⁩" in added["ar"]
    d = diff.diff(snap(make_ctx(profile="minimal")), snap(make_ctx()))
    assert "نمط الفحص" in d["notes"][0]["ar"] and "ملف الفحص" not in d["notes"][0]["ar"]
