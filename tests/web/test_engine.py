"""Engine and facade (spec §4.3, §3.5–§3.8; WP15a): pipeline, profiles and their request budgets, sensitivity, the
Issue → Finding conversion, scan meta (WEB990/WEB991), module isolation, crawl, snapshot/diff and the 1.0.1 facade.

Every scan runs against ``raw_http_server`` on 127.0.0.1. Names go through the test-only resolver hook
(``KASHIF_TEST_RESOLVE=1``): every name is 127.0.0.1 (marked public, as in the corpus), so nothing leaves the machine
(the conftest offline guard enforces it); third-party https URLs on port 443 simply find nothing listening.
"""

from __future__ import annotations

import json
import re

import pytest

from vulnscan.model import Finding
from vulnscan.webscan import engine, rules
from vulnscan.webscan.types import CORS_PROBE_ORIGIN, SENSITIVITY_CONFIDENCES, HeaderList, Response, ScanOptions

HOST = "site.kashif.test"
PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
ALLOWED_HEADERS = {"host", "user-agent", "accept", "accept-encoding", "accept-language", "origin", "cookie", "connection"}

PAGE = """<!doctype html><html><head><title>Home</title>
<link rel="icon" href="/static/icon.png">
<link rel="stylesheet" href="/static/site.css">
<script src="/static/app.js"></script>
<script src="https://cdn.third-party.example.net/lib.js"></script>
</head><body>
<form action="http://insecure.example.net/login" method="post"><input type="password" name="pw"></form>
<a href="/a">a</a> <a href="/private/x">private</a> <a href="/logout">out</a> <a href="https://other.example.org/">x</a>
</body></html>"""


def reply(status="200 OK", headers=(), body=b""):
    if isinstance(body, str):
        body = body.encode("utf-8")
    lines = [f"HTTP/1.1 {status}"] + [f"{k}: {v}" for k, v in headers]
    lines += [f"Content-Length: {len(body)}", "Connection: close"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


HTML = ("Content-Type", "text/html; charset=utf-8")


@pytest.fixture(autouse=True)
def _hook(monkeypatch, tmp_path):
    for k in PROXY_VARS:
        monkeypatch.delenv(k, raising=False)
    rmap = {"version": 1,
            "hosts": {HOST: {"status": "ok", "addresses": ["127.0.0.1"], "public": True},
                      f"www.{HOST}": {"status": "ok", "addresses": ["127.0.0.1"], "public": True}},
            "default": {"status": "ok", "addresses": ["127.0.0.1"], "public": True}}
    p = tmp_path / "resolve.json"
    p.write_text(json.dumps(rmap), encoding="utf-8")
    monkeypatch.setenv("KASHIF_TEST_RESOLVE", "1")
    monkeypatch.setenv("KASHIF_TEST_RESOLVE_MAP", str(p))
    monkeypatch.delenv("KASHIF_TEST_CAFILE", raising=False)
    monkeypatch.setenv("KASHIF_DEBUG", "1")          # a module error fails the test instead of being recorded


def requests_of(srv):
    """[(path, {header: value})] of what the server received, in order."""
    out = []
    for raw in srv.requests:
        head = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
        method, path = head[0].split(" ")[:2]
        assert method == "GET", head[0]
        hdrs = {}
        for line in head[1:]:
            k, _, v = line.partition(":")
            hdrs[k.strip().lower()] = v.strip()
        out.append((path, hdrs))
    return out


@pytest.fixture
def site(raw_http_server):
    srv = raw_http_server
    srv.routes["/"] = reply(headers=[HTML, ("Set-Cookie", "sid=0123456789abcdef; Path=/"),
                                     ("Server", "nginx/1.18.0")], body=PAGE)
    srv.routes["/a"] = reply(headers=[HTML], body="<html><body><p>page a</p><a href='/b'>b</a></body></html>")
    srv.routes["/b"] = reply(headers=[HTML], body="<html><body><p>page b, other text</p></body></html>")
    srv.routes["/private/x"] = reply(headers=[HTML], body="<html><body>secret area</body></html>")
    srv.routes["/robots.txt"] = reply(headers=[("Content-Type", "text/plain")],
                                      body="User-agent: *\nDisallow: /private/\n")
    srv.routes["/static/app.js"] = reply(headers=[("Content-Type", "application/javascript")], body="var a = 1;\n")
    srv.routes["/static/site.css"] = reply(headers=[("Content-Type", "text/css")], body="body{color:#000}\n")
    srv.routes["/static/icon.png"] = reply(headers=[("Content-Type", "image/png")], body=b"\x89PNG\r\n\x1a\n" + b"\0" * 64)
    srv.url_for = lambda path="/": f"http://{HOST}:{srv.port}{path}"
    return srv


def scan(srv, path="/", **kw):
    kw.setdefault("delay", 0.2)
    kw.setdefault("timeout", 5)
    return engine.scan(srv.url_for(path), ScanOptions(**kw))


# ----------------------------------------------------------------------------------------------- profiles (§4.3)

def test_minimal_profile_is_the_entry_chain_only(site):
    site.routes["/"] = reply("301 Moved Permanently", [("Location", "/home")])
    site.routes["/home"] = reply(headers=[HTML], body="<html><body>home</body></html>")
    res = scan(site, profile="minimal")
    assert [p for p, _ in requests_of(site)] == ["/", "/home"]
    assert res.requests == 2 and res.final_url.endswith("/home") and res.profile == "minimal"
    # header rules judge the final 2xx document, never the 301 (D1)
    hdr = [f for f in res.findings if f.rule_id == "WEB-content-security-policy"]
    assert hdr and all(f.extra["evidence"]["status"] == 200 for f in hdr)


def test_standard_profile_requests_match_the_scope_contract(site):
    res = scan(site, profile="standard")
    reqs = requests_of(site)
    paths = [p for p, _ in reqs]
    assert len(reqs) <= 45 and res.requests == len(reqs)
    assert paths[0] == "/" and paths.count("/") == 2                      # entry + the CORS GET
    for want in ("/robots.txt", "/.well-known/security.txt", "/security.txt", "/static/icon.png", "/static/app.js",
                 "/static/site.css"):
        assert want in paths, want
    assert not any("kashif-404" in p for p in paths)                      # no random path outside deep (§3.2)
    assert "/a" not in paths and "/sitemap.xml" not in paths               # no crawl, no sitemap without --crawl
    cors = [h for p, h in reqs if "origin" in h]
    assert len(cors) == 1 and cors[0]["origin"] == CORS_PROBE_ORIGIN and "cookie" not in cors[0]
    later = [h for p, h in reqs[1:] if "origin" not in h]
    assert later and all("sid=" in h.get("cookie", "") for h in later)    # the in-memory jar, same host only
    for _p, h in reqs:
        assert set(h) <= ALLOWED_HEADERS, h
        assert h["user-agent"].startswith("Kashif/") and h["accept-encoding"] == "gzip, deflate"


def test_deep_profile_stays_within_its_budget_and_the_never_list(site):
    site.routes["/.git/HEAD"] = reply(headers=[("Content-Type", "text/plain")], body="ref: refs/heads/main\n")
    res = scan(site, profile="deep")
    paths = [p for p, _ in requests_of(site)]
    assert len(paths) <= 150
    assert any("/kashif-404-" in p for p in paths) and "/.git/HEAD" in paths
    assert not any(re.search(r"heapdump|threaddump|pprof", p) for p in paths)
    git = [f for f in res.findings if f.rule_id == "WEB062" and ".git/HEAD" in f.snippet]
    assert git and git[0].snippet.startswith("/.git/HEAD → HTTP 200")


def test_crawl_honours_robots_skip_link_and_counts_pages(site):
    from vulnscan import web
    findings, note, pages = web.scan_site(site.url_for(), crawl=True, max_pages=10, max_depth=2, delay=0.2)
    paths = [p for p, _ in requests_of(site)]
    assert "/a" in paths and "/b" in paths
    assert "/private/x" not in paths and "/logout" not in paths            # robots Disallow and SKIP_LINK
    assert pages == 3 and isinstance(note, str) and "زحف" in note


# ----------------------------------------------------------------------------------------------- findings

def test_issue_to_finding_conversion(site):
    res = scan(site)
    assert res.findings and all(isinstance(f, Finding) for f in res.findings)
    sev = [rules.SEVERITIES.index(f.severity) for f in res.findings]
    assert sev == sorted(sev)                                               # most severe first
    for f in res.findings:
        meta = rules.RULES[f.rule_id]
        x = f.extra
        assert f.source == "web" and f.file == f"{HOST}:{site.port}" and f.line == 0
        assert f.title and f.title_ar and f.advice and f.cwe == meta.cwe
        assert f.severity in meta.allowed_severities and x["confidence"] in meta.allowed_confidences
        assert x["confidence"] in SENSITIVITY_CONFIDENCES["default"]
        for key in ("wstg", "asvs4", "asvs5", "evidence", "fp_key", "examples", "instances", "systemic", "kind",
                    "role", "remediation", "pages", "page_count", "advice_en", "notes"):
            assert key in x, (f.rule_id, key)
        assert x["fp_key"].startswith(f"{f.rule_id}|") and x["remediation"] == list(meta.fix)
        assert x["evidence"]["observed_at"].endswith("Z")
        if x["evidence"].get("curl"):
            assert x["evidence"]["curl"].startswith("curl ")
        assert "{" not in f.title and "{" not in f.advice                    # every placeholder was filled
    ids = {f.rule_id for f in res.findings}
    assert {"WEB051", "WEB010", "WEB021", "WEB000"} <= ids
    ck = [f for f in res.findings if f.rule_id == "WEB021"][0]
    assert "0123456789abcdef" not in json.dumps(ck.to_dict(), ensure_ascii=False)   # cookie values never in evidence


def test_fingerprints_are_stable_across_reruns(site):
    a = scan(site)
    b = scan(site)
    assert sorted(f.extra["fp_key"] for f in a.findings) == sorted(f.extra["fp_key"] for f in b.findings)
    assert sorted(f.fingerprint() for f in a.findings) == sorted(f.fingerprint() for f in b.findings)


def test_sensitivity_filters_by_confidence(site):
    strict = scan(site, sensitivity="strict")
    paranoid = scan(site, sensitivity="paranoid")
    assert strict.findings and all(f.extra["confidence"] == "certain" for f in strict.findings)
    assert {f.extra["fp_key"] for f in strict.findings} <= {f.extra["fp_key"] for f in paranoid.findings}
    with pytest.raises(ValueError):
        engine.scan(site.url_for(), ScanOptions(sensitivity="loud"))


def test_result_carries_grades_coverage_inventory_and_notes(site):
    res = scan(site)
    assert set(res.grades) == {"kashif", "observatory", "ssllabs"} and res.grades["kashif"]["grade"]
    states = {c["check"]: c["state"] for c in res.coverage["checks"]}
    assert set(states) >= set(rules.all_check_ids())
    assert sum(res.coverage["counts"].values()) == len(states)
    assert res.notes[0].startswith("فحص ويب سلبي بالملف standard")
    assert any(n.startswith("التغطية: ") for n in res.notes)
    inv = res.inventory
    assert inv["notes"][0]["en"].startswith("Passive web scan, profile standard") and "engine_errors" not in inv
    assert inv["requests"]["requests"] == res.requests and inv["redirect_chain"][0]["status"] == 200
    assert res.snapshot["target"] and res.diff is None and res.data_date


def test_snapshot_feeds_the_diff_of_the_next_scan(site):
    first = scan(site)
    second = engine.scan(site.url_for(), ScanOptions(delay=0.2, timeout=5), previous=first.snapshot)
    d = second.diff
    assert d["comparable"] and not d["findings"]["new"] and len(d["findings"]["unchanged"]) == len(second.findings)


# ----------------------------------------------------------------------------------------------- honest results

def test_waf_challenge_entry_gives_web990_and_no_letter_grade(raw_http_server):
    srv = raw_http_server
    srv.routes["/"] = reply("403 Forbidden", [HTML, ("Server", "cloudflare"), ("cf-mitigated", "challenge")],
                            "<html><head><title>Just a moment...</title></head><body></body></html>")
    res = engine.scan(f"http://{HOST}:{srv.port}/", ScanOptions(delay=0.2, timeout=5))
    ids = {f.rule_id for f in res.findings}
    assert "WEB990" in ids and res.grades["kashif"]["grade"] == "?"
    assert not ids & {"WEB-content-security-policy", "WEB-x-frame-options", "WEB-x-content-type-options"}
    assert len(srv.requests) == 1                                          # no optional request behind a challenge
    w = [f for f in res.findings if f.rule_id == "WEB990"][0]
    assert any("Cloudflare" in n["en"] for n in w.extra["notes"])


def test_unreadable_response_is_a_note_not_silence(site):
    site.routes["/robots.txt"] = reply(headers=[("Content-Type", "text/plain")] + [(f"X-F-{i}", "x") for i in range(120)],
                                       body="User-agent: *\n")
    res = scan(site)
    assert any("too many headers" in n["en"] for n in res.inventory["notes"])


def test_a_failing_check_module_is_isolated(site, monkeypatch):
    from vulnscan.webscan import headers
    monkeypatch.delenv("KASHIF_DEBUG")

    def boom(ctx):
        raise RuntimeError("bug")
    monkeypatch.setattr(headers, "run", boom)
    res = scan(site)
    states = {c["check"]: c for c in res.coverage["checks"]}
    assert states["WEB-x-frame-options"]["state"] == "not_tested"
    assert states["WEB-x-frame-options"]["reasons"][0]["code"] == "error"
    assert res.inventory["engine_errors"][0]["module"] == "headers"
    assert any(f.rule_id == "WEB051" for f in res.findings)                # the other modules still ran
    assert any(f.rule_id == "WEB991" for f in res.findings)                # and the gap is reported, never a pass


def test_paranoid_only_checks_do_not_make_the_grade_provisional():
    from vulnscan.webscan.coverage import Coverage
    cov = Coverage(["WEB409", "WEB020", "WEB705"])
    cov.not_tested("WEB409", "sensitivity")
    cov.not_applicable("WEB020")
    cov.not_tested("WEB705", "network")
    st = engine._grade_states(cov)
    assert st == {"WEB409": "not_applicable", "WEB020": "not_applicable", "WEB705": "not_tested"}


def test_unreachable_and_invalid_targets_raise():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(engine.WebUnreachable) as ei:
        engine.scan(f"http://127.0.0.1:{port}/", ScanOptions(delay=0.2, timeout=2))
    assert "لم يُفحص" in str(ei.value)
    for bad in ("ftp://example.org/", "file:///etc/passwd", "http://", "javascript:alert(1)"):
        with pytest.raises(engine.WebUnreachable):
            engine.scan(bad)


# ----------------------------------------------------------------------------------------------- offline helpers

def test_analyze_responses_needs_no_network():
    resp = Response(url="https://shop.example.org/", status=200, headers=HeaderList((HTML,)),
                    body=b'<img src="http://img.example.org/a.png"><script src="https://cdn.other-site.net/a.js"></script>')
    findings, ctx = engine.analyze_responses(resp.url, resp, ScanOptions(), modules=("content",))
    assert {"WEB050", "WEB053"} <= {f.rule_id for f in findings} and ctx.pages[0].response is resp


def test_engine_notes_translate_to_english():
    from vulnscan.i18n import to_en
    from vulnscan.i18n import cat_web2
    cat_web2.ensure_loaded()
    for n in (3, 11, 101):
        ar = engine.text("profile", "ar", profile="standard", requests=engine._count("requests", n, "ar"))
        assert to_en(ar) == engine.text("profile", "en", profile="standard", requests=engine._count("requests", n, "en"))
    for key, (en, ar) in engine.STR.items():
        if "{" not in ar:
            assert to_en(ar) == en, key


def test_http_target_without_an_https_check_has_a_provisional_grade(site):
    """Non-default port: the https counterpart is never contacted (§0.1), so TLS is unknown, not "not applicable"."""
    res = scan(site)
    states = {c["check"]: c for c in res.coverage["checks"]}
    assert states["WEB705"]["state"] == "not_tested"
    assert any("non-default port" in r["en"] for r in states["WEB705"]["reasons"])
    assert res.grades["kashif"]["provisional"] and res.grades["kashif"]["grade"].endswith("*")
    minimal = scan(site, profile="minimal")
    assert "profile" in {r["code"] for r in {c["check"]: c for c in minimal.coverage["checks"]}["WEB705"]["reasons"]}


def test_time_budget_gives_a_partial_result_not_an_error(site):
    res = scan(site, crawl=True, time_budget=0.7)
    assert res.findings and res.requests < 10
    assert any("time budget" in n["en"] for n in res.inventory["notes"])


def test_entry_cut_by_the_deadline_is_not_fetched_again_for_cors(site, monkeypatch):
    """Phase D (C-HOSTILE slow drip took two deadlines): after the entry URL hit the per-response deadline, the CORS GET
    of the same URL is not sent (it could only wait another deadline); the CORS checks are not_tested ("timeout")."""
    import dataclasses

    from vulnscan.webscan import http as _http
    real = _http.Fetcher.fetch
    sources = []

    def fetch(self, url, *, source="entry", **kw):
        sources.append(source)
        r = real(self, url, source=source, **kw)
        return dataclasses.replace(r, flags=r.flags | {"deadline"}) if source == "entry" else r
    monkeypatch.setattr(_http.Fetcher, "fetch", fetch)
    res = scan(site, profile="standard")
    assert "cors" not in sources and "wellknown" in sources
    assert not any("origin" in h for _p, h in requests_of(site))
    states = {c["check"]: c for c in res.coverage["checks"]}
    assert states["WEB320"]["state"] == "not_tested"
    assert "timeout" in {r["code"] for r in states["WEB320"]["reasons"]}
