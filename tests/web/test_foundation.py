"""WP0 foundation: frozen interfaces (types.py and the phase-B stubs), the data loader and data-file schemas,
and the coverage recorder."""

from __future__ import annotations

import gzip
import hashlib
import inspect
import json
import shlex
import subprocess
import sys

import pytest

from vulnscan.webscan import classify, cookies, coverage, csp, data, rules, simhash, transport
from vulnscan.webscan.types import (CheckModule, CookieFact, Evidence, HeaderList, Issue, Page, Response, ScanContext,
                                    ScanOptions, curl_command, normalise_charset, openssl_command, redact_secret,
                                    strip_controls, url_origin, user_agent)

# ----------------------------------------------------------------------------------------------- types


def test_headerlist_keeps_order_case_and_duplicates():
    h = HeaderList.of(("Set-Cookie", "a=1"), ("X-A", "1"), ("set-cookie", "b=2"))
    assert h.get_all("SET-COOKIE") == ["a=1", "b=2"] and h.first("x-a") == "1" and h.first("nope") is None
    assert h.has("x-a") and not h.has("x-b") and h.count("set-cookie") == 2
    assert h.joined("set-cookie") == "a=1, b=2" and h.joined("nope") is None
    assert h.names() == ["set-cookie", "x-a"] and len(h) == 3 and list(h)[0] == ("Set-Cookie", "a=1")
    assert HeaderList.from_mapping({"A": ["1", "2"], "B": "3"}).items == (("A", "1"), ("A", "2"), ("B", "3"))
    with pytest.raises(AttributeError):
        h.items = ()          # frozen


def test_response_identity_hash_and_helpers():
    r1 = Response("https://WWW.Example.test:443/a?b#c")
    r2 = Response("https://WWW.Example.test:443/a?b#c")
    assert r1 != r2 and len({r1: 1, r2: 2}) == 2          # eq=False: usable as dict keys (ctx.csp)
    assert r1.host == "www.example.test" and r1.is_https and r1.origin == "https://www.example.test"
    hop = Response("http://a.test/", status=301, headers=HeaderList.of(("Location", "/b")))
    final = Response("http://a.test/b", chain=[hop])
    assert hop.location == "http://a.test/b" and hop.is_redirect and final.hops() == [hop, final]
    assert url_origin("http://[::1]:8080/x") == "http://[::1]:8080"


@pytest.mark.parametrize("headers,body,expected", [
    ((("Content-Type", "text/html; charset=windows-1256"),), "عربي".encode("cp1256"), "عربي"),
    ((("Content-Type", 'text/html; charset="UTF-8"'),), "é".encode(), "é"),
    ((), b'<meta charset="iso-8859-1"><p>\xe9', '<meta charset="iso-8859-1"><p>é'),
    ((("Content-Type", "text/html; charset=latin1"),), b"\x93q\x94", "“q”"),   # latin1 = windows-1252
    ((), b"\xef\xbb\xbfbom", "bom"),
    ((("Content-Type", "text/html; charset=utf-8"),), b"\xff\xfeh\x00i\x00", "hi"),    # BOM beats the header
    ((("Content-Type", "text/html; charset=bogus-xyz"),), b"\xc3\xa9", "é"),            # unknown label → UTF-8
    ((), b"bad \xff byte", "bad � byte"),
])
def test_response_text_charset_detection(headers, body, expected):
    assert Response("https://a.test/", headers=HeaderList.of(*headers), body=body).text() == expected


def test_charset_label_normalisation():
    assert normalise_charset("utf8") == normalise_charset('"UTF-8"') == "UTF-8"
    assert normalise_charset("ISO-8859-1") == "windows-1252" and normalise_charset("shift_jis") == "Shift_JIS"
    assert normalise_charset("nonsense") is None and normalise_charset("") is None


def test_user_agent_is_honest():
    from vulnscan import __version__
    ua = user_agent()
    assert ua == f"Kashif/{__version__} (+https://abdulrahmanahmedelabed-prog.github.io/vulnscan/scanner.html)"
    assert "vulnscan" in ua and "Mozilla" not in ua and "github.com" not in ua


def test_evidence_redacts_cookies_and_quotes_commands(fixed_now):
    resp = Response("http://x.test/'$(id)'\n a", status=200,
                    headers=HeaderList.of(("Set-Cookie", "sid=supersecretvalue123; Path=/; HttpOnly"), ("Server", "x")),
                    request_headers=HeaderList.of(("User-Agent", "Kashif/1.1.0"), ("Cookie", "should-not-appear"),
                                                  ("Origin", "https://kashif-cors-check.invalid")),
                    body=b"hello")
    ev = Evidence.for_response(resp, where="header", name="Server", value="x" * 500, now=fixed_now)
    d = ev.to_dict()
    assert ["Set-Cookie", "sid=<redacted:19 bytes>; Path=/; HttpOnly"] in d["headers"]
    assert "supersecretvalue123" not in json.dumps(d)
    assert all(k.lower() != "cookie" for k, _ in d["request"]["headers"])
    assert len(d["match"]["value"]) == 300 and d["observed_at"] == "2026-11-13T12:00:00Z"
    assert d["body_sha256"] == hashlib.sha256(b"hello").hexdigest()
    argv = shlex.split(d["curl"])                                    # a crafted URL stays one argument
    assert argv[:6] == ["curl", "-sS", "-D", "-", "-o", "/dev/null"] and argv[-1].startswith("http://x.test/")
    assert "\n" not in argv[-1] and " " not in argv[-1] and "Origin: https://kashif-cors-check.invalid" in argv
    assert shlex.split(openssl_command("a.test", "2001:db8::1", 443, "-tls1")) == [
        "openssl", "s_client", "-connect", "[2001:db8::1]:443", "-servername", "a.test", "-tls1"]
    assert curl_command("https://a.test/", user_agent_value="UA").endswith("-A UA https://a.test/")


def test_secret_redaction_and_control_stripping():
    assert redact_secret("AKIAABCDEFGHIJKLMNOP") == "AKIA…OP" and redact_secret("short") == "*****"
    assert strip_controls("ok\x1b[31mred\x1b[0m\x07\x9b\ttab\nnl") == "okred\ttab\nnl"


def test_cookie_fact_redaction():
    r = Response("https://a.test/")
    c = CookieFact("sid", "abc123", {"secure": "", "samesite": "Lax", "domain": ".Example.test"}, "sid=abc123; Secure",
                   r, "a.test", True, cls="session")
    assert c.redacted() == "sid=<redacted:6 bytes>; Secure"
    assert c.secure and not c.httponly and c.samesite == "Lax" and c.domain == "example.test" and c.is_session_class


def test_scan_options_and_sensitivity():
    o = ScanOptions()
    assert (o.profile, o.sensitivity, o.delay, o.max_pages, o.max_bytes, o.lang) == ("standard", "default", 0.5, 20,
                                                                                     50_000_000, "ar")
    assert o.reports("firm") and not o.reports("tentative")
    assert ScanOptions(sensitivity="strict").reports("certain") and not ScanOptions(sensitivity="strict").reports("firm")
    assert ScanOptions(sensitivity="paranoid").reports("tentative") and ScanOptions(profile="deep").deep


def test_scan_context_all_responses_and_lookups(make_ctx, make_page, make_response):
    hop = make_response("http://example.test/", status=301, headers={"Location": "https://example.test/"})
    page = make_page("<p>x</p>", chain=[hop])
    sub = make_response("https://example.test/app.js", content_type="text/javascript", source="subresource")
    ctx = make_ctx(entry=page, subresources=[sub], wellknown={"/robots.txt": make_response("https://example.test/robots.txt")})
    rs = ctx.all_responses()
    assert hop in rs and page.response in rs and sub in rs and len(rs) == 4
    assert hop not in ctx.all_responses(include_hops=False)
    assert ctx.page_for(page.response) is page and ctx.target_host == "example.test"
    assert ctx.hsts_for("EXAMPLE.test.") is None and ctx.csp_for(page.response) is None
    assert ctx.now.tzinfo is not None


def test_check_module_protocol():
    class Mod:
        CHECKS = ("WEB000",)

        def run(self, ctx):
            return []
    assert isinstance(Mod(), CheckModule)
    assert isinstance(csp, CheckModule) and isinstance(cookies, CheckModule) and isinstance(transport, CheckModule)


def test_frozen_stub_signatures():
    """Phase-B modules implement these exact signatures (spec §4.2); the stubs were created by WP0."""
    def params(fn):
        return [(p.name, p.kind.name) for p in inspect.signature(fn).parameters.values()]
    assert params(classify.signature) == [("response", "POSITIONAL_OR_KEYWORD")]
    assert params(classify.similar) == [("a", "POSITIONAL_OR_KEYWORD"), ("b", "POSITIONAL_OR_KEYWORD")]
    assert params(classify.is_sensitive) == [("response", "POSITIONAL_OR_KEYWORD"), ("cookies", "KEYWORD_ONLY"),
                                             ("doc", "KEYWORD_ONLY")]
    assert params(simhash.simhash64) == [("features", "POSITIONAL_OR_KEYWORD")]
    assert params(csp.parse_all) == params(transport.hsts_facts) == params(cookies.parse_and_classify) == [
        ("ctx", "POSITIONAL_OR_KEYWORD")]
    assert csp.CHECKS == rules.checks_for_module("csp") and cookies.CHECKS == rules.checks_for_module("cookies")
    assert simhash.hamming(0b1011, 0b0001) == 2 and simhash.hamming(0, (1 << 64) - 1) == 64


def test_importing_the_package_stays_light():
    code = ("import sys, vulnscan.webscan, vulnscan.webscan.rules, vulnscan.webscan.types; "
            "bad=[m for m in ('vulnscan.webscan.engine','vulnscan.webscan.http','vulnscan.web','vulnscan.model') "
            "if m in sys.modules]; print(bad)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "[]"


def test_issue_defaults():
    i = Issue("WEB010", "https://a.test/", "certain", Evidence(), {"value": "nginx/1.2"})
    assert i.severity is None and i.group_value == "" and i.notes == [] and rules.validate_issue(i) == []
    assert Page(Response("https://a.test/"), None).depth == 0
    assert ScanContext(ScanOptions(), "https://a.test/").cookies == []


# ----------------------------------------------------------------------------------------------- data files

M = {"schema_version": 1, "date": "2026-11-13", "source": "https://example.invalid/src", "license": "MIT"}
SIG = {"all": [{"type": "regex", "pattern": "^ref: refs/", "flags": "m"}]}
DEEP = {"path": "/.git/HEAD", "rule": "WEB062", "severity": "high", "cwe": "CWE-527", "kinds": ["text", "download"],
        "signature": SIG, "strength": "strong", "title_en": "Exposed .git repository", "title_ar": "مستودع .git مكشوف",
        "advice_en": "Block .git.", "advice_ar": "امنع الوصول إلى .git."}
EXAMPLES = {
    "retire-jsrepository.json.gz": {"meta": M, "repository": {"jquery": {
        "vulnerabilities": [{"below": "1.6.3", "severity": "medium", "identifiers": {"CVE": ["CVE-2011-4969"]}}],
        "extractors": {"uri": ["/(§§version§§)/jquery(\\.min)?\\.js"]}}}},
    "csp-bypass.json": {"meta": M, "jsonp": ["//www.google.com/complete/search"], "angular": ["//ajax.googleapis.com"]},
    "hsts-preload.json.gz": {"meta": M, "tlds": ["dev", "app"], "entries": {"example.com": True, "a.example": False}},
    "psl.dat.meta.json": {"meta": M, "file": "psl.dat.gz", "sha256": "0" * 64, "rules": 9000},
    "cookies.json": {"meta": M, "entries": [{"name": "PHPSESSID", "match": "exact", "class": "session"},
                                            {"name": "_ga_*", "match": "glob", "class": "analytics", "source": "ocd"}]},
    "tech.json": {"meta": M, "technologies": [{
        "id": "wordpress", "name": "WordPress", "categories": ["cms"], "cpe": "cpe:2.3:a:wordpress:wordpress",
        "implies": ["php"], "excludes": [], "eol_product": "wordpress",
        "signals": [{"source": "meta", "name": "generator", "pattern": "WordPress ([\\d.]+)", "version": "\\1",
                     "confidence": 100}],
        "deep_paths": [{**DEEP, "path": "/wp-content/debug.log", "rule": "WEB082", "cwe": "CWE-532",
                        "signature": {"any": [{"type": "regex", "pattern": "PHP (Warning|Fatal error|Notice)"}]},
                        "strength": "weak"}]}]},
    "favicons.json": {"meta": M, "hashes": [{"hash": -156908512, "tech": "example"}]},
    "eol.json": {"meta": M, "products": {"php": {"cycles": [{"cycle": "7.4", "eol": "2022-11-28", "latest": "7.4.33"},
                                                           {"cycle": "8.4", "eol": False, "latest": "8.4.1"}]}}},
    "server-cve.json": {"meta": M, "products": {"nginx": [{"id": "CVE-2021-23017", "severity": "high", "cvss": 7.7,
                                                           "ranges": [{"at_or_above": "0.6.18", "below": "1.20.1"}],
                                                           "fixed": "1.20.1", "summary": "resolver off-by-one"}]}},
    "error-signatures.json": {"meta": M, "signatures": [{"id": "py-traceback", "rule": "WEB056", "platform": "python",
                                                         "signature": {"all": [{"type": "contains",
                                                                                "pattern": "Traceback (most recent call last):"}]}}]},
    "leak-headers.json": {"meta": M, "headers": [{"name": "X-AspNet-Version", "match": "exact", "rule": "WEB600"},
                                                 {"name": "X-Debug-", "match": "prefix", "rule": "WEB601"}]},
    "secret-rules.json": {"meta": M, "sec_rules": ["SEC001"], "extra": [], "publishable": ["^pk_live_"]},
    "malicious-hosts.json": {"meta": M, "hosts": [{"host": "polyfill.io", "match": "suffix", "reason": "supply-chain 2024"}],
                             "signatures": [{"id": "coinhive", "kind": "miner", "pattern": "CoinHive\\.Anonymous"}]},
    "takeover.json": {"meta": M, "providers": [{"name": "GitHub Pages", "cname": ["github.io"],
                                                "fingerprints": ["There isn't a GitHub Pages site here."], "status": 404,
                                                "vulnerable": True}]},
    "exposed-paths.json": {"meta": M, "paths": [DEEP]},
    "ct-logs.json": {"meta": M, "logs": {"A" * 43 + "=": {"operator": "Example CT", "state": "usable"}}},
    "tls-profiles.json": {"meta": M, "profiles": {k: {
        "tls_versions": ["TLSv1.2", "TLSv1.3"], "ciphersuites": ["TLS_AES_128_GCM_SHA256"], "ciphers": {"iana": []},
        "tls_curves": ["X25519"], "certificate_types": ["ecdsa"], "rsa_key_size": 2048, "maximum_certificate_lifespan": 366,
        "ocsp_staple": False} for k in ("intermediate", "modern")}},
    "observatory-v6.json": {"meta": M, "algorithm_version": 6, "max_score": 165, "extra_credit_threshold": 90,
                            "tests": {"strict-transport-security": {"hsts-not-implemented": -20}},
                            "grade_chart": {"100": "A+", "90": "A", "0": "F"}},
}


def test_every_schema_has_a_valid_example():
    assert set(EXAMPLES) == set(data.SCHEMAS)
    for name, obj in EXAMPLES.items():
        assert data.validate_data(name, obj) == [], name
    assert set(data.DATA_FILES) == (set(data.SCHEMAS) - {"psl.dat.meta.json"}) | {"psl.dat.gz"}


@pytest.mark.parametrize("name,mutate,needle", [
    ("exposed-paths.json", lambda o: o["paths"][0].pop("signature"), "missing 'signature'"),
    ("exposed-paths.json", lambda o: o["paths"][0].update(path="no-slash"), "does not match"),
    ("exposed-paths.json", lambda o: o["paths"][0].update(signature={"none": []}), "matches none"),
    ("exposed-paths.json", lambda o: o.update(paths=[o["paths"][0]] * 41), "more than 40"),
    ("tech.json", lambda o: o["technologies"][0]["deep_paths"][0].update(rule="WEB062x"), "not one of"),
    ("cookies.json", lambda o: o["entries"][0].update(**{"class": "unknown"}), "not one of"),
    ("favicons.json", lambda o: o["hashes"][0].update(hash=2 ** 31), "> 2147483647"),
    ("csp-bypass.json", lambda o: o.update(extra=1), "unexpected key"),
    ("ct-logs.json", lambda o: o["logs"].update(bad={"operator": "x", "state": "usable"}), "does not match"),
    ("server-cve.json", lambda o: o["products"]["nginx"][0].update(severity="info"), "not one of"),
    ("observatory-v6.json", lambda o: o["grade_chart"].update({"50": "E"}), "does not match"),
    ("csp-bypass.json", lambda o: o["meta"].update(date="13/11/2026"), "does not match"),
    ("csp-bypass.json", lambda o: o["meta"].update(schema_version=2), "schema_version 2"),
    ("eol.json", lambda o: o["products"]["php"]["cycles"][0].update(eol=True or 1, cycle=""), "shorter than 1"),
])
def test_schema_rejects_bad_data(name, mutate, needle):
    obj = json.loads(json.dumps(EXAMPLES[name]))
    mutate(obj)
    errs = data.validate_data(name, obj)
    assert errs and any(needle in e for e in errs), errs


def test_every_bundled_file_validates():
    for p in sorted(data.BUNDLED_DIR.iterdir()):
        if p.name in data.SCHEMAS:
            assert data.validate_file(p) == [], p.name


def _install_user_snapshot(home, day, files: dict[str, bytes], schema=1, bad_hash: str = ""):
    d = home / "webdata" / day
    d.mkdir(parents=True)
    manifest = {"schema_version": schema, "generated": day, "files": {}}
    for name, raw in files.items():
        (d / name).write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest() if name != bad_hash else "0" * 64
        manifest["files"][name] = {"sha256": digest, "size": len(raw)}
    (d / "MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
    return d


def test_user_snapshot_preferred_only_when_newer_valid_and_verified(tmp_path, monkeypatch):
    monkeypatch.setenv("KASHIF_HOME", str(tmp_path))
    newer = dict(EXAMPLES["csp-bypass.json"], meta=dict(M, date="2099-01-01"))
    raw = json.dumps(newer).encode()
    gz = gzip.compress(json.dumps(EXAMPLES["hsts-preload.json.gz"]).encode(), mtime=0)
    d = _install_user_snapshot(tmp_path, "2099-01-01", {"csp-bypass.json": raw, "hsts-preload.json.gz": gz,
                                                        "eol.json": b"{}"}, bad_hash="eol.json")
    data.clear_cache()
    assert data.user_dir() == d
    assert data.path_for("csp-bypass.json") == (d / "csp-bypass.json", "user")
    assert data.load_json("csp-bypass.json")["meta"]["date"] == "2099-01-01"
    assert data.load_json("hsts-preload.json.gz")["tlds"] == ["dev", "app"]           # .gz handled
    assert data.path_for("eol.json")[1] == "bundled"                                  # sha256 mismatch → bundled
    assert data.path_for("psl.dat.gz")[1] == "bundled"                                # not in the user manifest
    assert data.file_date("csp-bypass.json").isoformat() == "2099-01-01"


def test_user_snapshot_ignored_when_old_or_other_schema(tmp_path, monkeypatch):
    monkeypatch.setenv("KASHIF_HOME", str(tmp_path))
    raw = json.dumps(EXAMPLES["csp-bypass.json"]).encode()
    _install_user_snapshot(tmp_path, "2000-01-01", {"csp-bypass.json": raw})
    _install_user_snapshot(tmp_path, "2099-02-02", {"csp-bypass.json": raw}, schema=2)
    data.clear_cache()
    assert data.user_dir() is None and data.path_for("csp-bypass.json")[1] == "bundled"


def test_invalid_user_file_falls_back_to_bundled_psl_sidecar(tmp_path, monkeypatch):
    monkeypatch.setenv("KASHIF_HOME", str(tmp_path))
    broken = json.dumps({"meta": M, "file": "psl.dat.gz"}).encode()      # fails the schema
    _install_user_snapshot(tmp_path, "2099-03-03", {"psl.dat.meta.json": broken})
    data.clear_cache()
    assert data.path_for("psl.dat.meta.json")[1] == "user"
    assert data.load_json("psl.dat.meta.json")["file"] == "psl.dat.gz"
    assert data.validate_data("psl.dat.meta.json", data.load_json("psl.dat.meta.json")) == []


def test_staleness_notes(monkeypatch):
    from datetime import date, datetime, timezone
    dates = {"psl.dat.gz": date(2026, 1, 1), "server-cve.json": date(2026, 1, 1)}
    monkeypatch.setattr(data, "file_date", lambda name: dates.get(name))
    monkeypatch.setattr(data, "available", lambda name: name in dates)
    assert data.staleness(datetime(2026, 2, 1, tzinfo=timezone.utc)) == []
    notes = data.staleness(datetime(2026, 11, 13, tzinfo=timezone.utc))
    codes = {n["code"]: n for n in notes}
    assert set(codes) == {"data_old", "vuln_data_old"}
    assert "316 days ago" in codes["data_old"]["en"] and "قبل 316 يومًا" in codes["data_old"]["ar"]
    assert codes["vuln_data_old"]["rules"] == ("WEB800",)
    assert data.as_of("en") == "web data as of 2026-01-01" and data.as_of("ar") == "بيانات الويب بتاريخ 2026-01-01"


def test_bundled_snapshot_date_is_known():
    assert data.snapshot_date() is not None
    assert data.meta("psl.dat.gz")["license"] == "MPL-2.0"
    assert data.meta("missing.json") == {}


# ----------------------------------------------------------------------------------------------- coverage

def test_coverage_defaults_to_not_tested_never_pass():
    cov = coverage.Coverage()
    assert set(cov.states()) == set(rules.all_check_ids())
    assert cov.state("WEB000").state == "not_tested" and not cov.tested("WEB000")
    assert cov.counts()["not_tested"] == len(rules.all_check_ids())


def test_coverage_precedence_and_hosts():
    cov = coverage.Coverage(["A", "B", "C", "D"])
    cov.passed("A", host="x")
    cov.not_tested("A", "proxied", host="y")
    cov.passed("B", host="x")
    cov.failed("B", host="y")
    cov.inconclusive("B", "waf", host="z", detail_en="Cloudflare")
    cov.not_applicable("C", "http_only")
    cov.passed("C")
    cov.not_applicable("D")
    a, b, c = cov.state("A"), cov.state("B"), cov.state("C")
    assert a.state == "not_tested" and a.hosts == {"x": "pass", "y": "not_tested"}
    assert a.reasons == [("proxied", "scanning through a proxy", "الفحص يمر عبر وكيل (proxy)")]
    assert b.state == "fail" and b.reasons[0][1] == "a WAF challenge answered instead of the site: Cloudflare"
    assert c.state == "pass" and cov.tested("C") and cov.state("D").state == "not_applicable"
    assert cov.counts() == {"pass": 1, "fail": 1, "not_applicable": 1, "not_tested": 1, "inconclusive": 0}
    with pytest.raises(ValueError):
        cov.record("A", "ok")


def test_coverage_summary_both_languages_with_agreement():
    cov = coverage.Coverage([f"C{i}" for i in range(115)])
    for i in range(100):
        cov.passed(f"C{i}")
    for i in range(100, 111):
        cov.failed(f"C{i}")
    cov.not_applicable("C111")
    cov.not_tested("C112", "deep_off")
    cov.not_tested("C113", "tls13_encrypted")
    cov.inconclusive("C114", "rate_limited")
    assert cov.summary("en") == "100 passed · 11 failed · 1 not applicable · 2 not tested · 1 inconclusive"
    assert cov.summary("ar") == ("100 فحص ناجح · 11 فحصًا فاشلًا · فحص واحد غير منطبق · فحصان لم يُجرَيا · "
                                 "فحص واحد غير حاسم")
    assert [s.check_id for s in cov.skipped_for_limitations()] == ["C113", "C114"]     # deep_off is the user's choice
    lines = cov.reasons("en")
    assert "C112: not tested — deep mode off" in lines and "C113: not tested — encrypted in TLS 1.3" in lines
    assert "C113: لم يُجرَ — مشفّر في TLS 1.3" in cov.reasons("ar")
    d = cov.to_dict()
    assert d["counts"]["fail"] == 11 and len(d["checks"]) == 115


def test_every_reason_has_both_languages():
    for code, (en, ar, user) in coverage.REASONS.items():
        assert en and ar and isinstance(user, bool), code
        assert any("؀" <= ch <= "ۿ" for ch in ar), code


# ----------------------------------------------------------------------------------------------- test harness

def test_offline_guard_blocks_non_loopback():
    import socket
    with pytest.raises(RuntimeError, match="offline"):
        socket.getaddrinfo("example.com", 443)
    with pytest.raises(RuntimeError, match="offline"):
        socket.gethostbyname_ex("example.com")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(RuntimeError, match="offline"):
            s.connect(("192.0.2.1", 80))
    finally:
        s.close()
    assert socket.getaddrinfo("127.0.0.1", 80)          # loopback and IP literals stay allowed


def test_raw_http_server_serves_exact_bytes(raw_http_server, http_reply_builder):
    import http.client
    raw_http_server.routes["/dup"] = http_reply_builder("200 OK", [("Set-Cookie", "a=1"), ("Set-Cookie", "b=2"),
                                                                   ("Content-Type", "text/plain")], "hi")
    conn = http.client.HTTPConnection("127.0.0.1", raw_http_server.port, timeout=5)
    try:
        conn.request("GET", "/dup", headers={"User-Agent": user_agent()})
        resp = conn.getresponse()
        assert resp.status == 200 and resp.read() == b"hi"
        assert resp.headers.get_all("Set-Cookie") == ["a=1", "b=2"]
    finally:
        conn.close()
    assert raw_http_server.requests and raw_http_server.requests[0].startswith(b"GET /dup HTTP/1.1\r\n")
    conn = http.client.HTTPConnection("127.0.0.1", raw_http_server.port, timeout=5)
    try:
        conn.request("GET", "/missing")
        assert conn.getresponse().status == 404
    finally:
        conn.close()


def _lookup(text, catalog, patterns):
    import re
    if text in catalog:
        return catalog[text]
    for rx, en in patterns:
        m = re.fullmatch(rx, text, re.S)
        if m:
            return re.sub(r"\\g<(\w+)>", lambda g: m.groupdict().get(g.group(1)) or "", en)
    return None


def test_data_and_coverage_texts_have_catalogue_entries(monkeypatch):
    from datetime import date, datetime, timezone
    catalog, patterns = data.i18n_catalog()
    for age, day in ((1, date(2026, 11, 12)), (2, date(2026, 11, 11)), (95, date(2026, 8, 10)), (316, date(2026, 1, 1))):
        dates = {"psl.dat.gz": day, "eol.json": date(2026, 1, 1)}
        monkeypatch.setattr(data, "file_date", lambda name, d=dates: d.get(name))
        monkeypatch.setattr(data, "available", lambda name, d=dates: name in d)
        for note in data.staleness(datetime(2026, 11, 13, tzinfo=timezone.utc)):
            assert _lookup(note["ar"], catalog, patterns) == note["en"], note
        assert _lookup(data.as_of("ar"), catalog, patterns) == data.as_of("en")
    cov_catalog, _ = coverage.i18n_catalog()
    for en, ar, _user in coverage.REASONS.values():
        assert cov_catalog[ar] == en
