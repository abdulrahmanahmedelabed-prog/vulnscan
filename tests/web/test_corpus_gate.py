"""The passive web corpus, its scorer, the ZAP harness and the accuracy gate (spec §5.2–§5.5, WP16).

Everything here runs offline against servers on 127.0.0.1 started by the test itself. The full corpus gate
(``test_full_corpus_gate``) needs the assembled 1.1 engine; until then it is skipped with that reason.
"""

from __future__ import annotations

import http.client
import importlib
import json
import pathlib
import re
import socket
import ssl
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
BENCH = ROOT / "bench" / "web"
sys.path.insert(0, str(BENCH))

corpus = importlib.import_module("corpus")
score = importlib.import_module("score")
run_zap = importlib.import_module("run_zap")
run_kashif = importlib.import_module("run_kashif")
tls_servers = importlib.import_module("tls_servers")

# Every rule id of the spec §2 catalogue (headings and tables). The registry (WP0) is preferred when it exists.
SPEC_RULE_IDS = set("""
WEB-content-security-policy WEB-permissions-policy WEB-referrer-policy WEB-strict-transport-security
WEB-x-content-type-options WEB-x-frame-options WEB000 WEB010 WEB011 WEB020 WEB021 WEB022 WEB030 WEB040 WEB041 WEB042
WEB043 WEB050 WEB051 WEB052 WEB053 WEB054 WEB055 WEB056 WEB060 WEB061 WEB062 WEB070 WEB071 WEB072 WEB080 WEB081 WEB082
WEB083 WEB101 WEB102 WEB103 WEB104 WEB105 WEB106 WEB110 WEB111 WEB112 WEB113 WEB114 WEB115 WEB116 WEB117 WEB118 WEB119
WEB200 WEB201 WEB202 WEB203 WEB204 WEB205 WEB206 WEB207 WEB208 WEB209 WEB210 WEB211 WEB212 WEB213 WEB214 WEB215 WEB216
WEB217 WEB218 WEB219 WEB300 WEB301 WEB302 WEB303 WEB304 WEB305 WEB306 WEB307 WEB308 WEB309 WEB310 WEB311 WEB312 WEB313
WEB314 WEB315 WEB316 WEB317 WEB318 WEB320 WEB321 WEB322 WEB323 WEB324 WEB325 WEB326 WEB327 WEB400 WEB401 WEB402 WEB403
WEB404 WEB405 WEB406 WEB407 WEB408 WEB409 WEB410 WEB411 WEB412 WEB413 WEB414 WEB500 WEB501 WEB502 WEB503 WEB504 WEB505
WEB506 WEB507 WEB508 WEB509 WEB510 WEB511 WEB512 WEB513 WEB514 WEB515 WEB516 WEB517 WEB518 WEB519 WEB520 WEB521 WEB522
WEB600 WEB601 WEB602 WEB603 WEB604 WEB605 WEB606 WEB607 WEB608 WEB609 WEB610 WEB611 WEB612 WEB613 WEB614 WEB615 WEB616
WEB617 WEB619 WEB700 WEB701 WEB702 WEB703 WEB704 WEB705 WEB706 WEB707 WEB708 WEB709 WEB710 WEB711 WEB712 WEB713 WEB714
WEB715 WEB716 WEB717 WEB718 WEB719 WEB720 WEB800 WEB801 WEB802 WEB803 WEB900 WEB901 WEB903 WEB990 WEB991
""".split())


def _registry_ids() -> set[str]:
    try:
        rules = importlib.import_module("vulnscan.webscan.rules")
    except ImportError:
        return SPEC_RULE_IDS
    reg = getattr(rules, "RULES", None)
    return set(reg) if isinstance(reg, dict) and reg else SPEC_RULE_IDS


# ------------------------------------------------------------------------------------------- corpus structure


def test_corpus_is_valid_and_about_300_cases():
    assert corpus.validate() == []
    assert 280 <= len(corpus.CASES) <= 380
    groups = {c.group for c in corpus.CASES}
    assert groups == set(corpus.GROUPS)
    sizes = {g: sum(1 for c in corpus.CASES if c.group == g) for g in corpus.GROUPS}
    assert sizes["C-HOSTILE"] >= 12 and sizes["C-REVIEW"] >= 14 and sizes["C-CSP"] >= 40


def test_labels_json_is_generated_from_corpus():
    current = (BENCH / "labels.json").read_text(encoding="utf-8")
    assert current == corpus.labels_text(), "run: python bench/web/corpus.py --write-labels"
    doc = json.loads(current)
    assert doc["count"] == len(corpus.CASES)
    assert not re.search(r"[rs]k_live_[A-Za-z0-9]{24,}", current)      # secrets are built at run time, never stored


def test_every_label_names_a_catalogue_rule():
    known = _registry_ids()
    unknown = sorted({r for c in corpus.CASES for r in c.labels} - known)
    assert not unknown, f"labels use ids missing from the §2 catalogue: {unknown}"


def test_every_scored_rule_has_a_true_positive_and_a_trap():
    pos = {r for c in corpus.CASES for r, v in c.labels.items() if v}
    neg = {r for c in corpus.CASES for r, v in c.labels.items() if not v}
    assert pos - neg == set(), f"rules without a trap: {sorted(pos - neg)}"
    assert neg - pos == set(), f"rules without a true positive: {sorted(neg - pos)}"


def test_true_positive_cases_name_a_twin():
    missing = [c.id for c in corpus.CASES if any(c.labels.values()) and not c.twin and c.group != "C-GRADE"]
    assert not missing, f"true-positive cases without a trap twin: {missing}"


def test_every_defect_d1_to_d25_has_a_regression_case():
    have = {d for c in corpus.CASES for d in c.defect}
    assert have == {f"D{n}" for n in range(1, 26)}


def test_case_hosts_are_reserved_names_only():
    for c in corpus.CASES:
        for host in c.all_hosts():
            ok = (host.endswith((".kashif.test", ".kashif-third.test")) or host == "kashif-corpus.dev"
                  or host == "kashif-corpus-gone.s3.amazonaws.com")
            assert ok, f"{c.id}: unexpected host {host}"


def test_deep_list_never_requests_never_list_paths():
    """§0.1 never-list: heap/thread dumps and profilers are never served as routes Kashif should fetch."""
    for c in corpus.CASES:
        for path in c.routes:
            if "heapdump" in path or "threaddump" in path or "pprof" in path:
                assert "server_never" in c.expect, f"{c.id}: a never-list path must be guarded by server_never"


# ------------------------------------------------------------------------------------------- servers


@pytest.fixture(scope="module")
def server():
    srv = corpus.CorpusServer(mode="host").start()
    yield srv
    srv.stop()


def _get(srv, c, path=None, method="GET", headers=None, sni=True):
    url = srv.url(c)
    from urllib.parse import urlsplit
    u = urlsplit(url)
    if u.scheme == "https":
        ctx = ssl.create_default_context(cafile=str(srv.material.root))
        ctx.check_hostname = False
        sock = socket.create_connection(("127.0.0.1", u.port), timeout=10)
        ssock = ctx.wrap_socket(sock, server_hostname=u.hostname if sni else None)
        conn = http.client.HTTPSConnection("127.0.0.1", u.port, timeout=10)
        conn.sock = ssock
        peer = ssock.getpeercert()
    else:
        conn = http.client.HTTPConnection("127.0.0.1", u.port, timeout=10)
        peer = None
    conn.putrequest(method, path or u.path, skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", f"{u.hostname}:{u.port}")
    for k, v in (headers or {}).items():
        conn.putheader(k, v)
    conn.endheaders()
    r = conn.getresponse()
    body = r.read()
    conn.close()
    return r, body, peer


def test_server_routes_by_host_and_renders_tokens(server):
    c = server.by_id["red-http-to-https"]
    r, _body, _ = _get(server, c)
    assert r.status == 301
    loc = r.getheader("Location")
    assert loc == f"https://{c.host}:{server.https_port}/"
    nonce_case = server.by_id["csp-strict-good"]
    if "tls" in server.unavailable:
        pytest.skip(server.unavailable["tls"])
    r1, b1, _ = _get(server, nonce_case)
    r2, b2, _ = _get(server, nonce_case)
    n1 = re.search(r"'nonce-([^']+)'", r1.getheader("Content-Security-Policy")).group(1)
    n2 = re.search(r"'nonce-([^']+)'", r2.getheader("Content-Security-Policy")).group(1)
    assert n1 != n2 and f'nonce="{n1}"'.encode() in b1                 # a fresh nonce per response, header == body


def test_duplicate_headers_and_raw_bytes_are_sent_as_declared(server):
    if "tls" in server.unavailable:
        pytest.skip(server.unavailable["tls"])
    r, _, _ = _get(server, server.by_id["hsts-two-headers"])
    assert len(r.headers.get_all("Strict-Transport-Security")) == 2
    r, _, _ = _get(server, server.by_id["hdr-xcto-missing-js"])
    assert r.getheader("X-Content-Type-Options") is None and r.getheader("Server") is None   # no stray Server header


def test_cors_reflection_only_with_origin(server):
    if "tls" in server.unavailable:
        pytest.skip(server.unavailable["tls"])
    c = server.by_id["cors-reflect-creds"]
    r, _, _ = _get(server, c)
    assert r.getheader("Access-Control-Allow-Origin") is None
    r, _, _ = _get(server, c, headers={"Origin": corpus.CORS_PROBE_ORIGIN})
    assert r.getheader("Access-Control-Allow-Origin") == corpus.CORS_PROBE_ORIGIN


def test_sni_selects_the_case_certificate(server):
    if "tls" in server.unavailable:
        pytest.skip(server.unavailable["tls"])
    _, _, peer = _get(server, server.by_id["csp-strict-good"])
    sans = [v for k, v in peer.get("subjectAltName", ()) if k == "DNS"]
    assert "*.csp.kashif.test" in sans
    c = server.by_id["tls-wrong-host"]
    ctx = ssl.create_default_context(cafile=str(server.material.root))
    with socket.create_connection(("127.0.0.1", server.port_for(c)), timeout=10) as s:
        with pytest.raises(ssl.SSLCertVerificationError):
            ctx.wrap_socket(s, server_hostname=c.host)


def test_non_get_methods_are_recorded_as_violations(server):
    c = server.by_id["red-http-200"]
    before = len(server.violations)
    r, _, _ = _get(server, c, method="OPTIONS")
    assert r.status == 405
    assert len(server.violations) == before + 1
    server.violations.clear()                     # keep the shared fixture clean for other tests


def test_requests_are_recorded_per_case(server):
    c = server.by_id["exp-robots-admin"]
    _get(server, c, path="/robots.txt")
    recs = server.requests_for(c.id)
    assert recs and recs[-1].path == "/robots.txt" and recs[-1].status == 200


def test_prefix_and_active_routing(server):
    c = server.by_id["red-http-200"]
    assert server.route("127.0.0.1:1", f"/_case/{c.id}/x")[0] is c
    assert server.route("127.0.0.1:1", "/x")[0] is None
    server.set_active(c)
    try:
        assert server.route("127.0.0.1:1", "/robots.txt")[0] is c
    finally:
        server.set_active(None)


def test_resolver_map_marks_corpus_hosts_public_and_applies_overrides(server):
    m = server.resolver_map(server.by_id["rev-unregistered-script"], "/x/ca.pem")
    assert m["hosts"]["rev-unregistered-script.review.kashif.test"] == {"status": "ok", "addresses": ["127.0.0.1"],
                                                                       "public": True}
    assert m["hosts"]["cdn.kashif-gone.test"] == {"status": "nxdomain"}
    assert m["default"]["addresses"] == ["127.0.0.1"]            # unknown names never leave the machine
    assert m["tls"]["cafile"] == "/x/ca.pem"
    assert server.resolver_map(server.by_id["rev-all-nxdomain"])["default"] == {"status": "nxdomain"}
    two = server.resolver_map(server.by_id["tls-two-ips"])
    assert two["hosts"]["tls-two-ips.tls.kashif.test"]["addresses"] == ["127.0.0.1", "127.0.0.2"]
    take = server.resolver_map(server.by_id["exp-takeover"])["hosts"]["exp-takeover.exp.kashif.test"]
    assert take["canonical"] == "kashif-corpus-gone.github.io"


def test_requirements_are_reported_not_passed(server):
    for c in server.cases:
        miss = server.missing(c)
        if "stub" in c.requires and "stub" in server.unavailable:
            assert miss
        if "roca" in c.requires and "roca" in server.unavailable:
            assert miss


def test_mini_proxy_tunnels_to_the_corpus(server):
    c = server.by_id["red-http-200"]
    with socket.create_connection(server.proxy.server_address, timeout=10) as s:
        s.sendall(f"CONNECT {c.host}:{server.http_port} HTTP/1.1\r\nHost: {c.host}\r\n\r\n".encode())
        assert s.recv(100).startswith(b"HTTP/1.1 200")
        s.sendall(f"GET / HTTP/1.1\r\nHost: {c.host}:{server.http_port}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while chunk := s.recv(65536):
            data += chunk
    assert data.startswith(b"HTTP/1.1 200")


def test_tls_material_dates(server):
    if "tls" in server.unavailable:
        pytest.skip(server.unavailable["tls"])
    dec = ssl._ssl._test_decode_cert                    # stdlib helper used by CPython's own tests
    expired = dec(str(server.material.leaves["expired"]))
    notyet = dec(str(server.material.leaves["notyet"]))
    assert ssl.cert_time_to_seconds(expired["notAfter"]) < ssl.cert_time_to_seconds(notyet["notBefore"])
    assert "2090" in notyet["notBefore"]
    cnonly = dec(str(server.material.leaves["cnonly"]))
    assert "subjectAltName" not in cnonly


def test_two_ip_case_is_skipped_not_passed_without_127_0_0_2(server):
    c = server.by_id["tls-two-ips"]
    if "ip2" in server.unavailable:
        assert server.missing(c)
    else:
        assert not server.missing(c)


# ------------------------------------------------------------------------------------------- runner helpers


@pytest.mark.parametrize("cmd,ok", [
    ("curl -sS -D - -o /dev/null -A 'Kashif/1.1.0' 'http://x/'\"'\"'$(id)'\"'\"''", True),
    ("curl -sS 'http://x/$(id)'", True),
    ("curl -sS http://x/'$(id)'", True),
    ("curl -sS 'http://x/'$(id)''", False),
    ("curl -sS \"http://x/$(id)\"", False),
    ("curl -sS http://x/$(id)", False),
    ("curl -sS 'http://x/a; rm -rf /'", True),
    ("curl -sS http://x/a;id", False),
])
def test_shell_safe(cmd, ok):
    assert run_kashif.shell_safe(cmd) is ok


def test_summarize_findings_collects_urls_confidence_and_curl():
    data = {"findings": [{"rule_id": "WEB042", "severity": "medium", "title": "t", "file": "h",
                          "extra": {"confidence": "certain", "instances": 3, "examples": ["https://a.kashif.test/"],
                                    "evidence": {"request": {"url": "https://a.kashif.test/x"}, "curl": "curl 'u'"}}}]}
    f = run_kashif.summarize_findings(data)[0]
    assert f["rule"] == "WEB042" and f["confidence"] == "certain" and f["instances"] == 3
    assert f["urls"] == ["https://a.kashif.test/", "https://a.kashif.test/x"] and f["curl"] == ["curl 'u'"]


# ------------------------------------------------------------------------------------------- scorer and gate


def _labels(**cases):
    return {"cases": {cid: {"labels": lab, "defect": d, "expect": e} for cid, (lab, d, e) in cases.items()}}


def _res(*rules, exit=0, status="ran", conf="certain", web=None, **extra):
    return {"status": status, "exit": exit, "findings": [{"rule": r, "severity": "medium", "confidence": conf}
                                                         for r in rules], "web": web or {}, **extra}


def test_score_confusion_matrix_and_metrics():
    labels = _labels(a=({"WEB040": True}, ["D7"], {}), b=({"WEB040": False}, [], {}), c=({"WEB040": True}, [], {}),
                     d=({"WEB040": False}, [], {}), e=({"WEB040": True}, [], {}), f=({"WEB042": True}, [], {}))
    run = {"cases": {"a": _res("WEB040"), "b": _res("WEB040", conf="firm"), "c": _res(), "d": _res(),
                     "e": _res(status="skipped", reason="stub missing"),
                     "f": _res(web={"coverage": {"WEB042": {"state": "not_tested"}}})}}
    s = score.score(labels, run)
    r = s["rules"]["WEB040"]
    assert (r["tp"], r["fp"], r["fn"], r["tn"]) == (1, 1, 1, 1)
    assert r["precision"] == 0.5 and r["recall"] == 0.5 and r["f1"] == 0.5 and r["youden_j"] == 0.0
    assert s["rules"]["WEB042"]["inconclusive"] == 1 and s["inconclusive"] == 1       # never TN, never TP
    assert "e" in s["skipped"] and s["verdicts"]["e"]["WEB040"] == "skipped"
    assert s["precision_by_confidence"]["certain"] == 1.0 and s["precision_by_confidence"]["firm"] == 0.0
    assert s["confidence_monotone"] is True
    assert s["macro_f1"] == 0.5


def test_crashed_run_counts_must_fire_as_fn_and_traps_as_error():
    labels = _labels(a=({"WEB040": True, "WEB041": False}, [], {}))
    s = score.score(labels, {"cases": {"a": _res(exit=None, traceback=True)}})
    assert s["verdicts"]["a"] == {"WEB040": "fn", "WEB041": "error"} and "a" in s["errors"]


def test_expectations():
    lab = {"labels": {}, "expect": {"severity": {"WEB050": "low"}, "count": {"WEB051": 1}, "grade": "A+",
                                    "min_gap": 0.18, "json_contains": ["proxy"], "observatory": None}}
    res = _res("WEB050", "WEB051", "WEB051", web={"grades": {"kashif": {"grade": "A+"}}},
               traffic={"min_gap": 0.05}, contains={"proxy": True})
    got = {k: ok for k, ok, _ in score.expectations("x", lab, res, {})}
    assert got["severity:WEB050"] is False and got["count:WEB051"] is False and got["grade"] is True
    assert got["min_gap"] is False and got["json_contains:proxy"] is True and got["observatory"] is None


def test_defect_table_and_gate():
    labels = _labels(a=({"WEB040": False}, ["D7"], {}))
    now = score.score(labels, {"cases": {"a": _res()}})
    old = score.score(labels, {"cases": {"a": _res("WEB040")}})
    rows = score.defect_table(labels, now, old)
    d7 = next(r for r in rows if r["defect"] == "D7")
    assert d7 == {"defect": "D7", "cases": ["a"], "now": "fixed", "baseline": "wrong"}
    # the real targets, without the per-rule floors (a one-case corpus cannot score the other 183 rules; the floors
    # are checked by test_ratchet_only_goes_up and by the full corpus gate)
    mins = {**json.loads((BENCH / "min-score.json").read_text(encoding="utf-8")), "rules": {}}
    assert score.gate(now, mins, rows) == []
    assert any("D7 not fixed" in f for f in score.gate(old, mins, score.defect_table(labels, old, None)))


def test_ratchet_only_goes_up():
    mins = {"targets": {}, "rules": {"WEB040": {"precision": 1.0, "recall": 0.5}}}
    s = {"rules": {"WEB040": {"precision": 0.9, "recall": 1.0}, "WEB041": {"precision": 1.0, "recall": 1.0}}}
    out = score.ratchet(mins, s)
    assert out["rules"]["WEB040"] == {"precision": 1.0, "recall": 1.0} and out["rules"]["WEB041"]["recall"] == 1.0
    fails = score.gate({**s, "precision_by_confidence": {}, "macro_f1": None, "zap_fp_family_trap_failures": 0,
                        "confidence_monotone": True, "expectation_failures": [], "traffic_violations": {},
                        "server_violations": [], "errors": {}}, mins, [])
    assert fails == ["WEB040: precision 0.9 < recorded 1.0"]


def test_min_score_targets_are_the_spec_targets():
    t = json.loads((BENCH / "min-score.json").read_text(encoding="utf-8"))["targets"]
    assert t["precision_certain"] == 1.0 and t["precision_firm"] == 0.98 and t["recall_per_rule"] == 0.95
    assert t["macro_f1"] == 0.98 and t["zap_fp_family_trap_failures"] == 0 and t["defects_fixed"] is True


def test_recorded_1_0_2_baseline_gets_every_defect_case_wrong():
    """The 1.0.1/1.0.2 web.py (identical) was run on the corpus; every D-case shows its defect (spec §5.1 item 3)."""
    base = json.loads((BENCH / "results" / "1.0.2-legacy.json").read_text(encoding="utf-8"))
    assert base["mode"] == "legacy" and "1.0.2" in base["kashif_version"]
    labels = json.loads((BENCH / "labels.json").read_text(encoding="utf-8"))
    s = score.score(labels, base)
    rows = score.defect_table(labels, s, None)
    assert [r["defect"] for r in rows if r["now"] != "wrong"] == []


# ------------------------------------------------------------------------------------------- ZAP harness


def test_zap_plan_template_is_passive_only():
    text = (BENCH / "zap-plan.yaml").read_text(encoding="utf-8")
    jobs = re.findall(r"^\s*-\s*type:\s*([A-Za-z-]+)", text, re.M)
    assert jobs == ["passiveScan-config", "requestor", "passiveScan-wait", "report"]
    assert "activeScan" not in text.replace("no active scan", "")
    assert run_zap.plan_problems(text) == []
    assert run_zap.plan_problems(text + "\n  - type: activeScan\n") == ["activeScan"]
    assert run_zap.plan_problems(text + "\n  - type: spider\n") == ["spider"]


def test_generated_zap_plan_is_passive_and_lists_case_urls(tmp_path):
    out = tmp_path / "plan.yaml"
    assert run_zap.main(["--plan-only", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert run_zap.plan_problems(text) == [] and "activeScan" not in text.replace("no active scan", "")
    assert "/_case/red-http-200/" in text and "/_case/hostile-gzip-bomb/" not in text
    assert "@REQUESTS@" not in text


def test_run_zap_skips_honestly_without_zap(tmp_path, monkeypatch):
    monkeypatch.delenv("ZAP_HOME", raising=False)
    monkeypatch.setattr(run_zap.shutil, "which", lambda name: None)
    out = tmp_path / "zap.json"
    assert run_zap.main(["--zap", str(tmp_path / "nowhere"), "-o", str(out)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["status"] == "skipped" and "ZAP not found" in doc["reason"] and doc["cases"] == {}
    assert run_zap.main(["--zap", str(tmp_path / "nowhere"), "-o", str(out), "--require"]) == 2


def test_zap_mapping_matches_spec():
    must = {"10035", "10038", "10055", "10020", "10021", "10010", "10011", "10054", "90033", "10098", "90003", "10017",
            "10040", "10042", "10041", "10105", "10033", "90022", "10023", "10009", "10036", "10037", "10061", "10039",
            "10052", "10056", "10034", "20020", "2", "3", "10097", "10062", "10044", "10015", "10019", "90011", "10108",
            "10115", "10032", "90001", "90002", "10063", "90004", "10099", "110009", "10003"}
    have = {k.split("-")[0] for k in run_zap.ZAP_MAP} | {"10021"}
    assert must <= have
    assert set(run_zap.COVERS) <= _registry_ids()
    assert run_zap.map_alert({"pluginid": "10055", "alertRef": "10055-4"},
                             {"otherinfo": "script-src, form-action"}) == ["WEB042", "WEB205"]
    assert run_zap.map_alert({"pluginid": "10021"}, {"evidence": "nosnif"}) == ["WEB303"]
    rep = {"site": [{"alerts": [{"pluginid": "10020", "alertRef": "10020-1", "riskcode": "2", "confidence": "Medium",
                                 "instances": [{"uri": "https://127.0.0.1:1/_case/hdr-xfo-missing-login/"}]}]}]}
    got = run_zap.parse_report(rep, {"hdr-xfo-missing-login"})
    assert got["hdr-xfo-missing-login"][0]["rule"] == "WEB-x-frame-options"


def test_zap_scoring_uses_only_covered_rules_and_requested_cases():
    labels = _labels(a=({"WEB-x-frame-options": True, "WEB520": True}, [], {}), b=({"WEB-x-frame-options": False}, [], {}))
    run = {"tool": "zap", "covers": ["WEB-x-frame-options"], "case_filter": ["a"], "cases": {"a": _res()}}
    s = score.score(labels, run)
    assert set(s["rules"]) == {"WEB-x-frame-options"} and s["cases_scored"] == 1 and s["expectation_failures"] == []


# ------------------------------------------------------------------------------------------- the gate itself


def _kashif_11_available() -> str | None:
    try:
        importlib.import_module("vulnscan.webscan.engine")
    except ImportError as e:
        return f"the 1.1 web engine is not assembled yet ({e})"
    help_text = subprocess.run([sys.executable, "-m", "vulnscan", "--help"], cwd=ROOT, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=120, check=False).stdout
    if "--web-profile" not in help_text:
        return "the CLI has no --web-profile option yet (WP15b)"
    return None


def test_full_corpus_gate(tmp_path):
    """Spec §5.4: run the whole corpus through the CLI and gate on min-score.json (skipped until the 1.1 engine exists)."""
    import os
    if os.environ.get("KASHIF_SKIP_CORPUS") == "1":
        pytest.skip("KASHIF_SKIP_CORPUS=1")
    why = _kashif_11_available()
    if why:
        pytest.skip(why)
    results = tmp_path / "results.json"
    assert run_kashif.main(["-o", str(results), "--quiet"]) == 0
    code = score.main([str(results), "--min-score", str(BENCH / "min-score.json"), "--markdown",
                       str(tmp_path / "score.md"), "--baseline", str(BENCH / "results" / "1.0.2-legacy.json")])
    assert code == 0, (tmp_path / "score.md").read_text(encoding="utf-8")[:6000]


# ------------------------------------------------------------------------------------------- runner, end to end

_FAKE_CLI = r'''
"""A stand-in for the 1.1 CLI: resolves through the test hook, makes the entry GET and the CORS GET, reports HSTS."""
import http.client, json, os, shlex, ssl, sys, time, urllib.parse
argv = sys.argv[1:]
if "--version" in argv:
    print("vulnscan 1.1.0-stub"); sys.exit(0)
if "--help" in argv:
    print("--web-profile --web-sensitivity --no-proxy"); sys.exit(0)
assert os.environ.get("KASHIF_TEST_RESOLVE") == "1"
rmap = json.load(open(os.environ["KASHIF_TEST_RESOLVE_MAP"], encoding="utf-8"))
url, out = argv[0], argv[argv.index("-o") + 1]
u = urllib.parse.urlsplit(url)
entry = rmap["hosts"].get(u.hostname, rmap["default"])
addr = entry["addresses"][0]
def get(extra):
    if u.scheme == "https":
        ctx = ssl.create_default_context(cafile=os.environ["KASHIF_TEST_CAFILE"])
        conn = http.client.HTTPSConnection(addr, u.port, timeout=10, context=ctx)
        conn._tunnel_host = None
        conn.sock = ctx.wrap_socket(__import__("socket").create_connection((addr, u.port), 10), server_hostname=u.hostname)
    else:
        conn = http.client.HTTPConnection(addr, u.port, timeout=10)
    conn.putrequest("GET", u.path or "/", skip_host=True, skip_accept_encoding=True)
    for k, v in [("Host", u.netloc), ("User-Agent", "Kashif/1.1.0 (+stub)"), ("Accept", "*/*"),
                 ("Accept-Encoding", "gzip, deflate"), ("Accept-Language", "en")] + extra:
        conn.putheader(k, v)
    conn.endheaders()
    r = conn.getresponse(); r.read(); conn.close()
    return r
r = get([])
time.sleep(0.25)
get([("Origin", "https://kashif-cors-check.invalid")])
findings = []
if u.scheme == "https" and not r.getheader("Strict-Transport-Security"):
    findings.append({"rule_id": "WEB-strict-transport-security", "severity": "medium", "title": "x", "file": u.netloc,
                     "extra": {"confidence": "firm", "evidence": {"request": {"url": url},
                               "curl": shlex.join(["curl", "-sS", "-A", "Kashif/1.1.0", url])}}})
json.dump({"findings": findings, "web": {"grades": {"kashif": {"grade": "B+"}}, "coverage": {}}}, open(out, "w"))
'''


def test_runner_hook_mode_end_to_end_with_a_stub_cli(tmp_path):
    pkg = tmp_path / "vulnscan"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "__main__.py").write_text(_FAKE_CLI, encoding="utf-8")
    out = tmp_path / "res.json"
    cases = "csp-strict-good,hsts-missing,hsts-two-years,red-http-200"
    assert run_kashif.main(["--root", str(tmp_path), "--cases", cases, "-o", str(out), "--quiet", "--jobs", "2"]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["mode"] == "hook" and doc["kashif_version"] == "vulnscan 1.1.0-stub"
    res = doc["cases"]
    if res["hsts-missing"]["status"] == "skipped":
        pytest.skip(res["hsts-missing"]["reason"])
    assert [f["rule"] for f in res["hsts-missing"]["findings"]] == ["WEB-strict-transport-security"]
    assert res["hsts-two-years"]["findings"] == []
    t = res["hsts-missing"]["traffic"]
    assert t["requests"] == 2 and t["violations"] == [] and t["min_gap"] >= 0.2
    labels = json.loads((BENCH / "labels.json").read_text(encoding="utf-8"))
    s = score.score(labels, doc)
    assert s["verdicts"]["hsts-missing"]["WEB-strict-transport-security"] == "tp"
    assert s["verdicts"]["hsts-two-years"]["WEB-strict-transport-security"] == "tn"
    assert s["errors"] == {}


def test_min_score_has_a_floor_for_every_registry_rule():
    """Phase D ratchet (§5.4): every rule is scored on the corpus with at least one true positive, and its floor is
    recorded, so a rule that silently stops being exercised fails the gate ("no longer scored")."""
    from vulnscan.webscan import rules as _rules
    floors = json.loads((BENCH / "min-score.json").read_text(encoding="utf-8"))["rules"]
    assert set(floors) == set(_rules.RULE_IDS), sorted(set(_rules.RULE_IDS) ^ set(floors))
    labels = json.loads((BENCH / "labels.json").read_text(encoding="utf-8"))["cases"]
    tp = {r for c in labels.values() for r, v in c["labels"].items() if v}
    trap = {r for c in labels.values() for r, v in c["labels"].items() if not v}
    assert set(_rules.RULE_IDS) <= tp and set(_rules.RULE_IDS) <= trap, sorted(set(_rules.RULE_IDS) - (tp & trap))
