"""C-TLS corpus group (spec §5.2, WP10 acceptance) at module level: the corpus servers of bench/web (WP16) with their
test-only resolver and CA hooks, probed through the real Fetcher by tls/probe.py and judged by tls/assess.py, then
compared with the labels. The full CLI run (bench/web/run_kashif.py) needs the engine (WP15a); this test is the TLS
part of it and runs today. Cases whose requirement is missing here (no openssl CLI, 127.0.0.2 not bindable on macOS,
TLS 1.0 refused by the local OpenSSL) are skipped, never passed.

Offline: every name resolves to 127.0.0.1/127.0.0.2 through the hook; proxies are disabled.
"""

from __future__ import annotations

import concurrent.futures as cf
import sys
import urllib.parse
from pathlib import Path

import pytest

from vulnscan.webscan import coverage, rules, tls
from vulnscan.webscan.http import CorpusHooks, Fetcher
from vulnscan.webscan.types import ScanContext, ScanOptions

BENCH = Path(__file__).resolve().parents[2] / "bench" / "web"
sys.path.insert(0, str(BENCH))
corpus = pytest.importorskip("corpus")

TLS_RULES = {r for r, m in rules.RULES.items() if m.module == "tls"}
CASES = [c for c in corpus.CASES if c.group == "C-TLS" or (c.tls and set(c.labels) & TLS_RULES)]


@pytest.fixture(scope="module")
def results():
    srv = corpus.CorpusServer(CASES).start()
    try:
        if "tls" in srv.unavailable:
            pytest.skip(f"corpus TLS unavailable: {srv.unavailable['tls']}")

        def one(c):
            missing = srv.missing(c)
            if missing:
                return c.id, ("skip", "; ".join(missing))
            url = srv.url(c)
            cafile = str(srv.material.root)
            hooks = CorpusHooks(resolve_map=srv.resolver_map(c, cafile=cafile), cafile=cafile, publicly_trusted=True,
                                ct_required=bool(c.expect.get("ct_required")))
            profile = c.profile if c.profile in ("minimal", "standard", "deep") else "standard"
            opts = ScanOptions(profile=profile, timeout=2.0, use_proxy=False)
            ctx = ScanContext(options=opts, target=url, coverage=coverage.Coverage())
            p = urllib.parse.urlsplit(url)
            ctx.tls[p.hostname] = tls.scan_host(Fetcher(opts, url, hooks=hooks), p.hostname, p.port, profile=profile,
                                                timeout=opts.timeout)
            return c.id, ("ran", tls.run(ctx), ctx)

        with cf.ThreadPoolExecutor(max_workers=16) as ex:
            out = dict(ex.map(one, CASES))
    finally:
        srv.stop()
    return out


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_c_tls_case(case, results):
    res = results[case.id]
    if res[0] == "skip":
        pytest.skip(res[1])
    _ran, issues, ctx = res
    fired = {i.rule for i in issues}
    for i in issues:
        assert rules.validate_issue(i) == [], (i.rule, rules.validate_issue(i))
    problems = []
    for rule, want in case.labels.items():
        if rule not in TLS_RULES:
            continue
        if want and rule not in fired:
            problems.append(f"missed {rule} (state {ctx.coverage.state(rule).state})")
        if not want and rule in fired:
            problems.append(f"false positive {rule}: {[i.notes for i in issues if i.rule == rule]}")
    for rule, exp in (case.expect.get("states") or {}).items():
        if rule in TLS_RULES and ctx.coverage.state(rule).state != exp:
            problems.append(f"state {rule} = {ctx.coverage.state(rule).state}, expected {exp}")
    for rule, exp in (case.expect.get("severity") or {}).items():
        if rule in TLS_RULES and {i.severity for i in issues if i.rule == rule} != {exp}:
            problems.append(f"severity of {rule} is not {exp}")
    for rule, exp in (case.expect.get("max_severity") or {}).items():
        sev = [i.severity for i in issues if i.rule == rule]
        if any(rules.SEVERITIES.index(s) < rules.SEVERITIES.index(exp) for s in sev):
            problems.append(f"{rule} above {exp}: {sev}")
    assert not problems, problems
