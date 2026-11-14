"""tls/probe.py: handshake orchestration, tri-state results, back-off, pacing, IP sampling and the verify-code facts
of real handshakes (spec §2.8 steps 1–5, WP10). Everything runs against servers on 127.0.0.1: the raw-probe stub
(tests/web/tls_stub.py) and a Python ``ssl`` server with the fixture PKI."""

from __future__ import annotations

import socket
import ssl
import sys
import threading
import time
from pathlib import Path

import pytest

from vulnscan.webscan import coverage, tls
from vulnscan.webscan.http import CorpusHooks, Fetcher
from vulnscan.webscan.tls import probe, raw
from vulnscan.webscan.types import HeaderList, Response, ScanContext, ScanOptions

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tls_stub  # noqa: E402

CERTS = Path(__file__).resolve().parent.parent / "data" / "web" / "certs"
ROOT = str(CERTS / "root.pem")


class Connector:
    """The four members tls/probe.py uses, pointed at one local port whatever address it is asked for."""

    def __init__(self, port: int, *, addresses=("127.0.0.1",), proxy=None, strict: bool = False):
        self.port, self._addresses, self.proxy, self.strict = port, tuple(addresses), proxy, strict
        self.opened: list[tuple[str | None, float]] = []
        self.hooks = None

    def tls_context(self, verified: bool = True) -> ssl.SSLContext:
        if verified:
            ctx = ssl.create_default_context(cafile=ROOT)
            if not self.strict:
                ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
            else:
                ctx.verify_flags |= getattr(ssl, "VERIFY_X509_STRICT", 0)
            ctx.hostname_checks_common_name = False
            return ctx
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def open_tcp(self, host, port, *, ip=None, timeout=None):
        self.opened.append((ip, time.monotonic()))
        return socket.create_connection(("127.0.0.1", self.port), timeout)

    def addresses(self, host):
        return self._addresses

    def proxy_for(self, url):
        return self.proxy


class SSLServer:
    """A TLS server with the fixture PKI (chain and key chosen per test)."""

    def __init__(self, *certs: str, key: str = "leaf.key", seclevel0: bool = False):
        text = "".join((CERTS / c).read_text(encoding="ascii") for c in certs)
        self._chain = Path(self._tmp()) / "chain.pem"
        self._chain.write_text(text, encoding="ascii")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if seclevel0:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        ctx.load_cert_chain(str(self._chain), str(CERTS / key))
        self.ctx = ctx
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _tmp(self) -> str:
        import tempfile
        self._dir = tempfile.TemporaryDirectory(prefix="kashif-tls-test-")
        return self._dir.name

    def _serve(self):
        while not self._stop.is_set():
            try:
                c, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c):
        try:
            c.settimeout(3)
            with self.ctx.wrap_socket(c, server_side=True) as t:
                t.recv(1)
        except (OSError, ssl.SSLError):
            pass

    def close(self):
        self._stop.set()
        self.sock.close()
        self._dir.cleanup()


@pytest.fixture
def server_factory():
    made = []

    def make(*certs, **kw):
        s = SSLServer(*certs, **kw)
        made.append(s)
        return s
    yield make
    for s in made:
        s.close()


@pytest.fixture
def stub_factory():
    made = []

    def make(profile, **kw):
        s = tls_stub.StubServer(profile, hold=kw.pop("hold", 5), **kw)
        made.append(s)
        return s
    yield make
    for s in made:
        s.stop()


def probe_stub(stub, profile="standard", timeout=1.0, **kw):
    return probe.probe_ip(Connector(stub.port, **kw), "localhost", stub.port, "127.0.0.1", profile=profile,
                          timeout=timeout)


# ----------------------------------------------------------------------------------------------- decision rule

@pytest.mark.parametrize("fl,offered,expect", [
    (raw.Flight(result="hello", version=raw.TLS10), raw.TLS10, "yes"),
    (raw.Flight(result="hello", version=raw.TLS10), raw.TLS12, "no"),            # negotiated down
    (raw.Flight(result="hello", version=raw.TLS12), raw.TLS10, "no"),            # higher than offered (WEB716)
    (raw.Flight(result="hello", version=raw.TLS13, hrr=True), raw.TLS13, "yes"),
    (raw.Flight(result="hello", version=raw.TLS12), raw.TLS13, "no"),
    (raw.Flight(result="alert", alert=(2, 70)), raw.TLS10, "no"),
    (raw.Flight(result="alert", alert=(2, 40)), raw.TLS10, "no"),
    (raw.Flight(result="alert", alert=(2, 80)), raw.TLS10, "inconclusive"),       # internal_error decides nothing
    (raw.Flight(result="eof"), raw.TLS10, "no"),
    (raw.Flight(result="timeout"), raw.TLS10, "inconclusive"),
    (raw.Flight(result="not_tls"), raw.TLS10, "inconclusive"),
    (raw.Flight(result="error"), raw.TLS10, "inconclusive"),
    (raw.Flight(result="skipped", detail="backoff"), raw.TLS10, "inconclusive"),
])
def test_version_state(fl, offered, expect):
    st = probe.version_state(fl, offered)
    assert st["state"] == expect
    if expect == "inconclusive":
        assert st["reason"]
    assert st.get("higher", False) is (fl.result == "hello" and offered == raw.TLS10 and fl.version == raw.TLS12)


# ----------------------------------------------------------------------------------------------- against the stub

def test_modern_server(stub_factory):
    rep = probe_stub(stub_factory("modern"))
    v = {k: x["state"] for k, x in rep["versions"].items()}
    assert v == {"TLSv1.3": "yes", "TLSv1.2": "yes", "TLSv1.1": "no", "TLSv1.0": "no", "SSLv3": "no", "SSLv2": "no"}
    assert rep["downgrade_sentinel"] is True and rep["renegotiation_info"] is True and rep["compression"] is False
    assert {k: x["state"] for k, x in rep["categories"].items()}["aead"] == "yes"
    assert all(x["state"] == "no" for k, x in rep["categories"].items() if k != "aead")
    assert rep["chain_source"] == "raw" and len(rep["chain"]) == 2 and rep["ocsp"]["state"] == "absent"


def test_legacy_server(stub_factory):
    rep = probe_stub(stub_factory("legacy"))
    v = {k: x["state"] for k, x in rep["versions"].items()}
    assert v["TLSv1.0"] == v["TLSv1.1"] == v["TLSv1.2"] == "yes" and v["TLSv1.3"] == "no"
    cats = {k: x["state"] for k, x in rep["categories"].items()}
    assert cats["rc4"] == cats["3des"] == cats["krsa"] == "yes"
    assert rep["compression"] is True and rep["renegotiation_info"] is False
    assert rep["versions"]["TLSv1.0"]["cipher"]


def test_tls10_only_and_tls13_only(stub_factory):
    rep = probe_stub(stub_factory("tls10_only"))
    assert rep["versions"]["TLSv1.0"]["state"] == "yes" and rep["versions"]["TLSv1.2"]["state"] == "no"
    assert rep["category_version"] == "TLSv1.0" and rep["categories"]["aead"]["state"] == "no"
    rep = probe_stub(stub_factory("tls13_only"))
    assert rep["versions"]["TLSv1.3"]["state"] == "yes" and rep["category_version"] is None
    assert all(x["state"] == "not_applicable" for x in rep["categories"].values())
    assert rep["ocsp"] == {"state": "not_tested", "der": None, "reason": "tls13_encrypted"}


def test_sslv2_sslv3_higher_and_staple(stub_factory):
    assert probe_stub(stub_factory("sslv2"))["versions"]["SSLv2"]["state"] == "yes"
    assert probe_stub(stub_factory("sslv3_only"))["versions"]["SSLv3"]["state"] == "yes"
    rep = probe_stub(stub_factory("higher"))
    assert {h["offered"] for h in rep["higher_version"]} == {"TLSv1.0", "TLSv1.1"}
    rep = probe_stub(stub_factory("staple"))
    assert rep["ocsp"]["state"] == "stapled" and rep["ocsp"]["der"] and len(rep["tls_scts"]) == 1


def test_refusals_and_garbage(stub_factory):
    rep = probe_stub(stub_factory("alert70"))
    assert all(x["state"] == "no" for x in rep["versions"].values())
    rep = probe_stub(stub_factory("reset"))
    assert all(x["state"] in ("no", "inconclusive") for x in rep["versions"].values())
    rep = probe_stub(stub_factory("garbage"))
    assert all(x["state"] == "inconclusive" for x in rep["versions"].values())
    assert all(x["reason"] for x in rep["versions"].values())


def test_deep_profile_groups_order_and_dh(stub_factory):
    rep = probe_stub(stub_factory("pq"), profile="deep")
    d = rep["deep"]
    assert d["groups"]["X25519MLKEM768"] is True and d["groups"]["x448"] is False
    assert d["preferred_group"] == "X25519MLKEM768"
    assert d["server_preference"] is True and d["suites"][0] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert d["tls13_suites"]["TLS_AES_128_GCM_SHA256"] is True and d["tls13_suites"]["TLS_AES_128_CCM_SHA256"] is False
    rep = probe_stub(stub_factory("dhe1024"), profile="deep")
    assert rep["deep"]["dh_bits"] == 1024
    from vulnscan.webscan.tls.assess import COMMON_DH_SHA256
    assert COMMON_DH_SHA256.get(rep["deep"]["dh_prime_sha256"]) == "oakley-group-2"


def test_minimal_profile_sends_only_the_version_probes(stub_factory):
    stub = stub_factory("modern")
    rep = probe_stub(stub, profile="minimal")
    assert rep["categories"] == {} and rep["compression"] is None
    # 2 + 6 version probes (§4.3), plus the security-level-0 retry because the stub never completes a handshake
    assert len(stub.hellos) <= 2 + 6 + 2


def test_back_off_after_three_timeouts(stub_factory):
    stub = stub_factory("silent", hold=3)
    t0 = time.monotonic()
    rep = probe_stub(stub, timeout=0.5)
    assert rep["backoff"] is True
    states = [x for x in rep["versions"].values()]
    assert all(x["state"] == "inconclusive" for x in states)
    assert any(x.get("reason") == "backoff" for x in states)
    raw_connections = len(stub.connections) - 3        # three ssl handshakes (verified, legacy retry, unverified)
    assert raw_connections <= 3
    assert time.monotonic() - t0 < 15
    assert rep["notes"] and "3 timeouts" in rep["notes"][0][0]


def test_retry_once_on_inconclusive(stub_factory):
    stub = stub_factory("garbage")
    probe_stub(stub)
    sslv2 = [h for h in stub.hellos if h.sslv2]
    assert len(sslv2) == 2                               # not_tls → one retry, never more


def test_scan_host_samples_four_addresses(stub_factory):
    stub = stub_factory("modern")
    addrs = ("192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "2001:db8::1")
    rep = probe.scan_host(Connector(stub.port, addresses=addrs), "localhost", stub.port, profile="minimal", timeout=1.0)
    assert len(rep["ips"]) == 4 and len(rep["not_sampled"]) == 2
    assert "2001:db8::1" in rep["ips"]                   # both families are sampled
    assert rep["leaf"]["sigalg"] == "sha256WithRSAEncryption"


def test_scan_host_through_a_proxy(stub_factory):
    stub = stub_factory("modern")

    class P:
        display = "http://proxy.example:3128"
    rep = probe.scan_host(Connector(stub.port, proxy=P()), "localhost", stub.port, profile="minimal", timeout=1.0)
    assert rep["proxied"] is True and list(rep["ips"]) == ["proxy"] and rep["proxy"] == "http://proxy.example:3128"


def test_no_address():
    rep = probe.scan_host(Connector(1, addresses=()), "nowhere.example", 443, timeout=0.5)
    assert rep["error"]["code"] == "network" and rep["error"]["ar"]


def test_refused_connection_stops_the_ip():
    class Refusing(Connector):
        def open_tcp(self, host, port, *, ip=None, timeout=None):
            from vulnscan.webscan.http import FetchRefused
            raise FetchRefused("time_budget", "time budget reached")
    rep = probe.probe_ip(Refusing(1), "localhost", 1, "127.0.0.1", timeout=0.5)
    assert rep["status"] == "refused" and rep["reason"] == "time_budget"


# ----------------------------------------------------------------------------------------------- real handshakes

def test_verified_handshake_good_chain(server_factory):
    s = server_factory("leaf.pem", "int.pem")
    rep = probe.probe_ip(Connector(s.port), "localhost", s.port, "127.0.0.1", profile="minimal", timeout=3)
    ver = rep["verified"]
    assert ver["ok"] is True and ver["version"] == "TLSv1.3" and ver["alpn"] in ("h2", "http/1.1", None)
    assert len(ver["chain"]) == 2 and len(ver["verified_chain"]) == 3 and ver["chain_complete"]
    assert rep["chain_source"] == "ssl" and rep["unverified"] is None
    assert rep["versions"]["TLSv1.3"]["state"] == "yes" and rep["versions"]["TLSv1.2"]["state"] == "yes"


def test_cn_only_certificate_fails_with_code_62(server_factory):
    # hostname_checks_common_name = False: Python's default (True on 3.11–3.13) would accept this certificate
    s = server_factory("cnonly.pem", "int.pem")
    rep = probe.probe_ip(Connector(s.port), "localhost", s.port, "127.0.0.1", profile="minimal", timeout=3)
    assert rep["verified"]["ok"] is False and rep["verified"]["verify_code"] == 62
    assert rep["unverified"]["chain"]                       # D21: the leaf is still read for the other checks


def test_kashif_verifying_context_is_browser_parity(server_factory):
    """D19: Python 3.13 sets VERIFY_X509_STRICT, which fails a leaf without AKI with code 85; the Fetcher's context
    (WP1, the one tls/ uses) clears it and turns the CN fallback off."""
    f = Fetcher(ScanOptions(use_proxy=False), "https://localhost/", hooks=CorpusHooks(cafile=ROOT))
    ctx = f.tls_context(True)
    assert not ctx.verify_flags & getattr(ssl, "VERIFY_X509_STRICT", 0)
    assert ctx.hostname_checks_common_name is False
    s = server_factory("noaki.pem", "int.pem")
    strict = probe.ssl_handshake(Connector(s.port, strict=True), "localhost", s.port, "127.0.0.1", verified=True,
                                 timeout=3)
    if strict["ok"] is not False:
        pytest.skip(f"this OpenSSL ({ssl.OPENSSL_VERSION}) does not enforce AKI in strict mode")
    assert strict["verify_code"] == 85
    relaxed = probe.ssl_handshake(Connector(s.port), "localhost", s.port, "127.0.0.1", verified=True, timeout=3)
    assert relaxed["ok"] is True


def test_weak_digest_is_judged_again_at_security_level_0(server_factory):
    s = server_factory("sha1leaf.pem", "int.pem", seclevel0=True)
    rep = probe.probe_ip(Connector(s.port), "localhost", s.port, "127.0.0.1", profile="minimal", timeout=3)
    assert rep["verified"]["verify_code"] == 68
    assert rep["verified_legacy"]["ok"] is True and rep["chain_source"] == "ssl"
    ctx = ScanContext(options=ScanOptions(), target=f"https://localhost:{s.port}/", coverage=coverage.Coverage())
    ctx.tls["localhost"] = {"kind": "kashif-tls-host", "host": "localhost", "port": s.port, "proxied": False,
                            "proxy": None, "profile": "minimal", "ips": {"127.0.0.1": rep}, "not_sampled": [],
                            "error": None, "leaf": {}, "test_ca": {"publicly_trusted": False, "ct_required": False}}
    rules = {i.rule for i in tls.run(ctx)}
    assert "WEB708" in rules and "WEB072" in rules       # browsers reject a SHA-1 chain (verify code 68)


def test_leaf_only_server_gives_code_20(server_factory):
    s = server_factory("leaf.pem")
    rep = probe.probe_ip(Connector(s.port), "localhost", s.port, "127.0.0.1", profile="minimal", timeout=3)
    assert rep["verified"]["verify_code"] == 20 and len(rep["chain"]) == 1


# ----------------------------------------------------------------------------------------------- Fetcher integration

def test_pacing_through_the_fetcher(stub_factory):
    """≤ 5 handshakes per second per IP (§2.8 step 4), enforced by the Fetcher every tls/ connection goes through."""
    stub = stub_factory("modern")
    f = Fetcher(ScanOptions(use_proxy=False, timeout=2.0), f"https://127.0.0.1:{stub.port}/")
    rep = probe.scan_host(f, "127.0.0.1", stub.port, profile="minimal", timeout=2.0)
    assert rep["ips"]["127.0.0.1"]["status"] == "ok"
    times = stub.connections
    gaps = [b - a for a, b in zip(times, times[1:])]
    assert len(times) >= 8 and min(gaps) >= 0.15, gaps            # 0.2 s gap; slack for coarse Windows clocks
    assert f.handshakes == len(times)


def test_collect_uses_the_https_hosts_the_scan_reached(stub_factory):
    stub = stub_factory("modern")
    url = f"https://127.0.0.1:{stub.port}/"
    entry = Response(url=url, method="GET", status=200, reason="OK", http_version="HTTP/1.1", headers=HeaderList(()),
                     body=b"", truncated=False, encoding=None, request_headers=HeaderList(()), elapsed=0.0,
                     ip="127.0.0.1", error=None, chain=[], source="entry")
    opts = ScanOptions(profile="minimal", use_proxy=False, timeout=2.0)
    ctx = ScanContext(options=opts, target=url, entry=entry, coverage=coverage.Coverage())
    ctx.fetcher = Fetcher(opts, url)
    out = tls.collect(ctx)
    assert list(out) == [f"127.0.0.1:{stub.port}"]
    assert out[f"127.0.0.1:{stub.port}"]["ips"]["127.0.0.1"]["versions"]["TLSv1.3"]["state"] == "yes"
    assert tls.collect(ctx) is out                       # idempotent: a host is probed once


def test_collect_skips_plain_http_and_unreached_hosts():
    url = "http://example.test/"
    entry = Response(url=url, method="GET", status=200, reason="OK", http_version="HTTP/1.1", headers=HeaderList(()),
                     body=b"", truncated=False, encoding=None, request_headers=HeaderList(()), elapsed=0.0, ip=None,
                     error=None, chain=[], source="entry")
    ctx = ScanContext(options=ScanOptions(), target=url, entry=entry)
    ctx.fetcher = object()
    assert tls.collect(ctx) == {}
