"""Adversarial review of WP10 (spec §2.8, §0.6): regressions for the defects found in review. Offline: synthetic
``ctx.tls`` reports built from the fixture certificates, and servers on 127.0.0.1 only."""

from __future__ import annotations

import base64
import dataclasses
import socket
import sys
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest

from vulnscan import i18n
from vulnscan.webscan.tls import assess, probe, raw, x509

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_tls_assess import NOW, b64, fired, ip_report, run, state  # noqa: E402
from test_tls_probe import Connector  # noqa: E402

CERTS = Path(__file__).resolve().parent.parent / "data" / "web" / "certs"
PUBLIC = {"publicly_trusted": True, "ct_required": True}


def der(name: str) -> bytes:
    return x509.pem_to_der_list((CERTS / name).read_text(encoding="ascii"))[0]


def enc(d: bytes) -> str:
    return base64.b64encode(d).decode("ascii")


# ----------------------------------------------------------------------------------------------- expired chain

def test_expired_intermediate_is_web070_not_silence():
    # OpenSSL code 10 while the leaf is valid: an intermediate expired (here one from the store); 1.1.0-rc said nothing
    issues, ctx = run(ip_report(verified=False, code=10), test_ca=PUBLIC)
    f = fired(issues, "WEB070")
    assert len(f) == 1 and f[0].group_value == "chain_expired" and f[0].severity == "high"
    assert any("trust store" in n[0] for n in f[0].notes)
    assert state(ctx, "WEB072") == "pass"


def test_not_yet_valid_intermediate_is_web720_but_leaf_skew_is_not():
    issues, _ = run(ip_report(verified=False, code=9), test_ca=PUBLIC)
    assert [i.group_value for i in fired(issues, "WEB720")] == ["chain_not_yet_valid"]
    leaf = x509.parse_certificate(der("leaf.pem"))
    issues, _ = run(ip_report(verified=False, code=9), now=leaf.not_before - timedelta(minutes=2), test_ca=PUBLIC)
    assert not fired(issues, "WEB720")                       # the leaf itself, inside the 5-minute allowance


def test_expired_leaf_keeps_the_1_0_1_group():
    leaf = x509.parse_certificate(der("leaf.pem"))
    issues, _ = run(ip_report(verified=False, code=10), now=leaf.not_after + timedelta(days=1))
    assert [i.group_value for i in fired(issues, "WEB070")] == ["expired"]


# ----------------------------------------------------------------------------------------------- Arabic counts

def test_arabic_count_agreement_in_notes():
    issues, _ = run(ip_report(sent=("manysan.pem", "int.pem")), test_ca={"publicly_trusted": False, "ct_required": False})
    note = fired(issues, "WEB717")[0].notes[0]
    assert note == ("105 names in one certificate", "105 أسماء في شهادة واحدة")
    moz = [n for n in fired(issues, "WEB718")[0].notes if n[0].startswith("lifetime")][0]
    assert moz == ("lifetime 7305 days (maximum 366 days)", "مدة الصلاحية 7305 أيام (الحد الأقصى 366 يومًا)")
    issues, _ = run(ip_report(), test_ca=PUBLIC)
    n709 = fired(issues, "WEB709")[0].notes[0]
    assert "7305 أيام" in n709[1] and "200 يوم" in n709[1] and "200 days" in n709[0]


@pytest.mark.parametrize("n,ar", [(1, "اسم واحد"), (2, "اسمان"), (5, "5 أسماء"), (11, "11 اسمًا"), (100, "100 اسم"),
                                  (105, "105 أسماء"), (150, "150 اسمًا")])
def test_count_forms(n, ar):
    assert assess._count(n, "names")[1] == ar


def test_every_tls_note_translates_back_to_english():
    issues, _ = run(ip_report(sent=("manysan.pem", "int.pem")), test_ca=PUBLIC)
    issues2, _ = run(ip_report(verified=False, code=10), test_ca=PUBLIC)
    for i in issues + issues2:
        for en, ar in i.notes:
            assert i18n.to_en(ar) == en, (i.rule, ar)


def test_i18n_catalog_patterns_are_regular_expressions_that_match():
    import re
    exact, patterns = assess.i18n_catalog()
    compiled = [(re.compile(rx), en) for rx, en in patterns]
    assert all(rx.pattern.startswith("^") for rx, _ in compiled)
    en, ar = assess._t("lifetime", days=assess._count(400, "days"), issued="2026-04-01", limit=assess._count(200, "days"))
    assert any(rx.fullmatch(ar) for rx, _ in compiled)
    assert exact["يوم واحد"] == "1 day"


# ----------------------------------------------------------------------------------------------- hostile certificates

def test_giant_oid_is_rejected_quickly():
    t = time.monotonic()
    with pytest.raises(x509.X509Error):
        x509.oid_str(b"\x2a" + b"\xff" * 200_000 + b"\x01")
    with pytest.raises(x509.X509Error):
        x509.oid_str(b"\x2a" + b"\x81" * 20 + b"\x01")
    assert time.monotonic() - t < 0.5
    assert x509.oid_str(bytes.fromhex("2a864886f70d01010b")) == "1.2.840.113549.1.1.11"


def test_giant_modulus_skips_fermat_and_roca_and_is_info():
    n = (1 << 1_600_000) | 1
    t = time.monotonic()
    assert not x509.fermat_factorable(n) and not x509.roca_vulnerable(n)
    assert time.monotonic() - t < 0.5
    leaf = x509.parse_certificate(der("leaf.pem"))
    huge = dataclasses.replace(leaf, rsa_modulus=(1 << 20000) | 1, key_bits=20001)
    out = assess._Ip("192.0.2.1")
    assess._key(out, huge)
    cand = out.cands[("WEB707", "odd_size")]
    assert cand["severity"] == "info" and "16384" in cand["notes"][0][0]


def test_control_characters_in_names_are_dropped():
    d = der("leaf.pem").replace(b"Kashif", b"\x1b[31mX")   # issuer CN of the leaf; same length, signature now bogus
    c = x509.parse_certificate(d)
    assert "\x1b" not in c.issuer and "[31mX" in c.issuer
    assert x509.clean_text("a\x00b\x9bc\nd") == "abcd"


def test_serial_is_capped_in_the_summary():
    leaf = x509.parse_certificate(der("leaf.pem"))
    big = dataclasses.replace(leaf, serial_hex="ab" * 5000)
    assert len(big.summary()["serial"]) <= 64


# ----------------------------------------------------------------------------------------------- false positives

def _reissued(name: str) -> bytes:
    """The same CA certificate with another signature value (stands for a reissue: same subject and key)."""
    d = bytearray(der(name))
    d[-1] ^= 0x01
    return bytes(d)


def test_store_copy_of_a_sent_intermediate_is_not_web702():
    rep = ip_report()
    rep["verified"]["verified_chain"] = [b64("leaf.pem"), enc(_reissued("int.pem")), b64("root.pem")]
    issues, ctx = run(rep, test_ca=PUBLIC)
    assert not fired(issues, "WEB702") and state(ctx, "WEB702") == "pass"
    rep = ip_report(sent=("leaf.pem",))                       # really missing: still reported
    issues, _ = run(rep, test_ca=PUBLIC)
    assert fired(issues, "WEB702")


def test_name_encoding_difference_does_not_break_the_chain_order():
    leaf = x509.parse_certificate(der("leaf.pem"))
    inter = x509.parse_certificate(der("int.pem"))
    odd = dataclasses.replace(leaf, issuer_raw=b"\x31\x00", issuer="cn=kashif  test intermediate")
    out = assess._Ip("192.0.2.1")
    assess._order(out, {"chain_source": "ssl"}, [odd, inter], False)
    assert "WEB703" not in {k[0] for k in out.cands}


def test_locally_installed_private_ca_is_not_judged_by_public_rules():
    # a leaf without a CA/B Forum policy OID that verifies only because its root is in the local store (enterprise CA)
    rep = ip_report(sent=("ecleaf.pem", "int.pem"), verified_chain=("ecleaf.pem", "int.pem", "root.pem"))
    issues, ctx = run(rep)
    assert not fired(issues, "WEB709") and not fired(issues, "WEB713")
    assert state(ctx, "WEB709") == "not_applicable" and state(ctx, "WEB713") == "not_applicable"
    assert any("CA/Browser Forum policy" in n[0] for n in ctx.inventory["tls"]["localhost"]["notes"])
    issues, _ = run(rep, test_ca=PUBLIC)                       # the corpus hook still marks its CA as public
    assert fired(issues, "WEB709")
    issues, _ = run(ip_report())                               # a DV leaf (policy 2.23.140.1.2.1) stays public
    assert fired(issues, "WEB709")


def test_web715_ignores_items_undecided_on_one_node():
    a = ip_report(ip="192.0.2.1")
    b = ip_report(ip="192.0.2.2", cats={"rc4": "inconclusive"})
    b["compression"] = None
    issues, ctx = run(a, b)
    assert not fired(issues, "WEB715") and state(ctx, "WEB715") == "pass"
    c = ip_report(ip="192.0.2.3", versions={"TLSv1.0": "yes"})
    issues, _ = run(a, c)
    f = fired(issues, "WEB715")
    assert len(f) == 1 and "protocol versions" in f[0].notes[0][0]


# ----------------------------------------------------------------------------------------------- probe behaviour

class _Tarpit:
    """Accepts connections and never answers."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.conns: list[socket.socket] = []
        self._stop = threading.Event()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                c, _ = self.sock.accept()
                self.conns.append(c)
            except OSError:
                continue

    def close(self):
        self._stop.set()
        for c in self.conns:
            c.close()
        self.sock.close()


def test_silent_server_costs_few_timeouts():
    tp = _Tarpit()
    try:
        con = Connector(tp.port)
        t = time.monotonic()
        rep = probe.probe_ip(con, "localhost", tp.port, "127.0.0.1", profile="standard", timeout=1.0)
        took = time.monotonic() - t
    finally:
        tp.close()
    assert rep["backoff"] is True and rep["verified_legacy"] is None      # no second wait at security level 0
    assert len(con.opened) <= 3 and took < 5.0
    assert all(v["state"] == "inconclusive" for v in rep["versions"].values())


class _Refusing:
    """An IpSession stand-in whose every raw hello is refused with alert 40."""

    backed_off = False

    def send(self, hello):
        return raw.Flight(result="alert", alert=(2, 40), done=True)


def test_raw_refusals_are_not_evidence_when_a_normal_handshake_disagrees():
    rep = {"versions": {"TLSv1.2": {"state": "yes", "source": "ssl"}, "TLSv1.3": {"state": "no"}}, "categories": {},
           "compression": None,
           "verified": {"version": "TLSv1.2", "cipher": "ECDHE-RSA-AES128-GCM-SHA256"}}
    flights = {"TLSv1.2": raw.Flight(result="alert", alert=(2, 40), done=True)}
    probe._categories(rep, _Refusing(), "localhost", "TLSv1.2", flights)
    cats = rep["categories"]
    assert cats["aead"]["state"] == "yes" and cats["aead"]["source"] == "ssl"
    assert all(cats[n]["state"] == "inconclusive" for n in ("rc4", "3des", "krsa", "null_anon", "export_des", "cbc"))
    assert rep["compression"] is None
    # and the assessment then reports nothing as passed or failed on suites
    ipr = ip_report(cats={"aead": "yes"})
    ipr["categories"] = cats
    issues, ctx = run(ipr)
    assert not fired(issues, "WEB706") and state(ctx, "WEB706") == "not_tested"


def test_raw_refusals_still_count_when_the_raw_hello_of_that_version_worked():
    rep = {"versions": {"TLSv1.2": {"state": "yes"}, "TLSv1.3": {"state": "no"}}, "categories": {}, "compression": None}
    flights = {"TLSv1.2": raw.Flight(result="hello", version=raw.TLS12, cipher=0xC02F, done=True)}
    probe._categories(rep, _Refusing(), "localhost", "TLSv1.2", flights)
    assert rep["categories"]["rc4"]["state"] == "no" and rep["compression"] is False
    assert rep["categories"]["aead"]["state"] == "yes"


def test_now_constant_is_aware():
    assert NOW.tzinfo is not None


# ----------------------------------------------------------------------------------------------- OCSP-delivered SCTs

def _tlv(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    ln = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(ln)]) + ln + body


def _sct(log_id: bytes, ms: int) -> bytes:
    body = b"\x00" + log_id + ms.to_bytes(8, "big") + b"\x00\x00" + b"\x04\x03\x00\x02\x30\x00"
    return len(body).to_bytes(2, "big") + body


def ocsp_with_scts(log_ids, *, where: str = "single") -> bytes:
    """A minimal RFC 6960 OCSPResponse (status good) carrying an RFC 6962 SCT list extension."""
    gt = _tlv(0x18, b"20261112000000Z")
    later = _tlv(0x18, b"20261120000000Z")
    lst = b"".join(_sct(i, 1_794_000_000_000) for i in log_ids)
    ext = _tlv(0x30, _tlv(0x06, x509.OCSP_SCT_OID) + _tlv(0x04, _tlv(0x04, len(lst).to_bytes(2, "big") + lst)))
    exts = _tlv(0xA1, _tlv(0x30, ext))
    cert_id = _tlv(0x30, _tlv(0x30, _tlv(0x06, bytes.fromhex("2b0e03021a")) + b"\x05\x00") + _tlv(0x04, b"\x00" * 20)
                   + _tlv(0x04, b"\x00" * 20) + _tlv(0x02, b"\x01"))
    single = _tlv(0x30, cert_id + b"\x80\x00" + gt + _tlv(0xA0, later) + (exts if where == "single" else b""))
    rdata = _tlv(0x30, _tlv(0xA2, _tlv(0x04, b"\x00" * 20)) + gt + _tlv(0x30, single)
                 + (exts if where == "response" else b""))
    basic = _tlv(0x30, rdata + _tlv(0x30, _tlv(0x06, bytes.fromhex("2a864886f70d01010b")) + b"\x05\x00")
                 + _tlv(0x03, b"\x00" + b"\x00" * 16))
    rb = _tlv(0x30, _tlv(0x06, bytes.fromhex("2b0601050507300101")) + _tlv(0x04, basic))
    return _tlv(0x30, b"\x0a\x01\x00" + _tlv(0xA0, rb))


@pytest.mark.parametrize("where", ["single", "response"])
def test_scts_stapled_in_ocsp_satisfy_ct(where):
    from test_tls_assess import LOGS, Data
    ids = [base64.b64decode(k) for k in LOGS]
    resp = x509.parse_ocsp_response(ocsp_with_scts(ids, where=where))
    assert resp.cert_status == "good" and resp.has_scts and {s.log_id for s in resp.scts} == set(ids)
    staple = {"state": "stapled", "der": enc(ocsp_with_scts(ids, where=where)), "reason": ""}
    issues, ctx = run(ip_report(ocsp=staple), test_ca=PUBLIC, data=Data(LOGS, NOW.date()))
    assert not fired(issues, "WEB713") and state(ctx, "WEB713") == "pass"
    staple1 = {"state": "stapled", "der": enc(ocsp_with_scts(ids[:1], where=where)), "reason": ""}
    issues, _ = run(ip_report(ocsp=staple1), test_ca=PUBLIC, data=Data(LOGS, NOW.date()))
    assert [i.severity for i in fired(issues, "WEB713")] == ["low"]          # one SCT is not enough, but not "none"


class _Dripper(_Tarpit):
    """Answers every connection with one zero byte every 0.2 s (never a whole TLS record)."""

    def _loop(self):
        while not self._stop.is_set():
            try:
                c, _ = self.sock.accept()
            except OSError:
                continue
            self.conns.append(c)
            threading.Thread(target=self._drip, args=(c,), daemon=True).start()

    def _drip(self, c):
        try:
            c.settimeout(5)
            c.recv(4096)
            while not self._stop.is_set():
                c.sendall(b"\x16")
                time.sleep(0.2)
        except OSError:
            pass


def test_dripping_server_triggers_the_back_off():
    dr = _Dripper()
    try:
        con = Connector(dr.port)
        sess = probe.IpSession(con, "localhost", dr.port, "127.0.0.1", timeout=0.6)
        results = [sess.send(raw.client_hello("localhost", raw.TLS12, raw.LEGACY_SUITES)) for _ in range(4)]
    finally:
        dr.close()
    assert results[0].detail == raw.PARTIAL_TIMEOUT
    assert sess.backed_off and len(con.opened) == 3 and results[-1].result == "skipped"


def test_unreadable_staple_is_not_tested_not_pass():
    staple = {"state": "stapled", "der": enc(b"\x30\x03\x0a\x01"), "reason": ""}
    issues, ctx = run(ip_report(ocsp=staple))
    assert not fired(issues, "WEB714") and state(ctx, "WEB714") == "not_tested"


def test_a_probe_crash_on_one_host_becomes_not_tested(monkeypatch):
    from vulnscan.webscan import coverage
    from vulnscan.webscan.types import HeaderList, Response, ScanContext, ScanOptions
    url = "https://crash.test/"
    entry = Response(url=url, method="GET", status=200, reason="OK", http_version="HTTP/1.1", headers=HeaderList(()),
                     body=b"", truncated=False, encoding=None, request_headers=HeaderList(()), elapsed=0.0, ip=None,
                     error=None, chain=[], source="entry")
    ctx = ScanContext(options=ScanOptions(), target=url, entry=entry, coverage=coverage.Coverage(), now=NOW)

    def boom(*a, **k):
        raise RuntimeError("bug")
    monkeypatch.setattr(probe, "scan_host", boom)
    out = probe.collect(ctx, connector=object())
    assert out["crash.test"]["error"]["code"] == "error"
    from vulnscan.webscan import tls
    assert tls.run(ctx) == [] and ctx.coverage.state("WEB070").state == "not_tested"


def test_leaf_only_unknown_issuer_without_cab_policy_is_private_ca_not_incomplete_chain():
    issues, ctx = run(ip_report(sent=("ecleaf.pem",), verified=False, code=20))
    assert not fired(issues, "WEB702") and state(ctx, "WEB702") == "not_tested"
    f = fired(issues, "WEB701")
    assert len(f) == 1 and f[0].confidence == "tentative"
    issues, _ = run(ip_report(sent=("leaf.pem",), verified=False, code=20))         # DV leaf: missing intermediate
    assert fired(issues, "WEB702") and not fired(issues, "WEB701")
    issues, _ = run(ip_report(sent=("ecleaf.pem",), verified=False, code=20), test_ca=PUBLIC)   # corpus hook
    assert fired(issues, "WEB702")


def test_tls13_only_server_is_not_an_intermediate_profile_deviation():
    issues, ctx = run(ip_report(versions={"TLSv1.2": "no"}), test_ca={"publicly_trusted": False, "ct_required": False})
    devs = [n[0] for i in fired(issues, "WEB718") for n in i.notes]
    assert "TLS 1.2 disabled" not in devs
    inter = assess.mozilla_deviations(ip_report(versions={"TLSv1.2": "no", "TLSv1.3": "no", "TLSv1.0": "yes"}), None,
                                      {"tls_versions": ["TLSv1.2", "TLSv1.3"]}, deep=False)[0]
    assert ("TLS 1.2 disabled", "TLS 1.2 معطّل") in inter and ("TLS 1.0 enabled", "TLS 1.0 مفعّل") in inter


class _LazyStapler:
    """Refuses every category hello; the full-suite compression hello is answered with a staple (nginx after its
    lazy OCSP fetch)."""

    backed_off = False

    @staticmethod
    def _compression_methods(hello: bytes) -> int:
        p = 5 + 4 + 2 + 32
        p += 1 + hello[p]
        p += 2 + int.from_bytes(hello[p:p + 2], "big")
        return hello[p]

    def send(self, hello):
        if self._compression_methods(hello) == 2:            # the DEFLATE + null compression hello
            return raw.Flight(result="hello", version=raw.TLS12, cipher=0xC02F, compression=0, ocsp=b"\x30\x00",
                              done=True)
        return raw.Flight(result="alert", alert=(2, 40), done=True)


def test_late_staple_from_a_later_handshake_is_used():
    rep = {"versions": {"TLSv1.2": {"state": "yes"}, "TLSv1.3": {"state": "no"}}, "categories": {}, "compression": None,
           "ocsp": {"state": "absent", "der": None, "reason": ""}}
    flights = {"TLSv1.2": raw.Flight(result="hello", version=raw.TLS12, cipher=0xC02F, done=True)}
    probe._categories(rep, _LazyStapler(), "localhost", "TLSv1.2", flights)
    assert rep["ocsp"]["state"] == "stapled" and rep["ocsp"]["late"] is True and rep["compression"] is False
