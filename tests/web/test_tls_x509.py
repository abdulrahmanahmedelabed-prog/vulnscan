"""tls/x509.py: DER reader, SCT list, OCSP, host-name matching, ROCA and Fermat (spec §2.8, WP10).

Fixtures in tests/data/web/certs/ (README there): a test PKI generated with the openssl CLI, two certificates from the
ROCA authors' test data (crocs-muni/roca, MIT) and a research-lab certificate with two embedded SCTs. Python's own
DER decoder (``ssl._ssl._test_decode_cert``, private but present in 3.10–3.14) is used as an independent oracle.
"""

from __future__ import annotations

import random
import ssl
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vulnscan.webscan.tls import x509

CERTS = Path(__file__).resolve().parent.parent / "data" / "web" / "certs"
PEMS = sorted(p.name for p in CERTS.glob("*.pem"))


def load(name: str) -> x509.Certificate:
    return x509.parse_certificate(der(name))


def der(name: str) -> bytes:
    return x509.pem_to_der_list((CERTS / name).read_text(encoding="ascii"))[0]


# ----------------------------------------------------------------------------------------------- parsing

@pytest.mark.parametrize("name", PEMS)
def test_matches_pythons_own_decoder(name):
    oracle = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if oracle is None:
        pytest.skip("ssl._ssl._test_decode_cert not available")
    ref = oracle(str(CERTS / name))
    c = load(name)
    fmt = "%b %d %H:%M:%S %Y %Z"
    assert c.not_before == datetime.strptime(ref["notBefore"], fmt).replace(tzinfo=timezone.utc)
    assert c.not_after == datetime.strptime(ref["notAfter"], fmt).replace(tzinfo=timezone.utc)
    assert int(c.serial_hex, 16) == int(ref["serialNumber"], 16)
    ref_cn = [v for rdn in ref["subject"] for k, v in rdn if k == "commonName"]
    assert (c.subject_cn is None and not ref_cn) or c.subject_cn == ref_cn[0]
    ref_dns = [v for k, v in ref.get("subjectAltName", ()) if k == "DNS"]
    assert c.san_dns == ref_dns
    ref_ip = [v for k, v in ref.get("subjectAltName", ()) if k == "IP Address"]
    assert c.san_ip == ref_ip
    assert c.ocsp_urls == list(ref.get("OCSP", ()))
    assert c.ca_issuers == list(ref.get("caIssuers", ()))
    assert c.crl_urls == list(ref.get("crlDistributionPoints", ()))
    assert c.version == ref["version"]


def test_leaf_fields():
    c = load("leaf.pem")
    assert c.key_type == "RSA" and c.key_bits == 2048 and c.rsa_exponent == 65537
    assert c.sig_alg == "sha256WithRSAEncryption" and c.sig_hash == "sha256"
    assert c.subject_cn == "localhost" and c.issuer_cn == "Kashif Test Intermediate"
    assert c.has_san and c.san_dns == ["localhost"] and c.san_ip == ["127.0.0.1"]
    assert c.eku == ["serverAuth"] and not c.is_ca and not c.must_staple
    assert c.validation == "DV" and c.policies == ["2.23.140.1.2.1"]
    assert c.aki is not None and c.ski is not None and not c.self_issued
    assert round(c.lifetime) == 7305
    s = c.summary()
    assert s["key"] == "RSA 2048 e=65537" and s["not_after"] == "2046-11-01T00:00:00Z" and s["san_count"] == 2


def test_special_certificates():
    assert load("muststaple.pem").must_staple
    ec = load("ecleaf.pem")
    assert ec.key_type == "EC" and ec.curve == "secp256r1" and ec.key_bits == 256 and ec.rsa_equiv_bits == 3072
    assert load("sha1leaf.pem").sig_hash == "sha1"
    assert load("rsa1024leaf.pem").key_bits == 1024
    cn = load("cnonly.pem")
    assert not cn.has_san and cn.subject_cn == "localhost"
    assert load("noaki.pem").aki is None
    assert load("clientauth.pem").eku == ["clientAuth"]
    assert load("selfsigned.pem").self_issued
    root, inter = load("root.pem"), load("int.pem")
    assert root.is_ca and root.self_issued and inter.is_ca and not inter.self_issued
    assert inter.issuer_raw == root.subject_raw and load("leaf.pem").issuer_raw == inter.subject_raw
    assert len(load("manysan.pem").san_dns) == 105


def test_embedded_scts():
    c = load("sctleaf.pem")
    assert len(c.scts) == 2
    assert c.scts[0].log_id == bytes(range(32)) and c.scts[1].log_id == bytes(range(32, 64))
    assert all(s.source == "embedded" and s.version == 0 for s in c.scts)
    assert c.scts[0].timestamp.year >= 2026
    assert c.scts[0].to_dict()["log_id"] == c.scts[0].log_id_b64


def test_sct_list_rejects_garbage():
    assert x509.parse_sct_list(b"") == []
    assert x509.parse_sct_list(b"\x00\x05\x00\x03abc") == []          # too short to be an SCT
    assert x509.parse_sct_list(b"\xff\xff") == []


def test_time_formats():
    t = x509._time(b"491231235959Z", 0x17, 0, 13)
    assert t.year == 2049
    assert x509._time(b"500101000000Z", 0x17, 0, 13).year == 1950
    assert x509._time(b"20501231235959Z", 0x18, 0, 15).year == 2050
    with pytest.raises(x509.X509Error):
        x509._time(b"20501399000000Z", 0x18, 0, 15)


def test_malformed_input_only_raises_x509error():
    data = der("leaf.pem")
    for cut in range(0, len(data), 7):
        with pytest.raises(x509.X509Error):
            x509.parse_certificate(data[:cut])
        assert x509.try_parse(data[:cut]) is None
    rng = random.Random(42)
    for _ in range(500):
        d = bytearray(data)
        for _ in range(rng.randrange(1, 6)):
            d[rng.randrange(len(d))] = rng.randrange(256)
        try:
            x509.parse_certificate(bytes(d))
        except x509.X509Error:
            pass
    for blob in (b"", b"\x30", b"\x30\x84\xff\xff\xff\xff", b"\x30\x80", bytes(64), b"\x1f\x01\x00"):
        assert x509.try_parse(blob) is None


# ----------------------------------------------------------------------------------------------- OCSP

def test_ocsp_good_and_revoked():
    good = x509.parse_ocsp_response((CERTS / "ocsp-good.der").read_bytes())
    assert good.status == 0 and good.cert_status == "good"
    assert good.next_update is not None and good.this_update is not None and good.next_update > good.this_update
    revoked = x509.parse_ocsp_response((CERTS / "ocsp-revoked.der").read_bytes())
    assert revoked.cert_status == "revoked"
    assert x509.parse_ocsp_response(b"\x30\x03\x0a\x01\x01").status == 1      # malformedRequest, no body
    with pytest.raises(x509.X509Error):
        x509.parse_ocsp_response(b"\x30\x03\x02\x01\x00")
    with pytest.raises(x509.X509Error):
        x509.parse_ocsp_response((CERTS / "ocsp-good.der").read_bytes()[:200])


# ----------------------------------------------------------------------------------------------- host names

@pytest.mark.parametrize("host,ok", [
    ("localhost", True), ("LOCALHOST.", True), ("127.0.0.1", True), ("127.0.0.2", False), ("other", False),
    ("sub.localhost", False),
])
def test_host_matches_exact_and_ip(host, ok):
    assert x509.host_matches(load("leaf.pem"), host) is ok


@pytest.mark.parametrize("host,ok", [
    ("a.kashif.test", True), ("kashif.test", True), ("a.b.kashif.test", False), ("kashif.test.evil", False),
    ("akashif.test", False),
])
def test_host_matches_wildcard(host, ok):
    assert x509.host_matches(load("wildcard.pem"), host) is ok


def test_cn_only_certificate_never_matches():
    # browsers (and Kashif's verifying context with hostname_checks_common_name = False) ignore the CN
    assert not x509.host_matches(load("cnonly.pem"), "localhost")


def test_partial_and_short_wildcards_are_refused():
    c = load("wildcard.pem")
    c.san_dns = ["f*.example.test", "*.test", "*"]
    for h in ("foo.example.test", "example.test", "a.test", "x"):
        assert not x509.host_matches(c, h)


def test_idn_hosts_compare_as_a_labels():
    c = load("leaf.pem")
    c.san_dns = ["xn--mnchen-3ya.example"]
    assert x509.host_matches(c, "münchen.example")


# ----------------------------------------------------------------------------------------------- weak keys

# crocs-muni/roca detect.py (MIT): the fingerprint table for primes 3..167, compared with the one Kashif computes
ROCA_UPSTREAM_PREFIX = [6, 30, 126, 1026, 5658, 107286, 199410, 8388606, 536870910, 2147483646, 67109890,
                        2199023255550]


def test_roca_table_matches_the_authors_detector():
    assert list(x509._ROCA_PRINTS[:len(ROCA_UPSTREAM_PREFIX)]) == ROCA_UPSTREAM_PREFIX
    assert len(x509._ROCA_PRINTS) == 38


def test_roca_detection():
    assert x509.roca_vulnerable(load("roca-sample-positive.pem").rsa_modulus)     # ROCA authors' positive sample
    assert not x509.roca_vulnerable(load("roca-sample-negative.pem").rsa_modulus)
    assert x509.roca_vulnerable(load("roca-leaf.pem").rsa_modulus)                # Kashif's RSALib-structured key
    for name in ("leaf.pem", "rsa1024leaf.pem", "fermat-leaf.pem", "selfsigned.pem"):
        assert not x509.roca_vulnerable(load(name).rsa_modulus), name
    assert not x509.roca_vulnerable(None) and not x509.roca_vulnerable(1)


def test_fermat_detection():
    assert x509.fermat_factorable(load("fermat-leaf.pem").rsa_modulus)
    for name in ("leaf.pem", "roca-leaf.pem", "rsa1024leaf.pem"):
        assert not x509.fermat_factorable(load(name).rsa_modulus), name
    assert x509.fermat_factorable(101 * 103)
    assert x509.fermat_factorable(1009 * 1009)                                    # p == q
    assert not x509.fermat_factorable(4) and not x509.fermat_factorable(None)
    # the answer is a bool only: factors never leave the function (§0.6)
    assert x509.fermat_factorable(101 * 103) is True


def test_pem_round_trip():
    d = der("leaf.pem")
    assert x509.pem_to_der_list(x509.der_to_pem(d)) == [d]
