"""tls/raw.py: ClientHello builder and plaintext reply parser (spec §2.8 step 3, WP10).

The parser is checked on server flights recorded from OpenSSL 3.0.13 / 3.5.9 (tests/data/web/certs/tls-flights.json:
TLS 1.0, 1.2, 1.3, HRR for X25519MLKEM768, alerts, DOWNGRD sentinel, a full TLS 1.2 flight with OCSP staple and SCTs)
and on SSLv2/SSLv3 flights built by the stub (no current OpenSSL can serve them). Offline: socketpairs only.
"""

from __future__ import annotations

import json
import random
import socket
import struct
import sys
from pathlib import Path

import pytest

from vulnscan.webscan.tls import raw, x509

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tls_stub  # noqa: E402

FLIGHTS = json.loads((Path(__file__).resolve().parent.parent / "data" / "web" / "certs" / "tls-flights.json")
                     .read_text(encoding="utf-8"))["flights"]


def flight(name: str) -> bytes:
    return bytes.fromhex(FLIGHTS[name]["hex"])


def parse_hello(data: bytes) -> tls_stub.Hello:
    a, b = socket.socketpair()
    try:
        a.sendall(data)
        return tls_stub.read_hello(b)
    finally:
        a.close()
        b.close()


# ----------------------------------------------------------------------------------------------- builder

def test_client_hello_layout_tls12():
    h = raw.client_hello("example.test", raw.TLS12, raw.LEGACY_SUITES, random=bytes(32), session_id=bytes(32))
    assert h[:3] == b"\x16\x03\x01"                       # handshake record, record version 0x0301 like browsers
    assert struct.unpack(">H", h[3:5])[0] == len(h) - 5
    assert h[5] == 1                                       # ClientHello
    p = parse_hello(h)
    assert p.version == raw.TLS12 and p.record_version == raw.TLS10
    assert set(p.suites) == set(raw.LEGACY_SUITES)
    assert p.compression == (0,)
    assert raw.EXT_RENEG in p.extensions and p.extensions[raw.EXT_RENEG] == b"\x00"
    assert raw.EXT_STATUS_REQUEST in p.extensions and raw.EXT_SCT in p.extensions
    assert raw.EXT_SUPPORTED_VERSIONS not in p.extensions
    sni = p.extensions[0]
    assert sni.endswith(b"example.test")


def test_client_hello_tls13_and_empty_key_share():
    h = raw.client_hello("example.test", raw.TLS13, raw.TLS13_SUITES, groups=(raw.X25519MLKEM768,), key_share_groups=())
    p = parse_hello(h)
    assert p.version == raw.TLS12                          # legacy_version
    assert p.offered_versions == (raw.TLS13, raw.TLS12)
    assert p.groups() == (raw.X25519MLKEM768,)
    assert p.key_share_groups() == ()                      # empty list: a server supporting the group must send HRR
    full = parse_hello(raw.client_hello("example.test", raw.TLS13, raw.TLS13_SUITES))
    assert full.key_share_groups() == (0x001D,)


def test_no_sni_for_ip_literals_and_padding():
    for host in ("127.0.0.1", "::1", "[::1]".strip("[]")):
        p = parse_hello(raw.client_hello(host, raw.TLS12, raw.LEGACY_SUITES))
        assert 0 not in p.extensions                       # RFC 6066: no IP literal in server_name
    # hellos of 256..511 bytes are padded to 512 (RFC 7685), as browsers do for old load balancers
    for suites in (raw.TLS13_SUITES, raw.LEGACY_SUITES[:30], raw.LEGACY_SUITES):
        h = raw.client_hello("a.example.test", raw.TLS12, suites)
        message = len(h) - 5                               # handshake message incl. its 4-byte header
        assert not (0xFF < message < 0x200), message


def test_sslv2_and_sslv3_hellos():
    v2 = raw.sslv2_client_hello(challenge=bytes(16))
    assert v2[:11] == bytes.fromhex("802e0100020015000000" "10")
    assert len(v2) == 2 + 0x2E
    p = parse_hello(v2)
    assert p.sslv2 and p.version == raw.SSL2
    v3 = raw.sslv3_client_hello(random=bytes(32))
    assert v3[:3] == b"\x16\x03\x00"
    p3 = parse_hello(v3)
    assert p3.version == raw.SSL3 and raw.SCSV_RENEGOTIATION in p3.suites and p3.extensions == {}


def test_suite_categories():
    assert raw.suite_category(0x0005) == "rc4"
    assert raw.suite_category(0x000A) == "3des"
    assert raw.suite_category(0x0002) == "null"
    assert raw.suite_category(0x0034) == "anon"
    assert raw.suite_category(0x0003) == "export"
    assert raw.suite_category(0x0009) == "des"
    assert raw.suite_category(0x009C) == "krsa"
    assert raw.suite_category(0xC013) == "cbc"
    assert raw.suite_category(0xC02F) == "good"
    for name, suites in raw.CATEGORY_PROBES.items():
        assert suites, name
        assert not set(suites) & set(raw.TLS13_ALL_SUITES)
    assert set(raw.MOZILLA_INTERMEDIATE) <= set(raw.CATEGORY_PROBES["aead"])


# ----------------------------------------------------------------------------------------------- recorded flights

@pytest.mark.parametrize("name", sorted(FLIGHTS))
def test_recorded_flights_parse_as_recorded(name):
    rec = FLIGHTS[name]
    fl = raw.parse_flight(flight(name), eof=True)
    assert fl.result == rec["result"]
    assert (fl.version_name or "") == (rec["version"] or "")
    assert raw.suite_name(fl.cipher) == (rec["cipher"] or "")
    assert (list(fl.alert) if fl.alert else None) == rec["alert"]
    assert fl.done


def test_full_tls12_flight_details():
    fl = raw.parse_flight(flight("tls12_full"))
    assert fl.done and fl.result == "hello" and fl.version == raw.TLS12
    assert fl.downgrade == "tls12"                          # DOWNGRD sentinel: the server also speaks TLS 1.3
    assert raw.EXT_RENEG in fl.extensions and raw.EXT_STATUS_REQUEST in fl.extensions
    assert len(fl.certs) == 2
    leaf = x509.parse_certificate(fl.certs[0])
    assert leaf.subject_cn == "localhost" and leaf.must_staple
    assert fl.ocsp is not None and x509.parse_ocsp_response(fl.ocsp).cert_status == "good"
    scts = x509.parse_sct_list(fl.extensions[raw.EXT_SCT], source="tls")
    assert len(scts) == 2 and all(s.source == "tls" for s in scts)
    assert raw.parse_ske(fl.ske, "ECDHE") == {"group": "x25519"}


def test_hrr_downgrade_and_negotiate_down_flights():
    hrr = raw.parse_flight(flight("hrr_x25519mlkem768"))
    assert hrr.hrr and hrr.version == raw.TLS13 and hrr.selected_group() == raw.X25519MLKEM768
    sh13 = raw.parse_flight(flight("tls13_sh"))
    assert not sh13.hrr and sh13.version == raw.TLS13 and sh13.legacy_version == raw.TLS12
    down = raw.parse_flight(flight("tls10_answers_tls12"))
    assert down.version == raw.TLS10                        # asked for 1.2, got 1.0: "TLS 1.2 not supported"
    only12 = raw.parse_flight(flight("tls12_only_answers_tls13"))
    assert only12.version == raw.TLS12 and only12.downgrade is None
    dhe = raw.parse_flight(flight("tls12_dhe1024"))
    ske = raw.parse_ske(dhe.ske, "DHE")
    # recorded fact: OpenSSL 3.0.13's s_server used its automatic 2048-bit group despite -dhparam dh1024.pem
    assert ske["dh_bits"] == 2048 and len(ske["dh_prime"]) == 256
    weak = tls_stub.StubServer("dhe1024")
    try:
        data = weak.respond(parse_hello(raw.client_hello("localhost", raw.TLS12, raw.DHE_SUITES)))
    finally:
        weak.stop()
    ske = raw.parse_ske(raw.parse_flight(data).ske, "DHE")
    assert ske["dh_bits"] == 1024 and int.from_bytes(ske["dh_prime"], "big") == tls_stub.OAKLEY2


def test_synthetic_sslv2_and_sslv3_flights():
    leaf = tls_stub.fixture_der("leaf.pem")
    v2 = raw.parse_flight(tls_stub.sslv2_server_hello(leaf))
    assert v2.result == "hello" and v2.version == raw.SSL2 and v2.done
    srv = tls_stub.StubServer("sslv3_only")
    try:
        data = srv.respond(parse_hello(raw.sslv3_client_hello()))
    finally:
        srv.stop()
    v3 = raw.parse_flight(data)
    assert v3.result == "hello" and v3.version == raw.SSL3 and v3.extensions == {} and len(v3.certs) == 2


def test_alert_and_non_tls_replies():
    fl = raw.parse_flight(tls_stub.alert(70))
    assert fl.result == "alert" and fl.alert == (2, 70)
    http = raw.parse_flight(b"HTTP/1.1 400 Bad Request\r\n\r\n")
    assert http.result == "not_tls" and http.done
    assert raw.parse_flight(b"", eof=True).result == "eof"
    assert raw.parse_flight(b"").result == "incomplete"


def test_parser_never_raises_on_truncated_or_random_input():
    rng = random.Random(1234)
    samples = [flight(n) for n in FLIGHTS] + [tls_stub.sslv2_server_hello(tls_stub.fixture_der("leaf.pem"))]
    for data in samples:
        for cut in range(0, len(data), max(1, len(data) // 60)):
            for eof in (False, True):
                fl = raw.parse_flight(data[:cut], eof=eof)
                assert fl.result in ("hello", "alert", "eof", "not_tls", "incomplete")
                if eof:
                    assert fl.done
    for _ in range(400):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 300)))
        if rng.random() < 0.5:
            blob = b"\x16\x03\x03" + blob
        raw.parse_flight(blob, eof=True)
        raw.parse_ske(blob, "DHE")
        raw.parse_ske(blob, "ECDHE")


def test_flight_flips_bits_without_crashing():
    data = bytearray(flight("tls12_full"))
    rng = random.Random(7)
    for _ in range(300):
        d = bytearray(data)
        for _ in range(3):
            d[rng.randrange(len(d))] = rng.randrange(256)
        raw.parse_flight(bytes(d), eof=True)


# ----------------------------------------------------------------------------------------------- exchange()

def test_exchange_reads_a_flight_sent_in_pieces():
    a, b = socket.socketpair()
    data = flight("tls12_full")
    try:
        import threading

        def server():
            b.recv(4096)
            for i in range(0, len(data), 97):
                b.sendall(data[i:i + 97])

        t = threading.Thread(target=server, daemon=True)
        t.start()
        fl, got = raw.exchange(a, raw.client_hello("localhost", raw.TLS12, raw.LEGACY_SUITES), 5.0)
        t.join(2)
        assert fl.result == "hello" and fl.done and len(fl.certs) == 2 and got == data
    finally:
        a.close()
        b.close()


def test_exchange_timeout_and_eof():
    a, b = socket.socketpair()
    try:
        fl, _ = raw.exchange(a, b"\x16\x03\x01\x00\x00", 0.3)
        assert fl.result == "timeout"
    finally:
        a.close()
        b.close()
    a, b = socket.socketpair()
    try:
        b.close()
        fl, _ = raw.exchange(a, b"\x16\x03\x01\x00\x00", 1.0)
        assert fl.result == "eof"
    finally:
        a.close()
