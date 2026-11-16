"""Raw-probe stub: a TCP server on 127.0.0.1 that answers ClientHellos with server flights (spec §5.2, WP10).

Protocol tests must not depend on the local OpenSSL build (Ubuntu's OpenSSL 3 cannot serve SSLv3, RC4, TLS
compression or a missing renegotiation_info extension at all). The stub reads one ClientHello, decides what a server
with the chosen *profile* would answer, and writes that plaintext flight in exactly the layout of the real flights
recorded from OpenSSL in ``tests/data/web/certs/tls-flights.json`` (record header, ServerHello with extensions,
Certificate, CertificateStatus, ServerKeyExchange, ServerHelloDone; for TLS 1.3 a ServerHello or HelloRetryRequest
followed by an opaque encrypted record). It never completes a handshake: the reply is all a passive probe reads.

Two ways to use it:

* **standalone** (unit tests): ``StubServer("legacy")`` answers every hello itself.
* **with an upstream** (the corpus, ``bench/web/tls_servers.py``): ``start_stub("rc4", upstream=(host, port))``
  answers only the hellos its profile is about (an RC4-only hello, an SSLv3 hello, a compression offer, …) and pipes
  every other connection to the real TLS server, so the verified handshake and the HTTP requests of the scan still work.

API used by the corpus: ``start_stub(flight, upstream=(host, port)) -> (port, stop)``.
"""

import os
import select
import socket
import ssl
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

CERT_DIR = Path(__file__).resolve().parent.parent / "data" / "web" / "certs"

SSL2, SSL3, TLS10, TLS11, TLS12, TLS13 = 0x0002, 0x0300, 0x0301, 0x0302, 0x0303, 0x0304
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
DOWNGRD = b"DOWNGRD\x01"
EXT_STATUS_REQUEST, EXT_SCT, EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE, EXT_GROUPS, EXT_RENEG = 5, 18, 43, 51, 10, 0xFF01

RC4 = (0xC007, 0xC011, 0x0005, 0x0004)
NULL_ANON = (0x0001, 0x0002, 0x003B, 0xC006, 0xC010, 0x0034, 0x003A, 0x00A6, 0xC018, 0xC019)
EXPORT_DES = (0x0003, 0x0006, 0x0008, 0x0014, 0x0009, 0x0015)
TRIPLE_DES = (0xC008, 0xC012, 0x0016, 0x000A)
KRSA = (0x009C, 0x009D, 0x003C, 0x003D, 0x002F, 0x0035, 0x0041, 0x0084)
ECDHE_GCM = (0xC02F, 0xC030, 0xCCA8, 0xC02B, 0xC02C, 0xCCA9)
ECDHE_CBC = (0xC027, 0xC028, 0xC013, 0xC014, 0xC023, 0xC024, 0xC009, 0xC00A)
DHE = (0x009E, 0x009F, 0xCCAA, 0x0067, 0x006B, 0x0033, 0x0039)
TLS13_SUITES = (0x1301, 0x1302, 0x1303)
SSL3_OK = (0x002F, 0x0035, 0x000A, 0x0005)
# suites defined only for TLS 1.2 (AEAD and SHA-256/384 MACs): never picked in a TLS 1.0/1.1 answer
TLS12_ONLY = ECDHE_GCM + (0x009C, 0x009D, 0x003C, 0x003D, 0x009E, 0x009F, 0xCCAA, 0x0067, 0x006B, 0x003B, 0x00A6,
                          0xC027, 0xC028, 0xC023, 0xC024)

# RFC 2409 Oakley group 2 (1024-bit MODP): the classic shared Logjam prime
OAKLEY2 = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
              "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
              "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)


@dataclass
class Behaviour:
    """What the emulated server supports. Suites are in server preference order."""
    versions: frozenset = frozenset({TLS12, TLS13})
    suites: tuple = ECDHE_GCM
    tls13_suites: tuple = TLS13_SUITES
    groups13: tuple = (0x001D, 0x0017, 0x0018)
    compression: bool = False
    reneg: bool = True
    server_pref: bool = True
    ocsp: bool = False                 # staple the fixture OCSP response when asked
    sct_ext: bool = False              # send an SCT list in the TLS extension
    dh_prime: int = 1 << 2047 | 1      # bit length of the DHE prime is what probes read
    mode: str = "answer"               # answer | silent | reset | alert70 | higher | garbage
    passthrough: str = "none"          # none | not_matched (with an upstream)
    match: str = "all"                 # which hellos the stub answers itself when there is an upstream


PROFILES: dict[str, Behaviour] = {
    # standalone servers
    "modern": Behaviour(),
    "tls12_only": Behaviour(versions=frozenset({TLS12}), suites=ECDHE_GCM + ECDHE_CBC),
    "tls13_only": Behaviour(versions=frozenset({TLS13}), suites=()),
    "tls10_only": Behaviour(versions=frozenset({TLS10}), suites=ECDHE_CBC + KRSA),
    "legacy": Behaviour(versions=frozenset({TLS10, TLS11, TLS12}),
                        suites=KRSA + ECDHE_GCM + ECDHE_CBC + TRIPLE_DES + RC4 + DHE, compression=True, reneg=False),
    "sslv3_only": Behaviour(versions=frozenset({SSL3}), suites=SSL3_OK),
    "sslv2": Behaviour(versions=frozenset({SSL2, TLS12}), suites=ECDHE_GCM),
    "pq": Behaviour(groups13=(0x11EC, 0x001D, 0x0017)),
    "dhe1024": Behaviour(versions=frozenset({TLS12}), suites=ECDHE_GCM + DHE, dh_prime=OAKLEY2),
    "staple": Behaviour(ocsp=True, sct_ext=True),
    "alert70": Behaviour(mode="alert70"),
    "reset": Behaviour(mode="reset"),
    "silent": Behaviour(mode="silent"),
    "higher": Behaviour(mode="higher", versions=frozenset({TLS12})),
    "garbage": Behaviour(mode="garbage"),
    # corpus profiles (meant to run with an upstream; standalone they act as described)
    "sslv3": Behaviour(versions=frozenset({SSL3, TLS12, TLS13}), suites=ECDHE_GCM + SSL3_OK, match="sslv3",
                       passthrough="not_matched"),
    "rc4": Behaviour(suites=ECDHE_GCM + RC4, match="rc4_only", passthrough="not_matched"),
    "compression": Behaviour(compression=True, match="compression", passthrough="not_matched"),
    "no_renegotiation_info": Behaviour(reneg=False, match="legacy_hello", passthrough="not_matched"),
    "timeout": Behaviour(mode="silent", match="legacy_hello", passthrough="not_matched"),
    # phase D corpus profiles (bench/web): only the raw probes named by ``match`` are answered by the stub
    "dhe1024_pt": Behaviour(versions=frozenset({TLS12}), suites=DHE, dh_prime=OAKLEY2, match="dhe_only",
                            passthrough="not_matched"),
    "higher_pt": Behaviour(mode="higher", versions=frozenset({TLS12}), match="below_tls12", passthrough="not_matched"),
    "nopq_pt": Behaviour(groups13=(0x001D, 0x0017, 0x0018), match="single_group", passthrough="not_matched"),
    "pq_pt": Behaviour(groups13=(0x11EC, 0x001D, 0x0017, 0x0018), match="single_group", passthrough="not_matched"),
}


# ----------------------------------------------------------------------------------------------- ClientHello reader
# (no ``from __future__ import annotations`` here: bench/web/tls_servers.py loads this file without registering it in
# sys.modules, and dataclasses cannot resolve string annotations of such a module)

@dataclass
class Hello:
    sslv2: bool = False
    record_version: int = 0
    version: int = 0                   # legacy_version (SSLv2: the hello's version)
    suites: tuple = ()
    compression: tuple = (0,)
    extensions: dict = field(default_factory=dict)
    raw: bytes = b""
    session_id: bytes = b""

    @property
    def offered_versions(self) -> tuple:
        sv = self.extensions.get(EXT_SUPPORTED_VERSIONS)
        if sv:
            n = sv[0]
            return tuple(struct.unpack(">H", sv[1 + i:3 + i])[0] for i in range(0, n, 2))
        return ()

    @property
    def max_version(self) -> int:
        return max(self.offered_versions or (self.version,))

    @property
    def offers_tls13(self) -> bool:
        return TLS13 in self.offered_versions

    @property
    def signals_reneg(self) -> bool:
        return EXT_RENEG in self.extensions or 0x00FF in self.suites

    def groups(self) -> tuple:
        g = self.extensions.get(EXT_GROUPS)
        if not g or len(g) < 2:
            return ()
        n = struct.unpack(">H", g[:2])[0]
        return tuple(struct.unpack(">H", g[2 + i:4 + i])[0] for i in range(0, n, 2))

    def key_share_groups(self) -> tuple:
        ks = self.extensions.get(EXT_KEY_SHARE)
        if not ks or len(ks) < 2:
            return ()
        out, p = [], 2
        while p + 4 <= len(ks):
            g, ln = struct.unpack(">HH", ks[p:p + 4])
            out.append(g)
            p += 4 + ln
        return tuple(out)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def read_hello(sock: socket.socket) -> Hello | None:
    first = _recv_exact(sock, 2)
    if first[0] & 0x80 and first[0] not in (0x16,):
        length = ((first[0] & 0x7F) << 8) | first[1]
        body = _recv_exact(sock, length)
        if not body or body[0] != 1:
            return None
        ver = struct.unpack(">H", body[1:3])[0]
        cs_len = struct.unpack(">H", body[3:5])[0]
        specs = body[9:9 + cs_len]
        return Hello(sslv2=True, version=ver, suites=tuple(int.from_bytes(specs[i:i + 3], "big")
                                                           for i in range(0, len(specs), 3)), raw=first + body)
    rest = _recv_exact(sock, 3)
    hdr = first + rest
    if hdr[0] != 0x16:
        return None
    rlen = struct.unpack(">H", hdr[3:5])[0]
    payload = _recv_exact(sock, rlen)
    raw = hdr + payload
    while len(payload) >= 4 and len(payload) < 4 + int.from_bytes(payload[1:4], "big"):
        h2 = _recv_exact(sock, 5)
        more = _recv_exact(sock, struct.unpack(">H", h2[3:5])[0])
        raw += h2 + more
        payload += more
    if not payload or payload[0] != 1:
        return None
    m = payload[4:4 + int.from_bytes(payload[1:4], "big")]
    ver = struct.unpack(">H", m[0:2])[0]
    p = 34
    sid = bytes(m[p + 1:p + 1 + m[p]])
    p += 1 + m[p]
    n = struct.unpack(">H", m[p:p + 2])[0]
    suites = tuple(struct.unpack(">H", m[p + 2 + i:p + 4 + i])[0] for i in range(0, n, 2))
    p += 2 + n
    comp = tuple(m[p + 1:p + 1 + m[p]])
    p += 1 + m[p]
    exts: dict = {}
    if p + 2 <= len(m):
        end = p + 2 + struct.unpack(">H", m[p:p + 2])[0]
        p += 2
        while p + 4 <= end:
            t, ln = struct.unpack(">HH", m[p:p + 4])
            exts[t] = m[p + 4:p + 4 + ln]
            p += 4 + ln
    return Hello(record_version=struct.unpack(">H", hdr[1:3])[0], version=ver, suites=suites, compression=comp,
                 extensions=exts, raw=raw, session_id=sid)


# ----------------------------------------------------------------------------------------------- flight builder

def _u16(b: bytes) -> bytes:
    return struct.pack(">H", len(b)) + b


def _u24(b: bytes) -> bytes:
    return struct.pack(">I", len(b))[1:] + b


def _ext(t: int, body: bytes) -> bytes:
    return struct.pack(">H", t) + _u16(body)


def _record(ctype: int, version: int, payload: bytes) -> bytes:
    return struct.pack(">BHH", ctype, version, len(payload)) + payload


def _hs(mtype: int, body: bytes) -> bytes:
    return bytes([mtype]) + _u24(body)


def alert(desc: int, version: int = TLS12) -> bytes:
    return _record(21, version, bytes([2, desc]))


def server_hello(version: int, suite: int, *, random: bytes | None = None, session_id: bytes = b"", compression: int = 0,
                 extensions: bytes | None = None, legacy_version: int | None = None) -> bytes:
    rnd = random if random is not None else os.urandom(32)
    body = (struct.pack(">H", legacy_version if legacy_version is not None else min(version, TLS12)) + rnd
            + bytes([len(session_id)]) + session_id + struct.pack(">HB", suite, compression))
    if extensions is not None:
        body += _u16(extensions)
    return _hs(2, body)


def certificate_msg(certs: list[bytes]) -> bytes:
    return _hs(11, _u24(b"".join(_u24(c) for c in certs)))


def sct_list(n: int = 2) -> bytes:
    """A TLS-encoded SCT list with ``n`` syntactically valid SCTs (fabricated log ids, as in the lab certificate)."""
    items = b""
    for i in range(n):
        sct = (b"\x00" + bytes(range(32 * i, 32 * i + 32)) + struct.pack(">Q", 1_790_000_000_000 + i) + b"\x00\x00"
               + b"\x04\x03" + _u16(b"\x30" + bytes(69)))
        items += _u16(sct)
    return _u16(items)


def fixture_der(name: str) -> bytes:
    import base64
    text = (CERT_DIR / name).read_text(encoding="ascii")
    b64 = "".join(line for line in text.splitlines() if line and not line.startswith("-----"))
    return base64.b64decode(b64)


class StubServer:
    """One listening socket; every accepted connection is handled in a thread. ``hellos`` and ``connections`` record
    what clients sent (for pacing and back-off assertions)."""

    def __init__(self, profile: str | Behaviour = "modern", *, upstream: tuple[str, int] | None = None,
                 certs: list[bytes] | None = None, host: str = "127.0.0.1", hold: float = 30.0):
        self.behaviour = PROFILES[profile] if isinstance(profile, str) else profile
        self.name = profile if isinstance(profile, str) else "custom"
        self.upstream = upstream
        self._certs = certs
        self.hold = hold
        self.hellos: list[Hello] = []
        self.connections: list[float] = []
        self.answered: list[str] = []
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, 0))
        self._sock.listen(64)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, name=f"tls-stub-{self.name}", daemon=True)
        self._thread.start()

    # -- lifecycle --------------------------------------------------------------------------------------------
    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            with self._lock:
                self.connections.append(time.monotonic())
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    # -- certificates -----------------------------------------------------------------------------------------
    def certs(self) -> list[bytes]:
        if self._certs is None:
            got: list[bytes] = []
            if self.upstream is not None:
                got = _upstream_chain(self.upstream)
            self._certs = got or [fixture_der("leaf.pem"), fixture_der("int.pem")]
        return self._certs

    # -- one connection ---------------------------------------------------------------------------------------
    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(10)
        try:
            try:
                hello = read_hello(conn)
            except (EOFError, OSError, struct.error, IndexError):
                return
            if hello is None:
                return
            with self._lock:
                self.hellos.append(hello)
            b = self.behaviour
            if self.upstream is not None and b.passthrough == "not_matched" and not _matches(b.match, hello):
                self.answered.append("passthrough")
                _pipe(conn, hello.raw, self.upstream, self._stop)
                return
            reply = self.respond(hello)
            self.answered.append("silent" if reply is None else ("reset" if reply == b"" else "answer"))
            if reply is None:
                self._stop.wait(self.hold)          # hold the connection open without a byte: the client times out
                return
            if reply == b"":
                _reset(conn)
                return
            conn.sendall(reply)
            conn.settimeout(2)
            try:
                conn.recv(4096)                     # wait for the client to give up (it never answers a probe)
            except OSError:
                pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def respond(self, h: Hello) -> bytes | None:
        """The flight for one hello: bytes, ``b""`` for a reset, ``None`` for silence."""
        b = self.behaviour
        if b.mode == "silent":
            return None
        if b.mode == "reset":
            return b""
        if b.mode == "garbage":
            return b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
        if b.mode == "alert70":
            return alert(70, TLS10)
        if h.sslv2:
            if SSL2 not in b.versions:
                return b""                          # SSLv2-incapable servers simply close
            return sslv2_server_hello(self.certs()[0])
        offered = set(h.offered_versions) or {v for v in (TLS10, TLS11, TLS12, SSL3) if v <= h.version}
        if b.mode == "higher":
            return self._legacy(h, TLS12, legacy_version=TLS12)
        if TLS13 in offered and TLS13 in b.versions:
            return self._tls13(h)
        legacy_ok = sorted(v for v in b.versions if v in offered and v not in (TLS13, SSL2))
        if not legacy_ok:
            return alert(70, SSL3 if h.version == SSL3 else TLS10)
        return self._legacy(h, legacy_ok[-1])

    def _pick(self, offered: tuple, mine: tuple) -> int | None:
        if self.behaviour.server_pref:
            return next((s for s in mine if s in offered), None)
        return next((s for s in offered if s in mine), None)

    def _legacy(self, h: Hello, version: int, legacy_version: int | None = None) -> bytes:
        b = self.behaviour
        suites = b.suites
        if version == SSL3:
            suites = tuple(s for s in suites if s in SSL3_OK)
        elif version < TLS12:
            suites = tuple(s for s in suites if s not in TLS12_ONLY)
        suite = self._pick(h.suites, suites)
        if suite is None:
            return alert(40, version if version != SSL3 else SSL3)
        comp = 1 if (b.compression and 1 in h.compression) else 0
        exts = b""
        if version == SSL3:
            ext_block = None
        else:
            if b.reneg and h.signals_reneg:
                exts += _ext(EXT_RENEG, b"\x00")
            if b.ocsp and EXT_STATUS_REQUEST in h.extensions:
                exts += _ext(EXT_STATUS_REQUEST, b"")
            if b.sct_ext and EXT_SCT in h.extensions:
                exts += _ext(EXT_SCT, sct_list(2))
            ext_block = exts
        rnd = os.urandom(24) + (DOWNGRD if (TLS13 in b.versions and version == TLS12) else os.urandom(8))
        msgs = server_hello(version, suite, random=rnd, session_id=os.urandom(32), compression=comp,
                            extensions=ext_block, legacy_version=legacy_version)
        msgs += certificate_msg(self.certs())
        if b.ocsp and EXT_STATUS_REQUEST in h.extensions and version != SSL3:
            der = (CERT_DIR / "ocsp-good.der").read_bytes()
            msgs += _hs(22, b"\x01" + _u24(der))
        if suite in DHE:
            p = b.dh_prime
            pb = p.to_bytes((p.bit_length() + 7) // 8, "big")
            msgs += _hs(12, _u16(pb) + _u16(b"\x02") + _u16(os.urandom(len(pb))) + b"\x04\x01" + _u16(bytes(256)))
        elif suite in ECDHE_GCM + ECDHE_CBC + RC4[:2] + TRIPLE_DES[:2]:
            msgs += _hs(12, b"\x03\x00\x1d" + bytes([32]) + os.urandom(32) + b"\x04\x01" + _u16(bytes(256)))
        msgs += _hs(14, b"")
        rv = SSL3 if version == SSL3 else min(version, TLS12)
        out = b""
        for i in range(0, len(msgs), 16384):
            out += _record(22, rv, msgs[i:i + 16384])
        return out

    def _tls13(self, h: Hello) -> bytes:
        b = self.behaviour
        suite = self._pick(h.suites, b.tls13_suites)
        if suite is None:
            return alert(40)
        shares = h.key_share_groups()
        common = [g for g in b.groups13 if g in h.groups()] if b.server_pref else [g for g in h.groups() if g in b.groups13]
        if not common:
            return alert(40)
        sid = h.session_id
        if common[0] not in shares:
            exts = _ext(EXT_SUPPORTED_VERSIONS, struct.pack(">H", TLS13)) + _ext(EXT_KEY_SHARE, struct.pack(">H", common[0]))
            return _record(22, TLS12, server_hello(TLS12, suite, random=HRR_RANDOM, session_id=sid, extensions=exts))
        share = struct.pack(">H", common[0]) + _u16(os.urandom(32))
        exts = _ext(EXT_SUPPORTED_VERSIONS, struct.pack(">H", TLS13)) + _ext(EXT_KEY_SHARE, share)
        sh = _record(22, TLS12, server_hello(TLS12, suite, session_id=sid, extensions=exts))
        return sh + _record(20, TLS12, b"\x01") + _record(23, TLS12, os.urandom(64))


def sslv2_server_hello(cert: bytes) -> bytes:
    specs = bytes.fromhex("010080" "0700C0")
    conn_id = os.urandom(16)
    body = (b"\x04" + b"\x00" + b"\x01" + struct.pack(">H", SSL2) + struct.pack(">HHH", len(cert), len(specs), len(conn_id))
            + cert + specs + conn_id)
    return struct.pack(">H", 0x8000 | len(body)) + body


def _matches(rule: str, h: Hello) -> bool:
    if rule == "all":
        return True
    legacy = not h.offers_tls13 and not h.sslv2
    if rule == "sslv3":
        return not h.sslv2 and h.version == SSL3
    if rule == "rc4_only":
        return legacy and bool(h.suites) and all(s in RC4 or s in (0x00FF, 0x5600) for s in h.suites)
    if rule == "compression":
        return legacy and 1 in h.compression
    if rule == "legacy_hello":
        return legacy or h.sslv2
    if rule == "dhe_only":                 # the deep probe's DHE-suites-only hello
        return legacy and any(s in DHE for s in h.suites) and not any(s in ECDHE_GCM + ECDHE_CBC + KRSA for s in h.suites)
    if rule == "below_tls12":              # a hello offering at most TLS 1.1
        return legacy and not h.sslv2 and h.max_version < TLS12
    if rule == "single_group":             # the deep probe's one-group TLS 1.3 hellos (never a library handshake)
        return h.offers_tls13 and len(h.groups()) == 1
    return False


def _reset(conn: socket.socket) -> None:
    try:
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass


def _pipe(client: socket.socket, first: bytes, upstream: tuple[str, int], stop: threading.Event) -> None:
    try:
        up = socket.create_connection(upstream, timeout=5)
    except OSError:
        return
    try:
        up.sendall(first)
        client.setblocking(False)
        up.setblocking(False)
        idle = time.monotonic()
        while not stop.is_set() and time.monotonic() - idle < 30:
            r, _w, _x = select.select([client, up], [], [], 0.2)
            for s in r:
                try:
                    data = s.recv(65536)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    return
                if not data:
                    return
                (up if s is client else client).setblocking(True)
                (up if s is client else client).sendall(data)
                (up if s is client else client).setblocking(False)
                idle = time.monotonic()
    finally:
        try:
            up.close()
        except OSError:
            pass


def _upstream_chain(upstream: tuple[str, int]) -> list[bytes]:
    """The certificate chain the upstream server sends (read once, unverified) for the stub's own flights."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection(upstream, timeout=5) as s, ctx.wrap_socket(s) as ss:
            fn = getattr(ss, "get_unverified_chain", None)
            if fn is None:
                fn = getattr(getattr(ss, "_sslobj", None), "get_unverified_chain", None)
            chain = fn() if fn else None
            if chain:
                der = getattr(getattr(ssl, "_ssl", None), "ENCODING_DER", 2)
                return [c if isinstance(c, bytes) else c.public_bytes(der) for c in chain]
            leaf = ss.getpeercert(binary_form=True)
            return [leaf] if leaf else []
    except (OSError, ssl.SSLError, AttributeError, ValueError):
        return []


def start_stub(flight: str, upstream=None, **kw):
    """Start a stub for profile ``flight`` (see :data:`PROFILES`); returns ``(port, stop)``."""
    srv = StubServer(flight, upstream=upstream, **kw)
    return srv.port, srv.stop


__all__ = ["StubServer", "start_stub", "PROFILES", "Behaviour", "Hello", "read_hello", "server_hello", "alert",
           "certificate_msg", "fixture_der", "sct_list", "OAKLEY2"]
