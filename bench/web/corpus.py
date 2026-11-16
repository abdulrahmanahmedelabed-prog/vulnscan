"""Kashif passive web corpus: labelled local test cases and the servers that serve them (spec §5.2).

Every case is declarative: a host, an entry path, the responses its routes return and the labels the scan is scored on
(``True`` = the rule must fire, ``False`` = trap, the rule must stay silent; rules not named are not scored for that case).
Most true-positive cases have a trap twin. ``labels.json`` is generated from this file (``python corpus.py --write-labels``)
and committed, so reviewers see label changes as diffs.

Serving. One threaded HTTP listener and one HTTPS listener on 127.0.0.1 (ephemeral ports) serve every case; TLS profiles that
need other protocol settings get their own listener. A request is routed to its case in this order:

1. ``Host`` names a case host: ``<case-id>.<group>.kashif.test`` (RFC 6761 reserved), its aliases
   ``<case-id>-<alias>.<group>.kashif.test``, its third-party host ``<case-id>.kashif-third.test`` or an extra host;
   Kashif 1.1 reaches them through the test-only resolver hook (``KASHIF_TEST_RESOLVE=1``, map file in
   ``KASHIF_TEST_RESOLVE_MAP``), so cookie Domain, PSL, HSTS host logic and CORS origins are real;
2. path prefix ``/_case/<case-id>/…`` on any host (used for ZAP, which cannot use the hook, and for IP-literal cases);
3. the *active case* set by the runner (sequential runs of tools without the hook, e.g. the 1.0.x baseline).

Nothing here sends a request anywhere: the servers only answer. Only GET is served; any other method is recorded as a
violation (spec §5.7) and answered with 405.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import datetime as _dt
import hashlib
import http.server
import ipaddress
import json
import os
import pathlib
import re
import secrets
import select
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time
import urllib.parse
import zlib
from dataclasses import dataclass, field
from typing import Callable

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import tls_servers  # noqa: E402  (sibling module; bench/web is not a package)

HERE = pathlib.Path(__file__).resolve().parent
LABELS_FILE = HERE / "labels.json"
DOMAIN = "kashif.test"
THIRD_DOMAIN = "kashif-third.test"           # a different registrable domain: "third-party" for PSL purposes
CORS_PROBE_ORIGIN = "https://kashif-cors-check.invalid"
SCHEMA = 1

GROUPS = {
    "C-RED": "red", "C-HSTS": "hsts", "C-CSP": "csp", "C-HDR": "hdr", "C-CORS": "cors", "C-COOKIE": "cookie",
    "C-HTML": "html", "C-DOM": "dom", "C-DISC": "disc", "C-LIB": "lib", "C-TLS": "tls", "C-EXP": "exp", "C-WAF": "waf",
    "C-GRADE": "grade", "C-HOSTILE": "hostile", "C-REVIEW": "review",
}
SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("certain", "firm", "tentative")
PROFILES = ("minimal", "standard", "deep")
SENSITIVITIES = ("strict", "default", "paranoid")
# Requirements a case may declare; the runner marks the case `skipped` (never passed) when one is missing.
REQUIREMENTS = ("tls", "tls10", "stub", "ip2", "roca", "fixture:retire-hash", "slow")
EXPECT_KEYS = {
    "exit", "severity", "max_severity", "confidence", "count", "min_count", "grade", "grade_suffix", "grade_at_least_case",
    "observatory", "states", "max_elapsed", "stderr_absent", "json_contains", "server_never", "min_gap", "max_requests",
    "output_safe", "curl_quoted", "no_requests_on_ip2", "max_rss_mb", "min_requests", "entry_gap",
}

# --------------------------------------------------------------------------------------------- responses and cases


@dataclass
class R:
    """One response. ``body`` may be str (rendered with the tokens below) or bytes (sent as is)."""
    status: int = 200
    headers: list = field(default_factory=list)
    body: str | bytes = b""
    reason: str = ""
    special: str = ""              # "" | "drip" | "bomb" | "close"


Handler = Callable[["Req"], R]


@dataclass
class Case:
    id: str
    group: str
    labels: dict
    routes: dict
    path: str = "/"
    scheme: str = "https"
    tls: str | None = None           # tls_servers.PROFILES key; None = the shared certificate
    profile: str = "standard"
    sensitivity: str = "default"
    crawl: bool = False
    max_pages: int = 6
    max_depth: int = 2
    extra_args: tuple = ()
    env: dict = field(default_factory=dict)
    use_proxy: bool = False          # run through the corpus' local forward proxy (§0.7 case)
    dns: dict = field(default_factory=dict)   # resolver-hook overrides: name -> entry ("*" = default for unknown names)
    aliases: tuple = ()              # extra host labels: <id>-<alias>.<group>.kashif.test
    extra_hosts: dict = field(default_factory=dict)   # literal host name -> alias label
    url_host: str | None = None      # entry URL host override ("127.0.0.1" for IP-literal cases)
    defect: tuple = ()               # D-numbers of §1.6 this case is the regression case for
    expect: dict = field(default_factory=dict)
    requires: tuple = ()
    zap: bool = True
    zap_note: str = ""
    legacy: bool = True              # can be served to a tool without the resolver hook (single host, IP URL)
    twin: str = ""
    note: str = ""
    wellknown: bool = True           # add default robots.txt / security.txt / favicon routes
    ct_required: bool = False        # the test CA hook declares the CA bound by CT policy (WEB713 cases)

    @property
    def slug(self) -> str:
        return GROUPS[self.group]

    @property
    def host(self) -> str:
        return f"{self.id}.{self.slug}.{DOMAIN}"

    def alias_host(self, alias: str) -> str:
        if alias == "third":
            return f"{self.id}.{THIRD_DOMAIN}"
        for h, a in self.extra_hosts.items():
            if a == alias:
                return h
        return f"{self.id}-{alias}.{self.slug}.{DOMAIN}"

    def all_hosts(self) -> dict[str, str]:
        """host name -> alias ('' for the main host)."""
        out = {self.host: "", self.alias_host("third"): "third"}
        for a in self.aliases:
            out[self.alias_host(a)] = a
        out.update(self.extra_hosts)
        return out

    def label_dict(self) -> dict:
        d = {"group": self.group, "host": self.host, "scheme": self.scheme, "path": self.path, "profile": self.profile,
             "sensitivity": self.sensitivity, "labels": dict(sorted(self.labels.items()))}
        for key, default in (("tls", None), ("crawl", False), ("defect", ()), ("expect", {}), ("requires", ()),
                             ("twin", ""), ("note", ""), ("url_host", None), ("use_proxy", False), ("extra_args", ()),
                             ("ct_required", False)):
            val = getattr(self, key)
            if val != default:
                d[key] = list(val) if isinstance(val, tuple) else val
        d["zap"] = self.zap
        if self.zap_note:
            d["zap_note"] = self.zap_note
        d["legacy"] = self.legacy
        return d


CASES: list[Case] = []


def case(id: str, group: str, labels: dict, routes: dict | None = None, **kw) -> Case:
    if routes is None:
        routes = {}
    c = Case(id=id, group=group, labels=labels, routes=routes, **kw)
    CASES.append(c)
    return c


# --------------------------------------------------------------------------------------------- content helpers

STRICT_CSP = ("default-src 'self'; script-src 'nonce-{NONCE}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; "
              "form-action 'self'; frame-ancestors 'none'; report-to csp")
GOOD = [
    ("Content-Type", "text/html; charset=utf-8"),
    ("Strict-Transport-Security", "max-age=63072000; includeSubDomains"),
    ("Content-Security-Policy", STRICT_CSP),
    ("Reporting-Endpoints", 'csp="/csp-report"'),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cache-Control", "no-store"),
]


def H(base: list | None = None, drop: tuple | list = (), set: dict | None = None, add: tuple | list = ()) -> list:
    """Header list editing: start from ``base`` (default GOOD), drop names, replace/append values, append duplicates."""
    out = [tuple(h) for h in (GOOD if base is None else base) if h[0].lower() not in {d.lower() for d in drop}]
    for name, value in (set or {}).items():
        for i, (n, _v) in enumerate(out):
            if n.lower() == name.lower():
                out[i] = (n, value)
                break
        else:
            out.append((name, value))
    out.extend(tuple(a) for a in add)
    return out


def HTTP_HEADERS(**kw) -> list:
    """Good headers for a plain-http document (HSTS would be ignored there)."""
    return H(drop=["Strict-Transport-Security", *kw.pop("drop", ())], **kw)


def page(body: str = "", head: str = "", title: str = "Kashif corpus page", doctype: bool = True, charset: bool = True,
         html_attrs: str = ' lang="en"') -> str:
    meta = '<meta charset="utf-8">' if charset else ""
    return (("<!doctype html>\n" if doctype else "") + f"<html{html_attrs}><head>{meta}<title>{title}</title>{head}</head>"
            f"<body>{body}</body></html>\n")


TEXT = "<h1>Kashif corpus</h1><p>This page belongs to the Kashif passive web scanner corpus. It has no forms and no scripts.</p>"
SCRIPT = '<script nonce="{NONCE}">document.documentElement.dataset.ready = "1";</script>'
LOGIN_FORM = ('<form method="post" action="/login"><label>User <input name="user" autocomplete="username"></label>'
              '<label>Password <input type="password" name="pw" autocomplete="current-password"></label>'
              '<input type="hidden" name="csrf_token" value="{NONCE}"><button>Sign in</button></form>')
APP = TEXT + SCRIPT                                   # a document with a script (not "static")
LOGIN = TEXT + LOGIN_FORM + SCRIPT


def doc(body: str = APP, headers: list | None = None, status: int = 200, **page_kw) -> R:
    return R(status, H() if headers is None else headers, page(body, **page_kw))


def js(code: str, headers: list | None = None) -> R:
    return R(200, headers or [("Content-Type", "text/javascript; charset=utf-8"), ("X-Content-Type-Options", "nosniff"),
                              ("Cache-Control", "public, max-age=3600")], code)


def text(body: str, ctype: str = "text/plain; charset=utf-8", status: int = 200, extra: tuple = ()) -> R:
    return R(status, [("Content-Type", ctype), ("X-Content-Type-Options", "nosniff"), *extra], body)


def redirect(location: str, status: int = 301, headers: list | None = None, body: str = "") -> R:
    hs = list(headers if headers is not None else [("Content-Type", "text/html; charset=utf-8")])
    hs.append(("Location", location))
    return R(status, hs, body or f'<a href="{location}">Moved</a>\n')


NOT_FOUND = R(404, H(set={"Cache-Control": "no-store"}), page("<h1>Not found</h1><p>No such page.</p>", title="Not found"))
SECTXT = ("Contact: mailto:security@kashif.test\nExpires: {EXPIRES}\nPreferred-Languages: en, ar\n"
          "Canonical: {SELF}/.well-known/security.txt\n")
DEFAULT_ROOT = doc()
WELLKNOWN = {
    "/robots.txt": text("User-agent: *\nAllow: /\n"),
    "/.well-known/security.txt": text(SECTXT),
    "/favicon.ico": R(404, [("Content-Type", "text/plain; charset=utf-8"), ("X-Content-Type-Options", "nosniff")],
                      "not found\n"),
}

# --------------------------------------------------------------------------------------------- request context


@dataclass
class Req:
    case: Case
    alias: str
    path: str
    query: str
    headers: dict             # lower-case name -> list of values
    scheme: str
    hits: int                 # earlier requests for this (case, alias, path)
    case_hits: int            # earlier requests for this case
    corpus: "CorpusServer"
    host_header: str = ""

    def header(self, name: str) -> str | None:
        v = self.headers.get(name.lower())
        return v[0] if v else None


_TOKEN = re.compile(r"\{(HOST|SELF|HTTPS|HTTP|THIRD|NONCE|RAND|EXPIRES|PAST|HTTP_PORT|HTTPS_PORT|CASE)(?::([a-z0-9-]+))?\}")


def _render(text_: str, req: Req, per_response: dict) -> str:
    corpus, c = req.corpus, req.case

    def sub(m: re.Match) -> str:
        tok, arg = m.group(1), m.group(2)
        if tok == "NONCE":
            return per_response.setdefault("nonce", base64.b64encode(secrets.token_bytes(18)).decode())
        if tok == "RAND":
            return per_response.setdefault("rand", secrets.token_hex(16))
        if tok == "EXPIRES":
            return (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=180)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if tok == "PAST":
            return (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if tok == "HTTP_PORT":
            return str(corpus.http_port)
        if tok == "HTTPS_PORT":
            return str(corpus.port_for(c))
        if tok == "CASE":
            return c.id
        if tok == "SELF":
            return f"{req.scheme}://{req.host_header}" + (f"/_case/{c.id}" if corpus.mode == "prefix" else "")
        if tok == "HOST":
            return corpus.host_for(c, arg or "")
        if tok == "THIRD":
            return corpus.origin(c, "https", "third")
        return corpus.origin(c, tok.lower(), arg or "")
    return _TOKEN.sub(sub, text_)


# --------------------------------------------------------------------------------------------- the servers


@dataclass
class ReqRecord:
    t: float
    case: str
    alias: str
    method: str
    path: str
    headers: list
    scheme: str
    listener: str            # "http" | "https" | "tls:<profile>" | "http-ip2"
    status: int = 0


_BOMB: dict = {}


def _gzip_bomb() -> bytes:
    """About 1 MB of gzip that inflates to 1 GiB (computed once, lazily)."""
    if "data" not in _BOMB:
        co = zlib.compressobj(9, zlib.DEFLATED, 31)
        chunk = b"\0" * (1 << 20)
        parts = [co.compress(b"<!doctype html><html><body>")]
        for _ in range(1024):
            parts.append(co.compress(chunk))
        parts.append(co.flush())
        _BOMB["data"] = b"".join(parts)
    return _BOMB["data"]


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = ""                 # never used: responses are written raw
    sys_version = ""

    def log_message(self, format, *args):    # noqa: A002 - signature of the base class
        pass

    def _reject(self) -> None:
        corpus: CorpusServer = self.server.corpus      # type: ignore[attr-defined]
        corpus.violation(f"{self.command} {self.path} (only GET is allowed, spec §0.1)")
        self._write(R(405, [("Allow", "GET"), ("Content-Type", "text/plain")], "method not allowed\n"), None)

    do_POST = do_PUT = do_DELETE = do_OPTIONS = do_TRACE = do_PATCH = do_HEAD = do_CONNECT = _reject

    def do_GET(self) -> None:           # noqa: N802 - http.server naming
        corpus: CorpusServer = self.server.corpus      # type: ignore[attr-defined]
        listener = self.server.listener_name            # type: ignore[attr-defined]
        scheme = "https" if listener != "http" and listener != "http-ip2" else "http"
        hdrs: dict[str, list[str]] = {}
        for k, v in self.headers.items():
            hdrs.setdefault(k.lower(), []).append(v)
        host_header = (hdrs.get("host") or [""])[0]
        url = urllib.parse.urlsplit(self.path)
        path, query = url.path or "/", url.query
        if self.path.startswith(("http://", "https://")):     # absolute-form (only proxies should receive it)
            corpus.violation(f"absolute-form request target {self.path[:80]}")
        c, alias, path = corpus.route(host_header, path)
        rec = ReqRecord(time.time(), c.id if c else "", alias, "GET", path + (f"?{query}" if query else ""),
                        list(self.headers.items()), scheme, listener)
        corpus.record(rec)
        if c is None:
            self._write(R(404, [("Content-Type", "text/plain; charset=utf-8")], "no corpus case here\n"), rec)
            return
        hits, case_hits = corpus.count(c.id, alias, path)
        req = Req(c, alias, path, query, hdrs, scheme, hits, case_hits, corpus, host_header)
        resp = corpus.respond(req)
        self._write(resp, rec, req)

    def _write(self, resp: R, rec: ReqRecord | None, req: Req | None = None) -> None:
        per: dict = {}
        headers = []
        for name, value in resp.headers:
            if isinstance(value, str) and req is not None:
                value = _render(value, req, per)
            headers.append((name, value))
        body = resp.body
        if isinstance(body, str):
            body = (_render(body, req, per) if req is not None else body).encode("utf-8")
        if rec is not None:
            rec.status = resp.status
        if resp.special == "bomb":
            body = _gzip_bomb()
        names = {n.lower() for n, _ in headers}
        reason = resp.reason or (http.HTTPStatus(resp.status).phrase if _known(resp.status) else "Unknown")
        raw = bytearray(f"HTTP/1.1 {resp.status} {reason}\r\n".encode("latin-1"))
        for name, value in headers:
            raw += name.encode("latin-1") + b": " + (value if isinstance(value, bytes) else value.encode("utf-8")) + b"\r\n"
        drip = resp.special == "drip"
        if "content-length" not in names and "transfer-encoding" not in names:
            raw += f"Content-Length: {len(body) if not drip else 4096}\r\n".encode("ascii")
        close = drip or resp.special == "close" or (req is not None and (req.header("connection") or "").lower() == "close")
        if close:
            raw += b"Connection: close\r\n"
        raw += b"\r\n"
        try:
            self.wfile.write(bytes(raw))
            if drip:
                deadline = time.monotonic() + 60
                for i in range(4096):
                    if time.monotonic() > deadline or self.server.corpus.stopping.is_set():   # type: ignore[attr-defined]
                        break
                    self.wfile.write(b"<"[:1] if i == 0 else b"x")
                    self.wfile.flush()
                    time.sleep(0.5)
            else:
                self.wfile.write(body)
            self.wfile.flush()
        except (OSError, ssl.SSLError):
            close = True
        self.close_connection = close or self.close_connection


def _is_ip(host: str | None) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _known(status: int) -> bool:
    try:
        http.HTTPStatus(status)
        return True
    except ValueError:
        return False


class _HTTPListener(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 128

    def __init__(self, addr, corpus: CorpusServer, listener_name: str, ssl_context: ssl.SSLContext | None = None):
        self.corpus, self.listener_name, self.ssl_context = corpus, listener_name, ssl_context
        super().__init__(addr, _Handler)

    def finish_request(self, request, client_address):
        if self.ssl_context is not None:
            request.settimeout(15)
            try:
                request = self.ssl_context.wrap_socket(request, server_side=True)
            except (OSError, ssl.SSLError, ValueError):
                self.corpus.tls_failures += 1     # raw ClientHello probes and refused versions end here
                try:
                    request.close()
                except OSError:
                    pass
                return
            request.settimeout(70)
        else:
            request.settimeout(70)
        try:
            super().finish_request(request, client_address)
        except (OSError, ssl.SSLError):
            pass

    def handle_error(self, request, client_address):      # quiet: clients (scanners, probes) hang up all the time
        pass


class MiniProxy(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """A tiny forward proxy (CONNECT + absolute-form GET) that sends everything to the corpus on 127.0.0.1 (§0.7 case)."""
    daemon_threads = True

    def __init__(self, corpus: CorpusServer):
        self.corpus = corpus
        self.seen: list[str] = []
        super().__init__(("127.0.0.1", 0), _ProxyHandler)


class _ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock: socket.socket = self.request
        sock.settimeout(30)
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                return
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        line = head.split(b"\r\n", 1)[0].decode("latin-1")
        parts = line.split()
        if len(parts) < 3:
            return
        method, target = parts[0], parts[1]
        self.server.seen.append(f"{method} {target}")          # type: ignore[attr-defined]
        if method == "CONNECT":
            host, _, port = target.rpartition(":")
            port_i = int(port or 443)
            try:
                up = socket.create_connection(("127.0.0.1", port_i), timeout=10)
            except OSError:
                sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                return
            sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if rest:
                up.sendall(rest)
            _pipe(sock, up)
            return
        u = urllib.parse.urlsplit(target)
        if u.scheme != "http":
            sock.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        try:
            up = socket.create_connection(("127.0.0.1", u.port or 80), timeout=10)
        except OSError:
            sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        origin_line = f"{method} {u.path or '/'}{'?' + u.query if u.query else ''} {parts[2]}".encode("latin-1")
        lines = [ln for ln in head.split(b"\r\n")[1:] if not ln.lower().startswith((b"proxy-", b"connection:"))]
        up.sendall(b"\r\n".join([origin_line, *lines, b"Connection: close", b"", b""]) + rest)
        _pipe(sock, up)


def _pipe(a: socket.socket, b: socket.socket) -> None:
    socks = [a, b]
    try:
        while True:
            r, _, _ = select.select(socks, [], [], 30)
            if not r:
                return
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except OSError:
        return
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass


class CorpusServer:
    """Serves the cases. ``mode``: "host" (resolver hook), "prefix" (/_case/<id>/), "active" (one case at a time)."""

    def __init__(self, cases: list[Case] | None = None, mode: str = "host", pki_dir: str | None = None,
                 with_tls: bool = True):
        self.cases = list(CASES if cases is None else cases)
        self.by_id = {c.id: c for c in self.cases}
        self.mode = mode
        self.host_index: dict[str, tuple[Case, str]] = {}
        for c in self.cases:
            for h, alias in c.all_hosts().items():
                self.host_index[h.lower()] = (c, alias)
        self.active: Case | None = None
        self.log: list[ReqRecord] = []
        self.violations: list[str] = []
        self.tls_failures = 0
        self.stopping = threading.Event()
        self._lock = threading.Lock()
        self._counts: dict = {}
        self._servers: list = []
        self.http_port = 0
        self.https_port = 0
        self.ip2_port = 0
        self.own_ports: dict[str, int] = {}          # tls profile -> port
        self.unavailable: dict[str, str] = {}        # requirement -> reason
        self.pki_dir = pki_dir
        self.with_tls = with_tls
        self._pki: tls_servers.TempPKI | None = None
        self.material: tls_servers.Material | None = None
        self.contexts: dict[str, ssl.SSLContext] = {}
        self.proxy: MiniProxy | None = None
        self._stub_stops: list = []

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> CorpusServer:
        self._listen(("127.0.0.1", 0), "http", None)
        self.http_port = self._servers[-1].server_address[1]
        if tls_servers.can_bind("127.0.0.2"):
            try:
                self._listen(("127.0.0.2", self.http_port), "http-ip2", None)
                self.ip2_port = self.http_port
            except OSError as e:
                self.unavailable["ip2"] = f"cannot bind 127.0.0.2:{self.http_port}: {e}"
        else:
            self.unavailable["ip2"] = "127.0.0.2 is not configured on the loopback interface (default on macOS)"
        if self.with_tls:
            self._start_tls()
        else:
            self.unavailable["tls"] = "TLS disabled for this run"
        self.unavailable.setdefault("roca", "no ROCA fixture (tests/data/web/certs/roca-leaf.pem, WP10)")
        if tls_servers.roca_fixture() and "tls" not in self.unavailable:
            self.unavailable.pop("roca")
        retire = HERE.parent.parent / "tests" / "data" / "web" / "libs"
        if not any(retire.glob("*.js")) if retire.is_dir() else True:
            self.unavailable["fixture:retire-hash"] = "no exact retire.js-hashed library file in tests/data/web/libs (WP9)"
        if os.environ.get("KASHIF_CORPUS_SLOW") != "1":
            self.unavailable["slow"] = "slow case (set KASHIF_CORPUS_SLOW=1 to run it)"
        self.proxy = MiniProxy(self)
        threading.Thread(target=self.proxy.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        self.stopping.set()
        for s in self._servers:
            s.shutdown()
            s.server_close()
        if self.proxy:
            self.proxy.shutdown()
            self.proxy.server_close()
        for stop in self._stub_stops:
            try:
                stop()
            except Exception:                    # noqa: BLE001 - best effort
                pass
        if self._pki:
            self._pki.__exit__(None, None, None)

    def __enter__(self) -> CorpusServer:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    def _listen(self, addr, name: str, ctx: ssl.SSLContext | None) -> _HTTPListener:
        srv = _HTTPListener(addr, self, name, ctx)
        self._servers.append(srv)
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True).start()
        return srv

    def _start_tls(self) -> None:
        shared = [f"DNS:*.{slug}.{DOMAIN}" for slug in GROUPS.values()]
        shared += [f"DNS:*.{THIRD_DOMAIN}", "DNS:*.s3.amazonaws.com", "DNS:kashif-corpus.dev", "IP:127.0.0.1"]
        kinds: dict[str, list[str]] = {}
        for c in self.cases:
            if c.tls and c.tls in tls_servers.PROFILES:
                kinds.setdefault(tls_servers.PROFILES[c.tls].cert, []).append(c.host)
        kinds.setdefault("good", ["good.tls.kashif.test"])
        self._pki = tls_servers.TempPKI(shared, kinds, keep=self.pki_dir).__enter__()
        if self._pki.error or not self._pki.material:
            self.unavailable["tls"] = self._pki.error or "no TLS material"
            return
        self.material = mat = self._pki.material
        shared_ctx = tls_servers.server_context(mat, tls_servers.Profile("shared"))
        sni_map: dict[str, ssl.SSLContext] = {}
        for c in self.cases:
            if not c.tls:
                continue
            prof = tls_servers.PROFILES.get(c.tls)
            if prof is None or prof.own_port or prof.cert not in mat.leaves:
                continue
            ctx = self.contexts.get(c.tls) or tls_servers.server_context(mat, prof)
            self.contexts[c.tls] = ctx
            sni_map[c.host.lower()] = ctx

        def sni(sslobj, name, _ctx):
            target = sni_map.get((name or "").lower())
            if target is None and not name and self.active is not None and self.active.tls:
                target = self.contexts.get(self.active.tls)
            if target is not None:
                sslobj.context = target

        shared_ctx.sni_callback = sni
        self._listen(("127.0.0.1", 0), "https", shared_ctx)
        self.https_port = self._servers[-1].server_address[1]
        stub = None
        for c in self.cases:
            prof = tls_servers.PROFILES.get(c.tls or "")
            if prof is None or not prof.own_port or c.tls in self.own_ports:
                continue
            if c.tls == "roca":
                fx = tls_servers.roca_fixture()
                if not fx:
                    continue
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
                    ctx.load_cert_chain(str(fx[0]), str(fx[1]))
                except (OSError, ssl.SSLError, ValueError) as e:
                    self.unavailable["roca"] = f"ROCA fixture not loadable: {e}"
                    continue
            else:
                try:
                    ctx = tls_servers.server_context(mat, prof)
                except (ssl.SSLError, ValueError, OSError) as e:
                    self.unavailable[f"tls:{c.tls}"] = f"local OpenSSL refuses profile {c.tls}: {e}"
                    if c.tls == "tls10":
                        self.unavailable["tls10"] = f"local OpenSSL cannot serve TLS 1.0: {e}"
                    continue
            srv = self._listen(("127.0.0.1", 0), f"tls:{c.tls}", ctx)
            port = srv.server_address[1]
            self.own_ports[c.tls] = port
            if c.tls == "tls10" and not tls_servers.probe_version("127.0.0.1", port, "TLSv1", c.host):
                self.unavailable["tls10"] = "local OpenSSL refuses to negotiate TLS 1.0 (client or server side)"
            if prof.second_ip:
                if "ip2" in self.unavailable:
                    self.unavailable["tls:twoips"] = self.unavailable["ip2"]
                else:
                    other = tls_servers.server_context(mat, tls_servers.Profile("good", max_version="TLSv1_2"))
                    try:
                        self._listen(("127.0.0.2", port), f"tls:{c.tls}:ip2", other)
                    except OSError as e:
                        self.unavailable["tls:twoips"] = f"cannot bind 127.0.0.2:{port}: {e}"
            if prof.stub:
                stub = stub if stub is not None else (tls_servers.load_stub() or False)
                if not stub:
                    self.unavailable["stub"] = "raw-probe stub tests/web/tls_stub.py (WP10) with start_stub() not available"
                    continue
                try:
                    sport, stop = stub.start_stub(prof.stub, upstream=("127.0.0.1", port))
                except Exception as e:                       # noqa: BLE001 - stub problems only skip stub cases
                    self.unavailable["stub"] = f"stub failed to start: {e}"
                    continue
                self._stub_stops.append(stop)
                self.own_ports[c.tls] = sport

    # ------------------------------------------------------------------ routing and responses
    def route(self, host_header: str, path: str) -> tuple[Case | None, str, str]:
        host = host_header.rsplit(":", 1)[0] if not host_header.startswith("[") else host_header
        hit = self.host_index.get(host.lower())
        if hit:
            return hit[0], hit[1], path
        m = re.match(r"^/_case/([a-z0-9-]+)(/.*)?$", path)
        if m and m.group(1) in self.by_id:
            return self.by_id[m.group(1)], "", m.group(2) or "/"
        if self.active is not None:
            return self.active, "", path
        return None, "", path

    def count(self, case_id: str, alias: str, path: str) -> tuple[int, int]:
        with self._lock:
            k = (case_id, alias, path)
            n = self._counts.get(k, 0)
            self._counts[k] = n + 1
            m = self._counts.get(case_id, 0)
            self._counts[case_id] = m + 1
            return n, m

    def respond(self, req: Req) -> R:
        c = req.case
        key = f"{req.alias}:{req.path}" if req.alias else req.path
        routes = c.routes
        target = routes.get(key)
        if target is None and not req.alias and c.wellknown:
            target = WELLKNOWN.get(req.path)
        if target is None:
            for pattern, value in routes.items():
                if pattern.endswith("*") and key.startswith(pattern[:-1]):
                    target = value
                    break
        if target is None:
            target = routes.get(f"{req.alias}:*" if req.alias else "*")
        if target is None:
            target = DEFAULT_ROOT if req.path == "/" and not req.alias else NOT_FOUND
        return target(req) if callable(target) else target

    def record(self, rec: ReqRecord) -> None:
        with self._lock:
            self.log.append(rec)

    def violation(self, msg: str) -> None:
        with self._lock:
            self.violations.append(msg)

    # ------------------------------------------------------------------ addressing
    def port_for(self, c: Case, scheme: str = "https") -> int:
        if scheme == "http":
            return self.http_port
        if c.tls and c.tls in self.own_ports:
            return self.own_ports[c.tls]
        return self.https_port

    def host_for(self, c: Case, alias: str = "") -> str:
        if self.mode != "host":
            return "127.0.0.1"
        return c.alias_host(alias) if alias else (c.url_host or c.host)

    def origin(self, c: Case, scheme: str, alias: str = "") -> str:
        port = self.port_for(c, scheme) if not alias or scheme == "http" else self.https_port
        prefix = f"/_case/{c.id}" if self.mode == "prefix" or (self.mode == "host" and _is_ip(c.url_host)) else ""
        return f"{scheme}://{self.host_for(c, alias)}:{port}{prefix}"

    def url(self, c: Case) -> str:
        if self.mode == "host" and _is_ip(c.url_host):
            return f"{c.scheme}://{c.url_host}:{self.port_for(c, c.scheme)}/_case/{c.id}{c.path}"
        return self.origin(c, c.scheme) + c.path

    def set_active(self, c: Case | None) -> None:
        self.active = c

    def requests_for(self, case_id: str) -> list[ReqRecord]:
        with self._lock:
            return [r for r in self.log if r.case == case_id]

    def missing(self, c: Case) -> list[str]:
        """Reasons why ``c`` cannot run here (empty list = it can)."""
        out = []
        needs = list(c.requires)
        if c.scheme == "https" or c.tls:
            needs.append("tls")
        if c.tls:
            needs.append(f"tls:{c.tls}")
        for need in needs:
            if need in self.unavailable:
                out.append(f"{need}: {self.unavailable[need]}")
        if c.tls and tls_servers.PROFILES.get(c.tls, tls_servers.Profile()).own_port and c.tls not in self.own_ports \
                and "tls" not in self.unavailable and not out:
            out.append(f"tls:{c.tls}: listener not started")
        return out

    def resolver_map(self, c: Case, cafile: str | None = None) -> dict:
        """The test-only resolver-hook map for one case (spec §5.2): every name -> status/addresses/category."""
        ok = {"status": "ok", "addresses": ["127.0.0.1"], "public": True}
        hosts: dict[str, dict] = {}
        for other in self.cases:          # every corpus host resolves (a case may link to another case's host)
            for h in other.all_hosts():
                hosts[h] = dict(ok)
        if c.tls == "twoips":
            hosts[c.host] = {"status": "ok", "addresses": ["127.0.0.1", "127.0.0.2"], "public": True}
        default = dict(ok)
        for name, entry in c.dns.items():
            if name == "*":
                default = dict(entry)
            else:
                hosts[name] = {**ok, **entry} if entry.get("status", "ok") == "ok" else dict(entry)
        out = {"version": 1, "case": c.id, "hosts": hosts, "default": default,
               "note": "test-only map for KASHIF_TEST_RESOLVE=1; 'public' marks the address as public for the SSRF guard, "
                       "loopback and private-network logic"}
        if cafile:
            out["tls"] = {"cafile": cafile, "publicly_trusted": True, "ct_required": c.ct_required}
        return out


# --------------------------------------------------------------------------------------------- labels export


def labels_document(cases: list[Case] | None = None) -> dict:
    cs = CASES if cases is None else cases
    groups: dict[str, int] = {}
    for c in cs:
        groups[c.group] = groups.get(c.group, 0) + 1
    return {"schema": SCHEMA, "generated_by": "bench/web/corpus.py (python bench/web/corpus.py --write-labels)",
            "count": len(cs), "groups": dict(sorted(groups.items())),
            "cases": {c.id: c.label_dict() for c in cs}}


def labels_text(cases: list[Case] | None = None) -> str:
    return json.dumps(labels_document(cases), ensure_ascii=False, indent=1, sort_keys=False) + "\n"


def validate(cases: list[Case] | None = None) -> list[str]:
    """Structural checks of the corpus (also run by tests/web/test_corpus_gate.py)."""
    cs = CASES if cases is None else cases
    errors = []
    seen = set()
    for c in cs:
        if c.id in seen:
            errors.append(f"{c.id}: duplicate id")
        seen.add(c.id)
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,50}[a-z0-9]", c.id):
            errors.append(f"{c.id}: id must be a DNS label")
        if c.group not in GROUPS:
            errors.append(f"{c.id}: unknown group {c.group}")
        if c.profile not in PROFILES or c.sensitivity not in SENSITIVITIES:
            errors.append(f"{c.id}: bad profile/sensitivity")
        if c.scheme not in ("http", "https"):
            errors.append(f"{c.id}: bad scheme")
        if not c.labels and not c.expect:
            errors.append(f"{c.id}: neither labels nor expectations")
        for rule, v in c.labels.items():
            if not isinstance(v, bool):
                errors.append(f"{c.id}: label {rule} must be true/false")
            if not re.fullmatch(r"WEB(\d{3}|-[a-z-]+)", rule):
                errors.append(f"{c.id}: bad rule id {rule}")
        for k in c.expect:
            if k not in EXPECT_KEYS:
                errors.append(f"{c.id}: unknown expectation {k}")
        for k in ("severity", "max_severity"):
            for rule, sev in c.expect.get(k, {}).items():
                if sev not in SEVERITIES:
                    errors.append(f"{c.id}: bad severity {sev} for {rule}")
        for need in c.requires:
            if need not in REQUIREMENTS:
                errors.append(f"{c.id}: unknown requirement {need}")
        if c.tls and c.tls not in tls_servers.PROFILES:
            errors.append(f"{c.id}: unknown TLS profile {c.tls}")
        if c.twin and c.twin not in {x.id for x in cs}:
            errors.append(f"{c.id}: twin {c.twin} does not exist")
        for d in c.defect:
            if not re.fullmatch(r"D([1-9]|1\d|2[0-5])", d):
                errors.append(f"{c.id}: bad defect id {d}")
    return errors


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Kashif passive web corpus (labels, listing, local serving).")
    ap.add_argument("--write-labels", action="store_true", help="regenerate labels.json from this file")
    ap.add_argument("--check-labels", action="store_true", help="exit 1 when labels.json is out of date")
    ap.add_argument("--list", action="store_true", help="list cases")
    ap.add_argument("--serve", action="store_true", help="serve the corpus until interrupted (prints the case URLs)")
    ap.add_argument("--mode", choices=("host", "prefix", "active"), default="prefix")
    a = ap.parse_args(argv)
    errs = validate()
    if errs:
        print("\n".join(errs), file=sys.stderr)
        return 1
    if a.write_labels:
        LABELS_FILE.write_text(labels_text(), encoding="utf-8", newline="\n")
        print(f"wrote {LABELS_FILE} ({len(CASES)} cases)")
    if a.check_labels:
        current = LABELS_FILE.read_text(encoding="utf-8") if LABELS_FILE.exists() else ""
        if current != labels_text():
            print("labels.json is out of date: run python bench/web/corpus.py --write-labels", file=sys.stderr)
            return 1
    if a.list:
        for c in CASES:
            pos = ",".join(r for r, v in c.labels.items() if v)
            neg = ",".join(r for r, v in c.labels.items() if not v)
            print(f"{c.group:10} {c.id:38} +[{pos}] -[{neg}]")
    if a.serve:
        with CorpusServer(mode=a.mode) as srv:
            for c in CASES:
                print(f"{c.id:38} {srv.url(c)}")
            print(f"http :{srv.http_port}  https :{srv.https_port}  unavailable: {srv.unavailable}", flush=True)
            try:
                while True:
                    time.sleep(3600)
            except KeyboardInterrupt:
                pass
    return 0


# Cases follow (one section per group of spec §5.2). Grouped findings count once per case.


def _cors(acao: str | None = None, *, reflect: bool = False, creds: bool = False, vary: bool = False,
          base: list | None = None, body: str = APP, extra: tuple = ()) -> Handler:
    """A document whose CORS headers depend on the request's Origin (Kashif sends one benign Origin GET)."""
    def fn(req: Req) -> R:
        hs = H(base) if base is not None else H()
        origin = req.header("origin")
        if reflect and origin:
            hs.append(("Access-Control-Allow-Origin", origin))
        elif acao is not None:
            hs.append(("Access-Control-Allow-Origin", acao))
        if creds and (origin or acao):
            hs.append(("Access-Control-Allow-Credentials", "true"))
        if vary:
            hs.append(("Vary", "Origin"))
        hs.extend(extra)
        return R(200, hs, page(body))
    return fn


def _catch_all(resp: R) -> dict:
    return {"*": resp}


# ============================================================================================ C-RED redirects (16)
G = "C-RED"
case("red-http-200", G, {"WEB000": True}, {"/": doc(TEXT, HTTP_HEADERS())}, scheme="http", twin="red-http-to-https",
     note="plain HTTP serves content (non-default port: no https counterpart probe, reported without a variant)")
case("red-http-to-https", G, {"WEB000": False, "WEB101": False, "WEB102": False, "WEB103": False, "WEB105": False,
                              "WEB104": False},
     {"/": lambda r: redirect("{HTTPS}/") if r.scheme == "http" else doc()}, scheme="http", twin="red-http-200")
case("red-http-http-https", G, {"WEB101": True, "WEB000": False, "WEB102": False},
     {"/": lambda r: redirect("{HTTP:www}/") if r.scheme == "http" else doc(),
      "www:/": lambda r: redirect("{HTTPS:www}/") if r.scheme == "http" else doc()},
     scheme="http", aliases=("www",), legacy=False, twin="red-http-to-https",
     note="http://a -> http://www.a -> https://www.a: the first redirect is not to HTTPS")
case("red-http-https-other-host", G, {"WEB102": True, "WEB101": False, "WEB000": False},
     {"/": lambda r: redirect("{HTTPS:www}/") if r.scheme == "http" else doc(), "www:/": doc()},
     scheme="http", aliases=("www",), legacy=False, twin="red-http-to-https")
case("red-https-http-hop", G, {"WEB103": True},
     {"/": lambda r: redirect("{HTTP}/plain", 302) if r.scheme == "https" else doc(TEXT, HTTP_HEADERS()),
      "/plain": lambda r: doc(TEXT, HTTP_HEADERS())}, twin="red-http-to-https")
case("red-meta-refresh-http", G, {"WEB103": True},
     {"/": doc(TEXT, head='<meta http-equiv="refresh" content="0;url={HTTP}/">')}, twin="red-meta-refresh-https")
case("red-meta-refresh-https", G, {"WEB103": False},
     {"/": doc(TEXT, head='<meta http-equiv="refresh" content="0;url={HTTPS}/home">'), "/home": doc()},
     twin="red-meta-refresh-http")
case("red-302-upgrade", G, {"WEB105": True, "WEB000": False},
     {"/": lambda r: redirect("{HTTPS}/", 302) if r.scheme == "http" else doc()}, scheme="http", twin="red-308-upgrade")
case("red-308-upgrade", G, {"WEB105": False, "WEB000": False},
     {"/": lambda r: redirect("{HTTPS}/", 308) if r.scheme == "http" else doc()}, scheme="http", twin="red-302-upgrade")
case("red-loop-12", G, {"WEB104": True},
     {f"/r{i}": redirect(f"/r{i % 12 + 1}", 302) for i in range(1, 13)}, path="/r1", twin="red-short-chain",
     expect={"exit": [0, 1, 2]}, note="12-hop loop; the entry chain stops at 10 hops")
case("red-short-chain", G, {"WEB104": False, "WEB106": False},
     {"/": lambda r: redirect("{HTTPS}/", 301) if r.scheme == "http" else redirect("/home", 301), "/home": doc()},
     scheme="http", twin="red-loop-12")
_BIG_REDIRECT_BODY = page("<h1>Account</h1>" + LOGIN_FORM + "<table>" + "".join(
    f'<tr><td><a href="/item/{i}">Item {i}</a></td><td>Description of item number {i} in the catalogue.</td></tr>'
    for i in range(40)) + "</table>")
case("red-301-full-page", G, {"WEB106": True},
     {"/": R(301, [("Content-Type", "text/html; charset=utf-8"), ("Location", "/home")], _BIG_REDIRECT_BODY), "/home": doc()},
     twin="red-301-boilerplate", note="the 3xx renders the whole page (missing exit after header())")
case("red-301-boilerplate", G, {"WEB106": False},
     {"/": redirect("/home", 301, body='<html><body>Moved to <a href="/home">/home</a></body></html>'), "/home": doc()},
     twin="red-301-full-page")
case("red-301-home-headers", G, {"WEB-content-security-policy": False, "WEB-x-frame-options": False,
                                 "WEB-x-content-type-options": False, "WEB-referrer-policy": False,
                                 "WEB-permissions-policy": False},
     {"/": R(301, [("Location", "/home"), ("Content-Length", "0")], b""), "/home": doc(LOGIN, HTTP_HEADERS())},
     scheme="http", defect=("D1",), twin="red-http-200",
     note="1.0.1 judged the headers of the 301 (5 false positives) and never saw the HTML")
case("red-preloaded-dev", G, {"WEB000": True}, {"/": doc(TEXT, HTTP_HEADERS())}, scheme="http",
     extra_hosts={"kashif-corpus.dev": ""}, url_host="kashif-corpus.dev", legacy=False, zap=False,
     zap_note="needs the .dev host name", expect={"severity": {"WEB000": "info"}}, twin="red-http-200",
     note="hosts under a fully preloaded TLD are never fetched over http by browsers: info only")
case("red-api-403", G, {"WEB000": False},
     {"/api/v1/": R(403, [("Content-Type", "application/json"), ("X-Content-Type-Options", "nosniff")],
                    '{"error": "https required"}')}, path="/api/v1/", scheme="http", twin="red-http-200",
     note="an API that refuses plain HTTP is what ASVS 5.0 4.1.2 asks for")
case("red-js-location-http", G, {"WEB103": True},
     {"/": doc(TEXT + '<script nonce="{NONCE}">if (!window.kashif) { location.href = "{HTTP}/legacy"; }</script>')},
     sensitivity="paranoid", twin="red-meta-refresh-https", note="tentative variant (inline script), paranoid only")

# ============================================================================================ C-HSTS (18)
G = "C-HSTS"
STS = "Strict-Transport-Security"
case("hsts-missing", G, {"WEB-strict-transport-security": True}, {"/": doc(headers=H(drop=[STS]))}, twin="hsts-two-years")
case("hsts-max-age-0", G, {"WEB110": True, "WEB-strict-transport-security": False},
     {"/": doc(headers=H(set={STS: "max-age=0"}))}, twin="hsts-two-years")
case("hsts-max-age-0-quoted", G, {"WEB110": True, "WEB-strict-transport-security": False},
     {"/": doc(headers=H(set={STS: 'max-age="0"'}))}, twin="hsts-two-years")
case("hsts-300s", G, {"WEB111": True}, {"/": doc(headers=H(set={STS: "max-age=300; includeSubDomains"}))},
     expect={"severity": {"WEB111": "medium"}}, twin="hsts-two-years")
case("hsts-100-days", G, {"WEB111": True}, {"/": doc(headers=H(set={STS: "max-age=8640000; includeSubDomains"}))},
     expect={"severity": {"WEB111": "medium"}}, twin="hsts-two-years")
case("hsts-200-days", G, {"WEB111": True}, {"/": doc(headers=H(set={STS: "max-age=17280000; includeSubDomains"}))},
     expect={"severity": {"WEB111": "low"}}, twin="hsts-two-years")
case("hsts-two-headers", G, {"WEB113": True},
     {"/": doc(headers=H(add=[(STS, "max-age=300")]))}, twin="hsts-two-years")
case("hsts-folded", G, {"WEB112": True},
     {"/": doc(headers=H(set={STS: "max-age=63072000; includeSubDomains, max-age=63072000"}))}, twin="hsts-two-years",
     note="two values folded into one field with a comma: Chromium rejects it")
case("hsts-curly-quotes", G, {"WEB112": True},
     {"/": doc(headers=H(set={STS: "max-age=“63072000”; includeSubDomains"}))}, twin="hsts-two-years")
case("hsts-no-max-age", G, {"WEB112": True}, {"/": doc(headers=H(set={STS: "includeSubDomains"}))}, twin="hsts-two-years")
case("hsts-leading-zero", G, {"WEB112": True},
     {"/": doc(headers=H(set={STS: "max-age=063072000; includeSubDomains"}))}, twin="hsts-two-years")
case("hsts-preload-no-subdomains", G, {"WEB115": True, "WEB114": True},
     {"/": doc(headers=H(set={STS: "max-age=63072000; preload"}))}, twin="hsts-two-years",
     note="preload requested but includeSubDomains missing (and the host is a subdomain)")
case("hsts-meta", G, {"WEB116": True, "WEB-strict-transport-security": False},
     {"/": doc(head='<meta http-equiv="Strict-Transport-Security" content="max-age=63072000">')}, twin="hsts-two-years")
case("hsts-cross-host-hop", G, {"WEB117": True, "WEB-strict-transport-security": False},
     {"/": redirect("{HTTPS:www}/", 301, headers=[("Content-Type", "text/html")]), "www:/": doc()},
     aliases=("www",), legacy=False, twin="hsts-same-host-redirect")
case("hsts-on-http-only", G, {"WEB116": True, "WEB-strict-transport-security": False},
     {"/": doc(TEXT, HTTP_HEADERS(add=[(STS, "max-age=63072000")]))}, scheme="http",
     expect={"max_severity": {"WEB116": "info"}}, twin="hsts-missing", note="HSTS over http is ignored: info, never 'missing'")
case("hsts-two-years", G, {"WEB-strict-transport-security": False, "WEB110": False, "WEB111": False, "WEB112": False,
                           "WEB113": False, "WEB114": False, "WEB115": False, "WEB116": False, "WEB117": False},
     {"/": doc()}, twin="hsts-missing")
case("hsts-ip-literal", G, {"WEB-strict-transport-security": False}, {"/": doc(headers=H(drop=[STS]))},
     url_host="127.0.0.1", legacy=False, twin="hsts-missing",
     note="RFC 6797 §8.1: an IP-literal host is never a Known HSTS Host (not applicable)")
case("hsts-cert-invalid", G, {"WEB-strict-transport-security": False, "WEB701": True},
     {"/": doc(headers=H(drop=[STS]))}, tls="selfsigned", twin="hsts-missing", zap=False,
     note="HSTS is ignored on an invalid certificate: the certificate rule applies, HSTS is not judged")
case("hsts-same-host-redirect", G, {"WEB-strict-transport-security": False, "WEB117": False},
     {"/": redirect("/home", 301, headers=[("Content-Type", "text/html")]), "/home": doc()}, twin="hsts-cross-host-hop")

# ============================================================================================ C-CSP (40)
G = "C-CSP"
CSP = "Content-Security-Policy"


def csp(policy: str, body: str = APP, extra: dict | None = None, **kw) -> dict:
    return {"/": doc(body, H(set={CSP: policy, **(extra or {})}), **kw)}


GOOD_TAIL = "; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
case("csp-missing", G, {"WEB-content-security-policy": True}, {"/": doc(LOGIN, H(drop=[CSP]))}, twin="csp-meta-only")
case("csp-report-only", G, {"WEB200": True, "WEB-content-security-policy": False},
     {"/": doc(LOGIN, H(drop=[CSP], add=[("Content-Security-Policy-Report-Only", STRICT_CSP)]))}, twin="csp-enforced-and-ro")
case("csp-enforced-and-ro", G, {"WEB200": False, "WEB-content-security-policy": False},
     {"/": doc(LOGIN, H(add=[("Content-Security-Policy-Report-Only", "default-src 'none'")]))}, twin="csp-report-only")
case("csp-unsafe-inline", G, {"WEB040": True}, csp("script-src 'self' 'unsafe-inline'" + GOOD_TAIL),
     twin="csp-nonce-plus-unsafe-inline")
case("csp-default-self-script-inline", G, {"WEB040": True},
     csp("default-src 'self'; script-src 'unsafe-inline'" + GOOD_TAIL), defect=("D8",), twin="csp-script-src-elem",
     note="1.0.1 read default-src first and missed the weaker script-src")
case("csp-star", G, {"WEB042": True}, csp("script-src *" + GOOD_TAIL), twin="csp-host-wildcard")
case("csp-https-scheme", G, {"WEB042": True}, csp("script-src https:" + GOOD_TAIL), twin="csp-host-wildcard")
case("csp-data-script", G, {"WEB042": True}, csp("script-src 'self' data:" + GOOD_TAIL), twin="csp-host-wildcard")
case("csp-strict-dynamic-no-nonce", G, {"WEB203": True}, csp("script-src 'strict-dynamic' https:" + GOOD_TAIL),
     twin="csp-strict-good")
case("csp-nonce-no-base-uri", G, {"WEB204": True},
     csp("script-src 'nonce-{NONCE}' 'strict-dynamic'; object-src 'none'; form-action 'self'; frame-ancestors 'none'"),
     twin="csp-strict-good")
case("csp-login-no-form-action", G, {"WEB205": True},
     csp("script-src 'nonce-{NONCE}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
         body=LOGIN), expect={"severity": {"WEB205": "medium"}}, twin="csp-no-forms")
case("csp-no-forms", G, {"WEB205": False},
     csp("script-src 'nonce-{NONCE}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"),
     twin="csp-login-no-form-action")
case("csp-frame-ancestors-star", G, {"WEB206": True},
     {"/": doc(LOGIN, H(drop=["X-Frame-Options"], set={CSP: STRICT_CSP.replace("frame-ancestors 'none'", "frame-ancestors *")}))},
     twin="csp-strict-good")
case("csp-meta-frame-ancestors", G, {"WEB207": True, "WEB-content-security-policy": False},
     {"/": doc(APP, H(drop=[CSP]), head='<meta http-equiv="Content-Security-Policy" content="' + STRICT_CSP.replace(
         "; report-to csp", "") + '">')}, twin="csp-meta-only")
case("csp-meta-after-script", G, {"WEB208": True},
     {"/": doc(APP, H(drop=[CSP]), head='<script nonce="{NONCE}">window.k = 1;</script><meta http-equiv="Content-Security-Policy" '
              "content=\"default-src 'self'; script-src 'nonce-{NONCE}'; object-src 'none'; base-uri 'none'\">")},
     twin="csp-meta-only")
case("csp-google-allowlist", G, {"WEB209": True}, csp("script-src 'self' https://www.google.com" + GOOD_TAIL),
     twin="csp-strict-dynamic-allowlist", note="www.google.com hosts JSONP endpoints (CSP Evaluator bypass list)")
case("csp-strict-dynamic-allowlist", G, {"WEB209": False, "WEB042": False},
     csp("script-src 'nonce-{NONCE}' 'strict-dynamic' https://www.google.com" + GOOD_TAIL), twin="csp-google-allowlist",
     note="strict-dynamic with a nonce ignores the host allowlist")
case("csp-unsafe-hashes", G, {"WEB210": True},
     csp("script-src 'self' 'unsafe-hashes' 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='" + GOOD_TAIL),
     twin="csp-strict-good")
case("csp-http-source", G, {"WEB211": True}, csp("script-src 'self' http://cdn.kashif-third.test" + GOOD_TAIL),
     twin="csp-allowlist-only")
case("csp-static-nonce", G, {"WEB212": True},
     {"/": doc(TEXT + '<script nonce="c3RhdGljLW5vbmNlLTEyMzQ1Ng==">window.k = 1;</script>',
               H(set={CSP: STRICT_CSP.replace("{NONCE}", "c3RhdGljLW5vbmNlLTEyMzQ1Ng==")}))}, twin="csp-strict-good",
     note="the entry GET and the anonymous CORS GET carry the same nonce")
case("csp-short-nonce", G, {"WEB213": True},
     {"/": doc(TEXT + '<script nonce="abc">window.k = 1;</script>', H(set={CSP: STRICT_CSP.replace("{NONCE}", "abc")}))},
     twin="csp-strict-good")
case("csp-duplicate-directive", G, {"WEB202": True, "WEB040": False},
     csp("script-src 'self'; script-src 'unsafe-inline'" + GOOD_TAIL), twin="csp-strict-good",
     note="the second script-src is ignored (first occurrence wins)")
case("csp-unquoted-self", G, {"WEB201": True}, csp("script-src self" + GOOD_TAIL), twin="csp-strict-good")
case("csp-typo-directive", G, {"WEB201": True}, csp("default-src 'self'; scritp-src 'self'" + GOOD_TAIL),
     twin="csp-strict-good")
case("csp-unsafe-eval", G, {"WEB041": True}, csp("script-src 'self' 'unsafe-eval'" + GOOD_TAIL), twin="csp-strict-good")
case("csp-no-object-src", G, {"WEB043": True},
     csp("script-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"), twin="csp-default-none")
case("csp-style-inline", G, {"WEB214": True}, csp(STRICT_CSP + "; style-src 'self' 'unsafe-inline'"),
     expect={"max_severity": {"WEB214": "info"}}, twin="csp-strict-good")
case("csp-x-csp-only", G, {"WEB217": True, "WEB-content-security-policy": True},
     {"/": doc(LOGIN, H(drop=[CSP], add=[("X-Content-Security-Policy", "default-src 'self'")]))}, twin="csp-strict-good")
case("csp-deprecated-directive", G, {"WEB216": True}, csp(STRICT_CSP + "; block-all-mixed-content"),
     twin="csp-strict-good")
case("csp-allowlist-only", G, {"WEB218": True, "WEB209": False, "WEB211": False},
     csp("default-src 'self'; script-src 'self' https://static.kashif-third.test" + GOOD_TAIL),
     expect={"max_severity": {"WEB218": "info"}}, twin="csp-strict-good")
case("csp-nonce-plus-unsafe-inline", G, {"WEB040": False},
     csp("script-src 'nonce-{NONCE}' 'unsafe-inline'" + GOOD_TAIL), defect=("D7",), twin="csp-unsafe-inline",
     note="a nonce neutralises 'unsafe-inline' (kept only for old browsers)")
case("csp-strict-dynamic-compat", G, {"WEB040": False, "WEB042": False, "WEB209": False},
     csp("script-src 'nonce-{NONCE}' 'strict-dynamic' 'unsafe-inline' https:" + GOOD_TAIL), defect=("D7",),
     twin="csp-unsafe-inline", note="the recommended backwards-compatible strict CSP")
case("csp-host-wildcard", G, {"WEB042": False},
     csp("script-src 'self' https://*.kashif-third.test" + GOOD_TAIL), defect=("D9",), twin="csp-star")
case("csp-default-none", G, {"WEB043": False},
     csp("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; "
         "frame-ancestors 'none'"), defect=("D10",), twin="csp-no-object-src")
case("csp-meta-only", G, {"WEB-content-security-policy": False, "WEB207": False},
     {"/": doc(APP, H(drop=[CSP]), head="<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; "
              "script-src 'nonce-{NONCE}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; form-action 'self'\">")},
     defect=("D11",), twin="csp-missing")
case("csp-two-policies", G, {"WEB040": False, "WEB-content-security-policy": False},
     {"/": doc(APP, H(set={CSP: "script-src 'self' 'unsafe-inline'; object-src 'none'"},
                      add=[(CSP, "script-src 'self'; object-src 'none'; base-uri 'none'")]))}, twin="csp-unsafe-inline",
     note="two enforced policies: the second removes 'unsafe-inline' (intersection)")
case("csp-api-json", G, {"WEB-content-security-policy": False, "WEB-x-frame-options": False,
                         "WEB-permissions-policy": False, "WEB-referrer-policy": False},
     {"/api/v1/status": R(200, [("Content-Type", "application/json"), ("Strict-Transport-Security",
                                "max-age=63072000; includeSubDomains"), ("X-Content-Type-Options", "nosniff"),
                                ("Cache-Control", "no-store")], '{"status": "ok", "version": "2.4.1"}')},
     path="/api/v1/status", defect=("D2",), twin="csp-missing")
case("csp-script-src-elem", G, {"WEB040": False, "WEB042": False},
     csp("script-src 'unsafe-inline'; script-src-elem 'self'; script-src-attr 'none'" + GOOD_TAIL), defect=("D8",),
     twin="csp-default-self-script-inline",
     note="elements: 'self'; attributes: 'none'; the script-src fallback is never used. 1.0.1 read script-src and fired")
case("csp-404-no-csp", G, {"WEB-content-security-policy": False, "WEB-x-frame-options": False},
     {"/missing": R(404, H(drop=[CSP, "X-Frame-Options"]), page("<h1>Not found</h1>" + SCRIPT))}, path="/missing",
     twin="csp-missing", note="4xx documents are not judged at default sensitivity (G1)")
case("csp-strict-good", G, {"WEB040": False, "WEB041": False, "WEB042": False, "WEB043": False, "WEB200": False,
                            "WEB201": False, "WEB202": False, "WEB203": False, "WEB204": False, "WEB205": False,
                            "WEB206": False, "WEB207": False, "WEB208": False, "WEB209": False, "WEB210": False,
                            "WEB211": False, "WEB212": False, "WEB213": False, "WEB214": False, "WEB216": False,
                            "WEB217": False, "WEB218": False, "WEB-content-security-policy": False,
                            "WEB509": False, "WEB513": False, "WEB514": False, "WEB611": False, "WEB990": False},
     {"/": doc(LOGIN)}, twin="csp-missing")
case("csp-frame-ancestors-only", G, {"WEB042": True, "WEB040": False, "WEB043": False, "WEB204": False,
                                     "WEB-content-security-policy": False, "WEB-x-frame-options": False},
     {"/": doc(APP, H(drop=["X-Frame-Options"], set={CSP: "frame-ancestors 'none'"}))}, twin="csp-strict-good",
     note="non-script policy: one WEB042 with the note 'does not restrict scripts', no restatements")

# ============================================================================================ C-HDR other headers (31)
G = "C-HDR"
XFO, XCTO, RP, PP = "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"
CSP_NO_FA = STRICT_CSP.replace("; frame-ancestors 'none'", "")
case("hdr-xfo-missing-login", G, {"WEB-x-frame-options": True}, {"/": doc(LOGIN, H(drop=[XFO], set={CSP: CSP_NO_FA}))},
     twin="hdr-xfo-missing-fa-none")
case("hdr-xfo-allow-from", G, {"WEB300": True}, {"/": doc(LOGIN, H(set={XFO: "ALLOW-FROM https://partner.kashif.test/",
                                                                        CSP: CSP_NO_FA}))}, twin="hdr-xfo-sameorigin-dup")
case("hdr-xfo-deny-sameorigin", G, {"WEB301": True}, {"/": doc(LOGIN, H(set={XFO: "DENY, SAMEORIGIN", CSP: CSP_NO_FA}))},
     twin="hdr-xfo-sameorigin-dup")
case("hdr-xfo-meta", G, {"WEB302": True, "WEB-x-frame-options": True},
     {"/": doc(LOGIN, H(drop=[XFO], set={CSP: CSP_NO_FA}), head='<meta http-equiv="X-Frame-Options" content="DENY">')},
     twin="hdr-xfo-missing-fa-none")
case("hdr-xfo-sameorigin-dup", G, {"WEB301": False, "WEB300": False, "WEB-x-frame-options": False},
     {"/": doc(LOGIN, H(set={XFO: "SAMEORIGIN, SAMEORIGIN", CSP: CSP_NO_FA}))}, twin="hdr-xfo-deny-sameorigin")
case("hdr-xfo-missing-fa-none", G, {"WEB-x-frame-options": False, "WEB302": False}, {"/": doc(LOGIN, H(drop=[XFO]))},
     twin="hdr-xfo-missing-login", note="CSP frame-ancestors 'none' protects; XFO is not needed")
case("hdr-xcto-missing-js", G, {"WEB-x-content-type-options": True},
     {"/static/app.js": R(200, [("Content-Type", "text/javascript"), ("Cache-Control", "public, max-age=3600")],
                          "window.app = {version: 3};\n")}, path="/static/app.js", twin="hdr-xcto-missing-png")
case("hdr-xcto-nosnif", G, {"WEB303": True}, {"/": doc(headers=H(set={XCTO: "nosnif"}))}, twin="hdr-xcto-double")
case("hdr-xcto-double", G, {"WEB303": False, "WEB-x-content-type-options": False},
     {"/": doc(headers=H(set={XCTO: "nosniff, nosniff"}))}, twin="hdr-xcto-nosnif")
_PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")
case("hdr-xcto-missing-png", G, {"WEB-x-content-type-options": False},
     {"/img/logo.png": R(200, [("Content-Type", "image/png"), ("Cache-Control", "public, max-age=86400")], _PNG)},
     path="/img/logo.png", twin="hdr-xcto-missing-js", note="nosniff matters for script/style/JSON, not images")
case("hdr-xcto-missing-304", G, {"WEB-x-content-type-options": False, "WEB-content-security-policy": False,
                                 "WEB-x-frame-options": False},
     {"/": R(304, [("ETag", '"abc"'), ("Cache-Control", "no-cache")], b"")}, twin="hdr-xcto-missing-js",
     expect={"exit": [0, 1, 2]}, note="a 304 carries a subset of headers (RFC 9110 §15.4.5): never judge absence")
case("hdr-referrer-unsafe-url", G, {"WEB304": True}, {"/": doc(headers=H(set={RP: "unsafe-url"}))},
     expect={"severity": {"WEB304": "medium"}}, twin="hdr-referrer-missing")
case("hdr-referrer-missing", G, {"WEB-referrer-policy": True, "WEB304": False}, {"/": doc(headers=H(drop=[RP]))},
     expect={"max_severity": {"WEB-referrer-policy": "info"}}, twin="hdr-referrer-unsafe-url",
     note="browsers default to strict-origin-when-cross-origin: info only")
case("hdr-pp-feature-syntax", G, {"WEB305": True}, {"/": doc(headers=H(set={PP: "camera 'none'"}))},
     twin="hdr-pp-good", note="Feature-Policy syntax in Permissions-Policy: the whole header is ignored")
case("hdr-pp-geolocation-star", G, {"WEB306": True}, {"/": doc(headers=H(set={PP: "geolocation=*, camera=()"}))},
     twin="hdr-pp-good")
case("hdr-pp-good", G, {"WEB305": False, "WEB306": False, "WEB307": False, "WEB-permissions-policy": False,
                        "WEB308": False},
     {"/": doc(headers=H(set={PP: "geolocation=(self), camera=(), microphone=()"}))}, twin="hdr-pp-geolocation-star")
case("hdr-pp-missing", G, {"WEB-permissions-policy": True}, {"/": doc(headers=H(drop=[PP]))},
     expect={"max_severity": {"WEB-permissions-policy": "info"}}, twin="hdr-pp-good")
case("hdr-feature-policy-only", G, {"WEB307": True}, {"/": doc(headers=H(drop=[PP], add=[("Feature-Policy",
                                                                                         "camera 'none'")]))},
     twin="hdr-pp-good")
case("hdr-coop-typo", G, {"WEB308": True}, {"/": doc(headers=H(set={"Cross-Origin-Opener-Policy": "same-orign"}))},
     twin="hdr-pp-good")
case("hdr-coep-twice", G, {"WEB309": True}, {"/": doc(headers=H(add=[("Cross-Origin-Embedder-Policy", "require-corp"),
                                                                     ("Cross-Origin-Embedder-Policy", "credentialless")]))},
     twin="hdr-coep-missing")
case("hdr-coep-missing", G, {"WEB309": False, "WEB310": False, "WEB312": False, "WEB316": False, "WEB317": False},
     {"/": doc()}, twin="hdr-coep-twice",
     note="missing COEP is never reported")
case("hdr-corp-case", G, {"WEB310": True}, {"/": doc(headers=H(add=[("Cross-Origin-Resource-Policy", "Same-Origin")]))},
     twin="hdr-coep-missing", note="CORP tokens are case-sensitive")
case("hdr-xxss-enabled", G, {"WEB311": True}, {"/": doc(headers=H(add=[("X-XSS-Protection", "1")]))},
     expect={"max_severity": {"WEB311": "info"}}, twin="hdr-xxss-zero")
case("hdr-xxss-zero", G, {"WEB311": False}, {"/": doc(headers=H(add=[("X-XSS-Protection", "0")]))}, twin="hdr-xxss-enabled")
case("hdr-hpkp", G, {"WEB312": True}, {"/": doc(headers=H(add=[("Public-Key-Pins",
                                                               'pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="; '
                                                               'max-age=5184000')]))}, twin="hdr-coep-missing")
case("hdr-ctype-missing", G, {"WEB313": True}, {"/": R(200, H(drop=["Content-Type"]), page(TEXT))},
     twin="hdr-utf8-vs-utf-8")
case("hdr-json-as-html", G, {"WEB313": True},
     {"/api/data": R(200, H(set={"Content-Type": "text/html; charset=utf-8"}), '{"id": 7, "name": "kashif"}')},
     path="/api/data", twin="hdr-utf8-vs-utf-8")
case("hdr-charset-conflict", G, {"WEB314": True},
     {"/": R(200, H(), page(TEXT, head='<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">',
                            charset=False))}, twin="hdr-utf8-vs-utf-8")
case("hdr-utf8-vs-utf-8", G, {"WEB314": False, "WEB313": False},
     {"/": R(200, H(set={"Content-Type": "text/html; charset=utf8"}), page(TEXT, head='<meta charset="UTF-8">',
                                                                          charset=False))}, twin="hdr-charset-conflict",
     note="utf8 is a label of UTF-8 (Encoding Standard)")
case("hdr-cache-public-login", G, {"WEB315": True},
     {"/": doc(LOGIN, H(set={"Cache-Control": "public, max-age=600"}))}, twin="hdr-static-immutable")
case("hdr-setcookie-shared-cache", G, {"WEB315": True},
     {"/": doc(APP, H(set={"Cache-Control": "public, max-age=600"},
                      add=[("Set-Cookie", "sessionid={RAND}; Path=/; Secure; HttpOnly; SameSite=Lax")]))},
     expect={"severity": {"WEB315": "medium"}}, twin="hdr-static-immutable")
case("hdr-static-immutable", G, {"WEB315": False},
     {"/static/app.3f9a1c.css": R(200, [("Content-Type", "text/css"), ("X-Content-Type-Options", "nosniff"),
                                        ("Cache-Control", "public, max-age=31536000, immutable")], "body{margin:0}\n")},
     path="/static/app.3f9a1c.css", twin="hdr-cache-public-login")
case("hdr-clear-site-data-unquoted", G, {"WEB317": True},
     {"/": doc(headers=H(add=[("Clear-Site-Data", "cookies, storage")]))}, twin="hdr-coep-missing")
case("hdr-xpcdp-all", G, {"WEB316": True},
     {"/": doc(headers=H(add=[("X-Permitted-Cross-Domain-Policies", "all")]))}, twin="hdr-coep-missing")

# ============================================================================================ C-CORS (12)
G = "C-CORS"
case("cors-reflect-creds", G, {"WEB320": True}, {"/": _cors(reflect=True, creds=True, vary=True)}, twin="cors-fixed-allowlist")
case("cors-reflect-no-creds", G, {"WEB321": True, "WEB320": False},
     {"/": _cors(reflect=True, vary=True, extra=(("Cache-Control", "no-store"),))}, twin="cors-fixed-allowlist")
case("cors-null", G, {"WEB322": True}, {"/": _cors("null")}, twin="cors-none")
case("cors-star-creds", G, {"WEB323": True}, {"/": _cors("*", creds=True)}, twin="cors-star-static")
case("cors-reflect-no-vary", G, {"WEB324": True},
     {"/": _cors(reflect=True, base=H(set={"Cache-Control": "public, max-age=300"}))}, twin="cors-reflect-vary-ok")
case("cors-http-origin", G, {"WEB326": True}, {"/": _cors("http://partner.kashif.test")}, twin="cors-fixed-allowlist")
case("cors-acao-list", G, {"WEB325": True}, {"/": _cors("https://a.kashif.test https://b.kashif.test")},
     twin="cors-fixed-allowlist")
case("cors-star-session", G, {"WEB327": True},
     {"/": _cors("*", extra=(("Set-Cookie", "sessionid={RAND}; Path=/; Secure; HttpOnly; SameSite=Lax"),))},
     sensitivity="paranoid", twin="cors-star-static", note="WEB327 is tentative: paranoid sensitivity")
case("cors-fixed-allowlist", G, {"WEB320": False, "WEB321": False, "WEB324": False, "WEB326": False, "WEB325": False},
     {"/": _cors("https://app.kashif.test", creds=True, vary=True)}, twin="cors-reflect-creds",
     note="a fixed allowlisted origin that does not match the probe Origin")
case("cors-star-static", G, {"WEB327": False, "WEB323": False},
     {"/static/lib.js": R(200, [("Content-Type", "text/javascript"), ("X-Content-Type-Options", "nosniff"),
                                ("Access-Control-Allow-Origin", "*"), ("Cache-Control", "public, max-age=86400")],
                          "window.lib = 1;\n")}, path="/static/lib.js", sensitivity="paranoid", twin="cors-star-session")
case("cors-none", G, {"WEB320": False, "WEB321": False, "WEB322": False, "WEB323": False, "WEB324": False},
     {"/": doc()}, twin="cors-reflect-creds")
case("cors-reflect-vary-ok", G, {"WEB324": False, "WEB321": True},
     {"/": _cors(reflect=True, vary=True, extra=(("Cache-Control", "no-store"),))}, twin="cors-reflect-no-vary")

# ============================================================================================ C-COOKIE (31)
G = "C-COOKIE"
SC = "Set-Cookie"


def ck(*cookies: str, base: list | None = None, body: str = APP, sts: bool = True) -> dict:
    hs = H(base) if base is not None else H()
    if not sts:
        hs = H(hs, drop=[STS])
    return {"/": R(200, hs + [(SC, c) for c in cookies], page(body))}


SID = "sessionid={RAND}"
case("ck-session-no-secure-no-hsts", G, {"WEB020": True}, ck(SID + "; Path=/; HttpOnly; SameSite=Lax", sts=False),
     expect={"severity": {"WEB020": "high"}}, twin="ck-session-secure-ok")
case("ck-session-no-secure-hsts", G, {"WEB020": True}, ck(SID + "; Path=/; HttpOnly; SameSite=Lax"),
     expect={"severity": {"WEB020": "medium"}}, twin="ck-session-secure-ok")
case("ck-secure-pref", G, {"WEB020": True}, ck("secure_pref_sid={RAND}; Path=/; HttpOnly; SameSite=Lax", sts=False),
     defect=("D3",), twin="ck-session-secure-ok",
     note="the cookie name contains 'secure'; 1.0.1's substring test treated the flag as present")
case("ck-secure-prefix-no-secure", G, {"WEB401": True}, ck("__Secure-id={RAND}; Path=/; HttpOnly; SameSite=Lax"),
     twin="ck-host-correct")
case("ck-host-with-domain", G, {"WEB401": True},
     ck("__Host-sid={RAND}; Secure; HttpOnly; Path=/; SameSite=Lax; Domain={HOST}"), twin="ck-host-correct")
case("ck-samesite-none-no-secure", G, {"WEB400": True}, ck("embed_pref={RAND}; Path=/; SameSite=None"),
     twin="ck-session-secure-ok")
case("ck-samesite-lax2", G, {"WEB402": True}, ck(SID + "; Path=/; Secure; HttpOnly; SameSite=Lax2"),
     twin="ck-session-secure-ok")
case("ck-partitioned-no-secure", G, {"WEB403": True}, ck("widget_state={RAND}; Path=/; Partitioned"),
     twin="ck-session-secure-ok")
case("ck-domain-parent-session", G, {"WEB404": True},
     ck(SID + "; Path=/; Secure; HttpOnly; SameSite=Lax; Domain=cookie.kashif.test"), legacy=False,
     zap=False, zap_note="needs the real host name (ZAP column uses 127.0.0.1 URLs)", twin="ck-session-secure-ok")
case("ck-domain-public-suffix", G, {"WEB404": True}, ck("pref=dark; Path=/; Secure; SameSite=Lax; Domain=co.uk"),
     twin="ck-session-secure-ok", note="Domain is a public suffix that does not domain-match the host: rejected")
case("ck-session-90-days", G, {"WEB405": True}, ck(SID + "; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=7776000"),
     twin="ck-session-secure-ok")
case("ck-duplicate", G, {"WEB406": True}, ck("cart=1; Path=/; Secure; SameSite=Lax", "cart=2; Path=/; Secure; SameSite=Strict"),
     twin="ck-session-secure-ok")
case("ck-5kb", G, {"WEB408": True}, ck("blob=" + "A" * 5000 + "; Path=/; Secure; SameSite=Lax"), twin="ck-session-secure-ok")
case("ck-bigip", G, {"WEB411": True}, ck("BIGipServerweb_pool=83886090.20480.0000; Path=/; Secure; HttpOnly"),
     twin="ck-lb-cookie", note="decodes to 10.0.0.5:80")
_JWT_NONE = (base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode() + "." +
             base64.urlsafe_b64encode(b'{"sub":"1001","role":"user"}').rstrip(b"=").decode() + ".")
case("ck-jwt-alg-none", G, {"WEB412": True}, ck(f"auth_token={_JWT_NONE}; Path=/; Secure; HttpOnly; SameSite=Lax"),
     twin="ck-session-secure-ok")
case("ck-session-over-http", G, {"WEB413": True},
     {"/": lambda r: (R(301, [("Location", "{HTTPS}/"), (SC, SID + "; Path=/; HttpOnly; SameSite=Lax"),
                              ("Content-Length", "0")], b"") if r.scheme == "http" else doc())},
     scheme="http", twin="ck-session-secure-ok", note="the http->https hop sets the session cookie in clear text")
case("ck-secure-over-http", G, {"WEB410": True}, {"/": R(200, HTTP_HEADERS(add=[(SC, "pref=1; Path=/; Secure")]),
                                                        page(TEXT))}, scheme="http", twin="ck-session-secure-ok")
case("ck-session-no-httponly", G, {"WEB021": True}, ck(SID + "; Path=/; Secure; SameSite=Lax"), twin="ck-xsrf-token")
case("ck-session-no-samesite", G, {"WEB022": True}, ck(SID + "; Path=/; Secure; HttpOnly"), twin="ck-analytics-no-samesite")
case("ck-csrf-no-samesite", G, {"WEB022": True, "WEB021": False}, ck("csrftoken={RAND}; Path=/; Secure"),
     twin="ck-analytics-no-samesite")
case("ck-session-samesite-none", G, {"WEB407": True}, ck(SID + "; Path=/; Secure; HttpOnly; SameSite=None"),
     twin="ck-session-secure-ok")
case("ck-deletion", G, {"WEB020": False, "WEB021": False, "WEB022": False},
     ck("sid=deleted; Max-Age=0; Path=/", "sessionid=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/", sts=False),
     defect=("D4",), twin="ck-session-no-secure-no-hsts")
case("ck-ga", G, {"WEB021": False, "WEB022": False},
     ck("_ga=GA1.2.1234567890.1700000000; Path=/; Secure; Max-Age=63072000"), defect=("D5",), twin="ck-session-no-httponly",
     note="analytics cookies are read by JavaScript; HttpOnly/SameSite are not demanded")
case("ck-xsrf-token", G, {"WEB021": False}, ck("XSRF-TOKEN={RAND}; Path=/; Secure; SameSite=Lax"),
     twin="ck-session-no-httponly", note="double-submit CSRF cookies must be readable by JavaScript")
case("ck-host-correct", G, {"WEB401": False, "WEB020": False, "WEB021": False, "WEB022": False, "WEB404": False},
     ck("__Host-sid={RAND}; Secure; HttpOnly; Path=/; SameSite=Lax"), twin="ck-host-with-domain")
case("ck-analytics-no-samesite", G, {"WEB022": False}, ck("_gid=GA1.2.987654321.1700000000; Path=/; Secure"),
     twin="ck-session-no-samesite")
case("ck-lang", G, {"WEB021": False, "WEB022": False}, ck("lang=en; Path=/"), twin="ck-session-no-httponly")
case("ck-ignored", G, {"WEB020": False, "WEB021": False, "WEB022": False}, ck("legacy_sess={RAND}; Path=/", sts=False),
     extra_args=("--web-cookie-ignore", "legacy_sess"), twin="ck-session-no-secure-no-hsts",
     note="the cookie is on the user's ignore list")
case("ck-session-secure-ok", G, {"WEB020": False, "WEB021": False, "WEB022": False, "WEB400": False, "WEB402": False,
                                 "WEB403": False, "WEB405": False, "WEB406": False, "WEB407": False, "WEB408": False,
                                 "WEB410": False, "WEB412": False, "WEB413": False},
     ck(SID + "; Path=/; Secure; HttpOnly; SameSite=Lax"), twin="ck-session-no-secure-no-hsts")
case("ck-lb-cookie", G, {"WEB021": False, "WEB022": False, "WEB411": False}, ck("AWSALB=Zm9vYmFyYmF6cXV4; Path=/"),
     twin="ck-bigip")
case("ck-crawl-page-cookie", G, {"WEB020": True},
     {"/": doc(TEXT + '<p><a href="/account">Account</a></p>' + SCRIPT, H(drop=[STS])),
      "/account": R(200, H(drop=[STS], add=[(SC, SID + "; Path=/; HttpOnly; SameSite=Lax")]), page(LOGIN))},
     crawl=True, defect=("D23",), twin="ck-session-secure-ok",
     note="the cookie is set by a crawled page; 1.0.1 never checked crawled responses' cookies")

# ============================================================================================ C-HTML page content (29)
G = "C-HTML"
CDNJS = "https://cdnjs.cloudflare.com/ajax/libs"
SHA384 = "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
case("html-script-http", G, {"WEB050": True},
     {"/": doc(TEXT + '<script src="http://static.kashif-third.test/app.js"></script>')},
     expect={"severity": {"WEB050": "medium"}}, twin="html-a-href-http")
case("html-img-http", G, {"WEB050": True}, {"/": doc(TEXT + '<img src="http://static.kashif-third.test/logo.png" alt="">')},
     expect={"severity": {"WEB050": "low"}}, twin="html-a-href-http")
case("html-form-action-http", G, {"WEB051": True},
     {"/": doc(TEXT + '<form method="post" action="http://{HOST}/subscribe"><input name="email"><button>Go</button></form>')},
     twin="html-template-comment")
case("html-formaction-http", G, {"WEB051": True},
     {"/": doc(TEXT + '<form method="post" action="/save"><input name="q"><button formaction="http://{HOST}/save">Save'
                      '</button></form>')}, twin="html-template-comment")
case("html-password-http", G, {"WEB000": True, "WEB052": False}, {"/": doc(LOGIN, HTTP_HEADERS())}, scheme="http",
     twin="html-password-downgrade",
     note="the whole origin is plain HTTP: WEB000 (capped at D for a login page) explains the password field; WEB052 is "
          "suppressed as a duplicate (§3.5, one cause, one finding) and listed under web.inventory.suppressed")
case("html-password-downgrade", G, {"WEB052": True, "WEB103": True},
     {"/": lambda r: redirect("{HTTP}/login", 302) if r.scheme == "https" else doc(LOGIN, HTTP_HEADERS()),
      "/login": lambda r: doc(LOGIN, HTTP_HEADERS())}, twin="html-password-http",
     note="https entry redirected to a plain-http login page: WEB000 does not apply, so WEB052 is reported")
case("html-cdnjs-no-sri", G, {"WEB053": True, "WEB506": False, "WEB507": False},
     {"/": doc(TEXT + f'<script src="{CDNJS}/lodash.js/4.17.21/lodash.min.js"></script>')},
     expect={"severity": {"WEB053": "low"}}, twin="html-same-site-cdn")
case("html-css-no-sri", G, {"WEB053": True},
     {"/": doc(TEXT, head=f'<link rel="stylesheet" href="{CDNJS}/twitter-bootstrap/5.3.3/css/bootstrap.min.css">')},
     defect=("D22",), twin="html-same-site-cdn", note="1.0.1 only looked at scripts")
case("html-sri-no-crossorigin", G, {"WEB500": True},
     {"/": doc(TEXT + f'<script src="{CDNJS}/lodash.js/4.17.21/lodash.min.js" integrity="{SHA384}"></script>')},
     defect=("D22",), twin="html-sri-good")
case("html-sri-good", G, {"WEB500": False, "WEB501": False, "WEB502": False, "WEB053": False},
     {"/": doc(TEXT + f'<script src="{CDNJS}/lodash.js/4.17.21/lodash.min.js" integrity="{SHA384}" '
                      'crossorigin="anonymous"></script>')}, twin="html-sri-no-crossorigin")
case("html-sri-sha1", G, {"WEB501": True},
     {"/": doc(TEXT + f'<script src="{CDNJS}/lodash.js/4.17.21/lodash.min.js" '
                      'integrity="sha1-2jmj7l5rSw0yVb/vlWAYkK/YBwk=" crossorigin="anonymous"></script>')},
     twin="html-sri-good")
case("html-sri-over-http", G, {"WEB502": True},
     {"/": doc(TEXT + f'<script src="http://static.kashif-third.test/lib.js" integrity="{SHA384}" crossorigin="anonymous">'
                      '</script>', HTTP_HEADERS())}, scheme="http", twin="html-sri-good",
     note="on an https page WEB050 would explain the same element; here the page itself is http")
_LIB = "window.thirdPartyLib = {version: '1.0.0'};\n"
case("html-sri-mismatch", G, {"WEB503": True},
     {"/": doc(TEXT + '<script src="{THIRD}/lib.js" integrity="sha384-' + base64.b64encode(
         hashlib.sha384(b"something else").digest()).decode() + '" crossorigin="anonymous"></script>'),
      "third:/lib.js": js(_LIB, [("Content-Type", "text/javascript"), ("X-Content-Type-Options", "nosniff"),
                                 ("Access-Control-Allow-Origin", "*")])},
     profile="deep", legacy=False, zap=False, zap_note="needs the deep third-party fetch", twin="html-sri-match")
case("html-sri-match", G, {"WEB503": False},
     {"/": doc(TEXT + '<script src="{THIRD}/lib.js" integrity="sha384-' + base64.b64encode(
         hashlib.sha384(_LIB.encode()).digest()).decode() + '" crossorigin="anonymous"></script>'),
      "third:/lib.js": js(_LIB, [("Content-Type", "text/javascript"), ("X-Content-Type-Options", "nosniff"),
                                 ("Access-Control-Allow-Origin", "*")])},
     profile="deep", legacy=False, zap=False, zap_note="needs the deep third-party fetch", twin="html-sri-mismatch")
case("html-rel-opener", G, {"WEB505": True},
     {"/": doc(TEXT + '<a href="https://partner.kashif-third.test/" target="_blank" rel="opener">Partner</a>')},
     twin="html-blank-no-rel")
case("html-blank-no-rel", G, {"WEB505": False},
     {"/": doc(TEXT + '<a href="https://partner.kashif-third.test/" target="_blank">Partner</a>')}, twin="html-rel-opener",
     note="modern browsers imply noopener for target=_blank")
case("html-polyfill-io", G, {"WEB506": True}, {"/": doc(TEXT + '<script src="https://polyfill.io/v3/polyfill.min.js">'
                                                               '</script>')}, twin="html-cdnjs-no-sri")
case("html-coinhive", G, {"WEB507": True},
     {"/": doc(TEXT + '<script nonce="{NONCE}">var miner = new CoinHive.Anonymous("SITE_KEY"); miner.start();</script>')},
     twin="html-blank-no-rel")
case("html-login-get", G, {"WEB509": True},
     {"/": doc(TEXT + '<form method="get" action="/login"><input name="user"><input type="password" name="pw">'
                      '<button>Sign in</button></form>')}, twin="html-template-comment")
case("html-jsessionid-links", G, {"WEB510": True},
     {"/": doc(TEXT + '<p><a href="/cart;jsessionid=A1B2C3D4E5F6G7H8I9J0">Cart</a></p>')}, twin="html-blank-no-rel")
case("html-token-links", G, {"WEB511": True},
     {"/": doc(TEXT + '<p><a href="/reset?token=8f3a9c2b7d1e4f60a1b2">Reset</a></p>')}, sensitivity="paranoid",
     twin="html-blank-no-rel", note="WEB511 is tentative: paranoid sensitivity")
case("html-next-param", G, {"WEB512": True},
     {"/": doc(TEXT + '<p><a href="/login?next=https://partner.kashif-third.test/home">Log in</a></p>')},
     sensitivity="paranoid", expect={"max_severity": {"WEB512": "info"}}, twin="html-blank-no-rel")
case("html-params-benign", G, {"WEB510": False, "WEB511": False, "WEB512": False},
     {"/": doc(TEXT + '<p><a href="/page?sid=abc">Short id</a> <a href="/search?q=kashif">Search</a> '
                      '<a href="/login?next=/home">Log in</a></p>')}, sensitivity="paranoid", twin="html-token-links",
     note="a 3-character id, an ordinary query and a relative next= are not findings")
case("html-upload-form", G, {"WEB513": True},
     {"/": doc(TEXT + '<form method="post" action="/upload" enctype="multipart/form-data"><input type="file" name="f">'
                      '<button>Upload</button></form>')}, twin="html-blank-no-rel")
case("html-quirks-relative-css", G, {"WEB514": True},
     {"/": doc(TEXT, head='<link rel="stylesheet" href="style.css">', doctype=False),
      "/style.css": R(200, [("Content-Type", "text/css"), ("X-Content-Type-Options", "nosniff")], "body{margin:0}\n")},
     twin="html-blank-no-rel")
case("html-a-href-http", G, {"WEB050": False},
     {"/": doc(TEXT + '<p><a href="http://partner.kashif-third.test/">Partner (http)</a></p>')}, defect=("D6",),
     twin="html-script-http", note="navigation links are not mixed content")
case("html-canonical-http", G, {"WEB050": False}, {"/": doc(TEXT, head='<link rel="canonical" href="http://{HOST}/">')},
     twin="html-script-http")
case("html-xmlns", G, {"WEB050": False},
     {"/": doc(TEXT + '<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"><circle cx="4" cy="4" r="4"/></svg>',
               html_attrs=' lang="en" xmlns="http://www.w3.org/1999/xhtml"')}, twin="html-script-http")
case("html-template-comment", G, {"WEB050": False, "WEB051": False, "WEB052": False},
     {"/": doc(TEXT + '<template><script src="http://static.kashif-third.test/t.js"></script>'
                      '<form action="http://{HOST}/x"><input type="password"></form></template>'
                      '<!-- <img src="http://static.kashif-third.test/old.png"> -->')}, twin="html-script-http")
case("html-gtm-no-sri", G, {"WEB053": True},
     {"/": doc(TEXT + '<script async src="https://www.googletagmanager.com/gtag/js?id=G-KASHIF01"></script>')},
     expect={"max_severity": {"WEB053": "info"}}, twin="html-cdnjs-no-sri",
     note="evergreen script that cannot carry SRI: info, not low")
case("html-same-site-cdn", G, {"WEB053": False},
     {"/": doc(TEXT + '<script src="https://static.html.kashif.test/app.js"></script>')}, defect=("D22",),
     twin="html-cdnjs-no-sri", note="same registrable domain (static.* vs the page host): not a third party")
case("html-upgrade-insecure", G, {"WEB050": True},
     {"/": doc(TEXT + '<img src="http://static.kashif-third.test/logo.png" alt="">',
               H(set={CSP: STRICT_CSP + "; upgrade-insecure-requests"}))},
     expect={"max_severity": {"WEB050": "info"}}, twin="html-img-http",
     note="upgrade-insecure-requests: browsers upgrade the request, info only")
case("html-crawl-grouping", G, {"WEB051": True},
     {"/": doc(TEXT + '<p><a href="/a">A</a> <a href="/b">B</a> <a href="/c">C</a></p>'),
      **{f"/{p}": doc(TEXT + f'<form method="post" action="http://{{HOST}}/subscribe" class="f-{p}"><input name="e">'
                             '<button>Go</button></form>') for p in "abc"}},
     crawl=True, expect={"count": {"WEB051": 1}}, defect=("D24",), twin="html-template-comment",
     note="the same form on three crawled pages is one grouped finding; 1.0.1 keyed groups on the snippet")

# ============================================================================================ C-DOM (10)
G = "C-DOM"


def inline(code: str) -> str:
    return TEXT + '<div id="out"></div><script nonce="{NONCE}">\n' + code + "\n</script>"


case("dom-innerhtml-hash", G, {"WEB520": True},
     {"/": doc(inline('document.getElementById("out").innerHTML = decodeURIComponent(location.hash.slice(1));'))},
     twin="dom-textcontent")
case("dom-document-write-search", G, {"WEB520": True},
     {"/": doc(inline("document.write(decodeURIComponent(location.search));"))}, twin="dom-textcontent")
case("dom-location-param", G, {"WEB521": True},
     {"/": doc(inline('var target = new URLSearchParams(location.search).get("u");\nlocation = target;'))},
     twin="dom-location-constant")
case("dom-location-constant", G, {"WEB521": False}, {"/": doc(inline('if (!window.k) { location = "/home"; }'))},
     twin="dom-location-param")
case("dom-message-no-origin", G, {"WEB522": True},
     {"/": doc(inline('window.addEventListener("message", function (e) {\n'
                      '  document.getElementById("out").textContent = e.data;\n});'))},
     sensitivity="paranoid", twin="dom-message-origin-check")
case("dom-message-origin-check", G, {"WEB522": False},
     {"/": doc(inline('window.addEventListener("message", function (e) {\n'
                      '  if (e.origin !== "https://app.kashif.test") { return; }\n'
                      '  document.getElementById("out").textContent = e.data;\n});'))},
     sensitivity="paranoid", twin="dom-message-no-origin")
case("dom-external-file", G, {"WEB520": True},
     {"/": doc(TEXT + '<div id="out"></div><script src="/static/app.js"></script>'),
      "/static/app.js": js('var q = new URLSearchParams(location.search).get("q");\n'
                           'document.getElementById("out").innerHTML = "<b>" + q + "</b>";\n')},
     twin="dom-textcontent", note="same-site script fetched as a subresource")
case("dom-textcontent", G, {"WEB520": False},
     {"/": doc(inline('document.getElementById("out").textContent = location.hash;'))}, twin="dom-innerhtml-hash")
case("dom-dompurify", G, {"WEB520": False},
     {"/": doc(inline('document.getElementById("out").innerHTML = DOMPurify.sanitize(location.hash.slice(1));'))},
     twin="dom-innerhtml-hash")
_JQ_LIKE = ("/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors | jquery.org/license */\n"
            "!function(e){var t=e.document;e.jQuery=function(n){var d=t.createElement('div');"
            "d.innerHTML=location.hash;return d};}(window);\n")
case("dom-jquery-library", G, {"WEB520": False},
     {"/": doc(TEXT + '<script src="/static/jquery-3.7.1.min.js"></script>'), "/static/jquery-3.7.1.min.js": js(_JQ_LIKE)},
     twin="dom-external-file", note="library files are skipped (flows inside libraries are not the site's code)")


def _bundle(_req: Req) -> R:
    flow = 'document.getElementById("out").innerHTML=location.hash;'
    filler = "".join(f"function f{i}(a){{return a+{i}}};" for i in range(80000))
    return js((flow + filler)[: 2_100_000])           # the flow comes first: it survives the size cut


case("dom-big-bundle", G, {"WEB520": False},
     {"/": doc(TEXT + '<div id="out"></div><script src="/static/bundle.min.js"></script>'), "/static/bundle.min.js": _bundle},
     twin="dom-external-file", note="a 2 MB minified bundle is skipped and noted, never half-analysed")

# ============================================================================================ C-DISC disclosure (30)
G = "C-DISC"


def srv(server: str, body: str = APP, extra: tuple = ()) -> dict:
    return {"/": doc(body, H(add=[("Server", server), *extra]))}


case("disc-server-version", G, {"WEB010": True}, srv("Apache/2.4.49 (Unix)"), twin="disc-ecs-server")
case("disc-powered-by", G, {"WEB011": True}, {"/": doc(headers=H(add=[("X-Powered-By", "PHP/7.4.3")]))},
     twin="disc-nginx-bare")
case("disc-aspnet-version", G, {"WEB600": True}, {"/": doc(headers=H(add=[("X-AspNet-Version", "4.0.30319")]))},
     twin="disc-nginx-bare")
case("disc-debug-token", G, {"WEB601": True},
     {"/": doc(headers=H(add=[("X-Debug-Token", "a1b2c3"), ("X-Debug-Token-Link", "{SELF}/_profiler/a1b2c3")]))},
     twin="disc-nginx-bare")
case("disc-sourcemap-header", G, {"WEB602": True},
     {"/": doc(TEXT + '<script src="/static/app.min.js"></script>'),
      "/static/app.min.js": js("window.a=1;\n", [("Content-Type", "text/javascript"), ("X-Content-Type-Options", "nosniff"),
                                                 ("SourceMap", "/static/app.min.js.map")])},
     twin="disc-nginx-bare", note="referenced only (standard profile): info")
case("disc-internal-ip-location", G, {"WEB603": True},
     {"/robots.txt": R(301, [("Location", "http://10.0.0.5/robots.txt"), ("Content-Length", "0")], b"")},
     twin="disc-version-string", note="the redirect to a private address is not followed; the header is still a fact")
case("disc-etag-inode", G, {"WEB604": True},
     {"/": doc(headers=H(set={"Cache-Control": "no-cache"}, add=[("ETag", '"4a1b2-2c-5c6e8f3a1b2c0"')]))},
     twin="disc-nginx-bare")
_NGINX_INDEX = ("<html>\r\n<head><title>Index of /files/</title></head>\r\n<body>\r\n<h1>Index of /files/</h1><hr><pre>"
                '<a href="../">../</a>\r\n<a href="backup/">backup/</a>         12-Nov-2026 10:00       -\r\n'
                '<a href="report.pdf">report.pdf</a>     12-Nov-2026 10:00    48213\r\n</pre><hr></body>\r\n</html>\r\n')
case("disc-nginx-autoindex", G, {"WEB055": True},
     {"/files/": R(200, H(base=[("Content-Type", "text/html")], add=[("Server", "nginx")]), _NGINX_INDEX)},
     path="/files/", twin="disc-blog-index-of")
_IIS_INDEX = ('<html><head><title>{HOST} - /files/</title></head><body><H1>{HOST} - /files/</H1><hr>\r\n\r\n<pre>'
              '<A HREF="/">[To Parent Directory]</A><br><br> 11/12/2026 10:00 AM        48213 '
              '<A HREF="/files/report.pdf">report.pdf</A><br></pre><hr></body></html>')
case("disc-iis-listing", G, {"WEB055": True},
     {"/files/": R(200, [("Content-Type", "text/html"), ("Server", "Microsoft-IIS/10.0")], _IIS_INDEX)},
     path="/files/", twin="disc-blog-index-of")
case("disc-blog-index-of", G, {"WEB055": False, "WEB617": False},
     {"/": doc("<h1>Index of /blog posts</h1><p>An essay about directory listings and why to disable them.</p>",
               title="Index of /blog")}, twin="disc-nginx-autoindex", note="a title without file links is not a listing")
_WERKZEUG = page('<div class="debugger"><h1>ValueError</h1><div class="traceback"><h3>Traceback <em>(most recent call '
                 'last)</em></h3><ul><li><div class="frame" id="frame-140"><h4>File <cite class="filename">'
                 '"/srv/app/app.py"</cite>, line <em class="line">12</em></h4></div></li></ul></div>'
                 '<div class="footer">Brought to you by <strong class="arthur">DON\'T PANIC</strong>, your friendly '
                 'Werkzeug powered traceback interpreter.</div></div><script src="?__debugger__=yes&amp;cmd=resource&amp;'
                 'f=debugger.js"></script>', title="ValueError // Werkzeug Debugger")
case("disc-werkzeug", G, {"WEB605": True}, {"/": R(500, [("Content-Type", "text/html; charset=utf-8"),
                                                         ("Server", "Werkzeug/3.0.1 Python/3.12.3")], _WERKZEUG)},
     expect={"exit": [0, 1, 2]}, twin="disc-pre-traceback")
case("disc-django-debug-404", G, {"WEB605": True},
     {"/nope": R(404, [("Content-Type", "text/html; charset=utf-8")], page(
         "<h1>Page not found <span>(404)</span></h1><table><tr><th>Request URL:</th><td>{SELF}/nope</td></tr></table>"
         "<p>Using the URLconf defined in <code>mysite.urls</code>, Django tried these URL patterns.</p>"
         "<p>You're seeing this error because you have <code>DEBUG = True</code> in your Django settings file. "
         "Change that to <code>False</code>, and Django will display a standard 404 page.</p>",
         title="Page not found at /nope"))}, path="/nope", twin="disc-pre-traceback")
case("disc-sqlstate-500", G, {"WEB606": True},
     {"/search": R(500, [("Content-Type", "text/html; charset=utf-8")], page(
         "<b>Fatal error</b>: Uncaught PDOException: SQLSTATE[42000]: Syntax error or access violation: 1064 You have an "
         "error in your SQL syntax; check the manual that corresponds to your MySQL server version"))},
     path="/search", twin="disc-pre-traceback")
case("disc-path-500", G, {"WEB607": True},
     {"/report": R(500, [("Content-Type", "text/html; charset=utf-8")], page(
         "<b>Warning</b>: include(config.php): Failed to open stream: No such file or directory in "
         "<b>/var/www/html/index.php</b> on line <b>12</b>"))}, path="/report", sensitivity="paranoid",
     twin="disc-pre-traceback", note="WEB607 is tentative: paranoid")
case("disc-php-source", G, {"WEB608": True},
     {"/": R(200, H(), "<html><body><?php $db = mysqli_connect('localhost', 'app', $pw); echo $greeting; ?></body></html>\n")},
     twin="disc-php-escaped")
case("disc-php-escaped", G, {"WEB608": False},
     {"/": doc("<p>Use <code>&lt;?php echo $x; ?&gt;</code> to print a variable.</p>")}, twin="disc-php-source",
     note="documentation shows escaped PHP")
_SK = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc" + "Kq9Z"                 # built at import: no literal in the repository
_PK = "pk_" + "live_" + "51HkashifCorpusPublishableKey0" + "Xy"
case("disc-stripe-secret-inline", G, {"WEB609": True},
     {"/": doc(TEXT + '<script nonce="{NONCE}">var stripeSecret = "' + _SK + '";</script>')}, twin="disc-pk-live")
_PEM = ("-----BEGIN " + "PRIVATE KEY-----\n" + "\n".join(
    base64.b64encode(hashlib.sha512(str(i).encode()).digest()).decode() for i in range(6)) + "\n-----END " + "PRIVATE KEY-----")
case("disc-pem-in-js", G, {"WEB609": True},
     {"/": doc(TEXT + '<script src="/static/config.js"></script>'),
      "/static/config.js": js("window.cfg = {key: `" + _PEM + "`};\n")}, twin="disc-pk-live")
case("disc-pk-live", G, {"WEB609": False},
     {"/": doc(TEXT + '<script nonce="{NONCE}">var stripe = Stripe("' + _PK + '");</script>')},
     twin="disc-stripe-secret-inline", note="publishable keys are meant to be public")
_JAVA_SER = base64.b64encode(b"\xac\xed\x00\x05sr\x00\x13java.util.ArrayListx\x81\xd2\x1d\x99\xc7a\x9d\x03\x00\x01I"
                             b"\x00\x04sizexp\x00\x00\x00\x00w\x04\x00\x00\x00\x00x").decode()
case("disc-java-serialized-cookie", G, {"WEB610": True},
     ck(f"state={_JAVA_SER}; Path=/; Secure; HttpOnly; SameSite=Lax"), twin="disc-version-string")
_VS = base64.b64encode(b"\xff\x01\x0f\x0f\x05\x0b\x0a\x07\x0b0123456789abcdefghij" + b"\x64\x64" * 30).decode()
case("disc-viewstate-no-mac", G, {"WEB611": True},
     {"/": doc(TEXT + f'<form method="post" action="/default.aspx"><input type="hidden" name="__VIEWSTATE" '
                      f'id="__VIEWSTATE" value="{_VS}"><button>Go</button></form>',
               H(add=[("X-AspNet-Version", "2.0.50727")]))}, sensitivity="paranoid", twin="disc-version-string",
     note="ASP.NET ViewState without a MAC heuristic (tentative)")
_BCRYPT = "$2y$10$" + "N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
case("disc-bcrypt-json", G, {"WEB612": True},
     {"/api/user/7": R(200, [("Content-Type", "application/json"), ("X-Content-Type-Options", "nosniff")],
                       '{"id": 7, "name": "kashif", "password_hash": "' + _BCRYPT + '"}')}, path="/api/user/7",
     twin="disc-git-sha")
case("disc-git-sha", G, {"WEB612": False, "WEB613": False},
     {"/": doc(TEXT + "<footer>build 3f2a1c9e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39</footer>")}, twin="disc-bcrypt-json")
case("disc-card-number", G, {"WEB613": True},
     {"/": doc(TEXT + "<p>Card on file: 4539 1488 0343 6467 (expires 08/29)</p>")}, twin="disc-test-card")
case("disc-test-card", G, {"WEB613": True},
     {"/": doc(TEXT + "<p>Use the test card 4111 1111 1111 1111 in the sandbox.</p>")},
     expect={"max_severity": {"WEB613": "info"}}, twin="disc-card-number", note="well-known test numbers: info")
case("disc-openssl-banner", G, {"WEB615": True}, srv("Apache/2.2.22 (Unix) OpenSSL/1.0.1e"), sensitivity="paranoid",
     twin="disc-openssl-fips", note="WEB615 is tentative (banner only)")
case("disc-openssl-fips", G, {"WEB615": False}, srv("Apache/2.4.6 (Red Hat Enterprise Linux) OpenSSL/1.0.1e-fips"),
     sensitivity="paranoid", twin="disc-openssl-banner", note="RHEL backports fixes into -fips builds")
case("disc-apache-default-page", G, {"WEB617": True},
     {"/": R(200, [("Content-Type", "text/html")], page("<div class='page_header'><span>It works!</span></div><p>This is "
                                                       "the default welcome page used to test the correct operation of "
                                                       "the Apache2 server after installation on Ubuntu systems.</p>",
                                                       title="Apache2 Ubuntu Default Page: It works"))},
     twin="disc-blog-index-of")
case("disc-ecs-server", G, {"WEB010": False}, srv("ECS (dcb/7F84)"), defect=("D18",), twin="disc-server-version",
     note="a CDN point-of-presence id, not a version")
case("disc-nginx-bare", G, {"WEB010": False, "WEB011": False, "WEB600": False, "WEB601": False, "WEB604": False},
     srv("nginx", extra=(("ETag", '"6729f1a0-2c"'),)),
     twin="disc-server-version")
case("disc-pre-traceback", G, {"WEB056": False, "WEB606": False, "WEB607": False},
     {"/docs/errors": doc("<h1>Reading Python errors</h1><pre><code>Traceback (most recent call last):\n"
                          '  File "example.py", line 3, in &lt;module&gt;\n    main()\nValueError: invalid literal'
                          "</code></pre><p>The last line names the exception.</p>")}, path="/docs/errors",
     defect=("D16",), twin="disc-werkzeug", note="a traceback inside <pre> on a 200 docs page: tentative, not at default")
case("disc-version-string", G, {"WEB603": False, "WEB610": False}, {"/": doc(TEXT + "<p>Release v10.0.0.1 of the client is out.</p>")},
     twin="disc-internal-ip-location")
_SOFT_ERR = R(500, [("Content-Type", "text/html; charset=utf-8")], page(
    "<h1>Something went wrong</h1><div>java.lang.NullPointerException<br>\tat com.kashif.web.Router.route(Router.java:42)"
    "<br>\tat com.kashif.web.Servlet.service(Servlet.java:17)</div>", title="Error"))
case("disc-error-in-soft404", G, {"WEB056": True}, {"*": _SOFT_ERR}, wellknown=False, profile="deep",
     expect={"count": {"WEB056": 1}, "exit": [0, 1, 2]}, twin="disc-pre-traceback",
     note="a catch-all 500 page with a stack trace answers every path: one finding, not one per probe")

# ============================================================================================ C-LIB components (14)
G = "C-LIB"
case("lib-jquery-url", G, {"WEB054": True, "WEB803": True},
     {"/": doc(TEXT + '<script src="/static/jquery-1.12.4.min.js"></script>'),
      "/static/jquery-1.12.4.min.js": js("/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\n"
                                         "!function(a,b){a.jQuery={fn:{jquery:'1.12.4'}}}(window);\n")},
     twin="lib-jquery-371")
case("lib-jquery-renamed", G, {"WEB054": True},
     {"/": doc(TEXT + '<script src="/static/app.vendor.js"></script>'),
      "/static/app.vendor.js": js("/*! jQuery v2.2.4 | (c) jQuery Foundation | jquery.org/license */\n"
                                  "!function(a,b){a.jQuery={fn:{jquery:'2.2.4'}}}(window);\n")},
     twin="lib-jquery-371", note="version from the file banner, not the URL")
_RETIRE_FIXTURE = HERE.parent.parent / "tests" / "data" / "web" / "libs" / "jquery-deparam-0.5.3.js"


def _retire_fixture(_r: "Req") -> R:
    """The exact jquery-deparam 0.5.3 file (WP9 fixture) whose SHA-1 is in the bundled retire.js data, under a name
    that says nothing about the library: only the hash can identify it."""
    return R(200, [("Content-Type", "text/javascript; charset=utf-8"), ("X-Content-Type-Options", "nosniff"),
                   ("Cache-Control", "public, max-age=3600")], _RETIRE_FIXTURE.read_bytes())


case("lib-retire-hash", G, {"WEB054": True}, {"/": doc(TEXT + '<script src="/static/vendor.js"></script>'),
                                             "/static/vendor.js": _retire_fixture},
     requires=("fixture:retire-hash",), twin="lib-jquery-371",
     note="needs an exact library file whose SHA-1 is in retire.js (WP9 fixture); skipped otherwise")
case("lib-angular-182", G, {"WEB054": True, "WEB803": True},
     {"/": doc(TEXT + '<script src="/static/angular.min.js"></script>'),
      "/static/angular.min.js": js("/*\n AngularJS v1.8.2\n (c) 2010-2020 Google LLC. http://angularjs.org\n"
                                   " License: MIT\n*/\n(function(w){w.angular={version:{full:'1.8.2'}}})(window);\n")},
     twin="lib-jquery-371")
case("lib-lodash-bundle", G, {"WEB054": True},
     {"/": doc(TEXT + '<script src="/static/bundle.js"></script>'),
      "/static/bundle.js": js("/**\n * @license\n * Lodash <https://lodash.com/>\n * Copyright OpenJS Foundation\n */\n"
                              ";(function() {\n  var VERSION = '4.17.15';\n  var _ = {VERSION: VERSION};\n"
                              "  window._ = _;\n}.call(this));\n")}, twin="lib-jquery-371")
case("lib-php-81", G, {"WEB800": True}, {"/": doc(headers=H(add=[("X-Powered-By", "PHP/8.1.2")]))},
     sensitivity="paranoid", twin="lib-php-current", note="banner version: tentative")
case("lib-php-eol", G, {"WEB801": True}, {"/": doc(headers=H(add=[("X-Powered-By", "PHP/5.6.40")]))},
     twin="lib-php-current", note="PHP 5.6 reached end of life in 2018")
case("lib-php-current", G, {"WEB800": False, "WEB801": False}, {"/": doc(headers=H(add=[("X-Powered-By", "PHP")]))},
     sensitivity="paranoid", twin="lib-php-81")
case("lib-apache-ubuntu", G, {"WEB800": True}, srv("Apache/2.4.41 (Ubuntu)"), sensitivity="paranoid",
     twin="lib-php-current", note="tentative, with the distro-backport note")
case("lib-wordpress-49", G, {"WEB080": True, "WEB081": True},
     {"/": doc(TEXT + '<link rel="stylesheet" href="/wp-content/themes/twentyseventeen/style.css?ver=4.9">',
               head='<meta name="generator" content="WordPress 4.9">')}, twin="lib-wordpress-prose")
case("lib-jquery-371", G, {"WEB054": False, "WEB803": False, "WEB602": False},
     {"/": doc(TEXT + '<script src="/static/jquery-3.7.1.min.js"></script>'),
      "/static/jquery-3.7.1.min.js": js(_JQ_LIKE)}, twin="lib-jquery-url")
case("lib-jquery-prose", G, {"WEB054": False},
     {"/": doc("<h1>jQuery 1.4 tutorial</h1><p>In this tutorial we download jquery-1.4.2.min.js and compare it with "
               "jQuery 3.7.</p>")}, defect=("D15",), twin="lib-jquery-url", note="library names in prose are not libraries")
case("lib-administrator-text", G, {"WEB080": False},
     {"/": doc("<h1>Guide</h1><p>Our handbook explains the /administrator/ area of popular CMSs.</p>")},
     defect=("D15",), twin="lib-wordpress-49", note="'/administrator/' alone is not Joomla")
case("lib-wordpress-prose", G, {"WEB080": False, "WEB081": False},
     {"/": doc("<h1>WordPress 5.2 tutorial</h1><p>How to migrate from WordPress 5.2 to a static site.</p>")},
     defect=("D15",), twin="lib-wordpress-49")
case("lib-two-platforms", G, {"WEB080": True},
     {"/": R(200, H(add=[(SC, "laravel_session={RAND}; Path=/; Secure; HttpOnly; SameSite=Lax"),
                         (SC, "XSRF-TOKEN={RAND}; Path=/; Secure; SameSite=Lax")]),
             page(TEXT + '<link rel="stylesheet" href="/wp-content/themes/x/style.css">',
                  head='<meta name="generator" content="WordPress 6.6.2">'))},
     defect=("D15",), expect={"min_count": {"WEB080": 2}}, twin="lib-administrator-text",
     note="two platforms on one page; 1.0.1 reported only the first")

# ============================================================================================ C-TLS (22)
G = "C-TLS"
_CERT_RULES_SILENT = {"WEB070": False, "WEB071": False, "WEB072": False, "WEB700": False, "WEB701": False,
                      "WEB702": False, "WEB703": False, "WEB707": False, "WEB708": False, "WEB709": False,
                      "WEB714": False, "WEB715": False, "WEB720": False}
for _id, _prof, _labels, _extra in (
        ("tls-expired", "expired", {"WEB070": True}, {"defect": ("D21",), "twin": "tls-good-chain",
                                                      "note": "1.0.1 only read the expiry when the certificate validated"}),
        ("tls-not-yet-valid", "notyet", {"WEB720": True}, {"twin": "tls-good-chain"}),
        ("tls-self-signed", "selfsigned", {"WEB701": True}, {"twin": "tls-good-chain"}),
        ("tls-wrong-host", "wronghost", {"WEB700": True}, {"twin": "tls-good-chain"}),
        ("tls-leaf-only", "leafonly", {"WEB702": True}, {"twin": "tls-good-chain", "note": "intermediate not sent"}),
        ("tls-wrong-order", "wrongorder", {"WEB703": True}, {"twin": "tls-good-chain"}),
        ("tls-chain-with-root", "withroot", {"WEB703": True}, {"twin": "tls-good-chain",
                                                               "expect": {"max_severity": {"WEB703": "info"}}}),
        ("tls-sha1-leaf", "sha1", {"WEB708": True}, {"twin": "tls-good-chain"}),
        ("tls-rsa1024", "rsa1024", {"WEB707": True}, {"twin": "tls-good-chain"}),
        ("tls-roca", "roca", {"WEB707": True}, {"twin": "tls-good-chain", "requires": ("roca",)}),
        ("tls-400-days", "days400", {"WEB709": True}, {"twin": "tls-good-chain",
                                                       "note": "issued after 2026-03-15 with a 400-day lifetime"}),
        ("tls-must-staple", "muststaple", {"WEB714": True}, {"twin": "tls-good-chain"}),
        ("tls-expires-soon", "days90left5", {"WEB071": True}, {"twin": "rev-cert-90d-25-left",
                                                               "note": "5 days left of a 90-day certificate (< lifetime/10)"}),
        ("tls-wrong-eku", "wrongeku", {"WEB072": True}, {"twin": "tls-good-chain",
                                                         "note": "client-auth-only certificate: verification fails, no "
                                                                 "more specific rule applies"}),
        ("tls-no-tls13", "tls12only", {"WEB705": True}, {"twin": "tls-modern-only",
                                                         "expect": {"severity": {"WEB705": "low"}}}),
        ("tls10-accepted", "tls10", {"WEB030": True}, {"defect": ("D17",), "requires": ("tls10",), "twin": "tls-modern-only",
                                                       "note": "1.0.1's OpenSSL refused TLS 1.0 client-side: silent miss"}),
        ("tls-stub-sslv3", "stub-sslv3", {"WEB704": True}, {"requires": ("stub",), "twin": "tls-modern-only"}),
        ("tls-stub-rc4", "stub-rc4", {"WEB706": True}, {"requires": ("stub",), "twin": "tls-modern-only"}),
        ("tls-stub-compression", "stub-compression", {"WEB711": True}, {"requires": ("stub",), "twin": "tls-modern-only"}),
        ("tls-stub-no-reneg", "stub-noreneg", {"WEB712": True}, {"requires": ("stub",), "twin": "tls-modern-only"}),
        ("tls-two-ips", "twoips", {"WEB715": True}, {"requires": ("ip2",), "legacy": False, "twin": "tls-good-chain",
                                                     "note": "127.0.0.2 serves TLS 1.2 only; skipped (never passed) "
                                                             "where 127.0.0.2 cannot be bound (default macOS)"}),
        ("tls-good-no-aki", "noaki", {"WEB072": False, "WEB702": False}, {
            "defect": ("D19",), "twin": "tls-wrong-host",
            "note": "Python 3.13's VERIFY_X509_STRICT rejects a leaf without AKI that browsers accept"}),
        ("tls-modern-only", "modern", {"WEB030": False, "WEB704": False, "WEB706": False, "WEB711": False, "WEB712": False,
                                       "WEB705": False, "WEB716": False, "WEB717": False, "WEB718": False},
         {"twin": "tls10-accepted", "note": "TLS 1.2+1.3, ECDHE AEAD only, a certificate naming exact hosts: Mozilla "
                                            "intermediate conformant (WEB718 silent)"}),
        ("tls-stub-timeout", "stub-timeout", {"WEB030": False},
         {"requires": ("stub",), "expect": {"states": {"WEB030": "not_tested"}}, "twin": "tls10-accepted",
          "note": "raw probes time out: not_tested, never pass"}),
        ("tls-good-chain", "good", dict(_CERT_RULES_SILENT), {
            "defect": ("D20",), "twin": "tls-expired", "expect": {"stderr_absent": ["DeprecationWarning"]},
            "note": "1.0.1 used datetime.utcnow() (deprecated, naive)"}),
):
    _kw = dict(_extra)
    _kw.setdefault("zap", False)
    _kw.setdefault("zap_note", "ZAP's passive scanner has no TLS rules")
    case(_id, G, _labels, {"/": doc()}, tls=_prof, **_kw)

# ============================================================================================ C-EXP exposure (26)
G = "C-EXP"
_PLAIN = [("Content-Type", "text/plain; charset=utf-8")]


def site(extra: dict, body: str = APP, headers: list | None = None) -> dict:
    return {"/": doc(body, headers), **extra}


case("exp-git-head", G, {"WEB062": True}, site({"/.git/HEAD": R(200, _PLAIN, "ref: refs/heads/main\n")}), profile="deep",
     twin="exp-catchall-text-ok")
case("exp-env", G, {"WEB062": True},
     site({"/.env": R(200, _PLAIN, "APP_ENV=production\nAPP_KEY=base64:corpus-test-key\nDB_HOST=10.0.0.9\n"
                                   "DB_PASSWORD=corpus-test-password\n")}), profile="deep", twin="exp-env-html")
case("exp-ds-store", G, {"WEB062": True},
     site({"/.DS_Store": R(200, [("Content-Type", "application/octet-stream")],
                           b"\x00\x00\x00\x01Bud1\x00\x00\x10\x00\x00\x00\x08\x00" + b"\x00" * 64)}),
     profile="deep", twin="exp-catchall-octet")
case("exp-svn-entries", G, {"WEB062": True}, site({"/.svn/entries": R(200, _PLAIN, "12\n")}), profile="deep",
     twin="exp-catchall-octet")
_PHPINFO = page('<table><tr class="h"><td><h1 class="p">PHP Version 8.2.12</h1></td></tr></table><table>'
                '<tr><td class="e">System </td><td class="v">Linux web01 6.1.0 x86_64 </td></tr>'
                '<tr><td class="e">Server API </td><td class="v">Apache 2.0 Handler </td></tr></table>',
                title="PHP 8.2.12 - phpinfo()")
case("exp-phpinfo", G, {"WEB062": True}, site({"/phpinfo.php": R(200, [("Content-Type", "text/html; charset=UTF-8")],
                                                                    _PHPINFO)}), profile="deep", defect=("D12",),
     twin="exp-spa-catchall", note="HTML by nature: 1.0.1 rejected every HTML probe response")
_STATUS = page("<h1>Apache Server Status for {HOST} (via 10.0.0.5)</h1><dl><dt>Server Version: Apache/2.4.58 (Unix)</dt>"
               "<dt>Current Time: Thursday, 12-Nov-2026 10:00:00 UTC</dt></dl>", title="Apache Status")
case("exp-server-status", G, {"WEB062": True}, site({"/server-status": R(200, [("Content-Type", "text/html")], _STATUS)}),
     profile="deep", defect=("D12",), twin="exp-spa-catchall")
case("exp-actuator-env", G, {"WEB062": True},
     site({"/actuator/env": R(200, [("Content-Type", "application/vnd.spring-boot.actuator.v3+json")],
                              '{"activeProfiles": ["prod"], "propertySources": [{"name": "server.ports", '
                              '"properties": {"local.server.port": {"value": 8080}}}]}')}), profile="deep",
     twin="exp-catchall-text-ok")
case("exp-actuator-index", G, {"WEB062": True},
     site({"/actuator": R(200, [("Content-Type", "application/vnd.spring-boot.actuator.v3+json")],
                          '{"_links": {"self": {"href": "{SELF}/actuator"}, "heapdump": {"href": "{SELF}/actuator/heapdump"},'
                          ' "threaddump": {"href": "{SELF}/actuator/threaddump"}}}'),
           "/actuator/heapdump": R(500, _PLAIN, "this request must never be sent\n")}),
     profile="deep", expect={"server_never": ["/actuator/heapdump", "/actuator/threaddump", "/debug/pprof"]},
     twin="exp-catchall-text-ok", note="heapdump/threaddump are listed from the index, never requested (§0.1)")
case("exp-swagger", G, {"WEB062": True},
     site({"/swagger-ui/index.html": R(200, [("Content-Type", "text/html")], page(
         '<div id="swagger-ui"></div><script src="./swagger-ui-bundle.js"></script>', title="Swagger UI"))}),
     profile="deep", twin="exp-spa-catchall")
case("exp-laravel-log", G, {"WEB062": True},
     site({"/storage/logs/laravel.log": R(200, _PLAIN, "[2026-11-01 10:00:00] production.ERROR: SQLSTATE[HY000] [2002] "
                                                       "Connection refused {\"exception\":\"[object] (PDOException)\"}\n")}),
     profile="deep", twin="exp-catchall-text-ok")
case("exp-crossdomain", G, {"WEB903": True},
     site({"/crossdomain.xml": R(200, [("Content-Type", "text/x-cross-domain-policy")],
                                 '<?xml version="1.0"?>\n<cross-domain-policy><allow-access-from domain="*" secure="false"/>'
                                 "</cross-domain-policy>\n")}), profile="deep", twin="exp-catchall-text-ok")
case("exp-sectxt-expired", G, {"WEB900": True},
     site({"/.well-known/security.txt": text("Contact: mailto:security@kashif.test\nExpires: {PAST}\n")}),
     twin="exp-sectxt-valid")
case("exp-sectxt-no-contact", G, {"WEB900": True},
     site({"/.well-known/security.txt": text("Expires: {EXPIRES}\nPreferred-Languages: en\n")}), twin="exp-sectxt-valid")
case("exp-sectxt-valid", G, {"WEB900": False, "WEB060": False}, site({}), twin="exp-sectxt-expired")
case("exp-no-sectxt", G, {"WEB060": True}, site({"/.well-known/security.txt": NOT_FOUND, "/security.txt": NOT_FOUND}),
     twin="exp-sectxt-valid")
case("exp-robots-admin", G, {"WEB061": True},
     site({"/robots.txt": text("User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n")}), twin="exp-robots-admin-guide")
case("exp-robots-admin-guide", G, {"WEB061": False},
     site({"/robots.txt": text("User-agent: *\nDisallow: /administration-guide\nDisallow: /search\n")}),
     twin="exp-robots-admin")
_GH404 = page("<h1>404</h1><p><strong>There isn't a GitHub Pages site here.</strong></p>", title="Site not found")
case("exp-takeover", G, {"WEB901": True}, {"*": R(404, [("Content-Type", "text/html"), ("Server", "GitHub.com")], _GH404)},
     wellknown=False, legacy=False, zap=False, zap_note="needs the CNAME from the resolver hook",
     dns={"exp-takeover.exp.kashif.test": {"canonical": "kashif-corpus-gone.github.io",
                                           "aliases": ["exp-takeover.exp.kashif.test"]}},
     twin="exp-takeover-no-cname", note="CNAME to github.io + the provider's 404 fingerprint")
case("exp-takeover-no-cname", G, {"WEB901": False},
     {"*": R(404, [("Content-Type", "text/html"), ("Server", "GitHub.com")], _GH404)}, wellknown=False, twin="exp-takeover")
case("exp-wp-login", G, {"WEB083": True},
     site({"/wp-login.php": R(200, H(), page('<form name="loginform" id="loginform" action="/wp-login.php" method="post">'
                                              '<input type="text" name="log"><input type="password" name="pwd">'
                                              '<input type="submit" name="wp-submit" value="Log In"></form>',
                                              title="Log In &lsaquo; Corpus &#8212; WordPress"))},
          body=APP + '<link rel="stylesheet" href="/wp-content/themes/x/style.css">',
          headers=H(add=[("Link", '<{SELF}/wp-json/>; rel="https://api.w.org/"')])), profile="deep", twin="exp-spa-catchall")
case("exp-drupal-changelog", G, {"WEB082": True},
     site({"/core/CHANGELOG.txt": R(200, _PLAIN, "Drupal 10.1.6, 2023-11-01\n-------------------------\n- Fixed bugs.\n")},
          body=APP, headers=H(add=[("X-Generator", "Drupal 10 (https://www.drupal.org)")])), profile="deep",
     twin="exp-catchall-text-ok")
case("exp-catchall-octet", G, {"WEB062": False, "WEB082": False},
     {"*": R(200, [("Content-Type", "application/octet-stream")], b"\x00\x01kashif-catch-all\x00")}, wellknown=False,
     profile="deep", defect=("D13",), twin="exp-ds-store", note="every path answers 200 with the same bytes")
case("exp-catchall-text-ok", G, {"WEB062": False, "WEB903": False}, {"*": R(200, _PLAIN, "OK\n"), "/": doc()}, wellknown=False,
     profile="deep", twin="exp-git-head")
_SPA = page('<div id="root"></div><noscript>Login to continue</noscript><script src="/static/app.js"></script>',
            title="Corpus App")
case("exp-spa-catchall", G, {"WEB083": False, "WEB062": False},
     {"*": R(200, H(), _SPA), "/": doc(_SPA.split("<body>")[1].split("</body>")[0] +
                                       '<link rel="stylesheet" href="/wp-content/themes/x/style.css">')},
     wellknown=False, profile="deep", defect=("D14",), twin="exp-wp-login",
     note="an SPA answers every path with its shell (which says 'Login')")
case("exp-env-html", G, {"WEB062": False}, site({"/.env": doc(TEXT)}), profile="deep", twin="exp-env",
     note="an HTML page at /.env is not an exposed env file")
case("exp-deep-gap", G, {"WEB062": False}, site({}), profile="deep", defect=("D25",), expect={"min_gap": 0.18},
     twin="exp-git-head", note="every request, deep probes included, honours the global per-host gap")

# ============================================================================================ C-WAF (6)
G = "C-WAF"
_HEADER_RULES_SILENT = {"WEB-content-security-policy": False, "WEB-x-frame-options": False,
                        "WEB-strict-transport-security": False, "WEB-x-content-type-options": False,
                        "WEB-referrer-policy": False, "WEB-permissions-policy": False}
_CF = R(403, [("Content-Type", "text/html; charset=UTF-8"), ("Server", "cloudflare"), ("cf-mitigated", "challenge"),
              ("CF-RAY", "8f00aa11bb22cc33-FRA"), ("Cache-Control", "private, max-age=0, no-store")],
        page('<div id="challenge-platform"></div><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1">'
             "</script>", title="Just a moment..."))
case("waf-cloudflare", G, {"WEB990": True, **_HEADER_RULES_SILENT}, {"*": _CF}, wellknown=False,
     expect={"grade": "?"}, twin="waf-deep-probe-only")
case("waf-akamai", G, {"WEB990": True, **_HEADER_RULES_SILENT},
     {"*": R(403, [("Content-Type", "text/html"), ("Server", "AkamaiGHost"), ("Mime-Version", "1.0")],
             "<HTML><HEAD>\n<TITLE>Access Denied</TITLE>\n</HEAD><BODY>\n<H1>Access Denied</H1>\n You don't have permission "
             "to access \"http&#58;&#47;&#47;{HOST}&#47;\" on this server.<P>\nReference&#32;&#35;18&#46;1a2b3c4d&#46;"
             "1700000000&#46;5e6f7a8b\n</BODY>\n</HTML>\n")}, wellknown=False, twin="waf-deep-probe-only")
case("waf-aws", G, {"WEB990": True, **_HEADER_RULES_SILENT},
     {"*": R(403, [("Content-Type", "text/html"), ("x-amzn-waf-action", "captcha"), ("Server", "awselb/2.0")],
             page("<h1>403 Forbidden</h1>"))}, wellknown=False, twin="waf-deep-probe-only")


def _rate_limited_once(req: Req) -> R:
    if req.path == "/" and req.hits >= 1:
        return doc()
    return R(429, [("Content-Type", "text/plain"), ("Retry-After", "2")], "slow down\n")


case("waf-429-retry-after", G, {}, {"*": _rate_limited_once}, wellknown=False,
     expect={"entry_gap": 1.8, "max_requests": 4, "exit": [0, 1]},
     note="429 + Retry-After: 2 → one wait, then 200; the next 429 stops the host (partial, inconclusive)")
case("waf-503-twice", G, {"WEB990": True, "WEB-content-security-policy": False},
     {"*": R(503, [("Content-Type", "text/plain"), ("Retry-After", "1")], "maintenance\n")}, wellknown=False,
     expect={"max_requests": 3, "exit": [0, 1, 2]}, twin="waf-deep-probe-only")
case("waf-deep-probe-only", G, {"WEB-x-frame-options": True, "WEB062": False},
     {"/": doc(LOGIN, H(drop=["X-Frame-Options"], set={CSP: CSP_NO_FA})), "/.*": _CF, "/server-status": _CF,
      "/phpinfo.php": _CF, "/actuator*": _CF, "/swagger*": _CF, "/backup.sql": _CF, "/wp-*": _CF},
     profile="deep", twin="waf-cloudflare", note="the WAF only blocks the deep probes; the rest of the scan is normal")

# ============================================================================================ C-GRADE (11)
G = "C-GRADE"
_APLUS = H(set={"Cross-Origin-Resource-Policy": "same-origin"},
           add=[(SC, "__Host-sid={RAND}; Secure; HttpOnly; Path=/; SameSite=Lax")])
case("grade-aplus", G, {}, {"/": doc(APP, _APLUS)}, tls="modern", zap=False, expect={"grade": "A+"},
     note="strict CSP, HSTS 2 y, prefixed SameSite cookie, COOP+CORP, TLS 1.2/1.3 AEAD only")
case("grade-a", G, {"WEB114": True}, {"/": doc(APP, H(_APLUS, set={STS: "max-age=63072000"}))}, tls="modern", zap=False,
     expect={"grade": "A"}, note="as A+ but HSTS without includeSubDomains: cap A")
_B_HEADERS = H(drop=[CSP, "X-Frame-Options", XCTO],
               set={"Cache-Control": "public, max-age=600", "Cross-Origin-Resource-Policy": "Same-Origin"},
               add=[(SC, "__Host-sid={RAND}; Secure; HttpOnly; Path=/; SameSite=Lax"), ("Access-Control-Allow-Origin", "null"),
                    ("X-Permitted-Cross-Domain-Policies", "all"), ("Clear-Site-Data", "cookies")])
_B_BODY = (TEXT + '<form action="/search"><input name="q"><button>Search</button></form>'
           '<script src="http://static.kashif-third.test/widget.js"></script>')
case("grade-b", G, {"WEB-content-security-policy": True, "WEB050": True}, {"/": doc(_B_BODY, _B_HEADERS)}, tls="modern",
     zap=False, expect={"grade": "B"},
     note="browser-policy family at 0 (missing CSP/XFO/XCTO, WEB315, WEB322, WEB316, WEB317, WEB310) and one active mixed "
          "item: base ≈ 77-79 (hand-derived from §3.4; confirm in phase D)")
_C_HEADERS = H(_B_HEADERS, drop=[STS, SC],
               add=[(SC, "sessionid={RAND}; Secure; Path=/; Domain=grade.kashif.test; Max-Age=7776000"),
                    (SC, "pref=1; Path=/; SameSite=None"), ("Server", "Apache/2.4.58 (Ubuntu)"),
                    ("X-Powered-By", "PHP/8.3.1-1ubuntu1"),
                    ("X-Debug-Token", "c0ffee")])
_C_BODY = _B_BODY + '<form method="post" action="http://{HOST}/subscribe"><input name="e"><button>Go</button></form>'
case("grade-c", G, {"WEB-strict-transport-security": True}, {"/": doc(_C_BODY, _C_HEADERS)}, tls="modern", zap=False,
     legacy=False, expect={"grade": "C"},
     note="adds missing HSTS, weak cookies, banners and a debug header: base 58.75 (measured in phase D). The banners are "
          "distribution builds so WEB800 stays tentative (backports) and cannot cap the grade at F as a critical firm finding")
case("grade-f", G, {"WEB609": True}, {"/": doc(TEXT + '<script nonce="{NONCE}">var k = `' + _PEM + '`;</script>')},
     expect={"grade": "F"}, note="a critical finding caps the grade at F")
case("grade-star", G, {}, {"/": doc(TEXT, HTTP_HEADERS())}, scheme="http", expect={"grade_suffix": "*"},
     note="TLS cannot be tested (http target on a non-default port): the grade is provisional")
case("grade-waf", G, {"WEB990": True}, {"*": _CF}, wellknown=False, expect={"grade": "?"})
case("grade-mono-frame-ancestors", G, {}, {"/": doc(APP, H(drop=["X-Frame-Options"], set={CSP: "frame-ancestors 'none'"}))},
     expect={"grade_at_least_case": "grade-mono-no-csp"}, note="a clickjacking-only CSP never grades below no CSP")
case("grade-mono-no-csp", G, {"WEB-content-security-policy": True}, {"/": doc(APP, H(drop=[CSP]))})
case("grade-obs-165", G, {}, {"/": doc(APP, H(_APLUS, set={STS: "max-age=63072000; includeSubDomains; preload"}))},
     expect={"observatory": 140}, note="Observatory fixture: 140 recorded with the official @mdn/mdn-http-observatory "
                                       "1.7.2 analyzer (bench/web/observatory_official.py), never by hand; the corpus host is "
                                       "not in the preload list, so there is no preload credit")
case("grade-obs-100", G, {}, {"/": doc(APP, H(drop=["Permissions-Policy", "Cross-Origin-Opener-Policy"]))},
     expect={"observatory": 115}, note="Observatory fixture: 115 recorded with the official @mdn/mdn-http-observatory 1.7.2 "
                                       "analyzer (bench/web/observatory_official.py)")
case("grade-obs-0", G, {}, {"/": doc(LOGIN, HTTP_HEADERS(drop=[CSP, XFO, XCTO, RP],
                                                          add=[(SC, "sessionid={RAND}; Path=/")]))},
     scheme="http", expect={"observatory": 0}, note="Observatory fixture: 0 recorded with the official "
                                                    "@mdn/mdn-http-observatory 1.7.2 analyzer (bench/web/observatory_official.py)")

# ============================================================================================ C-HOSTILE (12, spec §0.6)
G = "C-HOSTILE"
_EVIL = '<script>alert("kashif-xss")</script>\x1b[31mRED\x1b[0m'
case("hostile-markup-ansi", G, {"WEB010": False},
     {"/": R(200, H(add=[("Server", _EVIL), ("X-Powered-By", "\x1b]8;;http://evil.kashif-third.test/\x1b\\click\x1b]8;;\x1b\\")]),
             page(APP, title=_EVIL.replace("<", "&lt;").replace(">", "&gt;") + "<script>document.title='x'</script>"))},
     expect={"output_safe": True}, note="target text must be escaped in HTML/Markdown and stripped of ANSI in the terminal")
case("hostile-curl-injection", G, {},
     {"/": redirect("{HTTP}/'$(id)'", 302), "*": doc(TEXT, HTTP_HEADERS())}, scheme="http",
     expect={"curl_quoted": True, "exit": [0, 1]}, note="every argument of the curl reproduction line is shell-quoted")
case("hostile-slow-drip", G, {}, {"/": R(200, [("Content-Type", "text/html")], b"", special="drip")}, requires=("slow",),
     expect={"max_elapsed": 50, "exit": [0, 1, 2]}, note="1 byte every 0.5 s: the 30 s per-response deadline stops it")
case("hostile-120-headers", G, {},
     {"/robots.txt": R(200, [("Content-Type", "text/plain")] + [(f"X-Filler-{i:03d}", "x") for i in range(120)],
                       "User-agent: *\nAllow: /\n")},
     expect={"json_contains": ["too many headers"], "exit": [0, 1]},
     note="http.client raises on > 100 header lines: the response is an error 'too many headers', never dropped silently")
case("hostile-gzip-bomb", G, {}, {"/": R(200, [("Content-Type", "text/html"), ("Content-Encoding", "gzip")], b"",
                                        special="bomb")},
     expect={"max_elapsed": 60, "max_rss_mb": 600, "exit": [0, 1]}, note="1 MB of gzip inflating to 1 GiB: capped")
case("hostile-brotli-body", G, {"WEB055": False, "WEB605": False, "WEB010": True, "WEB991": True},
     {"/": R(200, [("Content-Type", "text/html"), ("Content-Encoding", "br"), ("Server", "Apache/2.4.49 (Unix)")],
             page('<h1>Index of /</h1><a href="../">../</a><a href="?C=N;O=D">Name</a>' + _WERKZEUG, title="Index of /"))},
     twin="disc-nginx-autoindex", note="an unrequested coding: header rules run, body rules are not_tested (the bytes are "
                                       "never parsed)")
case("hostile-redirect-metadata", G, {}, {"/": redirect("http://169.254.169.254/latest/meta-data/", 302)},
     expect={"max_elapsed": 20, "exit": [0, 1, 2]}, note="cloud metadata addresses are never requested")
case("hostile-redirect-ip2", G, {}, {"/": redirect("http://127.0.0.2:{HTTP_PORT}/_case/hostile-redirect-ip2/landing", 302),
                                     "/landing": doc()},
     expect={"no_requests_on_ip2": True, "exit": [0, 1, 2]}, legacy=False,
     note="the hook labels the target public; a redirect to loopback 127.0.0.2 is not followed")
case("hostile-dns-rebinding", G, {},
     {"/": doc()}, dns={"hostile-dns-rebinding.hostile.kashif.test": {"sequence": [["127.0.0.1"], ["10.13.37.1"]]}},
     expect={"min_requests": 2, "max_elapsed": 40, "exit": [0, 1]}, legacy=False, zap=False,
     note="the second lookup answers a private address: the address is pinned per host for the whole scan")
case("hostile-redirect-file", G, {}, {"/": redirect("file:///etc/passwd", 302)}, expect={"exit": [0, 1, 2]})
case("hostile-redirect-javascript", G, {}, {"/": redirect("javascript:alert(document.domain)", 302)},
     expect={"exit": [0, 1, 2]})
case("hostile-obs-fold-hsts", G, {"WEB-strict-transport-security": False},
     {"/": doc(headers=H(set={STS: "max-age=63072000;\r\n includeSubDomains"}))},
     note="obsolete line folding: normalised, recorded as a fact, never a crash or a 'missing' finding")

# ============================================================================================ C-REVIEW (14)
G = "C-REVIEW"
case("rev-cn-only", G, {"WEB700": True}, {"/": doc()}, tls="cnonly", zap=False,
     note="CN-only certificate: browsers ignore the CN (hostname_checks_common_name = False)", twin="rev-cert-90d-25-left")
case("rev-shared-cache-session", G, {"WEB315": True},
     {"/": doc(APP, H(set={"Cache-Control": "public, max-age=300"},
                      add=[(SC, "sessionid=K0rpusSharedSessionValue0123456789; Path=/; Secure; HttpOnly; SameSite=Lax")]))},
     expect={"confidence": {"WEB315": "certain"}}, twin="hdr-static-immutable",
     note="the entry GET and the cookieless CORS GET receive the same session id: a shared cache leaks it")
case("rev-session-echo", G, {"WEB414": True},
     {"/": doc(APP + '<script nonce="{NONCE}">var sessionToken = "{RAND}";</script>',
               H(add=[(SC, "sessionid={RAND}; Path=/; Secure; HttpOnly; SameSite=Lax")]))}, twin="ck-xsrf-token",
     note="the HttpOnly session value is printed into the page")
case("rev-csrf-echo", G, {"WEB414": False},
     {"/": doc(LOGIN.replace('value="{NONCE}"', 'value="{RAND}"'),
               H(add=[(SC, "XSRF-TOKEN={RAND}; Path=/; Secure; SameSite=Lax")]))}, twin="rev-session-echo",
     note="double-submit CSRF tokens are meant to appear in the page (csrf class excluded)")
case("rev-jsdelivr-unpinned", G, {"WEB519": True},
     {"/": doc(TEXT + '<script src="https://cdn.jsdelivr.net/npm/kashif-lib@3/dist/lib.min.js"></script>')},
     twin="rev-jsdelivr-pinned")
case("rev-jsdelivr-pinned", G, {"WEB519": False},
     {"/": doc(TEXT + '<script src="https://cdn.jsdelivr.net/npm/kashif-lib@3.7.1/dist/lib.min.js"></script>')},
     twin="rev-jsdelivr-unpinned")
case("rev-unregistered-script", G, {"WEB517": True},
     {"/": doc(TEXT + '<script src="https://cdn.kashif-gone.test/app.js"></script>')},
     dns={"cdn.kashif-gone.test": {"status": "nxdomain"}, "kashif-gone.test": {"status": "nxdomain"}},
     legacy=False, zap=False, zap_note="needs the resolver hook", twin="rev-missing-host-live-domain",
     note="variant A: the script's registrable domain is not registered")
case("rev-s3-nosuchbucket", G, {"WEB517": True},
     {"/": doc(TEXT + '<script src="https://kashif-corpus-gone.s3.amazonaws.com:{HTTPS_PORT}/app.js"></script>'),
      "s3:/app.js": R(404, [("Content-Type", "application/xml"), ("Server", "AmazonS3")],
                      '<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>NoSuchBucket</Code><Message>The specified '
                      "bucket does not exist</Message><BucketName>kashif-corpus-gone</BucketName></Error>")},
     extra_hosts={"kashif-corpus-gone.s3.amazonaws.com": "s3"}, profile="deep", legacy=False, zap=False,
     twin="rev-missing-host-live-domain", note="variant C: the deep third-party fetch finds a deleted bucket")
case("rev-404-drops-headers", G, {"WEB318": True},
     {"/robots.txt": R(404, [("Content-Type", "text/html")], page("<h1>Not found</h1>"))}, twin="rev-404-keeps-headers",
     note="nginx add_header without 'always': the security headers vanish on error pages")
case("rev-404-keeps-headers", G, {"WEB318": False}, {"/robots.txt": NOT_FOUND}, twin="rev-404-drops-headers")
case("rev-missing-host-live-domain", G, {"WEB517": False},
     {"/": doc(TEXT + '<script src="https://ghost.kashif-third.test/app.js"></script>')},
     dns={"ghost.kashif-third.test": {"status": "nxdomain"}}, legacy=False, zap=False, twin="rev-unregistered-script",
     note="variant B (host missing inside a live domain) is low/tentative: not reported at default sensitivity")
case("rev-all-nxdomain", G, {"WEB517": False},
     {"/": doc(TEXT + '<script src="https://cdn.kashif-gone.test/app.js"></script>'
                      '<script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>')},
     dns={"*": {"status": "nxdomain"}}, expect={"states": {"WEB517": "not_tested"}}, legacy=False, zap=False,
     twin="rev-unregistered-script", note="resolver sanity guard: when everything is NXDOMAIN, nothing is concluded")
case("rev-proxied", G, {"WEB517": False},
     {"/": doc(TEXT + '<script src="https://cdn.kashif-gone.test/app.js"></script>')},
     dns={"cdn.kashif-gone.test": {"status": "nxdomain"}, "kashif-gone.test": {"status": "nxdomain"}},
     use_proxy=True, expect={"json_contains": ["proxy"]}, legacy=False, zap=False, twin="rev-unregistered-script",
     note="scanning through an HTTPS proxy: DNS-based checks are not_tested (§0.7)")
case("rev-cert-90d-25-left", G, {"WEB071": False}, {"/": doc()}, tls="days90left25", zap=False, twin="rev-cn-only",
     note="25 days left of a 90-day certificate is normal ACME renewal timing")
case("rev-xxss-block", G, {"WEB311": True}, {"/": doc(headers=H(add=[("X-XSS-Protection", "1; mode=block")]))},
     expect={"max_severity": {"WEB311": "info"}}, twin="hdr-xxss-zero")
case("rev-git-head-catchall", G, {"WEB062": True},
     {"*": R(200, _PLAIN, "Nothing to see here :)\n"), "/": doc(), "/.git/HEAD": R(200, _PLAIN, "ref: refs/heads/main\n")},
     wellknown=False, profile="deep", twin="exp-catchall-text-ok",
     note="a strong signature decides against a catch-all baseline of similar length")


# ============================================================================================ phase D additions
# Spec §5.4 asks for at least one true positive (and a trap) for every rule. These cases cover the rules the original
# groups left unscored; each sits in the group its rule belongs to.


def _gzip_doc(body: str, headers: list | None = None) -> Handler:
    """A gzip-encoded document (the corpus serves bytes as given), rendered per request like any other page."""
    def fn(req: "Req") -> R:
        raw = page(body).replace("{NONCE}", secrets.token_hex(12))
        return R(200, H(headers, set={"Content-Encoding": "gzip"}) if headers else H(set={"Content-Encoding": "gzip"}),
                 gzip.compress(raw.encode("utf-8")))
    return fn


def _jpeg(gps: bool) -> bytes:
    """A minimal JPEG whose EXIF APP1 has a GPS IFD with latitude and longitude (``gps``) or only an Orientation tag."""
    def entry(tag: int, typ: int, count: int, value: bytes) -> bytes:
        return struct.pack(">HHI", tag, typ, count) + value.ljust(4, b"\0")
    if gps:
        gps_ifd_at, data_at = 8 + 18, 8 + 18 + 54
        ifd0 = struct.pack(">H", 1) + entry(0x8825, 4, 1, struct.pack(">I", gps_ifd_at)) + b"\0\0\0\0"
        lat = struct.pack(">6I", 21, 1, 25, 1, 3, 1)
        lon = struct.pack(">6I", 39, 1, 49, 1, 7, 1)
        gps_ifd = (struct.pack(">H", 4) + entry(1, 2, 2, b"N") + entry(2, 5, 3, struct.pack(">I", data_at))
                   + entry(3, 2, 2, b"E") + entry(4, 5, 3, struct.pack(">I", data_at + 24)) + b"\0\0\0\0")
        tiff = b"MM\x00\x2a" + struct.pack(">I", 8) + ifd0 + gps_ifd + lat + lon
    else:
        tiff = b"MM\x00\x2a" + struct.pack(">I", 8) + struct.pack(">H", 1) + entry(0x0112, 3, 1, b"\0\x01") + b"\0" * 4
    app1 = b"Exif\0\0" + tiff
    return b"\xff\xd8" + b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1 + b"\xff\xd9"


_JPEG_HEADERS = [("Content-Type", "image/jpeg"), ("X-Content-Type-Options", "nosniff"), ("Cache-Control", "public, max-age=600")]
_APACHE_404 = R(404, [("Content-Type", "text/html; charset=iso-8859-1")],
                "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head><title>404 Not Found</title></head><body>"
                "<h1>Not Found</h1><p>The requested URL was not found on this server.</p><hr>"
                "<address>Apache/2.4.58 (Ubuntu) Server at {HOST} Port 443</address></body></html>\n")
_BASIC_401 = [("Content-Type", "text/html; charset=utf-8"), ("WWW-Authenticate", 'Basic realm="admin"'),
              ("X-Content-Type-Options", "nosniff")]
_TT = "; require-trusted-types-for 'script'"
_NO_REPORT = "default-src 'self'; script-src 'nonce-{NONCE}' 'strict-dynamic'" + GOOD_TAIL

# C-RED / C-HSTS: transport
case("red-basic-auth-http", "C-RED", {"WEB118": True}, {"/": R(401, _BASIC_401, page("<h1>Sign in required</h1>"))},
     scheme="http", twin="red-basic-auth-https", expect={"severity": {"WEB118": "high"}},
     note="WWW-Authenticate: Basic over plain HTTP: the password travels base64-encoded in clear text")
case("red-basic-auth-https", "C-RED", {"WEB118": False}, {"/": R(401, _BASIC_401, page("<h1>Sign in required</h1>"))},
     twin="red-basic-auth-http")
case("hsts-breach-token-gzip", "C-HSTS", {"WEB119": True}, {"/": _gzip_doc(LOGIN)}, sensitivity="paranoid",
     twin="hsts-breach-token-plain", note="gzip + a CSRF token in a form: the BREACH precondition (tentative, paranoid only)")
case("hsts-breach-token-plain", "C-HSTS", {"WEB119": False}, {"/": doc(LOGIN)}, sensitivity="paranoid",
     twin="hsts-breach-token-gzip")

# C-CSP
case("csp-no-reporting", "C-CSP", {"WEB215": True}, csp(_NO_REPORT), twin="csp-with-reporting")
case("csp-with-reporting", "C-CSP", {"WEB215": False, "WEB991": False}, {"/": doc()}, twin="csp-no-reporting",
     note="report-to with a matching Reporting-Endpoints group")
case("csp-no-trusted-types", "C-CSP", {"WEB219": True}, {"/": doc()}, sensitivity="paranoid", twin="csp-trusted-types")
case("csp-trusted-types", "C-CSP", {"WEB219": False}, csp(STRICT_CSP + _TT), sensitivity="paranoid",
     twin="csp-no-trusted-types")

# C-COOKIE
case("ck-session-no-host-prefix", "C-COOKIE", {"WEB409": True}, ck("sid={RAND}; Secure; HttpOnly; Path=/; SameSite=Lax"),
     sensitivity="paranoid", twin="ck-session-host-prefix")
case("ck-session-host-prefix", "C-COOKIE", {"WEB409": False},
     ck("__Host-sid={RAND}; Secure; HttpOnly; Path=/; SameSite=Lax"), sensitivity="paranoid",
     twin="ck-session-no-host-prefix")

# C-HTML: forms and markup
_CONTACT = '<form method="post" action="{HTTPS}/contact"><input name="email"><button>Send</button></form>'
case("html-http-form-to-https", "C-HTML", {"WEB504": True, "WEB103": True},
     {"/": lambda r: redirect("{HTTP}/contact", 302) if r.scheme == "https" else doc(TEXT + _CONTACT, HTTP_HEADERS()),
      "/contact": lambda r: doc(TEXT + _CONTACT, HTTP_HEADERS())}, twin="html-http-form-to-https-web000",
     note="an https entry redirected to a plain-http page whose form posts to https: a MITM can rewrite the form")
case("html-http-form-to-https-web000", "C-HTML", {"WEB000": True, "WEB504": False},
     {"/": doc(TEXT + _CONTACT, HTTP_HEADERS())}, scheme="http", twin="html-http-form-to-https",
     note="the whole origin is plain HTTP: WEB000 explains it and WEB504 is suppressed (§3.5)")
case("html-password-autocomplete-off", "C-HTML", {"WEB508": True},
     {"/": doc(TEXT + '<form method="post" action="/login"><input name="user"><input type="password" name="pw" '
                      'autocomplete="off"><input type="hidden" name="csrf_token" value="{NONCE}"><button>Go</button></form>')},
     twin="html-password-manager-ok")
case("html-password-manager-ok", "C-HTML", {"WEB508": False}, {"/": doc(LOGIN)}, twin="html-password-autocomplete-off")
case("html-inline-handlers", "C-HTML", {"WEB515": True},
     {"/": doc(TEXT + '<button onclick="go()">Go</button><a href="javascript:void(0)">menu</a>')},
     sensitivity="paranoid", twin="html-no-inline-handlers")
case("html-no-inline-handlers", "C-HTML", {"WEB515": False}, {"/": doc()}, sensitivity="paranoid",
     twin="html-inline-handlers")
_PROFILE_FORM = ('<form method="post" action="/profile"><input name="display_name"><input name="email">'
                 '<button>Save</button></form>')
case("html-form-no-csrf", "C-HTML", {"WEB516": True},
     {"/": doc(TEXT + _PROFILE_FORM, H(add=[(SC, "sid={RAND}; Secure; HttpOnly; Path=/")]))}, sensitivity="paranoid",
     twin="html-form-csrf-token", note="no anti-CSRF token and a session cookie without SameSite (tentative, paranoid)")
case("html-form-csrf-token", "C-HTML", {"WEB516": False},
     {"/": doc(TEXT + _PROFILE_FORM.replace("<button>", '<input type="hidden" name="csrf_token" value="{NONCE}"><button>'),
               H(add=[(SC, "sid={RAND}; Secure; HttpOnly; Path=/")]))}, sensitivity="paranoid", twin="html-form-no-csrf")
case("html-password-offsite", "C-HTML", {"WEB518": True},
     {"/": doc(TEXT + LOGIN_FORM.replace('action="/login"', 'action="{THIRD}/collect"'),
               H(set={CSP: STRICT_CSP.replace("form-action 'self'", "form-action 'self' {THIRD}")}))},
     twin="html-password-onsite", note="a credential form posting to another registrable domain (skimmer shape)")
case("html-password-onsite", "C-HTML", {"WEB518": False},
     {"/": doc(TEXT + LOGIN_FORM.replace('action="/login"', 'action="{HTTPS:accounts}/login"'))}, aliases=("accounts",),
     zap=False, twin="html-password-offsite", note="posting to another host of the same site (accounts.<site>) is fine")
case("html-flash-object", "C-HTML", {"WEB802": True},
     {"/": doc(TEXT + '<object type="application/x-shockwave-flash" data="/media/intro.swf" width="400" height="300">'
                      '</object>')}, twin="html-pdf-object")
case("html-pdf-object", "C-HTML", {"WEB802": False},
     {"/": doc(TEXT + '<object type="application/pdf" data="/media/guide.pdf" width="400" height="300"></object>')},
     twin="html-flash-object")

# C-DISC
case("disc-html-comment-secret", "C-DISC", {"WEB614": True},
     {"/": doc(TEXT + "<!-- TODO: remove before release, admin password=Winter2026 -->")}, sensitivity="paranoid",
     twin="disc-html-comment-plain")
case("disc-html-comment-plain", "C-DISC", {"WEB614": False}, {"/": doc(TEXT + "<!-- layout: two columns, v2 -->")},
     sensitivity="paranoid", twin="disc-html-comment-secret")
case("disc-error-page-banner", "C-DISC", {"WEB616": True},
     {"/.well-known/security.txt": _APACHE_404, "/security.txt": _APACHE_404}, twin="disc-error-page-plain",
     note="the stock Apache 404 page names the exact version")
case("disc-error-page-plain", "C-DISC", {"WEB616": False},
     {"/.well-known/security.txt": NOT_FOUND, "/security.txt": NOT_FOUND}, twin="disc-error-page-banner")
case("disc-jpeg-gps", "C-DISC", {"WEB619": True},
     {"/": doc(TEXT + '<img src="/media/team.jpg" alt="team">'), "/media/team.jpg": R(200, _JPEG_HEADERS, _jpeg(True))},
     crawl=True, twin="disc-jpeg-no-gps", note="EXIF GPSLatitude/GPSLongitude in a published photo (--crawl fetches it)")
case("disc-jpeg-no-gps", "C-DISC", {"WEB619": False},
     {"/": doc(TEXT + '<img src="/media/team.jpg" alt="team">'), "/media/team.jpg": R(200, _JPEG_HEADERS, _jpeg(False))},
     crawl=True, twin="disc-jpeg-gps")

# C-TLS: configuration and certificate-name notes, then raw-probe stub flights (deterministic, independent of the local
# OpenSSL build)
case("tls-intermediate-deviation", "C-TLS", {"WEB718": True, "WEB717": False}, {"/": doc()}, tls="good", zap=False,
     twin="tls-modern-only", note="OpenSSL's default server suites include CBC suites the Mozilla intermediate profile drops")
case("tls-wildcard-names", "C-TLS", {"WEB717": True}, {"/": doc()}, zap=False, twin="tls-modern-only",
     note="the corpus' shared certificate lists *.<registrable domain> wildcards (one per group)")
case("tls-modern-deep", "C-TLS", {"WEB710": False, "WEB716": False}, {"/": doc()}, tls="modern", profile="deep",
     zap=False, twin="tls-stub-dhe1024", note="no DHE suite accepted and no version above the one offered (deep probes)")
case("tls-stub-dhe1024", "C-TLS", {"WEB710": True}, {"/": doc()}, tls="stub-dhe1024", profile="deep", requires=("stub",),
     zap=False, twin="tls-modern-deep", expect={"severity": {"WEB710": "medium"}},
     note="DHE answered with the 1024-bit Oakley group 2 prime (Logjam's shared prime): medium")
case("tls-stub-higher", "C-TLS", {"WEB716": True}, {"/": doc()}, tls="stub-higher", requires=("stub",), zap=False,
     twin="tls-modern-deep", note="a TLS 1.0/1.1-only hello is answered with TLS 1.2")
case("tls-stub-no-pq", "C-TLS", {"WEB719": True}, {"/": doc()}, tls="stub-nopq", profile="deep", sensitivity="paranoid",
     requires=("stub",), zap=False, twin="tls-stub-pq", note="single-group probes: X25519MLKEM768 refused")
case("tls-stub-pq", "C-TLS", {"WEB719": False}, {"/": doc()}, tls="stub-pq", profile="deep", sensitivity="paranoid",
     requires=("stub",), zap=False, twin="tls-stub-no-pq", note="single-group probes: X25519MLKEM768 accepted")
case("tls-ct-missing", "C-TLS", {"WEB713": True}, {"/": doc()}, tls="good", zap=False, ct_required=True,
     twin="tls-ct-not-required", note="the test CA is declared publicly trusted and CT-bound: a leaf with 0 SCTs")
case("tls-ct-not-required", "C-TLS", {"WEB713": False}, {"/": doc()}, tls="good", zap=False, twin="tls-ct-missing",
     note="the same leaf from a CA that is not subject to CT policy (as private CAs are)")


if __name__ == "__main__":
    raise SystemExit(main())
