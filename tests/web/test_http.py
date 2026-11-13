"""HTTP fetcher (webscan/http.py, WP1): traffic contract, politeness, hostile-target safety, SSRF guard, resolver,
proxies and the test-only hooks. Everything runs against servers on 127.0.0.1 (the conftest offline guard blocks any
other connection or name resolution, so a test also proves that the fetcher did not try one)."""

from __future__ import annotations

import gzip
import json
import socket
import struct
import sys
import threading
import time
import zlib

import pytest

from vulnscan.webscan import http as wh
from vulnscan.webscan import robots
from vulnscan.webscan.types import ACCEPT_DOCUMENT, ACCEPT_PROBE, CORS_PROBE_ORIGIN, ScanOptions, user_agent

PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
              "NO_PROXY", "KASHIF_TEST_RESOLVE", "KASHIF_TEST_RESOLVE_MAP", "KASHIF_TEST_CAFILE")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in PROXY_VARS:
        monkeypatch.delenv(k, raising=False)


class FakeTime:
    """Monotonic clock that only moves when the fetcher sleeps (politeness waits are recorded, not slept)."""

    def __init__(self):
        self.t = 1000.0
        self.sleeps: list[float] = []

    def now(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.sleeps.append(round(s, 3))
        self.t += s


def make(target="", *, ft=None, hooks=None, proxies=None, **opts) -> wh.Fetcher:
    ft = ft or FakeTime()
    return wh.Fetcher(ScanOptions(**opts), target, hooks=hooks, proxies={} if proxies is None else proxies,
                      clock=ft.now, sleep=ft.sleep)


def hooks_for(hosts: dict, default=None, cafile=None) -> wh.CorpusHooks:
    return wh.CorpusHooks(resolve_map={"version": 1, "hosts": hosts, "default": default or {"status": "nxdomain"}},
                          cafile=cafile)


def request_headers(raw: bytes) -> tuple[str, list[tuple[str, str]]]:
    head = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
    return head[0], [tuple(x.strip() for x in line.split(":", 1)) for line in head[1:]]


# ----------------------------------------------------------------------------------------------- small servers

class KeepAliveServer:
    """HTTP/1.1 with persistent connections. ``routes[path] = (status_line, headers, body)``; counts connections and
    records (time, request bytes). ``close_idle`` closes each connection after one response without saying so."""

    def __init__(self, routes=None, close_idle=False):
        self.routes = routes or {}
        self.close_idle = close_idle
        self.connections = 0
        self.requests: list[tuple[float, bytes]] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def url(self, path="/", host="127.0.0.1"):
        return f"http://{host}:{self.port}{path}"

    def _serve(self):
        while not self._stop.is_set():
            try:
                c, _ = self.sock.accept()
            except OSError:
                continue
            self.connections += 1
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _handle(self, c):
        c.settimeout(5)
        buf = b""
        try:
            while True:
                while b"\r\n\r\n" not in buf:
                    chunk = c.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                req, _, buf = buf.partition(b"\r\n\r\n")
                self.requests.append((time.monotonic(), req + b"\r\n\r\n"))
                path = req.split(b" ")[1].decode("latin-1")
                status, headers, body = self.routes.get(path, ("404 Not Found", [], b"nope"))
                if callable(body):
                    body = body(req)
                head = f"HTTP/1.1 {status}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers)
                head += f"Content-Length: {len(body)}\r\n\r\n"
                c.sendall(head.encode("latin-1") + body)
                if self.close_idle:
                    return
        except OSError:
            return
        finally:
            c.close()

    def close(self):
        self._stop.set()
        self.sock.close()


@pytest.fixture
def ka_server():
    servers = []

    def build(routes=None, close_idle=False):
        s = KeepAliveServer(routes, close_idle)
        servers.append(s)
        return s
    yield build
    for s in servers:
        s.close()


def one_shot_server(handler) -> tuple[int, threading.Event, list]:
    """Accepts connections forever and runs ``handler(conn, index)`` for each; returns (port, stop, connections)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    s.settimeout(0.2)
    stop = threading.Event()
    conns: list = []

    def run():
        while not stop.is_set():
            try:
                c, _ = s.accept()
            except OSError:
                continue
            conns.append(c)
            threading.Thread(target=_safe, args=(handler, c, len(conns) - 1), daemon=True).start()
        s.close()
    threading.Thread(target=run, daemon=True).start()
    return s.getsockname()[1], stop, conns


def _safe(handler, c, i):
    try:
        handler(c, i)
    except OSError:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


def _read_request(c) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = c.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


# ----------------------------------------------------------------------------------------------- traffic contract

def test_exact_request_headers_and_honest_user_agent(raw_http_server, http_reply_builder):
    raw_http_server.routes["/"] = http_reply_builder("200 OK", [("Content-Type", "text/html")], "<p>hi</p>")
    f = make(raw_http_server.url("/"))
    r = f.fetch(raw_http_server.url("/"))
    p = f.fetch(raw_http_server.url("/robots.txt"), source="wellknown")
    assert r.status == 200 and r.body == b"<p>hi</p>" and p.status == 404
    line, hdrs = request_headers(raw_http_server.requests[0])
    assert line == "GET / HTTP/1.1"
    assert [k for k, _ in hdrs] == ["Host", "User-Agent", "Accept", "Accept-Encoding", "Accept-Language"]
    d = dict(hdrs)
    assert d["User-Agent"] == user_agent() and d["User-Agent"].startswith("Kashif/") and "Mozilla" not in d["User-Agent"]
    assert d["Accept"] == ACCEPT_DOCUMENT and d["Accept-Encoding"] == "gzip, deflate" and d["Accept-Language"] == "en"
    assert dict(request_headers(raw_http_server.requests[1])[1])["Accept"] == ACCEPT_PROBE
    assert r.request_headers.first("user-agent") == user_agent() and r.source == "entry" and r.method == "GET"
    assert r.ip == "127.0.0.1" and r.http_version == "HTTP/1.1" and f.requests == 2


def test_only_the_probe_origin_and_known_accepts_are_allowed():
    f = make()
    with pytest.raises(ValueError):
        f.fetch("http://127.0.0.1:9/", origin="null")
    with pytest.raises(ValueError):
        f.fetch("http://127.0.0.1:9/", origin="https://evil.example")
    with pytest.raises(ValueError):
        f.fetch("http://127.0.0.1:9/", accept="text/plain")
    assert f.requests == 0


def test_duplicate_headers_kept_in_order_and_case(raw_http_server, http_reply_builder):
    raw_http_server.routes["/"] = http_reply_builder("200 OK", [
        ("Strict-Transport-Security", "max-age=1"), ("set-cookie", "a=1"), ("X-A", "1"),
        ("Strict-Transport-Security", "max-age=2, max-age=3"), ("Set-Cookie", "b=2")], "ok")
    r = make().fetch(raw_http_server.url("/"))
    names = [k for k, _ in r.headers][:5]
    assert names == ["Strict-Transport-Security", "set-cookie", "X-A", "Strict-Transport-Security", "Set-Cookie"]
    assert r.headers.get_all("strict-transport-security") == ["max-age=1", "max-age=2, max-age=3"]
    assert r.headers.get_all("set-cookie") == ["a=1", "b=2"]


def test_obs_fold_is_unfolded_and_recorded_and_raw_bytes_survive(raw_http_server):
    raw_http_server.routes["/"] = (b"HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=63072000;\r\n includeSubDomains\r\n"
                                   b"X-Curly: max-age=\xe2\x80\x9c31536000\xe2\x80\x9d\r\nContent-Length: 2\r\n"
                                   b"Connection: close\r\n\r\nok")
    r = make().fetch(raw_http_server.url("/"))
    assert r.headers.first("strict-transport-security") == "max-age=63072000; includeSubDomains"
    assert {"obs-fold", "obs-fold:strict-transport-security"} <= r.flags
    assert r.headers.first("x-curly").encode("latin-1") == b"max-age=\xe2\x80\x9c31536000\xe2\x80\x9d"


# ----------------------------------------------------------------------------------------------- redirects

def _redirect(to: str, status="302 Found", extra=()) -> bytes:
    lines = [f"HTTP/1.1 {status}", f"Location: {to}", *(f"{k}: {v}" for k, v in extra), "Content-Length: 0",
             "Connection: close"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def test_redirect_chain_is_capped_at_ten_hops(raw_http_server):
    for i in range(15):
        raw_http_server.routes[f"/r{i}"] = _redirect(f"/r{i + 1}")
    r = make().fetch(raw_http_server.url("/r0"))
    assert r.status == 302 and "redirect-limit" in r.flags
    assert len(r.hops()) == 10 and len(raw_http_server.requests) == 10
    assert [h.url.rsplit("/", 1)[1] for h in r.chain][:3] == ["r0", "r1", "r2"] and all(not h.chain for h in r.chain)


def test_redirect_loop_is_detected(raw_http_server):
    raw_http_server.routes["/a"] = _redirect("/b", "301 Moved Permanently")
    raw_http_server.routes["/b"] = _redirect(raw_http_server.url("/a"))
    r = make().fetch(raw_http_server.url("/a"))
    assert "redirect-loop" in r.flags and len(raw_http_server.requests) == 2 and len(r.hops()) == 2


def test_cookie_login_flow_revisiting_a_url_is_not_a_loop(raw_http_server, http_reply_builder):
    def root(req):
        if b"Cookie: s=1" in req:
            return http_reply_builder("200 OK", [("Content-Type", "text/html")], "home")
        return _redirect("/login")
    raw_http_server.routes["/"] = root
    raw_http_server.routes["/login"] = _redirect("/", extra=[("Set-Cookie", "s=1; Path=/")])
    r = make().fetch(raw_http_server.url("/"))
    assert r.status == 200 and r.body == b"home" and len(r.chain) == 2


@pytest.mark.parametrize("loc", ["file:///etc/passwd", "javascript:alert(document.domain)", "data:text/html,x",
                                 "ftp://127.0.0.1/x"])
def test_non_http_redirects_are_not_followed(raw_http_server, loc):
    raw_http_server.routes["/"] = _redirect(loc)
    f = make()
    r = f.fetch(raw_http_server.url("/"))
    assert r.status == 302 and "redirect-blocked:scheme" in r.flags and len(raw_http_server.requests) == 1
    assert any(e["code"] == "scheme" for e in f.events)


def test_location_is_cleaned_like_a_browser_and_crafted_quotes_stay_data(raw_http_server, http_reply_builder):
    raw_http_server.routes["/"] = _redirect(" /n\text?a=b c#frag ")
    raw_http_server.routes["/next"] = _redirect("/'$(id)'")
    raw_http_server.routes["/'$(id)'"] = http_reply_builder("200 OK", [], "x")
    r = make().fetch(raw_http_server.url("/"))
    assert r.status == 200
    assert r.chain[1].url.endswith("/next?a=b%20c") and r.url.endswith("/'$(id)'")
    assert all(b"#" not in req.split(b"\r\n", 1)[0] for req in raw_http_server.requests)


def test_crawl_redirects_never_leave_the_site_but_the_entry_chain_may(raw_http_server, http_reply_builder):
    port = raw_http_server.port
    hooks = hooks_for({}, default={"status": "ok", "addresses": ["127.0.0.1"], "public": True})
    raw_http_server.routes["/out"] = _redirect(f"http://other-site.test:{port}/landing")
    raw_http_server.routes["/landing"] = http_reply_builder("200 OK", [], "elsewhere")
    base = f"http://www.kashif.test:{port}"
    f = make(base + "/", hooks=hooks, crawl=True)
    r = f.fetch(base + "/out", source="crawl")
    assert r.status == 302 and "redirect-blocked:offsite" in r.flags
    sub = f.fetch(f"http://cdn.kashif.test:{port}/landing", source="crawl")      # same registrable domain
    assert sub.status == 200
    entry = f.fetch(base + "/out")
    assert entry.status == 200 and entry.body == b"elsewhere" and len(entry.chain) == 1


def test_follow_false_and_https_counterpart_source(raw_http_server):
    raw_http_server.routes["/"] = _redirect("/x")
    r = make().fetch(raw_http_server.url("/"), follow=False, source="http_probe")
    assert r.status == 302 and not r.chain and r.source == "http_probe" and r.location.endswith("/x")


# ----------------------------------------------------------------------------------------------- decoding

def _raw_deflate(data: bytes) -> bytes:
    co = zlib.compressobj(wbits=-15)
    return co.compress(data) + co.flush()


@pytest.mark.parametrize("coding, encode", [("gzip", gzip.compress), ("x-gzip", gzip.compress),
                                            ("deflate", zlib.compress), ("deflate", _raw_deflate),
                                            ("gzip, identity", gzip.compress)])
def test_gzip_and_deflate_are_decoded(raw_http_server, http_reply_builder, coding, encode):
    page = b"<html>" + b"A" * 5000 + b"</html>"
    raw_http_server.routes["/"] = http_reply_builder("200 OK", [("Content-Encoding", coding)], encode(page))
    r = make().fetch(raw_http_server.url("/"))
    assert r.body == page and not r.truncated and r.encoding == coding.split(",")[0] and not r.flags


def test_stacked_known_codings_are_undone_in_reverse(raw_http_server, http_reply_builder):
    page = b"hello stacked"
    raw_http_server.routes["/"] = http_reply_builder("200 OK", [("Content-Encoding", "deflate"),
                                                                ("Content-Encoding", "gzip")],
                                                     gzip.compress(zlib.compress(page)))
    r = make().fetch(raw_http_server.url("/"))
    assert r.body == page and r.encoding == "deflate, gzip"


def test_gzip_bomb_is_stopped_at_the_cap(raw_http_server, http_reply_builder):
    co = zlib.compressobj(9, zlib.DEFLATED, 31)
    chunk = b"\0" * (1 << 20)
    bomb = co.compress(b"<html>") + b"".join(co.compress(chunk) for _ in range(200)) + co.flush()   # 200 MiB inflated
    raw_http_server.routes["/"] = http_reply_builder("200 OK", [("Content-Type", "text/html"),
                                                                ("Content-Encoding", "gzip")], bomb)
    f = make()
    t = time.monotonic()
    r = f.fetch(raw_http_server.url("/"))
    assert time.monotonic() - t < 5
    assert r.status == 200 and r.truncated and "truncated-body" in r.flags
    assert len(r.body) <= wh.CAPS["document"] and len(r.body) <= max(10 * len(bomb), wh.DECOMPRESS_FLOOR)


def test_decode_body_ratio_and_floor():
    page = b"x" * 3_000_000
    gz = gzip.compress(page)
    body, trunc, problem = wh.decode_body(gz, ["gzip"], 1_000_000)
    assert len(body) == 1_000_000 and trunc and problem is None
    assert wh.decode_body(b"\x00garbage", ["gzip"], 100)[2] == ("undecodable", "gzip")
    assert wh.decode_body(b"abc", ["br"], 100) == (b"", False, ("unsupported", "br"))
    assert wh.decode_body(b"abc", ["zstd", "gzip"], 100)[2][0] in ("unsupported", "undecodable")


@pytest.mark.parametrize("coding", ["br", "zstd", "compress", "gzip, br"])
def test_unknown_codings_leave_the_body_opaque(raw_http_server, http_reply_builder, coding):
    raw_http_server.routes["/"] = http_reply_builder("200 OK", [("Content-Type", "text/html"),
                                                                ("Content-Encoding", coding),
                                                                ("Server", "Apache/2.4.49")], b"\x1b\x2a\x00compressed")
    f = make()
    r = f.fetch(raw_http_server.url("/"))
    assert r.status == 200 and r.body == b"" and "opaque-coding" in r.flags
    assert any(fl.startswith("opaque-coding:") for fl in r.flags)
    assert r.headers.first("server") == "Apache/2.4.49"          # header rules still run
    assert wh.coverage_reason(r) == "unsupported_coding"
    assert any(e["code"] == "opaque_coding" for e in f.events)


def test_corrupt_gzip_is_opaque_not_garbage(raw_http_server, http_reply_builder):
    raw_http_server.routes["/"] = http_reply_builder("200 OK", [("Content-Encoding", "gzip")], b"not gzip at all")
    r = make().fetch(raw_http_server.url("/"))
    assert r.body == b"" and {"decode-error", "opaque-coding"} <= r.flags


# ----------------------------------------------------------------------------------------------- caps, deadline, headers

def test_caps_by_source_and_explicit_cap(raw_http_server, http_reply_builder):
    raw_http_server.routes["/big"] = http_reply_builder("200 OK", [("Content-Type", "image/jpeg")], b"\xff" * 200_000)
    f = make()
    r = f.fetch(raw_http_server.url("/big"), source="image")
    assert len(r.body) == wh.CAPS["image"] and r.truncated and "truncated-body" in r.flags
    r2 = f.fetch(raw_http_server.url("/big"), cap=1000)
    assert len(r2.body) == 1000 and r2.truncated
    r3 = f.fetch(raw_http_server.url("/big"))
    assert len(r3.body) == 200_000 and not r3.truncated
    assert any(e["code"] == "truncated" for e in f.events)


def test_monotonic_deadline_stops_a_dripping_body():
    def drip(c, _i):
        _read_request(c)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100000\r\n\r\n")
        for _ in range(100):
            c.sendall(b"x")
            time.sleep(0.05)
    port, stop, _conns = one_shot_server(drip)
    try:
        f = make(timeout=5, response_deadline=0.6)
        t = time.monotonic()
        r = f.fetch(f"http://127.0.0.1:{port}/")
        took = time.monotonic() - t
    finally:
        stop.set()
    assert took < 2.5, took
    assert r.status == 200 and r.truncated and "deadline" in r.flags and 0 < len(r.body) < 100
    assert any(e["code"] == "deadline" for e in f.events)


def test_monotonic_deadline_stops_dripping_headers():
    def drip(c, _i):
        _read_request(c)
        c.sendall(b"HTTP/1.1 200 OK\r\n")
        for i in range(200):
            c.sendall(b"X-%d: y\r\n" % (i % 50))
            time.sleep(0.05)
    port, stop, conns = one_shot_server(drip)
    try:
        t = time.monotonic()
        r = make(timeout=5, response_deadline=0.6).fetch(f"http://127.0.0.1:{port}/")
        took = time.monotonic() - t
    finally:
        stop.set()
    assert took < 2.5 and r.status is None and "error:deadline" in r.flags and "deadline" in r.error
    assert wh.coverage_reason(r) == "timeout" and len(conns) == 1          # never retried


def test_monotonic_deadline_cuts_a_stalled_tls_handshake():
    def stall(c, _i):
        c.recv(4096)                       # the ClientHello; never answer it
        time.sleep(3)
    port, stop, _conns = one_shot_server(stall)
    try:
        t = time.monotonic()
        r = make(timeout=5, response_deadline=0.5).fetch(f"https://127.0.0.1:{port}/")
        took = time.monotonic() - t
    finally:
        stop.set()
    assert took < 2.5 and r.status is None and wh.error_code(r) == "deadline"


def test_more_than_100_header_lines_is_an_error_not_a_silent_drop(raw_http_server, http_reply_builder):
    raw_http_server.routes["/robots.txt"] = http_reply_builder(
        "200 OK", [(f"X-Filler-{i:03d}", "x") for i in range(120)], "User-agent: *\n")
    r = make().fetch(raw_http_server.url("/robots.txt"), source="wellknown")
    assert r.status is None and wh.TOO_MANY_HEADERS in r.error and "error:too_many_headers" in r.flags
    assert wh.error_code(r) == "too_many_headers"


def test_oversized_header_block_is_an_error(raw_http_server, http_reply_builder):
    raw_http_server.routes["/"] = http_reply_builder("200 OK", [(f"X-Big-{i}", "v" * 1000) for i in range(90)], "ok")
    r = make().fetch(raw_http_server.url("/"))
    assert r.status is None and "error:header_too_large" in r.flags


# ----------------------------------------------------------------------------------------------- politeness

def test_min_gap_floor_applies_to_every_request_in_real_time(ka_server):
    srv = ka_server({"/": ("200 OK", [], b"ok"), "/robots.txt": ("200 OK", [], b""), "/x.js": ("200 OK", [], b"")})
    f = wh.Fetcher(ScanOptions(delay=0.0), srv.url(), proxies={})
    assert f.limiter.delay == wh.MIN_DELAY
    f.fetch(srv.url("/"))
    f.fetch(srv.url("/robots.txt"), source="wellknown")
    f.fetch(srv.url("/x.js"), source="subresource")
    times = [t for t, _ in srv.requests]
    gaps = [b - a for a, b in zip(times, times[1:])]
    assert len(gaps) == 2 and min(gaps) >= 0.9 * wh.MIN_DELAY, gaps
    assert srv.connections == 1                            # connection reuse per origin
    f.close()


def test_gap_and_crawl_delay_with_a_fake_clock(ka_server):
    srv = ka_server({"/": ("200 OK", [], b"ok")})
    ft = FakeTime()
    f = make(srv.url(), ft=ft, delay=0.5, crawl=True)
    f.fetch(srv.url("/"))
    f.fetch(srv.url("/"))
    assert ft.sleeps == [0.5]
    f.set_robots(srv.url("/robots.txt"), robots.parse("User-agent: *\nCrawl-delay: 3\n"))
    f.fetch(srv.url("/"))
    assert ft.sleeps[-1] == 3.0
    f.set_robots(srv.url("/"), robots.parse("User-agent: Kashif\nCrawl-delay: 50\n"))
    f.fetch(srv.url("/"))
    assert ft.sleeps[-1] == wh.MAX_CRAWL_DELAY
    f.limiter.set_gap("other", 0.01)
    assert f.limiter.gap("other") == 0.5                  # never below delay


def test_crawl_obeys_robots_but_other_sources_do_not(ka_server):
    srv = ka_server({"/private/a": ("200 OK", [], b"secret"), "/go": ("302 Found", [("Location", "/private/b")], b"")})
    f = make(srv.url(), crawl=True, max_pages=5)
    f.set_robots(srv.url("/"), robots.parse("User-agent: *\nDisallow: /private\n"))
    r = f.fetch(srv.url("/private/a"), source="crawl")
    assert r.status is None and "error:robots" in r.flags and wh.coverage_reason(r) == "robots"
    r2 = f.fetch(srv.url("/go"), source="crawl")
    assert r2.status == 302 and "redirect-blocked:robots" in r2.flags
    assert f.fetch(srv.url("/private/a"), source="probe").status == 200     # deep list / well-known are exempt
    f2 = make(srv.url(), crawl=True, respect_robots=False)
    f2.set_robots(srv.url("/"), robots.parse("User-agent: *\nDisallow: /\n"))
    assert f2.fetch(srv.url("/private/a"), source="crawl").status == 200


def test_429_waits_retry_after_once_then_a_second_one_stops_the_host(raw_http_server, http_reply_builder):
    hits = {"n": 0}

    def root(_req):
        hits["n"] += 1
        if hits["n"] == 1:
            return http_reply_builder("429 Too Many Requests", [("Retry-After", "2")], "slow down")
        return http_reply_builder("200 OK", [("Content-Type", "text/html")], "<p>ok</p>")
    raw_http_server.routes["/"] = root
    raw_http_server.routes["/robots.txt"] = http_reply_builder("429 Too Many Requests", [("Retry-After", "1")], "")
    ft = FakeTime()
    f = make(raw_http_server.url("/"), ft=ft)
    r = f.fetch(raw_http_server.url("/"))
    assert r.status == 200 and {"rate-limited", "retry-after-waited"} <= r.flags and 2.0 in ft.sleeps
    r2 = f.fetch(raw_http_server.url("/robots.txt"), source="wellknown")
    assert r2.status == 429 and "host-stopped" in r2.flags and wh.coverage_reason(r2) == "rate_limited"
    n = len(raw_http_server.requests)
    r3 = f.fetch(raw_http_server.url("/x"), source="wellknown")
    assert r3.status is None and "error:host_stopped" in r3.flags and len(raw_http_server.requests) == n == 3
    assert wh.coverage_reason(r3) == "rate_limited"
    codes = [e["code"] for e in f.events]
    assert codes.count("retry_after") == 1 and codes.count("host_stopped") == 1


def test_503_with_retry_after_twice_stops_and_503_without_is_plain(raw_http_server, http_reply_builder):
    raw_http_server.routes["/"] = http_reply_builder("503 Service Unavailable", [("Retry-After", "3600")], "busy")
    raw_http_server.routes["/plain"] = http_reply_builder("503 Service Unavailable", [], "busy")
    ft = FakeTime()
    f = make(ft=ft)
    plain = f.fetch(raw_http_server.url("/plain"))
    assert plain.status == 503 and not plain.flags
    r = f.fetch(raw_http_server.url("/"))
    assert r.status == 503 and "host-stopped" in r.flags and wh.MAX_RETRY_AFTER in ft.sleeps
    assert len(raw_http_server.requests) == 3


@pytest.mark.parametrize("value, expected", [("120", 120.0), ("0", 0.0), (" 7 ", 7.0), ("soon", None), ("", None),
                                             ("-1", None), ("Wed, 21 Oct 2015 07:28:00 GMT", 0.0)])
def test_parse_retry_after(value, expected):
    assert wh.parse_retry_after(value) == expected


def test_parse_retry_after_http_date_in_the_future():
    from datetime import datetime, timezone
    now = datetime(2026, 11, 13, 12, 0, 0, tzinfo=timezone.utc)
    assert wh.parse_retry_after("Fri, 13 Nov 2026 12:00:30 GMT", now) == 30.0


def test_transient_timeout_is_retried_once_with_a_doubled_timeout():
    def slow_first(c, i):
        _read_request(c)
        if i == 0:
            time.sleep(1.2)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
    port, stop, conns = one_shot_server(slow_first)
    try:
        r = make(timeout=0.4).fetch(f"http://127.0.0.1:{port}/")
    finally:
        stop.set()
    assert r.status == 200 and "retried" in r.flags and len(conns) == 2


def test_connection_reset_storm_stops_the_host():
    def reset(c, _i):
        _read_request(c)
        linger = struct.pack("HH", 1, 0) if sys.platform == "win32" else struct.pack("ii", 1, 0)
        c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)                 # close with RST
    port, stop, conns = one_shot_server(reset)
    try:
        f = make()
        r1 = f.fetch(f"http://127.0.0.1:{port}/")
        r2 = f.fetch(f"http://127.0.0.1:{port}/a")
        n = len(conns)
        r3 = f.fetch(f"http://127.0.0.1:{port}/b")
    finally:
        stop.set()
    assert r1.status is None and wh.error_code(r1) == "reset" and "retried" in r1.flags
    assert wh.error_code(r2) == "reset" and n == 3
    assert wh.error_code(r3) == "host_stopped" and len(conns) == 3
    assert any(e["code"] == "reset_storm" for e in f.events)


def test_stale_keepalive_connection_is_retried_transparently(ka_server):
    srv = ka_server({"/": ("200 OK", [], b"ok")}, close_idle=True)
    f = make(srv.url())
    assert f.fetch(srv.url("/")).status == 200
    time.sleep(0.05)
    r = f.fetch(srv.url("/"))
    assert r.status == 200 and srv.connections == 2


def test_refused_and_dns_errors_keep_the_os_wording():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    r = make().fetch(f"http://127.0.0.1:{port}/")
    assert r.status is None and wh.error_code(r) == "refused" and r.error
    f = make("http://gone.kashif.test/", hooks=hooks_for({}))
    r2 = f.fetch("http://gone.kashif.test/")
    assert wh.error_code(r2) == "dns" and "name or service not known" in r2.error.lower()
    assert f.dns["gone.kashif.test"].status == "nxdomain" and f.requests == 0


# ----------------------------------------------------------------------------------------------- budgets and profiles

def test_minimal_profile_is_one_chain(raw_http_server, http_reply_builder):
    raw_http_server.routes["/"] = _redirect("/home")
    raw_http_server.routes["/home"] = http_reply_builder("200 OK", [], "ok")
    f = make(raw_http_server.url("/"), profile="minimal")
    r = f.fetch(raw_http_server.url("/"))
    assert r.status == 200 and len(r.chain) == 1
    for source in ("cors", "wellknown", "http_probe", "subresource", "probe", "crawl"):
        x = f.fetch(raw_http_server.url("/"), source=source)
        assert x.status is None and wh.error_code(x) == "profile" and wh.coverage_reason(x) == "profile"
    assert f.requests == 2 and len(raw_http_server.requests) == 2 and f.budget == 10


def test_profile_budgets_and_request_budget_refusal(raw_http_server, http_reply_builder):
    raw_http_server.routes["/"] = http_reply_builder("200 OK", [], "ok")
    assert make(profile="standard").budget == 45 and make(profile="deep").budget == 150
    f = make(raw_http_server.url("/"), max_requests=2, crawl=True, max_pages=1)
    assert f.fetch(raw_http_server.url("/")).status == 200
    assert f.fetch(raw_http_server.url("/"), source="cors", origin=CORS_PROBE_ORIGIN).status == 200
    r = f.fetch(raw_http_server.url("/"), source="wellknown")
    assert wh.error_code(r) == "budget" and wh.coverage_reason(r) == "budget"
    assert f.fetch(raw_http_server.url("/"), source="crawl").status == 200       # crawl pages have their own budget
    assert wh.error_code(f.fetch(raw_http_server.url("/"), source="crawl")) == "budget"
    assert len(raw_http_server.requests) == 3 and f.stats()["by_source"] == {"entry": 1, "cors": 1, "crawl": 1}
    assert [e["code"] for e in f.events].count("budget") == 1
    with pytest.raises(ValueError):
        make(profile="turbo")


def test_redirect_hops_count_and_budget_stops_a_chain(raw_http_server, http_reply_builder):
    for i in range(5):
        raw_http_server.routes[f"/r{i}"] = _redirect(f"/r{i + 1}")
    f = make(max_requests=3)
    r = f.fetch(raw_http_server.url("/r0"))
    assert r.status == 302 and "redirect-blocked:budget" in r.flags and f.requests == 3


def test_byte_and_time_budgets(raw_http_server, http_reply_builder):
    raw_http_server.routes["/"] = http_reply_builder("200 OK", [], b"x" * 5000)
    f = make(max_bytes=3000)
    r = f.fetch(raw_http_server.url("/"))
    assert r.truncated and len(r.body) < 3000
    assert wh.error_code(f.fetch(raw_http_server.url("/"))) == "byte_budget"
    ft = FakeTime()
    f2 = make(ft=ft, time_budget=10)
    assert f2.fetch(raw_http_server.url("/")).status == 200
    ft.t += 11
    r2 = f2.fetch(raw_http_server.url("/"))
    assert wh.error_code(r2) == "time_budget" and wh.coverage_reason(r2) == "time_budget"


# ----------------------------------------------------------------------------------------------- cookies

def test_cookie_jar_is_host_only_and_never_on_the_cors_get(ka_server):
    srv = ka_server({"/set": ("200 OK", [("Set-Cookie", "sid=abc123; Path=/; Domain=localhost; HttpOnly"),
                                         ("Set-Cookie", "pref=1; Path=/app")], b"ok"),
                     "/x": ("200 OK", [], b"x"), "/app/y": ("200 OK", [], b"y"),
                     "/cors": ("200 OK", [("Set-Cookie", "anon=zzz")], b"c")})
    f = make(srv.url())
    f.fetch(srv.url("/set"))
    f.fetch(srv.url("/x"))
    f.fetch(srv.url("/app/y"))
    f.fetch(srv.url("/cors"), source="cors", origin=CORS_PROBE_ORIGIN)
    f.fetch(srv.url("/x"))
    f.fetch(srv.url("/x", host="localhost"), source="subresource")
    reqs = [dict(request_headers(r)[1]) for _, r in srv.requests]
    assert "Cookie" not in reqs[0]
    assert reqs[1]["Cookie"] == "sid=abc123"
    assert reqs[2]["Cookie"] == "pref=1; sid=abc123"                 # longer path first
    assert reqs[3]["Origin"] == CORS_PROBE_ORIGIN and "Cookie" not in reqs[3]
    assert reqs[4]["Cookie"] == "sid=abc123"                         # the anonymous response's cookie was not kept
    assert "Cookie" not in reqs[5]                                   # another host (Domain ignored)
    assert f.jar.names("127.0.0.1") == ["pref", "sid"]


def test_cookie_values_are_redacted_in_recorded_request_headers(ka_server):
    srv = ka_server({"/": ("200 OK", [("Set-Cookie", "sid=supersecret")], b"ok")})
    f = make(srv.url())
    f.fetch(srv.url("/"))
    r = f.fetch(srv.url("/"))
    assert r.request_headers.first("cookie") == "sid=<redacted:11 bytes>"
    assert "supersecret" not in repr(r.request_headers)


def test_cookie_jar_rules():
    now = {"t": 1_800_000_000.0}
    jar = wh.CookieJar(lambda: now["t"])
    jar.store("https://a.test/dir/page", ["s=1; Secure", "p=2", "d=3; Path=/other", "__Host-h=4; Secure; Path=/",
                                           "__Host-bad=5; Secure; Path=/; Domain=a.test", "__Host-nopath=1; Secure",
                                           "__Host-nosec=1; Path=/", "__Secure-x=6",
                                           "e=7; Expires=Wed, 21-Oct-2015 07:28:00 GMT", "m=8; Max-Age=60",
                                           "noequals", "=empty", "ctl=a\x01b"])
    assert jar.header_for("https://a.test/dir/x") == "s=1; p=2; m=8; __Host-h=4"      # longer paths first
    assert jar.header_for("http://a.test/dir/x") == "p=2; m=8"       # Secure cookies only over https
    assert jar.header_for("https://a.test/other/z") == "d=3; __Host-h=4"
    assert jar.header_for("https://b.a.test/dir/x") is None           # host-only
    now["t"] += 61
    assert "m=8" not in jar.header_for("https://a.test/dir/x")
    jar.store("https://a.test/", ["p=gone; Path=/dir; Max-Age=0"])
    assert "p=2" not in (jar.header_for("https://a.test/dir/x") or "")
    jar.store("http://a.test/", ["s2=1; Secure"])                    # insecure origin cannot set Secure
    assert "s2" not in jar.names("a.test")


@pytest.mark.parametrize("value, ok", [("Wed, 21 Oct 2015 07:28:00 GMT", True), ("Wed, 21-Oct-2015 07:28:00 GMT", True),
                                       ("Sunday, 06-Nov-94 08:49:37 GMT", True), ("Thu, 01 Jan 1970 00:00:00 GMT", True),
                                       ("garbage", False), ("Wed, 32 Oct 2015 07:28:00 GMT", False)])
def test_cookie_date_parser(value, ok):
    assert (wh.parse_cookie_date(value) is not None) is ok


# ----------------------------------------------------------------------------------------------- SSRF guard and DNS

@pytest.mark.parametrize("addr, cat", [
    ("169.254.169.254", "metadata"), ("fd00:ec2::254", "metadata"), ("100.100.100.200", "metadata"),
    ("::ffff:169.254.169.254", "metadata"), ("127.0.0.1", "loopback"), ("127.0.0.2", "loopback"), ("::1", "loopback"),
    ("0.0.0.0", "loopback"), ("10.1.2.3", "private"), ("172.16.0.1", "private"), ("192.168.1.1", "private"),
    ("fd12::1", "private"), ("100.64.0.1", "private"), ("169.254.1.1", "link-local"), ("fe80::1", "link-local"),
    ("8.8.8.8", "public"), ("2606:4700::1", "public"), ("192.0.2.1", "reserved"), ("224.0.0.1", "reserved"),
    ("not-an-ip", "reserved"),
])
def test_address_categories(addr, cat):
    assert wh.address_category(addr) == cat


def test_guard_rules_per_target_category():
    f = make("http://10.0.0.5/")
    assert f.target_category() == "private"
    assert f.guard_url("http://10.0.0.6/") == "" and f.guard_url("http://192.168.0.1:8080/") == ""
    assert f.guard_url("http://127.0.0.1/") == "ssrf" and f.guard_url("http://169.254.1.1/") == "ssrf"
    for meta in ("http://169.254.169.254/latest/meta-data/", "http://[fd00:ec2::254]/", "http://100.100.100.200/",
                 "http://[::ffff:169.254.169.254]/"):
        assert f.guard_url(meta) == "metadata", meta
    assert make("http://169.254.169.254/").guard_url("http://169.254.169.254/") == "metadata"   # even as the target
    lo = make("http://127.0.0.1:8000/")
    assert lo.guard_url("http://127.0.0.2/") == "" and lo.guard_url("http://10.0.0.1/") == "ssrf"
    assert lo.guard_url("file:///etc/passwd") == "scheme" and lo.guard_url("http://[::1/") == "bad_url"


def test_redirects_from_a_public_target_to_internal_addresses_are_refused(raw_http_server):
    port = raw_http_server.port
    hooks = hooks_for({"site.kashif.test": {"status": "ok", "addresses": ["127.0.0.1"], "public": True}})
    raw_http_server.routes["/meta"] = _redirect("http://169.254.169.254/latest/meta-data/")
    raw_http_server.routes["/ip2"] = _redirect(f"http://127.0.0.2:{port}/landing")
    raw_http_server.routes["/rfc1918"] = _redirect("http://10.13.37.1/")
    base = f"http://site.kashif.test:{port}"
    f = make(base + "/", hooks=hooks)
    assert f.target_category() == "public"
    for path, flag in (("/meta", "redirect-blocked:metadata"), ("/ip2", "redirect-blocked:ssrf"),
                       ("/rfc1918", "redirect-blocked:ssrf")):
        r = f.fetch(base + path)
        assert r.status == 302 and flag in r.flags and not r.chain, path
    direct = f.fetch("http://169.254.169.254/")
    assert direct.status is None and wh.error_code(direct) == "ssrf"
    assert len(raw_http_server.requests) == 3
    assert {e["code"] for e in f.events} >= {"metadata", "ssrf"}


def test_a_name_resolving_to_a_metadata_address_is_refused_even_if_the_hook_says_public():
    hooks = hooks_for({"evil.kashif.test": {"status": "ok", "addresses": ["169.254.169.254"], "public": True}})
    f = make("http://site.kashif.test/", hooks=hooks)
    r = f.fetch("http://evil.kashif.test/")
    assert wh.error_code(r) == "ssrf" and "metadata" in r.error and f.requests == 0


def test_dns_is_pinned_per_host_for_the_whole_scan(raw_http_server, http_reply_builder):
    raw_http_server.routes["/"] = http_reply_builder("200 OK", [], "ok")
    hooks = hooks_for({"rebind.kashif.test": {"status": "ok", "public": True,
                                              "sequence": [["127.0.0.1"], ["10.13.37.1"]]}})
    url = f"http://rebind.kashif.test:{raw_http_server.port}/"
    f = make(url, hooks=hooks)
    assert f.fetch(url).status == 200
    assert f.fetch(url + "robots.txt", source="wellknown").status == 404
    assert f.fetch(url).status == 200
    assert len(raw_http_server.requests) == 3 and f.dns["rebind.kashif.test"].addresses == ("127.0.0.1",)
    assert f.resolver._sequence["rebind.kashif.test"] == 1          # resolved exactly once


def test_hook_resolver_statuses_and_gethostbyname_ex_emulation():
    hooks = hooks_for({"a.kashif.test": {"status": "ok", "addresses": ["127.0.0.1"], "public": True,
                                         "canonical": "gone.github.io", "aliases": ["a.kashif.test"]},
                       "nx.kashif.test": {"status": "nxdomain"}, "nd.kashif.test": {"status": "nodata"},
                       "tf.kashif.test": {"status": "tempfail"}},
                      default={"status": "ok", "addresses": ["127.0.0.1"], "public": True})
    res = wh.Resolver(hooks)
    a = res.resolve("A.Kashif.Test.").record
    assert (a.status, a.addresses, a.canonical, a.aliases) == ("ok", ("127.0.0.1",), "gone.github.io", ("a.kashif.test",))
    assert a.registrable == "kashif.test"
    assert [res.resolve(h).record.status for h in ("nx.kashif.test", "nd.kashif.test", "tf.kashif.test")] == \
        ["nxdomain", "nodata", "tempfail"]
    assert res.resolve("other.kashif.test").record.addresses == ("127.0.0.1",)        # default entry
    assert res.resolve("192.0.2.7").record.addresses == ("192.0.2.7",)                # IP literals are not looked up
    assert wh.Resolver(hooks_for({})).resolve("x.kashif.test").record.status == "nxdomain"   # no default → nxdomain


def test_os_resolver_maps_eai_codes(monkeypatch):
    def fake(errno_):
        def getaddrinfo(host, *a, **k):
            if errno_ is None:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 0)),
                        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:21f::7", 0, 0, 0)),
                        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 0))]
            if errno_ == "timeout":
                raise socket.timeout("timed out")
            raise socket.gaierror(errno_, "x")
        return getaddrinfo
    monkeypatch.setattr(socket, "gethostbyname_ex", lambda h: ("edge.cdn.test.", ["www.site.test"], ["93.184.215.14"]))
    cases = [(socket.EAI_NONAME, "nxdomain"), (socket.EAI_AGAIN, "tempfail"), ("timeout", "tempfail"),
             (getattr(socket, "EAI_FAIL", -4), "tempfail")]
    if hasattr(socket, "EAI_NODATA"):
        cases.append((socket.EAI_NODATA, "nodata"))
    for code, status in cases:
        monkeypatch.setattr(socket, "getaddrinfo", fake(code))
        rec = wh.Resolver().resolve("www.site.test").record
        assert rec.status == status, code
        assert rec.addresses == ()
    monkeypatch.setattr(socket, "getaddrinfo", fake(None))
    rec = wh.Resolver().resolve("www.site.test").record
    assert rec.status == "ok" and rec.addresses == ("93.184.215.14", "2606:2800:21f::7")
    assert rec.canonical == "edge.cdn.test" and rec.aliases == ("www.site.test",)


def test_windows_wsa_codes_map_like_eai():
    assert wh.gai_status(socket.gaierror(11001, "host not found")) == "nxdomain"
    assert wh.gai_status(socket.gaierror(11004, "no data")) in ("nodata", "nxdomain")
    assert wh.gai_status(socket.gaierror(11002, "try again")) == "tempfail"
    assert wh.gai_status(TimeoutError()) == "tempfail"


def test_lookup_caps_confirmation_and_registrable_domain():
    hosts = {f"h{i}.kashif.test": {"status": "ok", "addresses": ["127.0.0.1"], "public": True} for i in range(35)}
    hosts.update({"cdn.gone-domain.test": {"status": "nxdomain"}, "gone-domain.test": {"status": "nxdomain"},
                  "x.live.test": {"status": "nxdomain"}, "live.test": {"status": "ok", "addresses": ["127.0.0.1"]}})
    ft = FakeTime()
    f = make("http://site.kashif.test/", ft=ft, hooks=hooks_for(hosts))
    recs = [f.lookup(f"h{i}.kashif.test") for i in range(35)]
    assert [r.status for r in recs].count("ok") == wh.DNS_REFERENCED_CAP
    assert recs[-1].status == "not_tested" and recs[-1].reason == "budget"
    a = f.lookup("cdn.gone-domain.test", purpose="target", confirm_missing=True)
    assert a.status == "nxdomain" and ft.sleeps == [wh.NXDOMAIN_RECHECK]
    f.lookup("cdn.gone-domain.test", purpose="target", confirm_missing=True)
    assert ft.sleeps == [wh.NXDOMAIN_RECHECK]                                   # confirmed once only
    assert f.lookup_registrable("cdn.gone-domain.test").registrable_status == "nxdomain"
    b = f.lookup_registrable("x.live.test", purpose="target")
    assert b.status == "nxdomain" and b.registrable == "live.test" and b.registrable_status == "ok"
    assert f.dns["x.live.test"].registrable_status == "ok"


# ----------------------------------------------------------------------------------------------- proxies

def test_http_through_a_proxy_sends_an_absolute_uri_and_resolves_nothing(raw_http_server, http_reply_builder):
    raw_http_server.routes["/x"] = http_reply_builder("200 OK", [], "via proxy")
    proxy = f"http://user:p%40ss@127.0.0.1:{raw_http_server.port}"
    f = make("http://site.kashif.test/x", proxies={"http": proxy, "https": proxy})
    assert f.proxied and any(e["code"] == "proxied" for e in f.events)
    assert "user" not in json.dumps(f.events) and "p@ss" not in json.dumps(f.events)
    r = f.fetch("http://site.kashif.test/x")             # the offline guard would block resolving this name
    assert r.status == 200 and r.body == b"via proxy" and "proxied" in r.flags and r.ip is None
    line, hdrs = request_headers(raw_http_server.requests[0])
    assert line == "GET http://site.kashif.test/x HTTP/1.1"
    d = dict(hdrs)
    assert d["Host"] == "site.kashif.test" and d["Proxy-Authorization"].startswith("Basic ")
    assert "Proxy-Authorization" not in dict(r.request_headers.items)
    dns = f.lookup("cdn.kashif.test")
    assert dns.status == "not_tested" and dns.reason == "proxied"
    assert f.guard_url("http://169.254.169.254/") == "metadata"         # IP literals are still guarded
    assert f.guard_url("http://intranet.kashif.test/") == ""            # names are resolved by the proxy


def test_no_proxy_bypass_and_use_proxy_false(raw_http_server, http_reply_builder, monkeypatch):
    raw_http_server.routes["/"] = http_reply_builder("200 OK", [], "direct")
    f = make(proxies={"http": "http://127.0.0.1:9", "no": "127.0.0.1,localhost"})
    r = f.fetch(raw_http_server.url("/"))
    assert r.status == 200 and "proxied" not in r.flags
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{raw_http_server.port}")
    env_f = wh.Fetcher(ScanOptions(), "http://site.kashif.test/")
    assert env_f.proxied and env_f.proxy_for("http://site.kashif.test/").port == raw_http_server.port
    off = wh.Fetcher(ScanOptions(use_proxy=False), "http://site.kashif.test/")
    assert not off.proxied and off.proxy_for("http://site.kashif.test/") is None
    monkeypatch.setenv("no_proxy", "site.kashif.test")
    assert not wh.Fetcher(ScanOptions(), "http://site.kashif.test/").proxied


def test_https_goes_through_a_connect_tunnel():
    seen = []

    def proxy(c, _i):
        req = _read_request(c)
        seen.append(req)
        c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
    port, stop, _ = one_shot_server(proxy)
    try:
        f = make("https://site.kashif.test/", proxies={"https": f"127.0.0.1:{port}"})
        r = f.fetch("https://site.kashif.test/")
    finally:
        stop.set()
    assert r.status is None and wh.error_code(r) == "proxy" and "proxied" in r.flags
    first = seen[0].split(b"\r\n")
    assert first[0] in (b"CONNECT site.kashif.test:443 HTTP/1.0", b"CONNECT site.kashif.test:443 HTTP/1.1")
    assert any(h.startswith(b"User-Agent: Kashif/") for h in first[1:])


@pytest.mark.parametrize("value, ok", [("http://p.example:3128", True), ("p.example:8080", True),
                                       ("socks5://p.example:1080", False), ("", False), ("http://:80", False)])
def test_parse_proxy(value, ok):
    assert (wh.parse_proxy(value) is not None) is ok


# ----------------------------------------------------------------------------------------------- test-only hooks

def test_hooks_are_ignored_unless_enabled(tmp_path):
    m = tmp_path / "map.json"
    m.write_text(json.dumps({"version": 1, "hosts": {"a.kashif.test": {"status": "ok"}},
                             "tls": {"cafile": "/x/root.pem", "publicly_trusted": True, "ct_required": False}}),
                 encoding="utf-8")
    env = {"KASHIF_TEST_RESOLVE_MAP": str(m), "KASHIF_TEST_CAFILE": "/x/ca.pem"}
    opts = ScanOptions()
    opts._resolve = {"hosts": {}}          # type: ignore[attr-defined]
    opts._cafile = "/evil.pem"             # type: ignore[attr-defined]
    assert wh.CorpusHooks.from_env(env) is None
    assert wh.CorpusHooks.from_env(env, opts) is None
    assert wh.CorpusHooks.from_env({**env, "KASHIF_TEST_RESOLVE": "true"}) is None
    h = wh.CorpusHooks.from_env({**env, "KASHIF_TEST_RESOLVE": "1"})
    assert h.resolve_map["hosts"] == {"a.kashif.test": {"status": "ok"}} and h.cafile == "/x/ca.pem"
    assert h.publicly_trusted and not h.ct_required
    h2 = wh.CorpusHooks.from_env({"KASHIF_TEST_RESOLVE": "1"}, opts)
    assert h2.resolve_map == {"hosts": {}} and h2.cafile == "/evil.pem"
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(ValueError):
        wh.CorpusHooks.from_env({"KASHIF_TEST_RESOLVE": "1", "KASHIF_TEST_RESOLVE_MAP": str(bad)})


def test_fetcher_reads_hooks_from_the_environment(monkeypatch, tmp_path):
    m = tmp_path / "map.json"
    m.write_text(json.dumps({"version": 1, "hosts": {}, "default": {"status": "nxdomain"}}), encoding="utf-8")
    monkeypatch.setenv("KASHIF_TEST_RESOLVE_MAP", str(m))
    assert wh.Fetcher(ScanOptions(), "http://x.kashif.test/", proxies={}).hooks is None
    monkeypatch.setenv("KASHIF_TEST_RESOLVE", "1")
    f = wh.Fetcher(ScanOptions(), "http://x.kashif.test/", proxies={})
    assert f.hooks is not None and f.lookup("x.kashif.test").status == "nxdomain"


def test_tls_contexts_are_browser_parity():
    import ssl
    ctx = make().tls_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert ctx.hostname_checks_common_name is False
    assert not ctx.verify_flags & getattr(ssl, "VERIFY_X509_STRICT", 0)
    un = make().tls_context(verified=False)
    assert un.verify_mode == ssl.CERT_NONE and not un.check_hostname


def test_open_tcp_is_guarded_and_paced(ka_server):
    srv = ka_server({})
    ft = FakeTime()
    f = make("http://127.0.0.1/", ft=ft)
    socks = [f.open_tcp("127.0.0.1", srv.port) for _ in range(3)]
    for s in socks:
        s.close()
    assert f.handshakes == 3 and ft.sleeps == [wh.TLS_GAP, wh.TLS_GAP] and f.requests == 0
    with pytest.raises(wh.FetchRefused) as e:
        f.open_tcp("169.254.169.254", 443)
    assert e.value.code == "metadata"
    with pytest.raises(wh.FetchRefused):
        f.open_tcp("127.0.0.1", srv.port, ip="10.0.0.1")
    assert f.addresses("127.0.0.1") == ("127.0.0.1",)


# ----------------------------------------------------------------------------------------------- helpers and i18n

def test_classify_error_and_coverage_reasons():
    import http.client
    import ssl
    assert wh.classify_error(http.client.HTTPException("got more than 100 headers"))[0] == "too_many_headers"
    assert wh.classify_error(socket.timeout())[0] == "timeout"
    assert wh.classify_error(ConnectionRefusedError(111, "Connection refused"))[1] == "[Errno 111] Connection refused"
    assert wh.classify_error(ssl.SSLError(1, "handshake failure"))[0] == "tls"
    assert wh.classify_error(OSError("Tunnel connection failed: 403 Forbidden"))[0] == "proxy"
    assert wh.classify_error(OSError(), deadline_fired=True)[0] == "deadline"
    assert wh.coverage_reason(None) == "not_run"
    for code in wh.ERROR_CODES:
        from vulnscan.webscan.coverage import REASONS
        assert wh.ERROR_CODES[code] in REASONS


def test_event_texts_have_english_via_the_catalogue():
    import re
    _catalog, patterns = wh.i18n_catalog()
    sample = {"host": "a.test", "status": "429", "seconds": "2", "url": "https://a.test/x", "category": "loopback",
              "message": "certificate has expired", "cap": "2000000", "coding": "br", "limit": "45",
              "proxy": "http://p.test:3128"}
    for code, (en, ar) in wh.EVENTS.items():
        ar_text, en_text = ar.format(**sample), en.format(**sample)
        assert re.search("[\u0600-\u06ff]", ar_text), code
        hit = [re.sub(r"\\g<(\w+)>", lambda g, m=m: m.group(g.group(1)), repl)
               for rx, repl in patterns for m in [re.fullmatch(rx, ar_text, re.S)] if m]
        assert en_text in hit, code


def test_next_url_and_prepare():
    assert wh.next_url("http://a.test/x/y", "../z#f") == "http://a.test/z"
    assert wh.next_url("http://a.test/", "  \t") is None
    assert wh.next_url("http://a.test/", "http://a.test:99999/") is None
    p = wh._prepare("HTTP://user:pw@A.Test:80/a b?q=ü#frag")
    assert p.url == "http://a.test/a%20b?q=%C3%BC" and p.host_header == "a.test" and p.target == "/a%20b?q=%C3%BC"
    assert wh._prepare("https://[::1]:8443/").host_header == "[::1]:8443"
    assert wh._prepare("mailto:x@y") == "scheme"


# ----------------------------------------------------------------------------------------------- corpus (WP16) cases

CORPUS_CASES = ("csp-strict-good", "hostile-redirect-metadata", "hostile-redirect-ip2", "hostile-dns-rebinding",
                "hostile-redirect-file", "hostile-redirect-javascript", "hostile-curl-injection", "hostile-120-headers",
                "hostile-brotli-body", "hostile-obs-fold-hsts", "waf-429-retry-after", "waf-503-twice",
                "hsts-cert-invalid", "rev-cn-only", "rev-proxied")


@pytest.fixture(scope="module")
def corpus_server():
    import importlib
    import pathlib
    import sys
    bench = pathlib.Path(__file__).resolve().parents[2] / "bench" / "web"
    if str(bench) not in sys.path:
        sys.path.insert(0, str(bench))
    corpus = importlib.import_module("corpus")
    cases = {c.id: c for c in corpus.CASES if c.id in CORPUS_CASES}
    srv = corpus.CorpusServer(list(cases.values()), mode="host").start()
    try:
        if "tls" in srv.unavailable:
            pytest.skip(f"corpus TLS unavailable: {srv.unavailable['tls']}")
        yield srv, cases, corpus
    finally:
        srv.stop()


def _corpus_fetcher(srv, c, *, ft=None, proxies=None, **opts) -> wh.Fetcher:
    cafile = str(srv.material.root)
    m = srv.resolver_map(c, cafile)
    hooks = wh.CorpusHooks(resolve_map=m, cafile=cafile, publicly_trusted=True, ct_required=False)
    kw = {"clock": ft.now, "sleep": ft.sleep} if ft else {}
    return wh.Fetcher(ScanOptions(delay=0.2, **opts), srv.url(c), hooks=hooks, proxies=proxies or {}, **kw)


def _mini_scan(f: wh.Fetcher, url: str) -> dict:
    """The fetches of a standard scan that WP1 owns the mechanics of: entry chain, cookieless CORS GET, robots.txt."""
    base = url.split("/", 3)
    origin = "/".join(base[:3])
    return {"entry": f.fetch(url), "cors": f.fetch(url, source="cors", origin=CORS_PROBE_ORIGIN),
            "robots": f.fetch(origin + "/robots.txt", source="wellknown")}


def _traffic_ok(srv, case_id: str, delay: float | None = None) -> list:
    recs = srv.requests_for(case_id)
    allowed = {"host", "user-agent", "accept", "accept-encoding", "accept-language", "origin", "cookie", "connection"}
    for r in recs:
        h = {k.lower(): v for k, v in r.headers}
        assert r.method == "GET" and set(h) <= allowed, (case_id, h)
        assert h["user-agent"] == user_agent()
        if "origin" in h:
            assert h["origin"] == CORS_PROBE_ORIGIN and "cookie" not in h
        assert "/kashif-404-" not in r.path
    if delay is not None:
        times = sorted(r.t for r in recs)
        assert all(b - a >= 0.9 * delay for a, b in zip(times, times[1:])), times
    return recs


def test_corpus_traffic_contract_on_a_normal_case(corpus_server):
    srv, cases, _corpus = corpus_server
    c = cases["csp-strict-good"]
    f = _corpus_fetcher(srv, c)
    out = _mini_scan(f, srv.url(c))
    assert out["entry"].status == 200 and not out["entry"].flags and out["entry"].body
    assert out["cors"].status == 200 and out["robots"].status == 200
    assert len(_traffic_ok(srv, c.id, delay=0.2)) == 3 and not srv.violations
    f.close()


@pytest.mark.parametrize("case_id, flag", [
    ("hostile-redirect-metadata", "redirect-blocked:metadata"), ("hostile-redirect-ip2", "redirect-blocked:ssrf"),
    ("hostile-redirect-file", "redirect-blocked:scheme"), ("hostile-redirect-javascript", "redirect-blocked:scheme"),
])
def test_corpus_hostile_redirects_are_not_followed(corpus_server, case_id, flag):
    srv, cases, _corpus = corpus_server
    c = cases[case_id]
    f = _corpus_fetcher(srv, c, ft=FakeTime())
    r = f.fetch(srv.url(c))
    assert r.status == 302 and flag in r.flags and not r.chain
    recs = _traffic_ok(srv, c.id)
    assert len(recs) == 1 and not any(x.listener.endswith("ip2") for x in recs)


def test_corpus_hostile_fetcher_cases(corpus_server):
    srv, cases, _corpus = corpus_server
    ft = FakeTime()
    c = cases["hostile-120-headers"]
    out = _mini_scan(_corpus_fetcher(srv, c, ft=ft), srv.url(c))
    assert out["entry"].status == 200 and wh.TOO_MANY_HEADERS in out["robots"].error
    c = cases["hostile-brotli-body"]
    r = _corpus_fetcher(srv, c, ft=ft).fetch(srv.url(c))
    assert r.status == 200 and r.body == b"" and "opaque-coding:br" in r.flags
    assert r.headers.first("server").startswith("Apache/2.4.49")
    c = cases["hostile-obs-fold-hsts"]
    r = _corpus_fetcher(srv, c, ft=ft).fetch(srv.url(c))
    assert r.headers.first("strict-transport-security") == "max-age=63072000; includeSubDomains"
    assert "obs-fold:strict-transport-security" in r.flags
    c = cases["hostile-curl-injection"]
    r = _corpus_fetcher(srv, c, ft=ft).fetch(srv.url(c))
    assert r.status == 200 and r.url.endswith("/'$(id)'") and len(r.chain) == 1
    c = cases["hostile-dns-rebinding"]
    f = _corpus_fetcher(srv, c, ft=ft)
    out = _mini_scan(f, srv.url(c))
    assert all(x.status == 200 for x in out.values()) and f.dns[c.host].addresses == ("127.0.0.1",)
    for cid in ("hostile-120-headers", "hostile-brotli-body", "hostile-obs-fold-hsts", "hostile-curl-injection",
                "hostile-dns-rebinding"):
        _traffic_ok(srv, cid)
    assert not srv.violations


def test_corpus_rate_limit_cases(corpus_server):
    srv, cases, _corpus = corpus_server
    ft = FakeTime()
    c = cases["waf-429-retry-after"]
    out = _mini_scan(_corpus_fetcher(srv, c, ft=ft), srv.url(c))
    assert out["entry"].status == 200 and 2.0 in ft.sleeps
    assert "host-stopped" in out["cors"].flags or "host-stopped" in out["robots"].flags
    assert len(_traffic_ok(srv, c.id)) <= c.expect["max_requests"]
    c = cases["waf-503-twice"]
    out = _mini_scan(_corpus_fetcher(srv, c, ft=FakeTime()), srv.url(c))
    assert out["entry"].status == 503 and "host-stopped" in out["entry"].flags
    assert wh.error_code(out["cors"]) == "host_stopped" and wh.error_code(out["robots"]) == "host_stopped"
    assert len(_traffic_ok(srv, c.id)) <= c.expect["max_requests"]


def test_corpus_certificate_errors_are_read_unverified_and_flagged(corpus_server):
    srv, cases, _corpus = corpus_server
    for cid, code in (("hsts-cert-invalid", None), ("rev-cn-only", 62)):
        c = cases[cid]
        f = _corpus_fetcher(srv, c, ft=FakeTime())
        r = f.fetch(srv.url(c))
        assert r.status == 200 and "cert-error" in r.flags, cid
        assert f.cert_errors[c.host][0] is not None and (code is None or f.cert_errors[c.host][0] == code)
        assert any(e["code"] == "cert_error" for e in f.events)
    good = cases["csp-strict-good"]
    assert "cert-error" not in _corpus_fetcher(srv, good, ft=FakeTime()).fetch(srv.url(good)).flags


def test_corpus_scan_through_the_proxy(corpus_server):
    srv, cases, _corpus = corpus_server
    c = cases["rev-proxied"]
    proxy = f"http://127.0.0.1:{srv.proxy.server_address[1]}"
    f = _corpus_fetcher(srv, c, ft=FakeTime(), proxies={"http": proxy, "https": proxy})
    assert f.proxied
    r = f.fetch(srv.url(c))
    assert r.status == 200 and "proxied" in r.flags and "cert-error" not in r.flags
    assert any(s.startswith("CONNECT ") for s in srv.proxy.seen)
    assert f.lookup("cdn.kashif-gone.test").status == "not_tested" and f.dns == {}
    _traffic_ok(srv, c.id)


# ----------------------------------------------------------------------------------------------- adversarial review

def _interim_server(n_requests: int, interim: bytes):
    """Keep-alive server answering each request with ``interim`` (1xx responses) and then a 200 naming the path."""
    def handle(c, _i):
        buf = b""
        for _ in range(n_requests):
            while b"\r\n\r\n" not in buf:
                d = c.recv(4096)
                if not d:
                    return
                buf += d
            req, _, buf = buf.partition(b"\r\n\r\n")
            path = req.split(b" ")[1]
            c.sendall(interim + b"HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'self'\r\n"
                      b"Content-Length: %d\r\n\r\n%s" % (len(path), path))
    return one_shot_server(handle)


def test_early_hints_are_skipped_and_the_keepalive_connection_stays_in_sync():
    # http.client returns a 103 as the final response and leaves the real 200 in the socket for the next request
    port, stop, conns = _interim_server(2, b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n"
                                           b"HTTP/1.1 102 Processing\r\n\r\n")
    try:
        f = make()
        one = f.fetch(f"http://127.0.0.1:{port}/one")
        two = f.fetch(f"http://127.0.0.1:{port}/two")
    finally:
        stop.set()
    assert (one.status, one.body, two.status, two.body) == (200, b"/one", 200, b"/two")
    assert one.headers.first("content-security-policy") == "default-src 'self'" and not one.headers.has("link")
    assert {"informational:103", "informational:102"} <= one.flags and len(conns) == 1


def test_an_endless_stream_of_interim_responses_is_an_error():
    port, stop, _ = _interim_server(1, b"HTTP/1.1 103 Early Hints\r\n\r\n" * 50)
    try:
        r = make().fetch(f"http://127.0.0.1:{port}/")
    finally:
        stop.set()
    assert r.status is None and wh.error_code(r) == "bad_response" and "informational" in r.error


@pytest.mark.parametrize("bad_line", [b"BadLine", b"X-Broken : 1", b": no name", b"X\xe9: latin", b"Na me: v"])
def test_a_malformed_header_line_does_not_drop_the_headers_after_it(raw_http_server, bad_line):
    # email.parser (behind http.client) stops at such a line and silently drops CSP/HSTS below it → false "missing"
    raw_http_server.routes["/"] = (b"HTTP/1.1 200 OK\r\nX-A: 1\r\n" + bad_line + b"\r\n"
                                   b"Content-Security-Policy: default-src 'self'\r\n"
                                   b"Strict-Transport-Security: max-age=63072000\r\nContent-Length: 2\r\n\r\nok")
    f = make()
    r = f.fetch(raw_http_server.url("/"))
    assert r.status == 200 and r.body == b"ok" and "malformed-header-line" in r.flags
    assert r.headers.first("content-security-policy") == "default-src 'self'"
    assert r.headers.first("strict-transport-security") == "max-age=63072000"
    if bad_line == b"X-Broken : 1":
        assert r.headers.first("x-broken") == "1"                      # trimmed name, kept like a browser
    assert f._pool                                                     # Content-Length framing still honoured


def test_a_leading_continuation_line_is_dropped_but_later_folds_are_kept(raw_http_server):
    raw_http_server.routes["/"] = (b"HTTP/1.1 200 OK\r\n  orphan\r\nX-A: 1\r\nX-B: a,\r\n\tb\r\n"
                                   b"Content-Length: 2\r\nConnection: close\r\n\r\nok")
    r = make().fetch(raw_http_server.url("/"))
    assert r.headers.items[:2] == (("X-A", "1"), ("X-B", "a, b"))
    assert {"malformed-header-line", "obs-fold", "obs-fold:x-b"} <= r.flags


@pytest.mark.parametrize("lines, ok", [(99, True), (100, True), (101, False)])
def test_header_line_limit_is_exactly_100(raw_http_server, lines, ok):
    # http.client counts the blank terminator too and so rejected exactly 100 header lines
    extra = "".join(f"X-H{i}: v\r\n" for i in range(lines - 2))
    raw_http_server.routes["/"] = (f"HTTP/1.1 200 OK\r\n{extra}Content-Length: 2\r\nConnection: close\r\n\r\nok"
                                   ).encode("latin-1")
    r = make().fetch(raw_http_server.url("/"))
    if ok:
        assert r.status == 200 and len(r.headers.items) == lines
    else:
        assert r.status is None and wh.error_code(r) == "too_many_headers" and wh.TOO_MANY_HEADERS in r.error


def test_header_block_over_64kb_of_short_lines_is_an_error(raw_http_server):
    extra = "".join(f"X-H{i}: {'v' * 900}\r\n" for i in range(80))      # 80 lines, ≈ 72 KB, every line short
    raw_http_server.routes["/"] = (f"HTTP/1.1 200 OK\r\n{extra}Content-Length: 2\r\n\r\nok").encode("latin-1")
    r = make().fetch(raw_http_server.url("/"))
    assert r.status is None and wh.error_code(r) == "header_too_large"


def test_body_shorter_than_content_length_is_incomplete_and_not_pooled(raw_http_server):
    raw_http_server.routes["/"] = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort"
    f = make()
    r = f.fetch(raw_http_server.url("/"))
    assert r.status == 200 and r.body == b"short" and r.truncated
    assert {"incomplete-body", "truncated-body"} <= r.flags and not f._pool


def test_utf8_location_bytes_are_followed_like_a_browser(raw_http_server, http_reply_builder):
    # Arabic paths: servers send raw UTF-8 bytes; http.client decodes them as Latin-1 (double encoding before the fix)
    raw_http_server.routes["/"] = (b"HTTP/1.1 302 Found\r\nLocation: /\xd8\xb9\xd8\xb1\xd8\xa8\xd9\x8a\r\n"
                                   b"Content-Length: 0\r\nConnection: close\r\n\r\n")
    raw_http_server.routes["/%D8%B9%D8%B1%D8%A8%D9%8A"] = http_reply_builder("200 OK", [], "arabic")
    r = make().fetch(raw_http_server.url("/"))
    assert r.status == 200 and r.body == b"arabic" and r.url.endswith("/%D8%B9%D8%B1%D8%A8%D9%8A")


@pytest.mark.parametrize("loc, expected", [
    ("/\\evil.test/x", "http://evil.test/x"),             # "\" is "/" in http(s) URLs (WHATWG)
    ("\\\\evil.test", "http://evil.test"),
    ("/a?q=\\x", "http://a.test/a?q=\\x"),                 # … but not in the query
    ("https:evil.test/p", "https://evil.test/p"),         # another special scheme without slashes
    ("http:/same", "http://a.test/same"),                 # same scheme without "//": relative
    ("/caf\xe9", "http://a.test/caf\xe9"),                # Latin-1 that is not UTF-8 stays as received
])
def test_next_url_follows_whatwg_rules(loc, expected):
    assert wh.next_url("http://a.test/p", loc) == expected


@pytest.mark.parametrize("host, literal", [
    ("2130706433", "127.0.0.1"), ("0x7f.1", "127.0.0.1"), ("127.1", "127.0.0.1"), ("0177.0.0.1", "127.0.0.1"),
    ("0xa9fea9fe", "169.254.169.254"), ("0251.0376.0251.0376", "169.254.169.254"), ("169.254.43518", "169.254.169.254"),
    ("example.com", None), ("08.1.1.1", None), ("1.2.3.4.5", None), ("4294967296", None), ("1" * 5000, None),
])
def test_numeric_ipv4_forms_are_ip_literals(host, literal):
    assert wh.ip_literal(host) == literal
    p = wh._prepare(f"http://{host}/x")
    if literal:
        assert p.host == literal and p.host_header == literal    # Host header and connection as a browser sends them
    elif host != "example.com":
        assert p == "bad_url"                                   # ends in a number but is not an address: invalid URL


def test_numeric_and_named_internal_hosts_are_guarded_through_a_proxy(raw_http_server, http_reply_builder):
    raw_http_server.routes["/"] = http_reply_builder("200 OK", [], "proxy")
    proxy = f"http://127.0.0.1:{raw_http_server.port}"
    f = make("http://site.kashif.test/", proxies={"http": proxy, "https": proxy})
    for url in ("http://0xa9fea9fe/latest/meta-data/", "http://2852039166/", "http://metadata.google.internal/",
                "http://[::ffff:a9fe:a9fe]/"):
        assert f.guard_url(url) == "metadata", url
        r = f.fetch(url)
        assert r.status is None and wh.error_code(r) == "ssrf", url
    for url in ("http://127.1/", "http://localhost/", "http://admin.localhost/"):
        assert f.guard_url(url) == "ssrf", url
    assert raw_http_server.requests == []                       # nothing reached the proxy


@pytest.mark.parametrize("addr, cat", [
    ("64:ff9b::a9fe:a9fe", "metadata"), ("64:ff9b::808:808", "public"), ("64:ff9b::a00:1", "private"),
    ("64:ff9b::7f00:1", "loopback"), ("2002:a9fe:a9fe::1", "metadata"), ("::a9fe:a9fe", "metadata"),
])
def test_ipv4_embedded_in_ipv6_is_categorised_by_the_ipv4_address(addr, cat):
    # on a DNS64/NAT64 network every public site resolves into 64:ff9b::/96, and the gateway connects to the IPv4 inside
    assert wh.address_category(addr) == cat


def test_nat64_target_is_public_and_its_metadata_address_is_still_refused():
    hooks = hooks_for({"www.kashif.test": {"status": "ok", "addresses": ["64:ff9b::5db8:d822"]},
                       "evil.kashif.test": {"status": "ok", "addresses": ["64:ff9b::a9fe:a9fe"]}})
    f = make("http://www.kashif.test/", hooks=hooks)
    assert f.target_category() == "public" and f.guard_url("http://evil.kashif.test/") == "metadata"


@pytest.mark.parametrize("url", ["http://a\x00b.test/", "http://a\x01b.test/", "http://a%00b.test/", "http://a|b.test/",
                                 "http://[fe80::1%25eth0]/", "http://a.test:0/"])
def test_forbidden_host_code_points_zone_ids_and_port_zero_are_bad_urls(url):
    assert wh._prepare(url) == "bad_url"
    assert wh._prepare("http://%61.kashif.test/").host == "a.kashif.test"   # percent-decoded like a browser


def test_robots_txt_is_read_up_to_500_kib(raw_http_server, http_reply_builder):
    body = ("# " + "x" * 98 + "\n") * 4000 + "User-agent: *\nDisallow: /late\n"    # ≈ 400 KB, rule at the end
    raw_http_server.routes["/robots.txt"] = http_reply_builder("200 OK", [("Content-Type", "text/plain")], body)
    raw_http_server.routes["/other.txt"] = http_reply_builder("200 OK", [("Content-Type", "text/plain")], body)
    f = make()
    r = f.fetch(raw_http_server.url("/robots.txt"), source="wellknown")
    assert not r.truncated and not robots.from_response(r).allowed("/late")
    assert f.fetch(raw_http_server.url("/other.txt"), source="wellknown").truncated    # other probes keep 256 KB


def test_the_address_that_answered_is_tried_first_next_time(raw_http_server, http_reply_builder, monkeypatch):
    raw_http_server.routes["/"] = http_reply_builder("200 OK", [], "ok")
    hooks = hooks_for({"dual.kashif.test": {"status": "ok", "addresses": ["::1", "127.0.0.1"], "public": True}})
    attempts = []
    real = wh.socket.create_connection

    def record(address, *a, **kw):
        attempts.append(address[0])
        if address[0] == "::1":
            raise OSError(101, "Network is unreachable")      # a dead AAAA (deterministic on every OS)
        return real(address, *a, **kw)
    monkeypatch.setattr(wh.socket, "create_connection", record)
    url = f"http://dual.kashif.test:{raw_http_server.port}/"
    f = make(url, hooks=hooks)
    assert f.fetch(url).status == 200 and f.fetch(url).status == 200
    assert attempts == ["::1", "127.0.0.1", "127.0.0.1"]


def test_the_cors_source_never_carries_cookies_even_without_an_origin(ka_server):
    srv = ka_server({"/set": ("200 OK", [("Set-Cookie", "sid=abc")], b"ok"), "/c": ("200 OK", [("Set-Cookie", "x=1")],
                                                                                      b"c")})
    f = make(srv.url())
    f.fetch(srv.url("/set"))
    f.fetch(srv.url("/c"), source="cors")
    assert "Cookie" not in dict(request_headers(srv.requests[1][1])[1]) and f.jar.names("127.0.0.1") == ["sid"]
