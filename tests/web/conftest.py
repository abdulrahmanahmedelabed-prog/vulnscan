"""Shared fixtures for the passive web scanner tests (tests/web, WP0).

* An autouse **offline guard**: tests may connect only to loopback addresses and resolve only ``localhost`` and IP
  literals; anything else raises :class:`NetworkBlocked` (a ``RuntimeError``, so code that catches ``OSError`` cannot
  hide it). Mark a test ``@pytest.mark.real_resolver`` to allow name resolution (still never non-loopback connects).
* Builders as fixtures (no import of this file needed): ``make_headers``, ``make_response``, ``make_page``,
  ``make_ctx`` and ``fixed_now``.
* ``raw_http_server``: a tiny HTTP/1.1 server on 127.0.0.1 that answers each path with raw bytes you give it
  (duplicate headers, obs-fold, broken framing — whatever the test needs). Requests are recorded.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from datetime import datetime, timezone

import pytest

from vulnscan.webscan import htmlparse
from vulnscan.webscan.types import HeaderList, Page, Response, ScanContext, ScanOptions

FIXED_NOW = datetime(2026, 11, 13, 12, 0, 0, tzinfo=timezone.utc)


class NetworkBlocked(RuntimeError):
    """A test tried to reach the network (tests/web must stay offline)."""


def pytest_configure(config):
    config.addinivalue_line("markers", "real_resolver: allow socket name resolution in this test (connects stay loopback)")


def _loopback(host) -> bool:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    h = str(host).strip("[]").split("%", 1)[0].lower()
    if h in ("localhost", "") or h.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _is_ip(host) -> bool:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    try:
        ipaddress.ip_address(str(host).strip("[]").split("%", 1)[0])
        return True
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def _offline_guard(request, monkeypatch):
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_getaddrinfo = socket.getaddrinfo
    allow_dns = request.node.get_closest_marker("real_resolver") is not None

    def check_addr(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6) and isinstance(address, tuple):
            if not _loopback(address[0]):
                raise NetworkBlocked(f"tests/web are offline: connect to {address[0]!r} blocked")

    def connect(self, address):
        check_addr(self, address)
        return real_connect(self, address)

    def connect_ex(self, address):
        check_addr(self, address)
        return real_connect_ex(self, address)

    def getaddrinfo(host, *args, **kwargs):
        if host is not None and not allow_dns and not _loopback(host) and not _is_ip(host):
            raise NetworkBlocked(f"tests/web are offline: name resolution of {host!r} blocked")
        return real_getaddrinfo(host, *args, **kwargs)

    def by_name(fn):
        def wrapper(host, *a, **kw):
            if not allow_dns and not _loopback(host) and not _is_ip(host):
                raise NetworkBlocked(f"tests/web are offline: name resolution of {host!r} blocked")
            return fn(host, *a, **kw)
        return wrapper

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket, "gethostbyname", by_name(socket.gethostbyname))
    monkeypatch.setattr(socket, "gethostbyname_ex", by_name(socket.gethostbyname_ex))
    yield


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path_factory, monkeypatch):
    """Point KASHIF_HOME at an empty directory so tests never read the developer's updated web data."""
    from vulnscan.webscan import data
    monkeypatch.setenv("KASHIF_HOME", str(tmp_path_factory.mktemp("kashif-home")))
    monkeypatch.delenv("VULNSCAN_HOME", raising=False)
    data.clear_cache()
    yield
    data.clear_cache()


# ----------------------------------------------------------------------------------------------- builders

@pytest.fixture
def fixed_now() -> datetime:
    return FIXED_NOW


def _headers(spec) -> HeaderList:
    if spec is None:
        return HeaderList()
    if isinstance(spec, HeaderList):
        return spec
    if isinstance(spec, dict):
        return HeaderList.from_mapping(spec)
    return HeaderList.of(*spec)


@pytest.fixture
def make_headers():
    """``make_headers(("Set-Cookie", "a=1"), ("Set-Cookie", "b=2"))`` or ``make_headers({"X": "1"})``."""
    def build(*pairs, **mapping):
        if len(pairs) == 1 and isinstance(pairs[0], (dict, HeaderList)):
            return _headers(pairs[0])
        if mapping:
            return HeaderList.from_mapping({k.replace("_", "-"): v for k, v in mapping.items()})
        return HeaderList.of(*pairs)
    return build


@pytest.fixture
def make_response():
    """``make_response(url, status=200, headers=..., body=str|bytes, content_type=..., **fields)``.

    ``content_type`` adds a Content-Type header unless ``headers`` already has one; ``chain`` takes earlier hops."""
    def build(url: str = "https://example.test/", status: int | None = 200, headers=None, body: str | bytes = b"",
              content_type: str | None = None, **fields) -> Response:
        hl = _headers(headers)
        if content_type and not hl.has("content-type"):
            hl = HeaderList(hl.items + (("Content-Type", content_type),))
        if isinstance(body, str):
            body = body.encode("utf-8")
        return Response(url=url, status=status, headers=hl, body=body, **fields)
    return build


@pytest.fixture
def make_page(make_response):
    """``make_page(html, url=..., headers=..., status=200, depth=0)`` → Page with its parsed light DOM."""
    def build(html: str, url: str = "https://example.test/", headers=None, status: int = 200, depth: int = 0,
              **fields) -> Page:
        resp = make_response(url, status=status, headers=headers, body=html,
                             content_type="text/html; charset=utf-8", kind=fields.pop("kind", "document"), **fields)
        return Page(resp, htmlparse.parse_response(resp), depth)
    return build


@pytest.fixture
def make_ctx(fixed_now):
    """``make_ctx(target=..., entry=..., pages=[...], profile=..., sensitivity=..., **ScanContext fields)``.

    When ``entry`` is a Page its response becomes ``ctx.entry`` and the page is put first in ``ctx.pages``."""
    def build(target: str = "https://example.test/", entry=None, profile: str = "standard",
              sensitivity: str = "default", options: ScanOptions | None = None, **fields) -> ScanContext:
        opts = options or ScanOptions(profile=profile, sensitivity=sensitivity)
        pages = list(fields.pop("pages", []))
        if isinstance(entry, Page):
            pages.insert(0, entry)
            entry = entry.response
        fields.setdefault("now", fixed_now)
        return ScanContext(options=opts, target=target, entry=entry, pages=pages, **fields)
    return build


# ----------------------------------------------------------------------------------------------- local server

class RawHTTPServer:
    """Serves ``routes[path] = bytes | callable(request_bytes) -> bytes`` on 127.0.0.1; unknown paths get a 404."""

    def __init__(self):
        self.routes: dict[str, object] = {}
        self.requests: list[bytes] = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, name="raw-http-server", daemon=True)
        self._thread.start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def url(self, path: str = "/") -> str:
        return self.base + path

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(5)
        try:
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            self.requests.append(data)
            line = data.split(b"\r\n", 1)[0].decode("latin-1")
            parts = line.split(" ")
            path = parts[1] if len(parts) > 1 else "/"
            if "://" in path:   # absolute-form (proxy style)
                path = "/" + path.split("://", 1)[1].split("/", 1)[-1] if "/" in path.split("://", 1)[1] else "/"
            route = self.routes.get(path, self.routes.get(path.split("?", 1)[0]))
            if route is None:
                reply = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnot found"
            elif callable(route):
                reply = route(data)
            else:
                reply = route
            conn.sendall(reply)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


def http_reply(status: str = "200 OK", headers=(), body: bytes | str = b"") -> bytes:
    """Build a raw HTTP/1.1 response (Content-Length and Connection: close added unless given)."""
    if isinstance(body, str):
        body = body.encode("utf-8")
    names = {k.lower() for k, _ in headers}
    lines = [f"HTTP/1.1 {status}"] + [f"{k}: {v}" for k, v in headers]
    if "content-length" not in names:
        lines.append(f"Content-Length: {len(body)}")
    if "connection" not in names:
        lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


@pytest.fixture
def raw_http_server():
    srv = RawHTTPServer()
    try:
        yield srv
    finally:
        srv.close()


@pytest.fixture
def http_reply_builder():
    return http_reply
