"""Scope contract (spec §0.1, §0.2; §6 phase D item 3): every kind of outbound traffic the web scanner can produce is
listed here, next to the row of the §0.1 table that allows it. A new request type, a new place that opens a
connection, a new request header or method, or a never-list path in any data file fails this test until the table
(and the spec) are updated on purpose.

Two halves:

* **static** — the source is read with ``ast``: every ``fetch(..., source=…)`` call in the package, every module that
  imports a network API or calls one, every HTTP method and request header the fetcher writes, the bounds of each row;
* **runtime** — one ``deep`` + ``--crawl`` scan of a local server on 127.0.0.1 (the busiest profile) records every
  request the fetcher made, by type, and every request the server received: all of them must fall in the table.
"""

from __future__ import annotations

import ast
import gzip
import json
import pathlib
import re

import pytest

from vulnscan.webscan import classify, engine, exposure, http
from vulnscan.webscan.types import (ACCEPT_DOCUMENT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, ACCEPT_PROBE, CORS_PROBE_ORIGIN,
                                    ScanOptions, user_agent)

ROOT = pathlib.Path(__file__).resolve().parents[2]
PKG = ROOT / "vulnscan"
WEB_CODE = sorted((PKG / "webscan").rglob("*.py")) + [PKG / "web.py"]
DATA_WEB = PKG / "data" / "web"

PROFILE_RANK = {"minimal": 0, "standard": 1, "deep": 2}

# ----------------------------------------------------------------------------------------------- the §0.1 table
# request type (the ``source`` of Fetcher.fetch) → (the §0.1 row that allows it, lowest profile, per-scan bound, extra
# condition). ``bound`` counts fetch() calls of that type (each may follow redirects within its hop limit).
ALLOWED: dict[str, tuple[str, str, int | None, str]] = {
    "entry": ("GET of the target URL, following redirects like a browser", "minimal", 1, ""),
    "http_probe": ("GET of the http:// counterpart of an https target (redirect test)", "standard", 1, "default ports"),
    "https_probe": ("GET of the https:// counterpart of an http target (WEB000 variants A/B)", "standard", 1,
                    "default ports"),
    "cors": ("GET of the same URL with the benign Origin, without the cookie jar", "standard", 1, ""),
    "wellknown": ("GET of robots.txt, security.txt (legacy path only after a 404), sitemap.xml (--crawl), the icon",
                  "standard", engine.MAX_WELLKNOWN, ""),
    "subresource": ("GET of scripts and stylesheets the page references (same-site; third-party with --deep)",
                    "standard", engine.MAX_SAME_SITE_SUBRESOURCES + engine.MAX_THIRD_PARTY, ""),
    "sourcemap": ("GET of source maps named by a fetched script or style", "deep", engine.MAX_SOURCEMAPS, ""),
    "image": ("GET of same-site JPEG images (first 128 KB, EXIF check)", "deep", engine.MAX_IMAGES, "or --crawl"),
    "crawl": ("Crawl of same-origin <a href> links", "standard", None, "--crawl only; --max-pages/--max-depth"),
    "probe": ("The opt-in deep probe of known accidentally-exposed files (fixed list)", "deep", exposure.MAX_PROBES, ""),
    "baseline": ("Random-path soft-404 baselines (/kashif-404-<16 hex>)", "deep", classify.MAX_BASELINES_PER_SCAN, ""),
}
# DNS (§0.1 last row): Fetcher.lookup kinds and their caps (the target's own lookup is one name, uncapped)
DNS_PURPOSES = {"target": None, "referenced": http.DNS_REFERENCED_CAP, "registrable": http.DNS_REGISTRABLE_CAP}

# modules allowed to touch a network API, and which ones (anything else in vulnscan/webscan or web.py fails)
NETWORK_MODULES = {
    "webscan/http.py": {"socket", "ssl", "http.client", "urllib.request"},   # the one fetcher (+ open_tcp for TLS)
    "webscan/tls/probe.py": {"socket", "ssl"},     # TLS handshakes over sockets from Fetcher.open_tcp
    "webscan/tls/raw.py": {"socket"},              # raw ClientHello exchange over a socket it is given
    "web.py": {"http.client", "urllib.request"},   # 1.0.1 helper ``_get``, kept for callers; the scanner never uses it
}
NET_IMPORTS = ("socket", "ssl", "http.client", "urllib.request", "urllib3", "requests", "asyncio", "ftplib", "smtplib",
               "telnetlib", "xmlrpc.client", "http.server", "socketserver")
# calls that open a connection or resolve a name: allowed only in these modules
CONNECT_CALLS = {"create_connection": {"webscan/http.py"}, "getaddrinfo": {"webscan/http.py"},
                 "gethostbyname_ex": {"webscan/http.py"}, "gethostbyname": set(), "urlopen": set(),
                 "HTTPConnection": {"webscan/http.py"}, "HTTPSConnection": {"webscan/http.py"},
                 "build_opener": {"web.py"}, "wrap_socket": {"webscan/http.py", "webscan/tls/probe.py"},
                 "set_tunnel": {"webscan/http.py"}, "putrequest": set(), "open_tcp": {"webscan/http.py",
                                                                                       "webscan/tls/probe.py"}}
REQUEST_HEADERS = {"User-Agent", "Accept", "Accept-Encoding", "Accept-Language", "Origin", "Cookie",
                   "Proxy-Authorization"}                    # §0.2 (+ the jar's Cookie; Proxy-Authorization: user's proxy)
FORBIDDEN_METHODS = {"OPTIONS", "TRACE", "PUT", "POST", "DELETE", "PATCH", "HEAD", "PROPFIND", "MKCOL", "COPY", "MOVE",
                     "LOCK", "UNLOCK", "PURGE", "DEBUG", "TRACK"}
# §0.1 "Never": endpoints whose GET makes the server do expensive or state-changing work
NEVER = re.compile(r"(?i)heap-?dump|thread-?dump|/debug/pprof|pprof/profile|/actuator/(?:shutdown|restart|pause|resume|"
                   r"refresh|loggers|caches)|cache[-_/]?purge|/purge\b|install(?:er)?\.php\?step|/setup\.php\?step")


def _rel(p: pathlib.Path) -> str:
    return p.relative_to(PKG).as_posix()


def _trees():
    for p in WEB_CODE:
        yield _rel(p), ast.parse(p.read_text(encoding="utf-8"), filename=str(p))


def _callee(node: ast.Call) -> str:
    f = node.func
    return f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""


def _kw(node: ast.Call, name: str):
    return next((k.value for k in node.keywords if k.arg == name), None)


# ----------------------------------------------------------------------------------------------- static half

def test_every_request_type_in_the_code_is_in_the_scope_table():
    found: dict[str, set[str]] = {}
    dynamic = []
    for rel, tree in _trees():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _callee(node) not in ("fetch", "_fetch"):
                continue
            src = _kw(node, "source")
            if src is None:
                found.setdefault("entry", set()).add(rel)          # Fetcher.fetch's default
            elif isinstance(src, ast.Constant) and isinstance(src.value, str):
                found.setdefault(src.value, set()).add(rel)
            elif isinstance(src, ast.IfExp) and all(isinstance(x, ast.Constant) for x in (src.body, src.orelse)):
                for x in (src.body, src.orelse):
                    found.setdefault(x.value, set()).add(rel)
            else:
                dynamic.append(f"{rel}:{node.lineno}")
    assert not dynamic, f"request type computed at run time (cannot be checked against §0.1): {dynamic}"
    unknown = {s: sorted(m) for s, m in found.items() if s not in ALLOWED}
    assert not unknown, f"request types not in the §0.1 table: {unknown}"
    # the table has no stale rows either: each type is produced somewhere (the entry by the engine itself)
    assert set(found) == set(ALLOWED), sorted(set(ALLOWED) - set(found))


def test_the_fetcher_accepts_exactly_the_table_and_refuses_anything_else():
    assert set(http.SOURCE_CLASS) == set(ALLOWED)
    assert http.DOCUMENT_SOURCES <= set(ALLOWED)
    f = http.Fetcher(ScanOptions(), "http://127.0.0.1:9/")
    with pytest.raises(ValueError, match="unknown request type"):
        f.fetch("http://127.0.0.1:9/", source="spider")
    for bad in ("null", "https://kashif-cors-check.invalid.evil.example", "https://attacker.example"):
        with pytest.raises(ValueError, match="benign CORS probe Origin"):
            f.fetch("http://127.0.0.1:9/", source="cors", origin=bad)
    assert f.requests == 0                                         # nothing was sent


def test_only_the_fetcher_and_tls_code_touch_the_network():
    imports: dict[str, set[str]] = {}
    calls: dict[str, set[str]] = {}
    for rel, tree in _trees():
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
            for n in names:
                hit = next((m for m in NET_IMPORTS if n == m or n.startswith(m + ".")), None)
                if hit:
                    imports.setdefault(rel, set()).add(hit)
            if isinstance(node, ast.Call) and _callee(node) in CONNECT_CALLS:
                calls.setdefault(_callee(node), set()).add(rel)
    extra = {m: sorted(v - NETWORK_MODULES.get(m, set())) for m, v in imports.items()
             if v - NETWORK_MODULES.get(m, set())}
    assert not extra, f"network APIs imported outside the fetcher/TLS code: {extra}"
    wrong = {c: sorted(ms - CONNECT_CALLS[c]) for c, ms in calls.items() if ms - CONNECT_CALLS[c]}
    assert not wrong, f"connections or lookups opened outside the allowed modules: {wrong}"


def test_only_get_is_ever_sent():
    for rel, tree in _trees():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _callee(node)
            if name == "request" and node.args and isinstance(node.func, ast.Attribute):
                m = node.args[0]
                assert isinstance(m, ast.Constant) and m.value == "GET", f"{rel}:{node.lineno} non-GET request"
            if name == "Request" and _kw(node, "method") is not None:
                assert getattr(_kw(node, "method"), "value", None) == "GET", f"{rel}:{node.lineno}"
            for a in node.args:
                if isinstance(a, ast.Constant) and a.value in FORBIDDEN_METHODS and name in ("request", "putrequest",
                                                                                             "_send", "fetch"):
                    pytest.fail(f"{rel}:{node.lineno}: method {a.value} (§0.1 never-list)")


def _send_header_names() -> set[str]:
    tree = ast.parse((PKG / "webscan" / "http.py").read_text(encoding="utf-8"))
    send = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_send")
    names: set[str] = set()
    for node in ast.walk(send):
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "headers" \
                and isinstance(node.value, ast.Dict):
            names |= {k.value for k in node.value.keys if isinstance(k, ast.Constant)}
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Subscript):
            t = node.targets[0]
            if isinstance(t.value, ast.Name) and t.value.id == "headers" and isinstance(t.slice, ast.Constant):
                names.add(t.slice.value)
    return names


def test_request_headers_are_the_honest_fixed_set():
    names = _send_header_names()
    assert names and names <= REQUEST_HEADERS, names - REQUEST_HEADERS
    assert {"User-Agent", "Accept", "Accept-Encoding", "Accept-Language"} <= names
    assert ACCEPT_DOCUMENT == "text/html,application/xhtml+xml,*/*;q=0.8" and ACCEPT_PROBE == "*/*"
    assert ACCEPT_ENCODING == "gzip, deflate" and ACCEPT_LANGUAGE == "en"            # never br/zstd (§0.4)
    assert CORS_PROBE_ORIGIN == "https://kashif-cors-check.invalid"
    from vulnscan import __version__
    assert re.fullmatch(r"Kashif/" + re.escape(__version__) + r" \(\+https://[^ )]+/vulnscan/scanner\.html\)", user_agent())
    assert "github.com" not in user_agent().lower()
    # no other place sets a header on an outgoing request (spoofing such as X-Forwarded-For is on the never-list)
    for rel, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _callee(node) in ("putheader", "add_header", "add_unredirected_header"):
                pytest.fail(f"{rel}:{node.lineno}: extra request header")
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and re.fullmatch(
                    r"(?i)x-forwarded-(for|host|proto)|x-real-ip|x-originating-ip|true-client-ip|forwarded",
                    node.value) and rel in NETWORK_MODULES:
                pytest.fail(f"{rel}:{node.lineno}: spoofing header name {node.value!r}")


def test_bounds_match_the_scope_table():
    assert http.PROFILE_BUDGETS == {"minimal": 10, "standard": 45, "deep": 150}
    assert http.MAX_HOPS == 10
    assert (engine.MAX_WELLKNOWN, engine.MAX_SAME_SITE_SUBRESOURCES, engine.MAX_THIRD_PARTY, engine.MAX_SOURCEMAPS,
            engine.MAX_IMAGES) == (5, 15, 10, 5, 10)
    assert exposure.MAX_PROBES <= 70
    assert (classify.MAX_BASELINES_PER_HOST, classify.MAX_BASELINES_PER_SCAN) == (5, 10)
    assert (http.DNS_REFERENCED_CAP, http.DNS_REGISTRABLE_CAP) == (30, 10)
    assert http.CAPS["image"] == 128_000
    assert http.TLS_GAP >= 0.2 and http.MIN_DELAY >= 0.2                    # ≤ 5 handshakes/s; request gap floor
    # the standard worst case of §0.1 fits its budget: 10 entry hops + 10 counterpart hops + CORS + 5 + 15 = 41
    assert 10 + 10 + 1 + engine.MAX_WELLKNOWN + engine.MAX_SAME_SITE_SUBRESOURCES <= http.PROFILE_BUDGETS["standard"]


def test_dns_lookups_are_the_two_allowed_kinds():
    purposes = set()
    for rel, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _callee(node) in ("lookup", "lookup_registrable"):
                p = _kw(node, "purpose")
                if isinstance(p, ast.Name) and p.id == "purpose" and rel == "webscan/http.py":
                    continue                        # lookup_registrable forwarding its own argument
                if p is not None:
                    assert isinstance(p, ast.Constant), f"{rel}:{node.lineno}: computed DNS purpose"
                    purposes.add(p.value)
    assert purposes <= set(DNS_PURPOSES), purposes
    f = http.Fetcher(ScanOptions(), "http://127.0.0.1:9/")
    with pytest.raises(ValueError, match="unknown DNS lookup kind"):
        f.lookup("a.example", purpose="zone-transfer")


def _data_texts():
    for p in sorted(DATA_WEB.rglob("*")):
        if p.suffix == ".gz":
            yield p, gzip.decompress(p.read_bytes()).decode("utf-8", "replace")
        elif p.suffix in (".json", ".txt", ".dat"):
            yield p, p.read_text(encoding="utf-8", errors="replace")


def test_no_data_file_lists_a_never_list_path():
    exposed = json.loads((DATA_WEB / "exposed-paths.json").read_text(encoding="utf-8"))
    paths = [d["path"] for d in exposed["paths"]]
    assert paths and not [p for p in paths if NEVER.search(p) or exposure.NEVER_LIST.search(p)]
    for p, text in _data_texts():
        if p.name in ("psl.dat.gz", "hsts-preload.json.gz", "retire-jsrepository.json.gz"):
            continue                  # host names and library signatures, never requested as paths
        for m in re.finditer(r'"(/[^"\s]{1,200})"', text):
            assert not NEVER.search(m.group(1)), f"{p.name}: {m.group(1)}"


def test_the_deep_list_has_no_never_list_path_for_any_platform():
    """Checked on the raw lists (``plan()`` also filters them, but the data itself must already be clean)."""
    raw = exposure.exposed_paths() + exposure.platform_paths(platforms=None) + list(exposure.POLICY_FILES.values())
    assert raw
    bad = sorted({p.path for p in raw if NEVER.search(p.path)})
    assert not bad, bad
    assert len(exposure.exposed_paths()) <= exposure.MAX_PROBES


# ----------------------------------------------------------------------------------------------- runtime half

HOST = "scope.kashif.test"
PAGE = """<!doctype html><html><head><title>Scope</title>
<link rel="icon" href="/static/icon.png"><link rel="stylesheet" href="/static/site.css">
<script src="/static/app.js"></script><script src="https://cdn.third-party.example.net/lib.js"></script>
</head><body><img src="/static/photo.jpg" alt=""><a href="/a">a</a> <a href="/logout">out</a>
<a href="/private/x">private</a></body></html>"""


def _reply(status="200 OK", headers=(), body=b""):
    body = body.encode("utf-8") if isinstance(body, str) else body
    lines = [f"HTTP/1.1 {status}", *(f"{k}: {v}" for k, v in headers), f"Content-Length: {len(body)}", "Connection: close"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


class _RecordingFetcher(http.Fetcher):
    """The real fetcher, recording every fetch() by type (requests are paced by a no-op sleep: local server only)."""

    def __init__(self, *a, **kw):
        super().__init__(*a, sleep=lambda _s: None, **kw)
        self.calls: list[tuple[str, str]] = []

    def fetch(self, url, *, source="entry", **kw):
        self.calls.append((source, url))
        return super().fetch(url, source=source, **kw)


@pytest.fixture
def _resolver(monkeypatch, tmp_path):
    for k in ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        monkeypatch.delenv(k, raising=False)
    rmap = {"version": 1, "default": {"status": "ok", "addresses": ["127.0.0.1"], "public": True}}
    p = tmp_path / "resolve.json"
    p.write_text(json.dumps(rmap), encoding="utf-8")
    monkeypatch.setenv("KASHIF_TEST_RESOLVE", "1")
    monkeypatch.setenv("KASHIF_TEST_RESOLVE_MAP", str(p))
    monkeypatch.delenv("KASHIF_TEST_CAFILE", raising=False)


def test_a_deep_crawl_scan_only_sends_traffic_from_the_table(raw_http_server, _resolver):
    srv = raw_http_server
    html = ("Content-Type", "text/html; charset=utf-8")
    jpeg = b"\xff\xd8\xff\xe1\x00\x16Exif\x00\x00MM\x00*\x00\x00\x00\x08\x00\x00\x00\x00\xff\xd9"
    srv.routes.update({
        "/": _reply(headers=[html, ("Set-Cookie", "sid=0123456789abcdef; Path=/")], body=PAGE),
        "/a": _reply(headers=[html], body="<html><body><p>a</p><a href='/b'>b</a></body></html>"),
        "/b": _reply(headers=[html], body="<html><body><p>b</p></body></html>"),
        "/private/x": _reply(headers=[html], body="<html><body>secret</body></html>"),
        "/robots.txt": _reply(headers=[("Content-Type", "text/plain")], body="User-agent: *\nDisallow: /private/\n"),
        "/static/app.js": _reply(headers=[("Content-Type", "application/javascript")],
                                 body="var a = 1;\n//# sourceMappingURL=app.js.map\n"),
        "/static/app.js.map": _reply(headers=[("Content-Type", "application/json")],
                                     body='{"version":3,"sources":["src/a.ts"],"mappings":""}'),
        "/static/site.css": _reply(headers=[("Content-Type", "text/css")], body="body{color:#000}\n"),
        "/static/icon.png": _reply(headers=[("Content-Type", "image/png")], body=b"\x89PNG\r\n\x1a\n" + b"\0" * 32),
        "/static/photo.jpg": _reply(headers=[("Content-Type", "image/jpeg")], body=jpeg),
    })
    target = f"http://{HOST}:{srv.port}/"
    opts = ScanOptions(profile="deep", crawl=True, max_pages=5, max_depth=2, delay=0.2, timeout=5)
    fetcher = _RecordingFetcher(opts, target)
    res = engine.scan(target, opts, fetcher=fetcher)

    by_type: dict[str, int] = {}
    for source, _url in fetcher.calls:
        assert source in ALLOWED, source
        by_type[source] = by_type.get(source, 0) + 1
    for source, n in by_type.items():
        bound = ALLOWED[source][2]
        assert bound is None or n <= bound, (source, n, bound)
        assert PROFILE_RANK[ALLOWED[source][1]] <= PROFILE_RANK["deep"]
    for want in ("entry", "cors", "wellknown", "subresource", "sourcemap", "image", "crawl", "probe", "baseline"):
        assert by_type.get(want), (want, by_type)
    assert by_type.get("crawl", 0) <= opts.max_pages
    assert sum(n for s, n in fetcher.counts.items() if s != "crawl") <= http.PROFILE_BUDGETS["deep"]
    assert fetcher.requests == res.requests

    # what reached the server: GET only (the raw server's parser), the fixed header set, the honest UA, no never-list
    received = 0
    for raw in srv.requests:
        head = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
        method, path = head[0].split(" ")[:2]
        assert method == "GET", head[0]
        names = {line.partition(":")[0].strip().lower() for line in head[1:]}
        assert names <= {"host", "user-agent", "accept", "accept-encoding", "accept-language", "origin", "cookie",
                         "connection"}, names
        assert not NEVER.search(path) and not exposure.NEVER_LIST.search(path), path
        assert not path.startswith("/private/") and "logout" not in path        # robots and SKIP_LINK honoured
        if "/kashif-404-" in path:
            assert re.fullmatch(r".*/kashif-404-[0-9a-f]{16}(\.[a-z0-9]+)?", path), path
        received += 1
    assert received == fetcher.requests
