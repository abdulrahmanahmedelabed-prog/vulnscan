"""1.1.0 accuracy round for the engine: findings hidden by the sensitivity filter, the crawl note (hard cap, Arabic
seconds), one proxy note, structured WebUnreachable for proxy failures, and the Observatory score behind a WAF.

Every scan runs against ``raw_http_server`` on 127.0.0.1 with the test resolver hook, as in test_engine.py.
"""

from __future__ import annotations

import json
import socket
import threading

import pytest

from vulnscan.webscan import engine, grade
from vulnscan.webscan.types import ScanOptions

HOST = "site.kashif.test"
PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
HTML = ("Content-Type", "text/html; charset=utf-8")


@pytest.fixture(autouse=True)
def _hook(monkeypatch, tmp_path):
    for k in PROXY_VARS:
        monkeypatch.delenv(k, raising=False)
    rmap = {"version": 1, "hosts": {HOST: {"status": "ok", "addresses": ["127.0.0.1"], "public": True}},
            "default": {"status": "ok", "addresses": ["127.0.0.1"], "public": True}}
    p = tmp_path / "resolve.json"
    p.write_text(json.dumps(rmap), encoding="utf-8")
    monkeypatch.setenv("KASHIF_TEST_RESOLVE", "1")
    monkeypatch.setenv("KASHIF_TEST_RESOLVE_MAP", str(p))
    monkeypatch.delenv("KASHIF_TEST_CAFILE", raising=False)
    monkeypatch.setenv("KASHIF_DEBUG", "1")


def reply(status="200 OK", headers=(), body=b""):
    if isinstance(body, str):
        body = body.encode("utf-8")
    lines = [f"HTTP/1.1 {status}"] + [f"{k}: {v}" for k, v in headers]
    lines += [f"Content-Length: {len(body)}", "Connection: close"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def url(srv, path="/"):
    return f"http://{HOST}:{srv.port}{path}"


# ----------------------------------------------------------------------------------------------- item 7

def test_hidden_by_sensitivity_is_counted_per_severity(raw_http_server):
    # a distribution build of Apache: its CVE match is tentative (backports), so it is hidden at default
    raw_http_server.routes["/"] = reply(headers=[HTML, ("Server", "Apache/2.4.41 (Ubuntu)")],
                                        body="<html><body><p>x</p></body></html>")
    res = engine.scan(url(raw_http_server), ScanOptions(profile="standard", delay=0.2, timeout=5))
    h = res.hidden_by_sensitivity
    assert h == res.inventory["hidden_by_sensitivity"]
    assert h["total"] >= 1 and sum(h["by_severity"].values()) == h["total"] and h["tls_proxied"] == 0
    assert "WEB800" not in {f.rule_id for f in res.findings}
    assert "hidden at the default sensitivity" in h["en"] and "--web-sensitivity paranoid" in h["en"]
    assert "مخفية" in h["ar"] and "--web-sensitivity paranoid" in h["ar"]
    shown = engine.scan(url(raw_http_server), ScanOptions(profile="standard", delay=0.2, timeout=5,
                                                          sensitivity="paranoid"))
    assert shown.hidden_by_sensitivity["total"] == 0 and "en" not in shown.hidden_by_sensitivity
    assert "WEB800" in {f.rule_id for f in shown.findings}


def test_crawl_pages_are_clamped_and_seconds_agree_in_arabic():
    assert engine.crawl_pages(10_000) == 500 and engine.crawl_pages(0) == 1 and engine.crawl_pages("x") == 20
    assert engine._count("seconds", 0.5, "ar") == "0.5 ثانية"
    assert engine._count("seconds", 1, "ar") == "ثانية واحدة"
    assert engine._count("seconds", 2, "ar") == "ثانيتين"
    assert engine._count("seconds", 0.5, "en") == "0.5 s"
    ar = engine.text("crawl", "ar", pages=engine._count("pages", 3, "ar"), delay=engine._count("seconds", 2, "ar"))
    assert "بفاصل ثانيتين على الأقل" in ar


def test_crawl_note_uses_the_clamped_page_count(raw_http_server):
    raw_http_server.routes["/"] = reply(headers=[HTML], body="<html><body><a href='/a'>a</a></body></html>")
    raw_http_server.routes["/a"] = reply(headers=[HTML], body="<html><body>a</body></html>")
    res = engine.scan(url(raw_http_server), ScanOptions(profile="standard", delay=0.2, timeout=5, crawl=True,
                                                        max_pages=100_000))
    (note,) = [n for n in res.inventory["notes"] if n["en"].startswith("Crawled")]
    assert "0.5 s or more" in note["en"] or "0.2 s or more" in note["en"]
    assert "ثانية" in note["ar"] and "ثانية ثانية" not in note["ar"]


def test_one_proxy_note_only(raw_http_server, monkeypatch):
    raw_http_server.routes["/"] = reply(headers=[HTML], body="<html><body>via proxy</body></html>")
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{raw_http_server.port}")
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{raw_http_server.port}")
    res = engine.scan(url(raw_http_server), ScanOptions(profile="minimal", delay=0.2, timeout=5))
    proxy_notes = [n for n in res.inventory["notes"] if "proxy" in n["en"].lower()]
    assert len(proxy_notes) == 1, proxy_notes
    assert f"127.0.0.1:{raw_http_server.port}" in proxy_notes[0]["en"]


# ----------------------------------------------------------------------------------------------- item 8

def _connect_refuser(status=b"403 Forbidden"):
    """A proxy that answers every CONNECT with ``status``."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    sock.settimeout(0.2)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                c, _ = sock.accept()
            except OSError:
                continue
            try:
                c.settimeout(3)
                c.recv(4096)
                c.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            finally:
                c.close()
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return sock.getsockname()[1], lambda: (stop.set(), sock.close())


def test_proxy_refusal_is_a_structured_unreachable(monkeypatch):
    port, stop = _connect_refuser()
    try:
        monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{port}")
        monkeypatch.setenv("https_proxy", f"http://127.0.0.1:{port}")
        with pytest.raises(engine.WebUnreachable) as exc:
            engine.scan(f"https://{HOST}/", ScanOptions(profile="minimal", delay=0.2, timeout=3))
    finally:
        stop()
    e = exc.value
    assert e.code == "proxy_refused" and e.proxy_status == 403 and e.proxy == f"http://127.0.0.1:{port}"
    assert e.findings == []          # never the TLS probes through a refusing proxy


def test_proxy_unreachable_code(monkeypatch):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                         # nothing listens there
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{port}")
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{port}")
    with pytest.raises(engine.WebUnreachable) as exc:
        engine.scan(f"http://{HOST}/", ScanOptions(profile="minimal", delay=0.2, timeout=2))
    assert exc.value.code == "proxy_unreachable" and exc.value.proxy == f"http://127.0.0.1:{port}"


# ----------------------------------------------------------------------------------------------- item 9

def test_observatory_is_not_scored_behind_a_waf_challenge(raw_http_server):
    raw_http_server.routes["/"] = reply("403 Forbidden", [HTML, ("Server", "cloudflare"), ("cf-mitigated", "challenge")],
                                        "<html><head><title>Just a moment...</title></head><body></body></html>")
    res = engine.scan(url(raw_http_server), ScanOptions(delay=0.2, timeout=5))
    obs = res.grades["observatory"]
    assert obs["score"] is None and obs["grade"] is None and obs.get("blocked") is True
    assert "WAF challenge" in obs["notes"][0]["en"] and "جدار حماية" in obs["notes"][0]["ar"]
    assert grade.summary(res.grades).startswith("Grades: Kashif ")


# ----------------------------------------------------------------------------------------------- item 1 (diff, end to end)

def test_rescan_at_a_lower_sensitivity_does_not_resolve_hidden_findings(raw_http_server):
    # paranoid shows the tentative CVE match of a distribution build; a default rescan hides it: not re-tested, and a
    # header that was really added is still resolved
    page = "<html><body><p>x</p></body></html>"
    raw_http_server.routes["/"] = reply(headers=[HTML, ("Server", "Apache/2.4.41 (Ubuntu)")], body=page)
    first = engine.scan(url(raw_http_server), ScanOptions(profile="standard", delay=0.2, timeout=5,
                                                          sensitivity="paranoid"))
    assert "WEB800" in {f.rule_id for f in first.findings}
    raw_http_server.routes["/"] = reply(headers=[HTML, ("Server", "Apache/2.4.41 (Ubuntu)"),
                                                 ("X-Content-Type-Options", "nosniff")], body=page)
    second = engine.scan(url(raw_http_server), ScanOptions(profile="standard", delay=0.2, timeout=5),
                         previous=first.snapshot)
    f = second.diff["findings"]
    assert "WEB800" not in {r["rule"] for r in f["resolved"]}
    nr = {r["rule"]: r["reason"]["code"] for r in f["not_retested"]}
    assert nr.get("WEB800") == "sensitivity"
    assert second.diff["counts"]["resolved"] == len(f["resolved"])
    assert "WEB-x-content-type-options" in {r["rule"] for r in f["resolved"]}
    for r in f["resolved"]:   # whatever is resolved was re-tested on its host in this scan
        assert r["confidence"] in ("certain", "firm")


def test_minimal_after_standard_resolves_nothing(raw_http_server):
    page = "<html><body><p>x</p></body></html>"
    raw_http_server.routes["/"] = reply(headers=[HTML], body=page)
    first = engine.scan(url(raw_http_server), ScanOptions(profile="standard", delay=0.2, timeout=5))
    second = engine.scan(url(raw_http_server), ScanOptions(profile="minimal", delay=0.2, timeout=5),
                         previous=first.snapshot)
    d = second.diff
    assert d["findings"]["resolved"] == [] and d["counts"]["resolved"] == 0
    assert d["counts"]["not_retested"] + d["counts"]["unchanged"] == len(first.snapshot["findings"])
