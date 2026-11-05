"""Passive checks against a running web application (one GET request).

Only runs when the user asserts authorization (``--authorized``): even a
single request is traffic against someone else's system.
"""

from __future__ import annotations

import http.client
import ssl
import urllib.error
import urllib.parse
import urllib.request

from .model import Finding

EXPECTED_HEADERS = [
    ("strict-transport-security", "high", "Missing Strict-Transport-Security", "ترويسة HSTS مفقودة",
     "أضف Strict-Transport-Security: max-age=31536000; includeSubDomains.", "CWE-319"),
    ("content-security-policy", "medium", "Missing Content-Security-Policy", "ترويسة CSP مفقودة",
     "أضف سياسة CSP تقيّد مصادر السكربتات.", "CWE-1021"),
    ("x-content-type-options", "low", "Missing X-Content-Type-Options", "ترويسة X-Content-Type-Options مفقودة",
     "أضف X-Content-Type-Options: nosniff.", "CWE-16"),
    ("x-frame-options", "medium", "Missing X-Frame-Options / frame-ancestors", "لا حماية من Clickjacking",
     "أضف X-Frame-Options: DENY أو frame-ancestors في CSP.", "CWE-1021"),
    ("referrer-policy", "info", "Missing Referrer-Policy", "ترويسة Referrer-Policy مفقودة",
     "أضف Referrer-Policy: strict-origin-when-cross-origin.", "CWE-200"),
]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def scan_url(url: str, timeout: float = 15.0) -> tuple[list[Finding], str | None]:
    findings: list[Finding] = []
    parsed = urllib.parse.urlparse(url)
    label = parsed.netloc or url
    if parsed.scheme == "http":
        findings.append(Finding("WEB000", "high", "Site served over plain HTTP", "الموقع يُقدَّم عبر HTTP غير مشفّر",
                                label, 0, url, "فعّل HTTPS وأعد توجيه HTTP إليه.", "CWE-319", source="web"))
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "vulnscan/0.1 (passive header check)"})
    try:
        resp = opener.open(req, timeout=timeout)
        status, headers = resp.status, resp.headers
    except urllib.error.HTTPError as e:
        status, headers = e.code, e.headers
    except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
        return findings, f"request failed: {e}"
    h = {k.lower(): v for k, v in headers.items()}
    if parsed.scheme == "https" or 300 <= status < 400:
        pass
    for name, sev, title, title_ar, advice, cwe in EXPECTED_HEADERS:
        if name == "strict-transport-security" and parsed.scheme != "https":
            continue
        if name == "x-frame-options" and "frame-ancestors" in h.get("content-security-policy", ""):
            continue
        if name not in h:
            findings.append(Finding(f"WEB-{name}", sev, title, title_ar, label, 0, f"HTTP {status}", advice, cwe, source="web"))
    server = h.get("server", "")
    if any(ch.isdigit() for ch in server):
        findings.append(Finding("WEB010", "low", f"Server header reveals version: {server}", "ترويسة Server تكشف الإصدار",
                                label, 0, server, "أخفِ رقم الإصدار من ترويسة Server.", "CWE-200", source="web"))
    powered = h.get("x-powered-by")
    if powered:
        findings.append(Finding("WEB011", "low", f"X-Powered-By reveals stack: {powered}", "ترويسة X-Powered-By تكشف التقنية",
                                label, 0, powered, "احذف ترويسة X-Powered-By.", "CWE-200", source="web"))
    for cookie in headers.get_all("set-cookie") or []:
        low = cookie.lower()
        cname = cookie.split("=", 1)[0].strip()
        if parsed.scheme == "https" and "secure" not in low:
            findings.append(Finding("WEB020", "medium", f"Cookie without Secure flag: {cname}", "كوكي بدون علامة Secure",
                                    label, 0, cookie[:120], "أضف Secure لكل الكوكيز.", "CWE-614", source="web"))
        if "httponly" not in low:
            findings.append(Finding("WEB021", "medium", f"Cookie without HttpOnly flag: {cname}", "كوكي بدون علامة HttpOnly",
                                    label, 0, cookie[:120], "أضف HttpOnly للكوكيز التي لا يحتاجها JavaScript.", "CWE-1004", source="web"))
        if "samesite" not in low:
            findings.append(Finding("WEB022", "low", f"Cookie without SameSite: {cname}", "كوكي بدون SameSite",
                                    label, 0, cookie[:120], "أضف SameSite=Lax أو Strict.", "CWE-1275", source="web"))
    if parsed.scheme == "https":
        findings.extend(_tls_checks(parsed.hostname or "", parsed.port or 443, label, timeout))
    return findings, None


def _tls_checks(host: str, port: int, label: str, timeout: float) -> list[Finding]:
    out = []
    for proto_name, min_v, max_v in (("TLS 1.0", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
                                      ("TLS 1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1)):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # nosec - we only probe protocol support
        try:
            ctx.minimum_version, ctx.maximum_version = min_v, max_v
        except (ValueError, ssl.SSLError):
            continue
        try:
            import socket
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    out.append(Finding("WEB030", "medium", f"Server accepts {proto_name}", f"الخادم يقبل {proto_name} القديم",
                                       label, 0, proto_name, "عطّل TLS 1.0/1.1 واقبل TLS 1.2+ فقط.", "CWE-326", source="web"))
        except (OSError, ssl.SSLError):
            pass
    return out
