"""Passive and light posture checks against a running web application.

Only runs when the user asserts authorization (``--authorized``): even a
single request is traffic against someone else's system. The default scan is
one GET of the given URL. ``deep=True`` reads the returned HTML (no extra
traffic) to flag mixed content, insecure forms, missing SRI and weak CSP, and
then makes a small, bounded number of extra GETs for well-known files that are
commonly left exposed by mistake (``.git/HEAD``, ``.env`` …). It never submits
forms, sends payloads, fuzzes parameters or tries to bypass anything: it only
reads what the server already serves.
"""

from __future__ import annotations

import http.client
import re
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
    ("permissions-policy", "info", "Missing Permissions-Policy", "ترويسة Permissions-Policy مفقودة",
     "قيّد الصلاحيات الحساسة (الكاميرا، الموقع…) بترويسة Permissions-Policy.", "CWE-16"),
]

# Well-known files that should not be reachable; probed only in deep mode.
# (path, severity, english, arabic, remediation, body-signature regex or None)
EXPOSED_PATHS = [
    ("/.git/HEAD", "high", "Exposed .git repository", "مستودع .git مكشوف",
     "امنع الوصول إلى مجلد .git من خادم الويب؛ المصدر الكامل قد يكون قابلًا للتنزيل.", r"ref:\s*refs/"),
    ("/.env", "critical", "Exposed .env file", "ملف .env مكشوف",
     "أزل .env من جذر الويب فورًا وأبطل أي أسرار فيه.", r"(?im)^[A-Z0-9_]{3,}\s*="),
    ("/.svn/entries", "high", "Exposed .svn metadata", "بيانات .svn مكشوفة",
     "امنع الوصول إلى .svn من خادم الويب.", None),
    ("/.DS_Store", "low", "Exposed .DS_Store", "ملف .DS_Store مكشوف",
     "احذف .DS_Store من النشر؛ قد يكشف أسماء الملفات.", None),
    ("/server-status", "medium", "Apache server-status exposed", "صفحة server-status مكشوفة",
     "قيّد mod_status على localhost فقط.", r"Apache Server Status"),
    ("/phpinfo.php", "high", "phpinfo() exposed", "صفحة phpinfo مكشوفة",
     "احذف ملفات phpinfo من الإنتاج؛ تكشف إعدادات الخادم.", r"phpinfo\(\)"),
    ("/.well-known/security.txt", "info", "No security.txt", "لا يوجد security.txt",
     "أضف /.well-known/security.txt لتسهيل الإبلاغ عن الثغرات (غيابه ليس ثغرة).", "__absent__"),
    ("/robots.txt", "info", "robots.txt reveals sensitive paths", "robots.txt يكشف مسارات حساسة",
     "لا تضع مسارات إدارية حساسة في robots.txt؛ فهو عام.", "__robots__"),
]
MAX_BODY = 600_000


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _get(url: str, timeout: float, read_body: bool = False):
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "vulnscan/0.1 (passive posture check)"})
    try:
        resp = opener.open(req, timeout=timeout)
        body = resp.read(MAX_BODY) if read_body else b""
        return resp.status, resp.headers, body, None
    except urllib.error.HTTPError as e:
        body = e.read(MAX_BODY) if read_body else b""
        return e.code, e.headers, body, None
    except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
        return None, None, b"", str(e)


def scan_url(url: str, timeout: float = 15.0, deep: bool = False) -> tuple[list[Finding], str | None]:
    findings: list[Finding] = []
    parsed = urllib.parse.urlparse(url)
    label = parsed.netloc or url
    https = parsed.scheme == "https"
    if parsed.scheme == "http":
        findings.append(Finding("WEB000", "high", "Site served over plain HTTP", "الموقع يُقدَّم عبر HTTP غير مشفّر",
                                label, 0, url, "فعّل HTTPS وأعد توجيه HTTP إليه.", "CWE-319", source="web"))

    status, headers, body, err = _get(url, timeout, read_body=True)
    if status is None:
        return findings, f"request failed: {err}"
    h = {k.lower(): v for k, v in headers.items()}

    for name, sev, title, title_ar, advice, cwe in EXPECTED_HEADERS:
        if name == "strict-transport-security" and not https:
            continue
        if name == "x-frame-options" and "frame-ancestors" in h.get("content-security-policy", ""):
            continue
        if name not in h:
            findings.append(Finding(f"WEB-{name}", sev, title, title_ar, label, 0, f"HTTP {status}", advice, cwe, source="web"))

    findings.extend(_csp_weaknesses(h.get("content-security-policy", ""), label))

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
        if https and "secure" not in low:
            findings.append(Finding("WEB020", "medium", f"Cookie without Secure flag: {cname}", "كوكي بدون علامة Secure",
                                    label, 0, cookie[:120], "أضف Secure لكل الكوكيز.", "CWE-614", source="web"))
        if "httponly" not in low:
            findings.append(Finding("WEB021", "medium", f"Cookie without HttpOnly flag: {cname}", "كوكي بدون علامة HttpOnly",
                                    label, 0, cookie[:120], "أضف HttpOnly للكوكيز التي لا يحتاجها JavaScript.", "CWE-1004", source="web"))
        if "samesite" not in low:
            findings.append(Finding("WEB022", "low", f"Cookie without SameSite: {cname}", "كوكي بدون SameSite",
                                    label, 0, cookie[:120], "أضف SameSite=Lax أو Strict.", "CWE-1275", source="web"))

    ctype = h.get("content-type", "")
    if "text/html" in ctype and body:
        findings.extend(_analyze_html(body.decode("utf-8", "replace"), parsed, label))

    if https:
        findings.extend(_tls_checks(parsed.hostname or "", parsed.port or 443, label, timeout))

    if deep:
        findings.extend(_probe_paths(parsed, timeout))

    return findings, None


def _csp_weaknesses(csp: str, label: str) -> list[Finding]:
    out = []
    if not csp:
        return out
    low = csp.lower()
    script = re.search(r"(?:script-src|default-src)([^;]*)", low)
    scope = script.group(1) if script else ""
    if "'unsafe-inline'" in scope:
        out.append(Finding("WEB040", "medium", "CSP allows 'unsafe-inline' scripts", "CSP يسمح بسكربتات inline",
                           label, 0, "script-src 'unsafe-inline'", "أزل 'unsafe-inline' واستخدم nonce أو hash.", "CWE-1021", source="web"))
    if "'unsafe-eval'" in scope:
        out.append(Finding("WEB041", "medium", "CSP allows 'unsafe-eval'", "CSP يسمح بـ unsafe-eval",
                           label, 0, "script-src 'unsafe-eval'", "أزل 'unsafe-eval'.", "CWE-1021", source="web"))
    if re.search(r"(script-src|default-src)[^;]*\*", low) and "'none'" not in scope:
        out.append(Finding("WEB042", "medium", "CSP script source uses wildcard *", "CSP يسمح بأي مصدر للسكربتات",
                           label, 0, "script-src *", "حدّد النطاقات المسموحة بدل *.", "CWE-1021", source="web"))
    if "object-src" not in low:
        out.append(Finding("WEB043", "low", "CSP missing object-src 'none'", "CSP بلا object-src",
                           label, 0, csp[:120], "أضف object-src 'none' لمنع الإضافات القديمة.", "CWE-1021", source="web"))
    return out


_ATTR = re.compile(r"""(src|href|action)\s*=\s*['"]([^'"]+)['"]""", re.I)


def _analyze_html(html: str, parsed, label: str) -> list[Finding]:
    out = []
    https = parsed.scheme == "https"
    # Mixed content: http resources referenced from an https page.
    if https:
        for m in _ATTR.finditer(html):
            val = m.group(2).strip()
            if val.lower().startswith("http://"):
                out.append(Finding("WEB050", "medium", "Mixed content: insecure resource on HTTPS page",
                                   "محتوى مختلط: مورد عبر HTTP في صفحة HTTPS", label, 0, val[:120],
                                   "حمّل كل الموارد عبر https://.", "CWE-311", source="web"))
                break
    # Forms posting to http, or to a different origin.
    for fm in re.finditer(r"<form\b[^>]*>", html, re.I):
        action = re.search(r"""action\s*=\s*['"]([^'"]+)['"]""", fm.group(0), re.I)
        if action and action.group(1).lower().startswith("http://"):
            out.append(Finding("WEB051", "high", "Form submits over plain HTTP", "نموذج يُرسل عبر HTTP",
                               label, 0, fm.group(0)[:120], "اجعل action للنموذج https://.", "CWE-319", source="web"))
            break
    # Password field served where the page or its form is not clearly https.
    if not https and re.search(r"<input[^>]*type\s*=\s*['\"]password['\"]", html, re.I):
        out.append(Finding("WEB052", "high", "Password field on non-HTTPS page", "حقل كلمة مرور في صفحة غير HTTPS",
                           label, 0, "<input type=password>", "قدّم صفحات تسجيل الدخول عبر HTTPS فقط.", "CWE-319", source="web"))
    # External scripts without Subresource Integrity.
    for sc in re.finditer(r"<script\b[^>]*\bsrc\s*=\s*['\"]([^'\"]+)['\"][^>]*>", html, re.I):
        src = sc.group(1)
        host = urllib.parse.urlparse(src).netloc
        if host and host != parsed.netloc and "integrity=" not in sc.group(0).lower():
            out.append(Finding("WEB053", "low", "External script without Subresource Integrity",
                               "سكربت خارجي بلا تحقق سلامة (SRI)", label, 0, src[:120],
                               "أضف السمة integrity (SRI) للسكربتات الخارجية.", "CWE-353", source="web"))
            break
    # Outdated jQuery (very common and easy to read from the URL).
    jq = re.search(r"jquery[-/](\d+)\.(\d+)[.\d]*(?:\.min)?\.js", html, re.I)
    if jq and int(jq.group(1)) < 3:
        out.append(Finding("WEB054", "medium", f"Outdated jQuery {jq.group(1)}.{jq.group(2)}",
                           f"إصدار jQuery قديم {jq.group(1)}.{jq.group(2)}", label, 0, jq.group(0),
                           "حدّث jQuery إلى 3.x أو أحدث (إصدارات 1.x/2.x بها XSS معروفة).", "CWE-1104", source="web"))
    # Directory listing.
    if re.search(r"<title>\s*Index of /", html, re.I):
        out.append(Finding("WEB055", "medium", "Directory listing enabled", "عرض فهرس المجلدات مفعّل",
                           label, 0, "Index of /", "عطّل autoindex/directory listing على الخادم.", "CWE-548", source="web"))
    # Leaked stack trace / debug output.
    if re.search(r"(Traceback \(most recent call last\)|Warning: .*on line \d+|Exception in thread|at [\w.$]+\([\w.]+\.java:\d+\))", html):
        out.append(Finding("WEB056", "medium", "Stack trace / debug output in response", "أثر استثناء أو تصحيح في الاستجابة",
                           label, 0, "stack trace", "عطّل عرض الأخطاء التفصيلية في الإنتاج.", "CWE-209", source="web"))
    return out


def _probe_paths(parsed, timeout: float) -> list[Finding]:
    out = []
    base = f"{parsed.scheme}://{parsed.netloc}"
    label = parsed.netloc
    for path, sev, title, title_ar, advice, sig in EXPOSED_PATHS:
        status, headers, body, err = _get(base + path, timeout, read_body=True)
        text = body.decode("utf-8", "replace") if body else ""
        if sig == "__absent__":
            if status != 200:
                out.append(Finding("WEB060", sev, title, title_ar, label, 0, path, advice, "CWE-200", source="web"))
            continue
        if sig == "__robots__":
            if status == 200:
                hits = [l for l in text.splitlines() if re.match(r"(?i)\s*disallow", l) and re.search(r"(admin|internal|private|backup|secret|config|db|sql)", l, re.I)]
                if hits:
                    out.append(Finding("WEB061", sev, title, title_ar, label, 0, hits[0][:120], advice, "CWE-200", source="web"))
            continue
        ctype = (headers.get("content-type", "") if headers else "").lower()
        if status == 200 and "text/html" not in ctype and (sig is None or re.search(sig, text)):
            out.append(Finding("WEB062", sev, title, title_ar, label, 0, f"{path} → HTTP 200", advice, "CWE-538", source="web"))
    return out


def _tls_checks(host: str, port: int, label: str, timeout: float) -> list[Finding]:
    out = []
    import socket
    # Certificate validity / expiry.
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
        import datetime
        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days = (not_after - datetime.datetime.utcnow()).days
        if days < 0:
            out.append(Finding("WEB070", "high", "TLS certificate expired", "شهادة TLS منتهية",
                               label, 0, cert["notAfter"], "جدّد شهادة TLS فورًا.", "CWE-298", source="web"))
        elif days < 15:
            out.append(Finding("WEB071", "medium", f"TLS certificate expires in {days} days", f"شهادة TLS تنتهي خلال {days} يومًا",
                               label, 0, cert["notAfter"], "جدّد الشهادة قبل انتهائها (ويفضَّل التجديد الآلي).", "CWE-298", source="web"))
    except ssl.SSLCertVerificationError as e:
        out.append(Finding("WEB072", "high", "TLS certificate does not validate", "شهادة TLS لا تجتاز التحقق",
                           label, 0, str(e)[:120], "استخدم شهادة موثوقة مطابقة للنطاق (مثل Let's Encrypt).", "CWE-295", source="web"))
    except (OSError, ssl.SSLError, KeyError, ValueError):
        pass
    # Obsolete protocol support.
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
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    out.append(Finding("WEB030", "medium", f"Server accepts {proto_name}", f"الخادم يقبل {proto_name} القديم",
                                       label, 0, proto_name, "عطّل TLS 1.0/1.1 واقبل TLS 1.2+ فقط.", "CWE-326", source="web"))
        except (OSError, ssl.SSLError):
            pass
    return out
