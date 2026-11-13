"""TLS handshake orchestration per IP: verified and unverified handshakes, raw ClientHello probes, pacing, tri-state
results (spec §2.8 steps 1–5, WP10).

Network access goes only through a *connector*: the scan's ``http.Fetcher`` (``open_tcp`` applies the SSRF guard, the DNS
pin, the proxy tunnel and the ≤ 5 handshakes/s/IP pacing; ``tls_context`` builds the browser-parity verifying context
with the test-only CA hook; ``addresses`` returns the pinned addresses). Tests may pass any object with the same four
members.

Results are plain JSON-safe dicts (``ctx.tls``) so the report, the inventory and other modules can read them; DER
certificates are stored base64-encoded and parsed again by ``tls/assess.py``. Shape::

    ctx.tls["host" or "host:port"] = {
        "kind": "kashif-tls-host", "host", "port", "proxied", "proxy", "profile",
        "ips": {"<ip>" or "proxy": <ip report>}, "not_sampled": [ip, …], "error": {code, en, ar} | None,
        "leaf": {"sigalg", "sha256", …}            # summary of the first IP's leaf (read by transport.py)
    }
    <ip report> = {"ip", "status": ok|unreachable|refused|not_tested, "reason": code, "detail",
                   "verified": {ok, verify_code, verify_message, version, cipher, alpn, chain, verified_chain, error},
                   "unverified": {...} | None, "chain": [b64 DER as sent], "chain_source": ssl|raw|none,
                   "versions": {"TLSv1.3": {"state": yes|no|inconclusive|not_tested, …}, …},
                   "higher_version": [{offered, answered}], "downgrade_sentinel": bool | None,
                   "categories": {name: {"state", "cipher", "version"}}, "category_version": "TLSv1.2" | None,
                   "renegotiation_info": bool | None, "compression": bool | None,
                   "ocsp": {"state": stapled|absent|not_tested, "der": b64 | None, "reason"},
                   "tls_scts": [b64 SCT list] , "chosen": {version: suite}, "deep": {…}, "handshakes": n,
                   "backoff": bool, "notes": [[en, ar], …]}

Decision rule for a raw probe (§2.8 step 3): a ServerHello with the offered version → ``yes``; an alert or a reset/EOF
→ ``no``; a timeout or a non-TLS reply → retried once, then ``inconclusive``. Three consecutive timeouts or connection
failures on one IP → back off: the remaining probes of that IP become ``inconclusive`` ("backoff"). A normal ``ssl``
handshake that negotiated a version is proof that the version is supported, whatever a raw probe saw.
"""

from __future__ import annotations

import base64
import socket
import ssl
import time
import urllib.parse
import warnings
from typing import Any, Callable

from . import raw

MAX_IPS = 4
MAX_HOSTS = 4
RAW_TIMEOUT_CAP = 6.0
BACKOFF_AFTER = 3
HOST_KIND = "kashif-tls-host"

# bilingual texts used in reports and notes (the English counterpart of every Arabic string, §6 rules)
STR: dict[str, tuple[str, str]] = {
    "backoff": ("the server stopped answering probes (3 timeouts or failed connections in a row); the remaining "
                "probes were skipped", "توقف الخادم عن الرد على الفحوص (3 مهلات أو اتصالات فاشلة متتالية)؛ فتُركت بقية الفحوص"),
    "timeout": ("the server did not answer the probe in time", "لم يرد الخادم على الفحص في الوقت المحدد"),
    "not_tls": ("the reply was not TLS", "لم يكن الرد بصيغة TLS"),
    "connect": ("connection failed", "فشل الاتصال"),
    "ssl_proof": ("a normal handshake negotiated this version", "تفاوضت مصافحة عادية على هذا الإصدار"),
    "raw_disagrees": ("a raw probe was refused although a normal handshake negotiated this version (rate limiting or "
                      "filtering)", "رُفض فحص خام مع أن مصافحة عادية تفاوضت على هذا الإصدار (تقييد للمعدل أو تصفية)"),
    "tls13_only": ("the server offers only TLS 1.3, whose suites are all strong", "يقدّم الخادم TLS 1.3 فقط، وكل مجموعاته قوية"),
    "no_legacy": ("no TLS 1.0–1.2 version could be confirmed", "تعذّر تأكيد أي إصدار من TLS 1.0 إلى 1.2"),
    "proxied": ("seen through proxy {proxy}; an inspecting proxy replaces the certificate",
                "شوهد عبر الوكيل {proxy}؛ والوكيل الذي يفحص الحركة يستبدل الشهادة"),
    "sampled": ("more than 4 addresses; this one was not sampled", "أكثر من 4 عناوين؛ لم يُختر هذا العنوان للفحص"),
    "no_address": ("no address to connect to", "لا يوجد عنوان للاتصال به"),
    "ipv6": ("IPv6 address unreachable from this network", "عنوان IPv6 غير قابل للوصول من هذه الشبكة"),
    "legacy_only": ("this Python build cannot complete a handshake with the protocols the server offers",
                    "لا يستطيع إصدار Python هذا إتمام مصافحة بالبروتوكولات التي يقدّمها الخادم"),
}


def _b64(der: bytes) -> str:
    return base64.b64encode(der).decode("ascii")


def unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def host_key(host: str, port: int) -> str:
    return host if port == 443 else f"{host}:{port}"


# ----------------------------------------------------------------------------------------------- ssl handshakes

def _der_list(items: Any) -> list[bytes]:
    out: list[bytes] = []
    for c in items or ():
        if isinstance(c, (bytes, bytearray)):
            out.append(bytes(c))
        elif hasattr(c, "public_bytes"):
            out.append(c.public_bytes(getattr(ssl._ssl, "ENCODING_DER", 1)))  # noqa: SLF001 - 3.10–3.12 Certificate
    return out


def _chain(ss: ssl.SSLSocket, which: str) -> list[bytes] | None:
    """``get_unverified_chain``/``get_verified_chain``: public on 3.13+, ``_sslobj`` on 3.10–3.12 (guarded)."""
    name = f"get_{which}_chain"
    try:
        fn = getattr(ss, name, None)
        if fn is None:
            obj = getattr(ss, "_sslobj", None)
            fn = getattr(obj, name, None) if obj is not None else None
        if fn is None:
            return None
        return _der_list(fn())
    except (ssl.SSLError, ValueError, AttributeError, TypeError):
        return None


def _legacy_inspection_context(ctx: ssl.SSLContext) -> None:
    """Let the *unverified* inspection handshake reach old servers (it judges nothing, it only reads certificates)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except (ValueError, ssl.SSLError, AttributeError):
            pass


def ssl_handshake(connector: Any, host: str, port: int, ip: str | None, *, verified: bool, timeout: float) -> dict:
    """One handshake with Python's ``ssl``: browser-parity verification (connector context) or CERT_NONE inspection."""
    out: dict = {"ok": None, "verify_code": None, "verify_message": "", "version": None, "cipher": None, "alpn": None,
                 "chain": [], "verified_chain": None, "error": None, "refused": None}
    try:
        ctx = connector.tls_context(verified)
    except Exception as e:   # noqa: BLE001 - a broken hook file must not crash the scan
        out["error"] = f"context: {e}"
        return out
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except (NotImplementedError, ssl.SSLError):
        pass
    if not verified:
        _legacy_inspection_context(ctx)
    try:
        sock = connector.open_tcp(host, port, ip=ip, timeout=timeout)
    except OSError as e:
        out["error"] = f"connect: {e}"
        out["refused"] = getattr(e, "code", None) or "network"
        return out
    sni = None if raw.is_ip(host) and not verified else host
    try:
        sock.settimeout(timeout)
        with ctx.wrap_socket(sock, server_hostname=sni) as ss:
            out["ok"] = True if verified else None
            out["version"] = ss.version()
            c = ss.cipher()
            out["cipher"] = c[0] if c else None
            try:
                out["alpn"] = ss.selected_alpn_protocol()
            except (NotImplementedError, ssl.SSLError):
                pass
            sent = _chain(ss, "unverified")
            if not sent:
                leaf = ss.getpeercert(binary_form=True)
                sent = [leaf] if leaf else []
            out["chain"] = [_b64(d) for d in sent]
            if verified:
                built = _chain(ss, "verified")
                out["verified_chain"] = [_b64(d) for d in built] if built is not None else None
    except ssl.SSLCertVerificationError as e:
        out["ok"] = False
        out["verify_code"] = getattr(e, "verify_code", None)
        out["verify_message"] = str(getattr(e, "verify_message", "") or e)[:300]
    except (ssl.SSLError, OSError, ValueError) as e:
        out["error"] = f"{e.__class__.__name__}: {e}"[:300]
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


# ----------------------------------------------------------------------------------------------- raw probe session

class IpSession:
    """All probes of one (host, port, IP). ``ip=None`` means "through the proxy tunnel / connector's choice"."""

    def __init__(self, connector: Any, host: str, port: int, ip: str | None, *, timeout: float,
                 clock: Callable[[], float] = time.monotonic):
        self.connector, self.host, self.port, self.ip = connector, host, port, ip
        self.timeout = max(0.5, min(float(timeout), RAW_TIMEOUT_CAP))
        self.ssl_timeout = max(1.0, float(timeout))
        self.failures = 0
        self.backed_off = False
        self.handshakes = 0
        self.refusal: str | None = None        # a guard/budget refusal stops the session
        self.clock = clock

    def _connect(self) -> socket.socket | None:
        if self.backed_off or self.refusal:
            return None
        try:
            sock = self.connector.open_tcp(self.host, self.port, ip=self.ip, timeout=self.timeout)
        except OSError as e:
            code = getattr(e, "code", None)
            if code:                                  # FetchRefused: guard, time budget …
                self.refusal = code
                return None
            self._fail()
            return None
        self.handshakes += 1
        return sock

    def _fail(self) -> None:
        self.failures += 1
        if self.failures >= BACKOFF_AFTER:
            self.backed_off = True

    def send(self, hello: bytes) -> raw.Flight:
        """One probe, retried once when inconclusive (timeout, non-TLS reply, failed connection)."""
        fl = raw.Flight(result="error", done=True)
        for _attempt in range(2):
            sock = self._connect()
            if sock is None:
                fl = raw.Flight(result="skipped" if (self.backed_off or self.refusal) else "error", done=True,
                                detail="backoff" if self.backed_off else (self.refusal or "connect"))
                if self.backed_off or self.refusal:
                    return fl
                continue
            try:
                fl, _data = raw.exchange(sock, hello, self.timeout)
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
            if fl.result in ("hello", "alert", "eof"):
                self.failures = 0
                return fl
            if fl.result == "timeout":
                self._fail()
            if self.backed_off:
                return fl
        return fl


def version_state(fl: raw.Flight, offered: int) -> dict:
    """Tri-state verdict of a version probe (§2.8 step 3) plus the facts the assessment needs."""
    d = {"state": "inconclusive", "result": fl.result, "answered": fl.version_name or None,
         "alert": list(fl.alert) if fl.alert else None, "detail": fl.detail, "cipher": raw.suite_name(fl.cipher) or None}
    if fl.result == "hello":
        if offered == raw.TLS13:
            d["state"] = "yes" if (fl.hrr or fl.version == raw.TLS13) else "no"
        elif fl.version == offered:
            d["state"] = "yes"
        else:
            d["state"] = "no"
            if fl.version and fl.version > offered and offered != raw.SSL2:
                d["higher"] = True
    elif fl.result == "alert":
        d["state"] = "inconclusive" if fl.alert and fl.alert[1] == 80 else "no"
    elif fl.result == "eof":
        d["state"] = "no"
    elif fl.result == "skipped":
        d["state"] = "inconclusive"
        d["reason"] = fl.detail or "backoff"
    if d["state"] == "inconclusive" and "reason" not in d:
        d["reason"] = {"timeout": "timeout", "not_tls": "not_tls", "error": "connect"}.get(fl.result, "timeout")
    return d


def _hello_for(host: str, name: str, **kw: Any) -> bytes:
    if name == "SSLv2":
        return raw.sslv2_client_hello()
    if name == "SSLv3":
        return raw.sslv3_client_hello()
    v = raw.VERSION_IDS[name]
    if v == raw.TLS13:
        return raw.client_hello(host, raw.TLS13, raw.TLS13_SUITES + raw.ECDHE_SUITES, **kw)
    return raw.client_hello(host, v, raw.LEGACY_SUITES, **kw)


# ----------------------------------------------------------------------------------------------- one IP

def probe_ip(connector: Any, host: str, port: int, ip: str | None, *, profile: str = "standard",
             timeout: float = 10.0) -> dict:
    """Run the profile's handshakes against one IP and return its JSON-safe report."""
    rep: dict = {"ip": ip, "status": "ok", "reason": "", "detail": "", "verified": None, "unverified": None,
                 "chain": [], "chain_source": "none", "versions": {}, "higher_version": [], "downgrade_sentinel": None,
                 "categories": {}, "category_version": None, "renegotiation_info": None, "compression": None,
                 "ocsp": {"state": "not_tested", "der": None, "reason": "not_run"}, "tls_scts": [], "chosen": {},
                 "deep": {}, "handshakes": 0, "backoff": False, "notes": []}
    sess = IpSession(connector, host, port, ip, timeout=timeout)

    # 1. verified handshake (browser parity) and, when it fails, the unverified one for the certificates (D21)
    ver = ssl_handshake(connector, host, port, ip, verified=True, timeout=sess.ssl_timeout)
    rep["verified"] = ver
    sess.handshakes += 1
    if ver.get("refused") and ver["refused"] not in ("network",):
        rep["status"], rep["reason"], rep["detail"] = "refused", ver["refused"], ver.get("error") or ""
        return _finish(rep, sess)
    if ver.get("refused") == "network" and ver.get("error"):
        # the TCP connection itself failed: one more try decides between "unreachable" and a flaky first attempt
        again = ssl_handshake(connector, host, port, ip, verified=True, timeout=sess.ssl_timeout)
        sess.handshakes += 1
        if again.get("refused"):
            rep["status"] = "unreachable"
            rep["reason"] = "ipv6_unreachable" if ip and ":" in ip else "network"
            rep["detail"] = again.get("error") or ""
            rep["verified"] = again
            return _finish(rep, sess)
        ver = rep["verified"] = again
    if ver.get("ok"):
        rep["chain"], rep["chain_source"] = list(ver.get("chain") or []), "ssl"
    else:
        unv = ssl_handshake(connector, host, port, ip, verified=False, timeout=sess.ssl_timeout)
        sess.handshakes += 1
        rep["unverified"] = unv
        if unv.get("chain"):
            rep["chain"], rep["chain_source"] = list(unv["chain"]), "ssl"

    # 2. raw version probes, newest first
    flights: dict[str, raw.Flight] = {}
    for name in raw.PROBE_VERSIONS:
        fl = sess.send(_hello_for(host, name))
        flights[name] = fl
        st = version_state(fl, raw.VERSION_IDS[name])
        rep["versions"][name] = st
        if st.get("higher"):
            rep["higher_version"].append({"offered": name, "answered": fl.version_name})
        if fl.result == "hello" and fl.cipher is not None and st["state"] == "yes":
            rep["chosen"][name] = raw.suite_name(fl.cipher)
        if name == "TLSv1.2" and fl.result == "hello" and fl.version == raw.TLS12:
            rep["downgrade_sentinel"] = fl.downgrade == "tls12"
    v12 = rep["versions"].get("TLSv1.2", {})
    if rep["downgrade_sentinel"] and rep["versions"]["TLSv1.3"]["state"] != "yes":
        rep["versions"]["TLSv1.3"] = {**rep["versions"]["TLSv1.3"], "state": "yes", "source": "downgrade_sentinel"}
    # a normal handshake is proof of support
    for hs in (ver, rep.get("unverified") or {}):
        nv = hs.get("version") if hs else None
        if nv in ("TLSv1.2", "TLSv1.3", "TLSv1.1", "TLSv1") and hs.get("chain"):
            key = "TLSv1.0" if nv == "TLSv1" else nv
            prev = rep["versions"].get(key, {})
            if prev.get("state") != "yes":
                note = STR["raw_disagrees"] if prev.get("state") == "no" else STR["ssl_proof"]
                rep["versions"][key] = {**prev, "state": "yes", "source": "ssl", "detail": note[0]}
    del v12

    # 3. the plaintext TLS ≤ 1.2 flight: certificates, OCSP staple, TLS SCTs, renegotiation_info
    cat_version = next((n for n in ("TLSv1.2", "TLSv1.1", "TLSv1.0") if rep["versions"].get(n, {}).get("state") == "yes"),
                       None)
    rep["category_version"] = cat_version
    base = flights.get(cat_version) if cat_version else None
    if base is not None and base.result == "hello" and base.version == raw.VERSION_IDS[cat_version]:
        rep["renegotiation_info"] = raw.EXT_RENEG in base.extensions
        if not rep["chain"] and base.certs:
            rep["chain"], rep["chain_source"] = [_b64(d) for d in base.certs], "raw"
        if base.ocsp:
            rep["ocsp"] = {"state": "stapled", "der": _b64(base.ocsp), "reason": ""}
        else:
            rep["ocsp"] = {"state": "absent", "der": None, "reason": ""}
        sct = base.extensions.get(raw.EXT_SCT)
        if sct:
            rep["tls_scts"] = [_b64(sct)]
    elif rep["versions"].get("TLSv1.3", {}).get("state") == "yes":
        rep["ocsp"] = {"state": "not_tested", "der": None, "reason": "tls13_encrypted"}
    else:
        rep["ocsp"] = {"state": "not_tested", "der": None, "reason": "timeout" if sess.backed_off else "no_legacy"}
    if not rep["chain"]:
        for name in ("TLSv1.0", "TLSv1.1", "SSLv3"):
            fl = flights.get(name)
            if fl is not None and fl.certs:
                rep["chain"], rep["chain_source"] = [_b64(d) for d in fl.certs], "raw"
                break

    # 4. cipher-suite categories and compression (standard and deep)
    if profile != "minimal":
        _categories(rep, sess, host, cat_version, flights)
        if profile == "deep":
            _deep(rep, sess, host, cat_version)
    return _finish(rep, sess)


def _categories(rep: dict, sess: IpSession, host: str, cat_version: str | None, flights: dict) -> None:
    if cat_version is None:
        reason = "tls13_only" if rep["versions"].get("TLSv1.3", {}).get("state") == "yes" else (
            "backoff" if sess.backed_off else "no_legacy")
        for name in raw.CATEGORY_PROBES:
            rep["categories"][name] = {"state": "not_applicable" if reason == "tls13_only" else "inconclusive",
                                       "reason": reason}
        rep["compression"] = None
        return
    v = raw.VERSION_IDS[cat_version]
    base = flights.get(cat_version)
    for name, suites in raw.CATEGORY_PROBES.items():
        if name == "aead":
            proven = rep["versions"].get("TLSv1.3", {}).get("state") == "yes" or (
                base is not None and base.cipher in suites)
            if proven:
                rep["categories"][name] = {"state": "yes", "cipher": raw.suite_name(base.cipher) if base and
                                           base.cipher in suites else "TLS 1.3", "version": cat_version, "source": "free"}
                continue
        if name == "cbc" and base is not None and base.cipher in suites:
            rep["categories"][name] = {"state": "yes", "cipher": raw.suite_name(base.cipher), "version": cat_version,
                                       "source": "free"}
            continue
        fl = sess.send(raw.client_hello(host, v, suites))
        rep["categories"][name] = _category_state(fl, v, suites, cat_version)
    fl = sess.send(raw.client_hello(host, v, raw.LEGACY_SUITES, compression=(1, 0)))
    if fl.result == "hello" and fl.version == v:
        rep["compression"] = fl.compression == 1
    elif fl.result in ("alert", "eof"):
        rep["compression"] = False
    else:
        rep["compression"] = None


def _category_state(fl: raw.Flight, v: int, suites: tuple[int, ...], version_name: str) -> dict:
    if fl.result == "hello":
        if fl.version == v and fl.cipher in suites:
            return {"state": "yes", "cipher": raw.suite_name(fl.cipher), "version": version_name}
        return {"state": "no", "detail": f"answered {fl.version_name} {raw.suite_name(fl.cipher)}"}
    if fl.result in ("alert", "eof"):
        return {"state": "no"}
    return {"state": "inconclusive", "reason": "backoff" if fl.result == "skipped" else (
        "timeout" if fl.result == "timeout" else "not_tls")}


def _deep(rep: dict, sess: IpSession, host: str, cat_version: str | None) -> None:
    deep: dict = {}
    rep["deep"] = deep
    tls13 = rep["versions"].get("TLSv1.3", {}).get("state") == "yes"
    if cat_version is not None:
        v = raw.VERSION_IDS[cat_version]
        # server order: offer everything, record the pick, remove it, repeat; then test preference with two suites
        remaining = list(raw.LEGACY_SUITES)
        picked: list[int] = []
        while remaining and len(picked) < 25:
            fl = sess.send(raw.client_hello(host, v, remaining))
            if not (fl.result == "hello" and fl.version == v and fl.cipher in remaining):
                break
            picked.append(fl.cipher)
            remaining.remove(fl.cipher)
        deep["suites"] = [raw.suite_name(c) for c in picked]
        deep["suites_complete"] = not sess.backed_off
        if len(picked) >= 2:
            fl = sess.send(raw.client_hello(host, v, [picked[1], picked[0]]))
            deep["server_preference"] = bool(fl.result == "hello" and fl.cipher == picked[0])
            deep["preferred"] = raw.suite_name(picked[0])
        # DHE parameters and ECDHE curve from the ServerKeyExchange
        fl = sess.send(raw.client_hello(host, v, raw.DHE_SUITES))
        if fl.result == "hello" and fl.cipher in raw.DHE_SUITES:
            ske = raw.parse_ske(fl.ske, "DHE")
            if ske:
                deep["dh_bits"] = ske["dh_bits"]
                deep["dh_prime_sha256"] = __import__("hashlib").sha256(ske["dh_prime"]).hexdigest()
        elif fl.result in ("alert", "eof", "hello"):
            deep["dh_bits"] = None
        fl = sess.send(raw.client_hello(host, v, raw.ECDHE_SUITES))
        if fl.result == "hello" and fl.cipher in raw.ECDHE_SUITES:
            ske = raw.parse_ske(fl.ske, "ECDHE")
            if ske:
                deep["ecdhe_group"] = ske["group"]
        # TLS_FALLBACK_SCSV: a lower version offered with the SCSV must get alert 86 from a server that supports more
        lower = next((n for n in ("TLSv1.1", "TLSv1.0") if rep["versions"].get(n, {}).get("state") == "yes"
                      and raw.VERSION_IDS[n] < v), None)
        if lower is not None:
            fl = sess.send(raw.client_hello(host, raw.VERSION_IDS[lower], raw.LEGACY_SUITES,
                                            extra_suites=(raw.SCSV_FALLBACK,)))
            deep["fallback_scsv"] = bool(fl.result == "alert" and fl.alert and fl.alert[1] == 86)
    if tls13:
        suites = {}
        for cid in raw.TLS13_ALL_SUITES:
            fl = sess.send(raw.client_hello(host, raw.TLS13, (cid,)))
            suites[raw.suite_name(cid)] = (fl.result == "hello" and (fl.hrr or fl.version == raw.TLS13)
                                           and fl.cipher == cid)
        deep["tls13_suites"] = suites
        groups: dict[str, bool | None] = {}
        for g in raw.PROBE_GROUPS:
            fl = sess.send(raw.client_hello(host, raw.TLS13, raw.TLS13_SUITES, groups=(g,), key_share_groups=()))
            if fl.result == "hello":
                groups[raw.GROUPS[g]] = bool(fl.hrr and fl.selected_group() == g)
            elif fl.result in ("alert", "eof"):
                groups[raw.GROUPS[g]] = False
            else:
                groups[raw.GROUPS[g]] = None
        deep["groups"] = groups
        fl = sess.send(raw.client_hello(host, raw.TLS13, raw.TLS13_SUITES,
                                        groups=(raw.X25519MLKEM768, 0x001D, 0x0017, 0x0018), key_share_groups=(0x001D,)))
        g = fl.selected_group() if fl.result == "hello" else None
        if g is not None:
            deep["preferred_group"] = raw.GROUPS.get(g, f"0x{g:04X}")
    deep["complete"] = not sess.backed_off and not sess.refusal


def _finish(rep: dict, sess: IpSession) -> dict:
    rep["handshakes"] = rep.get("handshakes", 0) + sess.handshakes
    rep["backoff"] = sess.backed_off
    if sess.refusal and rep["status"] == "ok":
        rep["notes"].append([f"probing stopped: {sess.refusal}", f"توقف الفحص: {sess.refusal}"])
        rep["stopped"] = sess.refusal
    if sess.backed_off:
        rep["notes"].append(list(STR["backoff"]))
    return rep


# ----------------------------------------------------------------------------------------------- one host

def scan_host(connector: Any, host: str, port: int = 443, *, profile: str = "standard", timeout: float = 10.0,
              max_ips: int = MAX_IPS) -> dict:
    """Probe every pinned address of ``host`` (≤ ``max_ips``; the rest are reported as not sampled)."""
    host = host.strip("[]").rstrip(".").lower()
    proxy = None
    try:
        proxy = connector.proxy_for(f"https://{host}:{port}/")
    except Exception:   # noqa: BLE001 - foreign connector
        proxy = None
    rep: dict = {"kind": HOST_KIND, "host": host, "port": port, "proxied": proxy is not None,
                 "proxy": getattr(proxy, "display", None) or (str(getattr(proxy, "host", "")) if proxy else None),
                 "profile": profile, "ips": {}, "not_sampled": [], "error": None, "leaf": {}}
    if proxy is not None:
        ips: list[str | None] = [None]
    else:
        try:
            addrs = list(connector.addresses(host))
        except OSError:
            addrs = []
        if raw.is_ip(host) and not addrs:
            addrs = [host]
        if not addrs:
            rep["error"] = {"code": "network", "en": STR["no_address"][0], "ar": STR["no_address"][1]}
            return rep
        # sample a mix of families: IPv4 first (always reachable where IPv6 may not be), then IPv6
        v4 = [a for a in addrs if ":" not in a]
        v6 = [a for a in addrs if ":" in a]
        ordered = v4[: max_ips - min(len(v6), max_ips // 2)] + v6
        ips = list(dict.fromkeys(ordered))[:max_ips]
        rep["not_sampled"] = [a for a in addrs if a not in ips]
    for ip in ips:
        r = probe_ip(connector, host, port, ip, profile=profile, timeout=timeout)
        rep["ips"][ip or "proxy"] = r
        if r.get("stopped") in ("time_budget",):
            break
    first = next((r for r in rep["ips"].values() if r.get("chain")), None)
    if first is not None:
        from .x509 import try_parse
        leaf = try_parse(unb64(first["chain"][0]))
        if leaf is not None:
            rep["leaf"] = leaf.summary()
    return rep


def _https_hosts(ctx: Any) -> list[tuple[str, int]]:
    """https hosts the scan actually reached (entry chain first, then the counterpart chains)."""
    out: dict[tuple[str, int], None] = {}
    roots = [ctx.entry, ctx.https_probe, ctx.http_probe]
    target = urllib.parse.urlsplit(ctx.target or "")
    for r in roots:
        if r is None:
            continue
        hops = r.hops() if hasattr(r, "hops") else [r]
        for h in hops:
            p = urllib.parse.urlsplit(h.url)
            if p.scheme.lower() != "https" or not p.hostname:
                continue
            reached = h.status is not None or any(f == "cert-error" or f.startswith("cert-verify") for f in h.flags) or (
                "certificate" in (h.error or "").lower() or "ssl" in (h.error or "").lower())
            if not reached:
                continue
            try:
                port = p.port or 443
            except ValueError:
                continue
            out.setdefault((p.hostname.lower().rstrip("."), port), None)
    if target.scheme == "https" and target.hostname and not out and ctx.entry is None:
        out.setdefault((target.hostname.lower(), target.port or 443), None)
    return list(out)


def collect(ctx: Any, connector: Any = None) -> dict:
    """Pipeline step 4 (§4.3): TLS assessment for each https host reached by the entry or counterpart chain. Fills and
    returns ``ctx.tls``. Engine-only (it is the network part of WP10); ``tls.assess.run`` then reads ``ctx.tls``."""
    connector = connector if connector is not None else getattr(ctx, "fetcher", None)
    if connector is None:
        return ctx.tls
    hosts = _https_hosts(ctx)
    for i, (host, port) in enumerate(hosts):
        key = host_key(host, port)
        if key in ctx.tls:
            continue
        if i >= MAX_HOSTS:
            ctx.tls[key] = {"kind": HOST_KIND, "host": host, "port": port, "proxied": False, "proxy": None,
                            "profile": ctx.options.profile, "ips": {}, "not_sampled": [], "leaf": {},
                            "error": {"code": "budget", "en": "more https hosts than the TLS budget allows",
                                      "ar": "عدد مضيفي HTTPS أكبر مما تسمح به ميزانية فحص TLS"}}
            continue
        ctx.tls[key] = scan_host(connector, host, port, profile=ctx.options.profile, timeout=ctx.options.timeout)
    return ctx.tls


__all__ = ["scan_host", "probe_ip", "collect", "ssl_handshake", "version_state", "IpSession", "host_key", "unb64",
           "STR", "MAX_IPS", "HOST_KIND"]
