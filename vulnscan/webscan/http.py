"""HTTP fetcher of the passive web scanner (spec §0.1, §0.2, §0.6, §0.7, §4.3; WP1).

Every request Kashif's web scan makes goes through one :class:`Fetcher` per scan. It owns:

* **Traffic contract (§0.1/§0.2).** GET only; exactly the headers ``User-Agent`` (the honest Kashif UA), ``Accept``
  (document or probe form), ``Accept-Encoding: gzip, deflate``, ``Accept-Language: en``, plus ``Cookie`` from the
  in-memory jar and, for the CORS GET only, ``Origin: https://kashif-cors-check.invalid`` (never with cookies).
* **Budgets.** Every request on the wire counts, redirect hops included: ``minimal`` = the entry chain only (≤ 10),
  ``standard`` ≤ 45, ``deep`` ≤ 150; crawl pages have their own budget (``max_pages``, hard cap 500). Total bytes
  (50 MB) and the scan's time budget (600 s) are enforced too. When a budget is reached the request is not sent and the
  response carries ``error`` and the flag ``error:budget`` (or ``time_budget`` / ``byte_budget``).
* **Politeness (§4.3).** One request at a time per host, a minimum gap of ``delay`` (floor 0.2 s) between requests to a
  host, raised by robots.txt ``Crawl-delay`` (≤ 10 s); 429, or 503 with ``Retry-After``: wait ``min(Retry-After, 60)``
  once and retry, a second one stops the host; one retry with a doubled timeout for transient errors; three resets in a
  row stop the host.
* **Hostile-target safety (§0.6).** Per-response monotonic wall-clock deadline (a watchdog closes the socket, so a
  server that drips bytes cannot hold the scan); size caps per resource class with ``truncated``; gzip/deflate decoding
  with a decompression-bomb guard; other content codings leave the body opaque (empty) with the flag
  ``opaque-coding``; more than 100 header lines → ``error`` "too many headers"; obsolete line folding normalised and
  recorded (flags ``obs-fold`` and ``obs-fold:<name>``).
* **SSRF guard and DNS pinning (§0.1).** A host is resolved once per scan and its addresses are pinned. Requests to
  loopback, private or link-local addresses are refused unless the target itself is in that category; cloud metadata
  addresses are never requested. Redirects to non-http(s) schemes are never followed.
* **Proxies (§0.7).** ``urllib.request.getproxies()``/``proxy_bypass()``; https through a CONNECT tunnel, http as
  absolute-URI requests; ``ScanOptions.use_proxy = False`` (``--no-proxy``) disables them. Through a proxy only IP
  literals are SSRF-checked and DNS facts are ``not_tested`` ("proxied").
* **Resolver.** :meth:`Fetcher.lookup` returns a :class:`~vulnscan.webscan.types.DnsRecord` with status ok, nxdomain
  (``EAI_NONAME``), nodata (``EAI_NODATA``), tempfail (``EAI_AGAIN``, timeouts, anything else) or not_tested.
* **Test-only hooks.** :class:`CorpusHooks` reads ``KASHIF_TEST_RESOLVE_MAP`` (resolver map) and ``KASHIF_TEST_CAFILE``
  (extra trusted CA) **only** when ``KASHIF_TEST_RESOLVE=1``; without it both variables are ignored.

Flags set on responses (``Response.flags``): ``obs-fold``, ``obs-fold:<name>``, ``truncated-body``, ``opaque-coding``,
``opaque-coding:<coding>``, ``decode-error``, ``incomplete-body``, ``deadline``, ``cert-error``, ``cert-verify:<code>``,
``proxied``, ``retried``, ``rate-limited``, ``retry-after-waited``, ``host-stopped``, ``redirect-loop``,
``redirect-limit``, ``redirect-blocked:<scheme|ssrf|metadata|offsite|robots|budget|bad-location>`` and, on responses that were
never received, ``error:<code>`` (codes in :data:`ERROR_CODES`). :func:`coverage_reason` maps them to coverage reasons.
"""

from __future__ import annotations

import base64
import dataclasses
import email.utils
import errno
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from . import psl
from .types import (ACCEPT_DOCUMENT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, ACCEPT_PROBE, CORS_PROBE_ORIGIN, PROFILES,
                    DnsRecord, HeaderList, Response, ScanOptions, normalise_host, safe_url, user_agent)

# ----------------------------------------------------------------------------------------------- constants

MIN_DELAY = 0.2                      # floor of the per-host gap (§4.3), whatever --delay says
MAX_CRAWL_DELAY = 10.0               # robots.txt Crawl-delay is honoured up to this
MAX_HOPS = 10                        # redirect chain bound (§0.1)
MAX_RETRY_AFTER = 60.0
DEFAULT_RETRY_AFTER = 5.0            # a 429 without a usable Retry-After
RESET_STORM = 3                      # consecutive connection resets that stop a host
MAX_HEADER_LINES = 100               # http.client's _MAXHEADERS on 3.10–3.14 (> 100 → "too many headers")
MAX_HEADER_BYTES = 64 * 1024         # header block cap (§0.6)
PROFILE_BUDGETS = {"minimal": 10, "standard": 45, "deep": 150}   # requests on the wire, crawl pages excluded (§0.1)
CRAWL_HARD_CAP = 500
CAPS = {"document": 2_000_000, "script": 3_000_000, "probe": 256_000, "image": 128_000}   # bytes after decoding
SOURCE_CLASS = {"entry": "document", "http_probe": "document", "https_probe": "document", "cors": "document",
                "crawl": "document", "subresource": "script", "sourcemap": "script", "wellknown": "probe",
                "probe": "probe", "baseline": "probe", "image": "image"}
DOCUMENT_SOURCES = frozenset({"entry", "http_probe", "https_probe", "cors", "crawl"})
DECOMPRESS_RATIO = 10                # decoded size ≤ 10 × the encoded size …
DECOMPRESS_FLOOR = 256_000           # … but never less than this (small pages compress better than 10:1)
METADATA_ADDRESSES = frozenset({"169.254.169.254", "fd00:ec2::254", "100.100.100.200"})
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
DNS_REFERENCED_CAP = 30              # referenced hosts looked up per scan (§0.1)
DNS_REGISTRABLE_CAP = 10             # registrable-domain lookups per scan (§0.1, WEB517)
NXDOMAIN_RECHECK = 2.0               # WEB517: a missing name is confirmed once, ≥ 2 s later
TLS_GAP = 0.2                        # ≤ 5 handshakes per second per address (§2.8)
ENV_HOOK = "KASHIF_TEST_RESOLVE"
ENV_MAP = "KASHIF_TEST_RESOLVE_MAP"
ENV_CAFILE = "KASHIF_TEST_CAFILE"

# error codes on responses that were never received (flag ``error:<code>``) → coverage reason code (coverage.REASONS)
ERROR_CODES = {
    "scheme": "network", "bad_url": "network", "dns": "network", "timeout": "timeout", "deadline": "timeout",
    "refused": "network", "reset": "network", "unreachable": "network", "network": "network", "tls": "network",
    "proxy": "network", "too_many_headers": "network", "header_too_large": "network", "bad_response": "network",
    "ssrf": "network", "budget": "budget", "time_budget": "time_budget", "byte_budget": "byte_budget",
    "host_stopped": "rate_limited", "profile": "profile", "robots": "robots",
}
TOO_MANY_HEADERS = "too many headers"

# bilingual texts of fetcher events (shown as scan notes); {placeholders} are filled by Fetcher._event
EVENTS: dict[str, tuple[str, str]] = {
    "retry_after": ("{host} asked the scanner to slow down (HTTP {status}, Retry-After: {seconds}); it waited once and "
                    "retried.",
                    "طلب {host} من الفاحص الإبطاء (HTTP {status}، Retry-After: {seconds})؛ فانتظر مرة واحدة ثم أعاد الطلب."),
    "host_stopped": ("{host} limited the scan's request rate again; no more requests were sent to it and the remaining "
                     "checks on it are inconclusive.",
                     "قيّد {host} معدل طلبات الفحص مرة أخرى؛ فلم تُرسل إليه طلبات أخرى، والفحوص المتبقية عليه غير حاسمة."),
    "reset_storm": ("{host} reset the connection three times in a row; no more requests were sent to it.",
                    "قطع {host} الاتصال ثلاث مرات متتالية؛ فلم تُرسل إليه طلبات أخرى."),
    "ssrf": ("Not requested: {url} points to a {category} address and the target is not on such a network "
             "(scanner safety guard).",
             "لم يُطلب {url} لأنه يشير إلى عنوان من نوع {category} والهدف ليس على شبكة كهذه (حماية الفاحص)."),
    "metadata": ("Not requested: {url} is a cloud-metadata address (scanner safety guard).",
                 "لم يُطلب {url} لأنه عنوان بيانات وصفية سحابية (حماية الفاحص)."),
    "scheme": ("A redirect to a non-HTTP(S) address was not followed: {url}",
               "لم يُتبَع توجيه إلى عنوان ليس HTTP أو HTTPS: {url}"),
    "cert_error": ("The TLS certificate of {host} did not validate ({message}); its responses were read over an "
                   "unverified connection, as evidence only.",
                   "لم تجتز شهادة TLS الخاصة بـ {host} التحقق ({message})؛ فقُرئت استجاباته عبر اتصال غير موثَّق للاستدلال فقط."),
    "truncated": ("The response from {url} was larger than the size cap ({cap} bytes) and was cut.",
                  "الاستجابة من {url} أكبر من الحد المسموح ({cap} بايت) فقُطعت."),
    "deadline": ("{url} did not finish within the per-response deadline ({seconds} s); the response was cut.",
                 "لم تكتمل الاستجابة من {url} خلال المهلة المحددة لكل استجابة ({seconds} ث)؛ فقُطعت."),
    "opaque_coding": ("{url} used the content-coding {coding}, which Kashif does not request; body checks did not run "
                      "on it.",
                      "استخدم {url} ترميز المحتوى {coding} الذي لا يطلبه كاشف؛ فلم تُجرَ فحوص المحتوى عليه."),
    "budget": ("The request budget of this profile ({limit}) was reached; the remaining checks were not tested.",
               "بلغ الفحص حدّ عدد الطلبات لهذا الملف ({limit})؛ فلم تُجرَ الفحوص المتبقية."),
    "time_budget": ("The scan's time budget ({limit} s) was reached; the result is partial.",
                    "بلغ الفحص حدّ الوقت المسموح ({limit} ث)؛ فالنتيجة جزئية."),
    "byte_budget": ("The scan's download budget ({limit} bytes) was reached; the result is partial.",
                    "بلغ الفحص حدّ حجم التنزيل ({limit} بايت)؛ فالنتيجة جزئية."),
    "proxied": ("Scanning through the proxy {proxy}; DNS checks are not tested and TLS is seen through the proxy.",
                "يمر الفحص عبر الوكيل {proxy}؛ فلم تُجرَ فحوص DNS، ويُرى TLS عبر الوكيل."),
}


def i18n_catalog() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """``(CATALOG, PATTERNS)`` Arabic → English for the event notes of this module (for i18n/cat_web2)."""
    from .rules import template_patterns
    patterns: list[tuple[str, str]] = []
    for en, ar in EVENTS.values():
        patterns += template_patterns(ar, en)
    return {}, patterns


# ----------------------------------------------------------------------------------------------- addresses

def ip_literal(host: str) -> str | None:
    """The canonical address when ``host`` is an IP literal (brackets and zone id allowed), else None."""
    h = normalise_host(host).split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        return None


def address_category(address: str) -> str:
    """metadata | loopback | link-local | private | reserved | public for one IP address (§0.1 SSRF guard)."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return "reserved"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if str(ip) in METADATA_ADDRESSES:
        return "metadata"
    if ip.is_loopback or ip.is_unspecified or (ip.version == 4 and ip in ipaddress.ip_network("0.0.0.0/8")):
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):   # carrier-grade NAT (shared address space)
        return "private"
    if ip.is_private and (ip.version == 6 and ip in ipaddress.ip_network("fc00::/7")
                          or ip.version == 4 and any(ip in ipaddress.ip_network(n)
                                                     for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))):
        return "private"
    if ip.is_multicast or ip.is_reserved or ip.is_private or not ip.is_global:
        return "reserved"
    return "public"


def _hook_category(category: str, public: bool) -> str:
    """The test hook may mark loopback addresses public; a metadata address stays metadata whatever it says."""
    return category if category == "metadata" or not public else "public"


def ssrf_allows(category: str, target_category: str, *, is_target: bool = False) -> bool:
    """§0.1: metadata never; public always; other categories only when the target is in the same category (the
    target host itself is always allowed, except metadata)."""
    if category == "metadata":
        return False
    if is_target or category == "public":
        return True
    return category == target_category


# ----------------------------------------------------------------------------------------------- test-only hooks

@dataclass(frozen=True)
class CorpusHooks:
    """Test-only resolver map and CA (spec §5.2), honoured only when ``KASHIF_TEST_RESOLVE=1``.

    Map format (bench/web/README.md): ``{"version": 1, "hosts": {name: {"status", "addresses", "public",
    "canonical", "aliases", "sequence"}}, "default": {...}, "tls": {"cafile", "publicly_trusted", "ct_required"}}``.
    Names missing from ``hosts`` use ``default`` (nxdomain when there is none), so no name ever leaves the machine."""
    resolve_map: dict | None = None
    cafile: str | None = None
    publicly_trusted: bool = False
    ct_required: bool = True

    @classmethod
    def from_env(cls, environ: dict | None = None, options: Any = None) -> "CorpusHooks | None":
        env = os.environ if environ is None else environ
        if env.get(ENV_HOOK) != "1":
            return None              # the other variables (and options._resolve/_cafile) are ignored
        rmap = getattr(options, "_resolve", None) if options is not None else None
        path = env.get(ENV_MAP)
        if rmap is None and path:
            with open(path, encoding="utf-8") as fh:
                rmap = json.load(fh)
        if rmap is not None:
            if not isinstance(rmap, dict) or not isinstance(rmap.get("hosts", {}), dict):
                raise ValueError(f"{ENV_MAP}: not a resolver map")
        tls = (rmap or {}).get("tls") or {}
        cafile = (getattr(options, "_cafile", None) if options is not None else None) or env.get(ENV_CAFILE) \
            or tls.get("cafile")
        return cls(resolve_map=rmap, cafile=cafile or None,
                   publicly_trusted=bool(tls.get("publicly_trusted", bool(cafile))),
                   ct_required=bool(tls.get("ct_required", True)))


# ----------------------------------------------------------------------------------------------- resolver

_EAI_NONAME = {c for c in (getattr(socket, "EAI_NONAME", None), 11001) if c is not None}          # 11001 WSAHOST_NOT_FOUND
_EAI_NODATA = {c for c in (getattr(socket, "EAI_NODATA", None), getattr(socket, "EAI_ADDRFAMILY", None), 11004)
               if c is not None} - _EAI_NONAME                                                     # 11004 WSANO_DATA
_EAI_AGAIN = {c for c in (getattr(socket, "EAI_AGAIN", None), 11002) if c is not None}             # 11002 WSATRY_AGAIN
_HOOK_ERRORS = {"nxdomain": (-2, "[Errno -2] Name or service not known"),
                "nodata": (-5, "[Errno -5] No address associated with hostname"),
                "tempfail": (-3, "[Errno -3] Temporary failure in name resolution")}


def gai_status(err: BaseException) -> str:
    """nxdomain | nodata | tempfail for a resolver exception (a timeout or unknown error is never 'nxdomain')."""
    code = getattr(err, "errno", None)
    if isinstance(err, socket.gaierror):
        if code in _EAI_NONAME:
            return "nxdomain"
        if code in _EAI_NODATA:
            return "nodata"
    return "tempfail"


@dataclass
class Resolution:
    record: DnsRecord
    public: bool = False             # the test hook marks these addresses public (address-category decisions)


class Resolver:
    """The OS resolver (``getaddrinfo`` + ``gethostbyname_ex`` for the canonical name), or the test hook map."""

    def __init__(self, hooks: CorpusHooks | None = None):
        self.hooks = hooks
        self._sequence: dict[str, int] = {}
        self._lock = threading.Lock()

    def resolve(self, host: str) -> Resolution:
        host = psl.normalise(host)
        reg = psl.registrable_domain(host) or ""
        lit = ip_literal(host)
        if lit:
            return Resolution(DnsRecord(host, "ok", (lit,), canonical=host, registrable=reg))
        if self.hooks is not None and self.hooks.resolve_map is not None:
            return self._hook(host, reg)
        return self._os(host, reg)

    def _hook(self, host: str, reg: str) -> Resolution:
        rmap = self.hooks.resolve_map if self.hooks else {}
        entry = (rmap.get("hosts") or {}).get(host)
        if entry is None:
            entry = rmap.get("default") or {"status": "nxdomain"}
        status = str(entry.get("status", "ok"))
        if status != "ok":
            errno_, msg = _HOOK_ERRORS.get(status, _HOOK_ERRORS["tempfail"])
            return Resolution(DnsRecord(host, status if status in _HOOK_ERRORS else "tempfail", registrable=reg,
                                        reason=msg, errno=errno_))
        addresses = entry.get("addresses") or ["127.0.0.1"]
        seq = entry.get("sequence")
        if seq:
            with self._lock:
                i = self._sequence.get(host, 0)
                self._sequence[host] = i + 1
            addresses = seq[min(i, len(seq) - 1)]
        addrs = tuple(str(a) for a in addresses)
        canonical = normalise_host(str(entry.get("canonical") or host))
        aliases = tuple(normalise_host(str(a)) for a in entry.get("aliases") or ())
        return Resolution(DnsRecord(host, "ok", addrs, canonical=canonical, aliases=aliases, registrable=reg),
                          public=bool(entry.get("public")))

    @staticmethod
    def _os(host: str, reg: str) -> Resolution:
        try:
            infos = socket.getaddrinfo(host, None, 0, socket.SOCK_STREAM)
        except socket.gaierror as e:
            return Resolution(DnsRecord(host, gai_status(e), registrable=reg, reason=str(e), errno=e.errno))
        except (OSError, UnicodeError, ValueError) as e:
            return Resolution(DnsRecord(host, "tempfail", registrable=reg, reason=str(e) or type(e).__name__,
                                        errno=getattr(e, "errno", None)))
        seen: dict[str, None] = {}
        for info in infos:
            seen.setdefault(str(info[4][0]), None)
        canonical, aliases = host, ()
        try:
            canon, alias_list, _addrs = socket.gethostbyname_ex(host)
            canonical = normalise_host(canon) or host
            aliases = tuple(normalise_host(a) for a in alias_list)
        except (OSError, UnicodeError, ValueError):
            pass                     # IPv6-only names: getaddrinfo answered; keep the queried name as canonical
        return Resolution(DnsRecord(host, "ok", tuple(seen), canonical=canonical, aliases=aliases, registrable=reg))


# ----------------------------------------------------------------------------------------------- proxies

@dataclass(frozen=True)
class Proxy:
    host: str
    port: int
    auth: str | None = None          # "Basic …" for Proxy-Authorization (from user:pass in the proxy URL)
    display: str = ""                # scheme://host:port without credentials (for notes)


def parse_proxy(value: str) -> Proxy | None:
    """A proxy URL as urllib accepts it (``http://[user:pass@]host[:port]`` or ``host:port``); None when unusable."""
    if not value:
        return None
    v = value.strip()
    if "://" not in v:
        v = "http://" + v
    p = urllib.parse.urlsplit(v)
    if p.scheme.lower() not in ("http", "https") or not p.hostname:
        return None
    try:
        port = p.port or (443 if p.scheme.lower() == "https" else 80)
    except ValueError:
        return None
    auth = None
    if p.username is not None:
        cred = f"{urllib.parse.unquote(p.username)}:{urllib.parse.unquote(p.password or '')}"
        auth = "Basic " + base64.b64encode(cred.encode("utf-8")).decode("ascii")
    host = normalise_host(p.hostname)
    shown = f"[{host}]" if ":" in host else host
    return Proxy(host, port, auth, f"http://{shown}:{port}")


# ----------------------------------------------------------------------------------------------- cookie jar

_COOKIE_MONTHS = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct",
                                              "nov", "dec"), start=1)}


def parse_cookie_date(value: str) -> float | None:
    """RFC 6265 §5.1.1 cookie-date → epoch seconds (None when unparsable)."""
    hms = day = month = year = None
    for tok in re.split(r"[\x09\x20-\x2f\x3b-\x40\x5b-\x60\x7b-\x7e]+", value):
        if not tok:
            continue
        if hms is None:
            m = re.fullmatch(r"(\d{1,2}):(\d{1,2}):(\d{1,2})\D*", tok)
            if m:
                hms = tuple(int(x) for x in m.groups())
                continue
        if day is None:
            m = re.fullmatch(r"(\d{1,2})\D*", tok)
            if m:
                day = int(m.group(1))
                continue
        if month is None and tok[:3].lower() in _COOKIE_MONTHS:
            month = _COOKIE_MONTHS[tok[:3].lower()]
            continue
        if year is None:
            m = re.fullmatch(r"(\d{2,4})\D*", tok)
            if m:
                year = int(m.group(1))
                year += 1900 if 70 <= year <= 99 else 2000 if year <= 69 else 0
                continue
    if None in (hms, day, month, year) or not (1 <= day <= 31) or year < 1601 or hms[0] > 23 or hms[1] > 59 or hms[2] > 59:
        return None
    try:
        return datetime(year, month, day, *hms, tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


@dataclass
class _Cookie:
    name: str
    value: str
    path: str
    secure: bool
    expires: float | None


class CookieJar:
    """In-memory per-scan cookie jar (§0.2): host-only (a cookie is only ever sent back to the exact host that set it,
    whatever its Domain attribute says), path-matched, Secure cookies only over https, never persisted. Values never
    leave this object except in the ``Cookie`` request header."""
    MAX_PER_HOST = 50
    MAX_SIZE = 4096

    def __init__(self, now: Callable[[], float] = time.time):
        self._now = now
        self._jar: dict[str, dict[tuple[str, str], _Cookie]] = {}
        self._lock = threading.Lock()

    def store(self, url: str, set_cookie_values: list[str]) -> None:
        p = urllib.parse.urlsplit(url)
        host = psl.normalise(p.hostname or "")
        if not host:
            return
        secure_origin = p.scheme.lower() == "https"
        default_path = _default_cookie_path(p.path)
        for raw in set_cookie_values:
            c = self._parse(raw, secure_origin, default_path)
            if c is None:
                continue
            with self._lock:
                bucket = self._jar.setdefault(host, {})
                key = (c.name, c.path)
                if c.expires is not None and c.expires <= self._now():
                    bucket.pop(key, None)          # deletion (Max-Age<=0 or Expires in the past)
                    continue
                if key not in bucket and len(bucket) >= self.MAX_PER_HOST:
                    continue
                bucket[key] = c

    def _parse(self, raw: str, secure_origin: bool, default_path: str) -> _Cookie | None:
        if len(raw) > self.MAX_SIZE:
            return None
        pair, _, attrs = raw.partition(";")
        name, eq, value = pair.partition("=")
        name, value = name.strip(" \t"), value.strip(" \t")
        if not eq or not name or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in name + value):
            return None
        path, secure, expires, max_age, has_domain = default_path, False, None, None, False
        for a in attrs.split(";"):
            k, _, v = a.partition("=")
            k, v = k.strip().lower(), v.strip()
            if k == "secure":
                secure = True
            elif k == "path":
                path = v if v.startswith("/") else default_path
            elif k == "domain":
                has_domain = bool(v)
            elif k == "max-age":
                if re.fullmatch(r"-?\d+", v):
                    max_age = int(v)
            elif k == "expires":
                exp = parse_cookie_date(v)
                if exp is not None:
                    expires = exp
        if max_age is not None:
            expires = self._now() + max_age if max_age > 0 else self._now() - 1
        if secure and not secure_origin:
            return None                        # RFC 6265bis: an insecure origin cannot set a Secure cookie
        low = name.lower()
        if (low.startswith("__secure-") or low.startswith("__host-")) and not (secure and secure_origin):
            return None                        # prefix rules: such a cookie is rejected by browsers
        if low.startswith("__host-") and (has_domain or path != "/"):
            return None
        return _Cookie(name, value, path, secure, expires)

    def header_for(self, url: str) -> str | None:
        p = urllib.parse.urlsplit(url)
        host = psl.normalise(p.hostname or "")
        https = p.scheme.lower() == "https"
        path = p.path or "/"
        now = self._now()
        with self._lock:
            bucket = self._jar.get(host) or {}
            for key in [k for k, c in bucket.items() if c.expires is not None and c.expires <= now]:
                bucket.pop(key, None)
            chosen = [c for c in bucket.values() if (https or not c.secure) and _path_match(path, c.path)]
        if not chosen:
            return None
        chosen.sort(key=lambda c: -len(c.path))
        return "; ".join(f"{c.name}={c.value}" for c in chosen)

    def names(self, host: str) -> list[str]:
        with self._lock:
            return sorted({c.name for c in (self._jar.get(psl.normalise(host)) or {}).values()})

    def signature(self, host: str) -> int:
        """Changes whenever the cookies of ``host`` change (redirect loop detection)."""
        with self._lock:
            items = sorted((c.name, c.path, c.value) for c in (self._jar.get(psl.normalise(host)) or {}).values())
        return hash(tuple(items))

    def clear(self) -> None:
        with self._lock:
            self._jar.clear()

    def __len__(self) -> int:
        with self._lock:
            return sum(len(b) for b in self._jar.values())


def _default_cookie_path(path: str) -> str:
    if not path or not path.startswith("/") or path.count("/") == 1:
        return "/"
    return path[: path.rfind("/")]


def _path_match(req: str, cookie_path: str) -> bool:
    if req == cookie_path:
        return True
    if req.startswith(cookie_path):
        return cookie_path.endswith("/") or req[len(cookie_path)] == "/"
    return False


def redact_cookie_request(value: str) -> str:
    """``a=1; b=xyz`` → ``a=<redacted:1 bytes>; b=<redacted:3 bytes>`` (request headers kept on Response)."""
    out = []
    for part in value.split(";"):
        n, eq, v = part.strip().partition("=")
        out.append(f"{n}=<redacted:{len(v.encode('utf-8', 'replace'))} bytes>" if eq else n)
    return "; ".join(out)


# ----------------------------------------------------------------------------------------------- limiter

class HostLimiter:
    """One request at a time per key (host) and a minimum gap between the requests to it (§4.3)."""

    def __init__(self, delay: float = 0.5, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        try:
            d = float(delay)
        except (TypeError, ValueError):
            d = MIN_DELAY
        self.delay = max(d if d == d else MIN_DELAY, MIN_DELAY)
        self._clock, self._sleep = clock, sleep
        self._last: dict[Any, float] = {}
        self._gap: dict[Any, float] = {}
        self._locks: dict[Any, threading.RLock] = {}
        self._guard = threading.Lock()

    def gap(self, key: Any) -> float:
        return self._gap.get(key, self.delay)

    def set_gap(self, key: Any, seconds: float) -> None:
        """Raise the gap of ``key`` (robots.txt Crawl-delay, capped at 10 s); never lowers it below ``delay``."""
        self._gap[key] = max(self.delay, min(float(seconds), MAX_CRAWL_DELAY))

    def lock(self, key: Any) -> threading.RLock:
        with self._guard:
            return self._locks.setdefault(key, threading.RLock())

    def wait_time(self, key: Any) -> float:
        last = self._last.get(key)
        if last is None:
            return 0.0
        return max(0.0, last + self.gap(key) - self._clock())

    def wait(self, key: Any) -> float:
        w = self.wait_time(key)
        if w > 0:
            self._sleep(w)
        return w

    def mark(self, key: Any) -> None:
        self._last[key] = self._clock()


# ----------------------------------------------------------------------------------------------- decoding

def content_codings(headers: HeaderList) -> list[str]:
    """Content-Encoding tokens in the order applied, lower-cased, without ``identity``."""
    out = []
    for v in headers.get_all("content-encoding"):
        for tok in v.split(","):
            t = tok.strip().lower()
            if t and t != "identity":
                out.append(t)
    return out


def decode_body(raw: bytes, codings: list[str], limit: int) -> tuple[bytes, bool, tuple[str, str] | None]:
    """Undo ``codings`` (gzip/x-gzip, deflate: zlib-wrapped first, raw fallback) with at most ``limit`` output bytes.

    Returns ``(body, truncated, problem)``; ``problem`` is ``("unsupported", coding)`` or ``("undecodable", coding)``
    and then ``body`` is empty: compressed bytes are never handed to body rules (§0.6)."""
    data, truncated = raw, False
    for coding in reversed(codings):
        if coding in ("gzip", "x-gzip"):
            attempts: tuple[int, ...] = (47, -15)        # gzip or zlib header (auto), raw deflate as a last resort
        elif coding == "deflate":
            attempts = (15, -15)                         # RFC 9110 says zlib; many servers send raw deflate
        else:
            return b"", False, ("unsupported", coding)
        out = None
        for wbits in attempts:
            d = zlib.decompressobj(wbits)
            try:
                out = d.decompress(data, limit + 1)
            except zlib.error:
                continue
            if not out and data:                         # nothing decodable (e.g. a bare header) → try the next form
                try:
                    out += d.flush(limit + 1)
                except zlib.error:
                    out = None
                    continue
            break
        if out is None:
            return b"", False, ("undecodable", coding)
        if len(out) > limit:
            out, truncated = out[:limit], True
        data = out
    return data, truncated, None


def parse_retry_after(value: str | None, now: datetime | None = None) -> float | None:
    """Seconds to wait from a Retry-After value (delta-seconds or HTTP-date), None when absent or invalid."""
    if not value:
        return None
    v = value.strip()
    if re.fullmatch(r"\d{1,10}", v):
        return float(int(v))
    try:
        when = email.utils.parsedate_to_datetime(v)
    except (TypeError, ValueError, IndexError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - (now or datetime.now(timezone.utc))).total_seconds())


_FOLD = re.compile(r"\r?\n[ \t]*")


def normalise_headers(pairs: list[tuple[str, str]]) -> tuple[tuple[tuple[str, str], ...], set[str]]:
    """Unfold obs-fold continuations (CRLF + whitespace → one space) and trim; returns the folded header names."""
    items, folded = [], set()
    for k, v in pairs:
        if "\n" in v or "\r" in v:
            v = _FOLD.sub(" ", v).replace("\r", " ").replace("\n", " ")
            folded.add(k.lower())
        items.append((k, v.strip(" \t")))
    return tuple(items), folded


# ----------------------------------------------------------------------------------------------- errors

class FetchRefused(OSError):
    """Raised by :meth:`Fetcher.open_tcp` when the guard, a budget or the profile forbids the connection."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class _Watchdog:
    """Closes the registered sockets when the per-response deadline passes (socket timeouts alone cannot bound a
    server that drips one byte per timeout, §0.6)."""

    def __init__(self, seconds: float):
        self.fired = False
        self._socks: list[socket.socket] = []
        self._lock = threading.Lock()
        self._timer = threading.Timer(max(0.0, seconds), self._fire)
        self._timer.daemon = True

    def start(self) -> "_Watchdog":
        self._timer.start()
        return self

    def add(self, sock: Any) -> None:
        if sock is None:
            return
        with self._lock:
            self._socks.append(sock)
            fired = self.fired
        if fired:
            _kill(sock)

    def _fire(self) -> None:
        with self._lock:
            self.fired = True
            socks = list(self._socks)
        for s in socks:
            _kill(s)

    def cancel(self) -> None:
        self._timer.cancel()


def _kill(sock: Any) -> None:
    try:
        socket.socket.shutdown(sock, socket.SHUT_RDWR)   # the plain-socket method also works on an SSLSocket
    except (OSError, ValueError, TypeError):
        pass


def _connect_factory(addresses: tuple[str, ...] | None, port_override: int | None,
                     on_socket: Callable[[socket.socket], None]):
    """A replacement for ``HTTPConnection._create_connection``: connects to the pinned addresses (never re-resolving
    the name, so DNS rebinding cannot change the address) and registers the socket with the current watchdog."""
    def create(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, *args, **kwargs):
        host, port = address[0], address[1]
        targets = list(addresses) if addresses else [host]
        last: OSError | None = None
        for a in targets:
            try:
                sock = socket.create_connection((a, port_override or port), timeout, source_address)
            except OSError as e:
                last = e
                continue
            on_socket(sock)
            return sock
        raise last or OSError("no address to connect to")
    return create


class _HTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection whose TLS socket is handed to the watchdog *before* the handshake, so a server that drips its
    handshake is cut by the per-response deadline too (the plain socket is detached by ``wrap_socket``)."""
    on_socket: Callable[[Any], None] | None = None

    def connect(self) -> None:
        http.client.HTTPConnection.connect(self)          # TCP through _create_connection (+ CONNECT tunnel)
        server_hostname = self._tunnel_host or self.host
        sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname, do_handshake_on_connect=False)
        self.sock = sock
        if self.on_socket is not None:
            self.on_socket(sock)
        sock.do_handshake()


# ----------------------------------------------------------------------------------------------- fetcher

@dataclass
class _Pin:
    addresses: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    record: DnsRecord | None = None
    error: str = ""


@dataclass
class _HostState:
    rate_limited: int = 0            # 429/503+Retry-After answers seen
    resets: int = 0                  # consecutive connection resets
    stopped: str = ""                # "rate_limited" | "reset" when no more requests go to the host


@dataclass
class _Prepared:
    url: str
    scheme: str
    host: str
    port: int
    target: str                      # request-target (origin-form)
    host_header: str


class Fetcher:
    """The single network gateway of a web scan (see the module docstring). Thread-safe; one per scan."""

    def __init__(self, options: ScanOptions | None = None, target: str = "", *, hooks: CorpusHooks | None = None,
                 resolver: Resolver | None = None, environ: dict | None = None, proxies: dict | None = None,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 wall: Callable[[], float] = time.time):
        self.options = options or ScanOptions()
        if self.options.profile not in PROFILES:
            raise ValueError(f"unknown profile {self.options.profile!r}")
        self.hooks = hooks if hooks is not None else CorpusHooks.from_env(environ, self.options)
        self.resolver = resolver or Resolver(self.hooks)
        self._clock, self._sleep = clock, sleep
        self._started = clock()
        self.limiter = HostLimiter(self.options.delay, clock, sleep)
        self.jar = CookieJar(wall)
        self.target = target
        self.target_host = psl.normalise(urllib.parse.urlsplit(target).hostname or "") if target else ""
        self._env_proxies = proxies is None
        self._proxies = self._load_proxies(proxies)
        self.requests = 0                # every request on the wire
        self.core_requests = 0           # counted against the profile budget
        self.crawl_requests = 0
        self.handshakes = 0              # TCP connections opened for tls/ (not HTTP requests)
        self.bytes_received = 0
        self.counts: dict[str, int] = {}
        self.dns: dict[str, DnsRecord] = {}
        self.cert_errors: dict[str, tuple[int | None, str]] = {}
        self.events: list[dict] = []
        self.robots: dict[str, Any] = {}         # origin → robots.Robots
        self._pins: dict[str, _Pin] = {}
        self._hosts: dict[str, _HostState] = {}
        self._pool: dict[tuple, http.client.HTTPConnection] = {}
        self._lock = threading.RLock()
        self._dns_counts = {"referenced": 0, "registrable": 0}
        self._event_once: set = set()
        self._confirmed: set[str] = set()
        self._tls_last: dict = {}
        self._target_category: str | None = None
        self._local = threading.local()
        if target and self.proxied:
            proxy = self.proxy_for(target)
            self._event("proxied", proxy=proxy.display if proxy else "")

    # -- configuration -----------------------------------------------------------------------------------------
    def _load_proxies(self, injected: dict | None) -> dict:
        if not self.options.use_proxy:
            return {}
        raw = injected if injected is not None else urllib.request.getproxies()
        out = {}
        for scheme in ("http", "https"):
            p = parse_proxy(raw.get(scheme, "")) if raw.get(scheme) else None
            if p is not None:
                out[scheme] = p
        if injected is not None and injected.get("no"):
            out["no"] = injected["no"]
        return out

    def proxy_for(self, url: str) -> Proxy | None:
        p = urllib.parse.urlsplit(url)
        scheme = p.scheme.lower()
        proxy = self._proxies.get(scheme)
        if proxy is None:
            return None
        host = p.hostname or ""
        try:
            hostport = f"{host}:{p.port}" if p.port else host
        except ValueError:
            hostport = host
        try:
            if self._env_proxies:
                bypass = urllib.request.proxy_bypass(hostport)
            else:
                bypass = urllib.request.proxy_bypass_environment(hostport, {"no": self._proxies.get("no", "")})
        except Exception:   # noqa: BLE001 - platform proxy configuration readers can fail in odd ways
            bypass = False
        return None if bypass else proxy

    @property
    def proxied(self) -> bool:
        """True when the scan target is fetched through a proxy (§0.7: DNS checks not_tested, TLS tentative)."""
        return bool(self.target) and self.proxy_for(self.target) is not None

    @property
    def budget(self) -> int:
        cap = PROFILE_BUDGETS[self.options.profile]
        if self.options.max_requests is not None:
            cap = max(0, int(self.options.max_requests))
        return cap

    @property
    def crawl_budget(self) -> int:
        return max(0, min(int(self.options.max_pages), CRAWL_HARD_CAP)) if self.options.crawl else 0

    def remaining_requests(self, source: str = "entry") -> int:
        if source == "crawl":
            return max(0, self.crawl_budget - self.crawl_requests)
        return max(0, self.budget - self.core_requests)

    def elapsed(self) -> float:
        return self._clock() - self._started

    def remaining_time(self) -> float:
        return max(0.0, float(self.options.time_budget) - self.elapsed())

    def host_stopped(self, host: str) -> str:
        st = self._hosts.get(psl.normalise(host))
        return st.stopped if st else ""

    # -- robots ------------------------------------------------------------------------------------------------
    def set_robots(self, origin_or_url: str, robots: Any) -> None:
        """Remember robots.txt for an origin; its Crawl-delay for Kashif raises that host's gap (≤ 10 s)."""
        p = urllib.parse.urlsplit(origin_or_url)
        origin = _origin(p)
        self.robots[origin] = robots
        delay = robots.crawl_delay() if robots is not None and hasattr(robots, "crawl_delay") else None
        if delay:
            self.limiter.set_gap(psl.normalise(p.hostname or ""), delay)

    def allowed_by_robots(self, url: str) -> bool:
        """Crawl permission (§4.3): True when robots are not respected, unknown for the origin, or allow the URL."""
        if not self.options.respect_robots:
            return True
        robots = self.robots.get(_origin(urllib.parse.urlsplit(url)))
        return True if robots is None else bool(robots.allowed(url))

    # -- events ------------------------------------------------------------------------------------------------
    def _event(self, code: str, once: Any = None, **params: Any) -> None:
        if once is not None:
            key = (code, once)
            if key in self._event_once:
                return
            self._event_once.add(key)
        en_t, ar_t = EVENTS[code]
        clean = {k: str(v) for k, v in params.items()}
        self.events.append({"code": code, **clean, "en": en_t.format(**clean), "ar": ar_t.format(**clean)})

    # -- address guard -----------------------------------------------------------------------------------------
    def _pin(self, host: str) -> _Pin:
        with self._lock:
            pin = self._pins.get(host)
        if pin is not None:
            return pin
        res = self.resolver.resolve(host)
        rec = res.record
        with self._lock:
            if host in self._pins:       # another thread pinned it meanwhile: first answer wins
                return self._pins[host]
            self.dns.setdefault(host, rec)
            if rec.status != "ok" or not rec.addresses:
                pin = _Pin(record=rec, error=rec.reason or f"name resolution failed: {rec.status}")
                if rec.status != "tempfail":
                    self._pins[host] = pin
                return pin
            cats = tuple(_hook_category(address_category(a), res.public) for a in rec.addresses)
            pin = _Pin(rec.addresses, cats, rec)
            self._pins[host] = pin
            return pin

    def target_category(self) -> str:
        """Address category of the scan target (public when it is reached through a proxy by name)."""
        if self._target_category is None:
            host = self.target_host
            lit = ip_literal(host) if host else None
            if lit:
                self._target_category = address_category(lit)
            elif not host or self.proxied:
                self._target_category = "public"
            else:
                pin = self._pin(host)
                self._target_category = pin.categories[0] if pin.categories else "public"
        return self._target_category

    def _guard(self, host: str, *, proxied: bool) -> tuple[tuple[str, ...] | None, str, str]:
        """``(addresses or None when proxied, refusal code, category)``; refusal code is "" when allowed (for "dns" the
        third item is the resolver's message)."""
        is_target = bool(self.target_host) and host == self.target_host
        lit = ip_literal(host)
        if proxied:
            if lit is None:
                return None, "", "public"
            cat = address_category(lit)
            if not ssrf_allows(cat, self.target_category(), is_target=is_target):
                return None, ("metadata" if cat == "metadata" else "ssrf"), cat
            return None, "", cat
        pin = self._pin(host)
        if pin.error:
            return (), "dns", pin.error
        tcat = self.target_category()
        allowed = tuple(a for a, c in zip(pin.addresses, pin.categories) if ssrf_allows(c, tcat, is_target=is_target))
        if not allowed:
            cat = "metadata" if "metadata" in pin.categories else pin.categories[0]
            return (), ("metadata" if cat == "metadata" else "ssrf"), cat
        return allowed, "", pin.categories[pin.addresses.index(allowed[0])]

    def guard_url(self, url: str) -> str:
        """"" when ``url`` may be requested, else the refusal code (scheme, bad_url, dns, ssrf, metadata)."""
        prep = _prepare(url)
        if isinstance(prep, str):
            return prep
        _addrs, code, _cat = self._guard(prep.host, proxied=self.proxy_for(prep.url) is not None)
        return code

    # -- DNS facts (ctx.dns) -------------------------------------------------------------------------------------
    def lookup(self, host: str, *, purpose: str = "referenced", confirm_missing: bool = False) -> DnsRecord:
        """Resolver status of ``host`` for ``ctx.dns`` (the OS resolver's normal lookup; §0.1 bounds: 30 referenced
        hosts, 10 registrable domains). ``confirm_missing`` repeats an nxdomain answer once, ≥ 2 s later (WEB517).
        Through a proxy every record is ``not_tested`` ("proxied")."""
        host = psl.normalise(host)
        reg = psl.registrable_domain(host) or ""
        if self.proxied:
            return DnsRecord(host, "not_tested", registrable=reg, reason="proxied")
        with self._lock:
            known = self.dns.get(host)
        if known is None or (known.status == "tempfail"):
            if purpose in self._dns_counts:
                cap = DNS_REFERENCED_CAP if purpose == "referenced" else DNS_REGISTRABLE_CAP
                if self._dns_counts[purpose] >= cap:
                    return DnsRecord(host, "not_tested", registrable=reg, reason="budget")
                self._dns_counts[purpose] += 1
            pin = self._pins.get(host)
            if pin is not None and pin.record is not None and pin.record.status == "ok":
                known = pin.record
            else:
                known = self._pin(host).record or DnsRecord(host, "tempfail", registrable=reg)
            with self._lock:
                self.dns[host] = known
        if confirm_missing and known.status == "nxdomain" and host not in self._confirmed:
            self._confirmed.add(host)
            self._sleep(NXDOMAIN_RECHECK)
            again = self.resolver.resolve(host).record
            if again.status != "nxdomain":
                known = again
                with self._lock:
                    self._pins.pop(host, None)
            with self._lock:
                self.dns[host] = known
        return known

    def lookup_registrable(self, host: str, *, purpose: str = "referenced") -> DnsRecord:
        """The record of ``host`` with ``registrable_status`` filled by one lookup of its registrable domain."""
        rec = self.lookup(host, purpose=purpose)
        if rec.status == "not_tested" or rec.registrable_status:
            return rec
        reg = rec.registrable or psl.registrable_domain(host) or ""
        if not reg:
            return rec
        if reg == rec.host:
            status = rec.status
        else:
            status = self.lookup(reg, purpose="registrable").status
        rec = dataclasses.replace(rec, registrable_status=status)
        with self._lock:
            self.dns[rec.host] = rec
        return rec

    # -- TLS support for tls/ ----------------------------------------------------------------------------------
    def tls_context(self, verified: bool = True) -> ssl.SSLContext:
        """Browser-parity verifying context (no X509_STRICT, CN-only certificates rejected, test CA from the hook) or
        an unverified one (CERT_NONE) for reading the leaf of a bad certificate."""
        if verified:
            ctx = ssl.create_default_context()
            if self.hooks is not None and self.hooks.cafile:
                ctx.load_verify_locations(cafile=self.hooks.cafile)
            strict = getattr(ssl, "VERIFY_X509_STRICT", 0)
            if strict:
                ctx.verify_flags &= ~strict
            try:
                ctx.hostname_checks_common_name = False
            except (AttributeError, ValueError):   # pragma: no cover - builds without the setting
                pass
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except (NotImplementedError, ssl.SSLError):   # pragma: no cover
            pass
        return ctx

    def addresses(self, host: str) -> tuple[str, ...]:
        """Pinned addresses of ``host`` the guard allows (empty when proxied, unresolvable or refused)."""
        host = psl.normalise(host)
        prep_proxied = self.proxy_for(f"https://{host}/") is not None
        if prep_proxied:
            return ()
        addrs, code, _cat = self._guard(host, proxied=False)
        return tuple(addrs or ()) if not code else ()

    def open_tcp(self, host: str, port: int, *, ip: str | None = None, timeout: float | None = None) -> socket.socket:
        """A connected TCP socket to ``host:port`` for tls/ (raw ClientHello probes and handshakes): the same SSRF guard,
        DNS pin and proxy (CONNECT tunnel) as HTTP requests, paced to ≤ 5 connections per second per address and
        within the scan's time budget. Raises :class:`FetchRefused` or ``OSError``."""
        host = psl.normalise(host)
        if self.remaining_time() <= 0:
            raise FetchRefused("time_budget", "time budget reached")
        timeout = float(timeout or self.options.timeout)
        proxy = self.proxy_for(f"https://{host}:{port}/")
        addrs, code, _cat = self._guard(host, proxied=proxy is not None)
        if code:
            raise FetchRefused(code, f"connection to {host} refused by the scanner's guard ({code})")
        if ip is not None:
            if proxy is not None or ip not in (addrs or ()):
                raise FetchRefused("ssrf", f"{ip} is not a pinned address of {host}")
            addrs = (ip,)
        key = ("tls", (addrs or (host,))[0])
        with self.limiter.lock(key):
            last = self._tls_last.get(key)
            gap = 0.0 if last is None else last + TLS_GAP - self._clock()
            if gap > 0:
                self._sleep(gap)
            self._tls_last[key] = self._clock()
            with self._lock:
                self.handshakes += 1
            if proxy is None:
                last_err: OSError | None = None
                for a in addrs or ():
                    try:
                        return socket.create_connection((a, port), timeout)
                    except OSError as e:
                        last_err = e
                raise last_err or OSError(f"no address for {host}")
            conn = http.client.HTTPConnection(proxy.host, proxy.port, timeout=timeout)
            conn.set_tunnel(host, port, headers=self._tunnel_headers(proxy))
            conn.connect()
            sock = conn.sock
            conn.sock = None
            return sock

    def _tunnel_headers(self, proxy: Proxy) -> dict:
        h = {"User-Agent": user_agent()}
        if proxy.auth:
            h["Proxy-Authorization"] = proxy.auth
        return h

    # -- fetching ----------------------------------------------------------------------------------------------
    def fetch(self, url: str, *, source: str = "entry", follow: bool = True, max_hops: int = MAX_HOPS,
              cookies: bool = True, origin: str | None = None, accept: str | None = None, cap: int | None = None,
              same_site_only: bool = False) -> Response:
        """GET ``url`` (following redirects like a browser unless ``follow`` is False) and return the final Response;
        earlier hops are in ``response.chain``. Never raises for network problems: failures come back as a Response
        with ``status=None``, ``error`` and an ``error:<code>`` flag.

        ``origin`` may only be :data:`CORS_PROBE_ORIGIN` (the CORS GET) and then no cookie is sent or stored.
        ``accept`` is ``"document"`` or ``"probe"`` (default by source). ``same_site_only`` (always on for the crawl)
        refuses redirects that leave the target's registrable domain."""
        if origin is not None and origin != CORS_PROBE_ORIGIN:
            raise ValueError("only the benign CORS probe Origin may be sent (§0.1)")
        if not self.target:              # the first URL fetched is the scan target (its category drives the guard)
            self.target = url
            self.target_host = psl.normalise(urllib.parse.urlsplit(url).hostname or "")
            self._target_category = None
        use_jar = cookies and origin is None
        accept_value = {"document": ACCEPT_DOCUMENT, "probe": ACCEPT_PROBE, None: None}.get(accept, "?")
        if accept_value == "?":
            raise ValueError("accept must be 'document' or 'probe'")
        if accept_value is None:
            accept_value = ACCEPT_DOCUMENT if source in DOCUMENT_SOURCES else ACCEPT_PROBE
        max_hops = max(1, min(int(max_hops), MAX_HOPS))
        same_site_only = same_site_only or source == "crawl"       # §4.3: the crawl never leaves the target's site
        if source == "crawl" and not self.allowed_by_robots(url):
            return self._error(safe_url(url), source, "robots", "disallowed by robots.txt")
        hops: list[Response] = []
        seen: set = set()
        current = url
        while True:
            prep = _prepare(current)
            seen.add((prep.url if isinstance(prep, _Prepared) else current,
                      self.jar.signature(prep.host) if use_jar and isinstance(prep, _Prepared) else 0))
            resp = self._hop(current, prep, source=source, use_jar=use_jar, origin=origin, accept=accept_value,
                             cap=cap)
            hops.append(resp)
            if use_jar and resp.status is not None:
                cookies_set = resp.headers.get_all("set-cookie")
                if cookies_set:
                    self.jar.store(resp.url, cookies_set)
            if not follow or resp.status not in REDIRECT_STATUSES or not resp.headers.has("location"):
                break
            nxt = next_url(resp.url, resp.headers.first("location") or "")
            stop = self._stop_reason(nxt, hops, max_hops, seen, use_jar, same_site_only, source)
            if stop:
                resp.flags = resp.flags | {stop}
                break
            current = nxt
        final = hops[-1]
        final.chain = hops[:-1]
        return final

    def _stop_reason(self, nxt: str | None, hops: list[Response], max_hops: int, seen: set, use_jar: bool,
                     same_site_only: bool, source: str) -> str:
        if nxt is None:
            return "redirect-blocked:bad-location"
        prep = _prepare(nxt)
        if prep == "scheme":
            self._event("scheme", once=nxt, url=safe_url(nxt)[:300])
            return "redirect-blocked:scheme"
        if isinstance(prep, str):
            return "redirect-blocked:bad-location"
        if len(hops) >= max_hops:
            return "redirect-limit"
        if (prep.url, self.jar.signature(prep.host) if use_jar else 0) in seen:
            return "redirect-loop"
        if same_site_only and self.target_host and not psl.same_site(prep.host, self.target_host):
            return "redirect-blocked:offsite"
        if source == "crawl" and not self.allowed_by_robots(prep.url):
            return "redirect-blocked:robots"
        _addrs, code, cat = self._guard(prep.host, proxied=self.proxy_for(prep.url) is not None)
        if code in ("ssrf", "metadata"):
            if code == "metadata":
                self._event("metadata", once=prep.url, url=prep.url[:300])
            else:
                self._event("ssrf", once=prep.url, url=prep.url[:300], category=cat)
            return f"redirect-blocked:{code}"
        if self._precheck(source, prep.host):
            return "redirect-blocked:budget"
        return ""

    def _error(self, url: str, source: str, code: str, message: str, *, request_headers: HeaderList | None = None,
               extra_flags: frozenset = frozenset(), elapsed: float = 0.0, ip: str | None = None) -> Response:
        return Response(url=url, status=None, error=message, source=source,
                        request_headers=request_headers or HeaderList(), elapsed=elapsed, ip=ip,
                        flags=frozenset({f"error:{code}"}) | extra_flags)

    def _precheck(self, source: str, host: str) -> tuple[str, str] | None:
        """A (code, message) refusal before anything is sent, or None."""
        if self.options.profile == "minimal" and source != "entry":
            return "profile", "not part of the minimal profile (one request chain)"
        st = self._hosts.get(host)
        if st is not None and st.stopped:
            return "host_stopped", f"no more requests to {host}: it {'rate-limited' if st.stopped == 'rate_limited' else 'reset'} the scan"
        if self.remaining_time() <= 0:
            self._event("time_budget", once="t", limit=f"{self.options.time_budget:g}")
            return "time_budget", "time budget reached"
        if self.bytes_received >= self.options.max_bytes:
            self._event("byte_budget", once="b", limit=self.options.max_bytes)
            return "byte_budget", "download budget reached"
        if self.remaining_requests(source) <= 0:
            if source != "crawl":
                self._event("budget", once="r", limit=self.budget)
            return "budget", "request budget reached"
        return None

    def _hop(self, url: str, prep: "_Prepared | str", *, source: str, use_jar: bool, origin: str | None,
             accept: str, cap: int | None) -> Response:
        """One request (plus at most one Retry-After retry and one transient retry) without following redirects."""
        if isinstance(prep, str):
            msg = "not an http(s) URL" if prep == "scheme" else "malformed URL"
            return self._error(safe_url(url), source, prep, msg)
        refused = self._precheck(source, prep.host)
        if refused:
            return self._error(prep.url, source, *refused)
        proxy = self.proxy_for(prep.url)
        addrs, code, cat = self._guard(prep.host, proxied=proxy is not None)
        if code:
            if code == "dns":
                return self._error(prep.url, source, "dns", cat or "name resolution failed")
            if code == "metadata":
                self._event("metadata", once=prep.url, url=prep.url[:300])
                return self._error(prep.url, source, "ssrf", "blocked: cloud-metadata address (scanner safety guard)")
            self._event("ssrf", once=prep.url, url=prep.url[:300], category=cat)
            return self._error(prep.url, source, "ssrf",
                               f"blocked: {cat} address not reachable from a {self.target_category()} target "
                               "(scanner safety guard)")
        state = self._hosts.setdefault(prep.host, _HostState())
        timeout = float(self.options.timeout)
        flags: set[str] = set()
        transient_retried = False
        waited = False
        lock = self.limiter.lock(prep.host)
        with lock:
            while True:
                refused = self._precheck(source, prep.host)
                if refused:
                    resp = self._error(prep.url, source, *refused)
                    break
                wait = self.limiter.wait_time(prep.host)
                if wait > self.remaining_time():
                    self._event("time_budget", once="t", limit=f"{self.options.time_budget:g}")
                    resp = self._error(prep.url, source, "time_budget", "time budget reached")
                    break
                if wait > 0:
                    self._sleep(wait)
                resp = self._send(prep, proxy, addrs, source=source, use_jar=use_jar, origin=origin, accept=accept,
                                  cap=cap, timeout=timeout)
                code = next((f[6:] for f in resp.flags if f.startswith("error:")), "")
                if code == "reset":
                    state.resets += 1
                    if state.resets >= RESET_STORM:
                        state.stopped = "reset"
                        self._event("reset_storm", once=prep.host, host=prep.host)
                elif resp.status is not None:
                    state.resets = 0
                if code in ("timeout", "reset") and not transient_retried and not state.stopped:
                    transient_retried = True
                    timeout *= 2
                    flags.add("retried")
                    continue
                if resp.status == 429 or (resp.status == 503 and resp.headers.has("retry-after")):
                    state.rate_limited += 1
                    flags.add("rate-limited")
                    if state.rate_limited == 1 and not waited:
                        ra = parse_retry_after(resp.headers.first("retry-after"))
                        seconds = min(ra if ra is not None else DEFAULT_RETRY_AFTER, MAX_RETRY_AFTER)
                        seconds = max(seconds, self.limiter.gap(prep.host))
                        if seconds < self.remaining_time():
                            self._event("retry_after", once=prep.host, host=prep.host, status=resp.status,
                                        seconds=(resp.headers.first("retry-after") or "-")[:40])
                            self._sleep(seconds)               # ≥ the gap since the last request
                            waited = True
                            flags.add("retry-after-waited")
                            continue
                    state.stopped = "rate_limited"
                    flags.add("host-stopped")
                    self._event("host_stopped", once=prep.host, host=prep.host)
                break
        if flags:
            resp.flags = resp.flags | flags
        return resp

    def _connection(self, prep: _Prepared, proxy: Proxy | None, addrs: tuple[str, ...] | None, verified: bool,
                    timeout: float) -> tuple[http.client.HTTPConnection, tuple, bool]:
        key = (prep.scheme, prep.host, prep.port, proxy.display if proxy else "", verified)
        with self._lock:
            conn = self._pool.pop(key, None)
        if conn is not None and conn.sock is not None:
            conn.timeout = timeout
            try:
                conn.sock.settimeout(timeout)
            except OSError:
                pass
            return conn, key, True
        if conn is not None:
            _close(conn)
        on_socket = self._register_socket
        https = prep.scheme == "https"
        if proxy is None:
            if https:
                conn = _HTTPSConnection(prep.host, prep.port, timeout=timeout, context=self.tls_context(verified))
                conn.on_socket = on_socket
            else:
                conn = http.client.HTTPConnection(prep.host, prep.port, timeout=timeout)
            conn._create_connection = _connect_factory(addrs, None, on_socket)
        else:
            if https:
                conn = _HTTPSConnection(proxy.host, proxy.port, timeout=timeout, context=self.tls_context(verified))
                conn.on_socket = on_socket
                conn.set_tunnel(prep.host, prep.port, headers=self._tunnel_headers(proxy))
            else:
                conn = http.client.HTTPConnection(proxy.host, proxy.port, timeout=timeout)
            conn._create_connection = _connect_factory(None, None, on_socket)
        return conn, key, False

    def _register_socket(self, sock: socket.socket) -> None:
        wd = getattr(self._local, "watchdog", None)
        if wd is not None:
            wd.add(sock)

    def _deadline(self) -> float:
        return max(0.05, min(float(self.options.response_deadline), self.remaining_time()))

    def _send(self, prep: _Prepared, proxy: Proxy | None, addrs: tuple[str, ...] | None, *, source: str,
              use_jar: bool, origin: str | None, accept: str, cap: int | None, timeout: float) -> Response:
        headers = {"User-Agent": user_agent(), "Accept": accept, "Accept-Encoding": ACCEPT_ENCODING,
                   "Accept-Language": ACCEPT_LANGUAGE}
        if origin:
            headers["Origin"] = origin
        cookie = self.jar.header_for(prep.url) if use_jar else None
        if cookie:
            headers["Cookie"] = cookie
        if proxy is not None and prep.scheme == "http" and proxy.auth:
            headers["Proxy-Authorization"] = proxy.auth
        recorded = [("Host", prep.host_header)] + [(k, redact_cookie_request(v) if k == "Cookie" else v)
                                                   for k, v in headers.items() if k != "Proxy-Authorization"]
        req_headers = HeaderList(tuple(recorded))
        base_flags: set[str] = {"proxied"} if proxy is not None else set()
        request_target = prep.url if (proxy is not None and prep.scheme == "http") else prep.target
        deadline_s = self._deadline()
        verified_failed = prep.host in self.cert_errors
        for attempt in range(3):     # stale pooled connection → one fresh retry; certificate error → unverified
            verified = not verified_failed
            conn, key, reused = self._connection(prep, proxy, addrs, verified, timeout)
            wd = _Watchdog(deadline_s).start()
            self._local.watchdog = wd
            t0 = self._clock()
            sent = False
            try:
                if conn.sock is None:
                    conn.connect()
                else:
                    wd.add(conn.sock)
                ip = None
                if proxy is None:
                    try:
                        ip = conn.sock.getpeername()[0]
                    except (OSError, AttributeError, IndexError):
                        ip = None
                conn.request("GET", request_target, headers=headers)
                sent = True
                self._count(source)
                self.limiter.mark(prep.host)
                resp = conn.getresponse()
                if wd.fired:             # the header block was cut by the deadline: never judge partial headers
                    raise TimeoutError("response deadline exceeded while reading the header block")
                result = self._read(conn, resp, prep, source, req_headers, cap, wd, t0, ip, base_flags)
                if not resp.isclosed() or resp.will_close or result.flags & {"incomplete-body", "deadline"}:
                    _close(conn)
                else:
                    with self._lock:
                        old = self._pool.pop(key, None)
                        self._pool[key] = conn
                    if old is not None and old is not conn:
                        _close(old)
                return result
            except ssl.SSLCertVerificationError as e:
                _close(conn)
                if sent or wd.fired:
                    return self._fail(e, prep, source, req_headers, wd, t0, base_flags)
                code_ = getattr(e, "verify_code", None)
                msg = getattr(e, "verify_message", "") or str(e)
                self.cert_errors[prep.host] = (code_, msg)
                self._event("cert_error", once=prep.host, host=prep.host, message=msg[:120])
                verified_failed = True
                continue
            except (http.client.RemoteDisconnected, BrokenPipeError, ConnectionResetError,
                    ConnectionAbortedError) as e:
                _close(conn)
                if reused and not wd.fired and attempt == 0:
                    continue             # an idle keep-alive connection the server had closed: retry on a new one
                return self._fail(e, prep, source, req_headers, wd, t0, base_flags)
            except (OSError, http.client.HTTPException, ValueError, ssl.SSLError) as e:
                _close(conn)
                return self._fail(e, prep, source, req_headers, wd, t0, base_flags)
            finally:
                wd.cancel()
                self._local.watchdog = None
        return self._error(prep.url, source, "network", "connection failed", request_headers=req_headers)

    def _fail(self, e: BaseException, prep: _Prepared, source: str, req_headers: HeaderList, wd: _Watchdog, t0: float,
              base_flags: set[str]) -> Response:
        code, msg = classify_error(e, deadline_fired=wd.fired, deadline=self._deadline())
        if code == "deadline":
            self._event("deadline", once=prep.url, url=prep.url[:300], seconds=f"{self._deadline():g}")
        extra = set(base_flags)
        if prep.host in self.cert_errors:
            c, _m = self.cert_errors[prep.host]
            extra |= {"cert-error", f"cert-verify:{c}"}
        return self._error(prep.url, source, code, msg, request_headers=req_headers, extra_flags=frozenset(extra),
                           elapsed=self._clock() - t0)

    def _count(self, source: str) -> None:
        with self._lock:
            self.requests += 1
            self.counts[source] = self.counts.get(source, 0) + 1
            if source == "crawl":
                self.crawl_requests += 1
            else:
                self.core_requests += 1

    def _read(self, conn: http.client.HTTPConnection, resp: http.client.HTTPResponse, prep: _Prepared, source: str,
              req_headers: HeaderList, cap: int | None, wd: _Watchdog, t0: float, ip: str | None,
              base_flags: set[str]) -> Response:
        flags = set(base_flags)
        items, folded = normalise_headers(resp.getheaders())
        if folded:
            flags.add("obs-fold")
            flags |= {f"obs-fold:{n}" for n in folded}
        header_bytes = sum(len(k) + len(v) + 4 for k, v in items) + len(resp.reason or "") + 15
        headers = HeaderList(items)
        if header_bytes > MAX_HEADER_BYTES:
            raise http.client.LineTooLong("header block larger than 64 KB")
        if prep.host in self.cert_errors:
            c, _m = self.cert_errors[prep.host]
            flags |= {"cert-error", f"cert-verify:{c}"}
        codings = content_codings(headers)
        limit = cap if cap is not None else _cap_for(source, headers)
        remaining_bytes = max(0, self.options.max_bytes - self.bytes_received - header_bytes)
        raw_limit = min(limit, remaining_bytes)
        chunks: list[bytes] = []
        got = 0
        raw_truncated = incomplete = False
        try:
            while True:
                if wd.fired:
                    break
                want = min(65536, raw_limit + 1 - got)
                if want <= 0:
                    raw_truncated = True
                    break
                chunk = resp.read1(want) if hasattr(resp, "read1") else resp.read(want)
                if not chunk:
                    break
                chunks.append(chunk)
                got += len(chunk)
        except http.client.IncompleteRead as e:
            if e.partial:
                chunks.append(bytes(e.partial))
                got += len(e.partial)
            incomplete = True
        except (OSError, ValueError, http.client.HTTPException, ssl.SSLError):
            incomplete = True
        raw = b"".join(chunks)
        if len(raw) > raw_limit:
            raw, raw_truncated = raw[:raw_limit], True
        if wd.fired:
            flags.add("deadline")
            self._event("deadline", once=prep.url, url=prep.url[:300], seconds=f"{self._deadline():g}")
        elif incomplete:
            flags.add("incomplete-body")
        with self._lock:
            self.bytes_received += len(raw) + header_bytes
        body, truncated = raw, raw_truncated or wd.fired or incomplete
        if codings:
            dec_limit = min(limit, max(DECOMPRESS_RATIO * len(raw), DECOMPRESS_FLOOR))
            body, dec_trunc, problem = decode_body(raw, codings, dec_limit)
            truncated = truncated or dec_trunc
            if problem is not None:
                kind, coding = problem
                if kind == "unsupported":
                    flags |= {"opaque-coding", f"opaque-coding:{coding}"}
                    self._event("opaque_coding", once=prep.url, url=prep.url[:300], coding=coding)
                else:
                    flags |= {"decode-error", "opaque-coding", f"opaque-coding:{coding}"}
                truncated = False
        if truncated and not ({"opaque-coding"} & flags):
            flags.add("truncated-body")
            if raw_truncated or (codings and len(body) >= limit):
                self._event("truncated", once=prep.url, url=prep.url[:300], cap=limit)
        version = {9: "HTTP/0.9", 10: "HTTP/1.0", 11: "HTTP/1.1"}.get(getattr(resp, "version", 11), "HTTP/1.1")
        return Response(url=prep.url, method="GET", status=resp.status, reason=resp.reason or "", http_version=version,
                        headers=headers, body=body, truncated=bool(truncated), encoding=", ".join(codings) or None,
                        request_headers=req_headers, elapsed=self._clock() - t0, ip=ip, error=None, source=source,
                        flags=frozenset(flags))

    # -- lifecycle ---------------------------------------------------------------------------------------------
    def close(self) -> None:
        with self._lock:
            conns = list(self._pool.values())
            self._pool.clear()
        for c in conns:
            _close(c)
        self.jar.clear()

    def __enter__(self) -> "Fetcher":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def stats(self) -> dict:
        return {"requests": self.requests, "core_requests": self.core_requests, "crawl_requests": self.crawl_requests,
                "by_source": dict(self.counts), "bytes": self.bytes_received, "handshakes": self.handshakes,
                "budget": self.budget, "proxied": self.proxied, "stopped_hosts": {h: s.stopped for h, s in
                                                                                   self._hosts.items() if s.stopped}}


# ----------------------------------------------------------------------------------------------- helpers

def _origin(p: urllib.parse.SplitResult) -> str:
    scheme = p.scheme.lower()
    host = psl.normalise(p.hostname or "")
    try:
        port = p.port
    except ValueError:
        port = None
    shown = f"[{host}]" if ":" in host else host
    if port is None or (scheme, port) in (("http", 80), ("https", 443)):
        return f"{scheme}://{shown}"
    return f"{scheme}://{shown}:{port}"


def _prepare(url: str) -> "_Prepared | str":
    """Canonical request data for ``url`` or an error code ("scheme", "bad_url"). User info is dropped, the URL is
    re-serialised with unsafe characters percent-encoded, and the fragment is removed."""
    try:
        p = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return "bad_url"
    scheme = p.scheme.lower()
    if scheme not in ("http", "https"):
        return "scheme"
    try:
        host = psl.normalise(p.hostname or "")
        port = p.port or (443 if scheme == "https" else 80)
    except (ValueError, UnicodeError):
        return "bad_url"
    if not host or any(ch in host for ch in " /\\@#?") or not (0 < port < 65536):
        return "bad_url"
    shown = f"[{host}]" if ":" in host else host
    default = (scheme, port) in (("http", 80), ("https", 443))
    netloc = shown if default else f"{shown}:{port}"
    path = p.path or "/"
    clean = safe_url(urllib.parse.urlunsplit((scheme, netloc, path, p.query, "")))
    q = urllib.parse.urlsplit(clean)
    target = (q.path or "/") + ("?" + q.query if q.query else "")
    if any(ord(ch) < 0x21 or ord(ch) > 0x7e for ch in target):
        return "bad_url"
    return _Prepared(clean, scheme, host, port, target, netloc)


def next_url(base: str, location: str) -> str | None:
    """The absolute URL a browser navigates to for ``Location: location`` (None when it cannot be parsed)."""
    loc = re.sub(r"[\t\n\r]", "", location.strip(" \t\n\r\f\x00"))
    if not loc:
        return None
    try:
        joined = urllib.parse.urljoin(base, loc)
        urllib.parse.urlsplit(joined).port      # noqa: B018 - raises ValueError for a bad port
    except ValueError:
        return None
    return urllib.parse.urldefrag(joined)[0]


def _cap_for(source: str, headers: HeaderList) -> int:
    cls = SOURCE_CLASS.get(source, "probe")
    if cls == "document":
        ct = (headers.first("content-type") or "").split(";", 1)[0].strip().lower()
        if "javascript" in ct or ct in ("text/css", "application/ecmascript", "text/ecmascript"):
            cls = "script"
    return CAPS[cls]


def _close(conn: Any) -> None:
    try:
        conn.close()
    except Exception:   # noqa: BLE001 - closing a half-dead connection must never raise
        pass


def classify_error(e: BaseException, *, deadline_fired: bool = False, deadline: float = 30.0) -> tuple[str, str]:
    """``(code, message)`` for a failed request; messages keep the OS wording that ``web.explain_failure`` reads."""
    if deadline_fired:
        return "deadline", f"response deadline exceeded ({deadline:g} s): the server kept the response open"
    text = str(e) or type(e).__name__
    if isinstance(e, http.client.HTTPException):
        if "more than" in text and "headers" in text:
            return "too_many_headers", f"{TOO_MANY_HEADERS} (more than {MAX_HEADER_LINES} header lines)"
        if isinstance(e, http.client.LineTooLong):
            return "header_too_large", f"header too large: {text}"
        if isinstance(e, http.client.RemoteDisconnected):
            return "reset", f"connection closed by the server: {text}"
        return "bad_response", f"malformed HTTP response: {text[:200]}"
    if isinstance(e, ssl.SSLCertVerificationError):
        return "tls", f"certificate verify failed: {getattr(e, 'verify_message', '') or text}"
    if isinstance(e, ssl.SSLError):
        return "tls", f"TLS (ssl) error: {text}"
    if isinstance(e, (socket.timeout, TimeoutError)):
        return "timeout", "timed out"
    if isinstance(e, ConnectionRefusedError):
        return "refused", text
    if isinstance(e, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return "reset", text
    if isinstance(e, socket.gaierror):
        return "dns", text
    if isinstance(e, OSError):
        if "tunnel connection failed" in text.lower():
            return "proxy", f"proxy refused the tunnel: {text}"
        unreachable = {getattr(errno, n, None) for n in ("ENETUNREACH", "EHOSTUNREACH")} | {10051, 10065}
        if e.errno in unreachable:
            return "unreachable", text
        return "network", text
    return "network", text


def error_code(response: Response | None) -> str:
    """The ``error:<code>`` of a response that was never received ("" otherwise)."""
    if response is None:
        return ""
    for f in response.flags:
        if f.startswith("error:"):
            return f[6:]
    return ""


def coverage_reason(response: Response | None) -> str | None:
    """coverage.REASONS code that explains why checks on ``response`` could not run (None when they can)."""
    if response is None:
        return "not_run"
    code = error_code(response)
    if code:
        return ERROR_CODES.get(code, "network")
    if "host-stopped" in response.flags or "rate-limited" in response.flags and response.status in (429, 503):
        return "rate_limited"
    if "opaque-coding" in response.flags:
        return "unsupported_coding"
    return None


__all__ = ["MIN_DELAY", "MAX_CRAWL_DELAY", "MAX_HOPS", "PROFILE_BUDGETS", "CRAWL_HARD_CAP", "CAPS", "SOURCE_CLASS",
           "METADATA_ADDRESSES", "ERROR_CODES", "EVENTS", "TOO_MANY_HEADERS", "CorpusHooks", "Resolver", "Resolution",
           "Proxy", "parse_proxy", "CookieJar", "parse_cookie_date", "HostLimiter", "FetchRefused", "Fetcher",
           "address_category", "ssrf_allows", "ip_literal", "gai_status", "content_codings", "decode_body",
           "parse_retry_after", "normalise_headers", "next_url", "classify_error", "error_code", "coverage_reason",
           "redact_cookie_request", "i18n_catalog"]
