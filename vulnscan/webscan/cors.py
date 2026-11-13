"""CORS from one benign Origin GET (spec §2.4), WP6.

Rules WEB320–WEB327. The engine sends one cookieless GET of the final entry URL with
``Origin: https://kashif-cors-check.invalid`` (RFC 6761 reserved; ``ctx.cors``). Kashif never sends ``Origin: null``,
look-alike origins or a preflight (``OPTIONS``): every verdict here reads responses the scan already has.

* Reflection rules (WEB320 credentialed, WEB321 without credentials, WEB324 missing ``Vary: Origin``) need a request
  that carried the probe Origin: the CORS response (and its redirect hops, which also carried it).
* Value rules (WEB322 ``null``, WEB323 ``*`` with credentials, WEB325 invalid value, WEB326 ``http://`` origin on https,
  WEB327 ``*`` on a response with session data) run on the probe and on the site's other final responses (the
  unprobed entry, crawled pages, same-site subresources and well-known files), because the value is a fact (G2).

Browser semantics (Fetch "CORS check"): one ``Access-Control-Allow-Origin`` field whose value is ``*``, ``null`` or a
serialised origin compared byte-for-byte with the request's Origin; credentials only with
``Access-Control-Allow-Credentials: true`` (exact, case-sensitive). Several ACAO fields are combined with ", " and the check
fails, so WEB325 replaces the other rules for that response.

Inputs: ``ctx.cookies`` (session/auth class of Set-Cookie facts, WP5), the ``sensitive`` flag (§WEB315, classify.py),
``ctx.dns`` / ``Response.ip`` (private targets raise WEB321 to medium). The module also writes the Observatory v6
``cross-origin-resource-sharing`` slug (Observatory sends an OPTIONS preflight; Kashif reads its GET probe with the same
algorithm).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from . import psl
from .rules import RULES, checks_for_module
from .types import CORS_PROBE_ORIGIN, Evidence, Issue, Response, ScanContext, strip_controls

CHECKS: tuple[str, ...] = checks_for_module("cors")

ACAO = "access-control-allow-origin"
ACAC = "access-control-allow-credentials"

STR: dict[str, tuple[str, str]] = {
    "reflected_creds": ("The response to Origin: {origin} allows that origin with credentials, so any website can read "
                        "this response with the visitor's cookies.",
                        "الاستجابة للطلب ذي Origin: {origin} تسمح لذلك الأصل مع الاعتماديات، فيستطيع أي موقع قراءة هذه "
                        "الاستجابة بكوكيز الزائر."),
    "reflected": ("The response to Origin: {origin} echoes that origin; any website can read it (without cookies).",
                  "الاستجابة للطلب ذي Origin: {origin} تعيد ذلك الأصل نفسه؛ فيستطيع أي موقع قراءتها (بلا كوكيز)."),
    "private_target": ("The target resolves to the private address {ip}: network position is the authentication here, "
                       "so a page on the visitor's browser can read intranet data.",
                       "يُحَلّ الهدف إلى العنوان الخاص {ip}: فموقع الشبكة هنا هو وسيلة المصادقة، وتستطيع صفحة في متصفح الزائر "
                       "قراءة بيانات الشبكة الداخلية."),
    "null": ("Access-Control-Allow-Origin: null is sent; sandboxed iframes and data: URLs of any site have the "
             "origin null.",
             "تُرسَل Access-Control-Allow-Origin: null؛ والإطارات المعزولة وعناوين data: من أي موقع لها الأصل null."),
    "null_creds": ("…together with Access-Control-Allow-Credentials: true.", "…مع Access-Control-Allow-Credentials: true."),
    "star_creds": ("Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true: browsers reject this "
                   "combination, which shows the policy is misconfigured.",
                   "القيمة Access-Control-Allow-Origin: * مع Access-Control-Allow-Credentials: true: ترفض المتصفحات هذه "
                   "التركيبة، وهذا يدل على خطأ في إعداد السياسة."),
    "no_vary": ("The origin is echoed but Vary is {vary}: a shared cache can store the answer for one origin and serve "
                "it to another.",
                "يُعاد الأصل لكن Vary هي {vary}: فيمكن لذاكرة مؤقتة مشتركة تخزين الإجابة لأصل وتقديمها لأصل آخر."),
    "vary_absent": ("absent", "غير موجودة"),
    "invalid_fields": ("Access-Control-Allow-Origin is sent in {count}: {value}. Browsers combine them and the CORS "
                       "check fails.",
                       "تُرسَل Access-Control-Allow-Origin في {count}: {value}. فيدمجها المتصفح ويفشل فحص CORS."),
    "invalid_value": ("Access-Control-Allow-Origin: {value} is not one origin; browsers accept only *, null or a single "
                      "origin.",
                      "القيمة Access-Control-Allow-Origin: {value} ليست أصلًا واحدًا؛ ولا يقبل المتصفح إلا * أو null أو "
                      "أصلًا واحدًا."),
    "http_origin": ("This HTTPS response trusts the plain-HTTP origin {value}, which a network attacker can impersonate.",
                    "تثق استجابة HTTPS هذه بالأصل غير المشفّر {value}، الذي يستطيع مهاجم على الشبكة انتحاله."),
    "star_session": ("Access-Control-Allow-Origin: * on a response that {why}.",
                     "القيمة Access-Control-Allow-Origin: * في استجابة {why}."),
    "why_cookie": ("sets the session cookie {cookie}", "تضبط كوكي الجلسة {cookie}"),
    "why_sensitive": ("carries sensitive data", "تحمل بيانات حساسة"),
}

_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
_FIELDS_FORMS = ("{n} field", "{n} fields", ("حقل واحد", "حقلين", "{n} حقول", "{n} حقلًا", "{n} حقل"))
_SESSIONISH = re.compile(r"sess|sid\b|^sid|auth|token|jwt|login|remember", re.I)


def _note(key: str, **values: Any) -> tuple[str, str]:
    en, ar = STR[key]

    def fill(text: str, lang: str) -> str:
        def sub(m: re.Match) -> str:
            v = values.get(m.group(1), m.group(0))
            if isinstance(v, tuple):
                v = v[1] if lang == "ar" else v[0]
            return strip_controls(str(v))
        return _PLACEHOLDER.sub(sub, text)
    return fill(en, "en"), fill(ar, "ar")


def _count(n: int, forms: tuple) -> tuple[str, str]:
    from ..i18n.plural import ar_count   # lazy: vulnscan.i18n imports webscan modules through cat_web2
    return (forms[0] if n == 1 else forms[1]).replace("{n}", str(n)), ar_count(n, forms[2])


def _short(value: str, limit: int = 160) -> str:
    v = " ".join(strip_controls(value).split())
    return v if len(v) <= limit else v[: limit - 1] + "…"


# ----------------------------------------------------------------------------------------------- facts

def acao_fields(r: Response) -> list[str]:
    return r.headers.get_all(ACAO)


def credentials(r: Response) -> bool:
    """``Access-Control-Allow-Credentials: true`` exactly as the Fetch standard requires (first field, trimmed)."""
    v = r.headers.first(ACAC)
    return v is not None and v.strip(" \t") == "true"


def invalid_acao(fields: list[str]) -> str:
    """Why an ACAO header can never pass the browser's CORS check ("" when it is one well-formed value)."""
    if len(fields) > 1:
        return "fields"
    v = fields[0].strip(" \t")
    if "," in v or " " in v or "\t" in v:
        return "value"
    return ""


def vary_has_origin(r: Response) -> tuple[bool, str]:
    values = [t.strip().lower() for v in r.headers.get_all("vary") for t in v.split(",") if t.strip()]
    return ("origin" in values or "*" in values), ", ".join(values)


def shared_storable(r: Response) -> bool:
    """False when no shared cache may store the response: ``Cache-Control`` no-store or private, or a ``Set-Cookie``
    without an explicit ``public`` (the §WEB324 guard)."""
    cc = {t.strip().split("=", 1)[0].strip().lower() for v in r.headers.get_all("cache-control") for t in v.split(",")}
    if "no-store" in cc or "private" in cc:
        return False
    if r.headers.has("set-cookie") and "public" not in cc:
        return False
    return True


def private_target(ctx: ScanContext) -> str:
    """The private (RFC 1918 / ULA / link-local) address the target resolves to, "" for public or loopback targets."""
    addrs: list[str] = []
    rec = ctx.dns.get(ctx.target_host) if ctx.dns else None
    if rec is not None and rec.status == "ok":
        addrs.extend(rec.addresses)
    if ctx.entry is not None and ctx.entry.ip:
        addrs.append(ctx.entry.ip)
    host = ctx.target_host
    try:
        ipaddress.ip_address(host)
        addrs.insert(0, host)
    except ValueError:
        pass
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a.split("%", 1)[0])
        except ValueError:
            continue
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if ip.is_loopback or ip.is_unspecified:
            continue
        if ip.is_private or ip.is_link_local:
            return str(ip)
    return ""


def _session_cookie(ctx: ScanContext, r: Response) -> str:
    facts = ctx.cookies_for(r)
    for c in facts:
        if c.is_session_class and not c.deletion and not c.ignored:
            return c.name
    if not ctx.cookies:          # stage 1 did not run (unit tests): a name-only fallback
        for v in r.headers.get_all("set-cookie"):
            name = v.split("=", 1)[0].strip()
            if name and _SESSIONISH.search(name):
                return name
    return ""


# ----------------------------------------------------------------------------------------------- the run

class _Run:
    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.issues: list[Issue] = []
        self.evaluated: dict[str, set[str]] = {}
        self.failed: dict[str, set[str]] = {}
        self.paranoid = ctx.options.sensitivity == "paranoid"
        self.own_sites = {psl.site(h) for h in (ctx.target_host, ctx.entry.host if ctx.entry else "") if h}
        self.blocked: dict[str, str] = {}
        if ctx.entry is not None and ctx.entry.kind in ("waf_challenge", "rate_limited"):
            reason = "waf" if ctx.entry.kind == "waf_challenge" else "rate_limited"
            for h in ctx.entry.hops():
                self.blocked[h.host] = reason
        self._emitted: set[tuple] = set()

    def own(self, r: Response) -> bool:
        return bool(r.host) and psl.site(r.host) in self.own_sites

    def seen(self, check: str, host: str) -> None:
        self.evaluated.setdefault(check, set()).add(host)

    def emit(self, rule: str, r: Response, value: str, *, severity: str | None = None, notes=None,
             group_value: str = "") -> None:
        meta = RULES[rule]
        key = (rule, r.url)
        if key in self._emitted:
            return
        self._emitted.add(key)
        conf = meta.confidence
        ev = Evidence.for_response(r, where="header", name="Access-Control-Allow-Origin", value=value, now=self.ctx.now)
        sev = severity if severity in meta.allowed_severities else None
        self.issues.append(Issue(rule=rule, url=r.url, confidence=conf, evidence=ev, severity=sev,
                                 group_value=group_value or _short(value, 80), notes=list(notes or []), host=r.host))
        self.seen(meta.check_id, r.host)
        if self.ctx.options.reports(conf):
            self.failed.setdefault(meta.check_id, set()).add(r.host)

    def record_coverage(self, probe_reason: str) -> None:
        cov = self.ctx.coverage
        if cov is None:
            return
        for check in CHECKS:
            hosts = self.evaluated.get(check, set())
            failed = self.failed.get(check, set())
            for host in sorted(hosts):
                (cov.failed if host in failed else cov.passed)(check, host)
            for host, reason in self.blocked.items():
                if host not in hosts:
                    cov.inconclusive(check, reason, host=host)
            if hosts or self.blocked:
                continue
            if RULES[check].paranoid_only and not self.paranoid:
                cov.not_tested(check, "sensitivity")
            elif check in _PROBE_CHECKS and probe_reason:
                cov.not_tested(check, probe_reason)
            else:
                cov.not_applicable(check)


_PROBE_CHECKS = ("WEB320", "WEB321", "WEB324")


def _responses(ctx: ScanContext, st: _Run) -> list[Response]:
    """The probe (and its hops) first, then the site's other final responses (value rules)."""
    out: list[Response] = []
    seen: set[int] = set()

    def add(r: Response | None) -> None:
        if r is None or id(r) in seen:
            return
        if r.status is None or r.error or not st.own(r) or r.host in st.blocked:
            return
        if r.kind in ("waf_challenge", "rate_limited"):
            return
        seen.add(id(r))
        out.append(r)

    if ctx.cors is not None:
        for h in ctx.cors.hops():
            add(h)
    for r in [ctx.entry, ctx.https_probe, ctx.http_probe] + [p.response for p in ctx.pages] + list(ctx.subresources) + \
            list(ctx.wellknown.values()):
        add(r)
    return out


def run(ctx: ScanContext) -> list[Issue]:
    st = _Run(ctx)
    probe_reason = ""
    if ctx.cors is None:
        probe_reason = "profile" if ctx.options.profile == "minimal" else "not_run"
    elif ctx.cors.status is None or ctx.cors.error:
        probe_reason = "network"
    private_ip = private_target(ctx)
    for r in _responses(ctx, st):
        probed = (r.request_headers.first("origin") or "") == CORS_PROBE_ORIGIN
        for c in CHECKS:
            if c in _PROBE_CHECKS and not probed:
                continue
            st.seen(c, r.host)
        fields = acao_fields(r)
        if not fields:
            continue
        creds = credentials(r)
        bad = invalid_acao(fields)
        if bad:
            joined = " | ".join(_short(f, 80) for f in fields)
            note = (_note("invalid_fields", count=_count(len(fields), _FIELDS_FORMS), value=joined) if bad == "fields"
                    else _note("invalid_value", value=_short(fields[0])))
            st.emit("WEB325", r, joined, notes=[note], group_value=bad)
            continue
        value = fields[0].strip(" \t")
        low = value.lower()
        if probed and value == CORS_PROBE_ORIGIN:
            if creds:
                st.emit("WEB320", r, value, notes=[_note("reflected_creds", origin=CORS_PROBE_ORIGIN)],
                        group_value="reflected+credentials")
            else:
                notes = [_note("reflected", origin=CORS_PROBE_ORIGIN)]
                sev = "low"
                if private_ip:
                    sev = "medium"
                    notes.append(_note("private_target", ip=private_ip))
                st.emit("WEB321", r, value, severity=sev, notes=notes, group_value="reflected")
            has_vary, vary = vary_has_origin(r)
            if not has_vary and shared_storable(r):
                st.emit("WEB324", r, value, notes=[_note("no_vary", vary=vary or _note("vary_absent"))],
                        group_value="no-vary")
        if low == "null":
            notes = [_note("null")] + ([_note("null_creds")] if creds else [])
            st.emit("WEB322", r, value, severity="high" if creds else "medium", notes=notes, group_value="null")
        elif value == "*":
            if creds:
                st.emit("WEB323", r, value, notes=[_note("star_creds")], group_value="*+credentials")
            cookie = _session_cookie(ctx, r)
            if cookie or "sensitive" in r.flags:
                why = _note("why_cookie", cookie=cookie) if cookie else _note("why_sensitive")
                st.emit("WEB327", r, value, notes=[_note("star_session", why=why)], group_value="*")
        elif low.startswith("http://") and r.is_https:
            st.emit("WEB326", r, value, notes=[_note("http_origin", value=_short(value))], group_value=low)
    st.record_coverage(probe_reason)
    slug = observatory_cors_slug(ctx.cors)
    if slug:
        ctx.observatory["cross-origin-resource-sharing"] = slug
    return st.issues


def observatory_cors_slug(probe: Response | None) -> str | None:
    """Observatory's ``cross-origin-resource-sharing`` result from the probe response (``None`` when not probed)."""
    if probe is None:
        return None
    if probe.status is None or probe.error:
        return "cross-origin-resource-sharing-not-implemented"
    acao = probe.headers.first(ACAO)
    if not acao:
        return "cross-origin-resource-sharing-not-implemented"
    data = acao[:256].strip().lower()
    origin = probe.request_headers.first("origin")
    acac = probe.headers.first(ACAC)
    if data == "*":
        return "cross-origin-resource-sharing-implemented-with-public-access"
    if origin and origin == acao and acac and acac.lower().strip() == "true":
        return "cross-origin-resource-sharing-implemented-with-universal-access"
    return "cross-origin-resource-sharing-implemented-with-restricted-access"


def i18n_catalog() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """``(CATALOG, PATTERNS)`` for cat_web2: fixed Arabic notes → English, and regex patterns for templated ones."""
    catalog: dict[str, str] = {}
    patterns: list[tuple[str, str]] = []
    for en, ar in STR.values():
        if "{" not in ar:
            catalog[ar] = en
            continue
        names: list[str] = []
        out, pos = [], 0
        for m in _PLACEHOLDER.finditer(ar):
            out.append(re.escape(ar[pos:m.start()]))
            if m.group(1) in names:
                out.append(f"(?P={m.group(1)})")
            else:
                out.append(f"(?P<{m.group(1)}>.+?)")
                names.append(m.group(1))
            pos = m.end()
        out.append(re.escape(ar[pos:]))
        patterns.append(("^" + "".join(out) + "$", _PLACEHOLDER.sub(lambda m: f"\\g<{m.group(1)}>", en)))
    return catalog, patterns


__all__ = ["CHECKS", "run", "acao_fields", "credentials", "invalid_acao", "vary_has_origin", "shared_storable",
           "private_target", "observatory_cors_slug", "STR", "i18n_catalog"]
