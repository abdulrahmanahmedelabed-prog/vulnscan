"""Cross-page grouping, dedupe, cross-rule suppression and cross-module adjustments (spec §3.5, stage 3, WP13).

The engine calls :func:`process` once, after every check module ran::

    result = group.process(issues, ctx)          # GroupResult
    for g in result.groups:                       # what the report shows (sensitivity applied)
        finding.extra.update(g.extra())           # instances, examples, pages, page_count, systemic, fp_key …
    grade.grades(ctx, result.all_groups(), …)     # the grade counts every group (§3.4 has its own confidence weights)

Steps (in this order):

1. **Adjustments** (:func:`adjust`): the cross-module escalations that need another module's results — WEB304 from
   WEB510/WEB511 evidence, WEB114 from cookie ``Domain`` facts (``ctx.cookies``). Issues are copied, never mutated.
2. **Suppression** (:func:`suppress`): one cause, one finding (the pairs of §3.5). Suppressed issues are kept in
   ``GroupResult.suppressed`` with a reason code (bilingual text in :data:`STR`), so a report can say why.
3. **Grouping** (:func:`group_issues`): one group per (rule, host, response kind, normalised value). ``fp_key`` is
   ``rule|host|kind|value`` with no counts, dates, nonces or URLs beyond the template, so it survives reruns.
4. **Sensitivity** (§3.6, applied after grouping): a group whose instances are all below the sensitivity is hidden;
   otherwise only its reported instances are shown.

Also here: URL templates (:func:`url_template`) and the crawl helper :class:`CrawlPlanner` (≤ 3 URLs per template,
near-duplicate skip), which engine.py uses during step 5 of §4.3. Pure functions; no network, no file system.
"""

from __future__ import annotations

import dataclasses
import hashlib
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from .rules import RULES, SEVERITIES
from .types import CONFIDENCES, SENSITIVITY_CONFIDENCES, SESSION_CLASSES, Issue, normalise_host, url_origin

SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}        # 0 = critical
CONF_RANK = {c: i for i, c in enumerate(CONFIDENCES)}      # 0 = certain
MAX_EXAMPLES = 5
SYSTEMIC_SHARE = 0.8
SYSTEMIC_MIN_RESPONSES = 2
TEMPLATE_CAP = 3

# bilingual texts (English, Arabic) shown with suppressed issues and adjustment notes
STR: dict[str, tuple[str, str]] = {
    "by_web000": ("explained by WEB000: the whole origin is served over plain HTTP",
                  "يفسّره WEB000: الموقع كله يُقدَّم عبر HTTP غير مشفّر"),
    "by_web704": ("explained by WEB704 on the same address (SSLv2/SSLv3 is the larger problem)",  # nosec - protocol name
                  "يفسّره WEB704 على العنوان نفسه (قبول SSLv2/SSLv3 هو المشكلة الأكبر)"),  # nosec - protocol name
    "by_web200": ("judged inside WEB200: the policy is report-only and enforces nothing",
                  "قُيّم ضمن WEB200: السياسة في وضع التقرير فقط ولا تفرض شيئًا"),
    "by_cert": ("HSTS is not judged on a host whose certificate is expired or invalid (WEB070/WEB072)",
                "لا يُقيَّم HSTS على مضيف شهادته منتهية أو غير صالحة (WEB070/WEB072)"),
    "by_framing": ("explained by a more specific framing finding (WEB206, WEB300 or WEB301)",
                   "يفسّره اكتشاف أدق عن التضمين (WEB206 أو WEB300 أو WEB301)"),
    "by_hsts_value": ("replaced by WEB110/WEB112 for the same response", "استُبدل بـ WEB110/WEB112 للاستجابة نفسها"),
    "by_web117": ("judged by WEB117 (an HTTPS hop that redirects to another host)",
                  "يقيّمه WEB117 (قفزة HTTPS توجّه إلى مضيف آخر)"),
    "by_web050": ("explained by WEB050 for the same element (mixed content)", "يفسّره WEB050 للعنصر نفسه (محتوى مختلط)"),
    "by_non_script": ("this policy does not restrict scripts (reported once as WEB042)",
                      "هذه السياسة لا تقيّد السكربتات (أُبلغ عنها مرة واحدة في WEB042)"),
    "esc_web304": ("raised to medium: crawled same-site URLs carry session or token parameters (WEB510/WEB511), and this "
                   "policy sends the full URL to other sites",
                   "رُفعت إلى متوسطة: روابط الموقع المزحوف تحمل معرّفات جلسة أو رموزًا (WEB510/WEB511)، وهذه السياسة ترسل "
                   "الرابط كاملًا إلى المواقع الأخرى"),
    "esc_web114": ("raised to low: the session cookie {cookie} is scoped to Domain={domain}, so a subdomain without HTTPS "
                   "can receive it", "رُفعت إلى منخفضة: كوكي الجلسة {cookie} مقيّد بالنطاق Domain={domain}، فيمكن أن يستقبله "
                   "نطاق فرعي بلا HTTPS"),
    "systemic": ("systemic: seen on {share}% of the fetched responses of this kind", "منهجي: ظهر في {share}% من الاستجابات "
                 "المجلوبة من هذا النوع"),
}

# §3.5 suppression pairs: suppressed rule → (suppressor rules, scope, reason)
#   scope "url" = same Issue.url, "origin" = same scheme+host+port, "host" = same host, "ip" = same host and IP set
_HSTS_RULES = ("WEB-strict-transport-security",) + tuple(f"WEB{n}" for n in range(110, 118))
_CSP_REPORT_ONLY = ("WEB040", "WEB041", "WEB042", "WEB043") + tuple(f"WEB{n}" for n in range(201, 220))
_NON_SCRIPT_SUPPRESSED = ("WEB040", "WEB043", "WEB204", "WEB209", "WEB218")
# WEB304 policies that send the full URL (path and query) to other sites over https
_FULL_URL_POLICIES = ("no-referrer-when-downgrade", "unsafe-url")


def t(key: str, lang: str = "en", **params: Any) -> str:
    en, ar = STR[key]
    text = ar if lang == "ar" else en
    return text.format(**params) if params else text


def note(key: str, **params: Any) -> tuple[str, str]:
    return t(key, "en", **params), t(key, "ar", **params)


# ----------------------------------------------------------------------------------------------- normalisation

_UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_SEG_ID = re.compile(
    r"^(?:\d+|" + _UUID + r"|[0-9a-fA-F]{16,}|(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{22,}={0,2}|"
    r"\d{4}-\d{2}-\d{2}|\d{8}|[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)*[-_]\d+)$")
_V_NONCE = re.compile(r"(?i)('nonce-)[^'\s]*(')|(\bnonce\s*=\s*[\"']?)[A-Za-z0-9+/=_-]+")
_V_UUID = re.compile(_UUID)
_V_ISO = re.compile(r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?\b")
_V_HTTPDATE = re.compile(r"(?i)\b(?:mon|tue|wed|thu|fri|sat|sun)[a-z]*,?\s+\d{1,2}[ -](?:jan|feb|mar|apr|may|jun|jul|aug|"
                         r"sep|oct|nov|dec)[a-z]*[ -]\d{2,4}\s+\d{2}:\d{2}:\d{2}(?:\s*(?:gmt|utc|[+-]\d{4}))?")
_V_HEX = re.compile(r"\b[0-9a-fA-F]{16,}\b")
_V_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_.-])(?=[A-Za-z0-9+/_-]*[0-9])(?=[A-Za-z0-9+/_-]*[A-Za-z])"
                      r"[A-Za-z0-9+/_-]{22,}={0,2}(?![A-Za-z0-9+/_.-])")
_V_NUM = re.compile(r"(?<![\d.])\d{5,}(?![\d.])")
_V_SPACE = re.compile(r"\s+")
VALUE_CAP = 120


def normalise_value(value: str | None) -> str:
    """The §3.5 group value: nonces, UUIDs, dates, long hex, token-like strings and long numbers replaced by
    placeholders, whitespace collapsed. Versions (``jquery@3.6.0``) and short numbers are kept."""
    if not value:
        return ""
    v = _V_SPACE.sub(" ", str(value)).strip()
    v = _V_NONCE.sub(lambda m: f"{m.group(1)}{{nonce}}{m.group(2)}" if m.group(1) else f"{m.group(3)}{{nonce}}", v)
    v = _V_UUID.sub("{uuid}", v)
    v = _V_HTTPDATE.sub("{date}", v)
    v = _V_ISO.sub("{date}", v)
    v = _V_HEX.sub("{hex}", v)
    v = _V_TOKEN.sub("{token}", v)
    v = _V_NUM.sub("{n}", v)
    return v


def _cap_key(value: str) -> str:
    if len(value) <= VALUE_CAP:
        return value
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]
    return f"{value[:80]}…#{digest}"


def _segment(seg: str) -> str:
    raw = urllib.parse.unquote(seg)
    return "{id}" if raw and _SEG_ID.match(raw) else seg


def url_template(url: str) -> str:
    """``https://h/blog/2026-11-12/my-post-123?id=7&q=x#top`` → ``https://h/blog/{id}/{id}?id={v}&q={v}``.

    Path segments that are all digits, UUIDs, hex ≥ 16, base64url ≥ 22, dates or slugs with a trailing numeric id
    become ``{id}``; query values become ``{v}``; the fragment is dropped; scheme and host are lower-cased and the default
    port is omitted."""
    try:
        p = urllib.parse.urlsplit(url)
        origin = url_origin(url)
    except ValueError:
        return url
    path = "/".join(_segment(s) for s in (p.path or "/").split("/"))
    out = origin + path
    if p.query:
        keys = []
        for part in p.query.split("&"):
            if not part:
                continue
            k = part.split("=", 1)[0]
            keys.append(f"{k}={{v}}" if "=" in part else k)
        if keys:
            out += "?" + "&".join(keys)
    return out


# ----------------------------------------------------------------------------------------------- crawl helper

class CrawlPlanner:
    """Crawl dedupe of §3.5: at most ``per_template`` URLs per URL template, and documents whose simhash is within
    ``distance`` of an earlier one are skipped (the first is kept). Used by engine.py during the crawl."""

    def __init__(self, per_template: int = TEMPLATE_CAP, distance: int = 3):
        self.per_template = per_template
        self.distance = distance
        self._counts: dict[str, int] = {}
        self._hashes: list[int] = []

    def allow(self, url: str) -> bool:
        """True (and counted) when the URL's template has been visited fewer than ``per_template`` times."""
        key = url_template(url)
        n = self._counts.get(key, 0)
        if n >= self.per_template:
            return False
        self._counts[key] = n + 1
        return True

    def near_duplicate(self, simhash_value: int | None) -> bool:
        """True when a document with a near-identical simhash was seen before; otherwise remembers this one."""
        if simhash_value is None:
            return False
        for h in self._hashes:
            if bin((h ^ simhash_value) & 0xFFFFFFFFFFFFFFFF).count("1") <= self.distance:
                return True
        self._hashes.append(simhash_value)
        return False

    def templates(self) -> dict[str, int]:
        return dict(self._counts)


# ----------------------------------------------------------------------------------------------- helpers

def issue_host(issue: Issue) -> str:
    if issue.host:
        h = issue.host
        if h.count(":") == 1 and h.rsplit(":", 1)[1].isdigit():   # "host:port" (TLS issues of a non-default port)
            h = h.rsplit(":", 1)[0]
        return normalise_host(h)
    try:
        return normalise_host(urllib.parse.urlsplit(issue.url).hostname or "")
    except ValueError:
        return ""


def severity_of(issue: Issue) -> str:
    return issue.severity or RULES[issue.rule].severity


def _origin(url: str) -> str:
    try:
        return url_origin(url)
    except ValueError:
        return url


def _match_value(issue: Issue) -> str:
    m = issue.evidence.match if issue.evidence is not None else None
    if not m:
        return ""
    return f"{m.get('name') or ''}={m.get('value') or ''}" if m.get("name") or m.get("value") else ""


def _evidence_header(issue: Issue) -> str:
    m = issue.evidence.match if issue.evidence is not None else None
    return str((m or {}).get("name") or "").lower()


def _kind(issue: Issue) -> str:
    return (issue.evidence.kind if issue.evidence is not None else "") or ""


def _roles(issue: Issue) -> frozenset[str]:
    return frozenset(issue.evidence.role if issue.evidence is not None else ())


def _reported(issue: Issue, sensitivity: str | None) -> bool:
    if sensitivity is None:
        return True
    return issue.confidence in SENSITIVITY_CONFIDENCES.get(sensitivity, SENSITIVITY_CONFIDENCES["default"])


def _entry_urls(ctx: Any) -> set[str]:
    out: set[str] = set()
    entry = getattr(ctx, "entry", None) if ctx is not None else None
    if entry is not None:
        out.add(entry.url)
        for h in entry.chain:
            out.add(h.url)
    target = getattr(ctx, "target", None) if ctx is not None else None
    if target:
        out.add(target)
    return out


# ----------------------------------------------------------------------------------------------- adjustments

def adjust(issues: Sequence[Issue], ctx: Any = None) -> list[Issue]:
    """Cross-module adjustments of §3.5 (copies, never mutates): WEB304 low → medium when same-site URLs carry
    session/token parameters (WEB510/WEB511) and the policy sends full URLs to other sites; WEB114 info → low when a
    session/auth cookie has ``Domain=`` of a parent domain (``ctx.cookies``)."""
    token_hosts = {_site(issue_host(i)) for i in issues if i.rule in ("WEB510", "WEB511")}
    out: list[Issue] = []
    for i in issues:
        if i.rule == "WEB304" and token_hosts and severity_of(i) == "low" and _site(issue_host(i)) in token_hosts:
            policy = str((i.params or {}).get("policy") or i.group_value or "").lower()
            if policy in _FULL_URL_POLICIES:
                i = dataclasses.replace(i, severity="medium", notes=list(i.notes) + [note("esc_web304")])
        elif i.rule == "WEB114" and severity_of(i) == "info" and ctx is not None:
            cookie = _parent_domain_session_cookie(ctx, issue_host(i))
            if cookie is not None:
                i = dataclasses.replace(i, severity="low", notes=list(i.notes) + [
                    note("esc_web114", cookie=cookie[0], domain=cookie[1])])
        out.append(i)
    return out


def _site(host: str) -> str:
    try:
        from .psl import registrable_domain
        return registrable_domain(host) or host
    except Exception:   # noqa: BLE001 - PSL data missing: fall back to the host itself
        return host


def _parent_domain_session_cookie(ctx: Any, host: str) -> tuple[str, str] | None:
    for c in getattr(ctx, "cookies", None) or ():
        if getattr(c, "deletion", False) or getattr(c, "ignored", False) or c.cls not in SESSION_CLASSES:
            continue
        dom = (c.domain or "").lstrip(".").lower()
        if dom and dom != host and host.endswith("." + dom):
            return c.name, dom
    return None


# ----------------------------------------------------------------------------------------------- suppression

def suppress(issues: Sequence[Issue], ctx: Any = None, sensitivity: str | None = None
             ) -> tuple[list[Issue], list[tuple[Issue, str]]]:
    """Cross-rule suppression of §3.5. Returns ``(kept, [(suppressed issue, reason key)])``. A suppressor counts only
    when it is itself reported at ``sensitivity`` (a hidden finding never hides a shown one)."""
    sup = [i for i in issues if _reported(i, sensitivity)]
    by_rule: dict[str, list[Issue]] = {}
    for i in sup:
        by_rule.setdefault(i.rule, []).append(i)

    def urls(*rules: str) -> set[str]:
        return {i.url for r in rules for i in by_rule.get(r, ())}

    web000_origins = {_origin(i.url) for i in by_rule.get("WEB000", ()) if severity_of(i) != "info"}
    web704 = [(issue_host(i), frozenset(i.ips)) for i in by_rule.get("WEB704", ())]
    web200_urls = urls("WEB200")
    cert_hosts = {issue_host(i) for r in ("WEB070", "WEB072") for i in by_rule.get(r, ())}
    framing_urls = urls("WEB206", "WEB300", "WEB301")
    hsts_value_urls = urls("WEB110", "WEB112")
    web117_urls = urls("WEB117")
    web050 = {(i.url, _element_url(i)) for i in by_rule.get("WEB050", ())}
    non_script_urls = {i.url for i in by_rule.get("WEB042", ()) if (i.params or {}).get("variant") == "non_script"}

    kept: list[Issue] = []
    dropped: list[tuple[Issue, str]] = []
    for i in issues:
        reason = None
        r = i.rule
        if r in ("WEB052", "WEB504") and _origin(i.url) in web000_origins:
            reason = "by_web000"
        elif r == "WEB030" and any(h == issue_host(i) and (not ips or not i.ips or set(i.ips) <= ips)
                                   for h, ips in web704):
            reason = "by_web704"
        elif r in _CSP_REPORT_ONLY and i.url in web200_urls and "report-only" in _evidence_header(i):
            reason = "by_web200"
        elif r in _HSTS_RULES and issue_host(i) in cert_hosts:
            reason = "by_cert"
        elif r == "WEB-x-frame-options" and i.url in framing_urls:
            reason = "by_framing"
        elif r == "WEB-strict-transport-security" and i.url in hsts_value_urls:
            reason = "by_hsts_value"
        elif r == "WEB-strict-transport-security" and i.url in web117_urls:
            reason = "by_web117"
        elif r == "WEB502" and (i.url, _element_url(i)) in web050:
            reason = "by_web050"
        elif r in _NON_SCRIPT_SUPPRESSED and i.url in non_script_urls:
            reason = "by_non_script"
        if reason:
            dropped.append((i, reason))
        else:
            kept.append(i)
    return kept, dropped


def _element_url(issue: Issue) -> str:
    m = issue.evidence.match if issue.evidence is not None else None
    v = str((m or {}).get("value") or "")
    return v.split("#", 1)[0]


# ----------------------------------------------------------------------------------------------- grouping

@dataclass
class Group:
    """One reported finding: every instance of one issue across pages (§3.5)."""
    rule: str
    host: str
    kind: str
    value: str                                  # normalised group value
    issues: list[Issue] = field(default_factory=list)
    systemic: bool = False
    share: float = 0.0                          # instances / fetched responses of this kind on this host
    entry_urls: frozenset[str] = frozenset()

    # -- identity --------------------------------------------------------------------------------------------
    @property
    def key(self) -> tuple[str, str, str, str]:
        return self.rule, self.host, self.kind, self.value

    @property
    def fp_key(self) -> str:
        """``rule|host|kind|value``: no counts, dates, nonces or URLs beyond the template (stable across reruns)."""
        return "|".join((self.rule, self.host, self.kind, _cap_key(self.value)))

    # -- representative values -------------------------------------------------------------------------------
    @property
    def issue(self) -> Issue:
        """The representative instance: most severe, then most certain, then the entry document, then first seen."""
        return min(self.issues, key=lambda i: (SEV_RANK[severity_of(i)], CONF_RANK.get(i.confidence, 9),
                                               0 if i.url in self.entry_urls else 1))

    @property
    def severity(self) -> str:
        return severity_of(self.issue)

    @property
    def confidence(self) -> str:
        return self.issue.confidence

    @property
    def url(self) -> str:
        return self.issue.url

    @property
    def roles(self) -> frozenset[str]:
        out: set[str] = set()
        for i in self.issues:
            out |= _roles(i)
        return frozenset(out)

    @property
    def instances(self) -> int:
        return len(self.issues)

    @property
    def urls(self) -> list[str]:
        return list(dict.fromkeys(i.url for i in self.issues))

    @property
    def examples(self) -> list[str]:
        """≤ 5 URLs, the entry document first."""
        urls = self.urls
        first = [u for u in urls if u in self.entry_urls]
        rest = [u for u in urls if u not in self.entry_urls]
        return (first + rest)[:MAX_EXAMPLES]

    @property
    def pages(self) -> list[str]:
        """Every URL template the issue was seen on."""
        return list(dict.fromkeys(url_template(u) for u in self.urls))

    @property
    def notes(self) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for i in self.issues:
            for n in i.notes:
                pair = (n[0], n[1]) if isinstance(n, (list, tuple)) and len(n) >= 2 else (str(n), str(n))
                if pair not in out:
                    out.append(pair)
        if self.systemic:
            out.append(note("systemic", share=int(round(self.share * 100))))
        return out

    def penalty_issue(self, weights: dict[str, float], penalties: dict[str, float]) -> float:
        """Grade penalty (§3.4): the largest severity × confidence weight among the instances."""
        return max((penalties[severity_of(i)] * weights.get(i.confidence, 0.0) for i in self.issues), default=0.0)

    def restrict(self, sensitivity: str | None) -> "Group | None":
        """The group with only the instances reported at ``sensitivity`` (None when none is)."""
        keep = [i for i in self.issues if _reported(i, sensitivity)]
        if not keep:
            return None
        if len(keep) == len(self.issues):
            return self
        return dataclasses.replace(self, issues=keep)

    def extra(self) -> dict:
        """``Finding.extra`` fields owned by grouping (the 1.0.1 ``pages``/``page_count`` subset included)."""
        return {"fp_key": self.fp_key, "instances": self.instances, "examples": self.examples, "pages": self.pages,
                "page_count": len(self.urls), "systemic": self.systemic, "group_value": self.value,
                "kind": self.kind}


@dataclass
class GroupResult:
    groups: list[Group] = field(default_factory=list)         # reported at the scan's sensitivity
    hidden: list[Group] = field(default_factory=list)         # all instances below the sensitivity
    suppressed: list[tuple[Issue, str]] = field(default_factory=list)
    raw_count: int = 0
    full: list[Group] = field(default_factory=list, repr=False)   # every group with all its instances

    def all_groups(self) -> list[Group]:
        """Reported and hidden groups with *all* their instances (what the grade counts)."""
        return list(self.full or self.groups + self.hidden)

    @property
    def noise_ratio(self) -> float:
        """Raw issues / reported findings (§5.3)."""
        return round(self.raw_count / len(self.groups), 3) if self.groups else 0.0

    def suppressed_summary(self) -> list[dict]:
        return [{"rule": i.rule, "url": i.url, "reason": reason, "en": STR[reason][0], "ar": STR[reason][1]}
                for i, reason in self.suppressed]


def _response_counts(ctx: Any) -> dict[tuple[str, str], set[str]]:
    counts: dict[tuple[str, str], set[str]] = {}
    if ctx is None or not hasattr(ctx, "all_responses"):
        return counts
    for r in ctx.all_responses():
        if r.status is None:
            continue
        try:
            host = r.host
        except ValueError:
            continue
        counts.setdefault((host, r.kind or ""), set()).add(r.url)
    return counts


def group_issues(issues: Iterable[Issue], ctx: Any = None) -> list[Group]:
    """Group by (rule, host, response kind, normalised value), in first-seen order. The value is ``Issue.group_value``
    normalised, or (when a module left it empty) the evidence's matched name/value normalised."""
    entry_urls = frozenset(_entry_urls(ctx))
    groups: dict[tuple[str, str, str, str], Group] = {}
    for i in issues:
        value = normalise_value(i.group_value if i.group_value else _match_value(i))
        key = (i.rule, issue_host(i), _kind(i), value)
        g = groups.get(key)
        if g is None:
            g = groups[key] = Group(rule=key[0], host=key[1], kind=key[2], value=key[3], entry_urls=entry_urls)
        g.issues.append(i)
    counts = _response_counts(ctx)
    for g in groups.values():
        total = counts.get((g.host, g.kind))
        if total and len(total) >= SYSTEMIC_MIN_RESPONSES:
            seen = len(set(g.urls) & total)
            g.share = seen / len(total)
            g.systemic = g.share >= SYSTEMIC_SHARE
    return list(groups.values())


def process(issues: Sequence[Issue], ctx: Any = None, sensitivity: str | None = None) -> GroupResult:
    """Adjust → suppress → group → apply sensitivity (§3.5, §3.6). ``sensitivity`` defaults to the scan's option."""
    if sensitivity is None and ctx is not None and getattr(ctx, "options", None) is not None:
        sensitivity = ctx.options.sensitivity
    adjusted = adjust(issues, ctx)
    kept, dropped = suppress(adjusted, ctx, sensitivity)
    full = group_issues(kept, ctx)
    shown, hidden = [], []
    for g in full:
        r = g.restrict(sensitivity)
        if r is None:
            hidden.append(g)
        else:
            shown.append(r)
    return GroupResult(groups=shown, hidden=hidden, suppressed=dropped, raw_count=len(issues), full=full)


def i18n_catalog() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """``(CATALOG, PATTERNS)`` of this module's Arabic strings for ``vulnscan/i18n/cat_web2.py``."""
    from .rules import template_patterns
    catalog: dict[str, str] = {}
    patterns: list[tuple[str, str]] = []
    for en, ar in STR.values():
        if "{" in ar:
            patterns.extend(template_patterns(ar, en))
        else:
            catalog[ar] = en
    return catalog, patterns


__all__ = ["Group", "GroupResult", "CrawlPlanner", "STR", "adjust", "suppress", "group_issues", "process",
           "normalise_value", "url_template", "issue_host", "severity_of", "note", "i18n_catalog"]
