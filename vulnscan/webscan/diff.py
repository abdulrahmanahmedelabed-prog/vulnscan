"""Scan-to-scan diff of web scans (spec §3.7, WP13).

Every web scan stores a snapshot (``store.py``: key ``web_snapshot`` of the scan JSON, built by :func:`snapshot`):
grades, check states, finding keys, and the inventory that matters for posture — final URL and chain, normalised
security header values, CSP directives, cookies (name, class, attributes; never values), third-party hosts,
libraries and technologies with versions, TLS per IP (protocols, suite categories, certificate sha256, issuer,
notAfter, key, SCT count), security.txt Expires, robots.txt disallow paths and deep-probe hits.

:func:`diff` compares two snapshots of the same normalised target and returns (JSON key ``web.diff``):

* ``findings``: ``new``, ``resolved`` and ``unchanged`` (matched by the stable ``fp_key`` of §3.5, else the
  fingerprint);
* ``grades``: the change per algorithm (``up`` / ``down`` / ``same``);
* ``posture``: changes that are not findings ("CSP changed: script-src added https://cdn.new.example", "new
  third-party script host", "certificate renewed, new issuer", "TLS 1.3 enabled", "new cookie __Host-x", "library jquery
  3.6.0 → 3.7.1", "security.txt expires in 20 days"), each ``regression`` / ``change`` / ``improvement`` with English and
  Arabic text; regressions first;
* ``notes``: comparability (a different target is refused; a profile difference is stated).

Pure functions over plain JSON data; no network, no file system.
"""

from __future__ import annotations

import hashlib
import math
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from .rules import PLURAL_PARAMS, RULES, SEVERITIES
from .types import url_origin

SCHEMA = 1
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SECURITY_HEADERS = ("strict-transport-security", "content-security-policy", "content-security-policy-report-only",
                    "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy",
                    "cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy",
                    "access-control-allow-origin", "access-control-allow-credentials", "cache-control",
                    "x-xss-protection", "integrity-policy", "reporting-endpoints", "server", "x-powered-by")
# CSP directives whose loosening is a regression (sources added) and whose removal un-restricts the page
_CSP_SENSITIVE = ("default-src", "script-src", "script-src-elem", "script-src-attr", "object-src", "base-uri",
                  "frame-ancestors", "form-action", "style-src", "connect-src", "frame-src", "child-src", "worker-src")
_THIRD_PARTY_DIRECTIVES = {"script-src": "script", "script-src-elem": "script", "style-src": "style",
                           "style-src-elem": "style", "frame-src": "frame", "child-src": "frame", "connect-src": "connect"}
_OLD_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")
_WEAK_SUITES = ("null_anon", "export_des", "rc4", "3des", "krsa", "cbc")
_COOKIE_FLAGS = ("secure", "httponly", "partitioned")
SECTXT_SOON_DAYS = 30
MAX_ITEMS = 200

STR: dict[str, tuple[str, str]] = {
    "not_comparable": ("not compared: the previous scan was of another target ({previous})",
                       "لم تُقارن: الفحص السابق كان لهدف آخر ({previous})"),
    "no_previous": ("no previous scan of this target to compare with", "لا يوجد فحص سابق لهذا الهدف للمقارنة به"),
    "profile_diff": ("the previous scan used the {previous} profile and this one {current}; checks that only one of them "
                     "runs are not comparable", "استخدم الفحص السابق ملف الفحص {previous} وهذا الفحص {current}؛ فالفحوص "
                     "التي يجريها أحدهما فقط غير قابلة للمقارنة"),
    "deep_diff": ("the previous scan was {previous}, this one {current}: exposure checks are not comparable",
                  "كان الفحص السابق بملف {previous} وهذا الفحص بملف {current}: فحوص الملفات المكشوفة غير قابلة للمقارنة"),
    "grade_up": ("{algorithm} grade improved: {before} → {after}", "تحسّنت درجة {algorithm}: من {before} إلى {after}"),
    "grade_down": ("{algorithm} grade dropped: {before} → {after}", "انخفضت درجة {algorithm}: من {before} إلى {after}"),
    "final_url": ("final URL changed: {before} → {after}", "تغيّر الرابط النهائي: من {before} إلى {after}"),
    "chain": ("redirect chain changed: {before} → {after}", "تغيّرت سلسلة التوجيه: من {before} إلى {after}"),
    "header_added": ("header added: {header}: {value}", "أُضيفت ترويسة: {header}: {value}"),
    "header_removed": ("header removed: {header} (was {value})", "حُذفت ترويسة: {header} (كانت {value})"),
    "header_changed": ("header changed: {header}: {before} → {after}", "تغيّرت ترويسة: {header}: من {before} إلى {after}"),
    "csp_added": ("CSP changed: {directive} added {sources}", "تغيّرت سياسة CSP: أُضيف إلى {directive}: {sources}"),
    "csp_removed": ("CSP changed: {directive} removed {sources}", "تغيّرت سياسة CSP: حُذف من {directive}: {sources}"),
    "csp_dir_added": ("CSP changed: new directive {directive} {sources}", "تغيّرت سياسة CSP: توجيه جديد {directive} {sources}"),
    "csp_dir_removed": ("CSP changed: directive {directive} removed", "تغيّرت سياسة CSP: حُذف التوجيه {directive}"),
    "csp_enabled": ("an enforced CSP was added", "أُضيفت سياسة CSP مفروضة"),
    "csp_disabled": ("the enforced CSP was removed", "حُذفت سياسة CSP المفروضة"),
    "cookie_new": ("new cookie {name} ({cls})", "كوكي جديد {name} ({cls})"),
    "cookie_gone": ("cookie no longer set: {name}", "لم يعد الكوكي {name} يُضبط"),
    "cookie_lost": ("cookie {name} lost the {flag} attribute", "فقد الكوكي {name} الخاصية {flag}"),
    "cookie_gained": ("cookie {name} gained the {flag} attribute", "اكتسب الكوكي {name} الخاصية {flag}"),
    "cookie_samesite": ("cookie {name}: SameSite {before} → {after}", "الكوكي {name}: SameSite من {before} إلى {after}"),
    "cookie_domain": ("cookie {name}: Domain {before} → {after}", "الكوكي {name}: Domain من {before} إلى {after}"),
    "third_new": ("new third-party {kind} host: {host}", "مضيف طرف ثالث جديد ({kind}): {host}"),
    "third_gone": ("third-party {kind} host no longer used: {host}", "لم يعد مضيف الطرف الثالث ({kind}) مستخدمًا: {host}"),
    "lib_changed": ("library {name} {before} → {after}", "المكتبة {name}: من {before} إلى {after}"),
    "lib_new": ("new library {name} {version}", "مكتبة جديدة {name} {version}"),
    "lib_gone": ("library no longer detected: {name} {version}", "لم تعد المكتبة مكتشفة: {name} {version}"),
    "tech_changed": ("technology {name} {before} → {after}", "التقنية {name}: من {before} إلى {after}"),
    "tech_new": ("new technology detected: {name} {version}", "تقنية جديدة مكتشفة: {name} {version}"),
    "tech_gone": ("technology no longer detected: {name} {version}", "لم تعد التقنية مكتشفة: {name} {version}"),
    "tls_enabled": ("{protocol} enabled on {ip}", "فُعّل {protocol} على {ip}"),
    "tls_disabled": ("{protocol} disabled on {ip}", "عُطّل {protocol} على {ip}"),
    "suite_enabled": ("weak cipher category {category} now offered on {ip}", "صار الخادم يعرض فئة التشفير الضعيفة {category} على {ip}"),
    "suite_disabled": ("weak cipher category {category} no longer offered on {ip}",
                       "لم يعد الخادم يعرض فئة التشفير الضعيفة {category} على {ip}"),
    "cert_renewed": ("certificate renewed on {ip} (valid until {not_after})", "جُدّدت الشهادة على {ip} (صالحة حتى {not_after})"),
    "cert_issuer": ("certificate renewed on {ip}, new issuer: {issuer}", "جُدّدت الشهادة على {ip} من جهة إصدار جديدة: {issuer}"),
    "cert_key": ("certificate key changed on {ip}: {before} → {after}", "تغيّر مفتاح الشهادة على {ip}: من {before} إلى {after}"),
    "scts_changed": ("SCTs on {ip}: {before} → {after}", "عدد SCT على {ip}: من {before} إلى {after}"),
    "tls_ip_new": ("new TLS address: {ip}", "عنوان TLS جديد: {ip}"),
    "tls_ip_gone": ("TLS address no longer seen: {ip}", "لم يعد عنوان TLS ظاهرًا: {ip}"),
    "sectxt_added": ("security.txt published", "نُشر ملف security.txt"),
    "sectxt_removed": ("security.txt no longer published", "لم يعد ملف security.txt منشورًا"),
    "sectxt_expires": ("security.txt Expires changed: {before} → {after}", "تغيّر تاريخ Expires في security.txt: من {before} إلى {after}"),
    "sectxt_soon": ("security.txt expires in {days}", "تنتهي صلاحية security.txt خلال {days}"),
    "sectxt_expired": ("security.txt has expired ({date})", "انتهت صلاحية security.txt ({date})"),
    "robots_added": ("robots.txt now disallows {path}", "صار robots.txt يمنع {path}"),
    "robots_removed": ("robots.txt no longer disallows {path}", "لم يعد robots.txt يمنع {path}"),
    "deep_new": ("newly exposed: {path}", "صار مكشوفًا: {path}"),
    "deep_gone": ("no longer exposed: {path}", "لم يعد مكشوفًا: {path}"),
    "check_regressed": ("check {check} now fails", "صار الفحص {check} فاشلًا"),
    "check_fixed": ("check {check} now passes", "صار الفحص {check} ناجحًا"),
    "check_coverage": ("check {check} could not be compared ({before} → {after})",
                       "تعذّرت مقارنة الفحص {check} (من {before} إلى {after})"),
}
_ALG_NAMES = {"kashif": "Kashif", "observatory": "Observatory", "ssllabs": "SSL Labs-compatible"}


def t(key: str, lang: str = "en", **params: Any) -> str:
    en, ar = STR[key]
    text = ar if lang == "ar" else en
    return text.format(**params) if params else text


def _days(n: int, lang: str) -> str:
    one, many, forms = PLURAL_PARAMS["days"]
    if lang == "ar":
        from ..i18n.plural import ar_count
        return ar_count(n, forms)
    return (one if n == 1 else many).replace("{n}", str(n))


# ----------------------------------------------------------------------------------------------- targets

def normalise_target(url: str) -> str:
    """``scheme://host[:port]/path`` lower-cased host, default port dropped, no query/fragment, no trailing slash."""
    try:
        p = urllib.parse.urlsplit((url or "").strip())
        origin = url_origin(url)
    except ValueError:
        return (url or "").strip().lower()
    path = (p.path or "/").rstrip("/") or "/"
    return origin + (path if path != "/" else "/")


def comparable(previous: dict | None, current: dict) -> bool:
    return bool(previous) and bool(current.get("target")) and previous.get("target") == current.get("target")


# ----------------------------------------------------------------------------------------------- snapshot

def _short(value: Any, n: int = 300) -> str:
    s = " ".join(str(value or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _iso(d: datetime | None) -> str:
    if d is None:
        return ""
    return d.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _finding_row(f: Any) -> dict | None:
    """One snapshot row from a group.Group, a model.Finding or a finding dict."""
    if hasattr(f, "fp_key") and hasattr(f, "issues"):           # group.Group
        meta = RULES.get(f.rule)
        params = dict(f.issue.params or {})
        return {"key": f.fp_key, "fingerprint": hashlib.sha256(f.fp_key.encode("utf-8")).hexdigest()[:16],
                "rule": f.rule, "severity": f.severity, "confidence": f.confidence, "host": f.host,
                "title_en": meta.title("en", **params) if meta else f.rule,
                "title_ar": meta.title("ar", **params) if meta else f.rule}
    if isinstance(f, dict):
        extra = f.get("extra") or {}
        key = extra.get("fp_key") or f.get("fingerprint") or ""
        return {"key": key, "fingerprint": f.get("fingerprint") or "", "rule": f.get("rule_id", ""),
                "severity": f.get("severity", ""), "confidence": extra.get("confidence", ""), "host": extra.get("host", ""),
                "title_en": f.get("title", ""), "title_ar": f.get("title_ar", "")}
    if hasattr(f, "rule_id"):                                     # model.Finding
        extra = getattr(f, "extra", {}) or {}
        fp = f.fingerprint() if hasattr(f, "fingerprint") else ""
        return {"key": extra.get("fp_key") or fp, "fingerprint": fp, "rule": f.rule_id, "severity": f.severity,
                "confidence": extra.get("confidence", ""), "host": extra.get("host", ""), "title_en": f.title,
                "title_ar": f.title_ar}
    return None


def _grade_brief(grades: dict | None) -> dict:
    g = grades or {}
    k, o, s = g.get("kashif") or {}, g.get("observatory") or {}, g.get("ssllabs") or {}
    return {"kashif": {"grade": k.get("grade"), "score": k.get("score")},
            "observatory": {"grade": o.get("grade"), "score": o.get("score")},
            "ssllabs": {"grade": s.get("grade"), "score": s.get("score")}}


def _states(coverage: Any) -> dict[str, str]:
    if coverage is None:
        return {}
    if hasattr(coverage, "states"):
        return {c: st.state for c, st in coverage.states().items()}
    if isinstance(coverage, dict) and isinstance(coverage.get("checks"), list):
        return {c.get("check"): c.get("state") for c in coverage["checks"] if isinstance(c, dict)}
    return {}


def _header_value(name: str, values: list[str]) -> str:
    from .group import normalise_value
    return _short(normalise_value(", ".join(values)), 500)


def _csp_snapshot(ctx: Any) -> list[dict]:
    entry = getattr(ctx, "entry", None)
    if entry is None or not hasattr(ctx, "csp_for"):
        return []
    facts = ctx.csp_for(entry)
    if facts is None:
        return []
    from .group import normalise_value
    out = []
    for p in facts.enforced:
        out.append({"origin": p.origin, "directives": {k: sorted({normalise_value(v) for v in vals})
                                                       for k, vals in sorted(p.directives.items())}})
    return out[:10]


def _host_of_source(src: str) -> str:
    s = src.strip().strip("'\"")
    if not s or s.endswith(":") and "//" not in s:
        return ""
    if s.startswith(("'", "nonce-", "sha")):
        return ""
    if "://" in s:
        s = s.split("://", 1)[1]
    host = s.split("/", 1)[0].split(":", 1)[0].lower()
    return host if "." in host or host == "*" else ""


def _third_parties(ctx: Any, csp: list[dict]) -> dict[str, list[str]]:
    out: dict[str, set[str]] = {}
    inv = getattr(ctx, "inventory", None) or {}
    tp = inv.get("third_parties")
    if isinstance(tp, dict):
        for host, kinds in tp.items():
            for k in kinds if isinstance(kinds, (list, tuple, set)) else [kinds]:
                out.setdefault(str(k), set()).add(str(host).lower())
    site_host = ""
    entry = getattr(ctx, "entry", None)
    if entry is not None:
        site_host = entry.host
    for pol in csp:
        for d, kind in _THIRD_PARTY_DIRECTIVES.items():
            for src in pol["directives"].get(d, []):
                h = _host_of_source(src)
                if h and h != site_host:
                    out.setdefault(kind, set()).add(h)
    return {k: sorted(v)[:MAX_ITEMS] for k, v in sorted(out.items())}


def _versions(rows: Any, name_keys: Sequence[str] = ("name",)) -> dict[str, str]:
    out: dict[str, str] = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        name = next((str(row[k]) for k in name_keys if row.get(k)), "")
        if name:
            out[name] = str(row.get("version") or "")
    return dict(sorted(out.items()))


def _tls_snapshot(inv: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    tls = inv.get("tls")
    if not isinstance(tls, dict):
        return out
    for host, hrep in sorted(tls.items()):
        if not isinstance(hrep, dict):
            continue
        for ip, irep in sorted((hrep.get("ips") or {}).items()):
            if not isinstance(irep, dict):
                continue
            chain = irep.get("chain") or []
            leaf = chain[0] if chain and isinstance(chain[0], dict) else {}
            scts = irep.get("scts") or {}
            out[f"{host} {ip}"] = {
                "protocols": sorted(k for k, v in (irep.get("protocols") or {}).items() if v == "yes"),
                "suites": sorted(k for k, v in (irep.get("suites") or {}).items() if v == "yes"),
                "cert_sha256": leaf.get("sha256") or "", "issuer": _short(leaf.get("issuer"), 300),
                "not_after": leaf.get("not_after") or "", "key": leaf.get("key") or "",
                "scts": int(scts.get("embedded", 0) or 0) + int(scts.get("tls", 0) or 0) if isinstance(scts, dict) else 0}
    return out


def snapshot(ctx: Any, findings: Iterable[Any] = (), grades: dict | None = None, coverage: Any = None, *,
             scan_id: str = "", version: str = "") -> dict:
    """The ``web_snapshot`` stored with a web scan (§3.7). JSON-safe; holds no cookie values and no bodies."""
    if not version:
        try:
            from .. import __version__ as version
        except ImportError:   # pragma: no cover
            version = ""
    if coverage is None:
        coverage = getattr(ctx, "coverage", None)
    opts = getattr(ctx, "options", None)
    entry = getattr(ctx, "entry", None)
    inv = getattr(ctx, "inventory", None) or {}
    rows = [r for r in (_finding_row(f) for f in findings) if r and r["key"]]
    headers: dict[str, str] = {}
    if entry is not None:
        for name in SECURITY_HEADERS:
            vals = entry.headers.get_all(name)
            if vals:
                headers[name] = _header_value(name, vals)
    csp = _csp_snapshot(ctx)
    cookies: dict[str, dict] = {}
    for c in getattr(ctx, "cookies", None) or ():
        if c.deletion or c.ignored:
            continue
        cookies[c.name] = {"class": c.cls, "secure": c.secure, "httponly": c.httponly, "partitioned": c.partitioned,
                           "samesite": (c.samesite or "").lower(), "domain": (c.domain or "").lstrip(".").lower(),
                           "path": c.path or "", "host": c.host}
    sectxt = inv.get("security_txt") if isinstance(inv.get("security_txt"), dict) else {}
    robots = inv.get("robots") if isinstance(inv.get("robots"), dict) else {}
    hits = inv.get("deep_probe_hits") if isinstance(inv.get("deep_probe_hits"), list) else []
    return {
        "schema": SCHEMA, "kashif": version, "scan_id": scan_id,
        "target": normalise_target(getattr(ctx, "target", "") or ""),
        "profile": getattr(opts, "profile", ""), "crawl": bool(getattr(opts, "crawl", False)),
        "sensitivity": getattr(opts, "sensitivity", ""), "scanned_at": _iso(getattr(ctx, "now", None)),
        "grades": _grade_brief(grades), "checks": dict(sorted(_states(coverage).items())),
        "findings": sorted(rows, key=lambda r: (SEV_RANK.get(r["severity"], 9), r["rule"], r["key"])),
        "inventory": {
            "final_url": entry.url if entry is not None else "",
            "chain": [[h.url, h.status] for h in (entry.hops() if entry is not None else [])],
            "headers": headers, "csp": csp, "cookies": dict(sorted(cookies.items())),
            "third_party": _third_parties(ctx, csp),
            "libraries": _versions(inv.get("libraries"), ("name", "component")),
            "technologies": _versions(inv.get("technologies"), ("name", "id")),
            "tls": _tls_snapshot(inv),
            "security_txt": {"present": bool(sectxt.get("present")), "expires": sectxt.get("expires") or ""},
            "robots_disallow": sorted({str(p) for p in robots.get("disallow") or []})[:MAX_ITEMS],
            "deep_hits": sorted({str(h.get("path")) for h in hits if isinstance(h, dict) and h.get("path")})[:MAX_ITEMS],
        },
    }


# ----------------------------------------------------------------------------------------------- diff

def _item(direction: str, kind: str, key: str, /, **params: Any) -> dict:
    ar_params = {k: (v[1] if isinstance(v, tuple) else v) for k, v in params.items()}
    en_params = {k: (v[0] if isinstance(v, tuple) else v) for k, v in params.items()}
    return {"direction": direction, "kind": kind, "id": key, "en": t(key, "en", **en_params),
            "ar": t(key, "ar", **ar_params)}


def _version_tuple(v: str) -> tuple:
    parts = []
    for p in str(v).replace("-", ".").split("."):
        parts.append((0, int(p), "") if p.isdigit() else (1, 0, p))
    return tuple(parts)


def _letter_rank(grade: Any) -> int | None:
    from .grade import LETTERS
    g = str(grade or "").rstrip("*")
    return LETTERS.index(g) if g in LETTERS else None


def _grade_changes(prev: dict, cur: dict) -> tuple[dict, list[dict]]:
    out: dict[str, dict] = {}
    items: list[dict] = []
    for alg in ("kashif", "observatory", "ssllabs"):
        b = (prev.get("grades") or {}).get(alg) or {}
        a = (cur.get("grades") or {}).get(alg) or {}
        before, after = b.get("grade"), a.get("grade")
        change = "same"
        rb, ra = _letter_rank(before), _letter_rank(after)
        if alg == "observatory" and b.get("score") is not None and a.get("score") is not None:
            change = "up" if a["score"] > b["score"] else "down" if a["score"] < b["score"] else "same"
        elif rb is not None and ra is not None:
            change = "up" if ra < rb else "down" if ra > rb else "same"
        elif before != after:
            change = "changed"
        out[alg] = {"before": before, "after": after, "change": change,
                    "score_before": b.get("score"), "score_after": a.get("score")}
        if change in ("up", "down"):
            shown_b = f"{b.get('score')} ({before})" if alg == "observatory" else before
            shown_a = f"{a.get('score')} ({after})" if alg == "observatory" else after
            items.append(_item("improvement" if change == "up" else "regression", "grade",
                               "grade_up" if change == "up" else "grade_down", algorithm=_ALG_NAMES[alg],
                               before=shown_b, after=shown_a))
    return out, items


def _header_changes(p: dict, c: dict) -> list[dict]:
    items: list[dict] = []
    for name in SECURITY_HEADERS:
        b, a = p.get(name), c.get(name)
        if b == a:
            continue
        shown = name.title() if name != "x-xss-protection" else "X-XSS-Protection"
        if b is None:
            weaker = name in ("server", "x-powered-by", "access-control-allow-origin", "access-control-allow-credentials")
            items.append(_item("regression" if weaker else "improvement", "header", "header_added", header=shown,
                               value=_short(a, 120)))
        elif a is None:
            weaker = name not in ("server", "x-powered-by", "access-control-allow-origin",
                                  "access-control-allow-credentials", "x-xss-protection")
            items.append(_item("regression" if weaker else "improvement", "header", "header_removed", header=shown,
                               value=_short(b, 120)))
        elif name not in ("content-security-policy",):     # the CSP is compared directive by directive below
            items.append(_item("change", "header", "header_changed", header=shown, before=_short(b, 120),
                               after=_short(a, 120)))
    return items


def _merge_csp(policies: list[dict]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for p in policies:
        for d, srcs in (p.get("directives") or {}).items():
            out.setdefault(d, set()).update(srcs)
    return out


def _csp_changes(prev: list[dict], cur: list[dict]) -> list[dict]:
    items: list[dict] = []
    if prev and not cur:
        return [_item("regression", "csp", "csp_disabled")]
    if cur and not prev:
        return [_item("improvement", "csp", "csp_enabled")]
    p, c = _merge_csp(prev), _merge_csp(cur)
    for d in sorted(set(p) | set(c)):
        if d not in p:
            items.append(_item("improvement", "csp", "csp_dir_added", directive=d, sources=" ".join(sorted(c[d]))[:200]))
            continue
        if d not in c:
            items.append(_item("regression" if d in _CSP_SENSITIVE else "change", "csp", "csp_dir_removed", directive=d))
            continue
        added, removed = sorted(c[d] - p[d]), sorted(p[d] - c[d])
        if added:
            items.append(_item("regression" if d in _CSP_SENSITIVE else "change", "csp", "csp_added", directive=d,
                               sources=" ".join(added)[:200]))
        if removed:
            items.append(_item("improvement" if d in _CSP_SENSITIVE else "change", "csp", "csp_removed", directive=d,
                               sources=" ".join(removed)[:200]))
    return items


def _cookie_changes(p: dict, c: dict) -> list[dict]:
    items: list[dict] = []
    for name in sorted(set(p) | set(c)):
        b, a = p.get(name), c.get(name)
        if b is None:
            items.append(_item("change", "cookie", "cookie_new", name=name, cls=a.get("class", "")))
            continue
        if a is None:
            items.append(_item("change", "cookie", "cookie_gone", name=name))
            continue
        for flag in _COOKIE_FLAGS:
            if b.get(flag) and not a.get(flag):
                items.append(_item("regression", "cookie", "cookie_lost", name=name, flag=flag.title()))
            elif a.get(flag) and not b.get(flag):
                items.append(_item("improvement", "cookie", "cookie_gained", name=name, flag=flag.title()))
        if (b.get("samesite") or "") != (a.get("samesite") or ""):
            order = {"strict": 0, "lax": 1, "none": 2, "": 3}
            direction = ("improvement" if order.get(a.get("samesite") or "", 3) < order.get(b.get("samesite") or "", 3)
                         else "regression")
            items.append(_item(direction, "cookie", "cookie_samesite", name=name, before=b.get("samesite") or "—",
                               after=a.get("samesite") or "—"))
        if (b.get("domain") or "") != (a.get("domain") or ""):
            direction = "regression" if a.get("domain") and not b.get("domain") else "change"
            items.append(_item(direction, "cookie", "cookie_domain", name=name, before=b.get("domain") or "—",
                               after=a.get("domain") or "—"))
    return items


def _third_changes(p: dict, c: dict) -> list[dict]:
    items: list[dict] = []
    for kind in sorted(set(p) | set(c)):
        b, a = set(p.get(kind) or []), set(c.get(kind) or [])
        for h in sorted(a - b):
            items.append(_item("regression" if kind == "script" else "change", "third_party", "third_new", kind=kind,
                               host=h))
        for h in sorted(b - a):
            items.append(_item("change", "third_party", "third_gone", kind=kind, host=h))
    return items


def _version_changes(p: dict, c: dict, kind: str) -> list[dict]:
    items: list[dict] = []
    for name in sorted(set(p) | set(c)):
        b, a = p.get(name), c.get(name)
        if b is None:
            items.append(_item("change", kind, f"{kind}_new", name=name, version=a or ""))
        elif a is None:
            items.append(_item("change", kind, f"{kind}_gone", name=name, version=b or ""))
        elif a != b:
            up = bool(a and b) and _version_tuple(a) > _version_tuple(b)
            items.append(_item("improvement" if up else "change", kind, f"{kind}_changed", name=name,
                               before=b or "?", after=a or "?"))
    return items


def _tls_changes(p: dict, c: dict) -> list[dict]:
    items: list[dict] = []
    for key in sorted(set(p) | set(c)):
        ip = key.split(" ", 1)[-1] if " " in key else key
        b, a = p.get(key), c.get(key)
        if b is None:
            items.append(_item("change", "tls", "tls_ip_new", ip=key))
            continue
        if a is None:
            items.append(_item("change", "tls", "tls_ip_gone", ip=key))
            continue
        bp, ap = set(b.get("protocols") or []), set(a.get("protocols") or [])
        for proto in sorted(ap - bp):
            items.append(_item("regression" if proto in _OLD_PROTOCOLS else "improvement", "tls", "tls_enabled",
                               protocol=proto.replace("TLSv", "TLS "), ip=ip))
        for proto in sorted(bp - ap):
            items.append(_item("improvement" if proto in _OLD_PROTOCOLS else "regression", "tls", "tls_disabled",
                               protocol=proto.replace("TLSv", "TLS "), ip=ip))
        bs, as_ = set(b.get("suites") or []), set(a.get("suites") or [])
        for cat in sorted((as_ - bs) & set(_WEAK_SUITES)):
            items.append(_item("regression", "tls", "suite_enabled", category=cat, ip=ip))
        for cat in sorted((bs - as_) & set(_WEAK_SUITES)):
            items.append(_item("improvement", "tls", "suite_disabled", category=cat, ip=ip))
        if b.get("cert_sha256") and a.get("cert_sha256") and b["cert_sha256"] != a["cert_sha256"]:
            if (b.get("issuer") or "") != (a.get("issuer") or ""):
                items.append(_item("change", "tls", "cert_issuer", ip=ip, issuer=_short(a.get("issuer"), 160)))
            else:
                items.append(_item("change", "tls", "cert_renewed", ip=ip, not_after=a.get("not_after") or "?"))
            if (b.get("key") or "") != (a.get("key") or ""):
                items.append(_item("change", "tls", "cert_key", ip=ip, before=b.get("key") or "?", after=a.get("key") or "?"))
        if int(b.get("scts") or 0) != int(a.get("scts") or 0):
            items.append(_item("regression" if int(a.get("scts") or 0) < int(b.get("scts") or 0) else "change", "tls",
                               "scts_changed", ip=ip, before=b.get("scts") or 0, after=a.get("scts") or 0))
    return items


def _parse_date(s: str) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _sectxt_changes(p: dict, c: dict, now: datetime | None) -> list[dict]:
    items: list[dict] = []
    if p.get("present") and not c.get("present"):
        items.append(_item("regression", "security_txt", "sectxt_removed"))
    elif c.get("present") and not p.get("present"):
        items.append(_item("improvement", "security_txt", "sectxt_added"))
    elif c.get("present") and (p.get("expires") or "") != (c.get("expires") or ""):
        items.append(_item("change", "security_txt", "sectxt_expires", before=p.get("expires") or "—",
                           after=c.get("expires") or "—"))
    exp = _parse_date(c.get("expires") or "") if c.get("present") else None
    if exp is not None and now is not None:
        left = (exp - now).total_seconds() / 86400
        if left < 0:
            items.append(_item("regression", "security_txt", "sectxt_expired", date=c["expires"]))
        elif left <= SECTXT_SOON_DAYS:
            n = max(1, math.ceil(left))          # "expires in 0 days" reads as already expired
            items.append(_item("regression", "security_txt", "sectxt_soon", days=(_days(n, "en"), _days(n, "ar"))))
    return items


def _set_changes(p: Iterable[str], c: Iterable[str], kind: str, added_key: str, removed_key: str, added_dir: str,
                 removed_dir: str) -> list[dict]:
    b, a = set(p or []), set(c or [])
    out = [_item(added_dir, kind, added_key, path=x) for x in sorted(a - b)]
    out += [_item(removed_dir, kind, removed_key, path=x) for x in sorted(b - a)]
    return out


def _check_changes(p: dict, c: dict) -> list[dict]:
    items: list[dict] = []
    for check in sorted(set(p) & set(c)):
        b, a = p[check], c[check]
        if b == a:
            continue
        if b == "pass" and a == "fail":
            items.append(_item("regression", "check", "check_regressed", check=check))
        elif b == "fail" and a == "pass":
            items.append(_item("improvement", "check", "check_fixed", check=check))
        elif {b, a} & {"not_tested", "inconclusive"} and {b, a} & {"pass", "fail"}:
            items.append(_item("change", "check", "check_coverage", check=check, before=b, after=a))
    return items


_ORDER = {"regression": 0, "change": 1, "improvement": 2}


# ----------------------------------------------------------------------------------------------- input hygiene
# A previous snapshot comes from disk (store.py, or a file the user names with --compare): an older Kashif, a hand
# edit or a wrong file must never crash the scan. Every snapshot is coerced to the shape snapshot() writes; anything
# of the wrong type is dropped.

def _s(v: Any) -> str:
    return v if isinstance(v, str) else ""


def _num(v: Any) -> int | float | None:
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _d(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _strs(v: Any) -> list[str]:
    return [x for x in v if isinstance(x, str)][:MAX_ITEMS * 5] if isinstance(v, (list, tuple)) else []


_ROW_FIELDS = ("key", "fingerprint", "rule", "severity", "confidence", "host", "title_en", "title_ar")


def sanitise(snap: Any) -> dict | None:
    """``snap`` coerced to the snapshot shape (None when it is not a snapshot at all)."""
    if not isinstance(snap, dict):
        return None
    inv = _d(snap.get("inventory"))
    grades = {alg: {"grade": _s(_d(g).get("grade")) or None, "score": _num(_d(g).get("score"))}
              for alg, g in _d(snap.get("grades")).items() if isinstance(alg, str)}
    rows = [{f: _s(r.get(f)) for f in _ROW_FIELDS} for r in snap.get("findings") or [] if isinstance(r, dict)] \
        if isinstance(snap.get("findings"), list) else []
    chain = [[h[0], _num(h[1])] for h in inv.get("chain") or [] if isinstance(h, (list, tuple)) and len(h) == 2
             and isinstance(h[0], str)] if isinstance(inv.get("chain"), list) else []
    csp = [{"origin": _s(p.get("origin")),
            "directives": {k: _strs(v) for k, v in _d(p.get("directives")).items() if isinstance(k, str)}}
           for p in inv.get("csp") or [] if isinstance(p, dict)] if isinstance(inv.get("csp"), list) else []
    cookies = {}
    for name, c in _d(inv.get("cookies")).items():
        if isinstance(name, str) and isinstance(c, dict):
            cookies[name] = {"class": _s(c.get("class")), "samesite": _s(c.get("samesite")), "domain": _s(c.get("domain")),
                             "path": _s(c.get("path")), "host": _s(c.get("host")),
                             **{f: c.get(f) is True for f in _COOKIE_FLAGS}}
    tls = {}
    for key, rep in _d(inv.get("tls")).items():
        if isinstance(key, str) and isinstance(rep, dict):
            scts = _num(rep.get("scts"))
            tls[key] = {"protocols": _strs(rep.get("protocols")), "suites": _strs(rep.get("suites")),
                        "cert_sha256": _s(rep.get("cert_sha256")), "issuer": _s(rep.get("issuer")),
                        "not_after": _s(rep.get("not_after")), "key": _s(rep.get("key")), "scts": int(scts or 0)}
    sectxt = _d(inv.get("security_txt"))
    return {
        "schema": _num(snap.get("schema")), "kashif": _s(snap.get("kashif")), "scan_id": _s(snap.get("scan_id")),
        "target": _s(snap.get("target")), "profile": _s(snap.get("profile")), "crawl": snap.get("crawl") is True,
        "sensitivity": _s(snap.get("sensitivity")), "scanned_at": _s(snap.get("scanned_at")), "grades": grades,
        "checks": {k: v for k, v in _d(snap.get("checks")).items() if isinstance(k, str) and isinstance(v, str)},
        "findings": rows,
        "inventory": {
            "final_url": _s(inv.get("final_url")), "chain": chain,
            "headers": {k: v for k, v in _d(inv.get("headers")).items() if isinstance(k, str) and isinstance(v, str)},
            "csp": csp, "cookies": cookies,
            "third_party": {k: _strs(v) for k, v in _d(inv.get("third_party")).items() if isinstance(k, str)},
            "libraries": {k: v for k, v in _d(inv.get("libraries")).items() if isinstance(k, str) and isinstance(v, str)},
            "technologies": {k: v for k, v in _d(inv.get("technologies")).items()
                             if isinstance(k, str) and isinstance(v, str)},
            "tls": tls,
            "security_txt": {"present": sectxt.get("present") is True, "expires": _s(sectxt.get("expires"))},
            "robots_disallow": _strs(inv.get("robots_disallow")), "deep_hits": _strs(inv.get("deep_hits")),
        },
    }


def diff(previous: dict | None, current: dict, *, now: datetime | None = None) -> dict:
    """``web.diff``: new / resolved / unchanged findings, grade changes and posture changes (regressions first).
    Both snapshots go through :func:`sanitise` first, so a malformed or foreign previous file is never a crash."""
    out: dict[str, Any] = {"schema": SCHEMA, "comparable": False, "previous": None, "notes": [],
                           "findings": {"new": [], "resolved": [], "unchanged": []}, "grades": {}, "posture": [],
                           "counts": {}}
    previous = sanitise(previous) if previous else None
    current = sanitise(current) or sanitise({})
    if not previous:
        out["notes"].append({"en": t("no_previous"), "ar": t("no_previous", "ar")})
        return out
    out["previous"] = {"scan_id": previous.get("scan_id", ""), "scanned_at": previous.get("scanned_at", ""),
                       "profile": previous.get("profile", ""), "kashif": previous.get("kashif", "")}
    if not comparable(previous, current):
        prev_target = previous.get("target", "")
        out["notes"].append({"en": t("not_comparable", previous=prev_target),
                             "ar": t("not_comparable", "ar", previous=prev_target)})
        return out
    out["comparable"] = True
    if previous.get("profile") != current.get("profile"):
        b, a = previous.get("profile") or "?", current.get("profile") or "?"
        key = "deep_diff" if "deep" in (a, b) else "profile_diff"
        out["notes"].append({"en": t(key, previous=b, current=a), "ar": t(key, "ar", previous=b, current=a)})
    if now is None:
        now = _parse_date(current.get("scanned_at", "")) or datetime.now(timezone.utc)
    prev_rows = {r["key"]: r for r in previous.get("findings") or [] if r.get("key")}
    cur_rows = {r["key"]: r for r in current.get("findings") or [] if r.get("key")}
    # fall back to the fingerprint for rows from a snapshot whose key scheme differs
    prev_fp = {r.get("fingerprint"): k for k, r in prev_rows.items() if r.get("fingerprint")}
    matched_prev: set[str] = set()
    for key, row in cur_rows.items():
        pk = key if key in prev_rows else prev_fp.get(row.get("fingerprint"))
        if pk is not None and pk not in matched_prev:
            matched_prev.add(pk)
            out["findings"]["unchanged"].append(row)
        else:
            out["findings"]["new"].append(row)
    out["findings"]["resolved"] = [r for k, r in prev_rows.items() if k not in matched_prev]
    for bucket in out["findings"].values():
        bucket.sort(key=lambda r: (SEV_RANK.get(r.get("severity", ""), 9), r.get("rule", ""), r.get("key", "")))
    out["grades"], items = _grade_changes(previous, current)
    pi, ci = previous.get("inventory") or {}, current.get("inventory") or {}
    if pi.get("final_url") and ci.get("final_url") and pi["final_url"] != ci["final_url"]:
        items.append(_item("change", "redirect", "final_url", before=pi["final_url"], after=ci["final_url"]))
    elif pi.get("chain") and ci.get("chain") and pi["chain"] != ci["chain"]:
        fmt = lambda ch: " → ".join(f"{u} ({s})" for u, s in ch)[:300]   # noqa: E731
        items.append(_item("change", "redirect", "chain", before=fmt(pi["chain"]), after=fmt(ci["chain"])))
    items += _header_changes(pi.get("headers") or {}, ci.get("headers") or {})
    items += _csp_changes(pi.get("csp") or [], ci.get("csp") or [])
    items += _cookie_changes(pi.get("cookies") or {}, ci.get("cookies") or {})
    items += _third_changes(pi.get("third_party") or {}, ci.get("third_party") or {})
    items += _version_changes(pi.get("libraries") or {}, ci.get("libraries") or {}, "lib")
    items += _version_changes(pi.get("technologies") or {}, ci.get("technologies") or {}, "tech")
    items += _tls_changes(pi.get("tls") or {}, ci.get("tls") or {})
    items += _sectxt_changes(pi.get("security_txt") or {}, ci.get("security_txt") or {}, now)
    items += _set_changes(pi.get("robots_disallow"), ci.get("robots_disallow"), "robots", "robots_added",
                          "robots_removed", "change", "change")
    if previous.get("profile") == current.get("profile"):
        items += _set_changes(pi.get("deep_hits"), ci.get("deep_hits"), "deep_probe", "deep_new", "deep_gone",
                              "regression", "improvement")
        items += _check_changes(previous.get("checks") or {}, current.get("checks") or {})
    items.sort(key=lambda i: _ORDER[i["direction"]])          # stable: regressions, changes, improvements
    out["posture"] = items
    out["counts"] = {"new": len(out["findings"]["new"]), "resolved": len(out["findings"]["resolved"]),
                     "unchanged": len(out["findings"]["unchanged"]),
                     "regressions": sum(1 for i in items if i["direction"] == "regression"),
                     "improvements": sum(1 for i in items if i["direction"] == "improvement")}
    return out


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


__all__ = ["SCHEMA", "STR", "snapshot", "diff", "normalise_target", "comparable", "i18n_catalog"]
