"""The three grades of a web scan (spec §3.4, WP13): the Kashif Web Grade (A+..F), the exact MDN HTTP Observatory
v6 score and grade, and the SSL Labs-compatible TLS grade. Each says which algorithm produced it.

    g = grade.grades(ctx, group_result.all_groups(), ctx.coverage)    # {"kashif": …, "observatory": …, "ssllabs": …}

**Kashif Web Grade** (:func:`kashif_grade`), exactly as §3.4 (a):

1. Six families with weights (``rules.GRADE_FAMILIES``): transport 20, TLS 20, browser policies 20, cookies 15, content
   15, exposure 10. Every rule belongs to one family (``RuleMeta.grade_family``); scan-meta rules never count.
2. Family score = max(0, 100 − Σ penalty). Penalty per severity: critical 100, high 40, medium 20, low 5, info 0; times
   the confidence weight: certain/firm 1, tentative 0 (0.5 at paranoid sensitivity). Each rule counts once however
   many pages share it (its worst group). **Sum cap per control** (``rules.CONTROLS``): on each host, the summed
   penalty of a control's findings (its "missing" rule and its weakness rules) is capped at the penalty the missing
   rule would have on those documents — so deleting a weak header never raises a grade. The same ceiling limits the
   severity a weakness finding contributes to the caps of step 6.
3. Base = Σ weight × family score / Σ weight of the *tested* families (coverage: at least one check passed or failed,
   or the family has findings). A family whose checks are all ``not_tested``/``inconclusive`` is left out and the
   grade gets the suffix ``*`` (provisional). A family whose checks are all ``not_applicable`` is left out silently.
4. Bonus (only when base ≥ 90 and no medium+ finding): +5 strict CSP or ``default-src 'none'``; +5 HSTS preloaded or
   preload-eligible with ≥ 1 year; +3 all cookies prefixed and SameSite; +2 COOP same-origin + CORP; at most +15.
5. Letter from Observatory's chart (≥ 100 A+, 90 A, 85 A-, 80 B+, 70 B, 65 B-, 60 C+, 50 C, 45 C-, 40 D+, 30 D, 25 D-).
6. Caps, applied last, the lowest wins (each listed with its reason); 7. A+ requirements; 8. a WAF/rate-limited entry
   (gate G4) gives ``?``, never a letter.

**Observatory** (:func:`observatory_score`): the scorer of ``mdn-http-observatory`` 1.7.2 ``src/scanner/index.js``
over the slugs the family modules wrote into ``ctx.observatory`` (their own job, quirks included), with the
modifiers and chart of ``data/web/observatory-v6.json``. Where Kashif's findings disagree with Observatory's verdict
the result lists the quirk (:func:`observatory_quirks`), so the report can show both.

**SSL Labs-compatible** (:func:`ssllabs`): ``webscan.tls.ssllabs_grade`` (WP10), labelled as excluding attack-only tests.

Pure functions of their inputs; no network, no file system beyond the bundled data file.
"""

from __future__ import annotations

from typing import Any, Iterable, Sequence

from .rules import CONTROLS, GRADE_FAMILIES, META_RULES, RULES, SEVERITIES
from .types import normalise_host

ALGORITHM = "kashif-web-1"
PENALTY: dict[str, float] = {"critical": 100.0, "high": 40.0, "medium": 20.0, "low": 5.0, "info": 0.0}
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
LETTERS = ("A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F")   # best → worst
CHART = ((100, "A+"), (90, "A"), (85, "A-"), (80, "B+"), (70, "B"), (65, "B-"), (60, "C+"), (50, "C"), (45, "C-"),
         (40, "D+"), (30, "D"), (25, "D-"))
FAMILY_ORDER = ("transport", "tls", "policies", "cookies", "content", "exposure")
CORE_FAMILIES = ("transport", "tls", "cookies")            # the "Transport, TLS or Cookies" of the caps table
BONUS_MAX = 15.0
ONE_YEAR = 31_536_000
OBS_PASS_EXCEPTIONS = frozenset({"csp-implemented-with-insecure-scheme-in-passive-content-only"})   # −10 yet pass
OBS_TESTS = ("content-security-policy", "cookies", "cross-origin-embedder-policy", "cross-origin-opener-policy",
             "cross-origin-resource-sharing", "redirection", "referrer-policy", "strict-transport-security",
             "subresource-integrity", "x-content-type-options", "x-frame-options", "cross-origin-resource-policy")

# what the "missing" rule of each control would weigh on a document (§3.1 severity modulation)
_STATIC_LOW = ("csp", "framing")

STR: dict[str, tuple[str, str]] = {
    # labels
    "kashif_label": ("Kashif Web Grade (A+ to F): six weighted families, capped by serious findings",
                     "درجة كاشف للويب (من A+ إلى F): ست مجموعات موزونة، مع حدود عليا عند وجود اكتشافات خطيرة"),
    "obs_label": ("MDN HTTP Observatory-compatible score (algorithm 6, the scorer of mdn-http-observatory 1.7.2)",
                  "درجة متوافقة مع MDN HTTP Observatory (الخوارزمية 6، بطريقة حساب mdn-http-observatory 1.7.2)"),
    "ssl_label": ("SSL Labs-compatible, excluding attack-only tests (Heartbleed, ROBOT, padding oracles, …), which Kashif "
                  "does not perform", "متوافقة مع SSL Labs، باستثناء اختبارات الهجوم (Heartbleed وROBOT وpadding oracle "
                  "…) التي لا يجريها كاشف"),
    # states
    "inconclusive": ("no grade: the site answered with a WAF challenge or a rate limit instead of the page (WEB990)",
                     "لا درجة: أجاب جدار حماية بتحدٍّ أو بتقييد للمعدل بدل الصفحة (WEB990)"),
    "nothing_tested": ("no grade: no check family could be tested", "لا درجة: تعذّر اختبار أي مجموعة من الفحوص"),
    "provisional": ("provisional: these families could not be tested: {families}",
                    "درجة مؤقتة: تعذّر اختبار هذه المجموعات: {families}"),
    "ssl_untested": ("not graded: no TLS handshake could be assessed", "بلا درجة: تعذّر تقييم أي مصافحة TLS"),
    "obs_down": ("not scored: the site did not answer", "لم تُحسب: لم يستجب الموقع"),
    "obs_none": ("not scored: no Observatory test result was computed in this scan",
                 "لم تُحسب: لم تُحسب أي نتيجة من اختبارات Observatory في هذا الفحص"),
    "obs_status": ("not scored: Observatory scores only 2xx, 3xx, 401 and 403 responses (got {status})",
                   "لم تُحسب: يحسب Observatory الاستجابات 2xx و3xx و401 و403 فقط (وصلت {status})"),
    "obs_partial": ("partial: these tests were not computed and count 0, as missing results do in Observatory: {tests}",
                    "جزئية: لم تُحسب هذه الاختبارات فاحتُسبت صفرًا كما يفعل Observatory مع النتائج المفقودة: {tests}"),
    "obs_cors": ("Kashif sends one GET with an Origin header instead of Observatory's OPTIONS preflight; the CORS result "
                 "uses that response", "يرسل كاشف طلب GET واحدًا مع ترويسة Origin بدل طلب OPTIONS الذي يرسله Observatory، "
                 "وتعتمد نتيجة CORS على تلك الاستجابة"),
    # caps
    "cap_critical": ("a critical finding", "وجود اكتشاف حرج"),
    "cap_high": ("a high-severity finding", "وجود اكتشاف عالي الخطورة"),
    "cap_rule": ("{rule}: {name}", "{rule}: {name}"),
    "cap_login_page": ("{rule} on a login page", "{rule} في صفحة تسجيل دخول"),
    "cap_http_login": ("the site is served over plain HTTP and has a login page (WEB000)",
                       "الموقع يُقدَّم عبر HTTP غير مشفّر وفيه صفحة تسجيل دخول (WEB000)"),
    "cap_sslv2": ("SSLv2 accepted (WEB704)", "الخادم يقبل SSLv2 (WEB704)"),
    "cap_sslv3": ("SSLv3 accepted (WEB704)", "الخادم يقبل SSLv3 (WEB704)"),  # nosec - protocol name
    "cap_no_csp": ("no enforced Content-Security-Policy on the scanned page", "لا توجد سياسة CSP مفروضة على الصفحة المفحوصة"),
    "cap_medium_core": ("a medium-severity finding in {family}", "وجود اكتشاف متوسط الخطورة في مجموعة {family}"),
    "cap_low_core": ("a low-severity finding in {family}", "وجود اكتشاف منخفض الخطورة في مجموعة {family}"),
    "cap_no_tls13": ("TLS 1.3 not supported (WEB705)", "عدم دعم TLS 1.3 (WEB705)"),
    "cap_hsts_short": ("HSTS max-age shorter than one year (WEB111)", "مدة HSTS أقصر من سنة (WEB111)"),
    "cap_hsts_isd": ("HSTS without includeSubDomains (WEB114)", "HSTS بلا includeSubDomains (WEB114)"),
    # A+ requirements
    "aplus_requires": ("A+ also requires: {items}", "تتطلب الدرجة A+ أيضًا: {items}"),
    "ap_provisional": ("every check family tested", "اختبار كل مجموعات الفحوص"),
    "ap_hsts": ("HTTPS with HSTS of at least one year", "HTTPS مع HSTS لمدة سنة على الأقل"),
    "ap_csp": ("an enforced CSP without WEB040, WEB041, WEB042, WEB204 or WEB209",
               "سياسة CSP مفروضة بلا WEB040 أو WEB041 أو WEB042 أو WEB204 أو WEB209"),
    "ap_tls": ("TLS 1.2 and 1.3 only, with AEAD forward-secret suites only",
               "TLS 1.2 و1.3 فقط، مع مجموعات تشفير AEAD ذات سرية أمامية فقط"),
    "ap_waf": ("no inconclusive part (WEB990)", "عدم وجود جزء غير حاسم (WEB990)"),
    # bonus
    "bonus_csp": ("strict CSP (nonce or hash with 'strict-dynamic', object-src 'none', base-uri) or default-src 'none'",
                  "سياسة CSP صارمة (nonce أو hash مع 'strict-dynamic' وobject-src 'none' وbase-uri) أو default-src 'none'"),
    "bonus_hsts": ("HSTS preloaded, or preload-eligible with at least one year",
                   "HSTS مُدرج في قائمة التحميل المسبق، أو مؤهل للإدراج بمدة سنة على الأقل"),
    "bonus_cookies": ("every cookie has a __Host- or __Secure- prefix and SameSite",
                      "كل الكوكيز تحمل البادئة __Host- أو __Secure- مع SameSite"),
    "bonus_iso": ("COOP same-origin together with CORP", "COOP بقيمة same-origin مع CORP"),
    # Observatory quirks (Kashif's finding and Observatory's verdict disagree; both are shown)
    "q_hsts_quoted": ("Observatory cannot parse a quoted max-age and passes it (even \"0\"); browsers honour the quoted "
                      "value, so Kashif reports HSTS as disabled (WEB110)",
                      "لا يستطيع Observatory قراءة max-age بين علامتي تنصيص فيعدّها ناجحة (حتى \"0\")؛ والمتصفحات تعتمد "
                      "القيمة المنصّصة، لذا يُبلغ كاشف أن HSTS معطّل (WEB110)"),
    "q_hsts_zero": ("Observatory scores max-age=0 as shorter than six months; browsers delete the HSTS entry, so Kashif "
                    "reports WEB110", "يعدّ Observatory القيمة max-age=0 أقصر من ستة أشهر؛ والمتصفحات تحذف قيد HSTS، لذا "
                    "يُبلغ كاشف عن WEB110"),
    "q_hsts_comma": ("Observatory marks an HSTS value containing a comma (repeated headers joined) as invalid; browsers "
                     "use the first header (WEB113)", "يعدّ Observatory قيمة HSTS التي فيها فاصلة (ترويسات مكررة مدموجة) "
                     "غير صالحة؛ والمتصفحات تعتمد الترويسة الأولى (WEB113)"),
    "q_xfo_fa": ("Observatory gives +5 for any frame-ancestors, even one that allows every site; Kashif reports WEB206",
                 "يمنح Observatory خمس نقاط لأي frame-ancestors حتى لو سمح بكل المواقع؛ ويُبلغ كاشف عن WEB206"),
    "q_xfo_dup": ("Observatory marks a repeated X-Frame-Options value as invalid; browsers honour it",
                  "يعدّ Observatory تكرار قيمة X-Frame-Options غير صالح؛ والمتصفحات تلتزم بها"),
    "q_csp_object": ("Observatory counts a policy without object-src or default-src as unsafe-inline; Kashif does not",
                     "يعدّ Observatory السياسة التي ليس فيها object-src ولا default-src سياسة unsafe-inline؛ وكاشف لا يعدّها كذلك"),
    "q_csp_dup": ("Observatory marks a policy with a repeated directive as invalid; browsers ignore only the repeat (WEB202)",
                  "يعدّ Observatory السياسة التي فيها توجيه مكرر غير صالحة؛ والمتصفحات تتجاهل التكرار فقط (WEB202)"),
    # one-line summary for the scan note
    "summary": ("Grades: Kashif {kashif} · Observatory {obs} · SSL Labs-compatible {ssl}",
                "الدرجات: كاشف {kashif} · Observatory {obs} · متوافقة مع SSL Labs {ssl}"),
    "none": ("not graded", "بلا درجة"),
}


def t(key: str, lang: str = "en", **params: Any) -> str:
    en, ar = STR[key]
    text = ar if lang == "ar" else en
    return text.format(**params) if params else text


def pair(key: str, **params: Any) -> dict[str, str]:
    return {"en": t(key, "en", **params), "ar": t(key, "ar", **params)}


# ----------------------------------------------------------------------------------------------- group access

def _rule(g: Any) -> str:
    return getattr(g, "rule", None) or getattr(g, "rule_id")


def _issues(g: Any) -> list:
    return list(getattr(g, "issues", None) or [g])


def _sev(i: Any) -> str:
    return getattr(i, "severity", None) or RULES[_rule(i)].severity


def _conf(i: Any) -> str:
    c = getattr(i, "confidence", None)
    if c is None and hasattr(i, "extra"):
        c = i.extra.get("confidence")
    return c or RULES[_rule(i)].confidence


def _host(g: Any) -> str:
    h = getattr(g, "host", "") or ""
    if h:
        return normalise_host(h)
    from .group import issue_host
    return issue_host(g)


def _roles(i: Any) -> frozenset[str]:
    ev = getattr(i, "evidence", None)
    return frozenset(getattr(ev, "role", None) or ())


def _urls(g: Any) -> set[str]:
    return {getattr(i, "url", "") for i in _issues(g)}


def _value(g: Any) -> str:
    return str(getattr(g, "value", "") or getattr(g, "group_value", "") or "")


def confidence_weights(paranoid: bool = False) -> dict[str, float]:
    return {"certain": 1.0, "firm": 1.0, "tentative": 0.5 if paranoid else 0.0}


def _penalty(g: Any, weights: dict[str, float]) -> float:
    return max((PENALTY[_sev(i)] * weights.get(_conf(i), 0.0) for i in _issues(g)), default=0.0)


def _counts(i: Any, weights: dict[str, float]) -> bool:
    return weights.get(_conf(i), 0.0) > 0


def _worst(g: Any, weights: dict[str, float]) -> str | None:
    """The most severe severity among the instances that count (confidence weight > 0)."""
    sevs = [_sev(i) for i in _issues(g) if _counts(i, weights)]
    return min(sevs, key=SEV_RANK.__getitem__) if sevs else None


def control_of(g: Any) -> str | None:
    """The §3.4 sum-cap control a finding belongs to (WEB207 goes to framing for frame-ancestors, else to CSP)."""
    rule = _rule(g)
    controls = RULES[rule].controls
    if not controls:
        return None
    if len(controls) > 1:
        return "framing" if "frame-ancestors" in _value(g).lower() and "framing" in controls else controls[0]
    return controls[0]


def missing_severity(control: str, roles: Iterable[frozenset[str]]) -> str:
    """The severity the control's "missing" rule would have on these documents (§3.1 modulation), from page roles
    alone (the fallback when the documents themselves are not at hand; :func:`would_be_severity` is exact)."""
    roles = list(roles)
    if control in _STATIC_LOW:
        return "low" if roles and all("static" in r for r in roles) else "medium"
    if control == "coop":
        return "low" if any(r & {"login", "authenticated"} for r in roles) else "info"
    return RULES[CONTROLS[control][0]].severity


# the roles that make a missing clickjacking defence medium (headers.py, WEB-x-frame-options)
_INTERACTIVE_ROLES = frozenset({"login", "signup", "authenticated", "admin"})
_UNKNOWN = object()


def _page_docs(ctx: Any) -> dict[str, Any] | None:
    """URL → parsed document (None when the page was not parsed) of every fetched page; None without a context."""
    pages = getattr(ctx, "pages", None) if ctx is not None else None
    if pages is None:
        return None
    out: dict[str, Any] = {}
    for p in pages:
        r = getattr(p, "response", None)
        if r is not None and getattr(r, "url", None):
            out.setdefault(r.url, getattr(p, "doc", None))
    return out


def _csp_static_doc(doc: Any) -> bool:
    """csp.py's rule for a missing CSP at low severity (no script, form, iframe, object, embed or on* attribute)."""
    try:
        from .csp import _static_doc
    except ImportError:   # pragma: no cover - csp.py renamed it: the role fallback still holds
        return False
    return _static_doc(doc)


def _would_be_medium(control: str, issue: Any, doc: Any) -> bool:
    """True when the control's missing rule would be medium (not low) on this issue's document."""
    roles = _roles(issue)
    if doc is _UNKNOWN:
        return missing_severity(control, [roles]) == "medium"
    if control == "csp":
        return not _csp_static_doc(doc)
    # framing: headers.py — medium on interactive documents (a role above, a live form or a password field)
    return bool(roles & _INTERACTIVE_ROLES) or (doc is not None and (any(getattr(f, "live", True) for f in doc.forms)
                                                                      or doc.has_password_field))


def would_be_severity(control: str, host: str, issues: Sequence[Any], ctx: Any = None,
                      docs: dict[str, Any] | None = None) -> str:
    """The severity the control's "missing" rule would have on the documents these findings were seen on, mirroring
    the emitting modules exactly when the context is at hand: CSP low on csp.py's static documents, clickjacking
    medium only on interactive documents (headers.py), HSTS info on a preloaded host (transport.py), COOP low only on
    login/authenticated pages. This is the per-control ceiling of §3.4 step 2."""
    if control == "hsts" and ctx is not None and hasattr(ctx, "hsts_for"):
        try:
            v = ctx.hsts_for(host)
        except (ValueError, AttributeError):
            v = None
        if v is not None and getattr(v, "preloaded", False):
            return "info"
    if control not in _STATIC_LOW:
        return missing_severity(control, [_roles(i) for i in issues])
    if docs is None:
        docs = _page_docs(ctx)
    if docs is None or not issues:
        return missing_severity(control, [_roles(i) for i in issues])
    medium = any(_would_be_medium(control, i, docs.get(getattr(i, "url", ""), _UNKNOWN)) for i in issues)
    return "medium" if medium else "low"


# ----------------------------------------------------------------------------------------------- families

def family_penalties(groups: Sequence[Any], paranoid: bool = False, ctx: Any = None
                     ) -> tuple[dict[str, float], dict[str, list[dict]], dict[int, str]]:
    """Per-family penalty with the per-control sum cap. Returns ``(penalty by family, contributions by family,
    ceilings)``; ``ceilings`` maps id(group) of every control *weakness* finding to the severity of the control's
    missing rule on those documents (:func:`would_be_severity`, exact when ``ctx`` is given): the most such a finding
    may contribute to the bonus gate and the caps."""
    weights = confidence_weights(paranoid)
    docs = _page_docs(ctx)
    plain: dict[tuple[str, str], float] = {}            # (rule, host) → worst penalty
    ctrl: dict[tuple[str, str], dict[str, float]] = {}  # (control, host) → rule → worst penalty
    ctrl_issues: dict[tuple[str, str], list[Any]] = {}
    missing_pen: dict[tuple[str, str], float] = {}
    members: list[tuple[Any, tuple[str, str]]] = []
    for g in groups:
        rule = _rule(g)
        if rule in META_RULES:
            continue
        p = _penalty(g, weights)
        host = _host(g)
        c = control_of(g)
        if c is None:
            plain[(rule, host)] = max(plain.get((rule, host), 0.0), p)
            continue
        key = (c, host)
        members.append((g, key))
        rules = ctrl.setdefault(key, {})
        rules[rule] = max(rules.get(rule, 0.0), p)
        ctrl_issues.setdefault(key, []).extend(_issues(g))
        if _is_missing_rule(rule, c):
            missing_pen[key] = max(missing_pen.get(key, 0.0), p)
    caps: dict[tuple[str, str], tuple[float, str]] = {}
    for key in ctrl:
        would = would_be_severity(key[0], key[1], ctrl_issues.get(key, []), ctx, docs)
        caps[key] = (max(PENALTY[would], missing_pen.get(key, 0.0)), would)
    ceilings = {id(g): caps[key][1] for g, key in members if not _is_missing_rule(_rule(g), key[0])}
    by_family: dict[str, float] = {f: 0.0 for f in FAMILY_ORDER}
    detail: dict[str, list[dict]] = {f: [] for f in FAMILY_ORDER}
    best_plain: dict[str, tuple[float, str]] = {}
    for (rule, host), p in plain.items():
        if p > best_plain.get(rule, (-1.0, ""))[0]:
            best_plain[rule] = (p, host)
    for rule, (p, host) in best_plain.items():
        fam = RULES[rule].grade_family
        if fam in by_family:
            by_family[fam] += p
            if p:
                detail[fam].append({"rule": rule, "host": host, "penalty": _num(p)})
    best_ctrl: dict[str, tuple[float, float, str, list[str]]] = {}
    for key, rules in ctrl.items():
        total = sum(rules.values())
        p = min(total, caps[key][0])
        if p > best_ctrl.get(key[0], (-1.0, 0.0, "", []))[0]:
            best_ctrl[key[0]] = (p, total, key[1], sorted(r for r, v in rules.items() if v))
    for c, (p, total, host, rules) in best_ctrl.items():
        fam = RULES[CONTROLS[c][0]].grade_family
        by_family[fam] += p
        if p or total:
            detail[fam].append({"control": c, "rules": rules, "host": host, "penalty": _num(p), "uncapped": _num(total)})
    return by_family, detail, ceilings


def _is_missing_rule(rule: str, control: str) -> bool:
    """True for a control's "missing" rule — unless that rule is also its weakness rule (WEB308 is both missing and
    invalid COOP), where only the would-be severity of the missing case may count."""
    missing, weak = CONTROLS[control]
    return rule == missing and rule not in weak


def effective_severity(g: Any, weights: dict[str, float], ceilings: dict[int, str]) -> str | None:
    """The worst severity among the instances that count, never above the control ceiling (None: nothing counts)."""
    worst = _worst(g, weights)
    ceiling = ceilings.get(id(g))
    if worst is None or ceiling is None:
        return worst
    return worst if SEV_RANK[worst] >= SEV_RANK[ceiling] else ceiling


def _coverage_states(coverage: Any) -> dict[str, str] | None:
    if coverage is None:
        return None
    if hasattr(coverage, "states"):
        return {cid: st.state for cid, st in coverage.states().items()}
    if isinstance(coverage, dict):
        checks = coverage.get("checks")
        if isinstance(checks, list):
            return {c.get("check"): c.get("state") for c in checks if isinstance(c, dict)}
        return {k: (v.get("state") if isinstance(v, dict) else v) for k, v in coverage.items()}
    return None


def family_states(coverage: Any, groups: Sequence[Any] = ()) -> dict[str, str]:
    """``tested`` | ``untested`` (all not_tested/inconclusive → provisional) | ``not_applicable`` per family."""
    states = _coverage_states(coverage)
    with_findings = {RULES[_rule(g)].grade_family for g in groups if _rule(g) in RULES}
    out: dict[str, str] = {}
    for fam in FAMILY_ORDER:
        if states is None or fam in with_findings:
            out[fam] = "tested"
            continue
        checks = {m.check_id for m in RULES.values() if m.grade_family == fam}
        seen = [states[c] for c in checks if c in states]
        if any(s in ("pass", "fail") for s in seen):
            out[fam] = "tested"
        elif seen and all(s == "not_applicable" for s in seen):
            out[fam] = "not_applicable"
        else:
            out[fam] = "untested"
    return out


def letter_for(score: float) -> str:
    s = round(score, 6)
    for floor, letter in CHART:
        if s >= floor:
            return letter
    return "F"


def _lower(a: str, b: str) -> str:
    return a if LETTERS.index(a) >= LETTERS.index(b) else b


# ----------------------------------------------------------------------------------------------- context facts

def _entry(ctx: Any):
    return getattr(ctx, "entry", None) if ctx is not None else None


def _entry_urls(ctx: Any) -> set[str]:
    e = _entry(ctx)
    out: set[str] = set()
    if e is not None:
        out.add(e.url)
        out.update(h.url for h in e.chain)
    if ctx is not None and getattr(ctx, "target", None):
        out.add(ctx.target)
    return out


def _entry_inconclusive(ctx: Any) -> bool:
    e = _entry(ctx)
    return e is not None and e.kind in ("waf_challenge", "rate_limited")


def _has_login(ctx: Any, groups: Sequence[Any], extra_issues: Iterable[Any] = ()) -> bool:
    for p in getattr(ctx, "pages", None) or ():
        if "login" in p.response.roles:
            return True
    for g in groups:
        for i in _issues(g):
            if "login" in _roles(i):
                return True
    return any("login" in _roles(i) for i in extra_issues)


def _hsts(ctx: Any):
    e = _entry(ctx)
    if e is None or not hasattr(ctx, "hsts_for"):
        return None
    try:
        return ctx.hsts_for(e.host)
    except ValueError:
        return None


def _hsts_year(ctx: Any) -> bool:
    e = _entry(ctx)
    v = _hsts(ctx)
    return bool(e is not None and e.is_https and v is not None and v.effective and (v.max_age or 0) >= ONE_YEAR)


def _csp_facts(ctx: Any):
    e = _entry(ctx)
    if e is None or not hasattr(ctx, "csp_for"):
        return None
    return ctx.csp_for(e)


def _tokens(policy: Any, name: str) -> list[str] | None:
    vals = policy.directives.get(name)
    if vals is None:
        return None
    return [v if v.lower().startswith(("'nonce-", "'sha")) else v.lower() for v in vals]


def _strict_policy(policy: Any) -> bool:
    script = _tokens(policy, "script-src")
    if script is None:
        script = _tokens(policy, "default-src")
    obj = _tokens(policy, "object-src")
    if obj is None:
        obj = _tokens(policy, "default-src")
    base = _tokens(policy, "base-uri")
    if not script or obj is None or base is None:
        return False
    has_nonce = any(v.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for v in script)
    return (has_nonce and "'strict-dynamic'" in script and obj == ["'none'"] and bool(base)
            and set(base) <= {"'none'", "'self'"})


def _default_none(policy: Any) -> bool:
    return _tokens(policy, "default-src") == ["'none'"]


def _first_token(value: str | None) -> str:
    return (value or "").split(";", 1)[0].split(",", 1)[0].strip().lower()


def tls_modern_only(ctx: Any) -> bool | None:
    """True when every assessed IP offers nothing older than TLS 1.2 and only AEAD forward-secret suites; False when one
    does not; None when no TLS handshake was assessed."""
    reports = getattr(ctx, "tls", None) or {}
    seen = False
    for rep in reports.values():
        if not isinstance(rep, dict):
            continue
        for ip in (rep.get("ips") or {}).values():
            if not isinstance(ip, dict) or ip.get("status") != "ok":
                continue
            seen = True
            versions = {k: (v or {}).get("state") for k, v in (ip.get("versions") or {}).items()}
            cats = {k: (v or {}).get("state") for k, v in (ip.get("categories") or {}).items()}
            if "yes" not in (versions.get("TLSv1.2"), versions.get("TLSv1.3")):
                return False        # (a TLS 1.3-only server qualifies; a missing TLS 1.3 is capped at A- by WEB705)
            if any(versions.get(v) == "yes" for v in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")):  # nosec - protocol name
                return False
            if any(cats.get(c) == "yes" for c in ("null_anon", "export_des", "rc4", "3des", "krsa", "cbc")):
                return False
    return True if seen else None


# ----------------------------------------------------------------------------------------------- Kashif grade

def kashif_grade(ctx: Any, groups: Sequence[Any], coverage: Any = None, *, sensitivity: str | None = None,
                 suppressed: Iterable[Any] = ()) -> dict:
    """The Kashif Web Grade (§3.4 a). ``groups``: every grouped finding (``GroupResult.all_groups()``);
    ``suppressed``: issues suppressed by grouping (they still tell whether the site has a login page)."""
    if sensitivity is None:
        sensitivity = getattr(getattr(ctx, "options", None), "sensitivity", "default")
    paranoid = sensitivity == "paranoid"
    weights = confidence_weights(paranoid)
    groups = [g for g in groups if _rule(g) in RULES]
    out: dict[str, Any] = {"algorithm": ALGORITHM, "label": pair("kashif_label"), "grade": "?", "letter": "?",
                           "score": None, "base": None, "provisional": False, "families": {}, "bonus": {"total": 0,
                           "items": []}, "caps": [], "aplus_missing": [], "notes": []}
    if _entry_inconclusive(ctx):
        out["notes"].append(pair("inconclusive"))
        out["inconclusive"] = True
        return out
    penalties, detail, ceilings = family_penalties(groups, paranoid, ctx)
    fstates = family_states(coverage, groups)
    num = den = 0.0
    untested: list[str] = []
    for fam in FAMILY_ORDER:
        en, ar, weight = GRADE_FAMILIES[fam]
        score = max(0.0, 100.0 - penalties[fam])
        state = fstates[fam]
        out["families"][fam] = {"name": {"en": en, "ar": ar}, "weight": weight, "score": _num(score),
                                "penalty": _num(penalties[fam]), "state": state, "contributions": detail[fam]}
        if state == "tested":
            num += weight * score
            den += weight
        elif state == "untested":
            untested.append(fam)
    if den == 0:
        out["notes"].append(pair("nothing_tested"))
        return out
    base = num / den
    provisional = bool(untested)
    out["provisional"] = provisional
    if provisional:
        out["notes"].append({"en": t("provisional", "en", families=", ".join(GRADE_FAMILIES[f][0] for f in untested)),
                             "ar": t("provisional", "ar", families="، ".join(GRADE_FAMILIES[f][1] for f in untested))})
    # step 4: bonus
    counting = [g for g in groups if _rule(g) not in META_RULES and _worst(g, weights) is not None]
    medium_plus = any(SEV_RANK[effective_severity(g, weights, ceilings) or "info"] <= SEV_RANK["medium"]
                      for g in counting)
    bonus_items = _bonus(ctx, groups) if base >= 90 and not medium_plus else []
    bonus = min(BONUS_MAX, sum(p for _k, p in bonus_items))
    score = base + bonus
    out.update(base=_num(base), score=_num(score))
    out["bonus"] = {"total": _num(bonus), "items": [{"id": k, "points": p, **pair(k)} for k, p in bonus_items]}
    letter = letter_for(score)
    # step 7: A+ requirements
    if letter == "A+":
        missing = _aplus_missing(ctx, groups, provisional)
        if missing:
            letter = "A"
            out["aplus_missing"] = [{"id": k, **pair(k)} for k in missing]
            out["notes"].append({"en": t("aplus_requires", "en", items="; ".join(t(k, "en") for k in missing)),
                                 "ar": t("aplus_requires", "ar", items="؛ ".join(t(k, "ar") for k in missing))})
    # step 6: caps (lowest wins)
    caps = _caps(ctx, groups, ceilings, suppressed)
    for cap in caps:
        letter = _lower(letter, cap["cap"])
    out["caps"] = caps
    out["letter"] = letter
    out["grade"] = letter + ("*" if provisional else "")
    return out


def _num(x: float) -> float:
    r = round(x, 2)
    return int(r) if r == int(r) else r


def _bonus(ctx: Any, groups: Sequence[Any]) -> list[tuple[str, float]]:
    items: list[tuple[str, float]] = []
    facts = _csp_facts(ctx)
    if facts is not None:
        enforced = list(getattr(facts, "enforced", []) or [])
        csp_weak = any(_rule(g).startswith("WEB2") and RULES[_rule(g)].family == "B" and
                       SEV_RANK[_worst(g, confidence_weights(True)) or "info"] <= SEV_RANK["low"] for g in groups)
        if any(_default_none(p) for p in enforced) or (any(_strict_policy(p) for p in enforced) and not csp_weak):
            items.append(("bonus_csp", 5.0))
    v = _hsts(ctx)
    e = _entry(ctx)
    if v is not None and e is not None and e.is_https and v.effective:
        not_eligible = any(_rule(g) == "WEB115" and _worst(g, confidence_weights(True)) == "low" for g in groups)
        eligible = (v.preload and v.include_subdomains and (v.max_age or 0) >= ONE_YEAR and not not_eligible)
        if v.preloaded or eligible:
            items.append(("bonus_hsts", 5.0))
    cookies = [c for c in (getattr(ctx, "cookies", None) or ()) if not c.deletion and not c.ignored]
    if cookies and all(c.name.lower().startswith(("__host-", "__secure-")) and
                       (c.samesite or "").lower() in ("lax", "strict", "none") for c in cookies):
        items.append(("bonus_cookies", 3.0))
    if e is not None and e.is_https:
        coop = _first_token(e.headers.first("cross-origin-opener-policy"))
        corp = (e.headers.joined("cross-origin-resource-policy") or "").strip().lower()
        if coop == "same-origin" and e.headers.count("cross-origin-opener-policy") == 1 and corp in ("same-origin",
                                                                                                    "same-site"):
            items.append(("bonus_iso", 2.0))
    return items


def _aplus_missing(ctx: Any, groups: Sequence[Any], provisional: bool) -> list[str]:
    missing: list[str] = []
    rules = {_rule(g) for g in groups}
    if provisional:
        missing.append("ap_provisional")
    if not _hsts_year(ctx):
        missing.append("ap_hsts")
    facts = _csp_facts(ctx)
    entry_urls = _entry_urls(ctx)
    weak = any(_rule(g) in ("WEB040", "WEB041", "WEB042", "WEB204", "WEB209") and _urls(g) & entry_urls for g in groups)
    if facts is None or not facts.has_enforced or weak:
        missing.append("ap_csp")
    if tls_modern_only(ctx) is not True:
        missing.append("ap_tls")
    if "WEB990" in rules:
        missing.append("ap_waf")
    return missing


def _cap(letter: str, key: str, rule_id: str = "", **params: Any) -> dict:
    if key == "cap_rule":
        m = RULES[rule_id]
        return {"cap": letter, "rule": rule_id, "en": t(key, "en", rule=rule_id, name=m.name_en),
                "ar": t(key, "ar", rule=rule_id, name=m.name_ar)}
    en_params = {k: (v[0] if isinstance(v, tuple) else v) for k, v in params.items()}
    ar_params = {k: (v[1] if isinstance(v, tuple) else v) for k, v in params.items()}
    return {"cap": letter, "rule": rule_id, "en": t(key, "en", **en_params), "ar": t(key, "ar", **ar_params)}


_SPECIAL_HIGH = frozenset({"WEB070", "WEB072", "WEB700", "WEB701", "WEB720", "WEB704", "WEB320", "WEB000", "WEB509"})
CAP_WEIGHTS = {"certain": 1.0, "firm": 1.0}          # tentative findings never cap a grade


def _caps(ctx: Any, groups: Sequence[Any], ceilings: dict[int, str], suppressed: Iterable[Any]) -> list[dict]:
    """Step 6 caps (certain/firm findings only; a control weakness never caps lower than its missing rule)."""
    caps: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(cap: dict) -> None:
        k = (cap["cap"], cap["en"])
        if k not in seen:
            seen.add(k)
            caps.append(cap)

    login_site = _has_login(ctx, groups, suppressed)
    entry_urls = _entry_urls(ctx)
    for g in groups:
        rule = _rule(g)
        if rule in META_RULES:
            continue
        sev = effective_severity(g, CAP_WEIGHTS, ceilings)
        if sev is None:
            continue
        insts = [i for i in _issues(g) if _counts(i, CAP_WEIGHTS)]
        fam = RULES[rule].grade_family
        special = rule in _SPECIAL_HIGH
        # F
        if sev == "critical":
            add(_cap("F", "cap_critical", rule))
        if rule in ("WEB070", "WEB072", "WEB700", "WEB720"):
            add(_cap("F", "cap_rule", rule))
        if rule == "WEB701" and any(_conf(i) == "certain" for i in insts):
            add(_cap("F", "cap_rule", rule))
        if rule == "WEB704":
            if any("SSLv2" in (getattr(i, "group_value", "") or "") for i in insts) or "SSLv2" in _value(g):
                add(_cap("F", "cap_sslv2", rule))
            else:
                add(_cap("D", "cap_sslv3", rule))
        if rule == "WEB052" and any(_roles(i) & {"login", "signup"} or not _roles(i) for i in insts):
            add(_cap("F", "cap_login_page", rule, rule=rule))
            special = True
        if rule == "WEB509" and sev == "high":
            add(_cap("F", "cap_login_page", rule, rule=rule))
        # D
        if rule == "WEB320":
            add(_cap("D", "cap_rule", rule))
        if rule == "WEB000" and sev != "info":
            add(_cap("D", "cap_http_login", rule) if login_site else _cap("B+", "cap_rule", rule))
        # C+
        if sev == "high" and not special:
            add(_cap("C+", "cap_high", rule))
        # B+
        if rule == "WEB030":
            add(_cap("B+", "cap_rule", rule))
        if rule in ("WEB-content-security-policy", "WEB200") and _urls(g) & entry_urls:
            add(_cap("B+", "cap_no_csp", rule))
        if fam in CORE_FAMILIES and sev == "medium":
            add(_cap("B+", "cap_medium_core", rule, family=(GRADE_FAMILIES[fam][0], GRADE_FAMILIES[fam][1])))
        # A-
        if rule == "WEB705" and sev == "low":
            add(_cap("A-", "cap_no_tls13", rule))
        if rule == "WEB111" and sev in ("low", "medium"):
            add(_cap("A-", "cap_hsts_short", rule))
        # A
        if fam in CORE_FAMILIES and sev == "low":
            add(_cap("A", "cap_low_core", rule, family=(GRADE_FAMILIES[fam][0], GRADE_FAMILIES[fam][1])))
        if rule == "WEB114":
            add(_cap("A", "cap_hsts_isd", rule))
    caps.sort(key=lambda c: -LETTERS.index(c["cap"]))
    return caps


# ----------------------------------------------------------------------------------------------- Observatory v6

def observatory_table(data_module: Any = None) -> dict:
    if data_module is None:
        from . import data as data_module
    return data_module.load_json("observatory-v6.json")


def observatory_score(slugs: dict[str, str], *, status: int | None = 200, table: dict | None = None) -> dict:
    """Observatory's ``analyzeScan`` scorer (mdn-http-observatory 1.7.2) over the 12 test slugs. A test without a slug
    is skipped exactly as Observatory skips a test without a result (and the result is marked ``partial``)."""
    table = table or observatory_table()
    out: dict[str, Any] = {"algorithm": f"mdn-observatory-v{table['algorithm_version']}",
                           "upstream_version": table.get("meta", {}).get("upstream_version", ""),
                           "label": pair("obs_label"), "score": None, "grade": None, "max_score": table["max_score"],
                           "tests": {}, "tests_passed": 0, "tests_quantity": len(OBS_TESTS), "partial": False,
                           "notes": [], "quirks": []}
    if status is None:
        out["notes"].append(pair("obs_down"))
        return out
    if not any(slugs.get(t) for t in OBS_TESTS):
        out["notes"].append(pair("obs_none"))
        return out
    if status < 200 or (status >= 400 and status not in (401, 403)):
        out["notes"].append(pair("obs_status", status=status))
        return out
    with_extra = uncurved = table.get("base_score", 100)
    passed = 0
    missing: list[str] = []
    for test in OBS_TESTS:
        slug = slugs.get(test)
        if not slug:
            missing.append(test)
            continue
        mod = table["tests"].get(test, {}).get(slug)
        known = mod is not None
        mod = int(mod or 0)
        ok = (mod >= 0 or slug in OBS_PASS_EXCEPTIONS) if known else False
        out["tests"][test] = {"slug": slug, "modifier": mod, "pass": ok, "known": known}
        passed += 1 if ok else 0
        with_extra += mod
        if mod < 0:
            uncurved += mod
    score = with_extra if uncurved >= table["extra_credit_threshold"] else uncurved
    score = max(score, 0)
    key = min(score - score % 5, 100)
    out.update(score=score, grade=table["grade_chart"][str(key)], tests_passed=passed, uncurved=uncurved,
               with_extra_credit=with_extra, extra_credit=uncurved >= table["extra_credit_threshold"])
    if missing:
        out["partial"] = True
        out["missing_tests"] = missing
        out["notes"].append(pair("obs_partial", tests=", ".join(missing)))
    return out


def observatory_auto(ctx: Any):
    """Observatory's ``responses.auto``: the https session's final response when https answered, else http's."""
    if ctx is None:
        return None
    for r in (getattr(ctx, "entry", None), getattr(ctx, "https_probe", None), getattr(ctx, "http_probe", None)):
        if r is not None and r.is_https and r.status is not None and not r.error:
            return r
    for r in (getattr(ctx, "entry", None), getattr(ctx, "http_probe", None)):
        if r is not None and r.status is not None and not r.error:
            return r
    return None


def observatory_quirks(slugs: dict[str, str], groups: Sequence[Any]) -> list[dict]:
    """Where Kashif's finding and Observatory's verdict disagree, name the quirk (both are shown in the report)."""
    rules = {_rule(g) for g in groups}
    q: list[str] = []
    hsts = slugs.get("strict-transport-security", "")
    if hsts in ("hsts-implemented-max-age-at-least-six-months", "hsts-preloaded") and "WEB110" in rules:
        q.append("q_hsts_quoted")
    if hsts == "hsts-implemented-max-age-less-than-six-months" and "WEB110" in rules:
        q.append("q_hsts_zero")
    if hsts == "hsts-header-invalid" and "WEB113" in rules and "WEB112" not in rules:
        q.append("q_hsts_comma")
    xfo = slugs.get("x-frame-options", "")
    if xfo == "x-frame-options-implemented-via-csp" and "WEB206" in rules:
        q.append("q_xfo_fa")
    if xfo == "x-frame-options-header-invalid" and not rules & {"WEB-x-frame-options", "WEB300"}:
        q.append("q_xfo_dup")
    csp = slugs.get("content-security-policy", "")
    if csp == "csp-implemented-with-unsafe-inline" and not rules & {"WEB040", "WEB042", "WEB043"}:
        q.append("q_csp_object")
    if csp == "csp-header-invalid" and "WEB202" in rules and not rules & {"WEB201", "WEB203"}:
        q.append("q_csp_dup")
    out = [{"id": k, **pair(k)} for k in q]
    if slugs.get("cross-origin-resource-sharing"):
        out.append({"id": "obs_cors", **pair("obs_cors")})
    return out


def observatory(ctx: Any, groups: Sequence[Any] = (), table: dict | None = None) -> dict:
    """The Observatory-compatible score of a scan from ``ctx.observatory`` (slugs written by the family modules)."""
    auto = observatory_auto(ctx)
    status = auto.status if auto is not None else None
    slugs = dict(getattr(ctx, "observatory", None) or {})
    res = observatory_score(slugs, status=status, table=table)
    if res["score"] is not None:
        res["quirks"] = observatory_quirks(slugs, groups)
    return res


# ----------------------------------------------------------------------------------------------- SSL Labs

def ssllabs(ctx: Any) -> dict:
    """The SSL Labs-compatible TLS grade of WP10 (worst host and IP), labelled as excluding attack-only tests."""
    g = None
    if ctx is not None and getattr(ctx, "tls", None):
        try:
            from .tls import ssllabs_grade
            g = ssllabs_grade(ctx)
        except Exception:   # noqa: BLE001 - a TLS report it cannot read must not break the other grades
            g = None
    if not g:
        return {"algorithm": "ssllabs-2009r-compatible", "grade": None, "label": pair("ssl_label"),
                "notes": [pair("ssl_untested")]}
    out = dict(g)
    out["algorithm"] = "ssllabs-2009r-compatible"
    out["label"] = pair("ssl_label")
    return out


# ----------------------------------------------------------------------------------------------- all three

def grades(ctx: Any, groups: Sequence[Any], coverage: Any = None, *, sensitivity: str | None = None,
           suppressed: Iterable[Any] = ()) -> dict:
    """``web.grades`` of the JSON report: ``{"kashif": …, "observatory": …, "ssllabs": …}``. ``groups`` may be a
    ``group.GroupResult`` (its groups and suppressed issues are then used) or a list of groups."""
    if coverage is None:
        coverage = getattr(ctx, "coverage", None)
    if hasattr(groups, "all_groups"):
        suppressed = list(suppressed) + [i for i, _reason in getattr(groups, "suppressed", ())]
        groups = groups.all_groups()
    groups = list(groups)
    return {"kashif": kashif_grade(ctx, groups, coverage, sensitivity=sensitivity, suppressed=suppressed),
            "observatory": observatory(ctx, groups), "ssllabs": ssllabs(ctx)}


def summary(g: dict, lang: str = "en") -> str:
    """One line for the scan note: ``Grades: Kashif B+ · Observatory 85/100 (A-) · SSL Labs-compatible A``."""
    none = t("none", lang)
    k = (g.get("kashif") or {}).get("grade") or none
    o = g.get("observatory") or {}
    obs = f"{o['score']} ({o['grade']})" if o.get("score") is not None else none
    s = (g.get("ssllabs") or {}).get("grade") or none
    return t("summary", lang, kashif=k, obs=obs, ssl=s)


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


__all__ = ["ALGORITHM", "PENALTY", "LETTERS", "CHART", "STR", "kashif_grade", "observatory_score", "observatory",
           "observatory_quirks", "observatory_auto", "ssllabs", "grades", "summary", "letter_for", "control_of",
           "missing_severity", "would_be_severity", "family_penalties", "family_states", "tls_modern_only", "confidence_weights",
           "i18n_catalog"]
