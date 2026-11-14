"""Honest coverage (spec §3.8): one state per check — pass, fail, not_applicable, not_tested, inconclusive.

Every check module registers the check ids it owns (``CheckModule.CHECKS``; by default every ``check_id`` of the
registry is known). During a scan modules record states, optionally per host, with a reason. Rules:

* A check nobody recorded is ``not_tested`` (reason ``not_run``) — never ``pass``.
* Several records of one check combine by precedence ``fail > inconclusive > not_tested > pass > not_applicable``:
  a check that was skipped somewhere is never shown as passed, and a finding is never hidden by a skip elsewhere
  (``hosts`` keeps the per-host detail for the report).
* ``not_tested``/``inconclusive`` checks are never counted in a grade (WP13 reads :meth:`Coverage.tested`).

Reasons are codes from :data:`REASONS` (bilingual text, and whether the reason is the profile/sensitivity choice
rather than a limitation — WEB991 is emitted only for the latter) or free text given in both languages.
"""

from __future__ import annotations

from typing import Iterable

from .types import CHECK_STATES, CheckState

PRECEDENCE = {"fail": 4, "inconclusive": 3, "not_tested": 2, "pass": 1, "not_applicable": 0}

# code → (English, Arabic, no_web991): reasons that are the user's own choice (profile, sensitivity) or that follow from
# another check's result or from passive scanning by design never trigger WEB991 (it lists limitations of this run)
REASONS: dict[str, tuple[str, str, bool]] = {
    "not_run": ("the check did not run", "لم يُجرَ هذا الفحص", False),
    "profile": ("not part of the selected scan profile", "ليس ضمن ملف الفحص المختار", True),
    "deep_off": ("deep mode off", "الوضع العميق غير مفعّل", True),
    "crawl_off": ("crawling off", "الزحف غير مفعّل", True),
    "sensitivity": ("shown only at paranoid sensitivity", "يظهر فقط بحساسية paranoid", True),
    "budget": ("request budget reached", "بلغ الفحص حدّ عدد الطلبات", False),
    "time_budget": ("time budget reached", "بلغ الفحص حدّ الوقت", False),
    "byte_budget": ("download budget reached", "بلغ الفحص حدّ حجم التنزيل", False),
    "waf": ("a WAF challenge answered instead of the site", "أجاب جدار حماية بتحدٍّ بدل الموقع", False),
    "rate_limited": ("the site rate-limited the scan (429/503)", "قيّد الموقع معدل الطلبات (429/503)", False),
    "timeout": ("the server did not answer in time", "لم يستجب الخادم في الوقت المحدد", False),
    "network": ("network error", "خطأ في الشبكة", False),
    "proxied": ("scanning through a proxy", "الفحص يمر عبر وكيل (proxy)", False),
    "resolver": ("the local resolver cannot resolve public names", "محلّل الأسماء المحلي لا يحلّ الأسماء العامة", False),
    "tls13_encrypted": ("encrypted in TLS 1.3", "مشفّر في TLS 1.3", False),
    "ipv6_unreachable": ("IPv6 address unreachable from this network", "عنوان IPv6 غير قابل للوصول من هذه الشبكة", False),
    "ip_sampled": ("more than 4 addresses; this one was not sampled", "أكثر من 4 عناوين؛ لم يُختر هذا العنوان للفحص", False),
    "unsupported_coding": ("unsupported content-coding", "ترميز محتوى غير مدعوم", False),
    "truncated": ("the response was larger than the size cap", "الاستجابة أكبر من الحد المسموح", False),
    "robots": ("disallowed by robots.txt", "ممنوع في robots.txt", True),
    "no_document": ("no HTML document was fetched", "لم تُجلب أي صفحة HTML", False),
    "http_only": ("the target is served over HTTP only", "الهدف يُقدَّم عبر HTTP فقط", False),
    "data_missing": ("the bundled data file is missing", "ملف البيانات المضمّن مفقود", False),
    "third_party_off": ("third-party lookups are off (--third-party-lookups)", "الاستعلامات لدى أطراف ثالثة معطّلة (--third-party-lookups)", True),
    "error": ("internal error in this check", "خطأ داخلي في هذا الفحص", False),
    "precondition": ("not checked because an earlier certificate check failed",
                     "لم يُفحص لأن فحصًا سابقًا للشهادة فشل", True),
    "no_policy": ("no enforced Content-Security-Policy on this host (judged by WEB-content-security-policy)",
                  "لا توجد سياسة CSP مفروضة على هذا المضيف (يقيّمها WEB-content-security-policy)", True),
    "revocation": ("certificate revocation (CRL/OCSP) is not checked: a passive scan does not contact the CA; only a "
                   "stapled OCSP response is read",
                   "لا يُتحقَّق من إلغاء الشهادة (CRL/OCSP): الفحص السلبي لا يتصل بجهة الإصدار، ويُقرأ ردّ OCSP المرفق "
                   "بالمصافحة (stapling) فقط", True),
    "dh_unmeasured": ("key exchange strength not measured (DHE offered; run --web-profile deep)",
                      "لم تُقَس قوة تبادل المفاتيح (الخادم يعرض DHE؛ شغّل --web-profile deep)", True),
    "distro_backport": ("possible match hidden at this sensitivity (distribution build: backports likely); run "
                        "--web-sensitivity paranoid",
                        "تطابق محتمل مخفي بهذه الحساسية (نسخة توزيعة: يُرجَّح أنها تتضمن الإصلاحات المنقولة)؛ شغّل "
                        "--web-sensitivity paranoid", True),
    "distro_support": ("distribution build: support depends on the distribution release",
                       "نسخة توزيعة: يتوقف دعمها على إصدار التوزيعة", False),
}

_FORMS = {
    "pass": ("فحص واحد ناجح", "فحصان ناجحان", "{n} فحوص ناجحة", "{n} فحصًا ناجحًا", "{n} فحص ناجح"),
    "fail": ("فحص واحد فاشل", "فحصان فاشلان", "{n} فحوص فاشلة", "{n} فحصًا فاشلًا", "{n} فحص فاشل"),
    "not_applicable": ("فحص واحد غير منطبق", "فحصان غير منطبقين", "{n} فحوص غير منطبقة", "{n} فحصًا غير منطبق",
                       "{n} فحص غير منطبق"),
    "not_tested": ("فحص واحد لم يُجرَ", "فحصان لم يُجرَيا", "{n} فحوص لم تُجرَ", "{n} فحصًا لم يُجرَ", "{n} فحص لم يُجرَ"),
    "inconclusive": ("فحص واحد غير حاسم", "فحصان غير حاسمين", "{n} فحوص غير حاسمة", "{n} فحصًا غير حاسم",
                     "{n} فحص غير حاسم"),
}
_EN = {"pass": "passed", "fail": "failed", "not_applicable": "not applicable", "not_tested": "not tested",
       "inconclusive": "inconclusive"}
STATE_NAMES = {"pass": ("passed", "ناجح"), "fail": ("failed", "فاشل"), "not_applicable": ("not applicable", "غير منطبق"),
               "not_tested": ("not tested", "لم يُجرَ"), "inconclusive": ("inconclusive", "غير حاسم")}


def reason_text(code: str, detail_en: str = "", detail_ar: str = "") -> tuple[str, str, str]:
    """``(code, en, ar)`` for a reason code, with an optional detail appended (e.g. the WAF provider)."""
    en, ar, _user = REASONS.get(code, (code.replace("_", " "), code.replace("_", " "), False))
    if detail_en:
        en = f"{en}: {detail_en}"
    if detail_ar or detail_en:
        ar = f"{ar}: {detail_ar or detail_en}"
    return code, en, ar


class Coverage:
    def __init__(self, checks: Iterable[str] | None = None):
        if checks is None:
            from .rules import all_check_ids
            checks = all_check_ids()
        self._known: dict[str, None] = dict.fromkeys(checks)
        self._records: dict[str, list[tuple[str, str, tuple[str, str, str] | None]]] = {}

    # -- registration and recording ------------------------------------------------------------------------
    def register(self, *check_ids: str) -> None:
        for c in check_ids:
            self._known.setdefault(c, None)

    def record(self, check_id: str, state: str, reason: str = "", *, host: str = "", detail_en: str = "",
               detail_ar: str = "") -> None:
        if state not in CHECK_STATES:
            raise ValueError(f"unknown coverage state {state!r}")
        if state in ("not_tested", "inconclusive") and not reason:
            reason = "not_run"
        rsn = reason_text(reason, detail_en, detail_ar) if reason else None
        self._known.setdefault(check_id, None)
        self._records.setdefault(check_id, []).append((state, host, rsn))

    def passed(self, check_id: str, host: str = "") -> None:
        self.record(check_id, "pass", host=host)

    def failed(self, check_id: str, host: str = "") -> None:
        self.record(check_id, "fail", host=host)

    def not_applicable(self, check_id: str, reason: str = "", host: str = "", **kw) -> None:
        self.record(check_id, "not_applicable", reason, host=host, **kw)

    def not_tested(self, check_id: str, reason: str, host: str = "", **kw) -> None:
        self.record(check_id, "not_tested", reason, host=host, **kw)

    def inconclusive(self, check_id: str, reason: str, host: str = "", **kw) -> None:
        self.record(check_id, "inconclusive", reason, host=host, **kw)

    def record_many(self, check_ids: Iterable[str], state: str, reason: str = "", **kw) -> None:
        for c in check_ids:
            self.record(c, state, reason, **kw)

    # -- reading ---------------------------------------------------------------------------------------------
    def state(self, check_id: str) -> CheckState:
        recs = self._records.get(check_id)
        if not recs:
            return CheckState(check_id, "not_tested", [reason_text("not_run")])
        best = max(recs, key=lambda r: PRECEDENCE[r[0]])[0]
        reasons: list[tuple[str, str, str]] = []
        hosts: dict[str, str] = {}
        for st, host, rsn in recs:
            if rsn and st != "pass" and rsn not in reasons:
                reasons.append(rsn)
            if host:
                prev = hosts.get(host)
                if prev is None or PRECEDENCE[st] > PRECEDENCE[prev]:
                    hosts[host] = st
        return CheckState(check_id, best, reasons, hosts)

    def states(self) -> dict[str, CheckState]:
        return {c: self.state(c) for c in self._known}

    def counts(self) -> dict[str, int]:
        out = dict.fromkeys(CHECK_STATES, 0)
        for st in self.states().values():
            out[st.state] += 1
        return out

    def partial(self, check_id: str) -> bool:
        """True when the check ran (pass or fail) but was also skipped somewhere (a not_tested or inconclusive record:
        a page over budget, a blocked host): its absence of a finding then proves nothing for the skipped part."""
        recs = self._records.get(check_id) or []
        return any(r[0] in ("not_tested", "inconclusive") for r in recs) and any(r[0] in ("pass", "fail") for r in recs)

    def tested(self, check_id: str) -> bool:
        """True when the check ran (pass or fail): only such checks may count in a grade."""
        return self.state(check_id).state in ("pass", "fail")

    def skipped_for_limitations(self) -> list[CheckState]:
        """not_tested/inconclusive checks with at least one reason that is not the user's own choice (WEB991)."""
        out = []
        for st in self.states().values():
            if st.state in ("not_tested", "inconclusive") and any(
                    not REASONS.get(code, ("", "", False))[2] and code != "not_run" for code, _en, _ar in st.reasons):
                out.append(st)
        return out

    def summary(self, lang: str = "en") -> str:
        """``"142 passed · 9 failed · 6 not applicable · 3 not tested · 1 inconclusive"`` (Arabic with agreement)."""
        counts = self.counts()
        if lang == "ar":
            from ..i18n.plural import ar_count   # lazy: vulnscan.i18n may import webscan modules
            return " · ".join(ar_count(counts[s], _FORMS[s]) for s in CHECK_STATES)
        return " · ".join(f"{counts[s]} {_EN[s]}" for s in CHECK_STATES)

    def reasons(self, lang: str = "en") -> list[str]:
        """One line per non-pass check: ``"WEB705: not tested — encrypted in TLS 1.3"``."""
        out = []
        for cid, st in self.states().items():
            if st.state in ("pass", "fail"):
                continue
            name = STATE_NAMES[st.state][1 if lang == "ar" else 0]
            why = "؛ ".join(r[2] for r in st.reasons) if lang == "ar" else "; ".join(r[1] for r in st.reasons)
            out.append(f"{cid}: {name} — {why}" if why else f"{cid}: {name}")
        return out

    def to_dict(self) -> dict:
        return {"counts": self.counts(), "checks": [s.to_dict() for s in self.states().values()]}


def i18n_catalog() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """``(CATALOG, PATTERNS)`` for the Arabic reason texts and state names (for cat_web2). The summary line and the
    reason lines are produced in either language by :meth:`Coverage.summary` / :meth:`Coverage.reasons`."""
    catalog = {ar: en for en, ar, _user in REASONS.values()}
    catalog.update({ar: en for en, ar in STATE_NAMES.values()})
    return catalog, []


__all__ = ["Coverage", "REASONS", "PRECEDENCE", "STATE_NAMES", "reason_text", "i18n_catalog"]
