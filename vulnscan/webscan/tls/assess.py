"""TLS and certificate assessment (spec §2.8, WP10): WEB030, WEB070–WEB072, WEB700–WEB720, the SSL Labs-compatible
grade (§3.4 c) and Mozilla server-side TLS 6.0 conformance.

A pure function of ``ctx.tls`` (filled by :func:`vulnscan.webscan.tls.probe.collect`, pipeline step 4): this module never
opens a socket. Every check is judged per IP (§2.8 step 5); identical findings of several IPs are merged and list the
IPs they apply to, and differences between IPs are explained by WEB715.

Tri-state honesty (§2.8 step 3, §3.8): a probe that timed out or was cut by the back-off is *inconclusive*; such a
check is recorded ``not_tested`` with the reason and is never shown as passed. A check that cannot apply (TLS
compression on a TLS 1.3-only server) is ``not_applicable``.

Certificate verdicts combine OpenSSL's verify code with facts parsed from the DER (x509.py). The verify code says which
step failed first; OpenSSL checks in this order (verified on 3.0.13 and 3.5.9): chain building (2, 18, 19, 20, 21),
chain extensions/purpose (26 …), security level (66–68), host name (62), then signatures and dates (7, 9, 10). So a
later code proves every earlier step passed, and the facts after the failing step come from the DER instead.
"""

from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import re
from datetime import timedelta
from typing import Any

from .. import psl, rules
from ..types import Evidence, Issue, openssl_command
from . import raw, x509

CHECKS: tuple[str, ...] = rules.checks_for_module("tls")
HOST_KIND = "kashif-tls-host"

# OpenSSL verify codes (x509_vfy.h)
CODE_HOSTNAME = 62
CODE_EXPIRED, CODE_NOT_YET = 10, 9
CODE_SELF_SIGNED, CODE_SELF_SIGNED_IN_CHAIN = 18, 19
CODE_NO_ISSUER = frozenset({2, 20, 21})
NOT_ANCHORED = frozenset({2, 18, 19, 20, 21})
SECLEVEL_CODES = frozenset({66, 67, 68})
# failures that only VERIFY_X509_STRICT raises (Kashif clears that flag for browser parity, D19): informational
STRICT_ONLY = frozenset({79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92})
# verify codes another rule reports (WEB700, WEB070, WEB720, WEB701/WEB702): WEB072 is not raised for them. The security-
# level codes are not here: a SHA-1 or weak-key chain is rejected by browsers, so it is a WEB072 failure (§2.8, T grade)
MAPPED = frozenset({CODE_HOSTNAME, CODE_EXPIRED, CODE_NOT_YET}) | NOT_ANCHORED | STRICT_ONLY

CLOCK_SKEW = timedelta(minutes=5)
CT_STALE_DAYS = 120
# CA/Browser Forum ballot SC-081: maximum validity by issuance date (notBefore)
LIFETIME_LIMITS = (("2026-03-15", 398), ("2027-03-15", 200), ("2029-03-15", 100), ("9999-12-31", 47))

# RFC 2409 Oakley group 2 and RFC 5114 1024-bit MODP: shared 1024-bit primes precomputation targets (Logjam)
COMMON_DH_PRIMES = {
    "oakley-group-2": int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E"
                          "3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5C"
                          "B6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16),
}
COMMON_DH_SHA256 = {hashlib.sha256(p.to_bytes((p.bit_length() + 7) // 8, "big")).hexdigest(): name
                    for name, p in COMMON_DH_PRIMES.items()}

VERSION_LABEL = {"SSLv2": "SSLv2", "SSLv3": "SSLv3", "TLSv1.0": "TLS 1.0", "TLSv1.1": "TLS 1.1", "TLSv1.2": "TLS 1.2",  # nosec
                 "TLSv1.3": "TLS 1.3"}
CATEGORY_RULE = {  # WEB706: probe category → (severity, English label, Arabic label)
    "null": ("high", "NULL encryption", "بلا تشفير (NULL)"),
    "anon": ("high", "anonymous key exchange", "تبادل مفاتيح مجهول الهوية (anon)"),
    "export": ("high", "EXPORT-grade suites", "مجموعات EXPORT ضعيفة"),
    "des": ("high", "single DES", "تشفير DES المفرد"),
    "rc4": ("high", "RC4", "RC4"),
    "3des": ("medium", "3DES (SWEET32)", "3DES (هجوم SWEET32)"),
    "krsa": ("low", "static RSA key exchange (no forward secrecy)", "تبادل مفاتيح RSA ثابت (بلا سرية أمامية)"),
}

STR: dict[str, tuple[str, str]] = {
    "proxied": ("seen through proxy {proxy}; an inspecting proxy replaces the certificate",
                "شوهد عبر الوكيل {proxy}؛ والوكيل الذي يفحص الحركة يستبدل الشهادة"),
    "no_cert": ("no certificate was received", "لم تُستلم أي شهادة"),
    "no_verify": ("the verified handshake did not complete", "لم تكتمل المصافحة مع التحقق"),
    "seclevel": ("trust judged with weak keys and digests allowed (they are reported by WEB707/WEB708)",
                 "قُيّمت الثقة مع السماح بالمفاتيح والخوارزميات الضعيفة (يُبلَّغ عنها في WEB707 وWEB708)"),
    "browser_reject": ("rejected by browsers: SHA-1 or weak key in chain (verify code {code}); the chain itself is "
                       "otherwise trusted",
                       "ترفضها المتصفحات: SHA-1 أو مفتاح ضعيف في السلسلة (رمز التحقق {code})؛ والسلسلة موثوقة فيما عدا ذلك"),
    "dh_unmeasured": ("key exchange strength not measured (DHE offered; run --web-profile deep)",
                      "لم تُقَس قوة تبادل المفاتيح (الخادم يعرض DHE؛ شغّل --web-profile deep)"),
    "trust_cap": ("certificate not trusted: {why}", "الشهادة غير موثوقة: {why}"),
    "mismatch_cap": ("certificate does not match the host name (WEB700)", "الشهادة لا تطابق اسم المضيف (WEB700)"),
    "strict_only": ("only Python's strict X.509 mode rejects this certificate (code {code}: {message}); browsers accept it",
                    "يرفض وضع X.509 الصارم في Python وحده هذه الشهادة (الرمز {code}: {message})؛ والمتصفحات تقبلها"),
    "no_handshake": ("no protocol version could be confirmed (every hello was refused)",
                     "تعذّر تأكيد أي إصدار للبروتوكول (رُفضت كل محاولات المصافحة)"),
    "inconclusive": ("a protocol probe was inconclusive ({reason})", "كان أحد فحوص البروتوكول غير حاسم ({reason})"),
    "tls13_only": ("the server offers only TLS 1.3", "يقدّم الخادم TLS 1.3 فقط"),
    "tls13_scts": ("SCTs in the TLS extension are encrypted in TLS 1.3 and could not be seen",
                   "تكون SCTs المرسلة في امتداد TLS مشفّرة في TLS 1.3 فتعذّر رؤيتها"),
    "not_public": ("the certificate is not publicly trusted", "الشهادة غير موثوقة عامة"),
    "private_policy": ("the certificate has no CA/Browser Forum policy identifier, which every publicly trusted certificate "
                       "has carried since 2023: it is trusted only through a locally installed (private) root",
                       "لا تحمل الشهادة معرّف سياسة منتدى CA/Browser الذي تحمله كل شهادة موثوقة عامة منذ 2023: فهي موثوقة "
                       "فقط عبر جذر مثبّت محليًا (جهة إصدار خاصة)"),
    "chain_expired": ("a certificate of the chain expired: {name} ({date})", "انتهت صلاحية شهادة في السلسلة: {name} ({date})"),
    "chain_not_yet": ("a certificate of the chain is not yet valid: {name} ({date})",
                      "شهادة في السلسلة لم تصبح صالحة بعد: {name} ({date})"),
    "chain_store_cert": ("a certificate supplied by the local trust store", "شهادة جاء بها مخزن الثقة المحلي"),
    "key_huge": ("unusually large RSA key ({bits} bits): browsers and OpenSSL refuse keys above 16384 bits",
                 "مفتاح RSA كبير على نحو غير معتاد ({bits} بت): ترفض المتصفحات وOpenSSL المفاتيح الأكبر من 16384 بت"),
    "ct_not_required": ("the test CA is marked as not needing CT", "جهة الإصدار التجريبية معلَّمة بأنها لا تحتاج CT"),
    "chain_unknown": ("the chain could not be checked because verification failed earlier",
                      "تعذّر فحص السلسلة لأن التحقق فشل في خطوة سابقة"),
    "leaf_only_api": ("this Python build exposes only the leaf certificate", "لا يتيح إصدار Python هذا إلا الشهادة الأخيرة"),
    "beast": ("CBC suite in TLS 1.0: BEAST precondition, not tested", "مجموعة CBC في TLS 1.0: شرط مسبق لهجوم BEAST، لم يُختبر"),
    "prefers_krsa": ("the server prefers a suite without forward secrecy ({suite})",
                     "يفضّل الخادم مجموعة بلا سرية أمامية ({suite})"),
    "no_aead": ("no AEAD cipher suite is offered", "لا توجد أي مجموعة تشفير من نوع AEAD"),
    "incomplete_or_private": ("incomplete chain or private CA: the last certificate sent ({issuer}) has an unknown issuer",
                              "سلسلة ناقصة أو جهة إصدار خاصة: مُصدِر آخر شهادة مُرسلة ({issuer}) غير معروف"),
    "store_supplied": ("intermediate supplied by the local trust store, not by the server: {names}",
                       "شهادة وسيطة جاء بها مخزن الثقة المحلي لا الخادم: {names}"),
    "leaf_only": ("the server sends only the leaf certificate", "يرسل الخادم الشهادة الأخيرة فقط دون الشهادات الوسيطة"),
    "order": ("certificates are not in issuing order", "الشهادات ليست بترتيب الإصدار"),
    "anchor": ("the root certificate is sent", "تُرسَل شهادة الجذر"),
    "extra": ("certificates that are not part of the path are sent: {names}", "تُرسَل شهادات ليست ضمن المسار: {names}"),
    "duplicate": ("a certificate is sent twice", "تُرسَل شهادة مرتين"),
    "key_small": ("weak key: {key}", "مفتاح ضعيف: {key}"),
    "roca": ("RSA key generated by the vulnerable Infineon library (ROCA, CVE-2017-15361)",
             "مفتاح RSA مولَّد بمكتبة Infineon المعيبة (ROCA، CVE-2017-15361)"),
    "fermat": ("RSA primes too close: the key factors with Fermat's method (CVE-2022-26320)",
               "عددا RSA الأوليان متقاربان: يمكن تحليل المفتاح بطريقة فيرما (CVE-2022-26320)"),
    "exp1": ("RSA public exponent is 1", "الأس العام لـ RSA يساوي 1"),
    "odd_size": ("unusual key size: {bits} bits", "طول مفتاح غير معتاد: {bits} بت"),
    "sig_leaf": ("the certificate is signed with {alg}", "الشهادة موقّعة بـ {alg}"),
    "sig_int": ("intermediate {name} is signed with {alg}", "الشهادة الوسيطة {name} موقّعة بـ {alg}"),
    "lifetime": ("lifetime {days}; the limit for a certificate issued on {issued} is {limit}",
                 "مدة الصلاحية {days}؛ والحد لشهادة صادرة في {issued} هو {limit}"),
    "dh": ("{bits}-bit Diffie-Hellman group", "مجموعة Diffie-Hellman بطول {bits} بت"),
    "dh_common": ("well-known shared prime ({name}): precomputation attacks (Logjam) apply",
                  "عدد أولي مشترك معروف ({name}): تنطبق عليه هجمات الحساب المسبق (Logjam)"),
    "no_scts": ("publicly trusted certificate without any SCT", "شهادة موثوقة عامة بلا أي SCT"),
    "few_scts": ("{n} from {ops}; Chrome requires {need} from 2 operators",
                 "{n} من {ops}؛ ويطلب Chrome {need} من مشغّلَين مختلفين"),
    "unknown_logs": ("some SCTs come from logs missing from the bundled list (as of {date})",
                     "بعض SCTs من سجلات غير موجودة في القائمة المضمّنة (بتاريخ {date})"),
    "ct_stale": ("the bundled CT log list is older than 120 days", "قائمة سجلات CT المضمّنة أقدم من 120 يومًا"),
    "revoked": ("the stapled OCSP response says the certificate is revoked", "تقول استجابة OCSP المدبّسة إن الشهادة ملغاة"),
    "staple_expired": ("the stapled OCSP response expired on {date}", "انتهت صلاحية استجابة OCSP المدبّسة في {date}"),
    "must_staple": ("the certificate requires OCSP stapling (must-staple) but no staple is sent: Firefox refuses the site",
                    "تشترط الشهادة تدبيس OCSP (must-staple) ولا يُرسَل أي تدبيس: يرفض Firefox الموقع"),
    "no_staple": ("the certificate names an OCSP responder but the server does not staple", "تذكر الشهادة خادم OCSP لكن الخادم لا يدبّس الاستجابة"),
    "higher": ("offered {offered}, the server answered {answered}", "عُرض {offered} فأجاب الخادم بـ {answered}"),
    "cn_only": ("no subjectAltName: browsers ignore the common name", "لا يوجد subjectAltName: تتجاهل المتصفحات الاسم الشائع"),
    "wildcard": ("wildcard {name} covers every host of {domain}", "الشهادة العامة {name} تغطي كل مضيفي {domain}"),
    "many_sans": ("{n} in one certificate", "{n} في شهادة واحدة"),
    "differs": ("{what} differs between {ips}", "{what} يختلف بين {ips}"),
    "ips_differ_hint": ("the weaker node's own findings list the addresses they apply to",
                        "نتائج العقدة الأضعف تذكر العناوين التي تنطبق عليها"),
    "not_sampled": ("{n} more address(es) were not sampled: {ips}", "لم تُفحص عناوين إضافية عددها {n}: {ips}"),
    "unreachable": ("{ip} could not be reached ({reason})", "تعذّر الوصول إلى {ip} ({reason})"),
    "dev_enabled": ("{what} enabled", "{what} مفعّل"),
    "dev_disabled": ("{what} disabled", "{what} معطّل"),
    "dev_offered": ("{what} offered", "{what} معروض"),
    "dev_dh": ("DH parameters of {bits} bits", "معاملات DH بطول {bits} بت"),
    "dev_dhe": ("DHE suites offered", "مجموعات DHE معروضة"),
    "dev_cert_type": ("{what} certificate", "شهادة من نوع {what}"),
    "dev_rsa": ("RSA key of {bits} bits", "مفتاح RSA بطول {bits} بت"),
    "dev_curve": ("certificate curve {what}", "منحنى الشهادة {what}"),
    "dev_sig": ("signature {what}", "التوقيع {what}"),
    "dev_life": ("lifetime {days} (maximum {max})", "مدة الصلاحية {days} (الحد الأقصى {max})"),
    "dev_staple": ("no OCSP staple", "لا يوجد تدبيس OCSP"),
    "applies_only": ("applies to {ips} only", "ينطبق على {ips} فقط"),
    "modern_ok": ("conforms to the Mozilla modern profile", "مطابق لملف Mozilla الحديث"),
    "intermediate_ok": ("conforms to the Mozilla intermediate profile", "مطابق لملف Mozilla المتوسط"),
    "pq_missing": ("X25519MLKEM768 is not accepted", "لا يُقبل X25519MLKEM768"),
    "ssllabs_label": ("SSL Labs-compatible, excluding attack-only tests (Heartbleed, ROBOT, padding oracles, …) and "
                      "certificate revocation (CRL/OCSP), which Kashif does not perform",
                      "متوافق مع SSL Labs، باستثناء اختبارات الهجوم (Heartbleed وROBOT وpadding oracles وغيرها) والتحقق "
                      "من إلغاء الشهادة (CRL/OCSP)، وهي لا يجريها كاشف"),
}

DIFF_WHAT = {"protocols": ("protocol versions", "إصدارات البروتوكول"), "suites": ("cipher-suite categories", "فئات مجموعات التشفير"),
             "cert": ("the certificate", "الشهادة"), "chain": ("the certificate chain", "سلسلة الشهادات"),
             "options": ("compression or renegotiation support", "دعم الضغط أو إعادة التفاوض")}


# count phrases: (English singular, English plural, Arabic one/two/few/many/other with {n}) for vulnscan.i18n.plural
COUNT_FORMS: dict[str, tuple[str, str, tuple[str, str, str, str, str]]] = {
    "days": ("{n} day", "{n} days", ("يوم واحد", "يومان", "{n} أيام", "{n} يومًا", "{n} يوم")),
    "names": ("{n} name", "{n} names", ("اسم واحد", "اسمان", "{n} أسماء", "{n} اسمًا", "{n} اسم")),
    "scts": ("{n} SCT", "{n} SCTs", ("طابع SCT واحد", "طابعا SCT", "{n} طوابع SCT", "{n} طابعًا SCT", "{n} طابع SCT")),
    "operators": ("{n} operator", "{n} operators", ("مشغّل واحد", "مشغّلان", "{n} مشغّلين", "{n} مشغّلًا", "{n} مشغّل")),
}


def _count(n: int, which: str) -> tuple[str, str]:
    """``(en, ar)`` phrase of ``n`` with the noun that agrees with it (Arabic: five forms, §6 rules)."""
    from ...i18n.plural import ar_count   # lazy: vulnscan.i18n imports webscan modules through cat_web2
    one, many, forms = COUNT_FORMS[which]
    return (one if n == 1 else many).replace("{n}", str(n)), ar_count(n, forms)


def _t(_name: str, **kw: Any) -> tuple[str, str]:
    """``(en, ar)`` of ``STR[_name]``; a value may be an ``(en, ar)`` pair (count phrases)."""
    en, ar = STR[_name]
    ken = {k: (v[0] if isinstance(v, tuple) else v) for k, v in kw.items()}
    kar = {k: (v[1] if isinstance(v, tuple) else v) for k, v in kw.items()}
    return en.format(**ken), ar.format(**kar)


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


@functools.lru_cache(maxsize=512)
def _cert(b64: str) -> x509.Certificate | None:
    """Parse a base64 DER certificate once (reports parse the same chain for every rule, grade and evidence)."""
    try:
        return x509.try_parse(_b64d(b64))
    except (ValueError, binascii.Error):
        return None


# ----------------------------------------------------------------------------------------------- per-IP evaluation

class _Ip:
    """Findings and coverage states of one IP."""

    def __init__(self, ip: str):
        self.ip = ip
        self.cands: dict[tuple[str, str], dict] = {}
        self.states: dict[str, tuple[str, str, tuple[str, str] | None]] = {}

    def state(self, check: str, state: str, reason: str = "", detail: tuple[str, str] | None = None) -> None:
        prev = self.states.get(check)
        order = {"fail": 4, "inconclusive": 3, "not_tested": 2, "pass": 1, "not_applicable": 0}
        if prev is None or order[state] > order[prev[0]]:
            self.states[check] = (state, reason, detail)

    def fail(self, rule: str, severity: str, *, confidence: str | None = None, group: str = "", params: dict | None = None,
             notes: list[tuple[str, str]] | None = None, name: str = "", value: str = "", flag: str = "") -> None:
        meta = rules.RULES[rule]
        sev = severity or meta.severity
        if sev not in meta.allowed_severities:
            sev = meta.severity
        conf = confidence or meta.confidence
        key = (rule, group)
        prev = self.cands.get(key)
        if prev is not None and rules.SEVERITIES.index(prev["severity"]) <= rules.SEVERITIES.index(sev):
            prev["notes"].extend(n for n in (notes or []) if n not in prev["notes"])
            return
        self.cands[key] = {"rule": rule, "severity": sev, "confidence": conf, "group": group, "params": dict(params or {}),
                           "notes": list(notes or []), "name": name, "value": value, "flag": flag}
        self.state(meta.check_id, "fail")


def _trust(iprep: dict) -> dict:
    """The verified-handshake result that decides *chain* trust (the security-level-0 retry when the first one failed
    only because of a weak key or digest, or could not negotiate a protocol). ``_browser_code`` keeps the security-level
    code of the default handshake: browsers reject that chain, whatever the retry says (WEB072, SSL Labs T)."""
    ver = iprep.get("verified") or {}
    leg = iprep.get("verified_legacy") or {}
    if leg and leg.get("ok") is not None and (ver.get("verify_code") in SECLEVEL_CODES or ver.get("ok") is None):
        out = {**leg, "_seclevel": True}
        if ver.get("verify_code") in SECLEVEL_CODES:
            out["_browser_code"] = ver.get("verify_code")
            out["_browser_message"] = ver.get("verify_message") or ""
        return out
    if ver.get("verify_code") in SECLEVEL_CODES:
        return {**ver, "_browser_code": ver.get("verify_code"), "_browser_message": ver.get("verify_message") or ""}
    return ver


def browser_rejection(trust: dict) -> int | None:
    """The OpenSSL security-level code (66/67/68) for which browsers reject this chain, or None."""
    code = trust.get("_browser_code")
    return code if code in SECLEVEL_CODES else None


def _chain(iprep: dict) -> list[x509.Certificate]:
    out = []
    for c in iprep.get("chain") or []:
        cert = _cert(c) if isinstance(c, str) else None
        if cert is not None:
            out.append(cert)
    return out


def _version_state(iprep: dict, name: str) -> str:
    return (iprep.get("versions") or {}).get(name, {}).get("state", "not_tested")


def _any_version_yes(iprep: dict) -> bool:
    return any(v.get("state") == "yes" for v in (iprep.get("versions") or {}).values())


def _inconclusive_reason(iprep: dict, names: tuple[str, ...]) -> str:
    """A coverage reason code (coverage.REASONS) for the first undecided probe among ``names``."""
    for n in names:
        v = (iprep.get("versions") or {}).get(n, {})
        if v.get("state") in ("inconclusive", "not_tested"):
            r = v.get("reason") or "timeout"
            if r in ("backoff", "not_tls", "timeout"):
                return "timeout"
            return r if r in ("time_budget", "budget", "proxied") else "network"
    return "timeout"


def evaluate_ip(ctx: Any, host_rep: dict, iprep: dict, profiles: dict, ct_logs: dict, ct_date: Any) -> _Ip:
    """All checks for one IP. Pure: reads the probe report, writes nothing."""
    host = host_rep["host"]
    ip = iprep.get("ip") or "proxy"
    out = _Ip(ip)
    now = ctx.now
    opts = ctx.options
    proxied = bool(host_rep.get("proxied"))
    test_ca = host_rep.get("test_ca")
    chain = _chain(iprep)
    leaf = chain[0] if chain else None
    trust = _trust(iprep)
    code = trust.get("verify_code")
    ok = trust.get("ok")
    seclevel_note = [STR["seclevel"]] if trust.get("_seclevel") else []

    # ----------------------------------------------------------------- certificate facts
    cert_checks = ("WEB070", "WEB071", "WEB720", "WEB707", "WEB708", "WEB709", "WEB717", "WEB700", "WEB701", "WEB702",
                   "WEB703", "WEB072", "WEB713", "WEB714")
    if leaf is None:
        for c in cert_checks:
            out.state(c, "not_tested", "network", _t("no_cert"))
    anchored = ok is True or (ok is False and code is not None and code not in NOT_ANCHORED)
    public = anchored and (test_ca is None or bool(test_ca.get("publicly_trusted")))
    if public and test_ca is None and leaf is not None and leaf.validation is None:
        # anchored by a root installed locally (enterprise/private CA): Chrome's CT policy and the CA/B lifetime limits
        # do not apply, and every publicly trusted leaf carries a CA/B Forum reserved policy OID (BR 7.1.2.7.9)
        public = False
        out.cands.setdefault(("_note", "private"), {"rule": "_note", "notes": [STR["private_policy"]]})
    if leaf is not None:
        _dates(out, leaf, now, code=code, chain=chain)
        _key(out, leaf)
        _signatures(out, chain)
        _lifetime(out, leaf, public, anchored, ok is not None)
        _names(out, leaf, host, code, ok)
        _trust_rules(out, iprep, trust, chain, host, public, anchored, seclevel_note, proxied,
                     private_hint=test_ca is None and leaf.validation is None)
        _order(out, iprep, chain, proxied)
        _ct(out, iprep, leaf, public, test_ca, ct_logs, ct_date, now, proxied, ok is not None)
        _ocsp(out, iprep, leaf, now)

    # ----------------------------------------------------------------- protocols
    _protocols(out, iprep, opts)
    _ciphers(out, iprep, opts)
    _options(out, iprep, opts)
    _deep(out, iprep, opts)
    _mozilla(out, iprep, leaf, profiles, opts)
    return out


def _dates(out: _Ip, leaf: x509.Certificate, now, *, code: int | None = None,
           chain: list[x509.Certificate] | tuple = ()) -> None:
    expired = leaf.not_after < now
    notyet = leaf.not_before > now + CLOCK_SKEW
    if expired:
        out.fail("WEB070", "high", group="expired", name="notAfter", value=x509._iso(leaf.not_after) or "")
    elif code == CODE_EXPIRED:
        # OpenSSL's code 10 with a valid leaf: an intermediate (sent, or from the store) expired; browsers fail too
        bad = next((c for c in chain[1:] if c.not_after < now), None)
        name = (bad.subject_cn or bad.subject) if bad is not None else _t("chain_store_cert")
        date = x509._iso(bad.not_after) if bad is not None else "?"
        out.fail("WEB070", "high", group="chain_expired", name="notAfter", value=f"{_pick(name, 0)} {date}",
                 notes=[_t("chain_expired", name=name, date=date)])
    else:
        out.state("WEB070", "pass")
    if notyet:
        out.fail("WEB720", "high", group="not_yet_valid", name="notBefore", value=x509._iso(leaf.not_before) or "")
    elif code == CODE_NOT_YET and leaf.not_before <= now:     # else the leaf itself, inside the clock-skew allowance
        bad = next((c for c in chain[1:] if c.not_before > now + CLOCK_SKEW), None)
        name = (bad.subject_cn or bad.subject) if bad is not None else _t("chain_store_cert")
        date = x509._iso(bad.not_before) if bad is not None else "?"
        out.fail("WEB720", "high", group="chain_not_yet_valid", name="notBefore", value=f"{_pick(name, 0)} {date}",
                 notes=[_t("chain_not_yet", name=name, date=date)])
    else:
        out.state("WEB720", "pass")
    if expired or notyet:
        out.state("WEB071", "not_applicable")
        return
    lifetime = leaf.lifetime
    remaining = leaf.remaining(now)
    days = max(0, int(remaining))
    if remaining < min(14.0, lifetime / 10):
        out.fail("WEB071", "medium", group="expires_soon", params={"days": days}, name="notAfter",
                 value=x509._iso(leaf.not_after) or "")
    elif remaining < min(30.0, lifetime / 6):
        out.fail("WEB071", "low", group="expires_soon", params={"days": days}, name="notAfter",
                 value=x509._iso(leaf.not_after) or "")
    else:
        out.state("WEB071", "pass")


def _pick(v: Any, i: int) -> Any:
    return v[i] if isinstance(v, tuple) else v


def _key(out: _Ip, leaf: x509.Certificate) -> None:
    probs: list[tuple[str, str, tuple[str, str]]] = []     # (severity, group, note)
    kt, bits = leaf.key_type, leaf.key_bits
    if kt in ("RSA", "RSA-PSS") and bits:
        n = leaf.rsa_modulus
        if bits < 1024:
            probs.append(("critical", "rsa_small", _t("key_small", key=f"RSA-{bits}")))
        elif bits < 2048:
            probs.append(("high", "rsa_small", _t("key_small", key=f"RSA-{bits}")))
        if leaf.rsa_exponent == 1:
            probs.append(("critical", "exp1", STR["exp1"]))
        if x509.roca_vulnerable(n):
            probs.append(("critical", "roca", STR["roca"]))
        if x509.fermat_factorable(n):
            probs.append(("critical", "fermat", STR["fermat"]))
        if bits > x509.MAX_TESTED_MODULUS_BITS and not probs:
            probs.append(("info", "odd_size", _t("key_huge", bits=bits)))
        elif bits % 8 and bits >= 1024 and not probs:
            probs.append(("info", "odd_size", _t("odd_size", bits=bits)))
    elif kt == "EC":
        if bits is None:
            probs.append(("info", "ec_curve", _t("key_small", key=f"EC {leaf.curve}")))
        elif bits < 224:
            probs.append(("high", "ec_small", _t("key_small", key=f"EC {leaf.curve} ({bits})")))
    elif kt == "DSA" and bits and bits < 2048:
        probs.append(("high", "dsa_small", _t("key_small", key=f"DSA-{bits}")))
    if not probs:
        out.state("WEB707", "pass")
        return
    order = rules.SEVERITIES
    worst = min(probs, key=lambda p: order.index(p[0]))
    out.fail("WEB707", worst[0], group=worst[1], notes=[p[2] for p in probs], name="key", value=leaf.key_text())


def _signatures(out: _Ip, chain: list[x509.Certificate]) -> None:
    worst = None
    notes = []
    for i, c in enumerate(chain):
        if i > 0 and (c.self_issued or not c.is_ca):
            continue                                   # a root's own signature is not checked by clients
        h = c.sig_hash
        sev = "high" if h in ("md2", "md5") else ("medium" if h == "sha1" else None)
        if sev is None:
            continue
        notes.append(_t("sig_leaf", alg=c.sig_alg) if i == 0 else _t("sig_int", name=c.subject_cn or c.subject,
                                                                         alg=c.sig_alg))
        if worst is None or rules.SEVERITIES.index(sev) < rules.SEVERITIES.index(worst[0]):
            worst = (sev, h, c.sig_alg)
    if worst is None:
        out.state("WEB708", "pass")
        return
    out.fail("WEB708", worst[0], group=worst[1], notes=notes, name="signatureAlgorithm", value=worst[2])


def _limit_for(issued) -> int:
    day = issued.date().isoformat()
    for until, limit in LIFETIME_LIMITS:
        if day < until:
            return limit
    return LIFETIME_LIMITS[-1][1]


def _lifetime(out: _Ip, leaf: x509.Certificate, public: bool, anchored: bool, verified: bool) -> None:
    if not verified:
        out.state("WEB709", "not_tested", "network", _t("no_verify"))
        return
    if not public:
        out.state("WEB709", "not_applicable", "", _t("not_public"))
        return
    if "WEB720" in {k[0] for k in out.cands}:
        out.state("WEB709", "not_applicable")          # a notBefore in the future is reported by WEB720
        return
    limit = _limit_for(leaf.not_before)
    days = leaf.lifetime
    if days > limit:
        out.fail("WEB709", "low", group=f"limit{limit}", name="validity", value=f"{days:.0f} days",
                 notes=[_t("lifetime", days=_count(round(days), "days"), issued=leaf.not_before.date().isoformat(),
                           limit=_count(limit, "days"))])
    else:
        out.state("WEB709", "pass")


def _names(out: _Ip, leaf: x509.Certificate, host: str, code: int | None, ok: bool | None) -> None:
    sans = ", ".join(leaf.san_names()[:20]) or "(none)"
    if ok is True or code in (CODE_EXPIRED, CODE_NOT_YET) or code in (7,):
        out.state("WEB700", "pass")                    # OpenSSL checked the host name before dates and signatures
    elif code == CODE_HOSTNAME or not x509.host_matches(leaf, host):
        out.fail("WEB700", "high", group="mismatch", name="subjectAltName", value=sans)
    else:
        out.state("WEB700", "pass")
    notes, group = [], ""
    if not leaf.has_san and "WEB700" not in {k[0] for k in out.cands}:
        notes.append(STR["cn_only"])
        group = "cn_only"
    if len(leaf.san_dns) > 100:
        notes.append(_t("many_sans", n=_count(len(leaf.san_dns), "names")))
        group = group or "many_sans"
    for name in leaf.san_dns:
        if name.startswith("*.") and len(name) > 2:
            base = name[2:].lower().rstrip(".")
            try:
                reg = psl.registrable_domain(base)
            except Exception:   # noqa: BLE001 - malformed names from the certificate
                reg = None
            if reg and reg == base:
                notes.append(_t("wildcard", name=name, domain=base))
                group = group or "wildcard"
                break
    if notes:
        out.fail("WEB717", "info", group=group, notes=notes, name="subjectAltName", value=sans)
    else:
        out.state("WEB717", "pass")


def _trust_rules(out: _Ip, iprep: dict, trust: dict, chain: list[x509.Certificate], host: str, public: bool,
                 anchored: bool, seclevel_note: list, proxied: bool, private_hint: bool = False) -> None:
    """``private_hint``: the leaf has no CA/B Forum policy OID, so an unknown issuer more likely means a private CA
    than a missing intermediate (every publicly trusted leaf carries one, BR 7.1.2.7.9)."""
    ok, code = trust.get("ok"), trust.get("verify_code")
    leaf = chain[0]
    tentative = "tentative" if proxied else None
    msg = str(trust.get("verify_message") or "")[:200]
    rejected = browser_rejection(trust)
    if ok is None:
        detail = _t("no_verify")
        if leaf.self_issued:
            out.fail("WEB701", "high", confidence=tentative or "certain", group="self_signed", name="issuer",
                     value=leaf.issuer)
        else:
            out.state("WEB701", "not_tested", "network", detail)
        out.state("WEB702", "not_tested", "network", detail)
        out.state("WEB072", "not_tested", "network", detail)
        return
    # WEB072: verify failures that no specific rule explains, and chains browsers reject for a SHA-1 or weak key
    # (the security-level-0 retry decides only whether the rest of the chain is trusted)
    from ..http import verify_text
    if rejected is not None:
        bmsg = str(trust.get("_browser_message") or "")[:200]
        out.fail("WEB072", "high", group=f"code{rejected}", name="verify", value=verify_text(rejected, bmsg)[0],
                 notes=[_t("browser_reject", code=rejected)] + seclevel_note)
    elif ok is True:
        out.state("WEB072", "pass")
    elif code in STRICT_ONLY:
        out.state("WEB072", "pass")
        out.cands.setdefault(("_note", "strict"), {"rule": "_note", "notes": [_t("strict_only", code=code, message=msg)]})
    elif code in MAPPED:
        out.state("WEB072", "pass")
    else:
        text = verify_text(code, msg)
        out.fail("WEB072", "high", group=f"code{code}", name="verify", value=text[0],
                 notes=[text] + seclevel_note)
    # WEB701: not publicly trusted
    sent_ca = [c for c in chain[1:] if c.is_ca and not c.self_issued]
    if code in (CODE_SELF_SIGNED, CODE_SELF_SIGNED_IN_CHAIN):
        out.fail("WEB701", "high", confidence=tentative or "certain", group="self_signed", name="issuer",
                 value=(chain[-1].subject if chain else ""), notes=seclevel_note)
    elif code in CODE_NO_ISSUER and sent_ca:
        top = sent_ca[-1]
        out.fail("WEB701", "high", confidence="tentative", group="unknown_issuer", name="issuer", value=top.issuer,
                 notes=[_t("incomplete_or_private", issuer=top.issuer)] + seclevel_note)
    elif code in CODE_NO_ISSUER and private_hint and not leaf.self_issued:
        out.fail("WEB701", "high", confidence="tentative", group="unknown_issuer", name="issuer", value=leaf.issuer,
                 notes=[_t("incomplete_or_private", issuer=leaf.issuer), STR["private_policy"]] + seclevel_note)
    elif code in CODE_NO_ISSUER:
        out.state("WEB701", "not_tested", "precondition", _t("chain_unknown"))
    elif anchored:
        out.state("WEB701", "pass")
    else:
        out.state("WEB701", "not_tested", "precondition", _t("chain_unknown"))
    # WEB702: incomplete chain
    conf702 = "tentative" if proxied else "firm"
    if code in CODE_NO_ISSUER and not sent_ca and not leaf.self_issued and not private_hint:
        out.fail("WEB702", "medium", confidence=conf702, group="leaf_only", name="chain", value=f"{len(chain)} certificate(s)",
                 notes=[STR["leaf_only"]])
    elif ok is True:
        if not public:
            out.state("WEB702", "not_applicable", "", _t("not_public"))
        elif iprep.get("chain_source") == "ssl_leaf":
            out.state("WEB702", "not_tested", "error", STR["leaf_only_api"])
        else:
            sent = {c.sha256 for c in chain}
            # the same CA certificate reissued (other serial or dates, same name and key: Windows' "CA" store,
            # cross-signed variants) is the same intermediate for path building
            sent_keys = {(c.subject_raw, c.spki_sha256) for c in chain}
            vchain = [_cert(c) for c in (trust.get("verified_chain") or [])]
            middle = [c for c in vchain[1:-1] if c is not None]
            missing = [c for c in middle if c.sha256 not in sent and (c.subject_raw, c.spki_sha256) not in sent_keys]
            if trust.get("verified_chain") is None:
                out.state("WEB702", "not_tested", "error", STR["leaf_only_api"])
            elif missing:
                names = ", ".join(c.subject_cn or c.subject for c in missing)
                out.fail("WEB702", "medium", confidence=conf702, group="store_supplied", name="chain", value=names,
                         notes=[_t("store_supplied", names=names)])
            else:
                out.state("WEB702", "pass")
    elif code in CODE_NO_ISSUER:
        out.state("WEB702", "not_tested", "precondition", _t("chain_unknown"))
    else:
        # another certificate check failed first (expired, name, signature …): completeness cannot be judged
        out.state("WEB702", "not_tested", "precondition", _t("chain_unknown"))


_WS = re.compile(r"\s+")


def _name_key(text: str) -> str:
    """OpenSSL compares names in a canonical form (case and inner whitespace folded, string types ignored)."""
    return _WS.sub(" ", text).strip().casefold()


def _issued_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
    return parent.subject_raw == child.issuer_raw or (
        bool(parent.subject) and _name_key(parent.subject) == _name_key(child.issuer))


def _order(out: _Ip, iprep: dict, chain: list[x509.Certificate], proxied: bool) -> None:
    if iprep.get("chain_source") == "ssl_leaf":
        out.state("WEB703", "not_tested", "error", STR["leaf_only_api"])
        return
    if len(chain) < 2:
        out.state("WEB703", "pass")
        return
    probs: list[tuple[str, str, tuple[str, str]]] = []
    seen: set[str] = set()
    if any(c.sha256 in seen or seen.add(c.sha256) for c in chain):
        probs.append(("info", "duplicate", STR["duplicate"]))
    # the issuing path among the sent certificates, starting at the leaf
    path = [0]
    used = {0}
    while True:
        cur = chain[path[-1]]
        if cur.self_issued or _issued_by(cur, cur):
            break
        nxt = next((i for i, c in enumerate(chain) if i not in used and _issued_by(cur, c)), None)
        if nxt is None:
            break
        path.append(nxt)
        used.add(nxt)
    if path != list(range(len(path))):
        probs.append(("low", "order", STR["order"]))
    if any(chain[i].self_issued or _issued_by(chain[i], chain[i]) for i in path[1:]):
        probs.append(("info", "anchor", STR["anchor"]))
    extras = [chain[i] for i in range(len(chain)) if i not in used and chain[i].sha256 != chain[0].sha256]
    extras = [c for c in extras if not any(c.sha256 == chain[j].sha256 for j in used)]
    if extras:
        probs.append(("info", "extra", _t("extra", names=", ".join(c.subject_cn or c.subject for c in extras[:5]))))
    if not probs:
        out.state("WEB703", "pass")
        return
    sev = "low" if any(p[0] == "low" for p in probs) else "info"
    out.fail("WEB703", sev, confidence="tentative" if proxied else "certain",
             group="+".join(sorted(p[1] for p in probs)), notes=[p[2] for p in probs], name="chain",
             value=" > ".join(c.subject_cn or c.subject for c in chain[:6]))


def _ct(out: _Ip, iprep: dict, leaf: x509.Certificate, public: bool, test_ca: dict | None, ct_logs: dict, ct_date,
        now, proxied: bool, verified: bool = True) -> None:
    if not verified:
        out.state("WEB713", "not_tested", "network", _t("no_verify"))
        return
    if not public:
        out.state("WEB713", "not_applicable", "", _t("not_public"))
        return
    if test_ca is not None and not test_ca.get("ct_required", True):
        out.state("WEB713", "not_applicable", "", STR["ct_not_required"])
        return
    tls_scts: list[x509.Sct] = []
    for s in iprep.get("tls_scts") or []:
        tls_scts.extend(x509.parse_sct_list(_b64d(s), source="tls"))
    ocsp_has = False
    ocsp_scts: list[x509.Sct] = []
    o = iprep.get("ocsp") or {}
    if o.get("state") == "stapled" and o.get("der"):
        try:
            resp = x509.parse_ocsp_response(_b64d(o["der"]))
            ocsp_has, ocsp_scts = resp.has_scts, list(resp.scts)
        except (x509.X509Error, ValueError):
            ocsp_has = False
    stale = ct_date is not None and (now.date() - ct_date).days > CT_STALE_DAYS
    base_conf = "tentative" if (stale or proxied) else "firm"
    notes = [STR["ct_stale"]] if stale else []
    embedded = leaf.scts
    if not embedded and not tls_scts and not ocsp_has:
        tls13_only = iprep.get("category_version") is None and _version_state(iprep, "TLSv1.3") == "yes"
        if tls13_only:
            # TLS-delivered SCTs are encrypted in TLS 1.3: absence is proven only for the certificate itself
            notes.append(STR["tls13_scts"])
            base_conf = "tentative"
        out.fail("WEB713", "medium", confidence=base_conf, group="none", notes=[STR["no_scts"]] + notes, name="scts",
                 value="0")
        return

    def judge(scts: list[x509.Sct], need: int) -> tuple[bool, bool, int, int]:
        """(compliant, depends_on_unknown_logs, distinct logs, distinct operators)"""
        logs = {s.log_id_b64 for s in scts}
        ops, unknown = set(), 0
        good_state = False
        for lid in logs:
            info = ct_logs.get(lid)
            if info is None:
                unknown += 1
                ops.add(f"?{lid}")
                continue
            ops.add(info.get("operator"))
            if info.get("state") in ("qualified", "usable", "readonly"):
                good_state = True
        compliant = len(logs) >= need and len(ops) >= 2 and (good_state or unknown > 0)
        known_ops = {o for o in ops if not str(o).startswith("?")}
        strict_ok = len(logs) >= need and len(known_ops) >= 2 and good_state
        return compliant, compliant and not strict_ok, len(logs), len(ops)

    need = 2 if leaf.lifetime <= 180 else 3
    emb_ok, emb_unknown, n_logs, n_ops = judge(embedded, need)
    tls_ok, tls_unknown, _tl, _to = judge(tls_scts, 2)
    ocsp_ok = judge(ocsp_scts, 2)[0] or judge(tls_scts + ocsp_scts, 2)[0]
    if emb_ok or tls_ok or ocsp_ok:
        out.state("WEB713", "pass")
        return
    any_unknown = any(s.log_id_b64 not in ct_logs for s in embedded + tls_scts + ocsp_scts)
    conf = "tentative" if (any_unknown or base_conf == "tentative") else "firm"
    if any_unknown:
        notes.append(_t("unknown_logs", date=str(ct_date or "?")))
    out.fail("WEB713", "low", confidence=conf, group="few", name="scts", value=str(len(embedded) + len(tls_scts)),
             notes=[_t("few_scts", n=_count(len(embedded), "scts"), ops=_count(n_ops, "operators"),
                       need=_count(need, "scts"))] + notes)


# coverage pseudo-check for revocation: a passive scan never contacts the CA (CRL/OCSP), so revocation is known
# only from a stapled OCSP response; without one it is recorded as not checked (never as a pass)
REVOCATION_CHECK = "WEB714-revocation"


def _variant(rule: str, name: str) -> dict:
    """``{"variant": name}`` when the registry knows that variant of ``rule`` (else no variant: the base title)."""
    return {"variant": name} if name in (rules.RULES[rule].variants or {}) else {}


def _ocsp(out: _Ip, iprep: dict, leaf: x509.Certificate, now) -> None:
    o = iprep.get("ocsp") or {}
    state = o.get("state")
    if not (state == "stapled" and o.get("der")):
        out.state(REVOCATION_CHECK, "not_tested", "revocation")
    if state == "stapled" and o.get("der"):
        try:
            resp = x509.parse_ocsp_response(_b64d(o["der"]))
        except (x509.X509Error, ValueError):
            out.state("WEB714", "not_tested", "error")      # an unreadable staple proves nothing either way
            return
        if resp.status == 0 and resp.cert_status == "revoked":
            out.fail("WEB714", "high", group="revoked", notes=[STR["revoked"]], name="ocsp", value="revoked",
                     params=_variant("WEB714", "revoked"))
        elif resp.next_update is not None and resp.next_update < now:
            out.fail("WEB714", "medium", group="expired", notes=[_t("staple_expired", date=x509._iso(resp.next_update))],
                     name="ocsp", value=x509._iso(resp.next_update) or "", params=_variant("WEB714", "expired"))
        else:
            out.state("WEB714", "pass")
        return
    if state == "absent":
        if leaf.must_staple:
            out.fail("WEB714", "medium", group="must_staple", notes=[STR["must_staple"]], name="ocsp", value="no staple")
        elif leaf.ocsp_urls:
            out.fail("WEB714", "info", group="no_staple", notes=[STR["no_staple"]], name="ocsp", value=leaf.ocsp_urls[0])
        else:
            out.state("WEB714", "pass")
        return
    reason = o.get("reason") or "timeout"
    if reason == "tls13_encrypted":
        if leaf.must_staple or leaf.ocsp_urls:
            out.state("WEB714", "not_tested", "tls13_encrypted")
        else:
            out.state("WEB714", "pass")                 # no OCSP responder: nothing to staple in any version
        return
    out.state("WEB714", "not_tested", "timeout" if reason in ("timeout", "backoff") else "network")


def _protocols(out: _Ip, iprep: dict, opts) -> None:
    versions = iprep.get("versions") or {}
    if not _any_version_yes(iprep):
        detail = STR["no_handshake"]
        for c in ("WEB030", "WEB704", "WEB705", "WEB716"):
            out.state(c, "not_tested", _inconclusive_reason(iprep, raw.PROBE_VERSIONS), detail)
        return
    flags = {"TLSv1.0": "-tls1", "TLSv1.1": "-tls1_1", "SSLv3": "-ssl3", "SSLv2": "-ssl2"}  # nosec - protocol name
    # WEB704 SSLv2 / SSLv3, WEB030 TLS 1.0 / 1.1: one finding per version (1.0.1 fingerprint continuity)
    for rule, names in (("WEB704", ("SSLv2", "SSLv3")), ("WEB030", ("TLSv1.0", "TLSv1.1"))):  # nosec - protocol name
        undecided = []
        for n in names:
            st = _version_state(iprep, n)
            if st == "yes":
                sev = {"SSLv2": "critical", "SSLv3": "high"}.get(n, "medium")  # nosec - protocol name
                v = versions.get(n, {})
                out.fail(rule, sev, group=n, params={"versions": VERSION_LABEL[n]}, name="protocol",
                         value=f"{VERSION_LABEL[n]} accepted" + (f" ({v.get('cipher')})" if v.get("cipher") else ""),
                         flag=flags[n])
            elif st != "no":
                undecided.append(n)
        if undecided and not any(_version_state(iprep, n) == "yes" for n in names):
            out.state(rule, "not_tested", _inconclusive_reason(iprep, tuple(undecided)),
                      _t("inconclusive", reason=", ".join(VERSION_LABEL[n] for n in undecided)))
        elif not any(_version_state(iprep, n) == "yes" for n in names):
            out.state(rule, "pass")
    # WEB705 missing TLS 1.2 / 1.3
    s12, s13 = _version_state(iprep, "TLSv1.2"), _version_state(iprep, "TLSv1.3")
    if s12 == "no" and s13 == "no":
        out.fail("WEB705", "high", group="no12no13", params={"versions": ["TLS 1.2", "TLS 1.3"],
                                                             **_variant("WEB705", "no12no13")},
                 name="protocol", value="TLS 1.2 and TLS 1.3 refused")
    elif s13 == "no" and s12 == "yes":
        out.fail("WEB705", "low", group="no13", params={"versions": ["TLS 1.3"]}, name="protocol",
                 value="TLS 1.3 refused", flag="-tls1_3")
    elif "yes" in (s12, s13) and s13 == "yes":
        out.state("WEB705", "pass")
    else:
        out.state("WEB705", "not_tested", _inconclusive_reason(iprep, ("TLSv1.3", "TLSv1.2")),
                  _t("inconclusive", reason="TLS 1.2 / TLS 1.3"))
    # WEB716 higher version than offered
    hv = iprep.get("higher_version") or []
    if hv:
        notes = [_t("higher", offered=h.get("offered"), answered=h.get("answered")) for h in hv]
        out.fail("WEB716", "low", group="higher", notes=notes, name="protocol",
                 value="; ".join(f"{h.get('offered')}→{h.get('answered')}" for h in hv))
    elif any(v.get("state") in ("inconclusive", "not_tested") for k, v in versions.items() if k != "TLSv1.3"):
        out.state("WEB716", "not_tested", _inconclusive_reason(iprep, ("TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3")))  # nosec
    else:
        out.state("WEB716", "pass")


def _ciphers(out: _Ip, iprep: dict, opts) -> None:
    cats = iprep.get("categories") or {}
    if opts.profile == "minimal":
        out.state("WEB706", "not_tested", "profile")
        return
    if not cats:
        out.state("WEB706", "not_tested", "not_run")
        return
    if all(v.get("state") == "not_applicable" for v in cats.values()):
        out.state("WEB706", "pass")                    # TLS 1.3 only: every suite is AEAD with forward secrecy
        return
    any_fail = False
    for name, res in cats.items():
        if res.get("state") != "yes" or name in ("cbc", "aead"):
            continue
        cid = _suite_id(res.get("cipher"))
        cat = raw.suite_category(cid) if cid is not None else {"null_anon": "null", "export_des": "export"}.get(name, name)
        if cat not in CATEGORY_RULE:
            continue
        sev, en, ar = CATEGORY_RULE[cat]
        out.fail("WEB706", sev, group=cat, notes=[(en, ar)], name="cipher", value=f"{res.get('cipher')} ({res.get('version')})",
                 flag={"TLSv1.0": "-tls1", "TLSv1.1": "-tls1_1", "TLSv1.2": "-tls1_2"}.get(res.get("version") or "", ""))  # nosec
        any_fail = True
    tls13 = _version_state(iprep, "TLSv1.3") == "yes"
    if cats.get("aead", {}).get("state") == "no" and not tls13:
        out.fail("WEB706", "medium", group="no_aead", notes=[STR["no_aead"]], name="cipher", value="no AEAD suite")
        any_fail = True
    v10 = (iprep.get("versions") or {}).get("TLSv1.0", {})  # nosec - protocol name
    cid10 = _suite_id(v10.get("cipher")) if v10.get("state") == "yes" else None
    if cid10 is not None and raw.suite_category(cid10) in ("cbc", "krsa", "3des"):
        out.fail("WEB706", "low", group="cbc_tls10", notes=[STR["beast"]], name="cipher", value=f"{v10.get('cipher')} (TLS 1.0)",
                 flag="-tls1")
        any_fail = True
    deep = iprep.get("deep") or {}
    pref = deep.get("preferred")
    if deep.get("server_preference") and pref and raw.suite_category(_suite_id(pref) or 0) == "krsa":
        out.fail("WEB706", "low", group="prefers_krsa", notes=[_t("prefers_krsa", suite=pref)], name="cipher", value=pref)
        any_fail = True
    undecided = [n for n, r in cats.items() if r.get("state") in ("inconclusive", "not_tested")]
    if undecided and not any_fail:
        reason = cats[undecided[0]].get("reason") or "timeout"
        out.state("WEB706", "not_tested", "timeout" if reason in ("backoff", "timeout", "not_tls") else "network",
                  _t("inconclusive", reason=", ".join(undecided)))
    elif not any_fail:
        out.state("WEB706", "pass")


_SUITE_BY_NAME = {s.name: cid for cid, s in raw.SUITES.items()}


def _suite_id(name: str | None) -> int | None:
    if not name:
        return None
    if name in _SUITE_BY_NAME:
        return _SUITE_BY_NAME[name]
    if name.startswith("0x"):
        try:
            return int(name, 16)
        except ValueError:
            return None
    return None


def _options(out: _Ip, iprep: dict, opts) -> None:
    tls13_only = iprep.get("category_version") is None and _version_state(iprep, "TLSv1.3") == "yes"
    comp = iprep.get("compression")
    if tls13_only:
        out.state("WEB711", "not_applicable", "", STR["tls13_only"])
    elif opts.profile == "minimal":
        out.state("WEB711", "not_tested", "profile")
    elif comp is True:
        out.fail("WEB711", "high", group="deflate", name="compression", value="DEFLATE accepted", flag="-tls1_2")
    elif comp is False:
        out.state("WEB711", "pass")
    else:
        out.state("WEB711", "not_tested", "timeout")
    reneg = iprep.get("renegotiation_info")
    if tls13_only:
        out.state("WEB712", "not_applicable", "", STR["tls13_only"])
    elif reneg is False:
        out.fail("WEB712", "low", group="no_reneg_info", name="extension", value="renegotiation_info (0xff01) missing",
                 flag={"TLSv1.0": "-tls1", "TLSv1.1": "-tls1_1"}.get(iprep.get("category_version") or "", "-tls1_2"))  # nosec
    elif reneg is True:
        out.state("WEB712", "pass")
    else:
        out.state("WEB712", "not_tested", "timeout")


def _deep(out: _Ip, iprep: dict, opts) -> None:
    deep = iprep.get("deep") or {}
    if not opts.deep:
        out.state("WEB710", "not_tested", "deep_off")
        out.state("WEB719", "not_tested", "deep_off" if opts.paranoid else "sensitivity")
        return
    if "dh_bits" in deep:
        bits = deep.get("dh_bits")
        if bits is None:
            out.state("WEB710", "pass")                # no DHE suite accepted
        else:
            common = COMMON_DH_SHA256.get(deep.get("dh_prime_sha256") or "")
            notes = [_t("dh", bits=bits)] + ([_t("dh_common", name=common)] if common else [])
            if bits < 1024:
                out.fail("WEB710", "high", group="dh_small", notes=notes, name="dh", value=f"{bits} bits")
            elif bits < 2048 or common:
                out.fail("WEB710", "medium", group="dh_small", notes=notes, name="dh", value=f"{bits} bits")
            else:
                out.state("WEB710", "pass")
    elif iprep.get("category_version") is None and _version_state(iprep, "TLSv1.3") == "yes":
        out.state("WEB710", "not_applicable", "", STR["tls13_only"])
    else:
        out.state("WEB710", "not_tested", "timeout")
    if not opts.paranoid:
        out.state("WEB719", "not_tested", "sensitivity")
        return
    groups = deep.get("groups") or {}
    pq = groups.get("X25519MLKEM768")
    if _version_state(iprep, "TLSv1.3") != "yes":
        out.fail("WEB719", "info", group="no_tls13", notes=[STR["pq_missing"]], name="group", value="no TLS 1.3")
    elif pq is True:
        out.state("WEB719", "pass")
    elif pq is False:
        out.fail("WEB719", "info", group="no_pq", notes=[STR["pq_missing"]], name="group", value="X25519MLKEM768")
    else:
        out.state("WEB719", "not_tested", "timeout")


# ----------------------------------------------------------------------------------------------- Mozilla 6.0

_GROUP_MOZ = {"x25519": "X25519", "secp256r1": "prime256v1", "secp384r1": "secp384r1", "X25519MLKEM768": "X25519MLKEM768"}
_SIG_MOZ = {"sha256WithRSAEncryption", "ecdsa-with-SHA256", "ecdsa-with-SHA384", "ecdsa-with-SHA512"}


def mozilla_deviations(iprep: dict, leaf: x509.Certificate | None, profile: dict, *,
                       deep: bool) -> tuple[list[tuple[str, str]], bool]:
    """Deviations (English, Arabic) from one Mozilla profile and whether the data was complete enough to judge."""
    devs: list[tuple[str, str]] = []
    complete = True

    def add(item: tuple[str, str]) -> None:
        if item not in devs:
            devs.append(item)

    allowed = {VERSION_LABEL.get(v, v) for v in profile.get("tls_versions", [])}
    disabled: list[tuple[str, str]] = []
    for name in raw.PROBE_VERSIONS:
        st = _version_state(iprep, name)
        label = VERSION_LABEL[name]
        if st == "yes" and label not in allowed:
            add(_t("dev_enabled", what=label))
        elif st == "no" and label in allowed:
            disabled.append(_t("dev_disabled", what=label))
        elif st not in ("yes", "no"):
            complete = False
    # a stricter server (TLS 1.3 only against the intermediate profile) is not a deviation; no allowed version is
    if disabled and not any(_version_state(iprep, n) == "yes" and VERSION_LABEL[n] in allowed for n in raw.PROBE_VERSIONS):
        for d in disabled:
            add(d)
    ciphers = profile.get("ciphers") or {}
    iana = set(ciphers.get("iana") or []) if isinstance(ciphers, dict) else set(ciphers)
    for name, res in (iprep.get("categories") or {}).items():
        if res.get("state") in ("inconclusive", "not_tested"):
            complete = False
        if name == "aead" or res.get("state") != "yes":
            continue
        if res.get("cipher") not in iana:
            add(_t("dev_offered", what=res.get("cipher")))
    if deep:
        dp = iprep.get("deep") or {}
        for suite in dp.get("suites") or []:
            if suite not in iana:
                add(_t("dev_offered", what=suite))
        moz_curves = set(profile.get("tls_curves") or [])
        for g, sup in (dp.get("groups") or {}).items():
            if sup and _GROUP_MOZ.get(g, g) not in moz_curves:
                add(_t("dev_offered", what=g))
        dh = dp.get("dh_bits")
        if dh and profile.get("dh_param_size") is None:
            add(STR["dev_dhe"])
        elif dh and dh < (profile.get("dh_param_size") or 0):
            add(_t("dev_dh", bits=dh))
    if leaf is not None:
        types = set(profile.get("certificate_types") or [])
        kt = {"RSA": "rsa", "EC": "ecdsa"}.get(leaf.key_type, leaf.key_type.lower())
        if kt not in types:
            add(_t("dev_cert_type", what=leaf.key_type))
        elif kt == "rsa" and (leaf.key_bits or 0) < int(profile.get("rsa_key_size") or 0):
            add(_t("dev_rsa", bits=leaf.key_bits))
        elif kt == "ecdsa" and leaf.curve and _GROUP_MOZ.get(leaf.curve, leaf.curve) not in set(
                profile.get("certificate_curves") or []):
            add(_t("dev_curve", what=leaf.curve))
        if leaf.sig_alg not in set(profile.get("certificate_signatures") or _SIG_MOZ):
            add(_t("dev_sig", what=leaf.sig_alg))
        life = int(profile.get("maximum_certificate_lifespan") or 0)
        if life and leaf.lifetime > life:
            add(_t("dev_life", days=_count(round(leaf.lifetime), "days"), max=_count(life, "days")))
        if profile.get("ocsp_staple") and leaf.ocsp_urls and (iprep.get("ocsp") or {}).get("state") == "absent":
            add(STR["dev_staple"])
    else:
        complete = False
    return devs, complete


def _mozilla(out: _Ip, iprep: dict, leaf: x509.Certificate | None, profiles: dict, opts) -> None:
    inter = (profiles or {}).get("intermediate")
    if not inter:
        out.state("WEB718", "not_tested", "data_missing")
        return
    if opts.profile == "minimal":
        out.state("WEB718", "not_tested", "profile")
        return
    if not _any_version_yes(iprep):
        out.state("WEB718", "not_tested", _inconclusive_reason(iprep, raw.PROBE_VERSIONS), STR["no_handshake"])
        return
    devs, complete = mozilla_deviations(iprep, leaf, inter, deep=opts.deep)
    if devs:
        out.fail("WEB718", "info", group="intermediate", notes=devs, name="mozilla",
                 value="; ".join(d[0] for d in devs)[:300])
    elif dh_unmeasured(iprep):
        out.state("WEB718", "not_tested", "dh_unmeasured")     # the DH size decides conformance and was not read
    elif complete:
        out.state("WEB718", "pass")
    else:
        out.state("WEB718", "not_tested", "timeout")


# ----------------------------------------------------------------------------------------------- SSL Labs-compatible

_PROTO_SCORE = {"SSLv2": 0, "SSLv3": 80, "TLSv1.0": 90, "TLSv1.1": 95, "TLSv1.2": 100, "TLSv1.3": 100}  # nosec - protocol name


def _kex_score(bits: int | None) -> int:
    if bits is None:
        return 0
    for limit, score in ((512, 20), (1024, 40), (2048, 80), (4096, 90)):
        if bits < limit:
            return score
    return 100


def _cipher_score(bits: int) -> int:
    if bits <= 0:
        return 0
    if bits < 128:
        return 20
    if bits < 256:
        return 80
    return 100


def dhe_offered(iprep: dict) -> bool:
    """True when a DHE suite was negotiated by any handshake or probe of this IP."""
    names = list((iprep.get("chosen") or {}).values()) + [r.get("cipher") for r in (iprep.get("categories") or {}).values()
                                                          if r.get("state") == "yes"]
    for key in ("verified", "verified_legacy", "unverified"):
        names.append((iprep.get(key) or {}).get("cipher"))
    for n in names:
        if not n:
            continue
        s = str(n)
        if s.startswith(("DHE-", "EDH-")) or "_DHE_" in s:
            return True
        cid = _suite_id(s)
        if cid is not None and cid in raw.SUITES and raw.SUITES[cid].kex == "DHE":
            return True
    return False


def dh_unmeasured(iprep: dict) -> bool:
    """A DHE suite is accepted but its group size was not read (standard profile: only --web-profile deep sends the
    DHE-only probe whose ServerKeyExchange carries the prime)."""
    return dhe_offered(iprep) and not (iprep.get("deep") or {}).get("dh_bits")


def _trust_failure(leaf: x509.Certificate, trust: dict, now, host: str) -> tuple[str, tuple[str, str]] | None:
    """``(T or M, (en, ar) reason)`` when the certificate makes SSL Labs grade the server T (not trusted) or M (name
    mismatch), else None."""
    from ..http import verify_text
    code, ok = trust.get("verify_code"), trust.get("ok")
    rejected = browser_rejection(trust)
    if leaf.not_after < now:
        why = verify_text(CODE_EXPIRED)
        return "T", (f"{why[0]} (WEB070)", f"{why[1]} (WEB070)")
    if leaf.not_before > now + CLOCK_SKEW:
        why = verify_text(CODE_NOT_YET)
        return "T", (f"{why[0]} (WEB720)", f"{why[1]} (WEB720)")
    if rejected is not None:
        why = verify_text(rejected)
        return "T", (f"{why[0]} (WEB072)", f"{why[1]} (WEB072)")
    if leaf.sig_hash == "sha1":
        return "T", ("SHA-1 certificate signature (WEB708)", "توقيع الشهادة بـ SHA-1 (WEB708)")
    if ok is False and code not in (CODE_HOSTNAME,) and code not in STRICT_ONLY:
        why = verify_text(code)
        rule = "WEB701" if code in NOT_ANCHORED else "WEB072"
        return "T", (f"{why[0]} ({rule})", f"{why[1]} ({rule})")
    mismatch = code == CODE_HOSTNAME if ok is False else (ok is not True and not x509.host_matches(leaf, host))
    if mismatch:
        return "M", STR["mismatch_cap"]
    return None


def ssllabs_ip(iprep: dict, now, *, hsts: Any = None, host: str = "") -> dict:
    """SSL Labs-compatible grade of one IP (§3.4 c): score = 0.3·protocol + 0.3·key exchange + 0.4·cipher strength,
    thresholds A ≥ 80 … E ≥ 20, then the caps of the 2009r guide that are passively measurable."""
    chain = _chain(iprep)
    leaf = chain[0] if chain else None
    trust = _trust(iprep)
    caps: list[tuple[str, str, str]] = []           # (letter, en, ar)
    provisional = False
    yes = [n for n in raw.PROBE_VERSIONS if _version_state(iprep, n) == "yes"]
    if any(_version_state(iprep, n) not in ("yes", "no") for n in raw.PROBE_VERSIONS):
        provisional = True
    if not yes or leaf is None:
        return {"grade": "?", "score": None, "provisional": True, "caps": [], "label": list(STR["ssllabs_label"])}
    proto = (_PROTO_SCORE[yes[0]] + _PROTO_SCORE[yes[-1]]) / 2      # best and worst (PROBE_VERSIONS is newest first)
    key_bits = leaf.rsa_equiv_bits if leaf is not None else None
    deep = iprep.get("deep") or {}
    dh = deep.get("dh_bits")
    kbits = min(b for b in (key_bits, dh) if b) if (key_bits or dh) else None
    cats = iprep.get("categories") or {}
    yes_cats = {n for n, r in cats.items() if r.get("state") == "yes"}
    kex = _kex_score(kbits)
    if "null_anon" in yes_cats and raw.suite_category(_suite_id(cats["null_anon"].get("cipher")) or 0) == "anon":
        kex = 0
    elif "export_des" in yes_cats and "EXPORT" in str(cats["export_des"].get("cipher")):
        kex = min(kex, 40)
    strongest = 0
    weakest = 256
    chosen = [s for s in (iprep.get("chosen") or {}).values()] + [r.get("cipher") for r in cats.values()
                                                                 if r.get("state") == "yes"]
    for name in chosen:
        cid = _suite_id(name)
        if cid is None or cid not in raw.SUITES:
            continue
        b = raw.SUITES[cid].bits
        strongest = max(strongest, b)
        weakest = min(weakest, b)
    if "TLSv1.3" in yes:
        strongest = max(strongest, 256 if "TLS_AES_256_GCM_SHA384" in chosen or "TLS_CHACHA20_POLY1305_SHA256" in chosen
                        else 128)
    if strongest == 0:
        strongest = weakest = 128
        provisional = True
    cipher = (_cipher_score(strongest) + _cipher_score(min(weakest, strongest))) / 2
    score = round(0.3 * proto + 0.3 * kex + 0.4 * cipher)
    letter = "A" if score >= 80 else "B" if score >= 65 else "C" if score >= 50 else "D" if score >= 35 else \
        "E" if score >= 20 else "F"

    def cap(lim: str, en: str, ar: str) -> None:
        caps.append((lim, en, ar))

    if "SSLv2" in yes:
        cap("F", "SSLv2 supported", "يدعم SSLv2")
    if yes[0] == "SSLv3":  # nosec - protocol name
        cap("F", "SSLv3 is the best protocol", "SSLv3 أفضل بروتوكول مدعوم")  # nosec - protocol name
    if "export_des" in yes_cats and "EXPORT" in str(cats["export_des"].get("cipher")):
        cap("F", "export cipher suites", "مجموعات EXPORT")
    if kbits is not None and kbits < 1024:
        cap("F", "key or DH parameters below 1024 bits", "مفتاح أو معاملات DH أقل من 1024 بت")
    if leaf is not None and leaf.sig_hash in ("md2", "md5"):
        cap("F", "MD5 certificate signature", "توقيع شهادة بـ MD5")
    if leaf is not None and (leaf.rsa_exponent == 1 or x509.roca_vulnerable(leaf.rsa_modulus)
                             or x509.fermat_factorable(leaf.rsa_modulus)):
        cap("F", "weak (factorable) key", "مفتاح ضعيف قابل للتحليل")
    if "null_anon" in yes_cats:
        cap("F", "NULL or anonymous suites", "مجموعات NULL أو مجهولة الهوية")
    if "TLSv1.2" not in yes and "TLSv1.3" not in yes:
        cap("C", "no TLS 1.2", "لا يدعم TLS 1.2")
    if "rc4" in yes_cats and any(v in yes for v in ("TLSv1.1", "TLSv1.2", "TLSv1.3")):  # nosec - protocol name
        cap("C", "RC4 with TLS 1.1 or newer", "RC4 مع TLS 1.1 أو أحدث")
    if "3des" in yes_cats and any(v in yes for v in ("TLSv1.1", "TLSv1.2", "TLSv1.3")):  # nosec - protocol name
        cap("C", "3DES with TLS 1.1 or newer", "3DES مع TLS 1.1 أو أحدث")
    if iprep.get("compression") is True:
        cap("C", "TLS compression (CRIME)", "ضغط TLS (CRIME)")
    if "SSLv3" in yes:  # nosec - protocol name
        cap("B", "SSLv3 supported", "يدعم SSLv3")  # nosec - protocol name
    if "TLSv1.0" in yes or "TLSv1.1" in yes:  # nosec - protocol name
        cap("B", "TLS 1.0 or 1.1 supported", "يدعم TLS 1.0 أو 1.1")
    if "rc4" in yes_cats:
        cap("B", "RC4", "RC4")
    if dh and dh < 2048:
        cap("B", "DH parameters below 2048 bits", "معاملات DH أقل من 2048 بت")
    if key_bits is not None and key_bits < 2048:
        cap("B", "key below 2048 bits", "مفتاح أقل من 2048 بت")
    if trust.get("verify_code") in CODE_NO_ISSUER and not [c for c in chain[1:] if c.is_ca]:
        cap("B", "incomplete chain", "سلسلة ناقصة")
    fs_known = "TLSv1.3" in yes or any(
        raw.SUITES.get(_suite_id(n) or 0, raw.Suite("", "", "", "", 0, "")).kex in ("ECDHE", "DHE") for n in chosen)
    if not fs_known and cats:
        cap("B", "no forward secrecy", "لا سرية أمامية")
    if cats.get("aead", {}).get("state") == "no" and "TLSv1.3" not in yes:
        cap("B", "no AEAD suites", "لا مجموعات AEAD")
    if "TLSv1.3" not in yes:
        cap("A-", "no TLS 1.3", "لا يدعم TLS 1.3")
    # certificate problems: SSL Labs' T (trust) or M (mismatch), named first among the caps
    failure = _trust_failure(leaf, trust, now, host) if leaf is not None else None
    special = failure[0] if failure else None
    # HSTS is judged only on a host whose certificate is valid (browsers ignore it otherwise, group.by_cert)
    hsts_judged = hsts is not None and not getattr(hsts, "cert_error", False) and special is None
    if hsts_judged and not getattr(hsts, "effective", False):
        cap("A-", "HSTS missing or invalid", "HSTS مفقود أو غير صالح")
    order = ["F", "E", "D", "C", "B", "A-", "A", "A+"]
    final = letter
    for lim, _en, _ar in caps:
        if order.index(lim) < order.index(final):
            final = lim
    notes: list[list[str]] = []
    if dh_unmeasured(iprep):
        provisional = True
        notes.append(list(STR["dh_unmeasured"]))
    if failure is not None:
        en, ar = _t("trust_cap", why=failure[1]) if special == "T" else failure[1]
        caps.insert(0, (special, en, ar))
    if special is None and final == "A" and not caps and hsts_judged and \
            (getattr(hsts, "max_age", 0) or 0) >= 15_552_000 and getattr(hsts, "effective", False):
        final = "A+"
    out = {"grade": special or final, "grade_if_trusted": final, "score": score,
           "subscores": {"protocol": proto, "key_exchange": kex, "cipher": cipher}, "provisional": provisional,
           "caps": [{"cap": c[0], "en": c[1], "ar": c[2]} for c in caps], "label": list(STR["ssllabs_label"])}
    if notes:
        out["notes"] = [{"en": n[0], "ar": n[1]} for n in notes]
    return out


def ssllabs_grade(ctx: Any) -> dict | None:
    """The SSL Labs-compatible grade of the scan (worst host, worst IP), for grade.py (WP13). None without TLS data."""
    order = ["F", "T", "M", "E", "D", "C", "B", "A-", "A", "A+", "?"]
    worst: dict | None = None
    for key, rep in sorted((ctx.tls or {}).items()):
        if not isinstance(rep, dict) or rep.get("kind") != HOST_KIND:
            continue
        hsts = ctx.hsts_for(rep["host"]) if hasattr(ctx, "hsts_for") else None
        for iprep in (rep.get("ips") or {}).values():
            if iprep.get("status") != "ok":
                continue
            g = ssllabs_ip(iprep, ctx.now, hsts=hsts, host=rep["host"])
            g["host"], g["ip"] = key, iprep.get("ip")
            if worst is None or order.index(g["grade"]) < order.index(worst["grade"]):
                worst = g
    return worst


# ----------------------------------------------------------------------------------------------- host level

def _ip_signature(iprep: dict, chain: list[x509.Certificate]) -> dict:
    """Decided facts of one IP, as ``{aspect: {item: value}}``. Undecided items (inconclusive probe, chain not
    readable) are left out, so an IP whose probe timed out is never reported as configured differently."""
    leaf_only = iprep.get("chain_source") == "ssl_leaf"
    return {
        "protocols": {k: v.get("state") for k, v in (iprep.get("versions") or {}).items()
                      if v.get("state") in ("yes", "no")},
        "suites": {k: v.get("state") for k, v in (iprep.get("categories") or {}).items()
                   if v.get("state") in ("yes", "no")},
        "cert": {"leaf": chain[0].sha256} if chain else {},
        "chain": {"chain": tuple(c.sha256 for c in chain)} if chain and not leaf_only else {},
        "options": {k: v for k, v in (("compression", iprep.get("compression")),
                                      ("renegotiation_info", iprep.get("renegotiation_info"))) if v is not None},
    }


def _differs(sigs: dict[str, dict], what: str) -> bool:
    """True when two IPs decided some item of ``what`` differently (items decided on one IP only are ignored)."""
    seen: dict[str, Any] = {}
    for s in sigs.values():
        for item, value in s[what].items():
            if item in seen and seen[item] != value:
                return True
            seen.setdefault(item, value)
    return False


def _evidence(ctx: Any, host_rep: dict, cand: dict, ip: str | None, iprep: dict) -> Evidence:
    chain = _chain(iprep)
    leaf = chain[0] if chain else None
    ver = _trust(iprep) or {}
    tls: dict = {"ip": ip, "version": ver.get("version"), "cipher": ver.get("cipher")}
    if leaf is not None:
        s = leaf.summary()
        tls.update(subject=s["subject"], issuer=s["issuer"], not_before=s["not_before"], not_after=s["not_after"],
                   san=s["san"][:20], key=s["key"], sigalg=s["sigalg"], sha256=s["sha256"])
    real_ip = ip if ip and ip != "proxy" else None
    cmd = openssl_command(host_rep["host"], real_ip, int(host_rep.get("port") or 443), cand.get("flag") or "")
    return Evidence.for_response(None, where="tls", name=cand.get("name") or cand["rule"], value=cand.get("value") or "",
                                 now=ctx.now, tls=tls, command=cmd)


def assess_host(ctx: Any, host_rep: dict, profiles: dict, ct_logs: dict, ct_date: Any) -> tuple[list[Issue], dict]:
    """Issues and per-check states of one host (all its IPs), plus an inventory summary."""
    host, port = host_rep["host"], int(host_rep.get("port") or 443)
    url = f"https://{host}/" if port == 443 else f"https://{host}:{port}/"
    cov = ctx.coverage
    inv: dict = {"host": host, "port": port, "proxied": bool(host_rep.get("proxied")), "ips": {}, "notes": []}
    if host_rep.get("error"):
        err = host_rep["error"]
        for c in CHECKS:
            if cov is not None:
                cov.record(c, "not_tested", err.get("code") or "network", host=host, detail_en=err.get("en", ""),
                           detail_ar=err.get("ar", ""))
        inv["error"] = err
        return [], inv
    reached: list[tuple[str, dict, _Ip]] = []
    for key, iprep in (host_rep.get("ips") or {}).items():
        for note in iprep.get("notes") or []:
            if list(note) not in inv["notes"]:
                inv["notes"].append(list(note))
        if iprep.get("status") != "ok":
            inv["notes"].append(list(_t("unreachable", ip=key, reason=iprep.get("reason") or "network")))
            continue
        reached.append((key, iprep, evaluate_ip(ctx, host_rep, iprep, profiles, ct_logs, ct_date)))
    if host_rep.get("not_sampled"):
        ns = host_rep["not_sampled"]
        inv["notes"].append(list(_t("not_sampled", n=len(ns), ips=", ".join(ns[:8]))))
    if not reached:
        reason = next((r.get("reason") for r in (host_rep.get("ips") or {}).values() if r.get("reason")), "network")
        for c in CHECKS:
            if cov is not None:
                cov.record(c, "not_tested", reason if reason in ("ipv6_unreachable", "time_budget", "timeout") else "network",
                           host=host)
        return [], inv
    proxied = bool(host_rep.get("proxied"))
    proxy_note = [_t("proxied", proxy=host_rep.get("proxy") or "?")] if proxied else []
    # coverage: every reachable IP's state (fail > inconclusive > not_tested > pass > not_applicable)
    for _key, _iprep, ev in reached:
        for check, (state, reason, detail) in ev.states.items():
            if cov is not None:
                kw = {"detail_en": detail[0], "detail_ar": detail[1]} if detail else {}
                if state in ("not_tested", "inconclusive"):
                    cov.record(check, state, reason or "not_run", host=host, **kw)
                elif state == "not_applicable":
                    cov.record(check, state, reason, host=host, **kw)
                else:
                    cov.record(check, state, host=host)
    # merge findings across IPs
    merged: dict[tuple[str, str], dict] = {}
    for key, iprep, ev in reached:
        for ck, cand in ev.cands.items():
            if cand["rule"] == "_note":
                inv["notes"].extend(list(n) for n in cand["notes"] if list(n) not in inv["notes"])
                continue
            m = merged.get(ck)
            if m is None:
                merged[ck] = {**cand, "ips": [key], "iprep": iprep, "notes": list(cand["notes"])}
            else:
                m["ips"].append(key)
                if rules.SEVERITIES.index(cand["severity"]) < rules.SEVERITIES.index(m["severity"]):
                    m["severity"], m["iprep"] = cand["severity"], iprep
                m["notes"].extend(n for n in cand["notes"] if n not in m["notes"])
    all_ips = [k for k, _r, _e in reached]
    issues: list[Issue] = []
    for (rule, group), m in merged.items():
        notes = list(m["notes"]) + proxy_note
        ips = tuple(i for i in m["ips"] if i != "proxy")
        if len(all_ips) > 1 and len(m["ips"]) < len(all_ips):
            notes.append(_t("applies_only", ips=", ".join(m["ips"])))
        ev = _evidence(ctx, host_rep, m, m["ips"][0], m["iprep"])
        issues.append(Issue(rule=rule, url=url, confidence=m["confidence"], evidence=ev, params=m["params"],
                            severity=m["severity"], group_value=group,
                            notes=notes, host=host, ips=ips))
    # WEB715: configuration differences between nodes
    if proxied:
        if cov is not None:
            cov.record("WEB715", "not_tested", "proxied", host=host)
    elif len(reached) < 2:
        if cov is not None:
            cov.record("WEB715", "not_applicable", host=host)
    else:
        sigs = {k: _ip_signature(r, _chain(r)) for k, r, _e in reached}
        diffs = []
        for what in ("protocols", "suites", "cert", "chain", "options"):
            if _differs(sigs, what):
                diffs.append(_t("differs", what=DIFF_WHAT[what], ips=", ".join(sigs)))
        if diffs:
            first = reached[0]
            cand = {"rule": "WEB715", "name": "nodes", "value": "; ".join(d[0] for d in diffs)[:300], "flag": ""}
            issues.append(Issue(rule="WEB715", url=url, confidence="certain", evidence=_evidence(ctx, host_rep, cand,
                                                                                                    first[0], first[1]),
                                severity="low", group_value="nodes", notes=diffs + [STR["ips_differ_hint"]], host=host,
                                ips=tuple(all_ips)))
            if cov is not None:
                cov.record("WEB715", "fail", host=host)
        elif cov is not None:
            cov.record("WEB715", "pass", host=host)
    # inventory and grades
    hsts = ctx.hsts_for(host) if hasattr(ctx, "hsts_for") else None
    for key, iprep, _ev in reached:
        chain = _chain(iprep)
        leaf = chain[0] if chain else None
        inter = (profiles or {}).get("intermediate") or {}
        modern = (profiles or {}).get("modern") or {}
        inter_devs, inter_complete = mozilla_deviations(iprep, leaf, inter, deep=ctx.options.deep) if inter else ([], False)
        modern_devs, modern_complete = mozilla_deviations(iprep, leaf, modern, deep=ctx.options.deep) if modern else ([], False)
        inv["ips"][key] = {
            "protocols": {k: v.get("state") for k, v in (iprep.get("versions") or {}).items()},
            "suites": {k: v.get("state") for k, v in (iprep.get("categories") or {}).items()},
            "chosen": dict(iprep.get("chosen") or {}),
            "alpn": (iprep.get("verified") or {}).get("alpn"),
            "chain": [c.summary() for c in chain[:6]],
            "ocsp": (iprep.get("ocsp") or {}).get("state"),
            "scts": {"embedded": len(leaf.scts) if leaf else 0,
                     "tls": sum(len(x509.parse_sct_list(_b64d(s))) for s in iprep.get("tls_scts") or [])},
            "deep": {k: v for k, v in (iprep.get("deep") or {}).items() if k != "dh_prime_sha256"},
            "mozilla": {"intermediate": {"conformant": not inter_devs and inter_complete,
                                         "deviations": [list(d) for d in inter_devs]},
                        "modern": {"conformant": not modern_devs and modern_complete,
                                   "deviations": [list(d) for d in modern_devs]}},
            "ssllabs": ssllabs_ip(iprep, ctx.now, hsts=hsts, host=host),
            "handshakes": iprep.get("handshakes"),
        }
    return issues, inv


def run(ctx: Any) -> list[Issue]:
    """Stage 2 (§4.2): TLS issues from ``ctx.tls``; writes ``ctx.inventory["tls"]`` and coverage states."""
    cov = ctx.coverage
    if cov is not None:
        cov.register(*CHECKS)
    reports = [r for r in (ctx.tls or {}).values() if isinstance(r, dict) and r.get("kind") == HOST_KIND]
    if not reports:
        target_https = (ctx.target or "").lower().startswith("https://")
        for c in CHECKS:
            if cov is None:
                break
            if target_https:
                cov.record(c, "not_tested", "network")
            else:
                cov.record(c, "not_applicable", "http_only")
        return []
    data_mod = ctx.data
    if data_mod is None:
        from .. import data as data_mod
    profiles: dict = {}
    ct_logs: dict = {}
    ct_date = None
    try:
        profiles = data_mod.load_json("tls-profiles.json").get("profiles", {})
    except (OSError, ValueError, AttributeError):
        profiles = {}
    try:
        ct_logs = data_mod.load_json("ct-logs.json").get("logs", {})
        ct_date = data_mod.file_date("ct-logs.json")
    except (OSError, ValueError, AttributeError):
        ct_logs, ct_date = {}, None
    issues: list[Issue] = []
    inventory: dict = {}
    for rep in sorted(reports, key=lambda r: (r.get("host", ""), r.get("port", 443))):
        found, inv = assess_host(ctx, rep, profiles, ct_logs, ct_date)
        issues.extend(found)
        inventory[rep["host"] if int(rep.get("port") or 443) == 443 else f"{rep['host']}:{rep['port']}"] = inv
    if isinstance(ctx.inventory, dict):
        ctx.inventory["tls"] = inventory
        g = ssllabs_grade(ctx)
        if g is not None:
            ctx.inventory["tls_grade"] = g
    return issues


_PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")


def i18n_catalog() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """``(CATALOG, PATTERNS)`` for ``vulnscan/i18n/cat_web2.py``: fixed Arabic strings of tls/ (notes, reasons) →
    English, and ``(regular expression, English replacement)`` pairs for the parametrised ones and the count
    phrases (``vulnscan.i18n.to_en`` translates the captured groups again, so a count phrase inside a note works)."""
    from .probe import STR as PROBE_STR
    exact: dict[str, str] = {}
    patterns: list[tuple[str, str]] = []
    pairs = list(STR.values()) + list(PROBE_STR.values()) + list(DIFF_WHAT.values()) + \
        [(e, a) for _s, e, a in CATEGORY_RULE.values()]
    for en, ar in pairs:
        if "{" not in ar:
            exact[ar] = en
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
    for en_one, en_many, forms in COUNT_FORMS.values():
        exact[forms[0]] = en_one.replace("{n}", "1")
        exact[forms[1]] = en_many.replace("{n}", "2")
        for form in forms[2:]:
            rx = "^" + re.escape(form).replace(re.escape("{n}"), r"(?P<n>\d+)") + "$"
            patterns.append((rx, en_many.replace("{n}", r"\g<n>")))
    return exact, patterns


__all__ = ["CHECKS", "run", "evaluate_ip", "assess_host", "ssllabs_ip", "ssllabs_grade", "mozilla_deviations", "STR",
           "i18n_catalog"]
